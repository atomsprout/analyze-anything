//! Windows Installer packages (MSI): extraction of the embedded cabinets under the resolved
//! install paths, and the meaning of the database tables.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};

use aa_core::Artifact;
use aa_core::plugin::{Output, Rule, SinkError, Unpack, UnpackSink, Unpacker};
use serde_json::json;

use crate::cab;
use crate::installer::{Command, Installer, MAX_ITEMS, RegistryWrite, Service, Shortcut};

const CFB_MAGIC: &[u8] = &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
/// Largest embedded stream read into memory.
const MAX_STREAM: u64 = 2 * 1024 * 1024 * 1024;

pub(super) type Package<'a> = msi::Package<Cursor<&'a [u8]>>;

pub struct Msi;

pub const RULES: &[Rule] = &[
    Rule {
        id: "msi.external-cabinet",
        title_zh: "MSI 的文件不在包内",
        title_en: "The MSI keeps files outside the package",
        text_zh: "MSI 引用了包外的 CAB 文件或未压缩的源文件，这些文件不在 MSI 内，没有分析。",
        text_en: "The MSI refers to cabinet files or uncompressed source files outside the package. They are not inside the MSI and were not analyzed.",
    },
    Rule {
        id: "msi.files-unreadable",
        title_zh: "MSI 内部分文件无法提取",
        title_en: "Some files in the MSI could not be extracted",
        text_zh: "MSI 内嵌的 CAB 中有文件无法解压，这些文件没有分析。",
        text_en: "Some files in the MSI's embedded cabinets could not be decompressed. They were not analyzed.",
    },
];

/// Opens `bytes` as an MSI database. `None` when it is another kind of compound file.
fn open(bytes: &[u8]) -> Option<Package<'_>> {
    if !bytes.starts_with(CFB_MAGIC) {
        return None;
    }
    // The reader is third-party code fed hostile input: a panic counts as "not readable".
    let package = std::panic::catch_unwind(|| msi::Package::open(Cursor::new(bytes))).ok()?.ok()?;
    (package.package_type() == msi::PackageType::Installer).then_some(package)
}

/// The rows of `table` as maps from column name to text. Integers are rendered in decimal;
/// nulls are absent.
fn rows(package: &mut Package, table: &str) -> Vec<BTreeMap<String, String>> {
    if !package.has_table(table) {
        return Vec::new();
    }
    let Ok(rows) = package.select_rows(msi::Select::table(table)) else { return Vec::new() };
    let mut out = Vec::new();
    for row in rows.take(200_000) {
        let mut map = BTreeMap::new();
        for (index, column) in row.columns().iter().enumerate() {
            match &row[index] {
                msi::Value::Null | msi::Value::Binary => {}
                msi::Value::Int(number) => {
                    map.insert(column.name().to_string(), number.to_string());
                }
                msi::Value::Str(text) => {
                    map.insert(column.name().to_string(), text.clone());
                }
            }
        }
        out.push(map);
    }
    out
}

fn get<'a>(row: &'a BTreeMap<String, String>, column: &str) -> &'a str {
    row.get(column).map(String::as_str).unwrap_or_default()
}

/// The long name of a `short|long` pair.
fn long_name(name: &str) -> &str {
    name.rsplit('|').next().unwrap_or(name)
}

/// Resolves every Directory row to its install path, e.g. `ProgramFilesFolder/Vendor/App`.
///
/// System folders keep their property name (`ProgramFilesFolder`, `AppDataFolder`): where they
/// point is decided on the target machine. `TARGETDIR` itself is the empty path.
fn directories(package: &mut Package) -> BTreeMap<String, String> {
    let table = rows(package, "Directory");
    let by_id: BTreeMap<&str, &BTreeMap<String, String>> = table.iter().map(|row| (get(row, "Directory"), row)).collect();
    let mut resolved = BTreeMap::new();
    for row in &table {
        let id = get(row, "Directory");
        let mut parts = Vec::new();
        let mut current = id;
        // Parent links are followed at most as deep as the table is long, so a cycle ends.
        for _ in 0..table.len().min(256) {
            let Some(row) = by_id.get(current) else { break };
            let parent = get(row, "Directory_Parent");
            // DefaultDir is `target:source`; the target is where files are installed.
            let target = long_name(get(row, "DefaultDir").split(':').next().unwrap_or_default());
            if parent.is_empty() || parent == current {
                // The root (TARGETDIR). Its DefaultDir "SourceDir" is not a folder name.
                break;
            }
            if target == "." {
                // "Same as the parent" — but a system folder is a place of its own.
                if current.ends_with("Folder") {
                    parts.push(current);
                }
            } else if !target.is_empty() {
                parts.push(target);
            }
            current = parent;
        }
        parts.reverse();
        resolved.insert(id.to_string(), parts.join("/"));
    }
    resolved
}

/// `File key -> install path` for every row of the File table.
fn file_paths(package: &mut Package) -> BTreeMap<String, String> {
    let directories = directories(package);
    let components: BTreeMap<String, String> = rows(package, "Component")
        .into_iter()
        .map(|row| (get(&row, "Component").to_string(), get(&row, "Directory_").to_string()))
        .collect();
    let mut paths = BTreeMap::new();
    for row in rows(package, "File") {
        let name = long_name(get(&row, "FileName"));
        let directory = components.get(get(&row, "Component_")).and_then(|d| directories.get(d)).map(String::as_str).unwrap_or_default();
        let path = if directory.is_empty() { name.to_string() } else { format!("{directory}/{name}") };
        paths.insert(get(&row, "File").to_string(), path);
    }
    paths
}

fn read_stream(package: &mut Package, name: &str) -> Option<Vec<u8>> {
    let mut data = Vec::new();
    package.read_stream(name).ok()?.take(MAX_STREAM).read_to_end(&mut data).ok()?;
    Some(data)
}

impl Unpacker for Msi {
    fn id(&self) -> &'static str {
        "msi"
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        let Some(mut package) = open(bytes) else { return Unpack::NotMine };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unpack(&mut package, sink)));
        match result {
            Ok(()) => Unpack::Done { kind: "msi" },
            Err(_) => Unpack::Failed { kind: "msi", detail: "the MSI database could not be read".into() },
        }
    }
}

fn unpack(package: &mut Package, sink: &mut dyn UnpackSink) {
    let paths = file_paths(package);
    let mut cabinets = BTreeSet::new();
    let mut external = Vec::new();
    for row in rows(package, "Media") {
        let cabinet = get(&row, "Cabinet").to_string();
        match cabinet.strip_prefix('#') {
            Some(stream) => {
                cabinets.insert(stream.to_string());
            }
            None if !cabinet.is_empty() => external.push(cabinet),
            None => {}
        }
    }
    let mut extracted = BTreeSet::new();
    let mut problems = Vec::new();
    let mut stopped = false;
    for stream in &cabinets {
        let Some(data) = read_stream(package, stream) else {
            problems.push(format!("cabinet stream {stream} could not be read"));
            continue;
        };
        let cabinet = match cab::parse(&data) {
            Ok(cabinet) => cabinet,
            Err(error) => {
                problems.push(format!("cabinet {stream}: {error}"));
                continue;
            }
        };
        // Files in a cabinet are named by their File-table key.
        problems.extend(cabinet.extract(|file, mut data| {
            let path = paths.get(&file.name).cloned().unwrap_or_else(|| format!("[not in File table]/{}", file.name));
            extracted.insert(file.name.clone());
            let more = !matches!(sink.add(&path, &mut data), Err(SinkError::LimitReached));
            stopped |= !more;
            more
        }));
        if stopped {
            return;
        }
    }
    // Other streams: Binary.* holds custom-action code, Icon.* the icons.
    let names: Vec<String> = package.streams().collect();
    for name in names {
        if cabinets.contains(&name) || name.starts_with('\u{5}') {
            continue;
        }
        let Some(data) = read_stream(package, &name) else { continue };
        let path = match name.split_once('.') {
            Some((table @ ("Binary" | "Icon"), key)) => format!("[{table}]/{key}"),
            _ => format!("[stream]/{name}"),
        };
        if sink.add(&path, &mut data.as_slice()) == Err(SinkError::LimitReached) {
            return;
        }
    }
    let missing = paths.keys().filter(|key| !extracted.contains(*key)).count();
    if !external.is_empty() || (missing > 0 && cabinets.is_empty()) {
        let detail = if external.is_empty() {
            aa_core::counted(missing as u64, "files are stored outside the package")
        } else {
            format!("external cabinets: {}", external.join(", "))
        };
        sink.limitation("msi.external-cabinet", Some(detail));
    }
    if !problems.is_empty() {
        let shown = problems.iter().take(5).cloned().collect::<Vec<_>>().join("; ");
        sink.limitation("msi.files-unreadable", Some(format!("{} problems: {shown}", problems.len())));
    }
}

fn registry_root(root: &str) -> &'static str {
    match root {
        "0" => "HKCR",
        "1" => "HKCU",
        "2" => "HKLM",
        "3" => "HKU",
        // -1: HKCU for a per-user installation, HKLM for a per-machine one.
        _ => "HKCU or HKLM (by install scope)",
    }
}

fn start_type(value: &str) -> Option<String> {
    Some(
        match value {
            "0" => "boot",
            "1" => "system",
            "2" => "auto",
            "3" => "demand",
            "4" => "disabled",
            _ => return None,
        }
        .to_string(),
    )
}

/// What a custom action runs, from its type number. `None` for actions that run nothing
/// (property and directory assignments, error messages).
fn custom_action(kind: i64, source: &str, target: &str) -> Option<String> {
    Some(match kind & 0x3f {
        1 => format!("DLL from Binary table: {source}!{target}"),
        17 => format!("installed DLL: {source}!{target}"),
        2 => format!("EXE from Binary table: {source} {target}"),
        18 => format!("installed EXE: {source} {target}"),
        34 => format!("[{source}] {target}"),
        50 => format!("[{source}] {target}"),
        5 | 21 => format!("JScript from {source}: {target}"),
        6 | 22 => format!("VBScript from {source}: {target}"),
        37 | 53 => format!("inline JScript: {target}"),
        38 | 54 => format!("inline VBScript: {target}"),
        _ => return None,
    })
}

/// Reads the tables of an MSI. `None` when `bytes` is not one.
pub fn analyze(file: &Artifact, bytes: &[u8], out: &mut Output) -> Option<Installer> {
    let mut package = open(bytes)?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let model = read_tables(&mut package);
        crate::msi_actions::read(&mut package, file, out);
        model
    }));
    match result {
        Ok(model) => Some(model),
        Err(_) => {
            out.limitation("windows.installer-unreadable", Some(file), Some("MSI: the database tables could not be read".into()));
            None
        }
    }
}

fn read_tables(package: &mut Package) -> Installer {
    let mut model = Installer { kind: "MSI", ..Installer::default() };
    let properties: BTreeMap<String, String> =
        rows(package, "Property").into_iter().map(|row| (get(&row, "Property").to_string(), get(&row, "Value").to_string())).collect();
    let property = |name: &str| properties.get(name).cloned().filter(|v| !v.is_empty());
    model.product = property("ProductName");
    model.version = property("ProductVersion");
    model.publisher = property("Manufacturer");
    let summary = package.summary_info();
    let mut format = vec!["Windows Installer database".to_string()];
    if let Some(arch) = summary.arch() {
        format.push(format!("platform {arch}"));
    }
    if let Some(tool) = summary.creating_application() {
        format.push(format!("built with {tool}"));
    }
    model.format = Some(format.join(", "));
    // ALLUSERS=1 is a per-machine installation, which needs administrator rights.
    if let Some(all_users) = property("ALLUSERS") {
        model.admin = Some((all_users == "1", "Property table: ALLUSERS".to_string()));
    }

    let directories = directories(package);
    model.install_dir = ["INSTALLDIR", "INSTALLFOLDER", "INSTALLLOCATION", "APPLICATIONFOLDER", "APPDIR", "TARGETDIR"]
        .iter()
        .find_map(|id| directories.get(*id).filter(|path| !path.is_empty()).cloned());

    let files = rows(package, "File");
    model.files = Some(files.len() as u64);
    model.files_bytes = Some(files.iter().filter_map(|row| get(row, "FileSize").parse::<u64>().ok()).sum());
    let file_paths = file_paths(package);
    // Component -> key file path, to name a service's binary.
    let key_files: BTreeMap<String, String> = rows(package, "Component")
        .into_iter()
        .filter_map(|row| Some((get(&row, "Component").to_string(), file_paths.get(get(&row, "KeyPath"))?.clone())))
        .collect();

    for row in rows(package, "Registry") {
        if model.registry.len() >= MAX_ITEMS {
            model.truncated = true;
            break;
        }
        model.registry.push(RegistryWrite {
            root: registry_root(get(&row, "Root")).to_string(),
            key: get(&row, "Key").to_string(),
            name: get(&row, "Name").to_string(),
            value: row.get("Value").cloned(),
            source: format!("Registry table, row {}", get(&row, "Registry")),
        });
    }
    for row in rows(package, "ServiceInstall") {
        let kind: i64 = get(&row, "ServiceType").parse().unwrap_or(0);
        let binary = key_files.get(get(&row, "Component_")).cloned();
        let arguments = get(&row, "Arguments");
        model.services.push(Service {
            name: get(&row, "Name").to_string(),
            display_name: row.get("DisplayName").cloned(),
            start: start_type(get(&row, "StartType")),
            // SERVICE_KERNEL_DRIVER (1) and SERVICE_FILE_SYSTEM_DRIVER (2).
            driver: kind & 0x3 != 0,
            account: row.get("StartName").cloned(),
            command: binary.map(|b| format!("{b} {arguments}").trim().to_string()),
            source: format!("ServiceInstall table, row {}", get(&row, "ServiceInstall")),
        });
    }
    // Drivers installed through DIFxApp.
    for row in rows(package, "MsiDriverPackages") {
        model.services.push(Service {
            name: get(&row, "Component").to_string(),
            driver: true,
            source: format!("MsiDriverPackages table, row {}", get(&row, "Component")),
            ..Service::default()
        });
    }
    let mut actions = Vec::new();
    for row in rows(package, "CustomAction") {
        let kind: i64 = get(&row, "Type").parse().unwrap_or(0);
        let (name, source, target) = (get(&row, "Action"), get(&row, "Source"), get(&row, "Target"));
        let mut flags = Vec::new();
        if kind & 0x400 != 0 {
            flags.push(crate::msi_actions::execution(kind));
        }
        if kind & 0xc00 == 0xc00 {
            flags.push("no impersonation requested");
        }
        if actions.len() < 2000 {
            actions.push(json!({ "action": name, "type": kind, "source": source, "target": target, "flags": flags }));
        }
        // Actions on installed files name them by File key; show the path instead.
        let installed = file_paths.get(source).map(String::as_str).unwrap_or(source);
        let command = match custom_action(kind, if matches!(kind & 0x3f, 17 | 18 | 21 | 22) { installed } else { source }, target) {
            Some(command) => Some(command),
            // Type 51 sets a property. Deferred actions get their command line this way
            // (the property is named after the action), so values that are command lines count.
            None if kind & 0x3f == 51 && looks_like_command(target) => Some(target.to_string()),
            None => None,
        };
        if let Some(command) = command
            && model.commands.len() < MAX_ITEMS
        {
            let note = if flags.is_empty() { String::new() } else { format!(" ({})", flags.join(", ")) };
            model.commands.push(Command { command, source: format!("CustomAction table, row {name}{note}") });
        }
    }
    for row in rows(package, "Shortcut") {
        if model.shortcuts.len() >= MAX_ITEMS {
            model.truncated = true;
            break;
        }
        let directory = directories.get(get(&row, "Directory_")).cloned().unwrap_or_else(|| get(&row, "Directory_").to_string());
        model.shortcuts.push(Shortcut {
            path: format!("{directory}/{}", long_name(get(&row, "Name"))),
            target: get(&row, "Target").to_string(),
            arguments: get(&row, "Arguments").to_string(),
            source: format!("Shortcut table, row {}", get(&row, "Shortcut")),
        });
    }
    for row in rows(package, "Environment") {
        // Prefix characters say how the variable is set: = create, + append, - remove on
        // uninstall, ! remove, * system variable.
        let name = get(&row, "Name").trim_start_matches(['=', '+', '-', '!', '*']).to_string();
        model.environment.push((name, get(&row, "Value").to_string(), format!("Environment table, row {}", get(&row, "Environment"))));
    }
    let conditions: Vec<_> = rows(package, "LaunchCondition")
        .iter()
        .take(100)
        .map(|row| json!({ "condition": get(row, "Condition"), "description": get(row, "Description") }))
        .collect();
    model.extra.insert("product_code".into(), json!(property("ProductCode")));
    model.extra.insert("upgrade_code".into(), json!(property("UpgradeCode")));
    model.extra.insert("launch_conditions".into(), json!(conditions));
    model.extra.insert("custom_actions".into(), json!(actions));
    model.extra.insert("has_digital_signature".into(), json!(package.has_digital_signature()));
    model.extra.insert("tables".into(), json!(package.tables().map(|t| t.name().to_string()).collect::<BTreeSet<_>>()));
    model.extra.insert(
        "summary".into(),
        json!({
            "title": summary_text(package.summary_info().title()),
            "subject": summary_text(package.summary_info().subject()),
            "author": summary_text(package.summary_info().author()),
            "comments": summary_text(package.summary_info().comments()),
        }),
    );
    model
}

fn summary_text(value: Option<&str>) -> Option<String> {
    value.map(str::to_string).filter(|v| !v.is_empty())
}

/// True when a property value reads like a command line rather than a path or a flag.
fn looks_like_command(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    [".exe", ".cmd", ".bat", ".ps1", ".vbs", "powershell", "cmd /c", "rundll32", "regsvr32", "msiexec"]
        .iter()
        .any(|needle| lower.contains(needle))
}
