//! NSIS installers: extraction of the embedded files and the meaning of the install script.
//!
//! The container, the script bytecode and the three compression schemes are read by the `nsis`
//! crate (see `docs/spikes/nsis.md` for what was verified against 7-Zip).

use std::collections::BTreeSet;

use aa_core::Artifact;
use aa_core::plugin::{Output, Rule, SinkError, Tree, Unpack, UnpackSink, Unpacker};
use nsis::{ExecCommand, NsisInstaller, RegistryOp, SolidStatus};
use serde_json::json;

use crate::installer::{Command, Installer, MAX_ITEMS, RegistryWrite, Shortcut};
use crate::pe::Pe;

/// The marker in an NSIS first header: `0xDEADBEEF` followed by `NullsoftInst`.
const MARKER: &[u8] = b"\xef\xbe\xad\xdeNullsoftInst";
/// Budget for a solid stream when extracting files.
const UNPACK_BUDGET: usize = 2 * 1024 * 1024 * 1024;
/// Budget when only the header and script are needed.
const HEADER_BUDGET: usize = 16 * 1024 * 1024;
/// Name of the child that holds the decoded install script.
pub const SCRIPT_NAME: &str = "[NSIS script].txt";

pub struct Nsis;

pub const RULES: &[Rule] = &[
    Rule {
        id: "nsis.files-unreadable",
        title_zh: "NSIS 安装包内部分文件无法提取",
        title_en: "Some files in the NSIS installer could not be extracted",
        text_zh: "安装包里有文件无法解压（数据损坏、超出解压预算，或使用了不支持的变体），这些文件没有分析。",
        text_en: "Some files in the installer could not be decompressed (damaged data, over the decompression budget, or an unsupported variant). They were not analyzed.",
    },
    Rule {
        id: "nsis.script-synthetic",
        title_zh: "NSIS 脚本是还原出来的",
        title_en: "The NSIS script is a reconstruction",
        text_zh: "“[NSIS script].txt”不是安装包里原有的文件，而是由安装包内的脚本字节码逐条还原出的文本，供阅读和提取其中的网址。",
        text_en: "\"[NSIS script].txt\" is not a file stored in the installer: it is the installer's script bytecode rendered as text, entry by entry, for reading and for URL extraction.",
    },
];

/// True when `bytes` is a PE file with an NSIS first header in its overlay.
pub fn is_nsis(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"MZ") {
        return false;
    }
    let Ok(pe) = Pe::parse(bytes) else { return false };
    let start = pe.end_of_image();
    // The first header sits at a 512-byte boundary right after the stub; allow some slack for
    // stubs that were signed or padded.
    let window = &bytes[start..bytes.len().min(start.saturating_add(4 * 1024 * 1024))];
    memchr::memmem::find(window, MARKER).is_some()
}

/// The path of a child, as 7-Zip names it: relative to `$INSTDIR`, other variables kept
/// (`$PLUGINSDIR/System.dll`). The engine's sink refuses anything that would escape.
fn child_path(path: &nsis::strings::NsisString) -> String {
    path.to_install_path().replace('\\', "/")
}

impl Unpacker for Nsis {
    fn id(&self) -> &'static str {
        "nsis"
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        if !is_nsis(bytes) {
            return Unpack::NotMine;
        }
        let installer = match NsisInstaller::builder(bytes).max_decompressed_size(UNPACK_BUDGET).parse() {
            Ok(installer) => installer,
            Err(error) => return Unpack::Failed { kind: "nsis", detail: error.to_string() },
        };
        let mut failures: Vec<String> = Vec::new();
        match installer.solid_status() {
            SolidStatus::Truncated { limit } => failures.push(format!("the solid stream is larger than the {limit}-byte budget")),
            SolidStatus::Failed(error) => failures.push(format!("the solid stream could not be decompressed: {error}")),
            SolidStatus::NotSolid | SolidStatus::Complete => {}
        }
        let mut seen = BTreeSet::new();
        let mut stopped = false;
        for file in installer.files() {
            let file = match file {
                Ok(file) => file,
                Err(error) => {
                    failures.push(error.to_string());
                    continue;
                }
            };
            let Ok(path) = file.dest_path().map(|p| child_path(&p)) else { continue };
            // The same data written to the same place twice (in different sections) is one file;
            // different data for one destination (per-language variants) are all kept.
            if path.is_empty() || !seen.insert(format!("{path}\u{0}{}", file.data_block_offset())) {
                continue;
            }
            match file.decompress() {
                Ok(content) => match sink.add(&path, &mut content.as_slice()) {
                    Ok(()) | Err(SinkError::Read(_)) => {}
                    Err(SinkError::LimitReached) => {
                        stopped = true;
                        break;
                    }
                },
                Err(error) => failures.push(format!("{path}: {error}")),
            }
        }
        if !stopped {
            for uninstaller in installer.uninstallers().flatten() {
                let Ok(path) = uninstaller.path().map(|p| child_path(&p)) else { continue };
                if path.is_empty() || !seen.insert(path.clone()) {
                    continue;
                }
                match uninstaller_image(&installer, &uninstaller) {
                    Ok(content) => {
                        if sink.add(&path, &mut content.as_slice()) == Err(SinkError::LimitReached) {
                            stopped = true;
                            break;
                        }
                    }
                    Err(error) => failures.push(format!("{path}: {error}")),
                }
            }
        }
        if !stopped {
            let script = script_text(&installer);
            if sink.add(SCRIPT_NAME, &mut script.as_bytes()).is_ok() {
                sink.limitation("nsis.script-synthetic", None);
            }
        }
        if !failures.is_empty() {
            let shown = failures.iter().take(5).cloned().collect::<Vec<_>>().join("; ");
            sink.limitation("nsis.files-unreadable", Some(format!("{} problems: {shown}", failures.len())));
        }
        Unpack::Done { kind: "nsis" }
    }
}

/// The uninstaller as the installer would write it: the installer's own stub with the icon
/// patches applied, followed by the uninstaller's header and data.
///
/// The `nsis` crate returns the stub unpatched and does not know the variant that stores the
/// whole uninstaller; both are handled here, the way NSIS itself and 7-Zip do: the patch list
/// (`size, offset, bytes` records ending at a zero size) is applied to the stub.
fn uninstaller_image(installer: &NsisInstaller, uninstaller: &nsis::Uninstaller) -> Result<Vec<u8>, nsis::Error> {
    use nsis::decompress::{CompressionMode, DecodeLimit, decompress_block, read_length_prefix};
    // The first block at the uninstaller's data offset.
    let solid = installer.compression_mode() == CompressionMode::Solid;
    let source = if solid { installer.solid_data() } else { installer.file_data() };
    let first_block = usize::try_from(uninstaller.data_offset()).ok().and_then(|relative| {
        let start = if solid { relative } else { installer.data_block_offset().saturating_add(relative) };
        let block = source.get(start..)?;
        let (compressed, size) = read_length_prefix(block).ok()?;
        let payload = block.get(4..4usize.saturating_add(size as usize))?;
        if compressed && !solid {
            decompress_block(payload, installer.compression(), DecodeLimit::Capped(64 * 1024 * 1024)).ok().map(|d| d.data)
        } else {
            Some(payload.to_vec())
        }
    });
    // Without an icon patch list (icon size 0) the block is the complete uninstaller program.
    if uninstaller.icon_size() == 0
        && let Some(image) = &first_block
        && image.starts_with(b"MZ")
    {
        return Ok(image.clone());
    }
    let mut image = uninstaller.decompress()?;
    let stub = installer.first_header_file_offset().min(image.len());
    let patches = first_block.unwrap_or_default();
    let mut at = 0usize;
    while let (Some(size), Some(offset)) = (crate::pe::u32_at(&patches, at), crate::pe::u32_at(&patches, at + 4)) {
        if size == 0 {
            break;
        }
        let (size, offset) = (size as usize, offset as usize);
        let Some(bytes) = patches.get(at + 8..(at + 8).saturating_add(size)) else { break };
        // Patches only ever touch the stub.
        if let Some(target) = offset.checked_add(size).filter(|end| *end <= stub).and_then(|end| image.get_mut(offset..end)) {
            target.copy_from_slice(bytes);
        }
        at += 8 + size;
    }
    Ok(image)
}

/// The script as text: one line per bytecode entry, in the notation of the `nsis` crate.
fn script_text(installer: &NsisInstaller) -> String {
    let mut text = String::new();
    text.push_str("; Install script reconstructed from the NSIS bytecode. Not a file of the installer.\n");
    if let Ok(dir) = installer.install_dir() {
        text.push_str(&format!("; InstallDir {dir}\n"));
    }
    let analysis = installer.script_analysis().ok();
    for (index, entry) in installer.entries().enumerate() {
        let Ok(entry) = entry else { continue };
        let mnemonic = installer.resolve_opcode(entry.which()).map(|o| o.mnemonic).unwrap_or("???");
        // Padding entries carry no information.
        if mnemonic == "EW_INVALID_OPCODE" {
            continue;
        }
        let detail = match analysis {
            Some(analysis) => installer.format_entry_params_with_analysis(&entry, analysis),
            None => installer.format_entry_params(&entry),
        };
        text.push_str(&format!("{index:6}: {mnemonic} {detail}\n"));
        if text.len() > 32 * 1024 * 1024 {
            text.push_str("; (truncated)\n");
            break;
        }
    }
    text
}

/// Reads what the install script does. `None` when `bytes` is not an NSIS installer.
pub fn analyze(tree: &dyn Tree, file: &Artifact, bytes: &[u8], out: &mut Output) -> Option<Installer> {
    if !file.is("nsis") && !is_nsis(bytes) {
        return None;
    }
    let installer = match NsisInstaller::builder(bytes).max_decompressed_size(HEADER_BUDGET).parse() {
        Ok(installer) => installer,
        Err(error) => {
            out.limitation("windows.installer-unreadable", Some(file), Some(format!("NSIS: {error}")));
            return None;
        }
    };
    let mut model = Installer { kind: "NSIS", ..Installer::default() };
    model.format = Some(format!(
        "NSIS {:?}, {:?} strings, {:?} compression ({:?})",
        installer.version(),
        installer.string_encoding(),
        installer.compression(),
        installer.compression_mode()
    ));
    // The installer's Name is language string 2 of each language table; the first table is the default.
    if let Some(Ok(table)) = installer.lang_tables().next()
        && let Ok(name) = installer.lang_string(&table, 2)
    {
        model.product = Some(name.to_string()).filter(|n| !n.is_empty());
    }
    // RequestExecutionLevel ends up in the stub's manifest.
    if let Ok(pe) = Pe::parse(bytes)
        && let Some(level) = pe
            .resources()
            .entries
            .iter()
            .find(|r| r.kind == crate::pe::ResId::Id(crate::pe::RT_MANIFEST))
            .and_then(|r| pe.data.get(r.offset?..r.offset? + r.size as usize))
            .and_then(|xml| crate::resources::parse_manifest(xml).ok())
            .and_then(|manifest| manifest.execution_level)
    {
        model.admin = Some((level.eq_ignore_ascii_case("requireAdministrator"), "manifest: requestedExecutionLevel".to_string()));
    }
    model.uninstaller = installer.is_uninstaller();
    model.install_dir = installer.install_dir().ok().map(|d| d.to_string()).filter(|d| !d.is_empty());

    // Entry numbers, so evidence can say where in the script something is.
    // Identical entries are told apart by taking their numbers in script order, which is the
    // order the typed iterators below yield them in.
    let mut entry_index: std::collections::BTreeMap<_, std::collections::VecDeque<usize>> = std::collections::BTreeMap::new();
    for (index, entry) in installer.entries().enumerate() {
        if let Ok(entry) = entry {
            entry_index.entry((entry.which(), entry.offsets())).or_default().push_back(index);
        }
    }
    let mut source = |entry: &nsis::nsis::entry::Entry| {
        let numbers = entry_index.get_mut(&(entry.which(), entry.offsets()));
        match numbers.and_then(|n| if n.len() > 1 { n.pop_front() } else { n.front().copied() }) {
            Some(index) => format!("script entry {index}"),
            None => "script".to_string(),
        }
    };

    for op in installer.registry_ops().flatten() {
        let RegistryOp::Write(write) = op else { continue };
        if model.registry.len() >= MAX_ITEMS {
            model.truncated = true;
            break;
        }
        model.registry.push(RegistryWrite {
            root: write.root_name().to_string(),
            key: write.key().map(|k| k.to_string()).unwrap_or_default(),
            name: write.value_name().map(|n| n.to_string()).unwrap_or_default(),
            value: write.data().ok().map(|d| d.to_string()),
            source: source(write.entry()),
        });
    }
    for command in installer.exec_commands().flatten() {
        if model.commands.len() >= MAX_ITEMS {
            model.truncated = true;
            break;
        }
        let (text, entry) = match &command {
            ExecCommand::Exec(op) => (op.command_line().map(|c| c.to_string()).unwrap_or_default(), op.entry()),
            ExecCommand::ShellExec(op) => {
                let part = |value: Result<nsis::strings::NsisString, nsis::Error>| value.map(|v| v.to_string()).unwrap_or_default();
                (format!("{} {} {}", part(op.verb()), part(op.file()), part(op.params())).trim().to_string(), op.entry())
            }
        };
        if !text.is_empty() {
            model.commands.push(Command { command: text, source: source(entry) });
        }
    }
    for shortcut in installer.shortcuts().flatten() {
        if model.shortcuts.len() >= MAX_ITEMS {
            model.truncated = true;
            break;
        }
        model.shortcuts.push(Shortcut {
            path: shortcut.link_path().map(|p| p.to_string()).unwrap_or_default(),
            target: shortcut.target().map(|t| t.to_string()).unwrap_or_default(),
            arguments: shortcut.parameters().map(|p| p.to_string()).unwrap_or_default(),
            source: source(shortcut.entry()),
        });
    }

    // NSIS has no version or publisher field; installers state them in the uninstall entry.
    for write in model.registry.iter().filter(|w| w.key.to_ascii_lowercase().contains("\\currentversion\\uninstall\\")) {
        let value = write.value.clone().filter(|v| !v.is_empty() && !v.contains('$'));
        match write.name.as_str() {
            "DisplayVersion" if model.version.is_none() => model.version = value,
            "Publisher" if model.publisher.is_none() => model.publisher = value,
            _ => {}
        }
    }

    // Plug-in calls take their arguments from the stack; the strings pushed just before a call
    // are its arguments in reverse order. That pairing is a heuristic, and is labelled so.
    let mut plugins = BTreeSet::new();
    let mut pushed: Vec<String> = Vec::new();
    for (index, entry) in installer.entries().enumerate() {
        let Ok(entry) = entry else { continue };
        match installer.resolve_opcode(entry.which()).map(|o| o.mnemonic) {
            Some("EW_PUSHPOP") if entry.offset(1) == 0 && entry.offset(2) == 0 => {
                if let Ok(text) = installer.read_string(entry.offset(0)) {
                    pushed.push(text.to_string());
                    if pushed.len() > 16 {
                        pushed.remove(0);
                    }
                }
            }
            Some("EW_REGISTERDLL") => {
                let dll = installer.read_string(entry.offset(0)).map(|d| d.to_string()).unwrap_or_default();
                let function = installer.read_string(entry.offset(1)).map(|f| f.to_string()).unwrap_or_default();
                let library = dll.rsplit(['\\', '/']).next().unwrap_or(&dll).to_string();
                let arguments: Vec<String> = pushed.drain(..).rev().collect();
                plugins.insert(format!("{library}::{function}"));
                let lower = library.to_ascii_lowercase();
                let source = format!("script entry {index}");
                if ["inetc.dll", "nsisdl.dll", "inetload.dll", "nsxfer.dll", "nscurl.dll"].contains(&lower.as_str()) {
                    let url = arguments.iter().find(|a| a.contains("://")).cloned();
                    let what = match url {
                        Some(url) => format!("{library}::{function} {url}"),
                        None => format!("{library}::{function} (the URL is computed at run time)"),
                    };
                    if model.downloads.len() < MAX_ITEMS {
                        model.downloads.push((what, source));
                    }
                } else if lower == "nsexec.dll" || lower == "execdos.dll" || lower == "execcmd.dll" {
                    if let Some(command) = arguments.iter().find(|a| !a.is_empty() && !a.starts_with('/'))
                        && model.commands.len() < MAX_ITEMS
                    {
                        model.commands.push(Command {
                            command: command.clone(),
                            source: format!("{source} ({library}::{function}, argument paired by position)"),
                        });
                    }
                } else if lower == "simplesc.dll" && function.eq_ignore_ascii_case("InstallService") && model.services.len() < MAX_ITEMS {
                    // SimpleSC::InstallService name display type start binary ...
                    model.services.push(crate::installer::Service {
                        name: arguments.first().cloned().unwrap_or_default(),
                        display_name: arguments.get(1).cloned(),
                        start: arguments.get(3).map(|s| match s.as_str() {
                            "0" => "boot".to_string(),
                            "1" => "system".to_string(),
                            "2" => "auto".to_string(),
                            "3" => "demand".to_string(),
                            "4" => "disabled".to_string(),
                            other => other.to_string(),
                        }),
                        driver: matches!(arguments.get(2).map(String::as_str), Some("1") | Some("2")),
                        account: None,
                        command: arguments.get(4).cloned(),
                        source: format!("{source} (SimpleSC::InstallService, arguments paired by position)"),
                    });
                }
            }
            // Anything that is not a push ends an argument list.
            Some("EW_PUSHPOP") => {}
            _ => pushed.clear(),
        }
    }

    // Files: what the unpacker produced, when it ran; otherwise the script's own list.
    let children: Vec<&Artifact> = tree.under(&file.path).into_iter().filter(|a| a.parent.as_deref() == Some(file.path.as_str())).collect();
    let installed: Vec<&&Artifact> =
        children.iter().filter(|a| a.name() != SCRIPT_NAME && !a.path[file.path.len()..].starts_with("/$PLUGINSDIR/")).collect();
    if installer.is_uninstaller() {
        // An uninstaller removes files; it installs none.
    } else if file.unpacked_by.as_deref() == Some("nsis") {
        model.files = Some(installed.len() as u64);
        model.files_bytes = Some(installed.iter().map(|a| a.size).sum());
    } else {
        let mut seen = BTreeSet::new();
        let count = installer.files().flatten().filter_map(|f| f.dest_path().ok()).filter(|p| seen.insert(p.to_string())).count();
        model.files = Some(count as u64);
    }
    model.extra.insert(
        "sections".into(),
        json!(
            installer
                .sections()
                .flatten()
                .filter_map(|s| {
                    let name = s.inline_name().or_else(|| installer.read_string(s.name_ptr()).ok().map(|n| n.to_string()))?;
                    (!name.is_empty()).then_some(name)
                })
                .take(200)
                .collect::<Vec<_>>()
        ),
    );
    model.extra.insert("plugin_calls".into(), json!(plugins.into_iter().take(500).collect::<Vec<_>>()));
    model.extra.insert(
        "uninstallers".into(),
        json!(installer.uninstallers().flatten().filter_map(|u| u.path().ok().map(|p| p.to_string())).take(20).collect::<Vec<_>>()),
    );
    model.extra.insert("script_entries".into(), json!(installer.entry_count()));
    Some(model)
}
