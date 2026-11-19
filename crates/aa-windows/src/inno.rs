//! Inno Setup installers: extraction of the packed files and the meaning of the setup header
//! and its `[Files]`, `[Registry]`, `[Icons]` and `[Run]` records.
//!
//! The format is read by the `innospect` crate (0.2, Apache-2.0).
//!
//! Checked by hand against `innoextract` 1.9, comparing the SHA-256 of every extracted file:
//! Inno Setup 6.2.2's own installer (92 files) and Git LFS 3.5.1 (Inno Setup 6.1, 3 files) are
//! identical. Inno Setup 6.4.0's installer extracts (95 files) but could not be compared:
//! innoextract 1.9 does not read 6.4. There is no committed fixture, because the Inno Setup
//! compiler runs only on Windows and real installers exceed the fixture size limit.

use std::collections::BTreeSet;

use aa_core::Artifact;
use aa_core::plugin::{Output, Rule, SinkError, Tree, Unpack, UnpackSink, Unpacker};
use innospect::InnoInstaller;
use serde_json::json;

use crate::installer::{Command, Installer, MAX_ITEMS, RegistryWrite, Shortcut};
use crate::pe::Pe;

/// The text every Inno Setup header block starts with.
const MARKER: &[u8] = b"Inno Setup Setup Data (";

pub struct Inno;

pub const RULES: &[Rule] = &[
    Rule {
        id: "inno.files-unreadable",
        title_zh: "Inno Setup 安装包内部分文件无法提取",
        title_en: "Some files in the Inno Setup installer could not be extracted",
        text_zh: "安装包里有文件无法解压（数据损坏或使用了不支持的变体），这些文件没有分析。",
        text_en: "Some files in the installer could not be decompressed (damaged data or an unsupported variant). They were not analyzed.",
    },
    Rule {
        id: "inno.encrypted",
        title_zh: "Inno Setup 安装包已加密",
        title_en: "The Inno Setup installer is encrypted",
        text_zh: "安装包的文件用密码加密，没有密码无法解开，这些文件没有分析。",
        text_en: "The installer's files are encrypted with a password. Without it they cannot be opened and were not analyzed.",
    },
];

/// True when `bytes` is a PE file carrying an Inno Setup header block after its image.
pub fn is_inno(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"MZ") {
        return false;
    }
    let Ok(pe) = Pe::parse(bytes) else { return false };
    bytes.get(pe.end_of_image()..).is_some_and(|overlay| memchr::memmem::find(overlay, MARKER).is_some())
}

/// Parses the installer. The reader is third-party code fed hostile input: a panic counts as
/// an error.
fn open(bytes: &[u8]) -> Result<InnoInstaller<'_>, String> {
    match std::panic::catch_unwind(|| InnoInstaller::from_bytes(bytes)) {
        Ok(Ok(installer)) => Ok(installer),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("the Inno Setup reader failed on this file".into()),
    }
}

/// An install path as a relative one: `{app}\bin\x.exe` becomes `bin/x.exe`; other constants
/// stay (`{sys}/driver.sys`).
fn child_path(destination: &str) -> String {
    let path = destination.replace('\\', "/");
    path.strip_prefix("{app}/").unwrap_or(&path).to_string()
}

impl Unpacker for Inno {
    fn id(&self) -> &'static str {
        "inno"
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        if !is_inno(bytes) {
            return Unpack::NotMine;
        }
        let installer = match open(bytes) {
            Ok(installer) => installer,
            Err(detail) => return Unpack::Failed { kind: "inno", detail },
        };
        if installer.is_encrypted() && installer.password_used().is_none() {
            sink.limitation("inno.encrypted", None);
            return Unpack::Done { kind: "inno" };
        }
        let mut failures = Vec::new();
        let mut seen = BTreeSet::new();
        for file in installer.files() {
            // Entries without stored data: the uninstaller stub and files fetched at install time.
            if file.location_index == u32::MAX {
                continue;
            }
            let path = child_path(&file.destination);
            // The same content installed to the same place under several conditions is one file.
            if path.is_empty() || !seen.insert((path.clone(), file.location_index)) {
                continue;
            }
            let content = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| installer.extract_to_vec(file)));
            match content {
                Ok(Ok(content)) => {
                    if sink.add(&path, &mut content.as_slice()) == Err(SinkError::LimitReached) {
                        return Unpack::Done { kind: "inno" };
                    }
                }
                Ok(Err(error)) => failures.push(format!("{path}: {error}")),
                Err(_) => failures.push(format!("{path}: the reader failed")),
            }
        }
        if !failures.is_empty() {
            let shown = failures.iter().take(5).cloned().collect::<Vec<_>>().join("; ");
            sink.limitation("inno.files-unreadable", Some(format!("{} problems: {shown}", failures.len())));
        }
        Unpack::Done { kind: "inno" }
    }
}

/// A registry value as text. Unicode installers store strings as UTF-16.
fn value_text(raw: &[u8]) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    let wide = raw.len().is_multiple_of(2) && raw.chunks_exact(2).filter(|c| c[1] == 0).count() * 2 >= raw.len() / 2;
    let text = if wide {
        let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(raw).into_owned()
    };
    Some(text.trim_end_matches('\0').to_string())
}

/// Reads what the installer does. `None` when `bytes` is not an Inno Setup installer.
pub fn analyze(tree: &dyn Tree, file: &Artifact, bytes: &[u8], out: &mut Output) -> Option<Installer> {
    if !is_inno(bytes) {
        return None;
    }
    let installer = match open(bytes) {
        Ok(installer) => installer,
        Err(error) => {
            out.limitation("windows.installer-unreadable", Some(file), Some(format!("Inno Setup: {error}")));
            return None;
        }
    };
    let mut model = Installer { kind: "Inno Setup", ..Installer::default() };
    let version = installer.version();
    model.format = Some(format!(
        "Inno Setup {}.{}.{}, {:?} compression{}",
        version.a,
        version.b,
        version.c,
        installer.compression(),
        if installer.is_encrypted() { ", encrypted" } else { "" }
    ));
    let text = |value: Option<&str>| value.map(str::to_string).filter(|v| !v.is_empty());
    if let Some(header) = installer.header() {
        model.product = text(header.app_name());
        model.version = text(header.app_version());
        model.publisher = text(header.app_publisher());
        model.install_dir = text(header.default_dir_name());
        let privileges = header.tail().privileges_required;
        model.admin = Some((
            matches!(privileges, Some(innospect::PrivilegesRequired::Admin) | Some(innospect::PrivilegesRequired::PowerUser)),
            "setup header: PrivilegesRequired".to_string(),
        ));
        model.extra.insert("app_id".into(), json!(text(header.app_id())));
        model.extra.insert("privileges_required".into(), json!(privileges.map(|p| format!("{p:?}"))));
    }

    let stored: Vec<_> = installer.files().iter().filter(|f| f.location_index != u32::MAX).collect();
    model.files = Some(stored.len() as u64);
    // Sizes come from the unpacked children when the unpacker ran.
    if file.unpacked_by.as_deref() == Some("inno") {
        let children: Vec<&Artifact> =
            tree.under(&file.path).into_iter().filter(|a| a.parent.as_deref() == Some(file.path.as_str())).collect();
        model.files = Some(children.len() as u64);
        model.files_bytes = Some(children.iter().map(|a| a.size).sum());
    }
    // Files the installer fetches or copies from outside itself at install time.
    for (index, entry) in installer.files().iter().enumerate() {
        if entry.location_index == u32::MAX && entry.source.contains("://") && model.downloads.len() < MAX_ITEMS {
            model.downloads.push((format!("{} -> {}", entry.source, entry.destination), format!("[Files] entry {index}")));
        }
    }
    for (index, entry) in installer.registry_entries().iter().enumerate() {
        if model.registry.len() >= MAX_ITEMS {
            model.truncated = true;
            break;
        }
        // Entries without a value type only create or delete keys.
        if entry.value_type.is_none() && entry.value_name.is_empty() {
            continue;
        }
        let root = match entry.hive {
            innospect::RegistryHive::ClassesRoot => "HKCR".to_string(),
            innospect::RegistryHive::CurrentUser => "HKCU".to_string(),
            innospect::RegistryHive::LocalMachine => "HKLM".to_string(),
            innospect::RegistryHive::Users => "HKU".to_string(),
            other => format!("{other:?}"),
        };
        model.registry.push(RegistryWrite {
            root,
            key: entry.subkey.clone(),
            name: entry.value_name.clone(),
            value: value_text(&entry.value),
            source: format!("[Registry] entry {index}"),
        });
    }
    for (index, entry) in installer.run_entries().iter().enumerate() {
        if model.commands.len() >= MAX_ITEMS {
            model.truncated = true;
            break;
        }
        model.commands.push(Command {
            command: format!("{} {}", entry.name, entry.parameters).trim().to_string(),
            source: format!("[Run] entry {index}"),
        });
    }
    for (index, entry) in installer.icons().iter().enumerate() {
        if model.shortcuts.len() >= MAX_ITEMS {
            model.truncated = true;
            break;
        }
        model.shortcuts.push(Shortcut {
            path: entry.name.clone(),
            target: entry.filename.clone(),
            arguments: entry.parameters.clone(),
            source: format!("[Icons] entry {index}"),
        });
    }
    model.extra.insert(
        "uninstall_run".into(),
        json!(
            installer
                .uninstall_runs()
                .iter()
                .take(200)
                .map(|r| format!("{} {}", r.name, r.parameters).trim().to_string())
                .collect::<Vec<_>>()
        ),
    );
    model.extra.insert("tasks".into(), json!(installer.tasks().iter().take(200).map(|t| t.name.clone()).collect::<Vec<_>>()));
    model.extra.insert("components".into(), json!(installer.components().iter().take(200).map(|c| c.name.clone()).collect::<Vec<_>>()));
    model.extra.insert("has_pascal_script".into(), json!(installer.compiled_code_bytes().is_some_and(|code| !code.is_empty())));
    model.extra.insert("encrypted".into(), json!(installer.is_encrypted()));
    Some(model)
}
