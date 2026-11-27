//! The tree pass: what only shows when files are looked at together — who signed what, which
//! vendors' components are present, what the imports add up to, and which application
//! frameworks the folder layout reveals.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use aa_core::plugin::{Output, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use regex::bytes::Regex;
use serde_json::{Value, json};

use crate::ID;
use crate::behaviour::CATEGORIES;

/// Files listed as evidence of one finding.
const MAX_EVIDENCE: usize = 12;
/// Largest script file searched for Electron settings.
const MAX_SCRIPT: u64 = 8 * 1024 * 1024;
/// Script files searched per Electron app.
const MAX_SCRIPTS: usize = 3000;
/// Largest JSON file parsed.
const MAX_JSON: u64 = 32 * 1024 * 1024;

pub fn analyze(tree: &dyn Tree, out: &mut Output) {
    crate::msi_actions::relate(tree, out);
    crate::nuspec::analyze_tree(tree, out);
    crate::vsix::analyze_tree(tree, out);
    crate::winget::analyze_tree(tree, out);
    crate::references::analyze(tree, out);
    crate::source_mapping::analyze(tree, out);
    crate::catalog_membership::analyze(tree, out);
    crate::msix_blockmap::analyze_tree(tree, out);
    crate::msix_zip::analyze(tree, out);
    crate::msix_zip::bundle::analyze(tree, out);
    // Folder -> the files directly inside it. Containers count as folders.
    let mut folders: BTreeMap<&str, Vec<&Artifact>> = BTreeMap::new();
    for artifact in tree.artifacts() {
        folders.entry(folder_of(&artifact.path)).or_default().push(artifact);
    }
    signers(tree, out);
    versions(tree, out);
    assemblies(tree, out);
    capabilities(tree, out);
    header_oddities(tree, out);
    electron(tree, &folders, out);
    runtimes(tree, &folders, out);
}

fn folder_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(folder, _)| folder)
}

fn text<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter().try_fold(value, |v, key| v.get(key))?.as_str()
}

fn finding(section: Section, rule: &str, confidence: Confidence, severity: Severity) -> Finding {
    Finding::new(section, ID, rule, confidence, severity)
}

/// One finding per distinct signer, and one for the unsigned files.
fn signers(tree: &dyn Tree, out: &mut Output) {
    #[derive(Default)]
    struct Group<'a> {
        files: Vec<&'a Artifact>,
        verified: usize,
        algorithms: BTreeSet<String>,
        timestamped: usize,
        authorities: BTreeSet<String>,
    }
    // (signer name, issuer) -> files
    let mut groups: BTreeMap<(String, String), Group> = BTreeMap::new();
    let mut unsigned: Vec<&Artifact> = Vec::new();
    let mut total = 0usize;
    for artifact in tree.artifacts() {
        let Some(fact) = artifact.facts.get("windows.authenticode") else { continue };
        total += 1;
        let signatures = fact.get("signatures").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
        let Some(primary) = signatures.first() else {
            unsigned.push(artifact);
            continue;
        };
        let subject = text(primary, &["signer", "common_name"]).or(text(primary, &["signer", "subject"])).unwrap_or("?").to_string();
        let issuer = text(primary, &["signer", "issuer"]).unwrap_or("?").to_string();
        let group = groups.entry((subject, issuer)).or_default();
        group.files.push(artifact);
        let passed = |signature: &Value| {
            ["file_digest", "content_digest", "signature", "chain"]
                .iter()
                .all(|check| text(signature, &["checks", check]) == Some("passed"))
        };
        if signatures.iter().all(passed) {
            group.verified += 1;
        }
        let mut stamped = false;
        for signature in signatures {
            if let Some(algorithm) = text(signature, &["digest_algorithm"]) {
                group.algorithms.insert(algorithm.to_string());
            }
            for stamp in signature.get("timestamps").and_then(Value::as_array).into_iter().flatten() {
                stamped = true;
                if let Some(authority) = text(stamp, &["authority", "common_name"]) {
                    group.authorities.insert(authority.to_string());
                }
            }
        }
        group.timestamped += usize::from(stamped);
    }
    if total == 0 {
        return;
    }
    out.summary(
        "windows.signers",
        json!({
            "pe_files": total,
            "unsigned": unsigned.len(),
            "unsigned_files": unsigned.iter().take(500).map(|a| a.path.as_str()).collect::<Vec<_>>(),
            "unsigned_truncated": unsigned.len() > 500,
            "signers": groups.iter().map(|((subject, issuer), group)| json!({
                "signer": subject,
                "issuer": issuer,
                "files": group.files.len(),
                "fully_verified": group.verified,
                "digest_algorithms": group.algorithms,
                "timestamped": group.timestamped,
                "timestamp_authorities": group.authorities,
                "sample_files": group.files.iter().take(20).map(|a| a.path.as_str()).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        }),
    );
    for ((subject, issuer), group) in &groups {
        let authorities =
            if group.authorities.is_empty() { "—".to_string() } else { group.authorities.iter().cloned().collect::<Vec<_>>().join(", ") };
        let all_passed = group.verified == group.files.len();
        let mut f = finding(
            Section::Provenance,
            "windows.signers",
            Confidence::Verified,
            if all_passed { Severity::Info } else { Severity::Medium },
        )
        .param("signer", subject.as_str())
        .param("issuer", issuer.as_str())
        .param("signed", group.files.len())
        .param("verified", group.verified)
        .param("algorithms", group.algorithms.iter().cloned().collect::<Vec<_>>().join(" + "))
        .param("timestamped", group.timestamped)
        .param("authorities", authorities);
        for file in group.files.iter().take(MAX_EVIDENCE) {
            let fact = file.facts.get("windows.authenticode");
            let primary = fact.and_then(|f| f.get("signatures")).and_then(|s| s.get(0));
            let offset = fact.and_then(|f| f.get("table_offset")).and_then(Value::as_u64).unwrap_or(0);
            let size = fact.and_then(|f| f.get("table_size")).and_then(Value::as_u64).unwrap_or(0);
            f = f.evidence(Evidence::bytes(
                file,
                offset,
                size,
                json!({
                    "signer": primary.and_then(|p| p.get("signer")).and_then(|s| s.get("subject")),
                    "serial": primary.and_then(|p| p.get("signer")).and_then(|s| s.get("serial")),
                    "signed_digest": primary.and_then(|p| p.get("signed_digest")),
                    "checks": primary.and_then(|p| p.get("checks")),
                }),
            ));
        }
        out.finding(f);
    }
    if !unsigned.is_empty() {
        let mut f = finding(Section::Provenance, "windows.unsigned-files", Confidence::Verified, Severity::Info)
            .param("unsigned", unsigned.len())
            .param("total", total);
        for file in unsigned.iter().take(MAX_EVIDENCE) {
            f = f.evidence(Evidence::field(file, "certificate table", Value::Null));
        }
        out.finding(f);
    }
}

/// The file name without directories and without the " (2)" the engine adds to duplicates.
fn comparable_name(name: &str) -> String {
    let name = name.rsplit(['/', '\\']).next().unwrap_or(name).trim();
    let name = match name.rsplit_once(" (") {
        Some((stem, copy)) if copy.strip_suffix(')').is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit())) => stem,
        _ => name,
    };
    name.to_ascii_lowercase()
}

/// Version resources: the identity of the input itself, who made the components, and files
/// whose name differs from the one their version resource records.
fn versions(tree: &dyn Tree, out: &mut Output) {
    let with_version: Vec<(&Artifact, &Value)> =
        tree.artifacts().iter().filter_map(|a| Some((a, a.facts.get("windows.version")?))).collect();
    if with_version.is_empty() {
        return;
    }
    let location = |file: &Artifact, fact: &Value, value: Value| {
        Evidence::bytes(
            file,
            fact.get("offset").and_then(Value::as_u64).unwrap_or(0),
            fact.get("size").and_then(Value::as_u64).unwrap_or(0),
            value,
        )
    };
    let describe = |fact: &Value| {
        let mut fields = Vec::new();
        for key in [
            "ProductName",
            "ProductVersion",
            "FileDescription",
            "FileVersion",
            "CompanyName",
            "OriginalFilename",
            "InternalName",
            "LegalCopyright",
        ] {
            let fixed = match key {
                "FileVersion" => text(fact, &["file_version"]),
                "ProductVersion" => text(fact, &["product_version"]),
                _ => None,
            };
            if let Some(value) = text(fact, &["strings", key]).filter(|v| !v.is_empty()).or(fixed) {
                fields.push(format!("{key}={value}"));
            }
        }
        fields.join("; ")
    };
    // The input's own files get a finding each while they are few; a folder of hundreds of
    // libraries is summarised by vendor instead.
    let top_level: Vec<&(&Artifact, &Value)> = with_version.iter().filter(|(a, _)| a.parent.is_none()).collect();
    if top_level.len() <= 3 {
        for (file, fact) in top_level {
            let fields = describe(fact);
            if !fields.is_empty() {
                out.finding(
                    finding(Section::Identity, "windows.version-info", Confidence::Verified, Severity::Info)
                        .param("fields", fields)
                        .evidence(location(file, fact, fact.get("strings").cloned().unwrap_or(Value::Null))),
                );
            }
        }
    }
    let mut vendors: BTreeMap<&str, Vec<&Artifact>> = BTreeMap::new();
    for (file, fact) in &with_version {
        if let Some(company) = text(fact, &["strings", "CompanyName"]).map(str::trim).filter(|c| !c.is_empty()) {
            vendors.entry(company).or_default().push(file);
        }
    }
    if with_version.len() > 1 && !vendors.is_empty() {
        let mut ranked: Vec<(&str, &Vec<&Artifact>)> = vendors.iter().map(|(k, v)| (*k, v)).collect();
        ranked.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then(a.0.cmp(b.0)));
        out.summary(
            "windows.vendors",
            json!(ranked.iter().take(200).map(|(vendor, files)| json!({ "company": vendor, "files": files.len() })).collect::<Vec<_>>()),
        );
        let mut f = finding(Section::Composition, "windows.vendors", Confidence::Verified, Severity::Info)
            .param("files", with_version.len())
            .param(
                "vendors",
                ranked.iter().take(10).map(|(vendor, files)| format!("{vendor} ({})", files.len())).collect::<Vec<_>>().join(", "),
            )
            .param("count", ranked.len());
        for (vendor, files) in ranked.iter().take(MAX_EVIDENCE) {
            if let Some(file) = files.first() {
                f = f.evidence(Evidence::field(file, "VS_VERSIONINFO/CompanyName", *vendor));
            }
        }
        out.finding(f);
    }
    let mut renamed = Vec::new();
    for (file, fact) in &with_version {
        let Some(original) = text(fact, &["strings", "OriginalFilename"]).filter(|o| !o.trim().is_empty()) else { continue };
        let (claimed, actual) = (comparable_name(original), comparable_name(file.name()));
        // Translated resource libraries are named <original>.mui.
        if claimed != actual && actual != format!("{claimed}.mui") && claimed != format!("{actual}.mui") {
            renamed.push((*file, *fact, original));
        }
    }
    if !renamed.is_empty() {
        let mut f = finding(Section::Anomalies, "windows.original-filename-mismatch", Confidence::Heuristic, Severity::Info)
            .param("count", renamed.len());
        for (file, fact, original) in renamed.iter().take(MAX_EVIDENCE) {
            f = f.evidence(location(file, fact, json!({ "original_filename": original, "actual": file.name() })));
        }
        out.finding(f);
    }
}

/// .NET assemblies: one finding each while the input's own files are few, one summary otherwise.
fn assemblies(tree: &dyn Tree, out: &mut Output) {
    let all: Vec<(&Artifact, &Value)> = tree.artifacts().iter().filter_map(|a| Some((a, a.facts.get("windows.dotnet")?))).collect();
    if all.is_empty() {
        return;
    }
    let framework = |fact: &Value| text(fact, &["target_framework"]).or(text(fact, &["runtime_version"])).unwrap_or("?").to_string();
    let location = |file: &Artifact, fact: &Value, value: Value| {
        Evidence::bytes(file, fact.get("clr_header_offset").and_then(Value::as_u64).unwrap_or(0), 72, value)
    };
    let top_level: Vec<&(&Artifact, &Value)> = all.iter().filter(|(a, _)| a.parent.is_none()).collect();
    if top_level.len() <= 3 {
        for (file, fact) in top_level {
            let name = text(fact, &["assembly", "name"]).or(text(fact, &["module"])).unwrap_or(file.name());
            out.finding(
                finding(Section::Composition, "windows.dotnet-assembly", Confidence::Verified, Severity::Info)
                    .param("name", name)
                    .param("version", text(fact, &["assembly", "version"]).unwrap_or("?"))
                    .param("framework", framework(fact))
                    .param("mode", text(fact, &["mode"]).unwrap_or("?"))
                    .param("types", fact.get("types").cloned().unwrap_or(Value::Null))
                    .param("methods", fact.get("methods").cloned().unwrap_or(Value::Null))
                    .param("references", fact.get("references").and_then(Value::as_array).map_or(0, Vec::len))
                    .evidence(location(file, fact, json!({ "assembly": fact.get("assembly") }))),
            );
        }
    }
    if all.len() > 1 {
        let mut frameworks: BTreeMap<String, usize> = BTreeMap::new();
        for (_, fact) in &all {
            *frameworks.entry(framework(fact)).or_default() += 1;
        }
        let mixed = all.iter().filter(|(_, f)| f.get("flags").and_then(|f| f.get("il_only")) == Some(&Value::Bool(false))).count();
        let mut ranked: Vec<(&String, &usize)> = frameworks.iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        out.summary(
            "windows.dotnet-assemblies",
            json!({ "assemblies": all.len(), "mixed_mode": mixed, "frameworks": ranked.iter().map(|(f, n)| json!({ "framework": f, "assemblies": n })).collect::<Vec<_>>() }),
        );
        let mut f = finding(Section::Composition, "windows.dotnet-assemblies", Confidence::Verified, Severity::Info)
            .param("count", all.len())
            .param("frameworks", ranked.iter().take(8).map(|(f, n)| format!("{f} ({n})")).collect::<Vec<_>>().join(", "))
            .param("mixed", mixed);
        for (file, fact) in all.iter().take(MAX_EVIDENCE) {
            f = f.evidence(location(
                file,
                fact,
                json!({ "assembly": text(fact, &["assembly", "name"]), "version": text(fact, &["assembly", "version"]) }),
            ));
        }
        out.finding(f);
    }
}

/// One finding per notable capability category, listing the files and the imports behind it.
fn capabilities(tree: &dyn Tree, out: &mut Output) {
    let mut summary = serde_json::Map::new();
    for category in CATEGORIES {
        let files: Vec<(&Artifact, &Value)> =
            tree.artifacts().iter().filter_map(|a| Some((a, a.facts.get("windows.capabilities")?.get(category.id)?))).collect();
        if files.is_empty() {
            continue;
        }
        summary.insert(
            category.id.to_string(),
            json!({ "files": files.len(), "sample_files": files.iter().take(20).map(|(a, _)| a.path.as_str()).collect::<Vec<_>>() }),
        );
        let Some(rule) = category.rule else { continue };
        let severity = if category.id == "injection" { Severity::Low } else { Severity::Info };
        let mut f = finding(Section::Capabilities, rule, Confidence::Derived, severity).param("files", files.len());
        for (file, apis) in files.iter().take(MAX_EVIDENCE) {
            f = f.evidence(Evidence::field(file, "import table", (*apis).clone()));
        }
        out.finding(f);
    }
    if !summary.is_empty() {
        out.summary("windows.capabilities", Value::Object(summary));
    }
}

/// Header oddities that are common enough to be reported once for all files: TLS callbacks,
/// blank link timestamps, and checksums that do not match the file.
fn header_oddities(tree: &dyn Tree, out: &mut Output) {
    let mut tls = Vec::new();
    let mut blank = Vec::new();
    let mut checksum = Vec::new();
    for artifact in tree.artifacts() {
        let Some(fact) = artifact.facts.get("windows.pe") else { continue };
        let number = |path: &[&str]| path.iter().try_fold(fact, |v, key| v.get(key)).and_then(Value::as_u64);
        let header = number(&["pe_header_offset"]).unwrap_or(0);
        if let Some(count) = number(&["tls_callbacks"]).filter(|&n| n > 0) {
            tls.push(Evidence::bytes(artifact, number(&["tls_directory_offset"]).unwrap_or(0), 24, json!({ "callbacks": count })));
        }
        // Only the two values no linker writes by accident; reproducible builds store a hash
        // in this field, so "implausible dates" are normal.
        if let Some(timestamp) = number(&["timestamp"]).filter(|&t| t == 0 || t == u64::from(u32::MAX)) {
            blank.push(Evidence::bytes(artifact, header + 8, 4, format!("{timestamp:#010x}")));
        }
        if let (Some(stored), Some(computed)) = (number(&["checksum", "stored"]), number(&["checksum", "computed"]))
            && stored != 0
            && stored != computed
        {
            checksum.push(Evidence::bytes(
                artifact,
                header + 24 + 64,
                4,
                json!({ "stored": format!("{stored:#010x}"), "computed": format!("{computed:#010x}") }),
            ));
        }
    }
    for (rule, evidence) in [("windows.tls-callbacks", tls), ("windows.timestamp-blank", blank), ("windows.checksum-mismatch", checksum)] {
        if evidence.is_empty() {
            continue;
        }
        let mut f = finding(Section::Anomalies, rule, Confidence::Verified, Severity::Info).param("files", evidence.len());
        for item in evidence.into_iter().take(MAX_EVIDENCE) {
            f = f.evidence(item);
        }
        out.finding(f);
    }
}

fn read_json(tree: &dyn Tree, file: &Artifact) -> Option<Value> {
    if file.size > MAX_JSON {
        return None;
    }
    let bytes = tree.read(&file.path).ok()?;
    serde_json::from_slice(bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&bytes)).ok()
}

static ELECTRON_VERSION: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"Chrome/([0-9]{2,3}\.[0-9.]{3,20}) Electron/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[-.A-Za-z0-9]{0,20})").ok()
});

/// Settings that switch off a protection of Electron's renderer: `(name, value, pattern, severity)`.
static ELECTRON_SETTINGS: LazyLock<Vec<(&'static str, &'static str, Regex, Severity)>> = LazyLock::new(|| {
    [
        ("nodeIntegration", "true", r"\bnodeIntegration\s*:\s*(?:true|!0)\b", Severity::Low),
        ("contextIsolation", "false", r"\bcontextIsolation\s*:\s*(?:false|!1)\b", Severity::Low),
        ("webSecurity", "false", r"\bwebSecurity\s*:\s*(?:false|!1)\b", Severity::Medium),
        ("sandbox", "false", r"\bsandbox\s*:\s*(?:false|!1)\b", Severity::Info),
        ("allowRunningInsecureContent", "true", r"\ballowRunningInsecureContent\s*:\s*(?:true|!0)\b", Severity::Medium),
    ]
    .into_iter()
    .filter_map(|(name, value, pattern, severity)| Some((name, value, Regex::new(pattern).ok()?, severity)))
    .collect()
});

/// The marker Electron puts in front of its fuse bytes.
const FUSE_SENTINEL: &[u8] = b"dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX";
const FUSE_NAMES: &[&str] = &[
    "RunAsNode",
    "EnableCookieEncryption",
    "EnableNodeOptionsEnvironmentVariable",
    "EnableNodeCliInspectArguments",
    "EnableEmbeddedAsarIntegrityValidation",
    "OnlyLoadAppFromAsar",
    "LoadBrowserProcessSpecificV8Snapshot",
    "GrantFileProtocolExtraPrivileges",
];

/// Electron applications: `resources/app.asar` or `resources/app/package.json` next to the
/// files every Electron distribution ships.
fn electron(tree: &dyn Tree, folders: &BTreeMap<&str, Vec<&Artifact>>, out: &mut Output) {
    let mut apps = Vec::new();
    for artifact in tree.artifacts() {
        // `code` is where the application's own files live: inside the asar, or the loose folder.
        let (root, code, packed) = if let Some(root) = artifact.path.strip_suffix("resources/app.asar") {
            (root, artifact.path.clone(), true)
        } else if let Some(root) = artifact.path.strip_suffix("resources/app/package.json") {
            (root, format!("{root}resources/app"), false)
        } else {
            continue;
        };
        if !(root.is_empty() || root.ends_with('/')) {
            continue;
        }
        let root = root.trim_end_matches('/');
        let siblings = folders.get(root).map(Vec::as_slice).unwrap_or_default();
        let marker = siblings.iter().find(|a| {
            let name = a.name().to_ascii_lowercase();
            name.ends_with(".pak")
                || matches!(name.as_str(), "ffmpeg.dll" | "icudtl.dat" | "v8_context_snapshot.bin" | "licenses.chromium.html")
        });
        let Some(marker) = marker else { continue };

        let package = tree.get(&format!("{code}/package.json"));
        let manifest = package.and_then(|p| read_json(tree, p));
        let field = |name: &str| manifest.as_ref().and_then(|m| m.get(name)).and_then(Value::as_str).map(str::to_string);
        let dependencies: Vec<String> = manifest
            .as_ref()
            .and_then(|m| m.get("dependencies"))
            .and_then(Value::as_object)
            .map(|d| d.iter().take(500).map(|(name, version)| format!("{name}@{}", version.as_str().unwrap_or("?"))).collect())
            .unwrap_or_default();

        // The Electron version: the distribution's `version` file, else the user-agent string
        // compiled into the main executable.
        let mut electron_version: Option<(String, Confidence, Evidence)> = None;
        if let Some(file) = siblings.iter().find(|a| a.name() == "version" && a.size < 64)
            && let Ok(bytes) = tree.read(&file.path)
        {
            let value = String::from_utf8_lossy(&bytes).trim().trim_start_matches('v').to_string();
            if value.split('.').count() >= 3 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
                electron_version = Some((value.clone(), Confidence::Verified, Evidence::whole(file, value)));
            }
        }
        let executable = siblings
            .iter()
            .filter(|a| a.extension().as_deref() == Some("exe") && a.facts.contains_key("windows.pe"))
            .max_by_key(|a| a.size);
        let mut chrome_version = None;
        let mut fuses: Option<(Vec<(String, String)>, usize)> = None;
        if let Some(executable) = executable
            && let Ok(bytes) = tree.read(&executable.path)
        {
            if let Some(regex) = ELECTRON_VERSION.as_ref()
                && let Some(captures) = regex.captures(&bytes)
                && let (Some(chrome), Some(electron)) = (captures.get(1), captures.get(2))
            {
                chrome_version = Some(String::from_utf8_lossy(chrome.as_bytes()).into_owned());
                if electron_version.is_none() {
                    let value = String::from_utf8_lossy(electron.as_bytes()).into_owned();
                    let evidence = Evidence::bytes(executable, electron.start() as u64, electron.len() as u64, value.clone());
                    electron_version = Some((value, Confidence::Heuristic, evidence));
                }
            }
            // Fuse wire: sentinel, version byte, count byte, then one state byte per fuse.
            if let Some(at) = memchr::memmem::find(&bytes, FUSE_SENTINEL) {
                let wire = at + FUSE_SENTINEL.len();
                if let (Some(&1), Some(&count)) = (bytes.get(wire), bytes.get(wire + 1))
                    && let Some(states) = bytes.get(wire + 2..wire + 2 + count as usize)
                {
                    let list = states
                        .iter()
                        .enumerate()
                        .map(|(index, state)| {
                            let name = FUSE_NAMES.get(index).map(|n| n.to_string()).unwrap_or_else(|| format!("fuse {index}"));
                            let state = match state {
                                b'0' => "disabled",
                                b'1' => "enabled",
                                b'r' => "removed",
                                _ => "unknown",
                            };
                            (name, state.to_string())
                        })
                        .collect();
                    fuses = Some((list, at));
                }
            }
        }

        let asar = if packed { artifact.facts.get("windows.asar") } else { None };
        let name = field("productName")
            .or(field("name"))
            .unwrap_or_else(|| root.rsplit('/').next().filter(|n| !n.is_empty()).unwrap_or("?").to_string());
        apps.push(json!({
            "folder": root,
            "name": name,
            "version": field("version"),
            "main": field("main"),
            "packed_in_asar": packed,
            "electron_version": electron_version.as_ref().map(|(v, _, _)| v),
            "electron_version_source": electron_version.as_ref().map(|(_, c, _)| if *c == Confidence::Verified { "version file" } else { "string in the executable" }),
            "chrome_version": chrome_version,
            "dependencies": dependencies,
            "fuses": fuses.as_ref().map(|(list, _)| list.iter().map(|(n, s)| json!({ "fuse": n, "state": s })).collect::<Vec<_>>()),
            "asar": asar,
        }));

        let confidence = electron_version.as_ref().map_or(Confidence::Derived, |(_, c, _)| *c);
        let mut f = finding(Section::Composition, "windows.electron-app", confidence, Severity::Info)
            .param("name", name)
            .param("version", field("version").unwrap_or_else(|| "?".into()))
            .param("electron", electron_version.as_ref().map_or("?".to_string(), |(v, _, _)| v.clone()))
            .param("chrome", chrome_version.clone().unwrap_or_else(|| "?".into()))
            .param("main", field("main").unwrap_or_else(|| "?".into()))
            .param("dependencies", dependencies.len())
            .evidence(Evidence::whole(marker, marker.name()));
        if let Some(package) = package {
            f = f.evidence(Evidence::field(
                package,
                "name, version, main",
                json!({ "name": field("name"), "version": field("version"), "main": field("main") }),
            ));
        }
        if let Some((_, _, evidence)) = &electron_version {
            f = f.evidence(evidence.clone());
        }
        out.finding(f);

        if let (Some((list, at)), Some(executable)) = (&fuses, executable) {
            let enabled: Vec<&str> = list.iter().filter(|(_, s)| s == "enabled").map(|(n, _)| n.as_str()).collect();
            let disabled: Vec<&str> = list.iter().filter(|(_, s)| s == "disabled").map(|(n, _)| n.as_str()).collect();
            let join = |items: &[&str]| if items.is_empty() { "—".to_string() } else { items.join(", ") };
            out.finding(
                finding(Section::Hardening, "windows.electron-fuses", Confidence::Verified, Severity::Info)
                    .param("enabled", join(&enabled))
                    .param("disabled", join(&disabled))
                    .evidence(Evidence::bytes(
                        executable,
                        *at as u64,
                        (FUSE_SENTINEL.len() + 2 + list.len()) as u64,
                        json!(list.iter().map(|(n, s)| format!("{n}={s}")).collect::<Vec<_>>()),
                    )),
            );
        }
        if let Some(asar) = asar
            && let Some(failed) = asar.get("integrity_failed").and_then(Value::as_array).filter(|f| !f.is_empty())
        {
            let mut f = finding(Section::Anomalies, "windows.asar-integrity-mismatch", Confidence::Verified, Severity::Medium)
                .param("count", failed.len());
            for path in failed.iter().take(MAX_EVIDENCE) {
                f = f.evidence(Evidence::field(artifact, "header integrity.hash", path.clone()));
            }
            out.finding(f);
        }

        // Renderer settings in the application's own scripts (not its dependencies').
        let prefix = format!("{code}/");
        let scripts = tree
            .artifacts()
            .iter()
            .filter(|a| a.path.starts_with(&prefix) && !a.path[prefix.len()..].contains("node_modules/"))
            .filter(|a| matches!(a.extension().as_deref(), Some("js" | "cjs" | "mjs" | "html" | "htm")) && a.size <= MAX_SCRIPT)
            .take(MAX_SCRIPTS);
        let mut hits: BTreeMap<usize, Vec<Evidence>> = BTreeMap::new();
        for script in scripts {
            let Ok(bytes) = tree.read(&script.path) else { continue };
            for (index, (_, _, regex, _)) in ELECTRON_SETTINGS.iter().enumerate() {
                for found in regex.find_iter(&bytes).take(3) {
                    let list = hits.entry(index).or_default();
                    if list.len() < MAX_EVIDENCE {
                        list.push(Evidence::bytes(
                            script,
                            found.start() as u64,
                            found.len() as u64,
                            String::from_utf8_lossy(found.as_bytes()).into_owned(),
                        ));
                    }
                }
            }
        }
        for (index, evidence) in hits {
            let (setting, value, _, severity) = &ELECTRON_SETTINGS[index];
            let mut f = finding(Section::Hardening, "windows.electron-setting", Confidence::Heuristic, *severity)
                .param("setting", *setting)
                .param("value", *value)
                .param("count", evidence.len());
            for item in evidence {
                f = f.evidence(item);
            }
            out.finding(f);
        }
    }
    if !apps.is_empty() {
        out.summary("windows.electron", json!(apps));
    }
}

/// Recognises a runtime or framework from one file's name and its neighbours.
fn runtime_of(artifact: &Artifact, folder: &[&Artifact]) -> Option<&'static str> {
    let name = artifact.name().to_ascii_lowercase();
    let has = |other: &str| folder.iter().any(|a| a.name().eq_ignore_ascii_case(other));
    let qt = |prefix: &str| {
        name.strip_prefix(prefix).is_some_and(|rest| rest.ends_with(".dll") && rest.chars().next().is_some_and(|c| c.is_ascii_alphabetic()))
    };
    Some(match name.as_str() {
        _ if qt("qt6") => "Qt 6",
        _ if qt("qt5") => "Qt 5",
        "qtcore4.dll" | "qtgui4.dll" => "Qt 4",
        "libcef.dll" => "Chromium Embedded Framework (CEF)",
        "nw.dll" | "nw_elf.dll" => "NW.js",
        "jvm.dll" => "Java runtime (bundled JVM)",
        "unityplayer.dll" => "Unity",
        "gameassembly.dll" if has("UnityPlayer.dll") => "Unity (IL2CPP)",
        "flutter_windows.dll" => "Flutter",
        "webview2loader.dll" => "Microsoft Edge WebView2 (used by Tauri, Wails and .NET WebView2 apps)",
        "coreclr.dll" | "hostfxr.dll" | "hostpolicy.dll" => ".NET (self-contained runtime)",
        "squirrel.exe" => "Squirrel installer/updater",
        "update.exe" if has("Squirrel.exe") || has("RELEASES") || folder.iter().any(|a| a.name().ends_with(".nupkg")) => {
            "Squirrel installer/updater"
        }
        "base_library.zip" | "pyz-00.pyz" => "PyInstaller",
        "library.zip" if folder.iter().any(|a| is_python_dll(&a.name().to_ascii_lowercase())) => "py2exe",
        "vcruntime140.dll" | "msvcp140.dll" | "vcruntime140_1.dll" => "Microsoft Visual C++ runtime (bundled)",
        "libgcc_s_seh-1.dll" | "libstdc++-6.dll" | "libwinpthread-1.dll" => "MinGW runtime",
        "uninstall.exe" | "uninst.exe" => "an uninstaller program",
        _ if name.ends_with(".runtimeconfig.json") => ".NET (framework-dependent application)",
        _ if name.ends_with(".jar") => "Java archives (.jar)",
        _ if name.ends_with(".nupkg") => "Squirrel installer/updater",
        _ if name.ends_with("-win64-shipping.exe") || name.ends_with("-win32-shipping.exe") => "Unreal Engine",
        _ if is_python_dll(&name) => "Python (embedded interpreter)",
        _ if name.len() == 12
            && name.is_ascii()
            && name.starts_with("unins")
            && name.ends_with(".exe")
            && name[5..8].bytes().all(|b| b.is_ascii_digit()) =>
        {
            "Inno Setup uninstaller"
        }
        _ => return None,
    })
}

fn is_python_dll(name: &str) -> bool {
    name.strip_prefix("python")
        .and_then(|rest| rest.strip_suffix(".dll"))
        .is_some_and(|version| !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit()))
}

/// Application frameworks and runtimes recognised from the files present.
fn runtimes(tree: &dyn Tree, folders: &BTreeMap<&str, Vec<&Artifact>>, out: &mut Output) {
    let mut found: BTreeMap<&'static str, Vec<&Artifact>> = BTreeMap::new();
    for files in folders.values() {
        for artifact in files {
            if let Some(runtime) = runtime_of(artifact, files) {
                found.entry(runtime).or_default().push(artifact);
            }
        }
    }
    // PyInstaller one-file programs: the archive cookie near the end of the executable.
    for artifact in tree.artifacts() {
        let Some(overlay) = artifact.facts.get("windows.pe").and_then(|f| f.get("overlay")).filter(|o| !o.is_null()) else { continue };
        let (Some(offset), Some(size)) = (overlay.get("offset").and_then(Value::as_u64), overlay.get("size").and_then(Value::as_u64))
        else {
            continue;
        };
        if size < 88 {
            continue;
        }
        let Ok(bytes) = tree.read(&artifact.path) else { continue };
        let end = (offset + size) as usize;
        let tail = bytes.get(end.saturating_sub(4096).max(offset as usize)..end.min(bytes.len())).unwrap_or_default();
        if memchr::memmem::find(tail, b"MEI\x0c\x0b\x0a\x0b\x0e").is_some() {
            found.entry("PyInstaller").or_default().push(artifact);
        }
    }
    if !found.is_empty() {
        out.summary(
            "windows.runtimes",
            json!(
                found
                    .iter()
                    .map(|(runtime, files)| json!({
                        "runtime": runtime,
                        "files": files.len(),
                        "sample_files": files.iter().take(20).map(|a| a.path.as_str()).collect::<Vec<_>>(),
                    }))
                    .collect::<Vec<_>>()
            ),
        );
    }
    for (runtime, files) in &found {
        let mut f = finding(Section::Composition, "windows.runtime", Confidence::Heuristic, Severity::Info)
            .param("runtime", *runtime)
            .param("files", files.len());
        for file in files.iter().take(MAX_EVIDENCE) {
            f = f.evidence(Evidence::whole(file, file.name()));
        }
        out.finding(f);
    }

    // .NET applications: runtimeconfig.json names the framework, deps.json the libraries.
    for artifact in tree.artifacts() {
        let name = artifact.name();
        if let Some(app) = name.strip_suffix(".runtimeconfig.json") {
            let Some(config) = read_json(tree, artifact) else { continue };
            let options = config.get("runtimeOptions");
            let mut frameworks = Vec::new();
            for key in ["framework", "frameworks", "includedFrameworks"] {
                let Some(value) = options.and_then(|o| o.get(key)) else { continue };
                for entry in value.as_array().map(Vec::as_slice).unwrap_or(std::slice::from_ref(value)).iter().take(16) {
                    if let (Some(name), Some(version)) = (text(entry, &["name"]), text(entry, &["version"])) {
                        frameworks.push(format!("{name} {version}"));
                    }
                }
            }
            let self_contained = options.is_some_and(|o| o.get("includedFrameworks").is_some());
            let deps = tree.get(&format!("{}{app}.deps.json", &artifact.path[..artifact.path.len() - name.len()]));
            let libraries = deps.and_then(|d| read_json(tree, d)).map(|deps| deps_libraries(&deps)).unwrap_or_default();
            out.fact(
                artifact,
                "windows.dotnet-app",
                json!({
                    "application": app,
                    "tfm": options.and_then(|o| text(o, &["tfm"])),
                    "frameworks": frameworks,
                    "self_contained": self_contained,
                    "libraries": libraries.iter().take(1000).collect::<Vec<_>>(),
                    "libraries_truncated": libraries.len() > 1000,
                }),
            );
            let mut f = finding(Section::Composition, "windows.dotnet-app", Confidence::Verified, Severity::Info)
                .param("application", app)
                .param("frameworks", if frameworks.is_empty() { "?".to_string() } else { frameworks.join(", ") })
                .param("mode", if self_contained { "self-contained" } else { "framework-dependent" })
                .param("libraries", libraries.len())
                .evidence(Evidence::field(
                    artifact,
                    "runtimeOptions",
                    json!({ "tfm": options.and_then(|o| text(o, &["tfm"])), "frameworks": frameworks }),
                ));
            if let Some(deps) = deps {
                f = f.evidence(Evidence::field(deps, "libraries", json!(libraries.iter().take(20).collect::<Vec<_>>())));
            }
            out.finding(f);
        }
    }
}

/// `name version` of every NuGet package a deps.json lists.
fn deps_libraries(deps: &Value) -> Vec<String> {
    let mut list: Vec<String> = deps
        .get("libraries")
        .and_then(Value::as_object)
        .map(|libraries| {
            libraries
                .iter()
                .filter(|(_, info)| text(info, &["type"]) == Some("package"))
                .map(|(key, _)| key.replacen('/', " ", 1))
                .collect()
        })
        .unwrap_or_default();
    list.sort();
    list
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_suffixes_are_ignored_when_comparing_names() {
        assert_eq!(comparable_name("Launcher.EXE (2)"), "launcher.exe");
        assert_eq!(comparable_name("C:\\dir\\App (x86).exe"), "app (x86).exe");
        assert_eq!(comparable_name("a/b/c.dll"), "c.dll");
    }

    #[test]
    fn electron_version_pattern() {
        let regex = ELECTRON_VERSION.as_ref().expect("regex");
        let captures = regex.captures(b"\0Mozilla/5.0 Chrome/124.0.6367.49 Electron/30.0.1 Safari\0").expect("match");
        assert_eq!(&captures[1], b"124.0.6367.49");
        assert_eq!(&captures[2], b"30.0.1");
        assert!(regex.captures(b"Electron/ and Chrome/").is_none());
    }

    #[test]
    fn electron_settings_patterns() {
        let hit = |index: usize, text: &str| ELECTRON_SETTINGS[index].2.is_match(text.as_bytes());
        assert!(hit(0, "webPreferences:{nodeIntegration:!0}"));
        assert!(hit(0, "nodeIntegration : true,"));
        assert!(!hit(0, "nodeIntegration: false"));
        assert!(!hit(0, "nodeIntegrationInWorker: true"));
        assert!(hit(1, "contextIsolation:false"));
        assert!(hit(2, "webSecurity: !1"));
        assert!(hit(3, "{ sandbox: false }"));
        assert!(!hit(3, "sandbox: true"));
    }

    #[test]
    fn deps_json_libraries() {
        let deps = json!({ "libraries": {
            "App/1.0.0": { "type": "project" },
            "Newtonsoft.Json/13.0.3": { "type": "package" },
            "Serilog/3.1.1": { "type": "package" },
        }});
        assert_eq!(deps_libraries(&deps), ["Newtonsoft.Json 13.0.3", "Serilog 3.1.1"]);
        assert!(deps_libraries(&json!({ "libraries": 5 })).is_empty());
    }
}
