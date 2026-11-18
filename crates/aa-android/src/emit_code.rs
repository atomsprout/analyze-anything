//! Findings and facts about what the package is made of: DEX code, SDKs, frameworks, packers,
//! native libraries, and notable files.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Section, Severity};
use serde_json::json;

use crate::dex::{self, Dex};
use crate::manifest::Manifest;
use crate::sdks::{self, Sdk};
use crate::{Package, elf, finding, listed};

const MAX_DEX_FILES: usize = 200;
const MAX_NATIVE_LIBS: usize = 2000;
/// Files larger than this are not searched for version strings.
const MAX_SEARCHED: u64 = 256 * 1024 * 1024;

/// How each group of API references is reported.
struct ApiGroup {
    group: &'static str,
    rule: &'static str,
    section: Section,
    severity: Severity,
    references: &'static [&'static str],
}

const API_GROUPS: &[ApiGroup] = &[
    ApiGroup { group: "dynamic-code", rule: "android.code-dynamic-loading", section: Section::Code, severity: Severity::Low, references: &["MASVS-CODE-4"] },
    ApiGroup { group: "command-exec", rule: "android.code-command-exec", section: Section::Code, severity: Severity::Low, references: &["MASVS-CODE-4"] },
    ApiGroup { group: "native-load", rule: "android.code-native-load", section: Section::Code, severity: Severity::Info, references: &[] },
    ApiGroup { group: "reflection", rule: "android.code-reflection", section: Section::Code, severity: Severity::Info, references: &[] },
    ApiGroup { group: "webview-js-interface", rule: "android.code-webview-js-interface", section: Section::Code, severity: Severity::Low, references: &["CWE-749", "MASVS-PLATFORM-2"] },
    ApiGroup { group: "webview-js-enabled", rule: "android.code-webview-js-enabled", section: Section::Code, severity: Severity::Info, references: &["MASVS-PLATFORM-2"] },
    ApiGroup { group: "webview-file-access", rule: "android.code-webview-file-access", section: Section::Code, severity: Severity::Low, references: &["MASVS-PLATFORM-2"] },
    ApiGroup { group: "webview-debugging", rule: "android.code-webview-debugging", section: Section::Code, severity: Severity::Info, references: &["MASVS-RESILIENCE-4"] },
    ApiGroup { group: "hostname-verifier-set", rule: "android.code-hostname-verifier-set", section: Section::Code, severity: Severity::Info, references: &["MASVS-NETWORK-1"] },
    ApiGroup { group: "device-identifiers", rule: "android.api-device-identifiers", section: Section::Privacy, severity: Severity::Low, references: &["MASVS-PRIVACY-1"] },
    ApiGroup { group: "location", rule: "android.api-location", section: Section::Privacy, severity: Severity::Info, references: &["MASVS-PRIVACY-1"] },
    ApiGroup { group: "sms-send", rule: "android.api-sms-send", section: Section::Privacy, severity: Severity::Low, references: &[] },
    ApiGroup { group: "audio-record", rule: "android.api-audio-record", section: Section::Privacy, severity: Severity::Info, references: &["MASVS-PRIVACY-1"] },
    ApiGroup { group: "camera", rule: "android.api-camera", section: Section::Privacy, severity: Severity::Info, references: &["MASVS-PRIVACY-1"] },
    ApiGroup { group: "installed-apps", rule: "android.api-installed-apps", section: Section::Privacy, severity: Severity::Low, references: &["MASVS-PRIVACY-1"] },
    ApiGroup { group: "clipboard-read", rule: "android.api-clipboard-read", section: Section::Privacy, severity: Severity::Info, references: &["MASVS-PRIVACY-1"] },
    ApiGroup { group: "accounts", rule: "android.api-accounts", section: Section::Privacy, severity: Severity::Info, references: &["MASVS-PRIVACY-1"] },
    ApiGroup { group: "screen-capture", rule: "android.api-screen-capture", section: Section::Privacy, severity: Severity::Low, references: &["MASVS-PRIVACY-1"] },
    ApiGroup { group: "accessibility-actions", rule: "android.api-accessibility-actions", section: Section::Code, severity: Severity::Low, references: &[] },
    ApiGroup { group: "package-install", rule: "android.api-package-install", section: Section::Code, severity: Severity::Low, references: &[] },
];

fn dex_order(name: &str) -> (u32, &str) {
    // classes.dex, classes2.dex, … in the order the runtime loads them.
    let number = name.strip_prefix("classes").and_then(|r| r.strip_suffix(".dex")).map(|n| if n.is_empty() { 1 } else { n.parse().unwrap_or(u32::MAX) });
    (number.unwrap_or(u32::MAX), name)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let first = needle[0];
    let mut at = 0;
    while let Some(offset) = haystack[at..=haystack.len() - needle.len()].iter().position(|b| *b == first) {
        let start = at + offset;
        if &haystack[start..start + needle.len()] == needle {
            return Some(start);
        }
        at = start + 1;
        if at > haystack.len() - needle.len() {
            break;
        }
    }
    None
}

pub fn run(package: &Package, manifest: &Manifest, out: &mut Output) {
    let anchor = package.anchor();

    // ---- DEX ----
    let mut dex_names: Vec<&str> =
        package.files.keys().map(String::as_str).filter(|n| !n.contains('/') && n.ends_with(".dex")).collect();
    dex_names.sort_by_key(|n| dex_order(n));
    let mut parsed: Vec<(&Artifact, Dex)> = Vec::new();
    for name in dex_names.iter().take(MAX_DEX_FILES) {
        let Some(artifact) = package.file(name) else { continue };
        let Some(bytes) = package.read(name) else {
            out.limitation("android.dex-unreadable", Some(artifact), Some("the file could not be read".into()));
            continue;
        };
        match dex::parse(&bytes) {
            Some(dex) => {
                out.kind(artifact, "dex");
                if !dex.problems.is_empty() {
                    out.limitation("android.dex-unreadable", Some(artifact), Some(listed(&dex.problems, 3)));
                }
                out.fact(
                    artifact,
                    "android.dex",
                    json!({
                        "version": dex.version,
                        "strings": dex.strings, "types": dex.types, "protos": dex.protos, "fields": dex.fields,
                        "methods": dex.methods, "classes": dex.classes, "native_methods": dex.native_methods,
                        "problems": dex.problems,
                    }),
                );
                parsed.push((artifact, dex));
            }
            None => out.limitation("android.dex-unreadable", Some(artifact), Some("no DEX header".into())),
        }
    }
    if dex_names.len() > MAX_DEX_FILES {
        out.limitation("android.dex-unreadable", Some(anchor), Some(format!("only the first {MAX_DEX_FILES} of {} DEX files were read", dex_names.len())));
    }

    // Package index: package (slash form) -> (classes, index of the first DEX that defines it).
    let mut packages: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let (mut total_classes, mut short_names) = (0usize, 0usize);
    for (index, (_, dex)) in parsed.iter().enumerate() {
        for class in &dex.class_names {
            total_classes += 1;
            let simple = dex::simple_name(class);
            // Inner and synthetic classes follow their outer class; judge the outer name.
            let outer = simple.split('$').next().unwrap_or(simple);
            if outer.len() <= 2 {
                short_names += 1;
            }
            packages.entry(dex::package_of(class)).or_insert((0, index)).0 += 1;
        }
    }

    if !parsed.is_empty() {
        let sum = |f: fn(&Dex) -> u32| parsed.iter().map(|(_, d)| u64::from(f(d))).sum::<u64>();
        let versions: BTreeSet<&str> = parsed.iter().map(|(_, d)| d.version.as_str()).collect();
        let mut f = finding(Section::Code, "android.dex-summary", Confidence::Verified, Severity::Info)
            .param("files", parsed.len())
            .param("classes", sum(|d| d.classes))
            .param("methods", sum(|d| d.methods))
            .param("fields", sum(|d| d.fields))
            .param("strings", sum(|d| d.strings))
            .param("native_methods", sum(|d| d.native_methods))
            .param("versions", versions.into_iter().collect::<Vec<_>>().join(", "));
        for (artifact, dex) in parsed.iter().take(30) {
            f = f.evidence(Evidence::bytes(artifact, 0x58, 16, json!({ "methods": dex.methods, "classes": dex.classes })));
        }
        out.finding(f);

        // Top-level packages: the first two segments, or one for single-segment packages.
        let mut top: BTreeMap<String, usize> = BTreeMap::new();
        for (package_name, (count, _)) in &packages {
            let mut segments = package_name.split('/');
            let key = match (segments.next(), segments.next()) {
                (Some(a), Some(b)) => format!("{a}.{b}"),
                (Some(a), None) if !a.is_empty() => a.to_string(),
                _ => "(default package)".to_string(),
            };
            *top.entry(key).or_default() += count;
        }
        let mut ranked: Vec<(&String, &usize)> = top.iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let shown: Vec<String> = ranked.iter().take(12).map(|(name, count)| format!("{name} ({count})")).collect();
        out.finding(
            finding(Section::Code, "android.dex-packages", Confidence::Verified, Severity::Info)
                .param("count", top.len())
                .param("packages", shown.join(", "))
                .evidence(Evidence::whole(parsed[0].0, json!(ranked.iter().take(12).map(|(n, c)| json!({ "package": n, "classes": c })).collect::<Vec<_>>()))),
        );
        let share = if total_classes > 0 { short_names as f64 / total_classes as f64 } else { 0.0 };
        out.fact(
            anchor,
            "android.code",
            json!({
                "dex_files": parsed.iter().map(|(a, _)| a.path.as_str()).collect::<Vec<_>>(),
                "classes": total_classes,
                "methods": sum(|d| d.methods),
                "native_methods": sum(|d| d.native_methods),
                "top_packages": ranked.iter().take(60).map(|(n, c)| json!({ "package": n, "classes": c })).collect::<Vec<_>>(),
                "top_packages_truncated": ranked.len() > 60,
                "short_class_name_share": (share * 1000.0).round() / 1000.0,
            }),
        );
        if total_classes >= 50 && share >= 0.25 {
            out.finding(
                finding(Section::Code, "android.obfuscated-names", Confidence::Heuristic, Severity::Info)
                    .param("percent", (share * 100.0).round())
                    .param("classes", total_classes)
                    .reference("MASVS-RESILIENCE-3")
                    .evidence(Evidence::whole(parsed[0].0, json!({ "short_names": short_names, "classes": total_classes }))),
            );
        }
        api_findings(&parsed, out);
    }

    // ---- SDKs, frameworks, packers ----
    let lib_files: Vec<(&str, &str, &Artifact)> = package
        .files
        .iter()
        .filter_map(|(name, artifact)| {
            let rest = name.strip_prefix("lib/")?;
            let (abi, file) = rest.split_once('/')?;
            (!file.contains('/') && file.ends_with(".so")).then_some((abi, file, *artifact))
        })
        .collect();
    let has_package = |prefix: &str| -> Option<usize> {
        packages
            .range(prefix..)
            .take_while(|(name, _)| name.starts_with(prefix))
            .find(|(name, _)| name.len() == prefix.len() || name.as_bytes()[prefix.len()] == b'/')
            .map(|(_, (_, dex_index))| *dex_index)
    };
    // What marks an SDK as present: (artifact, field, value) of each signal that hit.
    let signals = |sdk: &Sdk, with_packages: bool| -> Vec<Evidence> {
        let mut hits = Vec::new();
        if with_packages {
            for prefix in sdk.packages {
                if let Some(dex_index) = has_package(prefix) {
                    hits.push(Evidence::field(parsed[dex_index].0, "class package", prefix.replace('/', ".")));
                }
            }
        }
        for pattern in sdk.libs {
            if let Some((_, _, artifact)) = lib_files.iter().find(|(_, file, _)| sdks::glob(pattern, file)) {
                hits.push(Evidence::whole(artifact, artifact.name()));
            }
        }
        for marker in sdk.files {
            let hit = if marker.ends_with('/') {
                package.files.range(marker.to_string()..).next().filter(|(name, _)| name.starts_with(marker)).map(|(_, a)| *a)
            } else {
                package.file(marker)
            };
            if let Some(artifact) = hit {
                hits.push(Evidence::whole(artifact, *marker));
            }
        }
        hits
    };

    let mut sdk_rows = Vec::new();
    let mut libraries: Vec<(&str, Evidence)> = Vec::new();
    for sdk in sdks::SDKS {
        let hits = signals(sdk, true);
        let Some(first) = hits.first() else { continue };
        sdk_rows.push(json!({ "name": sdk.name, "vendor": sdk.vendor, "category": sdk.category.as_str(), "tracker": sdk.category.is_tracker() }));
        if sdk.category == sdks::Category::Library {
            libraries.push((sdk.name, first.clone()));
            continue;
        }
        let (section, rule) = if sdk.category.is_tracker() { (Section::Privacy, "android.tracker-sdk") } else { (Section::Composition, "android.sdk") };
        let mut f = finding(section, rule, Confidence::Derived, Severity::Info).param("name", sdk.name).param("vendor", sdk.vendor).param("category", sdk.category.as_str());
        if sdk.category.is_tracker() {
            f = f.reference("MASVS-PRIVACY-1");
        }
        for hit in hits.into_iter().take(3) {
            f = f.evidence(hit);
        }
        out.finding(f);
    }
    if !libraries.is_empty() {
        let names: Vec<&str> = libraries.iter().map(|(n, _)| *n).collect();
        let mut f = finding(Section::Composition, "android.libraries", Confidence::Derived, Severity::Info).param("count", names.len()).param("libraries", listed(&names, 40));
        for (_, evidence) in libraries.into_iter().take(40) {
            f = f.evidence(evidence);
        }
        out.finding(f);
    }

    let mut framework_rows = Vec::new();
    for framework in sdks::FRAMEWORKS {
        let hits = signals(framework, true);
        if hits.is_empty() {
            continue;
        }
        let detail = framework_detail(package, framework.name, &lib_files);
        framework_rows.push(json!({ "name": framework.name, "vendor": framework.vendor, "detail": detail }));
        let mut f = finding(Section::Composition, "android.framework", Confidence::Derived, Severity::Info)
            .param("name", framework.name)
            .param("vendor", framework.vendor)
            .param("detail", detail.clone().unwrap_or_else(|| "-".into()));
        for hit in hits.into_iter().take(3) {
            f = f.evidence(hit);
        }
        out.finding(f);
    }

    let application_class = manifest.application.as_ref().and_then(|a| a.name.as_deref()).map(|n| n.replace('.', "/"));
    let mut packer_rows = Vec::new();
    for packer in sdks::PACKERS {
        let mut hits = signals(packer, false);
        // A stub class counts only when it is the application's entry class.
        if let Some(class) = &application_class
            && packer.packages.iter().any(|p| class.starts_with(&format!("{p}/")) || class == p)
        {
            hits.push(Evidence::field(package.manifest, "application@android:name", class.replace('/', ".")));
        }
        if hits.is_empty() {
            continue;
        }
        packer_rows.push(json!({ "name": packer.name, "vendor": packer.vendor }));
        let mut f = finding(Section::Hardening, "android.packer", Confidence::Heuristic, Severity::Medium)
            .param("name", packer.name)
            .param("vendor", packer.vendor)
            .reference("MASVS-RESILIENCE-3");
        for hit in hits.into_iter().take(4) {
            f = f.evidence(hit);
        }
        out.finding(f);
        out.limitation("android.packed-code-hidden", Some(anchor), Some(packer.name.to_string()));
    }
    if !sdk_rows.is_empty() || !framework_rows.is_empty() || !packer_rows.is_empty() {
        out.fact(anchor, "android.sdks", json!({ "sdks": sdk_rows, "frameworks": framework_rows, "packers": packer_rows }));
    }

    native_libs(package, &lib_files, out);
    notable_files(package, out);
}

fn api_findings(parsed: &[(&Artifact, Dex)], out: &mut Output) {
    for group in API_GROUPS {
        let mut apis: BTreeSet<&str> = BTreeSet::new();
        let mut evidence = Vec::new();
        for (artifact, dex) in parsed {
            for (api_index, method_index, shown) in &dex.api_hits {
                if dex::APIS[*api_index].group == group.group && apis.insert(shown.as_str()) && evidence.len() < 12 {
                    evidence.push(Evidence::field(artifact, format!("method_ids[{method_index}]"), shown.clone()));
                }
            }
        }
        if apis.is_empty() {
            continue;
        }
        let names: Vec<&str> = apis.into_iter().collect();
        let mut f = finding(group.section, group.rule, Confidence::Derived, group.severity).param("apis", listed(&names, 6));
        for reference in group.references {
            f = f.reference(reference);
        }
        for e in evidence {
            f = f.evidence(e);
        }
        out.finding(f);
    }

    for (rule, pick, references) in [
        ("android.code-custom-trust-manager", (|d: &Dex| &d.trust_managers) as fn(&Dex) -> &Vec<String>, &["CWE-295", "MASVS-NETWORK-1"][..]),
        ("android.code-custom-hostname-verifier", |d: &Dex| &d.hostname_verifiers, &["CWE-295", "MASVS-NETWORK-1"][..]),
        ("android.code-ssl-error-handler", |d: &Dex| &d.ssl_error_handlers, &["CWE-295", "MASVS-NETWORK-1"][..]),
    ] {
        let mut classes: Vec<String> = Vec::new();
        let mut evidence = Vec::new();
        for (artifact, dex) in parsed {
            for class in pick(dex) {
                if evidence.len() < 10 {
                    evidence.push(Evidence::field(artifact, "class_defs", class.clone()));
                }
                classes.push(class.trim_start_matches('L').trim_end_matches(';').replace('/', "."));
            }
        }
        if classes.is_empty() {
            continue;
        }
        let mut f = finding(Section::Code, rule, Confidence::Heuristic, Severity::Low).param("count", classes.len()).param("classes", listed(&classes, 6));
        for reference in references {
            f = f.reference(reference);
        }
        for e in evidence {
            f = f.evidence(e);
        }
        out.finding(f);
    }

    let mut ciphers: BTreeMap<&str, &Artifact> = BTreeMap::new();
    let mut digests: BTreeMap<&str, &Artifact> = BTreeMap::new();
    for (artifact, dex) in parsed {
        for cipher in &dex.cipher_strings {
            ciphers.entry(cipher.as_str()).or_insert(artifact);
        }
        for digest in &dex.weak_digest_strings {
            digests.entry(digest.as_str()).or_insert(artifact);
        }
    }
    if !ciphers.is_empty() {
        let weak: Vec<(&str, &Artifact)> = ciphers
            .iter()
            .filter(|(c, _)| {
                let upper = c.to_ascii_uppercase();
                upper.contains("/ECB") || upper.starts_with("DES") || upper.starts_with("RC4") || upper.starts_with("ARCFOUR") || upper == "AES" || upper.starts_with("BLOWFISH")
            })
            .map(|(c, a)| (*c, *a))
            .collect();
        let names: Vec<&str> = ciphers.keys().copied().collect();
        let mut f = finding(Section::Code, "android.code-cipher-strings", Confidence::Heuristic, Severity::Info).param("count", names.len()).param("ciphers", listed(&names, 12));
        for (cipher, artifact) in ciphers.iter().take(12) {
            f = f.evidence(Evidence::field(artifact, "string_ids", *cipher));
        }
        out.finding(f);
        if !weak.is_empty() {
            let names: Vec<&str> = weak.iter().map(|(c, _)| *c).collect();
            let mut f = finding(Section::Code, "android.code-weak-cipher", Confidence::Heuristic, Severity::Low)
                .param("ciphers", listed(&names, 10))
                .reference("CWE-327")
                .reference("MASVS-CRYPTO-1");
            for (cipher, artifact) in weak.iter().take(10) {
                f = f.evidence(Evidence::field(artifact, "string_ids", *cipher));
            }
            out.finding(f);
        }
    }
    if !digests.is_empty() {
        let names: Vec<&str> = digests.keys().copied().collect();
        let mut f = finding(Section::Code, "android.code-weak-digest", Confidence::Heuristic, Severity::Info)
            .param("digests", listed(&names, 6))
            .reference("CWE-328")
            .reference("MASVS-CRYPTO-1");
        for (digest, artifact) in digests.iter().take(6) {
            f = f.evidence(Evidence::field(artifact, "string_ids", *digest));
        }
        out.finding(f);
    }
}

/// Version or build details of a framework, where a cheap look finds them.
fn framework_detail(package: &Package, name: &str, lib_files: &[(&str, &str, &Artifact)]) -> Option<String> {
    let lib = |file: &str| lib_files.iter().find(|(_, f, _)| *f == file).map(|(_, _, a)| *a);
    let has_lib = |file: &str| lib(file).is_some();
    match name {
        "Flutter" => {
            let mut parts = Vec::new();
            // The engine embeds the Dart SDK version as `3.5.4 (stable) (date) on "android_arm64"`.
            if let Some(engine) = lib("libflutter.so").filter(|a| a.size <= MAX_SEARCHED)
                && let Ok(bytes) = package.tree.read(&engine.path)
            {
                for channel in [&b" (stable)"[..], b" (beta)", b" (dev)", b" (main)"] {
                    if let Some(at) = find(&bytes, channel) {
                        let start = bytes[..at].iter().rposition(|b| !(b.is_ascii_digit() || *b == b'.' || *b == b'-' || b.is_ascii_alphabetic())).map_or(0, |p| p + 1);
                        let version = String::from_utf8_lossy(&bytes[start..at]);
                        if version.split('.').count() >= 3 && version.len() <= 32 && version.starts_with(|c: char| c.is_ascii_digit()) {
                            parts.push(format!("Dart {version}{}", String::from_utf8_lossy(channel)));
                            break;
                        }
                    }
                }
            }
            if has_lib("libapp.so") {
                parts.push("release build (AOT snapshot libapp.so)".into());
            } else if package.file("assets/flutter_assets/kernel_blob.bin").is_some() {
                parts.push("debug build (kernel_blob.bin, JIT)".into());
            }
            (!parts.is_empty()).then(|| parts.join("; "))
        }
        "React Native" => {
            let mut parts = Vec::new();
            if let Some(bytes) = package.read("assets/index.android.bundle") {
                // Hermes bytecode starts with a fixed magic followed by the bytecode version.
                if bytes.len() >= 12 && bytes[..8] == [0xc6, 0x1f, 0xbc, 0x03, 0xc1, 0x03, 0x19, 0x1f] {
                    let version = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
                    parts.push(format!("Hermes bytecode version {version}"));
                } else {
                    parts.push("JavaScript bundle in source form".into());
                }
            }
            if has_lib("libhermes.so") {
                parts.push("Hermes engine".into());
            } else if has_lib("libjsc.so") {
                parts.push("JavaScriptCore engine".into());
            }
            (!parts.is_empty()).then(|| parts.join("; "))
        }
        "Unity" => {
            let mut parts = Vec::new();
            if has_lib("libil2cpp.so") {
                parts.push("IL2CPP scripting backend".to_string());
            } else if lib_files.iter().any(|(_, f, _)| f.starts_with("libmono")) {
                parts.push("Mono scripting backend".to_string());
            }
            for file in ["assets/bin/Data/data.unity3d", "assets/bin/Data/globalgamemanagers", "assets/bin/Data/unity default resources"] {
                if let Some(bytes) = package.read(file)
                    && let Some(version) = unity_version(&bytes[..bytes.len().min(4096)])
                {
                    parts.push(format!("Unity {version}"));
                    break;
                }
            }
            (!parts.is_empty()).then(|| parts.join("; "))
        }
        "Xamarin / .NET for Android" => {
            let assemblies: Vec<&str> = package.files.keys().filter_map(|n| n.strip_prefix("assemblies/")).collect();
            let blob = assemblies.iter().any(|n| n.ends_with(".blob"));
            let maui = assemblies.iter().any(|n| n.starts_with("Microsoft.Maui")) || lib_files.iter().any(|(_, f, _)| f.contains("Microsoft.Maui"));
            let forms = assemblies.iter().any(|n| n.starts_with("Xamarin.Forms"));
            let mut parts = Vec::new();
            if maui {
                parts.push(".NET MAUI".to_string());
            } else if forms {
                parts.push("Xamarin.Forms".to_string());
            }
            if blob {
                parts.push("assemblies in an assembly store (assemblies.blob)".to_string());
            } else if !assemblies.is_empty() {
                parts.push(format!("{} assemblies", assemblies.iter().filter(|n| n.ends_with(".dll")).count()));
            }
            (!parts.is_empty()).then(|| parts.join("; "))
        }
        "Kotlin" => {
            let modules = package.files.keys().filter(|n| n.starts_with("META-INF/") && n.ends_with(".kotlin_module")).count();
            (modules > 0).then(|| format!("{modules} kotlin_module files"))
        }
        _ => None,
    }
}

/// A Unity version such as `2021.3.16f1` or `6000.0.23f1` among the first bytes of a data file.
fn unity_version(bytes: &[u8]) -> Option<String> {
    let text: Vec<&[u8]> = bytes.split(|b| !(b.is_ascii_alphanumeric() || *b == b'.')).collect();
    text.into_iter().find_map(|word| {
        let word = std::str::from_utf8(word).ok()?;
        let mut parts = word.split('.');
        let (major, minor, patch) = (parts.next()?, parts.next()?, parts.next()?);
        let year: u32 = major.parse().ok()?;
        let plausible_major = (5..=6).contains(&year) || (2017..=2030).contains(&year) || year == 6000;
        let patch_ok = patch.len() >= 3 && patch.chars().next()?.is_ascii_digit() && patch.contains(['f', 'p', 'b', 'a']) && patch.chars().last()?.is_ascii_digit();
        (parts.next().is_none() && plausible_major && minor.parse::<u32>().is_ok() && patch_ok && word.len() <= 20).then(|| word.to_string())
    })
}

fn native_libs(package: &Package, lib_files: &[(&str, &str, &Artifact)], out: &mut Output) {
    if lib_files.is_empty() {
        return;
    }
    let anchor = package.anchor();
    let mut by_abi: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (abi, file, _) in lib_files {
        by_abi.entry(abi).or_default().insert(file);
    }
    let abis: Vec<String> = by_abi.iter().map(|(abi, libs)| format!("{abi} ({})", libs.len())).collect();
    let mut f = finding(Section::Composition, "android.native-libs", Confidence::Verified, Severity::Info)
        .param("abis", abis.join(", "))
        .param("count", lib_files.len());
    for (_, _, artifact) in lib_files.iter().take(12) {
        f = f.evidence(Evidence::whole(artifact, artifact.size));
    }
    out.finding(f);

    // Every ABI should ship the same set; a library missing from one crashes there at load.
    let all: BTreeSet<&str> = by_abi.values().flatten().copied().collect();
    let gaps: Vec<String> = by_abi
        .iter()
        .filter_map(|(abi, libs)| {
            let missing: Vec<&str> = all.difference(libs).copied().collect();
            (!missing.is_empty()).then(|| format!("{abi} lacks {}", listed(&missing, 5)))
        })
        .collect();
    if by_abi.len() > 1 && !gaps.is_empty() {
        out.finding(
            finding(Section::Anomalies, "android.abi-mismatch", Confidence::Verified, Severity::Low)
                .param("gaps", listed(&gaps, 4))
                .evidence(Evidence::whole(anchor, json!(by_abi.iter().map(|(abi, libs)| json!({ "abi": abi, "libraries": libs.len() })).collect::<Vec<_>>()))),
        );
    }

    let mut rows = Vec::new();
    let (mut small_pages, mut checked_64) = (Vec::new(), 0usize);
    let (mut textrel, mut rwx, mut exec_stack) = (Vec::new(), Vec::new(), Vec::new());
    for (abi, file, artifact) in lib_files.iter().take(MAX_NATIVE_LIBS) {
        let Ok(bytes) = package.tree.read(&artifact.path) else { continue };
        let Some(parsed) = elf::parse(&bytes) else {
            rows.push(json!({ "abi": abi, "name": file, "elf": false }));
            continue;
        };
        rows.push(json!({
            "abi": abi, "name": file, "elf": true, "machine": parsed.machine_name(), "bits": parsed.bits,
            "min_load_align": parsed.min_load_align, "rwx_segment": parsed.rwx_segment,
            "text_relocations": parsed.text_relocations, "executable_stack": parsed.executable_stack,
        }));
        if parsed.bits == 64
            && let Some(align) = parsed.min_load_align
        {
            checked_64 += 1;
            if align < 16384 {
                small_pages.push((*artifact, align));
            }
        }
        if parsed.text_relocations {
            textrel.push(*artifact);
        }
        if parsed.rwx_segment {
            rwx.push(*artifact);
        }
        if parsed.executable_stack == Some(true) {
            exec_stack.push(*artifact);
        }
    }
    out.fact(anchor, "android.native_libs", json!({ "libraries": rows, "truncated": lib_files.len() > MAX_NATIVE_LIBS }));
    if !small_pages.is_empty() {
        let names: Vec<&str> = small_pages.iter().map(|(a, _)| a.name()).collect();
        let mut f = finding(Section::Hardening, "android.native-16k-pages", Confidence::Verified, Severity::Info)
            .param("count", small_pages.len())
            .param("total", checked_64)
            .param("libraries", listed(&names, 8));
        for (artifact, align) in small_pages.iter().take(12) {
            f = f.evidence(Evidence::field(artifact, "PT_LOAD p_align", *align));
        }
        out.finding(f);
    }
    for (rule, list, severity, field) in [
        ("android.native-text-relocations", &textrel, Severity::Low, "DT_TEXTREL"),
        ("android.native-rwx-segment", &rwx, Severity::Medium, "PT_LOAD flags RWX"),
        ("android.native-executable-stack", &exec_stack, Severity::Medium, "PT_GNU_STACK flags"),
    ] {
        if list.is_empty() {
            continue;
        }
        let names: Vec<String> = list.iter().map(|a| a.path.rsplitn(3, '/').take(2).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join("/")).collect();
        let mut f = finding(Section::Hardening, rule, Confidence::Verified, severity).param("count", list.len()).param("libraries", listed(&names, 8)).reference("MASVS-CODE-4");
        for artifact in list.iter().take(12) {
            f = f.evidence(Evidence::field(artifact, field, true));
        }
        out.finding(f);
    }
}

fn notable_files(package: &Package, out: &mut Output) {
    let anchor = package.anchor();
    // Code shipped as data: loaded at run time, if at all, outside what the manifest declares.
    let mut embedded: Vec<(&str, &Artifact, &str)> = Vec::new();
    let mut probed = 0;
    for (name, artifact) in &package.files {
        if !(name.starts_with("assets/") || name.starts_with("res/raw/")) {
            continue;
        }
        let extension = artifact.extension();
        let what = match extension.as_deref() {
            Some("dex") => Some("DEX"),
            Some("apk") => Some("APK"),
            Some("jar") => Some("JAR"),
            Some("so") => Some("native library"),
            _ if artifact.is("apk") => Some("APK"),
            _ => None,
        };
        let what = what.or_else(|| {
            // An unnamed DEX: look at the magic of a bounded number of files.
            if probed >= 400 || artifact.size < 0x70 || artifact.size > 64 * 1024 * 1024 {
                return None;
            }
            probed += 1;
            package.tree.read(&artifact.path).ok().filter(|b| dex::is_dex(b)).map(|_| "DEX")
        });
        if let Some(what) = what {
            embedded.push((name.as_str(), artifact, what));
        }
    }
    if !embedded.is_empty() {
        let shown: Vec<String> = embedded.iter().map(|(name, _, what)| format!("{name} ({what})")).collect();
        let mut f = finding(Section::Code, "android.embedded-code", Confidence::Verified, Severity::Low).param("count", embedded.len()).param("files", listed(&shown, 8));
        for (_, artifact, what) in embedded.iter().take(15) {
            f = f.evidence(Evidence::whole(artifact, *what));
        }
        out.finding(f);
    }

    let bundles: Vec<(&str, &Artifact)> = package
        .files
        .iter()
        .filter(|(name, _)| name.starts_with("assets/") && (name.ends_with(".bundle") || name.ends_with(".jsbundle") || name.ends_with(".js")))
        .map(|(n, a)| (n.as_str(), *a))
        .collect();
    if !bundles.is_empty() {
        let mut largest = bundles.clone();
        largest.sort_by(|a, b| b.1.size.cmp(&a.1.size).then(a.0.cmp(b.0)));
        let shown: Vec<String> = largest.iter().take(5).map(|(n, a)| format!("{n} ({} bytes)", a.size)).collect();
        let mut f = finding(Section::Composition, "android.js-bundles", Confidence::Verified, Severity::Info).param("count", bundles.len()).param("largest", shown.join(", "));
        for (_, artifact) in largest.iter().take(5) {
            f = f.evidence(Evidence::whole(artifact, artifact.size));
        }
        out.finding(f);
    }

    // Build metadata the toolchain leaves in the package.
    let mut build = serde_json::Map::new();
    let mut evidence = Vec::new();
    if let Some(artifact) = package.file("META-INF/com/android/build/gradle/app-metadata.properties")
        && let Some(bytes) = package.read("META-INF/com/android/build/gradle/app-metadata.properties")
    {
        for line in String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]).lines() {
            if let Some((key, value)) = line.split_once('=')
                && matches!(key.trim(), "androidGradlePluginVersion" | "appMetadataVersion")
            {
                let key = if key.trim() == "androidGradlePluginVersion" { "android_gradle_plugin" } else { "app_metadata_version" };
                build.insert(key.into(), json!(value.trim()));
                evidence.push(Evidence::field(artifact, key, value.trim()));
            }
        }
    }
    if let Some(artifact) = package.file("kotlin-tooling-metadata.json")
        && let Some(bytes) = package.read("kotlin-tooling-metadata.json")
        && bytes.len() <= 1024 * 1024
        && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
    {
        for (field, key) in [("buildPluginVersion", "kotlin_gradle_plugin"), ("buildSystemVersion", "gradle")] {
            if let Some(text) = value.get(field).and_then(|v| v.as_str()) {
                build.insert(key.into(), json!(text));
                evidence.push(Evidence::field(artifact, field, text));
            }
        }
    }
    let mut versions: Vec<(String, String)> = Vec::new();
    for (name, artifact) in package.files.range("META-INF/".to_string()..).take_while(|(n, _)| n.starts_with("META-INF/")) {
        let Some(library) = name.strip_prefix("META-INF/").and_then(|n| n.strip_suffix(".version")).filter(|n| !n.contains('/')) else { continue };
        if versions.len() >= 600 || artifact.size > 200 {
            continue;
        }
        if let Ok(bytes) = package.tree.read(&artifact.path) {
            let version = String::from_utf8_lossy(&bytes).trim().to_string();
            if !version.is_empty() && version.chars().all(|c| c.is_ascii_graphic()) {
                versions.push((library.to_string(), version));
            }
        }
    }
    if !versions.is_empty() {
        build.insert("library_versions".into(), json!(versions.iter().map(|(n, v)| json!({ "library": n, "version": v })).collect::<Vec<_>>()));
    }
    let baseline = package.file("assets/dexopt/baseline.prof");
    if let Some(profile) = baseline {
        build.insert("baseline_profile".into(), json!(true));
        evidence.push(Evidence::whole(profile, profile.size));
    }
    if !build.is_empty() {
        let mut parts = Vec::new();
        for (key, label) in [("android_gradle_plugin", "Android Gradle plugin"), ("kotlin_gradle_plugin", "Kotlin Gradle plugin"), ("gradle", "Gradle")] {
            if let Some(value) = build.get(key).and_then(|v| v.as_str()) {
                parts.push(format!("{label} {value}"));
            }
        }
        if !versions.is_empty() {
            parts.push(format!("{} library version files (META-INF/*.version)", versions.len()));
            if let Some((_, artifact)) = package.files.range("META-INF/".to_string()..).find(|(n, _)| n.ends_with(".version")) {
                evidence.push(Evidence::whole(artifact, versions.len()));
            }
        }
        if baseline.is_some() {
            parts.push("baseline profile".to_string());
        }
        out.fact(anchor, "android.build", serde_json::Value::Object(build));
        let mut f = finding(Section::Composition, "android.build-info", Confidence::Verified, Severity::Info).param("details", parts.join("; "));
        for e in evidence.into_iter().take(8) {
            f = f.evidence(e);
        }
        out.finding(f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dex_files_sort_in_load_order() {
        let mut names = vec!["classes10.dex", "classes2.dex", "classes.dex", "extra.dex"];
        names.sort_by_key(|n| dex_order(n));
        assert_eq!(names, vec!["classes.dex", "classes2.dex", "classes10.dex", "extra.dex"]);
    }

    #[test]
    fn substring_search() {
        assert_eq!(find(b"xx3.5.4 (stable) yy", b" (stable)"), Some(7));
        assert_eq!(find(b"abc", b"abcd"), None);
        assert_eq!(find(b"aab", b"ab"), Some(1));
        assert_eq!(find(b"", b"a"), None);
    }

    #[test]
    fn unity_versions() {
        assert_eq!(unity_version(b"UnityFS\0\0\0\0\x085.x.x\x002021.3.16f1\0").as_deref(), Some("2021.3.16f1"));
        assert_eq!(unity_version(b"\0\x006000.0.23f1\0").as_deref(), Some("6000.0.23f1"));
        assert_eq!(unity_version(b"1.2.3 and 10.0.0.1"), None);
    }
}
