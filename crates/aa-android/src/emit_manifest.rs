//! Findings and facts from the manifest: identity, platform settings, permissions, components.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Section, Severity};
use serde_json::json;

use crate::manifest::{Component, ComponentKind, ExportedBy, Manifest, sdk_label};
use crate::permissions::{self, Level};
use crate::xml::Document;
use crate::{Package, PackageKind, Resources, decode_xml, finding, listed, metadata, netsec, redact};

/// Evidence read from a manifest attribute.
fn attr(manifest: &Artifact, path: &str, value: impl Into<serde_json::Value>) -> Evidence {
    Evidence::field(manifest, path, value)
}

fn component_evidence(manifest: &Artifact, component: &Component) -> Evidence {
    match component.offset {
        Some(offset) => Evidence::bytes(manifest, offset, 8, component.name.clone()),
        None => Evidence::field(manifest, format!("{}@android:name", component.kind.as_str()), component.name.clone()),
    }
}

pub fn identity(package: &Package, m: &Manifest, document: &Document, out: &mut Output) {
    let file = package.manifest;
    if let Some(name) = &m.package {
        let mut f = finding(Section::Identity, "android.package", Confidence::Verified, Severity::Info)
            .param("package", name.clone())
            .param("version_name", m.version_name.clone().unwrap_or_else(|| "?".into()))
            .param("version_code", m.version_code.map(|c| c.to_string()).unwrap_or_else(|| "?".into()))
            .param(
                "format_en",
                match package.kind {
                    PackageKind::Apk => "APK",
                    PackageKind::Folder => "APK extracted to a folder",
                    PackageKind::Bundle => "Android App Bundle",
                },
            )
            .param(
                "format_zh",
                match package.kind {
                    PackageKind::Apk => "APK",
                    PackageKind::Folder => "已解压到文件夹的 APK",
                    PackageKind::Bundle => "Android App Bundle",
                },
            )
            .evidence(attr(file, "manifest@package", name.clone()));
        if let Some(code) = m.version_code {
            f = f.evidence(attr(file, "manifest@android:versionCode", code));
        }
        if let Some(version) = &m.version_name {
            f = f.evidence(attr(file, "manifest@android:versionName", version.clone()));
        }
        out.finding(f);
    }
    if let Some(split) = &m.split {
        out.finding(
            finding(Section::Identity, "android.split-apk", Confidence::Verified, Severity::Info)
                .param("split", split.clone())
                .param("for", m.config_for_split.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| "base".into()))
                .evidence(attr(file, "manifest@split", split.clone())),
        );
    }
    if !document.anomalies.is_empty() {
        let mut f = finding(Section::Anomalies, "android.manifest-anomalies", Confidence::Verified, Severity::Medium)
            .param("count", document.anomalies.len())
            .param("anomalies", listed(&document.anomalies, 6))
            .reference("MASVS-RESILIENCE-3");
        for anomaly in document.anomalies.iter().take(10) {
            f = f.evidence(Evidence::whole(file, anomaly.clone()));
        }
        out.finding(f);
    }
    if m.split.is_some() {
        return;
    }
    if let Some(label) = m.application.as_ref().and_then(|a| a.label.as_ref()) {
        match &label.value {
            Some(value) => out.finding(
                finding(Section::Identity, "android.app-label", Confidence::Verified, Severity::Info)
                    .param("label", value.clone())
                    .param("source_en", label.reference.clone().unwrap_or_else(|| "a literal in the manifest".into()))
                    .param("source_zh", label.reference.clone().unwrap_or_else(|| "清单中的字面值".into()))
                    .evidence(attr(file, "application@android:label", label.reference.clone().unwrap_or_else(|| value.clone()))),
            ),
            None => out.limitation(
                "android.reference-unresolved",
                Some(file),
                Some(format!("application label {}", label.reference.clone().unwrap_or_default())),
            ),
        }
    }
    {
        let min = m.min_sdk.unwrap_or(1);
        let mut f = finding(Section::Identity, "android.sdk-levels", Confidence::Verified, Severity::Info)
            .param("min", sdk_label(min))
            .param(
                "target_en",
                m.target_sdk.map(sdk_label).unwrap_or_else(|| format!("{} (not declared; the minimum applies)", sdk_label(min))),
            )
            .param("target_zh", m.target_sdk.map(sdk_label).unwrap_or_else(|| format!("{}（未声明，按最低版本计）", sdk_label(min))))
            .param("compile", m.compile_sdk.map(sdk_label).unwrap_or_else(|| "?".into()));
        f = match m.min_sdk {
            Some(v) => f.evidence(attr(file, "uses-sdk@android:minSdkVersion", v)),
            None => f.evidence(attr(file, "uses-sdk@android:minSdkVersion", serde_json::Value::Null)),
        };
        if let Some(v) = m.target_sdk {
            f = f.evidence(attr(file, "uses-sdk@android:targetSdkVersion", v));
        }
        if let Some(v) = m.compile_sdk {
            f = f.evidence(attr(file, "manifest@android:compileSdkVersion", v));
        }
        out.finding(f);
    }
    // Naming the platform's own class is the same as naming none.
    if let Some(class) = m.application.as_ref().and_then(|a| a.name.as_ref()).filter(|c| *c != "android.app.Application") {
        out.finding(
            finding(Section::Identity, "android.application-class", Confidence::Verified, Severity::Info)
                .param("class", class.clone())
                .evidence(attr(file, "application@android:name", class.clone())),
        );
    }
    let launchers = m.launcher_activities();
    if !launchers.is_empty() {
        let names: Vec<&str> = launchers.iter().map(|c| c.name.as_str()).collect();
        let mut f = finding(Section::Identity, "android.launcher-activity", Confidence::Verified, Severity::Info)
            .param("activities", listed(&names, 5));
        for c in launchers.iter().take(5) {
            f = f.evidence(component_evidence(file, c));
        }
        out.finding(f);
    }
    if let Some(shared) = &m.shared_user_id {
        let system = shared.starts_with("android.uid.");
        out.finding(
            finding(
                Section::Capabilities,
                "android.shared-user-id",
                Confidence::Verified,
                if system { Severity::Medium } else { Severity::Low },
            )
            .param("uid", shared.clone())
            .evidence(attr(file, "manifest@android:sharedUserId", shared.clone())),
        );
    }
    if !m.tools_leftovers.is_empty() {
        let mut f = finding(Section::Anomalies, "android.tools-leftovers", Confidence::Verified, Severity::Info)
            .param("count", m.tools_leftovers.len())
            .param("attributes", listed(&m.tools_leftovers, 8));
        for leftover in m.tools_leftovers.iter().take(8) {
            f = f.evidence(attr(file, leftover, true));
        }
        out.finding(f);
    }
    if package.kind == PackageKind::Bundle
        && let Some(container) = package.container
    {
        let prefix = format!("{}/", container.path);
        let modules: BTreeSet<&str> = package
            .tree
            .under(&container.path)
            .into_iter()
            .filter(|a| a.parent.as_deref() == Some(container.path.as_str()))
            .filter_map(|a| a.path.strip_prefix(&prefix)?.strip_suffix("/manifest/AndroidManifest.xml"))
            .filter(|module| !module.contains('/'))
            .collect();
        let modules: Vec<&str> = modules.into_iter().collect();
        let mut f = finding(Section::Structure, "android.bundle-modules", Confidence::Verified, Severity::Info)
            .param("count", modules.len())
            .param("modules", listed(&modules, 20));
        for module in modules.iter().take(20) {
            if let Some(a) = package.tree.get(&format!("{prefix}{module}/manifest/AndroidManifest.xml")) {
                f = f.evidence(Evidence::whole(a, *module));
            }
        }
        out.finding(f);
        if modules.len() > 1 {
            out.limitation(
                "android.bundle-modules-not-analyzed",
                Some(container),
                Some(format!(
                    "only the base module is analyzed in depth; other modules: {}",
                    listed(&modules.iter().filter(|m| **m != "base").collect::<Vec<_>>(), 10)
                )),
            );
        }
    }
}

/// Reads the network security configuration the manifest points at.
fn network_security_config(package: &Package, m: &Manifest, out: &mut Output) -> Option<(netsec::NetworkSecurityConfig, &'static str)> {
    let reference = m.application.as_ref()?.network_security_config.as_ref()?;
    let Some(path) = reference.value.as_deref() else {
        out.limitation(
            "android.reference-unresolved",
            Some(package.manifest),
            Some(format!("networkSecurityConfig {}", reference.reference.clone().unwrap_or_default())),
        );
        return None;
    };
    let file = package.file(path)?;
    let bytes = package.read(path)?;
    let config = decode_xml(&bytes).and_then(|doc| netsec::parse(&doc));
    match config {
        Some(config) => {
            out.fact(file, "android.network_security_config", config.to_json());
            out.kind(file, "android-network-security-config");
            // The path is leaked to a static string only through the artifact; evidence names the artifact.
            Some((config, "network security config"))
        }
        None => {
            out.limitation("android.resource-xml-unreadable", Some(file), None);
            None
        }
    }
}

pub fn hardening(package: &Package, m: &Manifest, _resources: &Resources, out: &mut Output) {
    let file = package.manifest;
    let Some(app) = &m.application else { return };
    let target = m.effective_target_sdk();

    if app.debuggable == Some(true) {
        out.finding(
            finding(Section::Hardening, "android.debuggable", Confidence::Verified, Severity::High)
                .reference("CWE-489")
                .reference("MASVS-RESILIENCE-4")
                .evidence(attr(file, "application@android:debuggable", true)),
        );
    }
    if app.test_only == Some(true) {
        out.finding(finding(Section::Hardening, "android.test-only", Confidence::Verified, Severity::Medium).evidence(attr(
            file,
            "application@android:testOnly",
            true,
        )));
    }
    // Backup. The attribute defaults to true when it is absent.
    if app.allow_backup != Some(false) {
        let explicit = app.allow_backup == Some(true);
        let mut f = finding(
            Section::Hardening,
            "android.allow-backup",
            if explicit { Confidence::Verified } else { Confidence::Derived },
            Severity::Low,
        )
        .param("how_en", if explicit { "is set to true" } else { "is not set, and its default is true" })
        .param("how_zh", if explicit { "设为 true" } else { "未设置，默认值为 true" })
        .param(
            "rules",
            match (&app.full_backup_content, &app.data_extraction_rules) {
                (None, None) => "-".to_string(),
                (a, b) => [a.as_ref().and_then(|t| t.shown()), b.as_ref().and_then(|t| t.shown())]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(", "),
            },
        )
        .reference("MASVS-STORAGE-2")
        .evidence(attr(file, "application@android:allowBackup", json!(app.allow_backup)));
        if let Some(rules) = app.full_backup_content.as_ref().and_then(|t| t.shown()) {
            f = f.evidence(attr(file, "application@android:fullBackupContent", rules));
        }
        if let Some(rules) = app.data_extraction_rules.as_ref().and_then(|t| t.shown()) {
            f = f.evidence(attr(file, "application@android:dataExtractionRules", rules));
        }
        out.finding(f);
    }

    // Cleartext traffic: the network security config wins over the manifest attribute, which
    // wins over the default for the target SDK.
    let config = network_security_config(package, m, out);
    let default_cleartext = target <= 27;
    let (cleartext, how_en, how_zh, confidence, evidence) = match (&config, app.uses_cleartext_traffic) {
        (Some((config, _)), _) if config.base_cleartext_permitted.is_some() => (
            config.base_cleartext_permitted == Some(true),
            "the network security configuration's base-config says so",
            "网络安全配置的 base-config 如此设置",
            Confidence::Verified,
            attr(file, "application@android:networkSecurityConfig", app.network_security_config.as_ref().and_then(|t| t.shown())),
        ),
        (None, Some(value)) => (
            value,
            "android:usesCleartextTraffic is set to true",
            "android:usesCleartextTraffic 设为 true",
            Confidence::Verified,
            attr(file, "application@android:usesCleartextTraffic", value),
        ),
        _ => (
            default_cleartext,
            "nothing in the package forbids it, and apps targeting API 27 or lower allow it by default",
            "包内没有禁止明文流量的设置，而目标 API 27 及以下的应用默认允许",
            Confidence::Derived,
            attr(file, "uses-sdk@android:targetSdkVersion", json!(m.target_sdk)),
        ),
    };
    if cleartext {
        out.finding(
            finding(Section::Hardening, "android.cleartext-allowed", confidence, Severity::Medium)
                .param("how_en", how_en)
                .param("how_zh", how_zh)
                .reference("CWE-319")
                .reference("MASVS-NETWORK-1")
                .evidence(evidence),
        );
    }
    if let Some((config, _)) = &config {
        let config_file =
            app.network_security_config.as_ref().and_then(|t| t.value.as_deref()).and_then(|p| package.file(p)).unwrap_or(file);
        let cleartext_domains = config.cleartext_domains();
        if !cleartext && !cleartext_domains.is_empty() {
            let mut f = finding(Section::Hardening, "android.cleartext-domains", Confidence::Verified, Severity::Low)
                .param("count", cleartext_domains.len())
                .param("domains", listed(&cleartext_domains, 10))
                .reference("CWE-319")
                .reference("MASVS-NETWORK-1");
            for domain in cleartext_domains.iter().take(10) {
                f = f.evidence(Evidence::field(config_file, "domain-config@cleartextTrafficPermitted", *domain));
            }
            out.finding(f);
        }
        let user_domains: Vec<&str> =
            config.domain_configs.iter().filter(|c| c.trusts_user_cas).flat_map(|c| c.domains.iter().map(|(d, _)| d.as_str())).collect();
        if config.base_trusts_user_cas || !user_domains.is_empty() {
            let domains = listed(&user_domains, 10);
            out.finding(
                finding(Section::Hardening, "android.trust-user-cas", Confidence::Verified, Severity::Medium)
                    .param(
                        "scope_en",
                        if config.base_trusts_user_cas { "all connections".to_string() } else { format!("the domains {domains}") },
                    )
                    .param("scope_zh", if config.base_trusts_user_cas { "所有连接".to_string() } else { format!("域名 {domains}") })
                    .reference("CWE-295")
                    .reference("MASVS-NETWORK-1")
                    .evidence(Evidence::field(config_file, "trust-anchors/certificates@src", "user")),
            );
        }
        if !config.base_custom_anchors.is_empty() {
            out.finding(
                finding(Section::Hardening, "android.custom-trust-anchors", Confidence::Verified, Severity::Info)
                    .param("anchors", listed(&config.base_custom_anchors, 5))
                    .evidence(Evidence::field(
                        config_file,
                        "base-config/trust-anchors/certificates@src",
                        config.base_custom_anchors.join(", "),
                    )),
            );
        }
        let pinned = config.pinned_domains();
        if !pinned.is_empty() {
            let expirations: BTreeSet<&str> = config.domain_configs.iter().filter_map(|c| c.pin_expiration.as_deref()).collect();
            let mut f = finding(Section::Hardening, "android.certificate-pinning", Confidence::Verified, Severity::Info)
                .param("count", pinned.len())
                .param("domains", listed(&pinned, 10))
                .param(
                    "expiration",
                    if expirations.is_empty() { "-".to_string() } else { expirations.into_iter().collect::<Vec<_>>().join(", ") },
                )
                .reference("MASVS-NETWORK-2");
            for domain in pinned.iter().take(10) {
                f = f.evidence(Evidence::field(config_file, "domain-config/pin-set", *domain));
            }
            out.finding(f);
        }
        if config.has_debug_overrides {
            out.finding(
                finding(Section::Hardening, "android.debug-overrides", Confidence::Verified, Severity::Info)
                    .param("user_cas", config.debug_trusts_user_cas)
                    .evidence(Evidence::field(config_file, "debug-overrides", config.debug_trusts_user_cas)),
            );
        }
    }

    if let Some(extract) = app.extract_native_libs {
        out.finding(
            finding(Section::Hardening, "android.extract-native-libs", Confidence::Verified, Severity::Info)
                .param("value", extract)
                .param(
                    "meaning_en",
                    if extract {
                        "native libraries are copied out of the APK at install"
                    } else {
                        "native libraries are loaded straight from the APK, which needs them stored uncompressed and page-aligned"
                    },
                )
                .param(
                    "meaning_zh",
                    if extract {
                        "安装时把原生库从 APK 中解压出来"
                    } else {
                        "原生库不解压，直接从 APK 中加载（要求库在 APK 内不压缩并按页对齐）"
                    },
                )
                .evidence(attr(file, "application@android:extractNativeLibs", extract)),
        );
    }
    if app.request_legacy_external_storage == Some(true) {
        out.finding(
            finding(Section::Hardening, "android.legacy-external-storage", Confidence::Verified, Severity::Low)
                .reference("MASVS-STORAGE-2")
                .evidence(attr(file, "application@android:requestLegacyExternalStorage", true)),
        );
    }
    let min = m.min_sdk.unwrap_or(1);
    if min < 23 {
        out.finding(
            finding(Section::Hardening, "android.min-sdk-old", Confidence::Derived, Severity::Low)
                .param("min", sdk_label(min))
                .reference("MASVS-CODE-1")
                .evidence(attr(file, "uses-sdk@android:minSdkVersion", json!(m.min_sdk))),
        );
    }
    if target < 31 {
        out.finding(
            finding(
                Section::Hardening,
                "android.target-sdk-old",
                Confidence::Derived,
                if target < 23 { Severity::Medium } else { Severity::Low },
            )
            .param("target", sdk_label(target))
            .reference("MASVS-CODE-1")
            .evidence(attr(file, "uses-sdk@android:targetSdkVersion", json!(m.target_sdk))),
        );
    }
}

pub fn permissions(package: &Package, m: &Manifest, out: &mut Output) {
    let file = package.manifest;
    let declared: BTreeMap<&str, Option<i64>> = m.permissions.iter().map(|p| (p.name.as_str(), p.protection_level)).collect();
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    let (mut normal, mut signature, mut other) = (Vec::new(), Vec::new(), Vec::new());
    for requested in &m.uses_permissions {
        if !seen.insert(requested.name.as_str()) {
            continue;
        }
        let known = permissions::lookup(&requested.name);
        let third = permissions::third_party(&requested.name);
        let level = match (known, third, declared.get(requested.name.as_str())) {
            (Some(p), _, _) => p.level,
            (None, Some(_), _) => Level::Normal,
            (None, None, Some(Some(level))) => permissions::declared_level(*level),
            (None, None, Some(None)) => Level::Normal,
            _ => Level::Unknown,
        };
        let (en, zh) = match (known, third) {
            (Some(p), _) => (Some(p.en), Some(p.zh)),
            (None, Some((en, zh))) => (Some(en), Some(zh)),
            _ => (None, None),
        };
        rows.push(json!({
            "name": requested.name,
            "level": level.as_str(),
            "platform": known.is_some(),
            "declared_here": declared.contains_key(requested.name.as_str()),
            "max_sdk": requested.max_sdk,
            "sdk23_only": requested.sdk23,
            "never_for_location": requested.never_for_location,
            "description_en": en,
            "description_zh": zh,
        }));
        let evidence = attr(file, "uses-permission@android:name", requested.name.clone());
        match level {
            Level::Dangerous | Level::Special => {
                let rule = if level == Level::Dangerous { "android.permission-dangerous" } else { "android.permission-special" };
                let mut limits = Vec::new();
                if let Some(max) = requested.max_sdk {
                    limits.push(format!("maxSdkVersion {max}"));
                }
                if requested.never_for_location {
                    limits.push("neverForLocation".to_string());
                }
                out.finding(
                    // The request is read from the manifest; its level comes from the embedded table.
                    finding(Section::Capabilities, rule, Confidence::Derived, Severity::Low)
                        .param("permission", requested.name.clone())
                        .param("description_en", en.unwrap_or("no description"))
                        .param("description_zh", zh.unwrap_or("暂无说明"))
                        .param("limits", if limits.is_empty() { "-".to_string() } else { limits.join(", ") })
                        .reference("MASVS-PRIVACY-1")
                        .evidence(evidence),
                );
            }
            // A permission the app defines itself is covered by the finding on defined permissions.
            _ if known.is_none() && third.is_none() && declared.contains_key(requested.name.as_str()) => {}
            Level::Normal => normal.push((requested.name.as_str(), evidence)),
            Level::Signature => signature.push((requested.name.as_str(), evidence)),
            Level::Unknown => other.push((requested.name.as_str(), evidence)),
        }
    }
    let mut summarise = |rule: &str, severity: Severity, list: Vec<(&str, Evidence)>| {
        if list.is_empty() {
            return;
        }
        let names: Vec<&str> = list.iter().map(|(n, _)| *n).collect();
        let mut f = finding(Section::Capabilities, rule, Confidence::Derived, severity)
            .param("count", names.len())
            .param("permissions", listed(&names, 40));
        for (_, evidence) in list.into_iter().take(40) {
            f = f.evidence(evidence);
        }
        out.finding(f);
    };
    summarise("android.permissions-normal", Severity::Info, normal);
    summarise("android.permissions-signature", Severity::Low, signature);
    summarise("android.permissions-other", Severity::Info, other);

    if !m.permissions.is_empty() {
        let weak: Vec<&str> = m
            .permissions
            .iter()
            .filter(|p| permissions::declared_level(p.protection_level.unwrap_or(0)) != Level::Signature)
            .map(|p| p.name.as_str())
            .collect();
        let names: Vec<&str> = m.permissions.iter().map(|p| p.name.as_str()).collect();
        let mut f = finding(Section::Capabilities, "android.permissions-declared", Confidence::Verified, Severity::Info)
            .param("count", names.len())
            .param("permissions", listed(&names, 20))
            .param("not_signature", weak.len());
        for p in m.permissions.iter().take(20) {
            f = f.evidence(attr(file, format!("permission[{}]@android:protectionLevel", p.name).as_str(), json!(p.protection_level)));
        }
        out.finding(f);
    }
    if !rows.is_empty() || !m.permissions.is_empty() {
        out.fact(
            file,
            "android.permissions",
            json!({
                "requested": rows.iter().take(1000).collect::<Vec<_>>(),
                "declared": m.permissions.iter().take(1000).map(|p| json!({
                    "name": p.name,
                    "protection_level": p.protection_level,
                    "level": permissions::declared_level(p.protection_level.unwrap_or(0)).as_str(),
                    "group": p.group,
                })).collect::<Vec<_>>(),
                "truncated": rows.len() > 1000 || m.permissions.len() > 1000,
            }),
        );
    }
    if !m.uses_features.is_empty() {
        let required: Vec<&str> = m.uses_features.iter().filter(|(_, r)| *r != Some(false)).map(|(n, _)| n.as_str()).collect();
        let optional = m.uses_features.len() - required.len();
        if !required.is_empty() {
            let mut f = finding(Section::Capabilities, "android.uses-features", Confidence::Verified, Severity::Info)
                .param("count", required.len())
                .param("features", listed(&required, 20))
                .param("optional", optional);
            for name in required.iter().take(20) {
                f = f.evidence(attr(file, "uses-feature@android:name", *name));
            }
            out.finding(f);
        }
    }
    let queries = m.queries_packages.len() + m.queries_intents.len() + m.queries_providers.len();
    if queries > 0 {
        let mut f = finding(Section::Capabilities, "android.queries", Confidence::Verified, Severity::Info)
            .param("packages", m.queries_packages.len())
            .param("intents", m.queries_intents.len())
            .param("examples", listed(&m.queries_packages.iter().chain(m.queries_intents.iter()).collect::<Vec<_>>(), 10));
        for name in m.queries_packages.iter().take(10) {
            f = f.evidence(attr(file, "queries/package@android:name", name.clone()));
        }
        for intent in m.queries_intents.iter().take(10) {
            f = f.evidence(attr(file, "queries/intent", intent.clone()));
        }
        out.finding(f);
    }
}

/// Services and receivers the system binds through a signature permission: declaring one asks
/// for a capability that the user grants in system settings.
const SPECIAL_COMPONENTS: &[(&str, &str, &str, Severity)] = &[
    (
        "android.permission.BIND_ACCESSIBILITY_SERVICE",
        "an accessibility service, which once enabled can read the screen and act for the user",
        "无障碍服务：启用后可读取屏幕内容并代替用户操作",
        Severity::Medium,
    ),
    (
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
        "a notification listener, which once enabled can read every notification",
        "通知监听服务：启用后可读取所有通知",
        Severity::Low,
    ),
    (
        "android.permission.BIND_DEVICE_ADMIN",
        "a device administrator, which once activated can lock or wipe the device",
        "设备管理员：激活后可锁定或清除设备",
        Severity::Medium,
    ),
    (
        "android.permission.BIND_VPN_SERVICE",
        "a VPN service, which once approved sees and routes the device's network traffic",
        "VPN 服务：获准后可查看并转发设备的网络流量",
        Severity::Low,
    ),
    (
        "android.permission.BIND_INPUT_METHOD",
        "an input method (keyboard), which once selected sees what the user types",
        "输入法：被选用后可看到用户输入的内容",
        Severity::Low,
    ),
    (
        "android.permission.BIND_AUTOFILL_SERVICE",
        "an autofill service, which once selected sees the fields of other apps",
        "自动填充服务：被选用后可看到其他应用的输入框内容",
        Severity::Low,
    ),
    ("android.permission.BIND_SCREENING_SERVICE", "a call screening service", "来电过滤服务", Severity::Info),
    ("android.permission.BIND_INCALL_SERVICE", "an in-call service (dialer)", "通话界面服务（拨号应用）", Severity::Info),
    ("android.permission.BIND_NFC_SERVICE", "an NFC card emulation service", "NFC 卡模拟服务", Severity::Info),
    (
        "android.permission.BIND_TELECOM_CONNECTION_SERVICE",
        "a telecom connection service (places calls)",
        "电话连接服务（可拨打电话）",
        Severity::Info,
    ),
];

pub fn components(package: &Package, m: &Manifest, out: &mut Output) {
    let file = package.manifest;
    if m.components.is_empty() {
        return;
    }
    let app_permission = m.application.as_ref().and_then(|a| a.permission.as_deref());
    let count = |kind: ComponentKind| m.components.iter().filter(|c| c.kind == kind).count();
    let exported_total = m.components.iter().filter(|c| c.exported && c.enabled != Some(false)).count();
    out.finding(
        finding(Section::Capabilities, "android.components", Confidence::Verified, Severity::Info)
            .param("activities", count(ComponentKind::Activity) + count(ComponentKind::ActivityAlias))
            .param("services", count(ComponentKind::Service))
            .param("receivers", count(ComponentKind::Receiver))
            .param("providers", count(ComponentKind::Provider))
            .param("exported", exported_total)
            .evidence(Evidence::whole(file, m.components.len())),
    );

    // Whether a permission keeps ordinary apps out: only signature-level ones do.
    let declared: BTreeMap<&str, Option<i64>> = m.permissions.iter().map(|p| (p.name.as_str(), p.protection_level)).collect();
    let strong_guard = |permission: Option<&str>| -> bool {
        let Some(permission) = permission else { return false };
        match (permissions::lookup(permission), declared.get(permission)) {
            (Some(p), _) => p.level == Level::Signature,
            (None, Some(level)) => permissions::declared_level(level.unwrap_or(0)) == Level::Signature,
            // A permission defined elsewhere: its level is not known here. Treat it as a guard.
            (None, None) => true,
        }
    };

    for (kind, rule, severity) in [
        (ComponentKind::Activity, "android.exported-activities", Severity::Low),
        (ComponentKind::Service, "android.exported-services", Severity::Low),
        (ComponentKind::Receiver, "android.exported-receivers", Severity::Low),
        (ComponentKind::Provider, "android.exported-providers", Severity::Medium),
    ] {
        let open: Vec<&Component> = m
            .components
            .iter()
            .filter(|c| c.kind == kind || (kind == ComponentKind::Activity && c.kind == ComponentKind::ActivityAlias))
            .filter(|c| c.exported && c.enabled != Some(false) && !c.is_launcher())
            .filter(|c| {
                if kind == ComponentKind::Provider {
                    !strong_guard(c.guard(app_permission))
                        && !(strong_guard(c.read_permission.as_deref()) && strong_guard(c.write_permission.as_deref()))
                } else {
                    !strong_guard(c.guard(app_permission))
                }
            })
            .collect();
        if open.is_empty() {
            continue;
        }
        let names: Vec<&str> = open.iter().map(|c| c.name.as_str()).collect();
        let mut f = finding(Section::Capabilities, rule, Confidence::Derived, severity)
            .param("count", open.len())
            .param("components", listed(&names, 15))
            .reference("CWE-926")
            .reference("MASVS-PLATFORM-1");
        for c in open.iter().take(25) {
            f = f.evidence(component_evidence(file, c));
        }
        out.finding(f);
    }

    let implicit: Vec<&Component> = m.components.iter().filter(|c| c.exported_by == ExportedBy::IntentFilter).collect();
    if !implicit.is_empty() {
        let target = m.effective_target_sdk();
        let names: Vec<&str> = implicit.iter().map(|c| c.name.as_str()).collect();
        let mut f = finding(
            Section::Anomalies,
            "android.implicit-export",
            Confidence::Derived,
            if target >= 31 { Severity::Medium } else { Severity::Low },
        )
        .param("count", implicit.len())
        .param("components", listed(&names, 10))
        .param("target", sdk_label(target))
        .reference("CWE-926")
        .reference("MASVS-PLATFORM-1");
        for c in implicit.iter().take(15) {
            f = f.evidence(component_evidence(file, c));
        }
        out.finding(f);
    }

    for c in &m.components {
        if let Some((_, en, zh, severity)) =
            SPECIAL_COMPONENTS.iter().find(|(permission, _, _, _)| c.permission.as_deref() == Some(*permission))
        {
            out.finding(
                finding(Section::Capabilities, "android.special-component", Confidence::Verified, *severity)
                    .param("component", c.name.clone())
                    .param("what_en", *en)
                    .param("what_zh", *zh)
                    .reference("MASVS-PLATFORM-1")
                    .evidence(component_evidence(file, c))
                    .evidence(attr(file, format!("{}[{}]@android:permission", c.kind.as_str(), c.name).as_str(), c.permission.clone())),
            );
        }
        if c.kind == ComponentKind::Provider && c.grant_uri_permissions == Some(true) && c.exported {
            out.finding(
                finding(Section::Capabilities, "android.provider-grant-uri", Confidence::Verified, Severity::Low)
                    .param("provider", c.name.clone())
                    .param("authorities", c.authorities.join(", "))
                    .reference("MASVS-PLATFORM-1")
                    .evidence(component_evidence(file, c)),
            );
        }
    }

    // Deep links: what URLs open the app.
    let mut links: BTreeSet<String> = BTreeSet::new();
    let mut custom_schemes: BTreeSet<String> = BTreeSet::new();
    let mut verified_hosts: BTreeSet<String> = BTreeSet::new();
    let mut link_evidence: Vec<Evidence> = Vec::new();
    for c in
        m.components.iter().filter(|c| matches!(c.kind, ComponentKind::Activity | ComponentKind::ActivityAlias) && c.enabled != Some(false))
    {
        let mut any = false;
        for filter in c.intent_filters.iter().filter(|f| f.is_browsable() || f.actions.iter().any(|a| a == "android.intent.action.VIEW")) {
            let schemes: BTreeSet<&str> = filter.data.iter().filter_map(|d| d.scheme.as_deref()).collect();
            let hosts: Vec<&str> = filter.data.iter().filter_map(|d| d.host.as_deref()).collect();
            let paths: Vec<&str> =
                filter.data.iter().filter_map(|d| d.path.as_deref().or(d.path_prefix.as_deref()).or(d.path_pattern.as_deref())).collect();
            for scheme in &schemes {
                if matches!(*scheme, "content" | "file") {
                    continue;
                }
                any = true;
                let web = matches!(*scheme, "http" | "https");
                if !web {
                    custom_schemes.insert((*scheme).to_string());
                }
                if hosts.is_empty() {
                    links.insert(format!("{scheme}://"));
                }
                for host in &hosts {
                    if web && filter.auto_verify == Some(true) {
                        verified_hosts.insert((*host).to_string());
                    }
                    if links.len() < 500 {
                        links.insert(format!("{scheme}://{host}{}", paths.first().copied().unwrap_or("")));
                    }
                }
            }
        }
        if any && link_evidence.len() < 20 {
            link_evidence.push(component_evidence(file, c));
        }
    }
    if !links.is_empty() {
        let list: Vec<&String> = links.iter().collect();
        let mut f = finding(Section::Capabilities, "android.deep-links", Confidence::Verified, Severity::Info)
            .param("count", links.len())
            .param("links", listed(&list, 15))
            .param(
                "custom_schemes",
                if custom_schemes.is_empty() { "-".to_string() } else { listed(&custom_schemes.iter().collect::<Vec<_>>(), 15) },
            )
            .param(
                "verified_hosts",
                if verified_hosts.is_empty() { "-".to_string() } else { listed(&verified_hosts.iter().collect::<Vec<_>>(), 15) },
            )
            .reference("MASVS-PLATFORM-1");
        for evidence in link_evidence {
            f = f.evidence(evidence);
        }
        out.finding(f);
        out.fact(
            file,
            "android.deep_links",
            json!({
                "links": links.iter().take(500).collect::<Vec<_>>(),
                "custom_schemes": custom_schemes,
                "app_link_hosts": verified_hosts,
                "truncated": links.len() >= 500,
            }),
        );
    }

    // Task affinity pointing at another app's package is how task hijacking is set up.
    let own = m.package.as_deref().unwrap_or("");
    let foreign: Vec<&Component> = m
        .components
        .iter()
        .filter(|c| matches!(c.kind, ComponentKind::Activity))
        .filter(|c| {
            c.task_affinity.as_deref().is_some_and(|a| {
                !a.is_empty() && !own.is_empty() && !a.starts_with(own) && a.contains('.') && !a.starts_with(':') && !a.starts_with('.')
            })
        })
        .filter(|c| matches!(c.launch_mode, Some(2..=4)))
        .collect();
    if !foreign.is_empty() {
        let shown: Vec<String> = foreign.iter().map(|c| format!("{} → {}", c.name, c.task_affinity.as_deref().unwrap_or(""))).collect();
        let mut f = finding(Section::Anomalies, "android.task-affinity", Confidence::Heuristic, Severity::Low)
            .param("count", foreign.len())
            .param("activities", listed(&shown, 5))
            .reference("MASVS-PLATFORM-3");
        for c in foreign.iter().take(10) {
            f = f.evidence(component_evidence(file, c));
        }
        out.finding(f);
    }
}

/// Keys and identifiers in meta-data and in the resource strings the google-services plugin writes.
pub fn keys(package: &Package, m: &Manifest, resources: &Resources, out: &mut Output) {
    let file = package.manifest;
    let mut all: Vec<&crate::manifest::MetaData> = m.application.iter().flat_map(|a| a.meta_data.iter()).collect();
    all.extend(m.components.iter().flat_map(|c| c.meta_data.iter()));
    let mut identifiers = Vec::new();
    let mut seen = BTreeSet::new();
    for meta in all {
        let Some(kind) = metadata::classify(&meta.name) else { continue };
        let Some(value) = meta.value.as_ref().and_then(|v| v.value.as_deref()) else { continue };
        if !seen.insert((meta.name.as_str(), value)) {
            continue;
        }
        // Booleans and short numbers under key-like names are settings, not keys.
        if kind.secret && value.len() >= 8 && value != "true" && value != "false" {
            let redacted = redact(value);
            out.finding(
                finding(Section::Secrets, "android.metadata-key", Confidence::Heuristic, Severity::Low)
                    .param("name", meta.name.clone())
                    .param("what", kind.what)
                    .param("redacted", redacted.clone())
                    .reference("CWE-798")
                    .evidence(attr(file, format!("meta-data[{}]@android:value", meta.name).as_str(), redacted)),
            );
        } else if !kind.secret {
            identifiers.push((meta.name.clone(), kind.what, value.to_string()));
        }
    }
    let names: Vec<&str> = metadata::GOOGLE_SERVICES.iter().map(|(n, _)| *n).collect();
    let strings = resources.find_strings(&names);
    let resource_file = package.file("resources.arsc").or_else(|| package.file("resources.pb"));
    let mut google = serde_json::Map::new();
    if let Some(resource_file) = resource_file {
        for (name, kind) in metadata::GOOGLE_SERVICES {
            let Some(value) = strings.get(*name) else { continue };
            if kind.secret {
                let redacted = redact(value);
                google.insert((*name).to_string(), json!(redacted));
                out.finding(
                    finding(Section::Secrets, "android.google-api-key", Confidence::Heuristic, Severity::Low)
                        .param("name", *name)
                        .param("redacted", redacted.clone())
                        .reference("CWE-798")
                        .evidence(Evidence::field(resource_file, format!("string/{name}"), redacted)),
                );
            } else {
                google.insert((*name).to_string(), json!(value));
            }
        }
        if !google.is_empty() {
            out.fact(resource_file, "android.google_services", serde_json::Value::Object(google.clone()));
            let shown: Vec<String> = google.iter().map(|(k, v)| format!("{k}={}", v.as_str().unwrap_or(""))).collect();
            let mut f = finding(Section::Network, "android.firebase-config", Confidence::Verified, Severity::Info)
                .param("values", listed(&shown, 8));
            for (name, value) in google.iter().take(8) {
                f = f.evidence(Evidence::field(resource_file, format!("string/{name}"), value.clone()));
            }
            out.finding(f);
        }
    }
    if !identifiers.is_empty() {
        let shown: Vec<String> = identifiers.iter().map(|(n, what, v)| format!("{what}: {v} ({n})")).collect();
        let mut f = finding(Section::Composition, "android.sdk-identifiers", Confidence::Verified, Severity::Info)
            .param("count", identifiers.len())
            .param("values", listed(&shown, 8));
        for (name, _, value) in identifiers.iter().take(8) {
            f = f.evidence(attr(file, format!("meta-data[{name}]@android:value").as_str(), value.clone()));
        }
        out.finding(f);
    }
}

pub fn resources_fact(package: &Package, resources: &Resources, out: &mut Output) {
    match resources {
        Resources::Arsc(table) => {
            let Some(file) = package.file("resources.arsc") else { return };
            out.kind(file, "android-resources");
            out.fact(
                file,
                "android.resources",
                json!({
                    "format": "arsc",
                    "packages": table.packages().iter().map(|(id, name)| json!({ "id": id, "name": name })).collect::<Vec<_>>(),
                    "type_chunks": table.type_chunks(),
                    "anomalies": table.anomalies.iter().take(20).collect::<Vec<_>>(),
                    "truncated": table.truncated,
                }),
            );
            if !table.anomalies.is_empty() || table.truncated {
                let mut f = finding(Section::Anomalies, "android.resources-anomalies", Confidence::Verified, Severity::Low)
                    .param("count", table.anomalies.len())
                    .param("anomalies", listed(&table.anomalies, 4));
                for anomaly in table.anomalies.iter().take(8) {
                    f = f.evidence(Evidence::whole(file, anomaly.clone()));
                }
                if table.anomalies.is_empty() {
                    f = f.evidence(Evidence::whole(file, "the table could not be read to its end"));
                }
                out.finding(f);
            }
        }
        Resources::Proto(table) => {
            let Some(file) = package.file("resources.pb") else { return };
            out.kind(file, "android-resources");
            out.fact(
                file,
                "android.resources",
                json!({ "format": "protobuf", "entries": table.entry_count(), "truncated": table.truncated }),
            );
        }
        Resources::None => {}
    }
}
