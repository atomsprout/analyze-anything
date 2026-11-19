//! Findings read from a bundle's `Info.plist`: identity, declared capabilities, transport
//! security settings.

use aa_core::plugin::Output;
use aa_core::{Confidence, Evidence, Finding, Section, Severity};
use plist::{Dictionary, Value};
use serde_json::json;

use crate::bundle::{Bundle, strings, truthy};
use crate::codesign::plist_to_json;

/// Items of a list shown in a finding's sentence before "…".
const SHOWN: usize = 12;
/// Exception domains reported one by one.
const MAX_DOMAINS: usize = 30;

pub fn finding(section: Section, rule: &str, confidence: Confidence, severity: Severity) -> Finding {
    Finding::new(section, crate::analyzer::ID, rule, confidence, severity)
}

/// A finding about `bundle`, which the rule's sentence names as `{bundle}`.
fn found_in(bundle: &Bundle<'_>, section: Section, rule: &str, confidence: Confidence, severity: Severity) -> Finding {
    finding(section, rule, confidence, severity).param("bundle", bundle.name())
}

/// Joins the first few items; the rest are counted.
pub fn shown(items: &[String]) -> String {
    let mut text = items.iter().take(SHOWN).cloned().collect::<Vec<_>>().join(", ");
    if items.len() > SHOWN {
        text.push_str(&format!(", … (+{})", items.len() - SHOWN));
    }
    text
}

fn text_of(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Integer(number) => Some(number.to_string()),
        Value::Real(number) => Some(number.to_string()),
        _ => None,
    }
}

fn device_family(id: i64) -> String {
    match id {
        1 => "iPhone".into(),
        2 => "iPad".into(),
        3 => "Apple TV".into(),
        4 => "Apple Watch".into(),
        6 => "Mac".into(),
        7 => "Apple Vision".into(),
        other => format!("family {other}"),
    }
}

/// Identity findings. Returns the bundle identifier when the plist has one.
pub fn identity(bundle: &Bundle<'_>, plist: &Dictionary, out: &mut Output) -> Option<String> {
    let info = bundle.info;
    let field = |key: &str| plist.get(key).and_then(text_of).filter(|text| !text.is_empty());
    let bundle_id = field("CFBundleIdentifier");
    match &bundle_id {
        Some(id) => out.finding(
            found_in(bundle, Section::Identity, "apple.bundle-id", Confidence::Verified, Severity::Info)
                .param("kind", bundle.kind())
                .param("bundle_id", id.as_str())
                .evidence(Evidence::field(info, "CFBundleIdentifier", id.as_str())),
        ),
        None => {
            out.finding(
                found_in(bundle, Section::Anomalies, "apple.bundle-id-missing", Confidence::Verified, Severity::Low)
                    .evidence(Evidence::field(info, "CFBundleIdentifier", serde_json::Value::Null)),
            )
        }
    }
    let names: Vec<(&str, String)> =
        ["CFBundleDisplayName", "CFBundleName"].into_iter().filter_map(|key| Some((key, field(key)?))).collect();
    if let Some((_, name)) = names.first() {
        let mut found =
            found_in(bundle, Section::Identity, "apple.bundle-name", Confidence::Verified, Severity::Info).param("name", name.as_str());
        for (key, value) in &names {
            found = found.evidence(Evidence::field(info, *key, value.as_str()));
        }
        out.finding(found);
    }
    let (short, build) = (field("CFBundleShortVersionString"), field("CFBundleVersion"));
    let version = match (&short, &build) {
        (Some(short), Some(build)) => Some(format!("{short} (build {build})")),
        (Some(short), None) => Some(short.clone()),
        (None, Some(build)) => Some(format!("build {build}")),
        (None, None) => None,
    };
    if let Some(version) = version {
        let mut found =
            found_in(bundle, Section::Identity, "apple.bundle-version", Confidence::Verified, Severity::Info).param("version", version);
        for (key, value) in [("CFBundleShortVersionString", &short), ("CFBundleVersion", &build)] {
            if let Some(value) = value {
                found = found.evidence(Evidence::field(info, key, value.as_str()));
            }
        }
        out.finding(found);
    }

    let platforms = strings(plist.get("CFBundleSupportedPlatforms"));
    for (key, default_platform) in [("MinimumOSVersion", "iOS"), ("LSMinimumSystemVersion", "macOS")] {
        if let Some(version) = field(key) {
            let platform = match (key, platforms.first().map(String::as_str)) {
                ("MinimumOSVersion", Some("iPhoneOS" | "iPhoneSimulator")) => "iOS",
                ("MinimumOSVersion", Some("AppleTVOS" | "AppleTVSimulator")) => "tvOS",
                ("MinimumOSVersion", Some("WatchOS" | "WatchSimulator")) => "watchOS",
                ("MinimumOSVersion", Some("XROS" | "XRSimulator")) => "visionOS",
                _ => default_platform,
            };
            out.finding(
                found_in(bundle, Section::Identity, "apple.min-os", Confidence::Verified, Severity::Info)
                    .param("platform", platform)
                    .param("version", version.as_str())
                    .evidence(Evidence::field(info, key, version.as_str())),
            );
        }
    }
    if !platforms.is_empty() {
        out.finding(
            found_in(bundle, Section::Identity, "apple.supported-platforms", Confidence::Verified, Severity::Info)
                .param("platforms", platforms.join(", "))
                .evidence(Evidence::field(info, "CFBundleSupportedPlatforms", json!(platforms))),
        );
    }
    let families: Vec<String> = plist
        .get("UIDeviceFamily")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(|v| v.as_signed_integer()).map(device_family).collect())
        .unwrap_or_default();
    if !families.is_empty() {
        out.finding(
            found_in(bundle, Section::Identity, "apple.device-families", Confidence::Verified, Severity::Info)
                .param("families", families.join(", "))
                .evidence(Evidence::field(info, "UIDeviceFamily", plist.get("UIDeviceFamily").map(plist_to_json).unwrap_or_default())),
        );
    }
    for (key, rule) in [("LSApplicationCategoryType", "apple.app-category"), ("NSHumanReadableCopyright", "apple.copyright")] {
        if let Some(value) = field(key) {
            out.finding(
                found_in(bundle, Section::Identity, rule, Confidence::Verified, Severity::Info)
                    .param("value", value.as_str())
                    .evidence(Evidence::field(info, key, value.as_str())),
            );
        }
    }

    // How it was built.
    let build_keys = [
        ("DTXcode", "Xcode"),
        ("DTXcodeBuild", "Xcode build"),
        ("DTSDKName", "SDK"),
        ("DTSDKBuild", "SDK build"),
        ("DTPlatformName", "platform"),
        ("DTPlatformVersion", "platform version"),
        ("DTPlatformBuild", "platform build"),
        ("DTCompiler", "compiler"),
        ("BuildMachineOSBuild", "build machine OS"),
    ];
    let present: Vec<(&str, &str, String)> = build_keys.iter().filter_map(|(key, label)| Some((*key, *label, field(key)?))).collect();
    if !present.is_empty() {
        let details = present.iter().map(|(_, label, value)| format!("{label} {value}")).collect::<Vec<_>>().join(", ");
        let mut found =
            found_in(bundle, Section::Composition, "apple.build-info", Confidence::Verified, Severity::Info).param("details", details);
        for (key, _, value) in &present {
            found = found.evidence(Evidence::field(info, *key, value.as_str()));
        }
        out.finding(found);
    }
    bundle_id
}

/// The human name of what an `NS…UsageDescription` key guards.
fn usage_resource(key: &str) -> String {
    let core = key.strip_prefix("NS").unwrap_or(key).strip_suffix("UsageDescription").unwrap_or(key);
    // Split CamelCase: "LocationWhenInUse" -> "Location When In Use".
    let mut out = String::new();
    let characters: Vec<char> = core.chars().collect();
    for (index, character) in characters.iter().enumerate() {
        let lower_before = index > 0 && characters[index - 1].is_lowercase();
        let lower_after = characters.get(index + 1).is_some_and(|next| next.is_lowercase());
        if index > 0 && character.is_uppercase() && (lower_before || lower_after) {
            out.push(' ');
        }
        out.push(*character);
    }
    out
}

/// Declared capabilities: usage descriptions, URL schemes, document types, background modes.
pub fn capabilities(bundle: &Bundle<'_>, plist: &Dictionary, out: &mut Output) {
    let info = bundle.info;
    let mut usage: Vec<(&String, &Value)> = plist.iter().filter(|(key, _)| key.ends_with("UsageDescription")).collect();
    usage.sort_by(|a, b| a.0.cmp(b.0));
    for (key, value) in usage {
        let purpose = text_of(value).unwrap_or_default();
        let rule = if purpose.trim().is_empty() { "apple.usage-description-empty" } else { "apple.usage-description" };
        out.finding(
            found_in(bundle, Section::Capabilities, rule, Confidence::Verified, Severity::Info)
                .param("key", key.as_str())
                .param("resource", usage_resource(key))
                .param("purpose", purpose.as_str())
                .reference("MASVS-PRIVACY-1")
                .evidence(Evidence::field(info, key.as_str(), purpose.as_str())),
        );
    }

    let mut schemes: Vec<String> = Vec::new();
    for entry in plist.get("CFBundleURLTypes").and_then(Value::as_array).into_iter().flatten() {
        schemes.extend(strings(entry.as_dictionary().and_then(|d| d.get("CFBundleURLSchemes"))));
    }
    schemes.sort();
    schemes.dedup();
    if !schemes.is_empty() {
        out.finding(
            found_in(bundle, Section::Capabilities, "apple.url-schemes", Confidence::Verified, Severity::Info)
                .param("count", schemes.len())
                .param("schemes", shown(&schemes))
                .reference("MASVS-PLATFORM-1")
                .evidence(Evidence::field(info, "CFBundleURLTypes[].CFBundleURLSchemes", json!(schemes))),
        );
    }
    let queried = strings(plist.get("LSApplicationQueriesSchemes"));
    if !queried.is_empty() {
        out.finding(
            found_in(bundle, Section::Capabilities, "apple.queried-schemes", Confidence::Verified, Severity::Info)
                .param("count", queried.len())
                .param("schemes", shown(&queried))
                .evidence(Evidence::field(info, "LSApplicationQueriesSchemes", json!(queried))),
        );
    }

    let mut documents: Vec<String> = Vec::new();
    for entry in plist.get("CFBundleDocumentTypes").and_then(Value::as_array).into_iter().flatten() {
        let Some(entry) = entry.as_dictionary() else { continue };
        let name = entry.get("CFBundleTypeName").and_then(Value::as_string).unwrap_or("");
        let mut accepted = strings(entry.get("LSItemContentTypes"));
        accepted.extend(strings(entry.get("CFBundleTypeExtensions")).into_iter().map(|e| format!(".{e}")));
        documents.push(match (name.is_empty(), accepted.is_empty()) {
            (false, false) => format!("{name} [{}]", accepted.join(" ")),
            (false, true) => name.to_string(),
            (true, _) => format!("[{}]", accepted.join(" ")),
        });
    }
    if !documents.is_empty() {
        out.finding(
            found_in(bundle, Section::Capabilities, "apple.document-types", Confidence::Verified, Severity::Info)
                .param("count", documents.len())
                .param("types", shown(&documents))
                .evidence(Evidence::field(info, "CFBundleDocumentTypes", json!(documents))),
        );
    }
    for (key, rule) in [("UTExportedTypeDeclarations", "apple.exported-types"), ("UTImportedTypeDeclarations", "apple.imported-types")] {
        let identifiers: Vec<String> = plist
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|entry| entry.as_dictionary()?.get("UTTypeIdentifier")?.as_string().map(str::to_string))
            .collect();
        if !identifiers.is_empty() {
            out.finding(
                found_in(bundle, Section::Capabilities, rule, Confidence::Verified, Severity::Info)
                    .param("count", identifiers.len())
                    .param("types", shown(&identifiers))
                    .evidence(Evidence::field(info, key, json!(identifiers))),
            );
        }
    }
    let modes = strings(plist.get("UIBackgroundModes"));
    if !modes.is_empty() {
        out.finding(
            found_in(bundle, Section::Capabilities, "apple.background-modes", Confidence::Verified, Severity::Info)
                .param("modes", modes.join(", "))
                .evidence(Evidence::field(info, "UIBackgroundModes", json!(modes))),
        );
    }
    // An array of names, or a dictionary of name -> required.
    let required: Vec<String> = match plist.get("UIRequiredDeviceCapabilities") {
        Some(Value::Array(_)) => strings(plist.get("UIRequiredDeviceCapabilities")),
        Some(Value::Dictionary(entries)) => entries.iter().filter(|(_, v)| truthy(Some(v)) == Some(true)).map(|(k, _)| k.clone()).collect(),
        _ => Vec::new(),
    };
    if !required.is_empty() {
        out.finding(
            found_in(bundle, Section::Capabilities, "apple.required-capabilities", Confidence::Verified, Severity::Info)
                .param("capabilities", required.join(", "))
                .evidence(Evidence::field(info, "UIRequiredDeviceCapabilities", json!(required))),
        );
    }
    for (key, rule) in [
        ("LSUIElement", "apple.agent-app"),
        ("LSBackgroundOnly", "apple.background-only"),
        ("UIFileSharingEnabled", "apple.file-sharing"),
        ("LSSupportsOpeningDocumentsInPlace", "apple.open-in-place"),
        ("NSAppleScriptEnabled", "apple.scriptable"),
    ] {
        if truthy(plist.get(key)) == Some(true) {
            out.finding(
                found_in(bundle, Section::Capabilities, rule, Confidence::Verified, Severity::Info)
                    .param("key", key)
                    .evidence(Evidence::field(info, key, true)),
            );
        }
    }
    extension_point(bundle, plist, out);
    if let Some(feed) = plist.get("SUFeedURL").and_then(Value::as_string) {
        let signed = plist.contains_key("SUPublicEDKey") || plist.contains_key("SUPublicDSAKeyFile");
        let insecure = feed.to_ascii_lowercase().starts_with("http://");
        let mut found = found_in(
            bundle,
            Section::Network,
            if insecure { "apple.update-feed-http" } else { "apple.update-feed" },
            Confidence::Verified,
            if insecure { Severity::Low } else { Severity::Info },
        )
        .param("url", feed)
        .param("signed_updates", signed)
        .evidence(Evidence::field(info, "SUFeedURL", feed));
        if insecure {
            found = found.reference("CWE-319");
        }
        out.finding(found);
    }
}

/// The extension point an app extension plugs into.
pub fn extension_point(bundle: &Bundle<'_>, plist: &Dictionary, out: &mut Output) {
    if let Some(extension) = plist.get("NSExtension").and_then(Value::as_dictionary)
        && let Some(point) = extension.get("NSExtensionPointIdentifier").and_then(Value::as_string)
    {
        out.finding(
            found_in(bundle, Section::Capabilities, "apple.extension-point", Confidence::Verified, Severity::Info)
                .param("point", point)
                .evidence(Evidence::field(bundle.info, "NSExtension.NSExtensionPointIdentifier", point)),
        );
    }
}

/// App Transport Security settings that weaken the default (HTTPS with TLS 1.2 and forward secrecy).
pub fn transport_security(bundle: &Bundle<'_>, plist: &Dictionary, out: &mut Output) {
    let info = bundle.info;
    let Some(ats) = plist.get("NSAppTransportSecurity").and_then(Value::as_dictionary) else { return };
    out.fact(info, "apple.ats", plist_to_json(&Value::Dictionary(ats.clone())));
    if truthy(ats.get("NSAllowsArbitraryLoads")) == Some(true) {
        // Since iOS 10 the narrower keys, when present, take the place of the global switch.
        let narrowed: Vec<&str> = ["NSAllowsArbitraryLoadsInWebContent", "NSAllowsArbitraryLoadsForMedia", "NSAllowsLocalNetworking"]
            .into_iter()
            .filter(|key| ats.contains_key(key))
            .collect();
        let rule = if narrowed.is_empty() { "apple.ats-arbitrary-loads" } else { "apple.ats-arbitrary-loads-narrowed" };
        out.finding(
            found_in(
                bundle,
                Section::Hardening,
                rule,
                Confidence::Verified,
                if narrowed.is_empty() { Severity::Medium } else { Severity::Low },
            )
            .param("narrowed_by", narrowed.join(", "))
            .reference("MASVS-NETWORK-1")
            .reference("CWE-319")
            .evidence(Evidence::field(info, "NSAppTransportSecurity.NSAllowsArbitraryLoads", true)),
        );
    }
    for key in ["NSAllowsArbitraryLoadsInWebContent", "NSAllowsArbitraryLoadsForMedia"] {
        if truthy(ats.get(key)) == Some(true) {
            out.finding(
                found_in(bundle, Section::Hardening, "apple.ats-relaxed", Confidence::Verified, Severity::Low)
                    .param("key", key)
                    .reference("MASVS-NETWORK-1")
                    .reference("CWE-319")
                    .evidence(Evidence::field(info, format!("NSAppTransportSecurity.{key}"), true)),
            );
        }
    }
    if truthy(ats.get("NSAllowsLocalNetworking")) == Some(true) {
        out.finding(
            found_in(bundle, Section::Hardening, "apple.ats-local-networking", Confidence::Verified, Severity::Info)
                .evidence(Evidence::field(info, "NSAppTransportSecurity.NSAllowsLocalNetworking", true)),
        );
    }
    let Some(domains) = ats.get("NSExceptionDomains").and_then(Value::as_dictionary) else { return };
    let mut names: Vec<&String> = domains.keys().collect();
    names.sort();
    let mut reported = 0usize;
    let mut unreported = 0usize;
    for name in names {
        let Some(settings) = domains.get(name).and_then(Value::as_dictionary) else { continue };
        let subdomains = truthy(settings.get("NSIncludesSubdomains")) == Some(true);
        let path = |key: &str| format!("NSAppTransportSecurity.NSExceptionDomains.{name}.{key}");
        let mut emit = |found: Finding, out: &mut Output| {
            if reported < MAX_DOMAINS {
                reported += 1;
                out.finding(found.param("domain", name.as_str()).param("subdomains", subdomains));
            } else {
                unreported += 1;
            }
        };
        let insecure_keys = [
            "NSExceptionAllowsInsecureHTTPLoads",
            "NSTemporaryExceptionAllowsInsecureHTTPLoads",
            "NSThirdPartyExceptionAllowsInsecureHTTPLoads",
        ];
        if let Some(key) = insecure_keys.into_iter().find(|key| truthy(settings.get(key)) == Some(true)) {
            emit(
                found_in(bundle, Section::Hardening, "apple.ats-insecure-domain", Confidence::Verified, Severity::Low)
                    .reference("MASVS-NETWORK-1")
                    .reference("CWE-319")
                    .evidence(Evidence::field(info, path(key), true)),
                out,
            );
        }
        let tls_keys = ["NSExceptionMinimumTLSVersion", "NSTemporaryExceptionMinimumTLSVersion", "NSThirdPartyExceptionMinimumTLSVersion"];
        if let Some((key, version)) = tls_keys.into_iter().find_map(|key| Some((key, settings.get(key)?.as_string()?)))
            && matches!(version, "TLSv1.0" | "TLSv1.1")
        {
            emit(
                found_in(bundle, Section::Hardening, "apple.ats-weak-tls", Confidence::Verified, Severity::Low)
                    .param("version", version)
                    .reference("MASVS-NETWORK-1")
                    .reference("CWE-326")
                    .evidence(Evidence::field(info, path(key), version)),
                out,
            );
        }
        let secrecy_keys = [
            "NSExceptionRequiresForwardSecrecy",
            "NSTemporaryExceptionRequiresForwardSecrecy",
            "NSThirdPartyExceptionRequiresForwardSecrecy",
        ];
        if let Some(key) = secrecy_keys.into_iter().find(|key| truthy(settings.get(key)) == Some(false)) {
            emit(
                found_in(bundle, Section::Hardening, "apple.ats-no-forward-secrecy", Confidence::Verified, Severity::Info)
                    .reference("MASVS-NETWORK-1")
                    .evidence(Evidence::field(info, path(key), false)),
                out,
            );
        }
    }
    if unreported > 0 {
        out.limitation(
            "apple.findings-capped",
            Some(info),
            Some(format!("{unreported} more App Transport Security exceptions are in the apple.ats fact")),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_keys_become_readable() {
        assert_eq!(usage_resource("NSCameraUsageDescription"), "Camera");
        assert_eq!(usage_resource("NSLocationWhenInUseUsageDescription"), "Location When In Use");
        assert_eq!(usage_resource("NSPhotoLibraryAddUsageDescription"), "Photo Library Add");
        assert_eq!(usage_resource("NFCReaderUsageDescription"), "NFC Reader");
        assert_eq!(usage_resource("NSFaceIDUsageDescription"), "Face ID");
    }

    #[test]
    fn long_lists_are_cut_with_a_count() {
        let items: Vec<String> = (0..15).map(|i| i.to_string()).collect();
        assert!(shown(&items).ends_with("… (+3)"));
        assert_eq!(shown(&items[..2]), "0, 1");
    }
}
