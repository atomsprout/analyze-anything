//! Findings about what a bundle is made of and what surrounds it: privacy manifests, embedded
//! code, the framework it was built with, IPA wrappers, disk images and installer packages.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::plugin::{Output, Tree};
use aa_core::{Artifact, Confidence, Evidence, Section, Severity};
use plist::Value as Plist;
use serde_json::{Value, json};

use crate::bundle::{Bundle, read_plist, strings, truthy};
use crate::codesign::plist_to_json;
use crate::info::{finding, shown};
use crate::signing::{main_slice, slices};

const MAX_MANIFESTS: usize = 40;
const MAX_LISTED: usize = 200;

/// Reports the privacy manifests (`PrivacyInfo.xcprivacy`) in and below `bundle`.
pub fn privacy(tree: &dyn Tree, bundle: &Bundle<'_>, out: &mut Output) {
    let manifests: Vec<&Artifact> = tree.under(&bundle.dir).into_iter().filter(|a| a.name() == "PrivacyInfo.xcprivacy").collect();
    if manifests.len() > MAX_MANIFESTS {
        out.limitation(
            "apple.findings-capped",
            Some(bundle.info),
            Some(format!("{} privacy manifests; the first {MAX_MANIFESTS} were reported", manifests.len())),
        );
    }
    for file in manifests.into_iter().take(MAX_MANIFESTS) {
        out.kind(file, "privacy-manifest");
        let plist = match read_plist(tree, file) {
            Ok(plist) => plist,
            Err(error) => {
                out.limitation("apple.plist-unreadable", Some(file), Some(error));
                continue;
            }
        };
        let Some(dictionary) = plist.as_dictionary() else { continue };
        out.fact(file, "apple.privacy-manifest", plist_to_json(&plist));
        // The folder that owns the manifest: the app itself, or an embedded framework or bundle.
        let owner = file.path.rsplit('/').skip(1).find(|part| part.contains('.')).unwrap_or(bundle.name()).to_string();
        let tracking = truthy(dictionary.get("NSPrivacyTracking")) == Some(true);
        let domains = strings(dictionary.get("NSPrivacyTrackingDomains"));
        let entries = |key: &str| dictionary.get(key).and_then(Plist::as_array).map(Vec::as_slice).unwrap_or_default();
        let collected: Vec<String> = entries("NSPrivacyCollectedDataTypes")
            .iter()
            .filter_map(Plist::as_dictionary)
            .filter_map(|entry| {
                let kind = entry.get("NSPrivacyCollectedDataType")?.as_string()?.trim_start_matches("NSPrivacyCollectedDataType");
                let mut notes = Vec::new();
                if truthy(entry.get("NSPrivacyCollectedDataTypeLinked")) == Some(true) {
                    notes.push("linked to identity");
                }
                if truthy(entry.get("NSPrivacyCollectedDataTypeTracking")) == Some(true) {
                    notes.push("used for tracking");
                }
                Some(if notes.is_empty() { kind.to_string() } else { format!("{kind} ({})", notes.join(", ")) })
            })
            .collect();
        let apis: Vec<String> = entries("NSPrivacyAccessedAPITypes")
            .iter()
            .filter_map(Plist::as_dictionary)
            .filter_map(|entry| {
                let kind = entry.get("NSPrivacyAccessedAPIType")?.as_string()?.trim_start_matches("NSPrivacyAccessedAPICategory");
                let reasons = strings(entry.get("NSPrivacyAccessedAPITypeReasons"));
                Some(if reasons.is_empty() { kind.to_string() } else { format!("{kind} [{}]", reasons.join(" ")) })
            })
            .collect();
        out.finding(
            finding(Section::Privacy, "apple.privacy-manifest", Confidence::Verified, Severity::Info)
                .param("owner", owner.as_str())
                .param("tracking", tracking)
                .param("collected", collected.len())
                .param("apis", apis.len())
                .evidence(Evidence::field(file, "NSPrivacyTracking", tracking)),
        );
        if tracking || !domains.is_empty() {
            out.finding(
                finding(Section::Privacy, "apple.privacy-tracking", Confidence::Verified, Severity::Low)
                    .param("owner", owner.as_str())
                    .param("domains", if domains.is_empty() { "-".to_string() } else { shown(&domains) })
                    .evidence(Evidence::field(file, "NSPrivacyTracking", tracking))
                    .evidence(Evidence::field(file, "NSPrivacyTrackingDomains", json!(domains))),
            );
        }
        if !collected.is_empty() {
            out.finding(
                finding(Section::Privacy, "apple.privacy-collected-data", Confidence::Verified, Severity::Info)
                    .param("owner", owner.as_str())
                    .param("count", collected.len())
                    .param("types", shown(&collected))
                    .evidence(Evidence::field(file, "NSPrivacyCollectedDataTypes", json!(collected))),
            );
        }
        if !apis.is_empty() {
            out.finding(
                finding(Section::Privacy, "apple.privacy-required-reason-apis", Confidence::Verified, Severity::Info)
                    .param("owner", owner.as_str())
                    .param("count", apis.len())
                    .param("apis", shown(&apis))
                    .evidence(Evidence::field(file, "NSPrivacyAccessedAPITypes", json!(apis))),
            );
        }
    }
}

/// Lists the code embedded in `bundle`: nested bundles and loose dynamic libraries.
pub fn embedded(tree: &dyn Tree, bundles: &[Bundle<'_>], index: usize, out: &mut Output) {
    let bundle = &bundles[index];
    let mut listed: Vec<Value> = Vec::new();
    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut first_of_kind: BTreeMap<&'static str, &Artifact> = BTreeMap::new();
    for nested in bundles.iter().filter(|b| b.dir != bundle.dir && bundle.contains(&b.dir)) {
        let kind = if nested.kind() == "app" && nested.dir.contains("/Watch/") { "watch-app" } else { nested.kind() };
        *counts.entry(kind).or_default() += 1;
        first_of_kind.entry(kind).or_insert(nested.info);
        if listed.len() < MAX_LISTED {
            listed.push(json!({
                "path": nested.dir,
                "kind": kind,
                "bundle_id": nested.string("CFBundleIdentifier"),
                "version": nested.string("CFBundleShortVersionString"),
                "build": nested.string("CFBundleVersion"),
                "extension_point": nested.plist.as_ref().ok().and_then(|p| p.get("NSExtension")).and_then(Plist::as_dictionary)
                    .and_then(|e| e.get("NSExtensionPointIdentifier")).and_then(Plist::as_string),
            }));
        }
    }
    let in_nested = |path: &str| bundles.iter().any(|b| b.dir != bundle.dir && bundle.contains(&b.dir) && b.contains(path));
    for artifact in tree.under(&bundle.dir) {
        if artifact.extension().as_deref() == Some("dylib") && !slices(artifact).is_empty() && !in_nested(&artifact.path) {
            *counts.entry("dylib").or_default() += 1;
            first_of_kind.entry("dylib").or_insert(artifact);
            if listed.len() < MAX_LISTED {
                listed.push(json!({ "path": artifact.path, "kind": "dylib" }));
            }
        }
    }
    if counts.is_empty() {
        return;
    }
    let total: usize = counts.values().sum();
    out.fact(bundle.info, "apple.embedded", json!({ "items": listed, "total": total, "truncated": total > MAX_LISTED }));
    let summary = counts.iter().map(|(kind, count)| format!("{count} {kind}")).collect::<Vec<_>>().join(", ");
    let mut found = finding(Section::Composition, "apple.embedded-code", Confidence::Verified, Severity::Info)
        .param("bundle", bundle.name())
        .param("count", total)
        .param("summary", summary);
    for (kind, artifact) in first_of_kind {
        found = found.evidence(Evidence::whole(artifact, json!({ "kind": kind, "count": counts[kind], "first": true })));
    }
    out.finding(found);
}

/// Names the application framework a bundle was built with, from its layout.
pub fn frameworks<'t>(tree: &'t dyn Tree, bundle: &Bundle<'_>, executable: Option<&'t Artifact>, out: &mut Output) {
    let files = tree.under(&bundle.dir);
    let prefix_length = if bundle.dir.is_empty() { 0 } else { bundle.dir.len() + 1 };
    // The first file whose path inside the bundle satisfies `test`.
    let find = |test: &dyn Fn(&str) -> bool| -> Option<&'t Artifact> {
        files.iter().copied().find(|a| a.path.get(prefix_length..).is_some_and(test))
    };
    let has_framework = |name: &'static str| move |path: &str| path.contains(&format!("Frameworks/{name}.framework/"));
    let mut hits: Vec<(&'static str, &'t Artifact, String)> = Vec::new();
    let mut add = |name: &'static str, artifact: Option<&'t Artifact>, why: &str| {
        if let Some(artifact) = artifact
            && !hits.iter().any(|hit| hit.0 == name)
        {
            hits.push((name, artifact, why.to_string()));
        }
    };
    add("Flutter", find(&has_framework("Flutter")).or_else(|| find(&has_framework("FlutterMacOS"))), "Flutter engine framework");
    add("Flutter", find(&|p| p.contains("flutter_assets/")), "flutter_assets folder");
    add("React Native", find(&|p| p.ends_with("main.jsbundle")), "bundled JavaScript (main.jsbundle)");
    add("React Native", find(&has_framework("hermes")).or_else(|| find(&has_framework("React"))), "React Native framework");
    add("Unity", find(&has_framework("UnityFramework")), "UnityFramework");
    add("Unity", find(&|p| p.ends_with("Frameworks/UnityPlayer.dylib") || p.ends_with("Data/globalgamemanagers")), "Unity player data");
    add(
        "Xamarin / .NET",
        find(&|p| {
            p.ends_with("Xamarin.iOS.dll")
                || p.ends_with("Microsoft.iOS.dll")
                || p.ends_with("Microsoft.macOS.dll")
                || p.ends_with("Xamarin.Mac.dll")
        }),
        "managed platform assembly",
    );
    add("Xamarin / .NET", find(&|p| p.contains("libxamarin") || p.contains("libmonosgen")), "Mono runtime library");
    add("Electron", find(&has_framework("Electron Framework")), "Electron Framework");
    add("Electron", find(&|p| p.ends_with("Resources/app.asar")), "app.asar archive");
    add("Capacitor", find(&has_framework("Capacitor")).or_else(|| find(&|p| p.ends_with("capacitor.config.json"))), "Capacitor runtime");
    add("Cordova", find(&has_framework("Cordova")).or_else(|| find(&|p| p.ends_with("www/cordova.js"))), "Cordova runtime");
    add("Qt", find(&has_framework("QtCore")), "QtCore framework");
    // Swift shows in the libraries the executable links, or in the runtime copied into the bundle.
    let swift_link = executable.filter(|file| {
        main_slice(file)
            .and_then(|s| s["libraries"].as_array())
            .is_some_and(|libraries| libraries.iter().filter_map(Value::as_str).any(|l| l.contains("libswiftCore")))
    });
    add("Swift", swift_link, "the main executable links libswiftCore");
    add("Swift", find(&|p| p.ends_with("Frameworks/libswiftCore.dylib")), "embedded Swift runtime");
    for (name, artifact, why) in hits {
        out.finding(
            finding(Section::Composition, "apple.framework", Confidence::Derived, Severity::Info)
                .param("framework", name)
                .param("bundle", bundle.name())
                .evidence(Evidence::whole(artifact, why)),
        );
    }
}

/// Localisations, icon and asset catalogs of a bundle.
pub fn structure(tree: &dyn Tree, bundle: &Bundle<'_>, out: &mut Output) {
    let files = tree.under(&bundle.dir);
    let resources = match bundle.layout {
        crate::bundle::Layout::Flat => bundle.root.clone(),
        _ => bundle.rooted("Resources"),
    };
    let resources_prefix = if resources.is_empty() { String::new() } else { format!("{resources}/") };
    let mut languages: BTreeSet<&str> = BTreeSet::new();
    let mut sample: Option<&Artifact> = None;
    let mut catalogs: Vec<&Artifact> = Vec::new();
    for artifact in &files {
        if artifact.name() == "Assets.car" {
            catalogs.push(artifact);
        }
        if let Some(relative) = artifact.path.strip_prefix(&resources_prefix)
            && let Some((folder, _)) = relative.split_once('/')
            && let Some(language) = folder.strip_suffix(".lproj")
        {
            languages.insert(language);
            sample.get_or_insert(artifact);
        }
    }
    if let Some(sample) = sample {
        let languages: Vec<String> = languages.into_iter().map(str::to_string).collect();
        out.finding(
            finding(Section::Structure, "apple.localizations", Confidence::Verified, Severity::Info)
                .param("bundle", bundle.name())
                .param("count", languages.len())
                .param("languages", languages.join(", "))
                .evidence(Evidence::whole(sample, json!(languages))),
        );
    }
    if let Some(first) = catalogs.first() {
        let total: u64 = catalogs.iter().map(|c| c.size).sum();
        out.finding(
            finding(Section::Structure, "apple.asset-catalogs", Confidence::Verified, Severity::Info)
                .param("bundle", bundle.name())
                .param("count", catalogs.len())
                .param("bytes", total)
                .evidence(Evidence::whole(first, json!({ "size": first.size }))),
        );
    }
    let Ok(plist) = &bundle.plist else { return };
    let icon_name = plist.get("CFBundleIconFile").and_then(Plist::as_string).map(str::to_string).or_else(|| {
        let primary = plist.get("CFBundleIcons")?.as_dictionary()?.get("CFBundlePrimaryIcon")?.as_dictionary()?;
        primary
            .get("CFBundleIconName")
            .and_then(Plist::as_string)
            .map(str::to_string)
            .or_else(|| strings(primary.get("CFBundleIconFiles")).into_iter().next_back())
    });
    let icon_name = icon_name.or_else(|| plist.get("CFBundleIconName").and_then(Plist::as_string).map(str::to_string));
    if let Some(icon) = icon_name {
        // The largest file whose name starts with the icon's name is the best rendition present.
        let stem = icon.trim_end_matches(".icns").trim_end_matches(".png");
        let file = files
            .iter()
            .copied()
            .filter(|a| {
                a.path.starts_with(&resources_prefix)
                    && a.name().starts_with(stem)
                    && matches!(a.extension().as_deref(), Some("icns" | "png"))
            })
            .max_by_key(|a| a.size);
        let mut found = finding(Section::Identity, "apple.app-icon", Confidence::Verified, Severity::Info)
            .param("bundle", bundle.name())
            .param("icon", icon.as_str())
            .evidence(Evidence::field(bundle.info, "CFBundleIconFile / CFBundleIcons", icon.as_str()));
        if let Some(file) = file {
            found = found.evidence(Evidence::whole(file, json!({ "size": file.size })));
        }
        out.finding(found);
    }
}

/// Things an IPA carries beside the app: store metadata and FairPlay keys.
pub fn ipa(tree: &dyn Tree, archive: &Artifact, app: &Bundle<'_>, out: &mut Output) {
    out.kind(archive, "ipa");
    out.finding(
        finding(Section::Overview, "apple.ipa", Confidence::Verified, Severity::Info)
            .param("app", app.name())
            .evidence(Evidence::whole(app.info, format!("Payload/{}", app.name()))),
    );
    if let Some(metadata) = tree.get(&format!("{}/iTunesMetadata.plist", archive.path)) {
        match read_plist(tree, metadata) {
            Ok(plist) => {
                if let Some(dictionary) = plist.as_dictionary() {
                    let text = |key: &str| dictionary.get(key).map(plist_to_json).filter(|v| !v.is_null());
                    // The buyer's account is personal data: recorded as present, never copied.
                    let account = ["appleId", "apple-id"].iter().any(|key| dictionary.contains_key(key))
                        || dictionary
                            .get("com.apple.iTunesStore.downloadInfo")
                            .and_then(Plist::as_dictionary)
                            .and_then(|d| d.get("accountInfo"))
                            .is_some();
                    let fact = json!({
                        "item_id": text("itemId"),
                        "item_name": text("itemName"),
                        "software_version_bundle_id": text("softwareVersionBundleId"),
                        "bundle_short_version": text("bundleShortVersionString"),
                        "artist_name": text("artistName"),
                        "genre": text("genre"),
                        "purchase_date": text("purchaseDate"),
                        "release_date": text("releaseDate"),
                        "store_front": text("s"),
                        "buyer_account_present": account,
                    });
                    out.finding(
                        finding(Section::Provenance, "apple.store-metadata", Confidence::Verified, Severity::Info)
                            .param("item", fact["item_name"].as_str().unwrap_or("?"))
                            .param("item_id", fact["item_id"].to_string())
                            .param("account_present", account)
                            .evidence(Evidence::field(metadata, "itemId", fact["item_id"].clone()))
                            .evidence(Evidence::field(metadata, "appleId", if account { json!("[redacted]") } else { Value::Null })),
                    );
                    out.fact(metadata, "apple.store-metadata", fact);
                }
            }
            Err(error) => out.limitation("apple.plist-unreadable", Some(metadata), Some(error)),
        }
    }
    let keys: Vec<&Artifact> = tree.under(&app.path("SC_Info")).into_iter().collect();
    if let Some(first) = keys.first() {
        out.finding(
            finding(Section::Provenance, "apple.sc-info", Confidence::Verified, Severity::Info)
                .param("count", keys.len())
                .evidence(Evidence::whole(first, json!({ "files": keys.iter().take(10).map(|k| k.name()).collect::<Vec<_>>() }))),
        );
    }
}

/// Reports a disk image from its `apple.dmg` fact.
pub fn disk_image(file: &Artifact, out: &mut Output) {
    let Some(fact) = file.facts.get("apple.dmg") else { return };
    if fact["encrypted"] == true {
        out.finding(
            finding(Section::Structure, "apple.dmg-encrypted", Confidence::Verified, Severity::Medium)
                .param("version", fact["encryption_version"].clone())
                .evidence(Evidence::bytes(file, 0, 8, "encrcdsa / cdsaencr")),
        );
        return;
    }
    let partitions = fact["partitions"].as_array().map(Vec::len).unwrap_or(0);
    let compression: Vec<String> =
        fact["compression"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)).collect();
    out.finding(
        finding(Section::Structure, "apple.dmg", Confidence::Verified, Severity::Info)
            .param("version", fact["udif_version"].clone())
            .param("partitions", partitions)
            .param("compression", if compression.is_empty() { "none".to_string() } else { compression.join(", ") })
            .param("megabytes", fact["sectors"].as_u64().unwrap_or(0) * 512 / (1024 * 1024))
            .evidence(Evidence::bytes(file, fact["trailer_offset"].as_u64().unwrap_or(0), 512, "koly")),
    );
}

/// Reports a xar archive's signature from its `apple.xar` fact.
pub fn package(file: &Artifact, out: &mut Output) -> bool {
    let Some(fact) = file.facts.get("apple.xar") else { return false };
    if fact["is_package"] == true {
        out.kind(file, "pkg");
    }
    let name = file.name();
    if fact["toc_checksum"]["matches"] == false {
        out.finding(
            finding(Section::Anomalies, "apple.xar-checksum-mismatch", Confidence::Verified, Severity::High)
                .param("file", name)
                .evidence(Evidence::whole(file, fact["toc_checksum"].clone())),
        );
    }
    let signatures = fact["signatures"].as_array().map(Vec::as_slice).unwrap_or_default();
    if signatures.is_empty() {
        if fact["is_package"] == true {
            out.finding(
                finding(Section::Provenance, "apple.pkg-unsigned", Confidence::Verified, Severity::Medium)
                    .param("file", name)
                    .evidence(Evidence::whole(file, json!({ "signature_elements": 0 }))),
            );
        }
        return false;
    }
    // The strongest signature a reader would rely on: prefer one that verified.
    let best = signatures.iter().find(|s| s["signature"] == "valid").unwrap_or(&signatures[0]);
    let certificates = best["chain"]["certificates"].as_array().map(Vec::as_slice).unwrap_or_default();
    let signer = certificates.first().and_then(|c| c["common_name"].as_str()).unwrap_or("?");
    let names: Vec<&str> = certificates.iter().map(|c| c["common_name"].as_str().unwrap_or("?")).collect();
    let mut found = finding(Section::Provenance, "apple.pkg-signed", Confidence::Verified, Severity::Info)
        .param("file", name)
        .param("signer", signer)
        .param("chain", names.join(" ← "))
        .param("styles", signatures.iter().filter_map(|s| s["style"].as_str()).collect::<Vec<_>>().join(", "));
    for (index, certificate) in certificates.iter().enumerate() {
        found = found.evidence(Evidence::field(file, format!("signature.certificates[{index}]"), certificate.clone()));
    }
    out.finding(found);
    let verdict = best["signature"].as_str().unwrap_or("");
    let check = Evidence::whole(
        file,
        json!({ "toc_checksum": fact["toc_checksum"], "signature": verdict, "style": best["style"], "links": best["chain"]["links"], "anchor": best["chain"]["anchor"] }),
    );
    if verdict == "valid" {
        let rule = if best["anchored"] == true { "apple.pkg-signature-valid-apple-root" } else { "apple.pkg-signature-valid" };
        out.finding(
            finding(Section::Provenance, rule, Confidence::Verified, Severity::Info)
                .param("file", name)
                .param("anchor", best["chain"]["anchor"].as_str().unwrap_or("?"))
                .evidence(check),
        );
    } else if verdict == "invalid" {
        out.finding(
            finding(Section::Provenance, "apple.pkg-signature-invalid", Confidence::Verified, Severity::High)
                .param("file", name)
                .evidence(check),
        );
    } else {
        out.limitation("apple.cms-unchecked", Some(file), Some(verdict.to_string()));
    }
    true
}

/// Largest installer description parsed.
const MAX_PACKAGE_XML: u64 = 16 * 1024 * 1024;

fn parse_xml<'a>(text: &'a str) -> Result<roxmltree::Document<'a>, String> {
    let options = roxmltree::ParsingOptions { allow_dtd: true, nodes_limit: 2_000_000 };
    roxmltree::Document::parse_with_options(text, options).map_err(|e| e.to_string())
}

/// Reports what the `PackageInfo` and `Distribution` files of an installer package declare:
/// what is installed where, and which scripts run during installation.
pub fn package_contents(tree: &dyn Tree, file: &Artifact, out: &mut Output) {
    let name = file.name();
    if (name != "PackageInfo" && name != "Distribution") || file.size > MAX_PACKAGE_XML {
        return;
    }
    // Only inside a xar archive: other files may happen to share the names.
    let in_package =
        file.parent.as_deref().and_then(|parent| tree.get(parent)).is_some_and(|parent| parent.facts.contains_key("apple.xar"));
    if !in_package {
        return;
    }
    let Ok(bytes) = tree.read(&file.path) else { return };
    let text = String::from_utf8_lossy(&bytes);
    let document = match parse_xml(&text) {
        Ok(document) => document,
        Err(error) => {
            out.limitation("apple.package-info-unreadable", Some(file), Some(error));
            return;
        }
    };
    let root = document.root_element();
    let elements = |tag: &'static str| root.descendants().filter(move |n| n.is_element() && n.tag_name().name() == tag);
    if name == "Distribution" {
        let title = elements("title").next().and_then(|n| n.text()).map(str::trim).filter(|t| !t.is_empty());
        let mut components: Vec<String> = elements("pkg-ref")
            .filter_map(|n| {
                Some(match n.attribute("version") {
                    Some(version) => format!("{} {version}", n.attribute("id")?),
                    None => n.attribute("id")?.to_string(),
                })
            })
            .collect();
        components.sort();
        // A pkg-ref appears twice, once bare and once with its version: keep the fuller one.
        let with_version: BTreeSet<String> = components.iter().filter_map(|c| c.split_once(' ').map(|(id, _)| id.to_string())).collect();
        components.retain(|c| c.contains(' ') || !with_version.contains(c));
        components.dedup();
        let scripted = elements("script").next().is_some() || elements("installation-check").any(|n| n.attribute("script").is_some());
        out.kind(file, "pkg-distribution");
        out.finding(
            finding(Section::Identity, "apple.pkg-distribution", Confidence::Verified, Severity::Info)
                .param("title", title.unwrap_or("(untitled)"))
                .param("count", components.len())
                .param("components", if components.is_empty() { "-".to_string() } else { shown(&components) })
                .param("scripted", scripted)
                .evidence(Evidence::field(file, "title", json!(title)))
                .evidence(Evidence::field(file, "pkg-ref", json!(components))),
        );
        return;
    }
    if root.tag_name().name() != "pkg-info" {
        return;
    }
    out.kind(file, "pkg-info");
    let payload = elements("payload").next();
    let attributes = [
        ("identifier", root.attribute("identifier")),
        ("version", root.attribute("version")),
        ("install location", root.attribute("install-location")),
        ("runs as", root.attribute("auth")),
        ("files", payload.and_then(|p| p.attribute("numberOfFiles"))),
        ("installed KB", payload.and_then(|p| p.attribute("installKBytes"))),
    ];
    let present: Vec<String> = attributes.iter().filter_map(|(label, value)| Some(format!("{label} {}", (*value)?))).collect();
    if !present.is_empty() {
        let mut found = finding(Section::Identity, "apple.pkg-component", Confidence::Verified, Severity::Info)
            .param("identifier", root.attribute("identifier").unwrap_or("(none)"))
            .param("details", present.join(", "));
        for (label, value) in attributes {
            if let Some(value) = value {
                found = found.evidence(Evidence::field(file, label, value));
            }
        }
        out.finding(found);
    }
    // Scripts run as root, before and after the payload is copied.
    let scripts: Vec<(String, String)> = elements("scripts")
        .flat_map(|scripts| scripts.children().filter(|n| n.is_element()))
        .filter_map(|n| Some((n.tag_name().name().to_string(), n.attribute("file")?.to_string())))
        .collect();
    if !scripts.is_empty() {
        let folder = file.path.strip_suffix("PackageInfo").unwrap_or("");
        let mut found = finding(Section::Capabilities, "apple.pkg-scripts", Confidence::Verified, Severity::Low)
            .param("identifier", root.attribute("identifier").unwrap_or("(none)"))
            .param("scripts", scripts.iter().map(|(phase, path)| format!("{phase} → {path}")).collect::<Vec<_>>().join(", "))
            .evidence(Evidence::field(file, "scripts", json!(scripts)));
        for (_, path) in &scripts {
            if let Some(script) = tree.get(&format!("{folder}Scripts/{}", path.trim_start_matches("./"))) {
                found = found.evidence(Evidence::whole(script, json!({ "size": script.size })));
            }
        }
        out.finding(found);
    }
}
