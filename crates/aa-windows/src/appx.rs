//! MSIX / APPX packages: the `AppxManifest.xml` at the package root.

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::json;

use crate::{ID, resources};

/// Capabilities that lift the app out of the sandbox or reach well beyond it.
const BROAD_CAPABILITIES: &[&str] = &[
    "runFullTrust",
    "allowElevation",
    "broadFileSystemAccess",
    "packageManagement",
    "packagedServices",
    "localSystemServices",
    "unvirtualizedResources",
    "inputInjectionBrokered",
    "appDiagnostics",
    "enterpriseAuthentication",
    "sharedUserCertificates",
    "documentsLibrary",
];

/// Reads `AppxManifest.xml`. Does nothing for other files.
pub fn analyze(file: &Artifact, bytes: &[u8], out: &mut Output) {
    if !file.name().eq_ignore_ascii_case("AppxManifest.xml") || bytes.len() > 16 * 1024 * 1024 {
        return;
    }
    let text = resources::decode_xml(bytes);
    let options = roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() };
    let document = match roxmltree::Document::parse_with_options(&text, options) {
        Ok(document) => document,
        Err(error) => {
            out.limitation("windows.msix-manifest-unreadable", Some(file), Some(error.to_string()));
            return;
        }
    };
    let root = document.root_element();
    if root.tag_name().name() != "Package" {
        return;
    }
    let elements = || root.descendants().filter(roxmltree::Node::is_element);
    let first = |name: &str| elements().find(|e| e.tag_name().name() == name);
    let text_of = |name: &str| first(name).and_then(|e| e.text()).map(str::trim).filter(|t| !t.is_empty()).map(str::to_string);
    let identity = first("Identity");
    let attribute = |name: &str| identity.and_then(|i| i.attribute(name)).map(str::to_string);

    let mut capabilities: Vec<String> = elements()
        .filter(|e| matches!(e.tag_name().name(), "Capability" | "DeviceCapability" | "CustomCapability"))
        .filter_map(|e| e.attribute("Name"))
        .map(str::to_string)
        .take(200)
        .collect();
    capabilities.sort();
    capabilities.dedup();
    let applications: Vec<_> = elements()
        .filter(|e| e.tag_name().name() == "Application")
        .take(50)
        .map(|e| json!({ "id": e.attribute("Id"), "executable": e.attribute("Executable"), "entry_point": e.attribute("EntryPoint") }))
        .collect();
    // Extensions: protocol handlers, file types, startup tasks, services, COM servers.
    let mut extensions = Vec::new();
    for extension in elements().filter(|e| e.tag_name().name() == "Extension").take(200) {
        let Some(category) = extension.attribute("Category") else { continue };
        let detail = extension
            .descendants()
            .filter(roxmltree::Node::is_element)
            .find_map(|e| match e.tag_name().name() {
                "Protocol" | "FileTypeAssociation" | "AppExecutionAlias" => e.attribute("Name").map(str::to_string),
                "StartupTask" => e.attribute("TaskId").map(str::to_string),
                "Service" => e.attribute("Name").map(str::to_string),
                _ => None,
            })
            .or_else(|| extension.attribute("Executable").map(str::to_string));
        extensions.push(json!({ "category": category, "detail": detail }));
    }

    out.fact(
        file,
        "windows.msix",
        json!({
            "identity": {
                "name": attribute("Name"),
                "publisher": attribute("Publisher"),
                "version": attribute("Version"),
                "architecture": attribute("ProcessorArchitecture"),
            },
            "display_name": text_of("DisplayName"),
            "publisher_display_name": text_of("PublisherDisplayName"),
            "capabilities": capabilities,
            "applications": applications,
            "extensions": extensions,
        }),
    );
    let finding = |section, rule: &str, severity| Finding::new(section, ID, rule, Confidence::Verified, severity);
    if let Some(name) = attribute("Name") {
        out.finding(
            finding(Section::Identity, "windows.msix-identity", Severity::Info)
                .param("name", name.clone())
                .param("version", attribute("Version").unwrap_or_else(|| "?".into()))
                .param("publisher", attribute("Publisher").unwrap_or_else(|| "?".into()))
                .param("display_name", text_of("DisplayName").unwrap_or_else(|| name.clone()))
                .evidence(Evidence::field(
                    file,
                    "Package/Identity",
                    json!({ "Name": name, "Publisher": attribute("Publisher"), "Version": attribute("Version") }),
                )),
        );
    }
    if !capabilities.is_empty() {
        let broad: Vec<&str> = capabilities.iter().map(String::as_str).filter(|c| BROAD_CAPABILITIES.contains(c)).collect();
        out.finding(
            finding(Section::Capabilities, "windows.msix-capabilities", if broad.is_empty() { Severity::Info } else { Severity::Low })
                .param("capabilities", capabilities.join(", "))
                .param("broad", if broad.is_empty() { "—".to_string() } else { broad.join(", ") })
                .evidence(Evidence::field(file, "Package/Capabilities", json!(capabilities))),
        );
    }
    if !applications.is_empty() || !extensions.is_empty() {
        out.finding(
            finding(Section::Capabilities, "windows.msix-entry-points", Severity::Info)
                .param("applications", applications.len())
                .param("extensions", extensions.len())
                .evidence(Evidence::field(file, "Package/Applications", json!({ "applications": applications, "extensions": extensions }))),
        );
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn manifest() -> Artifact {
        Artifact {
            path: "app.msix/AppxManifest.xml".into(),
            parent: Some("app.msix".into()),
            size: 1,
            digests: None,
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        }
    }

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities">
  <Identity Name="Fixture.App" Publisher="CN=Fixture Works" Version="1.2.3.0" ProcessorArchitecture="x64"/>
  <Properties><DisplayName>Fixture App</DisplayName><PublisherDisplayName>Fixture Works</PublisherDisplayName></Properties>
  <Applications>
    <Application Id="App" Executable="app\fixture.exe" EntryPoint="Windows.FullTrustApplication">
      <Extensions>
        <uap:Extension Category="windows.protocol"><uap:Protocol Name="fixture"/></uap:Extension>
        <uap:Extension Category="windows.startupTask" Executable="app\fixture.exe"><uap:StartupTask TaskId="FixtureStart"/></uap:Extension>
      </Extensions>
    </Application>
  </Applications>
  <Capabilities>
    <Capability Name="internetClient"/>
    <rescap:Capability Name="runFullTrust"/>
    <DeviceCapability Name="microphone"/>
  </Capabilities>
</Package>"#;

    #[test]
    fn manifest_is_read() {
        let mut out = Output::default();
        analyze(&manifest(), SAMPLE.as_bytes(), &mut out);
        let fact = &out.facts[0].value;
        assert_eq!(fact["identity"]["name"], "Fixture.App");
        assert_eq!(fact["identity"]["version"], "1.2.3.0");
        assert_eq!(fact["capabilities"], json!(["internetClient", "microphone", "runFullTrust"]));
        assert_eq!(fact["applications"][0]["executable"], "app\\fixture.exe");
        assert_eq!(fact["extensions"][0], json!({ "category": "windows.protocol", "detail": "fixture" }));
        assert_eq!(fact["extensions"][1]["detail"], "FixtureStart");
        let rules: Vec<&str> = out.findings.iter().map(|f| f.rule.as_str()).collect();
        assert_eq!(rules, ["windows.msix-identity", "windows.msix-capabilities", "windows.msix-entry-points"]);
        assert_eq!(out.findings[1].params["broad"], "runFullTrust");
    }

    #[test]
    fn broken_or_foreign_xml_is_handled() {
        let mut out = Output::default();
        analyze(&manifest(), b"<Package><Identity", &mut out);
        assert_eq!(out.limitations.len(), 1);
        assert!(out.findings.is_empty());
        let mut out = Output::default();
        analyze(&manifest(), b"<Other/>", &mut out);
        assert!(out.facts.is_empty() && out.limitations.is_empty());
    }
}
