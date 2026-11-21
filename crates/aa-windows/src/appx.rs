//! MSIX / APPX packages: the `AppxManifest.xml` at the package root.

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::json;

use crate::ID;

mod manifest;

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
    if !file.name().eq_ignore_ascii_case("AppxManifest.xml") {
        return;
    }
    let fact = match manifest::read(bytes) {
        Ok(fact) => fact,
        Err(reason) => {
            out.limitation("windows.msix-manifest-unreadable", Some(file), Some(reason.into()));
            return;
        }
    };
    if file.digests.as_ref().is_some_and(|d| fact["source_sha256"] != d.sha256) {
        out.limitation("windows.msix-manifest-unreadable", Some(file), Some("manifest bytes differ from captured digest".into()));
        return;
    }
    let attribute = |name: &str| {
        fact["identity"][match name {
            "Name" => "name",
            "Publisher" => "publisher",
            "Version" => "version",
            _ => "architecture",
        }]
        .as_str()
        .map(str::to_string)
    };
    let display_name = fact["display_name"].as_str().map(str::to_string);
    let capabilities: Vec<String> =
        fact["capabilities"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_string)).collect();
    let applications = fact["applications"].as_array().expect("manifest reader supplies application array");
    let extensions = fact["extensions"].as_array().expect("manifest reader supplies extension array");
    if !fact["projection_issues"].as_array().is_some_and(Vec::is_empty) || fact["projection_issues_omitted"].as_u64().unwrap_or(0) > 0 {
        out.limitation(
            "windows.msix-manifest-projection",
            Some(file),
            Some("unread, ambiguous, redacted or limited declarations are recorded in projection_issues".into()),
        );
    }
    if fact["identity_status"] == "ambiguous" {
        out.finding(
            Finding::new(Section::Identity, ID, "windows.msix-manifest-identities", Confidence::Verified, Severity::Info)
                .param(
                    "count",
                    fact["identity_declarations"].as_array().map_or(0, Vec::len) as u64
                        + fact["identity_declarations_omitted"].as_u64().unwrap_or(0),
                )
                .evidence(Evidence::field(file, "Package/Identity declarations", fact["identity_declarations"].clone())),
        );
    }
    let packages = fact["dependencies"].as_array().map_or(0, Vec::len);
    let families = fact["target_device_families"].as_array().map_or(0, Vec::len);
    if packages + families > 0 {
        out.finding(
            Finding::new(Section::Structure, ID, "windows.msix-dependencies", Confidence::Verified, Severity::Info)
                .param("packages", packages)
                .param("families", families)
                .evidence(Evidence::field(
                    file,
                    "Package/Dependencies",
                    json!({"packages":fact["dependencies"],"target_device_families":fact["target_device_families"]}),
                )),
        );
    }
    out.fact(file, "windows.msix", fact.clone());
    out.limitation("windows.msix-package-scope", Some(file), None);
    let finding = |section, rule: &str, severity| Finding::new(section, ID, rule, Confidence::Verified, severity);
    if let Some(name) = attribute("Name") {
        out.finding(
            finding(Section::Identity, "windows.msix-identity", Severity::Info)
                .param("name", name.clone())
                .param("version", attribute("Version").unwrap_or_else(|| "?".into()))
                .param("publisher", attribute("Publisher").unwrap_or_else(|| "?".into()))
                .param("display_name", display_name.clone().unwrap_or_else(|| name.clone()))
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
    fn duplicate_identity_and_stale_source_never_emit_a_selected_identity() {
        let duplicate =
            SAMPLE.replace("<Properties>", r#"<Identity Name="Other.App" Publisher="CN=Other" Version="9.0.0.0"/><Properties>"#);
        let mut out = Output::default();
        analyze(&manifest(), duplicate.as_bytes(), &mut out);
        assert!(out.findings.iter().any(|f| f.rule == "windows.msix-manifest-identities"));
        assert!(!out.findings.iter().any(|f| f.rule == "windows.msix-identity"));
        let mut source = manifest();
        source.digests = Some(aa_core::Digests { md5: String::new(), sha1: String::new(), sha256: "00".repeat(32) });
        let mut out = Output::default();
        analyze(&source, SAMPLE.as_bytes(), &mut out);
        assert!(out.facts.is_empty());
        assert!(out.findings.is_empty());
        assert!(!out.limitations.is_empty());
    }

    #[test]
    fn broken_or_foreign_xml_is_handled() {
        let mut out = Output::default();
        analyze(&manifest(), b"<Package><Identity", &mut out);
        assert_eq!(out.limitations.len(), 1);
        assert!(out.findings.is_empty());
        let mut out = Output::default();
        analyze(&manifest(), b"<Other/>", &mut out);
        assert!(out.facts.is_empty());
        assert!(out.limitations.iter().any(|l| l.code == "windows.msix-manifest-unreadable"));
    }
}
