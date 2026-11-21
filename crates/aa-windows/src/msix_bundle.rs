//! Bounded bundle declarations; relationships use original ZIP bytes in a separate pass.

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use roxmltree::{Node, ParsingOptions};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub(super) const MANIFEST: &str = "AppxMetadata/AppxBundleManifest.xml";
const NS: &str = "http://schemas.microsoft.com/appx/2013/bundle";
const MAX_XML: usize = 8 * 1024 * 1024;

struct Reader {
    issues: Vec<Value>,
    omitted: usize,
    text_left: usize,
}

impl Reader {
    fn issue(&mut self, node: Node<'_, '_>, reason: &str) {
        if self.issues.len() < 64 {
            self.issues.push(json!({"xml_offset":node.range().start,"xml_length":node.range().len(),"reason":reason}));
        } else {
            self.omitted += 1;
        }
    }

    fn attributes(&mut self, node: Node<'_, '_>, names: &[(&str, &str)], children: bool) -> (Value, bool) {
        let mut fields = Map::new();
        let mut established = true;
        for attribute in node.attributes() {
            let key = names.iter().find(|(name, _)| *name == attribute.name()).map(|(_, key)| *key);
            let Some(key) = key.filter(|_| attribute.namespace().is_none()) else {
                self.issue(node, "unread attribute or attribute namespace");
                established = false;
                continue;
            };
            let value = attribute.value();
            if value.len() > 8192 || value.len() > self.text_left {
                self.issue(node, "attribute or aggregate text budget");
                established = false;
                continue;
            }
            self.text_left -= value.len();
            match aa_core::text::redact_sensitive_text(value) {
                Ok(text) => {
                    if text != value {
                        self.issue(node, "redacted declaration cannot establish a relationship");
                        established = false;
                    }
                    fields.insert(key.into(), json!(text));
                }
                Err(_) => {
                    self.issue(node, "attribute redaction budget");
                    established = false;
                }
            }
        }
        if node.children().any(|n| (!children && n.is_element()) || (n.is_text() && n.text().is_some_and(|s| !s.trim().is_empty()))) {
            self.issue(node, "unexpected child element or non-whitespace text");
            established = false;
        }
        (Value::Object(fields), established)
    }
}

fn qualified(node: Node<'_, '_>, name: &str) -> bool {
    node.tag_name().namespace() == Some(NS) && node.tag_name().name() == name
}

fn version(value: Option<&str>) -> bool {
    value.is_some_and(|s| {
        let parts: Vec<_> = s.split('.').collect();
        parts.len() == 4 && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok())
    })
}

fn required(value: &Value, fields: &[&str]) -> bool {
    fields.iter().all(|key| value[key].as_str().is_some_and(|s| !s.is_empty()))
}

fn resources(reader: &mut Reader, package: Node<'_, '_>) -> (Vec<Value>, bool) {
    let mut rows = Vec::new();
    let mut established = true;
    let mut sections = 0;
    for section in package.children().filter(Node::is_element) {
        if !qualified(section, "Resources") {
            reader.issue(section, "unread package child or namespace; dependency/extension semantics unresolved");
            established = false;
            continue;
        }
        sections += 1;
        established &= reader.attributes(section, &[], true).1;
        for resource in section.children().filter(Node::is_element) {
            if !qualified(resource, "Resource") || rows.len() >= 200 {
                reader.issue(resource, "unread resource namespace/element or resource count budget");
                established = false;
                continue;
            }
            let (mut row, known) =
                reader.attributes(resource, &[("Language", "language"), ("Scale", "scale"), ("DXFeatureLevel", "dx_feature_level")], false);
            row["xml_offset"] = json!(resource.range().start);
            row["projection_established"] = json!(known);
            rows.push(row);
            established &= known;
        }
    }
    if sections != 1 {
        reader.issue(package, "resources section is missing or repeated");
        established = false;
    }
    (rows, established)
}

pub(super) fn read(bytes: &[u8]) -> Result<Value, &'static str> {
    let text = crate::msix_xml::decode(bytes, MAX_XML)?;
    let document = roxmltree::Document::parse_with_options(&text, ParsingOptions { allow_dtd: false, nodes_limit: 100_000 })
        .map_err(|_| "bundle XML is malformed, contains a DTD or exceeds its node budget")?;
    let root = document.root_element();
    if !qualified(root, "Bundle") {
        return Err("bundle root namespace or element is unsupported");
    }
    let mut reader = Reader { issues: Vec::new(), omitted: 0, text_left: 1024 * 1024 };
    let (root_fields, _) =
        reader.attributes(root, &[("SchemaVersion", "schema_version"), ("IgnorableNamespaces", "ignorable_namespaces")], true);
    if !root_fields["schema_version"].as_str().is_some_and(|s| {
        let parts: Vec<_> = s.split('.').collect();
        matches!(parts.len(), 2 | 3)
            && parts.iter().all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u32>().is_ok())
    }) {
        reader.issue(root, "bundle schema version is missing or outside numeric duo/trio profile");
    }
    let mut identities = Vec::new();
    let mut identity_count = 0usize;
    let mut packages = Vec::new();
    let mut packages_omitted = 0usize;
    let mut package_sections = 0usize;
    for section in root.children().filter(Node::is_element) {
        if qualified(section, "Identity") {
            identity_count += 1;
            if identities.len() >= 16 {
                reader.issue(section, "identity declaration count budget");
                continue;
            }
            let (mut identity, known) =
                reader.attributes(section, &[("Name", "name"), ("Publisher", "publisher"), ("Version", "version")], false);
            let established = known && required(&identity, &["name", "publisher", "version"]) && version(identity["version"].as_str());
            if !established {
                reader.issue(section, "bundle identity fields missing, unsupported, unread or redacted");
            }
            identity["projection_established"] = json!(established);
            identity["xml_offset"] = json!(section.range().start);
            identities.push(identity);
        } else if qualified(section, "Packages") {
            package_sections += 1;
            reader.attributes(section, &[], true);
            for node in section.children().filter(Node::is_element) {
                if !qualified(node, "Package") {
                    reader.issue(node, "unread package namespace or element");
                    continue;
                }
                if packages.len() >= 1024 {
                    packages_omitted += 1;
                    reader.issue(node, "package count budget");
                    continue;
                }
                let (mut row, known) = reader.attributes(
                    node,
                    &[
                        ("Type", "type"),
                        ("Version", "version"),
                        ("Architecture", "architecture"),
                        ("ResourceId", "resource_id"),
                        ("FileName", "file_name"),
                        ("Offset", "offset_literal"),
                        ("Size", "size_literal"),
                    ],
                    true,
                );
                let mut established = known
                    && required(&row, &["version", "file_name", "offset_literal", "size_literal"])
                    && version(row["version"].as_str());
                for (key, default) in [("type", "resource"), ("architecture", "neutral"), ("resource_id", "")] {
                    if row.get(key).is_none() {
                        row[key] = json!(default);
                    }
                }
                established &= matches!(row["type"].as_str(), Some("application" | "resource"));
                established &= matches!(row["architecture"].as_str(), Some("x86" | "x64" | "arm" | "arm64" | "neutral"));
                for (key, literal) in [("offset", "offset_literal"), ("size", "size_literal")] {
                    let number = row[literal]
                        .as_str()
                        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                        .and_then(|s| s.parse::<u64>().ok());
                    established &= number.is_some();
                    row[key] = json!(number);
                }
                if !established {
                    reader.issue(node, "package fields missing, unsupported, unread, redacted or outside integer range");
                }
                let (resources, resources_known) = resources(&mut reader, node);
                row["resources"] = json!(resources);
                row["resources_projection_established"] = json!(resources_known);
                row["projection_established"] = json!(established);
                row["xml_offset"] = json!(node.range().start);
                packages.push(row);
            }
        } else {
            reader.issue(section, "unread root element or namespace; optional/flat/modern bundle semantics unresolved");
        }
    }
    let mut names = BTreeMap::<String, usize>::new();
    for row in &packages {
        if let Some(name) = row["file_name"].as_str() {
            *names.entry(name.to_lowercase()).or_default() += 1;
        }
    }
    for row in &mut packages {
        if row["file_name"].as_str().is_some_and(|name| names.get(&name.to_lowercase()).copied().unwrap_or(0) > 1) || package_sections != 1
        {
            row["projection_established"] = json!(false);
        }
    }
    if package_sections != 1 || packages.is_empty() || packages_omitted != 0 || names.values().any(|n| *n > 1) {
        reader.issue(root, "missing/repeated/limited package declarations or colliding file names; no first declaration selected");
    }
    let identity_known = identity_count == 1 && identities[0]["projection_established"] == true;
    let identity = if identity_known { identities[0].clone() } else { Value::Null };
    if !identity_known {
        reader.issue(root, "bundle identity is missing, ambiguous or unsupported");
    }
    let fact = json!({"source_sha256":aa_core::sha256_hex(bytes),"namespace":NS,"schema_version":root_fields["schema_version"],
        "identity":identity,"identity_status":if identity_count>1 {"ambiguous"} else if identity_count==0 {"missing"} else if identity_known {"unique"}else{"unsupported"},
        "identity_projection_established":identity_known,"identity_declarations":identities,"identity_declarations_omitted":identity_count.saturating_sub(16),
        "packages":packages,"packages_omitted":packages_omitted,"package_sections":package_sections,
        "projection_issues":reader.issues,"projection_issues_omitted":reader.omitted,"xml_offset_basis":"decoded-UTF8-XML",
        "schema_validated":false,"package_signature_checked":false,"references_resolved":false});
    if serde_json::to_vec(&fact).map_err(|_| "bundle projection serialization")?.len() > 8 * 1024 * 1024 {
        return Err("bundle projection output byte budget");
    }
    Ok(fact)
}

pub(super) fn analyze(file: &Artifact, bytes: &[u8], out: &mut Output) {
    if !file.name().eq_ignore_ascii_case("AppxBundleManifest.xml") {
        return;
    }
    let fact = match read(bytes) {
        Ok(fact) if file.digests.as_ref().is_some_and(|d| fact["source_sha256"] == d.sha256) => fact,
        Ok(_) => {
            out.limitation("windows.msix-bundle-unreadable", Some(file), Some("bundle manifest differs from captured digest".into()));
            return;
        }
        Err(reason) => {
            out.limitation("windows.msix-bundle-unreadable", Some(file), Some(reason.into()));
            return;
        }
    };
    out.kind(file, "msix-bundle-manifest");
    out.finding(
        Finding::new(Section::Structure, "windows", "windows.msix-bundle", Confidence::Verified, Severity::Info)
            .param("count", fact["packages"].as_array().map_or(0, Vec::len))
            .evidence(Evidence::field(
                file,
                "Bundle/Identity and Packages",
                json!({"identity":fact["identity"],"packages":fact["packages"].as_array().into_iter().flatten().take(6).collect::<Vec<_>>()}),
            )),
    );
    out.limitation("windows.msix-bundle-scope", Some(file), None);
    if !fact["projection_issues"].as_array().is_some_and(Vec::is_empty) || fact["projection_issues_omitted"] != 0 {
        out.limitation(
            "windows.msix-bundle-unresolved",
            Some(file),
            Some("unread, ambiguous, redacted or limited declarations are recorded in projection_issues".into()),
        );
    }
    out.fact(file, "windows.msix-bundle", fact);
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = r#"<Identity Name="Fixture.Bundle" Publisher="CN=Fixture" Version="2.0.0.0"/>"#;
    const PACKAGE: &str = r#"<Package Type="application" Version="1.0.0.0" Architecture="x86" FileName="app.appx" Offset="40" Size="200"><Resources><Resource Language="en-US"/></Resources></Package>"#;
    fn xml(body: &str) -> String {
        format!(r#"<Bundle xmlns="{NS}" SchemaVersion="1.0">{body}</Bundle>"#)
    }
    fn project(body: &str) -> Value {
        read(xml(body).as_bytes()).expect("bounded bundle declarations")
    }

    #[test]
    fn namespaces_cardinality_and_field_failures_do_not_select_first_candidates() {
        let base = format!("{ID}<Packages>{PACKAGE}</Packages>");
        let fact = project(&base);
        assert_eq!(fact["identity_status"], "unique");
        assert_eq!(fact["packages"][0]["offset"], 40);
        assert_eq!(fact["packages"][0]["version"], "1.0.0.0");
        let qualifiers = project(&base.replace("Language=\"en-US\"", "Scale=\"150\" DXFeatureLevel=\"dx11\""));
        assert_eq!(qualifiers["packages"][0]["resources"][0]["scale"], "150");
        assert_eq!(qualifiers["packages"][0]["resources"][0]["dx_feature_level"], "dx11");
        let foreign_resource = project(&base.replace("<Resource Language", "<Resource xmlns=\"urn:foreign\" Language"));
        assert_eq!(foreign_resource["packages"][0]["resources_projection_established"], false);
        let repeated = project(&format!("{ID}{base}"));
        assert_eq!(repeated["identity_status"], "ambiguous");
        assert!(repeated["identity"].is_null());
        let duplicate = project(&format!("{ID}<Packages>{PACKAGE}{PACKAGE}</Packages>"));
        assert!(duplicate["packages"].as_array().expect("packages").iter().all(|r| r["projection_established"] == false));
        let repeated_sections = project(&format!("{base}<Packages>{PACKAGE}</Packages>"));
        assert_eq!(repeated_sections["packages"][0]["projection_established"], false);
        let foreign = project(&format!("<evil:Identity xmlns:evil=\"urn:evil\" Name=\"Fake\"/>{base}"));
        assert_eq!(foreign["identity"]["name"], "Fixture.Bundle");
        let nested = project(&format!("<Wrapper>{ID}</Wrapper><Packages>{PACKAGE}</Packages>"));
        assert_eq!(nested["identity_status"], "missing");
        for bad in [
            PACKAGE.replace("Offset=\"40\"", "Offset=\"18446744073709551616\""),
            PACKAGE.replace("1.0.0.0", "65536.0.0.0"),
            PACKAGE.replace("Architecture=\"x86\"", "Architecture=\"unknown\""),
            PACKAGE.replace("Type=\"application\"", "Type=\"unknown\""),
        ] {
            assert_eq!(project(&format!("{ID}<Packages>{bad}</Packages>"))["packages"][0]["projection_established"], false);
        }
        assert!(read(xml(&base).replace(NS, "urn:wrong").as_bytes()).is_err());
        assert!(read(format!("<!DOCTYPE Bundle [<!ENTITY x 'bad'>]>{}", xml(&base)).as_bytes()).is_err());
    }

    #[test]
    fn decoding_redaction_and_count_text_and_output_limits_are_explicit() {
        let base = xml(&format!("{ID}<Packages>{PACKAGE}</Packages>"));
        let utf16: Vec<_> = [vec![255, 254], base.encode_utf16().flat_map(u16::to_le_bytes).collect()].concat();
        assert_eq!(read(&utf16).expect("UTF16")["identity_status"], "unique");
        assert!(read(b"\xffinvalid").is_err());
        assert!(read(format!("<?xml version=\"1.0\" encoding=\"UTF-16\"?>{base}").as_bytes()).is_err());
        assert!(read(&vec![b' '; MAX_XML + 1]).is_err());
        assert!(read(xml(&"<Unknown/>".repeat(100_001)).as_bytes()).is_err());
        let secret = format!("sk-proj-{}", "x".repeat(32));
        let fact = project(&ID.replace("CN=Fixture", &secret));
        assert_eq!(fact["identity_projection_established"], false);
        assert!(!fact.to_string().contains(&secret));
        let fact = project(&ID.replace("Fixture.Bundle", &"x".repeat(8193)));
        assert_eq!(fact["identity_projection_established"], false);
        let fact = project(&format!("{ID}<Packages>{}</Packages>", PACKAGE.repeat(1025)));
        assert_eq!(fact["packages_omitted"], 1);
        assert_eq!(fact["packages"].as_array().expect("bounded rows").len(), 1024);
        assert!(serde_json::to_vec(&fact).expect("bounded projection").len() < 8 * 1024 * 1024);
        let issues = project(&format!("{ID}{}", "<Unknown/>".repeat(100)));
        assert_eq!(issues["projection_issues"].as_array().expect("bounded issues").len(), 64);
        assert!(issues["projection_issues_omitted"].as_u64().expect("omissions") > 0);
    }
}
