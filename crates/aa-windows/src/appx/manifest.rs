//! Namespace/path projections, not XSD validation or a claim of installability.

use roxmltree::Node;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const FOUNDATION: &str = "http://schemas.microsoft.com/appx/manifest/foundation/windows10";
const LEGACY: &str = "http://schemas.microsoft.com/appx/2010/manifest";
const UAP: &str = "http://schemas.microsoft.com/appx/manifest/uap/windows10";
const RESCAP: &str = "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities";
const DESKTOP: &str = "http://schemas.microsoft.com/appx/manifest/desktop/windows10";
const LEGACY_EXT: &str = "http://schemas.microsoft.com/appx/2013/manifest";
const FIELD: usize = 8192;

fn is(node: Node<'_, '_>, ns: &str, name: &str) -> bool {
    node.is_element() && node.tag_name().namespace() == Some(ns) && node.tag_name().name() == name
}

pub(super) fn quad(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|s| !s.is_empty() && s.len() <= 5 && s.bytes().all(|b| b.is_ascii_digit()) && s.parse::<u16>().is_ok())
}

struct Reader {
    issues: Vec<Value>,
    omitted: usize,
    text_left: usize,
}
impl Reader {
    fn issue(&mut self, node: Node<'_, '_>, reason: &str) {
        if self.issues.len() < 64 {
            self.issues.push(
                json!({"xml_offset":node.range().start,"xml_length":node.range().len(),"offset_basis":"decoded-UTF8-XML","reason":reason}),
            );
        } else {
            self.omitted += 1;
        }
    }
    fn literal(&mut self, node: Node<'_, '_>, value: &str) -> Option<String> {
        if value.len() > FIELD || value.len() > self.text_left {
            self.issue(node, "metadata text field or aggregate byte limit");
            return None;
        }
        self.text_left -= value.len();
        match aa_core::text::redact_sensitive_text(value) {
            Ok(text) => {
                if text != value {
                    self.issue(node, "credential-like metadata was redacted; it cannot establish an identity projection");
                }
                Some(text)
            }
            Err(_) => {
                self.issue(node, "metadata redaction limit");
                None
            }
        }
    }
    fn attr(&mut self, node: Node<'_, '_>, name: &str) -> Option<String> {
        node.attribute(name).and_then(|v| self.literal(node, v))
    }
    fn shape(&mut self, node: Node<'_, '_>, attributes: &[&str], children: bool) -> bool {
        let mut supported = true;
        for a in node.attributes() {
            if a.namespace().is_some() || !attributes.contains(&a.name()) {
                self.issue(node, "unread attribute or attribute namespace");
                supported = false;
            }
        }
        if node.children().any(|n| (n.is_text() && n.text().is_some_and(|s| !s.trim().is_empty())) || (!children && n.is_element())) {
            self.issue(node, "unexpected element or non-whitespace text");
            supported = false;
        }
        supported
    }
    fn scalar(&mut self, node: Node<'_, '_>) -> Option<String> {
        if node.attributes().len() != 0 || node.children().any(|n| n.is_element()) {
            self.issue(node, "scalar property has unread structure");
            return None;
        }
        let mut text = String::new();
        for child in node.children().filter(|n| n.is_text()) {
            let part = child.text().unwrap_or("");
            if text.len() + part.len() > FIELD {
                self.issue(node, "property text field limit");
                return None;
            }
            text.push_str(part);
        }
        self.literal(node, text.trim())
    }
    fn extensions(&mut self, section: Node<'_, '_>, base: &str, legacy: &mut Vec<Value>, declarations: &mut Vec<Value>, count: &mut usize) {
        self.shape(section, &[], true);
        for node in section.children().filter(Node::is_element) {
            *count += 1;
            if *count > 200 {
                self.issue(node, "extension count limit");
                continue;
            }
            let ns = node.tag_name().namespace().unwrap_or("");
            if node.tag_name().name() != "Extension"
                || !(ns == base || ns == LEGACY_EXT || (base == FOUNDATION && [UAP, DESKTOP].contains(&ns)))
            {
                self.issue(node, "unread extension namespace or element");
                continue;
            }
            let start = self.issues.len() + self.omitted;
            let supported = self.shape(node, &["Category", "Executable", "EntryPoint", "StartPage"], true);
            let category = self.attr(node, "Category");
            let executable = self.attr(node, "Executable");
            let mut details = Vec::new();
            for child in node.children().filter(Node::is_element) {
                let key = match child.tag_name().name() {
                    "Protocol" | "FileTypeAssociation" | "AppExecutionAlias" | "Service" => "Name",
                    "StartupTask" => "TaskId",
                    _ => {
                        self.issue(child, "unread extension detail element");
                        continue;
                    }
                };
                if child.tag_name().namespace() != Some(ns) {
                    self.issue(child, "unread extension detail namespace");
                    continue;
                }
                self.shape(child, &[key, "DisplayName", "Executable", "EntryPoint", "Enabled"], true);
                if child.children().any(|n| n.is_element()) {
                    self.issue(child, "nested extension detail remains unread");
                }
                if let Some(value) = self.attr(child, key) {
                    details.push(value);
                }
            }
            if category.as_deref().is_none_or(str::is_empty) {
                self.issue(node, "extension category absent");
            }
            if details.len() > 1 {
                self.issue(node, "multiple extension details; no single detail selected");
            }
            let detail = if details.len() == 1 {
                Some(details[0].clone())
            } else if details.is_empty() {
                executable.clone()
            } else {
                None
            };
            legacy.push(json!({"category":category,"detail":detail}));
            declarations.push(json!({"namespace":ns,"category":category,"details":details,"executable":executable,"scope":if section.parent().is_some_and(|p|is(p,base,"Application")) {"application"}else{"package"},
                "projection_supported":supported && start==self.issues.len()+self.omitted,"xml_offset":node.range().start}));
        }
    }
}

pub(super) fn read(bytes: &[u8]) -> Result<Value, &'static str> {
    let text = crate::msix_xml::decode(bytes, 16 * 1024 * 1024)?;
    let document = roxmltree::Document::parse_with_options(&text, roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: 100_000 })
        .map_err(|_| "manifest XML is malformed or exceeds its node budget")?;
    let root = document.root_element();
    let ns = root.tag_name().namespace().unwrap_or("");
    if root.tag_name().name() != "Package" || ![FOUNDATION, LEGACY].contains(&ns) {
        return Err("manifest root or namespace is outside supported package profile");
    }
    let mut reader = Reader { issues: Vec::new(), omitted: 0, text_left: 1024 * 1024 };
    reader.shape(root, &["IgnorableNamespaces"], true);
    if root.attribute("IgnorableNamespaces").is_some_and(|v| {
        v.len() > FIELD
            || v.split_ascii_whitespace().take(33).count() > 32
            || v.split_ascii_whitespace().any(|p| root.lookup_namespace_uri(Some(p)).is_none())
    }) {
        reader.issue(root, "unresolved or oversized IgnorableNamespaces declaration");
    }
    let identities: Vec<_> = root.children().filter(|n| is(*n, ns, "Identity")).collect();
    let mut identity_declarations = Vec::new();
    for node in identities.iter().take(16).copied() {
        let start = reader.issues.len() + reader.omitted;
        let shape = reader.shape(node, &["Name", "Publisher", "Version", "ProcessorArchitecture", "ResourceId"], false);
        let name = reader.attr(node, "Name");
        let publisher = reader.attr(node, "Publisher");
        let version = reader.attr(node, "Version");
        let architecture = reader.attr(node, "ProcessorArchitecture");
        let resource_id = reader.attr(node, "ResourceId");
        let required = [&name, &publisher, &version].iter().all(|v| v.as_deref().is_some_and(|s| !s.is_empty()));
        let values = version.as_deref().is_some_and(quad)
            && architecture.as_deref().is_none_or(|s| matches!(s, "x86" | "x64" | "arm" | "arm64" | "x86a64" | "neutral"));
        if !required || !values {
            reader.issue(node, "required identity fields, quad version or architecture are outside projection profile");
        }
        identity_declarations.push(json!({"identity":{"name":name,"publisher":publisher,"version":version,"architecture":architecture,"resource_id":resource_id},
            "projection_supported":shape && required && values && start==reader.issues.len()+reader.omitted,"xml_offset":node.range().start}));
    }
    if identities.len() != 1 {
        reader.issue(root, "no unique direct identity in the package namespace");
    }
    if identities.len() > 16 {
        reader.issue(root, "identity declaration count limit");
    }
    let identity_status = match identities.len() {
        0 => "missing",
        1 if identity_declarations[0]["projection_supported"] == true => "unique",
        1 => "unsupported",
        _ => "ambiguous",
    };
    let identity = if identity_status == "unique" { identity_declarations[0]["identity"].clone() } else { Value::Null };
    let mut properties: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut property_declarations = Vec::new();
    let mut property_sections = 0;
    let mut capabilities = Vec::new();
    let mut capability_declarations = Vec::new();
    let mut cap_count = 0usize;
    let mut applications = Vec::new();
    let mut application_declarations = Vec::new();
    let mut app_count = 0usize;
    let mut app_ids = BTreeMap::<String, usize>::new();
    let mut extensions = Vec::new();
    let mut extension_declarations = Vec::new();
    let mut ext_count = 0;
    let mut dependencies = Vec::new();
    let mut device_families = Vec::new();
    let mut dep_count = 0usize;
    let mut resources = Vec::new();
    let mut resource_count = 0usize;
    let mut resources_complete = true;
    let mut families_complete = true;
    let mut sections = BTreeMap::<&str, usize>::new();
    for section in root.children().filter(Node::is_element) {
        if is(section, ns, "Identity") {
            continue;
        }
        if section.tag_name().namespace() != Some(ns) {
            reader.issue(section, "root child namespace remains unread");
            continue;
        }
        let name = section.tag_name().name();
        *sections.entry(name).or_default() += 1;
        match name {
            "Properties" => {
                property_sections += 1;
                reader.shape(section, &[], true);
                for child in section.children().filter(Node::is_element) {
                    if property_declarations.len() >= 64 {
                        reader.issue(child, "property declaration count limit");
                        continue;
                    }
                    let key = child.tag_name().name();
                    if child.tag_name().namespace() != Some(ns)
                        || !["DisplayName", "PublisherDisplayName", "Description", "Logo", "Framework", "ResourcePackage"].contains(&key)
                    {
                        reader.issue(child, "unread property element or namespace");
                        continue;
                    }
                    let value = reader.scalar(child);
                    let value = json!(value);
                    properties.entry(key.into()).or_default().push(value.clone());
                    property_declarations.push(json!({"name":key,"value":value,"xml_offset":child.range().start}));
                }
            }
            "Capabilities" => {
                reader.shape(section, &[], true);
                for child in section.children().filter(Node::is_element) {
                    cap_count += 1;
                    if cap_count > 200 {
                        reader.issue(child, "capability declaration count limit");
                        continue;
                    }
                    let cns = child.tag_name().namespace().unwrap_or("");
                    let kind = child.tag_name().name();
                    if !((cns == ns && matches!(kind, "Capability" | "DeviceCapability"))
                        || (ns == FOUNDATION && [UAP, RESCAP].contains(&cns) && kind == "Capability"))
                    {
                        reader.issue(child, "unread capability element or namespace");
                        continue;
                    }
                    let start = reader.issues.len() + reader.omitted;
                    let shape = reader.shape(child, &["Name"], false);
                    let name = reader.attr(child, "Name");
                    if name.as_deref().is_none_or(str::is_empty) {
                        reader.issue(child, "capability name absent");
                    }
                    if let Some(name) = name.as_ref() {
                        capabilities.push(name.clone());
                    }
                    capability_declarations.push(json!({"kind":kind,"namespace":cns,"name":name,"projection_supported":shape && start==reader.issues.len()+reader.omitted,"xml_offset":child.range().start}));
                }
            }
            "Applications" => {
                reader.shape(section, &[], true);
                for app in section.children().filter(Node::is_element) {
                    app_count += 1;
                    if app_count > 50 {
                        reader.issue(app, "application declaration count limit");
                        continue;
                    }
                    if !is(app, ns, "Application") {
                        reader.issue(app, "unread application element or namespace");
                        continue;
                    }
                    let start = reader.issues.len() + reader.omitted;
                    let shape = reader.shape(app, &["Id", "Executable", "EntryPoint", "StartPage"], true);
                    let id = reader.attr(app, "Id");
                    let executable = reader.attr(app, "Executable");
                    let entry_point = reader.attr(app, "EntryPoint");
                    let start_page = reader.attr(app, "StartPage");
                    if let Some(id) = id.as_ref().filter(|s| !s.is_empty()) {
                        *app_ids.entry(id.clone()).or_default() += 1;
                    } else {
                        reader.issue(app, "application id absent");
                    }
                    applications.push(json!({"id":id,"executable":executable,"entry_point":entry_point}));
                    let extension_start = extension_declarations.len();
                    let mut extension_sections = 0;
                    for child in app.children().filter(Node::is_element) {
                        if is(child, ns, "Extensions") {
                            extension_sections += 1;
                            reader.extensions(child, ns, &mut extensions, &mut extension_declarations, &mut ext_count);
                        } else {
                            reader.issue(child, "application child remains unread");
                        }
                    }
                    if extension_sections > 1 {
                        reader.issue(app, "application extension section is repeated");
                        for row in &mut extension_declarations[extension_start..] {
                            row["projection_supported"] = json!(false);
                        }
                    }
                    application_declarations.push(json!({"id":id,"executable":executable,"entry_point":entry_point,"start_page":start_page,"projection_supported":shape && start==reader.issues.len()+reader.omitted,"xml_offset":app.range().start}));
                }
            }
            "Extensions" => reader.extensions(section, ns, &mut extensions, &mut extension_declarations, &mut ext_count),
            "Dependencies" => {
                families_complete &= reader.shape(section, &[], true);
                for child in section.children().filter(Node::is_element) {
                    dep_count += 1;
                    if dep_count > 128 {
                        families_complete = false;
                        reader.issue(child, "dependency/device-family declaration count limit");
                        continue;
                    }
                    let kind = child.tag_name().name();
                    if child.tag_name().namespace() != Some(ns)
                        || !(kind == "PackageDependency" || (kind == "TargetDeviceFamily" && ns == FOUNDATION))
                    {
                        families_complete = false;
                        reader.issue(child, "unread dependency element or namespace");
                        continue;
                    }
                    let attrs = if kind == "PackageDependency" {
                        &["Name", "Publisher", "MinVersion", "MaxMajorVersionTested"][..]
                    } else {
                        &["Name", "MinVersion", "MaxVersionTested"][..]
                    };
                    let start = reader.issues.len() + reader.omitted;
                    let shape = reader.shape(child, attrs, false);
                    let mut fields = serde_json::Map::new();
                    for key in attrs {
                        let value = reader.attr(child, key);
                        if (key.ends_with("Version") || *key == "MaxVersionTested") && value.as_deref().is_some_and(|v| !quad(v)) {
                            reader.issue(child, "dependency version is outside quad profile");
                        }
                        fields.insert((*key).into(), json!(value));
                    }
                    if fields["Name"].as_str().is_none_or(str::is_empty) {
                        reader.issue(child, "dependency/device-family name absent");
                    }
                    if fields["MinVersion"].as_str().is_none_or(str::is_empty)
                        || (kind == "TargetDeviceFamily" && fields["MaxVersionTested"].as_str().is_none_or(str::is_empty))
                    {
                        reader.issue(child, "required dependency/device-family version is absent");
                    }
                    if kind == "PackageDependency" && fields["Publisher"].as_str().is_none_or(str::is_empty) {
                        reader.issue(child, "dependency publisher or unsigned-dependency semantics remain unresolved");
                    }
                    if fields
                        .get("MaxMajorVersionTested")
                        .and_then(Value::as_str)
                        .is_some_and(|v| v.is_empty() || v.len() > 5 || !v.bytes().all(|b| b.is_ascii_digit()) || v.parse::<u16>().is_err())
                    {
                        reader.issue(child, "maximum major version is outside unsigned-16-bit profile");
                    }
                    let record = json!({"attributes":fields,"projection_supported":shape && start==reader.issues.len()+reader.omitted,"xml_offset":child.range().start});
                    if kind == "PackageDependency" {
                        dependencies.push(record);
                    } else {
                        device_families.push(record);
                    }
                }
            }
            "Resources" => {
                resources_complete &= reader.shape(section, &[], true);
                for child in section.children().filter(Node::is_element) {
                    resource_count += 1;
                    if resource_count > 200 {
                        resources_complete = false;
                        reader.issue(child, "resource declaration count limit");
                        continue;
                    }
                    if !is(child, ns, "Resource") {
                        resources_complete = false;
                        reader.issue(child, "unread resource element or namespace");
                        continue;
                    }
                    let start = reader.issues.len() + reader.omitted;
                    let qualifier_ns = if ns == FOUNDATION { UAP } else { LEGACY_EXT };
                    let mut shape = true;
                    for attribute in child.attributes() {
                        if !((attribute.namespace().is_none() && attribute.name() == "Language")
                            || (attribute.namespace() == Some(qualifier_ns) && matches!(attribute.name(), "Scale" | "DXFeatureLevel")))
                        {
                            reader.issue(child, "resource attribute or namespace is outside the qualified profile");
                            shape = false;
                        }
                    }
                    if child.children().any(|n| n.is_element() || (n.is_text() && n.text().is_some_and(|s| !s.trim().is_empty()))) {
                        reader.issue(child, "resource has unread child content");
                        shape = false;
                    }
                    let language = reader.attr(child, "Language");
                    let scale = child.attribute((qualifier_ns, "Scale")).and_then(|v| reader.literal(child, v));
                    let dx_feature_level = child.attribute((qualifier_ns, "DXFeatureLevel")).and_then(|v| reader.literal(child, v));
                    resources.push(json!({"language":language,"scale":scale,"dx_feature_level":dx_feature_level,"projection_supported":shape && start==reader.issues.len()+reader.omitted,"xml_offset":child.range().start}));
                }
            }
            _ => reader.issue(section, "root section remains unread"),
        }
    }
    for (name, count) in &sections {
        if *count > 1 {
            reader.issue(root, "repeated package section; projections retain declarations separately");
            if *name == "Applications" {
                for row in &mut application_declarations {
                    row["projection_supported"] = json!(false);
                }
            }
            match *name {
                "Dependencies" => {
                    for row in dependencies.iter_mut().chain(device_families.iter_mut()) {
                        row["projection_supported"] = json!(false);
                    }
                }
                "Capabilities" => {
                    for row in &mut capability_declarations {
                        row["projection_supported"] = json!(false);
                    }
                }
                "Resources" => {
                    for row in &mut resources {
                        row["projection_supported"] = json!(false);
                    }
                }
                "Extensions" => {
                    for row in &mut extension_declarations {
                        if row["scope"] == "package" {
                            row["projection_supported"] = json!(false);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    for values in properties.values() {
        if values.len() > 1 {
            reader.issue(root, "repeated scalar property; no single value selected");
        }
    }
    for row in &mut application_declarations {
        if row["id"].as_str().is_some_and(|id| app_ids.get(id).is_some_and(|count| *count > 1)) {
            row["projection_supported"] = json!(false);
            reader.issue(root, "application id is repeated");
        }
    }
    for records in [&mut dependencies, &mut device_families] {
        let mut names = BTreeMap::<String, usize>::new();
        for row in records.iter() {
            if let Some(name) = row["attributes"]["Name"].as_str() {
                *names.entry(name.into()).or_default() += 1;
            }
        }
        for row in records.iter_mut() {
            if row["attributes"]["Name"].as_str().is_some_and(|n| names.get(n).is_some_and(|c| *c > 1)) {
                row["projection_supported"] = json!(false);
                reader.issue(root, "dependency/device-family name is repeated; constraints are not combined");
            }
        }
    }
    for required in ["Properties", "Dependencies"] {
        if !sections.contains_key(required) {
            reader.issue(root, "required package section is absent from the projection");
        }
    }
    capabilities.sort();
    capabilities.dedup();
    let property = |key: &str| {
        if property_sections == 1 {
            properties.get(key).filter(|v| v.len() == 1).map(|v| v[0].clone()).unwrap_or(Value::Null)
        } else {
            Value::Null
        }
    };
    let resource_sections = sections.get("Resources").copied().unwrap_or(0);
    let resource_profile = crate::msix_declarations::resource_dimensions(&resources, "projection_supported");
    let resources_known = resource_sections == 1 && resources_complete && resource_profile.is_ok();
    if resource_sections == 1
        && let Err(reason) = resource_profile
    {
        reader.issue(root, reason);
    }
    let family_profile = crate::msix_declarations::family_constraints(&device_families);
    let families_known =
        sections.get("Dependencies") == Some(&1) && families_complete && !device_families.is_empty() && family_profile.is_ok();
    if let Err(reason) = family_profile {
        reader.issue(root, reason);
    }
    let fact = json!({"source_sha256":aa_core::sha256_hex(bytes),"namespace":ns,"xml_offset_basis":"decoded-UTF8-XML","identity":identity,"identity_status":identity_status,
        "identity_projection_established":identity_status=="unique","identity_declarations":identity_declarations,"identity_declarations_omitted":identities.len().saturating_sub(16),
        "display_name":property("DisplayName"),"publisher_display_name":property("PublisherDisplayName"),"property_declarations":property_declarations,
        "resource_package":property("ResourcePackage"),"property_sections":property_sections,
        "capabilities":capabilities,"capability_declarations":capability_declarations,"capability_declarations_omitted":cap_count.saturating_sub(200),
        "applications":applications,"application_declarations":application_declarations,"application_declarations_omitted":app_count.saturating_sub(50),
        "extensions":extensions,"extension_declarations":extension_declarations,"extension_declarations_omitted":ext_count.saturating_sub(200),
        "dependencies":dependencies,"target_device_families":device_families,"dependency_declarations_omitted":dep_count.saturating_sub(128),
        "resources":resources,"resource_declarations_omitted":resource_count.saturating_sub(200),"resources_projection_established":resources_known,
        "resources_state":if resource_sections==0 {"not-declared"}else if resources_known {"projected"}else{"unresolved"},
        "target_device_families_projection_established":families_known,"target_device_families_state":if device_families.is_empty() && families_complete {"not-declared"}else if families_known {"projected"}else{"unresolved"},
        "projection_issues":reader.issues,"projection_issues_omitted":reader.omitted,
        "schema_validated":false,"references_resolved":false,"package_signature_checked":false,"zip_structure_checked":false});
    if serde_json::to_vec(&fact).map_err(|_| "manifest publication failed")?.len() > 8 * 1024 * 1024 {
        return Err("manifest fact byte limit");
    }
    Ok(fact)
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = r#"<Identity Name="Fixture.App" Publisher="CN=Fixture" Version="1.2.3.4" ProcessorArchitecture="x64"/>"#;
    fn package(body: &str) -> String {
        format!(r#"<Package xmlns="{FOUNDATION}" xmlns:uap="{UAP}" xmlns:rescap="{RESCAP}" xmlns:evil="urn:foreign">{body}</Package>"#)
    }
    fn project(body: &str) -> Value {
        read(package(body).as_bytes()).expect("bounded manifest declarations")
    }

    #[test]
    fn only_direct_qualified_identity_and_section_paths_establish_projections() {
        let body = format!(
            r#"<evil:Identity Name="Wrong" Publisher="CN=Wrong" Version="9.9.9.9"/><Wrapper><Identity Name="Nested" Publisher="CN=Nested" Version="8.8.8.8"/><Capability Name="runFullTrust"/><Application Id="Hidden"/></Wrapper>{ID}<Properties><DisplayName>Real<![CDATA[ Name]]></DisplayName></Properties><Dependencies/><Capabilities><evil:Capability Name="runFullTrust"/><Capability Name="internetClient"/></Capabilities>"#
        );
        let fact = project(&body);
        assert_eq!(fact["identity"]["name"], "Fixture.App");
        assert_eq!(fact["identity_status"], "unique");
        assert_eq!(fact["display_name"], "Real Name");
        assert_eq!(fact["capabilities"], json!(["internetClient"]));
        assert!(fact["applications"].as_array().expect("applications").is_empty());
        assert!(!fact["projection_issues"].as_array().expect("issues").is_empty());
        let legacy = package(ID).replace(FOUNDATION, LEGACY);
        let fact = read(legacy.as_bytes()).expect("constructed legacy profile");
        assert_eq!(fact["identity_status"], "unique");
        assert!(read(package(ID).replace(FOUNDATION, "urn:fake-foundation").as_bytes()).is_err());
        let fact =
            project(&format!("{ID}<Properties><DisplayName><![CDATA[<!DOCTYPE literal>]]></DisplayName></Properties><Dependencies/>"));
        assert_eq!(fact["display_name"], "<!DOCTYPE literal>");
    }

    #[test]
    fn identity_scalar_application_and_detail_duplicates_never_select_a_first_value() {
        for second in [ID, r#"<Identity Name="Other.App" Publisher="CN=Other" Version="2.0.0.0"/>"#] {
            let fact = project(&format!("{ID}{second}"));
            assert_eq!(fact["identity_status"], "ambiguous");
            assert!(fact["identity"].is_null());
            assert_eq!(fact["identity_declarations"].as_array().expect("identities").len(), 2);
        }
        let fact = project(&format!(
            r#"{ID}<Properties><DisplayName>One</DisplayName><DisplayName>Two</DisplayName></Properties><Dependencies/><Applications><Application Id="Same" Executable="one.exe"/><Application Id="Same" Executable="two.exe"/></Applications><Extensions><uap:Extension Category="windows.protocol"><uap:Protocol Name="one"/><uap:Protocol Name="two"/></uap:Extension></Extensions>"#
        ));
        assert!(fact["display_name"].is_null());
        assert_eq!(fact["property_declarations"].as_array().expect("properties").len(), 2);
        assert!(fact["application_declarations"].as_array().expect("applications").iter().all(|a| a["projection_supported"] == false));
        assert!(fact["extensions"][0]["detail"].is_null());
        assert_eq!(fact["extension_declarations"][0]["details"], json!(["one", "two"]));
    }

    #[test]
    fn dependencies_device_families_and_resources_are_literal_and_never_host_resolved() {
        let fact = project(&format!(
            r#"{ID}<Properties/><Dependencies><PackageDependency Name="Library" Publisher="CN=Library" MinVersion="1.2.3.4" MaxMajorVersionTested="5"/><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.26100.0"/><evil:PackageDependency Name="Ignored"/></Dependencies><Resources><Resource Language="en-us" Scale="200"/></Resources>"#
        ));
        assert_eq!(fact["dependencies"].as_array().expect("dependencies").len(), 1);
        assert_eq!(fact["dependencies"][0]["attributes"]["MinVersion"], "1.2.3.4");
        assert_eq!(fact["dependencies"][0]["projection_supported"], true);
        assert_eq!(fact["target_device_families"][0]["attributes"]["Name"], "Windows.Desktop");
        assert_eq!(fact["resources"][0]["language"], "en-us");
        assert_eq!(fact["references_resolved"], false);
        assert_eq!(fact["schema_validated"], false);
        assert_eq!(fact["package_signature_checked"], false);
        let fact = project(&format!(
            r#"{ID}<Dependencies><PackageDependency Name="Same" Publisher="CN=Library" MinVersion="1.0.0.0"/><PackageDependency Name="Same" Publisher="CN=Other" MinVersion="2.0.0.0"/><TargetDeviceFamily Name="Windows.Desktop" MinVersion="65536.0.0.0"/></Dependencies>"#
        ));
        assert!(fact["dependencies"].as_array().expect("dependencies").iter().all(|d| d["projection_supported"] == false));
        assert_eq!(fact["target_device_families"][0]["projection_supported"], false);
    }

    #[test]
    fn resource_qualifier_namespaces_cardinality_and_defaults_remain_distinct() {
        let body = format!(
            r#"{ID}<Properties/><Dependencies/><Resources><Resource Language="en-US"/><Resource uap:Scale="200"/><Resource uap:DXFeatureLevel="dx11"/></Resources>"#
        );
        let model = project(&body);
        assert_eq!(model["resources_projection_established"], true);
        assert_eq!(model["resources"][1]["scale"], "200");
        assert_eq!(model["resources"][2]["dx_feature_level"], "dx11");
        for bad in [
            body.replace("uap:Scale=", "Scale="),
            body.replace("uap:DXFeatureLevel=", "evil:DXFeatureLevel="),
            body.replace("<Resource Language=\"en-US\"/>", "<Resource Language=\"en-US\"/><Resource Language=\"EN-us\"/>"),
            format!("{body}<Resources><Resource Language=\"fr-FR\"/></Resources>"),
        ] {
            assert_eq!(project(&bad)["resources_projection_established"], false);
        }
        let legacy = package(&body).replace(FOUNDATION, LEGACY).replace(UAP, LEGACY_EXT);
        assert_eq!(read(legacy.as_bytes()).expect("legacy qualified resources")["resources_projection_established"], true);
        assert_eq!(project(ID)["resources_state"], "not-declared");
        assert_eq!(project(&format!("{ID}<Resources/>"))["resources_state"], "projected");
    }

    #[test]
    fn strict_encodings_dtds_and_unsupported_identity_fields_remain_explicit() {
        let xml = format!("<?xml version='1.0' encoding='utf-16'?>{}", package(ID));
        for little in [true, false] {
            let mut bytes = if little { vec![255, 254] } else { vec![254, 255] };
            for unit in xml.encode_utf16() {
                bytes.extend(if little { unit.to_le_bytes() } else { unit.to_be_bytes() });
            }
            assert_eq!(read(&bytes).expect("strict BOM UTF16")["identity_status"], "unique");
        }
        assert!(read(format!("<?xml version='1.0' encoding='windows-1252'?>{}", package(ID)).as_bytes()).is_err());
        assert!(read(format!(r#"<!DOCTYPE Package [<!ENTITY x "expanded">]>{}"#, package(ID)).as_bytes()).is_err());
        for bytes in [&[255, 254, 0][..], &[255][..], &[0, 0, 0][..]] {
            assert!(read(bytes).is_err());
        }
        for changed in [
            ID.replace("1.2.3.4", "65536.0.0.0"),
            ID.replace("x64", "unsupported"),
            ID.replace("Publisher=", "evil:Publisher="),
            ID.replace("Name=\"Fixture.App\"", "Name=\"\""),
        ] {
            let fact = project(&changed);
            assert_eq!(fact["identity_status"], "unsupported");
            assert!(fact["identity"].is_null());
            assert_eq!(fact["identity_declarations"].as_array().expect("identity").len(), 1);
        }
        let secret = format!("AKIA{}", "A".repeat(16));
        let fact = project(&ID.replace("Fixture.App", &secret));
        assert_eq!(fact["identity_status"], "unsupported");
        assert!(!serde_json::to_string(&fact).expect("fact").contains(&secret));
    }

    #[test]
    fn counts_text_issue_and_document_limits_report_omissions_without_unbounded_facts() {
        let fact = project(&format!("{}{}<Dependencies/>", ID.repeat(17), "<Properties/>"));
        assert_eq!(fact["identity_status"], "ambiguous");
        assert_eq!(fact["identity_declarations_omitted"], 1);
        let fields = "<Capability Name=\"internetClient\"/>".repeat(201);
        let fact = project(&format!("{ID}<Capabilities>{fields}</Capabilities>"));
        assert_eq!(fact["capability_declarations_omitted"], 1);
        let fields = format!("<Capability Name=\"{}\"/>", "p".repeat(8190)).repeat(200);
        let fact = project(&format!("{ID}<Capabilities>{fields}</Capabilities>"));
        assert!(fact["projection_issues_omitted"].as_u64().expect("omissions") > 0);
        assert!(serde_json::to_vec(&fact).expect("fact").len() < 8 * 1024 * 1024);
        let fact = project(&ID.replace("Fixture.App", &"x".repeat(8193)));
        assert_eq!(fact["identity_status"], "unsupported");
        assert!(read(&vec![b' '; 16 * 1024 * 1024 + 1]).is_err());
        assert!(read(package(&"<Unknown/>".repeat(100_001)).as_bytes()).is_err());
    }
}
