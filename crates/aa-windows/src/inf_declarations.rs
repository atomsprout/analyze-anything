//! Bounded source relationships, without choosing an installation platform or host state.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde::Serialize;
use serde_json::{Value, json};

use super::{Entry, Inf};

const MAX_RECORDS: usize = 4096;
const MAX_EDGES: usize = 8192;
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_TARGETS: usize = 16;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Role {
    Install,
    ClassInstall,
    Services,
    Hardware,
    CoInstallers,
    Service,
    EventLog,
    Files,
    Registry,
}

struct Graph<'a> {
    inf: &'a Inf,
    names: BTreeMap<String, Vec<usize>>,
    namespace_complete: bool,
    records: Vec<Value>,
    edges: Vec<Value>,
    bytes: usize,
    omitted: usize,
    unresolved: usize,
    evidence: Vec<(usize, usize)>,
    roles: BTreeSet<(usize, Role)>,
    pending: BTreeSet<(usize, Role)>,
    context: Option<Role>,
}

fn fields(entry: &Entry) -> &[String] {
    entry.neutral_fields.as_deref().unwrap_or(&entry.fields)
}

fn field(entry: &Entry, index: usize) -> &str {
    fields(entry).get(index).map(String::as_str).unwrap_or("")
}

fn number(text: &str) -> Option<u32> {
    let (digits, radix) =
        if let Some(digits) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) { (digits, 16) } else { (text, 10) };
    if digits.is_empty() || !digits.bytes().all(|b| if radix == 16 { b.is_ascii_hexdigit() } else { b.is_ascii_digit() }) {
        return None;
    }
    u32::from_str_radix(digits, radix).ok()
}

// Companions are not install alternatives. Unknown version/build tokens stay outside
// the profile; the common unbuilt WDK architecture token is retained as a source shape.
fn install_name(name: &str, base: &str) -> bool {
    if name.eq_ignore_ascii_case(base) {
        return true;
    }
    let name = name.to_ascii_lowercase();
    let prefix = format!("{}.", base.to_ascii_lowercase());
    let Some(suffix) = name.strip_prefix(&prefix) else { return false };
    let mut pieces = suffix.split('.');
    matches!(pieces.next(), Some("nt" | "ntx86" | "ntia64" | "ntamd64" | "ntarm" | "ntarm64" | "nt$arch$"))
        && pieces.all(|piece| piece.bytes().all(|b| b.is_ascii_digit()))
}

fn media_name(name: &str, base: &str) -> bool {
    name.eq_ignore_ascii_case(base)
        || ["x86", "ia64", "amd64", "arm", "arm64"].iter().any(|arch| name.eq_ignore_ascii_case(&format!("{base}.{arch}")))
}

impl<'a> Graph<'a> {
    fn new(inf: &'a Inf) -> Self {
        let mut names: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (index, section) in inf.sections.iter().enumerate() {
            names.entry(section.name.to_ascii_lowercase()).or_default().push(index);
        }
        Self {
            inf,
            names,
            namespace_complete: inf.issue_count == 0
                && !inf.truncated
                && inf.sections.iter().all(|s| s.name.is_ascii() && !s.name.contains("[redacted")),
            records: Vec::new(),
            edges: Vec::new(),
            bytes: 0,
            omitted: 0,
            unresolved: 0,
            evidence: Vec::new(),
            roles: BTreeSet::new(),
            pending: BTreeSet::new(),
            context: None,
        }
    }

    fn admit(&mut self, value: &Value, edge: bool) -> bool {
        let count = if edge { self.edges.len() } else { self.records.len() };
        let limit = if edge { MAX_EDGES } else { MAX_RECORDS };
        if count >= limit || self.bytes >= MAX_OUTPUT_BYTES {
            self.omitted += 1;
            return false;
        }
        let size = serde_json::to_vec(value).map_or(MAX_OUTPUT_BYTES + 1, |bytes| bytes.len());
        if self.bytes.saturating_add(size) > MAX_OUTPUT_BYTES {
            self.omitted += 1;
            return false;
        }
        self.bytes += size;
        true
    }

    fn record(&mut self, section: usize, entry: usize, kind: &str, details: Value) {
        let source = &self.inf.sections[section].entries[entry];
        let value = json!({"kind":kind,"section":section,"entry":entry,"line":source.line,"end_line":source.end_line,
            "field_basis":if source.neutral_fields.is_some(){"neutral-projection"}else{"literal"},"details":details});
        if self.admit(&value, false) {
            self.records.push(value);
            if self.evidence.len() < 12 && !self.evidence.contains(&(section, entry)) {
                self.evidence.push((section, entry));
            }
        }
    }

    fn reference(&mut self, section: usize, entry: usize, field: usize, name: &str, kind: &str, alternatives: bool) -> Vec<usize> {
        if self.edges.len() >= MAX_EDGES || self.bytes >= MAX_OUTPUT_BYTES {
            self.omitted += 1;
            return Vec::new();
        }
        let targets: Vec<_> = if self.namespace_complete && !name.is_empty() && !name.contains(['%', '[', ']']) && name.is_ascii() {
            if alternatives {
                self.inf.sections.iter().enumerate().filter(|(_, s)| install_name(&s.name, name)).map(|(i, _)| i).collect()
            } else {
                self.names.get(&name.to_ascii_lowercase()).cloned().unwrap_or_default()
            }
        } else {
            Vec::new()
        };
        let status = if !self.namespace_complete {
            "section-namespace-incomplete-redacted-or-non-ascii"
        } else if name.is_empty() || name.contains(['%', '$', '[', ']']) || !name.is_ascii() {
            "unexpanded-or-unsupported-section-name"
        } else if targets.is_empty() {
            "no-supplied-section-occurrence"
        } else if alternatives {
            "declared-alternatives-no-platform-selection"
        } else if targets.len() == 1 {
            "single-source-occurrence"
        } else {
            "multiple-source-occurrences-no-selection"
        };
        if !matches!(status, "single-source-occurrence" | "declared-alternatives-no-platform-selection") {
            self.unresolved += 1;
        }
        let retained: Vec<_> = targets.iter().copied().take(MAX_TARGETS).collect();
        let value = json!({"kind":kind,"source_section":section,"source_entry":entry,"source_field":field,"source_role":self.context,
            "reference":name,"status":status,"target_sections":retained,"observed_target_count":targets.len(),"targets_truncated":targets.len()>MAX_TARGETS});
        if targets.len() > MAX_TARGETS {
            self.omitted += targets.len() - MAX_TARGETS;
        }
        if self.admit(&value, true) {
            self.edges.push(value);
            retained
        } else {
            Vec::new()
        }
    }

    fn assign(&mut self, targets: Vec<usize>, role: Role) {
        for target in targets {
            if self.roles.insert((target, role)) {
                self.pending.insert((target, role));
            }
        }
    }

    fn roots(&mut self) {
        let mut models = BTreeSet::new();
        for (section_index, section) in self.inf.sections.iter().enumerate() {
            if install_name(&section.name, "DefaultInstall") {
                self.assign(vec![section_index], Role::Install);
            }
            if install_name(&section.name, "ClassInstall32") {
                self.assign(vec![section_index], Role::ClassInstall);
            }
            for (entry_index, entry) in section.entries.iter().enumerate() {
                if section.name.eq_ignore_ascii_case("Version") {
                    let key = entry.key.as_deref().unwrap_or("").to_ascii_lowercase();
                    if matches!(
                        key.as_str(),
                        "provider" | "driverver" | "class" | "classguid" | "signature" | "pnplockdown" | "catalogfile"
                    ) || key
                        .strip_prefix("catalogfile.")
                        .is_some_and(|suffix| matches!(suffix, "nt" | "ntx86" | "ntia64" | "ntamd64" | "ntarm" | "ntarm64"))
                    {
                        self.record(section_index, entry_index, "version-declaration", json!({"name":entry.key,"values":fields(entry)}));
                    }
                } else if section.name.eq_ignore_ascii_case("Manufacturer") {
                    let base = field(entry, 0);
                    self.record(
                        section_index,
                        entry_index,
                        "manufacturer",
                        json!({"description_literal":entry.key,
                        "models_base":base,"target_os_versions":fields(entry).get(1..).unwrap_or_default()}),
                    );
                    if entry.key.is_none() && fields(entry).len() != 1 {
                        self.unresolved += 1;
                        continue;
                    }
                    if fields(entry).len() <= 1 {
                        models.extend(self.reference(section_index, entry_index, 0, base, "manufacturer-models", false));
                    } else {
                        for (index, decoration) in fields(entry).iter().enumerate().skip(1) {
                            models.extend(self.reference(
                                section_index,
                                entry_index,
                                index,
                                &format!("{base}.{decoration}"),
                                "manufacturer-models",
                                false,
                            ));
                        }
                    }
                } else if media_name(&section.name, "SourceDisksFiles") {
                    self.record(section_index, entry_index, "source-file", json!({"filename_literal":entry.key,"disk_id":field(entry,0),
                        "subdirectory":field(entry,1),"declared_size":field(entry,2),"extra_fields":fields(entry).get(3..).unwrap_or_default(),"source_path_resolved":false}));
                } else if media_name(&section.name, "SourceDisksNames") {
                    self.record(section_index, entry_index, "source-media", json!({"disk_id_literal":entry.key,"description":field(entry,0),
                        "tag_or_cab":field(entry,1),"path":field(entry,3),"flags":field(entry,4),"tag_file":field(entry,5),"media_root_resolved":false}));
                } else if section.name.eq_ignore_ascii_case("DestinationDirs") {
                    self.record(
                        section_index,
                        entry_index,
                        "destination-directory",
                        json!({"file_list_literal":entry.key,
                        "directory_id":field(entry,0),"subdirectory":field(entry,1),"host_path_resolved":false}),
                    );
                }
            }
        }
        for section in models {
            for (entry_index, entry) in self.inf.sections[section].entries.iter().enumerate() {
                self.record(
                    section,
                    entry_index,
                    "device-model",
                    json!({"description_literal":entry.key,"install_base":field(entry,0),
                    "hardware_id":field(entry,1),"compatible_ids":fields(entry).get(2..).unwrap_or_default()}),
                );
                let targets = self.reference(section, entry_index, 0, field(entry, 0), "model-install-alternatives", true);
                self.assign(targets, Role::Install);
            }
        }
        let roots: Vec<_> = self.roles.iter().filter(|(_, role)| *role == Role::Install).map(|(i, _)| *i).collect();
        for section in roots {
            for (suffix, role) in [("Services", Role::Services), ("HW", Role::Hardware), ("CoInstallers", Role::CoInstallers)] {
                // A companion's absence is ordinary; references are created only for declared occurrences.
                let name = format!("{}.{suffix}", self.inf.sections[section].name).to_ascii_lowercase();
                if self.namespace_complete {
                    let targets = self.names.get(&name).cloned().unwrap_or_default();
                    if targets.is_empty() {
                        continue;
                    }
                    let retained: Vec<_> = targets.iter().copied().take(MAX_TARGETS).collect();
                    let value = json!({"kind":"install-companion","source_section":section,"source_line":self.inf.sections[section].line,
                        "companion":suffix,"target_sections":retained,"observed_target_count":targets.len(),"targets_truncated":targets.len()>MAX_TARGETS,
                        "platform_selected":false});
                    self.omitted += targets.len().saturating_sub(MAX_TARGETS);
                    if self.admit(&value, true) {
                        self.edges.push(value);
                        self.assign(retained, role);
                    }
                }
            }
        }
    }

    fn directives(&mut self, section: usize, role: Role) {
        for (entry_index, entry) in self.inf.sections[section].entries.iter().enumerate() {
            let key = entry.key.as_deref().unwrap_or("").to_ascii_lowercase();
            if matches!(key.as_str(), "include" | "needs") {
                self.unresolved += 1;
                self.record(
                    section,
                    entry_index,
                    "external-install-reference",
                    json!({"directive":entry.key,"values":fields(entry),"followed":false}),
                );
            } else if key == "addservice" && role == Role::Services {
                let flags = number(field(entry, 1));
                let null_service = fields(entry).len() == 2 && field(entry, 0).is_empty() && flags == Some(2);
                let shape_supported =
                    null_service || ((3..=6).contains(&fields(entry).len()) && !field(entry, 0).is_empty() && !field(entry, 2).is_empty());
                if !shape_supported || (!field(entry, 1).is_empty() && flags.is_none()) {
                    self.unresolved += 1;
                }
                self.record(section, entry_index, "service-addition", json!({"service_name":field(entry,0),"flags_literal":field(entry,1),"flags_u32":flags,
                    "null_associated_service":null_service,"shape_supported":shape_supported,"associated_service_flag":flags.map(|f|f & 2 != 0),"service_install_section":field(entry,2),
                    "event_log_section":field(entry,3),"extra_fields":fields(entry).get(4..).unwrap_or_default(),"flags_fully_interpreted":false}));
                if !null_service {
                    let targets = self.reference(section, entry_index, 2, field(entry, 2), "service-install", false);
                    self.assign(targets, Role::Service);
                    if !field(entry, 3).is_empty() {
                        let targets = self.reference(section, entry_index, 3, field(entry, 3), "event-log-install", false);
                        self.assign(targets, Role::EventLog);
                    }
                }
            } else if key == "copyfiles" && matches!(role, Role::Install | Role::ClassInstall | Role::CoInstallers) {
                if fields(entry).iter().any(|name| name.starts_with('@')) && (fields(entry).len() != 1 || field(entry, 0) == "@") {
                    self.unresolved += 1;
                    self.record(
                        section,
                        entry_index,
                        "unsupported-copy-directive",
                        json!({"reason":"direct-copy-requires-one-nonempty-filename"}),
                    );
                    continue;
                }
                for (index, name) in fields(entry).iter().enumerate() {
                    if let Some(name) = name.strip_prefix('@') {
                        self.record(
                            section,
                            entry_index,
                            "direct-copy-source",
                            json!({"field":index,"filename":name,"supplied_path_resolved":false}),
                        );
                    } else {
                        let targets = self.reference(section, entry_index, index, name, "copy-file-list", false);
                        self.assign(targets, Role::Files);
                    }
                }
            } else if key == "addreg" && role != Role::Services {
                for (index, name) in fields(entry).iter().enumerate() {
                    let targets = self.reference(section, entry_index, index, name, "registry-list-use-context", false);
                    self.assign(targets, Role::Registry);
                }
            } else if role == Role::Service {
                let numeric = matches!(key.as_str(), "servicetype" | "starttype" | "errorcontrol" | "delayedautostart" | "bootflags");
                if numeric
                    || matches!(
                        key.as_str(),
                        "servicebinary"
                            | "dependencies"
                            | "displayname"
                            | "description"
                            | "loadordergroup"
                            | "startname"
                            | "security"
                            | "requiredprivileges"
                    )
                {
                    let value = if numeric && fields(entry).len() == 1 { number(field(entry, 0)) } else { None };
                    let start = if key == "starttype" {
                        value.and_then(|v| ["boot", "system", "auto", "demand", "disabled"].get(v as usize).copied())
                    } else {
                        None
                    };
                    if numeric && (value.is_none() || (key == "starttype" && start.is_none())) {
                        self.unresolved += 1;
                    }
                    self.record(
                        section,
                        entry_index,
                        "service-property",
                        json!({"name":entry.key,"values":fields(entry),"numeric_u32":value,
                        "declared_start_type":start,"host_path_resolved":false,"runtime_effect_established":false}),
                    );
                }
            }
        }
    }

    fn lists(&mut self, section: usize, role: Role) {
        for (entry_index, entry) in self.inf.sections[section].entries.iter().enumerate() {
            if entry.key.is_some() {
                self.unresolved += 1;
                self.record(section, entry_index, "unsupported-list-row", json!({"reason":"expected-an-unkeyed-list-row"}));
            } else if role == Role::Files {
                let source = if field(entry, 1).is_empty() { field(entry, 0) } else { field(entry, 1) };
                let shape_supported = !field(entry, 0).is_empty()
                    && fields(entry).len() <= 4
                    && (field(entry, 3).is_empty() || number(field(entry, 3)).is_some());
                if !shape_supported {
                    self.unresolved += 1;
                }
                self.record(
                    section,
                    entry_index,
                    "copy-file",
                    json!({"destination_filename":field(entry,0),"source_filename":source,
                    "unused_field":field(entry,2),"flags_literal":field(entry,3),"flags_u32":number(field(entry,3)),
                    "extra_fields":fields(entry).get(4..).unwrap_or_default(),"shape_supported":shape_supported,"supplied_path_resolved":false,"copy_performed":false}),
                );
            } else {
                let shape_supported = matches!(field(entry, 0).to_ascii_uppercase().as_str(), "HKCR" | "HKCU" | "HKLM" | "HKU" | "HKR")
                    && (field(entry, 3).is_empty() || number(field(entry, 3)).is_some());
                if !shape_supported {
                    self.unresolved += 1;
                }
                self.record(section, entry_index, "registry-row", json!({"root":field(entry,0),"subkey":field(entry,1),"value_name":field(entry,2),
                    "flags_literal":field(entry,3),"flags_u32":number(field(entry,3)),"data_fields":fields(entry).get(4..).unwrap_or_default(),
                    "shape_supported":shape_supported,"root_context_resolved":false,"operation_performed":false,"flags_fully_interpreted":false}));
            }
        }
    }

    fn build(&mut self) {
        self.roots();
        // Each section/role pair is visited once. References never recursively copy sections.
        while let Some((section, role)) = self.pending.pop_first() {
            self.context = Some(role);
            if matches!(role, Role::Files | Role::Registry) {
                self.lists(section, role);
            } else {
                self.directives(section, role);
            }
        }
    }
}

pub(super) fn analyze(file: &Artifact, inf: &Inf, out: &mut Output) {
    let mut graph = Graph::new(inf);
    graph.build();
    if !graph.records.is_empty() {
        let mut finding = Finding::new(Section::Structure, "windows", "windows.inf-declarations", Confidence::Derived, Severity::Info)
            .param("count", graph.records.len())
            .param("references", graph.edges.len());
        for (section, entry) in &graph.evidence {
            let entry = &inf.sections[*section].entries[*entry];
            finding = finding.evidence(Evidence::field(
                file,
                format!("INF/section {section}/line {}/field 0", entry.line),
                entry.fields.first().map(String::as_str).unwrap_or(""),
            ));
        }
        out.finding(finding);
    }
    if graph.omitted > 0 {
        out.limitation(
            "windows.inf-declarations-limit",
            Some(file),
            Some(aa_core::counted(graph.omitted as u64, "records or candidate details were omitted")),
        );
    }
    if graph.unresolved > 0 || !graph.namespace_complete {
        out.limitation(
            "windows.inf-declarations-unresolved",
            Some(file),
            Some(aa_core::counted(graph.unresolved as u64, "references or values were unresolved")),
        );
    }
    out.fact(file,"windows.inf-declarations",json!({"profile":"bounded-source-declarations-no-installation-selection","records":graph.records,"references":graph.edges,
        "omitted":graph.omitted,"unresolved":graph.unresolved,"section_namespace_complete":graph.namespace_complete,"platform_selected":false,
        "installed":false,"external_infs_followed":false,"host_registry_consulted":false}));
}

#[cfg(test)]
mod tests {
    use super::super::{parse, redact};
    use super::*;

    fn source(bytes: &[u8]) -> Inf {
        let mut inf = parse(bytes).expect("bounded INF source");
        redact(&mut inf).expect("redacted source");
        inf
    }

    fn records<'a>(graph: &'a Graph<'_>, kind: &'a str) -> impl Iterator<Item = &'a Value> {
        graph.records.iter().filter(move |record| record["kind"] == kind)
    }

    #[test]
    fn model_alternatives_services_copy_sources_and_registry_uses_retain_their_context() {
        let inf = source(include_bytes!("../tests/data/native-inf-relationships.inf"));
        let mut graph = Graph::new(&inf);
        graph.build();
        assert_eq!(records(&graph, "device-model").count(), 2);
        assert_eq!(records(&graph, "service-addition").count(), 2);
        assert_eq!(
            records(&graph, "service-addition").filter(|r| r["details"]["null_associated_service"] == true).count(),
            1,
            "{:?}",
            records(&graph, "service-addition").collect::<Vec<_>>()
        );
        let start = records(&graph, "service-property").find(|r| r["details"]["name"] == "StartType").expect("declared startup");
        assert_eq!(start["details"]["declared_start_type"], "demand");
        assert!(!start["details"]["runtime_effect_established"].as_bool().expect("effect marker"));
        let copy = records(&graph, "copy-file").next().expect("copy source declaration");
        assert_eq!(copy["details"]["source_filename"], "original.sys");
        assert_eq!(copy["details"]["destination_filename"], "renamed.sys");
        assert_eq!(records(&graph, "copy-file").count(), 1, "shared lists are not copied per use");
        assert_eq!(records(&graph, "registry-row").count(), 1);
        let contexts: BTreeSet<_> = graph
            .edges
            .iter()
            .filter(|r| r["kind"] == "registry-list-use-context")
            .map(|r| r["source_role"].as_str().expect("use context"))
            .collect();
        assert_eq!(contexts, BTreeSet::from(["install", "hardware", "service"]));
        assert_eq!(records(&graph, "source-file").count(), 1, "media decoration has no NT prefix");
        assert_eq!(records(&graph, "external-install-reference").count(), 2);
        assert!(!graph.edges.iter().any(|r| r["reference"] == "FakeService"));
        assert!(graph.edges.iter().any(|r| r["kind"] == "model-install-alternatives" && r["observed_target_count"] == 2));
        assert!(graph.unresolved >= 2, "external references are explicit");
        let mut repeat = Graph::new(&inf);
        repeat.build();
        assert_eq!(graph.records, repeat.records);
        assert_eq!(graph.edges, repeat.edges);
    }

    #[test]
    fn ambiguous_sections_unsupported_names_numerics_and_cycles_do_not_select_an_effect() {
        let inf = source(
            br#"[Version]
Signature="$Windows NT$"
[DefaultInstall.NT]
CopyFiles=Absent
[DefaultInstall.NT.Services]
AddService=Sample,,Service
[Service]
StartType=4294967296
AddReg=Service
[service]
StartType=99
ServiceType=-1
ServiceBinary=%12%\x.sys
"#,
        );
        let mut graph = Graph::new(&inf);
        graph.build();
        assert!(graph.edges.iter().any(|e| e["kind"] == "service-install" && e["status"] == "multiple-source-occurrences-no-selection"));
        assert!(graph.edges.iter().any(|e| e["reference"] == "Absent" && e["status"] == "no-supplied-section-occurrence"));
        assert_eq!(records(&graph, "service-property").filter(|r| r["details"]["name"] == "StartType").count(), 2);
        assert!(
            records(&graph, "service-property")
                .filter(|r| r["details"]["name"] == "StartType")
                .all(|r| r["details"]["declared_start_type"].is_null())
        );
        assert!(graph.roles.len() < 10, "cycles visit each section/role only once");
        assert!(graph.unresolved >= 5);
        for bytes in [
            b"[Version]\nSignature=X\n[DefaultInstall.NT]\nCopyFiles=%Missing%\n[Strings]\nA=B\n".as_slice(),
            b"\xEF\xBB\xBF[Version]\nSignature=X\n[DefaultInstall.NT]\nCopyFiles=Files\n[Files]\nx.sys\n[\xE2\x84\xAA]\nx=y\n".as_slice(),
            b"[Version]\nSignature=X\n[DefaultInstall.NT]\nCopyFiles=Files\n[Files]\nx.sys\n[broken\nx=y\n".as_slice(),
            b"[Version]\nSignature=X\n[DefaultInstall.NT]\nCopyFiles=Files\n[Files]\nx.sys\n[Bearer abcdef]\nx=y\n".as_slice(),
        ] {
            let inf = source(bytes);
            let mut graph = Graph::new(&inf);
            graph.build();
            assert!(records(&graph, "copy-file").next().is_none());
            assert!(graph.unresolved > 0 || !graph.namespace_complete);
        }
    }

    #[test]
    fn graph_budgets_bound_records_edges_candidates_and_serialized_output() {
        let mut text = String::from("[Version]\nSignature=X\n[DefaultInstall.NT]\nCopyFiles=Files\n");
        for _ in 0..18 {
            text.push_str("[Files]\nx.sys\n");
        }
        let inf = source(text.as_bytes());
        let mut graph = Graph::new(&inf);
        graph.build();
        let edge = graph.edges.iter().find(|e| e["kind"] == "copy-file-list").expect("bounded candidates");
        assert_eq!(edge["observed_target_count"], 18);
        assert_eq!(edge["target_sections"].as_array().expect("targets").len(), MAX_TARGETS);
        assert_eq!(records(&graph, "copy-file").count(), MAX_TARGETS);
        assert_eq!(graph.omitted, 2);
        let mut graph = Graph::new(&inf);
        graph.bytes = MAX_OUTPUT_BYTES;
        graph.record(0, 0, "version-declaration", json!({}));
        assert!(graph.reference(2, 0, 0, "Files", "test", false).is_empty());
        assert!(graph.records.is_empty() && graph.edges.is_empty());
        assert!(graph.omitted >= 2);
        let mut graph = Graph::new(&inf);
        for _ in 0..MAX_RECORDS + 1 {
            graph.record(0, 0, "test", json!({}));
        }
        assert_eq!(graph.records.len(), MAX_RECORDS);
        assert_eq!(graph.omitted, 1);
        let mut graph = Graph::new(&inf);
        for _ in 0..MAX_EDGES + 1 {
            graph.reference(0, 0, 0, "Files", "test", false);
        }
        assert_eq!(graph.edges.len(), MAX_EDGES);
        assert!(graph.omitted > 0);
    }

    #[test]
    fn derived_fields_never_reintroduce_redacted_registry_values_or_credentials() {
        let inf = source(
            br#"[Version]
Signature="$Windows NT$"
[DefaultInstall.NT]
AddReg=Registry
[Registry]
HKR,,Password,,"must-hide-this-value"
[DefaultInstall.NT.Services]
AddService=Example,,Service
[Service]
Description="token=must-hide-another-value"
"#,
        );
        let mut graph = Graph::new(&inf);
        graph.build();
        let serialized = serde_json::to_string(&graph.records).expect("graph JSON");
        assert!(!serialized.contains("must-hide"));
        assert!(serialized.contains("redacted"));
        assert_eq!(records(&graph, "registry-row").count(), 1);
    }

    #[test]
    fn bare_manufacturers_media_duplicates_and_class_contexts_are_not_installation_choices() {
        let inf = source(
            br#"[Version]
Signature="$Windows NT$"
[Manufacturer]
BareModels
[BareModels]
Device=Install,ROOT\BARE
[Install.NT]
CopyFiles=Files,@invalid-mix.sys
[SourceDisksNames]
1=First
1=Second
[ClassInstall32]
AddReg=Registry
[ClassInstall32.Services]
AddService=InvalidContext,,Service
[Service]
StartType=0
[Registry]
HKR,,Feature,,Value
"#,
        );
        let mut graph = Graph::new(&inf);
        graph.build();
        assert_eq!(records(&graph, "device-model").count(), 1);
        assert_eq!(records(&graph, "source-media").count(), 2, "media IDs are not selected or merged");
        assert_eq!(records(&graph, "registry-row").count(), 1);
        assert_eq!(records(&graph, "service-addition").count(), 0, "ClassInstall is not a DDInstall.Services context");
        assert_eq!(records(&graph, "unsupported-copy-directive").count(), 1);
        assert!(graph.unresolved > 0);
    }
}
