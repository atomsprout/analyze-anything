//! MSI scheduling declarations and links to captured Binary-table streams.
//!
//! Sequence numbers and conditions describe database declarations, not an installation trace.

use std::collections::{BTreeMap, BTreeSet};

use aa_core::plugin::{Output, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

use crate::msi::Package;

const MAX_ROWS: usize = 2000;
const MAX_TEXT: usize = 8192;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const SEQUENCES: [(&str, &str); 5] = [
    ("InstallExecuteSequence", "install-execute"),
    ("InstallUISequence", "install-ui"),
    ("AdminExecuteSequence", "admin-execute"),
    ("AdminUISequence", "admin-ui"),
    ("AdvtExecuteSequence", "advertise-execute"),
];

type Row = BTreeMap<String, Value>;

#[derive(Default)]
struct Budget {
    bytes: usize,
    issues: Vec<String>,
    incomplete: bool,
}

impl Budget {
    fn issue(&mut self, detail: String) {
        self.incomplete = true;
        if self.issues.len() < 12 {
            self.issues.push(detail);
        }
    }
}

/// Retain nulls and original column values, with independent limits on retained text and rows.
fn rows(package: &mut Package, table: &str, required: &[&str], budget: &mut Budget) -> Vec<Row> {
    if !package.has_table(table) {
        return Vec::new();
    }
    let selected = match package.select_rows(msi::Select::table(table)) {
        Ok(selected) => selected,
        Err(_) => {
            budget.issue(format!("{table}: table could not be read"));
            return Vec::new();
        }
    };
    let mut result = Vec::new();
    let mut identities = BTreeSet::new();
    for (index, row) in selected.enumerate() {
        if index == MAX_ROWS || budget.bytes >= MAX_BYTES {
            budget.issue(format!("{table}: row or total text limit reached"));
            break;
        }
        let mut fields = Row::new();
        let mut oversized = false;
        for (index, column) in row.columns().iter().enumerate() {
            let value = match &row[index] {
                msi::Value::Null => Value::Null,
                msi::Value::Binary => json!({"kind": "binary-stream"}),
                msi::Value::Int(value) => json!(value),
                msi::Value::Str(value) => {
                    if value.len() > MAX_TEXT || budget.bytes.saturating_add(value.len()) > MAX_BYTES {
                        oversized = true;
                        break;
                    }
                    budget.bytes += value.len();
                    json!(value)
                }
            };
            fields.insert(column.name().into(), value);
        }
        let unsupported = required.iter().any(|key| match fields.get(*key) {
            None => true,
            Some(value) => match *key {
                "Type" => !value.is_i64(),
                "Sequence" => !value.is_null() && !value.is_i64(),
                "Data" => value != &json!({"kind": "binary-stream"}),
                "Action" | "Name" => !value.as_str().is_some_and(|s| !s.is_empty()),
                _ => !value.is_null() && !value.is_string(),
            },
        });
        if oversized || unsupported {
            budget.issue(format!("{table}: row {index} exceeds text limits or has unsupported columns"));
            continue;
        }
        let key = match table {
            "Binary" => "Name",
            "LaunchCondition" => "Condition",
            _ => "Action",
        };
        if let Some(identity) = fields.get(key)
            && !identities.insert(identity.to_string())
        {
            budget.issue(format!("{table}: duplicate declared key"));
            // Repeated names in a hostile nonstandard schema must not multiply
            // sequence evidence when custom actions are associated.
            continue;
        }
        result.push(fields);
    }
    result.sort_by_cached_key(|row| serde_json::to_string(row).unwrap_or_default());
    result
}

fn text<'a>(row: &'a Row, key: &str) -> Option<&'a str> {
    row.get(key)?.as_str()
}

fn position(sequence: Option<i64>) -> &'static str {
    match sequence {
        Some(n) if n > 0 => "sequence-position",
        Some(-1) => "termination-success",
        Some(-2) => "termination-cancel",
        Some(-3) => "termination-error",
        Some(-4) => "termination-suspend",
        None => "not-scheduled-null",
        _ => "unsupported-sequence-value",
    }
}

pub(super) fn execution(kind: i64) -> &'static str {
    if kind & 0x400 == 0 {
        "immediate"
    } else {
        match kind & 0x300 {
            0 => "deferred",
            0x100 => "rollback",
            0x200 => "commit",
            _ => "unsupported-in-script-flags",
        }
    }
}

fn repeat(kind: i64) -> Option<&'static str> {
    (kind & 0x400 == 0).then_some(match kind & 0x300 {
        0 => "default",
        0x100 => "first-sequence",
        0x200 => "once-per-process",
        _ => "client-repeat",
    })
}

pub(super) fn read(package: &mut Package, file: &Artifact, out: &mut Output) {
    let mut budget = Budget::default();
    let mut sequences = Vec::new();
    let mut schedules: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut present_tables = Vec::new();
    for (table, phase) in SEQUENCES {
        if package.has_table(table) {
            present_tables.push(table);
        }
        let mut entries = Vec::new();
        for row in rows(package, table, &["Action", "Condition", "Sequence"], &mut budget) {
            let Some(action) = text(&row, "Action").filter(|s| !s.is_empty()) else {
                budget.issue(format!("{table}: action name is not established"));
                continue;
            };
            let sequence = row["Sequence"].as_i64();
            let condition = &row["Condition"];
            if (!row["Sequence"].is_null() && sequence.is_none()) || (!condition.is_null() && !condition.is_string()) {
                budget.issue(format!("{table}: unsupported column types for {action}"));
                continue;
            }
            let entry = json!({"table": table, "phase": phase, "action": action,
                "sequence": sequence, "position_kind": position(sequence), "condition": condition,
                "condition_evaluated": false, "row": row,
                "source": format!("{table} table, row {action}")});
            if position(sequence) == "unsupported-sequence-value" {
                budget.issue(format!("{table}: unsupported sequence value for {action}"));
            }
            schedules.entry(action.into()).or_default().push(entry.clone());
            entries.push(entry);
        }
        entries.sort_by(|a, b| {
            a["sequence"]
                .as_i64()
                .unwrap_or(i64::MAX)
                .cmp(&b["sequence"].as_i64().unwrap_or(i64::MAX))
                .then_with(|| a["action"].as_str().cmp(&b["action"].as_str()))
        });
        sequences.push(json!({"table": table, "phase": phase, "present": package.has_table(table), "rows": entries}));
    }
    let binaries = rows(package, "Binary", &["Name", "Data"], &mut budget);
    let conditions = rows(package, "LaunchCondition", &["Condition", "Description"], &mut budget);
    let mut actions = Vec::new();
    for row in rows(package, "CustomAction", &["Action", "Type", "Source", "Target"], &mut budget) {
        let (Some(action), Some(kind)) = (text(&row, "Action"), row["Type"].as_i64()) else {
            budget.issue("CustomAction: unsupported name or type".into());
            continue;
        };
        if !(0..=u16::MAX as i64).contains(&kind) {
            budget.issue(format!("CustomAction: unsupported type for {action}"));
        }
        let occurrences = schedules.get(action).cloned().unwrap_or_default();
        let source = text(&row, "Source");
        let binary = matches!(kind & 0x3f, 1 | 2 | 5 | 6);
        let binary_rows: Vec<_> = binaries.iter().filter(|b| text(b, "Name") == source).collect();
        actions.push(json!({"action": action, "type": kind, "base_type": kind & 0x3f,
            "source": source, "target": row["Target"], "row": row,
            "execution": execution(kind), "repeat_scheduling": repeat(kind),
            "no_impersonation_requested": kind & 0xc00 == 0xc00,
            "scheduling_status": if occurrences.is_empty() {"not-found-in-read-sequences"} else {"declared-in-sequence"},
            "schedules": occurrences, "binary_source": binary,
            "binary_rows": if binary {binary_rows} else {Vec::new()},
            "source_location": format!("CustomAction table, row {action}")}));
    }
    if budget.incomplete {
        out.limitation("windows.msi-actions-incomplete", Some(file), Some(budget.issues.join("; ")));
    }
    if !present_tables.is_empty() || !conditions.is_empty() {
        let mut finding = Finding::new(Section::Structure, crate::ID, "windows.msi-sequences", Confidence::Verified, Severity::Info);
        finding = finding.param("tables", present_tables.len()).param("conditions", conditions.len()).evidence(Evidence::field(
            file,
            "MSI sequence table inventory",
            json!(present_tables),
        ));
        for sequence in &sequences {
            for row in sequence["rows"].as_array().into_iter().flatten().take(2) {
                finding = finding.evidence(Evidence::field(file, row["source"].as_str().unwrap_or("MSI sequence"), row.clone()));
            }
        }
        for row in conditions.iter().take(2) {
            finding = finding.evidence(Evidence::field(file, "LaunchCondition table", json!(row)));
        }
        out.finding(finding);
    }
    out.fact(
        file,
        "windows.msi-actions",
        json!({"profile": "msi-actions-v1", "sequences": sequences,
        "custom_actions": actions, "launch_conditions": conditions, "incomplete": budget.incomplete,
        "issues": budget.issues, "conditions_evaluated": false, "execution_established": false}),
    );
}

fn binary_key(key: &str) -> bool {
    key.as_bytes().first().is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
        && key.len() <= 72
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
}

pub(super) fn relate(tree: &dyn Tree, out: &mut Output) {
    if !tree.artifacts().iter().any(|a| a.facts.contains_key("windows.msi-actions")) {
        return;
    }
    let mut children: BTreeMap<&str, BTreeMap<String, Vec<&Artifact>>> = BTreeMap::new();
    // The index is bounded independently of the number of action declarations.
    if tree.artifacts().len() > 100_000
        || tree.artifacts().iter().try_fold(0usize, |bytes, a| bytes.checked_add(a.path.len())).is_none_or(|n| n > 32 * 1024 * 1024)
    {
        if tree.artifacts().iter().any(|a| a.facts.contains_key("windows.msi-actions")) {
            out.limitation(
                "windows.msi-actions-incomplete",
                None,
                Some("target index exceeds 100,000 artifacts or 32 MiB of paths".into()),
            );
        }
        return;
    }
    for child in tree.artifacts() {
        if let Some(parent) = child.parent.as_deref()
            && let Some(local) = child.path.strip_prefix(parent).and_then(|p| p.strip_prefix('/'))
        {
            children.entry(parent).or_default().entry(local.to_ascii_lowercase()).or_default().push(child);
        }
    }
    let mut action_count = 0;
    let mut evidence_bytes = 0usize;
    for (index, file) in tree.artifacts().iter().filter(|a| a.facts.contains_key("windows.msi-actions")).enumerate() {
        if index == 500 {
            out.limitation(
                "windows.msi-actions-incomplete",
                None,
                Some("only the first 500 MSI declaration sources were associated".into()),
            );
            break;
        }
        let model = &file.facts["windows.msi-actions"];
        let mut references = Vec::new();
        let mut unresolved = 0;
        let mut truncated = model["incomplete"] == true;
        for action in model["custom_actions"].as_array().into_iter().flatten().take(MAX_ROWS) {
            let bytes = action.to_string().len();
            if action_count == 10_000 || evidence_bytes.saturating_add(bytes) > 16 * 1024 * 1024 {
                out.limitation(
                    "windows.msi-actions-incomplete",
                    Some(file),
                    Some("global action evidence limit: 10,000 actions or 16 MiB".into()),
                );
                truncated = true;
                break;
            }
            action_count += 1;
            evidence_bytes += bytes;
            let source = action["source"].as_str().unwrap_or("");
            let local = format!("[Binary]/{source}");
            let candidates = children.get(file.path.as_str()).and_then(|m| m.get(&local.to_ascii_lowercase()));
            let binary_rows = action["binary_rows"].as_array().map_or(0, Vec::len);
            let (target, reason) = if action["binary_source"] != true {
                (None, Some("action-source-outside-binary-profile"))
            } else if !binary_key(source) {
                (None, Some("binary-key-outside-path-profile"))
            } else if model["incomplete"] == true {
                (None, Some("declaration-table-read-incomplete"))
            } else if binary_rows != 1 {
                (None, Some("binary-row-not-unique-or-missing"))
            } else if file.facts.get("engine.container-listing").is_some_and(|v| v["complete"] == false) {
                (None, Some("container-listing-incomplete"))
            } else {
                match candidates.map(Vec::as_slice) {
                    Some([target]) if crate::references::name_changed(target) => (None, Some("target-entry-name-not-original-or-unique")),
                    Some([target]) if target.digests.is_some() => (Some(*target), None),
                    Some([_]) => (None, Some("target-content-unreadable")),
                    Some(_) => (None, Some("ambiguous-captured-target")),
                    None => (None, Some("binary-stream-not-captured")),
                }
            };
            if reason.is_some() {
                unresolved += 1;
            }
            let reference = json!({"action": action["action"], "declared_source": source,
                "field": action["source_location"], "declared": source,
                "status": if target.is_some() {"matched-supplied-declaration"} else {"unresolved"},
                "reason": reason, "target": target.map(|a| a.path.as_str()),
                "target_sha256": target.and_then(|a| a.digests.as_ref()).map(|d| d.sha256.as_str())});
            let mut finding = Finding::new(Section::Capabilities, crate::ID, "windows.msi-action", Confidence::Verified, Severity::Info)
                .param("action", action["action"].clone())
                .param("execution", action["execution"].clone())
                .param("count", action["schedules"].as_array().map_or(0, Vec::len))
                .evidence(Evidence::field(file, action["source_location"].as_str().unwrap_or("CustomAction table"), action.clone()))
                .evidence(Evidence::field(file, "CustomAction source relationship", reference.clone()));
            if let Some(target) = target {
                finding = finding.evidence(Evidence::field(
                    target,
                    "captured Binary stream SHA-256",
                    json!(target.digests.as_ref().map(|d| &d.sha256)),
                ));
            }
            out.finding(finding);
            references.push(reference);
        }
        if unresolved > 0 {
            out.limitation(
                "windows.msi-target-unresolved",
                Some(file),
                Some(format!("{unresolved} action sources were not bound to captured Binary streams; see windows.msi-action-targets")),
            );
        }
        out.fact(
            file,
            "windows.msi-action-targets",
            json!({"references": references, "truncated": truncated, "execution_established": false}),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::Digests;
    use aa_core::plugin::Bytes;

    struct Fixture(Vec<Artifact>);
    impl Tree for Fixture {
        fn artifacts(&self) -> &[Artifact] {
            &self.0
        }
        fn read(&self, _: &str) -> std::io::Result<Bytes> {
            panic!("target relationships must not read source bytes")
        }
    }

    fn artifact(path: &str, parent: Option<&str>) -> Artifact {
        Artifact {
            path: path.into(),
            parent: parent.map(str::to_string),
            size: 1,
            digests: Some(Digests { md5: String::new(), sha1: String::new(), sha256: "abc".into() }),
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        }
    }

    fn fixture() -> Fixture {
        let mut source = artifact("sample.msi", None);
        source.facts.insert(
            "windows.msi-actions".into(),
            json!({"incomplete": false, "custom_actions": [
                {"action": "Run", "source": "Payload", "source_location": "CustomAction table, row Run",
                 "binary_source": true, "binary_rows": [{"Name": "Payload"}], "execution": "immediate", "schedules": []}
            ]}),
        );
        Fixture(vec![source, artifact("sample.msi/[Binary]/Payload", Some("sample.msi"))])
    }

    fn reference(tree: &Fixture) -> Value {
        let mut out = Output::default();
        relate(tree, &mut out);
        out.facts[0].value["references"][0].clone()
    }

    #[test]
    fn target_resolution_refuses_ambiguity_missing_bytes_and_incomplete_capture() {
        let mut tree = fixture();
        assert_eq!(reference(&tree)["status"], "matched-supplied-declaration");
        tree.0.push(artifact("sample.msi/[Binary]/PAYLOAD", Some("sample.msi")));
        assert_eq!(reference(&tree)["reason"], "ambiguous-captured-target");
        tree.0.pop();
        tree.0[1].facts.insert("engine.entry-name".into(), json!({"normalized": true}));
        assert_eq!(reference(&tree)["reason"], "target-entry-name-not-original-or-unique");
        tree.0[1].facts.clear();
        tree.0[1].digests = None;
        assert_eq!(reference(&tree)["reason"], "target-content-unreadable");
        let mut tree = fixture();
        tree.0[0].facts.insert("engine.container-listing".into(), json!({"complete": false}));
        assert_eq!(reference(&tree)["reason"], "container-listing-incomplete");
        tree.0[0].facts.remove("engine.container-listing");
        tree.0[1].parent = Some("other.msi".into());
        assert_eq!(reference(&tree)["reason"], "binary-stream-not-captured");
    }

    #[test]
    fn malformed_keys_do_not_escape_the_container_or_normalize_to_existing_files() {
        for key in ["../Payload", "Payload/extra", "Payload\\extra", "C:Payload", "Payload ", "载荷", "1Payload", ""] {
            let mut tree = fixture();
            tree.0[0].facts.get_mut("windows.msi-actions").expect("action fact")["custom_actions"][0]["source"] = json!(key);
            assert_eq!(reference(&tree)["reason"], "binary-key-outside-path-profile", "{key}");
        }
    }

    #[test]
    fn many_supplied_packages_cannot_exceed_the_global_action_evidence_budget() {
        let mut tree = Fixture(Vec::new());
        for package in 0..6 {
            let mut source = fixture().0.remove(0);
            source.path = format!("package-{package}.msi");
            let template = source.facts["windows.msi-actions"]["custom_actions"][0].clone();
            let actions: Vec<_> = (0..MAX_ROWS)
                .map(|index| {
                    let mut action = template.clone();
                    action["action"] = json!(format!("Action{index}"));
                    action
                })
                .collect();
            source.facts.get_mut("windows.msi-actions").expect("declarations")["custom_actions"] = json!(actions);
            tree.0.push(source);
        }
        let mut out = Output::default();
        relate(&tree, &mut out);
        assert_eq!(out.findings.len(), 10_000);
        assert!(out.limitations.iter().any(|l| l.code == "windows.msi-actions-incomplete"));
        assert_eq!(out.facts.last().expect("last package status").value["truncated"], true);
    }

    #[test]
    fn row_limit_and_schema_mismatches_are_not_silent() {
        use msi::{Column, Insert, Package, PackageType, Value as M};
        let mut package = Package::create(PackageType::Installer, std::io::Cursor::new(Vec::new())).expect("controlled package");
        package
            .create_table("Binary", vec![Column::build("Name").primary_key().string(72), Column::build("Data").binary()])
            .expect("table");
        for index in 0..=MAX_ROWS {
            package.insert_rows(Insert::into("Binary").row(vec![M::from(format!("Payload{index}")), M::Binary])).expect("row");
        }
        let bytes = package.into_inner().expect("flush").into_inner();
        let mut package = Package::open(std::io::Cursor::new(bytes.as_slice())).expect("read package");
        let mut budget = Budget::default();
        assert_eq!(rows(&mut package, "Binary", &["Name", "Data"], &mut budget).len(), MAX_ROWS);
        assert!(budget.incomplete);
        let mut budget = Budget::default();
        assert!(rows(&mut package, "Binary", &["MissingColumn"], &mut budget).is_empty());
        assert!(budget.incomplete);
    }

    #[test]
    fn repeated_names_in_nonstandard_schemas_cannot_multiply_action_context() {
        use msi::{Column, Insert, Package, PackageType, Value as M};
        let mut package = Package::create(PackageType::Installer, std::io::Cursor::new(Vec::new())).expect("controlled package");
        package
            .create_table("CustomAction", vec![Column::build("Ordinal").primary_key().int16(), Column::build("Action").string(72)])
            .expect("nonstandard schema");
        for index in 0..100 {
            package.insert_rows(Insert::into("CustomAction").row(vec![M::Int(index), M::from("Repeated")])).expect("duplicate name");
        }
        let bytes = package.into_inner().expect("flush").into_inner();
        let mut package = Package::open(std::io::Cursor::new(bytes.as_slice())).expect("read package");
        let mut budget = Budget::default();
        assert_eq!(rows(&mut package, "CustomAction", &["Action"], &mut budget).len(), 1);
        assert!(budget.incomplete);
        assert!(budget.issues.iter().any(|s| s.contains("duplicate declared key")));
    }
}
