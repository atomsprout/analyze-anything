//! Compares two reports: what one says that the other does not, and which files differ.
//!
//! The typical use is two versions of the same application. Their reports rarely share a single
//! finding id, because an id covers the evidence, and the evidence names files by a path that
//! starts with the input's name (`App-1.0.dmg/…` against `App-1.1.dmg/…`) and carries their
//! hashes. So the comparison looks at what a finding *says* instead:
//!
//! * two findings are **the same statement** when they come from the same rule, about the file at
//!   the same place inside the input, with the same params, severity and confidence. Known
//!   artifact display paths are compared relative to the input; values read from it stay literal;
//! * findings of the same rule about the same place whose params differ are one statement that
//!   **changed**;
//! * what is left on one side only was **added** or **removed**.
//!
//! Files are compared by their place inside the input and their SHA-256.

use std::collections::BTreeMap;

use aa_core::{Finding, InputKind, Report, RuleText};
use serde::{Deserialize, Serialize};

/// Which of the two reports a description is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Side {
    pub name: String,
    pub sha256: Option<String>,
    pub tool_version: String,
    pub findings: u64,
    pub files: u64,
}

/// A finding of one report, with the place inside the input it is about.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Statement {
    /// Path of the file the finding rests on, relative to the input; empty for the input itself.
    pub place: String,
    pub finding: Finding,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Changed {
    pub place: String,
    pub before: Finding,
    pub after: Finding,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FindingDiff {
    /// Statements both reports make.
    pub unchanged: u64,
    /// Only in the second report.
    pub added: Vec<Statement>,
    /// Only in the first report.
    pub removed: Vec<Statement>,
    pub changed: Vec<Changed>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileState {
    pub size: u64,
    /// `None` when the file could not be read.
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    #[serde(flatten)]
    pub state: FileState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileChange {
    pub path: String,
    pub before: FileState,
    pub after: FileState,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileDiff {
    pub unchanged: u64,
    pub added: Vec<FileEntry>,
    pub removed: Vec<FileEntry>,
    /// Same place, different content.
    pub changed: Vec<FileChange>,
}

/// The result of comparing a first report (`a`, "before") with a second (`b`, "after").
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Diff {
    pub a: Side,
    pub b: Side,
    pub findings: FindingDiff,
    pub files: FileDiff,
    /// Text of every rule the listed findings mention, from whichever report has it; the second
    /// report's wording wins when both do.
    pub rules: BTreeMap<String, RuleText>,
}

/// A path as a place inside the input: without the input's own name in front when the input is
/// a single file, so that `App-1.0.zip/a.txt` and `App-1.1.zip/a.txt` are the same place.
fn place(report: &Report, path: &str) -> String {
    if report.input.kind == InputKind::File
        && let Some(rest) = path.strip_prefix(report.input.name.as_str())
    {
        if rest.is_empty() {
            return String::new();
        }
        if let Some(inside) = rest.strip_prefix('/') {
            return inside.to_string();
        }
    }
    path.to_string()
}

fn place_of(report: &Report, finding: &Finding) -> String {
    finding.evidence.first().map(|evidence| place(report, &evidence.artifact)).unwrap_or_default()
}

/// Only presentation parameters known to name input artifacts are relative to the input.
/// Product names, versions and paths embedded in the analyzed bytes retain their meaning.
fn parameter_place(report: &Report, finding: &Finding, key: &str, value: &serde_json::Value) -> Option<String> {
    let value = value.as_str()?;
    if finding.rule == "overview.kind-bundle" && key == "name" && value == report.input.name {
        return Some(String::new());
    }
    let artifact_name = key == "file" && finding.evidence.iter().any(|e| e.artifact == value);
    let displayed_path = key == "path" && matches!(finding.rule.as_str(), "structure.largest" | "overview.apple-bundles");
    (artifact_name || displayed_path)
        .then(|| if finding.rule == "overview.apple-bundles" && value == report.input.name { String::new() } else { place(report, value) })
}

fn same_parameters(a: &Report, x: &Finding, b: &Report, y: &Finding) -> bool {
    x.params.len() == y.params.len()
        && x.params.iter().all(|(key, before)| {
            let Some(after) = y.params.get(key) else { return false };
            before == after
                || parameter_place(a, x, key, before).zip(parameter_place(b, y, key, after)).is_some_and(|(left, right)| left == right)
        })
}

fn side(report: &Report) -> Side {
    Side {
        name: report.input.name.clone(),
        sha256: report.input.sha256.clone(),
        tool_version: report.tool.version.clone(),
        findings: report.findings.len() as u64,
        files: report.artifacts.len() as u64,
    }
}

/// Compares `a` (before) with `b` (after).
pub fn diff(a: &Report, b: &Report) -> Diff {
    Diff { a: side(a), b: side(b), findings: findings(a, b), files: files(a, b), rules: BTreeMap::new() }.with_rules(a, b)
}

impl Diff {
    fn with_rules(mut self, a: &Report, b: &Report) -> Self {
        let listed = self
            .findings
            .added
            .iter()
            .map(|s| &s.finding)
            .chain(self.findings.removed.iter().map(|s| &s.finding))
            .chain(self.findings.changed.iter().flat_map(|c| [&c.before, &c.after]));
        let mut rules = BTreeMap::new();
        for finding in listed {
            if let Some(text) = b.rules.get(&finding.rule).or_else(|| a.rules.get(&finding.rule)) {
                rules.insert(finding.rule.clone(), text.clone());
            }
        }
        self.rules = rules;
        self
    }

    /// True when the two reports make the same statements about the same files.
    pub fn is_empty(&self) -> bool {
        let (f, d) = (&self.findings, &self.files);
        f.added.is_empty()
            && f.removed.is_empty()
            && f.changed.is_empty()
            && d.added.is_empty()
            && d.removed.is_empty()
            && d.changed.is_empty()
    }
}

fn findings(a: &Report, b: &Report) -> FindingDiff {
    // Findings of each side by (rule, place), in report order.
    type Key = (String, String);
    let group = |report: &Report| {
        let mut groups: BTreeMap<Key, Vec<Finding>> = BTreeMap::new();
        for finding in &report.findings {
            groups.entry((finding.rule.clone(), place_of(report, finding))).or_default().push(finding.clone());
        }
        groups
    };
    let (mut before, mut after) = (group(a), group(b));
    let says_the_same = |x: &Finding, y: &Finding| {
        x.id == y.id || (same_parameters(a, x, b, y) && x.severity == y.severity && x.confidence == y.confidence)
    };

    let mut result = FindingDiff::default();
    let keys: Vec<Key> = before.keys().chain(after.keys()).cloned().collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    for key in keys {
        let mut old = before.remove(&key).unwrap_or_default();
        let mut new = after.remove(&key).unwrap_or_default();
        // Statements made on both sides first; what remains is paired up in order as changes.
        old.retain(|x| match new.iter().position(|y| says_the_same(x, y)) {
            Some(index) => {
                new.remove(index);
                result.unchanged += 1;
                false
            }
            None => true,
        });
        let mut new = new.into_iter();
        for x in old {
            match new.next() {
                Some(y) => result.changed.push(Changed { place: key.1.clone(), before: x, after: y }),
                None => result.removed.push(Statement { place: key.1.clone(), finding: x }),
            }
        }
        result.added.extend(new.map(|y| Statement { place: key.1.clone(), finding: y }));
    }
    // Most severe first, then by chapter, rule and place: the order a reader wants.
    let order = |f: &Finding, place: &str| (std::cmp::Reverse(f.severity), f.section, f.rule.clone(), place.to_string(), f.id.clone());
    result.added.sort_by_cached_key(|s| order(&s.finding, &s.place));
    result.removed.sort_by_cached_key(|s| order(&s.finding, &s.place));
    result.changed.sort_by_cached_key(|c| order(&c.after, &c.place));
    result
}

fn files(a: &Report, b: &Report) -> FileDiff {
    let index = |report: &Report| -> BTreeMap<String, FileState> {
        report
            .artifacts
            .iter()
            .map(|artifact| {
                let state = FileState { size: artifact.size, sha256: artifact.digests.as_ref().map(|d| d.sha256.clone()) };
                (place(report, &artifact.path), state)
            })
            .collect()
    };
    let (before, mut after) = (index(a), index(b));
    let mut result = FileDiff::default();
    for (path, old) in before {
        match after.remove(&path) {
            None => result.removed.push(FileEntry { path, state: old }),
            // Two files that could not be read are not known to be the same; say they differ
            // only when a hash shows it.
            Some(new) if new == old => result.unchanged += 1,
            Some(new) => result.changed.push(FileChange { path, before: old, after: new }),
        }
    }
    result.added = after.into_iter().map(|(path, state)| FileEntry { path, state }).collect();
    result
}

/// Language of [`text`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Zh,
    En,
}

/// Most entries of one list that [`text`] writes out; the JSON form always has all of them.
const TEXT_LIMIT: usize = 200;

/// The comparison as plain text, for a terminal.
pub fn text(diff: &Diff, language: Language) -> String {
    let zh = language == Language::Zh;
    let word = |chinese: &'static str, english: &'static str| if zh { chinese } else { english };
    let sentence = |finding: &Finding| {
        let Some(rule) = diff.rules.get(&finding.rule) else { return finding.rule.clone() };
        let (title, body) = if zh { (&rule.title_zh, &rule.text_zh) } else { (&rule.title_en, &rule.text_en) };
        format!("{title}: {}", aa_core::fill(body, &finding.params))
    };
    let severity = |finding: &Finding| {
        let level = match finding.severity {
            aa_core::Severity::High => word("高", "high"),
            aa_core::Severity::Medium => word("中", "medium"),
            aa_core::Severity::Low => word("低", "low"),
            aa_core::Severity::Info => word("提示", "info"),
        };
        format!("[{level}]")
    };
    let at = |place: &str| if place.is_empty() { String::new() } else { format!("  ({place})") };
    let digest =
        |state: &FileState| state.sha256.as_deref().map(|hash| hash[..hash.len().min(12)].to_string()).unwrap_or_else(|| "?".into());

    let mut out = String::new();
    let mut line = |text: String| {
        out.push_str(&text);
        out.push('\n');
    };
    line(format!("{}: {}  →  {}", word("对比", "Comparison"), diff.a.name, diff.b.name));
    line(String::new());
    let f = &diff.findings;
    line(format!(
        "{}: {} {} · {} {} · {} {} · {} {}",
        word("结论", "Findings"),
        f.added.len(),
        word("新增", "added"),
        f.removed.len(),
        word("消失", "removed"),
        f.changed.len(),
        word("变化", "changed"),
        f.unchanged,
        word("相同", "unchanged"),
    ));
    let d = &diff.files;
    line(format!(
        "{}: {} {} · {} {} · {} {} · {} {}",
        word("文件", "Files"),
        d.added.len(),
        word("新增", "added"),
        d.removed.len(),
        word("删除", "removed"),
        d.changed.len(),
        word("内容变化", "changed"),
        d.unchanged,
        word("相同", "unchanged"),
    ));
    let more = |total: usize| {
        (total > TEXT_LIMIT)
            .then(|| format!("  … {} {}", total - TEXT_LIMIT, word("条未列出，见 JSON 输出", "more not listed; see the JSON output")))
    };

    let statements = [(word("新增的结论", "Findings added"), '+', &f.added), (word("消失的结论", "Findings removed"), '-', &f.removed)];
    for (title, mark, list) in statements {
        if list.is_empty() {
            continue;
        }
        line(String::new());
        line(format!("{title} ({})", list.len()));
        for statement in list.iter().take(TEXT_LIMIT) {
            line(format!("{mark} {} {}{}", severity(&statement.finding), sentence(&statement.finding), at(&statement.place)));
        }
        if let Some(note) = more(list.len()) {
            line(note);
        }
    }
    if !f.changed.is_empty() {
        line(String::new());
        line(format!("{} ({})", word("变化的结论", "Findings changed"), f.changed.len()));
        for change in f.changed.iter().take(TEXT_LIMIT) {
            line(format!("~ {} {}{}", severity(&change.after), sentence(&change.after), at(&change.place)));
            line(format!("    {}: {}", word("之前", "before"), sentence(&change.before)));
        }
        if let Some(note) = more(f.changed.len()) {
            line(note);
        }
    }
    let lists = [(word("新增的文件", "Files added"), '+', &d.added), (word("删除的文件", "Files removed"), '-', &d.removed)];
    for (title, mark, list) in lists {
        if list.is_empty() {
            continue;
        }
        line(String::new());
        line(format!("{title} ({})", list.len()));
        for entry in list.iter().take(TEXT_LIMIT) {
            line(format!("{mark} {}  {} {}", entry.path, entry.state.size, word("字节", "bytes")));
        }
        if let Some(note) = more(list.len()) {
            line(note);
        }
    }
    if !d.changed.is_empty() {
        line(String::new());
        line(format!("{} ({})", word("内容变化的文件", "Files changed"), d.changed.len()));
        for change in d.changed.iter().take(TEXT_LIMIT) {
            let name = if change.path.is_empty() { word("（输入本身）", "(the input itself)") } else { change.path.as_str() };
            line(format!(
                "~ {name}  {} → {} {}  sha256 {} → {}",
                change.before.size,
                change.after.size,
                word("字节", "bytes"),
                digest(&change.before),
                digest(&change.after)
            ));
        }
        if let Some(note) = more(d.changed.len()) {
            line(note);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use aa_core::{Artifact, Confidence, Coverage, Digests, Evidence, Input, Section, Severity, Tool};

    use super::*;

    fn artifact(path: &str, content: &str) -> Artifact {
        Artifact {
            path: path.into(),
            parent: None,
            size: content.len() as u64,
            digests: Some(Digests { md5: String::new(), sha1: String::new(), sha256: aa_core::sha256_hex(content.as_bytes()) }),
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        }
    }

    fn finding(rule: &str, severity: Severity, on: &Artifact, params: &[(&str, &str)]) -> Finding {
        let mut found = Finding::new(Section::Identity, "test", rule, Confidence::Verified, severity);
        for (name, value) in params {
            found = found.param(name, *value);
        }
        found.evidence(Evidence::whole(on, "seen")).seal()
    }

    fn report(name: &str, artifacts: Vec<Artifact>, findings: Vec<Finding>) -> Report {
        let rule = |title: &str, text: &str| RuleText {
            title_zh: format!("{title}（中）"),
            title_en: title.into(),
            text_zh: format!("{text}（中）"),
            text_en: text.into(),
        };
        let rules = [
            ("app.version", rule("Version", "Version {version}.")),
            ("app.debuggable", rule("Debuggable", "The app can be debugged.")),
            ("app.permission", rule("Permission", "Asks for {name}.")),
            ("app.signed", rule("Signed", "Signed by {who}.")),
        ];
        Report {
            schema_version: aa_core::SCHEMA_VERSION,
            tool: Tool { name: "analyze-anything".into(), version: "0.1.0".into() },
            input: Input { name: name.into(), kind: InputKind::File, sha256: None },
            summary: BTreeMap::new(),
            artifacts,
            findings,
            limitations: Vec::new(),
            coverage: Coverage::default(),
            rules: rules.into_iter().map(|(id, text)| (id.to_string(), text)).collect(),
        }
    }

    /// Two versions of one app: the archive is renamed, a file changes, one goes, one comes.
    fn versions() -> (Report, Report) {
        let old = [
            artifact("app-1.0.zip", "zip one"),
            artifact("app-1.0.zip/Info", "v1"),
            artifact("app-1.0.zip/main", "code one"),
            artifact("app-1.0.zip/old.dat", "old"),
        ];
        let new = [
            artifact("app-1.1.zip", "zip two"),
            artifact("app-1.1.zip/Info", "v2"),
            artifact("app-1.1.zip/main", "code one"),
            artifact("app-1.1.zip/new.dat", "new"),
        ];
        let a = report(
            "app-1.0.zip",
            old.to_vec(),
            vec![
                finding("app.version", Severity::Info, &old[1], &[("version", "1.0")]),
                finding("app.signed", Severity::Info, &old[2], &[("who", "Example Corp")]),
                finding("app.debuggable", Severity::Low, &old[1], &[]),
                finding("app.permission", Severity::Info, &old[1], &[("name", "camera")]),
                finding("app.permission", Severity::Info, &old[1], &[("name", "contacts")]),
            ],
        );
        let b = report(
            "app-1.1.zip",
            new.to_vec(),
            vec![
                finding("app.version", Severity::Info, &new[1], &[("version", "1.1")]),
                finding("app.signed", Severity::Info, &new[2], &[("who", "Example Corp")]),
                finding("app.permission", Severity::Info, &new[1], &[("name", "camera")]),
                finding("app.permission", Severity::Medium, &new[3], &[("name", "location")]),
            ],
        );
        (a, b)
    }

    #[test]
    fn two_versions_show_what_was_added_removed_and_changed() {
        let (a, b) = versions();
        let result = diff(&a, &b);

        // The signature and the camera permission are said by both, though no id is shared.
        assert_eq!(result.findings.unchanged, 2);
        assert!(a.findings.iter().all(|x| b.findings.iter().all(|y| x.id != y.id)));
        let rules = |list: &[Statement]| list.iter().map(|s| (s.finding.rule.clone(), s.place.clone())).collect::<Vec<_>>();
        // The contacts permission and the debuggable flag are gone; a permission on a new file came.
        assert_eq!(
            rules(&result.findings.removed),
            [("app.debuggable".to_string(), "Info".to_string()), ("app.permission".into(), "Info".into())]
        );
        assert_eq!(rules(&result.findings.added), [("app.permission".to_string(), "new.dat".to_string())]);
        assert_eq!(result.findings.changed.len(), 1);
        let change = &result.findings.changed[0];
        assert_eq!(
            (change.place.as_str(), &change.before.params["version"], &change.after.params["version"]),
            ("Info", &"1.0".into(), &"1.1".into())
        );

        // Files: by place inside the archive, whatever the archive is called.
        assert_eq!(result.files.unchanged, 1, "main is the same");
        assert_eq!(result.files.added.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(), ["new.dat"]);
        assert_eq!(result.files.removed.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(), ["old.dat"]);
        assert_eq!(result.files.changed.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(), ["", "Info"]);
        assert!(!result.is_empty());

        // Only the rules of listed findings are carried, and the result survives JSON.
        assert_eq!(result.rules.keys().collect::<Vec<_>>(), ["app.debuggable", "app.permission", "app.version"]);
        let json = serde_json::to_string(&result).expect("json");
        assert_eq!(serde_json::from_str::<Diff>(&json).expect("parse"), result);
    }

    #[test]
    fn a_report_compared_with_itself_has_no_differences() {
        let (a, _) = versions();
        let result = diff(&a, &a);
        assert!(result.is_empty());
        assert_eq!(result.findings.unchanged, a.findings.len() as u64);
        assert_eq!(result.files.unchanged, a.artifacts.len() as u64);
        assert!(result.rules.is_empty());
    }

    #[test]
    fn renamed_inputs_keep_artifact_parameters_but_preserve_real_changes() {
        let make = |input: &str, member: &str, product: &str| {
            let file = artifact(&format!("{input}/{member}"), "same content");
            let statements = vec![
                finding("structure.largest", Severity::Info, &file, &[("path", &file.path)]),
                finding("test.file", Severity::Info, &file, &[("file", &file.path)]),
                finding("overview.product", Severity::Info, &file, &[("name", product)]),
                finding("binary.pe-pdb", Severity::Info, &file, &[("path", input)]),
            ];
            report(input, vec![file], statements)
        };
        let a = make("old.zip", "main", "old.zip");
        let b = make("new.zip", "main", "new.zip");
        let result = diff(&a, &b);
        assert_eq!(result.findings.unchanged, 2);
        assert_eq!(result.findings.changed.len(), 2, "product and embedded PDB paths are actual data");
        assert_eq!(a.findings[0].params["path"], "old.zip/main", "normalization must not rewrite the report");
        let c = make("new.zip", "other", "old.zip");
        let result = diff(&a, &c);
        assert_eq!(result.findings.added.len(), 4, "a changed member path remains significant");
        assert_eq!(result.findings.removed.len(), 4);
    }

    #[test]
    fn renamed_bundle_folders_only_normalize_the_input_label() {
        let file = artifact("Info.plist", "same bytes");
        let mut a =
            report("Old.app", vec![file.clone()], vec![finding("overview.kind-bundle", Severity::Info, &file, &[("name", "Old.app")])]);
        let mut b =
            report("New.app", vec![file.clone()], vec![finding("overview.kind-bundle", Severity::Info, &file, &[("name", "New.app")])]);
        a.input.kind = InputKind::Directory;
        b.input.kind = InputKind::Directory;
        assert!(diff(&a, &b).is_empty());
    }

    #[test]
    fn text_names_each_difference_in_either_language() {
        let (a, b) = versions();
        let result = diff(&a, &b);
        let english = text(&result, Language::En);
        assert!(english.starts_with("Comparison: app-1.0.zip  →  app-1.1.zip\n"), "{english}");
        assert!(english.contains("Findings: 1 added · 2 removed · 1 changed · 2 unchanged"), "{english}");
        assert!(english.contains("+ [medium] Permission: Asks for location.  (new.dat)"), "{english}");
        assert!(english.contains("- [low] Debuggable: The app can be debugged.  (Info)"), "{english}");
        assert!(english.contains("~ [info] Version: Version 1.1.  (Info)\n    before: Version: Version 1.0."), "{english}");
        assert!(english.contains("+ new.dat  3 bytes") && english.contains("- old.dat  3 bytes"), "{english}");
        assert!(english.contains("~ (the input itself)  7 → 7 bytes"), "{english}");
        let chinese = text(&result, Language::Zh);
        assert!(chinese.contains("结论: 1 新增 · 2 消失 · 1 变化 · 2 相同"), "{chinese}");
        assert!(chinese.contains("+ [中] Permission（中）: Asks for {name}.（中）".replace("{name}", "location").as_str()), "{chinese}");
    }

    #[test]
    fn folders_are_compared_by_their_paths_as_they_are() {
        let files = [artifact("a.txt", "one")];
        let mut a = report("left", files.to_vec(), Vec::new());
        let mut b = report("right", vec![artifact("a.txt", "two"), artifact("left/x", "x")], Vec::new());
        a.input.kind = InputKind::Directory;
        b.input.kind = InputKind::Directory;
        let result = diff(&a, &b);
        assert_eq!(result.files.changed.len(), 1);
        // A folder named like the other input is an ordinary folder, not a prefix to strip.
        assert_eq!(result.files.added.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(), ["left/x"]);
    }
}
