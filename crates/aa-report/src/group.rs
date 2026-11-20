//! Findings of one rule, shown as one entry.
//!
//! A real report holds hundreds of findings that say the same thing about different files. Every
//! readable output groups them the same way, and this module is the one place that decides how:
//! a chapter is a list of [`Group`]s, one per rule, in the order the report first mentions them; a group is a list of [`Variant`]s, one per
//! distinct sentence; a variant lists the findings that share that sentence.
//!
//! So "ASLR is on" is written once, followed by the files it holds for, instead of 475 times.
//! Nothing is dropped: the groups always hold every finding they were given, and an output that
//! lists only some of them says how many it left out.

use std::collections::BTreeMap;

use aa_core::{Confidence, Finding, Report, Section, Severity};

use crate::Lang;
use crate::doc::{finding_text, rule_title};
use crate::words::{self, ui};

/// Findings listed under a group of neutral facts in Markdown, text and PDF.
pub const LISTED_INFO: usize = 10;
/// Findings listed under a group that holds anything more severe than `Info`.
pub const LISTED_ABOVE_INFO: usize = 30;

/// One finding inside a group.
#[derive(Debug, Clone)]
pub struct Instance<'a> {
    /// Position of the finding in [`Report::findings`].
    pub index: usize,
    pub finding: &'a Finding,
    /// The artifact the finding is about — its first evidence — shortened to the file name and
    /// as many parent folders as it takes to tell it from the other subjects of the group.
    /// `None` for a finding without evidence.
    pub subject: Option<String>,
}

/// The findings of a group that read the same.
#[derive(Debug, Clone)]
pub struct Variant<'a> {
    /// The sentence, with the params filled in.
    pub text: String,
    /// Most severe first, otherwise in report order.
    pub instances: Vec<Instance<'a>>,
}

/// The findings of one rule.
#[derive(Debug, Clone)]
pub struct Group<'a> {
    /// Position in [`Report::findings`] of the group's first finding.
    pub first: usize,
    pub rule: &'a str,
    pub title: String,
    /// The highest severity among the findings.
    pub severity: Severity,
    /// Number of findings.
    pub count: usize,
    /// In the order their first finding appears in the group.
    pub variants: Vec<Variant<'a>>,
}

impl<'a> Group<'a> {
    /// Every finding of the group, in the order the variants list them.
    pub fn instances(&self) -> impl Iterator<Item = &Instance<'a>> {
        self.variants.iter().flat_map(|variant| variant.instances.iter())
    }

    /// How many findings a reading format lists before it counts the rest.
    pub fn listed(&self) -> usize {
        if self.severity == Severity::Info { LISTED_INFO } else { LISTED_ABOVE_INFO }
    }
}

/// The path of the first evidence, if the finding has any.
fn subject_path(finding: &Finding) -> Option<&str> {
    finding.evidence.first().map(|evidence| evidence.artifact.as_str())
}

/// Shortens each of `paths` to its last components: as few as tell it apart from the others.
fn short_subjects(paths: &[&str]) -> BTreeMap<String, String> {
    let split: Vec<Vec<&str>> = paths.iter().map(|path| path.split('/').collect()).collect();
    let mut out = BTreeMap::new();
    // Count how many distinct paths end in each suffix, for every suffix length that is needed.
    let mut keep = 1;
    let mut pending: Vec<usize> = (0..paths.len()).collect();
    while !pending.is_empty() {
        let mut seen: BTreeMap<String, Vec<&str>> = BTreeMap::new();
        for (index, parts) in split.iter().enumerate() {
            let owners = seen.entry(parts[parts.len().saturating_sub(keep)..].join("/")).or_default();
            if !owners.contains(&paths[index]) {
                owners.push(paths[index]);
            }
        }
        pending.retain(|&index| {
            let parts = &split[index];
            let suffix = parts[parts.len().saturating_sub(keep)..].join("/");
            let whole = keep >= parts.len();
            if whole || seen.get(&suffix).is_some_and(|owners| owners.len() == 1) {
                out.insert(paths[index].to_string(), if whole { paths[index].to_string() } else { format!("…/{suffix}") });
                false
            } else {
                true
            }
        });
        keep += 1;
    }
    out
}

/// Groups `findings` (each with its position in the report) by rule.
///
/// Groups come in the order their first finding appears in the report. The engine orders a
/// chapter's findings most severe first, then as the analyzers declared their rules — an order
/// chosen for reading — so the groups inherit it. Inside a group the findings keep report order,
/// except that anything above `Info` is listed before `Info`.
pub fn groups<'a>(report: &'a Report, lang: Lang, findings: impl Iterator<Item = (usize, &'a Finding)>) -> Vec<Group<'a>> {
    let mut by_rule: BTreeMap<&str, Vec<(usize, &Finding)>> = BTreeMap::new();
    for (index, finding) in findings {
        by_rule.entry(finding.rule.as_str()).or_default().push((index, finding));
    }
    let mut out: Vec<Group> = by_rule
        .into_iter()
        .map(|(rule, mut members)| {
            // A stable sort: findings of one severity keep their report order.
            members.sort_by_key(|(_, finding)| std::cmp::Reverse(finding.severity));
            let paths: Vec<&str> = members.iter().filter_map(|(_, finding)| subject_path(finding)).collect();
            let short = short_subjects(&paths);
            let mut variants: Vec<Variant> = Vec::new();
            let mut by_text: BTreeMap<String, usize> = BTreeMap::new();
            for (index, finding) in &members {
                let text = finding_text(report, lang, finding);
                let at = *by_text.entry(text.clone()).or_insert_with(|| {
                    variants.push(Variant { text, instances: Vec::new() });
                    variants.len() - 1
                });
                let subject = subject_path(finding).and_then(|path| short.get(path).cloned());
                variants[at].instances.push(Instance { index: *index, finding, subject });
            }
            Group {
                first: members.iter().map(|(index, _)| *index).min().unwrap_or(0),
                rule,
                title: rule_title(report, lang, rule),
                severity: members.iter().map(|(_, finding)| finding.severity).max().unwrap_or(Severity::Info),
                count: members.len(),
                variants,
            }
        })
        .collect();
    out.sort_by_key(|group| group.first);
    out
}

/// The groups of one chapter.
pub fn chapter(report: &Report, lang: Lang, section: Section) -> Vec<Group<'_>> {
    groups(report, lang, report.findings.iter().enumerate().filter(|(_, finding)| finding.section == section))
}

/// The groups of the "needs attention" list: every finding above `Info`, from all chapters.
pub fn attention(report: &Report, lang: Lang) -> Vec<Group<'_>> {
    groups(report, lang, report.findings.iter().enumerate().filter(|(_, finding)| finding.severity > Severity::Info))
}

/// `1234567` as `1,234,567`.
pub fn thousands(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A chapter heading with both counts, e.g. `安全加固 · 12 类 / 1,907 条`; the bare title when
/// the chapter is empty.
pub fn heading(lang: Lang, title: &str, groups: &[Group]) -> String {
    if groups.is_empty() {
        return title.to_string();
    }
    let findings: usize = groups.iter().map(|group| group.count).sum();
    let counts =
        crate::words::agree(&ui(lang, "chapter_counts").replace("{n}", &thousands(groups.len())).replace("{m}", &thousands(findings)));
    format!("{title} · {counts}")
}

/// The severities and confidence levels of a group, e.g. `低 × 141 · 已验证`.
pub fn label(lang: Lang, group: &Group) -> String {
    let severities: Vec<String> = [Severity::High, Severity::Medium, Severity::Low, Severity::Info]
        .into_iter()
        .filter_map(|severity| {
            let count = group.instances().filter(|i| i.finding.severity == severity).count();
            (count > 0).then(|| format!("{} × {}", words::severity(lang, severity), thousands(count)))
        })
        .collect();
    let confidences: Vec<&str> = [Confidence::Verified, Confidence::Derived, Confidence::Heuristic]
        .into_iter()
        .filter(|confidence| group.instances().any(|i| i.finding.confidence == *confidence))
        .map(|confidence| words::confidence(lang, confidence))
        .collect();
    format!("{} · {}", severities.join(" · "), confidences.join(" / "))
}

/// One line of a group as the reading formats list it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Row {
    /// A sentence several findings share, and the subjects it holds for (each named once).
    Shared {
        text: String,
        /// Findings that read this way, listed or not.
        count: usize,
        subjects: Vec<String>,
        /// True when not every subject is in `subjects`.
        cut: bool,
    },
    /// A sentence only one finding has.
    Single { subject: Option<String>, text: String },
}

/// A group cut to what the reading formats list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub rows: Vec<Row>,
    /// Findings of the group that no row names.
    pub not_shown: usize,
}

/// The rows Markdown, text and PDF list for `group`: its first [`Group::listed`] findings.
pub fn listing(group: &Group) -> Listing {
    let mut left = group.listed();
    let mut rows = Vec::new();
    for variant in &group.variants {
        if left == 0 {
            break;
        }
        let take = variant.instances.len().min(left);
        left -= take;
        if let [only] = variant.instances.as_slice() {
            rows.push(Row::Single { subject: only.subject.clone(), text: variant.text.clone() });
            continue;
        }
        let mut subjects: Vec<String> = Vec::new();
        for instance in &variant.instances[..take] {
            if let Some(subject) = &instance.subject
                && !subjects.contains(subject)
            {
                subjects.push(subject.clone());
            }
        }
        rows.push(Row::Shared {
            text: variant.text.clone(),
            count: variant.instances.len(),
            subjects,
            cut: take < variant.instances.len(),
        });
    }
    let shown = group.listed() - left;
    Listing { rows, not_shown: group.count - shown }
}

/// The sentence that says how many findings of a group a reading format left out.
pub fn not_shown_note(lang: Lang, not_shown: usize) -> String {
    ui(lang, "group_not_shown").replace("{n}", &thousands(not_shown))
}

/// The words in front of the subjects of a shared sentence.
pub fn shared_note(lang: Lang, count: usize) -> String {
    ui(lang, "group_shared").replace("{n}", &thousands(count))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subjects_keep_as_much_path_as_tells_them_apart() {
        let short = short_subjects(&["a/x/lib.so", "a/y/lib.so", "a/y/other.so", "top.bin", "b/y/lib.so", "a/x/lib.so"]);
        assert_eq!(short["a/x/lib.so"], "…/x/lib.so");
        assert_eq!(short["a/y/lib.so"], "a/y/lib.so");
        assert_eq!(short["b/y/lib.so"], "b/y/lib.so");
        assert_eq!(short["a/y/other.so"], "…/other.so");
        assert_eq!(short["top.bin"], "top.bin");
    }

    fn sample() -> Report {
        use aa_core::{Artifact, Coverage, Evidence, Input, InputKind, RuleText, Tool};
        let file = |path: &str| Artifact {
            path: path.into(),
            parent: None,
            size: 1,
            digests: None,
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        };
        let files: Vec<Artifact> = (0..50).map(|i| file(&format!("d/f{i:02}"))).collect();
        let finding = |rule: &str, severity: Severity, file: &Artifact, n: u64| {
            Finding::new(Section::Code, "t", rule, Confidence::Derived, severity).param("n", n).evidence(Evidence::whole(file, 0)).seal()
        };
        let mut findings: Vec<Finding> = files.iter().map(|f| finding("b.same", Severity::Info, f, 0)).collect();
        findings.push(finding("z.high", Severity::High, &files[0], 0));
        findings.push(finding("a.low", Severity::Low, &files[1], 1));
        findings.push(finding("a.low", Severity::Info, &files[2], 2));
        findings.push(finding("a.low", Severity::Low, &files[3], 2));
        findings.extend(files.iter().take(45).enumerate().map(|(i, f)| finding("c.each", Severity::Low, f, i as u64)));
        let text =
            |title: &str| RuleText { title_zh: title.into(), title_en: title.into(), text_zh: "n={n}".into(), text_en: "n={n}".into() };
        Report {
            schema_version: aa_core::SCHEMA_VERSION,
            tool: Tool { name: "t".into(), version: "0".into() },
            input: Input { name: "d".into(), kind: InputKind::Directory, sha256: None },
            summary: BTreeMap::new(),
            artifacts: files,
            findings,
            limitations: Vec::new(),
            coverage: Coverage::default(),
            rules: BTreeMap::from([
                ("b.same".into(), text("Same")),
                ("z.high".into(), text("Alarming")),
                ("a.low".into(), text("Mixed")),
                ("c.each".into(), text("Each differs")),
            ]),
        }
    }

    #[test]
    fn groups_come_in_report_order_and_hold_every_finding() {
        let report = sample();
        let groups = chapter(&report, Lang::En, Section::Code);
        assert_eq!(groups.iter().map(|g| g.title.as_str()).collect::<Vec<_>>(), ["Same", "Alarming", "Mixed", "Each differs"]);
        assert_eq!(groups.iter().map(|g| g.count).collect::<Vec<_>>(), [50, 1, 3, 45]);
        let mut indices: Vec<usize> = groups.iter().flat_map(|g| g.instances().map(|i| i.index)).collect();
        indices.sort_unstable();
        assert_eq!(indices, (0..report.findings.len()).collect::<Vec<_>>());
        assert_eq!(heading(Lang::Zh, "代码洞察", &groups), "代码洞察 · 4 类 / 99 条");
        assert_eq!(heading(Lang::Zh, "代码洞察", &[]), "代码洞察");
        assert_eq!(attention(&report, Lang::En).iter().map(|g| g.count).collect::<Vec<_>>(), [1, 2, 45]);
    }

    #[test]
    fn inside_a_group_anything_above_info_comes_first_otherwise_report_order() {
        let report = sample();
        let groups = chapter(&report, Lang::En, Section::Code);
        let mixed = &groups[2];
        assert_eq!(label(Lang::En, mixed), "Low × 2 · Info × 1 · Derived");
        // The report lists Low n=1, Info n=2, Low n=2: the Low findings move ahead of the Info one.
        assert_eq!(mixed.variants.iter().map(|v| v.text.as_str()).collect::<Vec<_>>(), ["n=1", "n=2"]);
        assert_eq!(mixed.variants[1].instances.iter().map(|i| i.finding.severity).collect::<Vec<_>>(), [Severity::Low, Severity::Info]);
        assert_eq!(mixed.variants[1].instances[0].subject.as_deref(), Some("…/f03"));
    }

    #[test]
    fn listings_stop_at_the_cap_and_count_what_they_leave_out() {
        let report = sample();
        let groups = chapter(&report, Lang::En, Section::Code);
        // Fifty neutral facts with one sentence: one row naming ten files.
        let same = listing(&groups[0]);
        assert_eq!(same.not_shown, 40);
        assert!(matches!(&same.rows[..], [Row::Shared { count: 50, subjects, cut: true, .. }] if subjects.len() == LISTED_INFO));
        assert_eq!(
            not_shown_note(Lang::En, same.not_shown),
            "40 more of this kind are not listed here; report.html and report.json hold them all."
        );
        // Forty-five Low findings that all differ: thirty rows.
        let each = listing(&groups[3]);
        assert_eq!((each.rows.len(), each.not_shown), (LISTED_ABOVE_INFO, 15));
        assert!(each.rows.iter().all(|row| matches!(row, Row::Single { subject: Some(_), .. })));
        // A small group is listed whole.
        assert_eq!(listing(&groups[2]).not_shown, 0);
    }

    #[test]
    fn thousands_are_separated() {
        assert_eq!([0, 999, 1000, 1234567].map(thousands), ["0", "999", "1,000", "1,234,567"]);
    }
}
