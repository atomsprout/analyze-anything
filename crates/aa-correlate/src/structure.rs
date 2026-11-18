//! The shape of the input: how much there is, what kinds, the largest files, duplicates, nesting.
//!
//! Facts written to the report summary:
//! - `structure.totals`: `{files, bytes, input_files, input_bytes, unpacked_files, unpacked_bytes, containers, max_depth}`
//! - `structure.by_type`: `[{type, files, bytes}]`, largest first, at most [`TYPES`] rows
//! - `structure.largest`: `[{path, bytes, type}]`, at most [`LARGEST`] rows
//! - `structure.duplicates`: `{groups: [{sha256, bytes, paths: [..]}], total_groups, wasted_bytes, truncated}`

use std::collections::BTreeMap;

use aa_core::plugin::{Analyzer, Output, Rule, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::json;

pub struct Structure;

const TYPES: usize = 40;
const LARGEST: usize = 25;
const DUPLICATE_GROUPS: usize = 200;
const DUPLICATE_PATHS: usize = 20;

const RULES: &[Rule] = &[
    Rule {
        id: "structure.totals",
        title_zh: "规模",
        title_en: "Size",
        text_zh: "共 {files} 个文件、{bytes} 字节。其中输入本身有 {input_files} 个文件（{input_bytes} 字节），另有 {unpacked_files} 个文件（{unpacked_bytes} 字节）是从 {containers} 个容器中解包得到的，最深嵌套 {max_depth} 层。",
        text_en: "{files} files, {bytes} bytes in all. The input itself holds {input_files} files ({input_bytes} bytes); a further {unpacked_files} files ({unpacked_bytes} bytes) were unpacked from {containers} containers, nested up to {max_depth} deep.",
    },
    Rule {
        id: "structure.by-type",
        title_zh: "按类型的体积分布",
        title_en: "Size by type",
        text_zh: "体积最大的类型是 {type}：{files} 个文件，共 {bytes} 字节，占全部内容的 {percent}%。完整分布见摘要数据 structure.by_type。",
        text_en: "The largest type is {type}: {files} files, {bytes} bytes, {percent}% of all content. The full breakdown is in the summary data structure.by_type.",
    },
    Rule {
        id: "structure.largest",
        title_zh: "最大的文件",
        title_en: "Largest file",
        text_zh: "最大的文件是 {path}（{bytes} 字节）。前 {listed} 名见摘要数据 structure.largest。",
        text_en: "The largest file is {path} ({bytes} bytes). The top {listed} are in the summary data structure.largest.",
    },
    Rule {
        id: "structure.duplicates",
        title_zh: "内容完全相同的文件",
        title_en: "Identical files",
        text_zh: "有 {groups} 组文件内容完全相同（SHA-256 一致），重复部分共 {wasted_bytes} 字节。",
        text_en: "{groups} groups of files have identical content (same SHA-256); the repeated copies add up to {wasted_bytes} bytes.",
    },
];

/// The label a file is counted under: what it was recognised as, else its MIME type.
fn type_of(artifact: &Artifact) -> String {
    match (&artifact.kind, &artifact.detected) {
        (Some(kind), _) => kind.clone(),
        (None, Some(detected)) => detected.mime.clone(),
        (None, None) => "unreadable".to_string(),
    }
}

/// How many containers an artifact sits inside.
fn depth(tree: &dyn Tree, artifact: &Artifact) -> u64 {
    let mut depth = 0;
    let mut parent = artifact.parent.as_deref();
    // The tree cannot hold a cycle, but a bound costs nothing.
    while let Some(path) = parent
        && depth < 64
    {
        depth += 1;
        parent = tree.get(path).and_then(|a| a.parent.as_deref());
    }
    depth
}

impl Analyzer for Structure {
    fn id(&self) -> &'static str {
        "structure"
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        let artifacts = tree.artifacts();
        if artifacts.is_empty() {
            return;
        }
        // A container's bytes are its children in packed form, so content totals count leaves
        // only; otherwise everything inside an archive would be counted twice.
        let leaves: Vec<&Artifact> = artifacts.iter().filter(|a| a.unpacked_by.is_none()).collect();
        let input: Vec<&Artifact> = artifacts.iter().filter(|a| a.parent.is_none()).collect();
        let unpacked: Vec<&Artifact> = artifacts.iter().filter(|a| a.parent.is_some()).collect();
        let bytes = |list: &[&Artifact]| list.iter().map(|a| a.size).sum::<u64>();
        let containers = artifacts.iter().filter(|a| a.unpacked_by.is_some()).count();
        let max_depth = artifacts.iter().map(|a| depth(tree, a)).max().unwrap_or(0);
        let leaf_bytes = bytes(&leaves);

        let totals = json!({
            "files": leaves.len(),
            "bytes": leaf_bytes,
            "input_files": input.len(),
            "input_bytes": bytes(&input),
            "unpacked_files": unpacked.len(),
            "unpacked_bytes": bytes(&unpacked),
            "containers": containers,
            "max_depth": max_depth,
        });
        out.summary("structure.totals", totals.clone());
        let mut finding = Finding::new(Section::Structure, "structure", "structure.totals", Confidence::Derived, Severity::Info);
        if let Some(fields) = totals.as_object() {
            for (name, value) in fields {
                finding = finding.param(name, value.clone());
            }
        }
        out.finding(finding.evidence(Evidence::whole(input[0], input.len())));

        let mut by_type: BTreeMap<String, (u64, u64)> = BTreeMap::new();
        for leaf in &leaves {
            let entry = by_type.entry(type_of(leaf)).or_default();
            entry.0 += 1;
            entry.1 += leaf.size;
        }
        let mut types: Vec<(String, u64, u64)> = by_type.into_iter().map(|(t, (files, bytes))| (t, files, bytes)).collect();
        types.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(&b.0)));
        let listed: Vec<_> =
            types.iter().take(TYPES).map(|(t, files, bytes)| json!({ "type": t, "files": files, "bytes": bytes })).collect();
        out.summary("structure.by_type", listed);
        if let Some((kind, files, kind_bytes)) = types.first()
            && leaf_bytes > 0
            && types.len() > 1
        {
            let percent = (*kind_bytes as f64 * 1000.0 / leaf_bytes as f64).round() / 10.0;
            let example = leaves.iter().find(|a| &type_of(a) == kind).unwrap_or(&leaves[0]);
            out.finding(
                Finding::new(Section::Structure, "structure", "structure.by-type", Confidence::Derived, Severity::Info)
                    .param("type", kind.clone())
                    .param("files", *files)
                    .param("bytes", *kind_bytes)
                    .param("percent", percent)
                    .evidence(Evidence::whole(example, kind.clone())),
            );
        }

        let mut largest = leaves.clone();
        largest.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.path.cmp(&b.path)));
        largest.truncate(LARGEST);
        out.summary(
            "structure.largest",
            largest.iter().map(|a| json!({ "path": a.path, "bytes": a.size, "type": type_of(a) })).collect::<Vec<_>>(),
        );
        if leaves.len() > 1
            && let Some(top) = largest.first()
        {
            out.finding(
                Finding::new(Section::Structure, "structure", "structure.largest", Confidence::Verified, Severity::Info)
                    .param("path", top.path.clone())
                    .param("bytes", top.size)
                    .param("listed", largest.len())
                    .evidence(Evidence::whole(top, top.size)),
            );
        }

        let mut by_digest: BTreeMap<&str, Vec<&Artifact>> = BTreeMap::new();
        for artifact in artifacts.iter().filter(|a| a.size > 0) {
            if let Some(digests) = &artifact.digests {
                by_digest.entry(digests.sha256.as_str()).or_default().push(artifact);
            }
        }
        let mut groups: Vec<(&str, Vec<&Artifact>)> = by_digest.into_iter().filter(|(_, members)| members.len() > 1).collect();
        if groups.is_empty() {
            return;
        }
        let wasted = |members: &[&Artifact]| members[0].size * (members.len() as u64 - 1);
        groups.sort_by(|a, b| wasted(&b.1).cmp(&wasted(&a.1)).then_with(|| a.0.cmp(b.0)));
        let wasted_bytes: u64 = groups.iter().map(|(_, members)| wasted(members)).sum();
        let listed: Vec<_> = groups
            .iter()
            .take(DUPLICATE_GROUPS)
            .map(|(sha256, members)| {
                json!({
                    "sha256": sha256,
                    "bytes": members[0].size,
                    "copies": members.len(),
                    "paths": members.iter().take(DUPLICATE_PATHS).map(|a| a.path.as_str()).collect::<Vec<_>>(),
                })
            })
            .collect();
        out.summary(
            "structure.duplicates",
            json!({ "groups": listed, "total_groups": groups.len(), "wasted_bytes": wasted_bytes, "truncated": groups.len() > DUPLICATE_GROUPS }),
        );
        let mut finding = Finding::new(Section::Structure, "structure", "structure.duplicates", Confidence::Verified, Severity::Info)
            .param("groups", groups.len())
            .param("wasted_bytes", wasted_bytes);
        for member in groups[0].1.iter().take(4) {
            finding = finding.evidence(Evidence::whole(member, groups[0].0));
        }
        out.finding(finding);
    }
}
