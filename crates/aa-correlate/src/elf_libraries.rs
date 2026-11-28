//! Match literal ELF dependency names to compatible captured libraries, without a loader.

use std::collections::BTreeMap;

use aa_core::plugin::{Analyzer, Output, Rule, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::{Value, json};

pub struct ElfLibraries;

const MAX_FILES: usize = 100_000;
const MAX_PATH_BYTES: usize = 32 * 1024 * 1024;
const MAX_REFERENCES: usize = 10_000;
const MAX_PER_SOURCE: usize = 512;
const MAX_NAME: usize = 4096;
const MAX_CANDIDATE_CHECKS: usize = 500_000;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

const RULES: &[Rule] = &[
    Rule {
        id: "composition.elf-library-reference",
        title_en: "ELF dependency and supplied library",
        title_zh: "ELF 依赖与随附库",
        text_en: "The literal dependency {name} has one supplied library with the same filename or SONAME and recorded ELF machine, class and byte order in this captured namespace. ABI compatibility and runtime loader selection remain unresolved.",
        text_zh: "字面依赖 {name} 在此已捕获命名空间中有一个文件名或 SONAME 相同、且已记录 ELF 机器类型、位数和字节序相同的随附库。ABI 兼容性与运行时加载器选择仍未确定。",
    },
    Rule {
        id: "composition.elf-library-unresolved",
        title_en: "ELF dependency relationship unresolved",
        title_zh: "ELF 依赖关系未确定",
        text_en: "Some literal dependencies could not be associated with an unambiguous compatible supplied library. Host libraries and loader search paths were not resolved.",
        text_zh: "部分字面依赖无法关联到唯一且兼容的随附库。没有解析主机库或加载器搜索路径。",
    },
    Rule {
        id: "composition.elf-library-budget",
        title_en: "ELF relationship budget reached",
        title_zh: "ELF 关系达到上限",
        text_en: "Some supplied-library relationships were omitted because the bounded file, name or reference budget was reached.",
        text_zh: "部分随附库关系因文件、名称或引用数量达到上限而省略。",
    },
];

fn header(file: &Artifact) -> Option<&Value> {
    file.facts.get("binary.header").filter(|header| header["format"] == "elf")
}

fn original(file: &Artifact) -> bool {
    file.facts.get("engine.entry-name").is_none_or(|name| name["normalized"] != true && name["colliding"] != true)
}

fn literal_name(name: &str) -> bool {
    // The binary reader clips C strings at 1024 bytes and replaces unreadable text.
    // Such text cannot establish exact dependency identity.
    !name.is_empty() && name.len() < 1024 && !name.contains(['/', '\\', '$', '\u{fffd}']) && !name.chars().any(char::is_control)
}

fn compatible(source: &Artifact, target: &Artifact) -> bool {
    let (Some(source), Some(target)) = (header(source), header(target)) else { return false };
    ["machine", "bits", "endian"].iter().all(|key| !source[*key].is_null() && source[*key] == target[*key])
}

fn complete(tree: &dyn Tree, source: &Artifact) -> bool {
    match source.parent.as_deref() {
        Some(parent) => {
            tree.get(parent).is_some_and(|parent| parent.facts.get("engine.container-listing").is_some_and(|fact| fact["complete"] == true))
        }
        None => tree.summary().get("engine.input-listing").is_some_and(|fact| fact["complete"] == true),
    }
}

impl Analyzer for ElfLibraries {
    fn id(&self) -> &'static str {
        "composition"
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        let files = tree.artifacts();
        if files.len() > MAX_FILES
            || files.iter().any(|file| file.path.len() > 8192)
            || files.iter().map(|file| file.path.len()).sum::<usize>() > MAX_PATH_BYTES
        {
            out.limitation(
                "composition.elf-library-budget",
                None,
                Some("supplied file index exceeds 100,000 files or 32 MiB of paths".into()),
            );
            return;
        }
        let mut index: BTreeMap<(Option<&str>, &str), Vec<&Artifact>> = BTreeMap::new();
        for file in files.iter().filter(|file| header(file).is_some_and(|h| h["file_type"] == "shared-library")) {
            let soname = file.facts.get("binary.linking").and_then(|fact| fact["soname"].as_str());
            for name in [Some(file.name()), soname].into_iter().flatten() {
                if !literal_name(name) {
                    continue;
                }
                let candidates = index.entry((file.parent.as_deref(), name)).or_default();
                if candidates.last().is_none_or(|candidate| candidate.path != file.path) {
                    candidates.push(file);
                }
            }
        }
        let mut total = 0usize;
        let mut candidate_checks = 0usize;
        let mut output_bytes = 0usize;
        for source in files.iter().filter(|file| header(file).is_some()) {
            let Some(fact) = source.facts.get("binary.libraries") else { continue };
            let Some(libraries) = fact["libraries"].as_array() else { continue };
            let mut rows = Vec::new();
            let mut unresolved = false;
            let mut truncated = fact["truncated"] == true;
            for (ordinal, library) in libraries.iter().enumerate() {
                if ordinal == MAX_PER_SOURCE || total == MAX_REFERENCES {
                    truncated = true;
                    break;
                }
                total += 1;
                let Some(name) = library["name"].as_str() else {
                    unresolved = true;
                    rows.push(json!({"field":format!("DT_NEEDED[{ordinal}]"),"status":"unresolved","reason":"dependency-name-unread"}));
                    continue;
                };
                let candidates = index.get(&(source.parent.as_deref(), name));
                let checks = candidates.map_or(0, Vec::len);
                let budget_exhausted = checks > MAX_CANDIDATE_CHECKS.saturating_sub(candidate_checks);
                let matching: Vec<_> = if budget_exhausted {
                    truncated = true;
                    Vec::new()
                } else {
                    candidate_checks += checks;
                    candidates.into_iter().flatten().filter(|target| target.path != source.path && compatible(source, target)).collect()
                };
                let reason = if budget_exhausted {
                    Some("candidate-comparison-budget-exhausted")
                } else if !literal_name(name) {
                    Some("dependency-name-outside-literal-basename-profile")
                } else if !original(source) {
                    Some("source-entry-name-not-original-or-unique")
                } else if !complete(tree, source) {
                    Some("captured-namespace-listing-incomplete")
                } else if matching.is_empty() {
                    Some("compatible-library-not-supplied")
                } else if matching.len() != 1 {
                    Some("multiple-compatible-supplied-libraries")
                } else if !original(matching[0]) || matching[0].digests.is_none() {
                    Some("target-entry-name-or-bytes-not-established")
                } else {
                    None
                };
                let target = reason.is_none().then(|| *matching[0]);
                let row = json!({
                    "field": format!("DT_NEEDED[{ordinal}]"), "declared": name.chars().take(MAX_NAME).collect::<String>(),
                    "declared_text_clipped":name.chars().count()>MAX_NAME,
                    "status": if target.is_some() { "matched-supplied-library" } else { "unresolved" },
                    "basis":"same-namespace-machine-class-byte-order-filename-or-soname",
                    "matched_by":target.map(|target|if target.facts.get("binary.linking").is_some_and(|fact|fact["soname"]==name){"soname"}else{"filename"}),
                    "target": target.map(|target| &target.path),
                    "target_sha256": target.and_then(|target| target.digests.as_ref().map(|digest| &digest.sha256)),
                    "reason":reason, "observed_compatible_candidates":matching.len(),
                    "candidates":matching.iter().take(20).map(|target| target.path.chars().take(400).collect::<String>()).collect::<Vec<_>>(),
                    "candidates_truncated":budget_exhausted || matching.len()>20,
                    "candidate_paths_clipped":matching.iter().take(20).any(|target| target.path.chars().count()>400), "runtime_target_resolved":false,"abi_compatibility_established":false,
                });
                let row_bytes = row.to_string().len();
                if row_bytes > MAX_OUTPUT_BYTES.saturating_sub(output_bytes) {
                    truncated = true;
                    break;
                }
                output_bytes += row_bytes;
                rows.push(row);
                if let Some(target) = target {
                    out.finding(Finding::new(Section::Composition, "composition", "composition.elf-library-reference", Confidence::Derived, Severity::Info)
                        .param("name", name)
                        .evidence(Evidence::field(source, format!("binary.libraries/libraries[{ordinal}]/name"), name))
                        .evidence(Evidence::whole(target, json!({"path":target.path,"header":target.facts.get("binary.header"),"soname":target.facts.get("binary.linking").and_then(|fact|fact.get("soname")),"sha256":target.digests.as_ref().map(|digest|&digest.sha256)}))));
                } else {
                    unresolved = true;
                }
            }
            if !rows.is_empty() || truncated {
                out.fact(
                    source,
                    "composition.elf-library-references",
                    json!({"references":rows,"truncated":truncated,"runtime_target_resolved":false,"host_libraries_checked":false}),
                );
            }
            if unresolved {
                out.limitation("composition.elf-library-unresolved", Some(source), None);
            }
            if truncated {
                out.limitation("composition.elf-library-budget", Some(source), None);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Supplied {
        files: Vec<Artifact>,
        summary: BTreeMap<String, Value>,
    }

    impl Tree for Supplied {
        fn artifacts(&self) -> &[Artifact] {
            &self.files
        }
        fn read(&self, _: &str) -> std::io::Result<aa_core::plugin::Bytes> {
            panic!("relationship pass must not read files")
        }
        fn summary(&self) -> &BTreeMap<String, Value> {
            &self.summary
        }
    }

    fn file(path: &str, name: Option<&str>) -> Artifact {
        Artifact {
            path: path.into(),
            parent: None,
            size: 1,
            digests: Some(aa_core::Digests { md5: String::new(), sha1: String::new(), sha256: "abc".into() }),
            detected: None,
            kind: Some("elf".into()),
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::from([
                (
                    "binary.header".into(),
                    json!({"format":"elf","file_type":if name.is_some(){"shared-library"}else{"executable"},"machine":62,"bits":64,"endian":"little"}),
                ),
                ("binary.linking".into(), json!({"soname":name})),
                (
                    "binary.libraries".into(),
                    json!({"libraries":if name.is_none(){vec![json!({"name":"libhello.so.1"})]}else{Vec::new()},"truncated":false}),
                ),
            ]),
        }
    }

    #[test]
    fn captured_soname_match_keeps_loader_selection_unknown_and_never_opens_bytes() {
        let tree = Supplied {
            files: vec![file("bin/app", None), file("lib/libhello.so.1.2", Some("libhello.so.1"))],
            summary: BTreeMap::from([("engine.input-listing".into(), json!({"complete":true}))]),
        };
        let mut out = Output::default();
        ElfLibraries.analyze_tree(&tree, &mut out);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].evidence.len(), 2);
        let fact = &out.facts[0].value;
        assert_eq!(fact["references"][0]["target"], "lib/libhello.so.1.2");
        assert_eq!(fact["runtime_target_resolved"], false);
    }

    #[test]
    fn ambiguous_partial_incompatible_and_renamed_libraries_remain_unresolved() {
        for mode in ["ambiguous", "incomplete", "architecture", "renamed", "namespace"] {
            let mut target = file("lib/libhello.so.1.2", Some("libhello.so.1"));
            let mut summary = BTreeMap::from([("engine.input-listing".into(), json!({"complete":true}))]);
            if mode == "architecture" {
                target.facts.get_mut("binary.header").expect("header")["machine"] = json!(183);
            }
            if mode == "renamed" {
                target.facts.insert("engine.entry-name".into(), json!({"colliding":true}));
            }
            if mode == "namespace" {
                target.parent = Some("other.tar".into());
            }
            if mode == "incomplete" {
                summary.clear();
            }
            let mut files = vec![file("bin/app", None), target];
            if mode == "ambiguous" {
                files.push(file("other/libhello.so.1", Some("libhello.so.1")));
            }
            let mut out = Output::default();
            ElfLibraries.analyze_tree(&Supplied { files, summary }, &mut out);
            assert!(out.findings.is_empty(), "{mode}");
            assert_eq!(out.facts[0].value["references"][0]["status"], "unresolved", "{mode}");
            assert!(out.limitations.iter().any(|limit| limit.code == "composition.elf-library-unresolved"));
        }
    }

    fn analyze(files: Vec<Artifact>) -> Output {
        let tree = Supplied { files, summary: BTreeMap::from([("engine.input-listing".into(), json!({"complete": true}))]) };
        let mut output = Output::default();
        ElfLibraries.analyze_tree(&tree, &mut output);
        output
    }

    fn dependencies(source: &mut Artifact, names: impl IntoIterator<Item = String>) {
        source.facts.insert(
            "binary.libraries".into(),
            json!({
                "libraries": names.into_iter().map(|name| json!({"name": name})).collect::<Vec<_>>(),
                "truncated": false,
            }),
        );
    }

    #[test]
    fn clipped_replacement_and_control_text_cannot_establish_literal_identity() {
        for name in ["a".repeat(1024), "界".repeat(342), "lib\u{fffd}hello.so".into(), "lib\nhello.so".into(), "lib\0hello.so".into()] {
            let mut source = file("bin/app", None);
            dependencies(&mut source, [name.clone()]);
            let target = file("lib/provider.so", Some(&name));
            let output = analyze(vec![source, target]);
            assert!(output.findings.is_empty(), "unreliable name {name:?}");
            assert_eq!(output.facts[0].value["references"][0]["reason"], "dependency-name-outside-literal-basename-profile");
            assert!(output.limitations.iter().any(|limit| limit.code == "composition.elf-library-unresolved"));
        }
        // A name below the binary reader's byte cap can still be compared exactly.
        let name = "a".repeat(1023);
        let mut source = file("bin/app", None);
        dependencies(&mut source, [name.clone()]);
        let output = analyze(vec![source, file("lib/provider.so", Some(&name))]);
        assert_eq!(output.findings.len(), 1);
        assert_eq!(output.facts[0].value["references"][0]["matched_by"], "soname");
    }

    #[test]
    fn filename_and_soname_matches_retain_their_actual_basis_and_leave_abi_unknown() {
        for (path, soname, basis) in [
            ("lib/libhello.so.1", "different-soname.so", "filename"),
            ("lib/versioned-provider.so", "libhello.so.1", "soname"),
            ("lib/libhello.so.1", "libhello.so.1", "soname"),
        ] {
            let mut source = file("bin/app", None);
            let mut target = file(path, Some(soname));
            // Matching these three header properties is useful evidence without deciding ABI flags.
            source.facts.get_mut("binary.header").expect("source header")["flags"] = json!(0x200);
            target.facts.get_mut("binary.header").expect("target header")["flags"] = json!(0x400);
            let output = analyze(vec![source, target]);
            assert_eq!(output.findings.len(), 1, "{basis}");
            let row = &output.facts[0].value["references"][0];
            assert_eq!(row["matched_by"], basis);
            assert_eq!(row["observed_compatible_candidates"], 1, "filename and SONAME must not count the same provider twice");
            assert_eq!(row["abi_compatibility_established"], false);
            assert_eq!(row["runtime_target_resolved"], false);
            let evidence = &output.findings[0].evidence[1];
            assert_eq!(evidence.location, aa_core::Location::Whole);
            assert_eq!(evidence.value["path"], path);
            assert_eq!(evidence.value["soname"], soname);
            assert_eq!(evidence.value["header"]["flags"], 0x400);
        }
        // A corrupt SONAME must not replace an independently exact captured filename.
        let output = analyze(vec![file("bin/app", None), file("lib/libhello.so.1", Some("bad\u{fffd}soname"))]);
        assert_eq!(output.facts[0].value["references"][0]["matched_by"], "filename");
    }

    #[test]
    fn renamed_or_colliding_providers_never_create_a_unique_confirmed_target() {
        for change in [json!({"normalized": true}), json!({"colliding": true}), json!({"normalized": true, "colliding": true})] {
            let mut target = file("lib/provider.so", Some("libhello.so.1"));
            target.facts.insert("engine.entry-name".into(), change.clone());
            let output = analyze(vec![file("bin/app", None), target.clone()]);
            assert!(output.findings.is_empty(), "{change}");
            assert_eq!(output.facts[0].value["references"][0]["reason"], "target-entry-name-or-bytes-not-established");

            // The uncertain provider also prevents another provider from looking unique.
            let output = analyze(vec![file("bin/app", None), target, file("lib/other-provider.so", Some("libhello.so.1"))]);
            assert!(output.findings.is_empty(), "{change}");
            assert_eq!(output.facts[0].value["references"][0]["reason"], "multiple-compatible-supplied-libraries");
        }
        let mut target = file("lib/provider.so", Some("libhello.so.1"));
        target.digests = None;
        let output = analyze(vec![file("bin/app", None), target]);
        assert!(output.findings.is_empty());
        assert_eq!(output.facts[0].value["references"][0]["reason"], "target-entry-name-or-bytes-not-established");
    }

    #[test]
    fn dependency_caps_are_explicit_and_shared_across_sources() {
        let mut source = file("bin/app", None);
        dependencies(&mut source, (0..MAX_PER_SOURCE + 1).map(|index| format!("libmissing{index}.so")));
        let output = analyze(vec![source]);
        assert_eq!(output.facts[0].value["references"].as_array().expect("reference rows").len(), MAX_PER_SOURCE);
        assert_eq!(output.facts[0].value["truncated"], true);
        assert!(output.limitations.iter().any(|limit| limit.code == "composition.elf-library-budget"));

        let files = (0..MAX_REFERENCES / MAX_PER_SOURCE + 2)
            .map(|index| {
                let mut source = file(&format!("bin/app{index:03}"), None);
                dependencies(&mut source, std::iter::repeat_n("libmissing.so".to_string(), MAX_PER_SOURCE));
                source
            })
            .collect();
        let output = analyze(files);
        let total: usize = output.facts.iter().map(|fact| fact.value["references"].as_array().expect("reference rows").len()).sum();
        assert_eq!(total, MAX_REFERENCES, "per-source limits must not reset the global declaration budget");
        assert!(output.facts.last().expect("last source budget fact").value["references"].as_array().expect("reference rows").is_empty());
        assert_eq!(output.facts.last().expect("last source budget fact").value["truncated"], true);
    }

    #[test]
    fn candidate_comparison_budget_preserves_an_unresolved_row_without_a_target() {
        let providers = 1000;
        let allowed = MAX_CANDIDATE_CHECKS / providers;
        assert!(allowed < MAX_PER_SOURCE, "fixture must reach the candidate budget before the per-source cap");
        let mut source = file("bin/app", None);
        dependencies(&mut source, std::iter::repeat_n("libhello.so.1".to_string(), allowed + 1));
        let mut files = vec![source];
        files.extend((0..providers).map(|index| file(&format!("lib/provider{index:04}.so"), Some("libhello.so.1"))));
        let output = analyze(files);
        assert!(output.findings.is_empty());
        let rows = output.facts[0].value["references"].as_array().expect("reference rows");
        assert_eq!(rows.len(), allowed + 1);
        assert_eq!(rows[0]["observed_compatible_candidates"], providers);
        assert_eq!(rows[0]["candidates"].as_array().expect("candidate preview").len(), 20);
        assert_eq!(rows[0]["candidates_truncated"], true);
        let exhausted = rows.last().expect("budget row");
        assert_eq!(exhausted["reason"], "candidate-comparison-budget-exhausted");
        assert_eq!(exhausted["status"], "unresolved");
        assert!(exhausted["target"].is_null());
        assert_eq!(exhausted["candidates_truncated"], true);
        assert_eq!(output.facts[0].value["truncated"], true);
        assert!(output.limitations.iter().any(|limit| limit.code == "composition.elf-library-budget"));
    }

    #[test]
    fn overlong_archive_paths_are_refused_before_a_reference_can_duplicate_them() {
        let target = file(&format!("{}/provider.so", "a".repeat(8193)), Some("libhello.so.1"));
        let output = analyze(vec![file("bin/app", None), target]);
        assert!(output.findings.is_empty());
        assert!(output.facts.is_empty());
        assert_eq!(output.limitations.len(), 1);
        assert_eq!(output.limitations[0].code, "composition.elf-library-budget");
    }
}
