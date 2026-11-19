//! Rules the person running the analysis supplies, in YARA syntax, matched against every file.
//!
//! A match is a fact about the bytes; what it means is up to whoever wrote the rule. The rule's
//! own `severity` metadata (`info`, `low`, `medium`, `high`) sets the finding's severity.

use aa_core::plugin::{Analyzer, Output, Rule, Tree};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use boreal::{Compiler, MetadataValue, Scanner};

/// Files larger than this are not scanned; the report records each one skipped.
const MAX_SCANNED: u64 = 256 * 1024 * 1024;
/// Matched strings cited as evidence per rule per file.
const EVIDENCE: usize = 8;

const RULES: &[Rule] = &[
    Rule {
        id: "yara.match",
        title_zh: "自定义规则命中",
        title_en: "Custom rule matched",
        text_zh: "你提供的 YARA 规则 {rule}（命名空间 {namespace}）在这个文件上命中，匹配到 {strings} 处字符串。命中说明文件内容符合规则写的条件，它意味着什么取决于这条规则。",
        text_en: "Your YARA rule {rule} (namespace {namespace}) matched this file, with {strings} string matches. A match means the content meets the rule's condition; what that signifies depends on the rule.",
    },
    Rule {
        id: "yara.too-large",
        title_zh: "文件过大，未用自定义规则扫描",
        title_en: "Too large for the custom rules",
        text_zh: "文件超过自定义规则的扫描上限，没有用这些规则扫描。",
        text_en: "The file exceeds the size the custom rules are run on and was not scanned with them.",
    },
    Rule {
        id: "yara.scan-failed",
        title_zh: "自定义规则扫描未完成",
        title_en: "Custom rule scan did not finish",
        text_zh: "用自定义规则扫描这个文件时出错或超时，结果可能不全。",
        text_en: "Scanning this file with the custom rules failed or timed out; results may be incomplete.",
    },
];

pub struct Yara {
    scanner: Scanner,
}

/// Compiles `source` into an analyzer. The error text is the compiler's, naming the line at fault.
pub fn analyzer(source: &str) -> Result<Box<dyn Analyzer>, String> {
    let mut compiler = Compiler::new();
    compiler.add_rules_str(source).map_err(|error| error.to_string())?;
    Ok(Box::new(Yara { scanner: compiler.finalize() }))
}

impl Analyzer for Yara {
    fn id(&self) -> &'static str {
        "yara"
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn analyze_file(&self, tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        if file.size > MAX_SCANNED {
            out.limitation("yara.too-large", Some(file), Some(format!("{} bytes", file.size)));
            return;
        }
        let Ok(bytes) = tree.read(&file.path) else { return };
        let result = match self.scanner.scan_mem(&bytes) {
            Ok(result) => result,
            Err((error, partial)) => {
                out.limitation("yara.scan-failed", Some(file), Some(error.to_string()));
                partial
            }
        };
        for matched in &result.rules {
            let severity =
                matched.metadatas.iter().find(|meta| self.scanner.get_string_symbol(meta.name).eq_ignore_ascii_case("severity")).and_then(
                    |meta| match meta.value {
                        MetadataValue::Bytes(symbol) => {
                            Some(String::from_utf8_lossy(self.scanner.get_bytes_symbol(symbol)).to_ascii_lowercase())
                        }
                        _ => None,
                    },
                );
            let severity = match severity.as_deref() {
                Some("high") => Severity::High,
                Some("medium") => Severity::Medium,
                Some("info") => Severity::Info,
                _ => Severity::Low,
            };
            let strings: usize = matched.matches.iter().map(|m| m.matches.len()).sum();
            let mut finding = Finding::new(Section::Anomalies, "yara", "yara.match", Confidence::Verified, severity)
                .param("rule", matched.name)
                .param("namespace", matched.namespace)
                .param("strings", strings);
            let hits = matched.matches.iter().flat_map(|string| string.matches.iter().map(move |hit| (string.name, hit)));
            for (name, hit) in hits.take(EVIDENCE) {
                finding = finding.evidence(Evidence::bytes(file, hit.offset as u64, hit.length as u64, format!("${name}")));
            }
            if finding.evidence.is_empty() {
                finding = finding.evidence(Evidence::whole(file, matched.name));
            }
            out.finding(finding);
        }
    }
}

#[cfg(test)]
mod tests {
    use aa_core::plugin::Bytes;

    use super::*;

    struct One(Artifact, Vec<u8>);

    impl Tree for One {
        fn artifacts(&self) -> &[Artifact] {
            std::slice::from_ref(&self.0)
        }

        fn read(&self, _path: &str) -> std::io::Result<Bytes> {
            Ok(Bytes::from_vec(self.1.clone()))
        }
    }

    fn scan(rules: &str, content: &[u8]) -> Output {
        let file = Artifact {
            path: "sample.bin".into(),
            parent: None,
            size: content.len() as u64,
            digests: None,
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: Default::default(),
        };
        let tree = One(file, content.to_vec());
        let mut out = Output::default();
        analyzer(rules).expect("the rules compile").analyze_file(&tree, &tree.0, &mut out);
        out
    }

    const RULE: &str = r#"rule marker { meta: severity = "high" strings: $a = "MARKER" condition: $a }"#;

    #[test]
    fn a_match_is_reported_with_its_offsets_and_the_rule_severity() {
        let out = scan(RULE, b"..MARKER....MARKER");
        assert_eq!(out.findings.len(), 1);
        let finding = &out.findings[0];
        assert_eq!(finding.params["rule"], "marker");
        assert_eq!(finding.params["strings"], 2);
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.evidence[0].location, aa_core::Location::Bytes { offset: 2, length: 6 });
        assert_eq!(finding.evidence[1].location, aa_core::Location::Bytes { offset: 12, length: 6 });
    }

    #[test]
    fn no_match_reports_nothing() {
        assert!(scan(RULE, b"nothing here").findings.is_empty());
    }

    #[test]
    fn a_rule_without_severity_is_low() {
        let out = scan(r#"rule plain { strings: $a = "x" condition: $a }"#, b"x");
        assert_eq!(out.findings[0].severity, Severity::Low);
    }

    #[test]
    fn rules_that_do_not_compile_give_the_compiler_message() {
        let error = analyzer("rule broken { condition: }").err().expect("an error");
        assert!(!error.is_empty());
    }
}
