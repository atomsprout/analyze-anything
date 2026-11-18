//! HTML and PDF output, checked on reports built in code: hostile text, both languages, an empty
//! report, a large one, and the same bytes on every render.

use std::collections::BTreeMap;

use aa_core::{
    Artifact, Confidence, Coverage, Detected, Digests, Evidence, Finding, Input, InputKind, Limitation, Report, RuleText, SCHEMA_VERSION,
    Section, Severity, Tool, sha256_hex,
};
use aa_report::{Format, Lang, render};
use serde_json::{Value, json};

/// Strings a hostile input could put anywhere in a report.
const HOSTILE: &[&str] = &[
    "\"><script>alert(1)</script>",
    "</script><script>alert(2)</script>",
    "<img src=x onerror=alert(3)>",
    "javascript:alert(4)",
    "' onmouseover='alert(5)",
    "<!-- --><style>*{display:none}</style>",
    "evil\u{202e}fdp.exe",
    "zero\u{200b}width\u{2028}line\u{2029}para\u{feff}",
    "{{script}} {{report}} {name}",
    "#eval(\"1+1\") *bold* _emph_ $x^2$ `raw` <label> @cite \\ #import \"@preview/x:1.0.0\": *",
    "#read(\"/etc/passwd\") #include \"report.json\" ]]) }} //",
];

fn artifact(path: &str, size: u64) -> Artifact {
    Artifact {
        path: path.to_string(),
        parent: None,
        size,
        digests: Some(Digests { md5: "0".repeat(32), sha1: "1".repeat(40), sha256: sha256_hex(path.as_bytes()) }),
        detected: Some(Detected { mime: "application/octet-stream".into(), usual_extension: Some("bin".into()) }),
        kind: None,
        entropy: Some(4.25),
        unpacked_by: None,
        facts: BTreeMap::new(),
    }
}

fn rule(title_zh: &str, title_en: &str, text_zh: &str, text_en: &str) -> RuleText {
    RuleText { title_zh: title_zh.into(), title_en: title_en.into(), text_zh: text_zh.into(), text_en: text_en.into() }
}

fn report(name: &str, artifacts: Vec<Artifact>, findings: Vec<Finding>, limitations: Vec<Limitation>) -> Report {
    let mut rules = BTreeMap::new();
    rules.insert("test.rule".to_string(), rule("测试规则", "Test rule", "在 {path} 看到 {what}。", "Saw {what} in {path}."));
    rules.insert("read_failed".to_string(), rule("读取失败", "Could not be read", "这些文件无法读取。", "These files could not be read."));
    Report {
        schema_version: SCHEMA_VERSION,
        tool: Tool { name: "analyze-anything".into(), version: "0.0.1".into() },
        input: Input { name: name.to_string(), kind: InputKind::File, sha256: Some(sha256_hex(name.as_bytes())) },
        summary: BTreeMap::new(),
        coverage: Coverage {
            artifacts_total: artifacts.len() as u64,
            artifacts_analyzed: artifacts.len() as u64,
            bytes_analyzed: artifacts.iter().map(|a| a.size).sum(),
            containers_unpacked: 0,
            truncated: false,
        },
        artifacts,
        findings,
        limitations,
        rules,
    }
}

/// A report with a finding in every chapter and at every severity and confidence, references,
/// each kind of evidence location, long values and facts.
fn full() -> Report {
    let mut container = artifact("app.zip", 9_000_000);
    container.kind = Some("zip".into());
    container.unpacked_by = Some("zip".into());
    container
        .facts
        .insert("zip.entries".into(), json!({ "count": 3, "names": ["a", "b", "c"], "big": 18446744073709551615u64, "ratio": 2.0 }));
    let mut inner = artifact(&format!("app.zip/lib/{}.so", "long-name-".repeat(30)), 123_456);
    inner.parent = Some("app.zip".into());
    inner.kind = Some("elf".into());
    let mut unread = artifact("app.zip/secret.bin", 0);
    unread.parent = Some("app.zip".into());
    unread.digests = None;
    unread.detected = None;
    unread.entropy = None;
    let artifacts = vec![container, inner, unread];

    let severities = [Severity::Info, Severity::Low, Severity::Medium, Severity::High];
    let confidences = [Confidence::Verified, Confidence::Derived, Confidence::Heuristic];
    let mut findings = Vec::new();
    for (index, section) in Section::ALL.into_iter().enumerate() {
        let subject = &artifacts[index % 2];
        let finding = Finding::new(section, "test", "test.rule", confidences[index % 3], severities[index % 4])
            .param("path", subject.path.as_str())
            .param("what", format!("thing {index}"))
            .reference("CWE-798")
            .reference("MASVS-STORAGE-1")
            .evidence(Evidence::whole(subject, "whole value"))
            .evidence(Evidence::field(subject, "CFBundleIdentifier", "com.example.app"))
            .evidence(Evidence::bytes(subject, 4096, 64, "f".repeat(3000)))
            .evidence(Evidence::whole(subject, json!({ "n": 1.0, "list": [1, 2, 3] })));
        findings.push(finding.seal());
    }
    let limitations = vec![
        Limitation::new("read_failed", Some("app.zip/secret.bin"), Some("Permission denied (os error 13)".into())),
        Limitation::new("limit_depth", None, None),
    ];
    let mut report = report("app.zip", artifacts, findings, limitations);
    report.summary.insert("structure.totals".into(), json!({ "files": 3, "bytes": 9_123_456 }));
    report.coverage.artifacts_analyzed = 2;
    report.coverage.containers_unpacked = 1;
    report.coverage.truncated = true;
    report
}

/// A report in which every string an input can influence is hostile.
fn hostile() -> Report {
    let mut artifacts = Vec::new();
    let mut findings = Vec::new();
    let mut limitations = Vec::new();
    let mut rules = BTreeMap::new();
    for (index, text) in HOSTILE.iter().enumerate() {
        let mut item = artifact(&format!("dir/{text}/{text}"), 7);
        item.kind = Some((*text).to_string());
        item.detected = Some(Detected { mime: (*text).to_string(), usual_extension: Some((*text).to_string()) });
        item.unpacked_by = Some((*text).to_string());
        item.parent = Some((*text).to_string());
        item.facts.insert((*text).to_string(), json!({ *text: [*text, { *text: *text }] }));
        let rule_id = format!("hostile.{index}.{text}");
        rules.insert(rule_id.clone(), rule(text, text, &format!("{text} {{value}}"), &format!("{text} {{value}}")));
        let finding = Finding::new(Section::ALL[index % 12], text, &rule_id, Confidence::Heuristic, Severity::High)
            .param("value", *text)
            .param(text, json!([*text]))
            .reference(text)
            .reference("CWE-79")
            .evidence(Evidence::field(&item, *text, *text))
            .evidence(Evidence::whole(&item, json!({ *text: *text })));
        findings.push(finding.seal());
        limitations.push(Limitation::new(text, Some(&item.path), Some((*text).to_string())));
        rules.insert((*text).to_string(), rule(text, text, text, text));
        artifacts.push(item);
    }
    let name = HOSTILE.join(" ");
    let mut report = report(&name, artifacts, findings, limitations);
    report.tool = Tool { name: HOSTILE[0].into(), version: HOSTILE[1].into() };
    report.rules = rules;
    for text in HOSTILE {
        report.summary.insert((*text).to_string(), json!({ *text: *text }));
    }
    report
}

fn large(artifacts: usize, findings: usize) -> Report {
    let files: Vec<Artifact> =
        (0..artifacts).map(|i| artifact(&format!("root/dir{:02}/sub{}/file{i:05}.bin", i % 40, i % 7), i as u64 * 31)).collect();
    let found: Vec<Finding> = (0..findings)
        .map(|i| {
            let subject = &files[(i * 37) % files.len()];
            Finding::new(
                Section::ALL[i % 12],
                "test",
                "test.rule",
                Confidence::Derived,
                [Severity::Info, Severity::Low, Severity::High][i % 3],
            )
            .param("path", subject.path.as_str())
            .param("what", i as u64)
            .evidence(Evidence::bytes(subject, i as u64, 8, format!("value {i}")))
            .seal()
        })
        .collect();
    let limitations = (0..50).map(|i| Limitation::new("read_failed", Some(&files[i].path), None)).collect();
    report("root", files, found, limitations)
}

fn html(report: &Report, lang: Lang) -> String {
    String::from_utf8(render(report, Format::Html, lang).expect("html renders")).expect("html is UTF-8")
}

/// The text between `open` and the next `close`.
fn between<'a>(text: &'a str, open: &str, close: &str) -> &'a str {
    let start = text.find(open).expect("opening marker") + open.len();
    &text[start..start + text[start..].find(close).expect("closing marker")]
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |n, (i, byte)| n | (u32::from(*byte) << (16 - 8 * i)));
        (0..4).for_each(|i| out.push(if i <= chunk.len() { ALPHABET[(n >> (18 - 6 * i)) as usize & 63] as char } else { '=' }));
    }
    out
}

fn csp_source(content: &str) -> String {
    let hex = sha256_hex(content.as_bytes());
    let digest: Vec<u8> = (0..32).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("hex")).collect();
    format!("'sha256-{}'", base64(&digest))
}

/// The page with the shipped script and style sheet cut out: what is left is the template, the
/// static copy of the report and the two data blocks — everything a report can influence.
fn without_shipped_code(page: &str) -> String {
    let style = between(page, "<style>", "</style>");
    let script = &page[page.rfind("<script>").expect("script") + "<script>".len()..page.rfind("</script>").expect("script end")];
    page.replacen(style, "", 1).replacen(script, "", 1)
}

#[test]
fn html_is_one_file_that_loads_nothing() {
    let page = html(&full(), Lang::Zh);
    assert!(page.starts_with("<!DOCTYPE html>"));
    assert_eq!(page.matches("<script").count(), 3, "two data blocks and one script");
    assert_eq!(page.matches("<style").count(), 1);
    let rest = without_shipped_code(&page);
    for loader in
        ["<link", "<img", "<iframe", "<object", "<embed", "<base", "<form", "src=", "href=", "url(", "@import", "<svg", "<video", "<audio"]
    {
        assert!(!rest.contains(loader), "the page contains {loader}");
    }
    let style = between(&page, "<style>", "</style>");
    assert!(!style.contains("url(") && !style.contains("@import") && !style.contains("@font-face"));
    assert!(page.contains("default-src 'none'"));
}

#[test]
fn html_policy_names_exactly_the_shipped_style_and_script() {
    let page = html(&full(), Lang::En);
    let policy = between(&page, "http-equiv=\"Content-Security-Policy\" content=\"", "\">");
    let style = between(&page, "<style>", "</style>");
    let script = &page[page.rfind("<script>").expect("script") + "<script>".len()..page.rfind("</script>").expect("script end")];
    assert!(policy.contains(&format!("style-src {};", csp_source(style))), "{policy}");
    assert!(policy.contains(&format!("script-src {};", csp_source(script))), "{policy}");
    assert!(!policy.contains("unsafe-inline") && !policy.contains("unsafe-eval") && !policy.contains("http"));
}

#[test]
fn html_embeds_the_whole_report() {
    for report in [full(), hostile(), large(50, 20)] {
        let page = html(&report, Lang::Zh);
        let data = between(&page, "<script type=\"application/json\" id=\"report-data\">", "</script>");
        let back: Report = serde_json::from_str(data).expect("the embedded data is the report");
        assert_eq!(back, report);
        let view: Value = serde_json::from_str(between(&page, "id=\"view-data\">", "</script>")).expect("view data is JSON");
        assert_eq!(view["texts"].as_array().map(Vec::len), Some(report.findings.len()));
        assert_eq!(view["lang"], "zh");
    }
}

#[test]
fn html_hostile_text_is_inert() {
    let report = hostile();
    for lang in [Lang::Zh, Lang::En] {
        let page = html(&report, lang);
        let rest = without_shipped_code(&page);
        // The data blocks cannot end early or be read as markup: they hold no `<`, `>` or `&`.
        assert_eq!(rest.matches("<script").count(), 3);
        assert_eq!(rest.matches("</script").count(), 3);
        for id in ["report-data", "view-data"] {
            let data = between(&page, &format!("id=\"{id}\">"), "</script>");
            assert!(!data.contains(['<', '>', '&']), "{id} holds markup characters");
        }
        // In the static copy, take away the tags the renderer writes itself: what remains is text
        // from the report, and it holds nothing that could start a tag or leave an attribute.
        let mut text = between(&page, "<div id=\"static\">", "<div id=\"app\"").to_string();
        for tag in [
            "<noscript>",
            "</noscript>",
            "<p class=\"note\">",
            "<p class=\"note\" id=\"script-failed\" hidden>",
            "<div class=\"tablewrap\">",
            "</div>",
        ] {
            text = text.replace(tag, "");
        }
        for name in ["h1", "h2", "h3", "h4", "h5", "h6", "p", "ul", "li", "table", "thead", "tbody", "tr", "th", "td"] {
            text = text.replace(&format!("<{name}>"), "").replace(&format!("</{name}>"), "");
        }
        assert!(!text.contains(['<', '>', '"', '\'']), "report text reached the page as markup");
        // Text that hides or reorders what is read is nowhere in the file, not even in the data.
        for hidden in ['\u{202e}', '\u{200b}', '\u{2028}', '\u{2029}', '\u{feff}'] {
            assert!(!page.contains(hidden), "U+{:04X} is in the page", hidden as u32);
        }
        // The static copy shows the text, escaped and with the hidden characters spelled out.
        let fallback = between(&page, "<div id=\"static\">", "<div id=\"app\"");
        assert!(fallback.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(fallback.contains("evil[U+202E]fdp.exe"));
        assert!(fallback.contains("javascript:alert(4)"));
        // A value that looks like a template slot is not filled in a second time.
        assert!(fallback.contains("{{script}} {{report}}"));
        // The data still holds the exact original strings.
        let back: Report = serde_json::from_str(between(&page, "id=\"report-data\">", "</script>")).expect("report");
        assert_eq!(back, report);
    }
}

#[test]
fn html_static_copy_holds_the_whole_reading_content() {
    let report = full();
    let page = html(&report, Lang::En);
    let fallback = between(&page, "<div id=\"static\">", "<div id=\"app\"");
    for chapter in [
        "Overview",
        "Identity",
        "Provenance and signing",
        "Structure",
        "Hardening",
        "Secrets",
        "Anomalies",
        "File inventory",
        "Coverage and limitations",
    ] {
        assert!(fallback.contains(&format!(">{chapter}</h2>")), "no chapter {chapter}");
    }
    assert_eq!(fallback.matches("Test rule: Saw thing").count(), report.findings.len());
    assert!(fallback.contains("Could not be read (1)"));
    assert!(fallback.contains("Permission denied (os error 13)"));
    assert!(fallback.contains("<noscript>"));
    assert!(page.contains("<html lang=\"en\">"));
}

#[test]
fn html_speaks_both_languages_and_opens_in_the_one_asked_for() {
    let report = full();
    let zh = html(&report, Lang::Zh);
    let en = html(&report, Lang::En);
    assert_ne!(zh, en);
    assert!(zh.contains("<html lang=\"zh-CN\">") && zh.contains("<title>分析报告: app.zip</title>"));
    assert!(en.contains("<title>Analysis report: app.zip</title>"));
    for page in [&zh, &en] {
        let view: Value = serde_json::from_str(between(page, "id=\"view-data\">", "</script>")).expect("view");
        assert_eq!(view["words"]["zh"]["coverage"], "覆盖度与局限");
        assert_eq!(view["words"]["en"]["coverage"], "Coverage and limitations");
        assert_eq!(view["words"]["zh"]["sections"]["network"], "网络与端点");
        assert_eq!(view["texts"][0][0], "在 app.zip 看到 thing 0。");
        assert_eq!(view["texts"][0][1], "Saw thing 0 in app.zip.");
        // Values a script would print differently travel as text.
        assert_eq!(view["values"]["0"][3], "{\"list\":[1,2,3],\"n\":1.0}");
        assert_eq!(view["exact"]["a0/zip.entries/big"], "18446744073709551615");
        assert_eq!(view["exact"]["a0/zip.entries/ratio"], "2.0");
    }
}

#[test]
fn html_is_the_same_on_every_render() {
    for report in [full(), hostile()] {
        assert_eq!(render(&report, Format::Html, Lang::Zh).expect("html"), render(&report, Format::Html, Lang::Zh).expect("html"));
    }
}

#[test]
fn html_renders_an_empty_report() {
    let mut report = report("empty", Vec::new(), Vec::new(), Vec::new());
    report.input = Input { name: "empty".into(), kind: InputKind::Directory, sha256: None };
    report.rules.clear();
    let page = html(&report, Lang::En);
    let fallback = between(&page, "<div id=\"static\">", "<div id=\"app\"");
    assert_eq!(fallback.matches("No findings in this chapter.").count(), 12);
    assert!(fallback.contains("No limitations were recorded."));
    let back: Report = serde_json::from_str(between(&page, "id=\"report-data\">", "</script>")).expect("report");
    assert_eq!(back, report);
}

#[test]
fn html_handles_a_large_report() {
    let report = large(4000, 1500);
    let started = std::time::Instant::now();
    let page = html(&report, Lang::Zh);
    assert!(started.elapsed().as_secs() < 20, "took {:?}", started.elapsed());
    let back: Report = serde_json::from_str(between(&page, "id=\"report-data\">", "</script>")).expect("report");
    assert_eq!(back.artifacts.len(), 4000);
    // The static copy lists every finding but only the first files, and says so.
    let fallback = between(&page, "<div id=\"static\">", "<div id=\"app\"");
    assert_eq!(fallback.matches("<tr>").count(), aa_report::doc::INVENTORY_ROWS + 1);
    assert!(fallback.contains("report.json"));
    assert_eq!(fallback.matches("测试规则: ").count(), 1500);
}

#[cfg(feature = "pdf")]
mod pdf {
    use super::*;

    fn pdf(report: &Report, lang: Lang) -> Vec<u8> {
        let bytes = render(report, Format::Pdf, lang).expect("pdf renders");
        assert!(bytes.starts_with(b"%PDF-"), "not a PDF");
        assert!(bytes.ends_with(b"%%EOF") || bytes.ends_with(b"%%EOF\n"));
        bytes
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|window| window == needle)
    }

    #[test]
    fn pdf_is_the_same_on_every_render() {
        let report = full();
        let first = pdf(&report, Lang::Zh);
        assert_eq!(first, pdf(&report, Lang::Zh));
        assert_eq!(pdf(&report, Lang::En), pdf(&report, Lang::En));
        // No clock reaches the file.
        assert!(!contains(&first, b"/CreationDate") && !contains(&first, b"/ModDate"));
    }

    #[test]
    fn pdf_speaks_both_languages_with_embedded_fonts() {
        let report = full();
        let zh = pdf(&report, Lang::Zh);
        let en = pdf(&report, Lang::En);
        assert_ne!(zh, en);
        for bytes in [&zh, &en] {
            assert!(contains(bytes, b"NotoSansSC"), "the text font is not embedded");
            assert!(contains(bytes, b"JetBrainsMono"), "the monospace font is not embedded");
            assert!(contains(bytes, b"/FontFile"), "fonts are referenced, not embedded");
        }
    }

    #[test]
    fn pdf_renders_hostile_text_as_text() {
        // The template would fail to compile, or the bytes would change between runs, if any of
        // this were read as Typst markup or code; the unit tests in the PDF module check the
        // typeset text itself.
        let report = hostile();
        assert_eq!(pdf(&report, Lang::Zh), pdf(&report, Lang::Zh));
        pdf(&report, Lang::En);
    }

    #[test]
    fn pdf_renders_an_empty_report() {
        let mut report = report("empty", Vec::new(), Vec::new(), Vec::new());
        report.input = Input { name: "empty".into(), kind: InputKind::Directory, sha256: None };
        report.rules.clear();
        pdf(&report, Lang::Zh);
        pdf(&report, Lang::En);
    }

    #[test]
    fn pdf_handles_a_large_report() {
        let report = large(2000, 96);
        let started = std::time::Instant::now();
        let bytes = pdf(&report, Lang::Zh);
        assert!(started.elapsed().as_secs() < 120, "took {:?}", started.elapsed());
        // The inventory is cut to its first rows, so the file stays a reading document.
        assert!(bytes.len() < 4_000_000, "{} bytes", bytes.len());
    }
}

#[cfg(not(feature = "pdf"))]
#[test]
fn pdf_says_so_when_it_was_left_out_of_the_build() {
    assert!(matches!(render(&full(), Format::Pdf, Lang::Zh), Err(aa_report::RenderError::PdfNotBuilt)));
}
