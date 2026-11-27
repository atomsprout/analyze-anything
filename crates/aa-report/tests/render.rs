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
            content_lost: 0,
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
        assert!(fallback.contains(&format!(">{chapter}</h2>")) || fallback.contains(&format!(">{chapter} · ")), "no chapter {chapter}");
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
    // Each chapter holds one rule: one entry per chapter, plus the one under "needs attention".
    assert_eq!(fallback.matches("] 测试规则 — ").count(), 13);
    assert!(fallback.contains("共 125 条") && fallback.contains("本类另有 95 条未在此列出"));
}

fn text_of(report: &Report, format: Format, lang: Lang) -> String {
    String::from_utf8(render(report, format, lang).expect("renders")).expect("UTF-8")
}

/// A report with a rule that hits many files, one that hits a few with differing sentences, and
/// rules that hit once.
fn repetitive() -> Report {
    let files: Vec<Artifact> = (0..40).map(|i| artifact(&format!("app/lib{}/mod{i:02}.dll", i % 2), 100)).collect();
    let mut findings = Vec::new();
    for file in &files {
        findings.push(
            Finding::new(Section::Hardening, "t", "h.aslr", Confidence::Verified, Severity::Info).evidence(Evidence::whole(file, 1)).seal(),
        );
    }
    for (i, file) in files.iter().enumerate().take(35) {
        findings.push(
            Finding::new(Section::Hardening, "t", "h.nocfg", Confidence::Verified, Severity::Low)
                .param("arch", if i < 33 { "x64" } else { "x86" })
                .evidence(Evidence::whole(file, 0))
                .seal(),
        );
    }
    findings.push(
        Finding::new(Section::Hardening, "t", "h.weak", Confidence::Heuristic, Severity::High)
            .evidence(Evidence::whole(&files[3], 0))
            .seal(),
    );
    findings.push(
        Finding::new(Section::Hardening, "t", "h.note", Confidence::Derived, Severity::Info).evidence(Evidence::whole(&files[4], 0)).seal(),
    );
    // As the engine orders a chapter: most severe first, otherwise as found.
    findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));
    let mut report = report("app", files, findings, Vec::new());
    report.rules.insert("h.aslr".into(), rule("已启用 ASLR", "ASLR is on", "加载地址可以随机化。", "The load address can be randomized."));
    report.rules.insert("h.nocfg".into(), rule("未启用 CFG", "CFG is off", "{arch} 映像没有启用 CFG。", "The {arch} image has no CFG."));
    report.rules.insert("h.weak".into(), rule("弱签名", "Weak signature", "签名算法过时。", "The signature algorithm is outdated."));
    report.rules.insert("h.note".into(), rule("备注", "A note", "只出现一次。", "Seen once."));
    report
}

#[test]
fn findings_of_one_rule_are_one_entry_in_markdown_and_text() {
    let report = repetitive();
    let markdown = text_of(&report, Format::Markdown, Lang::En);
    let text = text_of(&report, Format::Text, Lang::En);

    // The chapter heading counts both; groups come in the order the report first mentions them.
    assert!(markdown.contains("## Hardening · 4 kinds / 77 findings"));
    let chapter = &markdown[markdown.find("## Hardening").expect("chapter")..markdown.find("## Network").expect("next chapter")];
    let order: Vec<usize> =
        ["Weak signature", "CFG is off", "ASLR is on", "A note"].iter().map(|title| chapter.find(title).expect("title")).collect();
    assert!(order.is_sorted(), "{order:?}");

    // A rule that hit once reads as before: the sentence, its evidence, its id.
    assert!(chapter.contains("- \\[High · Heuristic\\] Weak signature: The signature algorithm is outdated.\n  - Evidence: app/lib1/mod03.dll = 0\n  - Finding ID: "));

    // One sentence shared by 40 files is written once; neutral facts list ten and count the rest.
    assert_eq!(chapter.matches("The load address can be randomized.").count(), 1);
    assert!(chapter.contains("- \\[Info × 40 · Verified\\] ASLR is on — 40 findings\n  - The load address can be randomized. — The same holds 40 times, for: …/mod00.dll, …/mod01.dll,"));
    assert!(chapter.contains("…/mod09.dll …\n  - 30 more of this kind are not listed here; report.html and report.json hold them all.\n"));
    let aslr = &chapter[chapter.find("ASLR is on").expect("group")..chapter.find("A note").expect("next group")];
    assert!(!aslr.contains("mod10.dll"));

    // Anything above Info lists thirty, sentence by sentence in report order.
    let cfg = &chapter[chapter.find("CFG is off").expect("group")..chapter.find("ASLR is on").expect("next group")];
    assert!(cfg.starts_with("CFG is off — 35 findings\n  - The x64 image has no CFG. — The same holds 33 times, for: "));
    assert!(cfg.contains("…/mod29.dll …\n  - 5 more of this kind are not listed here"));
    assert!(!cfg.contains("x86"));

    // "Needs attention" follows the overview and holds only what is above Info.
    let attention = &markdown
        [markdown.find("## Needs attention · 2 kinds / 36 findings").expect("attention")..markdown.find("## Identity").expect("chapters")];
    assert!(attention.contains("Weak signature") && attention.contains("CFG is off") && !attention.contains("ASLR is on"));
    assert!(markdown.find("## Overview").expect("overview") < markdown.find("## Needs attention").expect("attention"));

    // Text says the same, line for line.
    let strip = |line: &str| line.trim_start_matches([' ', '-', '*', '#']).replace('\\', "");
    let from_markdown: Vec<String> = markdown.lines().filter(|l| !l.is_empty() && !l.starts_with('|')).map(strip).collect();
    let from_text: Vec<String> =
        text.lines().filter(|l| !l.is_empty() && !l.contains('\t') && !l.chars().all(|c| c == '=' || c == '-')).map(strip).collect();
    assert_eq!(from_markdown, from_text);
}

#[test]
fn nothing_above_info_is_said_plainly() {
    let mut report = repetitive();
    report.findings.retain(|f| f.severity == Severity::Info);
    let markdown = text_of(&report, Format::Markdown, Lang::Zh);
    assert!(markdown.contains("## 需要关注\n\n没有严重度高于“提示”的结论。这只代表已启用的检查没有命中，不代表没有问题。\n"));
    let page = html(&report, Lang::En);
    assert!(between(&page, "<div id=\"static\">", "<div id=\"app\"").contains("No finding is above &quot;Info&quot;."));
}

#[test]
fn html_carries_what_the_script_needs_to_group_alike() {
    let report = repetitive();
    let page = html(&report, Lang::En);
    let view: Value = serde_json::from_str(between(&page, "id=\"view-data\">", "</script>")).expect("view");
    // Every finding is still in the page, with its shortened subject.
    assert_eq!(view["subjects"].as_array().map(Vec::len), Some(report.findings.len()));
    assert!(view["subjects"].as_array().is_some_and(|subjects| subjects.contains(&json!("…/mod00.dll"))));
    assert!(view.get("ranks").is_none(), "groups follow report order; the script needs no order of its own");
    // The static copy is grouped too.
    let fallback = between(&page, "<div id=\"static\">", "<div id=\"app\"");
    assert_eq!(fallback.matches("The load address can be randomized.").count(), 1);
    assert!(fallback.contains("Hardening · 4 kinds / 77 findings</h2>"));
}

#[test]
fn a_container_names_its_unpacker_next_to_its_kind() {
    let mut report = full();
    report.artifacts[0].kind = Some("pe".into());
    report.artifacts[0].unpacked_by = Some("nsis".into());
    assert!(text_of(&report, Format::Markdown, Lang::En).contains("| pe (application/octet-stream) · unpacked by nsis |"));
    assert!(text_of(&report, Format::Text, Lang::Zh).contains("pe (application/octet-stream) · 由 nsis 解包"));
}

#[test]
fn fifty_thousand_files_and_five_thousand_findings_stay_fast() {
    let report = large(50_000, 5_000);
    let started = std::time::Instant::now();
    let markdown = text_of(&report, Format::Markdown, Lang::Zh);
    let text = text_of(&report, Format::Text, Lang::Zh);
    let page = html(&report, Lang::Zh);
    assert!(started.elapsed().as_secs() < 60, "took {:?}", started.elapsed());
    // Grouped, the reading formats stay short however many findings there are.
    assert!(markdown.lines().count() < 1500, "{} lines", markdown.lines().count());
    assert!(text.lines().count() < 1500);
    assert!(page.len() > 10_000_000);
    #[cfg(feature = "pdf")]
    {
        let started = std::time::Instant::now();
        let bytes = render(&report, Format::Pdf, Lang::Zh).expect("pdf");
        assert!(started.elapsed().as_secs() < 120, "took {:?}", started.elapsed());
        assert!(bytes.len() < 4_000_000);
    }
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

#[test]
fn reports_for_people_end_by_naming_the_tool_and_where_it_lives() {
    let report = full();
    let closing = format!("Generated by {} {} · {}", report.tool.name, report.tool.version, aa_report::PROJECT_URL);
    for format in [Format::Markdown, Format::Text] {
        let text = String::from_utf8(render(&report, format, Lang::En).expect("renders")).expect("text");
        assert!(text.trim_end().ends_with(&closing), "{format:?} ends with: {}", &text[text.len().saturating_sub(120)..]);
    }
    let page = html(&report, Lang::En);
    assert!(page.contains(aa_report::PROJECT_URL));
    assert!(html(&report, Lang::Zh).contains("本报告由以下工具生成"));
    // Data for programs carries the tool in its own fields and no such line.
    let json = String::from_utf8(render(&report, Format::Json, Lang::En).expect("renders")).expect("text");
    assert!(!json.contains(aa_report::PROJECT_URL));
}

#[test]
fn opening_questions_reuse_findings_and_bound_the_preview() {
    let input = full();
    for lang in [Lang::En, Lang::Zh] {
        let questions = aa_report::doc::questions(&input, lang);
        assert_eq!(questions.len(), 4);
        for question in questions {
            assert!(question.samples.len() <= 3);
            assert!(question.total >= question.samples.len());
            for sample in question.samples {
                let finding = &input.findings[sample.index];
                assert_eq!(sample.id, finding.id);
                assert_eq!(sample.confidence, finding.confidence);
                assert!(aa_report::doc::finding_text(&input, lang, finding).starts_with(sample.text.trim_end_matches('…')));
            }
        }
    }
    let empty = report("empty", Vec::new(), Vec::new(), Vec::new());
    assert!(aa_report::doc::questions(&empty, Lang::En).iter().all(|q| q.total == 0 && q.samples.is_empty()));
}

#[test]
fn identity_preview_keeps_aggregate_counts_from_displacing_input_identity() {
    let mut input = full();
    let prototype = input.findings[0].clone();
    input.findings.clear();
    for (id, rule, section) in [
        ("attention", "overview.attention", Section::Overview),
        ("signers", "overview.win-inner-signers", Section::Overview),
        ("kind", "overview.kind-folder", Section::Overview),
        ("identity", "binary.pe-identity", Section::Identity),
        ("identity2", "binary.pe-identity", Section::Identity),
    ] {
        let mut finding = prototype.clone();
        finding.id = id.into();
        finding.rule = rule.into();
        finding.section = section;
        input.findings.push(finding);
    }
    for lang in [Lang::En, Lang::Zh] {
        let questions = aa_report::doc::questions(&input, lang);
        assert_eq!(questions[0].total, 5);
        assert_eq!(questions[0].samples.iter().map(|sample| sample.id.as_str()).collect::<Vec<_>>(), ["kind", "identity", "identity2"]);
        // Counts and signing facts are still available in the full report.
        assert!(input.findings.iter().any(|finding| finding.id == "attention"));
    }
    input.input.kind = InputKind::Directory;
    input.findings[3].evidence = vec![
        Evidence::field(&artifact("tools/helper.dll", 12), "format", "PE32+"),
        Evidence::field(&artifact("tools/helper.dll", 12), "arch", "x86_64"),
    ];
    assert!(aa_report::doc::questions(&input, Lang::En)[0].samples[1].text.starts_with("tools/helper.dll: "));
}

#[test]
fn content_loss_is_visible_even_without_a_truncation_flag() {
    let mut report = full();
    report.coverage.truncated = false;
    report.coverage.content_lost = 1;
    assert!(aa_report::doc::content_incomplete(&report));
    for format in [Format::Markdown, Format::Text] {
        let output = String::from_utf8(render(&report, format, Lang::En).expect("renders")).expect("text");
        assert!(output.contains("The analysis stopped early or skipped content"));
        assert!(output.contains("Recorded content losses: 1"));
        assert!(!output.contains("Every enumerated file was read in full"));
    }
    report.coverage.content_lost = 0;
    report.coverage.artifacts_analyzed = 0;
    assert!(aa_report::doc::content_incomplete(&report));
}

#[test]
fn relationship_index_preserves_ambiguity_evidence_and_preview_limits() {
    let mut report = full();
    let source = report.artifacts[0].path.clone();
    let rows: Vec<Value> = (0..55)
        .map(|index| {
            json!({
                "field": format!("RelativePath[{index}]"),
                "declared": HOSTILE[0],
                "status": "unresolved",
                "reason": "ambiguous-target",
                "target": null,
                "target_sha256": null,
            })
        })
        .collect();
    report.artifacts[0].facts.insert("windows.input-references".into(), json!({"references": rows, "truncated": true}));
    let relationships = aa_report::relationships::collect(&report);
    assert_eq!(relationships.total, 55);
    assert_eq!(relationships.rows.len(), 50);
    assert!(relationships.source_truncated);
    assert_eq!(relationships.rows[0].source, source);
    assert_eq!(relationships.rows[0].location, "RelativePath[0]");
    assert_eq!(relationships.rows[0].reason.as_deref(), Some("ambiguous-target"));
    assert!(relationships.rows[0].target.is_none());
    let page = html(&report, Lang::En);
    assert!(page.contains("ambiguous-target"));
    // Hostile declarations reach only escaped text or embedded JSON, never HTML instructions.
    assert!(!page.contains(HOSTILE[0]));
    assert_eq!(page, html(&report, Lang::En));
    for format in [Format::Markdown, Format::Text] {
        let text = String::from_utf8(render(&report, format, Lang::En).expect("renders")).expect("text");
        assert!(text.contains("50 / 55"));
        assert!(text.contains("Underlying relationship facts were truncated"));
        assert!(text.contains("ambiguous-target"));
    }
    #[cfg(feature = "pdf")]
    assert!(!render(&report, Format::Pdf, Lang::En).expect("PDF relationship table").is_empty());
}

#[test]
fn catalog_index_keeps_all_captured_digest_candidates_and_search_scope() {
    let mut report = full();
    report.artifacts[0].facts.insert(
        "windows.catalog-membership".into(),
        json!({
            "entries_omitted": 1,
            "entries": [{"status": "digest-agreement", "declared_digest": "abcd", "search_complete": false,
                "observed_match_count": 2, "algorithm": "sha256", "sip_hash_profile": "flat-file", "matches": [
                    {"path": "first.bin", "sha256": "1111"}, {"path": "second.bin", "sha256": "2222"},
                ]}],
        }),
    );
    let relationships = aa_report::relationships::collect(&report);
    assert_eq!(relationships.total, 2);
    assert!(relationships.source_truncated);
    assert_eq!(relationships.rows[0].target.as_deref(), Some("first.bin"));
    assert_eq!(relationships.rows[1].target.as_deref(), Some("second.bin"));
    assert!(
        relationships.rows.iter().all(|row| row.status == "digest-agreement"
            && row.reason.as_deref().is_some_and(|reason| reason.contains("\"search_complete\":false")))
    );
}

#[test]
fn msi_actions_enter_the_existing_relationship_reading_index() {
    let mut report = full();
    report.artifacts[0].facts.insert(
        "windows.msi-action-targets".into(),
        json!({"truncated": false, "references": [
            {"field": "CustomAction table, row RunPayload", "declared": "Payload", "status": "matched-supplied-declaration",
             "target": "installer.msi/[Binary]/Payload", "target_sha256": "1234", "reason": null},
            {"field": "CustomAction table, row Missing", "declared": "Absent", "status": "unresolved",
             "target": null, "target_sha256": null, "reason": "binary-stream-not-captured"}
        ]}),
    );
    let index = aa_report::relationships::collect(&report);
    assert_eq!(index.total, 2);
    assert_eq!(index.rows[0].location, "CustomAction table, row RunPayload");
    assert_eq!(index.rows[0].target.as_deref(), Some("installer.msi/[Binary]/Payload"));
    for format in [Format::Markdown, Format::Text, Format::Html] {
        let output = String::from_utf8(render(&report, format, Lang::En).expect("MSI relationships render")).expect("text format");
        assert!(output.contains("binary-stream-not-captured"));
        assert!(output.contains("CustomAction table, row RunPayload"));
    }
}
