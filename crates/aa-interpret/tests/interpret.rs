//! The interpretation end to end, against a stand-in for the model.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::time::Duration;

use aa_core::{Confidence, Coverage, Finding, Input, InputKind, Report, RuleText, Section, Severity, Tool};
use aa_interpret::config::{Overrides, resolve};
use aa_interpret::provider::HttpRequest;
use aa_interpret::{Language, Net, Provider, Settings, Transport, interpret, markdown};
use serde_json::{Value, json};

fn rule(title: &str, text: &str) -> RuleText {
    RuleText { title_zh: format!("{title}（中文）"), title_en: title.into(), text_zh: text.into(), text_en: text.into() }
}

fn report() -> Report {
    let signed =
        Finding::new(Section::Provenance, "apple", "apple.signed", Confidence::Verified, Severity::Info).param("team", "ABCDE12345").seal();
    let key = Finding::new(Section::Secrets, "content", "content.secret", Confidence::Heuristic, Severity::Medium)
        .param("kind", "Stripe live secret key")
        .param("redacted", "sk_live_…9f")
        .seal();
    let mut url = Vec::new();
    for index in 0..30 {
        url.push(
            Finding::new(Section::Network, "content", "content.url", Confidence::Verified, Severity::Info)
                .param("url", format!("https://example.com/{index}"))
                .seal(),
        );
    }
    let mut findings = vec![signed];
    findings.extend(url);
    findings.push(key);
    Report {
        schema_version: aa_core::SCHEMA_VERSION,
        tool: Tool { name: "analyze-anything".into(), version: "0.0.0".into() },
        input: Input { name: "Example.ipa".into(), kind: InputKind::File, sha256: None },
        summary: Default::default(),
        artifacts: Vec::new(),
        findings,
        limitations: Vec::new(),
        coverage: Coverage::default(),
        rules: [
            ("apple.signed".to_string(), rule("Signed", "Signed by team {team}.")),
            ("content.secret".to_string(), rule("Embedded secret", "Looks like a {kind}: {redacted}.")),
            ("content.url".to_string(), rule("URL", "Mentions {url}.")),
        ]
        .into(),
    }
}

fn settings(provider: &str, base_url: Option<&str>) -> Settings {
    let flags = Overrides {
        provider: Provider::from_id(provider),
        model: Some("test-model".into()),
        base_url: base_url.map(str::to_string),
        ..Overrides::default()
    };
    resolve(Overrides::default(), flags).expect("resolves")
}

/// Answers every request with one reply and remembers what was asked.
struct Canned {
    status: u16,
    body: String,
    asked: RefCell<Vec<HttpRequest>>,
}

impl Canned {
    fn new(status: u16, body: Value) -> Self {
        Canned { status, body: body.to_string(), asked: RefCell::new(Vec::new()) }
    }
}

impl Transport for Canned {
    fn post(&self, request: &HttpRequest, _: Duration) -> Result<(u16, String), String> {
        self.asked.borrow_mut().push(request.clone());
        Ok((self.status, self.body.clone()))
    }
}

/// What a model might say: F1 is the medium finding (most serious first), F2 the signature.
fn said() -> String {
    json!({
        "summary": [{ "text": "The package is signed by one team.", "cites": ["F2"] }],
        "notable": [
            { "text": "It may contain a live payment key.", "cites": ["F1"] },
            { "text": "It is probably malware.", "cites": [] },
            { "text": "It phones home.", "cites": ["F999"] },
        ],
        "next_steps": [{ "text": "Check whether the key is real and revoke it.", "cites": ["F1"] }],
    })
    .to_string()
}

#[test]
fn claude_is_asked_the_anthropic_way_and_unbacked_statements_are_dropped() {
    let transport = Canned::new(
        200,
        json!({
            "model": "claude-opus-5-5",
            "stop_reason": "end_turn",
            "content": [{ "type": "thinking", "thinking": "…" }, { "type": "text", "text": said() }],
        }),
    );
    let report = report();
    let result = interpret(&report, &settings("anthropic", None), Language::En, Some("test-key"), &transport).expect("interprets");

    let asked = transport.asked.borrow();
    assert_eq!(asked[0].url, "https://api.anthropic.com/v1/messages");
    assert!(asked[0].headers.contains(&("x-api-key".to_string(), "test-key".to_string())));
    assert!(asked[0].headers.iter().any(|(name, _)| name == "anthropic-version"));
    let body: Value = serde_json::from_str(&asked[0].body).expect("json");
    assert_eq!(body["model"], "test-model");
    assert_eq!(body["output_config"]["format"]["type"], "json_schema");
    let sent = body["messages"][0]["content"].as_str().expect("text");
    // The report's own words go out; only twelve of the thirty neutral URL findings do.
    assert!(sent.contains("Looks like a Stripe live secret key: sk_live_…9f."));
    assert_eq!(sent.matches("\"title\": \"URL\"").count(), 12);

    assert_eq!(result.model, "claude-opus-5-5");
    assert!(result.ai_generated);
    assert_eq!((result.findings_total, result.findings_sent, result.statements_dropped), (32, 14, 2));
    let secret = report.findings.last().expect("a finding").id.clone();
    assert_eq!(result.notable.len(), 1);
    assert_eq!(result.notable[0].findings, vec![secret.clone()]);
    assert_eq!(result.summary[0].findings, vec![report.findings[0].id.clone()]);
    // Every finding named exists in the report.
    for statement in result.summary.iter().chain(&result.notable).chain(&result.next_steps) {
        assert!(statement.findings.iter().all(|id| report.findings.iter().any(|f| &f.id == id)));
    }
    let text = markdown(&result);
    assert!(text.contains("AI-generated"));
    assert!(text.contains(&secret[..16]));
    assert!(!text.contains("malware"));
}

#[test]
fn an_openai_compatible_service_is_asked_its_way() {
    let transport = Canned::new(
        200,
        json!({ "model": "local", "choices": [{ "finish_reason": "stop", "message": { "role": "assistant", "content": format!("```json\n{}\n```", said()) } }] }),
    );
    let settings = settings("openai-compatible", Some("http://localhost:11434/v1"));
    let result = interpret(&report(), &settings, Language::Zh, None, &transport).expect("interprets");
    let asked = transport.asked.borrow();
    assert_eq!(asked[0].url, "http://localhost:11434/v1/chat/completions");
    assert!(!asked[0].headers.iter().any(|(name, _)| name == "authorization"));
    let body: Value = serde_json::from_str(&asked[0].body).expect("json");
    assert_eq!(body["messages"][0]["role"], "system");
    assert!(body["messages"][0]["content"].as_str().expect("text").contains("Simplified Chinese"));
    assert!(body["messages"][1]["content"].as_str().expect("text").contains("Embedded secret（中文）"));
    assert_eq!(result.statements_dropped, 2);
    assert!(markdown(&result).contains("AI 生成"));
}

#[test]
fn a_key_goes_out_as_a_bearer_token() {
    let transport = Canned::new(200, json!({ "choices": [{ "message": { "content": said() } }] }));
    let result = interpret(&report(), &settings("openai", None), Language::En, Some("test-key"), &transport).expect("interprets");
    assert!(transport.asked.borrow()[0].headers.contains(&("authorization".to_string(), "Bearer test-key".to_string())));
    // The service did not name a model, so the one that was asked for is recorded.
    assert_eq!(result.model, "test-model");
}

#[test]
fn failures_are_told_plainly() {
    let report = report();
    let ask = |provider: &str, status: u16, body: Value, key: Option<&str>| {
        interpret(&report, &settings(provider, None), Language::En, key, &Canned::new(status, body)).expect_err("fails")
    };
    assert!(ask("anthropic", 200, json!({}), None).contains("ANTHROPIC_API_KEY is not set"));
    let denied = ask(
        "anthropic",
        401,
        json!({ "type": "error", "error": { "type": "authentication_error", "message": "invalid x-api-key" } }),
        Some("k"),
    );
    assert!(denied.contains("401") && denied.contains("invalid x-api-key"));
    assert!(ask("anthropic", 200, json!({ "stop_reason": "refusal", "content": [] }), Some("k")).contains("declined"));
    assert!(
        ask("openai", 200, json!({ "choices": [{ "finish_reason": "length", "message": { "content": "{" } }] }), Some("k"))
            .contains("cut off")
    );
    assert!(
        ask("openai", 200, json!({ "choices": [{ "message": { "content": "Sure! It looks fine." } }] }), Some("k"))
            .contains("no JSON object")
    );
    let unbacked = json!({ "summary": [{ "text": "Looks fine.", "cites": [] }] }).to_string();
    assert!(ask("openai", 200, json!({ "choices": [{ "message": { "content": unbacked } }] }), Some("k")).contains("no interpretation"));
}

#[test]
fn a_report_without_findings_is_not_sent() {
    let mut report = report();
    report.findings.clear();
    let transport = Canned::new(200, json!({}));
    assert!(interpret(&report, &settings("anthropic", None), Language::En, Some("k"), &transport).is_err());
    assert!(transport.asked.borrow().is_empty());
}

/// The real transport, against a server on this machine that speaks just enough HTTP.
#[test]
fn the_network_transport_posts_and_reads_the_reply() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
    let address = listener.local_addr().expect("address");
    let reply = json!({ "model": "served", "choices": [{ "message": { "content": said() } }] }).to_string();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accepts");
        let mut seen = Vec::new();
        let mut buffer = [0u8; 4096];
        // Read the head, then as much body as it announces.
        let (head_end, length) = loop {
            let read = stream.read(&mut buffer).expect("reads");
            seen.extend_from_slice(&buffer[..read]);
            if let Some(at) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&seen[..at]).to_lowercase();
                let length: usize = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .map(|v| v.trim().parse().expect("a number"))
                    .unwrap_or(0);
                break (at + 4, length);
            }
        };
        while seen.len() < head_end + length {
            let read = stream.read(&mut buffer).expect("reads");
            seen.extend_from_slice(&buffer[..read]);
        }
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
            reply.len()
        );
        stream.write_all(response.as_bytes()).expect("writes");
        String::from_utf8_lossy(&seen).into_owned()
    });
    let settings = settings("openai-compatible", Some(&format!("http://{address}/v1")));
    let result = interpret(&report(), &settings, Language::En, Some("test-key"), &Net).expect("interprets");
    let request = server.join().expect("server");
    assert!(request.starts_with("POST /v1/chat/completions HTTP/1.1"));
    assert!(request.to_lowercase().contains("authorization: bearer test-key"));
    assert!(request.contains("Report data:"));
    assert_eq!(result.model, "served");
    assert_eq!(result.notable.len(), 1);
}

#[test]
fn a_server_that_is_not_there_is_an_error_not_a_hang() {
    let settings = settings("openai-compatible", Some("http://127.0.0.1:1/v1"));
    assert!(interpret(&report(), &settings, Language::En, None, &Net).expect_err("fails").contains("cannot reach"));
}
