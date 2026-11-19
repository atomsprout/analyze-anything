//! The interpretation end to end, against stand-ins for the model and for the other programs.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use aa_core::{Confidence, Coverage, Evidence, Finding, Input, InputKind, Location, Report, RuleText, Section, Severity, Tool};
use aa_interpret::config::{Overrides, resolve};
use aa_interpret::delegate::Finished;
use aa_interpret::provider::HttpRequest;
use aa_interpret::tools::Tools;
use aa_interpret::{Context, Engine, Language, Net, Processes, Provider, Runner, Settings, Transport, interpret, markdown};
use serde_json::{Value, json};

fn rule(title: &str, text: &str) -> RuleText {
    RuleText { title_zh: format!("{title}（中文）"), title_en: title.into(), text_zh: text.into(), text_en: text.into() }
}

fn report() -> Report {
    let signed =
        Finding::new(Section::Provenance, "apple", "apple.signed", Confidence::Verified, Severity::Info).param("team", "ABCDE12345").seal();
    let mut key = Finding::new(Section::Secrets, "content", "content.secret", Confidence::Heuristic, Severity::Medium)
        .param("kind", "Stripe live secret key")
        .param("redacted", "sk_live_…9f");
    key.evidence.push(Evidence {
        artifact: "Example.ipa/Payload/Example.app/config.json".into(),
        sha256: None,
        location: Location::Bytes { offset: 40, length: 32 },
        value: json!("sk_live_…9f"),
    });
    let key = key.seal();
    let mut findings = vec![signed];
    for index in 0..30 {
        findings.push(
            Finding::new(Section::Network, "content", "content.url", Confidence::Verified, Severity::Info)
                .param("url", format!("https://example.com/{index}"))
                .seal(),
        );
    }
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

fn settings(text: &str) -> Settings {
    let file = aa_interpret::config::parse(text).expect("parses");
    resolve(file, Overrides::default(), &|_| None).expect("resolves")
}

/// Answers each request with the next reply and remembers what was asked.
struct Canned {
    replies: RefCell<Vec<(u16, Value)>>,
    asked: RefCell<Vec<HttpRequest>>,
}

impl Canned {
    fn new(replies: Vec<(u16, Value)>) -> Self {
        Canned { replies: RefCell::new(replies), asked: RefCell::new(Vec::new()) }
    }

    fn body(&self, index: usize) -> Value {
        serde_json::from_str(&self.asked.borrow()[index].body).expect("json")
    }
}

impl Transport for Canned {
    fn post(&self, request: &HttpRequest, _: Duration) -> Result<(u16, String), String> {
        self.asked.borrow_mut().push(request.clone());
        let mut replies = self.replies.borrow_mut();
        assert!(!replies.is_empty(), "asked more often than expected");
        let (status, body) = replies.remove(0);
        Ok((status, body.to_string()))
    }
}

/// No program may be started in a test that does not expect one.
struct NoPrograms;

impl Runner for NoPrograms {
    fn run(&self, program: &str, _: &[String], _: &str, _: &Path, _: Duration) -> Result<Finished, String> {
        panic!("{program} was started");
    }
}

fn ask(
    report: &Report,
    settings: &Settings,
    language: Language,
    transport: &dyn Transport,
    runner: &dyn Runner,
) -> Result<aa_interpret::Interpretation, String> {
    let mut steps = |_: &str| {};
    let context = Context {
        report_path: Path::new("/tmp/report.json"),
        program: Path::new("/usr/local/bin/analyze-anything"),
        transport,
        runner,
        on_step: &mut steps,
    };
    interpret(report, settings, language, context)
}

/// What a model might say about [`report`].
fn said(report: &Report) -> String {
    let secret = &report.findings.last().expect("a finding").id[..10];
    let signed = &report.findings[0].id[..10];
    json!({
        "summary": [{ "text": "The package is signed by one team.", "cites": [signed] }],
        "notable": [
            { "text": "It may contain a live payment key.", "cites": [secret, secret] },
            { "text": "It is probably malware.", "cites": [] },
            { "text": "It phones home.", "cites": ["0000000000"] },
            { "text": "It is fine.", "cites": ["F1"] },
        ],
        "next_steps": [{ "text": "Check whether the key is real and revoke it.", "cites": [secret] }],
    })
    .to_string()
}

#[test]
fn the_tools_answer_from_the_report_and_only_from_it() {
    let report = report();
    let tools = Tools::new(&report, Language::En);
    let brief = tools.brief();
    assert_eq!(brief["findings_total"], 32);
    // Only what is above "info" is in the brief; the rest is counted.
    assert_eq!(brief["findings_above_info"].as_array().expect("a list").len(), 1);
    assert_eq!(brief["findings_by_section_and_severity"]["network"]["info"], 30);

    let urls = tools.call("list_findings", &json!({ "section": "network", "limit": 5, "offset": 28 })).expect("lists");
    assert_eq!((urls["matching"].as_u64(), urls["findings"].as_array().map(Vec::len)), (Some(30), Some(2)));
    let found = tools.call("list_findings", &json!({ "query": "STRIPE key" })).expect("lists");
    assert_eq!(found["matching"], 1);
    let id = found["findings"][0]["id"].as_str().expect("an id");
    assert!(id.len() >= 10 && report.findings.last().expect("a finding").id.starts_with(id));

    let whole = tools.call("get_finding", &json!({ "id": id })).expect("shows");
    assert_eq!(whole["evidence"][0]["where"], "bytes 40..72");
    assert_eq!(whole["evidence"][0]["file"], "Example.ipa/Payload/Example.app/config.json");
    assert!(tools.call("get_finding", &json!({ "id": "0000000000" })).is_err());
    assert!(tools.call("get_finding", &json!({ "id": "" })).is_err());
    assert!(tools.call("read_file", &json!({ "path": "/etc/passwd" })).expect_err("no such tool").contains("no tool named"));
    // A reference must be long enough to be meant, and must name one finding.
    assert!(tools.find(&report.findings[0].id[..7]).is_none());
    assert!(tools.find(&report.findings[0].id).is_some());
}

#[test]
fn claude_is_asked_the_anthropic_way_round_after_round() {
    let report = report();
    let secret = report.findings.last().expect("a finding").id.clone();
    let transport = Canned::new(vec![
        (
            200,
            json!({
                "model": "claude-opus-5-5",
                "stop_reason": "tool_use",
                "content": [
                    { "type": "thinking", "thinking": "…", "signature": "s" },
                    { "type": "tool_use", "id": "toolu_1", "name": "get_finding", "input": { "id": &secret[..10] } },
                    { "type": "tool_use", "id": "toolu_2", "name": "no_such_tool", "input": {} },
                ],
            }),
        ),
        (200, json!({ "model": "claude-opus-5-5", "stop_reason": "end_turn", "content": [{ "type": "text", "text": said(&report) }] })),
    ]);
    let settings = settings("[ai]\nprovider = \"anthropic\"\nmodel = \"test-model\"\napi_key = \"test-key\"\n");
    let result = ask(&report, &settings, Language::En, &transport, &NoPrograms).expect("interprets");

    let asked = transport.asked.borrow();
    assert_eq!(asked[0].url, "https://api.anthropic.com/v1/messages");
    assert!(asked[0].headers.contains(&("x-api-key".to_string(), "test-key".to_string())));
    assert!(asked[0].headers.iter().any(|(name, _)| name == "anthropic-version"));
    let first = transport.body(0);
    assert_eq!(first["model"], "test-model");
    assert_eq!(first["tools"].as_array().expect("tools").len(), 3);
    assert!(first["tools"][0]["input_schema"].is_object());
    assert!(first["messages"][0]["content"].as_str().expect("text").contains("Looks like a Stripe live secret key"));
    // The second request repeats the model's blocks unchanged and answers each question.
    let second = transport.body(1);
    assert_eq!(second["messages"][1]["content"][0]["type"], "thinking");
    assert_eq!(second["messages"][1]["content"][0]["signature"], "s");
    let answers = second["messages"][2]["content"].as_array().expect("answers");
    assert_eq!((answers[0]["type"].as_str(), answers[0]["tool_use_id"].as_str()), (Some("tool_result"), Some("toolu_1")));
    assert!(answers[0]["content"].as_str().expect("text").contains("bytes 40..72"));
    assert!(answers[1]["content"].as_str().expect("text").starts_with("error: there is no tool named"));

    assert_eq!((result.engine, result.model.as_str(), result.lookups), (Engine::Api, "claude-opus-5-5", Some(2)));
    assert!(result.ai_generated);
    // Of five notable statements, the one that cites a real finding stays.
    assert_eq!(result.statements_dropped, 3);
    assert_eq!(result.notable.len(), 1);
    assert_eq!(result.notable[0].findings, vec![secret.clone()]);
    assert_eq!(result.summary[0].findings, vec![report.findings[0].id.clone()]);
    let text = markdown(&result);
    assert!(text.contains("AI-generated") && text.contains(&secret[..16]) && !text.contains("malware"));
}

#[test]
fn an_openai_compatible_service_is_asked_its_way() {
    let report = report();
    let transport = Canned::new(vec![
        (
            200,
            json!({ "model": "local", "choices": [{ "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": null, "reasoning_content": "kept",
                "tool_calls": [{ "id": "call_1", "type": "function", "function": { "name": "list_findings", "arguments": "{\"severity\":\"medium\"}" } },
                               { "id": "call_2", "type": "function", "function": { "name": "list_files", "arguments": "not json" } }],
            } }] }),
        ),
        (
            200,
            json!({ "model": "local", "choices": [{ "finish_reason": "stop", "message": { "role": "assistant", "content": format!("```json\n{}\n```", said(&report)) } }] }),
        ),
    ]);
    let settings = settings("[ai]\nprovider = \"openai-compatible\"\nbase_url = \"http://localhost:11434/v1\"\nmodel = \"local\"\n");
    let result = ask(&report, &settings, Language::Zh, &transport, &NoPrograms).expect("interprets");
    let asked = transport.asked.borrow();
    assert_eq!(asked[0].url, "http://localhost:11434/v1/chat/completions");
    assert!(!asked[0].headers.iter().any(|(name, _)| name == "authorization"));
    let first = transport.body(0);
    assert_eq!(first["messages"][0]["role"], "system");
    assert!(first["messages"][0]["content"].as_str().expect("text").contains("Simplified Chinese"));
    assert!(first["messages"][1]["content"].as_str().expect("text").contains("Embedded secret（中文）"));
    assert_eq!(first["tools"][0]["type"], "function");
    let second = transport.body(1);
    // The model's message goes back whole, then one answer per question.
    assert_eq!(second["messages"][2]["reasoning_content"], "kept");
    assert_eq!((second["messages"][3]["role"].as_str(), second["messages"][3]["tool_call_id"].as_str()), (Some("tool"), Some("call_1")));
    assert!(second["messages"][3]["content"].as_str().expect("text").contains("\"matching\":1"));
    assert_eq!(second["messages"][4]["tool_call_id"], "call_2");
    assert_eq!(result.lookups, Some(2));
    assert!(markdown(&result).contains("AI 生成"));
}

#[test]
fn a_model_that_keeps_asking_is_told_to_answer_and_then_given_up_on() {
    let report = report();
    let more = || {
        (
            200,
            json!({ "choices": [{ "message": { "content": "", "tool_calls": [{ "id": "c", "type": "function", "function": { "name": "list_findings", "arguments": "{}" } }] } }] }),
        )
    };
    let transport = Canned::new(vec![more(), more(), more()]);
    let settings = settings("[ai]\nprovider = \"openai\"\nmodel = \"m\"\napi_key = \"k\"\nmax_turns = 2\n");
    let error = ask(&report, &settings, Language::En, &transport, &NoPrograms).expect_err("gives up");
    assert!(error.contains("gave no answer in 2 rounds"));
    assert!(transport.asked.borrow()[0].headers.contains(&("authorization".to_string(), "Bearer k".to_string())));
    // With the second round's answers came the word that it was the last.
    let third = transport.body(2);
    let messages = third["messages"].as_array().expect("messages");
    assert!(messages.last().expect("a message")["content"].as_str().expect("text").contains("give your answer now"));
}

#[test]
fn a_service_without_tools_still_answers_from_the_brief() {
    let report = report();
    let transport = Canned::new(vec![
        (400, json!({ "error": { "message": "tools are not supported" } })),
        (200, json!({ "model": "plain", "choices": [{ "message": { "content": said(&report) } }] })),
    ]);
    let settings = settings("[ai]\nprovider = \"openai\"\nmodel = \"m\"\napi_key = \"k\"\n");
    let result = ask(&report, &settings, Language::En, &transport, &NoPrograms).expect("interprets");
    assert!(transport.body(1).get("tools").is_none());
    assert_eq!((result.model.as_str(), result.lookups), ("plain", Some(0)));
}

#[test]
fn failures_are_told_plainly() {
    let report = report();
    let anthropic = settings("[ai]\nprovider = \"anthropic\"\napi_key = \"k\"\n");
    let openai = settings("[ai]\nprovider = \"openai\"\nmodel = \"m\"\napi_key = \"k\"\n");
    let fails = |settings: &Settings, replies: Vec<(u16, Value)>| {
        ask(&report, settings, Language::En, &Canned::new(replies), &NoPrograms).expect_err("fails")
    };
    let denied = fails(
        &anthropic,
        vec![(401, json!({ "type": "error", "error": { "type": "authentication_error", "message": "invalid x-api-key" } }))],
    );
    assert!(denied.contains("401") && denied.contains("invalid x-api-key"));
    assert!(fails(&openai, vec![(402, json!({ "error": { "message": "Insufficient Balance" } }))]).contains("no balance"));
    // A refusal to do without tools either is reported as the first refusal.
    assert!(
        fails(&openai, vec![(400, json!({ "error": { "message": "bad model" } })), (400, json!({ "error": { "message": "bad model" } }))])
            .contains("bad model")
    );
    assert!(fails(&anthropic, vec![(200, json!({ "stop_reason": "refusal", "content": [] }))]).contains("declined"));
    assert!(
        fails(&openai, vec![(200, json!({ "choices": [{ "finish_reason": "length", "message": { "content": "{" } }] }))])
            .contains("cut off")
    );
    assert!(
        fails(&openai, vec![(200, json!({ "choices": [{ "message": { "content": "Sure! It looks fine." } }] }))])
            .contains("no JSON object")
    );
    let unbacked = json!({ "summary": [{ "text": "Looks fine.", "cites": [] }] }).to_string();
    assert!(fails(&openai, vec![(200, json!({ "choices": [{ "message": { "content": unbacked } }] }))]).contains("no interpretation"));
}

#[test]
fn a_report_without_findings_is_not_sent() {
    let mut report = report();
    report.findings.clear();
    let transport = Canned::new(Vec::new());
    assert!(ask(&report, &settings("[ai]\nprovider = \"anthropic\"\napi_key = \"k\"\n"), Language::En, &transport, &NoPrograms).is_err());
}

/// Stands in for another program: remembers how it was started and prints what it is told to.
struct Scripted {
    prints: String,
    writes_answer: bool,
    started: RefCell<Vec<(String, Vec<String>, String)>>,
}

impl Runner for Scripted {
    fn run(&self, program: &str, arguments: &[String], input: &str, folder: &Path, _: Duration) -> Result<Finished, String> {
        self.started.borrow_mut().push((program.to_string(), arguments.to_vec(), input.to_string()));
        // What the program is pointed at exists while it runs.
        let servers: Value =
            serde_json::from_str(&std::fs::read_to_string(folder.join("mcp.json")).expect("the server list")).expect("json");
        assert_eq!(servers["mcpServers"]["report"]["command"], "/usr/local/bin/analyze-anything");
        assert_eq!(servers["mcpServers"]["report"]["args"], json!(["mcp", "/tmp/report.json", "--lang", "en"]));
        if self.writes_answer {
            std::fs::write(folder.join("answer.txt"), &self.prints).expect("writes");
        }
        Ok(Finished { success: true, stdout: self.prints.clone(), stderr: String::new() })
    }
}

fn after(arguments: &[String], flag: &str) -> String {
    let at = arguments.iter().position(|argument| argument == flag).unwrap_or_else(|| panic!("{flag} is missing"));
    arguments[at + 1].clone()
}

#[test]
fn claude_code_is_started_with_the_reports_tools_and_nothing_else() {
    let report = report();
    let runner = Scripted {
        prints: json!({ "type": "result", "is_error": false, "result": said(&report), "modelUsage": { "claude-fable-5-2": {} } })
            .to_string(),
        writes_answer: false,
        started: RefCell::new(Vec::new()),
    };
    let result =
        ask(&report, &settings("[ai]\nengine = \"claude\"\n"), Language::En, &Canned::new(Vec::new()), &runner).expect("interprets");
    let started = runner.started.borrow();
    let (program, arguments, input) = &started[0];
    assert_eq!(program, "claude");
    assert!(arguments.contains(&"--print".to_string()) && arguments.contains(&"--strict-mcp-config".to_string()));
    assert_eq!(after(arguments, "--tools"), "");
    assert_eq!(after(arguments, "--allowedTools"), "mcp__report__list_findings,mcp__report__get_finding,mcp__report__list_files");
    assert_eq!(after(arguments, "--permission-mode"), "dontAsk");
    assert!(after(arguments, "--system-prompt").contains("Use no other tool"));
    assert!(input.starts_with("Report data:"));
    assert_eq!((result.engine, result.model.as_str(), result.lookups), (Engine::Claude, "claude-fable-5-2", None));
    assert_eq!(result.statements_dropped, 3);
}

#[test]
fn claude_code_saying_it_failed_is_a_failure() {
    let runner = Scripted {
        prints: json!({ "is_error": true, "result": "Failed to authenticate" }).to_string(),
        writes_answer: false,
        started: RefCell::new(Vec::new()),
    };
    let error =
        ask(&report(), &settings("[ai]\nengine = \"claude\"\n"), Language::En, &Canned::new(Vec::new()), &runner).expect_err("fails");
    assert!(error.contains("Failed to authenticate"));
}

#[test]
fn codex_is_started_read_only_with_the_reports_server() {
    let report = report();
    let runner = Scripted { prints: said(&report), writes_answer: true, started: RefCell::new(Vec::new()) };
    let result = ask(&report, &settings("[ai]\nengine = \"codex\"\nmodel = \"gpt-x\"\n"), Language::En, &Canned::new(Vec::new()), &runner)
        .expect("interprets");
    let started = runner.started.borrow();
    let (program, arguments, input) = &started[0];
    assert_eq!(program, "codex");
    assert_eq!(arguments[0], "exec");
    assert_eq!(after(arguments, "--sandbox"), "read-only");
    assert_eq!(after(arguments, "--model"), "gpt-x");
    assert!(arguments.contains(&"mcp_servers.report.command=\"/usr/local/bin/analyze-anything\"".to_string()));
    assert!(arguments.contains(&"mcp_servers.report.args=[\"mcp\",\"/tmp/report.json\",\"--lang\",\"en\"]".to_string()));
    assert_eq!(arguments.last().map(String::as_str), Some("-"));
    assert!(input.contains("You explain a static-analysis report") && input.contains("Report data:"));
    assert_eq!((result.engine, result.model.as_str()), (Engine::Codex, "gpt-x"));
}

/// A command of the user's own, run for real: a script that prints an answer.
#[cfg(unix)]
#[test]
fn a_command_of_ones_own_is_run_and_its_output_checked() {
    let report = report();
    let folder = tempfile::tempdir().expect("a folder");
    let answer = folder.path().join("answer.json");
    std::fs::write(&answer, said(&report)).expect("writes");
    // It proves it was given the prompt on its input and in a file, and where the server list is.
    let script = format!("grep -q 'Report data:' \"$1\" && test -f \"$2\" && grep -q 'Report data:' && cat '{}'", answer.display());
    let text = format!(
        "[ai]\nengine = \"command\"\ncommand = [\"sh\", \"-c\", {}, \"sh\", \"{{prompt_file}}\", \"{{mcp_config}}\"]\n",
        json!(script)
    );
    let result = ask(&report, &settings(&text), Language::En, &Canned::new(Vec::new()), &Processes).expect("interprets");
    assert_eq!((result.engine, result.model.as_str()), (Engine::Command, "command"));
    assert_eq!(result.notable.len(), 1);

    let missing = settings("[ai]\nengine = \"command\"\ncommand = [\"analyze-anything-no-such-program\"]\n");
    assert!(ask(&report, &missing, Language::En, &Canned::new(Vec::new()), &Processes).expect_err("fails").contains("not installed"));
    let slow = settings("[ai]\nengine = \"command\"\ncommand = [\"sleep\", \"30\"]\ntimeout_seconds = 1\n");
    assert!(
        ask(&report, &slow, Language::En, &Canned::new(Vec::new()), &Processes).expect_err("fails").contains("did not finish in 1 seconds")
    );
}

#[test]
fn the_tool_server_speaks_the_protocol() {
    let report = report();
    let id = &report.findings.last().expect("a finding").id[..10];
    let input = [
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "t", "version": "0" } } }),
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }),
        json!({ "jsonrpc": "2.0", "id": "three", "method": "tools/call", "params": { "name": "get_finding", "arguments": { "id": id } } }),
        json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": { "name": "delete_everything", "arguments": {} } }),
        json!({ "jsonrpc": "2.0", "id": 5, "method": "resources/list" }),
    ]
    .map(|message| message.to_string())
    .join("\n")
        + "\nnot json\n";
    let mut output = Vec::new();
    aa_interpret::mcp::serve(&report, Language::En, input.as_bytes(), &mut output).expect("serves");
    let replies: Vec<Value> =
        String::from_utf8(output).expect("text").lines().map(|line| serde_json::from_str(line).expect("json")).collect();
    // One reply per request; the notification gets none.
    assert_eq!(replies.len(), 6);
    assert_eq!(replies[0]["result"]["serverInfo"]["name"], "analyze-anything");
    assert!(replies[0]["result"]["capabilities"]["tools"].is_object());
    let tools = replies[1]["result"]["tools"].as_array().expect("tools");
    assert_eq!(
        tools.iter().map(|tool| tool["name"].as_str().expect("a name")).collect::<Vec<_>>(),
        ["list_findings", "get_finding", "list_files"]
    );
    assert!(tools.iter().all(|tool| tool["inputSchema"]["type"] == "object"));
    assert_eq!(replies[2]["id"], "three");
    assert!(replies[2]["result"]["content"][0]["text"].as_str().expect("text").contains("Stripe live secret key"));
    assert_eq!(replies[3]["result"]["isError"], true);
    assert_eq!(replies[4]["error"]["code"], -32601);
    assert_eq!(replies[5]["error"]["code"], -32700);
}

/// The real transport, against a server on this machine that speaks just enough HTTP.
#[test]
fn the_network_transport_posts_and_reads_the_reply() {
    let report = report();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("binds");
    let address = listener.local_addr().expect("address");
    let reply = json!({ "model": "served", "choices": [{ "message": { "content": said(&report) } }] }).to_string();
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
    let settings = settings(&format!(
        "[ai]\nprovider = \"openai-compatible\"\nbase_url = \"http://{address}/v1\"\nmodel = \"m\"\napi_key = \"test-key\"\n"
    ));
    let result = ask(&report, &settings, Language::En, &Net, &NoPrograms).expect("interprets");
    let request = server.join().expect("server");
    assert!(request.starts_with("POST /v1/chat/completions HTTP/1.1"));
    assert!(request.to_lowercase().contains("authorization: bearer test-key"));
    assert!(request.contains("Report data:"));
    assert_eq!((result.model.as_str(), result.notable.len()), ("served", 1));
}

#[test]
fn a_server_that_is_not_there_is_an_error_not_a_hang() {
    let settings = settings("[ai]\nprovider = \"openai-compatible\"\nbase_url = \"http://127.0.0.1:1/v1\"\nmodel = \"m\"\n");
    assert!(ask(&report(), &settings, Language::En, &Net, &NoPrograms).expect_err("fails").contains("cannot reach"));
}

#[test]
fn the_provider_names_read_as_written() {
    assert_eq!(Provider::Anthropic.id(), "anthropic");
    assert_eq!(settings("[ai]\nengine = \"api\"\nprovider = \"openai\"\nmodel = \"m\"\napi_key = \"k\"\n").engine(), Engine::Api);
}
