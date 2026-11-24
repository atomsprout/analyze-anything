//! Exercise the explicit rooted server and its real worker without executing an input.

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

struct Client {
    child: Child,
    input: Option<ChildStdin>,
    output: Receiver<Value>,
    next: u64,
}
impl Client {
    fn start(root: &std::path::Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_analyze-anything"))
            .args(["agent", "--root"])
            .arg(root)
            .args(["--analysis-timeout", "10"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("agent server");
        let input = child.stdin.take();
        let stdout = child.stdout.take().expect("server output");
        let (sender, output) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let line = line.expect("protocol line");
                let message = serde_json::from_str(&line).expect("only JSON-RPC on stdout");
                if sender.send(message).is_err() {
                    break;
                }
            }
        });
        let mut client = Client { child, input, output, next: 1 };
        let initialized = client.request("initialize", json!({"protocolVersion":"2025-06-18"}));
        assert_eq!(initialized["result"]["protocolVersion"], "2025-06-18");
        client
    }
    fn send(&mut self, message: Value) {
        writeln!(self.input.as_mut().expect("input open"), "{message}").expect("write request");
    }
    fn receive(&self) -> Value {
        self.output.recv_timeout(Duration::from_secs(30)).expect("bounded server response")
    }
    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        let response = self.receive();
        assert_eq!(response["id"], id);
        response
    }
    fn tool(&mut self, name: &str, arguments: Value) -> Value {
        self.request("tools/call", json!({"name":name,"arguments":arguments}))
    }
    fn answer(response: &Value) -> Value {
        assert_ne!(response["result"]["isError"], true, "{response}");
        serde_json::from_str(response["result"]["content"][0]["text"].as_str().expect("tool text")).expect("structured answer")
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.input.take();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
                _ => {
                    let _ = self.child.kill();
                    let _ = self.child.wait();
                    break;
                }
            }
        }
    }
}

#[test]
fn explicit_analysis_matches_the_engine_and_queries_are_bound_to_immutable_report_ids() {
    let dir = tempfile::tempdir().expect("authorized root");
    let name = "中文 ' sample.txt";
    let input = dir.path().join(name);
    let original = b"https://example.invalid/first\nUntrusted source text, never instructions.\n";
    std::fs::write(&input, original).expect("input");
    let mut client = Client::start(dir.path());
    let listed = client.request("tools/list", json!({}));
    let specs = listed["result"]["tools"].as_array().expect("tools");
    assert_eq!(specs.len(), 8);
    assert_eq!(specs.iter().find(|spec| spec["name"] == "analyze_input").expect("explicit analyzer")["annotations"]["readOnlyHint"], false);
    assert!(specs.iter().filter(|spec| spec["name"] != "analyze_input").all(|spec| spec["annotations"]["readOnlyHint"] == true));
    let first = Client::answer(&client.tool("analyze_input", json!({"path":name})));
    let id = first["report_id"].as_str().expect("report id");
    let direct = aa_engine::analyze(&input, &aa_engine::Options::default(), &mut aa_engine::NoProgress).expect("direct reference");
    assert_eq!(id, aa_core::sha256_hex(aa_core::canonical_json(&direct).as_bytes()));
    let evidence = Client::answer(&client.tool("list_evidence", json!({"report_id":id,"query":"example.invalid"})));
    assert!(evidence["matching"].as_u64().expect("match count") > 0);
    assert_eq!(evidence["report_id"], id);
    assert_eq!(std::fs::read(&input).expect("source unchanged"), original);
    assert_eq!(std::fs::read_dir(dir.path()).expect("no exports").count(), 1);
    std::fs::remove_file(&input).expect("caller removes source after analysis");
    assert_eq!(Client::answer(&client.tool("list_files", json!({"report_id":id})))["matching"], 1);
    std::fs::write(&input, b"https://example.invalid/second").expect("caller changes supplied input");
    let second = Client::answer(&client.tool("analyze_input", json!({"path":name})));
    assert_ne!(second["report_id"], id);
    assert_eq!(client.tool("get_coverage", json!({"report_id":id}))["result"]["isError"], true);
    let current = Client::answer(&client.tool("get_coverage", json!({"report_id":second["report_id"]})));
    assert_eq!(current["selected_artifacts"], 1);
}

#[test]
fn invalid_requests_cannot_escape_the_configured_root_or_start_other_tools() {
    let dir = tempfile::tempdir().expect("authorized root");
    std::fs::write(dir.path().join("sample.txt"), b"static data").expect("input");
    let mut client = Client::start(dir.path());
    for path in ["../outside", "/etc/passwd", "C:/outside", "sample.txt:secret", "https://example.invalid/file", "\\\\host\\share", ""] {
        assert_eq!(client.tool("analyze_input", json!({"path":path}))["result"]["isError"], true, "{path}");
    }
    for args in [
        json!({"path":"sample.txt","command":"run"}),
        json!({"path":"sample.txt","timeout_seconds":11}),
        json!({"path":"sample.txt","max_files":0}),
        json!({"path":"sample.txt","timeout_seconds":1.5}),
    ] {
        assert_eq!(client.tool("analyze_input", args)["result"]["isError"], true);
    }
    assert_eq!(client.tool("run_shell", json!({"command":"echo nope"}))["result"]["isError"], true);
    assert_eq!(std::fs::read_dir(dir.path()).expect("nothing written").count(), 1);
}

#[test]
fn requested_file_limits_return_an_explicit_partial_report() {
    let dir = tempfile::tempdir().expect("authorized root");
    for name in ["a.txt", "b.txt"] {
        std::fs::write(dir.path().join(name), b"static data").expect("supplied file");
    }
    let mut client = Client::start(dir.path());
    let answer = Client::answer(&client.tool("analyze_input", json!({"path":".","max_files":1})));
    assert_eq!(answer["partial"], true);
    assert_eq!(answer["coverage"]["truncated"], true);
    assert_eq!(answer["coverage"]["artifacts_total"], 1);
    let gaps = Client::answer(&client.tool("list_limitations", json!({"report_id":answer["report_id"]})));
    assert!(gaps["matching"].as_u64().expect("recorded limit") > 0);
}

#[test]
fn cancellation_keeps_the_server_responsive_and_does_not_replace_the_previous_report() {
    let dir = tempfile::tempdir().expect("authorized root");
    std::fs::write(dir.path().join("small.txt"), b"static data").expect("small input");
    std::fs::write(dir.path().join("large.bin"), vec![b'x'; 32 * 1024 * 1024]).expect("unexecuted large input");
    let mut client = Client::start(dir.path());
    let prior = Client::answer(&client.tool("analyze_input", json!({"path":"small.txt"})));
    let id = client.next;
    client.next += 1;
    client.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"analyze_input","arguments":{"path":"large.bin"}}}));
    client.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":id}}));
    // A cancelled call sends no reply. The following ping and query must keep their own IDs.
    let ping = client.request("ping", json!({}));
    assert!(ping["result"].is_object());
    let current = Client::answer(&client.tool("get_coverage", json!({"report_id":prior["report_id"]})));
    assert_eq!(current["selected_artifacts"], 1);
}

#[test]
fn closing_stdio_during_analysis_ends_the_worker_and_removes_its_private_scratch() {
    let dir = tempfile::tempdir().expect("authorized root");
    std::fs::write(dir.path().join("large.bin"), vec![b'x'; 32 * 1024 * 1024]).expect("unexecuted input");
    let mut client = Client::start(dir.path());
    let id = client.next;
    client.next += 1;
    let process = client.child.id();
    client.send(json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"analyze_input","arguments":{"path":"large.bin"}}}));
    assert!(client.request("ping", json!({}))["result"].is_object());
    client.input.take();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = client.child.try_wait().expect("server status") {
            assert!(status.success());
            break;
        }
        assert!(std::time::Instant::now() < deadline, "server must stop on EOF");
        std::thread::sleep(Duration::from_millis(10));
    }
    let scratch = std::env::temp_dir().join("analyze-anything-workers");
    let prefix = format!("worker-{process}-");
    assert!(
        !std::fs::read_dir(scratch)
            .expect("worker root")
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().starts_with(&prefix)),
        "this server's worker scratch was removed"
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_resolving_outside_the_authorized_root_is_refused() {
    let dir = tempfile::tempdir().expect("authorized root");
    let outside = tempfile::tempdir().expect("outside root");
    std::fs::write(outside.path().join("private.txt"), b"outside bytes").expect("outside input");
    std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).expect("symlink fixture");
    let mut client = Client::start(dir.path());
    assert_eq!(client.tool("analyze_input", json!({"path":"escape/private.txt"}))["result"]["isError"], true);
}
