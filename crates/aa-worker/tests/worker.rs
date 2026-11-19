use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aa_engine::{Event, NoProgress, Options, Registry};
use aa_worker::protocol::{LimitOverrides, MAX_CHUNK, Request, Response};
use aa_worker::{Worker, WorkerError, serve};

const WAIT: Duration = Duration::from_secs(60);

fn worker_program() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_aa-worker"))
}

/// Bytes that do not compress and that no type detector recognises; the same on every run.
fn noise(length: usize) -> Vec<u8> {
    let mut state = 0x2545_f491u32;
    let mut bytes = Vec::with_capacity(length);
    for _ in 0..length {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        bytes.push((state >> 24) as u8);
    }
    bytes[..4].copy_from_slice(&[0x00, 0x01, 0x02, 0x03]);
    bytes
}

/// A zip with a small text file and a file large enough to be kept on disk while analyzed.
fn sample(dir: &Path) -> (PathBuf, Vec<u8>) {
    let big = noise(700 * 1024);
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (name, data) in [("readme.txt", b"see https://example.com/docs\n".as_slice()), ("big.bin", &big)] {
        writer.start_file(name, options).expect("start entry");
        writer.write_all(data).expect("write entry");
    }
    let path = dir.join("sample.zip");
    std::fs::write(&path, writer.finish().expect("finish").into_inner()).expect("write");
    (path, big)
}

/// Reads responses until the report or an error arrives; returns it and the steps before it.
fn until_done(worker: &mut Worker) -> (Response, Vec<Event>) {
    let mut steps = Vec::new();
    loop {
        match worker.receive(WAIT).expect("a response") {
            Response::Progress { step } => steps.push(step),
            other => return (other, steps),
        }
    }
}

fn files_in(dir: &Path) -> usize {
    std::fs::read_dir(dir).map(|entries| entries.count()).unwrap_or(0)
}

#[test]
fn a_worker_process_reports_what_the_engine_reports_and_serves_bytes() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (path, big) = sample(dir.path());
    let scratch_root = dir.path().join("scratch");
    let mut worker = Worker::start(worker_program(), &[], &scratch_root).expect("start");
    worker.analyze(&path, LimitOverrides::default()).expect("send");

    let (done, steps) = until_done(&mut worker);
    let Response::Report { report } = done else { panic!("expected a report, got {done:?}") };
    let direct = aa_engine::analyze_with(&Registry::standard(), &path, &Options::default(), &mut NoProgress).expect("readable");
    // The same bytes of report.json as the command line writes for this input.
    assert_eq!(
        serde_json::to_string_pretty(&*report).expect("json"),
        serde_json::to_string_pretty(&direct).expect("json"),
        "a worker must not change the report"
    );
    assert!(matches!(steps.first(), Some(Event::Listed { files: 1 })), "{steps:?}");
    assert!(steps.iter().any(|step| matches!(step, Event::Unpacked { children: 2, .. })));
    assert_eq!(steps.last(), Some(&Event::Finished));

    // Bytes of the input, of a small child and of a child that was spilled to the scratch folder.
    let mut read = |id, path: &str, offset, length| {
        worker.send(&Request::ReadBytes { id, path: path.into(), offset, length }).expect("send");
        worker.receive(WAIT).expect("an answer")
    };
    assert_eq!(
        read(1, "sample.zip", 0, 4),
        Response::Bytes { id: 1, hex: "504b0304".into(), size: std::fs::metadata(&path).expect("stat").len() }
    );
    assert_eq!(read(2, "sample.zip/readme.txt", 4, 5), Response::Bytes { id: 2, hex: hex::encode("https"), size: 29 });
    assert_eq!(
        read(3, "sample.zip/big.bin", 4096, 64),
        Response::Bytes { id: 3, hex: hex::encode(&big[4096..4160]), size: big.len() as u64 }
    );
    // A request for more than a chunk is cut to a chunk; one for a missing file is an error.
    let Response::Bytes { hex, .. } = read(4, "sample.zip/big.bin", 0, u64::MAX) else { panic!("expected bytes") };
    assert_eq!(hex.len() as u64, MAX_CHUNK.min(big.len() as u64) * 2);
    assert!(matches!(read(5, "sample.zip/nope", 0, 1), Response::Error { id: Some(5), .. }));

    // What was unpacked lives in the scratch folder, and goes with the worker.
    let scratch = worker.scratch().to_path_buf();
    assert_eq!(files_in(&scratch), 1, "the spilled child is in the scratch folder");
    assert!(worker.stop(WAIT), "a worker that is asked to close ends on its own");
    drop(worker);
    assert!(!scratch.exists());
    assert_eq!(files_in(&scratch_root), 0);
}

#[test]
fn a_cancelled_analysis_still_reports_and_says_it_was_cancelled() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (path, _) = sample(dir.path());
    let mut worker = Worker::start(worker_program(), &[], &dir.path().join("scratch")).expect("start");
    // Cancelling first makes the outcome certain: the run stops at its first check.
    worker.send(&Request::Cancel).expect("send");
    worker.analyze(&path, LimitOverrides::default()).expect("send");
    let (done, _) = until_done(&mut worker);
    let Response::Report { report } = done else { panic!("expected a report, got {done:?}") };
    assert!(report.limitations.iter().any(|l| l.code == "cancelled"), "{:?}", report.limitations);
    assert!(report.coverage.truncated);
}

#[test]
fn requests_a_worker_cannot_serve_are_answered_not_fatal() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (path, _) = sample(dir.path());
    let mut worker = Worker::start(worker_program(), &[], &dir.path().join("scratch")).expect("start");

    worker.send(&Request::ReadBytes { id: 9, path: "x".into(), offset: 0, length: 1 }).expect("send");
    assert!(matches!(worker.receive(WAIT), Ok(Response::Error { id: Some(9), .. })), "nothing was analyzed yet");

    worker.analyze(&dir.path().join("does-not-exist"), LimitOverrides::default()).expect("send");
    let (done, _) = until_done(&mut worker);
    assert!(matches!(&done, Response::Error { id: None, message } if message.contains("does-not-exist")), "{done:?}");

    worker.analyze(&path, LimitOverrides::default()).expect("send");
    assert!(matches!(worker.receive(WAIT), Ok(Response::Error { id: None, .. })), "one analysis per worker");
    assert!(worker.is_running());
}

// The stand-in for a misbehaving worker is a shell command.
#[cfg(unix)]
#[test]
fn a_worker_that_does_not_answer_is_killed_and_its_scratch_removed() {
    let dir = tempfile::tempdir().expect("temp dir");
    let scratch_root = dir.path().join("scratch");
    // A stand-in for a worker stuck inside an analyzer: it reads nothing and never ends.
    let mut worker = Worker::start(Path::new("/bin/sh"), &["-c", "sleep 600"], &scratch_root).expect("start");
    std::fs::write(worker.scratch().join("00000001"), b"half unpacked").expect("write");
    assert!(matches!(worker.receive(Duration::from_millis(100)), Err(WorkerError::Timeout)));

    let begun = std::time::Instant::now();
    assert!(!worker.stop(Duration::from_millis(300)), "it had to be killed");
    assert!(begun.elapsed() < Duration::from_secs(10));
    assert!(!worker.is_running());
    drop(worker);
    assert_eq!(files_in(&scratch_root), 0, "what it had unpacked is gone");
}

// The stand-in for a misbehaving worker is a shell command.
#[cfg(unix)]
#[test]
fn a_worker_that_crashes_is_noticed_and_cleaned_up_after() {
    let dir = tempfile::tempdir().expect("temp dir");
    let scratch_root = dir.path().join("scratch");
    // A stand-in for a worker that dies mid-run: it leaves a file and exits with an error.
    let mut worker = Worker::start(Path::new("/bin/sh"), &["-c", "echo not-json; exit 3"], &scratch_root).expect("start");
    std::fs::write(worker.scratch().join("00000001"), b"half unpacked").expect("write");
    let error = worker.receive(WAIT).expect_err("no response can come");
    assert!(matches!(&error, WorkerError::Gone(text) if text.contains('3')), "{error}");
    drop(worker);
    assert_eq!(files_in(&scratch_root), 0);

    assert!(matches!(Worker::start(Path::new("/no/such/program"), &[], &scratch_root), Err(WorkerError::Start(_))));
    assert_eq!(files_in(&scratch_root), 0, "a worker that never started leaves no folder");
}

/// Collects what a server writes, for running one inside the test process.
#[derive(Clone, Default)]
struct Collected(Arc<Mutex<Vec<u8>>>);

impl Write for Collected {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn converse(input: &[u8]) -> Vec<Response> {
    let output = Collected::default();
    serve(std::io::Cursor::new(input.to_vec()), output.clone());
    let bytes = output.0.lock().expect("lock").clone();
    String::from_utf8(bytes).expect("utf-8").lines().map(|line| serde_json::from_str(line).expect("a response")).collect()
}

#[test]
fn malformed_requests_get_an_error_each_and_the_server_carries_on() {
    let mut input = Vec::new();
    input.extend_from_slice(b"\n   \n");
    input.extend_from_slice(b"not json\n");
    input.extend_from_slice(b"{\"request\":\"launch_missiles\"}\n");
    input.extend_from_slice(b"{\"request\":\"read_bytes\",\"id\":\"one\"}\n");
    input.extend_from_slice(&[0xff, 0xfe, b'\n']);
    input.extend_from_slice(&vec![b'a'; 2 * 1024 * 1024]);
    input.extend_from_slice(b"\n{\"request\":\"read_bytes\",\"id\":7,\"path\":\"p\",\"offset\":0,\"length\":1}\n");
    input.extend_from_slice(b"{\"request\":\"close\"}\n{\"request\":\"read_bytes\",\"id\":8,\"path\":\"p\",\"offset\":0,\"length\":1}\n");

    let responses = converse(&input);
    let ids: Vec<Option<u64>> = responses
        .iter()
        .map(|response| match response {
            Response::Error { id, .. } => *id,
            other => panic!("expected only errors, got {other:?}"),
        })
        .collect();
    // Five malformed lines, then the one well-formed request; nothing after `close` is served.
    assert_eq!(ids, [None, None, None, None, None, Some(7)]);
    assert!(converse(b"").is_empty());
    assert!(converse(b"{\"request\":\"cancel\"}").is_empty(), "a last line without a newline is still read");
}

#[test]
fn messages_have_the_documented_shape_and_survive_a_round_trip() {
    let requests = [
        (Request::Cancel, r#"{"request":"cancel"}"#),
        (Request::Close, r#"{"request":"close"}"#),
        (
            Request::ReadBytes { id: 3, path: "a.zip/b".into(), offset: 16, length: 256 },
            r#"{"request":"read_bytes","id":3,"path":"a.zip/b","offset":16,"length":256}"#,
        ),
    ];
    for (request, json) in requests {
        assert_eq!(serde_json::to_string(&request).expect("json"), json);
        assert_eq!(serde_json::from_str::<Request>(json).expect("parse"), request);
    }
    // Limits may be left out, in whole or in part.
    let analyze: Request = serde_json::from_str(r#"{"request":"analyze","path":"/in/a.zip","scratch":"/tmp/s"}"#).expect("parse");
    assert_eq!(analyze, Request::Analyze { path: "/in/a.zip".into(), scratch: "/tmp/s".into(), limits: LimitOverrides::default() });
    let limited: Request =
        serde_json::from_str(r#"{"request":"analyze","path":"a","scratch":"s","limits":{"max_depth":2}}"#).expect("parse");
    let Request::Analyze { limits, .. } = limited else { panic!("expected analyze") };
    assert_eq!(limits.apply().max_depth, 2);
    assert_eq!(limits.apply().max_files, aa_engine::Limits::default().max_files);

    let responses = [
        (Response::Progress { step: Event::Listed { files: 2 } }, r#"{"response":"progress","step":{"event":"listed","files":2}}"#),
        (Response::Bytes { id: 3, hex: "00ff".into(), size: 9 }, r#"{"response":"bytes","id":3,"hex":"00ff","size":9}"#),
        (Response::Error { id: None, message: "no".into() }, r#"{"response":"error","id":null,"message":"no"}"#),
    ];
    for (response, json) in responses {
        assert_eq!(serde_json::to_string(&response).expect("json"), json);
        assert_eq!(serde_json::from_str::<Response>(json).expect("parse"), response);
    }
}
