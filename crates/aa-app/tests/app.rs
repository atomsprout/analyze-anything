use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aa_app::export::{self, Kind, Lang};
use aa_app::history::{History, HistoryError};
use aa_app::run::{Program, Run, Update};
use aa_core::Report;
use aa_engine::{NoProgress, Options, Registry};
use aa_worker::protocol::LimitOverrides;

const WAIT: Duration = Duration::from_secs(60);

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

fn direct(path: &Path) -> Report {
    aa_engine::analyze_with(&Registry::standard(), path, &Options::default(), &mut NoProgress).expect("readable")
}

fn program(dir: &Path) -> Program {
    Program { path: env!("CARGO_BIN_EXE_aa-app-worker").into(), arguments: Vec::new(), scratch_root: dir.join("scratch") }
}

fn start(program: &Program, input: &Path) -> (Run, Receiver<Update>) {
    let (sender, updates) = channel();
    let run = Run::start(program, input, LimitOverrides::default(), move |update| {
        let _ = sender.send(update);
    })
    .expect("start");
    (run, updates)
}

/// The update that ends a run, and how many progress steps came before it.
fn outcome(updates: &Receiver<Update>) -> (Update, usize) {
    let mut steps = 0;
    loop {
        match updates.recv_timeout(WAIT).expect("an update") {
            Update::Progress(_) => steps += 1,
            last => return (last, steps),
        }
    }
}

fn entries(dir: &Path) -> usize {
    std::fs::read_dir(dir).map(|list| list.count()).unwrap_or(0)
}

#[test]
fn source_root_settings_survive_the_app_worker_channel() {
    let dir = tempfile::tempdir().expect("temp dir");
    let input = dir.path().join("drivers");
    std::fs::create_dir(&input).expect("input folder");
    std::fs::write(
        input.join("driver.inf"),
        b"[Version]\nSignature=\"$Windows NT$\"\n[SourceDisksNames]\n1=Disk\n[SourceDisksFiles]\npayload.bin=1\n",
    )
    .expect("INF");
    std::fs::write(input.join("payload.bin"), b"payload").expect("payload");
    let roots = vec![aa_app::run::WindowsSourceRoot { inf: "DRIVER.INF".into(), root: ".".into() }];
    let (sender, updates) = channel();
    let run = Run::start_with_source_roots(&program(dir.path()), &input, LimitOverrides::default(), roots.clone(), move |update| {
        let _ = sender.send(update);
    })
    .expect("start configured run");
    let (last, _) = outcome(&updates);
    let Update::Done(report) = last else { panic!("expected a report, got {last:?}") };
    let options = Options { windows_source_roots: roots, ..Options::default() };
    let expected = aa_engine::analyze_with(&Registry::standard(), &input, &options, &mut NoProgress).expect("direct report");
    assert_eq!(*report, expected);
    assert_eq!(report.summary["engine.windows-source-roots"][0]["inf"], "driver.inf");
    assert!(report.findings.iter().any(|finding| finding.rule == "windows.inf-source-files"));
    drop(run);
}

#[test]
fn a_run_reports_like_the_engine_then_serves_bytes_until_dropped() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (path, big) = sample(dir.path());
    let program = program(dir.path());
    let (run, updates) = start(&program, &path);
    assert!(run.read("sample.zip", 0, 4).is_err(), "nothing can be read before the report");

    let (last, steps) = outcome(&updates);
    let Update::Done(report) = last else { panic!("expected a report, got {last:?}") };
    assert!(steps >= 3, "listing, unpacking and finishing are always reported");
    assert_eq!(*report, direct(&path));

    let chunk = run.read("sample.zip/big.bin", 100, 50).expect("read");
    assert_eq!((chunk.bytes.as_slice(), chunk.size), (&big[100..150], big.len() as u64));
    assert_eq!(run.read("sample.zip/readme.txt", 0, 3).expect("read").bytes, b"see");
    assert!(run.read("sample.zip/absent", 0, 1).is_err());
    // Cancelling a finished run changes nothing.
    run.cancel();
    assert_eq!(run.read("sample.zip/readme.txt", 25, 100).expect("read").bytes, b"ocs\n");

    assert_eq!(entries(&program.scratch_root), 1);
    drop(run);
    assert_eq!(entries(&program.scratch_root), 0, "dropping the run removes what it unpacked");
    assert!(updates.recv_timeout(Duration::from_millis(200)).is_err(), "nothing follows the report");
}

#[test]
fn a_cancelled_run_says_so_once_and_leaves_nothing() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (path, _) = sample(dir.path());
    let program = program(dir.path());
    let (run, updates) = start(&program, &path);
    run.cancel();
    run.cancel();
    // Whether the worker had finished or not when the request arrived, the user gets no report.
    let (last, _) = outcome(&updates);
    assert_eq!(last, Update::Cancelled);
    assert!(run.read("sample.zip", 0, 1).is_err());
    drop(run);
    assert_eq!(entries(&program.scratch_root), 0);
}

// The stand-in for a stuck worker is a shell command.
#[cfg(unix)]
#[test]
fn a_stuck_worker_is_killed_when_the_run_is_cancelled() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (path, _) = sample(dir.path());
    // A stand-in for a worker stuck inside an analyzer: it ignores every request.
    let stuck =
        Program { path: "/bin/sh".into(), arguments: vec!["-c".into(), "sleep 600".into()], scratch_root: dir.path().join("scratch") };
    let (run, updates) = start(&stuck, &path);
    let begun = std::time::Instant::now();
    run.cancel();
    assert_eq!(outcome(&updates).0, Update::Cancelled);
    let took = begun.elapsed();
    assert!(took >= aa_app::run::CANCEL_GRACE && took < aa_app::run::CANCEL_GRACE + Duration::from_secs(5), "{took:?}");
    drop(run);
    assert_eq!(entries(&stuck.scratch_root), 0);
}

#[test]
fn a_run_that_cannot_be_done_fails_with_the_reason() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (run, updates) = start(&program(dir.path()), &dir.path().join("missing.bin"));
    let (last, _) = outcome(&updates);
    assert!(matches!(&last, Update::Failed(message) if message.contains("missing.bin")), "{last:?}");
    drop(run);

    // A worker that dies without a word; the stand-in is a shell command.
    if !cfg!(unix) {
        return;
    }
    let dying = Program { path: "/bin/sh".into(), arguments: vec!["-c".into(), "exit 7".into()], scratch_root: dir.path().join("scratch") };
    let (run, updates) = start(&dying, &dir.path().join("missing.bin"));
    let (last, _) = outcome(&updates);
    assert!(matches!(&last, Update::Failed(message) if message.contains('7')), "{last:?}");
    drop(run);
    assert_eq!(entries(&dying.scratch_root), 0);

    let nowhere = Program { path: "/no/such/program".into(), arguments: Vec::new(), scratch_root: dir.path().join("scratch") };
    assert!(Run::start(&nowhere, &dir.path().join("x"), LimitOverrides::default(), |_| {}).is_err());
}

#[test]
fn every_format_is_written_and_a_folder_verifies() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (path, _) = sample(dir.path());
    let report = direct(&path);
    let out = dir.path().join("out");
    let kinds: Vec<Kind> = Kind::ALL.into_iter().filter(|kind| kind.available()).collect();
    let mut asked = kinds.clone();
    asked.push(Kind::Json);
    let written = export::write_folder(&report, &out, &asked, Lang::En, &[]).expect("write");
    assert_eq!(written.len(), kinds.len() + 1, "each kind once, then the manifest");
    for kind in &kinds {
        let bytes = std::fs::read(out.join(kind.file_name())).expect("the file");
        assert_eq!(bytes, export::render(&report, *kind, Lang::En, &[]).expect("render"), "{kind:?}");
        assert_eq!(Kind::from_id(kind.id()), Some(*kind));
        assert!(kind.file_name().ends_with(kind.extension()));
    }
    assert!(aa_export::manifest::verify(&out).expect("a manifest").intact());
    // The JSON is the report, and reads back as the same report.
    assert_eq!(export::load(&out.join("report.json")).expect("load"), report);
    assert_eq!(Kind::from_id("exe"), None);

    std::fs::write(out.join("old.json"), br#"{"schema_version":1}"#).expect("write");
    assert!(export::load(&out.join("old.json")).is_err());
}

#[test]
fn history_keeps_reports_newest_first_and_forgets_on_request() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (path, _) = sample(dir.path());
    let report = direct(&path);
    let history = History::open(&dir.path().join("history")).expect("open");
    assert!(history.list().is_empty());

    let at = |seconds| UNIX_EPOCH + Duration::from_secs(seconds);
    let first = history.add(&report, Some(&path), at(1_795_132_800)).expect("add");
    let second = history.add(&report, None, at(1_795_132_800)).expect("add");
    let third = history.add(&report, Some(&path), at(1_795_132_900)).expect("add");
    assert_eq!((first.id.as_str(), second.id.as_str(), third.id.as_str()), ("20261120-000000", "20261120-000000-1", "20261120-000140"));
    assert_eq!(
        history.list().iter().map(|e| e.id.as_str()).collect::<Vec<_>>(),
        [third.id.as_str(), second.id.as_str(), first.id.as_str()]
    );

    assert_eq!(first.name, "sample.zip");
    assert_eq!(first.sha256, report.input.sha256);
    assert_eq!(first.source.as_deref(), Some(path.to_string_lossy().as_ref()));
    assert_eq!(first.artifacts, 3);
    assert_eq!(first.high + first.medium + first.low + first.info, report.findings.len() as u64);
    assert!(!first.partial);
    assert_eq!(history.entry(&first.id).expect("entry"), first);

    // What is kept is the report and its manifest, and nothing of the input.
    assert_eq!(history.load(&first.id).expect("load"), report);
    let folder = dir.path().join("history").join(&first.id);
    let mut names: Vec<String> =
        std::fs::read_dir(&folder).expect("list").flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    assert_eq!(names, ["entry.json", "manifest.json", "report.json"]);
    assert!(aa_export::manifest::verify(&folder).is_ok());
    // The time is in the entry only: the kept report is the bytes the command line would write.
    assert_eq!(
        std::fs::read(folder.join("report.json")).expect("read"),
        export::render(&report, Kind::Json, Lang::Zh, &[]).expect("render")
    );

    history.remove(&second.id).expect("remove");
    assert!(matches!(history.load(&second.id), Err(HistoryError::Unknown(_))));
    assert!(matches!(history.remove(&second.id), Err(HistoryError::Unknown(_))));
    assert_eq!(history.list().len(), 2);
    assert_eq!(history.clear().expect("clear"), 2);
    assert!(history.list().is_empty());
}

#[test]
fn history_refuses_names_it_did_not_make_and_reports_it_cannot_read() {
    let dir = tempfile::tempdir().expect("temp dir");
    let (path, _) = sample(dir.path());
    let root = dir.path().join("history");
    let history = History::open(&root).expect("open");
    std::fs::write(dir.path().join("secret"), b"outside").expect("write");
    for id in ["", "..", "../secret", "a/b", "/etc", "A", "x.y", &"a".repeat(65)] {
        assert!(matches!(history.load(id), Err(HistoryError::Unknown(_))), "{id:?}");
        assert!(matches!(history.remove(id), Err(HistoryError::Unknown(_))), "{id:?}");
    }
    assert!(dir.path().join("secret").exists());

    // A report in a layout this version does not read: listed, but opening says why not.
    let entry = history.add(&direct(&path), None, SystemTime::now()).expect("add");
    std::fs::write(root.join(&entry.id).join("report.json"), br#"{"schema_version":1}"#).expect("write");
    assert!(matches!(history.load(&entry.id), Err(HistoryError::Unreadable(_))));
    assert_eq!(history.list().len(), 1);
    // Stray folders and an entry that names another folder are not listed.
    std::fs::create_dir(root.join("stray")).expect("mkdir");
    std::fs::create_dir(root.join("copied")).expect("mkdir");
    std::fs::copy(root.join(&entry.id).join("entry.json"), root.join("copied").join("entry.json")).expect("copy");
    assert_eq!(history.list().len(), 1);
}
