mod support;

use aa_core::Artifact;
use aa_core::plugin::{SinkError, Unpack, UnpackSink};
use std::collections::BTreeMap;
use std::io::Read;

fn file() -> Artifact {
    Artifact {
        path: "fixture.deb".into(),
        parent: None,
        size: 0,
        digests: None,
        detected: None,
        kind: None,
        entropy: None,
        unpacked_by: None,
        facts: BTreeMap::new(),
    }
}

#[derive(Default)]
struct Sink {
    files: Vec<(String, Vec<u8>)>,
    limitations: Vec<String>,
}
impl UnpackSink for Sink {
    fn add(&mut self, path: &str, data: &mut dyn Read) -> Result<(), SinkError> {
        let mut bytes = Vec::new();
        data.read_to_end(&mut bytes).expect("read test member");
        self.files.push((path.into(), bytes));
        Ok(())
    }
    fn limitation(&mut self, code: &str, _detail: Option<String>) {
        self.limitations.push(code.into());
    }
}
fn unpack(id: &str, bytes: &[u8]) -> (Unpack, Sink) {
    let unpacker = aa_linux::unpackers().into_iter().find(|unpacker| unpacker.id() == id).expect("registered unpacker");
    let mut sink = Sink::default();
    let result = unpacker.unpack(&file(), bytes, &mut sink);
    (result, sink)
}

#[test]
fn deb_exposes_separate_original_members() {
    let bytes = support::deb(support::CONTROL, b"data");
    let (result, sink) = unpack("deb", &bytes);
    assert_eq!(result, Unpack::Done { kind: "deb" });
    assert_eq!(sink.files.iter().map(|file| file.0.as_str()).collect::<Vec<_>>(), ["debian-binary", "control.tar", "data.tar"]);
    assert!(sink.limitations.is_empty());
}

#[test]
fn deb_rejects_ambiguous_members_versions_and_lengths_before_extraction() {
    let tar = support::tar(&[("control", support::CONTROL)]);
    for bytes in [
        support::ar(&[("debian-binary", b"3.0\n"), ("control.tar", &tar), ("data.tar", &tar)]),
        support::ar(&[("debian-binary", b"2.0\n"), ("data.tar", &tar), ("control.tar", &tar)]),
        support::ar(&[("debian-binary", b"2.0\n"), ("control.tar", &tar), ("data.tar", &tar), ("control.tar.gz", &tar)]),
    ] {
        let (result, sink) = unpack("deb", &bytes);
        assert!(matches!(result, Unpack::Failed { .. }));
        assert!(sink.files.is_empty());
    }
    let mut bytes = support::deb(support::CONTROL, b"data");
    bytes[56..66].copy_from_slice(b"9999999999");
    assert!(matches!(unpack("deb", &bytes).0, Unpack::Failed { .. }));
}

#[test]
fn cpio_resolves_complete_hardlink_groups_with_a_late_body_without_creating_links() {
    let mut bytes = Vec::new();
    support::cpio_entry(&mut bytes, "a", b"", 0o100644, 7, 2, true);
    support::cpio_entry(&mut bytes, "b", b"shared", 0o100644, 7, 2, true);
    support::cpio_entry(&mut bytes, "link", b"/etc/shadow", 0o120777, 8, 1, true);
    support::cpio_entry(&mut bytes, "TRAILER!!!", b"", 0, 0, 1, false);
    let (result, sink) = unpack("cpio", &bytes);
    assert_eq!(result, Unpack::Done { kind: "cpio" });
    assert_eq!(sink.files, [("a".into(), b"shared".to_vec()), ("b".into(), b"shared".to_vec())]);
}

#[test]
fn cpio_reports_incomplete_hardlinks_and_refuses_corrupt_crc_or_trailing_archives() {
    let mut bytes = Vec::new();
    support::cpio_entry(&mut bytes, "alias", b"", 0o100644, 7, 2, true);
    support::cpio_entry(&mut bytes, "TRAILER!!!", b"", 0, 0, 1, false);
    let (result, sink) = unpack("cpio", &bytes);
    assert_eq!(result, Unpack::Done { kind: "cpio" });
    assert_eq!(sink.limitations, ["cpio.entry-unread"]);
    assert!(sink.files.is_empty());
    let mut crc = Vec::new();
    support::cpio_entry(&mut crc, "body", b"abc", 0o100644, 1, 1, true);
    support::cpio_entry(&mut crc, "TRAILER!!!", b"", 0, 0, 1, false);
    crc[116] = b'x';
    assert!(matches!(unpack("cpio", &crc).0, Unpack::Failed { .. }));
    let mut appended = support::cpio();
    appended.extend(support::cpio());
    assert!(matches!(unpack("cpio", &appended).0, Unpack::Failed { .. }));
    assert!(matches!(unpack("cpio", b"07070X00000000").0, Unpack::Failed { .. }));
}

#[test]
fn rpm_exposes_the_declared_payload_without_running_script_tags() {
    for compressor in ["none", "gzip"] {
        let bytes = support::rpm(compressor, Vec::new());
        let (result, sink) = unpack("rpm", &bytes);
        assert_eq!(result, Unpack::Done { kind: "rpm" });
        assert_eq!(sink.files.len(), 1);
        assert!(sink.limitations.is_empty());
    }
    let (result, sink) = unpack("rpm", &support::rpm("lz4", Vec::new()));
    assert_eq!(result, Unpack::Done { kind: "rpm" });
    assert_eq!(sink.limitations, ["rpm.payload-unread"]);
    assert!(sink.files.is_empty());
    let (result, sink) = unpack("rpm", &support::rpm("none", vec![(5114, 4, 6u32.to_be_bytes().to_vec(), 1)]));
    assert_eq!(result, Unpack::Done { kind: "rpm" });
    assert_eq!(sink.limitations, ["rpm.payload-unread"]);
}

#[test]
fn rpm_checks_counts_offsets_types_and_string_terminators_before_extraction() {
    let bytes = support::rpm("none", Vec::new());
    for (offset, bad) in [(120, u32::MAX), (124, u32::MAX), (132, 99), (136, u32::MAX), (140, u32::MAX)] {
        let mut corrupted = bytes.clone();
        corrupted[offset..offset + 4].copy_from_slice(&bad.to_be_bytes());
        let (result, sink) = unpack("rpm", &corrupted);
        assert!(matches!(result, Unpack::Failed { .. }), "offset {offset}");
        assert!(sink.files.is_empty());
    }
    let (result, _) = unpack("rpm", &support::rpm("none", vec![(2000, 6, b"unterminated".to_vec(), 1)]));
    assert!(matches!(result, Unpack::Failed { .. }));
}

#[test]
fn every_short_prefix_fails_without_partial_members_or_panics() {
    for (id, bytes) in
        [("deb", support::deb(support::CONTROL, b"data")), ("rpm", support::rpm("none", Vec::new())), ("cpio", support::cpio())]
    {
        let minimum = if id == "rpm" {
            4
        } else if id == "cpio" {
            6
        } else {
            24
        };
        for end in minimum..bytes.len() {
            let (result, sink) = unpack(id, &bytes[..end]);
            // RPM payload bytes can be truncated after a complete header; the CPIO reader
            // then reports the truncated member when that child reaches it.
            if id != "rpm" {
                assert!(matches!(result, Unpack::Failed { .. }), "{id}: prefix {end}");
                assert!(sink.files.is_empty());
            }
        }
    }
}
