use aa_core::{Artifact, Report};
use aa_engine::{NoProgress, Options, Registry, analyze_bytes};

fn analyze(name: &str, bytes: &[u8]) -> Report {
    let report = analyze_bytes(&Registry::standard(), name, bytes.to_vec(), &Options::default(), &mut NoProgress);
    let again = analyze_bytes(&Registry::standard(), name, bytes.to_vec(), &Options::default(), &mut NoProgress);
    assert_eq!(report, again, "image analysis must be deterministic");
    for finding in &report.findings {
        assert!(!finding.evidence.is_empty(), "{} needs source evidence", finding.rule);
        for evidence in &finding.evidence {
            assert!(report.artifacts.iter().any(|file| file.path == evidence.artifact), "{}", evidence.artifact);
        }
    }
    report
}

fn root(report: &Report) -> &Artifact {
    report.artifacts.iter().find(|file| file.parent.is_none()).expect("image root")
}

#[test]
fn real_xz_snap_reaches_metadata_components_payload_and_source_relationships() {
    let bytes = include_bytes!("../../aa-linux/tests/data/upstream-hello-world-29.snap");
    assert_eq!(aa_core::sha256_hex(bytes), "a14a4c44b085499d45f4182388b941fc9d5d87c5fe04f7405e087f52da61c407");
    let report = analyze("hello-world.snap", bytes);
    let package = root(&report);
    assert_eq!(package.kind.as_deref(), Some("snap"));
    assert_eq!(package.unpacked_by.as_deref(), Some("squashfs"));
    let identity = &package.facts["snap.package"];
    let native: serde_json::Value = serde_json::from_str(include_str!("../../aa-linux/tests/data/linux-images-native.ref.json"))
        .expect("recorded Linux native comparison");
    let reference = native["samples"]
        .as_array()
        .expect("native samples")
        .iter()
        .find(|sample| sample["file"] == "upstream-hello-world-29.snap")
        .expect("hash-bound snap reference");
    assert_eq!(reference["sha256"], aa_core::sha256_hex(bytes));
    let entries = package.facts["squashfs.directory"]["entries"].as_array().expect("captured directory");
    let expected = reference["native_entries"].as_array().expect("native directory");
    assert_eq!(entries.len(), expected.len());
    for entry in expected {
        let path = entry["path"].as_str().expect("native path");
        let captured = entries.iter().find(|captured| captured["path"] == path).expect("native path is captured");
        assert_eq!(captured["uid"], entry["uid"]);
        assert_eq!(captured["gid"], entry["gid"]);
        if let Some(hash) = entry["sha256"].as_str() {
            let file = report.artifacts.iter().find(|file| file.path == format!("hello-world.snap/{path}")).expect("regular file");
            assert_eq!(file.size, entry["size"].as_u64().expect("native file size"));
            assert_eq!(file.digests.as_ref().expect("regular file digests").sha256, hash);
        }
    }
    assert_eq!(identity["name"], "hello-world");
    assert_eq!(identity["version"], "6.4");
    assert_eq!(identity["source"], "hello-world.snap/meta/snap.yaml");
    assert_eq!(identity["references"].as_array().expect("command references").len(), 4);
    for row in identity["references"].as_array().expect("command references") {
        assert_eq!(row["status"], "matched-supplied-declaration");
        let target = report.artifacts.iter().find(|file| Some(file.path.as_str()) == row["target"].as_str()).expect("captured command");
        assert_eq!(row["target_sha256"], target.digests.as_ref().expect("captured bytes").sha256);
    }
    let components = report.summary["composition.components"]["components"].as_array().expect("component list");
    let component = components.iter().find(|row| row["ecosystem"] == "snap").expect("snap component");
    assert_eq!(component["name"], "hello-world");
    assert_eq!(component["version"], "6.4");
    assert_eq!(component["manifest"]["path"], identity["source"]);
    assert_eq!(component["manifest"]["sha256"], identity["source_sha256"]);
    assert!(report.findings.iter().any(|finding| finding.rule == "overview.kind-snap"));
    assert!(report.limitations.iter().any(|limit| limit.code == "snap.runtime-unchecked"));
}

#[test]
fn constructed_filesystem_and_type2_appimage_reach_semantic_report_without_execution() {
    let filesystem = appdir();
    let plain = analyze("fixture.squashfs", &filesystem);
    assert_eq!(root(&plain).unpacked_by.as_deref(), Some("squashfs"));
    assert!(plain.findings.iter().any(|finding| finding.rule == "overview.kind-squashfs"));
    assert!(!plain.summary.contains_key("composition.components"));

    let mut image = vec![0; 128];
    image[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    image[8..11].copy_from_slice(b"AI\x02");
    put16(&mut image, 16, 2);
    put16(&mut image, 18, 62);
    put32(&mut image, 20, 1);
    put64(&mut image, 40, 64);
    put16(&mut image, 52, 64);
    put16(&mut image, 58, 64);
    put16(&mut image, 60, 1);
    image.extend(filesystem);
    let report = analyze("fixture.AppImage", &image);
    let app = root(&report);
    assert_eq!(app.kind.as_deref(), Some("appimage"));
    assert_eq!(app.unpacked_by.as_deref(), Some("appimage"));
    assert_eq!(app.facts["appimage.identity"]["name"], "Fixture App");
    assert!(app.facts["appimage.identity"]["version"].is_null());
    assert_eq!(app.facts["appimage.entry"]["status"], "matched-supplied-declaration");
    assert_eq!(app.facts["appimage.entry"]["target"], "fixture.AppImage/[filesystem].squashfs/AppRun");
    let components = report.summary["composition.components"]["components"].as_array().expect("components");
    let component = components.iter().find(|row| row["ecosystem"] == "appimage").expect("AppImage component");
    assert_eq!(component["name"], "Fixture App");
    assert!(component["version"].is_null(), "Desktop Entry Version is not a software release version");
    assert!(report.findings.iter().any(|finding| finding.rule == "overview.kind-appimage"));
    assert!(report.limitations.iter().any(|limit| limit.code == "appimage.version-unresolved"));
}

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}
fn meta(bytes: &mut Vec<u8>, contents: &[u8]) -> usize {
    let start = bytes.len();
    bytes.extend((0x8000 | contents.len() as u16).to_le_bytes());
    bytes.extend(contents);
    start
}

/// A tiny filesystem uses uncompressed blocks under the gzip profile. Its AppRun is inert data.
fn appdir() -> Vec<u8> {
    let mut bytes = vec![0; 96];
    let mut inodes = Vec::new();
    let mut directory = vec![0; 12];
    put32(&mut directory, 0, 1);
    put32(&mut directory, 8, 2);
    for (index, name, contents) in [
        (0u16, "AppRun", b"inert AppRun fixture\n".as_slice()),
        (1, "fixture.desktop", b"[Desktop Entry]\nType=Application\nName=Fixture App\nVersion=1.0\nExec=AppRun\n".as_slice()),
    ] {
        let data_offset = bytes.len();
        bytes.extend(contents);
        let inode_offset = inodes.len();
        let mut inode = vec![0; 32];
        put16(&mut inode, 0, 2);
        put16(&mut inode, 2, 0o755);
        put32(&mut inode, 12, u32::from(index) + 2);
        put32(&mut inode, 16, data_offset as u32);
        put32(&mut inode, 20, u32::MAX);
        put32(&mut inode, 28, contents.len() as u32);
        inode.extend((0x0100_0000 | contents.len() as u32).to_le_bytes());
        inodes.extend(inode);
        let entry = directory.len();
        directory.resize(entry + 8, 0);
        put16(&mut directory, entry, inode_offset as u16);
        put16(&mut directory, entry + 2, index);
        put16(&mut directory, entry + 4, 2);
        put16(&mut directory, entry + 6, name.len() as u16 - 1);
        directory.extend(name.as_bytes());
    }
    let root_offset = inodes.len();
    let mut root = vec![0; 32];
    put16(&mut root, 0, 1);
    put16(&mut root, 2, 0o755);
    put32(&mut root, 12, 1);
    put32(&mut root, 20, 2);
    put16(&mut root, 24, directory.len() as u16 + 3);
    put32(&mut root, 28, 1);
    inodes.extend(root);
    let inode_table = meta(&mut bytes, &inodes);
    let directory_table = meta(&mut bytes, &directory);
    let id_pointer = meta(&mut bytes, &0u32.to_le_bytes());
    let id_table = bytes.len();
    bytes.extend((id_pointer as u64).to_le_bytes());
    let used = bytes.len();
    bytes[..4].copy_from_slice(b"hsqs");
    put32(&mut bytes, 4, 3);
    put32(&mut bytes, 12, 4096);
    put16(&mut bytes, 20, 1);
    put16(&mut bytes, 22, 12);
    put16(&mut bytes, 26, 1);
    put16(&mut bytes, 28, 4);
    put64(&mut bytes, 32, root_offset as u64);
    put64(&mut bytes, 40, used as u64);
    put64(&mut bytes, 48, id_table as u64);
    put64(&mut bytes, 56, u64::MAX);
    put64(&mut bytes, 64, inode_table as u64);
    put64(&mut bytes, 72, directory_table as u64);
    put64(&mut bytes, 80, u64::MAX);
    put64(&mut bytes, 88, u64::MAX);
    bytes
}
