//! Windows filesystem fixtures stay under private temporary roots; nothing is executed from them.
#![cfg(windows)]

use aa_engine::{NoProgress, Options, analyze};

#[test]
fn junctions_are_not_followed_as_roots_children_or_ancestors() {
    let dir = tempfile::tempdir().expect("private fixture root");
    let input = dir.path().join("input");
    let outside = dir.path().join("outside");
    std::fs::create_dir(&input).expect("input folder");
    std::fs::create_dir(&outside).expect("external fixture folder");
    std::fs::write(outside.join("secret.txt"), "must remain unread").expect("external fixture data");
    std::fs::write(input.join("中文 file.txt"), "visible").expect("ordinary fixture data");
    let link = input.join("junction");
    let status = std::process::Command::new("cmd")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&link)
        .arg(&outside)
        .output()
        .expect("Windows junction fixture command");
    assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
    let report = analyze(&input, &Options::default(), &mut NoProgress).expect("ordinary input root");
    assert_eq!(report.artifacts.len(), 1);
    assert_eq!(report.artifacts[0].path, "中文 file.txt");
    assert!(report.coverage.content_lost > 0);
    let skipped = report.limitations.iter().find(|l| l.code == "engine.local-content-skipped").expect("junction limitation");
    assert_eq!(skipped.artifact.as_deref(), Some("junction"));
    assert!(report.rules.contains_key(&skipped.code));
    assert!(analyze(&link, &Options::default(), &mut NoProgress).is_err());
    assert!(analyze(&link.join("secret.txt"), &Options::default(), &mut NoProgress).is_err());
    assert_eq!(std::fs::read_to_string(outside.join("secret.txt")).expect("unchanged fixture"), "must remain unread");
}

#[test]
fn named_streams_are_refused_and_hardlinks_remain_ordinary_files() {
    let dir = tempfile::tempdir().expect("private fixture root");
    let file = dir.path().join("original.txt");
    std::fs::write(&file, "ordinary data").expect("write fixture");
    let stream = dir.path().join("original.txt:extra");
    std::fs::write(&stream, "separate stream data").expect("write NTFS stream fixture");
    assert!(analyze(&stream, &Options::default(), &mut NoProgress).is_err());
    std::fs::hard_link(&file, dir.path().join("alias.txt")).expect("hardlink fixture");
    let report = analyze(dir.path(), &Options::default(), &mut NoProgress).expect("local folder");
    assert_eq!(report.artifacts.len(), 2);
    assert_eq!(report.artifacts[0].digests, report.artifacts[1].digests);
}

#[test]
fn long_unicode_paths_are_read_and_locked_content_is_reported() {
    use std::os::windows::fs::OpenOptionsExt;
    let dir = tempfile::tempdir().expect("private fixture root");
    let mut deep = dir.path().to_path_buf();
    for _ in 0..20 {
        deep.push("long-name-中文");
    }
    std::fs::create_dir_all(&deep).expect("long path fixture");
    let file = deep.join("visible.txt");
    std::fs::write(&file, "local text").expect("long path content");
    let report = analyze(&file, &Options::default(), &mut NoProgress).expect("long Unicode path");
    assert!(report.artifacts[0].digests.is_some());
    let locked_path = dir.path().join("locked.txt");
    std::fs::write(&locked_path, "exclusive content").expect("locked fixture data");
    let held = std::fs::OpenOptions::new().read(true).share_mode(0).open(&locked_path).expect("exclusive read handle");
    let report = analyze(dir.path(), &Options::default(), &mut NoProgress).expect("folder remains readable");
    assert!(report.coverage.content_lost > 0);
    assert!(report.limitations.iter().any(|l| l.artifact.as_deref() == Some("locked.txt")));
    assert!(report.artifacts.iter().filter(|a| a.path == "locked.txt").all(|a| a.digests.is_none()));
    drop(held);
}
