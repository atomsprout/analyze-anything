//! Verify that actual parsed declarations reach the report index without inventing resolution.

use std::io::{Cursor, Write};

use aa_engine::{NoProgress, Options, Registry, analyze_bytes};
use aa_report::{Format, Lang, render};

fn input(targets: &[&str]) -> Vec<u8> {
    let mut shortcut = vec![0; 76];
    shortcut[..20].copy_from_slice(&[0x4c, 0, 0, 0, 1, 0x14, 2, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46]);
    shortcut[20..24].copy_from_slice(&0x88u32.to_le_bytes());
    shortcut[60..64].copy_from_slice(&1u32.to_le_bytes());
    let relative: Vec<u16> = "target.txt".encode_utf16().collect();
    shortcut.extend(u16::try_from(relative.len()).expect("short fixture name").to_le_bytes());
    for unit in relative {
        shortcut.extend(unit.to_le_bytes());
    }
    shortcut.extend([0; 4]);
    let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    archive.start_file("launch.lnk", options).expect("shortcut member");
    archive.write_all(&shortcut).expect("shortcut bytes");
    archive.start_file("native.lnk", options).expect("native shortcut member");
    archive.write_all(include_bytes!("../../aa-windows/tests/data/native.lnk")).expect("existing licensed native fixture");
    for target in targets {
        archive.start_file(*target, options).expect("target member");
        archive.write_all(b"supplied bytes only").expect("target content");
    }
    archive.finish().expect("finish archive").into_inner()
}

#[test]
fn supplied_missing_and_ambiguous_targets_survive_analysis_and_rendering() {
    let registry = Registry::standard();
    for (targets, matched) in [(&["target.txt"][..], true), (&[][..], false), (&["target.txt", "TARGET.txt"][..], false)] {
        let bytes = input(targets);
        let report = analyze_bytes(&registry, "software.zip", bytes.clone(), &Options::default(), &mut NoProgress);
        let indexed = aa_report::relationships::collect(&report);
        let row = indexed.rows.iter().find(|row| row.source == "software.zip/launch.lnk").expect("parsed reference");
        assert_eq!(row.location, "RelativePath");
        assert_eq!(row.declaration, "target.txt");
        if matched {
            assert_eq!(row.status, "matched-supplied-declaration");
            assert_eq!(row.target.as_deref(), Some("software.zip/target.txt"));
            assert_eq!(row.target_sha256.as_deref(), Some(aa_core::sha256_hex(b"supplied bytes only").as_str()));
        } else {
            assert_eq!(row.status, "unresolved");
            assert!(row.target.is_none());
            assert!(row.reason.is_some());
        }
        assert!(indexed.rows.iter().any(|row| row.source == "software.zip/native.lnk" && row.status == "unresolved"));
        let again = analyze_bytes(&registry, "software.zip", bytes, &Options::default(), &mut NoProgress);
        assert_eq!(serde_json::to_vec(&report).expect("report JSON"), serde_json::to_vec(&again).expect("repeated JSON"));
        for lang in [Lang::En, Lang::Zh] {
            for format in [Format::Markdown, Format::Text, Format::Html] {
                let rendered = String::from_utf8(render(&report, format, lang).expect("render relationship")).expect("UTF-8");
                assert!(rendered.contains("RelativePath"));
                assert!(rendered.contains(&row.status));
            }
        }
    }
}
