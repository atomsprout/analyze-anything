//! `analyze-anything selftest`: analyzes samples built into the program and compares the results with values
//! recorded when the samples were made. It shows that this build, on this machine, unpacks,
//! hashes, analyzes and renders as intended, without needing any file from the user.

use aa_core::Report;
use aa_engine::{NoProgress, Options, Registry, analyze_bytes};
use aa_report::{Format, Lang};

/// The same two files packed three ways. Their digests are those `sha256sum` printed for the
/// originals when the archives were made (see crates/aa-unpack/tests/data/README.md).
const SAMPLES: &[(&str, &str, &[u8])] = &[
    ("sample.zip", "sample.zip", include_bytes!("../../aa-unpack/tests/data/sample.zip")),
    ("sample.tar.gz", "sample.tar.gz/sample.tar", include_bytes!("../../aa-unpack/tests/data/sample.tar.gz")),
    ("sample.7z", "sample.7z", include_bytes!("../../aa-unpack/tests/data/sample.7z")),
];
const TEXT_SHA256: &str = "a013aeaf2dce832ec132dfbce6afcb4e1a6a6b72a50f76e4a6fe0885b2a7d4e7";
const BINARY_SHA256: &str = "9a2ef41ddd562fadaa764d10516043d58caf9f5e0b14cd3ff5ac4ff30ab3be11";

fn sha256(report: &Report, path: &str) -> Option<String> {
    report.artifacts.iter().find(|a| a.path == path).and_then(|a| a.digests.as_ref()).map(|d| d.sha256.clone())
}

/// One named check and whether it held.
fn check(failures: &mut u32, name: &str, held: bool) {
    println!("{} {name}", if held { "ok  " } else { "FAIL" });
    if !held {
        *failures += 1;
    }
}

pub fn run() -> Result<u8, String> {
    let registry = Registry::standard();
    let mut failures = 0;
    let mut last = None;
    for (name, root, bytes) in SAMPLES {
        let report = analyze_bytes(&registry, name, bytes.to_vec(), &Options::default(), &mut NoProgress);
        check(
            &mut failures,
            &format!("{name}: text file unpacks to the recorded bytes"),
            sha256(&report, &format!("{root}/a.txt")).as_deref() == Some(TEXT_SHA256),
        );
        check(
            &mut failures,
            &format!("{name}: binary file unpacks to the recorded bytes"),
            sha256(&report, &format!("{root}/sub/b.bin")).as_deref() == Some(BINARY_SHA256),
        );
        check(&mut failures, &format!("{name}: nothing was lost"), report.limitations.is_empty() && report.coverage.content_lost == 0);
        let again = analyze_bytes(&registry, name, bytes.to_vec(), &Options::default(), &mut NoProgress);
        check(
            &mut failures,
            &format!("{name}: a second run gives the same report"),
            serde_json::to_string(&report).ok() == serde_json::to_string(&again).ok(),
        );
        last = Some(report);
    }
    if let Some(report) = last {
        check(
            &mut failures,
            "the host written in the text file is found",
            report.summary.get("content.hosts").is_some_and(|h| h["hosts"][0]["host"] == "example.com"),
        );
        let every_rule_has_text = report.findings.iter().all(|f| report.rules.contains_key(&f.rule));
        check(&mut failures, "every finding has its rule text", every_rule_has_text && !report.findings.is_empty());
        let mut formats = vec![("JSON", Format::Json), ("Markdown", Format::Markdown), ("text", Format::Text), ("HTML", Format::Html)];
        if cfg!(feature = "pdf") {
            formats.push(("PDF", Format::Pdf));
        }
        for (name, format) in formats {
            let rendered = aa_report::render(&report, format, Lang::Zh);
            let same = rendered.as_ref().ok() == aa_report::render(&report, format, Lang::Zh).as_ref().ok();
            check(
                &mut failures,
                &format!("{name} renders, the same bytes each time"),
                rendered.is_ok_and(|bytes| !bytes.is_empty()) && same,
            );
        }
    }
    if failures == 0 {
        println!("selftest passed");
        Ok(0)
    } else {
        Err(format!("selftest: {failures} checks failed"))
    }
}
