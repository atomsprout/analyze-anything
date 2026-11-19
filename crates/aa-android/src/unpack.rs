//! Opens Android packages the generic ZIP unpacker cannot.
//!
//! Android reads an APK from its central directory and is lenient in ways ZIP tools are not, and
//! malware lives in the gap:
//!
//! - The file may start with anything. The Janus technique puts a DEX in front; a tool that
//!   looks for `PK` at offset 0 sees no archive.
//! - A compression method other than 8 (deflate) is treated as "stored", using the uncompressed
//!   size, whatever the method and compressed-size fields say. Entries with a bogus method
//!   ("BadPack") stop ZIP libraries cold.
//! - The encryption flag is ignored; a ZIP library asks for a password.
//!
//! A file with one of these traits and an `AndroidManifest.xml` in its central directory is
//! opened here the way the platform reads it, so that the package inside gets analyzed. Ordinary
//! APKs are left to the generic unpacker.

use aa_core::Artifact;
use aa_core::plugin::{SinkError, Unpack, UnpackSink, Unpacker};

use crate::zipraw;

pub struct OddApk;

impl Unpacker for OddApk {
    fn id(&self) -> &'static str {
        "android-zip"
    }

    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        // Every file of the tree is offered here, so the cheap test comes first: an end record
        // within the last 64 KiB that ends the file.
        if zipraw::find_eocd(bytes).is_none() {
            return Unpack::NotMine;
        }
        let Some(archive) = zipraw::parse(bytes) else { return Unpack::NotMine };
        if archive.entry("AndroidManifest.xml").is_none() {
            return Unpack::NotMine;
        }
        let prefixed = !(bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06"));
        let odd_entries = archive.entries.iter().any(|e| !matches!(e.method, 0 | 8) || e.flags & 1 != 0);
        if !prefixed && !odd_entries {
            return Unpack::NotMine;
        }
        let mut failures: Vec<String> = Vec::new();
        for entry in &archive.entries {
            if entry.name.ends_with('/') {
                continue;
            }
            // The sink enforces the size limits on what is read.
            let result = match entry.android_data(bytes) {
                Ok((true, data)) => sink.add(&entry.name, &mut flate2::read::DeflateDecoder::new(data)),
                Ok((false, mut data)) => sink.add(&entry.name, &mut data),
                Err(why) => {
                    failures.push(format!("{}: {why}", entry.name));
                    continue;
                }
            };
            match result {
                Ok(()) | Err(SinkError::Read(_)) => {}
                Err(SinkError::LimitReached) => break,
            }
        }
        if failures.is_empty() {
            Unpack::Done { kind: "zip" }
        } else {
            let shown = failures.iter().take(5).cloned().collect::<Vec<_>>().join("; ");
            Unpack::Failed { kind: "zip", detail: format!("{} entries could not be opened: {shown}", failures.len()) }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    #[derive(Default)]
    struct Collect {
        files: Vec<(String, Vec<u8>)>,
    }

    impl UnpackSink for Collect {
        fn add(&mut self, path: &str, data: &mut dyn Read) -> Result<(), SinkError> {
            let mut content = Vec::new();
            data.read_to_end(&mut content).map_err(|e| SinkError::Read(e.to_string()))?;
            self.files.push((path.to_string(), content));
            Ok(())
        }

        fn limitation(&mut self, _code: &str, _detail: Option<String>) {}
    }

    fn artifact() -> Artifact {
        Artifact {
            path: "x.apk".into(),
            parent: None,
            size: 0,
            digests: None,
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: Default::default(),
        }
    }

    #[test]
    fn opens_a_janus_file_and_leaves_ordinary_zips_alone() {
        let janus = std::fs::read(format!("{}/tests/data/v1-janus.apk", env!("CARGO_MANIFEST_DIR"))).expect("fixture");
        let mut sink = Collect::default();
        assert_eq!(OddApk.unpack(&artifact(), &janus, &mut sink), Unpack::Done { kind: "zip" });
        let names: Vec<&str> = sink.files.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"AndroidManifest.xml") && names.contains(&"classes.dex") && names.contains(&"META-INF/MANIFEST.MF"));
        // Deflated entries come out whole: the manifest is binary XML again.
        let manifest = &sink.files.iter().find(|(n, _)| n == "AndroidManifest.xml").expect("manifest").1;
        assert!(crate::axml::looks_like_axml(manifest));

        let ordinary = std::fs::read(format!("{}/tests/data/v1.apk", env!("CARGO_MANIFEST_DIR"))).expect("fixture");
        let mut sink = Collect::default();
        assert_eq!(OddApk.unpack(&artifact(), &ordinary, &mut sink), Unpack::NotMine);
        // A prefixed archive that is not an Android package is not claimed either.
        let other = zipraw::tests::build_zip(b"junk", &[("readme.txt", b"hi")]);
        assert_eq!(OddApk.unpack(&artifact(), &other, &mut sink), Unpack::NotMine);
        assert_eq!(OddApk.unpack(&artifact(), b"", &mut sink), Unpack::NotMine);
        assert!(sink.files.is_empty());
    }

    /// A stored manifest whose method and compressed size are garbage, and an entry flagged as
    /// encrypted: Android reads both; so does this unpacker, and the analyzer reports the trick.
    #[test]
    fn opens_entries_with_bogus_method_and_encryption_flag() {
        let fixture = |name: &str| std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).expect("fixture");
        let manifest = fixture("AndroidManifest.bin");
        let dex = fixture("classes.dex");
        let mut apk = zipraw::tests::build_zip(
            b"",
            &[("AndroidManifest.xml", &manifest), ("classes.dex", &dex), ("resources.arsc", &fixture("resources.arsc"))],
        );
        let archive = zipraw::parse(&apk).expect("zip");
        let (first, second) = (archive.entries[0].clone(), archive.entries[1].clone());
        // Method 0x1d2a and a wrong compressed size on the manifest, in both headers.
        for (at, method_at, size_at) in [(first.local_offset as usize, 8, 18), (first.cd_offset as usize, 10, 20)] {
            apk[at + method_at..at + method_at + 2].copy_from_slice(&0x1d2au16.to_le_bytes());
            apk[at + size_at..at + size_at + 4].copy_from_slice(&7u32.to_le_bytes());
        }
        // The encryption flag on classes.dex.
        for (at, flags_at) in [(second.local_offset as usize, 6), (second.cd_offset as usize, 8)] {
            apk[at + flags_at] |= 1;
        }
        let mut sink = Collect::default();
        assert_eq!(OddApk.unpack(&artifact(), &apk, &mut sink), Unpack::Done { kind: "zip" });
        assert_eq!(sink.files[0], ("AndroidManifest.xml".to_string(), manifest));
        assert_eq!(sink.files[1], ("classes.dex".to_string(), dex));
    }

    #[test]
    fn damaged_input_does_not_panic() {
        let janus = std::fs::read(format!("{}/tests/data/v1-janus.apk", env!("CARGO_MANIFEST_DIR"))).expect("fixture");
        for cut in (0..janus.len()).step_by(211) {
            let _ = OddApk.unpack(&artifact(), &janus[..cut], &mut Collect::default());
        }
        let start = janus.len() - 1200;
        for position in (start..janus.len()).step_by(3) {
            let mut bad = janus.clone();
            bad[position] = 0xff;
            let _ = OddApk.unpack(&artifact(), &bad, &mut Collect::default());
        }
    }
}
