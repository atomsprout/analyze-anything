//! ZIP archives, which also covers IPA, APK, JAR, and Office documents.

use std::io::Cursor;

use aa_core::Artifact;
use aa_core::plugin::{Rule, SinkError, Unpack, UnpackSink, Unpacker};

pub struct Zip;

const RULES: &[Rule] = &[
    Rule {
        id: "zip.entry-encrypted",
        title_zh: "压缩包内有加密文件",
        title_en: "Encrypted entries in archive",
        text_zh: "压缩包里有需要密码才能解开的文件，这些文件没有分析。",
        text_en: "The archive holds entries that need a password. They were not analyzed.",
    },
    Rule {
        id: "zip.entry-names-duplicated",
        title_zh: "ZIP 中央目录包含同名条目",
        title_en: "Repeated entry names in ZIP central directory",
        text_zh: "ZIP 中央目录重复使用了条目名称。当前 ZIP 读取库没有保留这些条目的所有版本；条目枚举不完整，未据此建立名称唯一的文件关联。",
        text_en: "The ZIP central directory repeats entry names. The ZIP reader did not retain every version of those entries. Enumeration is incomplete, so name-unique file relationships were not established.",
    },
];

impl Unpacker for Zip {
    fn id(&self) -> &'static str {
        "zip"
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        // A local file header, or the end-of-central-directory record of an empty archive.
        if !(bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06")) {
            return Unpack::NotMine;
        }
        let mut archive = match ::zip::ZipArchive::new(Cursor::new(bytes)) {
            Ok(archive) => archive,
            Err(error) => return Unpack::Failed { kind: "zip", detail: error.to_string() },
        };
        // ZipArchive indexes names rather than every directory record. Do not let
        // a collapsed duplicate make a supplied-file lookup appear unambiguous.
        if archive.has_duplicate_names() {
            sink.limitation("zip.entry-names-duplicated", None);
        }
        let mut encrypted = 0u64;
        let mut failures: Vec<String> = Vec::new();
        for index in 0..archive.len() {
            let mut entry = match archive.by_index(index) {
                Ok(entry) => entry,
                Err(::zip::result::ZipError::UnsupportedArchive(reason)) if reason.contains("Password") => {
                    encrypted += 1;
                    continue;
                }
                Err(error) => {
                    failures.push(format!("entry {index}: {error}"));
                    continue;
                }
            };
            if entry.is_dir() {
                continue;
            }
            let name = String::from_utf8_lossy(entry.name_raw()).into_owned();
            match sink.add(&name, &mut entry) {
                Ok(()) | Err(SinkError::Read(_)) => {}
                Err(SinkError::LimitReached) => break,
            }
        }
        if encrypted > 0 {
            sink.limitation("zip.entry-encrypted", Some(aa_core::counted(encrypted, "encrypted entries")));
        }
        if failures.is_empty() {
            Unpack::Done { kind: "zip" }
        } else {
            let shown = failures.iter().take(5).cloned().collect::<Vec<_>>().join("; ");
            Unpack::Failed { kind: "zip", detail: format!("{} entries could not be opened: {shown}", failures.len()) }
        }
    }
}
