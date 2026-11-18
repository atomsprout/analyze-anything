//! The unpackers: disk images, xar archives, and cpio payloads.

use std::io::Read;

use aa_core::Artifact;
use aa_core::plugin::{Rule, SinkError, Unpack, UnpackSink, Unpacker};

use crate::disk::{self, Disk, VolumeKind, apfs, hfs, udif};
use crate::pkg;

/// Unreadable files named one by one in limitations before the rest are only counted.
const NAMED_FAILURES: usize = 20;

pub struct Dmg;

const DMG_RULES: &[Rule] = &[
    Rule {
        id: "dmg.encrypted",
        title_zh: "磁盘映像已加密",
        title_en: "Encrypted disk image",
        text_zh: "磁盘映像用密码加密，没有密码无法读取其中的任何内容，因此里面的文件没有分析。",
        text_en: "The disk image is encrypted with a password. Nothing inside can be read without it, so its files were not analyzed.",
    },
    Rule {
        id: "dmg.no-filesystem",
        title_zh: "磁盘映像中没有可读取的文件系统",
        title_en: "No readable file system in the disk image",
        text_zh: "磁盘映像的容器已解开，但其中没有找到本工具能读取的文件系统（支持 HFS+/HFSX 与未加密的 APFS），因此里面的文件没有分析。",
        text_en: "The image container was opened, but no file system this tool reads (HFS+/HFSX, unencrypted APFS) was found in it, so its files were not analyzed.",
    },
    Rule {
        id: "dmg.volume-unreadable",
        title_zh: "磁盘映像中的卷无法读取",
        title_en: "A volume of the disk image could not be read",
        text_zh: "磁盘映像中有一个卷无法读取（已加密、已损坏，或用到了本工具不支持的结构），该卷里的文件没有分析。",
        text_en: "One volume of the disk image could not be read (encrypted, damaged, or using structures this tool does not support). Its files were not analyzed.",
    },
    Rule {
        id: "dmg.volume-incomplete",
        title_zh: "卷的文件目录只读出了一部分",
        title_en: "A volume's file catalog was read only in part",
        text_zh: "卷的文件目录有损坏或超出限额，只读出了一部分；没读到的文件没有分析。",
        text_en: "The volume's catalog is damaged or over a limit and was read only in part. Files not reached were not analyzed.",
    },
    Rule {
        id: "dmg.file-unreadable",
        title_zh: "磁盘映像中的文件无法读取",
        title_en: "Files in the disk image could not be read",
        text_zh: "卷的目录列出了这些文件，但它们的数据无法读出（数据块损坏、压缩方式不支持等），因此没有分析。",
        text_en: "The volume lists these files, but their data could not be read (damaged blocks, unsupported compression, …), so they were not analyzed.",
    },
];

/// Reports unreadable files: the first few by name, the rest as a count.
#[derive(Default)]
struct Failures {
    count: usize,
}

impl Failures {
    fn add(&mut self, sink: &mut dyn UnpackSink, path: &str, reason: &str) {
        self.count += 1;
        if self.count <= NAMED_FAILURES {
            sink.limitation("dmg.file-unreadable", Some(format!("{path}: {reason}")));
        }
    }

    fn finish(&self, sink: &mut dyn UnpackSink) {
        if self.count > NAMED_FAILURES {
            sink.limitation("dmg.file-unreadable", Some(format!("{} more files", self.count - NAMED_FAILURES)));
        }
    }
}

/// Adds one file to the sink. `false` means the sink's limit was reached.
fn emit(sink: &mut dyn UnpackSink, failures: &mut Failures, path: &str, opened: Result<Box<dyn Read + '_>, String>) -> bool {
    match opened {
        Ok(mut reader) => !matches!(sink.add(path, &mut reader), Err(SinkError::LimitReached)),
        Err(reason) => {
            failures.add(sink, path, &reason);
            true
        }
    }
}

/// Extracts every volume found on `disk`. Returns how many volumes were opened, or `None`
/// once the sink's limit stops everything.
fn extract(disk: &dyn Disk, label: &str, many: bool, sink: &mut dyn UnpackSink, failures: &mut Failures) -> Option<usize> {
    let mut opened = 0;
    for (start, length, kind) in disk::find_volumes(disk) {
        let part = disk::SubDisk { inner: disk, start, length };
        match kind {
            VolumeKind::HfsPlus => match hfs::Volume::open(&part) {
                Ok(volume) => {
                    opened += 1;
                    if let Some(damage) = &volume.damage {
                        sink.limitation("dmg.volume-incomplete", Some(format!("{label}: {damage}")));
                    }
                    let prefix =
                        if many { format!("{}/", volume.name.clone().unwrap_or_else(|| label.to_string())) } else { String::new() };
                    for file in volume.files.iter().filter(|f| !f.is_symlink()) {
                        if !emit(sink, failures, &format!("{prefix}{}", file.path), volume.open_file(file)) {
                            return None;
                        }
                    }
                }
                Err(reason) => sink.limitation("dmg.volume-unreadable", Some(format!("{label} (HFS+): {reason}"))),
            },
            VolumeKind::Apfs => match apfs::open(&part) {
                Ok((volumes, skipped)) => {
                    for skip in skipped {
                        sink.limitation("dmg.volume-unreadable", Some(format!("{} (APFS): {}", skip.name, skip.reason)));
                    }
                    let many = many || volumes.len() > 1;
                    for volume in &volumes {
                        opened += 1;
                        if let Some(damage) = &volume.damage {
                            sink.limitation("dmg.volume-incomplete", Some(format!("{}: {damage}", volume.name)));
                        }
                        let prefix = if many { format!("{}/", volume.name) } else { String::new() };
                        for file in volume.files.iter().filter(|f| !f.is_symlink()) {
                            if !emit(sink, failures, &format!("{prefix}{}", file.path), volume.open_file(file)) {
                                return None;
                            }
                        }
                    }
                }
                Err(reason) => sink.limitation("dmg.volume-unreadable", Some(format!("{label} (APFS): {reason}"))),
            },
        }
    }
    Some(opened)
}

impl Unpacker for Dmg {
    fn id(&self) -> &'static str {
        "dmg"
    }

    fn rules(&self) -> &'static [Rule] {
        DMG_RULES
    }

    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        if let Some(scheme) = udif::encryption(bytes) {
            let version = if scheme == udif::Encryption::V2 { 2 } else { 1 };
            sink.limitation("dmg.encrypted", Some(format!("encrypted image format version {version}")));
            return Unpack::Done { kind: "dmg" };
        }
        let mut failures = Failures::default();
        let Some(koly) = udif::koly(bytes) else {
            // A bare file system or partitioned disk without the UDIF wrapper.
            let raw = disk::RawDisk(bytes);
            if disk::find_volumes(&raw).is_empty() {
                return Unpack::NotMine;
            }
            extract(&raw, "disk", false, sink, &mut failures);
            failures.finish(sink);
            return Unpack::Done { kind: "disk-image" };
        };
        let tables = match udif::tables(bytes, &koly) {
            Ok(tables) => tables,
            Err(detail) => return Unpack::Failed { kind: "dmg", detail },
        };
        // Partitions that hold a file system this crate reads.
        let partitions: Vec<udif::Partition<'_>> = tables.iter().map(|table| udif::Partition::new(bytes, table)).collect();
        let with_volumes = partitions.iter().filter(|p| !disk::find_volumes(*p).is_empty()).count();
        let mut opened = 0;
        let mut foreign = Vec::new();
        for partition in &partitions {
            if let Some(name) = disk::foreign_filesystem(partition) {
                foreign.push(format!("{}: {name}", partition.table.name));
            }
            match extract(partition, &partition.table.name, with_volumes > 1, sink, &mut failures) {
                Some(count) => opened += count,
                None => {
                    failures.finish(sink);
                    return Unpack::Done { kind: "dmg" };
                }
            }
        }
        failures.finish(sink);
        if with_volumes == 0 {
            let detail = if foreign.is_empty() { None } else { Some(foreign.join("; ")) };
            sink.limitation("dmg.no-filesystem", detail);
        } else if opened == 0 {
            return Unpack::Failed { kind: "dmg", detail: "no volume of the image could be opened".into() };
        }
        Unpack::Done { kind: "dmg" }
    }
}

pub struct XarArchive;

const XAR_RULES: &[Rule] = &[
    Rule {
        id: "xar.entry-unreadable",
        title_zh: "xar 归档中的文件无法读取",
        title_en: "Entries of the xar archive could not be read",
        text_zh: "归档的目录列出了这些文件，但它们的数据无法解出（编码方式不支持或数据越界），因此没有分析。",
        text_en: "The archive lists these entries, but their data could not be decoded (unsupported encoding, or data outside the file), so they were not analyzed.",
    },
    Rule {
        id: "xar.checksum-mismatch",
        title_zh: "xar 归档中的文件校验和不符",
        title_en: "Entry checksum mismatch in xar archive",
        text_zh: "这些文件解出后的校验和与归档目录中记录的不一致，说明归档损坏或被改动过。文件仍按解出的内容分析。",
        text_en: "The checksum of these entries, once extracted, differs from the one the archive records: the archive is damaged or was altered. The entries were still analyzed as extracted.",
    },
    Rule {
        id: "xar.listing-truncated",
        title_zh: "xar 归档的目录过大",
        title_en: "The xar table of contents is too large",
        text_zh: "归档目录中的条目数超过上限，只处理了前面的一部分。",
        text_en: "The archive lists more entries than this tool reads; only the first ones were processed.",
    },
];

impl Unpacker for XarArchive {
    fn id(&self) -> &'static str {
        "xar"
    }

    fn rules(&self) -> &'static [Rule] {
        XAR_RULES
    }

    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        if !pkg::is_xar(bytes) {
            return Unpack::NotMine;
        }
        let archive = match pkg::xar(bytes) {
            Ok(archive) => archive,
            Err(detail) => return Unpack::Failed { kind: "xar", detail },
        };
        if archive.truncated {
            sink.limitation("xar.listing-truncated", None);
        }
        let mut unreadable = Vec::new();
        let mut mismatched = Vec::new();
        for file in &archive.files {
            match archive.open(bytes, file) {
                Ok(reader) => {
                    let mut checked = pkg::Checked::new(reader, file.extracted_checksum.as_ref());
                    match sink.add(&file.path, &mut checked) {
                        Ok(()) => {
                            // The sink may stop at exactly the last byte; one more read sees the end.
                            let _ = checked.read(&mut [0u8; 1]);
                            if checked.mismatch {
                                mismatched.push(file.path.clone());
                            }
                        }
                        Err(SinkError::Read(_)) => {}
                        Err(SinkError::LimitReached) => break,
                    }
                }
                Err(reason) => unreadable.push(format!("{}: {reason}", file.path)),
            }
        }
        for (code, list) in [("xar.entry-unreadable", unreadable), ("xar.checksum-mismatch", mismatched)] {
            if !list.is_empty() {
                let shown = list.iter().take(NAMED_FAILURES).cloned().collect::<Vec<_>>().join("; ");
                let more = list.len().saturating_sub(NAMED_FAILURES);
                sink.limitation(code, Some(if more > 0 { format!("{shown}; and {more} more") } else { shown }));
            }
        }
        Unpack::Done { kind: "xar" }
    }
}

/// cpio archives, bare or behind the compressions installer packages use (gzip, bzip2, pbzx).
/// A compressed stream that is not a cpio archive is left to the generic unpackers, except
/// pbzx, which nothing else opens.
pub struct Payload;

fn starts_with_cpio(reader: &mut dyn Read) -> bool {
    let mut magic = [0u8; 6];
    reader.read_exact(&mut magic).is_ok() && pkg::is_cpio(&magic)
}

impl Unpacker for Payload {
    fn id(&self) -> &'static str {
        "cpio"
    }

    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        let (kind, mut reader): (&'static str, Box<dyn Read + '_>) = if pkg::is_cpio(bytes) {
            ("cpio", Box::new(bytes))
        } else if bytes.starts_with(&[0x1f, 0x8b, 0x08]) {
            if !starts_with_cpio(&mut flate2::read::MultiGzDecoder::new(bytes)) {
                return Unpack::NotMine;
            }
            ("cpio-gzip", Box::new(flate2::read::MultiGzDecoder::new(bytes)))
        } else if bytes.starts_with(b"BZh") {
            if !starts_with_cpio(&mut bzip2::read::MultiBzDecoder::new(bytes)) {
                return Unpack::NotMine;
            }
            ("cpio-bzip2", Box::new(bzip2::read::MultiBzDecoder::new(bytes)))
        } else if let Some(mut probe) = pkg::Pbzx::new(bytes) {
            if !starts_with_cpio(&mut probe) {
                // Some other content: hand it on whole, as one child.
                let Some(mut stream) = pkg::Pbzx::new(bytes) else { return Unpack::NotMine };
                return match sink.add("content", &mut stream) {
                    Ok(()) | Err(SinkError::LimitReached) => Unpack::Done { kind: "pbzx" },
                    Err(SinkError::Read(detail)) => Unpack::Failed { kind: "pbzx", detail },
                };
            }
            match pkg::Pbzx::new(bytes) {
                Some(stream) => ("cpio-pbzx", Box::new(stream)),
                None => return Unpack::NotMine,
            }
        } else {
            return Unpack::NotMine;
        };
        match pkg::cpio(&mut reader, sink) {
            Ok(_) => Unpack::Done { kind },
            Err(detail) => Unpack::Failed { kind, detail },
        }
    }
}
