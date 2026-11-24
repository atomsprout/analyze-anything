//! Bounded SVR4 newc/crc directories. Links never become host filesystem links.

use std::collections::BTreeMap;

use aa_core::plugin::{Analyzer, Output, Rule, SinkError, Tree, Unpack, UnpackSink, Unpacker};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::json;

use crate::{MAX_ENTRIES, MAX_METADATA, Result, align, extent, number};

pub struct Cpio;
type ResolvedLinks = BTreeMap<(u32, u32, u32), Result<(usize, usize)>>;

const RULES: &[Rule] = &[
    Rule {
        id: "cpio.contents",
        title_en: "CPIO contents",
        title_zh: "CPIO 内容",
        text_en: "The CPIO directory declares {count} entries. Regular-file bytes were offered to the analysis tree; links and special files were not created.",
        text_zh: "CPIO 目录声明了 {count} 个条目。普通文件字节交给分析树读取，没有创建链接或特殊文件。",
    },
    Rule {
        id: "cpio.entry-unread",
        title_en: "CPIO entry could not be read",
        title_zh: "CPIO 条目无法读取",
        text_en: "An entry could not be retained within the supported CPIO profile.",
        text_zh: "一个条目无法在受支持的 CPIO 范围内保留。",
    },
    Rule {
        id: "cpio.special-file",
        title_en: "CPIO special-file semantics remain unresolved",
        title_zh: "CPIO 特殊文件语义未确定",
        text_en: "A link or special-file declaration was retained as metadata. No target was followed or special file created.",
        text_zh: "链接或特殊文件声明作为元数据保留，没有跟随目标或创建特殊文件。",
    },
    Rule {
        id: "cpio.directory-unread",
        title_en: "CPIO directory could not be read",
        title_zh: "CPIO 目录无法读取",
        text_en: "The archive was recognized, but its complete directory could not be retained.",
        text_zh: "已识别此归档，但无法保留完整目录。",
    },
];

struct Entry {
    name: String,
    header: usize,
    offset: usize,
    size: usize,
    mode: u32,
    inode: u32,
    device: (u32, u32),
    links: u32,
    crc: bool,
}

struct Directory {
    entries: Vec<Entry>,
    end: usize,
}

fn recognized(bytes: &[u8]) -> bool {
    bytes.starts_with(b"070701") || bytes.starts_with(b"070702") || bytes.starts_with(b"07070X")
}

fn parse(bytes: &[u8]) -> Result<Directory> {
    let mut at = 0usize;
    let mut names = 0usize;
    let mut entries = Vec::new();
    loop {
        let header = extent(bytes, at, 110)?;
        if &header[..6] != b"070701" && &header[..6] != b"070702" {
            return Err("only SVR4 newc/crc CPIO is supported; old ASCII and RPM 07070X profiles remain unread".into());
        }
        let mut fields = [0u32; 13];
        for (index, value) in fields.iter_mut().enumerate() {
            *value = number(&header[6 + index * 8..14 + index * 8], 16)?;
        }
        let name_size = fields[11] as usize;
        if name_size == 0 || name_size > 4096 {
            return Err("CPIO name exceeds the 4096-byte profile or has no terminator".into());
        }
        names = names.checked_add(name_size).ok_or("CPIO directory size overflow")?;
        if names > MAX_METADATA || entries.len() >= MAX_ENTRIES {
            return Err("CPIO directory budget exhausted".into());
        }
        let raw_name = extent(bytes, at + 110, name_size)?;
        let end_name = raw_name.iter().position(|byte| *byte == 0).ok_or("CPIO name is not terminated")?;
        if raw_name[end_name..].iter().any(|byte| *byte != 0) {
            return Err("CPIO name has data after its terminator".into());
        }
        let name = std::str::from_utf8(&raw_name[..end_name]).map_err(|_| "CPIO name is not UTF-8")?.to_string();
        let offset = align(at + 110 + name_size, 4)?;
        let size = fields[6] as usize;
        let data = extent(bytes, offset, size)?;
        let next = align(offset.checked_add(size).ok_or("CPIO entry overflow")?, 4)?;
        extent(bytes, offset + size, next - offset - size)?;
        if &header[..6] == b"070702" {
            let checksum = data.iter().fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte)));
            if checksum != fields[12] {
                return Err(format!("CPIO byte-sum mismatch at header {at}"));
            }
        } else if fields[12] != 0 {
            return Err("nonzero checksum in newc entry".into());
        }
        if name == "TRAILER!!!" {
            if size != 0 {
                return Err("CPIO trailer carries data".into());
            }
            if bytes[next..].iter().any(|byte| *byte != 0) {
                return Err("concatenated CPIO archives or nonzero trailing data are outside this profile".into());
            }
            return Ok(Directory { entries, end: next });
        }
        if name.is_empty() || fields[4] == 0 {
            return Err("CPIO entry has an empty name or zero link count".into());
        }
        let kind = fields[1] & 0o170000;
        if kind != 0o100000 && kind != 0o120000 && size != 0 {
            return Err("CPIO non-file entry has a data body".into());
        }
        entries.push(Entry {
            name,
            header: at,
            offset,
            size,
            mode: fields[1],
            inode: fields[0],
            device: (fields[7], fields[8]),
            links: fields[4],
            crc: &header[..6] == b"070702",
        });
        at = next;
    }
}

/// A hardlink group can carry its bytes in its last member. Resolve only an unambiguous
/// body shared by the complete declared group; missing aliases remain explicit gaps.
fn hardlinks(directory: &Directory) -> BTreeMap<(u32, u32, u32), Vec<usize>> {
    let mut groups: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for (index, entry) in directory.entries.iter().enumerate() {
        if entry.mode & 0o170000 == 0o100000 && entry.links > 1 {
            groups.entry((entry.device.0, entry.device.1, entry.inode)).or_default().push(index);
        }
    }
    groups
}

fn body<'a>(entry: &'a Entry, resolved: &ResolvedLinks, bytes: &'a [u8]) -> Result<&'a [u8]> {
    if entry.links == 1 {
        return extent(bytes, entry.offset, entry.size);
    }
    let &(offset, size) = resolved
        .get(&(entry.device.0, entry.device.1, entry.inode))
        .ok_or("missing CPIO hardlink group")?
        .as_ref()
        .map_err(Clone::clone)?;
    extent(bytes, offset, size)
}

fn resolve_group(group: &[usize], directory: &Directory, bytes: &[u8]) -> Result<(usize, usize)> {
    let entry = &directory.entries[group[0]];
    if group.len() != entry.links as usize || group.iter().any(|index| directory.entries[*index].links != entry.links) {
        return Err("incomplete or inconsistent CPIO hardlink group".into());
    }
    let mut found: Option<(usize, usize)> = None;
    for index in group {
        let candidate = &directory.entries[*index];
        if candidate.size != 0 {
            let value = extent(bytes, candidate.offset, candidate.size)?;
            if found.is_some_and(|(offset, size)| &bytes[offset..offset + size] != value) {
                return Err("CPIO hardlink group has conflicting data bodies".into());
            }
            found = Some((candidate.offset, candidate.size));
        }
    }
    Ok(found.unwrap_or((entry.offset, 0)))
}

impl Unpacker for Cpio {
    fn id(&self) -> &'static str {
        "cpio"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        if !recognized(bytes) {
            return Unpack::NotMine;
        }
        let directory = match parse(bytes) {
            Ok(directory) => directory,
            Err(detail) => return Unpack::Failed { kind: "cpio", detail },
        };
        let resolved = hardlinks(&directory).into_iter().map(|(key, group)| (key, resolve_group(&group, &directory, bytes))).collect();
        for entry in &directory.entries {
            match entry.mode & 0o170000 {
                0o100000 => match body(entry, &resolved, bytes) {
                    Ok(mut data) => match sink.add(&entry.name, &mut data) {
                        Ok(()) => {}
                        Err(SinkError::LimitReached) => break,
                        Err(SinkError::Read(detail)) => sink.limitation("cpio.entry-unread", Some(format!("{}: {detail}", entry.name))),
                    },
                    Err(detail) => sink.limitation("cpio.entry-unread", Some(format!("{}: {detail}", entry.name))),
                },
                0o040000 => {}
                _ => {}
            }
        }
        Unpack::Done { kind: "cpio" }
    }
}

impl Analyzer for Cpio {
    fn id(&self) -> &'static str {
        "cpio"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn analyze_file(&self, tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        if file.unpacked_by.as_deref() != Some("cpio") {
            return;
        }
        let bytes = match tree.read(&file.path) {
            Ok(bytes) => bytes,
            Err(error) => {
                out.limitation("cpio.directory-unread", Some(file), Some(error.to_string()));
                return;
            }
        };
        let directory = match parse(&bytes) {
            Ok(value) => value,
            Err(detail) => {
                out.limitation("cpio.directory-unread", Some(file), Some(detail));
                return;
            }
        };
        let mut entries = Vec::new();
        for entry in &directory.entries {
            let kind = entry.mode & 0o170000;
            let target = if kind == 0o120000 {
                if entry.size > 4096 {
                    out.limitation("cpio.special-file", Some(file), Some(format!("{}: link target exceeds 4096 bytes", entry.name)));
                    None
                } else {
                    match std::str::from_utf8(&bytes[entry.offset..entry.offset + entry.size])
                        .map_err(|_| "CPIO link target is not UTF-8")
                        .and_then(aa_core::text::redact_sensitive_text)
                    {
                        Ok(value) => Some(value),
                        Err(detail) => {
                            out.limitation("cpio.special-file", Some(file), Some(detail.into()));
                            None
                        }
                    }
                }
            } else {
                None
            };
            if kind != 0o100000 && kind != 0o040000 {
                out.limitation("cpio.special-file", Some(file), Some(format!("{}: mode {:o}", entry.name, entry.mode)));
            }
            entries.push(json!({"path": entry.name, "header_offset": entry.header, "offset": entry.offset, "stored_size": entry.size,
                "mode": entry.mode, "inode": entry.inode, "device": [entry.device.0, entry.device.1], "links": entry.links,
                "byte_sum_checked": entry.crc, "link_target": target}));
        }
        out.fact(file, "cpio.directory", json!({"entries": entries, "end": directory.end}));
        out.finding(
            Finding::new(Section::Structure, "cpio", "cpio.contents", Confidence::Verified, Severity::Info)
                .param("count", directory.entries.len())
                .evidence(Evidence::bytes(file, 0, directory.end as u64, json!({"entry_count": directory.entries.len()}))),
        );
    }
}
