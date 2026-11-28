//! SquashFS v4 directories and stored files, with bounded metadata and decompression.
//! No filesystem is mounted, and symlinks, devices and xattrs remain declarations.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::sync::Arc;

use aa_core::plugin::{Analyzer, Output, Rule, SinkError, Tree, Unpack, UnpackSink, Unpacker};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::json;

use crate::{MAX_ENTRIES, MAX_METADATA, Result, extent};

pub struct Squashfs;
const MAX_BLOCK: usize = 1024 * 1024;
const MAX_FILE: u64 = 256 * 1024 * 1024;
const MAX_BLOCKS: usize = 262_144;
const MAX_DECODED: usize = 512 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 16 * 1024 * 1024;
const NONE: u64 = u64::MAX;

const RULES: &[Rule] = &[
    Rule {
        id: "squashfs.contents",
        title_en: "SquashFS contents",
        title_zh: "SquashFS 内容",
        text_en: "The SquashFS v4 directory contains {count} entries. Supported regular-file bytes were read without mounting the filesystem or running its contents.",
        text_zh: "SquashFS v4 目录包含 {count} 个条目。读取了受支持的普通文件字节，没有挂载文件系统或运行其中内容。",
    },
    Rule {
        id: "squashfs.directory-unread",
        title_en: "SquashFS directory could not be read",
        title_zh: "SquashFS 目录无法读取",
        text_en: "The filesystem metadata was malformed, exceeded a bounded profile or used an unsupported version or compressor.",
        text_zh: "文件系统元数据格式错误、超出受限范围，或使用不受支持的版本或压缩方式。",
    },
    Rule {
        id: "squashfs.entry-unread",
        title_en: "SquashFS file bytes could not be read",
        title_zh: "SquashFS 文件字节无法读取",
        text_en: "A file's declarations were retained, but its bytes could not be read within the supported block, size or decompression profile.",
        text_zh: "保留了一个文件的声明，但无法在受支持的块、大小或解压范围内读取其字节。",
    },
    Rule {
        id: "squashfs.special-file",
        title_en: "SquashFS links and special files remain declarations",
        title_zh: "SquashFS 链接与特殊文件仍为声明",
        text_en: "Symlink targets and special-file types are metadata. No target was followed, and no device, socket or FIFO was created.",
        text_zh: "符号链接目标和特殊文件类型作为元数据保留，没有跟随目标，也没有创建设备、套接字或 FIFO。",
    },
    Rule {
        id: "squashfs.metadata-scope",
        title_en: "SquashFS runtime and extended metadata remain unresolved",
        title_zh: "SquashFS 运行时与扩展元数据未确定",
        text_en: "Filesystem ownership and mode values are declarations. Extended attributes, ACL effects, export lookup semantics, mounting eligibility and runtime behavior were not established.",
        text_zh: "文件系统所有者和模式值是声明，没有确定扩展属性、ACL 效果、导出索引语义、挂载条件或运行时行为。",
    },
];

fn u16_at(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(extent(bytes, at, 2)?.try_into().map_err(|_| "short SquashFS u16")?))
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(extent(bytes, at, 4)?.try_into().map_err(|_| "short SquashFS u32")?))
}
fn u64_at(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(extent(bytes, at, 8)?.try_into().map_err(|_| "short SquashFS u64")?))
}
fn address(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| "SquashFS address exceeds address space".into())
}

#[derive(Clone)]
struct Super {
    inodes: u32,
    block: usize,
    fragments: usize,
    compression: u16,
    ids: usize,
    root: u64,
    used: usize,
    inode_table: usize,
    directory_table: usize,
    fragment_table: u64,
    id_table: usize,
    xattr_table: u64,
}
impl Super {
    fn parse(bytes: &[u8]) -> Result<Self> {
        extent(bytes, 0, 96)?;
        if !bytes.starts_with(b"hsqs") || u16_at(bytes, 28)? != 4 || u16_at(bytes, 30)? != 0 {
            return Err("only little-endian SquashFS v4.0 is supported".into());
        }
        let block = u32_at(bytes, 12)? as usize;
        if !(4096..=MAX_BLOCK).contains(&block) || !block.is_power_of_two() || u16_at(bytes, 22)? != block.ilog2() as u16 {
            return Err("SquashFS block size/log is invalid or exceeds 1 MiB".into());
        }
        let inodes = u32_at(bytes, 4)?;
        let fragments = u32_at(bytes, 16)? as usize;
        let compression = u16_at(bytes, 20)?;
        if !matches!(compression, 1 | 4) {
            return Err(format!("SquashFS compressor {compression} is outside the gzip/XZ profile"));
        }
        if inodes == 0 || inodes as usize > MAX_ENTRIES || fragments > MAX_ENTRIES {
            return Err("SquashFS inode or fragment count exceeds 100000".into());
        }
        let used = address(u64_at(bytes, 40)?)?;
        let inode_table = address(u64_at(bytes, 64)?)?;
        let directory_table = address(u64_at(bytes, 72)?)?;
        let id_table = address(u64_at(bytes, 48)?)?;
        let ids = u16_at(bytes, 26)? as usize;
        if used > bytes.len()
            || inode_table < 96
            || inode_table >= directory_table
            || directory_table >= used
            || id_table >= used
            || ids == 0
        {
            return Err("SquashFS table ordering or bytes_used is outside the captured image".into());
        }
        Ok(Self {
            inodes,
            block,
            fragments,
            compression,
            ids,
            root: u64_at(bytes, 32)?,
            used,
            inode_table,
            directory_table,
            fragment_table: u64_at(bytes, 80)?,
            id_table,
            xattr_table: u64_at(bytes, 56)?,
        })
    }
}

fn decode(data: &[u8], compression: u16, maximum: usize) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    match compression {
        1 => {
            let mut reader = flate2::read::ZlibDecoder::new(data);
            reader.by_ref().take(maximum as u64 + 1).read_to_end(&mut result).map_err(|error| error.to_string())?;
            if result.len() > maximum || reader.total_in() != data.len() as u64 {
                return Err("SquashFS zlib output or stream extent exceeds its block".into());
            }
        }
        4 => {
            // XZ dictionaries are checked before allocation, independently of the output cap.
            let mut reader = lzma_bounded::XzReader::new_mem_limit(Cursor::new(data), false, 32 * 1024);
            reader.by_ref().take(maximum as u64 + 1).read_to_end(&mut result).map_err(|error| error.to_string())?;
            if result.len() > maximum || reader.into_inner().position() != data.len() as u64 {
                return Err("SquashFS XZ output or stream extent exceeds its block".into());
            }
        }
        _ => return Err("unsupported SquashFS compression".into()),
    }
    Ok(result)
}

#[derive(Default)]
struct Metadata {
    blocks: BTreeMap<usize, (Vec<u8>, usize)>,
    decoded: usize,
}
impl Metadata {
    fn read(&mut self, bytes: &[u8], sb: &Super, mut block: usize, mut offset: usize, length: usize, end: usize) -> Result<Vec<u8>> {
        if offset >= 8192 || length > MAX_METADATA {
            return Err("SquashFS metadata offset or read exceeds its profile".into());
        }
        let mut result = Vec::new();
        while result.len() < length {
            if block < sb.inode_table || block >= end {
                return Err("SquashFS metadata pointer is outside its table".into());
            }
            if !self.blocks.contains_key(&block) {
                if self.blocks.len() >= 4096 {
                    return Err("SquashFS metadata block count exceeds 4096".into());
                }
                let header = u16_at(bytes, block)?;
                let size = (header & 0x7fff) as usize;
                if size == 0 || size > 8192 || block.checked_add(2 + size).is_none_or(|next| next > end) {
                    return Err("SquashFS metadata block extent is invalid".into());
                }
                let raw = extent(bytes, block + 2, size)?;
                let data = if header & 0x8000 != 0 { raw.to_vec() } else { decode(raw, sb.compression, 8192)? };
                self.decoded = self.decoded.checked_add(data.len()).ok_or("SquashFS metadata budget overflow")?;
                if data.is_empty() || self.decoded > MAX_METADATA {
                    return Err("SquashFS decoded metadata exceeds 16 MiB".into());
                }
                self.blocks.insert(block, (data, block + 2 + size));
            }
            let (data, next) = self.blocks.get(&block).ok_or("missing SquashFS metadata block")?;
            if *next > end || offset >= data.len() {
                return Err("SquashFS metadata cursor exceeds its decoded block".into());
            }
            let take = (length - result.len()).min(data.len() - offset);
            result.extend_from_slice(&data[offset..offset + take]);
            block = *next;
            offset = 0;
        }
        Ok(result)
    }
}

#[derive(Clone)]
struct Chunk {
    offset: Option<usize>,
    stored: usize,
    maximum: usize,
    start: usize,
    length: usize,
    compressed: bool,
    fragment: bool,
}
struct Entry {
    path: String,
    inode: u32,
    kind: &'static str,
    mode: u16,
    uid: u32,
    gid: u32,
    size: u64,
    target: Option<String>,
    chunks: Vec<Chunk>,
    unread: Option<String>,
    reference: u64,
}
struct Filesystem {
    sb: Super,
    entries: Vec<Entry>,
}

fn chunk(sb: &Super, offset: u64, word: u32, maximum: usize, start: usize, length: usize, fragment: bool) -> Result<Chunk> {
    if word >> 25 != 0 {
        return Err("SquashFS data size has unsupported flag bits".into());
    }
    let stored = (word & 0x00ff_ffff) as usize;
    let offset = address(offset)?;
    if stored > sb.block || stored != 0 && (offset < 96 || offset.checked_add(stored).is_none_or(|end| end > sb.inode_table)) {
        return Err("SquashFS data block extent is outside its data area".into());
    }
    if stored == 0 && fragment {
        return Err("SquashFS fragment has an empty stored block".into());
    }
    Ok(Chunk { offset: (stored != 0).then_some(offset), stored, maximum, start, length, compressed: word & 0x0100_0000 == 0, fragment })
}

fn parse(bytes: &[u8]) -> Result<Filesystem> {
    let sb = Super::parse(bytes)?;
    let bytes = &bytes[..sb.used];
    let mut metadata = Metadata::default();
    let mut ids = Vec::new();
    for index in 0..sb.ids.div_ceil(2048) {
        let pointer = address(u64_at(bytes, sb.id_table.checked_add(index * 8).ok_or("SquashFS id index overflow")?)?)?;
        if pointer >= sb.id_table {
            return Err("SquashFS id metadata does not precede its index".into());
        }
        let count = (sb.ids - ids.len()).min(2048);
        let raw = metadata.read(bytes, &sb, pointer, 0, count * 4, sb.id_table)?;
        for value in raw.chunks_exact(4) {
            ids.push(u32_at(value, 0)?);
        }
    }
    let mut fragments = Vec::new();
    if sb.fragments != 0 {
        let table = address(sb.fragment_table)?;
        for index in 0..sb.fragments.div_ceil(512) {
            let pointer = address(u64_at(bytes, table.checked_add(index * 8).ok_or("SquashFS fragment index overflow")?)?)?;
            if pointer >= table {
                return Err("SquashFS fragment metadata does not precede its index".into());
            }
            let count = (sb.fragments - fragments.len()).min(512);
            let raw = metadata.read(bytes, &sb, pointer, 0, count * 16, table)?;
            for value in raw.chunks_exact(16) {
                fragments.push((u64_at(value, 0)?, u32_at(value, 8)?));
            }
        }
    }
    let mut stack = vec![(String::new(), sb.root, 0usize, None, None)];
    let mut directories = BTreeSet::new();
    let mut inode_numbers = BTreeMap::new();
    let mut entries = Vec::new();
    let mut paths = BTreeSet::new();
    let mut path_bytes = 0usize;
    let mut block_count = 0usize;
    let mut directory_bytes = 0usize;
    while let Some((path, reference, depth, expected_type, expected_inode)) = stack.pop() {
        if entries.len() >= MAX_ENTRIES || depth > 64 {
            return Err("SquashFS path count or directory depth exceeds its profile".into());
        }
        let block = sb.inode_table.checked_add(address(reference >> 16)?).ok_or("SquashFS inode pointer overflow")?;
        let offset = (reference & 0xffff) as usize;
        let raw = metadata.read(bytes, &sb, block, offset, 16, sb.directory_table)?;
        let kind = u16_at(&raw, 0)?;
        let short_kind = if kind > 7 { kind - 7 } else { kind };
        if !matches!(kind, 1..=14) || expected_type.is_some_and(|expected| expected != short_kind) {
            return Err("SquashFS directory/inode type mismatch".into());
        }
        let inode = u32_at(&raw, 12)?;
        let uid = u16_at(&raw, 4)? as usize;
        let gid = u16_at(&raw, 6)? as usize;
        if inode == 0
            || inode > sb.inodes
            || uid >= ids.len()
            || gid >= ids.len()
            || expected_inode.is_some_and(|expected| expected != inode)
        {
            return Err("SquashFS inode, directory inode number or owner index is inconsistent".into());
        }
        if inode_numbers.insert(inode, reference).is_some_and(|previous| previous != reference) || path.is_empty() && !matches!(kind, 1 | 8)
        {
            return Err("SquashFS inode identity is repeated inconsistently or the root is not a directory".into());
        }
        let mut entry = Entry {
            path: path.clone(),
            inode,
            kind: "special",
            mode: u16_at(&raw, 2)?,
            uid: ids[uid],
            gid: ids[gid],
            size: 0,
            target: None,
            chunks: Vec::new(),
            unread: None,
            reference,
        };
        match kind {
            1 | 8 => {
                if !directories.insert(reference) {
                    return Err("SquashFS directory cycle or repeated directory reference".into());
                }
                let raw = metadata.read(bytes, &sb, block, offset, if kind == 1 { 32 } else { 40 }, sb.directory_table)?;
                let (start, size, dir_offset) = if kind == 1 {
                    (u32_at(&raw, 16)?, u16_at(&raw, 24)? as usize, u16_at(&raw, 26)? as usize)
                } else {
                    (u32_at(&raw, 24)?, u32_at(&raw, 20)? as usize, u16_at(&raw, 34)? as usize)
                };
                let size = size.checked_sub(3).ok_or("SquashFS directory size is below its bias")?;
                directory_bytes = directory_bytes.checked_add(size).ok_or("SquashFS directory budget overflow")?;
                if directory_bytes > MAX_METADATA {
                    return Err("SquashFS directory contents exceed 16 MiB".into());
                }
                let start = sb.directory_table.checked_add(start as usize).ok_or("SquashFS directory address overflow")?;
                let data = metadata.read(bytes, &sb, start, dir_offset, size, sb.used)?;
                let mut at = 0;
                while at < data.len() {
                    let count = u32_at(&data, at)? as usize;
                    let inode_block = u32_at(&data, at + 4)?;
                    let base_inode = u32_at(&data, at + 8)?;
                    if count >= 256 {
                        return Err("SquashFS directory header exceeds 256 entries".into());
                    }
                    at += 12;
                    for _ in 0..=count {
                        let child_offset = u16_at(&data, at)?;
                        let delta = u16_at(&data, at + 2)? as i16;
                        let child_type = u16_at(&data, at + 4)?;
                        let length = u16_at(&data, at + 6)? as usize + 1;
                        let number = i64::from(base_inode) + i64::from(delta);
                        if length > 256 || !(1..=7).contains(&child_type) || number <= 0 || number > i64::from(sb.inodes) {
                            return Err("SquashFS directory entry count, inode or name length is invalid".into());
                        }
                        let name = std::str::from_utf8(extent(&data, at + 8, length)?).map_err(|_| "SquashFS name is not UTF-8")?;
                        if name.is_empty()
                            || matches!(name, "." | "..")
                            || name.contains(['/', '\\', '\0'])
                            || name.chars().any(char::is_control)
                        {
                            return Err("SquashFS name is outside the literal path profile".into());
                        }
                        let child_path = if path.is_empty() { name.into() } else { format!("{path}/{name}") };
                        path_bytes = path_bytes.checked_add(child_path.len()).ok_or("SquashFS path budget overflow")?;
                        if child_path.len() > 4096
                            || path_bytes > MAX_PATH_BYTES
                            || stack.len() + entries.len() >= MAX_ENTRIES
                            || !paths.insert(child_path.clone())
                        {
                            return Err("SquashFS duplicate paths or path budget exceeded".into());
                        }
                        stack.push((
                            child_path,
                            (u64::from(inode_block) << 16) | u64::from(child_offset),
                            depth + 1,
                            Some(child_type),
                            Some(number as u32),
                        ));
                        at += 8 + length;
                    }
                }
                entry.kind = "directory";
            }
            2 | 9 => {
                entry.kind = "file";
                let header_size = if kind == 2 { 32 } else { 56 };
                let raw = metadata.read(bytes, &sb, block, offset, header_size, sb.directory_table)?;
                let (mut start, size, fragment, fragment_offset) = if kind == 2 {
                    (u64::from(u32_at(&raw, 16)?), u64::from(u32_at(&raw, 28)?), u32_at(&raw, 20)?, u32_at(&raw, 24)?)
                } else {
                    (u64_at(&raw, 16)?, u64_at(&raw, 24)?, u32_at(&raw, 44)?, u32_at(&raw, 48)?)
                };
                entry.size = size;
                let blocks = address(size / sb.block as u64 + u64::from(size % sb.block as u64 != 0 && fragment == u32::MAX))?;
                block_count = block_count.checked_add(blocks).ok_or("SquashFS file block count overflow")?;
                if size > MAX_FILE || block_count > MAX_BLOCKS {
                    entry.unread = Some("file exceeds 256 MiB or the shared 262144-block profile".into());
                } else {
                    let list = metadata.read(bytes, &sb, block, offset, header_size + blocks * 4, sb.directory_table)?;
                    for index in 0..blocks {
                        let word = u32_at(&list, header_size + index * 4)?;
                        let length = if index + 1 == blocks && fragment == u32::MAX && size % sb.block as u64 != 0 {
                            (size % sb.block as u64) as usize
                        } else {
                            sb.block
                        };
                        match chunk(&sb, start, word, length, 0, length, false) {
                            Ok(chunk) => {
                                start = start.checked_add(chunk.stored as u64).ok_or("SquashFS data offset overflow")?;
                                entry.chunks.push(chunk);
                            }
                            Err(error) => {
                                entry.unread = Some(error);
                                break;
                            }
                        }
                    }
                    if fragment != u32::MAX {
                        let tail = (size % sb.block as u64) as usize;
                        if tail == 0 {
                            entry.unread = Some("fragment declared for a file with no fragment tail".into());
                        } else if let Some(&(start, word)) = fragments.get(fragment as usize) {
                            match chunk(&sb, start, word, sb.block, fragment_offset as usize, tail, true) {
                                Ok(chunk) => entry.chunks.push(chunk),
                                Err(error) => entry.unread = Some(error),
                            }
                        } else {
                            entry.unread = Some("file fragment index exceeds its fragment table".into());
                        }
                    }
                }
            }
            3 | 10 => {
                entry.kind = "symlink";
                let raw = metadata.read(bytes, &sb, block, offset, 24, sb.directory_table)?;
                let length = u32_at(&raw, 20)? as usize;
                if length > 4096 {
                    entry.unread = Some("symlink target exceeds 4096 bytes".into());
                } else {
                    let raw = metadata.read(bytes, &sb, block, offset, 24 + length, sb.directory_table)?;
                    entry.target = Some(std::str::from_utf8(&raw[24..]).map_err(|_| "SquashFS symlink target is not UTF-8")?.to_string());
                    entry.size = length as u64;
                }
            }
            _ => {}
        }
        if !path.is_empty() {
            entries.push(entry);
        }
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(Filesystem { sb, entries })
}

#[derive(Default)]
struct DataBudget {
    decoded: usize,
    fragments: BTreeMap<(usize, usize), Arc<Vec<u8>>>,
    fragment_bytes: usize,
}
struct FileReader<'a> {
    bytes: &'a [u8],
    sb: &'a Super,
    chunks: &'a [Chunk],
    index: usize,
    current: Arc<Vec<u8>>,
    position: usize,
    end: usize,
    budget: &'a mut DataBudget,
}
impl FileReader<'_> {
    fn next(&mut self) -> Result<bool> {
        let Some(chunk) = self.chunks.get(self.index) else { return Ok(false) };
        self.index += 1;
        let key = (chunk.offset.unwrap_or(0), chunk.stored);
        let cached = chunk.fragment.then(|| self.budget.fragments.get(&key).cloned()).flatten();
        self.current = if let Some(data) = cached {
            data
        } else {
            self.budget.decoded = self.budget.decoded.checked_add(chunk.maximum).ok_or("SquashFS data budget overflow")?;
            if self.budget.decoded > MAX_DECODED {
                return Err("SquashFS decoded data exceeds 512 MiB".into());
            }
            let data = if let Some(offset) = chunk.offset {
                let raw = extent(self.bytes, offset, chunk.stored)?;
                if chunk.compressed { decode(raw, self.sb.compression, chunk.maximum)? } else { raw.to_vec() }
            } else {
                vec![0; chunk.maximum]
            };
            if !chunk.fragment && data.len() != chunk.maximum {
                return Err("SquashFS file block has the wrong decoded size".into());
            }
            let data = Arc::new(data);
            if chunk.fragment {
                self.budget.fragment_bytes =
                    self.budget.fragment_bytes.checked_add(data.len()).ok_or("SquashFS fragment cache overflow")?;
                if self.budget.fragment_bytes > MAX_METADATA {
                    return Err("SquashFS fragment cache exceeds 16 MiB".into());
                }
                self.budget.fragments.insert(key, data.clone());
            }
            data
        };
        self.position = chunk.start;
        self.end = chunk.start.checked_add(chunk.length).ok_or("SquashFS fragment slice overflow")?;
        if self.end > self.current.len() {
            return Err("SquashFS file tail exceeds its fragment block".into());
        }
        Ok(true)
    }
}
impl Read for FileReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.position == self.end && !self.next().map_err(std::io::Error::other)? {
            return Ok(0);
        }
        let count = buffer.len().min(self.end - self.position);
        buffer[..count].copy_from_slice(&self.current[self.position..self.position + count]);
        self.position += count;
        Ok(count)
    }
}

impl Unpacker for Squashfs {
    fn id(&self) -> &'static str {
        "squashfs"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        if !bytes.starts_with(b"hsqs") && !bytes.starts_with(b"sqsh") {
            return Unpack::NotMine;
        }
        let fs = match parse(bytes) {
            Ok(fs) => fs,
            Err(detail) => return Unpack::Failed { kind: "squashfs", detail },
        };
        let mut budget = DataBudget::default();
        for entry in &fs.entries {
            if entry.kind != "file" {
                continue;
            }
            if let Some(error) = &entry.unread {
                sink.limitation("squashfs.entry-unread", Some(format!("{}: {error}", entry.path)));
                continue;
            }
            let mut reader = FileReader {
                bytes,
                sb: &fs.sb,
                chunks: &entry.chunks,
                index: 0,
                current: Arc::new(Vec::new()),
                position: 0,
                end: 0,
                budget: &mut budget,
            };
            match sink.add(&entry.path, &mut reader) {
                Ok(()) => {}
                Err(SinkError::LimitReached) => break,
                Err(SinkError::Read(error)) => sink.limitation("squashfs.entry-unread", Some(format!("{}: {error}", entry.path))),
            }
            if budget.decoded > MAX_DECODED || budget.fragment_bytes > MAX_METADATA {
                break;
            }
        }
        Unpack::Done { kind: "squashfs" }
    }
}
impl Analyzer for Squashfs {
    fn id(&self) -> &'static str {
        "squashfs"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn analyze_file(&self, tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        if file.unpacked_by.as_deref() != Some("squashfs") {
            return;
        }
        let fs = match tree.read(&file.path).map_err(|error| error.to_string()).and_then(|bytes| parse(&bytes)) {
            Ok(fs) => fs,
            Err(error) => {
                out.limitation("squashfs.directory-unread", Some(file), Some(error));
                return;
            }
        };
        let entries:Vec<_>=fs.entries.iter().map(|entry|json!({"path":entry.path,"inode":entry.inode,"inode_reference":entry.reference,
            "type":entry.kind,"mode":entry.mode,"uid":entry.uid,"gid":entry.gid,"size":entry.size,"link_target":entry.target,"unread":entry.unread})).collect();
        out.fact(file,"squashfs.directory",json!({"superblock":{"bytes_used":fs.sb.used,"version_major":4,"version_minor":0,"compression":fs.sb.compression,"block_size":fs.sb.block,"inodes":fs.sb.inodes},"entries":entries}));
        out.finding(
            Finding::new(Section::Structure, "squashfs", "squashfs.contents", Confidence::Verified, Severity::Info)
                .param("count", fs.entries.len())
                .evidence(Evidence::bytes(
                    file,
                    0,
                    96,
                    json!({"bytes_used":fs.sb.used,"inode_count":fs.sb.inodes,"compression":fs.sb.compression}),
                )),
        );
        if fs.entries.iter().any(|entry| matches!(entry.kind, "symlink" | "special")) {
            out.limitation("squashfs.special-file", Some(file), None);
        }
        if fs.entries.iter().any(|entry| entry.unread.is_some()) {
            out.limitation("squashfs.entry-unread", Some(file), None);
        }
        out.limitation(
            "squashfs.metadata-scope",
            Some(file),
            Some(if fs.sb.xattr_table != NONE {
                "extended attribute table retained as an uninterpreted declaration".into()
            } else {
                "runtime filesystem semantics were not evaluated".into()
            }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn put16(bytes: &mut [u8], at: usize, value: u16) {
        bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn base(kind: u16, inode: u32) -> Vec<u8> {
        let mut raw = vec![0; 16];
        put16(&mut raw, 0, kind);
        put16(&mut raw, 2, 0o755);
        put32(&mut raw, 12, inode);
        raw
    }
    fn meta(bytes: &mut Vec<u8>, data: &[u8]) -> usize {
        let at = bytes.len();
        bytes.extend((0x8000 | data.len() as u16).to_le_bytes());
        bytes.extend(data);
        at
    }
    fn fixture(fragment: bool) -> Vec<u8> {
        let payload = b"bounded-file\n";
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload).expect("compress fixture");
        let encoded = encoder.finish().expect("finish fixture compression");
        let mut bytes = vec![0; 96];
        bytes.extend(&encoded);
        let mut file = base(2, 2);
        file.resize(32, 0);
        put32(&mut file, 16, 96);
        put32(&mut file, 20, if fragment { 0 } else { u32::MAX });
        put32(&mut file, 28, payload.len() as u32);
        if !fragment {
            file.extend((encoded.len() as u32).to_le_bytes());
        }
        let link_offset = file.len();
        let mut link = base(3, 3);
        link.resize(24, 0);
        put32(&mut link, 16, 1);
        put32(&mut link, 20, 13);
        link.extend(b"../../outside");
        file.extend(link);
        let root_offset = file.len();
        let mut root = base(1, 1);
        root.resize(32, 0);
        let mut directory = vec![0; 12];
        put32(&mut directory, 0, 1);
        put32(&mut directory, 8, 2);
        for (name, offset, number, kind) in [("a", 0, 0, 2), ("link", link_offset, 1, 3)] {
            let at = directory.len();
            directory.resize(at + 8, 0);
            put16(&mut directory, at, offset as u16);
            put16(&mut directory, at + 2, number);
            put16(&mut directory, at + 4, kind);
            put16(&mut directory, at + 6, name.len() as u16 - 1);
            directory.extend(name.as_bytes());
        }
        put32(&mut root, 20, 2);
        put16(&mut root, 24, directory.len() as u16 + 3);
        put32(&mut root, 28, 1);
        file.extend(root);
        let inode_table = meta(&mut bytes, &file);
        let directory_table = meta(&mut bytes, &directory);
        let fragment_table = if fragment {
            let mut raw = vec![0; 16];
            put64(&mut raw, 0, 96);
            put32(&mut raw, 8, encoded.len() as u32);
            let pointer = meta(&mut bytes, &raw);
            let table = bytes.len();
            bytes.extend((pointer as u64).to_le_bytes());
            table as u64
        } else {
            NONE
        };
        let id_pointer = meta(&mut bytes, &1000u32.to_le_bytes());
        let id_table = bytes.len();
        bytes.extend((id_pointer as u64).to_le_bytes());
        let used = bytes.len();
        bytes[..4].copy_from_slice(b"hsqs");
        put32(&mut bytes, 4, 3);
        put32(&mut bytes, 12, 4096);
        put32(&mut bytes, 16, u32::from(fragment));
        put16(&mut bytes, 20, 1);
        put16(&mut bytes, 22, 12);
        put16(&mut bytes, 26, 1);
        put16(&mut bytes, 28, 4);
        put64(&mut bytes, 32, root_offset as u64);
        put64(&mut bytes, 40, used as u64);
        put64(&mut bytes, 48, id_table as u64);
        put64(&mut bytes, 56, NONE);
        put64(&mut bytes, 64, inode_table as u64);
        put64(&mut bytes, 72, directory_table as u64);
        put64(&mut bytes, 80, fragment_table);
        put64(&mut bytes, 88, NONE);
        bytes
    }
    fn contents(bytes: &[u8], fs: &Filesystem, budget: &mut DataBudget) -> Result<Vec<u8>> {
        let entry = fs.entries.iter().find(|entry| entry.kind == "file").ok_or("fixture file missing")?;
        let mut reader =
            FileReader { bytes, sb: &fs.sb, chunks: &entry.chunks, index: 0, current: Arc::new(Vec::new()), position: 0, end: 0, budget };
        let mut data = Vec::new();
        reader.read_to_end(&mut data).map_err(|error| error.to_string())?;
        Ok(data)
    }
    #[test]
    fn published_xz_snap_exposes_its_captured_files_without_execution() {
        let bytes = include_bytes!("../tests/data/upstream-hello-world-29.snap");
        assert_eq!(aa_core::sha256_hex(bytes), "a14a4c44b085499d45f4182388b941fc9d5d87c5fe04f7405e087f52da61c407");
        let fs = parse(bytes).expect("published SquashFS metadata");
        assert_eq!(fs.entries.len(), 9);
        assert_eq!(fs.sb.compression, 4);
        let native: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/squashfs-native.ref.json")).expect("native reference");
        let expected = native["records"][0]["entries"].as_array().expect("native entries");
        assert_eq!(expected.len(), fs.entries.len());
        let mut budget = DataBudget::default();
        for (entry, reference) in fs.entries.iter().zip(expected) {
            assert_eq!(entry.path, reference["path"].as_str().expect("native path"));
            assert_eq!(entry.kind, reference["type"]);
            assert_eq!(entry.mode, reference["mode_bits"]);
            assert_eq!(entry.uid, reference["uid"]);
            assert_eq!(entry.gid, reference["gid"]);
            if entry.kind != "file" {
                continue;
            }
            assert!(entry.unread.is_none(), "{}: {:?}", entry.path, entry.unread);
            let mut reader = FileReader {
                bytes,
                sb: &fs.sb,
                chunks: &entry.chunks,
                index: 0,
                current: Arc::new(Vec::new()),
                position: 0,
                end: 0,
                budget: &mut budget,
            };
            let mut data = Vec::new();
            reader.read_to_end(&mut data).expect("read published file bytes");
            assert_eq!(data.len() as u64, entry.size, "{}", entry.path);
            assert_eq!(aa_core::sha256_hex(&data), reference["sha256"], "{}", entry.path);
            if entry.path == "meta/snap.yaml" {
                assert!(std::str::from_utf8(&data).expect("YAML text").contains("name: hello-world"));
            }
        }
    }

    #[test]
    fn gzip_blocks_fragment_cache_and_symlinks_remain_bounded_data() {
        for fragment in [false, true] {
            let bytes = fixture(fragment);
            let fs = parse(&bytes).expect("constructed gzip filesystem");
            let mut budget = DataBudget::default();
            assert_eq!(contents(&bytes, &fs, &mut budget).expect("fixture bytes"), b"bounded-file\n");
            assert_eq!(fs.entries[1].kind, "symlink");
            assert_eq!(fs.entries[1].target.as_deref(), Some("../../outside"));
            assert_eq!(fs.entries[0].uid, 1000);
            let decoded = budget.decoded;
            contents(&bytes, &fs, &mut budget).expect("repeated bounded bytes");
            if fragment {
                assert_eq!(budget.decoded, decoded, "shared fragment must not be decompressed again");
                assert_eq!(budget.fragments.len(), 1);
            }
        }
    }

    #[test]
    fn malformed_superblocks_directories_and_short_extents_are_rejected() {
        let valid = fixture(false);
        for length in 0..valid.len() {
            assert!(parse(&valid[..length]).is_err(), "short prefix {length}");
        }
        for (field, value) in [(4, 100001u32), (12, 2_097_152), (16, 100001)] {
            let mut bytes = valid.clone();
            put32(&mut bytes, field, value);
            assert!(parse(&bytes).is_err());
        }
        for compression in [0, 2, 3, 5, 6] {
            let mut bytes = valid.clone();
            put16(&mut bytes, 20, compression);
            assert!(parse(&bytes).is_err());
        }
        let sb = Super::parse(&valid).expect("fixture superblock");
        let mut bad = valid.clone();
        put16(&mut bad, sb.directory_table + 2 + 12 + 2, 9);
        assert!(parse(&bad).is_err(), "directory number must agree with inode");
        let mut bad = valid.clone();
        put16(&mut bad, sb.directory_table + 2 + 12 + 4, 1);
        assert!(parse(&bad).is_err(), "directory type must agree with inode");
        let mut bad = valid.clone();
        bad[sb.directory_table + 2 + 12 + 8] = b'/';
        assert!(parse(&bad).is_err(), "names cannot create extra path segments");
        let mut bad = valid.clone();
        put16(&mut bad, sb.directory_table + 2 + 12, sb.root as u16);
        put16(&mut bad, sb.directory_table + 2 + 14, (-1i16) as u16);
        put16(&mut bad, sb.directory_table + 2 + 16, 1);
        assert!(parse(&bad).is_err(), "directory cycle cannot recursively construct a tree");
    }

    #[test]
    fn metadata_data_and_fragment_budgets_fail_before_unbounded_allocation() {
        let bytes = fixture(true);
        let fs = parse(&bytes).expect("fragment fixture");
        let mut budget = DataBudget { decoded: MAX_DECODED, ..DataBudget::default() };
        assert!(contents(&bytes, &fs, &mut budget).is_err());
        let mut budget = DataBudget { fragment_bytes: MAX_METADATA, ..DataBudget::default() };
        assert!(contents(&bytes, &fs, &mut budget).is_err());
        let mut metadata = Metadata { decoded: MAX_METADATA, ..Metadata::default() };
        assert!(metadata.read(&bytes, &fs.sb, fs.sb.inode_table, 0, 16, fs.sb.directory_table).is_err());
        let mut metadata = Metadata::default();
        assert!(metadata.read(&bytes, &fs.sb, fs.sb.inode_table, 8192, 1, fs.sb.directory_table).is_err());
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&[b'a'; 8193]).expect("test compression");
        let compressed = encoder.finish().expect("compressed fixture");
        assert!(decode(&compressed, 1, 8192).is_err(), "small compressed input must not expand past a metadata block");
        let mut trailing = compressed;
        trailing.extend(b"trailing");
        assert!(decode(&trailing, 1, 9000).is_err(), "a decoder must consume exactly its declared compressed extent");
    }

    #[test]
    fn xz_dictionary_limit_is_checked_before_a_giant_dictionary_is_allocated() {
        let bytes = include_bytes!("../tests/data/upstream-hello-world-29.snap");
        let fs = parse(bytes).expect("published fixture");
        let chunk = fs.entries.iter().flat_map(|entry| entry.chunks.iter()).find(|chunk| chunk.compressed).expect("XZ data block");
        let mut stream = extent(bytes, chunk.offset.expect("stored block"), chunk.stored).expect("block extent").to_vec();
        let header_size = (stream[12] as usize + 1) * 4;
        let flags = stream[13];
        let mut at = 14;
        for flag in [0x40, 0x80] {
            if flags & flag != 0 {
                while stream[at] & 0x80 != 0 {
                    at += 1;
                }
                at += 1;
            }
        }
        assert_eq!(&stream[at..at + 2], &[0x21, 1], "one LZMA2 filter with one property byte");
        stream[at + 2] = 40; // LZMA2's largest dictionary, far above the 32 MiB decoder limit.
        let mut crc = u32::MAX;
        for byte in &stream[12..12 + header_size - 4] {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
            }
        }
        put32(&mut stream, 12 + header_size - 4, !crc);
        let error = decode(&stream, 4, MAX_BLOCK).expect_err("oversized XZ dictionary must fail");
        assert!(error.contains("mem_limit") || error.contains("memory"), "{error}");
    }

    #[test]
    fn metadata_cursor_crosses_blocks_and_directory_depth_is_bounded() {
        let mut bytes = fixture(false);
        let mut sb = Super::parse(&bytes).expect("fixture superblock");
        bytes.truncate(sb.inode_table);
        meta(&mut bytes, &[1; 8192]);
        meta(&mut bytes, &[2; 3]);
        sb.directory_table = bytes.len();
        let mut metadata = Metadata::default();
        assert_eq!(metadata.read(&bytes, &sb, sb.inode_table, 8190, 5, sb.directory_table).expect("cross-block read"), [1, 1, 2, 2, 2]);

        let mut bytes = fixture(false);
        let sb = Super::parse(&bytes).expect("fixture superblock");
        bytes.truncate(sb.inode_table);
        let mut inodes = Vec::new();
        let mut directories = Vec::new();
        for index in 0..67u32 {
            let mut inode = base(1, index + 1);
            inode.resize(32, 0);
            put32(&mut inode, 20, 2);
            put16(&mut inode, 26, directories.len() as u16);
            if index != 66 {
                let mut directory = vec![0; 21];
                put32(&mut directory, 8, index + 2);
                put16(&mut directory, 12, ((index + 1) * 32) as u16);
                put16(&mut directory, 16, 1);
                directory[20] = b'a';
                put16(&mut inode, 24, directory.len() as u16 + 3);
                directories.extend(directory);
            } else {
                put16(&mut inode, 24, 3);
            }
            inodes.extend(inode);
        }
        let inode_table = meta(&mut bytes, &inodes);
        let directory_table = meta(&mut bytes, &directories);
        let id_pointer = meta(&mut bytes, &0u32.to_le_bytes());
        let id_table = bytes.len();
        bytes.extend((id_pointer as u64).to_le_bytes());
        let used = bytes.len();
        put32(&mut bytes, 4, 67);
        put64(&mut bytes, 32, 0);
        put64(&mut bytes, 40, used as u64);
        put64(&mut bytes, 48, id_table as u64);
        put64(&mut bytes, 64, inode_table as u64);
        put64(&mut bytes, 72, directory_table as u64);
        let error = parse(&bytes).err().expect("excessive directory depth must fail");
        assert!(error.contains("depth"), "{error}");
    }
}
