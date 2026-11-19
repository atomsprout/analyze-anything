//! A read-only view of an OLE compound file (MS-CFB), as far as hashing an MSI needs it.
//!
//! The signature of an MSI covers the raw bytes of directory entries (names as stored, CLSIDs,
//! state bits, timestamps), so this reader hands those out untouched instead of going through a
//! library that decodes them. Every sector number, chain and sibling link comes from the file
//! and is checked: a chain that loops, a directory tree that visits an entry twice or a stream
//! that does not fit the file is an error, never a guess.

use crate::pe::{u16_at, u32_at, u64_at};

const MAGIC: &[u8] = &[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
const END_OF_CHAIN: u32 = 0xffff_fffe;
const FREE_SECTOR: u32 = 0xffff_ffff;
/// The largest regular sector number.
const MAX_SECTOR: u32 = 0xffff_fffa;
const NO_STREAM: u32 = 0xffff_ffff;
const ENTRY_SIZE: usize = 128;
const MINI_SECTOR: usize = 64;
/// Streams shorter than this live in the mini stream. The format fixes the value.
const MINI_CUTOFF: u64 = 4096;
/// Storages nested deeper than this are refused.
const MAX_DEPTH: u32 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Storage,
    Stream,
    Root,
}

/// One 128-byte directory entry.
#[derive(Debug, Clone, Copy)]
pub struct Entry<'a> {
    raw: &'a [u8],
    pub kind: Kind,
    /// Bytes of the name including its two-byte terminator: even, 2..=64.
    name_length: usize,
    /// The stream size, read as the file's version defines it.
    pub size: u64,
}

impl<'a> Entry<'a> {
    /// The name as stored (UTF-16LE), with its terminator. This is what entries are sorted by.
    pub fn name_with_terminator(&self) -> &'a [u8] {
        &self.raw[..self.name_length]
    }

    /// The name as stored (UTF-16LE), without its terminator.
    pub fn name_bytes(&self) -> &'a [u8] {
        &self.raw[..self.name_length - 2]
    }

    /// The name as text, for messages.
    pub fn name(&self) -> String {
        let units: Vec<u16> = self.name_bytes().chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16_lossy(&units)
    }

    pub fn clsid(&self) -> &'a [u8] {
        &self.raw[80..96]
    }

    pub fn state_bits(&self) -> &'a [u8] {
        &self.raw[96..100]
    }

    pub fn created(&self) -> &'a [u8] {
        &self.raw[100..108]
    }

    pub fn modified(&self) -> &'a [u8] {
        &self.raw[108..116]
    }

    /// The low four bytes of the size field, as stored.
    pub fn size_bytes(&self) -> &'a [u8] {
        &self.raw[120..124]
    }

    fn link(&self, offset: usize) -> u32 {
        u32_at(self.raw, offset).unwrap_or(NO_STREAM)
    }

    fn start(&self) -> u32 {
        self.link(116)
    }
}

/// A directory entry with the entries below it.
#[derive(Debug, Clone)]
pub struct Node<'a> {
    pub entry: Entry<'a>,
    /// Empty for streams. In directory-tree order, which is not the order signatures hash in.
    pub children: Vec<Node<'a>>,
}

#[derive(Debug)]
pub struct Compound<'a> {
    data: &'a [u8],
    major: u16,
    sector_shift: u32,
    fat_sectors: Vec<u32>,
    directory_sectors: Vec<u32>,
    mini_fat_sectors: Vec<u32>,
    /// The sectors of the root entry's stream, which holds the mini sectors.
    mini_stream_sectors: Vec<u32>,
}

/// True when `data` starts with the compound-file magic.
pub fn is_compound(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

impl<'a> Compound<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Compound<'a>, String> {
        if !is_compound(data) {
            return Err("not a compound file".into());
        }
        if data.len() < 512 {
            return Err("the file ends inside the compound-file header".into());
        }
        let field16 = |offset| u16_at(data, offset).unwrap_or(0);
        let field32 = |offset| u32_at(data, offset).unwrap_or(0);
        let major = field16(26);
        let sector_shift = u32::from(field16(30));
        if field16(28) != 0xfffe {
            return Err("the header's byte-order mark is not little endian".into());
        }
        if !matches!((major, sector_shift), (3, 9) | (4, 12)) {
            return Err(format!("unsupported compound-file version {major} with sector shift {sector_shift}"));
        }
        if field16(32) != 6 || u64::from(field32(56)) != MINI_CUTOFF {
            return Err("the header declares a non-standard mini stream".into());
        }
        let mut file = Compound {
            data,
            major,
            sector_shift,
            fat_sectors: Vec::new(),
            directory_sectors: Vec::new(),
            mini_fat_sectors: Vec::new(),
            mini_stream_sectors: Vec::new(),
        };
        let limit = file.sector_limit();
        // The first 109 FAT sector numbers are in the header, the rest in a chain of DIFAT sectors.
        let mut fat = Vec::new();
        let mut complete = false;
        for index in 0..109 {
            let sector = field32(76 + index * 4);
            if sector == FREE_SECTOR {
                complete = true;
                break;
            }
            fat.push(sector);
        }
        let per_sector = file.sector_size() / 4;
        let mut difat = field32(68);
        let mut steps = 0usize;
        while !complete && difat <= MAX_SECTOR {
            steps += 1;
            if steps > limit {
                return Err("the DIFAT chain loops".into());
            }
            let sector = file.sector(difat)?;
            for index in 0..per_sector - 1 {
                let entry = u32_at(sector, index * 4).ok_or("a DIFAT sector is cut short")?;
                if entry == FREE_SECTOR {
                    complete = true;
                    break;
                }
                if fat.len() >= limit {
                    return Err("more FAT sectors are declared than the file can hold".into());
                }
                fat.push(entry);
            }
            difat = u32_at(sector, (per_sector - 1) * 4).ok_or("a DIFAT sector is cut short")?;
        }
        if fat.iter().any(|&sector| sector > MAX_SECTOR) {
            return Err("the DIFAT names an invalid FAT sector".into());
        }
        file.fat_sectors = fat;
        file.directory_sectors = file.chain(field32(48))?;
        if file.directory_sectors.is_empty() {
            return Err("the file has no directory".into());
        }
        file.mini_fat_sectors = file.chain(field32(60))?;
        let root = file.entry(0)?;
        if root.kind != Kind::Root {
            return Err("the first directory entry is not the root storage".into());
        }
        file.mini_stream_sectors = file.chain(root.start())?;
        Ok(file)
    }

    fn sector_size(&self) -> usize {
        1 << self.sector_shift
    }

    /// No chain in this file can be longer than this many sectors.
    fn sector_limit(&self) -> usize {
        (self.data.len() >> self.sector_shift) + 1
    }

    /// The bytes of sector `number` that are inside the file; the last sector may be cut short.
    fn sector(&self, number: u32) -> Result<&'a [u8], String> {
        let start = (u64::from(number) + 1) << self.sector_shift;
        let length = self.data.len() as u64;
        if number > MAX_SECTOR || start >= length {
            return Err(format!("sector {number} lies outside the file"));
        }
        let end = (start + self.sector_size() as u64).min(length);
        Ok(&self.data[start as usize..end as usize])
    }

    /// The sector that follows `number` in its chain.
    fn next(&self, number: u32) -> Result<u32, String> {
        let per_sector = self.sector_size() / 4;
        let index = number as usize;
        let fat = *self.fat_sectors.get(index / per_sector).ok_or_else(|| format!("sector {number} has no FAT entry"))?;
        u32_at(self.sector(fat)?, (index % per_sector) * 4).ok_or_else(|| format!("the FAT entry of sector {number} is cut off"))
    }

    /// Every sector of the chain starting at `start`.
    fn chain(&self, start: u32) -> Result<Vec<u32>, String> {
        let limit = self.sector_limit();
        let mut sectors = Vec::new();
        let mut current = start;
        while current != END_OF_CHAIN {
            // A chain that was never allocated is written as "free" by some tools.
            if current == FREE_SECTOR && sectors.is_empty() {
                break;
            }
            if current > MAX_SECTOR {
                return Err(format!("a sector chain continues at the invalid sector {current:#x}"));
            }
            if sectors.len() >= limit {
                return Err("a sector chain loops".into());
            }
            sectors.push(current);
            current = self.next(current)?;
        }
        Ok(sectors)
    }

    /// Number of directory entries the directory stream has room for.
    fn entry_count(&self) -> usize {
        self.directory_sectors.len() * (self.sector_size() / ENTRY_SIZE)
    }

    fn entry(&self, id: u32) -> Result<Entry<'a>, String> {
        let per_sector = self.sector_size() / ENTRY_SIZE;
        let index = id as usize;
        let sector = *self.directory_sectors.get(index / per_sector).ok_or_else(|| format!("directory entry {id} does not exist"))?;
        let offset = (index % per_sector) * ENTRY_SIZE;
        let raw = self.sector(sector)?.get(offset..offset + ENTRY_SIZE).ok_or_else(|| format!("directory entry {id} is cut off"))?;
        let kind = match raw[66] {
            1 => Kind::Storage,
            2 => Kind::Stream,
            5 => Kind::Root,
            other => return Err(format!("directory entry {id} has the invalid type {other}")),
        };
        let name_length = usize::from(u16_at(raw, 64).unwrap_or(0));
        if !(2..=64).contains(&name_length) || name_length % 2 != 0 {
            return Err(format!("directory entry {id} has an invalid name length ({name_length})"));
        }
        // Version 3 files use only the low half of the size field; the high half may hold garbage.
        let size = if self.major == 3 { u64::from(u32_at(raw, 120).unwrap_or(0)) } else { u64_at(raw, 120).unwrap_or(0) };
        Ok(Entry { raw, kind, name_length, size })
    }

    /// The root storage with everything below it.
    pub fn tree(&self) -> Result<Node<'a>, String> {
        let mut seen = vec![false; self.entry_count()];
        let root = self.entry(0)?;
        seen[0] = true;
        let children = self.children(&root, &mut seen, 0)?;
        Ok(Node { entry: root, children })
    }

    fn children(&self, storage: &Entry<'a>, seen: &mut [bool], depth: u32) -> Result<Vec<Node<'a>>, String> {
        if depth > MAX_DEPTH {
            return Err("storages are nested too deeply".into());
        }
        // The entries of a storage form a binary tree linked by sibling ids.
        let mut pending = vec![storage.link(76)];
        let mut nodes = Vec::new();
        while let Some(id) = pending.pop() {
            if id == NO_STREAM {
                continue;
            }
            let visited = seen.get_mut(id as usize).ok_or_else(|| format!("directory entry {id} does not exist"))?;
            if std::mem::replace(visited, true) {
                return Err(format!("directory entry {id} is linked more than once"));
            }
            let entry = self.entry(id)?;
            if entry.kind == Kind::Root {
                return Err(format!("directory entry {id} is a second root storage"));
            }
            pending.push(entry.link(72));
            pending.push(entry.link(68));
            let children = if entry.kind == Kind::Storage { self.children(&entry, seen, depth + 1)? } else { Vec::new() };
            nodes.push(Node { entry, children });
        }
        Ok(nodes)
    }

    /// Feeds the content of `stream` to `sink`, piece by piece.
    pub fn read(&self, stream: &Entry<'a>, sink: &mut dyn FnMut(&[u8])) -> Result<(), String> {
        if stream.kind != Kind::Stream {
            return Err(format!("{:?} is not a stream", stream.name()));
        }
        if stream.size > self.data.len() as u64 {
            return Err(format!("stream {:?} declares {} bytes, more than the file holds", stream.name(), stream.size));
        }
        let short = || format!("stream {:?} is shorter than its declared size", stream.name());
        let mut remaining = stream.size as usize;
        let mut current = stream.start();
        if stream.size < MINI_CUTOFF {
            let per_sector = self.sector_size() / 4;
            while remaining > 0 {
                if current > MAX_SECTOR {
                    return Err(short());
                }
                let position = current as usize * MINI_SECTOR;
                let holder = *self.mini_stream_sectors.get(position >> self.sector_shift).ok_or_else(short)?;
                let within = position & (self.sector_size() - 1);
                let take = remaining.min(MINI_SECTOR);
                sink(self.sector(holder)?.get(within..within + take).ok_or_else(short)?);
                remaining -= take;
                let fat = *self.mini_fat_sectors.get(current as usize / per_sector).ok_or_else(short)?;
                current = u32_at(self.sector(fat)?, (current as usize % per_sector) * 4).ok_or_else(short)?;
            }
        } else {
            while remaining > 0 {
                if current > MAX_SECTOR {
                    return Err(short());
                }
                let take = remaining.min(self.sector_size());
                sink(self.sector(current)?.get(..take).ok_or_else(short)?);
                remaining -= take;
                current = self.next(current)?;
            }
        }
        Ok(())
    }

    /// The content of `stream`, when it is at most `limit` bytes long.
    pub fn read_to_vec(&self, stream: &Entry<'a>, limit: u64) -> Result<Vec<u8>, String> {
        if stream.size > limit {
            return Err(format!("stream {:?} is {} bytes long, more than is read here", stream.name(), stream.size));
        }
        let mut bytes = Vec::new();
        self.read(stream, &mut |piece| bytes.extend_from_slice(piece))?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Write};

    use super::*;

    /// A compound file written by the `cfb` crate: small and large streams, nested storages.
    pub(crate) fn sample(version: cfb::Version) -> Vec<u8> {
        let mut file = cfb::CompoundFile::create_with_version(version, Cursor::new(Vec::new())).expect("create");
        file.create_storage("/outer").expect("storage");
        file.create_storage("/outer/inner").expect("storage");
        for (path, length) in [("/small", 100usize), ("/large", 9000), ("/outer/a", 5000), ("/outer/inner/b", 70), ("/empty", 0)] {
            let mut stream = file.create_stream(path).expect("stream");
            stream.write_all(&content(path, length)).expect("write");
        }
        file.flush().expect("flush");
        file.into_inner().into_inner()
    }

    pub(crate) fn content(path: &str, length: usize) -> Vec<u8> {
        (0..length).map(|i| (i * 31 + path.len() * 7) as u8).collect()
    }

    fn find<'a, 'n>(node: &'n Node<'a>, name: &str) -> &'n Node<'a> {
        node.children.iter().find(|c| c.entry.name() == name).unwrap_or_else(|| panic!("no entry {name}"))
    }

    #[test]
    fn reads_streams_and_storages_of_both_versions() {
        for version in [cfb::Version::V3, cfb::Version::V4] {
            let bytes = sample(version);
            let file = Compound::parse(&bytes).expect("parse");
            let root = file.tree().expect("tree");
            assert_eq!(root.entry.kind, Kind::Root);
            assert_eq!(root.entry.name(), "Root Entry");
            let mut names: Vec<String> = root.children.iter().map(|c| c.entry.name()).collect();
            names.sort();
            assert_eq!(names, ["empty", "large", "outer", "small"]);
            for (node, path, length) in [(find(&root, "small"), "/small", 100), (find(&root, "large"), "/large", 9000)] {
                assert_eq!(node.entry.kind, Kind::Stream);
                assert_eq!(file.read_to_vec(&node.entry, 1 << 20).expect("read"), content(path, length));
            }
            let outer = find(&root, "outer");
            assert_eq!(outer.entry.kind, Kind::Storage);
            assert_eq!(file.read_to_vec(&find(outer, "a").entry, 1 << 20).expect("read"), content("/outer/a", 5000));
            let inner = find(outer, "inner");
            assert_eq!(file.read_to_vec(&find(inner, "b").entry, 1 << 20).expect("read"), content("/outer/inner/b", 70));
            assert_eq!(find(&root, "empty").entry.size, 0);
            assert!(file.read_to_vec(&find(&root, "large").entry, 100).is_err(), "the size limit applies");
            assert!(file.read(&outer.entry, &mut |_| {}).is_err(), "a storage has no content");
        }
    }

    #[test]
    fn damaged_files_are_errors_not_panics() {
        let bytes = sample(cfb::Version::V3);
        let walk = |data: &[u8]| {
            let Ok(file) = Compound::parse(data) else { return };
            let Ok(root) = file.tree() else { return };
            let mut pending = vec![&root];
            while let Some(node) = pending.pop() {
                if node.entry.kind == Kind::Stream {
                    let _ = file.read_to_vec(&node.entry, 1 << 20);
                }
                pending.extend(&node.children);
            }
        };
        for cut in (0..bytes.len()).step_by(61) {
            walk(&bytes[..cut]);
        }
        for at in 0..bytes.len() {
            // Headers, FAT and directory are in the first sectors; sample the rest.
            if at > 2048 && at % 7 != 0 {
                continue;
            }
            for value in [0x00, 0x01, 0x7f, 0xff] {
                let mut changed = bytes.clone();
                changed[at] = value;
                walk(&changed);
            }
        }
    }

    #[test]
    fn loops_and_shared_entries_are_refused() {
        let bytes = sample(cfb::Version::V3);
        let file = Compound::parse(&bytes).expect("parse");
        let directory = (file.directory_sectors[0] as usize + 1) << 9;
        // The root's child points back at the root.
        let mut changed = bytes.clone();
        changed[directory + 76..directory + 80].copy_from_slice(&0u32.to_le_bytes());
        let error = Compound::parse(&changed).expect("parse").tree().expect_err("cycle");
        assert!(error.contains("more than once"), "{error}");
        // Every FAT entry points at sector 0: all chains loop.
        let mut changed = bytes.clone();
        let fat = (file.fat_sectors[0] as usize + 1) << 9;
        for entry in changed[fat..fat + 512].chunks_exact_mut(4) {
            entry.copy_from_slice(&0u32.to_le_bytes());
        }
        assert!(Compound::parse(&changed).is_err());
        // A stream that claims to be larger than the file.
        let mut changed = bytes.clone();
        let root = file.tree().expect("tree");
        let large = find(&root, "large").entry;
        let offset = large.raw.as_ptr() as usize - bytes.as_ptr() as usize;
        changed[offset + 120..offset + 124].copy_from_slice(&0x7fff_ffffu32.to_le_bytes());
        let file = Compound::parse(&changed).expect("parse");
        let root = file.tree().expect("tree");
        assert!(file.read(&find(&root, "large").entry, &mut |_| {}).is_err());
    }
}
