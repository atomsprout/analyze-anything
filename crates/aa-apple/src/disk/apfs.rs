//! APFS containers, read-only: the newest valid checkpoint, the object maps, and for every
//! unencrypted volume the file-system tree (inodes, directory entries, extents, the extended
//! attributes that carry compressed files).
//!
//! Not handled: encrypted volumes, snapshots other than the live tree, Fusion drives, and
//! checkpoint descriptor areas that are not contiguous.

use std::collections::{BTreeMap, BTreeSet};

use super::{Disk, RunReader, decmpfs};
use crate::util::{le16, le32, le64, slice};

const MAX_BLOCK: u32 = 65536;
/// Most records read from one file-system tree.
const MAX_RECORDS: usize = 4_000_000;
/// Most B-tree nodes visited in one tree.
const MAX_NODES: usize = 2_000_000;
const MAX_DEPTH: usize = 256;
const ROOT_DIRECTORY: u64 = 2;

const OBJECT_TYPE_MASK: u32 = 0xffff;
const TYPE_NX_SUPERBLOCK: u32 = 1;
const TYPE_BTREE_ROOT: u32 = 2;
const TYPE_BTREE_NODE: u32 = 3;

const NODE_ROOT: u16 = 1;
const NODE_LEAF: u16 = 2;
const NODE_FIXED: u16 = 4;

const RECORD_INODE: u64 = 3;
const RECORD_XATTR: u64 = 4;
const RECORD_FILE_EXTENT: u64 = 8;
const RECORD_DIR_ENTRY: u64 = 9;

const FS_UNENCRYPTED: u64 = 1;
const INCOMPAT_CASE_INSENSITIVE: u64 = 1;
const INCOMPAT_NORMALIZATION_INSENSITIVE: u64 = 8;
const INCOMPAT_SEALED: u64 = 0x20;

/// The Fletcher-64 checksum APFS stores in the first eight bytes of every object.
fn checksum_ok(block: &[u8]) -> bool {
    let Some(stored) = le64(block, 0) else { return false };
    let (mut low, mut high) = (0u64, 0u64);
    for word in block[8..].chunks_exact(4) {
        low = (low + u32::from_le_bytes([word[0], word[1], word[2], word[3]]) as u64) % 0xffff_ffff;
        high = (high + low) % 0xffff_ffff;
    }
    let check_low = 0xffff_ffff - ((low + high) % 0xffff_ffff);
    let check_high = 0xffff_ffff - ((low + check_low) % 0xffff_ffff);
    stored == (check_high << 32) | check_low
}

struct Container<'a> {
    disk: &'a dyn Disk,
    block_size: u64,
}

impl Container<'_> {
    fn block(&self, address: u64) -> Result<Vec<u8>, String> {
        let offset = address.checked_mul(self.block_size).ok_or("block address overflow")?;
        self.disk.read_vec(offset, self.block_size as usize).map_err(|e| format!("block {address}: {e}"))
    }

    /// Visits every leaf record of the B-tree rooted at block `root`, as `(key, value)`.
    /// `resolve` turns the child ids of inner nodes into block addresses.
    fn walk(
        &self,
        root: u64,
        resolve: &dyn Fn(u64) -> Option<u64>,
        visit: &mut dyn FnMut(&[u8], &[u8]) -> bool,
    ) -> Result<(), String> {
        let mut pending = vec![(root, 0usize)];
        let mut seen = BTreeSet::new();
        let mut physical = false;
        while let Some((address, depth)) = pending.pop() {
            if depth > 16 || seen.len() >= MAX_NODES || !seen.insert(address) {
                return Err(format!("the B-tree is malformed at block {address}"));
            }
            let node = self.block(address)?;
            let object_type = le32(&node, 24).unwrap_or(0);
            let kind = object_type & OBJECT_TYPE_MASK;
            if depth == 0 {
                // A tree stored physically names its children by block address.
                physical = object_type & 0xc000_0000 == 0x4000_0000;
            }
            if kind != TYPE_BTREE_ROOT && kind != TYPE_BTREE_NODE {
                return Err(format!("block {address} is not a B-tree node"));
            }
            let short = || format!("B-tree node at block {address} is truncated");
            let flags = le16(&node, 32).ok_or_else(short)?;
            let count = le32(&node, 36).ok_or_else(short)? as usize;
            let table_offset = le16(&node, 40).ok_or_else(short)? as usize;
            let table_length = le16(&node, 42).ok_or_else(short)? as usize;
            let table = 56 + table_offset;
            let keys = table + table_length;
            let values_end = if flags & NODE_ROOT != 0 { node.len().saturating_sub(40) } else { node.len() };
            let fixed = flags & NODE_FIXED != 0;
            let entry_size = if fixed { 4 } else { 8 };
            if count.saturating_mul(entry_size) > table_length || keys > node.len() {
                return Err(format!("B-tree node at block {address} claims {count} entries"));
            }
            let leaf = flags & NODE_LEAF != 0;
            let mut children = Vec::new();
            for index in 0..count {
                let entry = table + index * entry_size;
                let (key_offset, key_length, value_offset, value_length) = if fixed {
                    (le16(&node, entry).ok_or_else(short)? as usize, None, le16(&node, entry + 2).ok_or_else(short)? as usize, None)
                } else {
                    (
                        le16(&node, entry).ok_or_else(short)? as usize,
                        Some(le16(&node, entry + 2).ok_or_else(short)? as usize),
                        le16(&node, entry + 4).ok_or_else(short)? as usize,
                        Some(le16(&node, entry + 6).ok_or_else(short)? as usize),
                    )
                };
                let bad = || format!("entry {index} of the B-tree node at block {address} is out of range");
                let key_start = keys + key_offset;
                // Fixed-size trees here are object maps: 16-byte keys, 16-byte values in leaves.
                let key = slice(&node, key_start, key_length.unwrap_or(16)).ok_or_else(bad)?;
                let value_length = value_length.unwrap_or(if leaf { 16 } else { 8 });
                // 0xffff marks a key without a value.
                let value = if value_offset == 0xffff {
                    &[][..]
                } else {
                    let value_start = values_end.checked_sub(value_offset).ok_or_else(bad)?;
                    slice(&node, value_start, value_length).ok_or_else(bad)?
                };
                if leaf {
                    if !visit(key, value) {
                        return Ok(());
                    }
                } else {
                    let child = le64(value, 0).ok_or_else(bad)?;
                    let child = if physical { child } else { resolve(child).ok_or_else(|| format!("child object {child} is not in the object map"))? };
                    children.push((child, depth + 1));
                }
            }
            // Popped in order, so leaves are visited left to right.
            pending.extend(children.into_iter().rev());
        }
        Ok(())
    }

    /// Reads an object map: `object id -> (transaction id, block)` for the newest transaction.
    fn object_map(&self, address: u64) -> Result<BTreeMap<u64, (u64, u64)>, String> {
        let omap = self.block(address)?;
        let tree = le64(&omap, 48).ok_or("the object map is truncated")?;
        let mut map: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
        self.walk(tree, &Some, &mut |key, value| {
            if let (Some(id), Some(xid), Some(block)) = (le64(key, 0), le64(key, 8), le64(value, 8)) {
                let entry = map.entry(id).or_insert((xid, block));
                if xid >= entry.0 {
                    *entry = (xid, block);
                }
            }
            map.len() < MAX_RECORDS
        })?;
        Ok(map)
    }
}

#[derive(Debug, Clone, Default)]
struct Inode {
    mode: u16,
    private_id: u64,
    size: Option<u64>,
    compressed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub path: String,
    pub mode: u16,
    inode: u64,
}

impl File {
    pub fn is_symlink(&self) -> bool {
        self.mode & 0o170000 == 0o120000
    }
}

enum Attribute {
    Inline(Vec<u8>),
    /// A separate data stream: `(stream id, size)`.
    Stream(u64, u64),
}

pub struct Volume<'a> {
    container: Container<'a>,
    pub name: String,
    pub case_sensitive: bool,
    pub sealed: bool,
    inodes: BTreeMap<u64, Inode>,
    /// `(stream id, logical offset) -> (length, block)`; block 0 is a hole.
    extents: BTreeMap<(u64, u64), (u64, u64)>,
    /// `(inode, attribute name) -> value`, for the two attributes compression uses.
    attributes: BTreeMap<(u64, &'static str), Attribute>,
    pub files: Vec<File>,
    pub damage: Option<String>,
}

/// A volume of the container that was not read, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Skipped {
    pub name: String,
    pub reason: String,
}

/// Opens every readable volume of the APFS container on `disk`.
pub fn open(disk: &dyn Disk) -> Result<(Vec<Volume<'_>>, Vec<Skipped>), String> {
    let head = disk.read_vec(0, 4096.min(disk.len() as usize)).map_err(|e| format!("the container superblock is unreadable: {e}"))?;
    if slice(&head, 32, 4) != Some(b"NXSB") {
        return Err("not an APFS container".into());
    }
    let block_size = le32(&head, 36).ok_or("the container superblock is truncated")?;
    if !(4096..=MAX_BLOCK).contains(&block_size) || !block_size.is_power_of_two() {
        return Err(format!("the block size {block_size} is not valid"));
    }
    let container = Container { disk, block_size: block_size as u64 };
    let first = container.block(0)?;
    // The copy in block 0 may be stale: take the newest valid superblock of the checkpoint area.
    let descriptor_blocks = le32(&first, 104).unwrap_or(0);
    let descriptor_base = le64(&first, 112).unwrap_or(0);
    let mut newest = (le64(&first, 16).unwrap_or(0), first.clone());
    let mut newest_valid = checksum_ok(&first);
    if descriptor_blocks & 0x8000_0000 == 0 {
        for index in 0..(descriptor_blocks as u64).min(4096) {
            let Ok(block) = container.block(descriptor_base.saturating_add(index)) else { break };
            if le32(&block, 24).map(|t| t & OBJECT_TYPE_MASK) == Some(TYPE_NX_SUPERBLOCK)
                && slice(&block, 32, 4) == Some(b"NXSB")
                && checksum_ok(&block)
                && let Some(xid) = le64(&block, 16)
                && (xid > newest.0 || !newest_valid)
            {
                newest = (xid, block);
                newest_valid = true;
            }
        }
    }
    let superblock = newest.1;
    let omap_address = le64(&superblock, 160).ok_or("the container superblock is truncated")?;
    let container_map = container.object_map(omap_address).map_err(|e| format!("container object map: {e}"))?;
    let max_volumes = le32(&superblock, 180).unwrap_or(0).min(100) as usize;
    let mut volumes = Vec::new();
    let mut skipped = Vec::new();
    for index in 0..max_volumes {
        let Some(id) = le64(&superblock, 184 + index * 8).filter(|id| *id != 0) else { continue };
        let fallback = format!("volume {}", index + 1);
        let Some(&(_, address)) = container_map.get(&id) else {
            skipped.push(Skipped { name: fallback, reason: format!("volume object {id} is not in the container's object map") });
            continue;
        };
        let container = Container { disk, block_size: block_size as u64 };
        match Volume::open(container, address) {
            Ok(volume) => volumes.push(volume),
            Err((name, reason)) => skipped.push(Skipped { name: name.unwrap_or(fallback), reason }),
        }
    }
    Ok((volumes, skipped))
}

/// The extended fields of an inode: `(type, value)` pairs.
fn extended_fields(blob: &[u8]) -> Vec<(u8, &[u8])> {
    let mut fields = Vec::new();
    let Some(count) = le16(blob, 0) else { return fields };
    let mut data = 4 + count as usize * 4;
    for index in 0..count as usize {
        let entry = 4 + index * 4;
        let (Some(&kind), Some(size)) = (blob.get(entry), le16(blob, entry + 2)) else { break };
        let Some(value) = slice(blob, data, size as usize) else { break };
        fields.push((kind, value));
        // Values are padded to eight bytes.
        data += (size as usize + 7) & !7;
    }
    fields
}

impl<'a> Volume<'a> {
    fn open(container: Container<'a>, address: u64) -> Result<Self, (Option<String>, String)> {
        let superblock = container.block(address).map_err(|e| (None, e))?;
        if slice(&superblock, 32, 4) != Some(b"APSB") {
            return Err((None, format!("block {address} is not a volume superblock")));
        }
        let name = slice(&superblock, 704, 256).map(crate::util::c_string).filter(|n| !n.is_empty());
        let fail = |reason: String| (name.clone(), reason);
        let short = || fail("the volume superblock is truncated".into());
        let incompatible = le64(&superblock, 56).ok_or_else(short)?;
        let flags = le64(&superblock, 264).ok_or_else(short)?;
        if flags & FS_UNENCRYPTED == 0 {
            return Err(fail("the volume is encrypted".into()));
        }
        let omap_address = le64(&superblock, 128).ok_or_else(short)?;
        let root_id = le64(&superblock, 136).ok_or_else(short)?;
        let map = container.object_map(omap_address).map_err(|e| fail(format!("volume object map: {e}")))?;
        let root = map.get(&root_id).map(|entry| entry.1).ok_or_else(|| fail("the file-system tree is not in the object map".into()))?;
        let hashed_names = incompatible & (INCOMPAT_CASE_INSENSITIVE | INCOMPAT_NORMALIZATION_INSENSITIVE) != 0;

        let mut inodes: BTreeMap<u64, Inode> = BTreeMap::new();
        let mut extents = BTreeMap::new();
        let mut attributes = BTreeMap::new();
        // Directory entries: `(parent inode, name, child inode)`.
        let mut entries: Vec<(u64, String, u64)> = Vec::new();
        let mut records = 0usize;
        let outcome = container.walk(root, &|id| map.get(&id).map(|entry| entry.1), &mut |key, value| {
            records += 1;
            let Some(header) = le64(key, 0) else { return true };
            let (id, kind) = (header & 0x0fff_ffff_ffff_ffff, header >> 60);
            match kind {
                RECORD_INODE => {
                    let mut inode = Inode {
                        private_id: le64(value, 8).unwrap_or(id),
                        mode: le16(value, 80).unwrap_or(0),
                        compressed: le32(value, 68).is_some_and(|flags| flags & 0x20 != 0),
                        size: None,
                    };
                    for (field, data) in value.get(92..).map(extended_fields).unwrap_or_default() {
                        if field == 8 {
                            inode.size = le64(data, 0);
                        }
                    }
                    inodes.insert(id, inode);
                }
                RECORD_DIR_ENTRY => {
                    let name = if hashed_names {
                        le32(key, 8).and_then(|n| slice(key, 12, (n & 0x3ff) as usize))
                    } else {
                        le16(key, 8).and_then(|n| slice(key, 10, n as usize))
                    };
                    if let (Some(name), Some(child)) = (name, le64(value, 0)) {
                        entries.push((id, crate::util::c_string(name), child));
                    }
                }
                RECORD_FILE_EXTENT => {
                    if let (Some(logical), Some(length), Some(block)) = (le64(key, 8), le64(value, 0), le64(value, 8)) {
                        extents.insert((id, logical), (length & 0x00ff_ffff_ffff_ffff, block));
                    }
                }
                RECORD_XATTR => {
                    let name = le16(key, 8).and_then(|n| slice(key, 10, n as usize)).map(crate::util::c_string);
                    let wanted = match name.as_deref() {
                        Some("com.apple.decmpfs") => Some("com.apple.decmpfs"),
                        Some("com.apple.ResourceFork") => Some("com.apple.ResourceFork"),
                        _ => None,
                    };
                    if let (Some(wanted), Some(flags), Some(length)) = (wanted, le16(value, 0), le16(value, 2)) {
                        let data = slice(value, 4, length as usize);
                        let attribute = if flags & 1 != 0 {
                            data.and_then(|d| Some(Attribute::Stream(le64(d, 0)?, le64(d, 8)?)))
                        } else {
                            data.map(|d| Attribute::Inline(d.to_vec()))
                        };
                        if let Some(attribute) = attribute {
                            attributes.insert((id, wanted), attribute);
                        }
                    }
                }
                _ => {}
            }
            records < MAX_RECORDS
        });
        let mut damage = outcome.err().map(|e| format!("file-system tree: {e}"));
        if records >= MAX_RECORDS {
            damage.get_or_insert(format!("only the first {MAX_RECORDS} records were read"));
        }

        // Child inode -> (parent, name), then paths from the root directory down.
        let mut children: BTreeMap<u64, Vec<(&str, u64)>> = BTreeMap::new();
        for (parent, name, child) in &entries {
            children.entry(*parent).or_default().push((name.as_str(), *child));
        }
        let mut files = Vec::new();
        let mut pending: Vec<(u64, String, usize)> = vec![(ROOT_DIRECTORY, String::new(), 0)];
        let mut visited = BTreeSet::new();
        while let Some((directory, prefix, depth)) = pending.pop() {
            if depth > MAX_DEPTH || !visited.insert(directory) {
                continue;
            }
            for (name, child) in children.get(&directory).map(Vec::as_slice).unwrap_or_default() {
                let path = format!("{prefix}{}", name.replace('/', ":"));
                let Some(inode) = inodes.get(child) else { continue };
                match inode.mode & 0o170000 {
                    0o040000 => pending.push((*child, format!("{path}/"), depth + 1)),
                    0o100000 | 0o120000 => files.push(File { path, mode: inode.mode, inode: *child }),
                    _ => {}
                }
            }
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(Volume {
            container,
            name: name.unwrap_or_default(),
            case_sensitive: incompatible & INCOMPAT_CASE_INSENSITIVE == 0,
            sealed: incompatible & INCOMPAT_SEALED != 0,
            inodes,
            extents,
            attributes,
            files,
            damage,
        })
    }

    /// The runs of data stream `id`, in logical order, with holes made explicit.
    fn runs(&self, id: u64) -> Result<Vec<(Option<u64>, u64)>, String> {
        let mut runs = Vec::new();
        let mut position = 0u64;
        for (&(_, logical), &(length, block)) in self.extents.range((id, 0)..=(id, u64::MAX)) {
            if logical < position {
                return Err("file extents overlap".into());
            }
            if logical > position {
                runs.push((None, logical - position));
            }
            let offset = block.checked_mul(self.container.block_size).ok_or("extent overflow")?;
            if offset.checked_add(length).is_none_or(|end| end > self.container.disk.len()) {
                return Err("an extent lies outside the container".into());
            }
            runs.push((if block == 0 { None } else { Some(offset) }, length));
            position = logical.checked_add(length).ok_or("extent overflow")?;
        }
        Ok(runs)
    }

    fn stream(&self, id: u64, size: u64) -> Result<RunReader<'_>, String> {
        let mut runs = self.runs(id)?;
        let covered: u64 = runs.iter().map(|run| run.1).sum();
        if covered < size {
            // A sparse tail has no extent record.
            runs.push((None, size - covered));
        }
        Ok(RunReader::new(self.container.disk, runs, size))
    }

    fn attribute(&self, inode: u64, name: &'static str) -> Result<Option<Vec<u8>>, String> {
        match self.attributes.get(&(inode, name)) {
            None => Ok(None),
            Some(Attribute::Inline(data)) => Ok(Some(data.clone())),
            Some(Attribute::Stream(id, size)) => {
                if *size > super::MAX_READ as u64 {
                    return Err(format!("attribute {name} of {size} bytes is too large"));
                }
                let mut out = Vec::with_capacity(*size as usize);
                std::io::Read::read_to_end(&mut self.stream(*id, *size)?, &mut out).map_err(|e| e.to_string())?;
                Ok(Some(out))
            }
        }
    }

    /// Opens the content of `file` for reading.
    pub fn open_file(&self, file: &File) -> Result<Box<dyn std::io::Read + '_>, String> {
        let inode = self.inodes.get(&file.inode).ok_or("the inode is missing")?;
        if inode.compressed
            && let Some(header) = self.attribute(file.inode, "com.apple.decmpfs")?
        {
            let data = decmpfs::expand(&header, || {
                self.attribute(file.inode, "com.apple.ResourceFork")?.ok_or_else(|| "the compressed file has no resource fork".to_string())
            })?;
            return Ok(Box::new(std::io::Cursor::new(data)));
        }
        Ok(Box::new(self.stream(inode.private_id, inode.size.unwrap_or(0))?))
    }
}

#[cfg(test)]
mod tests {
    use super::super::RawDisk;
    use super::*;

    #[test]
    fn open_rejects_garbage_without_panicking() {
        assert!(open(&RawDisk(&[])).is_err());
        assert!(open(&RawDisk(&[0u8; 8192])).is_err());
        let mut image = vec![0u8; 16 * 4096];
        image[32..36].copy_from_slice(b"NXSB");
        // Block size zero.
        assert!(open(&RawDisk(&image)).is_err());
        image[36..40].copy_from_slice(&4096u32.to_le_bytes());
        // Object map at a block outside the image.
        image[160..168].copy_from_slice(&1_000_000u64.to_le_bytes());
        assert!(open(&RawDisk(&image)).is_err());
        // Object map inside the image, but its tree is not a B-tree node.
        image[160..168].copy_from_slice(&2u64.to_le_bytes());
        image[2 * 4096 + 48..2 * 4096 + 56].copy_from_slice(&3u64.to_le_bytes());
        assert!(open(&RawDisk(&image)).is_err());
        // A B-tree node that claims far more entries than fit.
        let node = 3 * 4096;
        image[node + 24..node + 28].copy_from_slice(&TYPE_BTREE_ROOT.to_le_bytes());
        image[node + 32..node + 34].copy_from_slice(&(NODE_ROOT | NODE_LEAF | NODE_FIXED).to_le_bytes());
        image[node + 36..node + 40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(open(&RawDisk(&image)).is_err());
        // An inner node whose child is itself.
        image[node + 32..node + 34].copy_from_slice(&(NODE_ROOT | NODE_FIXED).to_le_bytes());
        image[node + 36..node + 40].copy_from_slice(&1u32.to_le_bytes());
        image[node + 42..node + 44].copy_from_slice(&16u16.to_le_bytes());
        image[node + 56 + 2..node + 56 + 4].copy_from_slice(&8u16.to_le_bytes());
        image[node + 4096 - 40 - 8..node + 4096 - 40].copy_from_slice(&3u64.to_le_bytes());
        assert!(open(&RawDisk(&image)).is_err());
    }

    #[test]
    fn extended_fields_stop_at_the_end() {
        assert!(extended_fields(&[]).is_empty());
        // Two fields declared, only the first has its data.
        let mut blob = vec![2, 0, 0, 0, 4, 0, 3, 0, 8, 0, 40, 0];
        blob.extend_from_slice(b"ab\0\0\0\0\0\0");
        let fields = extended_fields(&blob);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0], (4, &b"ab\0"[..]));
    }

    #[test]
    fn checksum_matches_reference_values() {
        // An all-zero body sums to zero, which the algorithm stores as all ones.
        let mut block = vec![0u8; 4096];
        assert!(!checksum_ok(&block));
        block[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(checksum_ok(&block));
        assert!(!checksum_ok(&[1, 2, 3]));
    }
}
