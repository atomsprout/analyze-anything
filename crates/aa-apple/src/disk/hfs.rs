//! HFS+ and HFSX volumes, read-only: the volume header, the catalog B-tree (every file and
//! folder), the extents overflow B-tree (files in more than eight pieces) and the attributes
//! B-tree (only for transparently compressed files).

use std::collections::{BTreeMap, BTreeSet};

use super::{Disk, RunReader, decmpfs};
use crate::util::{be16, be32, be64, slice};

const ROOT_FOLDER: u32 = 2;
const EXTENTS_FILE: u32 = 3;
const CATALOG_FILE: u32 = 4;
const ATTRIBUTES_FILE: u32 = 8;
/// Most catalog entries read from one volume.
const MAX_ENTRIES: usize = 2_000_000;
/// Deepest folder nesting followed when building a path.
const MAX_DEPTH: usize = 256;
const DATA_FORK: u8 = 0x00;
const RESOURCE_FORK: u8 = 0xff;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fork {
    pub size: u64,
    pub blocks: u32,
    /// `(first allocation block, number of blocks)`, the eight extents of the catalog record.
    pub extents: Vec<(u32, u32)>,
}

fn fork(bytes: &[u8], offset: usize) -> Option<Fork> {
    let size = be64(bytes, offset)?;
    let blocks = be32(bytes, offset + 12)?;
    let mut extents = Vec::new();
    for index in 0..8 {
        let start = be32(bytes, offset + 16 + index * 8)?;
        let count = be32(bytes, offset + 20 + index * 8)?;
        if count > 0 {
            extents.push((start, count));
        }
    }
    Some(Fork { size, blocks, extents })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub id: u32,
    pub path: String,
    /// The BSD mode, e.g. `0o100644`; zero when the volume records none.
    pub mode: u16,
    pub data: Fork,
    pub resource: Fork,
    /// The inode number for a hard link; the content lives in the volume's private folder.
    pub link_to: Option<u32>,
    pub compressed: bool,
}

impl File {
    pub fn is_symlink(&self) -> bool {
        self.mode & 0o170000 == 0o120000
    }
}

pub struct Volume<'a> {
    disk: &'a dyn Disk,
    pub block_size: u64,
    pub name: Option<String>,
    /// Extents beyond the first eight: `(file id, fork type, first block of the run) -> extents`.
    overflow: BTreeMap<(u32, u8, u32), Vec<(u32, u32)>>,
    pub files: Vec<File>,
    /// Content of hard-linked files: inode number -> index into `private`.
    inodes: BTreeMap<u32, usize>,
    /// Files of the private folders, which are not part of the visible tree.
    private: Vec<File>,
    /// `com.apple.decmpfs` values by file id.
    compressed: BTreeMap<u32, Vec<u8>>,
    /// What went wrong while reading the catalog, if it could only be read in part.
    pub damage: Option<String>,
}

/// The records of every leaf node of a B-tree file, visited through the leaf chain.
fn leaf_records(tree: &[u8], mut visit: impl FnMut(&[u8]) -> bool) -> Result<(), String> {
    let node_size = be16(tree, 14 + 18).ok_or("the B-tree header is truncated")? as usize;
    if !(512..=32768).contains(&node_size) || !node_size.is_power_of_two() {
        return Err(format!("the B-tree node size {node_size} is not valid"));
    }
    let total = tree.len() / node_size;
    let mut node = be32(tree, 14 + 10).ok_or("the B-tree header is truncated")? as usize;
    let mut seen = BTreeSet::new();
    while node != 0 {
        if node >= total || !seen.insert(node) {
            return Err(format!("the B-tree leaf chain is broken at node {node}"));
        }
        let bytes = &tree[node * node_size..(node + 1) * node_size];
        let kind = bytes[8] as i8;
        let records = be16(bytes, 10).unwrap_or(0) as usize;
        if kind != -1 {
            return Err(format!("node {node} in the leaf chain is not a leaf"));
        }
        if (records + 1) * 2 + 14 > node_size {
            return Err(format!("leaf node {node} claims {records} records"));
        }
        for index in 0..records {
            let start = be16(bytes, node_size - 2 * (index + 1)).unwrap_or(0) as usize;
            let end = be16(bytes, node_size - 2 * (index + 2)).unwrap_or(0) as usize;
            if start < 14 || end <= start || end > node_size {
                return Err(format!("record {index} of leaf node {node} has bad offsets"));
            }
            if !visit(&bytes[start..end]) {
                return Ok(());
            }
        }
        node = be32(bytes, 0).unwrap_or(0) as usize;
    }
    Ok(())
}

/// Splits a B-tree record into its key (without the length) and its data.
fn key_and_data(record: &[u8]) -> Option<(&[u8], &[u8])> {
    let key_length = be16(record, 0)? as usize;
    let key = slice(record, 2, key_length)?;
    // Data starts on an even offset.
    let data_at = (2 + key_length + 1) & !1;
    Some((key, record.get(data_at..)?))
}

fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|pair| u16::from_be_bytes([pair[0], pair[1]])).collect();
    String::from_utf16_lossy(&units)
}

enum Entry {
    Folder { id: u32, parent: u32, name: String },
    File { parent: u32, name: String, file: File },
}

fn catalog_entry(record: &[u8]) -> Option<Entry> {
    let (key, data) = key_and_data(record)?;
    let parent = be32(key, 0)?;
    let name_units = be16(key, 4)? as usize;
    let name = utf16(slice(key, 6, name_units.checked_mul(2)?)?);
    match be16(data, 0)? {
        1 => Some(Entry::Folder { id: be32(data, 8)?, parent, name }),
        2 => {
            let id = be32(data, 8)?;
            let mode = be16(data, 32 + 10)?;
            let special = be32(data, 32 + 12)?;
            let link_to = (slice(data, 48, 8)? == b"hlnkhfs+").then_some(special);
            Some(Entry::File {
                parent,
                name,
                file: File { id, path: String::new(), mode, data: fork(data, 88)?, resource: fork(data, 168)?, link_to, compressed: false },
            })
        }
        _ => None,
    }
}

impl<'a> Volume<'a> {
    pub fn open(disk: &'a dyn Disk) -> Result<Self, String> {
        let header = disk.read_vec(1024, 512).map_err(|e| format!("the volume header is unreadable: {e}"))?;
        let signature = &header[..2];
        if signature != b"H+" && signature != b"HX" {
            return Err("not an HFS+ volume".into());
        }
        let short = || "the volume header is truncated".to_string();
        let block_size = be32(&header, 40).ok_or_else(short)? as u64;
        if !(512..=1 << 24).contains(&block_size) || !block_size.is_power_of_two() {
            return Err(format!("the allocation block size {block_size} is not valid"));
        }
        let extents_fork = fork(&header, 192).ok_or_else(short)?;
        let catalog_fork = fork(&header, 272).ok_or_else(short)?;
        let attributes_fork = fork(&header, 352).ok_or_else(short)?;
        let mut volume = Volume {
            disk,
            block_size,
            name: None,
            overflow: BTreeMap::new(),
            files: Vec::new(),
            inodes: BTreeMap::new(),
            private: Vec::new(),
            compressed: BTreeMap::new(),
            damage: None,
        };

        if extents_fork.size > 0 {
            // The extents file has no overflow records of its own.
            let tree = volume.read_fork(EXTENTS_FILE, DATA_FORK, &extents_fork).map_err(|e| format!("extents overflow file: {e}"))?;
            let mut overflow = BTreeMap::new();
            let outcome = leaf_records(&tree, |record| {
                if let Some((key, data)) = key_and_data(record)
                    && let (Some(&fork_type), Some(id), Some(start)) = (key.first(), be32(key, 2), be32(key, 6))
                {
                    let extents: Vec<(u32, u32)> =
                        (0..8).filter_map(|i| Some((be32(data, i * 8)?, be32(data, i * 8 + 4)?))).filter(|e| e.1 > 0).collect();
                    overflow.insert((id, fork_type, start), extents);
                }
                overflow.len() < MAX_ENTRIES
            });
            volume.overflow = overflow;
            if let Err(error) = outcome {
                volume.damage = Some(format!("extents overflow file: {error}"));
            }
        }

        let catalog = volume.read_fork(CATALOG_FILE, DATA_FORK, &catalog_fork).map_err(|e| format!("catalog file: {e}"))?;
        // Folder id -> (parent id, name).
        let mut folders: BTreeMap<u32, (u32, String)> = BTreeMap::new();
        let mut files: Vec<(u32, String, File)> = Vec::new();
        let outcome = leaf_records(&catalog, |record| {
            match catalog_entry(record) {
                Some(Entry::Folder { id, parent, name }) => {
                    folders.insert(id, (parent, name));
                }
                Some(Entry::File { parent, name, file }) => files.push((parent, name, file)),
                None => {}
            }
            folders.len() + files.len() < MAX_ENTRIES
        });
        if let Err(error) = outcome {
            volume.damage = Some(format!("catalog file: {error}"));
        } else if folders.len() + files.len() >= MAX_ENTRIES {
            volume.damage = Some(format!("only the first {MAX_ENTRIES} catalog entries were read"));
        }
        volume.name = folders.get(&ROOT_FOLDER).map(|(_, name)| name.clone());

        if attributes_fork.size > 0 {
            match volume.read_fork(ATTRIBUTES_FILE, DATA_FORK, &attributes_fork) {
                Ok(tree) => {
                    let mut compressed = BTreeMap::new();
                    let outcome = leaf_records(&tree, |record| {
                        if let Some((key, data)) = key_and_data(record)
                            && let (Some(id), Some(units)) = (be32(key, 2), be16(key, 10))
                            && let Some(name) = slice(key, 12, units as usize * 2)
                            && utf16(name) == "com.apple.decmpfs"
                            && be32(data, 0) == Some(0x10)
                            && let Some(size) = be32(data, 12)
                            && let Some(value) = slice(data, 16, size as usize)
                        {
                            compressed.insert(id, value.to_vec());
                        }
                        compressed.len() < MAX_ENTRIES
                    });
                    volume.compressed = compressed;
                    if let Err(error) = outcome {
                        volume.damage.get_or_insert(format!("attributes file: {error}"));
                    }
                }
                Err(error) => {
                    volume.damage.get_or_insert(format!("attributes file: {error}"));
                }
            }
        }

        // The path of a folder, or `None` for the private folders and for broken parent chains.
        let folder_path = |mut id: u32| -> Option<Vec<&str>> {
            let mut parts = Vec::new();
            while id != ROOT_FOLDER {
                let (parent, name) = folders.get(&id)?;
                if parts.len() >= MAX_DEPTH {
                    return None;
                }
                parts.push(name.as_str());
                id = *parent;
            }
            parts.reverse();
            Some(parts)
        };
        let is_private = |name: &str| name.contains("HFS+ Private Data") || name.starts_with(".HFS+ Private Directory Data");
        for (parent, name, mut file) in files {
            let Some(mut parts) = folder_path(parent) else { continue };
            file.compressed = volume.compressed.contains_key(&file.id) && file.data.size == 0;
            if parts.first().is_some_and(|top| is_private(top)) {
                if let Some(number) = name.strip_prefix("iNode").and_then(|n| n.parse::<u32>().ok()) {
                    volume.inodes.insert(number, volume.private.len());
                }
                volume.private.push(file);
                continue;
            }
            parts.push(&name);
            // A `/` in a name is stored as it is and shown as `:`; NUL cannot be shown at all.
            file.path = parts.iter().map(|part| part.replace('/', ":").replace('\0', "")).collect::<Vec<_>>().join("/");
            volume.files.push(file);
        }
        volume.files.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(volume)
    }

    /// The runs of a fork on disk, following the extents overflow file where needed.
    fn runs(&self, id: u32, fork_type: u8, fork: &Fork) -> Result<Vec<(Option<u64>, u64)>, String> {
        let needed = fork.size.div_ceil(self.block_size);
        let mut runs = Vec::new();
        let mut covered: u64 = 0;
        let mut push = |extents: &[(u32, u32)], covered: &mut u64| -> Result<(), String> {
            for &(start, count) in extents {
                let offset = (start as u64).checked_mul(self.block_size).ok_or("extent overflow")?;
                let length = count as u64 * self.block_size;
                if offset.checked_add(length).is_none_or(|end| end > self.disk.len()) {
                    return Err("an extent lies outside the volume".into());
                }
                runs.push((Some(offset), length));
                *covered += count as u64;
            }
            Ok(())
        };
        push(&fork.extents, &mut covered)?;
        while covered < needed {
            let Ok(key) = u32::try_from(covered) else { break };
            let Some(more) = self.overflow.get(&(id, fork_type, key)) else {
                return Err(format!("extents cover {covered} of {needed} blocks"));
            };
            if more.is_empty() {
                return Err("an empty overflow extent record".into());
            }
            push(more, &mut covered)?;
        }
        Ok(runs)
    }

    fn read_fork(&self, id: u32, fork_type: u8, fork: &Fork) -> Result<Vec<u8>, String> {
        if fork.size > super::MAX_READ as u64 {
            return Err(format!("{} bytes is too large to read into memory", fork.size));
        }
        let mut out = Vec::with_capacity(fork.size as usize);
        std::io::Read::read_to_end(&mut RunReader::new(self.disk, self.runs(id, fork_type, fork)?, fork.size), &mut out)
            .map_err(|e| e.to_string())?;
        Ok(out)
    }

    /// The file that holds the content of `file`: itself, or the inode file of a hard link.
    fn content<'f>(&'f self, file: &'f File) -> Result<&'f File, String> {
        match file.link_to {
            None => Ok(file),
            Some(inode) => self
                .inodes
                .get(&inode)
                .and_then(|index| self.private.get(*index))
                .ok_or_else(|| format!("hard link target iNode{inode} is missing")),
        }
    }

    /// Opens the content of `file` for reading.
    pub fn open_file(&self, file: &File) -> Result<Box<dyn std::io::Read + '_>, String> {
        let file = self.content(file)?;
        if file.compressed
            && let Some(attribute) = self.compressed.get(&file.id)
        {
            let data = decmpfs::expand(attribute, || self.read_fork(file.id, RESOURCE_FORK, &file.resource))?;
            return Ok(Box::new(std::io::Cursor::new(data)));
        }
        Ok(Box::new(RunReader::new(self.disk, self.runs(file.id, DATA_FORK, &file.data)?, file.data.size)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_walk_survives_garbage() {
        // Header node only, pointing at a first leaf that does not exist.
        let mut tree = vec![0u8; 1024];
        tree[14 + 18..14 + 20].copy_from_slice(&512u16.to_be_bytes());
        tree[14 + 10..14 + 14].copy_from_slice(&9u32.to_be_bytes());
        assert!(leaf_records(&tree, |_| true).is_err());
        // A leaf that links to itself.
        tree[14 + 10..14 + 14].copy_from_slice(&1u32.to_be_bytes());
        tree[512..516].copy_from_slice(&1u32.to_be_bytes());
        tree[512 + 8] = 0xff;
        assert!(leaf_records(&tree, |_| true).is_err());
        // A leaf claiming more records than fit.
        tree[512 + 10..512 + 12].copy_from_slice(&60000u16.to_be_bytes());
        assert!(leaf_records(&tree, |_| true).is_err());
        // Bad node sizes.
        tree[14 + 18..14 + 20].copy_from_slice(&7u16.to_be_bytes());
        assert!(leaf_records(&tree, |_| true).is_err());
        assert!(leaf_records(&[], |_| true).is_err());
    }

    #[test]
    fn records_with_bad_keys_are_skipped() {
        assert!(catalog_entry(&[]).is_none());
        assert!(catalog_entry(&[0xff, 0xff, 0, 0]).is_none());
        // Key claims a 1000-unit name in a 12-byte record.
        let mut record = vec![0u8; 12];
        record[1] = 8;
        record[6..8].copy_from_slice(&1000u16.to_be_bytes());
        assert!(catalog_entry(&record).is_none());
    }

    #[test]
    fn open_rejects_non_volumes() {
        assert!(Volume::open(&super::super::RawDisk(&[0u8; 100])).is_err());
        assert!(Volume::open(&super::super::RawDisk(&[0u8; 4096])).is_err());
        let mut image = vec![0u8; 8192];
        image[1024..1026].copy_from_slice(b"H+");
        // Block size zero.
        assert!(Volume::open(&super::super::RawDisk(&image)).is_err());
        image[1024 + 40..1024 + 44].copy_from_slice(&4096u32.to_be_bytes());
        // Catalog fork claims data outside the image.
        image[1024 + 272..1024 + 280].copy_from_slice(&8192u64.to_be_bytes());
        image[1024 + 272 + 16..1024 + 272 + 20].copy_from_slice(&1000u32.to_be_bytes());
        image[1024 + 272 + 20..1024 + 272 + 24].copy_from_slice(&2u32.to_be_bytes());
        assert!(Volume::open(&super::super::RawDisk(&image)).is_err());
    }
}
