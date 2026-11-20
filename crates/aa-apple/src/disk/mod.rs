//! Disk images: the UDIF container (`.dmg`) and the HFS+ and APFS file systems inside it.

pub mod apfs;
pub mod decmpfs;
pub mod hfs;
pub mod udif;

use std::io::Read;

/// Largest single read from a disk into memory. File data is streamed and not bound by this.
pub const MAX_READ: usize = 512 * 1024 * 1024;

/// Random access to the bytes of a disk, a partition or a volume.
pub trait Disk {
    fn len(&self) -> u64;

    /// Fills `buf` from `offset`. Fails when the range is outside the disk or cannot be decoded.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), String>;

    fn read_vec(&self, offset: u64, length: usize) -> Result<Vec<u8>, String> {
        if length > MAX_READ {
            return Err(format!("refusing to read {length} bytes at once"));
        }
        let end = offset.checked_add(length as u64).ok_or("offset overflow")?;
        if end > self.len() {
            return Err(format!("read of {length} bytes at {offset} is past the end ({})", self.len()));
        }
        let mut buf = vec![0u8; length];
        self.read_at(offset, &mut buf)?;
        Ok(buf)
    }
}

/// A disk that is plain bytes in memory.
pub struct RawDisk<'a>(pub &'a [u8]);

impl Disk for RawDisk<'_> {
    fn len(&self) -> u64 {
        self.0.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), String> {
        let start = usize::try_from(offset).map_err(|_| "offset overflow")?;
        let source = crate::util::slice(self.0, start, buf.len()).ok_or("read past the end of the image")?;
        buf.copy_from_slice(source);
        Ok(())
    }
}

/// A window into another disk.
pub struct SubDisk<'a> {
    pub inner: &'a dyn Disk,
    pub start: u64,
    pub length: u64,
}

impl Disk for SubDisk<'_> {
    fn len(&self) -> u64 {
        self.length
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), String> {
        let end = offset.checked_add(buf.len() as u64).ok_or("offset overflow")?;
        if end > self.length {
            return Err("read past the end of the partition".into());
        }
        self.inner.read_at(self.start.checked_add(offset).ok_or("offset overflow")?, buf)
    }
}

/// Reads a file's data from its runs on disk, in order, up to its logical size.
pub struct RunReader<'a> {
    disk: &'a dyn Disk,
    /// `(offset on disk, length)`; `None` as offset is a hole that reads as zeros.
    runs: Vec<(Option<u64>, u64)>,
    run: usize,
    within: u64,
    remaining: u64,
}

impl<'a> RunReader<'a> {
    pub fn new(disk: &'a dyn Disk, runs: Vec<(Option<u64>, u64)>, size: u64) -> Self {
        RunReader { disk, runs, run: 0, within: 0, remaining: size }
    }
}

impl Read for RunReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.remaining > 0 && !buf.is_empty() {
            let Some(&(offset, length)) = self.runs.get(self.run) else {
                return Err(std::io::Error::other("the file's extents end before its size"));
            };
            if self.within >= length {
                self.run += 1;
                self.within = 0;
                continue;
            }
            let take = (length - self.within).min(self.remaining).min(buf.len() as u64).min(1 << 20) as usize;
            match offset {
                Some(offset) => {
                    let at = offset.checked_add(self.within).ok_or_else(|| std::io::Error::other("offset overflow"))?;
                    self.disk.read_at(at, &mut buf[..take]).map_err(std::io::Error::other)?;
                }
                None => buf[..take].fill(0),
            }
            self.within += take as u64;
            self.remaining -= take as u64;
            return Ok(take);
        }
        Ok(0)
    }
}

/// A file system found on a disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeKind {
    HfsPlus,
    Apfs,
}

/// Where the supported file systems on `disk` start: the disk itself, or the partitions of a
/// GUID or Apple partition map. Unrecognised content gives an empty list.
pub fn find_volumes(disk: &dyn Disk) -> Vec<(u64, u64, VolumeKind)> {
    let probe = |start: u64| -> Option<VolumeKind> {
        let head = disk.read_vec(start, 2048).ok()?;
        if head.get(32..36) == Some(b"NXSB") {
            return Some(VolumeKind::Apfs);
        }
        // Two letters are not enough to go by: any file may hold "H+" at that place (a picture
        // did). The header's version and block size must make sense for the letters as well.
        let header = head.get(1024..1024 + 44)?;
        let version = u16::from_be_bytes([header[2], header[3]]);
        let block = u32::from_be_bytes([header[40], header[41], header[42], header[43]]);
        let looks_right = match &header[..2] {
            b"H+" => version == 4,
            b"HX" => version == 5,
            _ => false,
        };
        (looks_right && (512..=1 << 24).contains(&block) && block.is_power_of_two()).then_some(VolumeKind::HfsPlus)
    };
    if let Some(kind) = probe(0) {
        return vec![(0, disk.len(), kind)];
    }
    let mut found = Vec::new();
    let mut consider = |start: u64, length: u64| {
        if start < disk.len()
            && length > 0
            && let Some(kind) = probe(start)
        {
            found.push((start, length.min(disk.len() - start), kind));
        }
    };
    let Ok(head) = disk.read_vec(0, 1024.min(disk.len() as usize)) else { return found };
    if head.get(512..520) == Some(b"EFI PART") {
        // GUID partition table: entries of `size` bytes from sector `first`.
        let (Some(first), Some(count), Some(size)) =
            (crate::util::le64(&head, 512 + 72), crate::util::le32(&head, 512 + 80), crate::util::le32(&head, 512 + 84))
        else {
            return found;
        };
        let (count, size) = (count.min(256) as u64, size as u64);
        if !(48..=4096).contains(&size) {
            return found;
        }
        let Some(table_at) = first.checked_mul(512) else { return found };
        let Ok(table) = disk.read_vec(table_at, (count * size) as usize) else { return found };
        for entry in table.chunks_exact(size as usize) {
            if let (Some(start), Some(end)) = (crate::util::le64(entry, 32), crate::util::le64(entry, 40))
                && end >= start
                && let (Some(start), Some(length)) = (start.checked_mul(512), (end - start + 1).checked_mul(512))
            {
                consider(start, length);
            }
        }
    } else if head.get(512..514) == Some(b"PM") {
        // Apple partition map: one 512-byte entry per partition, starting at sector 1.
        let count = crate::util::be32(&head, 512 + 4).unwrap_or(0).min(64) as u64;
        for index in 0..count {
            let Ok(entry) = disk.read_vec(512 * (1 + index), 512) else { break };
            if entry.get(0..2) != Some(b"PM") {
                break;
            }
            if let (Some(start), Some(blocks)) = (crate::util::be32(&entry, 8), crate::util::be32(&entry, 12)) {
                consider(start as u64 * 512, blocks as u64 * 512);
            }
        }
    }
    found
}

/// Names a file system this crate cannot read, from its signature, for a limitation's detail.
pub fn foreign_filesystem(disk: &dyn Disk) -> Option<&'static str> {
    let head = disk.read_vec(0, 2048.min(disk.len() as usize)).ok()?;
    if head.get(1024..1026) == Some(b"BD") {
        return Some("HFS (classic)");
    }
    if head.get(54..59) == Some(b"FAT12") || head.get(54..59) == Some(b"FAT16") || head.get(82..87) == Some(b"FAT32") {
        return Some("FAT");
    }
    if head.get(3..8) == Some(b"EXFAT") {
        return Some("exFAT");
    }
    if disk.read_vec(0x8001, 5).ok().as_deref() == Some(b"CD001") {
        return Some("ISO 9660");
    }
    None
}
