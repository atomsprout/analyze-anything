//! The ZIP structures of an APK, read straight from its bytes.
//!
//! Archive libraries hide what an attacker plays with: duplicate names, local headers that
//! disagree with the central directory, data in front of the first entry. Android itself reads
//! the central directory, so that is the view taken here, and everything is cross-checked
//! against the local headers.

use std::collections::BTreeMap;
use std::io::Read;

use crate::reader::{slice_at, u16_at, u32_at, u64_at};

const EOCD_SIG: u32 = 0x0605_4b50;
const CD_SIG: u32 = 0x0201_4b50;
const LFH_SIG: u32 = 0x0403_4b50;
const ZIP64_LOCATOR_SIG: u32 = 0x0706_4b50;
const EOCD_MIN: usize = 22;
/// Entries read from one archive.
pub const MAX_ENTRIES: usize = 400_000;

#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub name: String,
    pub flags: u16,
    pub method: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub local_offset: u64,
    /// Offset of the entry's record in the central directory.
    pub cd_offset: u64,
    /// Offset of the entry's data, from its local header. `None` when the local header is unreadable.
    pub data_offset: Option<u64>,
    /// How the local header differs from the central record, if it does.
    pub local_mismatch: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Archive {
    pub eocd_offset: u64,
    pub cd_offset: u64,
    pub cd_size: u64,
    pub comment_len: u16,
    /// Number of entries the end record declares.
    pub declared_entries: u64,
    pub zip64: bool,
    pub entries: Vec<Entry>,
    /// True when the central directory could not be read to its end.
    pub truncated: bool,
    /// Offset of the first local header: bytes before it belong to no entry.
    pub first_local_offset: Option<u64>,
    /// Bytes after the end record and its comment. Android's signature schemes v2+ and
    /// apksigner do not accept such a file.
    pub trailing_bytes: u64,
}

/// Finds the end-of-central-directory record: the last one whose comment ends exactly at the
/// end of the file, which is the rule Android and apksigner apply.
pub fn find_eocd(data: &[u8]) -> Option<usize> {
    if data.len() < EOCD_MIN {
        return None;
    }
    let lowest = data.len().saturating_sub(EOCD_MIN + 0xffff);
    let mut pos = data.len() - EOCD_MIN;
    loop {
        if u32_at(data, pos) == Some(EOCD_SIG) && usize::from(u16_at(data, pos + 20)?) == data.len() - pos - EOCD_MIN {
            return Some(pos);
        }
        if pos == lowest {
            return None;
        }
        pos -= 1;
    }
}

/// The last end record whose comment fits in the file, whatever follows it.
fn find_eocd_loose(data: &[u8]) -> Option<usize> {
    let lowest = data.len().checked_sub(EOCD_MIN)?.saturating_sub(4 * 1024 * 1024);
    let mut pos = data.len() - EOCD_MIN;
    loop {
        if u32_at(data, pos) == Some(EOCD_SIG) && usize::from(u16_at(data, pos + 20)?) <= data.len() - pos - EOCD_MIN {
            return Some(pos);
        }
        if pos == lowest {
            return None;
        }
        pos -= 1;
    }
}

pub fn parse(data: &[u8]) -> Option<Archive> {
    let eocd = find_eocd(data).or_else(|| find_eocd_loose(data))?;
    let mut declared_entries = u64::from(u16_at(data, eocd + 10)?);
    let mut cd_size = u64::from(u32_at(data, eocd + 12)?);
    let mut cd_offset = u64::from(u32_at(data, eocd + 16)?);
    let comment_len = u16_at(data, eocd + 20)?;
    let mut zip64 = false;
    if eocd >= 20 && u32_at(data, eocd - 20) == Some(ZIP64_LOCATOR_SIG) {
        zip64 = true;
        if let Some(record) = u64_at(data, eocd - 20 + 8).and_then(|o| usize::try_from(o).ok())
            && u32_at(data, record) == Some(0x0606_4b50)
        {
            declared_entries = u64_at(data, record + 32)?;
            cd_size = u64_at(data, record + 40)?;
            cd_offset = u64_at(data, record + 48)?;
        }
    }
    let mut archive = Archive {
        eocd_offset: eocd as u64,
        cd_offset,
        cd_size,
        comment_len,
        declared_entries,
        zip64,
        entries: Vec::new(),
        truncated: false,
        first_local_offset: None,
        trailing_bytes: (data.len() - eocd - EOCD_MIN).saturating_sub(usize::from(comment_len)) as u64,
    };
    let mut pos = usize::try_from(cd_offset).ok()?;
    let cd_end = pos.checked_add(usize::try_from(cd_size).ok()?)?.min(eocd);
    while pos + 46 <= cd_end {
        if u32_at(data, pos) != Some(CD_SIG) {
            archive.truncated = true;
            break;
        }
        if archive.entries.len() >= MAX_ENTRIES {
            archive.truncated = true;
            break;
        }
        let name_len = usize::from(u16_at(data, pos + 28)?);
        let extra_len = usize::from(u16_at(data, pos + 30)?);
        let comment = usize::from(u16_at(data, pos + 32)?);
        let Some(name) = slice_at(data, pos + 46, name_len) else {
            archive.truncated = true;
            break;
        };
        let mut entry = Entry {
            name: String::from_utf8_lossy(name).into_owned(),
            flags: u16_at(data, pos + 8)?,
            method: u16_at(data, pos + 10)?,
            crc32: u32_at(data, pos + 16)?,
            compressed_size: u64::from(u32_at(data, pos + 20)?),
            uncompressed_size: u64::from(u32_at(data, pos + 24)?),
            local_offset: u64::from(u32_at(data, pos + 42)?),
            cd_offset: pos as u64,
            data_offset: None,
            local_mismatch: None,
        };
        check_local(data, &mut entry, name);
        archive.first_local_offset = Some(archive.first_local_offset.map_or(entry.local_offset, |o: u64| o.min(entry.local_offset)));
        archive.entries.push(entry);
        pos += 46 + name_len + extra_len + comment;
    }
    if pos < cd_end && !archive.truncated && cd_end - pos >= 4 && u32_at(data, pos) == Some(CD_SIG) {
        archive.truncated = true;
    }
    Some(archive)
}

fn check_local(data: &[u8], entry: &mut Entry, central_name: &[u8]) {
    let Ok(at) = usize::try_from(entry.local_offset) else { return };
    if u32_at(data, at) != Some(LFH_SIG) {
        entry.local_mismatch = Some("no local header at the recorded offset".into());
        return;
    }
    let (Some(flags), Some(method), Some(name_len), Some(extra_len)) =
        (u16_at(data, at + 6), u16_at(data, at + 8), u16_at(data, at + 26), u16_at(data, at + 28))
    else {
        entry.local_mismatch = Some("local header is cut short".into());
        return;
    };
    let (name_len, extra_len) = (usize::from(name_len), usize::from(extra_len));
    entry.data_offset = Some((at + 30 + name_len + extra_len) as u64);
    let mut differences = Vec::new();
    match slice_at(data, at + 30, name_len) {
        Some(local_name) if local_name == central_name => {}
        Some(local_name) => differences.push(format!("name \"{}\"", String::from_utf8_lossy(&local_name[..local_name.len().min(120)]))),
        None => differences.push("name runs past the file".into()),
    }
    if method != entry.method {
        differences.push(format!("compression method {method} (central directory: {})", entry.method));
    }
    // With a data descriptor (flag bit 3) the local sizes are legitimately zero.
    if flags & 0x08 == 0 {
        let local_compressed = u32_at(data, at + 18).map(u64::from);
        let local_uncompressed = u32_at(data, at + 22).map(u64::from);
        if local_compressed != Some(entry.compressed_size) || local_uncompressed != Some(entry.uncompressed_size) {
            differences.push("sizes".into());
        }
    }
    if flags & 0x01 != entry.flags & 0x01 {
        differences.push("encryption flag".into());
    }
    if !differences.is_empty() {
        entry.local_mismatch = Some(format!("local header differs in {}", differences.join(", ")));
    }
}

impl Archive {
    /// Names that appear more than once in the central directory, with their counts.
    pub fn duplicate_names(&self) -> Vec<(String, usize)> {
        let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
        for entry in &self.entries {
            *counts.entry(entry.name.as_str()).or_default() += 1;
        }
        counts.into_iter().filter(|(_, n)| *n > 1).map(|(name, n)| (name.to_string(), n)).collect()
    }

    /// The entry Android uses for `name`: with duplicates, the last one in the central directory.
    pub fn entry(&self, name: &str) -> Option<&Entry> {
        self.entries.iter().rev().find(|e| e.name == name)
    }
}

impl Entry {
    /// The entry's raw data the way Android reads it: deflate data when the method is 8,
    /// otherwise the bytes as they are, whatever the method field says. Malware sets bogus
    /// methods and compressed sizes on stored entries, which stops ZIP tools but not the device.
    pub fn android_data<'a>(&self, data: &'a [u8]) -> Result<(bool, &'a [u8]), String> {
        let offset = self.data_offset.ok_or("no readable local header")?;
        let start = usize::try_from(offset).map_err(|_| "offset out of range")?;
        let deflated = self.method == 8;
        let size = if deflated || self.method == 0 { self.compressed_size } else { self.uncompressed_size };
        let length = usize::try_from(size).map_err(|_| "size out of range")?;
        let raw = slice_at(data, start, length).ok_or("entry data runs past the file")?;
        Ok((deflated, raw))
    }
}

/// Feeds an entry's uncompressed bytes to `sink` in pieces, never holding more than a buffer.
/// Fails on bad deflate data or more than `limit` bytes.
pub fn stream_entry(data: &[u8], entry: &Entry, limit: u64, mut sink: impl FnMut(&[u8])) -> Result<u64, String> {
    let (deflated, raw) = entry.android_data(data)?;
    if !deflated {
        if raw.len() as u64 > limit {
            return Err("entry is larger than the limit".into());
        }
        sink(raw);
        return Ok(raw.len() as u64);
    }
    let mut decoder = flate2::read::DeflateDecoder::new(raw);
    let mut buffer = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = decoder.read(&mut buffer).map_err(|e| format!("deflate: {e}"))?;
        if read == 0 {
            return Ok(total);
        }
        total += read as u64;
        if total > limit {
            return Err("entry is larger than the limit".into());
        }
        sink(&buffer[..read]);
    }
}

/// Reads a whole entry into memory, up to `limit` bytes.
pub fn read_entry(data: &[u8], entry: &Entry, limit: u64) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    stream_entry(data, entry, limit, |piece| out.extend_from_slice(piece))?;
    Ok(out)
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Builds a stored-only ZIP from `(name, data)` pairs, with `prefix` bytes in front.
    pub fn build_zip(prefix: &[u8], files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = prefix.to_vec();
        let mut central = Vec::new();
        for (name, data) in files {
            let offset = out.len() as u32;
            let crc = crc32(data);
            let mut common = Vec::new();
            common.extend_from_slice(&20u16.to_le_bytes()); // version needed
            common.extend_from_slice(&0u16.to_le_bytes()); // flags
            common.extend_from_slice(&0u16.to_le_bytes()); // method
            common.extend_from_slice(&[0, 0, 0x21, 0]); // time, date
            common.extend_from_slice(&crc.to_le_bytes());
            common.extend_from_slice(&(data.len() as u32).to_le_bytes());
            common.extend_from_slice(&(data.len() as u32).to_le_bytes());
            common.extend_from_slice(&(name.len() as u16).to_le_bytes());
            common.extend_from_slice(&0u16.to_le_bytes()); // extra
            out.extend_from_slice(&LFH_SIG.to_le_bytes());
            out.extend_from_slice(&common);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(data);
            central.extend_from_slice(&CD_SIG.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes()); // version made by
            central.extend_from_slice(&common);
            central.extend_from_slice(&[0; 2 + 2 + 2 + 4]); // comment, disk, internal, external
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
        }
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(&EOCD_SIG.to_le_bytes());
        out.extend_from_slice(&[0; 4]);
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(files.len() as u16).to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    pub fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xffff_ffffu32;
        for byte in data {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
            }
        }
        !crc
    }

    #[test]
    fn reads_entries_and_data() {
        let zip = build_zip(b"", &[("a.txt", b"hello"), ("dir/b.bin", &[1, 2, 3])]);
        let archive = parse(&zip).expect("archive");
        assert_eq!(archive.entries.len(), 2);
        assert_eq!(archive.declared_entries, 2);
        assert_eq!(archive.first_local_offset, Some(0));
        assert!(archive.entries.iter().all(|e| e.local_mismatch.is_none()));
        assert!(archive.duplicate_names().is_empty());
        let entry = archive.entry("a.txt").expect("entry");
        assert_eq!(read_entry(&zip, entry, 100).expect("data"), b"hello");
        assert!(read_entry(&zip, entry, 2).is_err());
    }

    #[test]
    fn sees_duplicates_prefix_and_local_mismatch() {
        let mut zip = build_zip(b"dex\n035\0junk", &[("classes.dex", b"one"), ("classes.dex", b"two"), ("x", b"y")]);
        let archive = parse(&zip).expect("archive");
        assert_eq!(archive.duplicate_names(), vec![("classes.dex".to_string(), 2)]);
        assert_eq!(archive.first_local_offset, Some(12));
        assert_eq!(read_entry(&zip, archive.entry("classes.dex").expect("entry"), 10).expect("data"), b"two");
        // Rename the last entry in its local header only.
        let at = usize::try_from(archive.entries[2].local_offset).expect("offset") + 30;
        zip[at] = b'z';
        let archive = parse(&zip).expect("archive");
        assert!(archive.entries[2].local_mismatch.as_deref().is_some_and(|m| m.contains("name")));
    }

    #[test]
    fn truncation_and_corruption_do_not_panic() {
        let zip = build_zip(b"", &[("a", b"1234567890"), ("b", b"x")]);
        for cut in 0..zip.len() {
            if let Some(archive) = parse(&zip[..cut]) {
                for e in &archive.entries {
                    let _ = read_entry(&zip[..cut], e, 100);
                }
            }
        }
        for i in 0..zip.len() {
            for v in [0u8, 0xff] {
                let mut bad = zip.clone();
                bad[i] = v;
                if let Some(archive) = parse(&bad) {
                    for e in &archive.entries {
                        let _ = read_entry(&bad, e, 100);
                    }
                }
            }
        }
    }

    #[test]
    fn eocd_must_end_the_file() {
        let mut zip = build_zip(b"", &[("a", b"1")]);
        zip.extend_from_slice(b"trailing");
        assert!(find_eocd(&zip).is_none());
        let archive = parse(&zip).expect("archive");
        assert_eq!(archive.trailing_bytes, 8);
        assert_eq!(archive.entries.len(), 1);
    }
}
