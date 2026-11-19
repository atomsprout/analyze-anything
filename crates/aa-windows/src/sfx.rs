//! Self-extracting archives: a PE stub with a 7z, ZIP, RAR or CAB archive appended.
//!
//! The archive is handed on as one child, which the generic unpackers then open. Overlays
//! that do not start with a known archive signature are left alone.

use aa_core::Artifact;
use aa_core::plugin::{SinkError, Unpack, UnpackSink, Unpacker};

use crate::pe::{Pe, u16_at, u32_at};

pub struct Sfx;

const SEVEN_ZIP: &[u8] = b"7z\xbc\xaf\x27\x1c";
const RAR: &[u8] = b"Rar!\x1a\x07";
const ZIP: &[u8] = b"PK\x03\x04";
const CAB: &[u8] = b"MSCF";

/// Finds an archive in the overlay: `(offset inside the overlay, child name)`.
fn find(overlay: &[u8]) -> Option<(usize, &'static str)> {
    for (magic, name) in [(SEVEN_ZIP, "[overlay].7z"), (RAR, "[overlay].rar"), (ZIP, "[overlay].zip"), (CAB, "[overlay].cab")] {
        if overlay.starts_with(magic) {
            return Some((0, name));
        }
    }
    // 7-Zip installers put a text configuration between the stub and the archive.
    if overlay.starts_with(b";!@Install@!") {
        let window = &overlay[..overlay.len().min(1024 * 1024)];
        return memchr::memmem::find(window, SEVEN_ZIP).map(|at| (at, "[overlay].7z"));
    }
    None
}

/// ZIP offsets may count from the start of the whole file. If so, returns a copy of the
/// archive with them rebased to the start of the overlay.
fn rebase_zip(archive: &[u8], shift: u32) -> Option<Vec<u8>> {
    // End of central directory: searched from the end, past a possible comment.
    let tail = archive.len().saturating_sub(65_557);
    let eocd = tail + memchr::memmem::rfind(&archive[tail..], b"PK\x05\x06")?;
    let entries = u16_at(archive, eocd + 10)? as usize;
    let directory = u32_at(archive, eocd + 16)?;
    // Offsets that already work need no change.
    if entries == 0 || archive.get(directory as usize..).is_some_and(|d| d.starts_with(b"PK\x01\x02")) {
        return None;
    }
    let mut at = directory.checked_sub(shift)? as usize;
    if !archive.get(at..)?.starts_with(b"PK\x01\x02") {
        return None;
    }
    let mut fixed = archive.to_vec();
    fixed.get_mut(eocd + 16..eocd + 20)?.copy_from_slice(&(directory - shift).to_le_bytes());
    for _ in 0..entries {
        if !archive.get(at..)?.starts_with(b"PK\x01\x02") {
            return None;
        }
        let local = u32_at(archive, at + 42)?.checked_sub(shift)?;
        fixed.get_mut(at + 42..at + 46)?.copy_from_slice(&local.to_le_bytes());
        at += 46 + u16_at(archive, at + 28)? as usize + u16_at(archive, at + 30)? as usize + u16_at(archive, at + 32)? as usize;
    }
    Some(fixed)
}

impl Unpacker for Sfx {
    fn id(&self) -> &'static str {
        "sfx"
    }

    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        if !bytes.starts_with(b"MZ") {
            return Unpack::NotMine;
        }
        let Ok(pe) = Pe::parse(bytes) else { return Unpack::NotMine };
        let Some((start, length)) = pe.overlay() else { return Unpack::NotMine };
        let overlay = &bytes[start..start + length];
        let Some((offset, name)) = find(overlay) else { return Unpack::NotMine };
        let archive = &overlay[offset..];
        let rebased =
            if name.ends_with(".zip") { u32::try_from(start + offset).ok().and_then(|shift| rebase_zip(archive, shift)) } else { None };
        let mut data = rebased.as_deref().unwrap_or(archive);
        match sink.add(name, &mut data) {
            Ok(()) | Err(SinkError::LimitReached) => Unpack::Done { kind: "sfx" },
            Err(SinkError::Read(detail)) => Unpack::Failed { kind: "sfx", detail },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_signatures_are_found() {
        assert_eq!(find(b"7z\xbc\xaf\x27\x1c\0\x04"), Some((0, "[overlay].7z")));
        assert_eq!(find(b"Rar!\x1a\x07\x01\x00"), Some((0, "[overlay].rar")));
        let with_config = b";!@Install@!UTF-8!\nTitle=\"x\"\n;!@InstallEnd@!7z\xbc\xaf\x27\x1c";
        assert_eq!(find(with_config), Some((with_config.len() - 6, "[overlay].7z")));
        assert_eq!(find(b"\0\0\0\0\xef\xbe\xad\xdeNullsoftInst"), None);
        assert_eq!(find(b""), None);
    }

    #[test]
    fn zip_offsets_are_rebased() {
        // One empty stored entry "a", offsets counted from 100 bytes before the archive.
        let mut zip = Vec::new();
        zip.extend_from_slice(b"PK\x03\x04");
        zip.extend_from_slice(&[0; 22]);
        zip.extend_from_slice(&[1, 0, 0, 0]);
        zip.push(b'a');
        let directory = zip.len() as u32;
        zip.extend_from_slice(b"PK\x01\x02");
        zip.extend_from_slice(&[0; 24]);
        zip.extend_from_slice(&[1, 0, 0, 0, 0, 0]);
        zip.extend_from_slice(&[0; 8]);
        zip.extend_from_slice(&100u32.to_le_bytes());
        zip.push(b'a');
        zip.extend_from_slice(b"PK\x05\x06");
        zip.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
        zip.extend_from_slice(&47u32.to_le_bytes());
        zip.extend_from_slice(&(directory + 100).to_le_bytes());
        zip.extend_from_slice(&[0, 0]);
        let fixed = rebase_zip(&zip, 100).expect("rebased");
        let eocd = fixed.len() - 22;
        assert_eq!(u32_at(&fixed, eocd + 16), Some(directory));
        assert_eq!(u32_at(&fixed, directory as usize + 42), Some(0));
        // Already-correct offsets and garbage are left alone.
        assert_eq!(rebase_zip(&fixed, 100), None);
        assert_eq!(rebase_zip(b"PK\x05\x06", 5), None);
        assert_eq!(rebase_zip(&zip[..zip.len() - 3], 100), None);
    }
}
