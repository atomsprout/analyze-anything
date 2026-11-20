//! Microsoft Cabinet archives: uncompressed, MSZIP and LZX folders.
//!
//! The container is read here rather than with the `cab` crate, which re-decompresses a folder
//! from its start for every file (quadratic on the large single-folder cabinets installers
//! ship). LZX decoding is the `lzxd` crate's; MSZIP is deflate with the previous block as
//! dictionary.

use aa_core::Artifact;
use aa_core::plugin::{Rule, SinkError, Unpack, UnpackSink, Unpacker};

use crate::pe::{u16_at, u32_at};

/// Files larger than this are not extracted: a file is held in memory while it is handed on.
const MAX_FILE: u64 = 1024 * 1024 * 1024;
const MAX_FILES: usize = 1_000_000;

#[derive(Debug, Clone)]
pub struct CabFile {
    pub name: String,
    pub size: u32,
    /// Offset of the file's data inside its folder's uncompressed stream.
    pub offset: u32,
    /// Folder index; `None` for files that continue from or into another cabinet.
    pub folder: Option<u16>,
}

#[derive(Debug, Clone)]
struct Folder {
    first_block: usize,
    blocks: u16,
    compression: u16,
}

#[derive(Debug)]
pub struct Cabinet<'a> {
    data: &'a [u8],
    folders: Vec<Folder>,
    pub files: Vec<CabFile>,
    /// Reserved bytes in front of every data block's payload.
    block_reserve: usize,
}

fn cstring(data: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let rest = data.get(at..)?;
    let rest = &rest[..rest.len().min(1024)];
    let end = rest.iter().position(|&b| b == 0)?;
    Some((&rest[..end], at + end + 1))
}

pub fn parse(data: &[u8]) -> Result<Cabinet<'_>, String> {
    if !data.starts_with(b"MSCF") {
        return Err("no MSCF signature".into());
    }
    let short = "cabinet header cut short";
    let files_offset = u32_at(data, 16).ok_or(short)? as usize;
    let folder_count = u16_at(data, 26).ok_or(short)? as usize;
    let file_count = u16_at(data, 28).ok_or(short)? as usize;
    let flags = u16_at(data, 30).ok_or(short)?;
    let mut at = 36;
    let (mut folder_reserve, mut block_reserve) = (0usize, 0usize);
    if flags & 4 != 0 {
        let header_reserve = u16_at(data, at).ok_or(short)? as usize;
        folder_reserve = *data.get(at + 2).ok_or(short)? as usize;
        block_reserve = *data.get(at + 3).ok_or(short)? as usize;
        at += 4 + header_reserve;
    }
    // Names of the previous and next cabinet and disk.
    for flag in [1u16, 2] {
        if flags & flag != 0 {
            for _ in 0..2 {
                at = cstring(data, at).ok_or(short)?.1;
            }
        }
    }
    let mut folders = Vec::new();
    for _ in 0..folder_count {
        let header = data.get(at..at + 8).ok_or("folder table cut short")?;
        folders.push(Folder {
            first_block: u32_at(header, 0).unwrap_or(0) as usize,
            blocks: u16_at(header, 4).unwrap_or(0),
            compression: u16_at(header, 6).unwrap_or(0),
        });
        at += 8 + folder_reserve;
    }
    let mut files = Vec::new();
    let mut at = files_offset;
    for _ in 0..file_count.min(MAX_FILES) {
        let header = data.get(at..at.saturating_add(16)).ok_or("file table cut short")?;
        let folder = u16_at(header, 8).unwrap_or(0);
        let attributes = u16_at(header, 14).unwrap_or(0);
        let (raw, next) = cstring(data, at + 16).ok_or("file name not terminated")?;
        // Attribute 0x80 marks a UTF-8 name; otherwise it is the OEM code page, read as Latin-1.
        let name =
            if attributes & 0x80 != 0 { String::from_utf8_lossy(raw).into_owned() } else { raw.iter().map(|&b| b as char).collect() };
        files.push(CabFile {
            name,
            size: u32_at(header, 0).unwrap_or(0),
            offset: u32_at(header, 4).unwrap_or(0),
            // 0xFFFD..0xFFFF: continued from the previous or into the next cabinet.
            folder: ((folder as usize) < folders.len()).then_some(folder),
        });
        at = next;
    }
    Ok(Cabinet { data, folders, files, block_reserve })
}

enum Codec {
    Stored,
    MsZip { dictionary: Vec<u8> },
    Lzx(Box<lzxd::Lzxd>),
}

impl Codec {
    fn new(compression: u16) -> Result<Codec, String> {
        match compression & 0x0f {
            0 => Ok(Codec::Stored),
            1 => Ok(Codec::MsZip { dictionary: Vec::new() }),
            2 => Err("Quantum compression is not supported".into()),
            3 => {
                let window = match (compression >> 8) & 0x1f {
                    15 => lzxd::WindowSize::KB32,
                    16 => lzxd::WindowSize::KB64,
                    17 => lzxd::WindowSize::KB128,
                    18 => lzxd::WindowSize::KB256,
                    19 => lzxd::WindowSize::KB512,
                    20 => lzxd::WindowSize::MB1,
                    21 => lzxd::WindowSize::MB2,
                    22 => lzxd::WindowSize::MB4,
                    23 => lzxd::WindowSize::MB8,
                    24 => lzxd::WindowSize::MB16,
                    25 => lzxd::WindowSize::MB32,
                    other => return Err(format!("LZX window of 2^{other} bytes is not valid")),
                };
                Ok(Codec::Lzx(Box::new(lzxd::Lzxd::new(window))))
            }
            other => Err(format!("unknown compression type {other}")),
        }
    }

    fn block(&mut self, payload: &[u8], uncompressed: usize) -> Result<Vec<u8>, String> {
        match self {
            Codec::Stored => Ok(payload.to_vec()),
            Codec::MsZip { dictionary } => {
                let deflate = payload.strip_prefix(b"CK").ok_or("MSZIP block without CK signature")?;
                let mut inflater = flate2::Decompress::new(false);
                // Prime the window with the previous block's output, fed as a stored block.
                if !dictionary.is_empty() {
                    let length = dictionary.len() as u16;
                    let mut stored = vec![0u8];
                    stored.extend_from_slice(&length.to_le_bytes());
                    stored.extend_from_slice(&(!length).to_le_bytes());
                    stored.extend_from_slice(dictionary);
                    let mut sink = Vec::with_capacity(dictionary.len());
                    inflater.decompress_vec(&stored, &mut sink, flate2::FlushDecompress::Sync).map_err(|e| e.to_string())?;
                }
                let mut out = Vec::with_capacity(uncompressed);
                inflater.decompress_vec(deflate, &mut out, flate2::FlushDecompress::Finish).map_err(|e| format!("MSZIP: {e}"))?;
                if out.len() != uncompressed {
                    return Err(format!("MSZIP block gave {} bytes, the header says {uncompressed}", out.len()));
                }
                dictionary.extend_from_slice(&out);
                if dictionary.len() > 32768 {
                    dictionary.drain(..dictionary.len() - 32768);
                }
                Ok(out)
            }
            Codec::Lzx(decoder) => {
                // The decoder is third-party code fed hostile input: a panic becomes an error.
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    decoder.decompress_next(payload, uncompressed).map(<[u8]>::to_vec)
                }));
                match result {
                    Ok(Ok(out)) => Ok(out),
                    Ok(Err(error)) => Err(format!("LZX: {error}")),
                    Err(_) => Err("LZX decoder failed on this data".into()),
                }
            }
        }
    }
}

impl Cabinet<'_> {
    /// Decompresses every folder once, handing each file's bytes to `visit` in folder order.
    /// `visit` returns false to stop. Returns the problems met on the way.
    pub fn extract(&self, mut visit: impl FnMut(&CabFile, &[u8]) -> bool) -> Vec<String> {
        let mut problems = Vec::new();
        let partial = self.files.iter().filter(|f| f.folder.is_none()).count();
        if partial > 0 {
            problems.push(aa_core::counted(partial as u64, "files continue in another cabinet of the set"));
        }
        for (index, folder) in self.folders.iter().enumerate() {
            let mut wanted: Vec<&CabFile> = self.files.iter().filter(|f| f.folder == Some(index as u16)).collect();
            wanted.sort_by_key(|f| f.offset);
            wanted.retain(|f| {
                let fits = u64::from(f.size) <= MAX_FILE;
                if !fits {
                    problems.push(format!("{}: larger than the extraction limit", f.name));
                }
                fits
            });
            if wanted.is_empty() {
                continue;
            }
            let mut codec = match Codec::new(folder.compression) {
                Ok(codec) => codec,
                Err(error) => {
                    problems.push(format!("folder {index} ({} files): {error}", wanted.len()));
                    continue;
                }
            };
            // `buffer` holds the folder's uncompressed bytes from `buffer_start` on.
            let (mut buffer, mut buffer_start) = (Vec::new(), 0u64);
            let mut next = 0usize;
            let mut at = folder.first_block;
            'blocks: for block in 0..folder.blocks {
                let Some(header) = self.data.get(at..at.saturating_add(8)) else {
                    problems.push(format!("folder {index}: data block {block} lies outside the file"));
                    break;
                };
                let compressed = u16_at(header, 4).unwrap_or(0) as usize;
                let uncompressed = u16_at(header, 6).unwrap_or(0) as usize;
                let start = at + 8 + self.block_reserve;
                let Some(payload) = self.data.get(start..start.saturating_add(compressed)) else {
                    problems.push(format!("folder {index}: data block {block} is cut short"));
                    break;
                };
                at = start + compressed;
                // A zero uncompressed size means the block continues in the next cabinet.
                if uncompressed == 0 {
                    problems.push(format!("folder {index}: continues in another cabinet"));
                    break;
                }
                match codec.block(payload, uncompressed) {
                    Ok(data) => buffer.extend_from_slice(&data),
                    Err(error) => {
                        problems.push(format!("folder {index}, block {block}: {error}"));
                        break;
                    }
                }
                let available = buffer_start + buffer.len() as u64;
                while let Some(file) = wanted.get(next) {
                    let (start, end) = (u64::from(file.offset), u64::from(file.offset) + u64::from(file.size));
                    if end > available {
                        break;
                    }
                    next += 1;
                    if start < buffer_start {
                        problems.push(format!("{}: overlaps another file's data", file.name));
                        continue;
                    }
                    let slice = &buffer[(start - buffer_start) as usize..(end - buffer_start) as usize];
                    if !visit(file, slice) {
                        return problems;
                    }
                }
                // Drop what no remaining file needs.
                let keep_from = wanted.get(next).map_or(available, |f| u64::from(f.offset).clamp(buffer_start, available));
                buffer.drain(..(keep_from - buffer_start) as usize);
                buffer_start = keep_from;
                if next == wanted.len() {
                    break 'blocks;
                }
            }
            if next < wanted.len() {
                problems.push(format!("folder {index}: {} files could not be read", wanted.len() - next));
            }
        }
        problems
    }
}

pub struct Cab;

pub const RULES: &[Rule] = &[Rule {
    id: "cab.files-unreadable",
    title_zh: "CAB 包内部分文件无法提取",
    title_en: "Some files in the cabinet could not be extracted",
    text_zh: "压缩包里有文件无法解压（数据损坏、分卷不全，或使用了不支持的 Quantum 压缩），这些文件没有分析。",
    text_en: "Some files in the cabinet could not be decompressed (damaged data, a missing part of a multi-cabinet set, or unsupported Quantum compression). They were not analyzed.",
}];

impl Unpacker for Cab {
    fn id(&self) -> &'static str {
        "cab"
    }

    fn rules(&self) -> &'static [Rule] {
        RULES
    }

    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        if !bytes.starts_with(b"MSCF") {
            return Unpack::NotMine;
        }
        let cabinet = match parse(bytes) {
            Ok(cabinet) => cabinet,
            Err(detail) => return Unpack::Failed { kind: "cab", detail },
        };
        let problems = cabinet.extract(|file, mut data| !matches!(sink.add(&file.name, &mut data), Err(SinkError::LimitReached)));
        if !problems.is_empty() {
            let shown = problems.iter().take(5).cloned().collect::<Vec<_>>().join("; ");
            sink.limitation("cab.files-unreadable", Some(format!("{} problems: {shown}", problems.len())));
        }
        Unpack::Done { kind: "cab" }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_cabinets_do_not_panic() {
        let good = include_bytes!("../tests/data/fixture.cab");
        assert!(parse(b"MSCF").is_err());
        assert!(parse(b"nope").is_err());
        for cut in [8, 20, 36, 40, 60, 80, 120, good.len() / 2, good.len() - 1] {
            if let Ok(cabinet) = parse(&good[..cut]) {
                cabinet.extract(|_, _| true);
            }
        }
        // Every header field in turn set to all ones.
        for at in (4..64.min(good.len() - 4)).step_by(2) {
            let mut bad = good.to_vec();
            bad[at..at + 4].copy_from_slice(&[0xff; 4]);
            if let Ok(cabinet) = parse(&bad) {
                cabinet.extract(|_, _| true);
            }
        }
        // Corrupt compressed data.
        let mut bad = good.to_vec();
        for byte in bad.iter_mut().skip(200).step_by(7) {
            *byte ^= 0x55;
        }
        if let Ok(cabinet) = parse(&bad) {
            cabinet.extract(|_, _| true);
        }
    }
}
