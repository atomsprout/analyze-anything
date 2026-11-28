//! Bounded LZ4 frames with independent blocks; dictionaries and legacy streams stay unread.

use std::hash::Hasher;
use std::io::{self, Read};

use aa_core::plugin::{Analyzer, Output, Rule, SinkError, Tree, Unpack, UnpackSink, Unpacker};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::json;
use twox_hash::XxHash32;

pub struct Lz4;

const MAGIC: &[u8] = &[0x04, 0x22, 0x4d, 0x18];
const MAX_OUTPUT: u64 = 256 * 1024 * 1024;
const MAX_BLOCKS: usize = 65_536;
const RULES: &[Rule] = &[
    Rule {
        id: "lz4.frame",
        title_en: "LZ4 frame header",
        title_zh: "LZ4 帧头",
        text_en: "This LZ4 frame declares independent blocks with at most {block_size} decoded bytes per block. Header and declared block/content checksums detect corruption; they do not authenticate the contents.",
        text_zh: "此 LZ4 帧声明了独立数据块，每块解码后最多 {block_size} 字节。头部与声明的块及内容校验和用于发现损坏，不认证内容。",
    },
    Rule {
        id: "lz4.profile-unread",
        title_en: "LZ4 profile unread",
        title_zh: "LZ4 格式范围未读取",
        text_en: "The frame header is damaged or outside the bounded independent-block profile. Dictionaries, linked blocks, legacy/raw streams and concatenated frames are not decoded by this profile.",
        text_zh: "帧头损坏或超出有界独立数据块支持范围。此范围不解码字典、关联块、旧版或原始流与串联帧。",
    },
];

#[derive(Clone, Copy)]
struct Header {
    end: usize,
    block_size: usize,
    content_size: Option<u64>,
    block_checksum: bool,
    content_checksum: bool,
}

fn take<'a>(bytes: &'a [u8], at: &mut usize, length: usize) -> Result<&'a [u8], String> {
    let end = at.checked_add(length).ok_or("LZ4 extent overflow")?;
    let value = bytes.get(*at..end).ok_or("LZ4 extent exceeds the input")?;
    *at = end;
    Ok(value)
}

fn word(bytes: &[u8], at: &mut usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(take(bytes, at, 4)?.try_into().map_err(|_| "LZ4 word unread")?))
}

fn header(bytes: &[u8]) -> Result<Header, String> {
    if !bytes.starts_with(MAGIC) {
        return Err("supported LZ4 frame magic is absent".into());
    }
    let flags = *bytes.get(4).ok_or("LZ4 flags are truncated")?;
    let descriptor = *bytes.get(5).ok_or("LZ4 block descriptor is truncated")?;
    if flags >> 6 != 1 || flags & 2 != 0 || descriptor & 0x8f != 0 {
        return Err("LZ4 version or reserved header bits are outside the profile".into());
    }
    if flags & 0x20 == 0 || flags & 1 != 0 {
        return Err("linked blocks and external dictionaries are outside the LZ4 profile".into());
    }
    let block_size = match (descriptor >> 4) & 7 {
        4 => 64 * 1024,
        5 => 256 * 1024,
        6 => 1024 * 1024,
        7 => 4 * 1024 * 1024,
        _ => return Err("LZ4 maximum block size is invalid".into()),
    };
    let mut at = 6;
    let content_size = if flags & 8 != 0 {
        let value = u64::from_le_bytes(take(bytes, &mut at, 8)?.try_into().map_err(|_| "LZ4 size unread")?);
        if value > MAX_OUTPUT {
            return Err("LZ4 declared output exceeds the 256 MiB frame budget".into());
        }
        Some(value)
    } else {
        None
    };
    let expected = (XxHash32::oneshot(0, &bytes[4..at]) >> 8) as u8;
    if take(bytes, &mut at, 1)?[0] != expected {
        return Err("LZ4 header checksum differs".into());
    }
    Ok(Header { end: at, block_size, content_size, block_checksum: flags & 0x10 != 0, content_checksum: flags & 4 != 0 })
}

fn length(bytes: &[u8], at: &mut usize, base: usize) -> Result<usize, String> {
    let mut value = base;
    if base == 15 {
        loop {
            let next = take(bytes, at, 1)?[0];
            value = value.checked_add(usize::from(next)).ok_or("LZ4 length overflow")?;
            if value > 4 * 1024 * 1024 {
                return Err("LZ4 sequence exceeds the maximum block budget".into());
            }
            if next != 255 {
                break;
            }
        }
    }
    Ok(value)
}

fn block(bytes: &[u8], maximum: usize, out: &mut Vec<u8>) -> Result<(), String> {
    out.clear();
    let mut at = 0;
    let mut last_match = None;
    while at < bytes.len() {
        let token = take(bytes, &mut at, 1)?[0];
        let literals = length(bytes, &mut at, usize::from(token >> 4))?;
        if literals > maximum.saturating_sub(out.len()) {
            return Err("LZ4 literals exceed the declared block maximum".into());
        }
        out.extend_from_slice(take(bytes, &mut at, literals)?);
        if at == bytes.len() {
            if last_match.is_some_and(|start| literals < 5 || out.len() - start < 12) {
                return Err("LZ4 terminal literals or last-match distance violate the block format".into());
            }
            return Ok(());
        }
        let distance = usize::from(u16::from_le_bytes(take(bytes, &mut at, 2)?.try_into().map_err(|_| "LZ4 match unread")?));
        if distance == 0 || distance > out.len() {
            return Err("LZ4 match references bytes outside this independent block".into());
        }
        let count = length(bytes, &mut at, usize::from(token & 15))?.checked_add(4).ok_or("LZ4 match length overflow")?;
        if count > maximum.saturating_sub(out.len()) {
            return Err("LZ4 match exceeds the declared block maximum".into());
        }
        // Overlapping matches deliberately reuse bytes appended by the same match.
        last_match = Some(out.len());
        for _ in 0..count {
            let value = out[out.len() - distance];
            out.push(value);
        }
    }
    Err("LZ4 compressed block has no terminal literal sequence".into())
}

struct Decoder<'a> {
    input: &'a [u8],
    header: Header,
    at: usize,
    decoded: Vec<u8>,
    delivered: usize,
    total: u64,
    blocks: usize,
    hash: XxHash32,
    finished: bool,
    failed: bool,
}

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8]) -> Result<Self, String> {
        let header = header(input)?;
        Ok(Self {
            input,
            header,
            at: header.end,
            decoded: Vec::new(),
            delivered: 0,
            total: 0,
            blocks: 0,
            hash: XxHash32::default(),
            finished: false,
            failed: false,
        })
    }

    fn next(&mut self) -> Result<(), String> {
        let descriptor = word(self.input, &mut self.at)?;
        if descriptor == 0 {
            if self.header.content_size.is_some_and(|expected| expected != self.total) {
                return Err("LZ4 decoded size differs from the declared content size".into());
            }
            if self.header.content_checksum && word(self.input, &mut self.at)? != self.hash.finish_32() {
                return Err("LZ4 content checksum differs".into());
            }
            if self.at != self.input.len() {
                return Err("trailing data or concatenated LZ4 frames are outside this profile".into());
            }
            self.finished = true;
            return Ok(());
        }
        self.blocks += 1;
        if self.blocks > MAX_BLOCKS {
            return Err("LZ4 frame exceeds the 65,536 block budget".into());
        }
        let size = usize::try_from(descriptor & 0x7fff_ffff).map_err(|_| "LZ4 block size overflow")?;
        if size > self.header.block_size || size == 0 && descriptor & 0x8000_0000 == 0 {
            return Err("LZ4 stored block size exceeds its bounded profile".into());
        }
        let data = take(self.input, &mut self.at, size)?;
        if self.header.block_checksum && word(self.input, &mut self.at)? != XxHash32::oneshot(0, data) {
            return Err("LZ4 block checksum differs".into());
        }
        if descriptor & 0x8000_0000 != 0 {
            self.decoded.clear();
            self.decoded.extend_from_slice(data);
        } else {
            block(data, self.header.block_size, &mut self.decoded)?;
        }
        self.total += self.decoded.len() as u64;
        if self.total > MAX_OUTPUT || self.header.content_size.is_some_and(|expected| self.total > expected) {
            return Err("LZ4 decoded output exceeds the frame budget or declared size".into());
        }
        self.hash.write(&self.decoded);
        self.delivered = 0;
        Ok(())
    }
}

impl Read for Decoder<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.failed {
            return Err(io::Error::other("LZ4 decoding previously failed"));
        }
        while self.delivered == self.decoded.len() && !self.finished {
            if let Err(error) = self.next() {
                self.failed = true;
                return Err(io::Error::other(error));
            }
        }
        let count = output.len().min(self.decoded.len() - self.delivered);
        output[..count].copy_from_slice(&self.decoded[self.delivered..self.delivered + count]);
        self.delivered += count;
        Ok(count)
    }
}

impl Unpacker for Lz4 {
    fn id(&self) -> &'static str {
        "lz4"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn unpack(&self, file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        if !bytes.starts_with(MAGIC) {
            return Unpack::NotMine;
        }
        let mut decoder = match Decoder::new(bytes) {
            Ok(decoder) => decoder,
            Err(detail) => return Unpack::Failed { kind: "lz4", detail },
        };
        let name = file.name().strip_suffix(".lz4").filter(|name| !name.is_empty()).unwrap_or("content");
        match sink.add(name, &mut decoder) {
            Ok(()) | Err(SinkError::LimitReached) => Unpack::Done { kind: "lz4" },
            Err(SinkError::Read(detail)) => Unpack::Failed { kind: "lz4", detail },
        }
    }
}

impl Analyzer for Lz4 {
    fn id(&self) -> &'static str {
        "lz4"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn analyze_file(&self, tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        let Ok(bytes) = tree.read(&file.path) else { return };
        if !bytes.starts_with(MAGIC) && file.extension().as_deref() != Some("lz4") {
            return;
        }
        let header = match header(&bytes) {
            Ok(header) => header,
            Err(reason) => {
                out.limitation("lz4.profile-unread", Some(file), Some(reason));
                return;
            }
        };
        out.kind(file, "lz4");
        let complete = file.facts.get("engine.container-listing").is_some_and(|fact| fact["complete"] == true);
        out.fact(file,"lz4.frame",json!({"block_independent":true,"maximum_block_size":header.block_size,"content_size":header.content_size,
            "block_checksum_declared":header.block_checksum,"content_checksum_declared":header.content_checksum,"header_checksum_matches":true,
            "complete_decoding":complete,"declared_checksums_checked":complete,"authenticated":false}));
        out.finding(
            Finding::new(Section::Structure, "lz4", "lz4.frame", Confidence::Verified, Severity::Info)
                .param("block_size", header.block_size)
                .evidence(Evidence::bytes(
                    file,
                    0,
                    header.end as u64,
                    json!({"maximum_block_size":header.block_size,"content_size":header.content_size}),
                )),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn native_writer_samples_match_pinned_reference_and_original_text() {
        let reference: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/native-lz4.ref.json")).expect("native comparison record");
        assert_eq!(reference["passed"], 40);
        let samples: &[(&str, &[u8])] = &[
            ("default.txt.lz4", include_bytes!("../tests/data/native-default.txt.lz4")),
            ("all-checksums.txt.lz4", include_bytes!("../tests/data/native-all-checksums.txt.lz4")),
            ("no-content-checksum.txt.lz4", include_bytes!("../tests/data/native-no-content-checksum.txt.lz4")),
            ("short-stored.txt.lz4", include_bytes!("../tests/data/native-short-stored.txt.lz4")),
        ];
        for (name, bytes) in samples {
            let row =
                reference["samples"].as_array().expect("sample records").iter().find(|row| row["file"] == *name).expect("pinned sample");
            assert_eq!(hex::encode(Sha256::digest(bytes)), row["sha256"]);
            let mut decoder = Decoder::new(bytes).expect("native frame header");
            let mut decoded = Vec::new();
            decoder.read_to_end(&mut decoded).expect("native blocks and checksums");
            let expected = if *name == "short-stored.txt.lz4" {
                b"abc".to_vec()
            } else {
                b"Analyze Anything native LZ4 fixture. Project-authored Apache-2.0 data.\n".repeat(3000)
            };
            assert_eq!(decoded, expected);
            assert_eq!(hex::encode(Sha256::digest(&decoded)), row["source_sha256"]);
            assert!(decoder.finished);
        }
    }

    fn frame(payload: &[u8], compressed: bool, decoded: &[u8]) -> Vec<u8> {
        let mut bytes = MAGIC.to_vec();
        bytes.extend_from_slice(&[0x7c, 0x40]);
        bytes.extend_from_slice(&(decoded.len() as u64).to_le_bytes());
        bytes.push((XxHash32::oneshot(0, &bytes[4..]) >> 8) as u8);
        let descriptor = payload.len() as u32 | if compressed { 0 } else { 0x8000_0000 };
        bytes.extend_from_slice(&descriptor.to_le_bytes());
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&XxHash32::oneshot(0, payload).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&XxHash32::oneshot(0, decoded).to_le_bytes());
        bytes
    }

    #[test]
    fn stored_and_overlapping_compressed_blocks_stream_with_all_checksums() {
        // One literal followed by an overlapping seven-byte match, then five literals.
        let encoded = [0x13, b'a', 1, 0, 0x50, b'b', b'c', b'd', b'e', b'f'];
        for bytes in [frame(b"abcdef", false, b"abcdef"), frame(&encoded, true, b"aaaaaaaabcdef"), frame(&[], false, &[])] {
            let mut decoder = Decoder::new(&bytes).expect("valid frame");
            let mut actual = Vec::new();
            decoder.read_to_end(&mut actual).expect("checksums and decoded stream");
            assert_eq!(actual.len() as u64, decoder.header.content_size.expect("declared size"));
            assert!(decoder.finished);
        }
    }

    #[test]
    fn every_short_prefix_corrupt_checksum_and_trailing_frame_is_rejected() {
        let bytes = frame(b"hello", false, b"hello");
        for end in 0..bytes.len() {
            if let Ok(mut decoder) = Decoder::new(&bytes[..end]) {
                assert!(decoder.read_to_end(&mut Vec::new()).is_err(), "prefix {end}");
            }
        }
        for at in [14, 24, 32] {
            let mut bad = bytes.clone();
            bad[at] ^= 1;
            let failed = match Decoder::new(&bad) {
                Err(_) => true,
                Ok(mut decoder) => decoder.read_to_end(&mut Vec::new()).is_err(),
            };
            assert!(failed, "corruption {at}");
        }
        let mut trailing = bytes.clone();
        trailing.extend_from_slice(&bytes);
        assert!(Decoder::new(&trailing).expect("first header").read_to_end(&mut Vec::new()).is_err());
    }

    #[test]
    fn dictionary_linked_blocks_huge_sizes_and_invalid_matches_cannot_allocate_from_input() {
        let bytes = frame(b"hello", false, b"hello");
        for flags in [0x5c, 0x7d, 0xbc] {
            let mut bad = bytes.clone();
            bad[4] = flags;
            assert!(Decoder::new(&bad).is_err());
        }
        let mut huge = bytes.clone();
        huge[6..14].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(Decoder::new(&huge).is_err());
        for encoded in [&[0x00, 0, 0][..], &[0x10, b'a', 2, 0][..], &[0xf0, 255][..]] {
            assert!(block(encoded, 64 * 1024, &mut Vec::new()).is_err());
        }
        let mut out = Vec::new();
        assert!(block(&[0x10, b'a', 1, 0], 4, &mut out).is_err());
        assert!(out.len() <= 4);
    }
}
