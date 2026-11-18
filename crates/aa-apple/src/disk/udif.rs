//! UDIF, the container format of `.dmg` files: a 512-byte `koly` trailer, an XML property list
//! of block tables (`blkx`), and compressed chunks that add up to the partitions of a disk.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::io::Read;
use std::rc::Rc;

use super::Disk;
use crate::util::{be32, be64, slice};

pub const KOLY_SIZE: usize = 512;
const SECTOR: u64 = 512;
/// A chunk larger than this once decompressed is refused. Real images use 1 MiB chunks or less.
const MAX_CHUNK: u64 = 256 * 1024 * 1024;
/// Most chunks of one block table.
const MAX_CHUNKS: u32 = 4_000_000;
/// Decompressed chunks kept per partition.
const CACHE_CHUNKS: usize = 24;

pub const ZERO: u32 = 0;
pub const RAW: u32 = 1;
pub const IGNORE: u32 = 2;
pub const ADC: u32 = 0x8000_0004;
pub const ZLIB: u32 = 0x8000_0005;
pub const BZIP2: u32 = 0x8000_0006;
pub const LZFSE: u32 = 0x8000_0007;
pub const LZMA: u32 = 0x8000_0008;
pub const COMMENT: u32 = 0x7fff_fffe;
pub const END: u32 = 0xffff_ffff;

/// The name of a chunk type, for facts and limitation details.
pub fn chunk_name(kind: u32) -> Option<&'static str> {
    Some(match kind {
        ZERO | IGNORE => "zero",
        RAW => "raw",
        ADC => "adc",
        ZLIB => "zlib",
        BZIP2 => "bzip2",
        LZFSE => "lzfse",
        LZMA => "lzma",
        _ => return None,
    })
}

/// The trailer of a UDIF image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Koly {
    /// Offset of the trailer in the file.
    pub offset: u64,
    pub version: u32,
    pub flags: u32,
    pub data_fork_offset: u64,
    pub data_fork_length: u64,
    pub xml_offset: u64,
    pub xml_length: u64,
    pub sector_count: u64,
}

/// How an image that is not a readable UDIF is protected, if it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    /// `encrcdsa` header: version 2 encrypted image.
    V2,
    /// `cdsaencr` trailer: version 1 encrypted image.
    V1,
}

pub fn encryption(bytes: &[u8]) -> Option<Encryption> {
    if bytes.starts_with(b"encrcdsa") {
        Some(Encryption::V2)
    } else if bytes.ends_with(b"cdsaencr") {
        Some(Encryption::V1)
    } else {
        None
    }
}

pub fn koly(bytes: &[u8]) -> Option<Koly> {
    let offset = bytes.len().checked_sub(KOLY_SIZE)?;
    let k = &bytes[offset..];
    if &k[..4] != b"koly" {
        return None;
    }
    Some(Koly {
        offset: offset as u64,
        version: be32(k, 4)?,
        flags: be32(k, 12)?,
        data_fork_offset: be64(k, 24)?,
        data_fork_length: be64(k, 32)?,
        xml_offset: be64(k, 216)?,
        xml_length: be64(k, 224)?,
        sector_count: be64(k, 492)?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Chunk {
    pub kind: u32,
    /// Where the chunk's data starts in the partition, in bytes.
    pub start: u64,
    pub length: u64,
    /// Where the stored (compressed) bytes are in the file.
    pub source: u64,
    pub source_length: u64,
}

/// One block table: a partition of the disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub name: String,
    /// First sector of the partition on the whole disk.
    pub first_sector: u64,
    pub sectors: u64,
    pub chunks: Vec<Chunk>,
}

impl Table {
    /// How many chunks of each type the table has.
    pub fn chunk_kinds(&self) -> BTreeMap<u32, u64> {
        let mut kinds = BTreeMap::new();
        for chunk in &self.chunks {
            *kinds.entry(chunk.kind).or_insert(0) += 1;
        }
        kinds
    }
}

/// Parses one `mish` block table.
fn table(name: &str, mish: &[u8], koly: &Koly) -> Result<Table, String> {
    if slice(mish, 0, 4) != Some(b"mish") {
        return Err(format!("block table '{name}' does not start with 'mish'"));
    }
    let short = || format!("block table '{name}' is truncated");
    let first_sector = be64(mish, 8).ok_or_else(short)?;
    let sectors = be64(mish, 16).ok_or_else(short)?;
    let data_offset = be64(mish, 24).ok_or_else(short)?;
    let count = be32(mish, 200).ok_or_else(short)?;
    if count > MAX_CHUNKS || (count as usize).saturating_mul(40) > mish.len().saturating_sub(204) {
        return Err(format!("block table '{name}' claims {count} chunks but holds fewer"));
    }
    let mut chunks = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let at = 204 + index * 40;
        let kind = be32(mish, at).ok_or_else(short)?;
        if kind == COMMENT || kind == END {
            continue;
        }
        let sector = be64(mish, at + 8).ok_or_else(short)?;
        let sector_count = be64(mish, at + 16).ok_or_else(short)?;
        let offset = be64(mish, at + 24).ok_or_else(short)?;
        let source_length = be64(mish, at + 32).ok_or_else(short)?;
        let bad = || format!("chunk {index} of block table '{name}' has values out of range");
        let start = sector.checked_mul(SECTOR).ok_or_else(bad)?;
        let length = sector_count.checked_mul(SECTOR).ok_or_else(bad)?;
        start.checked_add(length).ok_or_else(bad)?;
        let source = koly.data_fork_offset.checked_add(data_offset).and_then(|base| base.checked_add(offset)).ok_or_else(bad)?;
        if length == 0 {
            continue;
        }
        chunks.push(Chunk { kind, start, length, source, source_length });
    }
    chunks.sort_by_key(|chunk| chunk.start);
    Ok(Table { name: name.to_string(), first_sector, sectors, chunks })
}

/// The block tables of an image, in the order the property list gives them.
pub fn tables(bytes: &[u8], koly: &Koly) -> Result<Vec<Table>, String> {
    let xml = usize::try_from(koly.xml_offset)
        .ok()
        .zip(usize::try_from(koly.xml_length).ok())
        .and_then(|(offset, length)| slice(bytes, offset, length))
        .ok_or("the property list lies outside the file")?;
    let root = plist::Value::from_reader_xml(std::io::Cursor::new(xml)).map_err(|e| format!("the property list is unreadable: {e}"))?;
    let blkx = root
        .as_dictionary()
        .and_then(|d| d.get("resource-fork"))
        .and_then(plist::Value::as_dictionary)
        .and_then(|d| d.get("blkx"))
        .and_then(plist::Value::as_array)
        .ok_or("the property list has no resource-fork/blkx array")?;
    let mut tables = Vec::new();
    for entry in blkx {
        let Some(entry) = entry.as_dictionary() else { continue };
        let name = entry.get("Name").and_then(plist::Value::as_string).unwrap_or("");
        let Some(data) = entry.get("Data").and_then(plist::Value::as_data) else { continue };
        tables.push(table(name, data, koly)?);
    }
    Ok(tables)
}

/// Apple Data Compression, used by old images.
fn adc(source: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    let mut out: Vec<u8> = Vec::with_capacity(limit.min(1 << 20));
    let mut at = 0;
    while at < source.len() && out.len() < limit {
        let byte = source[at];
        let (length, distance, used) = if byte & 0x80 != 0 {
            let length = (byte & 0x7f) as usize + 1;
            let literal = slice(source, at + 1, length).ok_or("ADC literal run is truncated")?;
            out.extend_from_slice(literal);
            at += 1 + length;
            continue;
        } else if byte & 0x40 != 0 {
            let pair = slice(source, at + 1, 2).ok_or("ADC match is truncated")?;
            ((byte & 0x3f) as usize + 4, ((pair[0] as usize) << 8) | pair[1] as usize, 3)
        } else {
            let next = *source.get(at + 1).ok_or("ADC match is truncated")?;
            (((byte & 0x3f) >> 2) as usize + 3, (((byte & 0x03) as usize) << 8) | next as usize, 2)
        };
        at += used;
        let from = out.len().checked_sub(distance + 1).ok_or("ADC match points before the start")?;
        for index in 0..length {
            let value = out[from + index];
            out.push(value);
        }
    }
    Ok(out)
}

/// Reads at most `limit` bytes from a decoder; more is an error, not an allocation.
fn bounded(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    reader.by_ref().take(limit as u64).read_to_end(&mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

/// Decompresses the stored bytes of one chunk into exactly `length` bytes.
pub fn decompress(kind: u32, source: &[u8], length: usize) -> Result<Vec<u8>, String> {
    let mut out = match kind {
        ZLIB => bounded(flate2::read::ZlibDecoder::new(source), length),
        BZIP2 => bounded(bzip2::read::BzDecoder::new(source), length),
        LZMA => bounded(lzma_rust2::XzReader::new(source, false), length),
        LZFSE => bounded(lzfse_rust::LzfseRingDecoder::default().reader_bytes(source), length),
        ADC => adc(source, length),
        other => return Err(format!("chunk type {other:#x} is not supported")),
    }
    .map_err(|e| format!("{} chunk: {e}", chunk_name(kind).unwrap_or("?")))?;
    // A chunk may decode to less than its sector count; the rest of the sectors are zero.
    out.resize(length, 0);
    Ok(out)
}

struct Cache {
    chunks: BTreeMap<usize, Rc<Vec<u8>>>,
    order: VecDeque<usize>,
}

/// One partition of an image, decompressed on demand.
pub struct Partition<'a> {
    file: &'a [u8],
    pub table: &'a Table,
    length: u64,
    cache: RefCell<Cache>,
}

impl<'a> Partition<'a> {
    pub fn new(file: &'a [u8], table: &'a Table) -> Self {
        let end = table.chunks.last().map(|c| c.start + c.length).unwrap_or(0);
        let length = end.max(table.sectors.saturating_mul(SECTOR));
        Partition { file, table, length, cache: RefCell::new(Cache { chunks: BTreeMap::new(), order: VecDeque::new() }) }
    }

    fn stored(&self, chunk: &Chunk) -> Result<&'a [u8], String> {
        usize::try_from(chunk.source)
            .ok()
            .zip(usize::try_from(chunk.source_length).ok())
            .and_then(|(offset, length)| slice(self.file, offset, length))
            .ok_or_else(|| "a chunk's data lies outside the file".to_string())
    }

    fn decoded(&self, index: usize, chunk: &Chunk) -> Result<Rc<Vec<u8>>, String> {
        if let Some(found) = self.cache.borrow().chunks.get(&index) {
            return Ok(found.clone());
        }
        if chunk.length > MAX_CHUNK {
            return Err(format!("a compressed chunk of {} bytes is too large", chunk.length));
        }
        let data = Rc::new(decompress(chunk.kind, self.stored(chunk)?, chunk.length as usize)?);
        let mut cache = self.cache.borrow_mut();
        if cache.order.len() >= CACHE_CHUNKS
            && let Some(oldest) = cache.order.pop_front()
        {
            cache.chunks.remove(&oldest);
        }
        cache.order.push_back(index);
        cache.chunks.insert(index, data.clone());
        Ok(data)
    }
}

impl Disk for Partition<'_> {
    fn len(&self) -> u64 {
        self.length
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), String> {
        let end = offset.checked_add(buf.len() as u64).ok_or("offset overflow")?;
        if end > self.length {
            return Err("read past the end of the partition".into());
        }
        let chunks = &self.table.chunks;
        let mut position = offset;
        let mut filled = 0usize;
        // The first chunk that ends after `position`.
        let mut index = chunks.partition_point(|chunk| chunk.start + chunk.length <= position);
        while filled < buf.len() {
            let want = buf.len() - filled;
            let chunk = chunks.get(index).filter(|chunk| chunk.start <= position && position - chunk.start < chunk.length);
            let Some(chunk) = chunk else {
                // Sectors no chunk covers read as zeros, up to the next chunk.
                let gap_end = chunks.get(index).map(|c| c.start).unwrap_or(self.length);
                let take = want.min((gap_end.saturating_sub(position)) as usize).max(1).min(want);
                buf[filled..filled + take].fill(0);
                filled += take;
                position += take as u64;
                continue;
            };
            let within = position - chunk.start;
            let take = want.min((chunk.length - within) as usize);
            let target = &mut buf[filled..filled + take];
            match chunk.kind {
                ZERO | IGNORE => target.fill(0),
                RAW => {
                    let stored = self.stored(chunk)?;
                    let part = slice(stored, within as usize, take).ok_or("a raw chunk is shorter than its sectors")?;
                    target.copy_from_slice(part);
                }
                _ => {
                    let data = self.decoded(index, chunk)?;
                    let part = slice(&data, within as usize, take).ok_or("a chunk decoded to less than its sectors")?;
                    target.copy_from_slice(part);
                }
            }
            filled += take;
            position += take as u64;
            index += 1;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adc_decodes_literals_and_matches() {
        // Literal "abc", then a two-byte match of length 3 at distance 2 (offset field 2).
        let source = [0x82, b'a', b'b', b'c', 0x00, 0x02];
        assert_eq!(adc(&source, 64).expect("valid"), b"abcabc");
        // Three-byte match: length 4, distance 0 (repeat last byte).
        let source = [0x80, b'x', 0x40, 0x00, 0x00];
        assert_eq!(adc(&source, 64).expect("valid"), b"xxxxx");
        assert!(adc(&[0x00, 0x05], 64).is_err());
        assert!(adc(&[0x85, b'a'], 64).is_err());
    }

    #[test]
    fn koly_needs_signature_and_size() {
        assert_eq!(koly(b"short"), None);
        let mut trailer = vec![0u8; 600];
        assert_eq!(koly(&trailer), None);
        let at = trailer.len() - KOLY_SIZE;
        trailer[at..at + 4].copy_from_slice(b"koly");
        trailer[at + 7] = 4;
        let parsed = koly(&trailer).expect("koly");
        assert_eq!((parsed.version, parsed.offset), (4, 88));
    }

    #[test]
    fn block_table_with_huge_count_is_refused() {
        let koly = Koly { offset: 0, version: 4, flags: 0, data_fork_offset: 0, data_fork_length: 0, xml_offset: 0, xml_length: 0, sector_count: 0 };
        let mut mish = vec![0u8; 204 + 40];
        mish[..4].copy_from_slice(b"mish");
        mish[200..204].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(table("t", &mish, &koly).is_err());
        for cut in [0, 3, 100, 203] {
            assert!(table("t", &mish[..cut], &koly).is_err());
        }
        mish[200..204].copy_from_slice(&1u32.to_be_bytes());
        mish[204..208].copy_from_slice(&ZLIB.to_be_bytes());
        mish[212..220].copy_from_slice(&u64::MAX.to_be_bytes());
        mish[220..228].copy_from_slice(&8u64.to_be_bytes());
        assert!(table("t", &mish, &koly).is_err());
    }

    #[test]
    fn partition_reads_zero_raw_and_compressed_chunks() {
        use std::io::Write;
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&[7u8; 512]).expect("write");
        let packed = encoder.finish().expect("finish");
        let mut file = vec![9u8; 512];
        file.extend_from_slice(&packed);
        let table = Table {
            name: "p".into(),
            first_sector: 0,
            sectors: 4,
            chunks: vec![
                Chunk { kind: RAW, start: 0, length: 512, source: 0, source_length: 512 },
                Chunk { kind: ZERO, start: 512, length: 512, source: 0, source_length: 0 },
                Chunk { kind: ZLIB, start: 1024, length: 512, source: 512, source_length: packed.len() as u64 },
            ],
        };
        let partition = Partition::new(&file, &table);
        assert_eq!(partition.len(), 2048);
        let all = partition.read_vec(0, 2048).expect("read");
        assert!(all[..512].iter().all(|b| *b == 9));
        assert!(all[512..1024].iter().all(|b| *b == 0));
        assert!(all[1024..1536].iter().all(|b| *b == 7));
        assert!(all[1536..].iter().all(|b| *b == 0));
        assert_eq!(partition.read_vec(500, 30).expect("read")[..12], [9u8; 12]);
        assert!(partition.read_vec(2000, 100).is_err());
        // A chunk whose stored bytes lie outside the file fails without panicking.
        let broken = Table { chunks: vec![Chunk { kind: ZLIB, start: 0, length: 512, source: 1 << 40, source_length: 10 }], ..table.clone() };
        assert!(Partition::new(&file, &broken).read_vec(0, 512).is_err());
    }
}
