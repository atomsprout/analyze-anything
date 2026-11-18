//! Installer packages: the xar archive (`.pkg`, `.xip`, Safari extensions), the `pbzx` stream
//! and the cpio archives a package keeps its payload and scripts in.

use std::io::Read;

use aa_core::plugin::{SinkError, UnpackSink};
use sha1::Digest;

use crate::util::{be16, be32, be64, slice};

/// Largest table of contents expanded into memory.
const MAX_TOC: u64 = 256 * 1024 * 1024;
const MAX_TOC_NODES: u32 = 8_000_000;
const MAX_FILES: usize = 1_000_000;
const MAX_NAME: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XarFile {
    pub path: String,
    /// Offset of the stored bytes in the heap; `None` for an entry without data.
    pub offset: Option<u64>,
    pub length: u64,
    pub size: u64,
    /// MIME-like name of the encoding, e.g. `application/x-gzip`.
    pub encoding: String,
    /// `(algorithm, hex digest)` of the extracted bytes.
    pub extracted_checksum: Option<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XarSignature {
    /// `RSA` or `CMS`.
    pub style: String,
    pub offset: u64,
    pub size: u64,
    /// DER certificates, leaf first.
    pub certificates: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Xar {
    pub version: u16,
    /// Offset in the file where the heap starts.
    pub heap: u64,
    pub toc_compressed: u64,
    /// The table of contents as stored (zlib).
    pub toc_range: (usize, usize),
    /// `(algorithm, heap offset, size)` of the checksum of the stored table of contents.
    pub checksum: Option<(String, u64, u64)>,
    pub signatures: Vec<XarSignature>,
    pub files: Vec<XarFile>,
    /// True when the table listed more files than this crate reads.
    pub truncated: bool,
}

pub fn is_xar(bytes: &[u8]) -> bool {
    bytes.starts_with(b"xar!") && be16(bytes, 4).is_some_and(|size| size >= 28)
}

fn child<'a, 'i>(node: roxmltree::Node<'a, 'i>, name: &str) -> Option<roxmltree::Node<'a, 'i>> {
    node.children().find(|c| c.is_element() && c.tag_name().name() == name)
}

fn text<'a>(node: roxmltree::Node<'a, '_>, name: &str) -> Option<&'a str> {
    child(node, name).and_then(|c| c.text()).map(str::trim)
}

fn number(node: roxmltree::Node<'_, '_>, name: &str) -> Option<u64> {
    text(node, name)?.parse().ok()
}

/// Decodes standard base64, ignoring whitespace. `None` on any other character.
pub fn base64(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return None,
        };
        buffer = (buffer << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Parses the header and table of contents of a xar archive.
pub fn xar(bytes: &[u8]) -> Result<Xar, String> {
    if !is_xar(bytes) {
        return Err("not a xar archive".into());
    }
    let short = || "the xar header is truncated".to_string();
    let header_size = be16(bytes, 4).ok_or_else(short)? as usize;
    let version = be16(bytes, 6).ok_or_else(short)?;
    let toc_compressed = be64(bytes, 8).ok_or_else(short)?;
    let toc_size = be64(bytes, 16).ok_or_else(short)?;
    be32(bytes, 24).ok_or_else(short)?;
    if toc_size > MAX_TOC {
        return Err(format!("the table of contents claims {toc_size} bytes"));
    }
    let stored = usize::try_from(toc_compressed)
        .ok()
        .and_then(|length| slice(bytes, header_size, length))
        .ok_or("the table of contents lies outside the file")?;
    let mut xml = Vec::new();
    flate2::read::ZlibDecoder::new(stored)
        .take(toc_size.saturating_add(1))
        .read_to_end(&mut xml)
        .map_err(|e| format!("the table of contents does not decompress: {e}"))?;
    let xml = String::from_utf8_lossy(&xml);
    let options = roxmltree::ParsingOptions { allow_dtd: false, nodes_limit: MAX_TOC_NODES };
    let document =
        roxmltree::Document::parse_with_options(&xml, options).map_err(|e| format!("the table of contents is not valid XML: {e}"))?;
    let toc = child(document.root_element(), "toc").ok_or("the table of contents has no <toc> element")?;

    let checksum = child(toc, "checksum")
        .and_then(|node| Some((node.attribute("style")?.to_ascii_lowercase(), number(node, "offset")?, number(node, "size")?)));
    let mut signatures = Vec::new();
    for node in toc.children().filter(|c| c.is_element() && matches!(c.tag_name().name(), "signature" | "x-signature")) {
        let (Some(offset), Some(size)) = (number(node, "offset"), number(node, "size")) else { continue };
        let certificates = node
            .descendants()
            .filter(|c| c.is_element() && c.tag_name().name() == "X509Certificate")
            .filter_map(|c| base64(c.text().unwrap_or("")))
            .take(16)
            .collect();
        signatures.push(XarSignature { style: node.attribute("style").unwrap_or("").to_string(), offset, size, certificates });
    }

    let mut files = Vec::new();
    let mut truncated = false;
    // Depth-first, in document order: `(node, path of its folder)`.
    let mut pending: Vec<(roxmltree::Node<'_, '_>, String, usize)> =
        toc.children().filter(|c| c.is_element() && c.tag_name().name() == "file").map(|c| (c, String::new(), 0)).collect();
    pending.reverse();
    while let Some((node, prefix, depth)) = pending.pop() {
        if files.len() >= MAX_FILES {
            truncated = true;
            break;
        }
        let Some(name) = text(node, "name").filter(|n| !n.is_empty() && n.len() <= MAX_NAME) else { continue };
        let path = format!("{prefix}{name}");
        if text(node, "type").unwrap_or("file") == "directory" {
            if depth < 128 {
                let mut inner: Vec<_> = node
                    .children()
                    .filter(|c| c.is_element() && c.tag_name().name() == "file")
                    .map(|c| (c, format!("{path}/"), depth + 1))
                    .collect();
                inner.reverse();
                pending.extend(inner);
            }
            continue;
        }
        if text(node, "type").unwrap_or("file") != "file" {
            continue;
        }
        let data = child(node, "data");
        let extracted_checksum = data
            .and_then(|d| child(d, "extracted-checksum"))
            .and_then(|c| Some((c.attribute("style")?.to_ascii_lowercase(), c.text()?.trim().to_ascii_lowercase())));
        files.push(XarFile {
            path,
            offset: data.and_then(|d| number(d, "offset")),
            length: data.and_then(|d| number(d, "length")).unwrap_or(0),
            size: data.and_then(|d| number(d, "size")).unwrap_or(0),
            encoding: data
                .and_then(|d| child(d, "encoding"))
                .and_then(|e| e.attribute("style"))
                .unwrap_or("application/octet-stream")
                .to_string(),
            extracted_checksum,
        });
    }
    let heap = header_size as u64 + toc_compressed;
    Ok(Xar { version, heap, toc_compressed, toc_range: (header_size, toc_compressed as usize), checksum, signatures, files, truncated })
}

impl Xar {
    /// The bytes at `offset` of the heap.
    pub fn heap_slice<'a>(&self, bytes: &'a [u8], offset: u64, length: u64) -> Option<&'a [u8]> {
        let start = usize::try_from(self.heap.checked_add(offset)?).ok()?;
        slice(bytes, start, usize::try_from(length).ok()?)
    }

    /// A reader of the decoded content of `file`.
    pub fn open<'a>(&self, bytes: &'a [u8], file: &XarFile) -> Result<Box<dyn Read + 'a>, String> {
        let Some(offset) = file.offset else { return Ok(Box::new(std::io::empty())) };
        let stored = self.heap_slice(bytes, offset, file.length).ok_or("the entry's data lies outside the file")?;
        Ok(match file.encoding.as_str() {
            "application/octet-stream" => Box::new(stored),
            "application/x-gzip" | "application/zlib" => Box::new(flate2::read::ZlibDecoder::new(stored)),
            "application/x-bzip2" => Box::new(bzip2::read::BzDecoder::new(stored)),
            "application/x-xz" => Box::new(lzma_rust2::XzReader::new(stored, false)),
            other => return Err(format!("encoding {other} is not supported")),
        })
    }
}

enum Hasher {
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha512(sha2::Sha512),
}

/// Hashes what passes through, to compare with the checksum the archive records.
pub struct Checked<R> {
    inner: R,
    hasher: Option<Hasher>,
    expected: String,
    done: bool,
    /// Set once the stream ended and its digest differed.
    pub mismatch: bool,
}

impl<R: Read> Checked<R> {
    pub fn new(inner: R, checksum: Option<&(String, String)>) -> Self {
        let hasher = checksum.and_then(|(style, _)| match style.as_str() {
            "sha1" => Some(Hasher::Sha1(sha1::Sha1::new())),
            "sha256" => Some(Hasher::Sha256(sha2::Sha256::new())),
            "sha512" => Some(Hasher::Sha512(sha2::Sha512::new())),
            _ => None,
        });
        Checked { inner, hasher, expected: checksum.map(|c| c.1.clone()).unwrap_or_default(), done: false, mismatch: false }
    }
}

impl<R: Read> Read for Checked<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let count = self.inner.read(buf)?;
        match (&mut self.hasher, count) {
            (Some(Hasher::Sha1(h)), 1..) => h.update(&buf[..count]),
            (Some(Hasher::Sha256(h)), 1..) => h.update(&buf[..count]),
            (Some(Hasher::Sha512(h)), 1..) => h.update(&buf[..count]),
            (Some(_), 0) if !self.done && !buf.is_empty() => {
                self.done = true;
                let digest = match self.hasher.take() {
                    Some(Hasher::Sha1(h)) => hex::encode(h.finalize()),
                    Some(Hasher::Sha256(h)) => hex::encode(h.finalize()),
                    Some(Hasher::Sha512(h)) => hex::encode(h.finalize()),
                    None => String::new(),
                };
                self.mismatch = digest != self.expected;
            }
            _ => {}
        }
        Ok(count)
    }
}

/// True when `bytes` start like a cpio header this crate reads.
pub fn is_cpio(bytes: &[u8]) -> bool {
    bytes.starts_with(b"070707") || bytes.starts_with(b"070701") || bytes.starts_with(b"070702")
}

fn digits(field: &[u8], radix: u32) -> Option<u64> {
    u64::from_str_radix(std::str::from_utf8(field).ok()?, radix).ok()
}

fn fill(reader: &mut dyn Read, buf: &mut [u8]) -> Result<(), String> {
    reader.read_exact(buf).map_err(|e| format!("the archive ends inside an entry: {e}"))
}

fn skip(reader: &mut dyn Read, count: u64) -> Result<(), String> {
    let copied = std::io::copy(&mut reader.take(count), &mut std::io::sink()).map_err(|e| e.to_string())?;
    if copied == count { Ok(()) } else { Err("the archive ends inside an entry".into()) }
}

/// What a cpio archive yielded.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CpioSummary {
    pub files: u64,
    /// Entries that are not regular files (folders, links, devices).
    pub others: u64,
    /// True when the sink's limit stopped extraction.
    pub stopped: bool,
}

/// Reads a cpio archive (`odc` or `newc`/`crc`) from `reader`, adding every regular file to `sink`.
pub fn cpio(reader: &mut dyn Read, sink: &mut dyn UnpackSink) -> Result<CpioSummary, String> {
    let mut summary = CpioSummary::default();
    loop {
        let mut magic = [0u8; 6];
        fill(reader, &mut magic)?;
        let (mode, name_size, file_size, newc) = match &magic {
            b"070707" => {
                let mut rest = [0u8; 70];
                fill(reader, &mut rest)?;
                let field = |from: usize, to: usize| digits(&rest[from - 6..to - 6], 8).ok_or("a header field is not octal");
                (field(18, 24)?, field(59, 65)?, field(65, 76)?, false)
            }
            b"070701" | b"070702" => {
                let mut rest = [0u8; 104];
                fill(reader, &mut rest)?;
                let field = |index: usize| digits(&rest[index * 8..index * 8 + 8], 16).ok_or("a header field is not hexadecimal");
                (field(1)?, field(11)?, field(6)?, true)
            }
            _ => return Err(format!("entry {} does not start with a cpio magic", summary.files + summary.others + 1)),
        };
        if name_size == 0 || name_size as usize > MAX_NAME {
            return Err(format!("an entry name of {name_size} bytes"));
        }
        let mut name = vec![0u8; name_size as usize];
        fill(reader, &mut name)?;
        if newc {
            skip(reader, (4 - (110 + name_size) % 4) % 4)?;
        }
        let name = crate::util::c_string(&name);
        if name == "TRAILER!!!" {
            return Ok(summary);
        }
        let padding = if newc { (4 - file_size % 4) % 4 } else { 0 };
        if mode & 0o170000 != 0o100000 {
            summary.others += 1;
            skip(reader, file_size + padding)?;
            continue;
        }
        let mut data = reader.take(file_size);
        let outcome = sink.add(&name, &mut data);
        // Whatever the sink left unread still has to be passed over.
        let unread = data.limit();
        match outcome {
            Ok(()) => summary.files += 1,
            Err(SinkError::Read(_)) => {}
            Err(SinkError::LimitReached) => {
                summary.stopped = true;
                return Ok(summary);
            }
        }
        skip(reader, unread + padding)?;
    }
}

/// Decodes a `pbzx` stream: a sequence of chunks, each an xz stream or stored bytes.
pub struct Pbzx<'a> {
    rest: &'a [u8],
    chunk: std::io::Cursor<Vec<u8>>,
    /// Decoded size a chunk may have, from the stream's header.
    chunk_size: u64,
    more: bool,
}

impl<'a> Pbzx<'a> {
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        if !bytes.starts_with(b"pbzx") {
            return None;
        }
        let chunk_size = be64(bytes, 4)?;
        Some(Pbzx {
            rest: &bytes[12..],
            chunk: std::io::Cursor::new(Vec::new()),
            chunk_size: chunk_size.clamp(1 << 16, 1 << 30),
            more: true,
        })
    }

    fn next_chunk(&mut self) -> std::io::Result<bool> {
        if !self.more || self.rest.is_empty() {
            return Ok(false);
        }
        let bad = || std::io::Error::other("the pbzx stream is truncated");
        let size = be64(self.rest, 0).ok_or_else(bad)?;
        let length = be64(self.rest, 8).ok_or_else(bad)?;
        let stored = usize::try_from(length).ok().and_then(|length| slice(self.rest, 16, length)).ok_or_else(bad)?;
        self.rest = &self.rest[16 + stored.len()..];
        let data = if stored.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
            let mut out = Vec::new();
            lzma_rust2::XzReader::new(stored, false).take(self.chunk_size.max(size.min(1 << 30))).read_to_end(&mut out)?;
            out
        } else {
            stored.to_vec()
        };
        self.chunk = std::io::Cursor::new(data);
        Ok(true)
    }
}

impl Read for Pbzx<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let count = self.chunk.read(buf)?;
            if count > 0 || buf.is_empty() {
                return Ok(count);
            }
            if !self.next_chunk()? {
                return Ok(0);
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::io::Write;

    use super::*;

    #[derive(Default)]
    pub struct Collect {
        pub files: Vec<(String, Vec<u8>)>,
        pub limitations: Vec<String>,
    }

    impl UnpackSink for Collect {
        fn add(&mut self, path: &str, data: &mut dyn Read) -> Result<(), SinkError> {
            let mut bytes = Vec::new();
            data.read_to_end(&mut bytes).map_err(|e| SinkError::Read(e.to_string()))?;
            self.files.push((path.to_string(), bytes));
            Ok(())
        }

        fn limitation(&mut self, code: &str, _detail: Option<String>) {
            self.limitations.push(code.to_string());
        }
    }

    fn odc_entry(name: &str, mode: u32, data: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
            1,
            2,
            mode,
            0,
            0,
            1,
            0,
            0,
            name.len() + 1,
            data.len()
        )
        .into_bytes();
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out.extend_from_slice(data);
        out
    }

    fn newc_entry(name: &str, mode: u32, data: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
            1,
            mode,
            0,
            0,
            1,
            0,
            data.len(),
            0,
            0,
            0,
            0,
            name.len() + 1,
            0
        )
        .into_bytes();
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(data);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    #[test]
    fn cpio_odc_and_newc() {
        for entry in [odc_entry as fn(&str, u32, &[u8]) -> Vec<u8>, newc_entry] {
            let mut archive = entry("./dir", 0o040755, b"");
            archive.extend(entry("./dir/a.txt", 0o100644, b"hello"));
            archive.extend(entry("./link", 0o120777, b"dir/a.txt"));
            archive.extend(entry("./b", 0o100644, b""));
            archive.extend(entry("TRAILER!!!", 0, b""));
            let mut sink = Collect::default();
            let summary = cpio(&mut &archive[..], &mut sink).expect("valid archive");
            assert_eq!(summary, CpioSummary { files: 2, others: 2, stopped: false });
            assert_eq!(sink.files, vec![("./dir/a.txt".to_string(), b"hello".to_vec()), ("./b".to_string(), Vec::new())]);
            // Every truncation is an error or a shorter listing, never a panic.
            for cut in 0..archive.len() {
                let _ = cpio(&mut &archive[..cut], &mut Collect::default());
            }
        }
    }

    #[test]
    fn cpio_rejects_bad_headers() {
        assert!(cpio(&mut &b"07070Xgarbage"[..], &mut Collect::default()).is_err());
        let mut huge_name = odc_entry("a", 0o100644, b"x");
        huge_name[59..65].copy_from_slice(b"777777");
        assert!(cpio(&mut &huge_name[..], &mut Collect::default()).is_err());
        let mut bad_digits = odc_entry("a", 0o100644, b"x");
        bad_digits[20] = b'z';
        assert!(cpio(&mut &bad_digits[..], &mut Collect::default()).is_err());
    }

    pub fn xar_archive(toc: &str, heap: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(toc.as_bytes()).expect("write");
        let packed = encoder.finish().expect("finish");
        let mut out = b"xar!".to_vec();
        out.extend_from_slice(&28u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&(packed.len() as u64).to_be_bytes());
        out.extend_from_slice(&(toc.len() as u64).to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&packed);
        out.extend_from_slice(heap);
        out
    }

    const TOC: &str = r#"<?xml version="1.0" encoding="UTF-8"?><xar><toc>
        <checksum style="sha1"><offset>0</offset><size>20</size></checksum>
        <file id="1"><name>Distribution</name><type>file</type>
          <data><offset>20</offset><size>5</size><length>5</length><encoding style="application/octet-stream"/>
          <extracted-checksum style="sha1">aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d</extracted-checksum></data></file>
        <file id="2"><name>a.pkg</name><type>directory</type>
          <file id="3"><name>PackageInfo</name><type>file</type>
            <data><offset>25</offset><size>3</size><length>3</length><encoding style="application/octet-stream"/></data></file>
          <file id="4"><name>empty</name><type>file</type></file>
        </file></toc></xar>"#;

    #[test]
    fn xar_lists_and_reads_files() {
        let mut heap = vec![0u8; 20];
        heap.extend_from_slice(b"helloabc");
        let archive = xar_archive(TOC, &heap);
        let parsed = xar(&archive).expect("valid xar");
        assert_eq!(parsed.checksum, Some(("sha1".to_string(), 0, 20)));
        let paths: Vec<&str> = parsed.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["Distribution", "a.pkg/PackageInfo", "a.pkg/empty"]);
        let mut first = Checked::new(parsed.open(&archive, &parsed.files[0]).expect("open"), parsed.files[0].extracted_checksum.as_ref());
        let mut content = Vec::new();
        first.read_to_end(&mut content).expect("read");
        assert_eq!(content, b"hello");
        assert!(!first.mismatch);
        let wrong = ("sha1".to_string(), "00".repeat(20));
        let mut second = Checked::new(parsed.open(&archive, &parsed.files[0]).expect("open"), Some(&wrong));
        second.read_to_end(&mut content).expect("read");
        assert!(second.mismatch);
        // Data past the end of the file is an error on open.
        assert!(parsed.open(&archive[..archive.len() - 4], &parsed.files[1]).is_err());
    }

    #[test]
    fn xar_malformed_inputs() {
        let archive = xar_archive(TOC, &[0u8; 28]);
        for cut in [0, 3, 10, 27, 28, 40, 100] {
            assert!(xar(&archive[..cut.min(archive.len())]).is_err(), "cut {cut}");
        }
        let mut huge = archive.clone();
        huge[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(xar(&huge).is_err());
        let mut huge = archive.clone();
        huge[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
        assert!(xar(&huge).is_err());
        assert!(xar(&xar_archive("<xar><toc><file>", &[])).is_err());
        assert!(xar(&xar_archive("<notxar/>", &[])).is_err());
    }

    #[test]
    fn pbzx_stored_and_xz_chunks() {
        let mut stream = b"pbzx".to_vec();
        stream.extend_from_slice(&(1u64 << 24).to_be_bytes());
        stream.extend_from_slice(&(1u64 << 24).to_be_bytes());
        stream.extend_from_slice(&3u64.to_be_bytes());
        stream.extend_from_slice(b"abc");
        stream.extend_from_slice(&0u64.to_be_bytes());
        stream.extend_from_slice(&2u64.to_be_bytes());
        stream.extend_from_slice(b"de");
        let mut out = Vec::new();
        Pbzx::new(&stream).expect("pbzx").read_to_end(&mut out).expect("read");
        assert_eq!(out, b"abcde");
        for cut in 12..stream.len() {
            let mut out = Vec::new();
            let _ = Pbzx::new(&stream[..cut]).expect("pbzx").read_to_end(&mut out);
        }
        assert!(Pbzx::new(b"pbzx").is_none());
        assert!(Pbzx::new(b"nope").is_none());
    }

    #[test]
    fn base64_decodes() {
        assert_eq!(base64("aGVsbG8=").as_deref(), Some(&b"hello"[..]));
        assert_eq!(base64("aGVs\nbG8h").as_deref(), Some(&b"hello!"[..]));
        assert_eq!(base64("a*b"), None);
    }
}
