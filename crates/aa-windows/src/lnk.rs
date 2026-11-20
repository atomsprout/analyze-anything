//! Bounded Shell Link declarations, without invoking shell resolution or loading handlers.

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde::Serialize;
use serde_json::json;

const HEADER: &[u8] = &[0x4c, 0, 0, 0, 1, 0x14, 2, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46];
const MAX_BYTES: usize = 1024 * 1024;
const MAX_BLOCKS: usize = 128;

type Result<T> = std::result::Result<T, &'static str>;

fn range(bytes: &[u8], start: usize, length: usize) -> Result<&[u8]> {
    bytes.get(start..start.checked_add(length).ok_or("shortcut offset overflow")?).ok_or("shortcut range exceeds its containing structure")
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16> {
    let b = range(bytes, at, 2)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    let b = range(bytes, at, 4)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[derive(Debug, Serialize)]
struct Declaration {
    field: &'static str,
    value: String,
    offset: usize,
    length: usize,
}

#[derive(Debug, Default)]
struct Link {
    flags: u32,
    fields: Vec<Declaration>,
    limits: std::collections::BTreeSet<&'static str>,
    extra_signatures: Vec<u32>,
}

impl Link {
    fn text(&mut self, field: &'static str, bytes: &[u8], offset: usize, wide: bool) -> Result<()> {
        let value = if wide {
            if !bytes.len().is_multiple_of(2) {
                return Err("odd UTF-16 declaration length");
            }
            let units: Vec<u16> = bytes.chunks_exact(2).map(|b| u16::from_le_bytes([b[0], b[1]])).collect();
            String::from_utf16(&units).map_err(|_| "invalid UTF-16 declaration")?
        } else if bytes.is_ascii() {
            String::from_utf8(bytes.to_vec()).map_err(|_| "invalid ASCII declaration")?
        } else {
            self.limits.insert("non-ASCII legacy text not decoded; the input does not establish a code page");
            return Ok(());
        };
        self.fields.push(Declaration { field, value: aa_core::text::redact_sensitive_text(&value)?, offset, length: bytes.len() });
        Ok(())
    }

    fn terminated(&mut self, field: &'static str, block: &[u8], at: usize, minimum: usize, base: usize, wide: bool) -> Result<()> {
        if at < minimum || at >= block.len() {
            return Err("shortcut string offset points outside its data area");
        }
        let tail = &block[at..];
        let length = if wide {
            tail.chunks_exact(2).position(|b| b == [0, 0]).and_then(|n| n.checked_mul(2)).ok_or("unterminated UTF-16 declaration")?
        } else {
            tail.iter().position(|&b| b == 0).ok_or("unterminated legacy declaration")?
        };
        self.text(field, &tail[..length], base + at, wide)
    }

    fn link_info(&mut self, block: &[u8], base: usize) -> Result<()> {
        let header = u32_at(block, 4)? as usize;
        if header != 28 && header < 36 || header > block.len() {
            return Err("invalid LinkInfo header size");
        }
        let flags = u32_at(block, 8)?;
        if flags & !3 != 0 || header > 36 {
            self.limits.insert("LinkInfo has flags or header extensions that are not interpreted");
        }
        if flags & 1 != 0 {
            let volume = u32_at(block, 12)? as usize;
            if volume < header {
                return Err("volume offset points inside LinkInfo header");
            }
            let size = u32_at(block, volume)? as usize;
            if size < 16 {
                return Err("invalid volume structure size");
            }
            range(block, volume, size)?;
            self.limits.insert("volume metadata is not interpreted");
            self.terminated("LinkInfo/LocalBasePath", block, u32_at(block, 16)? as usize, header, base, false)?;
            if header >= 36 && u32_at(block, 28)? != 0 {
                self.terminated("LinkInfo/LocalBasePathUnicode", block, u32_at(block, 28)? as usize, header, base, true)?;
            }
        }
        self.terminated("LinkInfo/CommonPathSuffix", block, u32_at(block, 24)? as usize, header, base, false)?;
        if header >= 36 && u32_at(block, 32)? != 0 {
            self.terminated("LinkInfo/CommonPathSuffixUnicode", block, u32_at(block, 32)? as usize, header, base, true)?;
        }
        if flags & 2 != 0 {
            let at = u32_at(block, 20)? as usize;
            if at < header {
                return Err("network offset points inside LinkInfo header");
            }
            let length = u32_at(block, at)? as usize;
            if length < 20 {
                return Err("invalid network structure size");
            }
            let network = range(block, at, length)?;
            let name = u32_at(network, 8)? as usize;
            let minimum = if name > 20 { 28 } else { 20 };
            self.terminated("LinkInfo/Network/NetName", network, name, minimum, base + at, false)?;
            let network_flags = u32_at(network, 4)?;
            if network_flags & 1 != 0 {
                self.terminated("LinkInfo/Network/DeviceName", network, u32_at(network, 12)? as usize, minimum, base + at, false)?;
            }
            if name > 20 {
                self.terminated("LinkInfo/Network/NetNameUnicode", network, u32_at(network, 20)? as usize, minimum, base + at, true)?;
                if network_flags & 1 != 0 {
                    self.terminated(
                        "LinkInfo/Network/DeviceNameUnicode",
                        network,
                        u32_at(network, 24)? as usize,
                        minimum,
                        base + at,
                        true,
                    )?;
                }
            }
            self.limits.insert("network provider metadata is not interpreted; network references are not contacted");
        }
        Ok(())
    }
}

fn parse(bytes: &[u8]) -> Result<Link> {
    if bytes.len() > MAX_BYTES {
        return Err("Shell Link exceeds the 1 MiB reader limit");
    }
    if !bytes.starts_with(HEADER) {
        return Err("invalid Shell Link header size or class identifier");
    }
    range(bytes, 0, 76)?;
    let mut link = Link { flags: u32_at(bytes, 20)?, ..Link::default() };
    if link.flags & !0x07ff_ffff != 0 {
        link.limits.insert("reserved Shell Link flag bits are set and not interpreted");
    }
    let mut cursor = 76;
    if link.flags & 1 != 0 {
        let length = u16_at(bytes, cursor)? as usize;
        cursor += 2;
        let ids = range(bytes, cursor, length)?;
        let mut position = 0;
        let mut count = 0;
        loop {
            let size = u16_at(ids, position)? as usize;
            if size == 0 {
                if position + 2 != ids.len() {
                    return Err("trailing data inside Shell Link IDList");
                }
                break;
            }
            if size < 2 || count >= 4096 {
                return Err("invalid or excessive Shell Link IDList items");
            }
            range(ids, position, size)?;
            position += size;
            count += 1;
        }
        cursor += length;
        link.limits.insert("Shell namespace IDList items are not interpreted or resolved");
    }
    if link.flags & 2 != 0 {
        let length = u32_at(bytes, cursor)? as usize;
        let block = range(bytes, cursor, length)?;
        link.link_info(block, cursor)?;
        cursor += length;
    }
    for (mask, field) in [(4, "Name"), (8, "RelativePath"), (16, "WorkingDirectory"), (32, "Arguments"), (64, "IconLocation")] {
        if link.flags & mask == 0 {
            continue;
        }
        let count = u16_at(bytes, cursor)? as usize;
        cursor += 2;
        let wide = link.flags & 0x80 != 0;
        let length = count.checked_mul(if wide { 2 } else { 1 }).ok_or("Shell Link character count overflow")?;
        link.text(field, range(bytes, cursor, length)?, cursor, wide)?;
        cursor += length;
    }
    for count in 0..=MAX_BLOCKS {
        let size = u32_at(bytes, cursor)? as usize;
        if size < 4 {
            if cursor + 4 != bytes.len() {
                link.limits.insert("bytes after the ExtraData terminator are not interpreted");
            }
            return Ok(link);
        }
        if size < 8 || count == MAX_BLOCKS {
            return Err("invalid or excessive Shell Link ExtraData blocks");
        }
        let block = range(bytes, cursor, size)?;
        let signature = u32_at(block, 4)?;
        link.extra_signatures.push(signature);
        if matches!(signature, 0xa0000001 | 0xa0000007) {
            if size != 0x314 {
                return Err("invalid environment declaration block size");
            }
            let (ansi, wide) = if signature == 0xa0000001 {
                ("Environment/TargetAnsi", "Environment/TargetUnicode")
            } else {
                ("Environment/IconAnsi", "Environment/IconUnicode")
            };
            link.terminated(ansi, &block[..268], 8, 8, cursor, false)?;
            link.terminated(wide, block, 268, 268, cursor, true)?;
        } else {
            link.limits.insert("one or more ExtraData blocks are not interpreted");
        }
        cursor += size;
    }
    Err("excessive Shell Link ExtraData blocks")
}

pub fn analyze(file: &Artifact, bytes: &[u8], out: &mut Output) {
    if file.extension().as_deref() != Some("lnk") && !bytes.starts_with(HEADER) {
        return;
    }
    let link = match parse(bytes) {
        Ok(link) => link,
        Err(reason) => {
            out.limitation("windows.shortcut-unreadable", Some(file), Some(reason.into()));
            return;
        }
    };
    out.kind(file, "shell-link");
    let show_command = u32_at(bytes, 60).ok();
    let icon_index = u32_at(bytes, 56).ok().map(|v| v as i32);
    out.fact(
        file,
        "windows.shell-link",
        json!({"flags": link.flags, "show_command": show_command, "icon_index": icon_index,
        "run_as_user": link.flags & 0x2000 != 0, "prefer_environment_path": link.flags & 0x02000000 != 0,
        "force_no_link_info": link.flags & 0x100 != 0,
        "declarations": link.fields, "extra_signatures": link.extra_signatures, "target_resolved": false}),
    );
    let mut finding = Finding::new(Section::Capabilities, "windows", "windows.shell-link", Confidence::Verified, Severity::Info)
        .evidence(Evidence::bytes(file, 20, 4, link.flags));
    for field in link.fields.iter().take(12) {
        finding = finding.evidence(Evidence::bytes(
            file,
            field.offset as u64,
            field.length as u64,
            json!({"field": field.field, "value": field.value}),
        ));
    }
    out.finding(finding);
    // Even a fully decoded set of declarations does not establish a usable system target.
    out.limitation("windows.shortcut-target-unresolved", Some(file), None);
    if !link.limits.is_empty() {
        out.limitation("windows.shortcut-partial", Some(file), Some(link.limits.into_iter().collect::<Vec<_>>().join("; ")));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(flags: u32) -> Vec<u8> {
        let mut bytes = HEADER.to_vec();
        bytes.resize(76, 0);
        bytes[20..24].copy_from_slice(&flags.to_le_bytes());
        bytes
    }

    #[test]
    fn unicode_declarations_keep_references_and_redact_arguments() {
        let mut bytes = header(0xf8);
        for value in [r"..\目标.exe", r"%SystemRoot%", "--password fixture-secret", r"\\server\share\icon.ico"] {
            let units: Vec<u16> = value.encode_utf16().collect();
            bytes.extend((units.len() as u16).to_le_bytes());
            bytes.extend(units.into_iter().flat_map(u16::to_le_bytes));
        }
        bytes.extend([0; 4]);
        let link = parse(&bytes).expect("Unicode Shell Link");
        assert_eq!(link.fields[0].value, r"..\目标.exe");
        assert_eq!(link.fields[1].value, "%SystemRoot%");
        assert_eq!(link.fields[2].value, "--password [redacted]");
        assert_eq!(link.fields[3].value, r"\\server\share\icon.ico");
        for length in 0..bytes.len() {
            assert!(parse(&bytes[..length]).is_err(), "cut at {length}");
        }
    }

    #[test]
    fn malformed_lengths_and_legacy_text_are_explicit() {
        let mut legacy = header(4);
        legacy.extend(1u16.to_le_bytes());
        legacy.push(0x80);
        legacy.extend([0; 4]);
        let link = parse(&legacy).expect("legacy structure is bounded");
        assert!(link.fields.is_empty());
        assert!(!link.limits.is_empty());
        for flags in [1, 2, 0x80 | 4] {
            let mut broken = header(flags);
            broken.extend([0xff; 8]);
            assert!(parse(&broken).is_err());
        }
        let mut invalid = header(0);
        invalid.extend(7u32.to_le_bytes());
        invalid.extend([0; 4]);
        assert!(parse(&invalid).is_err());
        let mut unknown = header(0);
        unknown.extend(8u32.to_le_bytes());
        unknown.extend(0xa0000099u32.to_le_bytes());
        unknown.extend([0; 4]);
        assert!(!parse(&unknown).expect("unknown bounded block").limits.is_empty());
    }

    #[test]
    fn network_paths_stay_text_and_offsets_cannot_escape_the_network_block() {
        let mut network = vec![0; 20];
        network[8..12].copy_from_slice(&20u32.to_le_bytes());
        network.extend(b"\\\\server\\share\0");
        let network_size = network.len() as u32;
        network[..4].copy_from_slice(&network_size.to_le_bytes());
        let mut info = vec![0; 28];
        info[4..8].copy_from_slice(&28u32.to_le_bytes());
        info[8..12].copy_from_slice(&2u32.to_le_bytes());
        info[20..24].copy_from_slice(&28u32.to_le_bytes());
        info.extend(network);
        let suffix_at = info.len() as u32;
        info[24..28].copy_from_slice(&suffix_at.to_le_bytes());
        info.extend(b"target.exe\0");
        let info_size = info.len() as u32;
        info[..4].copy_from_slice(&info_size.to_le_bytes());
        let mut bytes = header(2);
        bytes.extend(info);
        bytes.extend([0; 4]);
        let link = parse(&bytes).expect("UNC declarations");
        assert!(link.fields.iter().any(|f| f.field == "LinkInfo/Network/NetName" && f.value == r"\\server\share"));
        assert!(link.fields.iter().any(|f| f.field == "LinkInfo/CommonPathSuffix" && f.value == "target.exe"));
        for offset in [0u32, 19, network_size, u32::MAX] {
            let mut malformed = bytes.clone();
            malformed[76 + 28 + 8..76 + 28 + 12].copy_from_slice(&offset.to_le_bytes());
            assert!(parse(&malformed).is_err(), "network offset {offset}");
        }
    }

    #[test]
    fn opaque_idlists_and_environment_paths_have_bounded_structure() {
        let mut bytes = header(1);
        bytes.extend(6u16.to_le_bytes());
        bytes.extend([4, 0, 0xaa, 0xbb, 0, 0]);
        bytes.extend([0; 4]);
        assert!(!parse(&bytes).expect("bounded opaque IDList").limits.is_empty());
        bytes[78..80].copy_from_slice(&1u16.to_le_bytes());
        assert!(parse(&bytes).is_err());
        let mut environment = header(0x200);
        let mut block = vec![0; 0x314];
        block[..4].copy_from_slice(&0x314u32.to_le_bytes());
        block[4..8].copy_from_slice(&0xa0000001u32.to_le_bytes());
        let path = r"%SystemRoot%\file.exe";
        block[8..8 + path.len()].copy_from_slice(path.as_bytes());
        let wide: Vec<u8> = path.encode_utf16().flat_map(u16::to_le_bytes).collect();
        block[268..268 + wide.len()].copy_from_slice(&wide);
        environment.extend(block);
        environment.extend([0; 4]);
        let link = parse(&environment).expect("unexpanded target declarations");
        assert_eq!(link.fields.len(), 2);
        assert!(link.fields.iter().all(|f| f.value == path));
        let mut excessive = header(0);
        for _ in 0..MAX_BLOCKS + 1 {
            excessive.extend(8u32.to_le_bytes());
            excessive.extend(0xa0000099u32.to_le_bytes());
        }
        excessive.extend([0; 4]);
        assert!(parse(&excessive).is_err());
    }
}
