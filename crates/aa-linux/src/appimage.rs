//! Type 2 AppImages: a checked ELF runtime followed by a bounded SquashFS image.

use aa_core::plugin::{Analyzer, Output, Rule, SinkError, Tree, Unpack, UnpackSink, Unpacker};
use aa_core::{Artifact, Confidence, Evidence, Finding, Section, Severity};
use serde_json::json;

pub struct AppImage;

const MAX_SECTIONS: usize = 8192;
const MAX_PROGRAMS: usize = 1024;
const IMAGE_NAME: &str = "[filesystem].squashfs";
type Result<T> = std::result::Result<T, &'static str>;

const RULES: &[Rule] = &[
    Rule {
        id: "appimage.identity",
        title_en: "Declared AppImage application identity",
        title_zh: "AppImage 应用身份声明",
        text_en: "The captured root Desktop Entry declares application {name}. This is supplied application metadata, not publisher authentication or an installed-state check.",
        text_zh: "已捕获的根桌面入口声明了应用 {name}。这是所提供应用的元数据，没有认证发布者或检查安装状态。",
    },
    Rule {
        id: "appimage.metadata-unresolved",
        title_en: "AppImage application identity remains unresolved",
        title_zh: "AppImage 应用身份未确定",
        text_en: "One original captured root Desktop Entry with a readable name was not established. Other captured application metadata remains available as evidence.",
        text_zh: "没有确定唯一原始的、名称可读的根桌面入口。其他已捕获应用元数据仍作为证据提供。",
    },
    Rule {
        id: "appimage.contents",
        title_en: "AppImage Type 2 filesystem",
        title_zh: "AppImage Type 2 文件系统",
        text_en: "The ELF runtime is followed by a SquashFS filesystem at byte {offset}, containing {size} bytes. The range was established from the runtime's section table and the filesystem header; no runtime was invoked.",
        text_zh: "ELF 运行时后，在字节 {offset} 处有一个包含 {size} 字节的 SquashFS 文件系统。通过运行时节表及文件系统头确定范围，没有调用运行时。",
    },
    Rule {
        id: "appimage.entry",
        title_en: "Captured AppImage entry",
        title_zh: "已捕获 AppImage 入口",
        text_en: "The captured filesystem declares AppRun. Its bytes or literal link target identify a supplied entry; execution and runtime target selection were not established.",
        text_zh: "已捕获的文件系统声明了 AppRun。其字节或字面链接目标标识了所提供的入口，没有确定执行或运行时目标选择。",
    },
    Rule {
        id: "appimage.unread",
        title_en: "AppImage profile could not be read",
        title_zh: "AppImage 格式范围无法读取",
        text_en: "The AppImage marker was recognized, but the supported ELF-to-SquashFS layout could not be established within the checked profile.",
        text_zh: "已识别 AppImage 标记，但无法在有检查的支持范围内确定 ELF 至 SquashFS 的布局。",
    },
    Rule {
        id: "appimage.entry-unresolved",
        title_en: "AppImage entry remains unresolved",
        title_zh: "AppImage 入口未确定",
        text_en: "The captured AppRun declaration is missing, ambiguous, unsupported or does not identify an original supplied regular file. Links and runtime behavior were not followed.",
        text_zh: "已捕获的 AppRun 声明缺失、有歧义、不受支持，或未标识原始的所提供普通文件。没有跟随链接或推断运行时行为。",
    },
    Rule {
        id: "appimage.authenticity-unchecked",
        title_en: "AppImage authenticity and runtime behavior were not established",
        title_zh: "AppImage 来源真实性及运行时行为未确定",
        text_en: "Embedded signatures, update information and runtime code were not authenticated or evaluated. Reading the filesystem does not establish trust, installation or execution.",
        text_zh: "没有认证内嵌签名、更新信息或求值运行时代码。读取文件系统不能确定可信性、安装或执行。",
    },
    Rule {
        id: "appimage.trailing-data",
        title_en: "AppImage has additional bytes after the filesystem",
        title_zh: "AppImage 文件系统后存在额外字节",
        text_en: "Bytes after the declared SquashFS extent are outside this container profile. They were not interpreted as additional files or trusted metadata.",
        text_zh: "SquashFS 声明范围后的字节超出此容器支持范围，没有将其解释为额外文件或可信元数据。",
    },
];

#[derive(Debug)]
struct Layout {
    offset: usize,
    size: usize,
    bits: u8,
    little_endian: bool,
    machine: u16,
    sections: usize,
    trailing: usize,
    padding_only: bool,
}

fn range(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    let end = offset.checked_add(length).ok_or("AppImage range overflow")?;
    bytes.get(offset..end).ok_or("AppImage range exceeds the supplied file")
}

fn number(bytes: &[u8], offset: usize, width: usize, little: bool) -> Result<u64> {
    let raw = range(bytes, offset, width)?;
    let mut value = 0u64;
    if little {
        for byte in raw.iter().rev() {
            value = (value << 8) | u64::from(*byte);
        }
    } else {
        for byte in raw {
            value = (value << 8) | u64::from(*byte);
        }
    }
    Ok(value)
}

fn address(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| "AppImage offset exceeds the address space")
}

fn extent(bytes: &[u8], offset: u64, size: u64) -> Result<usize> {
    let start = address(offset)?;
    let size = address(size)?;
    range(bytes, start, size)?;
    start.checked_add(size).ok_or("AppImage section extent overflow")
}

fn marker(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x7fELF") && bytes.get(8..10) == Some(b"AI")
}

fn parse(bytes: &[u8]) -> Result<Layout> {
    if !marker(bytes) || bytes.get(10) != Some(&2) {
        return Err("only AppImage Type 2 is supported");
    }
    let class = *bytes.get(4).ok_or("truncated ELF identification")?;
    let little = match bytes.get(5) {
        Some(1) => true,
        Some(2) => false,
        _ => return Err("unknown ELF byte order"),
    };
    if bytes.get(6) != Some(&1) {
        return Err("unsupported ELF identification version");
    }
    let (header_size, section_size, program_size) = match class {
        1 => (52, 40, 32),
        2 => (64, 64, 56),
        _ => return Err("unknown ELF class"),
    };
    range(bytes, 0, header_size)?;
    if !matches!(number(bytes, 16, 2, little)?, 2 | 3) {
        return Err("the AppImage runtime must have executable or shared-object ELF type");
    }
    if number(bytes, 20, 4, little)? != 1 {
        return Err("unsupported ELF header version");
    }
    let (phoff, shoff, ehsize, phentsize, phnum, shentsize, shnum) = if class == 1 {
        (number(bytes, 28, 4, little)?, number(bytes, 32, 4, little)?, 40, 42, 44, 46, 48)
    } else {
        (number(bytes, 32, 8, little)?, number(bytes, 40, 8, little)?, 52, 54, 56, 58, 60)
    };
    if number(bytes, ehsize, 2, little)? != header_size as u64 {
        return Err("nonstandard ELF header size is outside this AppImage profile");
    }
    let sections = address(number(bytes, shnum, 2, little)?)?;
    if sections == 0 || sections > MAX_SECTIONS || number(bytes, shentsize, 2, little)? != section_size as u64 {
        return Err("extended, absent or oversized ELF section tables are unsupported");
    }
    let shoff = address(shoff)?;
    if shoff < header_size {
        return Err("ELF section table overlaps the header");
    }
    let table_size = sections.checked_mul(section_size).ok_or("ELF section-table size overflow")?;
    range(bytes, shoff, table_size)?;
    let table_end = shoff.checked_add(table_size).ok_or("ELF section-table extent overflow")?;
    let last = shoff + (sections - 1) * section_size;
    if number(bytes, last + 4, 4, little)? == 8 {
        return Err("a final NOBITS section has no supported runtime extent");
    }
    let (offset_field, size_field, width) = if class == 1 { (16, 20, 4) } else { (24, 32, 8) };
    let last_end = extent(bytes, number(bytes, last + offset_field, width, little)?, number(bytes, last + size_field, width, little)?)?;
    let offset = table_end.max(last_end);
    // The upstream runtime uses this layout. Other file-backed sections must fit it;
    // a magic string in an unrelated section is never used to discover a payload.
    for index in 0..sections {
        let at = shoff + index * section_size;
        if number(bytes, at + 4, 4, little)? == 8 {
            continue;
        }
        let end = extent(bytes, number(bytes, at + offset_field, width, little)?, number(bytes, at + size_field, width, little)?)?;
        if end > offset {
            return Err("ELF section extends beyond the supported runtime boundary");
        }
    }
    let programs = address(number(bytes, phnum, 2, little)?)?;
    if programs > MAX_PROGRAMS {
        return Err("ELF program-header count limit");
    }
    if programs != 0 {
        if number(bytes, phentsize, 2, little)? != program_size as u64 {
            return Err("nonstandard ELF program-header size");
        }
        let phoff = address(phoff)?;
        if phoff < header_size || phoff.checked_add(programs * program_size).is_none_or(|end| end > offset) {
            return Err("ELF program-header table exceeds the runtime");
        }
        for index in 0..programs {
            let at = phoff + index * program_size;
            let (offset_field, size_field, width) = if class == 1 { (4, 16, 4) } else { (8, 32, 8) };
            let end = extent(bytes, number(bytes, at + offset_field, width, little)?, number(bytes, at + size_field, width, little)?)?;
            if end > offset {
                return Err("ELF segment exceeds the supported runtime boundary");
            }
        }
    }
    let header = range(bytes, offset, 96)?;
    if !header.starts_with(b"hsqs") || number(header, 28, 2, true)? != 4 || number(header, 30, 2, true)? != 0 {
        return Err("the proven runtime boundary does not contain a supported little-endian SquashFS v4 image");
    }
    let size = address(number(header, 40, 8, true)?)?;
    if size < 96 {
        return Err("declared SquashFS extent is shorter than its superblock");
    }
    range(bytes, offset, size)?;
    let trailing = bytes.len() - offset - size;
    let padding_only = trailing <= 4095 && bytes[offset + size..].iter().all(|byte| *byte == 0);
    Ok(Layout {
        offset,
        size,
        bits: if class == 1 { 32 } else { 64 },
        little_endian: little,
        machine: number(bytes, 18, 2, little)? as u16,
        sections,
        trailing,
        padding_only,
    })
}

impl Unpacker for AppImage {
    fn id(&self) -> &'static str {
        "appimage"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn unpack(&self, _file: &Artifact, bytes: &[u8], sink: &mut dyn UnpackSink) -> Unpack {
        if !marker(bytes) {
            return Unpack::NotMine;
        }
        let layout = match parse(bytes) {
            Ok(layout) => layout,
            Err(detail) => return Unpack::Failed { kind: "appimage", detail: detail.into() },
        };
        if layout.trailing != 0 && !layout.padding_only {
            sink.limitation("appimage.trailing-data", Some(format!("{} bytes after the declared filesystem", layout.trailing)));
        }
        match sink.add(IMAGE_NAME, &mut &bytes[layout.offset..layout.offset + layout.size]) {
            Ok(()) | Err(SinkError::LimitReached) => Unpack::Done { kind: "appimage" },
            Err(SinkError::Read(detail)) => Unpack::Failed { kind: "appimage", detail },
        }
    }
}

fn original(file: &Artifact) -> bool {
    file.facts.get("engine.entry-name").is_none_or(|name| name["normalized"] != true && name["colliding"] != true)
}

fn relative_target(value: &str) -> Option<String> {
    let value = value.strip_prefix("./").unwrap_or(value);
    if value.is_empty()
        || value.len() > 4096
        || value.contains(['\\', '\0', '$', '%'])
        || value.split('/').any(|part| part.is_empty() || part == "." || part == "..")
    {
        return None;
    }
    Some(value.to_string())
}

impl Analyzer for AppImage {
    fn id(&self) -> &'static str {
        "appimage"
    }
    fn rules(&self) -> &'static [Rule] {
        RULES
    }
    fn analyze_file(&self, tree: &dyn Tree, file: &Artifact, out: &mut Output) {
        if file.unpacked_by.as_deref() != Some("appimage") {
            return;
        }
        let parsed = tree.read(&file.path).map_err(|_| "AppImage bytes unavailable").and_then(|bytes| parse(&bytes));
        let layout = match parsed {
            Ok(layout) => layout,
            Err(detail) => {
                out.limitation("appimage.unread", Some(file), Some(detail.into()));
                return;
            }
        };
        out.kind(file, "appimage");
        out.fact(
            file,
            "appimage.container",
            json!({"type":2,"elf_bits":layout.bits,"elf_little_endian":layout.little_endian,
            "machine":layout.machine,"section_count":layout.sections,"filesystem_offset":layout.offset,"filesystem_size":layout.size,
            "filesystem_child":IMAGE_NAME,"trailing_bytes":layout.trailing,"trailing_zero_padding":layout.padding_only,
            "runtime_invoked":false,"signature_verified":false}),
        );
        out.finding(
            Finding::new(Section::Structure, "appimage", "appimage.contents", Confidence::Verified, Severity::Info)
                .param("offset", layout.offset)
                .param("size", layout.size)
                .evidence(Evidence::bytes(file, 8, 3, "AI02"))
                .evidence(Evidence::bytes(file, layout.offset as u64, 96, json!({"magic":"hsqs","bytes_used":layout.size}))),
        );
        out.limitation("appimage.authenticity-unchecked", Some(file), None);
    }
    fn analyze_tree(&self, tree: &dyn Tree, out: &mut Output) {
        for (index, file) in tree.artifacts().iter().filter(|file| file.facts.contains_key("appimage.container")).enumerate() {
            if index == 1024 {
                out.limitation("appimage.entry-unresolved", None, Some("AppImage relationship source budget exhausted".into()));
                break;
            }
            // The file pass deliberately keeps the first, general ELF kind. The
            // tree pass can refine it once the captured container is established.
            out.kind(file, "appimage");
            let path = format!("{}/{IMAGE_NAME}", file.path);
            let Some(image) = tree.get(&path).filter(|image| image.parent.as_deref() == Some(file.path.as_str()) && original(image)) else {
                out.limitation(
                    "appimage.entry-unresolved",
                    Some(file),
                    Some("captured filesystem child is unavailable or ambiguous".into()),
                );
                continue;
            };
            let Some(entries) = image.facts.get("squashfs.directory").and_then(|fact| fact["entries"].as_array()) else {
                out.limitation("appimage.entry-unresolved", Some(file), Some("filesystem directory was not read".into()));
                continue;
            };
            let complete = image.facts.get("engine.container-listing").is_some_and(|listing| listing["complete"] == true);
            let mut desktops = entries.iter().filter(|entry| {
                entry["path"].as_str().is_some_and(|name| {
                    let name = name.trim_start_matches('/');
                    !name.contains('/') && name.ends_with(".desktop")
                })
            });
            let desktop = desktops
                .next()
                .filter(|_| desktops.next().is_none())
                .and_then(|entry| entry["path"].as_str())
                .and_then(|name| tree.get(&format!("{path}/{}", name.trim_start_matches('/'))))
                .filter(|candidate| {
                    complete
                        && original(candidate)
                        && candidate.digests.is_some()
                        && candidate.parent.as_deref() == Some(path.as_str())
                        && candidate
                            .facts
                            .get("linux.desktop-entry")
                            .is_some_and(|fact| fact["name"].as_str().is_some_and(|name| !name.is_empty()))
                });
            if let Some(desktop) = desktop {
                out.fact(
                    file,
                    "appimage.identity",
                    json!({"name":desktop.facts["linux.desktop-entry"]["name"],"source":desktop.path,
                    "source_sha256":desktop.digests.as_ref().map(|digest|&digest.sha256),"publisher_authenticated":false}),
                );
                out.finding(
                    Finding::new(Section::Identity, "appimage", "appimage.identity", Confidence::Verified, Severity::Info)
                        .param("name", desktop.facts["linux.desktop-entry"]["name"].clone())
                        .evidence(Evidence::field(desktop, "Desktop Entry/Name", desktop.facts["linux.desktop-entry"]["name"].clone())),
                );
            } else {
                out.limitation("appimage.metadata-unresolved", Some(file), None);
            }
            let found: Vec<_> = entries
                .iter()
                .filter(|entry| entry["path"].as_str().is_some_and(|path| path.trim_start_matches('/') == "AppRun"))
                .collect();
            let entry = found.first().copied().filter(|_| found.len() == 1);
            let declared = entry.and_then(|entry| entry["link_target"].as_str());
            let relative = if let Some(declared) = declared { relative_target(declared) } else { entry.map(|_| "AppRun".into()) };
            let target = relative.as_deref().and_then(|relative| tree.get(&format!("{path}/{relative}"))).filter(|target| {
                complete && original(target) && target.digests.is_some() && target.parent.as_deref() == Some(path.as_str())
            });
            let relation = json!({"field":"AppRun","basis":"captured-filesystem-entry","declared":declared,
                "status":if target.is_some(){"matched-supplied-declaration"}else{"unresolved"},
                "target":target.map(|target|&target.path),"target_sha256":target.and_then(|target|target.digests.as_ref().map(|digest|&digest.sha256)),
                "source_entry":entry,"runtime_target_resolved":false});
            out.fact(file, "appimage.entry", relation);
            if let (Some(entry), Some(target)) = (entry, target) {
                out.finding(
                    Finding::new(Section::Structure, "appimage", "appimage.entry", Confidence::Verified, Severity::Info)
                        .evidence(Evidence::field(image, "SquashFS/AppRun", entry.clone()))
                        .evidence(Evidence::whole(
                            target,
                            json!({"path":target.path,"sha256":target.digests.as_ref().map(|digest|&digest.sha256)}),
                        )),
                );
            } else {
                out.limitation(
                    "appimage.entry-unresolved",
                    Some(file),
                    Some("AppRun cannot be linked to one original regular supplied file in a complete filesystem".into()),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::BTreeMap;
    struct Supplied {
        files: Vec<Artifact>,
    }
    impl Tree for Supplied {
        fn artifacts(&self) -> &[Artifact] {
            &self.files
        }
        fn read(&self, _path: &str) -> std::io::Result<aa_core::plugin::Bytes> {
            panic!("entry relationships never read or execute a target")
        }
    }
    fn artifact(path: &str, parent: Option<&str>) -> Artifact {
        Artifact {
            path: path.into(),
            parent: parent.map(str::to_string),
            size: 7,
            digests: Some(aa_core::Digests { md5: "0".repeat(32), sha1: "0".repeat(40), sha256: aa_core::sha256_hex(b"fixture") }),
            detected: None,
            kind: None,
            entropy: None,
            unpacked_by: None,
            facts: BTreeMap::new(),
        }
    }

    fn image() -> Vec<u8> {
        let mut bytes = vec![0u8; 224];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[8..11].copy_from_slice(b"AI\x02");
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[40..48].copy_from_slice(&64u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&1u16.to_le_bytes());
        bytes[128..132].copy_from_slice(b"hsqs");
        bytes[156..158].copy_from_slice(&4u16.to_le_bytes());
        bytes[168..176].copy_from_slice(&96u64.to_le_bytes());
        bytes
    }

    #[test]
    fn checked_elf_extents_establish_payload_without_scanning() {
        let bytes = image();
        let layout = parse(&bytes).expect("bounded AppImage layout");
        assert_eq!((layout.offset, layout.size, layout.bits), (128, 96, 64));
        for count in 0..bytes.len() {
            assert!(parse(&bytes[..count]).is_err(), "short prefix {count}");
        }
        let mut wrong = bytes.clone();
        wrong[128..132].fill(0);
        wrong.extend_from_slice(&bytes[128..]);
        assert!(parse(&wrong).is_err(), "later hsqs cannot replace the ELF-proven boundary");
    }

    #[test]
    fn oversized_tables_and_filesystem_extents_are_rejected_before_allocation() {
        for (at, data) in
            [(40, u64::MAX.to_le_bytes().to_vec()), (60, u16::MAX.to_le_bytes().to_vec()), (168, u64::MAX.to_le_bytes().to_vec())]
        {
            let mut bytes = image();
            bytes[at..at + data.len()].copy_from_slice(&data);
            assert!(parse(&bytes).is_err());
        }
        let mut bytes = image();
        bytes[10] = 1;
        assert!(parse(&bytes).is_err());
        let mut bytes = image();
        bytes.extend_from_slice(b"extra");
        assert!(!parse(&bytes).expect("known extent").padding_only);
        let mut bytes = image();
        bytes.extend_from_slice(&[0; 12]);
        assert!(parse(&bytes).expect("zero padding").padding_only);
    }

    #[test]
    fn link_targets_are_literal_namespace_local_paths() {
        assert_eq!(relative_target("./usr/bin/app").as_deref(), Some("usr/bin/app"));
        for path in ["/usr/bin/app", "../app", "usr/../app", "usr\\app", "$APP", "usr//app", ""] {
            assert!(relative_target(path).is_none(), "{path}");
        }
    }

    #[test]
    fn both_elf_classes_and_byte_orders_have_checked_runtime_boundaries() {
        for class in [1u8, 2] {
            for little in [false, true] {
                let (header_size, section_size) = if class == 1 { (52usize, 40usize) } else { (64, 64) };
                let offset = header_size + section_size;
                let mut bytes = vec![0u8; offset + 96];
                bytes[..4].copy_from_slice(b"\x7fELF");
                bytes[4] = class;
                bytes[5] = if little { 1 } else { 2 };
                bytes[6] = 1;
                bytes[8..11].copy_from_slice(b"AI\x02");
                let put = |bytes: &mut [u8], at: usize, value: u64, width: usize| {
                    let raw = if little { value.to_le_bytes() } else { value.to_be_bytes() };
                    let raw = if little { &raw[..width] } else { &raw[8 - width..] };
                    bytes[at..at + width].copy_from_slice(raw);
                };
                put(&mut bytes, 16, 2, 2);
                put(&mut bytes, 18, 62, 2);
                put(&mut bytes, 20, 1, 4);
                let (shoff, ehsize, shentsize, shnum, width) = if class == 1 { (32, 40, 46, 48, 4) } else { (40, 52, 58, 60, 8) };
                put(&mut bytes, shoff, header_size as u64, width);
                put(&mut bytes, ehsize, header_size as u64, 2);
                put(&mut bytes, shentsize, section_size as u64, 2);
                put(&mut bytes, shnum, 1, 2);
                bytes[offset..offset + 4].copy_from_slice(b"hsqs");
                bytes[offset + 28..offset + 30].copy_from_slice(&4u16.to_le_bytes());
                bytes[offset + 40..offset + 48].copy_from_slice(&96u64.to_le_bytes());
                let layout = parse(&bytes).expect("supported constructed ELF profile");
                assert_eq!(layout.offset, offset);
                assert_eq!(layout.little_endian, little);
                assert_eq!(layout.bits, if class == 1 { 32 } else { 64 });
            }
        }
    }

    #[test]
    fn captured_entry_and_identity_require_one_original_complete_filesystem_namespace() {
        let root = "example.AppImage";
        let image = "example.AppImage/[filesystem].squashfs";
        let mut source = artifact(root, None);
        source.facts.insert("appimage.container".into(), json!({"type":2}));
        let mut filesystem = artifact(image, Some(root));
        filesystem.facts.insert("engine.container-listing".into(), json!({"complete":true}));
        filesystem.facts.insert("squashfs.directory".into(),json!({"entries":[{"path":"AppRun","type":"symlink","link_target":"usr/bin/example"},{"path":"example.desktop","type":"file"}]}));
        let target = artifact(&format!("{image}/usr/bin/example"), Some(image));
        let mut desktop = artifact(&format!("{image}/example.desktop"), Some(image));
        desktop.facts.insert("linux.desktop-entry".into(), json!({"name":"Example"}));
        let check = |mut files: Vec<Artifact>| {
            files.sort_by(|a, b| a.path.cmp(&b.path));
            let mut out = Output::default();
            AppImage.analyze_tree(&Supplied { files }, &mut out);
            out
        };
        let out = check(vec![source.clone(), filesystem.clone(), target.clone(), desktop.clone()]);
        assert!(out.facts.iter().any(|fact| fact.key == "appimage.identity" && fact.value["name"] == "Example"));
        assert!(out.facts.iter().any(|fact| fact.key == "appimage.entry" && fact.value["status"] == "matched-supplied-declaration"));
        assert!(out.findings.iter().all(|finding| !finding.evidence.is_empty()));
        let mut partial = filesystem.clone();
        partial.facts.insert("engine.container-listing".into(), json!({"complete":false}));
        let out = check(vec![source.clone(), partial, target.clone(), desktop.clone()]);
        assert!(!out.facts.iter().any(|fact| fact.key == "appimage.identity"));
        assert!(out.facts.iter().any(|fact| fact.key == "appimage.entry" && fact.value["status"] == "unresolved"));
        let mut changed = target;
        changed.facts.insert("engine.entry-name".into(), json!({"colliding":true}));
        let out = check(vec![source, filesystem, changed, desktop]);
        assert!(out.facts.iter().any(|fact| fact.key == "appimage.entry" && fact.value["status"] == "unresolved"));
        assert!(out.facts.iter().all(|fact| fact.value.get("runtime_target_resolved").is_none_or(|value| value == &Value::Bool(false))));
    }
}
