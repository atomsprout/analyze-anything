//! The parts of Mach-O this crate needs: the slices of a universal binary, and from each
//! slice's load commands the code signature, the encryption info, segments and build versions.

use crate::util::{be32, slice, u32_at, u64_at};

const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
const MAX_SLICES: u32 = 32;
const MAX_COMMANDS: u32 = 65536;

const LC_SEGMENT: u32 = 0x1;
const LC_SEGMENT_64: u32 = 0x19;
const LC_CODE_SIGNATURE: u32 = 0x1d;
const LC_ENCRYPTION_INFO: u32 = 0x21;
const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
const LC_LOAD_DYLIB: u32 = 0xc;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_VERSION_MIN_MACOSX: u32 = 0x24;
const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
const LC_VERSION_MIN_TVOS: u32 = 0x2f;
const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
const LC_BUILD_VERSION: u32 = 0x32;

/// One architecture of a file: the whole file for a thin binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slice {
    pub offset: usize,
    pub size: usize,
}

fn thin_magic(bytes: &[u8]) -> Option<(bool, bool)> {
    // (64-bit, big-endian)
    match be32(bytes, 0)? {
        0xfeed_face => Some((false, true)),
        0xfeed_facf => Some((true, true)),
        0xcefa_edfe => Some((false, false)),
        0xcffa_edfe => Some((true, false)),
        _ => None,
    }
}

/// The Mach-O slices of `bytes`; `None` when it is not a Mach-O file at all.
pub fn slices(bytes: &[u8]) -> Option<Vec<Slice>> {
    if thin_magic(bytes).is_some() {
        return Some(vec![Slice { offset: 0, size: bytes.len() }]);
    }
    let magic = be32(bytes, 0)?;
    if magic != FAT_MAGIC && magic != FAT_MAGIC_64 {
        return None;
    }
    // Java class files share the magic; their "count" is a version number of 45 or more,
    // and their "slices" do not point at Mach-O headers.
    let count = be32(bytes, 4)?;
    if count == 0 || count > MAX_SLICES {
        return None;
    }
    let mut slices = Vec::new();
    for index in 0..count as usize {
        let (offset, size) = if magic == FAT_MAGIC {
            let entry = 8 + index * 20;
            (be32(bytes, entry + 8)? as u64, be32(bytes, entry + 12)? as u64)
        } else {
            let entry = 8 + index * 32;
            (crate::util::be64(bytes, entry + 8)?, crate::util::be64(bytes, entry + 16)?)
        };
        let (offset, size) = (usize::try_from(offset).ok()?, usize::try_from(size).ok()?);
        let part = slice(bytes, offset, size)?;
        thin_magic(part)?;
        slices.push(Slice { offset, size });
    }
    Some(slices)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub name: String,
    pub file_offset: u64,
    pub file_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Encryption {
    /// Offset of the load command in the slice.
    pub command_offset: usize,
    pub offset: u32,
    pub size: u32,
    /// Zero when the range is not encrypted (any more).
    pub id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub segment: String,
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MachO {
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub file_type: u32,
    pub segments: Vec<Segment>,
    /// The `__TEXT,__info_plist` section, when the binary embeds one.
    pub info_plist: Option<Section>,
    /// `(offset, size)` of the signature in the slice, and the offset of the load command.
    pub code_signature: Option<(u32, u32, usize)>,
    pub encryption: Option<Encryption>,
    pub libraries: Vec<String>,
    /// `(platform, minimum OS, SDK)` from the build-version or version-min command.
    pub build: Option<(String, String, Option<String>)>,
}

impl MachO {
    /// The architecture's usual name.
    pub fn arch(&self) -> String {
        let subtype = self.cpu_subtype & 0x00ff_ffff;
        match (self.cpu_type, subtype) {
            (7, _) => "i386".into(),
            (0x0100_0007, 8) => "x86_64h".into(),
            (0x0100_0007, _) => "x86_64".into(),
            (12, 9) => "armv7".into(),
            (12, 11) => "armv7s".into(),
            (12, 12) => "armv7k".into(),
            (12, _) => "arm".into(),
            (0x0100_000c, 2) => "arm64e".into(),
            (0x0100_000c, _) => "arm64".into(),
            (0x0200_000c, _) => "arm64_32".into(),
            (18, _) => "ppc".into(),
            (0x0100_0012, _) => "ppc64".into(),
            (other, _) => format!("cpu-{other:#x}"),
        }
    }

    /// What the file is, from the header's file type.
    pub fn file_kind(&self) -> &'static str {
        match self.file_type {
            1 => "object",
            2 => "executable",
            6 => "dylib",
            7 => "dylinker",
            8 => "bundle",
            10 => "dsym",
            11 => "kext",
            _ => "other",
        }
    }
}

fn version(packed: u32) -> String {
    let (major, minor, patch) = (packed >> 16, (packed >> 8) & 0xff, packed & 0xff);
    if patch == 0 { format!("{major}.{minor}") } else { format!("{major}.{minor}.{patch}") }
}

fn platform(id: u32) -> String {
    match id {
        1 => "macOS".into(),
        2 => "iOS".into(),
        3 => "tvOS".into(),
        4 => "watchOS".into(),
        5 => "bridgeOS".into(),
        6 => "Mac Catalyst".into(),
        7 => "iOS Simulator".into(),
        8 => "tvOS Simulator".into(),
        9 => "watchOS Simulator".into(),
        10 => "DriverKit".into(),
        11 => "visionOS".into(),
        12 => "visionOS Simulator".into(),
        other => format!("platform {other}"),
    }
}

/// Parses the header and load commands of one slice.
pub fn parse(bytes: &[u8]) -> Result<MachO, String> {
    let (wide, big) = thin_magic(bytes).ok_or("not a Mach-O header")?;
    let short = || "the Mach-O header is truncated".to_string();
    let word = |offset: usize| u32_at(bytes, offset, big);
    let mut macho = MachO {
        cpu_type: word(4).ok_or_else(short)?,
        cpu_subtype: word(8).ok_or_else(short)?,
        file_type: word(12).ok_or_else(short)?,
        ..MachO::default()
    };
    let commands = word(16).ok_or_else(short)?;
    let commands_size = word(20).ok_or_else(short)? as usize;
    let start: usize = if wide { 32 } else { 28 };
    let end = start.checked_add(commands_size).filter(|end| *end <= bytes.len()).ok_or("the load commands run past the end of the file")?;
    if commands > MAX_COMMANDS {
        return Err(format!("the header claims {commands} load commands"));
    }
    let mut at = start;
    for index in 0..commands {
        let bad = || format!("load command {index} is malformed");
        let command = word(at).ok_or_else(bad)?;
        let size = word(at + 4).ok_or_else(bad)? as usize;
        if size < 8 || at.checked_add(size).is_none_or(|next| next > end) {
            return Err(bad());
        }
        let body = &bytes[at..at + size];
        let field = |offset: usize| u32_at(body, offset, big);
        match command {
            LC_SEGMENT | LC_SEGMENT_64 => {
                let name = crate::util::c_string(slice(body, 8, 16).ok_or_else(bad)?);
                let (file_offset, file_size, sections, section_size, first) = if command == LC_SEGMENT_64 {
                    (u64_at(body, 40, big).ok_or_else(bad)?, u64_at(body, 48, big).ok_or_else(bad)?, field(64).ok_or_else(bad)?, 80, 72)
                } else {
                    (field(32).ok_or_else(bad)? as u64, field(36).ok_or_else(bad)? as u64, field(48).ok_or_else(bad)?, 68, 56)
                };
                if name == "__TEXT" {
                    for section in 0..(sections as usize).min(256) {
                        let base = first + section * section_size;
                        let Some(section_name) = slice(body, base, 16).map(crate::util::c_string) else { break };
                        if section_name == "__info_plist" {
                            let (offset, size) = if command == LC_SEGMENT_64 {
                                (field(base + 48).map(u64::from), u64_at(body, base + 40, big))
                            } else {
                                (field(base + 40).map(u64::from), field(base + 36).map(u64::from))
                            };
                            if let (Some(offset), Some(size)) = (offset, size) {
                                macho.info_plist = Some(Section { segment: name.clone(), name: section_name, offset, size });
                            }
                        }
                    }
                }
                macho.segments.push(Segment { name, file_offset, file_size });
            }
            LC_CODE_SIGNATURE => {
                macho.code_signature = Some((field(8).ok_or_else(bad)?, field(12).ok_or_else(bad)?, at));
            }
            LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
                macho.encryption = Some(Encryption {
                    command_offset: at,
                    offset: field(8).ok_or_else(bad)?,
                    size: field(12).ok_or_else(bad)?,
                    id: field(16).ok_or_else(bad)?,
                });
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB => {
                if let Some(name) = field(8).and_then(|offset| body.get(offset as usize..))
                    && macho.libraries.len() < 4096
                {
                    macho.libraries.push(crate::util::c_string(name));
                }
            }
            LC_BUILD_VERSION => {
                if let (Some(id), Some(minimum), Some(sdk)) = (field(8), field(12), field(16)) {
                    macho.build = Some((platform(id), version(minimum), Some(version(sdk))));
                }
            }
            LC_VERSION_MIN_MACOSX | LC_VERSION_MIN_IPHONEOS | LC_VERSION_MIN_TVOS | LC_VERSION_MIN_WATCHOS if macho.build.is_none() => {
                let id = match command {
                    LC_VERSION_MIN_MACOSX => 1,
                    LC_VERSION_MIN_IPHONEOS => 2,
                    LC_VERSION_MIN_TVOS => 3,
                    _ => 4,
                };
                if let (Some(minimum), Some(sdk)) = (field(8), field(12)) {
                    macho.build = Some((platform(id), version(minimum), (sdk != 0).then(|| version(sdk))));
                }
            }
            _ => {}
        }
        at += size;
    }
    Ok(macho)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A minimal little-endian 64-bit Mach-O: one `__TEXT` segment, an encryption command and
    /// a code-signature command pointing at `signature` appended after `code`.
    pub fn build(code: &[u8], signature: &[u8], crypt_id: u32) -> Vec<u8> {
        let mut commands = Vec::new();
        let mut segment = vec![0u8; 72];
        segment[..4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        segment[4..8].copy_from_slice(&72u32.to_le_bytes());
        segment[8..14].copy_from_slice(b"__TEXT");
        commands.extend(segment);
        let header_and_commands = 32 + 72 + 24 + 16;
        let code_at = header_and_commands;
        for value in [LC_ENCRYPTION_INFO_64, 24, code_at as u32, code.len() as u32, crypt_id, 0] {
            commands.extend(value.to_le_bytes());
        }
        for value in [LC_CODE_SIGNATURE, 16, (code_at + code.len()) as u32, signature.len() as u32] {
            commands.extend(value.to_le_bytes());
        }
        let mut out = Vec::new();
        for value in [0xfeed_facfu32, 0x0100_000c, 0, 2, 3, commands.len() as u32, 0, 0] {
            out.extend(value.to_le_bytes());
        }
        out.extend(commands);
        out.extend_from_slice(code);
        out.extend_from_slice(signature);
        out
    }

    #[test]
    fn parses_commands() {
        let file = build(&[0x90; 64], b"SIGNATURE", 1);
        let parsed = parse(&file).expect("valid");
        assert_eq!(parsed.arch(), "arm64");
        assert_eq!(parsed.file_kind(), "executable");
        assert_eq!(parsed.segments[0].name, "__TEXT");
        assert_eq!(parsed.encryption.map(|e| (e.offset, e.size, e.id)), Some((144, 64, 1)));
        assert_eq!(parsed.code_signature.map(|s| (s.0, s.1)), Some((208, 9)));
        assert_eq!(slices(&file), Some(vec![Slice { offset: 0, size: file.len() }]));
    }

    #[test]
    fn malformed_headers_do_not_panic() {
        let file = build(&[0; 16], b"", 0);
        for cut in 0..file.len() {
            let _ = parse(&file[..cut]);
            let _ = slices(&file[..cut]);
        }
        let mut huge = file.clone();
        huge[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse(&huge).is_err());
        let mut zero_size = file.clone();
        zero_size[36..40].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse(&zero_size).is_err());
        let mut long_command = file;
        long_command[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse(&long_command).is_err());
    }

    #[test]
    fn fat_headers() {
        let thin = build(&[0; 8], b"", 0);
        let mut fat = Vec::new();
        for value in [FAT_MAGIC, 1, 0x0100_000c, 0, 4096, thin.len() as u32, 12] {
            fat.extend(value.to_be_bytes());
        }
        fat.resize(4096, 0);
        fat.extend_from_slice(&thin);
        assert_eq!(slices(&fat), Some(vec![Slice { offset: 4096, size: thin.len() }]));
        // A Java class file: same magic, version 52 where the slice count would be.
        let class = [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 0, 10, 0, 3];
        assert_eq!(slices(&class), None);
        // A slice outside the file.
        let mut outside = fat.clone();
        outside[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(slices(&outside), None);
        assert_eq!(slices(b"plain text"), None);
    }
}
