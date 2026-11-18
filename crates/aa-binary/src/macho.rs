//! Mach-O, thin and universal: header, load commands, segments and sections, symbols, hardening.
//!
//! Code signatures, entitlements and FairPlay encryption belong to `aa-apple`; this module only
//! records where `LC_CODE_SIGNATURE` and `LC_ENCRYPTION_INFO` point.

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Section, Severity};
use serde_json::{Map, Value, json};

use crate::common::{
    Capped, EntropyBudget, MAX_LIBRARIES, MAX_SECTIONS, MAX_SYMBOLS, Marks, Problems, Rd, Symbol, finding, flag_names, hex, hx, sample,
    symbols_json, text,
};
use crate::lang::{self, Region};

/// Slices of a universal binary read at most. Real files have two to five.
const MAX_SLICES: u32 = 32;
/// Load commands read at most.
const MAX_COMMANDS: u32 = 16_384;

const MH_TWOLEVEL: u32 = 0x80;
const MH_ALLOW_STACK_EXECUTION: u32 = 0x2_0000;
const MH_PIE: u32 = 0x20_0000;
const MH_NO_HEAP_EXECUTION: u32 = 0x100_0000;

const FLAGS: &[(u64, &str)] = &[
    (0x1, "NOUNDEFS"),
    (0x2, "INCRLINK"),
    (0x4, "DYLDLINK"),
    (0x8, "BINDATLOAD"),
    (0x10, "PREBOUND"),
    (0x20, "SPLIT_SEGS"),
    (0x80, "TWOLEVEL"),
    (0x100, "FORCE_FLAT"),
    (0x200, "NOMULTIDEFS"),
    (0x800, "PREBINDABLE"),
    (0x2000, "SUBSECTIONS_VIA_SYMBOLS"),
    (0x8000, "WEAK_DEFINES"),
    (0x1_0000, "BINDS_TO_WEAK"),
    (0x2_0000, "ALLOW_STACK_EXECUTION"),
    (0x4_0000, "ROOT_SAFE"),
    (0x8_0000, "SETUID_SAFE"),
    (0x10_0000, "NO_REEXPORTED_DYLIBS"),
    (0x20_0000, "PIE"),
    (0x40_0000, "DEAD_STRIPPABLE_DYLIB"),
    (0x80_0000, "HAS_TLV_DESCRIPTORS"),
    (0x100_0000, "NO_HEAP_EXECUTION"),
    (0x200_0000, "APP_EXTENSION_SAFE"),
    (0x400_0000, "NLIST_OUTOFSYNC_WITH_DYLDINFO"),
    (0x800_0000, "SIM_SUPPORT"),
    (0x8000_0000, "DYLIB_IN_CACHE"),
];

fn command_name(cmd: u32) -> String {
    let name = match cmd {
        0x1 => "LC_SEGMENT",
        0x2 => "LC_SYMTAB",
        0x4 => "LC_THREAD",
        0x5 => "LC_UNIXTHREAD",
        0xb => "LC_DYSYMTAB",
        0xc => "LC_LOAD_DYLIB",
        0xd => "LC_ID_DYLIB",
        0xe => "LC_LOAD_DYLINKER",
        0xf => "LC_ID_DYLINKER",
        0x10 => "LC_PREBOUND_DYLIB",
        0x11 => "LC_ROUTINES",
        0x12 => "LC_SUB_FRAMEWORK",
        0x13 => "LC_SUB_UMBRELLA",
        0x14 => "LC_SUB_CLIENT",
        0x15 => "LC_SUB_LIBRARY",
        0x16 => "LC_TWOLEVEL_HINTS",
        0x17 => "LC_PREBIND_CKSUM",
        0x8000_0018 => "LC_LOAD_WEAK_DYLIB",
        0x19 => "LC_SEGMENT_64",
        0x1a => "LC_ROUTINES_64",
        0x1b => "LC_UUID",
        0x8000_001c => "LC_RPATH",
        0x1d => "LC_CODE_SIGNATURE",
        0x1e => "LC_SEGMENT_SPLIT_INFO",
        0x8000_001f => "LC_REEXPORT_DYLIB",
        0x20 => "LC_LAZY_LOAD_DYLIB",
        0x21 => "LC_ENCRYPTION_INFO",
        0x22 => "LC_DYLD_INFO",
        0x8000_0022 => "LC_DYLD_INFO_ONLY",
        0x8000_0023 => "LC_LOAD_UPWARD_DYLIB",
        0x24 => "LC_VERSION_MIN_MACOSX",
        0x25 => "LC_VERSION_MIN_IPHONEOS",
        0x26 => "LC_FUNCTION_STARTS",
        0x27 => "LC_DYLD_ENVIRONMENT",
        0x8000_0028 => "LC_MAIN",
        0x29 => "LC_DATA_IN_CODE",
        0x2a => "LC_SOURCE_VERSION",
        0x2b => "LC_DYLIB_CODE_SIGN_DRS",
        0x2c => "LC_ENCRYPTION_INFO_64",
        0x2d => "LC_LINKER_OPTION",
        0x2e => "LC_LINKER_OPTIMIZATION_HINT",
        0x2f => "LC_VERSION_MIN_TVOS",
        0x30 => "LC_VERSION_MIN_WATCHOS",
        0x31 => "LC_NOTE",
        0x32 => "LC_BUILD_VERSION",
        0x8000_0033 => "LC_DYLD_EXPORTS_TRIE",
        0x8000_0034 => "LC_DYLD_CHAINED_FIXUPS",
        0x8000_0035 => "LC_FILESET_ENTRY",
        0x36 => "LC_ATOM_INFO",
        other => return hx(u64::from(other)),
    };
    name.to_string()
}

/// The architecture name `lipo` and `file` use.
pub fn arch_name(cputype: u32, cpusubtype: u32) -> Option<&'static str> {
    let sub = cpusubtype & 0x00ff_ffff;
    Some(match (cputype, sub) {
        (7, _) => "i386",
        (0x0100_0007, 8) => "x86_64h",
        (0x0100_0007, _) => "x86_64",
        (12, 6) => "armv6",
        (12, 9) => "armv7",
        (12, 11) => "armv7s",
        (12, 12) => "armv7k",
        (12, _) => "arm",
        (0x0100_000c, 2) => "arm64e",
        (0x0100_000c, _) => "arm64",
        (0x0200_000c, _) => "arm64_32",
        (18, _) => "ppc",
        (0x0100_0012, _) => "ppc64",
        _ => return None,
    })
}

fn file_type_name(filetype: u32) -> Option<&'static str> {
    Some(match filetype {
        1 => "object",
        2 => "executable",
        3 => "fvmlib",
        4 => "core",
        5 => "preload",
        6 => "dylib",
        7 => "dylinker",
        8 => "bundle",
        9 => "dylib-stub",
        10 => "dsym",
        11 => "kext",
        12 => "fileset",
        _ => return None,
    })
}

fn platform_name(platform: u32) -> String {
    match platform {
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

/// `X.Y.Z` from the packed `xxxx.yy.zz` form.
pub fn version(packed: u32) -> String {
    let (major, minor, patch) = (packed >> 16, (packed >> 8) & 0xff, packed & 0xff);
    if patch == 0 { format!("{major}.{minor}") } else { format!("{major}.{minor}.{patch}") }
}

fn protection(bits: u32) -> String {
    [(1, 'r'), (2, 'w'), (4, 'x')].iter().map(|(bit, c)| if bits & bit != 0 { *c } else { '-' }).collect()
}

/// Thin Mach-O magic: `Some((little_endian, is_64_bit))`.
fn thin_magic(data: &[u8]) -> Option<(bool, bool)> {
    match data.get(..4)? {
        [0xfe, 0xed, 0xfa, 0xce] => Some((false, false)),
        [0xce, 0xfa, 0xed, 0xfe] => Some((true, false)),
        [0xfe, 0xed, 0xfa, 0xcf] => Some((false, true)),
        [0xcf, 0xfa, 0xed, 0xfe] => Some((true, true)),
        _ => None,
    }
}

/// The number of slices when `data` starts like a universal binary, and whether it is the 64-bit
/// variant. Java class files share the magic; their "slice count" is a class-file version of 45
/// or more, which is how `file` tells the two apart.
fn fat_magic(data: &[u8]) -> Option<(u32, bool)> {
    let rd = Rd::new(data, false);
    let wide = match rd.u32(0)? {
        0xcafe_babe => false,
        0xcafe_babf => true,
        _ => return None,
    };
    let count = rd.u32(4)?;
    (1..=MAX_SLICES).contains(&count).then_some((count, wide))
}

pub fn is_macho(data: &[u8]) -> bool {
    thin_magic(data).is_some() || fat_magic(data).is_some()
}

pub fn analyze(file: &Artifact, data: &[u8], out: &mut Output) {
    let mut problems = Problems::default();
    if thin_magic(data).is_some() {
        out.kind(file, "macho");
        match slice(file, data, 0, "", out, &mut problems) {
            Some(facts) => {
                for (key, value) in facts {
                    out.fact(file, &format!("binary.{key}"), value);
                }
            }
            None => problems.malformed("the Mach-O header is truncated or invalid; nothing else was read"),
        }
    } else if let Some((count, wide)) = fat_magic(data) {
        fat(file, data, count, wide, out, &mut problems);
    }
    problems.emit(file, out);
}

fn fat(file: &Artifact, data: &[u8], count: u32, wide: bool, out: &mut Output, problems: &mut Problems) {
    let rd = Rd::new(data, false);
    let entry_size: u64 = if wide { 32 } else { 20 };
    let mut entries = Vec::new();
    for i in 0..u64::from(count) {
        let at = 8 + i * entry_size;
        let (Some(cputype), Some(cpusubtype)) = (rd.u32(at), rd.u32(at + 4)) else { break };
        let fields = if wide {
            (rd.u64(at + 8), rd.u64(at + 16), rd.u32(at + 24))
        } else {
            (rd.word(at + 8, false), rd.word(at + 12, false), rd.u32(at + 16))
        };
        let (Some(offset), Some(size), Some(align)) = fields else { break };
        entries.push((cputype, cpusubtype, offset, size, align, at));
    }
    // A Java class file with a tiny version number could still pass the magic test; a universal
    // binary's first slice must lie inside the file and start with something recognisable.
    let plausible = entries.len() == count as usize
        && entries.iter().any(|(_, _, offset, size, _, _)| {
            rd.bytes(*offset, *size).is_some_and(|slice| thin_magic(slice).is_some() || slice.starts_with(b"!<arch>\n"))
        });
    if !plausible {
        return;
    }
    out.kind(file, "macho-fat");
    let arch_of = |cputype: u32, cpusubtype: u32| {
        arch_name(cputype, cpusubtype).map_or_else(|| format!("cpu {cputype}/{}", cpusubtype & 0x00ff_ffff), str::to_string)
    };
    let archs: Vec<String> = entries.iter().map(|(cputype, cpusubtype, ..)| arch_of(*cputype, *cpusubtype)).collect();
    out.finding(
        finding(Section::Identity, "binary.macho-fat", Confidence::Verified, Severity::Info)
            .param("count", count)
            .param("archs", archs.join(", "))
            .evidence(Evidence::bytes(file, 0, 8 + u64::from(count) * entry_size, archs.join(", "))),
    );
    let mut slices = Vec::new();
    for (cputype, cpusubtype, offset, size, align, _) in &entries {
        let arch = arch_of(*cputype, *cpusubtype);
        let mut value = Map::new();
        value.insert("arch".into(), arch.clone().into());
        value.insert("cputype".into(), (*cputype).into());
        value.insert("cpusubtype".into(), (*cpusubtype).into());
        value.insert("offset".into(), (*offset).into());
        value.insert("size".into(), (*size).into());
        value.insert("align".into(), (*align).into());
        let label = format!("[{arch}] ");
        let kind = match rd.bytes(*offset, *size) {
            None => {
                problems.malformed(format!("the {arch} slice extends past the end of the file and was not read"));
                "truncated"
            }
            Some(bytes) if bytes.starts_with(b"!<arch>\n") => "archive",
            Some(bytes) => match thin_magic(bytes).and_then(|_| slice(file, bytes, *offset, &label, out, problems)) {
                Some(facts) => {
                    for (key, fact) in facts {
                        value.insert(key.into(), fact);
                    }
                    "macho"
                }
                None => {
                    problems.malformed(format!("the {arch} slice is not a readable Mach-O file"));
                    "unknown"
                }
            },
        };
        value.insert("kind".into(), kind.into());
        slices.push(Value::Object(value));
    }
    out.fact(file, "binary.header", json!({ "format": "macho-fat", "fat64": wide, "slices": count, "archs": archs }));
    out.fact(file, "binary.slices", Value::Array(slices));
}

struct Segment {
    name: String,
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: u32,
    initprot: u32,
    flags: u32,
    nsects: u32,
    at: u64,
}

struct Dylib {
    name: String,
    kind: &'static str,
    current: u32,
    compatibility: u32,
}

/// Parses one thin Mach-O image (`data` is the whole image, `base` its offset in the file),
/// emits its findings, and returns its facts keyed without the `binary.` prefix.
fn slice(
    file: &Artifact,
    data: &[u8],
    base: u64,
    label: &str,
    out: &mut Output,
    problems: &mut Problems,
) -> Option<Vec<(&'static str, Value)>> {
    let (le, wide) = thin_magic(data)?;
    let rd = Rd::new(data, le);
    let cputype = rd.u32(4)?;
    let cpusubtype = rd.u32(8)?;
    let filetype = rd.u32(12)?;
    let ncmds = rd.u32(16)?;
    let sizeofcmds = u64::from(rd.u32(20)?);
    let flags = rd.u32(24)?;
    let header_size: u64 = if wide { 32 } else { 28 };
    let arch = arch_name(cputype, cpusubtype);
    let arch_text = arch.map_or_else(|| format!("cpu {cputype}/{}", cpusubtype & 0x00ff_ffff), str::to_string);

    let mut commands = Vec::new();
    let mut segments: Vec<Segment> = Vec::new();
    let mut section_values = Vec::new();
    let mut regions = Vec::new();
    let mut sections_total = 0u64;
    let mut dylibs: Vec<Dylib> = Vec::new();
    let mut rpaths = Vec::new();
    let mut install_name = None;
    let mut dylinker = None;
    let mut uuid: Option<(String, u64)> = None;
    let mut symtab = None;
    // The fact value, the command's offset, then platform, minimum OS and SDK as text.
    let mut min_os: Option<(Value, u64, String, String, String)> = None;
    // An SDK version of zero means the field was not filled in (usual in object files).
    let sdk_version = |sdk: u32| (sdk != 0).then(|| version(sdk));
    let sdk_text = |sdk: u32| sdk_version(sdk).unwrap_or_else(|| "not recorded".to_string());
    let mut tools = Vec::new();
    let mut code_signature = None;
    let mut encryption = None;
    let mut entry_offset = None;
    let mut entry_address = None;
    let mut source_version = None;
    let mut restrict = None;
    let mut dwarf = false;
    let mut high_entropy = Vec::new();
    let mut budget = EntropyBudget::new(rd.len());

    let commands_end = (header_size + sizeofcmds).min(rd.len());
    if header_size + sizeofcmds > rd.len() {
        problems.malformed(format!("{label}the load commands extend past the end of the file"));
    }
    let mut at = header_size;
    for index in 0..ncmds.min(MAX_COMMANDS) {
        let (Some(cmd), Some(cmdsize)) = (rd.u32(at), rd.u32(at + 4)) else {
            problems.malformed(format!("{label}load command {index} is cut off"));
            break;
        };
        let cmdsize = u64::from(cmdsize);
        if cmdsize < 8 || at + cmdsize > commands_end {
            problems
                .malformed(format!("{label}load command {index} has an invalid size ({cmdsize}); the remaining commands were not read"));
            break;
        }
        let end = at + cmdsize;
        commands.push(json!({ "cmd": command_name(cmd), "offset": at, "size": cmdsize }));
        // A string inside a command: a 32-bit offset from the command's start.
        let lc_str = |field: u64| rd.u32(at + field).map(u64::from).filter(|o| *o < cmdsize).and_then(|o| rd.cstr(at + o, end));
        match cmd {
            0x1 | 0x19 => {
                let big = cmd == 0x19;
                let name = text(rd.bytes(at + 8, 16).unwrap_or(&[]));
                let w = |n: u64| rd.word(at + 24 + n * if big { 8 } else { 4 }, big);
                let tail = at + if big { 56 } else { 40 };
                if let (
                    Some(vmaddr),
                    Some(vmsize),
                    Some(fileoff),
                    Some(filesize),
                    Some(maxprot),
                    Some(initprot),
                    Some(nsects),
                    Some(seg_flags),
                ) = (w(0), w(1), w(2), w(3), rd.u32(tail), rd.u32(tail + 4), rd.u32(tail + 8), rd.u32(tail + 12))
                {
                    let section_size: u64 = if big { 80 } else { 68 };
                    let first = tail + 16;
                    let fits = (end - first.min(end)) / section_size;
                    if u64::from(nsects) > fits {
                        problems
                            .malformed(format!("{label}segment {name} declares {nsects} sections but only {fits} fit in its load command"));
                    }
                    for i in 0..u64::from(nsects).min(fits) {
                        let s = first + i * section_size;
                        let section_name = text(rd.bytes(s, 16).unwrap_or(&[]));
                        let segment_name = text(rd.bytes(s + 16, 16).unwrap_or(&[]));
                        let fields = if big {
                            (rd.u64(s + 32), rd.u64(s + 40), rd.u32(s + 48), rd.u32(s + 64))
                        } else {
                            (rd.word(s + 32, false), rd.word(s + 36, false), rd.u32(s + 40), rd.u32(s + 56))
                        };
                        let (Some(address), Some(size), Some(offset), Some(section_flags)) = fields else { break };
                        sections_total += 1;
                        // Zero-fill sections occupy memory only.
                        let stored = !matches!(section_flags & 0xff, 0x1 | 0xc | 0x12) && offset != 0;
                        let entropy = if stored { budget.of(&rd, u64::from(offset), size) } else { None };
                        if stored {
                            regions.push(Region { name: section_name.clone(), offset: u64::from(offset), size });
                        }
                        dwarf |= segment_name == "__DWARF";
                        if segment_name == "__RESTRICT" && section_name == "__restrict" {
                            restrict = Some(s);
                        }
                        if let Some(e) = entropy
                            && e >= 7.2
                            && section_flags & 0x8000_0400 != 0
                            && size >= 4096
                        {
                            high_entropy.push((format!("{segment_name},{section_name}"), e, u64::from(offset), size));
                        }
                        if section_values.len() < MAX_SECTIONS {
                            section_values.push(json!({
                                "name": section_name,
                                "segment": segment_name,
                                "address": address,
                                "offset": offset,
                                "size": size,
                                "flags": section_flags,
                                "entropy": entropy,
                            }));
                        }
                    }
                    segments.push(Segment { name, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, flags: seg_flags, nsects, at });
                }
            }
            0x2 => symtab = (|| Some((rd.u32(at + 8)?, rd.u32(at + 12)?, rd.u32(at + 16)?, rd.u32(at + 20)?)))(),
            0xc | 0x8000_0018 | 0x8000_001f | 0x20 | 0x8000_0023 => {
                let kind = match cmd {
                    0xc => "load",
                    0x8000_0018 => "weak",
                    0x8000_001f => "reexport",
                    0x20 => "lazy",
                    _ => "upward",
                };
                // Symbols refer to libraries by their position among these commands, so a
                // library whose name cannot be read still takes a place.
                dylibs.push(Dylib {
                    name: lc_str(8).unwrap_or_default(),
                    kind,
                    current: rd.u32(at + 16).unwrap_or(0),
                    compatibility: rd.u32(at + 20).unwrap_or(0),
                });
            }
            0xd => install_name = lc_str(8),
            0xe => dylinker = lc_str(8),
            0x8000_001c if rpaths.len() < MAX_LIBRARIES => rpaths.extend(lc_str(8)),
            0x1b => {
                if let Some(bytes) = rd.bytes(at + 8, 16).filter(|_| cmdsize >= 24) {
                    let h = hex(bytes).to_uppercase();
                    uuid = Some((format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..]), at + 8));
                }
            }
            0x1d => code_signature = rd.u32(at + 8).zip(rd.u32(at + 12)),
            0x21 | 0x2c => encryption = (|| Some((rd.u32(at + 8)?, rd.u32(at + 12)?, rd.u32(at + 16)?)))(),
            0x24 | 0x25 | 0x2f | 0x30 => {
                let platform = match cmd {
                    0x24 => "macOS",
                    0x25 => "iOS",
                    0x2f => "tvOS",
                    _ => "watchOS",
                };
                if let (Some(minimum), Some(sdk)) = (rd.u32(at + 8), rd.u32(at + 12)) {
                    let source = command_name(cmd);
                    // LC_BUILD_VERSION is the newer record; keep it if both are present.
                    min_os.get_or_insert((
                        json!({ "platform": platform, "minos": version(minimum), "sdk": sdk_version(sdk), "source": source }),
                        at,
                        platform.to_string(),
                        version(minimum),
                        sdk_text(sdk),
                    ));
                }
            }
            0x32 => {
                if let (Some(platform), Some(minimum), Some(sdk), Some(ntools)) =
                    (rd.u32(at + 8), rd.u32(at + 12), rd.u32(at + 16), rd.u32(at + 20))
                {
                    let platform = platform_name(platform);
                    min_os = Some((
                        json!({ "platform": platform, "minos": version(minimum), "sdk": sdk_version(sdk), "source": "LC_BUILD_VERSION" }),
                        at,
                        platform,
                        version(minimum),
                        sdk_text(sdk),
                    ));
                    for i in 0..u64::from(ntools).min(cmdsize.saturating_sub(24) / 8) {
                        if let (Some(tool), Some(tool_version)) = (rd.u32(at + 24 + i * 8), rd.u32(at + 28 + i * 8)) {
                            let name = match tool {
                                1 => "clang".to_string(),
                                2 => "swift".to_string(),
                                3 => "ld".to_string(),
                                4 => "lld".to_string(),
                                other => format!("tool {other}"),
                            };
                            tools.push((name, version(tool_version), at + 24 + i * 8));
                        }
                    }
                }
            }
            0x8000_0028 => entry_offset = rd.u64(at + 8),
            0x5 => {
                // The entry point is the program counter in the initial thread state.
                let pc = match (cputype, rd.u32(at + 8)) {
                    (0x0100_0007, Some(4)) => rd.u64(at + 16 + 16 * 8),
                    (0x0100_000c, Some(6)) => rd.u64(at + 16 + 32 * 8),
                    (7, Some(1)) => rd.word(at + 16 + 10 * 4, false),
                    (12, Some(1)) => rd.word(at + 16 + 15 * 4, false),
                    _ => None,
                };
                entry_address = pc.filter(|_| cmdsize >= 16);
            }
            0x2a => {
                source_version = rd
                    .u64(at + 8)
                    .map(|v| format!("{}.{}.{}.{}.{}", v >> 40, (v >> 30) & 0x3ff, (v >> 20) & 0x3ff, (v >> 10) & 0x3ff, v & 0x3ff))
            }
            _ => {}
        }
        at = end;
    }
    if ncmds > MAX_COMMANDS {
        problems.malformed(format!("{label}the header declares {ncmds} load commands; only the first {MAX_COMMANDS} were read"));
    }
    if entry_address.is_none()
        && let Some(offset) = entry_offset
    {
        entry_address = segments.iter().find(|s| s.name == "__TEXT").and_then(|s| s.vmaddr.checked_add(offset));
    }

    // Symbols.
    let mut marks = Marks::default();
    let mut imports = Capped::new(MAX_SYMBOLS);
    let mut exports = Capped::new(MAX_SYMBOLS);
    let mut symbols_read = None;
    let (mut locals, mut stabs) = (0u64, 0u64);
    let entry_size: u64 = if wide { 16 } else { 12 };
    if let Some((symoff, nsyms, stroff, strsize)) = symtab {
        let (symoff, nsyms, stroff, strsize) = (u64::from(symoff), u64::from(nsyms), u64::from(stroff), u64::from(strsize));
        let fits = rd.len().saturating_sub(symoff) / entry_size;
        if nsyms > fits {
            problems.malformed(format!("{label}the symbol table declares {nsyms} symbols but only {fits} fit in the file"));
        }
        if stroff + strsize > rd.len() {
            problems.malformed(format!("{label}the string table extends past the end of the file"));
        }
        let mut read = 0u64;
        for i in 0..nsyms.min(fits) {
            let s = symoff + i * entry_size;
            let (Some(strx), Some(n_type), Some(n_desc), Some(value)) = (rd.u32(s), rd.u8(s + 4), rd.u16(s + 6), rd.word(s + 8, wide))
            else {
                break;
            };
            read += 1;
            if n_type & 0xe0 != 0 {
                // Source files, object files and functions: what a debugger reads. Apple's
                // `strip` leaves one marker entry of another type behind, which is not counted.
                if matches!(n_type, 0x24 | 0x64 | 0x66) {
                    stabs += 1;
                }
                continue;
            }
            let (kind, external, private) = (n_type & 0x0e, n_type & 1 != 0, n_type & 0x10 != 0);
            if !external {
                locals += 1;
            }
            let strx = u64::from(strx);
            if strx == 0 || strx >= strsize {
                continue;
            }
            let Some(name) = rd.cstr(stroff + strx, stroff + strsize).filter(|n| !n.is_empty()) else { continue };
            let undefined = kind == 0 && external;
            marks.see(&name, 1, undefined, s);
            if undefined {
                let mut symbol = Symbol::new(name).with("weak", n_desc & 0x40 != 0);
                if flags & MH_TWOLEVEL != 0 {
                    symbol.library = match usize::from(n_desc >> 8) {
                        0 => None,
                        0xfe => Some("(dynamic lookup)".into()),
                        0xff => Some("(main executable)".into()),
                        ordinal => dylibs.get(ordinal - 1).map(|d| d.name.clone()),
                    };
                }
                imports.push(symbol);
            } else if external && !private && matches!(kind, 0x2 | 0xa | 0xe) {
                exports.push(Symbol::new(name).with("address", value));
            }
        }
        symbols_read = Some(read);
    }
    // `strip` removes local symbols and debug entries; what dyld needs (imports, exports) stays.
    let local_symbols = symbols_read.map(|_| locals);
    let stripped = locals == 0 && stabs == 0;

    let library_names: Vec<String> = dylibs.iter().map(|d| d.name.clone()).collect();
    let toolchain = lang::detect(&rd, &marks, &library_names, &regions, &[]);
    let go_build_id = if toolchain.has("Go") { lang::go_build_id(data) } else { None };
    let file_type = file_type_name(filetype);
    let file_type_text = file_type.map_or_else(|| format!("file type {filetype}"), str::to_string);
    let bits = if wide { 64 } else { 32 };

    // Findings: identity.
    out.finding(
        finding(Section::Identity, "binary.macho-identity", Confidence::Verified, Severity::Info)
            .param("label", label)
            .param("bits", bits)
            .param("arch", arch_text.as_str())
            .param("file_type", file_type_text.as_str())
            .evidence(Evidence::bytes(file, base, header_size, hex(rd.bytes(0, header_size).unwrap_or(&[])))),
    );
    if let Some((_, at, platform, minimum, sdk)) = &min_os {
        out.finding(
            finding(Section::Identity, "binary.macho-min-os", Confidence::Verified, Severity::Info)
                .param("label", label)
                .param("platform", platform.as_str())
                .param("minos", minimum.as_str())
                .param("sdk", sdk.as_str())
                .evidence(Evidence::bytes(file, base + at, 24, format!("{platform} {minimum}, SDK {sdk}"))),
        );
    }
    if let Some((id, at)) = &uuid {
        out.finding(
            finding(Section::Identity, "binary.build-id", Confidence::Verified, Severity::Info)
                .param("label", label)
                .param("kind", "Mach-O UUID")
                .param("id", id.as_str())
                .evidence(Evidence::bytes(file, base + at, 16, id.as_str())),
        );
    }

    // Composition.
    if !dylibs.is_empty() {
        let mut f = finding(Section::Composition, "binary.libraries", Confidence::Verified, Severity::Info)
            .param("label", label)
            .param("count", dylibs.len())
            .param("sample", sample(&library_names, 8));
        for name in library_names.iter().take(8) {
            f = f.evidence(Evidence::field(file, format!("{label}LC_LOAD_DYLIB"), name.as_str()));
        }
        out.finding(f);
    }
    toolchain.emit(file, base, label, out);
    if let Some((_, _, at)) = tools.first() {
        let list = tools.iter().map(|(name, v, _)| format!("{name} {v}")).collect::<Vec<_>>().join(", ");
        out.finding(
            finding(Section::Composition, "binary.macho-build-tools", Confidence::Verified, Severity::Info)
                .param("label", label)
                .param("tools", list.as_str())
                .evidence(Evidence::bytes(file, base + at, 8 * tools.len() as u64, list.as_str())),
        );
    }
    for (name, e, offset, size) in high_entropy.iter().take(4) {
        out.finding(
            finding(Section::Anomalies, "binary.code-high-entropy", Confidence::Heuristic, Severity::Low)
                .param("name", format!("{label}{name}"))
                .param("entropy", *e)
                .evidence(Evidence::bytes(file, base + offset, *size, *e)),
        );
    }

    // Code.
    if symbols_read.is_some() {
        crate::emit_symbols(file, out, Some(stripped), Some(locals + stabs), Some((imports.total, exports.total)), label);
    } else {
        problems.undetermined(format!("{label}the file has no symbol table (LC_SYMTAB); imports and exports were not read"));
    }
    if dwarf || stabs > 0 {
        let what = if dwarf {
            "DWARF sections (__DWARF segment)".to_string()
        } else {
            format!("{stabs} debug symbol table entries (a debug map naming source and object files)")
        };
        out.finding(
            finding(Section::Code, "binary.debug-info", Confidence::Verified, Severity::Info)
                .param("label", label)
                .param("what", what.as_str())
                .evidence(Evidence::field(file, format!("{label}symbol table"), what.as_str())),
        );
    }

    // Hardening, for images that are loaded and run.
    let mut hardening = Map::new();
    if matches!(filetype, 2 | 6 | 8 | 11) {
        let flags_evidence = || Evidence::bytes(file, base + 24, 4, format!("flags = {}", hx(u64::from(flags))));
        let hard = |rule: &str, confidence, severity| finding(Section::Hardening, rule, confidence, severity).param("label", label);
        if filetype == 2 {
            let pie = flags & MH_PIE != 0;
            hardening.insert("pie".into(), pie.into());
            let (rule, severity) = if pie { ("binary.macho-pie", Severity::Info) } else { ("binary.macho-no-pie", Severity::Medium) };
            out.finding(hard(rule, Confidence::Verified, severity).evidence(flags_evidence()));

            let stack_exec = flags & MH_ALLOW_STACK_EXECUTION != 0;
            hardening.insert("nx_stack".into(), (!stack_exec).into());
            let (rule, severity) =
                if stack_exec { ("binary.macho-stack-exec", Severity::Medium) } else { ("binary.macho-nx-stack", Severity::Info) };
            out.finding(hard(rule, Confidence::Verified, severity).evidence(flags_evidence()));

            let heap_flag = flags & MH_NO_HEAP_EXECUTION != 0;
            hardening.insert("nx_heap_flag".into(), heap_flag.into());
            if heap_flag {
                out.finding(hard("binary.macho-nx-heap", Confidence::Verified, Severity::Info).evidence(flags_evidence()));
            } else if cputype == 7 {
                // Only 32-bit x86 has an executable heap unless the flag forbids it.
                out.finding(hard("binary.macho-no-nx-heap", Confidence::Verified, Severity::Low).evidence(flags_evidence()));
            }
        } else {
            hardening.insert("pie".into(), Value::Null);
        }

        let unsafe_code = toolchain.has("C++") || toolchain.has("Objective-C");
        let safe_language = ["Go", "Rust", "Swift"].into_iter().find(|l| toolchain.has(l)).filter(|_| !unsafe_code);
        match (&marks.canary, symbols_read) {
            (Some((symbol, at)), _) => {
                hardening.insert("canary".into(), true.into());
                out.finding(
                    hard("binary.canary", Confidence::Derived, Severity::Info).param("symbol", symbol.as_str()).evidence(Evidence::bytes(
                        file,
                        base + at,
                        entry_size,
                        symbol.as_str(),
                    )),
                );
            }
            (None, None) => {
                hardening.insert("canary".into(), Value::Null);
            }
            (None, Some(_)) => {
                hardening.insert("canary".into(), false.into());
                let evidence = Evidence::field(file, format!("{label}symbol table"), "___stack_chk_fail not referenced");
                match safe_language {
                    Some(language) => out.finding(
                        hard("binary.no-canary-safe-language", Confidence::Heuristic, Severity::Info)
                            .param("language", language)
                            .evidence(evidence),
                    ),
                    None => out.finding(hard("binary.no-canary", Confidence::Heuristic, Severity::Low).evidence(evidence)),
                }
            }
        }

        // ARC matters only where there is Objective-C code to manage.
        if toolchain.has("Objective-C") && symbols_read.is_some() {
            match &marks.arc {
                Some((symbol, at)) => {
                    hardening.insert("arc".into(), true.into());
                    out.finding(
                        hard("binary.macho-arc", Confidence::Derived, Severity::Info)
                            .param("symbol", symbol.as_str())
                            .evidence(Evidence::bytes(file, base + at, entry_size, symbol.as_str())),
                    );
                }
                None => {
                    hardening.insert("arc".into(), false.into());
                    out.finding(hard("binary.macho-no-arc", Confidence::Heuristic, Severity::Low).evidence(Evidence::field(
                        file,
                        format!("{label}symbol table"),
                        "_objc_release not referenced",
                    )));
                }
            }
        } else {
            hardening.insert("arc".into(), Value::Null);
        }

        hardening.insert("restrict_segment".into(), restrict.is_some().into());
        if let Some(at) = restrict {
            out.finding(hard("binary.macho-restrict", Confidence::Verified, Severity::Info).evidence(Evidence::bytes(
                file,
                base + at,
                32,
                "__RESTRICT,__restrict",
            )));
        }

        let wx: Vec<&Segment> = segments.iter().filter(|s| s.initprot & 6 == 6).collect();
        hardening.insert("writable_executable".into(), (!wx.is_empty()).into());
        for segment in wx.iter().take(4) {
            out.finding(
                finding(Section::Hardening, "binary.writable-executable", Confidence::Verified, Severity::Medium)
                    .param("what", format!("{label}segment {}", segment.name))
                    .evidence(Evidence::bytes(file, base + segment.at, 8, protection(segment.initprot))),
            );
        }
    }

    // Facts.
    let segment_values: Vec<Value> = segments
        .iter()
        .map(|s| {
            json!({
                "name": s.name,
                "vmaddr": s.vmaddr,
                "vmsize": s.vmsize,
                "fileoff": s.fileoff,
                "filesize": s.filesize,
                "maxprot": protection(s.maxprot),
                "initprot": protection(s.initprot),
                "flags": s.flags,
                "nsects": s.nsects,
            })
        })
        .collect();
    let library_values: Vec<Value> = dylibs
        .iter()
        .take(MAX_LIBRARIES)
        .map(|d| json!({ "name": d.name, "kind": d.kind, "current_version": version(d.current), "compatibility_version": version(d.compatibility) }))
        .collect();
    let mut toolchain_value = toolchain.to_json();
    toolchain_value["build_tools"] = tools.iter().map(|(name, v, _)| json!({ "tool": name, "version": v })).collect::<Vec<_>>().into();
    let debug_kinds: Vec<&str> = [dwarf.then_some("dwarf"), (stabs > 0).then_some("stabs")].into_iter().flatten().collect();
    let mut facts = vec![
        (
            "header",
            json!({
                "format": "macho",
                "arch": arch,
                "cputype": cputype,
                "cpusubtype": cpusubtype,
                "bits": bits,
                "endian": if le { "little" } else { "big" },
                "file_type": file_type,
                "filetype_raw": filetype,
                "flags": flag_names(u64::from(flags), FLAGS),
                "flags_raw": flags,
                "entry": entry_address,
                "entry_offset": entry_offset,
                "uuid": uuid.as_ref().map(|(id, _)| id),
                "min_os": min_os.as_ref().map(|(value, ..)| value),
                "source_version": source_version,
                "go_build_id": go_build_id.as_ref().map(|(id, _)| id),
            }),
        ),
        (
            "macho",
            json!({
                "load_commands": commands,
                "code_signature": code_signature.map(|(offset, size)| json!({ "offset": offset, "size": size })),
                "encryption": encryption.map(|(offset, size, id)| json!({ "offset": offset, "size": size, "cryptid": id })),
            }),
        ),
        ("sections", json!({ "sections": section_values, "total": sections_total, "truncated": sections_total > MAX_SECTIONS as u64 })),
        ("segments", json!({ "segments": segment_values, "truncated": false })),
        ("libraries", json!({ "libraries": library_values, "truncated": dylibs.len() > MAX_LIBRARIES })),
        ("linking", json!({ "install_name": install_name, "dylinker": dylinker, "rpaths": rpaths })),
        ("symbols", json!({ "stripped": stripped, "symbols": symbols_read, "local": local_symbols, "debug_entries": stabs })),
        (
            "debug",
            json!({
                "has_debug_info": dwarf || stabs > 0,
                "kinds": debug_kinds,
            }),
        ),
        ("toolchain", toolchain_value),
        ("hardening", Value::Object(hardening)),
    ];
    if symbols_read.is_some() {
        facts.push(("imports", symbols_json(imports, true)));
        facts.push(("exports", symbols_json(exports, false)));
    }
    Some(facts)
}
