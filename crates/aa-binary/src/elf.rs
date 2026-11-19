//! ELF: header, program and section headers, dynamic section, symbols, notes, hardening.

use std::collections::BTreeSet;

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Section, Severity};
use serde_json::{Value, json};

use crate::common::{
    Capped, EntropyBudget, MAX_LIBRARIES, MAX_SECTIONS, MAX_SYMBOLS, Marks, Problems, Rd, Symbol, finding, flag_names, hex, hx, sample,
    symbols_json, text,
};
use crate::lang::{self, Region};

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;

const SHT_SYMTAB: u32 = 2;
const SHT_NOTE: u32 = 7;
const SHT_NOBITS: u32 = 8;
const SHT_DYNSYM: u32 = 11;

const DT_NEEDED: u64 = 1;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_STRSZ: u64 = 10;
const DT_SONAME: u64 = 14;
const DT_RPATH: u64 = 15;
const DT_BIND_NOW: u64 = 24;
const DT_RUNPATH: u64 = 29;
const DT_FLAGS: u64 = 30;
const DT_FLAGS_1: u64 = 0x6fff_fffb;
const DF_BIND_NOW: u64 = 0x8;
const DF_1_NOW: u64 = 0x1;
const DF_1_PIE: u64 = 0x0800_0000;

/// Dynamic entries read at most; real files have a few dozen.
const MAX_DYNAMIC: u64 = 65_536;
/// Notes read at most.
const MAX_NOTES: usize = 256;

struct Segment {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
    /// Where the program header itself is in the file.
    at: u64,
}

struct SectionHeader {
    name: String,
    kind: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

fn machine_name(machine: u16) -> Option<&'static str> {
    Some(match machine {
        2 => "sparc",
        3 => "i386",
        8 => "mips",
        20 => "powerpc",
        21 => "powerpc64",
        22 => "s390x",
        40 => "arm",
        43 => "sparc64",
        50 => "ia64",
        62 => "x86_64",
        183 => "aarch64",
        243 => "riscv",
        247 => "bpf",
        258 => "loongarch",
        _ => return None,
    })
}

fn os_abi_name(abi: u8) -> Option<&'static str> {
    Some(match abi {
        0 => "System V",
        2 => "NetBSD",
        3 => "GNU/Linux",
        6 => "Solaris",
        9 => "FreeBSD",
        12 => "OpenBSD",
        97 => "ARM",
        255 => "standalone",
        _ => return None,
    })
}

fn segment_type(kind: u32) -> String {
    match kind {
        0 => "NULL".into(),
        1 => "LOAD".into(),
        2 => "DYNAMIC".into(),
        3 => "INTERP".into(),
        4 => "NOTE".into(),
        5 => "SHLIB".into(),
        6 => "PHDR".into(),
        7 => "TLS".into(),
        0x6474_e550 => "GNU_EH_FRAME".into(),
        0x6474_e551 => "GNU_STACK".into(),
        0x6474_e552 => "GNU_RELRO".into(),
        0x6474_e553 => "GNU_PROPERTY".into(),
        other => hx(u64::from(other)),
    }
}

fn section_type(kind: u32) -> String {
    match kind {
        0 => "NULL".into(),
        1 => "PROGBITS".into(),
        2 => "SYMTAB".into(),
        3 => "STRTAB".into(),
        4 => "RELA".into(),
        5 => "HASH".into(),
        6 => "DYNAMIC".into(),
        7 => "NOTE".into(),
        8 => "NOBITS".into(),
        9 => "REL".into(),
        11 => "DYNSYM".into(),
        14 => "INIT_ARRAY".into(),
        15 => "FINI_ARRAY".into(),
        16 => "PREINIT_ARRAY".into(),
        17 => "GROUP".into(),
        18 => "SYMTAB_SHNDX".into(),
        19 => "RELR".into(),
        0x6fff_fff5 => "GNU_ATTRIBUTES".into(),
        0x6fff_fff6 => "GNU_HASH".into(),
        0x6fff_fffd => "VERDEF".into(),
        0x6fff_fffe => "VERNEED".into(),
        0x6fff_ffff => "VERSYM".into(),
        other => hx(u64::from(other)),
    }
}

const SECTION_FLAGS: &[(u64, &str)] = &[
    (0x1, "WRITE"),
    (0x2, "ALLOC"),
    (0x4, "EXECINSTR"),
    (0x10, "MERGE"),
    (0x20, "STRINGS"),
    (0x40, "INFO_LINK"),
    (0x80, "LINK_ORDER"),
    (0x200, "GROUP"),
    (0x400, "TLS"),
    (0x800, "COMPRESSED"),
];

fn rwx(flags: u32) -> String {
    [(4, 'r'), (2, 'w'), (1, 'x')].iter().map(|(bit, c)| if flags & bit != 0 { *c } else { '-' }).collect()
}

/// What the dynamic section says.
#[derive(Default)]
struct Dynamic {
    present: bool,
    needed: Vec<String>,
    soname: Option<String>,
    rpath: Vec<String>,
    runpath: Vec<String>,
    flags: Option<(u64, u64)>,
    flags_1: Option<(u64, u64)>,
    /// Offset of the entry that asks for immediate binding, if any.
    bind_now: Option<u64>,
    /// Offset of the DT_RPATH or DT_RUNPATH entry.
    path_at: Option<u64>,
    strtab: Option<(u64, u64)>,
    symtab: Option<u64>,
    hash: Option<u64>,
}

pub fn analyze(file: &Artifact, data: &[u8], out: &mut Output) {
    out.kind(file, "elf");
    let mut problems = Problems::default();
    if parse(file, data, out, &mut problems).is_none() {
        problems.malformed("the ELF header is truncated or invalid; nothing else was read");
    }
    problems.emit(file, out);
}

fn parse(file: &Artifact, data: &[u8], out: &mut Output, problems: &mut Problems) -> Option<()> {
    let wide = match data.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let rd = Rd::new(
        data,
        match data.get(5)? {
            1 => true,
            2 => false,
            _ => return None,
        },
    );
    let os_abi = rd.u8(7)?;
    let e_type = rd.u16(16)?;
    let machine = rd.u16(18)?;
    let (entry, phoff, shoff, tail) = if wide {
        (rd.u64(24)?, rd.u64(32)?, rd.u64(40)?, 48)
    } else {
        (rd.word(24, false)?, rd.word(28, false)?, rd.word(32, false)?, 36)
    };
    let e_flags = rd.u32(tail)?;
    let phentsize = u64::from(rd.u16(tail + 6)?);
    let mut phnum = u64::from(rd.u16(tail + 8)?);
    let shentsize = u64::from(rd.u16(tail + 10)?);
    let mut shnum = u64::from(rd.u16(tail + 12)?);
    let mut shstrndx = u64::from(rd.u16(tail + 14)?);

    let (min_ph, min_sh) = if wide { (56, 64) } else { (32, 40) };

    // Section headers. Counts too large for the 16-bit fields live in section 0.
    let mut sections: Vec<SectionHeader> = Vec::new();
    let mut sections_cut = false;
    if shoff != 0 && shoff < rd.len() && shentsize >= min_sh {
        if shnum == 0 {
            shnum = rd.word(shoff + if wide { 32 } else { 20 }, wide).unwrap_or(0);
        }
        if shstrndx == 0xffff {
            shstrndx = rd.u32(shoff + if wide { 40 } else { 24 }).map_or(0, u64::from);
        }
        if phnum == 0xffff {
            phnum = rd.u32(shoff + if wide { 44 } else { 28 }).map_or(0, u64::from);
        }
        let fits = rd.len().saturating_sub(shoff) / shentsize;
        if shnum > fits {
            problems.malformed(format!("the section header table declares {shnum} entries but only {fits} fit in the file"));
            shnum = fits;
        }
        let raw: Vec<(u32, SectionHeader)> = (0..shnum.min(MAX_SECTIONS as u64))
            .filter_map(|i| {
                let at = shoff + i * shentsize;
                let name = rd.u32(at)?;
                let kind = rd.u32(at + 4)?;
                let (flags, addr, offset, size, link, entsize) = if wide {
                    (rd.u64(at + 8)?, rd.u64(at + 16)?, rd.u64(at + 24)?, rd.u64(at + 32)?, rd.u32(at + 40)?, rd.u64(at + 56)?)
                } else {
                    (
                        rd.word(at + 8, false)?,
                        rd.word(at + 12, false)?,
                        rd.word(at + 16, false)?,
                        rd.word(at + 20, false)?,
                        rd.u32(at + 24)?,
                        rd.word(at + 36, false)?,
                    )
                };
                Some((name, SectionHeader { name: String::new(), kind, flags, addr, offset, size, link, entsize }))
            })
            .collect();
        sections_cut = shnum > MAX_SECTIONS as u64;
        let names = usize::try_from(shstrndx).ok().and_then(|i| raw.get(i)).map(|(_, s)| (s.offset, s.size));
        sections = raw
            .into_iter()
            .map(|(name, mut section)| {
                if let Some((offset, size)) = names
                    && u64::from(name) < size
                {
                    section.name = rd.cstr(offset.saturating_add(u64::from(name)), offset.saturating_add(size)).unwrap_or_default();
                }
                section
            })
            .collect();
        if names.is_none() && !sections.is_empty() {
            problems.malformed("the section name table index is out of range; sections are unnamed");
        }
    } else if shoff != 0 && shoff < rd.len() {
        problems.malformed(format!("the section header entry size is {shentsize}, smaller than the format requires"));
    }

    // Program headers.
    let mut segments: Vec<Segment> = Vec::new();
    if phoff != 0 && phoff < rd.len() && phnum != 0 {
        if phentsize < min_ph {
            problems.malformed(format!("the program header entry size is {phentsize}, smaller than the format requires"));
        } else {
            let fits = rd.len().saturating_sub(phoff) / phentsize;
            if phnum > fits {
                problems.malformed(format!("the program header table declares {phnum} entries but only {fits} fit in the file"));
            }
            segments = (0..phnum.min(fits).min(MAX_SECTIONS as u64))
                .filter_map(|i| {
                    let at = phoff + i * phentsize;
                    let kind = rd.u32(at)?;
                    Some(if wide {
                        Segment {
                            kind,
                            flags: rd.u32(at + 4)?,
                            offset: rd.u64(at + 8)?,
                            vaddr: rd.u64(at + 16)?,
                            filesz: rd.u64(at + 32)?,
                            memsz: rd.u64(at + 40)?,
                            align: rd.u64(at + 48)?,
                            at,
                        }
                    } else {
                        Segment {
                            kind,
                            offset: rd.word(at + 4, false)?,
                            vaddr: rd.word(at + 8, false)?,
                            filesz: rd.word(at + 16, false)?,
                            memsz: rd.word(at + 20, false)?,
                            flags: rd.u32(at + 24)?,
                            align: rd.word(at + 28, false)?,
                            at,
                        }
                    })
                })
                .collect();
        }
    }
    let to_offset = |vaddr: u64| {
        segments
            .iter()
            .filter(|s| s.kind == PT_LOAD)
            .find(|s| vaddr >= s.vaddr && vaddr - s.vaddr < s.filesz)
            .and_then(|s| s.offset.checked_add(vaddr - s.vaddr))
    };

    let interp = segments.iter().find(|s| s.kind == PT_INTERP).and_then(|s| rd.cstr(s.offset, s.offset.saturating_add(s.filesz)));
    let has_interp = segments.iter().any(|s| s.kind == PT_INTERP);

    // Dynamic section.
    let mut dynamic = Dynamic::default();
    if let Some(segment) = segments.iter().find(|s| s.kind == PT_DYNAMIC && s.offset < rd.len()) {
        dynamic.present = true;
        let step = if wide { 16 } else { 8 };
        let count = (segment.filesz / step).min(MAX_DYNAMIC);
        let mut strings: Vec<(u64, u64, u64)> = Vec::new();
        let mut strsz = None;
        let mut strtab = None;
        let mut complete = false;
        for i in 0..count {
            let at = segment.offset.saturating_add(i * step);
            let (Some(tag), Some(value)) = (rd.word(at, wide), rd.word(at + step / 2, wide)) else {
                problems.malformed("the dynamic section runs past the end of the file");
                break;
            };
            match tag {
                0 => {
                    complete = true;
                    break;
                }
                DT_NEEDED | DT_SONAME | DT_RPATH | DT_RUNPATH => strings.push((tag, value, at)),
                DT_STRTAB => strtab = Some(value),
                DT_STRSZ => strsz = Some(value),
                DT_SYMTAB => dynamic.symtab = Some(value),
                DT_HASH => dynamic.hash = Some(value),
                DT_FLAGS => {
                    dynamic.flags = Some((value, at));
                    if value & DF_BIND_NOW != 0 {
                        dynamic.bind_now = Some(at);
                    }
                }
                DT_FLAGS_1 => {
                    dynamic.flags_1 = Some((value, at));
                    if value & DF_1_NOW != 0 {
                        dynamic.bind_now.get_or_insert(at);
                    }
                }
                DT_BIND_NOW => dynamic.bind_now = Some(at),
                _ => {}
            }
        }
        if !complete && count == MAX_DYNAMIC {
            problems.malformed("the dynamic section has more entries than are read");
        }
        dynamic.strtab = strtab.and_then(to_offset).zip(strsz);
        match dynamic.strtab {
            Some((base, size)) => {
                for (tag, value, at) in strings {
                    let Some(string) = (value < size).then(|| rd.cstr(base.saturating_add(value), base.saturating_add(size))).flatten()
                    else {
                        problems.malformed("a dynamic entry names a string outside the dynamic string table");
                        continue;
                    };
                    let split = |s: &str| s.split(':').map(str::to_string).collect::<Vec<_>>();
                    match tag {
                        // Kept well past what the fact shows, so the count in the finding is right
                        // for any real file, but not without bound.
                        DT_NEEDED if dynamic.needed.len() < 4 * MAX_LIBRARIES => dynamic.needed.push(string),
                        DT_NEEDED => {}
                        DT_SONAME => dynamic.soname = Some(string),
                        DT_RPATH => {
                            dynamic.rpath = split(&string);
                            dynamic.path_at.get_or_insert(at);
                        }
                        _ => {
                            dynamic.runpath = split(&string);
                            dynamic.path_at = Some(at);
                        }
                    }
                }
            }
            None if !strings.is_empty() => problems.malformed("the dynamic string table could not be located; library names are missing"),
            None => {}
        }
    }

    // Symbols. Section headers are the normal way in; without them the dynamic entries serve.
    let mut marks = Marks::default();
    let mut imports = Capped::new(MAX_SYMBOLS);
    let mut exports = Capped::new(MAX_SYMBOLS);
    let symsize: u64 = if wide { 24 } else { 16 };
    let mut walk = |table: (u64, u64), strings: (u64, u64), is_dynamic: bool, problems: &mut Problems| -> u64 {
        let (offset, size) = table;
        let fits = rd.len().saturating_sub(offset) / symsize;
        let count = size / symsize;
        if count > fits {
            problems.malformed("a symbol table runs past the end of the file");
        }
        let mut named = 0;
        for i in 1..count.min(fits) {
            let at = offset + i * symsize;
            let Some(name_index) = rd.u32(at) else { break };
            let (info, other, shndx, value) = if wide {
                (rd.u8(at + 4), rd.u8(at + 5), rd.u16(at + 6), rd.u64(at + 8))
            } else {
                (rd.u8(at + 12), rd.u8(at + 13), rd.u16(at + 14), rd.word(at + 4, false))
            };
            let (Some(info), Some(other), Some(shndx), Some(value)) = (info, other, shndx, value) else { break };
            if name_index == 0 || u64::from(name_index) >= strings.1 {
                continue;
            }
            let Some(name) = rd.cstr(strings.0.saturating_add(u64::from(name_index)), strings.0.saturating_add(strings.1)) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            named += 1;
            let (bind, kind) = (info >> 4, info & 0xf);
            let undefined = shndx == 0;
            marks.see(&name, 0, undefined, at);
            // Only the dynamic table is the interface to other files; section and file symbols
            // are not part of it.
            if !is_dynamic || kind == 3 || kind == 4 || !(bind == 1 || bind == 2) {
                continue;
            }
            if undefined {
                imports.push(Symbol::new(name).with("weak", bind == 2));
            } else if other & 0x3 == 0 || other & 0x3 == 3 {
                exports.push(Symbol::new(name).with("address", value).with("weak", bind == 2));
            }
        }
        named
    };
    let table_of = |kind: u32| {
        sections.iter().find(|s| s.kind == kind).and_then(|s| {
            let strings = sections.get(usize::try_from(s.link).ok()?)?;
            Some(((s.offset, s.size), (strings.offset, strings.size)))
        })
    };
    let mut dynsym_count = None;
    if let Some((table, strings)) = table_of(SHT_DYNSYM) {
        dynsym_count = Some(walk(table, strings, true, problems));
    } else if let (Some(symtab), Some(strings)) = (dynamic.symtab.and_then(to_offset), dynamic.strtab) {
        // Without section headers the size of the dynamic symbol table is not stored. The SysV
        // hash table records it; failing that, the table conventionally ends where the strings begin.
        let from_hash = dynamic.hash.and_then(to_offset).and_then(|at| rd.u32(at.checked_add(4)?)).map(|n| u64::from(n) * symsize);
        let size = from_hash.or_else(|| strings.0.checked_sub(symtab));
        match size {
            Some(size) => dynsym_count = Some(walk((symtab, size), strings, true, problems)),
            None => problems
                .undetermined("the dynamic symbol table has no recorded size (no section headers, no DT_HASH); imports were not read"),
        }
    }
    let symtab_count = table_of(SHT_SYMTAB).map(|(table, strings)| walk(table, strings, false, problems));
    let stripped = symtab_count.is_none();

    // Notes: build id, Go build id, ABI tags, control-flow properties.
    let mut build_id: Option<(String, u64)> = None;
    let mut go_build_id: Option<(String, u64)> = None;
    let mut abi_tag = None;
    let mut android_api = None;
    let mut properties: Vec<&'static str> = Vec::new();
    let mut property_at = None;
    let mut note_areas: Vec<(u64, u64, u64)> =
        segments.iter().filter(|s| s.kind == PT_NOTE).map(|s| (s.offset, s.filesz, if s.align == 8 { 8 } else { 4 })).collect();
    if note_areas.is_empty() {
        note_areas = sections.iter().filter(|s| s.kind == SHT_NOTE).map(|s| (s.offset, s.size, 4)).collect();
    }
    let mut notes_read = 0;
    for (offset, size, align) in note_areas {
        let end = offset.saturating_add(size).min(rd.len());
        let mut at = offset;
        while at.saturating_add(12) <= end && notes_read < MAX_NOTES {
            notes_read += 1;
            let (Some(namesz), Some(descsz), Some(kind)) = (rd.u32(at), rd.u32(at + 4), rd.u32(at + 8)) else { break };
            // Name and descriptor each start on an alignment boundary counted from the note's start.
            let pad = |n: u64| n.div_ceil(align) * align;
            let name_at = at + 12;
            let desc_at = at.saturating_add(pad(12 + u64::from(namesz)));
            let next = desc_at.saturating_add(pad(u64::from(descsz)));
            let (Some(name), Some(desc)) = (rd.bytes(name_at, u64::from(namesz)), rd.bytes(desc_at, u64::from(descsz))) else { break };
            if desc_at.saturating_add(u64::from(descsz)) > end {
                break;
            }
            let note = Rd::new(desc, rd.le);
            match (text(name).as_str(), kind) {
                ("GNU", 3) if !desc.is_empty() && desc.len() <= 64 => build_id = Some((hex(desc), desc_at)),
                ("Go", 4) if desc.len() <= 256 => go_build_id = Some((text(desc), desc_at)),
                ("GNU", 1) => {
                    if let (Some(0), Some(a), Some(b), Some(c)) = (note.u32(0), note.u32(4), note.u32(8), note.u32(12)) {
                        abi_tag = Some(format!("Linux {a}.{b}.{c}"));
                    }
                }
                ("Android", 1) => android_api = note.u32(0),
                ("GNU", 5) => {
                    // An array of (type, size, data) records, each padded to the note alignment.
                    let mut p = 0u64;
                    while let (Some(pr_type), Some(pr_size)) = (note.u32(p), note.u32(p + 4)) {
                        if let Some(bits) = note.u32(p + 8).filter(|_| pr_size >= 4) {
                            let names: &[(u32, &str)] = match (pr_type, machine) {
                                (0xc000_0002, 3 | 62) => &[(1, "IBT"), (2, "SHSTK")],
                                (0xc000_0000, 183) => &[(1, "BTI"), (2, "PAC")],
                                _ => &[],
                            };
                            for (bit, name) in names {
                                if bits & bit != 0 && !properties.contains(name) {
                                    properties.push(name);
                                    property_at = Some(desc_at + p);
                                }
                            }
                        }
                        p = p.saturating_add(8 + pad(u64::from(pr_size)));
                    }
                }
                _ => {}
            }
            if next <= at {
                break;
            }
            at = next;
        }
    }

    // File type. ET_DYN covers both shared libraries and position-independent executables.
    let pie_flag = dynamic.flags_1.filter(|(value, _)| value & DF_1_PIE != 0);
    let file_type = match e_type {
        1 => "object",
        2 => "executable",
        3 if pie_flag.is_some() => "pie-executable",
        3 if dynamic.soname.is_none() && has_interp => "pie-executable",
        3 => "shared-library",
        4 => "core",
        _ => "unknown",
    };
    let is_static = !dynamic.present && !has_interp && matches!(e_type, 2 | 3);
    let arch = machine_name(machine);
    let arch_text = arch.map_or_else(|| format!("machine {machine}"), str::to_string);
    let bits = if wide { 64 } else { 32 };
    let endian = if rd.le { "little" } else { "big" };

    // Sections fact, with entropy of what is stored in the file.
    let mut budget = EntropyBudget::new(rd.len());
    let mut regions = Vec::new();
    let mut debug_sections = BTreeSet::new();
    let mut comment = Vec::new();
    let mut debuglink = None;
    let mut packed_upx = memchr::memmem::find(data.get(..data.len().min(4096)).unwrap_or(&[]), b"UPX!").map(|at| at as u64);
    let mut section_values = Vec::new();
    let mut high_entropy = Vec::new();
    for section in &sections {
        let stored = section.kind != SHT_NOBITS && section.kind != 0;
        let entropy = if stored { budget.of(&rd, section.offset, section.size) } else { None };
        if stored && section.offset.checked_add(section.size).is_none_or(|end| end > rd.len()) {
            problems.malformed(format!("section {} extends past the end of the file", section.name));
        }
        if stored {
            regions.push(Region { name: section.name.clone(), offset: section.offset, size: section.size });
        }
        let name = section.name.as_str();
        // `.debug_gdb_scripts` names helper scripts for a debugger and stays in stripped files;
        // it is not debug information.
        if (name.starts_with(".debug_") || name.starts_with(".zdebug_") || name == ".stab") && name != ".debug_gdb_scripts" {
            debug_sections.insert(section.name.clone());
        }
        if name == ".comment"
            && let Some(bytes) = rd.bytes(section.offset, section.size.min(4096))
        {
            let idents: BTreeSet<String> = bytes.split(|b| *b == 0).filter(|part| !part.is_empty()).map(text).collect();
            comment = idents.into_iter().map(|ident| (ident, section.offset)).collect();
        }
        if name == ".gnu_debuglink" {
            debuglink = rd.cstr(section.offset, section.offset.saturating_add(section.size));
        }
        if name == "UPX0" || name == "UPX1" {
            packed_upx.get_or_insert(section.offset);
        }
        if let Some(e) = entropy
            && e >= 7.2
            && section.flags & 0x4 != 0
            && section.size >= 4096
        {
            high_entropy.push((section.name.clone(), e, section.offset, section.size));
        }
        section_values.push(json!({
            "name": section.name,
            "type": section_type(section.kind),
            "flags": flag_names(section.flags, SECTION_FLAGS),
            "address": section.addr,
            "offset": section.offset,
            "size": section.size,
            "entsize": section.entsize,
            "entropy": entropy,
        }));
    }

    let libraries: Vec<String> = dynamic.needed.clone();
    let idents: Vec<String> = comment.iter().map(|(ident, _)| ident.clone()).collect();
    let toolchain = lang::detect(&rd, &marks, &libraries, &regions, &idents);
    if go_build_id.is_none() && toolchain.has("Go") {
        go_build_id = lang::go_build_id(data);
    }

    // Facts.
    out.fact(
        file,
        "binary.header",
        json!({
            "format": "elf",
            "arch": arch,
            "machine": machine,
            "bits": bits,
            "endian": endian,
            "file_type": file_type,
            "elf_type": e_type,
            "os_abi": os_abi_name(os_abi),
            "os_abi_raw": os_abi,
            "flags": e_flags,
            "entry": entry,
            "build_id": build_id.as_ref().map(|(id, _)| id),
            "go_build_id": go_build_id.as_ref().map(|(id, _)| id),
            "abi_tag": abi_tag,
            "android_api": android_api,
        }),
    );
    out.fact(file, "binary.sections", json!({ "sections": section_values, "total": shnum, "truncated": sections_cut }));
    let segment_values: Vec<Value> = segments
        .iter()
        .map(|s| {
            json!({
                "type": segment_type(s.kind),
                "flags": rwx(s.flags),
                "offset": s.offset,
                "vaddr": s.vaddr,
                "filesz": s.filesz,
                "memsz": s.memsz,
                "align": s.align,
            })
        })
        .collect();
    out.fact(file, "binary.segments", json!({ "segments": segment_values, "truncated": phnum > segments.len() as u64 }));
    let library_values: Vec<Value> = libraries.iter().take(MAX_LIBRARIES).map(|name| json!({ "name": name, "kind": "needed" })).collect();
    out.fact(file, "binary.libraries", json!({ "libraries": library_values, "truncated": libraries.len() > MAX_LIBRARIES }));
    out.fact(
        file,
        "binary.linking",
        json!({
            "static": is_static,
            "interp": interp,
            "soname": dynamic.soname,
            "rpath": dynamic.rpath,
            "runpath": dynamic.runpath,
            "dt_flags": dynamic.flags.map(|(v, _)| v),
            "dt_flags_1": dynamic.flags_1.map(|(v, _)| v),
        }),
    );
    let (import_total, export_total) = (imports.total, exports.total);
    let imports_known = dynsym_count.is_some();
    if imports_known {
        out.fact(file, "binary.imports", symbols_json(imports, true));
        out.fact(file, "binary.exports", symbols_json(exports, false));
    }
    out.fact(file, "binary.symbols", json!({ "stripped": stripped, "symtab": symtab_count, "dynsym": dynsym_count }));
    let has_debug = !debug_sections.is_empty();
    out.fact(
        file,
        "binary.debug",
        json!({
            "has_debug_info": has_debug,
            "kinds": if has_debug { vec!["dwarf"] } else { Vec::new() },
            "sections": debug_sections,
            "debuglink": debuglink,
        }),
    );
    let mut toolchain_value = toolchain.to_json();
    toolchain_value["compiler_idents"] = comment.iter().map(|(ident, _)| ident.as_str()).collect::<Vec<_>>().into();
    out.fact(file, "binary.toolchain", toolchain_value);

    // Identity.
    out.finding(
        finding(Section::Identity, "binary.elf-identity", Confidence::Verified, Severity::Info)
            .param("bits", bits)
            .param("endian", endian)
            .param("arch", arch_text)
            .param("file_type", file_type.replace('-', " "))
            .evidence(Evidence::bytes(file, 0, 20, hex(data.get(..20).unwrap_or(&[])))),
    );
    if let Some((id, at)) = &build_id {
        out.finding(
            finding(Section::Identity, "binary.build-id", Confidence::Verified, Severity::Info)
                .param("label", "")
                .param("kind", "GNU build ID")
                .param("id", id.as_str())
                .evidence(Evidence::bytes(file, *at, id.len() as u64 / 2, id.as_str())),
        );
    }

    // Composition.
    if !libraries.is_empty() {
        let mut f = finding(Section::Composition, "binary.libraries", Confidence::Verified, Severity::Info)
            .param("label", "")
            .param("count", libraries.len())
            .param("sample", sample(&libraries, 8));
        for name in libraries.iter().take(8) {
            f = f.evidence(Evidence::field(file, "DT_NEEDED", name.as_str()));
        }
        out.finding(f);
    } else if is_static {
        out.finding(finding(Section::Composition, "binary.static", Confidence::Verified, Severity::Info).evidence(Evidence::field(
            file,
            "program headers",
            "no PT_DYNAMIC, no PT_INTERP",
        )));
    }
    toolchain.emit(file, 0, "", out);
    for (ident, at) in comment.iter().take(8) {
        out.finding(
            finding(Section::Composition, "binary.compiler-ident", Confidence::Verified, Severity::Info)
                .param("ident", ident.as_str())
                .evidence(Evidence::bytes(file, *at, ident.len() as u64, ident.as_str())),
        );
    }
    if let Some(at) = packed_upx {
        out.finding(
            finding(Section::Anomalies, "binary.packed-upx", Confidence::Heuristic, Severity::Low)
                .evidence(Evidence::bytes(file, at, 4, "UPX")),
        );
    }
    for (name, e, offset, size) in high_entropy.iter().take(4) {
        out.finding(
            finding(Section::Anomalies, "binary.code-high-entropy", Confidence::Heuristic, Severity::Low)
                .param("name", name.as_str())
                .param("entropy", *e)
                .evidence(Evidence::bytes(file, *offset, *size, *e)),
        );
    }

    // Code.
    let counts = imports_known.then_some((import_total, export_total)).filter(|counts| *counts != (0, 0));
    crate::emit_symbols(file, out, Some(stripped), symtab_count, counts, "");
    if has_debug || debuglink.is_some() {
        let what = match (&debuglink, has_debug) {
            (Some(link), false) => format!("separate debug file {link} (.gnu_debuglink)"),
            _ => "DWARF sections".to_string(),
        };
        out.finding(
            finding(Section::Code, "binary.debug-info", Confidence::Verified, Severity::Info)
                .param("label", "")
                .param("what", what.as_str())
                .evidence(Evidence::field(file, "section names", what.as_str())),
        );
    }

    // Hardening applies to things that get loaded, not to relocatable objects or core dumps.
    let mut hardening = serde_json::Map::new();
    if matches!(e_type, 2 | 3) {
        let hard = |rule: &str, confidence, severity| finding(Section::Hardening, rule, confidence, severity);
        let e_type_evidence = Evidence::bytes(file, 16, 2, e_type);

        // PIE.
        match file_type {
            "pie-executable" => {
                hardening.insert("pie".into(), true.into());
                let f = match pie_flag {
                    Some((value, at)) => hard("binary.elf-pie", Confidence::Verified, Severity::Info).evidence(Evidence::bytes(
                        file,
                        at,
                        if wide { 16 } else { 8 },
                        format!("DT_FLAGS_1 = {}", hx(value)),
                    )),
                    // ET_DYN with a program interpreter and no library name: the rule `file` uses.
                    None => hard("binary.elf-pie", Confidence::Derived, Severity::Info),
                };
                out.finding(f.evidence(e_type_evidence));
            }
            "executable" => {
                hardening.insert("pie".into(), false.into());
                out.finding(hard("binary.elf-no-pie", Confidence::Verified, Severity::Medium).evidence(e_type_evidence));
            }
            _ => {
                hardening.insert("pie".into(), Value::Null);
            }
        }

        // NX stack.
        match segments.iter().find(|s| s.kind == PT_GNU_STACK) {
            Some(stack) => {
                let executable = stack.flags & 1 != 0;
                hardening.insert("nx".into(), (!executable).into());
                let (rule, severity) =
                    if executable { ("binary.elf-nx-disabled", Severity::Medium) } else { ("binary.elf-nx", Severity::Info) };
                out.finding(hard(rule, Confidence::Verified, severity).evidence(Evidence::bytes(
                    file,
                    stack.at,
                    phentsize,
                    format!("PT_GNU_STACK flags {}", rwx(stack.flags)),
                )));
            }
            None if segments.is_empty() => {
                hardening.insert("nx".into(), Value::Null);
                problems.undetermined("no program headers were read, so the stack and RELRO settings are unknown");
            }
            None => {
                hardening.insert("nx".into(), Value::Null);
                out.finding(hard("binary.elf-nx-unmarked", Confidence::Verified, Severity::Low).evidence(Evidence::bytes(
                    file,
                    phoff,
                    phentsize * segments.len() as u64,
                    "no PT_GNU_STACK program header",
                )));
            }
        }

        // RELRO.
        if !segments.is_empty() {
            let relro = segments.iter().find(|s| s.kind == PT_GNU_RELRO);
            let step = if wide { 16 } else { 8 };
            match (relro, dynamic.bind_now) {
                (Some(relro), Some(now)) => {
                    hardening.insert("relro".into(), "full".into());
                    out.finding(
                        hard("binary.elf-relro-full", Confidence::Verified, Severity::Info)
                            .evidence(Evidence::bytes(file, relro.at, phentsize, "PT_GNU_RELRO"))
                            .evidence(Evidence::bytes(file, now, step, "BIND_NOW")),
                    );
                }
                (Some(relro), None) => {
                    hardening.insert("relro".into(), "partial".into());
                    out.finding(hard("binary.elf-relro-partial", Confidence::Verified, Severity::Low).evidence(Evidence::bytes(
                        file,
                        relro.at,
                        phentsize,
                        "PT_GNU_RELRO, no BIND_NOW",
                    )));
                }
                (None, _) => {
                    hardening.insert("relro".into(), "none".into());
                    // Without a dynamic section there are no run-time relocations to protect.
                    let (rule, severity) = if dynamic.present {
                        ("binary.elf-relro-none", Severity::Medium)
                    } else {
                        ("binary.elf-relro-static", Severity::Info)
                    };
                    out.finding(hard(rule, Confidence::Verified, severity).evidence(Evidence::bytes(
                        file,
                        phoff,
                        phentsize * segments.len() as u64,
                        "no PT_GNU_RELRO program header",
                    )));
                }
            }
        }

        // Stack canary and FORTIFY, inferred from symbols.
        let symbols_visible = dynsym_count.is_some_and(|n| n > 0) || symtab_count.is_some();
        let safe_language = ["Go", "Rust"].into_iter().find(|l| toolchain.has(l));
        match &marks.canary {
            Some((symbol, at)) => {
                hardening.insert("canary".into(), true.into());
                out.finding(
                    hard("binary.canary", Confidence::Derived, Severity::Info)
                        .param("symbol", symbol.as_str())
                        .param("label", "")
                        .evidence(Evidence::bytes(file, *at, symsize, symbol.as_str())),
                );
            }
            // A Go program has no C code unless it links a C library, which a static one does not.
            None if !symbols_visible && is_static && toolchain.has("Go") => {
                hardening.insert("canary".into(), false.into());
                out.finding(
                    hard("binary.no-canary-safe-language", Confidence::Heuristic, Severity::Info)
                        .param("language", "Go")
                        .param("label", "")
                        .evidence(Evidence::field(file, "toolchain marker", "statically linked Go program")),
                );
            }
            None if !symbols_visible => {
                hardening.insert("canary".into(), Value::Null);
                problems
                    .undetermined("stack canary: the file has no symbols to look for __stack_chk_fail in (stripped and statically linked)");
            }
            None => {
                hardening.insert("canary".into(), false.into());
                let evidence = Evidence::field(file, "symbol tables", "__stack_chk_fail not referenced");
                match safe_language {
                    Some(language) if !toolchain.has("C++") => out.finding(
                        hard("binary.no-canary-safe-language", Confidence::Heuristic, Severity::Info)
                            .param("language", language)
                            .param("label", "")
                            .evidence(evidence),
                    ),
                    _ => out.finding(hard("binary.no-canary", Confidence::Heuristic, Severity::Low).param("label", "").evidence(evidence)),
                }
            }
        }
        if !marks.fortified.is_empty() {
            let names: Vec<String> = marks.fortified.iter().cloned().collect();
            hardening.insert("fortify".into(), true.into());
            hardening.insert("fortified_functions".into(), names.clone().into());
            out.finding(
                hard("binary.elf-fortify", Confidence::Derived, Severity::Info)
                    .param("count", names.len())
                    .param("sample", sample(&names, 6))
                    .evidence(Evidence::field(file, "imported symbols", names.first().cloned().unwrap_or_default())),
            );
        } else if !marks.fortifiable.is_empty() && safe_language.is_none() {
            let names: Vec<String> = marks.fortifiable.iter().cloned().collect();
            hardening.insert("fortify".into(), false.into());
            out.finding(
                hard("binary.elf-no-fortify", Confidence::Heuristic, Severity::Low)
                    .param("sample", sample(&names, 6))
                    .evidence(Evidence::field(file, "imported symbols", names.first().cloned().unwrap_or_default())),
            );
        } else {
            // Nothing imported that fortification would replace: the question does not arise.
            hardening.insert("fortify".into(), Value::Null);
        }

        // Library search paths baked into the file.
        let paths: Vec<String> = dynamic.runpath.iter().chain(&dynamic.rpath).cloned().collect();
        hardening.insert("rpath".into(), (!dynamic.rpath.is_empty()).into());
        hardening.insert("runpath".into(), (!dynamic.runpath.is_empty()).into());
        if let Some(at) = dynamic.path_at.filter(|_| !paths.is_empty()) {
            // A relative or temporary directory lets whoever controls it supply a library.
            let risky = paths.iter().any(|p| {
                p.is_empty() || p.starts_with("/tmp") || !(p.starts_with('/') || p.starts_with("$ORIGIN") || p.starts_with("${ORIGIN}"))
            });
            let kind = if dynamic.runpath.is_empty() { "RPATH" } else { "RUNPATH" };
            out.finding(
                hard(
                    if risky { "binary.elf-rpath-risky" } else { "binary.elf-rpath" },
                    Confidence::Verified,
                    if risky { Severity::Medium } else { Severity::Low },
                )
                .param("kind", kind)
                .param("paths", paths.join(":"))
                .evidence(Evidence::bytes(file, at, if wide { 16 } else { 8 }, paths.join(":"))),
            );
        }

        // Segments that are writable and executable at once.
        let wx: Vec<&Segment> = segments.iter().filter(|s| s.kind == PT_LOAD && s.flags & 3 == 3).collect();
        hardening.insert("writable_executable".into(), (!wx.is_empty()).into());
        for segment in wx.iter().take(4) {
            out.finding(
                hard("binary.writable-executable", Confidence::Verified, Severity::Medium)
                    .param("what", format!("LOAD segment at {}", hx(segment.vaddr)))
                    .evidence(Evidence::bytes(file, segment.at, phentsize, rwx(segment.flags))),
            );
        }

        // Control-flow protection markers.
        hardening.insert("cf_protection".into(), properties.clone().into());
        if let Some(at) = property_at {
            out.finding(
                hard("binary.elf-cf-protection", Confidence::Verified, Severity::Info)
                    .param("features", properties.join(", "))
                    .evidence(Evidence::bytes(file, at, 12, properties.join(", "))),
            );
        }
    }
    out.fact(file, "binary.hardening", Value::Object(hardening));
    Some(())
}
