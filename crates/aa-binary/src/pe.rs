//! PE (Windows executables, DLLs, drivers): headers, sections, imports, exports, debug directory,
//! load configuration, Rich header, overlay, hardening.
//!
//! Authenticode verification, resources, manifests, .NET metadata and installer detection belong
//! to `aa-windows`; this module only records where those structures are.

use aa_core::plugin::Output;
use aa_core::{Artifact, Confidence, Evidence, Section, Severity};
use serde_json::{Value, json};

use crate::common::{
    Capped, EntropyBudget, MAX_LIBRARIES, MAX_SECTIONS, MAX_SYMBOLS, Marks, Problems, Rd, Symbol, entropy, finding, flag_names, hex, hx,
    sample, symbols_json, text,
};
use crate::lang::{self, Region};

/// Import descriptors read at most.
const MAX_DESCRIPTORS: u64 = 4096;
/// Imported functions read per library at most.
const MAX_THUNKS: u64 = 65_536;
/// Imported functions read in total, so descriptors that all point at one long table cannot
/// keep the parser busy.
const MAX_IMPORTS: u64 = 1_000_000;
/// Exported names read at most.
const MAX_EXPORTS: u64 = 1_000_000;
/// COFF symbols looked at for toolchain markers.
const MAX_COFF_SYMBOLS: u64 = 2_000_000;

const DIRECTORIES: [&str; 16] = [
    "export",
    "import",
    "resource",
    "exception",
    "security",
    "basereloc",
    "debug",
    "architecture",
    "globalptr",
    "tls",
    "load_config",
    "bound_import",
    "iat",
    "delay_import",
    "clr",
    "reserved",
];

const CHARACTERISTICS: &[(u64, &str)] = &[
    (0x0001, "RELOCS_STRIPPED"),
    (0x0002, "EXECUTABLE_IMAGE"),
    (0x0004, "LINE_NUMS_STRIPPED"),
    (0x0008, "LOCAL_SYMS_STRIPPED"),
    (0x0020, "LARGE_ADDRESS_AWARE"),
    (0x0100, "32BIT_MACHINE"),
    (0x0200, "DEBUG_STRIPPED"),
    (0x0400, "REMOVABLE_RUN_FROM_SWAP"),
    (0x0800, "NET_RUN_FROM_SWAP"),
    (0x1000, "SYSTEM"),
    (0x2000, "DLL"),
    (0x4000, "UP_SYSTEM_ONLY"),
];

const HIGH_ENTROPY_VA: u16 = 0x0020;
const DYNAMIC_BASE: u16 = 0x0040;
const FORCE_INTEGRITY: u16 = 0x0080;
const NX_COMPAT: u16 = 0x0100;
const NO_SEH: u16 = 0x0400;
const GUARD_CF: u16 = 0x4000;

const DLL_CHARACTERISTICS: &[(u64, &str)] = &[
    (0x0020, "HIGH_ENTROPY_VA"),
    (0x0040, "DYNAMIC_BASE"),
    (0x0080, "FORCE_INTEGRITY"),
    (0x0100, "NX_COMPAT"),
    (0x0200, "NO_ISOLATION"),
    (0x0400, "NO_SEH"),
    (0x0800, "NO_BIND"),
    (0x1000, "APPCONTAINER"),
    (0x2000, "WDM_DRIVER"),
    (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
];

const SECTION_FLAGS: &[(u64, &str)] = &[
    (0x0000_0020, "CNT_CODE"),
    (0x0000_0040, "CNT_INITIALIZED_DATA"),
    (0x0000_0080, "CNT_UNINITIALIZED_DATA"),
    (0x0200_0000, "MEM_DISCARDABLE"),
    (0x1000_0000, "MEM_SHARED"),
    (0x2000_0000, "MEM_EXECUTE"),
    (0x4000_0000, "MEM_READ"),
    (0x8000_0000, "MEM_WRITE"),
];

fn machine_name(machine: u16) -> Option<&'static str> {
    Some(match machine {
        0x014c => "i386",
        0x8664 => "x86_64",
        0x01c0 | 0x01c2 | 0x01c4 => "arm",
        0xaa64 => "arm64",
        0xa641 => "arm64ec",
        0x0200 => "ia64",
        0x0ebc => "efi-bytecode",
        0x5032 => "riscv32",
        0x5064 => "riscv64",
        0x6264 => "loongarch64",
        _ => return None,
    })
}

fn subsystem_name(subsystem: u16) -> Option<&'static str> {
    Some(match subsystem {
        1 => "native",
        2 => "windows-gui",
        3 => "windows-console",
        5 => "os2-console",
        7 => "posix-console",
        9 => "windows-ce",
        10 => "efi-application",
        11 => "efi-boot-service-driver",
        12 => "efi-runtime-driver",
        13 => "efi-rom",
        14 => "xbox",
        16 => "windows-boot-application",
        _ => return None,
    })
}

/// Seconds since 1970 as `YYYY-MM-DDThh:mm:ssZ`.
pub fn utc(seconds: u32) -> String {
    let days = i64::from(seconds / 86_400);
    let rest = seconds % 86_400;
    // Days-to-civil conversion (Howard Hinnant's algorithm), valid for the whole u32 range.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rest / 3600, rest % 3600 / 60, rest % 60)
}

struct SectionHeader {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_offset: u32,
    flags: u32,
    /// Where the 40-byte section header is in the file.
    at: u64,
}

struct Image<'a> {
    rd: Rd<'a>,
    sections: Vec<SectionHeader>,
    size_of_headers: u64,
    image_base: u64,
}

impl Image<'_> {
    /// The file offset of a relative virtual address, when the address is backed by file bytes.
    fn offset(&self, rva: u64) -> Option<u64> {
        for section in &self.sections {
            let start = u64::from(section.virtual_address);
            if rva >= start && rva - start < u64::from(section.raw_size) {
                return Some(u64::from(section.raw_offset) + (rva - start));
            }
        }
        (rva < self.size_of_headers).then_some(rva)
    }

    fn cstr_at(&self, rva: u64) -> Option<String> {
        self.rd.cstr(self.offset(rva)?, self.rd.len())
    }
}

pub fn analyze(file: &Artifact, data: &[u8], out: &mut Output) {
    let mut problems = Problems::default();
    if parse(file, data, out, &mut problems).is_none() {
        problems.malformed("the PE headers are truncated or invalid; nothing else was read");
    }
    problems.emit(file, out);
}

/// True when `data` has the DOS stub pointing at a `PE\0\0` signature.
pub fn is_pe(data: &[u8]) -> bool {
    let rd = Rd::new(data, true);
    data.starts_with(b"MZ") && rd.u32(0x3c).is_some_and(|lfanew| rd.bytes(u64::from(lfanew), 4) == Some(b"PE\0\0"))
}

fn parse(file: &Artifact, data: &[u8], out: &mut Output, problems: &mut Problems) -> Option<()> {
    out.kind(file, "pe");
    let rd = Rd::new(data, true);
    let lfanew = u64::from(rd.u32(0x3c)?);
    let coff = lfanew + 4;
    let machine = rd.u16(coff)?;
    let section_count = rd.u16(coff + 2)?;
    let timestamp = rd.u32(coff + 4)?;
    let symbol_table = u64::from(rd.u32(coff + 8)?);
    let symbol_count = u64::from(rd.u32(coff + 12)?);
    let optional_size = u64::from(rd.u16(coff + 16)?);
    let characteristics = rd.u16(coff + 18)?;
    let opt = coff + 20;
    let magic = rd.u16(opt)?;
    let wide = match magic {
        0x10b => false,
        0x20b => true,
        _ => return None,
    };
    let linker = (rd.u8(opt + 2)?, rd.u8(opt + 3)?);
    let entry = rd.u32(opt + 16)?;
    let image_base = if wide { rd.u64(opt + 24)? } else { u64::from(rd.u32(opt + 28)?) };
    let os_version = (rd.u16(opt + 40)?, rd.u16(opt + 42)?);
    let subsystem_version = (rd.u16(opt + 48)?, rd.u16(opt + 50)?);
    let size_of_image = rd.u32(opt + 56)?;
    let size_of_headers = rd.u32(opt + 60)?;
    let checksum = rd.u32(opt + 64)?;
    let subsystem = rd.u16(opt + 68)?;
    let dll_characteristics = rd.u16(opt + 70)?;
    let directory_count = rd.u32(opt + if wide { 108 } else { 92 })?.min(16);
    let directories_at = opt + if wide { 112 } else { 96 };
    // A directory entry counts only if it lies inside the optional header the file declares.
    let directory = |index: u64| -> Option<(u64, u64)> {
        if index >= u64::from(directory_count) || (directories_at - opt) + (index + 1) * 8 > optional_size {
            return None;
        }
        let at = directories_at + index * 8;
        let (rva, size) = (rd.u32(at)?, rd.u32(at + 4)?);
        (rva != 0 && size != 0).then_some((u64::from(rva), u64::from(size)))
    };

    // COFF string table: long section names and symbol names live there.
    let string_table = (symbol_table != 0).then(|| symbol_table + symbol_count * 18).filter(|at| *at < rd.len());
    let string_table_size = string_table.and_then(|at| rd.u32(at)).map(u64::from);

    // Sections.
    let table = opt + optional_size;
    let fits = rd.len().saturating_sub(table) / 40;
    if u64::from(section_count) > fits {
        problems.malformed(format!("the section table declares {section_count} sections but only {fits} fit in the file"));
    }
    let sections: Vec<SectionHeader> = (0..u64::from(section_count).min(fits).min(MAX_SECTIONS as u64))
        .filter_map(|i| {
            let at = table + i * 40;
            let mut name = text(rd.bytes(at, 8)?);
            // `/123` is an offset into the string table (names longer than eight bytes).
            if let Some(index) = name.strip_prefix('/').and_then(|n| n.parse::<u64>().ok())
                && let Some(long) = string_table.and_then(|base| rd.cstr(base + index, rd.len()))
            {
                name = long;
            }
            Some(SectionHeader {
                name,
                virtual_size: rd.u32(at + 8)?,
                virtual_address: rd.u32(at + 12)?,
                raw_size: rd.u32(at + 16)?,
                raw_offset: rd.u32(at + 20)?,
                flags: rd.u32(at + 36)?,
                at,
            })
        })
        .collect();
    let image = Image { rd, sections, size_of_headers: u64::from(size_of_headers), image_base };

    let arch = machine_name(machine);
    let arch_text = arch.map_or_else(|| format!("machine {}", hx(u64::from(machine))), str::to_string);
    let is_dll = characteristics & 0x2000 != 0;
    let file_type = match subsystem {
        _ if is_dll => "dll",
        1 => "driver",
        10..=13 => "efi",
        _ => "executable",
    };
    let format = if wide { "PE32+" } else { "PE32" };

    // Section facts.
    let mut budget = EntropyBudget::new(rd.len());
    let mut regions = Vec::new();
    let mut section_values = Vec::new();
    let mut end_of_sections = u64::from(size_of_headers).min(rd.len());
    let mut has_code = false;
    let mut wx = Vec::new();
    let mut high_entropy = Vec::new();
    let mut dwarf = false;
    let mut upx = None;
    for section in &image.sections {
        let (offset, size) = (u64::from(section.raw_offset), u64::from(section.raw_size));
        let section_entropy = budget.of(&rd, offset, size);
        if size > 0 {
            if offset + size > rd.len() {
                problems.malformed(format!("section {} extends past the end of the file", section.name));
            }
            end_of_sections = end_of_sections.max((offset + size).min(rd.len()));
            regions.push(Region { name: section.name.clone(), offset, size });
        }
        let executable = section.flags & 0x2000_0000 != 0;
        has_code |= executable;
        if executable && section.flags & 0x8000_0000 != 0 {
            wx.push(section);
        }
        if let Some(e) = section_entropy
            && e >= 7.2
            && executable
            && size >= 4096
        {
            high_entropy.push((section.name.clone(), e, offset, size));
        }
        dwarf |= section.name.starts_with(".debug_");
        if section.name.starts_with("UPX") {
            upx.get_or_insert(section.at);
        }
        section_values.push(json!({
            "name": section.name,
            "virtual_address": section.virtual_address,
            "virtual_size": section.virtual_size,
            "offset": section.raw_offset,
            "size": section.raw_size,
            "flags": flag_names(u64::from(section.flags) & 0xf200_00e0, SECTION_FLAGS),
            "characteristics": section.flags,
            "entropy": section_entropy,
        }));
    }

    // Imports, ordinary and delay-loaded.
    let mut marks = Marks::default();
    let mut imports = Capped::new(MAX_SYMBOLS);
    let mut libraries: Vec<(String, &'static str, u64)> = Vec::new();
    let thunk_size: u64 = if wide { 8 } else { 4 };
    let ordinal_bit: u64 = if wide { 1 << 63 } else { 1 << 31 };
    let mut thunks_left = MAX_IMPORTS;
    let mut walk_thunks = |library: &str, thunks: u64| -> u64 {
        let Some(start) = image.offset(thunks) else { return 0 };
        let mut count = 0;
        for i in 0..MAX_THUNKS.min(thunks_left) {
            thunks_left -= 1;
            let at = start + i * thunk_size;
            let Some(value) = rd.word(at, wide).filter(|v| *v != 0) else { break };
            count += 1;
            let mut symbol = if value & ordinal_bit != 0 {
                Symbol::new(format!("#{}", value & 0xffff)).with("ordinal", value & 0xffff)
            } else {
                // A hint (two bytes) then the name.
                match image.cstr_at((value & 0x7fff_ffff) + 2) {
                    Some(name) if !name.is_empty() => {
                        marks.see(&name, 0, true, at);
                        Symbol::new(name)
                    }
                    _ => continue,
                }
            };
            symbol.library = Some(library.to_string());
            imports.push(symbol);
        }
        count
    };
    let mut imports_read = true;
    if let Some((rva, _)) = directory(1) {
        match image.offset(rva) {
            Some(start) => {
                for i in 0..MAX_DESCRIPTORS {
                    let at = start + i * 20;
                    let (Some(lookup), Some(name), Some(iat)) = (rd.u32(at), rd.u32(at + 12), rd.u32(at + 16)) else {
                        problems.malformed("the import table runs past the end of the file");
                        break;
                    };
                    if name == 0 && iat == 0 {
                        break;
                    }
                    let Some(library) = image.cstr_at(u64::from(name)) else {
                        problems.malformed("an import descriptor names a library outside the file");
                        continue;
                    };
                    // The lookup table survives binding; the address table is the fallback.
                    let count = walk_thunks(&library, u64::from(if lookup != 0 { lookup } else { iat }));
                    libraries.push((library, "import", count));
                }
            }
            None => {
                imports_read = false;
                problems.malformed("the import directory points outside the file; imports were not read");
            }
        }
    }
    if let Some((rva, _)) = directory(13)
        && let Some(start) = image.offset(rva)
    {
        for i in 0..MAX_DESCRIPTORS {
            let at = start + i * 32;
            let (Some(attributes), Some(name), Some(names)) = (rd.u32(at), rd.u32(at + 4), rd.u32(at + 16)) else { break };
            if name == 0 {
                break;
            }
            // Old-style descriptors hold virtual addresses instead of RVAs.
            let fix = |value: u32| if attributes & 1 != 0 { u64::from(value) } else { u64::from(value).wrapping_sub(image.image_base) };
            let Some(library) = image.cstr_at(fix(name)) else { continue };
            let count = walk_thunks(&library, fix(names));
            libraries.push((library, "delay-import", count));
        }
    }

    // Exports.
    let mut exports = Capped::new(MAX_SYMBOLS);
    let mut export_name = None;
    let mut export_functions = None;
    if let Some((rva, size)) = directory(0) {
        match image.offset(rva) {
            Some(at) => {
                export_name = rd.u32(at + 12).and_then(|name| image.cstr_at(u64::from(name)));
                let base = rd.u32(at + 16).unwrap_or(0);
                let functions = rd.u32(at + 20).unwrap_or(0);
                let names = rd.u32(at + 24).unwrap_or(0);
                export_functions = Some(functions);
                let tables = (
                    rd.u32(at + 28).and_then(|r| image.offset(u64::from(r))),
                    rd.u32(at + 32).and_then(|r| image.offset(u64::from(r))),
                    rd.u32(at + 36).and_then(|r| image.offset(u64::from(r))),
                );
                if let (Some(function_table), Some(name_table), Some(ordinal_table)) = tables {
                    if u64::from(names) > MAX_EXPORTS {
                        problems.malformed(format!("the export table declares {names} names; only the first {MAX_EXPORTS} were read"));
                    }
                    for i in 0..u64::from(names).min(MAX_EXPORTS) {
                        let (Some(name_rva), Some(index)) = (rd.u32(name_table + i * 4), rd.u16(ordinal_table + i * 2)) else {
                            problems.malformed("the export name table runs past the end of the file");
                            break;
                        };
                        let Some(name) = image.cstr_at(u64::from(name_rva)) else { continue };
                        marks.see(&name, 0, false, name_table + i * 4);
                        let mut symbol = Symbol::new(name).with("ordinal", u64::from(base) + u64::from(index));
                        if let Some(address) = rd.u32(function_table + u64::from(index) * 4).filter(|_| u32::from(index) < functions) {
                            symbol = symbol.with("address", address);
                            // An address inside the export directory is a forwarder string.
                            if u64::from(address) >= rva
                                && u64::from(address) < rva + size
                                && let Some(target) = image.cstr_at(u64::from(address))
                            {
                                symbol = symbol.with("forwarder", target);
                            }
                        }
                        exports.push(symbol);
                    }
                } else if names > 0 {
                    problems.malformed("the export tables point outside the file; exported names were not read");
                }
            }
            None => problems.malformed("the export directory points outside the file"),
        }
    }

    // COFF symbols (MinGW and Go keep them): only looked at for toolchain markers.
    let mut coff_symbols = None;
    if let (Some(strings), Some(strings_size)) = (string_table, string_table_size)
        && symbol_count > 0
    {
        let mut index = 0;
        let mut named = 0u64;
        while index < symbol_count.min(MAX_COFF_SYMBOLS) {
            let at = symbol_table + index * 18;
            let Some(raw) = rd.bytes(at, 18) else { break };
            let name = if raw.starts_with(&[0, 0, 0, 0]) {
                rd.u32(at + 4).map(u64::from).filter(|o| *o < strings_size).and_then(|o| rd.cstr(strings + o, strings + strings_size))
            } else {
                raw.get(..8).map(text)
            };
            if let Some(name) = name.filter(|n| !n.is_empty()) {
                named += 1;
                // 32-bit Windows prefixes C symbols with an underscore.
                marks.see(&name, usize::from(machine == 0x14c), false, at);
            }
            index += 1 + u64::from(raw.get(17).copied().unwrap_or(0));
        }
        coff_symbols = Some(named);
    }

    // Debug directory.
    let mut debug_entries = Vec::new();
    let mut codeview: Option<(String, String, u32, u64)> = None;
    let mut repro = false;
    let mut cet = None;
    if let Some((rva, size)) = directory(6)
        && let Some(start) = image.offset(rva)
    {
        for i in 0..(size / 28).min(64) {
            let at = start + i * 28;
            let (Some(kind), Some(data_size), Some(pointer)) = (rd.u32(at + 12), rd.u32(at + 16), rd.u32(at + 24)) else { break };
            let pointer = u64::from(pointer);
            debug_entries.push(json!({
                "type": kind,
                "timestamp": rd.u32(at + 4),
                "size": data_size,
                "offset": pointer,
            }));
            match kind {
                // CodeView: "RSDS", a GUID, an age, then the path of the PDB.
                2 if rd.bytes(pointer, 4) == Some(b"RSDS") => {
                    if let (Some(guid), Some(age), Some(path)) =
                        (rd.bytes(pointer + 4, 16), rd.u32(pointer + 20), rd.cstr(pointer + 24, pointer + u64::from(data_size)))
                    {
                        codeview.get_or_insert((path, guid_text(guid), age, pointer));
                    }
                }
                16 => repro = true,
                20 => cet = rd.u32(pointer).map(|flags| (flags & 1 != 0, pointer)),
                _ => {}
            }
        }
    }

    // Load configuration: the fields exist only as far as the structure's own size reaches.
    let load_config = directory(10).and_then(|(rva, _)| image.offset(rva));
    let load_config_size = load_config.and_then(|at| rd.u32(at)).map(u64::from);
    let config_field = |offset: u64, wide_field: bool| -> Option<u64> {
        let (at, size) = (load_config?, load_config_size?);
        (offset + if wide_field { 8 } else { 4 } <= size).then(|| rd.word(at + offset, wide_field)).flatten()
    };
    let (cookie, seh_table, seh_count, guard_flags) = if wide {
        (config_field(88, true), config_field(96, true), config_field(104, true), config_field(144, false))
    } else {
        (config_field(60, false), config_field(64, false), config_field(68, false), config_field(88, false))
    };
    if directory(10).is_some() && load_config_size.is_none() {
        problems.malformed("the load configuration directory points outside the file; /GS and SafeSEH were not checked");
    }

    // CLR header (.NET).
    let clr = directory(14).and_then(|(rva, _)| {
        let at = image.offset(rva)?;
        Some((rd.u16(at + 4)?, rd.u16(at + 6)?, rd.u32(at + 16)?, at))
    });
    let il_only = clr.is_some_and(|(_, _, flags, _)| flags & 1 != 0);

    // Certificate table. Its "address" is a file offset, unlike every other directory.
    let security = directory(4);
    let security_valid = security.is_some_and(|(offset, size)| offset.checked_add(size).is_some_and(|end| end <= rd.len()));
    if security.is_some() && !security_valid {
        problems.malformed("the certificate table lies outside the file");
    }

    // Rich header: tool records the Microsoft linker leaves between the DOS stub and the PE header.
    let rich = rich_header(&rd, lfanew);

    // Overlay: bytes after everything the headers account for. The COFF symbol and string tables
    // and the certificate table normally sit there and are not counted as unexplained.
    let mut accounted = end_of_sections;
    if let (Some(strings), Some(size)) = (string_table, string_table_size)
        && symbol_table >= accounted
    {
        accounted = accounted.max((strings + size).min(rd.len()));
    }
    let overlay = (accounted < rd.len()).then(|| {
        let (offset, size) = (accounted, rd.len() - accounted);
        let certificate = security.filter(|(start, _)| security_valid && *start >= offset);
        let before = certificate.map_or(size, |(start, _)| start - offset);
        let after = certificate.map_or(0, |(start, length)| rd.len() - (start + length));
        // Signing pads the file to eight bytes before the certificate table.
        let unexplained = before > if certificate.is_some() { 7 } else { 0 };
        (offset, size, before, after, unexplained)
    });

    let library_names: Vec<String> = libraries.iter().map(|(name, _, _)| name.clone()).collect();
    let toolchain = lang::detect(&rd, &marks, &library_names, &regions, &[]);
    let go_build_id = if toolchain.has("Go") { lang::go_build_id(data) } else { None };
    let mingw = rich.is_none() && linker.0 == 2 && image.sections.iter().any(|s| s.name == ".CRT" || s.name == ".idata");

    // Facts.
    let directory_values: Vec<Value> = (0..u64::from(directory_count))
        .filter_map(|i| {
            let at = directories_at + i * 8;
            Some(json!({ "name": DIRECTORIES.get(usize::try_from(i).ok()?)?, "rva": rd.u32(at)?, "size": rd.u32(at + 4)? }))
        })
        .collect();
    out.fact(
        file,
        "binary.header",
        json!({
            "format": "pe",
            "pe32plus": wide,
            "arch": arch,
            "machine": machine,
            "bits": if wide { 64 } else { 32 },
            "endian": "little",
            "file_type": file_type,
            "subsystem": subsystem_name(subsystem),
            "subsystem_raw": subsystem,
            "characteristics": flag_names(u64::from(characteristics), CHARACTERISTICS),
            "dll_characteristics": flag_names(u64::from(dll_characteristics), DLL_CHARACTERISTICS),
            "dll_characteristics_raw": dll_characteristics,
            "timestamp": timestamp,
            "timestamp_is_hash": repro,
            "entry": entry,
            "image_base": image_base,
            "size_of_image": size_of_image,
            "size_of_headers": size_of_headers,
            "checksum": checksum,
            "linker_version": format!("{}.{}", linker.0, linker.1),
            "os_version": format!("{}.{}", os_version.0, os_version.1),
            "subsystem_version": format!("{}.{}", subsystem_version.0, subsystem_version.1),
            "go_build_id": go_build_id.as_ref().map(|(id, _)| id),
        }),
    );
    out.fact(
        file,
        "binary.pe",
        json!({
            "directories": directory_values,
            "certificate_table": security.filter(|_| security_valid).map(|(offset, size)| json!({ "offset": offset, "size": size })),
            "clr": clr.map(|(major, minor, flags, _)| json!({
                "runtime_version": format!("{major}.{minor}"),
                "flags": flags,
                "il_only": flags & 1 != 0,
                "requires_32bit": flags & 2 != 0,
                "strong_name_signed": flags & 8 != 0,
            })),
            "load_config": load_config_size.map(|size| json!({
                "size": size,
                "security_cookie": cookie,
                "se_handler_table": seh_table,
                "se_handler_count": seh_count,
                "guard_flags": guard_flags,
            })),
            "rich_header": rich.as_ref().map(|r| json!({ "offset": r.offset, "key": r.key, "entries": r.entries })),
            "export_name": export_name,
        }),
    );
    out.fact(
        file,
        "binary.sections",
        json!({ "sections": section_values, "total": section_count, "truncated": usize::from(section_count) > image.sections.len() }),
    );
    let library_values: Vec<Value> =
        libraries.iter().take(MAX_LIBRARIES).map(|(name, kind, count)| json!({ "name": name, "kind": kind, "functions": count })).collect();
    out.fact(file, "binary.libraries", json!({ "libraries": library_values, "truncated": libraries.len() > MAX_LIBRARIES }));
    let (import_total, export_total) = (imports.total, exports.total);
    if imports_read {
        out.fact(file, "binary.imports", symbols_json(imports, true));
    }
    let mut exports_value = symbols_json(exports, false);
    exports_value["functions"] = export_functions.into();
    out.fact(file, "binary.exports", exports_value);
    out.fact(
        file,
        "binary.symbols",
        json!({ "stripped": coff_symbols.is_none(), "coff_symbols": coff_symbols, "coff_symbol_entries": symbol_count }),
    );
    let mut debug_kinds = Vec::new();
    if codeview.is_some() {
        debug_kinds.push("pdb-reference");
    }
    if dwarf {
        debug_kinds.push("dwarf");
    }
    out.fact(
        file,
        "binary.debug",
        json!({
            "has_debug_info": dwarf,
            "kinds": debug_kinds,
            "pdb": codeview.as_ref().map(|(path, guid, age, _)| json!({ "path": path, "guid": guid, "age": age })),
            "entries": debug_entries,
            "debug_stripped_flag": characteristics & 0x200 != 0,
        }),
    );
    if let Some((offset, size, before, after, unexplained)) = overlay {
        out.fact(
            file,
            "binary.overlay",
            json!({
                "offset": offset,
                "size": size,
                "payload_size": before,
                "after_signature_size": after,
                "certificate_table_only": !unexplained && after == 0,
                "entropy": rd.bytes(offset, before).and_then(entropy),
            }),
        );
    }
    let mut toolchain_value = toolchain.to_json();
    toolchain_value["dotnet"] = clr.is_some().into();
    toolchain_value["rich_header"] = rich.is_some().into();
    toolchain_value["mingw_hint"] = mingw.into();
    out.fact(file, "binary.toolchain", toolchain_value);

    // Identity.
    out.finding(
        finding(Section::Identity, "binary.pe-identity", Confidence::Verified, Severity::Info)
            .param("format", format)
            .param("arch", arch_text)
            .param("file_type", file_type)
            .param("subsystem", subsystem_name(subsystem).map_or_else(|| format!("subsystem {subsystem}"), str::to_string))
            .evidence(Evidence::bytes(file, coff, 20, hex(rd.bytes(coff, 20).unwrap_or(&[]))))
            .evidence(Evidence::bytes(file, opt + 68, 2, subsystem)),
    );
    let timestamp_rule = match (repro, timestamp) {
        (true, _) => "binary.pe-timestamp-hash",
        (false, 0) => "binary.pe-timestamp-zero",
        _ => "binary.pe-timestamp",
    };
    out.finding(
        finding(Section::Identity, timestamp_rule, Confidence::Verified, Severity::Info)
            .param("raw", timestamp)
            .param("utc", utc(timestamp))
            .evidence(Evidence::bytes(file, coff + 4, 4, timestamp)),
    );
    if let Some((path, guid, age, at)) = &codeview {
        out.finding(
            finding(Section::Code, "binary.pe-pdb", Confidence::Verified, Severity::Info)
                .param("path", path.as_str())
                .param("guid", guid.as_str())
                .param("age", *age)
                .evidence(Evidence::bytes(file, *at, 24 + path.len() as u64, path.as_str())),
        );
    }
    if dwarf {
        out.finding(
            finding(Section::Code, "binary.debug-info", Confidence::Verified, Severity::Info)
                .param("label", "")
                .param("what", "DWARF sections")
                .evidence(Evidence::field(file, "section names", ".debug_*")),
        );
    }

    // Composition.
    if !libraries.is_empty() {
        let mut f = finding(Section::Composition, "binary.libraries", Confidence::Verified, Severity::Info)
            .param("label", "")
            .param("count", libraries.len())
            .param("sample", sample(&library_names, 8));
        for name in library_names.iter().take(8) {
            f = f.evidence(Evidence::field(file, "import table", name.as_str()));
        }
        out.finding(f);
    }
    if imports_read || export_total > 0 {
        crate::emit_symbols(file, out, None, None, Some((import_total, export_total)), "");
    }
    if let Some((major, minor, flags, at)) = clr {
        out.finding(
            finding(Section::Composition, "binary.pe-dotnet", Confidence::Verified, Severity::Info)
                .param("version", format!("{major}.{minor}"))
                .param(
                    "kind",
                    match (flags & 1 != 0, flags & 2 != 0) {
                        (true, false) => "IL only: the machine type in the PE header does not restrict where it runs",
                        (true, true) => "IL only, marked as requiring a 32-bit process",
                        (false, _) => "mixed native and IL code",
                    },
                )
                .evidence(Evidence::bytes(file, at, 20, format!("flags {}", hx(u64::from(flags))))),
        );
    }
    toolchain.emit(file, 0, "", out);
    if let Some(rich) = &rich {
        out.finding(
            finding(Section::Composition, "binary.pe-rich-header", Confidence::Derived, Severity::Info)
                .param("entries", rich.entries.len())
                .param("linker", format!("{}.{}", linker.0, linker.1))
                .evidence(Evidence::bytes(file, rich.offset, rich.length, "Rich")),
        );
    } else if mingw {
        out.finding(
            finding(Section::Composition, "binary.pe-mingw", Confidence::Heuristic, Severity::Info)
                .param("linker", format!("{}.{}", linker.0, linker.1))
                .evidence(Evidence::bytes(file, opt + 2, 2, format!("{}.{}", linker.0, linker.1))),
        );
    }

    // Structure and anomalies.
    if let Some((offset, size, before, after, unexplained)) = overlay {
        if unexplained {
            out.finding(
                finding(Section::Structure, "binary.pe-overlay", Confidence::Verified, Severity::Info)
                    .param("offset", offset)
                    .param("size", before)
                    .evidence(Evidence::bytes(file, offset, before, hex(rd.bytes(offset, before.min(16)).unwrap_or(&[])))),
            );
        }
        if after > 0 {
            out.finding(
                finding(Section::Anomalies, "binary.pe-data-after-signature", Confidence::Verified, Severity::Low)
                    .param("size", after)
                    .evidence(Evidence::bytes(
                        file,
                        offset + size - after,
                        after,
                        hex(rd.bytes(offset + size - after, after.min(16)).unwrap_or(&[])),
                    )),
            );
        }
    }
    if let Some(at) = upx {
        out.finding(
            finding(Section::Anomalies, "binary.packed-upx", Confidence::Heuristic, Severity::Low)
                .evidence(Evidence::bytes(file, at, 8, "UPX")),
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

    // Provenance: only whether a signature is attached. Verifying it is aa-windows' job.
    match security.filter(|_| security_valid) {
        Some((offset, size)) => out.finding(
            finding(Section::Provenance, "binary.pe-signature-present", Confidence::Verified, Severity::Info)
                .param("size", size)
                .evidence(Evidence::bytes(file, offset, size, "certificate table")),
        ),
        None => {
            out.finding(finding(Section::Provenance, "binary.pe-unsigned", Confidence::Verified, Severity::Low).evidence(Evidence::bytes(
                file,
                directories_at + 32,
                8,
                "security directory empty",
            )))
        }
    }

    // Hardening. A file without executable sections (resources only) has nothing to protect.
    let mut hardening = serde_json::Map::new();
    hardening.insert("applicable".into(), has_code.into());
    if has_code {
        let flags_evidence = || Evidence::bytes(file, opt + 70, 2, format!("DllCharacteristics = {}", hx(u64::from(dll_characteristics))));
        let hard = |rule: &str, confidence, severity| finding(Section::Hardening, rule, confidence, severity).evidence(flags_evidence());
        let flag = |bit: u16| dll_characteristics & bit != 0;

        // ASLR needs both the flag and relocations to move the image with.
        let relocs_stripped = characteristics & 1 != 0;
        let aslr = flag(DYNAMIC_BASE) && !(relocs_stripped && !is_dll);
        hardening.insert("aslr".into(), aslr.into());
        if aslr {
            out.finding(hard("binary.pe-aslr", Confidence::Verified, Severity::Info));
        } else if flag(DYNAMIC_BASE) {
            out.finding(hard("binary.pe-aslr-no-relocs", Confidence::Verified, Severity::Medium).evidence(Evidence::bytes(
                file,
                coff + 18,
                2,
                "IMAGE_FILE_RELOCS_STRIPPED",
            )));
        } else {
            out.finding(hard("binary.pe-no-aslr", Confidence::Verified, Severity::Medium));
        }
        if wide {
            hardening.insert("high_entropy_va".into(), flag(HIGH_ENTROPY_VA).into());
            let (rule, severity) = if flag(HIGH_ENTROPY_VA) {
                ("binary.pe-high-entropy-va", Severity::Info)
            } else {
                ("binary.pe-no-high-entropy-va", Severity::Low)
            };
            out.finding(hard(rule, Confidence::Verified, severity));
        }
        hardening.insert("dep".into(), flag(NX_COMPAT).into());
        let (rule, severity) = if flag(NX_COMPAT) { ("binary.pe-dep", Severity::Info) } else { ("binary.pe-no-dep", Severity::Medium) };
        out.finding(hard(rule, Confidence::Verified, severity));

        hardening.insert("force_integrity".into(), flag(FORCE_INTEGRITY).into());
        if flag(FORCE_INTEGRITY) {
            out.finding(hard("binary.pe-force-integrity", Confidence::Verified, Severity::Info));
        }
        hardening.insert("cet_compat".into(), cet.map(|(on, _)| on).into());
        if let Some((true, at)) = cet {
            out.finding(finding(Section::Hardening, "binary.pe-cet", Confidence::Verified, Severity::Info).evidence(Evidence::bytes(
                file,
                at,
                4,
                "IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT",
            )));
        }

        // The checks below concern native code the compiler instruments; IL-only .NET images
        // have none.
        if il_only {
            for key in ["cfg", "gs", "safe_seh"] {
                hardening.insert(key.into(), Value::Null);
            }
        } else {
            hardening.insert("cfg".into(), flag(GUARD_CF).into());
            let (rule, severity) = if flag(GUARD_CF) { ("binary.pe-cfg", Severity::Info) } else { ("binary.pe-no-cfg", Severity::Low) };
            out.finding(hard(rule, Confidence::Verified, severity));

            // /GS: the compiler registers the address of its stack cookie in the load configuration.
            let config_evidence = |what: String| match load_config {
                Some(at) => Evidence::bytes(file, at, load_config_size.unwrap_or(0).min(256), what),
                None => Evidence::bytes(file, directories_at + 80, 8, "load configuration directory empty"),
            };
            let safe_language = ["Go", "Rust"].into_iter().find(|l| toolchain.has(l));
            if directory(10).is_some() && load_config_size.is_none() {
                hardening.insert("gs".into(), Value::Null);
            } else if let Some(cookie) = cookie.filter(|c| *c != 0) {
                hardening.insert("gs".into(), true.into());
                out.finding(
                    finding(Section::Hardening, "binary.pe-gs", Confidence::Derived, Severity::Info)
                        .evidence(config_evidence(format!("SecurityCookie = {}", hx(cookie)))),
                );
            } else if let Some((symbol, at)) = &marks.canary {
                // MinGW uses the GCC stack protector, which shows up as a symbol instead.
                hardening.insert("gs".into(), true.into());
                out.finding(
                    finding(Section::Hardening, "binary.canary", Confidence::Derived, Severity::Info)
                        .param("symbol", symbol.as_str())
                        .param("label", "")
                        .evidence(Evidence::bytes(file, *at, 18, symbol.as_str())),
                );
            } else {
                hardening.insert("gs".into(), false.into());
                let f = match safe_language {
                    Some(language) => finding(Section::Hardening, "binary.no-canary-safe-language", Confidence::Heuristic, Severity::Info)
                        .param("language", language)
                        .param("label", ""),
                    None => finding(Section::Hardening, "binary.pe-no-gs", Confidence::Heuristic, Severity::Low),
                };
                out.finding(f.evidence(config_evidence("no SecurityCookie".into())));
            }

            // SafeSEH exists only on 32-bit x86; other architectures use table-based unwinding.
            if machine == 0x14c {
                if flag(NO_SEH) {
                    hardening.insert("safe_seh".into(), Value::Null);
                    out.finding(hard("binary.pe-no-seh", Confidence::Verified, Severity::Info));
                } else if directory(10).is_some() && load_config_size.is_none() {
                    hardening.insert("safe_seh".into(), Value::Null);
                } else if let (Some(table), Some(count)) = (seh_table.filter(|t| *t != 0), seh_count.filter(|c| *c != 0)) {
                    hardening.insert("safe_seh".into(), true.into());
                    out.finding(
                        finding(Section::Hardening, "binary.pe-safeseh", Confidence::Verified, Severity::Info)
                            .param("handlers", count)
                            .evidence(config_evidence(format!("SEHandlerTable = {}, SEHandlerCount = {count}", hx(table)))),
                    );
                } else {
                    hardening.insert("safe_seh".into(), false.into());
                    out.finding(
                        finding(Section::Hardening, "binary.pe-no-safeseh", Confidence::Verified, Severity::Low)
                            .evidence(config_evidence("no SEHandlerTable".into())),
                    );
                }
            }
        }

        hardening.insert("writable_executable".into(), (!wx.is_empty()).into());
        for section in wx.iter().take(4) {
            out.finding(
                finding(Section::Hardening, "binary.writable-executable", Confidence::Verified, Severity::Medium)
                    .param("what", format!("section {}", section.name))
                    .evidence(Evidence::bytes(file, section.at + 36, 4, hx(u64::from(section.flags)))),
            );
        }
    }
    hardening.insert("signature_present".into(), security_valid.into());
    out.fact(file, "binary.hardening", Value::Object(hardening));
    Some(())
}

/// A GUID in the usual text form: the first three fields are little-endian integers.
pub fn guid_text(bytes: &[u8]) -> String {
    let field = |range: std::ops::Range<usize>, reverse: bool| {
        let part = bytes.get(range).unwrap_or(&[]);
        if reverse {
            part.iter().rev().map(|b| format!("{b:02X}")).collect::<String>()
        } else {
            part.iter().map(|b| format!("{b:02X}")).collect()
        }
    };
    format!("{}-{}-{}-{}-{}", field(0..4, true), field(4..6, true), field(6..8, true), field(8..10, false), field(10..16, false))
}

pub struct Rich {
    pub offset: u64,
    pub length: u64,
    pub key: u32,
    /// `{ product_id, build, count }` per tool record, in file order.
    pub entries: Vec<Value>,
}

/// Decodes the Rich header: records XOR-ed with a key, between a `DanS` marker and `Rich`.
pub fn rich_header(rd: &Rd, lfanew: u64) -> Option<Rich> {
    let stub = rd.bytes(0, lfanew.min(4096))?;
    let end = memchr::memmem::find(stub, b"Rich")? as u64;
    let key = rd.u32(end + 4)?;
    let mut entries = Vec::new();
    let mut at = end;
    // Records are word pairs and the marker starts a pair, so walk back two words at a time until the marker; real headers have a few dozen records.
    for _ in 0..512 {
        at = at.checked_sub(8)?;
        let (a, b) = (rd.u32(at)? ^ key, rd.u32(at + 4)? ^ key);
        if a == 0x536e_6144 {
            break;
        }
        entries.push(json!({ "product_id": a >> 16, "build": a & 0xffff, "count": b }));
    }
    if rd.u32(at)? ^ key != 0x536e_6144 {
        return None;
    }
    // The three words after the marker are padding, read above as records; drop them.
    entries.retain(|e| !(e["product_id"] == 0 && e["build"] == 0 && e["count"] == 0));
    entries.reverse();
    Some(Rich { offset: at, length: end + 8 - at, key, entries })
}
