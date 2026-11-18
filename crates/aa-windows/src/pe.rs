//! A small, bounds-checked PE reader: just what the Windows analyzer needs.
//!
//! Every offset and count comes from the file and is checked before use; nothing here indexes
//! a slice directly with a value read from the input.

use sha2::Digest;

/// Reads `N` bytes at `offset`, if they are all there.
fn array<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    data.get(offset..offset.checked_add(N)?)?.try_into().ok()
}

pub fn u16_at(data: &[u8], offset: usize) -> Option<u16> {
    array(data, offset).map(u16::from_le_bytes)
}

pub fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    array(data, offset).map(u32::from_le_bytes)
}

pub fn u64_at(data: &[u8], offset: usize) -> Option<u64> {
    array(data, offset).map(u64::from_le_bytes)
}

/// Index of the data directories this crate reads.
pub const DIR_EXPORT: usize = 0;
pub const DIR_IMPORT: usize = 1;
pub const DIR_RESOURCE: usize = 2;
pub const DIR_SECURITY: usize = 4;
pub const DIR_TLS: usize = 9;
pub const DIR_DELAY_IMPORT: usize = 13;
pub const DIR_CLR: usize = 14;

pub const SCN_CNT_CODE: u32 = 0x20;
pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;

pub const SUBSYSTEM_NATIVE: u16 = 1;

/// Caps on what is collected from one file.
const MAX_IMPORT_DLLS: usize = 1024;
const MAX_IMPORT_FUNCTIONS: usize = 20_000;
const MAX_RESOURCES: usize = 20_000;

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_size: u32,
    pub raw_pointer: u32,
    pub characteristics: u32,
    /// File offset of this section's header.
    pub header_offset: usize,
}

impl Section {
    pub fn contains_rva(&self, rva: u32) -> bool {
        let span = self.virtual_size.max(self.raw_size);
        rva >= self.virtual_address && (rva - self.virtual_address) < span
    }

    pub fn executable(&self) -> bool {
        self.characteristics & SCN_MEM_EXECUTE != 0
    }

    pub fn writable(&self) -> bool {
        self.characteristics & SCN_MEM_WRITE != 0
    }
}

#[derive(Debug, Clone)]
pub struct Pe<'a> {
    pub data: &'a [u8],
    pub pe_offset: usize,
    pub machine: u16,
    pub timestamp: u32,
    pub characteristics: u16,
    pub is64: bool,
    pub entry_point: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub checksum: u32,
    pub checksum_offset: usize,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    /// `(rva or file offset, size)` of each data directory present.
    pub directories: Vec<(u32, u32)>,
    /// File offset of the first data directory entry.
    pub directories_offset: usize,
    pub sections: Vec<Section>,
    /// Sections the header declares; larger than `sections.len()` when the table is cut short.
    pub declared_sections: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportFunction {
    pub name: Option<String>,
    pub ordinal: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct ImportDll {
    pub name: String,
    pub delayed: bool,
    pub functions: Vec<ImportFunction>,
}

#[derive(Debug, Clone, Default)]
pub struct Imports {
    pub dlls: Vec<ImportDll>,
    pub truncated: bool,
}

/// A resource type, name or language: a number or a string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResId {
    Id(u32),
    Name(String),
}

impl ResId {
    pub fn id(&self) -> Option<u32> {
        match self {
            ResId::Id(id) => Some(*id),
            ResId::Name(_) => None,
        }
    }
}

impl std::fmt::Display for ResId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResId::Id(id) => write!(f, "{id}"),
            ResId::Name(name) => write!(f, "{name}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Resource {
    pub kind: ResId,
    pub name: ResId,
    pub language: u32,
    pub size: u32,
    /// File offset of the data, when the RVA maps into the file and the data fits.
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct Resources {
    pub entries: Vec<Resource>,
    pub truncated: bool,
}

pub const RT_ICON: u32 = 3;
pub const RT_GROUP_ICON: u32 = 14;
pub const RT_VERSION: u32 = 16;
pub const RT_MANIFEST: u32 = 24;

/// The usual name of a numeric resource type.
pub fn resource_type_name(id: u32) -> Option<&'static str> {
    Some(match id {
        1 => "CURSOR",
        2 => "BITMAP",
        3 => "ICON",
        4 => "MENU",
        5 => "DIALOG",
        6 => "STRING",
        7 => "FONTDIR",
        8 => "FONT",
        9 => "ACCELERATOR",
        10 => "RCDATA",
        11 => "MESSAGETABLE",
        12 => "GROUP_CURSOR",
        14 => "GROUP_ICON",
        16 => "VERSION",
        17 => "DLGINCLUDE",
        19 => "PLUGPLAY",
        20 => "VXD",
        21 => "ANICURSOR",
        22 => "ANIICON",
        23 => "HTML",
        24 => "MANIFEST",
        _ => return None,
    })
}

/// True when `data` starts like a PE image (an MZ header pointing at a PE signature).
pub fn looks_like_pe(data: &[u8]) -> bool {
    data.starts_with(b"MZ")
        && u32_at(data, 0x3c).is_some_and(|e| data.get(e as usize..(e as usize).saturating_add(4)) == Some(b"PE\0\0".as_slice()))
}

impl<'a> Pe<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Pe<'a>, String> {
        if !data.starts_with(b"MZ") {
            return Err("no MZ header".into());
        }
        let pe_offset = u32_at(data, 0x3c).ok_or("file ends inside the DOS header")? as usize;
        if data.get(pe_offset..pe_offset.saturating_add(4)) != Some(b"PE\0\0".as_slice()) {
            return Err("no PE signature where the DOS header points".into());
        }
        let coff = pe_offset + 4;
        let short = "file ends inside the PE headers";
        let machine = u16_at(data, coff).ok_or(short)?;
        let declared_sections = u16_at(data, coff + 2).ok_or(short)?;
        let timestamp = u32_at(data, coff + 4).ok_or(short)?;
        let optional_size = u16_at(data, coff + 16).ok_or(short)? as usize;
        let characteristics = u16_at(data, coff + 18).ok_or(short)?;
        let opt = coff + 20;
        let magic = u16_at(data, opt).ok_or(short)?;
        let is64 = match magic {
            0x10b => false,
            0x20b => true,
            other => return Err(format!("unknown optional header magic {other:#x}")),
        };
        let entry_point = u32_at(data, opt + 16).ok_or(short)?;
        let image_base = if is64 { u64_at(data, opt + 24).ok_or(short)? } else { u64::from(u32_at(data, opt + 28).ok_or(short)?) };
        let section_alignment = u32_at(data, opt + 32).ok_or(short)?;
        let file_alignment = u32_at(data, opt + 36).ok_or(short)?;
        let size_of_image = u32_at(data, opt + 56).ok_or(short)?;
        let size_of_headers = u32_at(data, opt + 60).ok_or(short)?;
        let checksum_offset = opt + 64;
        let checksum = u32_at(data, checksum_offset).ok_or(short)?;
        let subsystem = u16_at(data, opt + 68).ok_or(short)?;
        let dll_characteristics = u16_at(data, opt + 70).ok_or(short)?;
        let count_offset = opt + if is64 { 108 } else { 92 };
        let directories_offset = count_offset + 4;
        // The count is capped both by the format (16) and by the room the optional header has.
        let declared_dirs = u32_at(data, count_offset).ok_or(short)? as usize;
        let room = (opt + optional_size).saturating_sub(directories_offset) / 8;
        let mut directories = Vec::new();
        for index in 0..declared_dirs.min(16).min(room) {
            let at = directories_offset + index * 8;
            match (u32_at(data, at), u32_at(data, at + 4)) {
                (Some(address), Some(size)) => directories.push((address, size)),
                _ => break,
            }
        }
        let table = opt + optional_size;
        let mut sections = Vec::new();
        for index in 0..declared_sections as usize {
            let at = table + index * 40;
            let Some(header) = data.get(at..at + 40) else { break };
            let raw_name = &header[..8];
            let end = raw_name.iter().position(|&b| b == 0).unwrap_or(8);
            sections.push(Section {
                name: String::from_utf8_lossy(&raw_name[..end]).into_owned(),
                virtual_size: u32_at(header, 8).unwrap_or(0),
                virtual_address: u32_at(header, 12).unwrap_or(0),
                raw_size: u32_at(header, 16).unwrap_or(0),
                raw_pointer: u32_at(header, 20).unwrap_or(0),
                characteristics: u32_at(header, 36).unwrap_or(0),
                header_offset: at,
            });
        }
        Ok(Pe {
            data,
            pe_offset,
            machine,
            timestamp,
            characteristics,
            is64,
            entry_point,
            image_base,
            section_alignment,
            file_alignment,
            size_of_image,
            size_of_headers,
            checksum,
            checksum_offset,
            subsystem,
            dll_characteristics,
            directories,
            directories_offset,
            sections,
            declared_sections,
        })
    }

    pub fn is_dll(&self) -> bool {
        self.characteristics & 0x2000 != 0
    }

    /// A data directory that is present and not empty.
    pub fn directory(&self, index: usize) -> Option<(u32, u32)> {
        self.directories.get(index).copied().filter(|&(address, size)| address != 0 && size != 0)
    }

    pub fn section_of(&self, rva: u32) -> Option<&Section> {
        self.sections.iter().find(|s| s.contains_rva(rva))
    }

    /// File offset of `rva`, when it lies in the headers or in a section's stored bytes.
    pub fn offset_of(&self, rva: u32) -> Option<usize> {
        for section in &self.sections {
            if section.contains_rva(rva) {
                let delta = rva - section.virtual_address;
                if delta >= section.raw_size {
                    return None;
                }
                let offset = (section.raw_pointer as usize).checked_add(delta as usize)?;
                return (offset < self.data.len()).then_some(offset);
            }
        }
        // Before the first section the image maps the headers one to one.
        let first = self.sections.iter().map(|s| s.virtual_address).min().unwrap_or(u32::MAX);
        (rva < first && (rva as usize) < self.data.len()).then_some(rva as usize)
    }

    /// `length` bytes at `rva`, when they are all stored in the file.
    pub fn slice(&self, rva: u32, length: usize) -> Option<&'a [u8]> {
        let offset = self.offset_of(rva)?;
        self.data.get(offset..offset.checked_add(length)?)
    }

    /// The NUL-terminated string at `rva`, at most `max` bytes.
    pub fn cstr(&self, rva: u32, max: usize) -> Option<String> {
        let offset = self.offset_of(rva)?;
        let window = self.data.get(offset..)?;
        let window = &window[..window.len().min(max)];
        let end = window.iter().position(|&b| b == 0)?;
        Some(String::from_utf8_lossy(&window[..end]).into_owned())
    }

    /// End of the last section's stored bytes: where an overlay would begin.
    pub fn end_of_image(&self) -> usize {
        let mut end = (self.size_of_headers as usize).min(self.data.len());
        for section in &self.sections {
            if section.raw_size > 0 {
                end = end.max((section.raw_pointer as usize).saturating_add(section.raw_size as usize));
            }
        }
        end.min(self.data.len())
    }

    /// The certificate table as `(file offset, size)`, when it lies inside the file.
    pub fn certificate_table(&self) -> Option<(usize, usize)> {
        let (offset, size) = self.directory(DIR_SECURITY)?;
        let (offset, size) = (offset as usize, size as usize);
        (offset.checked_add(size)? <= self.data.len()).then_some((offset, size))
    }

    /// Data after the image that is not the certificate table, as `(offset, length)`.
    pub fn overlay(&self) -> Option<(usize, usize)> {
        let start = self.end_of_image();
        let end = match self.certificate_table() {
            Some((offset, _)) if offset >= start => offset,
            _ => self.data.len(),
        };
        (end > start).then(|| (start, end - start))
    }

    /// The checksum the optional header should hold, computed over the whole file.
    pub fn compute_checksum(&self) -> u32 {
        let mut sum: u64 = 0;
        let skip = self.checksum_offset;
        let mut chunks = self.data.chunks_exact(2);
        let mut position = 0usize;
        for pair in &mut chunks {
            if position != skip && position != skip + 2 {
                sum += u64::from(u16::from_le_bytes([pair[0], pair[1]]));
                sum = (sum & 0xffff) + (sum >> 16);
            }
            position += 2;
        }
        if let [last] = chunks.remainder() {
            sum += u64::from(*last);
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum = (sum & 0xffff) + (sum >> 16);
        (sum as u32).wrapping_add(self.data.len() as u32)
    }

    /// Feeds `hasher` the bytes Authenticode signs: the whole file except the checksum, the
    /// certificate-table directory entry, and the certificate table itself.
    ///
    /// Returns `None` when the header has no room for a certificate-table entry.
    pub fn authenticode_digest<D: Digest>(&self) -> Option<Vec<u8>> {
        let entry = self.directories_offset.checked_add(DIR_SECURITY * 8)?;
        if self.directories.len() <= DIR_SECURITY || entry + 8 > self.data.len() {
            return None;
        }
        let (table_start, table_end) = match self.certificate_table() {
            Some((offset, size)) => (offset, offset + size),
            None => (self.data.len(), self.data.len()),
        };
        if table_start < entry + 8 {
            return None;
        }
        let mut hasher = D::new();
        hasher.update(self.data.get(..self.checksum_offset)?);
        hasher.update(self.data.get(self.checksum_offset + 4..entry)?);
        hasher.update(self.data.get(entry + 8..table_start)?);
        hasher.update(self.data.get(table_end..)?);
        Some(hasher.finalize().to_vec())
    }

    /// The import table and the delay-load import table.
    pub fn imports(&self) -> Imports {
        let mut imports = Imports::default();
        let mut functions = 0usize;
        if let Some((rva, _)) = self.directory(DIR_IMPORT) {
            for index in 0..MAX_IMPORT_DLLS + 1 {
                let Some(descriptor) = self.slice(rva.wrapping_add(index as u32 * 20), 20) else { break };
                let lookup = u32_at(descriptor, 0).unwrap_or(0);
                let name_rva = u32_at(descriptor, 12).unwrap_or(0);
                let address_table = u32_at(descriptor, 16).unwrap_or(0);
                if name_rva == 0 && address_table == 0 {
                    break;
                }
                if index == MAX_IMPORT_DLLS {
                    imports.truncated = true;
                    break;
                }
                let Some(name) = self.cstr(name_rva, 256) else { continue };
                // The lookup table survives binding; fall back to the address table.
                let thunks = if lookup != 0 { lookup } else { address_table };
                let list = self.thunks(thunks, &mut functions, &mut imports.truncated);
                imports.dlls.push(ImportDll { name, delayed: false, functions: list });
            }
        }
        if let Some((rva, _)) = self.directory(DIR_DELAY_IMPORT) {
            for index in 0..MAX_IMPORT_DLLS + 1 {
                let Some(descriptor) = self.slice(rva.wrapping_add(index as u32 * 32), 32) else { break };
                let attributes = u32_at(descriptor, 0).unwrap_or(0);
                let mut name_rva = u32_at(descriptor, 4).unwrap_or(0);
                let mut names = u32_at(descriptor, 16).unwrap_or(0);
                if name_rva == 0 {
                    break;
                }
                if index == MAX_IMPORT_DLLS {
                    imports.truncated = true;
                    break;
                }
                // Old 32-bit images store virtual addresses instead of RVAs (attribute bit 0 clear).
                if attributes & 1 == 0 && !self.is64 {
                    let base = self.image_base as u32;
                    name_rva = name_rva.wrapping_sub(base);
                    names = names.wrapping_sub(base);
                }
                let Some(name) = self.cstr(name_rva, 256) else { continue };
                let list = self.thunks(names, &mut functions, &mut imports.truncated);
                imports.dlls.push(ImportDll { name, delayed: true, functions: list });
            }
        }
        imports
    }

    fn thunks(&self, rva: u32, total: &mut usize, truncated: &mut bool) -> Vec<ImportFunction> {
        let mut list = Vec::new();
        if rva == 0 {
            return list;
        }
        let width = if self.is64 { 8 } else { 4 };
        for index in 0u32.. {
            let Some(raw) = self.slice(rva.wrapping_add(index.wrapping_mul(width)), width as usize) else { break };
            let value = if self.is64 { u64_at(raw, 0).unwrap_or(0) } else { u64::from(u32_at(raw, 0).unwrap_or(0)) };
            if value == 0 {
                break;
            }
            if *total >= MAX_IMPORT_FUNCTIONS {
                *truncated = true;
                break;
            }
            *total += 1;
            let by_ordinal = if self.is64 { value >> 63 != 0 } else { value >> 31 != 0 };
            if by_ordinal {
                list.push(ImportFunction { name: None, ordinal: Some(value as u16) });
            } else {
                // Hint (2 bytes), then the name.
                let name = self.cstr((value as u32).wrapping_add(2), 512).filter(|n| !n.is_empty());
                list.push(ImportFunction { name, ordinal: None });
            }
        }
        list
    }

    /// The name the export directory gives the image (its original DLL name).
    pub fn export_name(&self) -> Option<String> {
        let (rva, _) = self.directory(DIR_EXPORT)?;
        let header = self.slice(rva, 40)?;
        self.cstr(u32_at(header, 12)?, 256).filter(|n| !n.is_empty())
    }

    /// Number of TLS callbacks, when a TLS directory with a readable callback array exists.
    pub fn tls_callbacks(&self) -> Option<usize> {
        let (rva, _) = self.directory(DIR_TLS)?;
        let callbacks_va = if self.is64 { u64_at(self.slice(rva, 40)?, 24)? } else { u64::from(u32_at(self.slice(rva, 24)?, 12)?) };
        if callbacks_va == 0 {
            return Some(0);
        }
        let mut rva = u32::try_from(callbacks_va.checked_sub(self.image_base)?).ok()?;
        let width = if self.is64 { 8 } else { 4 };
        let mut count = 0;
        while count < 64 {
            let raw = self.slice(rva, width as usize)?;
            let value = if self.is64 { u64_at(raw, 0)? } else { u64::from(u32_at(raw, 0)?) };
            if value == 0 {
                break;
            }
            count += 1;
            rva = rva.checked_add(width)?;
        }
        Some(count)
    }

    /// Every leaf of the resource tree (type / name / language).
    pub fn resources(&self) -> Resources {
        let mut out = Resources::default();
        let Some((rva, size)) = self.directory(DIR_RESOURCE) else { return out };
        let Some(base) = self.offset_of(rva) else { return out };
        let end = base.saturating_add(size as usize).min(self.data.len());
        let Some(area) = self.data.get(base..end) else { return out };
        let mut visited = 0usize;
        for (kind, type_offset) in self.resource_entries(area, 0, &mut visited) {
            let Some(type_dir) = type_offset.strip_dir() else { continue };
            for (name, name_offset) in self.resource_entries(area, type_dir, &mut visited) {
                let Some(name_dir) = name_offset.strip_dir() else { continue };
                for (language, leaf) in self.resource_entries(area, name_dir, &mut visited) {
                    let Target::Data(at) = leaf else { continue };
                    let (Some(data_rva), Some(length)) = (u32_at(area, at), u32_at(area, at + 4)) else { continue };
                    if out.entries.len() >= MAX_RESOURCES {
                        out.truncated = true;
                        return out;
                    }
                    let offset = self.slice(data_rva, length as usize).and_then(|_| self.offset_of(data_rva));
                    out.entries.push(Resource {
                        kind: kind.clone(),
                        name: name.clone(),
                        language: language.id().unwrap_or(0),
                        size: length,
                        offset,
                    });
                }
            }
        }
        if visited >= MAX_RESOURCES * 2 {
            out.truncated = true;
        }
        out
    }

    fn resource_entries(&self, area: &[u8], dir: usize, visited: &mut usize) -> Vec<(ResId, Target)> {
        let mut entries = Vec::new();
        let (Some(named), Some(ids)) = (u16_at(area, dir + 12), u16_at(area, dir + 14)) else { return entries };
        for index in 0..(named as usize + ids as usize) {
            if *visited >= MAX_RESOURCES * 2 {
                break;
            }
            *visited += 1;
            let at = dir + 16 + index * 8;
            let (Some(id), Some(target)) = (u32_at(area, at), u32_at(area, at + 4)) else { break };
            let id = if id & 0x8000_0000 != 0 {
                let at = (id & 0x7fff_ffff) as usize;
                let Some(length) = u16_at(area, at) else { continue };
                let Some(raw) = area.get(at + 2..at + 2 + length as usize * 2) else { continue };
                let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
                ResId::Name(String::from_utf16_lossy(&units))
            } else {
                ResId::Id(id)
            };
            let target = if target & 0x8000_0000 != 0 { Target::Dir((target & 0x7fff_ffff) as usize) } else { Target::Data(target as usize) };
            entries.push((id, target));
        }
        entries
    }
}

#[derive(Clone, Copy)]
enum Target {
    Dir(usize),
    Data(usize),
}

impl Target {
    fn strip_dir(self) -> Option<usize> {
        match self {
            Target::Dir(offset) => Some(offset),
            Target::Data(_) => None,
        }
    }
}

/// Shannon entropy of `data`, 0.0 to 8.0.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let total = data.len() as f64;
    let mut bits = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            bits -= p * p.log2();
        }
    }
    bits
}
