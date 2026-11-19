//! `resources.arsc`, the compiled resource table of an APK.
//!
//! Only the structure is indexed up front (packages, their string pools, and where each type
//! chunk lies); entries are read on demand, so a table with millions of entries costs little and
//! a count field can never drive an allocation.

use std::collections::BTreeMap;

use crate::axml::typed_value;
use crate::reader::{slice_at, u16_at, u32_at};
use crate::strpool::{CHUNK_STRING_POOL, StringPool};
use crate::xml::Value;

const CHUNK_TABLE: u16 = 0x0002;
const CHUNK_PACKAGE: u16 = 0x0200;
const CHUNK_TYPE: u16 = 0x0201;
const FLAG_SPARSE: u8 = 0x01;
const FLAG_OFFSET16: u8 = 0x02;
const ENTRY_COMPLEX: u16 = 0x0001;
const ENTRY_COMPACT: u16 = 0x0008;
const MAX_PACKAGES: usize = 64;
const MAX_TYPE_CHUNKS: usize = 200_000;
const MAX_REFERENCE_DEPTH: usize = 12;
/// Values returned for one resource id across configurations.
const MAX_CONFIGS: usize = 256;

struct TypeChunk {
    type_id: u8,
    flags: u8,
    entry_count: usize,
    /// Absolute offsets into the file.
    offsets_at: usize,
    entries_at: usize,
    end: usize,
    config: Config,
}

/// The part of a resource configuration the report shows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Config {
    pub is_default: bool,
    pub locale: Option<String>,
    pub density: Option<u16>,
    pub sdk: Option<u16>,
}

impl Config {
    /// `default`, or qualifiers such as `zh-rCN-480dpi-v26`. Qualifiers other than locale,
    /// density and SDK level are shown as `other`.
    pub fn describe(&self) -> String {
        if self.is_default {
            return "default".into();
        }
        let mut parts = Vec::new();
        if let Some(locale) = &self.locale {
            parts.push(locale.clone());
        }
        if let Some(density) = self.density {
            parts.push(format!("{density}dpi"));
        }
        if let Some(sdk) = self.sdk {
            parts.push(format!("v{sdk}"));
        }
        if parts.is_empty() { "other".into() } else { parts.join("-") }
    }
}

struct Package<'a> {
    id: u32,
    name: String,
    type_id_offset: u32,
    types: Option<StringPool<'a>>,
    keys: Option<StringPool<'a>>,
    chunks: Vec<TypeChunk>,
}

pub struct Table<'a> {
    data: &'a [u8],
    global: Option<StringPool<'a>>,
    packages: Vec<Package<'a>>,
    pub anomalies: Vec<String>,
    pub truncated: bool,
}

/// One entry as stored: its key and, for a simple entry, its value.
struct RawEntry {
    key: u32,
    /// `None` for a complex (bag) entry such as a style or an array.
    value: Option<(u8, u32)>,
}

/// What a resource id stands for.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved {
    /// `type/name`, e.g. `string/app_name`.
    pub name: Option<String>,
    /// The value in the default configuration, or the best other one; references are followed.
    pub value: Option<Value>,
    /// The configuration `value` was taken from.
    pub config: Option<String>,
    /// How many configurations define the resource.
    pub configs: usize,
}

impl<'a> Table<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if u16_at(data, 0)? != CHUNK_TABLE {
            return None;
        }
        let header_size = usize::from(u16_at(data, 2)?);
        let declared = u32_at(data, 4)? as usize;
        let mut table = Table { data, global: None, packages: Vec::new(), anomalies: Vec::new(), truncated: false };
        if declared != data.len() {
            table.anomalies.push(format!("table size field is {declared}, the file has {} bytes", data.len()));
        }
        let end = declared.min(data.len());
        let mut pos = header_size.max(8);
        while pos + 8 <= end {
            let Some((kind, header, size)) = chunk_header(data, pos, end) else {
                table.anomalies.push(format!("chunk at offset {pos} has an impossible size"));
                table.truncated = true;
                break;
            };
            match kind {
                CHUNK_STRING_POOL if table.global.is_none() => table.global = StringPool::parse(&data[pos..pos + size]),
                CHUNK_PACKAGE => {
                    if table.packages.len() >= MAX_PACKAGES {
                        table.truncated = true;
                        break;
                    }
                    if let Some(package) = parse_package(data, pos, header, size, &mut table.anomalies, &mut table.truncated) {
                        table.packages.push(package);
                    }
                }
                _ => {}
            }
            pos += size;
        }
        Some(table)
    }

    /// `(package id, package name)` of each package in the table.
    pub fn packages(&self) -> Vec<(u32, String)> {
        self.packages.iter().map(|p| (p.id, p.name.clone())).collect()
    }

    /// Number of type chunks (one per type and configuration).
    pub fn type_chunks(&self) -> usize {
        self.packages.iter().map(|p| p.chunks.len()).sum()
    }

    fn package(&self, id: u32) -> Option<&Package<'a>> {
        let package_id = id >> 24;
        self.packages.iter().find(|p| p.id == package_id)
    }

    fn entry(&self, chunk: &TypeChunk, index: usize) -> Option<RawEntry> {
        let data = self.data;
        let offset = if chunk.flags & FLAG_SPARSE != 0 {
            // Sorted (index, offset / 4) pairs.
            let (mut low, mut high) = (0usize, chunk.entry_count);
            let mut found = None;
            while low < high {
                let middle = low + (high - low) / 2;
                let at = chunk.offsets_at + middle * 4;
                let entry_index = usize::from(u16_at(data, at)?);
                match entry_index.cmp(&index) {
                    std::cmp::Ordering::Equal => {
                        found = Some(usize::from(u16_at(data, at + 2)?) * 4);
                        break;
                    }
                    std::cmp::Ordering::Less => low = middle + 1,
                    std::cmp::Ordering::Greater => high = middle,
                }
            }
            found?
        } else if index >= chunk.entry_count {
            return None;
        } else if chunk.flags & FLAG_OFFSET16 != 0 {
            let raw = u16_at(data, chunk.offsets_at + index * 2)?;
            if raw == 0xffff {
                return None;
            }
            usize::from(raw) * 4
        } else {
            let raw = u32_at(data, chunk.offsets_at + index * 4)?;
            if raw == 0xffff_ffff {
                return None;
            }
            raw as usize
        };
        let at = chunk.entries_at.checked_add(offset)?;
        if at + 8 > chunk.end {
            return None;
        }
        let size = u16_at(data, at)?;
        let flags = u16_at(data, at + 2)?;
        let third = u32_at(data, at + 4)?;
        if flags & ENTRY_COMPACT != 0 {
            return Some(RawEntry { key: u32::from(size), value: Some(((flags >> 8) as u8, third)) });
        }
        if flags & ENTRY_COMPLEX != 0 {
            return Some(RawEntry { key: third, value: None });
        }
        let value_at = at.checked_add(usize::from(size).max(8))?;
        if value_at + 8 > chunk.end {
            return None;
        }
        Some(RawEntry { key: third, value: Some((*data.get(value_at + 3)?, u32_at(data, value_at + 4)?)) })
    }

    fn type_name(&self, package: &Package, type_id: u8) -> Option<String> {
        let index = u32::from(type_id).checked_sub(1)?.checked_sub(package.type_id_offset)?;
        package.types.as_ref()?.get(index)
    }

    /// Every configuration's value for `id`, default first. The name is the same in all of them.
    fn lookup(&self, id: u32) -> (Option<String>, Vec<(Config, Option<Value>)>) {
        let Some(package) = self.package(id) else { return (None, Vec::new()) };
        let type_id = ((id >> 16) & 0xff) as u8;
        let index = (id & 0xffff) as usize;
        let mut name = None;
        let mut values = Vec::new();
        for chunk in package.chunks.iter().filter(|c| c.type_id == type_id) {
            let Some(entry) = self.entry(chunk, index) else { continue };
            if name.is_none() {
                let key = package.keys.as_ref().and_then(|k| k.get(entry.key));
                name = match (self.type_name(package, type_id), key) {
                    (Some(kind), Some(key)) => Some(format!("{kind}/{key}")),
                    _ => None,
                };
            }
            let value = entry.value.map(|(data_type, data)| typed_value(data_type, data, self.global.as_ref()));
            values.push((chunk.config.clone(), value));
            if values.len() >= MAX_CONFIGS {
                break;
            }
        }
        values.sort_by_key(|(config, _)| !config.is_default);
        (name, values)
    }

    /// Resolves `id` to its name and a representative value: the default configuration's, or
    /// when there is none (icons often have only density-specific files) the densest one's.
    /// References to other resources are followed, a bounded number of times.
    pub fn resolve(&self, id: u32) -> Option<Resolved> {
        let (name, values) = self.lookup(id);
        if name.is_none() && values.is_empty() {
            return None;
        }
        let configs = values.len();
        let mut picked = values
            .iter()
            .find(|(config, _)| config.is_default)
            .or_else(|| values.iter().max_by_key(|(config, _)| (config.density.filter(|d| *d < 0xfffe).unwrap_or(0), config.sdk)))
            .cloned();
        let mut depth = 0;
        while let Some((_, Some(Value::Ref(next)))) = &picked {
            depth += 1;
            if depth > MAX_REFERENCE_DEPTH || *next == id || *next == 0 {
                break;
            }
            let (_, next_values) = self.lookup(*next);
            let better = next_values
                .iter()
                .find(|(config, _)| config.is_default)
                .or_else(|| next_values.iter().max_by_key(|(config, _)| (config.density.filter(|d| *d < 0xfffe).unwrap_or(0), config.sdk)))
                .cloned();
            match better {
                Some(found) => picked = Some(found),
                None => break,
            }
        }
        let (config, value) = match picked {
            Some((config, value)) => (Some(config.describe()), value),
            None => (None, None),
        };
        Some(Resolved { name, value, config, configs })
    }

    /// The default-configuration values of the string resources called `names`.
    pub fn find_strings(&self, names: &[&str]) -> BTreeMap<String, String> {
        let mut found = BTreeMap::new();
        for package in &self.packages {
            let (Some(keys), Some(types)) = (&package.keys, &package.types) else { continue };
            let Some(string_type) = (0..types.count().min(256) as u32).find(|i| types.get(*i).as_deref() == Some("string")) else {
                continue;
            };
            let type_id = (string_type + 1 + package.type_id_offset) as u8;
            let mut wanted: BTreeMap<u32, String> = BTreeMap::new();
            for index in 0..keys.count() as u32 {
                if let Some(key) = keys.get(index)
                    && names.contains(&key.as_str())
                {
                    wanted.insert(index, key);
                }
            }
            if wanted.is_empty() {
                continue;
            }
            for chunk in package.chunks.iter().filter(|c| c.type_id == type_id && c.config.is_default) {
                let sparse = chunk.flags & FLAG_SPARSE != 0;
                for slot in 0..chunk.entry_count {
                    let index = if sparse {
                        match u16_at(self.data, chunk.offsets_at + slot * 4) {
                            Some(index) => usize::from(index),
                            None => break,
                        }
                    } else {
                        slot
                    };
                    let Some(entry) = self.entry(chunk, index) else { continue };
                    if let Some(name) = wanted.get(&entry.key)
                        && let Some((data_type, data)) = entry.value
                        && let Value::Str(text) = typed_value(data_type, data, self.global.as_ref())
                    {
                        found.entry(name.clone()).or_insert(text);
                    }
                }
            }
        }
        found
    }
}

fn chunk_header(data: &[u8], pos: usize, end: usize) -> Option<(u16, usize, usize)> {
    let kind = u16_at(data, pos)?;
    let header = usize::from(u16_at(data, pos + 2)?);
    let size = u32_at(data, pos + 4)? as usize;
    if header < 8 || size < header || size > end.checked_sub(pos)? {
        return None;
    }
    Some((kind, header, size))
}

fn parse_package<'a>(
    data: &'a [u8],
    start: usize,
    header: usize,
    size: usize,
    anomalies: &mut Vec<String>,
    truncated: &mut bool,
) -> Option<Package<'a>> {
    let end = start + size;
    let id = u32_at(data, start + 8)?;
    let name_units: Vec<u16> = slice_at(data, start + 12, 256)?
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|u| *u != 0)
        .collect();
    let type_strings = u32_at(data, start + 268)? as usize;
    let key_strings = u32_at(data, start + 276)? as usize;
    // Older tables have a 284-byte header without the type id offset.
    let type_id_offset = if header >= 288 { u32_at(data, start + 284).unwrap_or(0) } else { 0 };
    let mut package = Package {
        id,
        name: String::from_utf16_lossy(&name_units),
        type_id_offset: if type_id_offset < 256 { type_id_offset } else { 0 },
        types: None,
        keys: None,
        chunks: Vec::new(),
    };
    let mut pos = start + header;
    while pos + 8 <= end {
        let Some((kind, chunk_header_size, chunk_size)) = chunk_header(data, pos, end) else {
            anomalies.push(format!("chunk at offset {pos} has an impossible size"));
            *truncated = true;
            break;
        };
        match kind {
            CHUNK_STRING_POOL => {
                let pool = StringPool::parse(&data[pos..pos + chunk_size]);
                let relative = pos - start;
                if relative == type_strings || (package.types.is_none() && relative != key_strings) {
                    package.types = pool;
                } else if relative == key_strings || package.keys.is_none() {
                    package.keys = pool;
                }
            }
            CHUNK_TYPE => {
                if package.chunks.len() >= MAX_TYPE_CHUNKS {
                    *truncated = true;
                    break;
                }
                if let Some(chunk) = parse_type(data, pos, chunk_header_size, chunk_size) {
                    package.chunks.push(chunk);
                } else {
                    anomalies.push(format!("type chunk at offset {pos} is malformed"));
                }
            }
            _ => {}
        }
        pos += chunk_size;
    }
    Some(package)
}

fn parse_type(data: &[u8], start: usize, header: usize, size: usize) -> Option<TypeChunk> {
    let end = start + size;
    let type_id = *data.get(start + 8)?;
    let flags = *data.get(start + 9)?;
    let declared = u32_at(data, start + 12)? as usize;
    let entries_start = u32_at(data, start + 16)? as usize;
    if type_id == 0 || entries_start < header || entries_start > size {
        return None;
    }
    let stride = if flags & FLAG_SPARSE == 0 && flags & FLAG_OFFSET16 != 0 { 2 } else { 4 };
    let entry_count = declared.min((entries_start - header) / stride);
    let config_size = (u32_at(data, start + 20)? as usize).min(header.saturating_sub(20));
    let config_bytes = slice_at(data, start + 20, config_size)?;
    Some(TypeChunk {
        type_id,
        flags,
        entry_count,
        offsets_at: start + header,
        entries_at: start + entries_start,
        end,
        config: parse_config(config_bytes),
    })
}

fn parse_config(bytes: &[u8]) -> Config {
    let is_default = bytes.iter().skip(4).all(|b| *b == 0);
    if is_default {
        return Config { is_default: true, ..Config::default() };
    }
    let two = |at: usize| -> Option<String> {
        let pair = bytes.get(at..at + 2)?;
        (pair[0].is_ascii_lowercase() || pair[0].is_ascii_uppercase())
            .then(|| pair.iter().filter(|b| b.is_ascii_alphabetic()).map(|b| *b as char).collect())
    };
    let locale = match (two(8), two(10)) {
        (Some(language), Some(country)) => Some(format!("{language}-r{country}")),
        (Some(language), None) => Some(language),
        _ => None,
    };
    let density = u16_at(bytes, 14).filter(|d| *d != 0);
    let sdk = u16_at(bytes, 24).filter(|s| *s != 0);
    Config { is_default: false, locale, density, sdk }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::strpool::tests::build_pool;

    fn chunk(kind: u16, header: &[u8], body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&((8 + header.len()) as u16).to_le_bytes());
        out.extend_from_slice(&((8 + header.len() + body.len()) as u32).to_le_bytes());
        out.extend_from_slice(header);
        out.extend_from_slice(body);
        out
    }

    fn entry(key: u32, data_type: u8, data: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&key.to_le_bytes());
        out.extend_from_slice(&[8, 0, 0, data_type]);
        out.extend_from_slice(&data.to_le_bytes());
        out
    }

    fn type_chunk(type_id: u8, config: &[u8; 28], entries: &[Option<Vec<u8>>]) -> Vec<u8> {
        let mut offsets = Vec::new();
        let mut body = Vec::new();
        for e in entries {
            match e {
                Some(e) => {
                    offsets.extend_from_slice(&(body.len() as u32).to_le_bytes());
                    body.extend_from_slice(e);
                }
                None => offsets.extend_from_slice(&0xffff_ffffu32.to_le_bytes()),
            }
        }
        let header_len = 8 + 12 + 28;
        let mut header = vec![type_id, 0, 0, 0];
        header.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        header.extend_from_slice(&((header_len + offsets.len()) as u32).to_le_bytes());
        header.extend_from_slice(config);
        offsets.extend(body);
        chunk(CHUNK_TYPE, &header, &offsets)
    }

    /// A table with package 0x7f `com.example`: `string/app_name` = "Example" (default) and
    /// "示例" (zh), `string/alias` -> app_name, `string/google_app_id`, `mipmap/icon` (480dpi only).
    pub fn sample() -> Vec<u8> {
        let global = build_pool(&["Example", "示例", "1:123:android:abc", "res/mipmap-xxhdpi/icon.png"], true);
        let types = build_pool(&["string", "mipmap"], true);
        let keys = build_pool(&["app_name", "alias", "google_app_id", "icon"], true);
        let default = {
            let mut c = [0u8; 28];
            c[0] = 28;
            c
        };
        let mut zh = default;
        zh[8] = b'z';
        zh[9] = b'h';
        let mut dense = default;
        dense[14..16].copy_from_slice(&480u16.to_le_bytes());
        let mut body = Vec::new();
        body.extend(&types);
        body.extend(&keys);
        body.extend(type_chunk(1, &default, &[Some(entry(0, 3, 0)), Some(entry(1, 1, 0x7f01_0000)), Some(entry(2, 3, 2))]));
        body.extend(type_chunk(1, &zh, &[Some(entry(0, 3, 1)), None, None]));
        body.extend(type_chunk(2, &dense, &[Some(entry(3, 3, 3))]));
        let mut header = Vec::new();
        header.extend_from_slice(&0x7fu32.to_le_bytes());
        let mut name = [0u8; 256];
        for (i, u) in "com.example".encode_utf16().enumerate() {
            name[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        header.extend_from_slice(&name);
        header.extend_from_slice(&288u32.to_le_bytes()); // type strings
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&((288 + types.len()) as u32).to_le_bytes()); // key strings
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes()); // type id offset
        let package = chunk(CHUNK_PACKAGE, &header, &body);
        let mut table_body = global;
        table_body.extend(package);
        chunk(CHUNK_TABLE, &1u32.to_le_bytes(), &table_body)
    }

    #[test]
    fn resolves_names_values_and_references() {
        let data = sample();
        let table = Table::parse(&data).expect("table");
        assert!(table.anomalies.is_empty(), "{:?}", table.anomalies);
        assert_eq!(table.packages(), vec![(0x7f, "com.example".to_string())]);
        let app_name = table.resolve(0x7f01_0000).expect("app_name");
        assert_eq!(app_name.name.as_deref(), Some("string/app_name"));
        assert_eq!(app_name.value, Some(Value::Str("Example".into())));
        assert_eq!(app_name.config.as_deref(), Some("default"));
        assert_eq!(app_name.configs, 2);
        let alias = table.resolve(0x7f01_0001).expect("alias");
        assert_eq!(alias.name.as_deref(), Some("string/alias"));
        assert_eq!(alias.value, Some(Value::Str("Example".into())));
        let icon = table.resolve(0x7f02_0000).expect("icon");
        assert_eq!(icon.name.as_deref(), Some("mipmap/icon"));
        assert_eq!(icon.value, Some(Value::Str("res/mipmap-xxhdpi/icon.png".into())));
        assert_eq!(icon.config.as_deref(), Some("480dpi"));
        assert!(table.resolve(0x7f01_0009).is_none());
        assert!(table.resolve(0x0101_0000).is_none());
        assert_eq!(table.find_strings(&["google_app_id", "missing"]).get("google_app_id").map(String::as_str), Some("1:123:android:abc"));
    }

    #[test]
    fn a_reference_cycle_ends() {
        let mut data = sample();
        // Point `alias` at itself.
        let needle = 0x7f01_0000u32.to_le_bytes();
        let at = data.windows(8).position(|w| w[..4] == [8, 0, 0, 1] && w[4..] == needle).expect("reference");
        data[at + 4..at + 8].copy_from_slice(&0x7f01_0001u32.to_le_bytes());
        let table = Table::parse(&data).expect("table");
        let alias = table.resolve(0x7f01_0001).expect("alias");
        assert_eq!(alias.value, Some(Value::Ref(0x7f01_0001)));
    }

    #[test]
    fn truncations_and_corruption_do_not_panic() {
        let data = sample();
        for cut in 0..data.len() {
            if let Some(table) = Table::parse(&data[..cut]) {
                let _ = table.resolve(0x7f01_0000);
                let _ = table.resolve(0x7f02_0000);
                let _ = table.find_strings(&["google_app_id"]);
            }
        }
        for i in 0..data.len() {
            for v in [0x00, 0xff, 0x7f] {
                let mut bad = data.clone();
                bad[i] = v;
                if let Some(table) = Table::parse(&bad) {
                    let _ = table.resolve(0x7f01_0000);
                    let _ = table.resolve(0x7f01_0001);
                    let _ = table.resolve(0x7f02_0000);
                    let _ = table.find_strings(&["google_app_id", "app_name"]);
                }
            }
        }
    }

    #[test]
    fn huge_entry_count_costs_nothing() {
        let mut data = sample();
        // The first type chunk's entry count.
        let at = data.windows(4).position(|w| w == [0x01, 0x02, 0x30, 0x00]).expect("type chunk") + 12;
        data[at..at + 4].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        let table = Table::parse(&data).expect("table");
        assert_eq!(table.resolve(0x7f01_0000).and_then(|r| r.value), Some(Value::Str("Example".into())));
        let _ = table.find_strings(&["google_app_id"]);
    }
}
