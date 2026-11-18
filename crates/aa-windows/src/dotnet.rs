//! .NET assemblies: the CLR header and the ECMA-335 metadata tables.

use std::collections::BTreeSet;

use serde_json::{Value, json};
use sha1::{Digest, Sha1};

use crate::pe::{DIR_CLR, Pe, u16_at, u32_at, u64_at};

const MAX_LISTED: usize = 300;
const MAX_PINVOKES: usize = 2000;
/// Rows of one table that are walked.
const MAX_ROWS: u32 = 2_000_000;

#[derive(Debug, Clone, Default)]
pub struct DotNet {
    pub runtime_version: Option<String>,
    pub il_only: bool,
    pub requires_32bit: bool,
    pub prefers_32bit: bool,
    pub strong_name_flag: bool,
    /// Size of the strong-name signature blob; 0 when there is none.
    pub strong_name_signature_size: u32,
    pub native_entry_point: bool,
    pub module: Option<String>,
    pub mvid: Option<String>,
    pub assembly_name: Option<String>,
    pub assembly_version: Option<String>,
    pub culture: Option<String>,
    pub public_key_token: Option<String>,
    pub target_framework: Option<String>,
    /// `(name, version, public key token)`.
    pub references: Vec<(String, String, Option<String>)>,
    pub references_truncated: bool,
    pub types: Option<u32>,
    pub methods: Option<u32>,
    pub namespaces: Vec<String>,
    pub namespaces_truncated: bool,
    /// `(library, function)` of each P/Invoke.
    pub pinvokes: Vec<(String, String)>,
    pub pinvokes_truncated: bool,
    pub resources: Vec<String>,
    /// `(tool, marker)` of each obfuscator hint.
    pub obfuscator_hints: Vec<(String, String)>,
    /// Why the metadata tables could not be read, when they could not.
    pub metadata_error: Option<String>,
}

impl DotNet {
    pub fn json(&self) -> Value {
        json!({
            "runtime_version": self.runtime_version,
            "flags": {
                "il_only": self.il_only,
                "requires_32bit": self.requires_32bit,
                "prefers_32bit": self.prefers_32bit,
                "strong_name_signed": self.strong_name_flag,
                "native_entry_point": self.native_entry_point,
            },
            "strong_name_signature_size": self.strong_name_signature_size,
            "module": self.module,
            "mvid": self.mvid,
            "assembly": {
                "name": self.assembly_name,
                "version": self.assembly_version,
                "culture": self.culture,
                "public_key_token": self.public_key_token,
            },
            "target_framework": self.target_framework,
            "references": self.references.iter().map(|(n, v, t)| json!({ "name": n, "version": v, "public_key_token": t })).collect::<Vec<_>>(),
            "references_truncated": self.references_truncated,
            "types": self.types,
            "methods": self.methods,
            "namespaces": self.namespaces,
            "namespaces_truncated": self.namespaces_truncated,
            "pinvokes": self.pinvokes.iter().map(|(l, f)| json!({ "library": l, "function": f })).collect::<Vec<_>>(),
            "pinvokes_truncated": self.pinvokes_truncated,
            "resources": self.resources,
            "obfuscator_hints": self.obfuscator_hints.iter().map(|(t, m)| json!({ "tool": t, "marker": m })).collect::<Vec<_>>(),
            "metadata_error": self.metadata_error,
        })
    }
}

/// Column kinds of the metadata tables.
#[derive(Clone, Copy)]
enum Col {
    U16,
    U32,
    Str,
    Guid,
    Blob,
    Idx(usize),
    Coded(&'static [usize], u32),
}

/// A table number no file uses, for the unused slots of coded indexes.
const NONE: usize = 63;

const TYPE_DEF_OR_REF: Col = Col::Coded(&[2, 1, 27], 2);
const HAS_CONSTANT: Col = Col::Coded(&[4, 8, 23], 2);
const HAS_CUSTOM_ATTRIBUTE: Col = Col::Coded(&[6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43], 5);
const HAS_FIELD_MARSHAL: Col = Col::Coded(&[4, 8], 1);
const HAS_DECL_SECURITY: Col = Col::Coded(&[2, 6, 32], 2);
const MEMBER_REF_PARENT: Col = Col::Coded(&[2, 1, 26, 6, 27], 3);
const HAS_SEMANTICS: Col = Col::Coded(&[20, 23], 1);
const METHOD_DEF_OR_REF: Col = Col::Coded(&[6, 10], 1);
const MEMBER_FORWARDED: Col = Col::Coded(&[4, 6], 1);
const IMPLEMENTATION: Col = Col::Coded(&[38, 35, 39], 2);
const CUSTOM_ATTRIBUTE_TYPE: Col = Col::Coded(&[NONE, NONE, 6, 10, NONE], 3);
const RESOLUTION_SCOPE: Col = Col::Coded(&[0, 26, 35, 1], 2);
const TYPE_OR_METHOD_DEF: Col = Col::Coded(&[2, 6], 1);

use Col::{Blob, Guid, Idx, Str, U16, U32};

/// Columns of tables 0 to 44, as ECMA-335 II.22 defines them.
const SCHEMA: [&[Col]; 45] = [
    &[U16, Str, Guid, Guid, Guid],                        // 0 Module
    &[RESOLUTION_SCOPE, Str, Str],                        // 1 TypeRef
    &[U32, Str, Str, TYPE_DEF_OR_REF, Idx(4), Idx(6)],    // 2 TypeDef
    &[Idx(4)],                                            // 3 FieldPtr
    &[U16, Str, Blob],                                    // 4 Field
    &[Idx(6)],                                            // 5 MethodPtr
    &[U32, U16, U16, Str, Blob, Idx(8)],                  // 6 MethodDef
    &[Idx(8)],                                            // 7 ParamPtr
    &[U16, U16, Str],                                     // 8 Param
    &[Idx(2), TYPE_DEF_OR_REF],                           // 9 InterfaceImpl
    &[MEMBER_REF_PARENT, Str, Blob],                      // 10 MemberRef
    &[U16, HAS_CONSTANT, Blob],                           // 11 Constant
    &[HAS_CUSTOM_ATTRIBUTE, CUSTOM_ATTRIBUTE_TYPE, Blob], // 12 CustomAttribute
    &[HAS_FIELD_MARSHAL, Blob],                           // 13 FieldMarshal
    &[U16, HAS_DECL_SECURITY, Blob],                      // 14 DeclSecurity
    &[U16, U32, Idx(2)],                                  // 15 ClassLayout
    &[U32, Idx(4)],                                       // 16 FieldLayout
    &[Blob],                                              // 17 StandAloneSig
    &[Idx(2), Idx(20)],                                   // 18 EventMap
    &[Idx(20)],                                           // 19 EventPtr
    &[U16, Str, TYPE_DEF_OR_REF],                         // 20 Event
    &[Idx(2), Idx(23)],                                   // 21 PropertyMap
    &[Idx(23)],                                           // 22 PropertyPtr
    &[U16, Str, Blob],                                    // 23 Property
    &[U16, Idx(6), HAS_SEMANTICS],                        // 24 MethodSemantics
    &[Idx(2), METHOD_DEF_OR_REF, METHOD_DEF_OR_REF],      // 25 MethodImpl
    &[Str],                                               // 26 ModuleRef
    &[Blob],                                              // 27 TypeSpec
    &[U16, MEMBER_FORWARDED, Str, Idx(26)],               // 28 ImplMap
    &[U32, Idx(4)],                                       // 29 FieldRVA
    &[U32, U32],                                          // 30 ENCLog
    &[U32],                                               // 31 ENCMap
    &[U32, U16, U16, U16, U16, U32, Blob, Str, Str],      // 32 Assembly
    &[U32],                                               // 33 AssemblyProcessor
    &[U32, U32, U32],                                     // 34 AssemblyOS
    &[U16, U16, U16, U16, U32, Blob, Str, Str, Blob],     // 35 AssemblyRef
    &[U32, Idx(35)],                                      // 36 AssemblyRefProcessor
    &[U32, U32, U32, Idx(35)],                            // 37 AssemblyRefOS
    &[U32, Str, Blob],                                    // 38 File
    &[U32, U32, Str, Str, IMPLEMENTATION],                // 39 ExportedType
    &[U32, U32, Str, IMPLEMENTATION],                     // 40 ManifestResource
    &[Idx(2), Idx(2)],                                    // 41 NestedClass
    &[U16, U16, TYPE_OR_METHOD_DEF, Str],                 // 42 GenericParam
    &[METHOD_DEF_OR_REF, Blob],                           // 43 MethodSpec
    &[Idx(42), TYPE_DEF_OR_REF],                          // 44 GenericParamConstraint
];

struct Tables<'a> {
    data: &'a [u8],
    rows: [u32; 64],
    /// Offset of each table inside `data`.
    starts: [usize; 45],
    wide_strings: bool,
    wide_guids: bool,
    wide_blobs: bool,
    strings: &'a [u8],
    blobs: &'a [u8],
    guids: &'a [u8],
}

impl<'a> Tables<'a> {
    fn width(&self, column: Col) -> usize {
        match column {
            U16 => 2,
            U32 => 4,
            Str => 2 + 2 * usize::from(self.wide_strings),
            Guid => 2 + 2 * usize::from(self.wide_guids),
            Blob => 2 + 2 * usize::from(self.wide_blobs),
            Idx(table) => 2 + 2 * usize::from(self.rows[table] > 0xffff),
            Col::Coded(tables, bits) => {
                let largest = tables.iter().map(|&t| self.rows[t]).max().unwrap_or(0);
                2 + 2 * usize::from(largest >= (1u32 << (16 - bits)))
            }
        }
    }

    fn row_size(&self, table: usize) -> usize {
        SCHEMA[table].iter().map(|&c| self.width(c)).sum()
    }

    /// The raw value of `column` in `row` (zero-based) of `table`.
    fn cell(&self, table: usize, row: u32, column: usize) -> Option<u32> {
        if row >= self.rows[table] {
            return None;
        }
        let schema = SCHEMA[table];
        let before: usize = schema.get(..column)?.iter().map(|&c| self.width(c)).sum();
        let at = self.starts[table].checked_add((row as usize).checked_mul(self.row_size(table))?)?.checked_add(before)?;
        match self.width(*schema.get(column)?) {
            2 => u16_at(self.data, at).map(u32::from),
            _ => u32_at(self.data, at),
        }
    }

    fn string(&self, index: u32) -> Option<String> {
        let rest = self.strings.get(index as usize..)?;
        let rest = &rest[..rest.len().min(1024)];
        let end = rest.iter().position(|&b| b == 0)?;
        Some(String::from_utf8_lossy(&rest[..end]).into_owned())
    }

    fn string_cell(&self, table: usize, row: u32, column: usize) -> Option<String> {
        self.string(self.cell(table, row, column)?)
    }

    fn blob(&self, index: u32) -> Option<&'a [u8]> {
        let rest = self.blobs.get(index as usize..)?;
        let (length, header) = compressed_length(rest)?;
        rest.get(header..header.checked_add(length)?)
    }

    fn guid(&self, index: u32) -> Option<String> {
        let at = (index as usize).checked_sub(1)?.checked_mul(16)?;
        let g = self.guids.get(at..at + 16)?;
        Some(format!(
            "{:08x}-{:04x}-{:04x}-{}-{}",
            u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
            u16::from_le_bytes([g[4], g[5]]),
            u16::from_le_bytes([g[6], g[7]]),
            hex::encode(&g[8..10]),
            hex::encode(&g[10..16])
        ))
    }
}

/// An ECMA-335 compressed unsigned integer: `(value, bytes used)`.
fn compressed_length(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()? as usize;
    if first & 0x80 == 0 {
        Some((first, 1))
    } else if first & 0xc0 == 0x80 {
        Some((((first & 0x3f) << 8) | *data.get(1)? as usize, 2))
    } else if first & 0xe0 == 0xc0 {
        Some((((first & 0x1f) << 24) | (*data.get(1)? as usize) << 16 | (*data.get(2)? as usize) << 8 | *data.get(3)? as usize, 4))
    } else {
        None
    }
}

/// The last eight bytes of the SHA-1 of a public key, reversed: the public key token.
fn public_key_token(key: &[u8]) -> String {
    let digest = Sha1::digest(key);
    let mut token: Vec<u8> = digest[12..].to_vec();
    token.reverse();
    hex::encode(token)
}

/// Marker type names obfuscators leave behind.
const OBFUSCATOR_MARKERS: &[(&str, &str)] = &[
    ("ConfusedByAttribute", "ConfuserEx"),
    ("DotfuscatorAttribute", "Dotfuscator"),
    ("PoweredByAttribute", "SmartAssembly"),
    ("ObfuscatedByGoliath", "Goliath.NET"),
    ("YanoAttribute", "Yano"),
    ("BabelObfuscatorAttribute", "Babel"),
    ("BabelAttribute", "Babel"),
    ("ProcessedByXenocode", "Xenocode"),
    ("ProtectedWithCryptoObfuscatorAttribute", "Crypto Obfuscator"),
    ("ZYXDNGuarder", "DNGuard"),
    ("EMyPID_8234_", "MPRESS"),
    ("ObfuscatedByAgileDotNetAttribute", "Agile.NET"),
    ("SecureTeam.Attributes", ".NET Reactor / Agile.NET"),
    ("NineRays.Obfuscator", "Spices.Net"),
    ("ProtectedByAttribute", "unknown protector"),
    ("VMProtect", "VMProtect"),
    ("Eazfuscator", "Eazfuscator.NET"),
    ("KoiVM", "KoiVM"),
    ("SuppressIldasmAttribute", "SuppressIldasm (blocks ildasm; also used without obfuscation)"),
];

/// Reads the CLR header and metadata. `None` when the image has no CLR header.
pub fn analyze(pe: &Pe) -> Option<DotNet> {
    let (rva, _) = pe.directory(DIR_CLR)?;
    let header = pe.slice(rva, 72)?;
    let flags = u32_at(header, 16)?;
    let mut out = DotNet {
        il_only: flags & 0x1 != 0,
        requires_32bit: flags & 0x2 != 0 && flags & 0x2_0000 == 0,
        prefers_32bit: flags & 0x2_0000 != 0,
        strong_name_flag: flags & 0x8 != 0,
        native_entry_point: flags & 0x10 != 0,
        strong_name_signature_size: if u32_at(header, 32)? != 0 { u32_at(header, 36)? } else { 0 },
        ..DotNet::default()
    };
    let (metadata_rva, metadata_size) = (u32_at(header, 8)?, u32_at(header, 12)?);
    match pe.slice(metadata_rva, metadata_size as usize) {
        Some(metadata) => {
            if let Err(error) = read_metadata(metadata, &mut out) {
                out.metadata_error = Some(error);
            }
        }
        None => out.metadata_error = Some("the metadata lies outside the file".into()),
    }
    Some(out)
}

fn read_metadata(metadata: &[u8], out: &mut DotNet) -> Result<(), String> {
    if u32_at(metadata, 0) != Some(0x424a_5342) {
        return Err("no BSJB metadata signature".into());
    }
    let version_length = u32_at(metadata, 12).ok_or("metadata header cut short")? as usize;
    let version = metadata.get(16..16usize.saturating_add(version_length)).ok_or("metadata version string cut short")?;
    let end = version.iter().position(|&b| b == 0).unwrap_or(version.len());
    out.runtime_version = Some(String::from_utf8_lossy(&version[..end]).into_owned());
    let mut at = 16 + version_length + 2;
    let stream_count = u16_at(metadata, at).ok_or("metadata header cut short")?;
    at += 2;
    let empty: &[u8] = &[];
    let (mut tables, mut strings, mut blobs, mut guids) = (None, empty, empty, empty);
    for _ in 0..stream_count.min(32) {
        let offset = u32_at(metadata, at).ok_or("stream header cut short")? as usize;
        let size = u32_at(metadata, at + 4).ok_or("stream header cut short")? as usize;
        let name_bytes = metadata.get(at + 8..(at + 8 + 32).min(metadata.len())).ok_or("stream header cut short")?;
        let name_length = name_bytes.iter().position(|&b| b == 0).ok_or("stream name not terminated")?;
        let name = &name_bytes[..name_length];
        at += 8 + (name_length + 1).div_ceil(4) * 4;
        let Some(stream) = metadata.get(offset..offset.saturating_add(size)) else { continue };
        match name {
            b"#~" | b"#-" => tables = Some(stream),
            b"#Strings" => strings = stream,
            b"#Blob" => blobs = stream,
            b"#GUID" => guids = stream,
            _ => {}
        }
    }
    let data = tables.ok_or("no metadata table stream")?;
    let heap_sizes = *data.get(6).ok_or("table stream cut short")?;
    let valid = u64_at(data, 8).ok_or("table stream cut short")?;
    let mut rows = [0u32; 64];
    let mut at = 24;
    for (table, slot) in rows.iter_mut().enumerate() {
        if valid >> table & 1 == 1 {
            *slot = u32_at(data, at).ok_or("row counts cut short")?;
            at += 4;
        }
    }
    let mut t = Tables {
        data,
        rows,
        starts: [0; 45],
        wide_strings: heap_sizes & 1 != 0,
        wide_guids: heap_sizes & 2 != 0,
        wide_blobs: heap_sizes & 4 != 0,
        strings,
        blobs,
        guids,
    };
    for (table, &count) in rows.iter().enumerate().take(SCHEMA.len()) {
        t.starts[table] = at;
        at = at.checked_add(t.row_size(table).checked_mul(count as usize).ok_or("table size overflow")?).ok_or("table size overflow")?;
    }
    if at > data.len() {
        return Err("the metadata tables run past the end of their stream".into());
    }

    out.module = t.string_cell(0, 0, 1);
    out.mvid = t.cell(0, 0, 2).and_then(|g| t.guid(g));
    if rows[32] > 0 {
        let part = |column| t.cell(32, 0, column).unwrap_or(0);
        out.assembly_version = Some(format!("{}.{}.{}.{}", part(1), part(2), part(3), part(4)));
        out.assembly_name = t.string_cell(32, 0, 7);
        out.culture = t.string_cell(32, 0, 8).filter(|c| !c.is_empty());
        out.public_key_token = t.cell(32, 0, 6).and_then(|b| t.blob(b)).filter(|k| !k.is_empty()).map(public_key_token);
    }
    for row in 0..rows[35].min(MAX_ROWS) {
        if out.references.len() >= MAX_LISTED {
            out.references_truncated = true;
            break;
        }
        let part = |column| t.cell(35, row, column).unwrap_or(0);
        let version = format!("{}.{}.{}.{}", part(0), part(1), part(2), part(3));
        let Some(name) = t.string_cell(35, row, 6) else { continue };
        // The blob is a full public key when flag 1 is set, otherwise the 8-byte token.
        let token = t
            .cell(35, row, 5)
            .and_then(|b| t.blob(b))
            .filter(|k| !k.is_empty())
            .map(|key| if part(4) & 1 != 0 { public_key_token(key) } else { hex::encode(key) });
        out.references.push((name, version, token));
    }
    out.types = Some(rows[2]);
    out.methods = Some(rows[6]);

    let mut namespaces = BTreeSet::new();
    let mut hints: BTreeSet<(String, String)> = BTreeSet::new();
    let mut note_name = |namespace: &str, name: &str| {
        for (marker, tool) in OBFUSCATOR_MARKERS {
            if name.contains(marker) || namespace.contains(marker) {
                hints.insert((tool.to_string(), if namespace.is_empty() { name.to_string() } else { format!("{namespace}.{name}") }));
            }
        }
    };
    let mut unreadable_names = 0u32;
    let type_rows = rows[2].min(MAX_ROWS);
    for row in 0..type_rows {
        let name = t.string_cell(2, row, 1).unwrap_or_default();
        let namespace = t.string_cell(2, row, 2).unwrap_or_default();
        note_name(&namespace, &name);
        // Renaming obfuscators use control characters, private-use code points or lone symbols.
        if name.chars().any(|c| c.is_control() || ('\u{e000}'..='\u{f8ff}').contains(&c) || ('\u{200b}'..='\u{202e}').contains(&c)) {
            unreadable_names += 1;
        }
        if !namespace.is_empty() {
            namespaces.insert(namespace);
        }
    }
    for row in 0..rows[1].min(MAX_ROWS) {
        let name = t.string_cell(1, row, 1).unwrap_or_default();
        let namespace = t.string_cell(1, row, 2).unwrap_or_default();
        note_name(&namespace, &name);
    }
    if type_rows >= 10 && unreadable_names * 5 >= type_rows {
        hints.insert((
            "renaming obfuscator".to_string(),
            format!("{unreadable_names} of {type_rows} type names contain unprintable characters"),
        ));
    }
    out.namespaces_truncated = namespaces.len() > MAX_LISTED;
    out.namespaces = namespaces.into_iter().take(MAX_LISTED).collect();
    out.obfuscator_hints = hints.into_iter().take(32).collect();

    let mut pinvokes = BTreeSet::new();
    for row in 0..rows[28].min(MAX_ROWS) {
        let (Some(function), Some(scope)) = (t.string_cell(28, row, 2), t.cell(28, row, 3)) else { continue };
        let Some(library) = scope.checked_sub(1).and_then(|r| t.string_cell(26, r, 0)) else { continue };
        // An empty import name means "same as the method": look the method up.
        let function = if function.is_empty() {
            t.cell(28, row, 1)
                .filter(|coded| coded & 1 == 1)
                .and_then(|coded| t.string_cell(6, (coded >> 1).checked_sub(1)?, 3))
                .unwrap_or_default()
        } else {
            function
        };
        pinvokes.insert((library, function));
    }
    out.pinvokes_truncated = pinvokes.len() > MAX_PINVOKES;
    out.pinvokes = pinvokes.into_iter().take(MAX_PINVOKES).collect();

    for row in 0..rows[40].min(MAX_LISTED as u32) {
        if let Some(name) = t.string_cell(40, row, 2) {
            out.resources.push(name);
        }
    }
    out.resources.sort();

    // [assembly: TargetFramework("...")]: a custom attribute on the Assembly row whose
    // constructor belongs to a TypeRef named TargetFrameworkAttribute.
    for row in 0..rows[12].min(MAX_ROWS) {
        let (Some(parent), Some(kind)) = (t.cell(12, row, 0), t.cell(12, row, 1)) else { continue };
        // HasCustomAttribute tag 14 is Assembly; CustomAttributeType tag 3 is MemberRef.
        if parent & 0x1f != 14 || kind & 0x7 != 3 {
            continue;
        }
        let Some(member) = (kind >> 3).checked_sub(1) else { continue };
        let Some(class) = t.cell(10, member, 0) else { continue };
        // MemberRefParent tag 1 is TypeRef.
        if class & 0x7 != 1 {
            continue;
        }
        let Some(type_ref) = (class >> 3).checked_sub(1) else { continue };
        if t.string_cell(1, type_ref, 1).as_deref() != Some("TargetFrameworkAttribute") {
            continue;
        }
        let Some(value) = t.cell(12, row, 2).and_then(|b| t.blob(b)) else { continue };
        // Prolog 0x0001, then a length-prefixed UTF-8 string.
        if value.starts_with(&[1, 0])
            && let Some((length, header)) = compressed_length(&value[2..])
            && let Some(text) = value.get(2 + header..2 + header + length)
        {
            out.target_framework = Some(String::from_utf8_lossy(text).into_owned());
            break;
        }
    }
    Ok(())
}
