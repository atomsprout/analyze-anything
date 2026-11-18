//! Android binary XML (AXML), the format of `AndroidManifest.xml` and compiled resources in an APK.
//!
//! The decoder follows what the platform's `ResXMLTree` accepts rather than what `aapt` writes:
//! malware manifests routinely carry a wrong file type, oversized headers, extra chunks, attribute
//! records of unusual size and names that are empty or misleading. Each of those is tolerated and
//! noted in [`Document::anomalies`].

use crate::attr_ids;
use crate::reader::{slice_at, u16_at, u32_at};
use crate::strpool::{CHUNK_STRING_POOL, StringPool};
use crate::xml::{ANDROID_NS, Attr, Document, Element, Value};

const CHUNK_XML: u16 = 0x0003;
const CHUNK_RESOURCE_MAP: u16 = 0x0180;
const CHUNK_START_NAMESPACE: u16 = 0x0100;
const CHUNK_END_NAMESPACE: u16 = 0x0101;
const CHUNK_START_ELEMENT: u16 = 0x0102;
const CHUNK_END_ELEMENT: u16 = 0x0103;
const CHUNK_CDATA: u16 = 0x0104;

const NO_INDEX: u32 = 0xffff_ffff;
const MAX_DEPTH: usize = 128;
const MAX_ELEMENTS: usize = 200_000;
const MAX_ATTRS: usize = 4096;
const MAX_TEXT: usize = 1 << 20;

/// True when `data` starts like a binary XML file. Hostile files alter the type, so the check
/// is on the shape of the header: a small header size and a plausible first chunk.
pub fn looks_like_axml(data: &[u8]) -> bool {
    let (Some(kind), Some(header_size)) = (u16_at(data, 0), u16_at(data, 2)) else { return false };
    if kind == CHUNK_XML && header_size == 8 {
        return true;
    }
    // A text file starts with `<` or a byte-order mark; anything else with a string pool
    // right after a short header is treated as binary XML.
    let header_size = usize::from(header_size);
    (8..=64).contains(&header_size) && u16_at(data, header_size) == Some(CHUNK_STRING_POOL) && data.first() != Some(&b'<')
}

/// Decodes a typed value (`Res_value`).
pub fn typed_value(data_type: u8, data: u32, pool: Option<&StringPool>) -> Value {
    match data_type {
        0x00 => Value::Null,
        0x01 => Value::Ref(data),
        0x02 => Value::AttrRef(data),
        0x03 => pool.and_then(|p| p.get(data)).map(Value::Str).unwrap_or(Value::Null),
        0x04 => Value::Float(f32::from_bits(data)),
        0x07 => Value::Ref(data), // dynamic reference
        0x10 => Value::Int(data as i32),
        0x11 => Value::Hex(data),
        0x12 => Value::Bool(data != 0),
        _ => Value::Other { data_type, data },
    }
}

/// Decodes a binary XML file. Never panics; a file that is not AXML gives a document without a root.
pub fn parse(data: &[u8]) -> Document {
    let mut doc = Document::default();
    let (Some(kind), Some(header_size), Some(declared_size)) = (u16_at(data, 0), u16_at(data, 2), u32_at(data, 4)) else {
        doc.anomalies.push("file is shorter than a chunk header".into());
        return doc;
    };
    if kind != CHUNK_XML {
        doc.anomalies.push(format!("file type is 0x{kind:04x}, not 0x0003"));
    }
    if header_size != 8 {
        doc.anomalies.push(format!("file header size is {header_size}, not 8"));
    }
    let declared_size = declared_size as usize;
    if declared_size != data.len() {
        doc.anomalies.push(format!("file size field is {declared_size}, the file has {} bytes", data.len()));
    }
    let end = declared_size.min(data.len());

    let mut pool: Option<StringPool> = None;
    let mut resource_map: &[u8] = &[];
    // Elements whose end has not been seen yet.
    let mut stack: Vec<Element> = Vec::new();
    // (prefix, uri) pairs in scope are not needed: attributes carry the namespace URI itself.
    let mut elements = 0usize;
    let mut unknown_chunks = 0usize;
    let mut pos = usize::from(header_size).max(8);

    while pos + 8 <= end {
        let (Some(chunk_type), Some(chunk_header), Some(chunk_size)) = (u16_at(data, pos), u16_at(data, pos + 2), u32_at(data, pos + 4))
        else {
            break;
        };
        let (chunk_header, chunk_size) = (usize::from(chunk_header), chunk_size as usize);
        if chunk_size < 8 || chunk_header < 8 || chunk_header > chunk_size || chunk_size > end - pos {
            doc.anomalies.push(format!("chunk at offset {pos} has an impossible size"));
            doc.truncated = true;
            break;
        }
        let chunk = &data[pos..pos + chunk_size];
        match chunk_type {
            CHUNK_STRING_POOL => {
                if pool.is_some() {
                    doc.anomalies.push("more than one string pool".into());
                } else if let Some(parsed) = StringPool::parse(chunk) {
                    doc.anomalies.extend(parsed.anomalies.iter().map(|a| (*a).to_string()));
                    pool = Some(parsed);
                } else {
                    doc.anomalies.push("string pool header is malformed".into());
                }
            }
            CHUNK_RESOURCE_MAP => resource_map = &chunk[chunk_header..],
            CHUNK_START_NAMESPACE | CHUNK_END_NAMESPACE => {}
            CHUNK_START_ELEMENT => {
                elements += 1;
                if elements > MAX_ELEMENTS || stack.len() >= MAX_DEPTH {
                    doc.anomalies.push("element count or nesting depth exceeds the decoder's limit".into());
                    doc.truncated = true;
                    break;
                }
                let element = start_element(chunk, chunk_header, pos, pool.as_ref(), resource_map, &mut doc);
                stack.push(element);
            }
            CHUNK_END_ELEMENT => {
                if let Some(done) = stack.pop() {
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(done),
                        None => {
                            if doc.root.is_none() {
                                doc.root = Some(done);
                            } else {
                                doc.anomalies.push("more than one root element".into());
                            }
                        }
                    }
                } else {
                    doc.anomalies.push("end of an element that was never started".into());
                }
            }
            CHUNK_CDATA => {
                if let (Some(index), Some(parent), Some(pool)) = (u32_at(chunk, chunk_header), stack.last_mut(), pool.as_ref())
                    && let Some(text) = pool.get(index)
                    && parent.text.len() + text.len() <= MAX_TEXT
                {
                    parent.text.push_str(&text);
                }
            }
            _ => unknown_chunks += 1,
        }
        pos += chunk_size;
    }
    if unknown_chunks > 0 {
        doc.anomalies.push(format!("{unknown_chunks} chunks of unknown type"));
    }
    if !stack.is_empty() {
        doc.anomalies.push("elements left open at the end of the file".into());
        doc.truncated = true;
        // Close what is open so that what was read is still usable.
        while let Some(done) = stack.pop() {
            match stack.last_mut() {
                Some(parent) => parent.children.push(done),
                None => {
                    if doc.root.is_none() {
                        doc.root = Some(done);
                    }
                }
            }
        }
    }
    if pool.is_none() {
        doc.anomalies.push("no string pool".into());
    }
    doc.anomalies.sort();
    doc.anomalies.dedup();
    doc
}

fn start_element(
    chunk: &[u8],
    header: usize,
    file_offset: usize,
    pool: Option<&StringPool>,
    resource_map: &[u8],
    doc: &mut Document,
) -> Element {
    let string = |index: Option<u32>| index.filter(|i| *i != NO_INDEX).and_then(|i| pool.and_then(|p| p.get(i)));
    let mut element = Element { offset: Some(file_offset as u64), ..Element::default() };
    // ResXMLTree_attrExt: ns, name, attributeStart, attributeSize, attributeCount, id/class/style indices.
    element.ns = string(u32_at(chunk, header)).filter(|ns| !ns.is_empty());
    element.name = string(u32_at(chunk, header + 4)).unwrap_or_default();
    let (Some(attr_start), Some(attr_size), Some(attr_count)) =
        (u16_at(chunk, header + 8), u16_at(chunk, header + 10), u16_at(chunk, header + 12))
    else {
        doc.anomalies.push("element header is cut short".into());
        return element;
    };
    let (attr_start, mut attr_size, attr_count) = (usize::from(attr_start), usize::from(attr_size), usize::from(attr_count));
    if attr_size != 20 {
        doc.anomalies.push(format!("attribute records are {attr_size} bytes, not 20"));
        if attr_size < 20 {
            // The platform reads 20 bytes per record whatever a smaller size claims.
            attr_size = 20;
        }
    }
    if attr_start != 20 {
        doc.anomalies.push(format!("attributes start at offset {attr_start}, not 20"));
    }
    for i in 0..attr_count.min(MAX_ATTRS) {
        let Some(record) = slice_at(chunk, header + attr_start + i * attr_size, 20) else {
            doc.anomalies.push("attribute records run past the element".into());
            break;
        };
        let name_index = u32_at(record, 4).unwrap_or(NO_INDEX);
        let raw_name = string(Some(name_index)).unwrap_or_default();
        let res_id = u32_at(resource_map, (name_index as usize).saturating_mul(4)).filter(|id| *id != 0);
        let ns = string(u32_at(record, 0)).filter(|ns| !ns.is_empty());
        let name = match res_id.and_then(attr_ids::name) {
            Some(known) => {
                if !raw_name.is_empty() && raw_name != known {
                    doc.anomalies.push("attribute name text differs from the name of its resource id".into());
                } else if raw_name.is_empty() {
                    doc.anomalies.push("attribute names are stripped; names come from resource ids".into());
                }
                known.to_string()
            }
            None => raw_name.clone(),
        };
        let raw = string(u32_at(record, 8));
        let data_type = record[15];
        let data = u32_at(record, 16).unwrap_or(0);
        let mut value = typed_value(data_type, data, pool);
        if matches!(value, Value::Null)
            && let Some(raw) = &raw
        {
            value = Value::Str(raw.clone());
        }
        // An attribute with a framework resource id is an android: attribute whatever its namespace says.
        let ns = match (&ns, res_id) {
            (None, Some(id)) if id >> 24 == 0x01 => Some(ANDROID_NS.to_string()),
            _ => ns,
        };
        element.attrs.push(Attr { ns, name, raw_name, res_id, value, raw });
    }
    element
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

    fn u32s(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    /// One attribute record: ns, name, raw value, typed value.
    fn attr(ns: u32, name: u32, raw: u32, data_type: u8, data: u32) -> Vec<u8> {
        let mut out = u32s(&[ns, name, raw]);
        out.extend_from_slice(&[8, 0, 0, data_type]);
        out.extend_from_slice(&data.to_le_bytes());
        out
    }

    fn start(name: u32, attrs: &[Vec<u8>]) -> Vec<u8> {
        let mut body = u32s(&[NO_INDEX, name]);
        body.extend_from_slice(&20u16.to_le_bytes());
        body.extend_from_slice(&20u16.to_le_bytes());
        body.extend_from_slice(&(attrs.len() as u16).to_le_bytes());
        body.extend_from_slice(&[0; 6]);
        for a in attrs {
            body.extend_from_slice(a);
        }
        chunk(CHUNK_START_ELEMENT, &u32s(&[1, NO_INDEX]), &body)
    }

    fn end(name: u32) -> Vec<u8> {
        chunk(CHUNK_END_ELEMENT, &u32s(&[1, NO_INDEX]), &u32s(&[NO_INDEX, name]))
    }

    /// A small manifest: `<manifest package="com.example"><application android:debuggable="true"
    /// android:label="@0x7f010000"/></manifest>`.
    pub fn sample() -> Vec<u8> {
        // Strings: 0 debuggable, 1 label, 2 android ns, 3 manifest, 4 package, 5 com.example, 6 application
        let pool = build_pool(&["debuggable", "label", ANDROID_NS, "manifest", "package", "com.example", "application"], true);
        let map = chunk(CHUNK_RESOURCE_MAP, &[], &u32s(&[0x0101_000f, 0x0101_0001]));
        let mut body = Vec::new();
        body.extend(pool);
        body.extend(map);
        body.extend(start(3, &[attr(NO_INDEX, 4, 5, 0x03, 5)]));
        body.extend(start(6, &[attr(2, 0, NO_INDEX, 0x12, 0xffff_ffff), attr(2, 1, NO_INDEX, 0x01, 0x7f01_0000)]));
        body.extend(end(6));
        body.extend(end(3));
        let mut file = Vec::new();
        file.extend_from_slice(&CHUNK_XML.to_le_bytes());
        file.extend_from_slice(&8u16.to_le_bytes());
        file.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
        file.extend(body);
        file
    }

    #[test]
    fn decodes_a_small_manifest() {
        let data = sample();
        assert!(looks_like_axml(&data));
        let doc = parse(&data);
        assert!(doc.anomalies.is_empty(), "{:?}", doc.anomalies);
        let root = doc.root.expect("root");
        assert_eq!(root.name, "manifest");
        assert_eq!(root.plain("package").and_then(|a| a.value.as_str()), Some("com.example"));
        let app = root.child("application").expect("application");
        assert_eq!(app.android("debuggable").and_then(|a| a.value.as_bool()), Some(true));
        assert_eq!(app.android("label").and_then(|a| a.value.as_ref_id()), Some(0x7f01_0000));
    }

    #[test]
    fn attribute_names_come_from_resource_ids() {
        let mut data = sample();
        // Overwrite the text "debuggable" with something else of the same length.
        let at = data.windows(10).position(|w| w == b"debuggable").expect("string");
        data[at..at + 10].copy_from_slice(b"xxxxxxxxxx");
        let doc = parse(&data);
        let app = doc.root.as_ref().and_then(|r| r.child("application")).expect("application");
        assert_eq!(app.android("debuggable").and_then(|a| a.value.as_bool()), Some(true));
        assert!(doc.anomalies.iter().any(|a| a.contains("differs")));
    }

    #[test]
    fn wrong_type_and_extra_chunks_are_tolerated() {
        let mut data = sample();
        data[0] = 0x08; // bogus file type
        // Append an unknown chunk and fix the size field.
        data.extend(chunk(0x7777, &[], &[1, 2, 3, 4]));
        let size = data.len() as u32;
        data[4..8].copy_from_slice(&size.to_le_bytes());
        assert!(looks_like_axml(&data));
        let doc = parse(&data);
        assert_eq!(doc.root.as_ref().map(|r| r.name.as_str()), Some("manifest"));
        assert!(doc.anomalies.iter().any(|a| a.contains("file type")));
        assert!(doc.anomalies.iter().any(|a| a.contains("unknown type")));
    }

    #[test]
    fn truncation_at_every_length_does_not_panic() {
        let data = sample();
        for cut in 0..data.len() {
            let doc = parse(&data[..cut]);
            assert!(doc.root.is_none() || doc.truncated || !doc.anomalies.is_empty());
        }
    }

    #[test]
    fn corrupted_bytes_do_not_panic() {
        let data = sample();
        for i in 0..data.len() {
            for v in [0x00, 0xff, 0x80] {
                let mut bad = data.clone();
                bad[i] = v;
                let _ = parse(&bad);
            }
        }
    }

    #[test]
    fn deep_nesting_is_bounded() {
        let pool = build_pool(&["a"], true);
        let mut body = pool;
        for _ in 0..(MAX_DEPTH + 50) {
            body.extend(start(0, &[]));
        }
        let mut file = Vec::new();
        file.extend_from_slice(&CHUNK_XML.to_le_bytes());
        file.extend_from_slice(&8u16.to_le_bytes());
        file.extend_from_slice(&((8 + body.len()) as u32).to_le_bytes());
        file.extend(body);
        let doc = parse(&file);
        assert!(doc.truncated);
        assert!(doc.root.is_some());
    }

    #[test]
    fn text_is_not_axml() {
        assert!(!looks_like_axml(b"<?xml version=\"1.0\"?><manifest/>"));
        assert!(!looks_like_axml(b""));
    }
}
