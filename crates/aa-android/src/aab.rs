//! App bundles (`.aab`): the manifest and resource table are protobuf messages (aapt2's
//! `Resources.proto`), decoded here into the same shapes the APK decoders produce.

use std::collections::BTreeMap;

use crate::arsc::Resolved;
use crate::proto::{self, Field};
use crate::xml::{Attr, Document, Element, Value};

const MAX_DEPTH: usize = 100;
const MAX_ELEMENTS: usize = 200_000;
const MAX_ENTRIES: usize = 2_000_000;

fn item_value(item: &[u8]) -> Value {
    for (number, field) in proto::fields(item) {
        let Some(body) = field.bytes() else { continue };
        match number {
            // Reference { type = 1; id = 2; name = 3 }
            1 => {
                let id = proto::first(body, 2).and_then(Field::varint).unwrap_or(0) as u32;
                return Value::Ref(id);
            }
            // String, RawString: { value = 1 }; FileReference: { path = 1 }
            2 | 3 | 5 => return proto::first(body, 1).and_then(Field::string).map(Value::Str).unwrap_or(Value::Str(String::new())),
            // StyledString { value = 1 }
            4 => return proto::first(body, 1).and_then(Field::string).map(Value::Str).unwrap_or(Value::Null),
            // Primitive
            7 => {
                return match proto::fields(body).next() {
                    Some((6, Field::Varint(v))) => Value::Int(v as i32),
                    Some((7, Field::Varint(v))) => Value::Hex(v as u32),
                    Some((8, Field::Varint(v))) => Value::Bool(v != 0),
                    Some((3, Field::Fixed32(v))) => Value::Float(f32::from_bits(v)),
                    Some((9..=12, Field::Varint(v))) => Value::Other { data_type: 0x1c, data: v as u32 },
                    _ => Value::Null,
                };
            }
            _ => {}
        }
    }
    Value::Null
}

fn attribute(data: &[u8]) -> Attr {
    let mut attr = Attr { ns: None, name: String::new(), raw_name: String::new(), res_id: None, value: Value::Null, raw: None };
    let mut compiled = None;
    for (number, field) in proto::fields(data) {
        match (number, field) {
            (1, f) => attr.ns = f.string().filter(|s| !s.is_empty()),
            (2, f) => attr.name = f.string().unwrap_or_default(),
            (3, f) => attr.raw = f.string(),
            (5, Field::Varint(id)) => attr.res_id = Some(id as u32).filter(|id| *id != 0),
            (6, Field::Bytes(item)) => compiled = Some(item_value(item)),
            _ => {}
        }
    }
    attr.raw_name = attr.name.clone();
    attr.value = match compiled {
        Some(Value::Null) | None => attr.raw.clone().map(Value::Str).unwrap_or(Value::Null),
        Some(value) => value,
    };
    attr
}

fn element(data: &[u8], depth: usize, budget: &mut usize, doc: &mut Document) -> Element {
    let mut out = Element::default();
    for (number, field) in proto::fields(data) {
        match (number, field) {
            (2, f) => out.ns = f.string().filter(|s| !s.is_empty()),
            (3, f) => out.name = f.string().unwrap_or_default(),
            (4, Field::Bytes(attr)) if out.attrs.len() < 4096 => out.attrs.push(attribute(attr)),
            // XmlNode { element = 1; text = 2 }
            (5, Field::Bytes(node)) => {
                for (kind, inner) in proto::fields(node) {
                    match (kind, inner) {
                        (1, Field::Bytes(child)) => {
                            if depth >= MAX_DEPTH || *budget == 0 {
                                doc.truncated = true;
                                continue;
                            }
                            *budget -= 1;
                            let child = element(child, depth + 1, budget, doc);
                            out.children.push(child);
                        }
                        (2, f) => {
                            if let Some(text) = f.string()
                                && out.text.len() + text.len() < (1 << 20)
                            {
                                out.text.push_str(&text);
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// Decodes a protobuf `XmlNode`, the format of every XML file in a bundle.
pub fn parse_xml(data: &[u8]) -> Document {
    let mut doc = Document::default();
    let mut budget = MAX_ELEMENTS;
    let mut it = proto::fields(data);
    for (number, field) in it.by_ref() {
        if number == 1
            && let Field::Bytes(root) = field
        {
            let root = element(root, 0, &mut budget, &mut doc);
            doc.root = Some(root);
        }
    }
    if it.malformed {
        doc.anomalies.push("the protobuf message is malformed".into());
    }
    doc
}

/// True when `data` looks like a protobuf `XmlNode` with an element: field 1, length-delimited.
pub fn looks_like_proto_xml(data: &[u8]) -> bool {
    data.first() == Some(&0x0a) && proto::fields(data).next().is_some_and(|(n, f)| n == 1 && f.bytes().is_some())
}

/// The resource table of a bundle module (`resources.pb`), indexed by resource id.
pub struct ProtoTable<'a> {
    /// id -> (type name, entry message)
    entries: BTreeMap<u32, (String, &'a [u8])>,
    pub truncated: bool,
}

fn entry_name(entry: &[u8]) -> Option<String> {
    proto::first(entry, 2).and_then(Field::string)
}

/// The entry's value in the default configuration, else in its first one.
fn entry_value(entry: &[u8]) -> (Option<Value>, usize) {
    let mut first = None;
    let mut default = None;
    let mut configs = 0;
    for (number, field) in proto::fields(entry) {
        // ConfigValue { config = 1; value = 2 }
        if number != 6 {
            continue;
        }
        let Some(config_value) = field.bytes() else { continue };
        configs += 1;
        let is_default = proto::first(config_value, 1).and_then(Field::bytes).is_none_or(<[u8]>::is_empty);
        // Value { item = 4; compound_value = 5 }
        let value =
            proto::first(config_value, 2).and_then(Field::bytes).and_then(|v| proto::first(v, 4)).and_then(Field::bytes).map(item_value);
        if is_default && default.is_none() {
            default = value.clone();
        }
        if first.is_none() {
            first = value;
        }
    }
    (default.or(first), configs)
}

impl<'a> ProtoTable<'a> {
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let mut table = ProtoTable { entries: BTreeMap::new(), truncated: false };
        let mut any = false;
        // ResourceTable { package = 2 }
        for (number, field) in proto::fields(data) {
            let (2, Some(package)) = (number, field.bytes()) else { continue };
            any = true;
            let package_id =
                proto::first(package, 1).and_then(Field::bytes).and_then(|m| proto::first(m, 1)).and_then(Field::varint).unwrap_or(0x7f)
                    as u32;
            // Package { type = 3 }
            for (number, field) in proto::fields(package) {
                let (3, Some(kind)) = (number, field.bytes()) else { continue };
                let type_id =
                    proto::first(kind, 1).and_then(Field::bytes).and_then(|m| proto::first(m, 1)).and_then(Field::varint).unwrap_or(0)
                        as u32;
                let type_name = proto::first(kind, 2).and_then(Field::string).unwrap_or_default();
                // Type { entry = 3 }
                for (number, field) in proto::fields(kind) {
                    let (3, Some(entry)) = (number, field.bytes()) else { continue };
                    if table.entries.len() >= MAX_ENTRIES {
                        table.truncated = true;
                        return Some(table);
                    }
                    let entry_id =
                        proto::first(entry, 1).and_then(Field::bytes).and_then(|m| proto::first(m, 1)).and_then(Field::varint).unwrap_or(0)
                            as u32;
                    let id = (package_id << 24) | ((type_id & 0xff) << 16) | (entry_id & 0xffff);
                    table.entries.insert(id, (type_name.clone(), entry));
                }
            }
        }
        any.then_some(table)
    }

    /// Number of resource entries in the table.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn resolve(&self, id: u32) -> Option<Resolved> {
        let (type_name, entry) = self.entries.get(&id)?;
        let name = entry_name(entry).map(|n| format!("{type_name}/{n}"));
        let (mut value, configs) = entry_value(entry);
        let mut depth = 0;
        while let Some(Value::Ref(next)) = value {
            depth += 1;
            if depth > 12 || next == id {
                break;
            }
            match self.entries.get(&next) {
                Some((_, target)) => value = entry_value(target).0,
                None => break,
            }
        }
        Some(Resolved { name, value, config: None, configs })
    }

    /// The values of the string resources called `names`.
    pub fn find_strings(&self, names: &[&str]) -> BTreeMap<String, String> {
        let mut found = BTreeMap::new();
        for (type_name, entry) in self.entries.values() {
            if type_name != "string" {
                continue;
            }
            if let Some(name) = entry_name(entry)
                && names.contains(&name.as_str())
                && let (Some(Value::Str(text)), _) = entry_value(entry)
            {
                found.insert(name, text);
            }
        }
        found
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::proto::tests::{bytes_field, varint_field};

    fn string_item(text: &str) -> Vec<u8> {
        bytes_field(2, &bytes_field(1, text.as_bytes()))
    }

    fn attr(ns: &str, name: &str, value: &str, res_id: u32, item: Option<Vec<u8>>) -> Vec<u8> {
        let mut out = bytes_field(1, ns.as_bytes());
        out.extend(bytes_field(2, name.as_bytes()));
        out.extend(bytes_field(3, value.as_bytes()));
        if res_id != 0 {
            out.extend(varint_field(5, u64::from(res_id)));
        }
        if let Some(item) = item {
            out.extend(bytes_field(6, &item));
        }
        out
    }

    fn el(name: &str, attrs: &[Vec<u8>], children: &[Vec<u8>]) -> Vec<u8> {
        let mut out = bytes_field(3, name.as_bytes());
        for a in attrs {
            out.extend(bytes_field(4, a));
        }
        for c in children {
            out.extend(bytes_field(5, &bytes_field(1, c)));
        }
        out
    }

    /// `<manifest package="com.example"><application android:debuggable="true" android:label="@0x7f010000"/></manifest>`
    pub fn sample_manifest() -> Vec<u8> {
        let ns = crate::xml::ANDROID_NS;
        let debuggable = attr(ns, "debuggable", "true", 0x0101_000f, Some(bytes_field(7, &varint_field(8, 1))));
        let label = attr(ns, "label", "@string/app_name", 0x0101_0001, Some(bytes_field(1, &varint_field(2, 0x7f01_0000))));
        let app = el("application", &[debuggable, label], &[]);
        let root = el("manifest", &[attr("", "package", "com.example", 0, Some(string_item("com.example")))], &[app]);
        bytes_field(1, &root)
    }

    pub fn sample_table() -> Vec<u8> {
        let config_value = bytes_field(2, &bytes_field(4, &string_item("Example")));
        let mut entry = bytes_field(1, &varint_field(1, 0));
        entry.extend(bytes_field(2, b"app_name"));
        entry.extend(bytes_field(6, &config_value));
        let mut kind = bytes_field(1, &varint_field(1, 1));
        kind.extend(bytes_field(2, b"string"));
        kind.extend(bytes_field(3, &entry));
        let mut package = bytes_field(1, &varint_field(1, 0x7f));
        package.extend(bytes_field(2, b"com.example"));
        package.extend(bytes_field(3, &kind));
        bytes_field(2, &package)
    }

    #[test]
    fn decodes_manifest_and_table() {
        let data = sample_manifest();
        assert!(looks_like_proto_xml(&data));
        let doc = parse_xml(&data);
        let root = doc.root.expect("root");
        assert_eq!(root.name, "manifest");
        assert_eq!(root.plain("package").and_then(|a| a.value.as_str()), Some("com.example"));
        let app = root.child("application").expect("application");
        assert_eq!(app.android("debuggable").and_then(|a| a.value.as_bool()), Some(true));
        assert_eq!(app.android("label").and_then(|a| a.value.as_ref_id()), Some(0x7f01_0000));
        let table_bytes = sample_table();
        let table = ProtoTable::parse(&table_bytes).expect("table");
        let resolved = table.resolve(0x7f01_0000).expect("entry");
        assert_eq!(resolved.name.as_deref(), Some("string/app_name"));
        assert_eq!(resolved.value, Some(Value::Str("Example".into())));
        assert_eq!(table.find_strings(&["app_name"]).get("app_name").map(String::as_str), Some("Example"));
    }

    #[test]
    fn malformed_messages_do_not_panic() {
        for data in [sample_manifest(), sample_table()] {
            for cut in 0..data.len() {
                let _ = parse_xml(&data[..cut]);
                if let Some(table) = ProtoTable::parse(&data[..cut]) {
                    let _ = table.resolve(0x7f01_0000);
                }
            }
            for i in 0..data.len() {
                for v in [0u8, 0xff, 0x7f] {
                    let mut bad = data.clone();
                    bad[i] = v;
                    let _ = parse_xml(&bad);
                    if let Some(table) = ProtoTable::parse(&bad) {
                        let _ = table.resolve(0x7f01_0000);
                    }
                }
            }
        }
    }

    #[test]
    fn nesting_is_bounded() {
        // 500 nested elements.
        let mut data = el("leaf", &[], &[]);
        for _ in 0..500 {
            data = el("e", &[], &[data]);
        }
        let doc = parse_xml(&bytes_field(1, &data));
        assert!(doc.truncated);
        assert!(doc.root.is_some());
    }
}
