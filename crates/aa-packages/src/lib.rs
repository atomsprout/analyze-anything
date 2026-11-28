//! Bounded package declarations read from captured archive members, without runtimes.

mod java;
mod npm;
mod wheel;

use aa_core::Artifact;
use aa_core::plugin::{Analyzer, Tree};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) type Result<T> = std::result::Result<T, String>;
pub(crate) const MAX_TEXT: usize = 1024 * 1024;
pub(crate) const MAX_FIELDS: usize = 8192;
pub(crate) const MAX_FIELD: usize = 16 * 1024;
pub(crate) const MAX_PACKAGES: usize = 256;

pub fn analyzers() -> Vec<Box<dyn Analyzer>> {
    vec![Box::new(wheel::Wheel), Box::new(npm::Npm), Box::new(java::Java)]
}

pub(crate) fn original(file: &Artifact) -> bool {
    file.facts.get("engine.entry-name").is_none_or(|fact| fact["normalized"] != true && fact["colliding"] != true)
}

pub(crate) fn members<'a>(tree: &'a dyn Tree, container: &Artifact) -> Result<BTreeMap<&'a str, &'a Artifact>> {
    if container.path.len() > 8192
        || !original(container)
        || container.facts.get("engine.container-listing").is_none_or(|fact| fact["complete"] != true)
    {
        return Err("captured package namespace is incomplete, renamed or ambiguous".into());
    }
    let prefix = format!("{}/", container.path);
    let mut members = BTreeMap::new();
    let mut path_bytes = 0usize;
    for file in tree.artifacts().iter().filter(|file| file.parent.as_deref() == Some(&container.path)) {
        let path = file.path.strip_prefix(&prefix).ok_or("member does not belong to its declared container namespace")?;
        path_bytes = path_bytes.checked_add(path.len()).ok_or("package path budget overflow")?;
        if members.len() >= 100_000
            || path_bytes > 16 * 1024 * 1024
            || file.path.len() > 8192
            || path.len() > 4096
            || !original(file)
            || members.insert(path, file).is_some()
        {
            return Err("package member count, original-name or path budget exceeded".into());
        }
    }
    Ok(members)
}

pub(crate) fn read_text(tree: &dyn Tree, file: &Artifact, maximum: usize) -> Result<String> {
    if file.size > maximum as u64 {
        return Err("package metadata exceeds its byte limit".into());
    }
    let bytes = tree.read(&file.path).map_err(|error| error.to_string())?;
    if bytes.len() > maximum || bytes.contains(&0) {
        return Err("package metadata exceeds its byte limit or contains NUL".into());
    }
    std::str::from_utf8(&bytes).map(str::to_string).map_err(|_| "package metadata is not UTF-8".into())
}

pub(crate) fn inventory(members: &BTreeMap<&str, &Artifact>) -> Value {
    let rows: Vec<_> = members
        .iter()
        .take(5000)
        .map(|(path, file)| {
            json!({"path":path,"size":file.size,
        "sha256":file.digests.as_ref().map(|digest|&digest.sha256),"kind":file.kind})
        })
        .collect();
    json!({"members":rows,"total":members.len(),"truncated":members.len()>5000})
}

pub(crate) fn scalar(text: &str) -> Result<String> {
    if text.is_empty() || text.len() > MAX_FIELD || text.chars().any(char::is_control) {
        return Err("empty, oversized or control-containing package scalar".into());
    }
    aa_core::text::redact_sensitive_text(text).map_err(str::to_string)
}

pub(crate) fn redacted(value: &Value) -> Result<Value> {
    Ok(match value {
        Value::String(text) => Value::String(aa_core::text::redact_sensitive_text(text).map_err(str::to_string)?),
        Value::Array(values) => Value::Array(values.iter().map(redacted).collect::<Result<_>>()?),
        Value::Object(values) => {
            Value::Object(values.iter().map(|(key, value)| Ok((key.clone(), redacted(value)?))).collect::<Result<_>>()?)
        }
        value => value.clone(),
    })
}

/// Reject duplicate keys before an object can be collapsed into a JSON map.
pub(crate) fn unique_json(text: &str) -> Result<Value> {
    if text.len() > MAX_TEXT {
        return Err("JSON package metadata exceeds 1 MiB".into());
    }
    struct Seed<'a> {
        depth: usize,
        nodes: &'a mut usize,
    }
    impl<'de> DeserializeSeed<'de> for Seed<'_> {
        type Value = Value;
        fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> std::result::Result<Value, D::Error> {
            *self.nodes += 1;
            if self.depth > 32 || *self.nodes > MAX_FIELDS {
                return Err(serde::de::Error::custom("JSON nesting or value count exceeds the package profile"));
            }
            deserializer.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Seed<'_> {
        type Value = Value;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("bounded package JSON")
        }
        fn visit_bool<E: serde::de::Error>(self, value: bool) -> std::result::Result<Value, E> {
            Ok(value.into())
        }
        fn visit_i64<E: serde::de::Error>(self, value: i64) -> std::result::Result<Value, E> {
            Ok(value.into())
        }
        fn visit_u64<E: serde::de::Error>(self, value: u64) -> std::result::Result<Value, E> {
            Ok(value.into())
        }
        fn visit_f64<E: serde::de::Error>(self, value: f64) -> std::result::Result<Value, E> {
            Ok(value.into())
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> std::result::Result<Value, E> {
            if value.len() > MAX_FIELD {
                return Err(E::custom("JSON string exceeds the package field limit"));
            }
            Ok(value.into())
        }
        fn visit_string<E: serde::de::Error>(self, value: String) -> std::result::Result<Value, E> {
            self.visit_str(&value)
        }
        fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> std::result::Result<Value, A::Error> {
            let mut values = Vec::new();
            while let Some(value) = sequence.next_element_seed(Seed { depth: self.depth + 1, nodes: self.nodes })? {
                values.push(value);
            }
            Ok(Value::Array(values))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> std::result::Result<Value, A::Error> {
            let mut values = serde_json::Map::new();
            let mut keys = BTreeSet::new();
            while let Some(key) = object.next_key::<String>()? {
                if key.len() > MAX_FIELD || !keys.insert(key.clone()) {
                    return Err(serde::de::Error::custom("duplicate or oversized package JSON key"));
                }
                let value = object.next_value_seed(Seed { depth: self.depth + 1, nodes: self.nodes })?;
                values.insert(key, value);
            }
            Ok(Value::Object(values))
        }
    }
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let mut nodes = 0;
    let value = Seed { depth: 0, nodes: &mut nodes }.deserialize(&mut deserializer).map_err(|error| error.to_string())?;
    deserializer.end().map_err(|error| error.to_string())?;
    Ok(value)
}

#[cfg(test)]
pub(crate) mod testsupport;
