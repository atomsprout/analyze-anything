//! Bounded JSON for image metadata, rejecting duplicate keys before interpretation.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

pub(super) struct Budget {
    nodes: usize,
    strings: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Self { nodes: 100_000, strings: 16 * 1024 * 1024 }
    }
}

pub(super) fn parse(bytes: &[u8], budget: &mut Budget) -> crate::Result<Value> {
    if bytes.len() > 2 * 1024 * 1024 {
        return Err("image JSON exceeds the 2 MiB document profile".into());
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Seed { budget, depth: 0 }.deserialize(&mut decoder).map_err(|error| error.to_string())?;
    decoder.end().map_err(|error| error.to_string())?;
    Ok(value)
}

struct Seed<'a> {
    budget: &'a mut Budget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        if self.depth > 32 || self.budget.nodes == 0 {
            return Err(de::Error::custom("image JSON nesting or node budget exhausted"));
        }
        self.budget.nodes -= 1;
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded image JSON")
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Number::from_f64(value).map(Value::Number).ok_or_else(|| E::custom("nonfinite image JSON number"))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        if value.len() > 64 * 1024 {
            return Err(E::custom("image JSON string exceeds the 64 KiB profile"));
        }
        self.budget.strings =
            self.budget.strings.checked_sub(value.len()).ok_or_else(|| E::custom("image JSON string budget exhausted"))?;
        Ok(Value::String(value.to_string()))
    }
    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        self.visit_str(&value)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(Seed { budget: self.budget, depth: self.depth + 1 })? {
            if values.len() >= 100_000 {
                return Err(de::Error::custom("image JSON array budget exhausted"));
            }
            values.push(value);
        }
        Ok(Value::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Map::new();
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.len() >= 4096 || key.len() > 4096 {
                return Err(de::Error::custom("image JSON key or object budget exhausted"));
            }
            self.budget.strings =
                self.budget.strings.checked_sub(key.len()).ok_or_else(|| de::Error::custom("image JSON key byte budget exhausted"))?;
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom("duplicate image JSON object key"));
            }
            let value = map.next_value_seed(Seed { budget: self.budget, depth: self.depth + 1 })?;
            values.insert(key, value);
        }
        Ok(Value::Object(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_nested_keys_depth_and_node_budgets_are_not_silent_defaults() {
        assert!(parse(br#"{"config":{"Env":[],"Env":["secret"]}}"#, &mut Budget::default()).is_err());
        assert!(parse(format!("{}0{}", "[".repeat(34), "]".repeat(34)).as_bytes(), &mut Budget::default()).is_err());
        assert!(parse(b"[1,2]", &mut Budget { nodes: 2, strings: 100 }).is_err());
        assert!(parse(b"{} trailing", &mut Budget::default()).is_err());
        assert_eq!(parse(b"{\"optional\":null}", &mut Budget::default()).expect("literal null")["optional"], Value::Null);
    }
}
