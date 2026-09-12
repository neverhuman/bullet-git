//! Recursive duplicate-key rejection; no last-value-wins report semantics.
use super::Result;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

const MAX_JSON_BYTES: usize = 64 * 1024 * 1024;
struct Checked(Value);
struct CheckedVisitor;
impl<'de> Deserialize<'de> for Checked {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(CheckedVisitor)
    }
}
impl<'de> Visitor<'de> for CheckedVisitor {
    type Value = Checked;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON with unique object keys and finite numbers")
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Checked, E> {
        Ok(Checked(Value::Bool(value)))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Checked, E> {
        Ok(Checked(Value::Number(Number::from(value))))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Checked, E> {
        Ok(Checked(Value::Number(Number::from(value))))
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Checked, E> {
        Number::from_f64(value)
            .map(|value| Checked(Value::Number(value)))
            .ok_or_else(|| E::custom("NONFINITE_JSON"))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Checked, E> {
        Ok(Checked(Value::String(value.to_owned())))
    }
    fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Checked, E> {
        Ok(Checked(Value::String(value)))
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Checked, E> {
        Ok(Checked(Value::Null))
    }
    fn visit_none<E: de::Error>(self) -> std::result::Result<Checked, E> {
        Ok(Checked(Value::Null))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut array: A) -> std::result::Result<Checked, A::Error> {
        let mut values = Vec::new();
        while let Some(Checked(value)) = array.next_element()? {
            values.push(value);
        }
        Ok(Checked(Value::Array(values)))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut object: A) -> std::result::Result<Checked, A::Error> {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!("DUPLICATE_JSON_KEY:{key}")));
            }
            let Checked(value) = object.next_value()?;
            values.insert(key, value);
        }
        Ok(Checked(Value::Object(values)))
    }
}

pub(super) fn decode(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > MAX_JSON_BYTES {
        return Err("JSON_BYTE_LIMIT".into());
    }
    // serde_json's default finite recursion limit remains enabled.
    let mut parser = serde_json::Deserializer::from_slice(bytes);
    let Checked(value) = Checked::deserialize(&mut parser).map_err(|error| error.to_string())?;
    parser.end().map_err(|error| error.to_string())?;
    Ok(value)
}
