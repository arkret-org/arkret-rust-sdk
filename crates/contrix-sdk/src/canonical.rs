use serde::Serialize;
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};

use crate::{Error, Result};

/// Serialize a value with Contrix canonical JSON.
///
/// The v1 SDK uses an integer-only number profile for signing and hashing. This
/// rejects JSON floats even if serde_json can represent them.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    let mut out = Vec::new();
    write_canonical_value(&value, &mut out)?;
    Ok(out)
}

pub fn canonical_json_string<T: Serialize>(value: &T) -> Result<String> {
    let bytes = canonical_json_bytes(value)?;
    String::from_utf8(bytes)
        .map_err(|err| Error::Protocol(format!("canonical JSON produced invalid UTF-8: {err}")))
}

pub fn sha256_digest(bytes: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(bytes.as_ref());
    format!("sha256:{digest:x}")
}

pub fn canonical_sha256<T: Serialize>(value: &T) -> Result<String> {
    Ok(sha256_digest(canonical_json_bytes(value)?))
}

fn write_canonical_value(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => write_number(number, out)?,
        Value::String(string) => {
            serde_json::to_writer(out, string)?;
        }
        Value::Array(items) => {
            out.push(b'[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                write_canonical_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => write_object(map, out)?,
    }

    Ok(())
}

fn write_number(number: &Number, out: &mut Vec<u8>) -> Result<()> {
    if let Some(n) = number.as_i64() {
        out.extend_from_slice(n.to_string().as_bytes());
    } else if let Some(n) = number.as_u64() {
        out.extend_from_slice(n.to_string().as_bytes());
    } else {
        return Err(Error::NonCanonicalNumber);
    }

    Ok(())
}

fn write_object(map: &Map<String, Value>, out: &mut Vec<u8>) -> Result<()> {
    out.push(b'{');

    let mut keys = map.keys().collect::<Vec<_>>();
    keys.sort_unstable();

    for (idx, key) in keys.into_iter().enumerate() {
        if idx > 0 {
            out.push(b',');
        }
        serde_json::to_writer(&mut *out, key)?;
        out.push(b':');
        write_canonical_value(&map[key], out)?;
    }

    out.push(b'}');
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn canonical_json_sorts_object_keys() {
        let value = json!({ "b": 2, "a": 1 });
        let actual = canonical_json_string(&value).unwrap();
        assert_eq!(actual, r#"{"a":1,"b":2}"#);
        assert_eq!(
            sha256_digest(actual.as_bytes()),
            "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
        );
    }

    #[test]
    fn canonical_json_rejects_float_numbers() {
        let value = json!({ "n": 1.5 });
        assert!(matches!(canonical_json_string(&value), Err(Error::NonCanonicalNumber)));
    }
}
