//! `cx.schema.patch.v1` — canonical field-patch grammar.
//!
//! Mirrors `contrix-spec/spec/v1/artifacts/schemas/patch.schema.json`. A
//! patch is an object whose property names are dotted field paths
//! (snake_case identifiers, optional stable-key selectors
//! `field[<key>=<canonical-json-string>]`, backtick-quoted literals for
//! non-snake_case keys; max 1024 bytes, max 16 nesting segments) and
//! whose values are either:
//!
//! - A **direct value** — any JSON value that is *not* a JSON object
//!   containing a `$op` discriminator. Equivalent to `{"$op":"set",
//!   "value":<value>}`.
//! - An **explicit op object** — `{ "$op": "set"|"unset"|"add"|"remove",
//!   "value": ... }`. `value` is required for `set`/`add`/`remove` and
//!   MUST be absent for `unset`.
//!
//! Reducer parser rules (selector semantics, redactable-field
//! protection, reducer-managed-field protection) are defined normatively
//! in `zh/models/event-and-patch.md §4`. This module only models the
//! wire grammar; semantic enforcement happens in the reducer layer.

use std::collections::BTreeMap;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, Result};

/// Registered schema id for the field-patch wire format.
///
/// The in-prose name `cx.patch.v1` resolves to this same artifact.
pub const PATCH_SCHEMA: &str = "cx.schema.patch.v1";

/// Maximum patch-path length in bytes, per spec.
pub const PATCH_PATH_MAX_BYTES: usize = 1024;

/// Maximum patch-path nesting depth (segments separated by `.`).
pub const PATCH_PATH_MAX_SEGMENTS: usize = 16;

/// Explicit op discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PatchOpKind {
    /// Replace the field with `value`.
    Set,
    /// Remove the field. `value` MUST be absent.
    Unset,
    /// Add `value` to a collection at the field.
    Add,
    /// Remove `value` from a collection at the field.
    Remove,
}

/// A single patch entry. Either an inline value (sugared `set`) or an
/// explicit `{ "$op": ..., "value": ... }` object.
#[derive(Clone, Debug, PartialEq)]
pub enum PatchOp {
    /// Direct value form: `path: <value>` sugars to `{ "$op": "set",
    /// "value": <value> }`. The value MUST NOT itself be a JSON object
    /// carrying a `$op` field; reducers MUST detect that case and
    /// reject with `patch_path_invalid` per spec.
    DirectValue(Value),
    /// Explicit op object.
    Explicit {
        op: PatchOpKind,
        /// Required for `set`/`add`/`remove`; absent for `unset`.
        value: Option<Value>,
    },
}

impl PatchOp {
    /// Build a `set` operation with the given value.
    pub fn set(value: impl Into<Value>) -> Self {
        Self::Explicit { op: PatchOpKind::Set, value: Some(value.into()) }
    }

    /// Build an `unset` operation.
    pub fn unset() -> Self {
        Self::Explicit { op: PatchOpKind::Unset, value: None }
    }

    /// Build an `add` operation.
    pub fn add(value: impl Into<Value>) -> Self {
        Self::Explicit { op: PatchOpKind::Add, value: Some(value.into()) }
    }

    /// Build a `remove` operation.
    pub fn remove(value: impl Into<Value>) -> Self {
        Self::Explicit { op: PatchOpKind::Remove, value: Some(value.into()) }
    }

    /// Resolve the operation kind regardless of form.
    pub fn op(&self) -> PatchOpKind {
        match self {
            Self::DirectValue(_) => PatchOpKind::Set,
            Self::Explicit { op, .. } => *op,
        }
    }

    /// Borrow the value, if any. `unset` has none.
    pub fn value(&self) -> Option<&Value> {
        match self {
            Self::DirectValue(v) => Some(v),
            Self::Explicit { value, .. } => value.as_ref(),
        }
    }
}

impl Serialize for PatchOp {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::DirectValue(value) => value.serialize(serializer),
            Self::Explicit { op, value } => {
                let len = if value.is_some() { 2 } else { 1 };
                let mut map = serializer.serialize_map(Some(len))?;
                map.serialize_entry("$op", op)?;
                if let Some(v) = value {
                    map.serialize_entry("value", v)?;
                }
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for PatchOp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        // We parse to `Value` first so we can distinguish "object with
        // $op discriminator" from "object that happens to be the
        // direct value" (the latter is a degenerate but spec-legal
        // case: an object value WITHOUT a `$op` key sugars to set).
        let value = Value::deserialize(deserializer)?;
        match &value {
            Value::Object(map) if map.contains_key("$op") => {
                let op = map
                    .get("$op")
                    .and_then(Value::as_str)
                    .ok_or_else(|| de::Error::custom("$op must be a string"))?;
                let op_kind: PatchOpKind = serde_json::from_value(Value::String(op.to_owned()))
                    .map_err(|err| de::Error::custom(format!("invalid $op: {err}")))?;
                let inner_value = map.get("value").cloned();
                if matches!(op_kind, PatchOpKind::Unset) && inner_value.is_some() {
                    return Err(de::Error::custom("patch op 'unset' must not carry a value"));
                }
                if !matches!(op_kind, PatchOpKind::Unset) && inner_value.is_none() {
                    return Err(de::Error::custom(format!("patch op '{op}' requires a value",)));
                }
                if map.keys().any(|k| k.as_str() != "$op" && k.as_str() != "value") {
                    return Err(de::Error::custom(
                        "patch op object must contain only $op and value",
                    ));
                }
                Ok(Self::Explicit { op: op_kind, value: inner_value })
            }
            _ => Ok(Self::DirectValue(value)),
        }
    }
}

/// A field-patch (cx.schema.patch.v1). MUST contain at least one entry
/// (`minProperties: 1` in the spec). Use [`Patch::insert`] /
/// [`Patch::insert_op`] to build one programmatically.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Patch {
    entries: BTreeMap<String, PatchOp>,
}

impl Patch {
    /// Create an empty patch. Callers MUST add at least one entry
    /// before serialising; an empty patch is rejected at validation.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a direct-value entry. Sugars to `{$op: set, value}`.
    pub fn insert(&mut self, path: impl Into<String>, value: impl Into<Value>) -> Result<()> {
        let path = path.into();
        validate_path(&path)?;
        self.entries.insert(path, PatchOp::DirectValue(value.into()));
        Ok(())
    }

    /// Insert an explicit-op entry.
    pub fn insert_op(&mut self, path: impl Into<String>, op: PatchOp) -> Result<()> {
        let path = path.into();
        validate_path(&path)?;
        self.entries.insert(path, op);
        Ok(())
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the patch is empty (invalid for the wire).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over (path, op) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &PatchOp)> {
        self.entries.iter()
    }

    /// Validate that the patch satisfies the spec's wire-level
    /// constraints (`minProperties: 1` and path syntax).
    pub fn validate(&self) -> Result<()> {
        if self.entries.is_empty() {
            return Err(Error::Protocol(
                "patch must contain at least one entry (minProperties: 1)".to_owned(),
            ));
        }
        for path in self.entries.keys() {
            validate_path(path)?;
        }
        Ok(())
    }
}

/// Validate a patch path's surface syntax. Reducers still need to do
/// the full ABNF check (`zh/models/event-and-patch.md §4.2.1`); this
/// only enforces the byte-length and segment-count limits the spec
/// names explicitly.
pub fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(Error::Protocol("patch path must not be empty".to_owned()));
    }
    if path.len() > PATCH_PATH_MAX_BYTES {
        return Err(Error::Protocol(format!(
            "patch path exceeds {PATCH_PATH_MAX_BYTES} bytes ({} bytes)",
            path.len()
        )));
    }
    // Count top-level dot segments. Selectors (`[...]`) are part of a
    // segment, not a separator. We treat `.` as the splitter and let
    // the reducer's parser handle nested selectors.
    let segments = path.split('.').count();
    if segments > PATCH_PATH_MAX_SEGMENTS {
        return Err(Error::Protocol(format!(
            "patch path exceeds {PATCH_PATH_MAX_SEGMENTS} segments ({segments} segments)",
        )));
    }
    Ok(())
}

impl Serialize for Patch {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.entries.len()))?;
        for (k, v) in &self.entries {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Patch {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct PatchVisitor;
        impl<'de> Visitor<'de> for PatchVisitor {
            type Value = Patch;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a cx.schema.patch.v1 object (path -> op)")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut access: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut entries: BTreeMap<String, PatchOp> = BTreeMap::new();
                while let Some((path, op)) = access.next_entry::<String, PatchOp>()? {
                    if let Err(err) = validate_path(&path) {
                        return Err(de::Error::custom(err.to_string()));
                    }
                    entries.insert(path, op);
                }
                Ok(Patch { entries })
            }
        }
        deserializer.deserialize_map(PatchVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn direct_value_sugar_round_trips() {
        let mut p = Patch::new();
        p.insert("title", "hello").unwrap();
        let json_text = serde_json::to_string(&p).unwrap();
        assert_eq!(json_text, r#"{"title":"hello"}"#);
        let parsed: Patch = serde_json::from_str(&json_text).unwrap();
        assert_eq!(parsed, p);
        let op = parsed.iter().next().unwrap().1;
        assert_eq!(op.op(), PatchOpKind::Set);
        assert_eq!(op.value(), Some(&json!("hello")));
    }

    #[test]
    fn explicit_set_round_trips() {
        let mut p = Patch::new();
        p.insert_op("counts.pending", PatchOp::set(42)).unwrap();
        let json_text = serde_json::to_string(&p).unwrap();
        // Direct-value sugar is preferred over explicit set when both
        // would serialise to the same shape; but PatchOp::set() builds
        // an explicit Explicit variant, so we expect explicit output.
        assert!(json_text.contains(r#""$op":"set""#));
        let parsed: Patch = serde_json::from_str(&json_text).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn unset_has_no_value() {
        let mut p = Patch::new();
        p.insert_op("optional_field", PatchOp::unset()).unwrap();
        let json_text = serde_json::to_string(&p).unwrap();
        assert_eq!(json_text, r#"{"optional_field":{"$op":"unset"}}"#);
        let parsed: Patch = serde_json::from_str(&json_text).unwrap();
        assert_eq!(parsed, p);
    }

    #[test]
    fn unset_with_value_rejected() {
        let err = serde_json::from_str::<Patch>(r#"{"f":{"$op":"unset","value":1}}"#).unwrap_err();
        assert!(err.to_string().contains("must not carry a value"));
    }

    #[test]
    fn set_without_value_rejected() {
        let err = serde_json::from_str::<Patch>(r#"{"f":{"$op":"set"}}"#).unwrap_err();
        assert!(err.to_string().contains("requires a value"));
    }

    #[test]
    fn unknown_op_field_rejected() {
        let err = serde_json::from_str::<Patch>(r#"{"f":{"$op":"set","value":1,"extra":true}}"#)
            .unwrap_err();
        assert!(err.to_string().contains("must contain only $op and value"));
    }

    #[test]
    fn add_remove_round_trip() {
        let mut p = Patch::new();
        p.insert_op("labels", PatchOp::add(json!("urgent"))).unwrap();
        p.insert_op("labels", PatchOp::remove(json!("draft"))).unwrap();
        // BTreeMap dedupes by key; the second insert wins.
        assert_eq!(p.len(), 1);
        let op = p.iter().next().unwrap().1;
        assert_eq!(op.op(), PatchOpKind::Remove);
        assert_eq!(op.value(), Some(&json!("draft")));
    }

    #[test]
    fn empty_patch_fails_validate() {
        let p = Patch::new();
        assert!(p.validate().is_err());
    }

    #[test]
    fn path_too_long_rejected() {
        let long_path = "a".repeat(PATCH_PATH_MAX_BYTES + 1);
        let mut p = Patch::new();
        assert!(p.insert(long_path, "x").is_err());
    }

    #[test]
    fn path_too_deep_rejected() {
        let deep_path =
            std::iter::repeat("a").take(PATCH_PATH_MAX_SEGMENTS + 1).collect::<Vec<_>>().join(".");
        let mut p = Patch::new();
        assert!(p.insert(deep_path, "x").is_err());
    }

    #[test]
    fn empty_path_rejected() {
        let mut p = Patch::new();
        assert!(p.insert("", "x").is_err());
    }
}
