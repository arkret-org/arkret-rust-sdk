//! `ak.schema.patch.v1` — canonical field-patch grammar.
//!
//! Mirrors `arkret-spec/spec/v1/artifacts/schemas/patch.schema.json`. A
//! patch is an object whose property names are dotted field paths
//! (snake_case identifiers, optional stable-key selectors
//! `field[<key>=<canonical-json-string>]`, backtick-quoted literals for
//! non-snake_case keys; max 1024 bytes, max 16 nesting segments) and
//! whose values are either:
//!
//! - A **direct value** — any JSON value that is *not* a JSON object containing a `$op`
//!   discriminator. Equivalent to `{"$op":"set", "value":<value>}`.
//! - An **explicit op object** — `{ "$op": "set"|"unset"|"add"|"remove", "value": ... }`. `value`
//!   is required for `set`/`add`/`remove` and MUST be absent for `unset`.
//!
//! Selector semantics and redactable-field protection are defined in
//! `zh/models/event-and-patch.md §4`.

use std::collections::BTreeMap;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Result, WireError};
use crate::error_codes::ReasonCode;
use crate::generated::REDACTABLE_FIELD_PATHS;

/// Maximum patch-path length in bytes, per spec.
pub const PATCH_PATH_MAX_BYTES: usize = 1024;

/// Maximum patch-path nesting depth (segments separated by `.`).
pub const PATCH_PATH_MAX_SEGMENTS: usize = 16;

/// Whether a registered path bans `candidate`: the path itself and every dotted
/// descendant of it fall together (`event-and-patch.md` section 4.2.5).
///
/// Shared with consumers of the forbidden-wire-fields projection
/// (`crate::forbidden_wire`) so every matcher applies the same cover rule.
pub fn patch_path_covers(registered: &str, candidate: &str) -> bool {
    candidate == registered
        || (candidate.len() > registered.len()
            && candidate.starts_with(registered)
            && candidate.as_bytes()[registered.len()] == b'.')
}

/// Strip selector suffixes and reject backtick-quoted segments so a registered
/// path can be compared against a wire path segment by segment.
/// Explicit op discriminator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// carrying a `$op` field; validators MUST detect that case and
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
        Self::Explicit {
            op: PatchOpKind::Set,
            value: Some(value.into()),
        }
    }

    /// Build an `unset` operation.
    pub fn unset() -> Self {
        Self::Explicit {
            op: PatchOpKind::Unset,
            value: None,
        }
    }

    /// Build an `add` operation.
    pub fn add(value: impl Into<Value>) -> Self {
        Self::Explicit {
            op: PatchOpKind::Add,
            value: Some(value.into()),
        }
    }

    /// Build a `remove` operation.
    pub fn remove(value: impl Into<Value>) -> Self {
        Self::Explicit {
            op: PatchOpKind::Remove,
            value: Some(value.into()),
        }
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
                    return Err(de::Error::custom(format!(
                        "patch op '{op}' requires a value",
                    )));
                }
                if map
                    .keys()
                    .any(|k| k.as_str() != "$op" && k.as_str() != "value")
                {
                    return Err(de::Error::custom(
                        "patch op object must contain only $op and value",
                    ));
                }
                Ok(Self::Explicit {
                    op: op_kind,
                    value: inner_value,
                })
            }
            _ => Ok(Self::DirectValue(value)),
        }
    }
}

/// A field-patch (ak.schema.patch.v1). MUST contain at least one entry
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
        self.entries
            .insert(path, PatchOp::DirectValue(value.into()));
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

    /// Apply the patch to `prestate` and return the complete post-state.
    ///
    /// The caller supplies the current committed value; the result is the
    /// complete post-state submitted for governance-Station admission.
    /// `prestate` is never mutated: everything happens on a
    /// clone that is discarded on the first failure, which is how §4.4's
    /// "every path succeeds or none applies" atomicity is met.
    ///
    /// Application order is the **canonical patch-path order**: ascending
    /// bytewise over the wire path strings, which is what [`Patch`]'s
    /// `BTreeMap` already stores, so it does not depend on the order the
    /// paths arrived in on the wire nor on any hash-map iteration order.
    /// §4.4 permits exactly this and nothing more: canonical path order is
    /// for signing and diagnostics only and MUST NOT become an "apply A then
    /// B" business escape hatch, so any patch whose result could depend on it (a path
    /// that is a prefix of another, or two paths that decode to the same
    /// field) is rejected as `patch_atomic_conflict` before a single op is
    /// applied. After that rejection the remaining paths are pairwise
    /// disjoint object locations and the result is order-independent by
    /// construction. Patch paths are pure ASCII under the §4.2.1 ABNF, so
    /// bytewise order and RFC 8785's UTF-16 code-unit order coincide.
    ///
    /// Op semantics, all fail-closed (§4.4: any single failure fails the whole
    /// patch, with no partial application of the paths that did pass):
    ///
    /// - `set` — replaces or creates the leaf. Missing **intermediate** object segments are
    ///   created, which `strand-and-message.md` §4.6/§4.8 requires (a `discussion` track that does
    ///   not exist yet is created by `tracks.discussion.enabled` + `tracks.discussion.is_primary`
    ///   in one patch). An intermediate that exists but is not a JSON object is a type mismatch and
    ///   fails.
    /// - `unset` — removes an **existing** leaf. Nothing is auto-created and an absent path fails
    ///   rather than becoming a silent no-op.
    /// - `add` / `remove` — the target MUST already exist and be a JSON array (the "collection"
    ///   these ops are defined against; §4.3.1 step 3 maps them onto `or_set` add/remove, i.e. set
    ///   semantics). `add` rejects a value already present, `remove` rejects a value that is absent
    ///   or present more than once. None of the three degenerates into a no-op.
    ///
    /// Selector segments (`field[key="value"]`) are refused; see
    /// `parse_object_path`.
    ///
    /// Redactable-field protection runs before application.
    pub fn apply(&self, prestate: &Value) -> Result<Value> {
        // `apply` only receives prestate JSON, and trusting an `id` found inside
        // it to choose the safety policy would let a caller borrow another
        // kind's carve-outs. The object kind is proven one layer up, from the
        // payload's typed target, so this hop stays on the superset.
        self.apply_checked(prestate)
    }

    /// Apply a patch after the caller has bound it to the typed target carried
    /// by the validated operation payload.
    ///
    /// Object-specific exceptions are safe only on this path. In particular,
    /// a Strand may update `schema_refs` to atomically activate a registered
    /// profile, while the same path remains create-locked for a Morph.
    pub fn apply_for_typed_target(&self, prestate: &Value, target_ref: &str) -> Result<Value> {
        let _ = target_ref;
        self.apply_checked(prestate)
    }

    fn apply_checked(&self, prestate: &Value) -> Result<Value> {
        validate_patch_semantic_safety(self)?;

        let mut parsed: Vec<(&str, Vec<String>, &PatchOp)> = Vec::with_capacity(self.entries.len());
        for (path, op) in &self.entries {
            parsed.push((path.as_str(), parse_object_path(path)?, op));
        }
        for (index, (path, segments, _)) in parsed.iter().enumerate() {
            for (other_path, other_segments, _) in &parsed[index + 1..] {
                if segments_overlap(segments, other_segments) {
                    return Err(WireError::Protocol(format!(
                        "{}: patch paths '{path}' and '{other_path}' write the same field or a \
                         parent/child pair; split them into separate Events",
                        ReasonCode::PATCH_ATOMIC_CONFLICT
                    )));
                }
            }
        }

        let mut post = prestate.clone();
        for (path, segments, op) in &parsed {
            apply_one(&mut post, path, segments, op)?;
        }
        Ok(post)
    }

    /// Validate that the patch satisfies the spec's wire-level
    /// constraints (`minProperties: 1` and path syntax).
    pub fn validate(&self) -> Result<()> {
        if self.entries.is_empty() {
            return Err(WireError::Protocol(
                "patch must contain at least one entry (minProperties: 1)".to_owned(),
            ));
        }
        for path in self.entries.keys() {
            validate_path(path)?;
        }
        Ok(())
    }
}

/// Validate a patch path's surface syntax. Admission still needs to do
/// the full ABNF check (`zh/models/event-and-patch.md §4.2.1`); this
/// only enforces the byte-length and segment-count limits the spec
/// names explicitly.
pub fn validate_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(WireError::Protocol(
            "patch path must not be empty".to_owned(),
        ));
    }
    if path.len() > PATCH_PATH_MAX_BYTES {
        return Err(WireError::Protocol(format!(
            "patch path exceeds {PATCH_PATH_MAX_BYTES} bytes ({} bytes)",
            path.len()
        )));
    }
    // Count top-level dot segments. Selectors (`[...]`) are part of a
    // segment, not a separator. We treat `.` as the splitter and let
    // the admission parser handle nested selectors.
    let segments = path.split('.').count();
    if segments > PATCH_PATH_MAX_SEGMENTS {
        return Err(WireError::Protocol(format!(
            "patch path exceeds {PATCH_PATH_MAX_SEGMENTS} segments ({segments} segments)",
        )));
    }
    Ok(())
}

/// Parse a patch path into its decoded object keys.
///
/// Implements the §4.2.1 ABNF for the two segment forms this crate can
/// resolve against a JSON document: `identifier` (`^[a-z][a-z0-9_]{0,63}$`)
/// and `quoted-identifier` (backtick-quoted printable ASCII, a literal
/// backtick doubled). The parser is deterministic and takes no fallback path,
/// per §4.2.2 — the first byte that does not fit the grammar ends the parse.
///
/// **`selector-segment` is refused.** It is not part of `ak.patch.v1`: §4.2.1
/// states the form MUST be rejected, and §4.2.3 gives the alternatives (rebuild
/// the collection as a map, use a profile-registered move/update event, or an
/// explicit API field). A selector segment fails closed with
/// `patch_path_invalid`.
fn parse_object_path(path: &str) -> Result<Vec<String>> {
    validate_path(path)?;
    let bytes = path.as_bytes();
    let mut segments: Vec<String> = Vec::new();
    let mut cursor = 0usize;
    loop {
        if cursor >= bytes.len() {
            return Err(patch_path_invalid(path, "has an empty trailing segment"));
        }
        if bytes[cursor] == b'`' {
            cursor += 1;
            let mut decoded = String::new();
            loop {
                let Some(&byte) = bytes.get(cursor) else {
                    return Err(patch_path_invalid(
                        path,
                        "has an unterminated backtick-quoted segment",
                    ));
                };
                if byte == b'`' {
                    // A literal backtick is escaped as two backticks.
                    if bytes.get(cursor + 1) == Some(&b'`') {
                        decoded.push('`');
                        cursor += 2;
                        continue;
                    }
                    cursor += 1;
                    break;
                }
                if !(0x20..=0x7f).contains(&byte) {
                    return Err(patch_path_invalid(
                        path,
                        "has a quoted segment with a byte outside quoted-char (%x20-5F / %x61-7F)",
                    ));
                }
                decoded.push(byte as char);
                cursor += 1;
            }
            if decoded.is_empty() {
                return Err(patch_path_invalid(path, "has an empty quoted segment"));
            }
            segments.push(decoded);
        } else {
            let start = cursor;
            while cursor < bytes.len() && bytes[cursor] != b'.' {
                cursor += 1;
            }
            let raw = &path[start..cursor];
            if raw.contains('[') || raw.contains(']') {
                return Err(patch_path_invalid(
                    path,
                    "uses a stable-key selector segment, which this applier refuses: the ABNF and \
                     the registered patch_path pattern disagree on the selector-value form and the \
                     key's uniqueness is only knowable from the item schema",
                ));
            }
            if !is_patch_identifier(raw) {
                return Err(patch_path_invalid(
                    path,
                    "has a segment that is not a ^[a-z][a-z0-9_]{0,63}$ identifier",
                ));
            }
            segments.push(raw.to_owned());
        }
        if cursor == bytes.len() {
            break;
        }
        if bytes[cursor] != b'.' {
            return Err(patch_path_invalid(
                path,
                "has a malformed segment separator",
            ));
        }
        cursor += 1;
    }
    Ok(segments)
}

fn is_patch_identifier(segment: &str) -> bool {
    let mut chars = segment.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    segment.len() <= 64
        && first.is_ascii_lowercase()
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Whether two decoded paths address the same field or a parent/child pair.
fn segments_overlap(left: &[String], right: &[String]) -> bool {
    left.iter().zip(right).all(|(a, b)| a == b)
}

fn apply_one(root: &mut Value, path: &str, segments: &[String], op: &PatchOp) -> Result<()> {
    let (leaf, parents) = segments
        .split_last()
        .ok_or_else(|| patch_path_invalid(path, "decodes to no segments"))?;
    match op.op() {
        PatchOpKind::Set => {
            let value = required_value(path, op)?;
            let parent = descend_mut(root, path, parents, true)?;
            let object = expect_object_mut(parent, path, leaf)?;
            object.insert(leaf.clone(), value.clone());
        }
        PatchOpKind::Unset => {
            let parent = descend_mut(root, path, parents, false)?;
            let object = expect_object_mut(parent, path, leaf)?;
            if object.remove(leaf).is_none() {
                return Err(patch_apply_failed(
                    path,
                    "the field does not exist in the pre-state",
                ));
            }
        }
        PatchOpKind::Add => {
            let value = required_value(path, op)?;
            let target = descend_mut(root, path, segments, false)?;
            let items = expect_array_mut(target, path)?;
            if items.iter().any(|item| item == value) {
                return Err(patch_apply_failed(
                    path,
                    "the collection already contains this value",
                ));
            }
            items.push(value.clone());
        }
        PatchOpKind::Remove => {
            let value = required_value(path, op)?;
            let target = descend_mut(root, path, segments, false)?;
            let items = expect_array_mut(target, path)?;
            let hits: Vec<usize> = items
                .iter()
                .enumerate()
                .filter(|(_, item)| *item == value)
                .map(|(index, _)| index)
                .collect();
            match hits.as_slice() {
                [] => {
                    return Err(patch_apply_failed(
                        path,
                        "the collection does not contain this value",
                    ));
                }
                [index] => {
                    items.remove(*index);
                }
                _ => {
                    return Err(patch_apply_failed(
                        path,
                        "the collection contains this value more than once",
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Walk `segments` from `root`. `create_missing` is only ever true for `set`,
/// where §4.6/§4.8 of `strand-and-message.md` require a missing intermediate
/// object to be created; every other op must find the path already there.
fn descend_mut<'a>(
    root: &'a mut Value,
    path: &str,
    segments: &[String],
    create_missing: bool,
) -> Result<&'a mut Value> {
    let mut current = root;
    for segment in segments {
        let Value::Object(object) = current else {
            return Err(not_an_object(path, segment));
        };
        if !object.contains_key(segment) {
            if !create_missing {
                return Err(patch_apply_failed(
                    path,
                    &format!("segment '{segment}' does not exist in the pre-state"),
                ));
            }
            object.insert(segment.clone(), Value::Object(serde_json::Map::new()));
        }
        current = object
            .get_mut(segment)
            .expect("segment was just verified or inserted");
    }
    Ok(current)
}

fn expect_object_mut<'a>(
    value: &'a mut Value,
    path: &str,
    leaf: &str,
) -> Result<&'a mut serde_json::Map<String, Value>> {
    value
        .as_object_mut()
        .ok_or_else(|| not_an_object(path, leaf))
}

fn expect_array_mut<'a>(value: &'a mut Value, path: &str) -> Result<&'a mut Vec<Value>> {
    value.as_array_mut().ok_or_else(|| {
        patch_apply_failed(
            path,
            "add/remove need a JSON array but the field is not one",
        )
    })
}

fn required_value<'a>(path: &str, op: &'a PatchOp) -> Result<&'a Value> {
    op.value()
        .ok_or_else(|| patch_apply_failed(path, "op requires a `value` but carries none"))
}

fn not_an_object(path: &str, segment: &str) -> WireError {
    patch_apply_failed(
        path,
        &format!("the value enclosing '{segment}' is not a JSON object"),
    )
}

fn patch_path_invalid(path: &str, detail: &str) -> WireError {
    WireError::Protocol(format!(
        "{}: patch path '{path}' {detail}",
        ReasonCode::PATCH_PATH_INVALID
    ))
}

fn patch_apply_failed(path: &str, detail: &str) -> WireError {
    WireError::Protocol(format!("patch path '{path}' cannot be applied: {detail}"))
}

/// Validate cross-object patch safety rules that are independent of the
/// current committed object value.
pub fn validate_patch_semantic_safety(patch: &Patch) -> Result<()> {
    patch.validate()?;
    for (path, op) in patch.iter() {
        if matches!(op.op(), PatchOpKind::Unset | PatchOpKind::Remove)
            && patch_path_targets_redactable_unset(path)
        {
            return Err(WireError::Protocol(
                ReasonCode::PATCH_UNSET_REDACTABLE_FIELD.to_owned(),
            ));
        }
    }
    Ok(())
}

/// Whether a patch path addresses a registered redactable content-carrier slot.
///
/// The slot set is the canonical projection in
/// `registry/redactable-field-registry.json`; this module never spells its own
/// list. `metadata`, `encrypted_metadata`, `metadata.title`, `metadata.summary`
/// and every path under `metadata.fields` are ordinary optional members, not
/// content slots: `$op="unset"` is their only non-terminal clear path and MUST
/// be accepted (`event-and-patch.md` §4.2.4). Realm-defined
/// `redactable: true` fields are declared by their own Realm schema and are
/// enforced by the governance Station's schema policy, not here.
fn patch_path_targets_redactable_unset(path: &str) -> bool {
    REDACTABLE_FIELD_PATHS
        .iter()
        .any(|slot| path == *slot || path.starts_with(&format!("{slot}.")))
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
                f.write_str("a ak.schema.patch.v1 object (path -> op)")
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
    use serde_json::json;

    use super::*;

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
        p.insert_op("labels", PatchOp::add(json!("urgent")))
            .unwrap();
        p.insert_op("labels", PatchOp::remove(json!("draft")))
            .unwrap();
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
        let deep_path = std::iter::repeat_n("a", PATCH_PATH_MAX_SEGMENTS + 1)
            .collect::<Vec<_>>()
            .join(".");
        let mut p = Patch::new();
        assert!(p.insert(deep_path, "x").is_err());
    }

    #[test]
    fn empty_path_rejected() {
        let mut p = Patch::new();
        assert!(p.insert("", "x").is_err());
    }

    #[test]
    fn validate_patch_semantic_safety_rejects_direct_redactable_unset() {
        let mut patch = Patch::new();
        patch
            .insert_op("encrypted_content", PatchOp::unset())
            .unwrap();

        let err = validate_patch_semantic_safety(&patch).unwrap_err();
        assert!(
            err.to_string()
                .contains(ReasonCode::PATCH_UNSET_REDACTABLE_FIELD)
        );
    }

    #[test]
    fn validate_patch_semantic_safety_allows_non_redactable_metadata_unset() {
        // `event-and-patch.md` §4.2.4 keeps these out of the ban on purpose:
        // they are ordinary optional members, and `unset` is their only
        // non-terminal clear path.
        for path in [
            "metadata",
            "metadata.title",
            "metadata.summary",
            "metadata.fields.summary",
            "metadata.fields.due_date",
            "encrypted_metadata",
        ] {
            let mut patch = Patch::new();
            patch.insert_op(path, PatchOp::unset()).unwrap();
            validate_patch_semantic_safety(&patch)
                .unwrap_or_else(|error| panic!("unset on {path} must be accepted: {error}"));
        }
    }

    #[test]
    fn validate_patch_semantic_safety_allows_set_on_a_redactable_slot() {
        // Clearing a body is ordinary authoring: `set` with an empty body stays
        // legal on the very paths whose `unset` is banned.
        for path in REDACTABLE_FIELD_PATHS {
            let mut patch = Patch::new();
            patch
                .insert_op(
                    *path,
                    PatchOp::set(serde_json::json!({"kind": "ak.content.text", "body": ""})),
                )
                .unwrap();
            validate_patch_semantic_safety(&patch)
                .unwrap_or_else(|error| panic!("set on {path} must be accepted: {error}"));
        }
    }

    #[test]
    fn redactable_slot_paths_come_from_the_registry_projection() {
        // The registry projection is the source: separating Strand Description
        // from Synthesis added the two `tracks.synthesis.*` slots, and this
        // assertion is what keeps the constant honest about that.
        assert_eq!(
            REDACTABLE_FIELD_PATHS,
            &[
                "content",
                "encrypted_content",
                "tracks.synthesis.content",
                "tracks.synthesis.encrypted_content"
            ]
        );
        for path in REDACTABLE_FIELD_PATHS {
            let mut patch = Patch::new();
            patch.insert_op(*path, PatchOp::unset()).unwrap();
            let error = validate_patch_semantic_safety(&patch).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(ReasonCode::PATCH_UNSET_REDACTABLE_FIELD)
            );
        }
    }

    fn patch_of(entries: &[(&str, PatchOp)]) -> Patch {
        let mut patch = Patch::new();
        for (path, op) in entries {
            patch.insert_op(*path, op.clone()).unwrap();
        }
        patch
    }

    #[test]
    fn apply_set_returns_the_complete_poststate() {
        let prestate = json!({"metadata": {"fields": {"review_status": "pending"}}});
        let patch = patch_of(&[(
            "metadata.fields.review_status",
            PatchOp::set(json!("approved")),
        )]);

        let post = patch.apply(&prestate).unwrap();

        assert_eq!(
            post,
            json!({"metadata": {"fields": {"review_status": "approved"}}})
        );
        // The pre-state is left untouched.
        assert_eq!(
            prestate,
            json!({"metadata": {"fields": {"review_status": "pending"}}})
        );
    }

    #[test]
    fn apply_direct_value_sugars_to_set() {
        let mut patch = Patch::new();
        patch.insert("title", "renamed").unwrap();

        let post = patch.apply(&json!({"title": "old"})).unwrap();

        assert_eq!(post, json!({"title": "renamed"}));
    }

    #[test]
    fn apply_set_creates_missing_intermediate_objects() {
        // strand-and-message.md §4.6/§4.8: switching to a `discussion` track
        // that does not exist yet writes `enabled` + `is_primary` in one patch.
        let prestate = json!({"tracks": {"synthesis": {"is_primary": true}}});
        let patch = patch_of(&[
            ("tracks.discussion.enabled", PatchOp::set(json!(true))),
            ("tracks.discussion.is_primary", PatchOp::set(json!(true))),
            ("tracks.synthesis.is_primary", PatchOp::set(json!(false))),
        ]);

        let post = patch.apply(&prestate).unwrap();

        assert_eq!(
            post,
            json!({
                "tracks": {
                    "synthesis": {"is_primary": false},
                    "discussion": {"enabled": true, "is_primary": true}
                }
            })
        );
    }

    #[test]
    fn apply_is_independent_of_wire_entry_order() {
        let prestate = json!({"tracks": {"synthesis": {"is_primary": true}}});
        let forward: Patch = serde_json::from_str(
            r#"{"tracks.discussion.is_primary":{"$op":"set","value":true},
                "tracks.synthesis.is_primary":{"$op":"set","value":false}}"#,
        )
        .unwrap();
        let reversed: Patch = serde_json::from_str(
            r#"{"tracks.synthesis.is_primary":{"$op":"set","value":false},
                "tracks.discussion.is_primary":{"$op":"set","value":true}}"#,
        )
        .unwrap();

        assert_eq!(
            forward.apply(&prestate).unwrap(),
            reversed.apply(&prestate).unwrap()
        );
    }

    #[test]
    fn apply_set_on_a_non_object_intermediate_fails_closed() {
        let patch = patch_of(&[("metadata.title", PatchOp::set(json!("x")))]);

        let err = patch
            .apply(&json!({"metadata": "not-an-object"}))
            .unwrap_err();

        assert!(err.to_string().contains("not a JSON object"));
    }

    #[test]
    fn profile_schema_activation_is_a_regular_atomic_patch() {
        let patch = patch_of(&[
            (
                "schema_refs",
                PatchOp::set(json!(["ak.schema.calendar_event.v1"])),
            ),
            (
                "metadata.fields.calendar",
                PatchOp::set(json!({"status": "confirmed"})),
            ),
        ]);
        let prestate = json!({"metadata": {"fields": {}}});

        let expected = json!({
            "metadata": {"fields": {"calendar": {"status": "confirmed"}}},
            "schema_refs": ["ak.schema.calendar_event.v1"],
        });
        assert_eq!(patch.apply(&prestate).unwrap(), expected);
        assert_eq!(
            patch
                .apply_for_typed_target(
                    &prestate,
                    "ak:strand:AU5DHBAGpYtmqCmUCrwMu2Tclj6LWbwoSjogDjJMHyNA",
                )
                .unwrap(),
            expected
        );
    }

    #[test]
    fn apply_on_a_non_object_root_fails_closed() {
        let patch = patch_of(&[("title", PatchOp::set(json!("x")))]);

        let err = patch.apply(&json!("scalar")).unwrap_err();

        assert!(err.to_string().contains("not a JSON object"));
    }

    #[test]
    fn apply_unset_removes_an_existing_field() {
        let patch = patch_of(&[("metadata.draft_note", PatchOp::unset())]);

        let post = patch
            .apply(&json!({"metadata": {"draft_note": "x", "keep": 1}}))
            .unwrap();

        assert_eq!(post, json!({"metadata": {"keep": 1}}));
    }

    #[test]
    fn apply_unset_on_a_missing_field_fails_closed() {
        let patch = patch_of(&[("metadata.draft_note", PatchOp::unset())]);

        let err = patch.apply(&json!({"metadata": {"keep": 1}})).unwrap_err();

        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn apply_unset_on_a_missing_parent_fails_closed() {
        let patch = patch_of(&[("metadata.draft_note", PatchOp::unset())]);

        let err = patch.apply(&json!({})).unwrap_err();

        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn apply_add_appends_to_an_existing_array() {
        let patch = patch_of(&[("labels", PatchOp::add(json!("urgent")))]);

        let post = patch.apply(&json!({"labels": ["draft"]})).unwrap();

        assert_eq!(post, json!({"labels": ["draft", "urgent"]}));
    }

    #[test]
    fn apply_add_of_a_present_value_fails_closed() {
        let patch = patch_of(&[("labels", PatchOp::add(json!("draft")))]);

        let err = patch.apply(&json!({"labels": ["draft"]})).unwrap_err();

        assert!(err.to_string().contains("already contains"));
    }

    #[test]
    fn apply_add_against_a_non_array_fails_closed() {
        let patch = patch_of(&[("labels", PatchOp::add(json!("urgent")))]);

        let err = patch.apply(&json!({"labels": "draft"})).unwrap_err();

        assert!(err.to_string().contains("need a JSON array"));
    }

    #[test]
    fn apply_add_on_a_missing_field_fails_closed() {
        let patch = patch_of(&[("labels", PatchOp::add(json!("urgent")))]);

        let err = patch.apply(&json!({})).unwrap_err();

        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn apply_remove_drops_the_matching_element() {
        let patch = patch_of(&[("labels", PatchOp::remove(json!("draft")))]);

        let post = patch
            .apply(&json!({"labels": ["draft", "urgent"]}))
            .unwrap();

        assert_eq!(post, json!({"labels": ["urgent"]}));
    }

    #[test]
    fn apply_remove_of_an_absent_value_fails_closed() {
        let patch = patch_of(&[("labels", PatchOp::remove(json!("draft")))]);

        let err = patch.apply(&json!({"labels": ["urgent"]})).unwrap_err();

        assert!(err.to_string().contains("does not contain"));
    }

    #[test]
    fn apply_remove_of_a_duplicated_value_fails_closed() {
        let patch = patch_of(&[("labels", PatchOp::remove(json!("draft")))]);

        let err = patch
            .apply(&json!({"labels": ["draft", "draft"]}))
            .unwrap_err();

        assert!(err.to_string().contains("more than once"));
    }

    #[test]
    fn apply_rejects_parent_child_path_conflicts() {
        let patch = patch_of(&[
            ("metadata", PatchOp::set(json!({"title": "a"}))),
            ("metadata.title", PatchOp::set(json!("b"))),
        ]);

        let err = patch
            .apply(&json!({"metadata": {"title": "x"}}))
            .unwrap_err();

        assert!(err.to_string().contains(ReasonCode::PATCH_ATOMIC_CONFLICT));
    }

    #[test]
    fn apply_rejects_two_spellings_of_the_same_field() {
        // `title` and `` `title` `` decode to the same object key, so canonical
        // path order would silently pick a winner.
        let patch = patch_of(&[
            ("title", PatchOp::set(json!("a"))),
            ("`title`", PatchOp::set(json!("b"))),
        ]);

        let err = patch.apply(&json!({"title": "x"})).unwrap_err();

        assert!(err.to_string().contains(ReasonCode::PATCH_ATOMIC_CONFLICT));
    }

    #[test]
    fn apply_supports_backtick_quoted_segments() {
        let patch = patch_of(&[("metadata.`Odd Key`", PatchOp::set(json!(1)))]);

        let post = patch.apply(&json!({"metadata": {}})).unwrap();

        assert_eq!(post, json!({"metadata": {"Odd Key": 1}}));
    }

    #[test]
    fn apply_decodes_a_doubled_backtick_as_a_literal_one() {
        let patch = patch_of(&[("`a``b`", PatchOp::set(json!(1)))]);

        let post = patch.apply(&json!({})).unwrap();

        assert_eq!(post, json!({"a`b": 1}));
    }

    #[test]
    fn apply_fails_closed_on_selector_segments() {
        let patch = patch_of(&[(r#"items[id="x"].name"#, PatchOp::set(json!("y")))]);

        let err = patch
            .apply(&json!({"items": [{"id": "x", "name": "old"}]}))
            .unwrap_err();

        let message = err.to_string();
        assert!(message.contains(ReasonCode::PATCH_PATH_INVALID));
        assert!(message.contains("stable-key selector"));
    }

    #[test]
    fn apply_rejects_non_identifier_segments() {
        for path in ["Title", "_title", "ti-tle", "métadonnées"] {
            let patch = patch_of(&[(path, PatchOp::set(json!(1)))]);
            let err = patch.apply(&json!({})).unwrap_err();
            assert!(
                err.to_string().contains(ReasonCode::PATCH_PATH_INVALID),
                "{path} must be rejected as patch_path_invalid"
            );
        }
    }

    #[test]
    fn apply_rejects_malformed_quoted_segments() {
        for path in ["`unterminated", "``", "`ok`x"] {
            let patch = patch_of(&[(path, PatchOp::set(json!(1)))]);
            let err = patch.apply(&json!({})).unwrap_err();
            assert!(
                err.to_string().contains(ReasonCode::PATCH_PATH_INVALID),
                "{path} must be rejected as patch_path_invalid"
            );
        }
    }

    #[test]
    fn apply_rejects_redactable_paths_before_touching_the_prestate() {
        let redactable = patch_of(&[("encrypted_content", PatchOp::unset())]);
        assert!(
            redactable
                .apply(&json!({"encrypted_content": "x"}))
                .unwrap_err()
                .to_string()
                .contains(ReasonCode::PATCH_UNSET_REDACTABLE_FIELD)
        );
    }

    #[test]
    fn apply_rejects_an_empty_patch() {
        assert!(Patch::new().apply(&json!({})).is_err());
    }

    #[test]
    fn apply_leaves_the_prestate_untouched_when_one_path_fails() {
        let prestate = json!({"metadata": {"keep": 1}});
        let patch = patch_of(&[
            ("metadata.added", PatchOp::set(json!(true))),
            ("metadata.missing", PatchOp::unset()),
        ]);

        assert!(patch.apply(&prestate).is_err());
        assert_eq!(prestate, json!({"metadata": {"keep": 1}}));
    }
}
