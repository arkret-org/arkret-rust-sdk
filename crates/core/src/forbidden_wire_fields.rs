//! Forbidden wire-field registry (CXP-0007 + earlier rounds).
//!
//! Single source of truth for the spec's
//! `artifacts/registry/forbidden-wire-fields.json` hard-reject set as it
//! lands in the SDK. Receivers (soland, sodmin, yougen, etc.) call
//! [`is_forbidden_wire_field`] to reject any Event payload that carries
//! one of these legacy field names at the wire layer.
//!
//! This module is intentionally narrow: it covers field names that are
//! `hard_reject` AT THE TOP LEVEL of an Event payload object or known
//! payload sub-objects. Path-shaped entries (`fields.stage`,
//! `patch:stage`, …) and prefix-shaped entries
//! (`cx:notif:`, `cx:devmsg:`, …) are NOT covered here yet — they need
//! callers to pass the surrounding context, which is best handled by
//! richer validators in the SDK schema layer.

/// Spec `forbidden-wire-fields.json` entries that name a single
/// top-level field. Receivers MUST hard-reject any Event payload that
/// carries one of these keys.
///
/// Source of truth: `spec/v1/artifacts/registry/forbidden-wire-fields.json`
/// (CXP-0007 spec floor 2b0d70d, plus earlier rounds carried forward).
pub const FORBIDDEN_WIRE_FIELDS: &[&str] = &[
    // Legacy timeline / Realm/Space inversion.
    "branch",
    "room_kind",
    // CXP-0007 pre-rename Flow scope field — spec renamed to
    // `scope_circle_id`; the SDK additionally hard-rejects the
    // pre-CXP-0007 `discussion_realm_ref` field carried over from the
    // pre-inversion code base. (Plan calls out `discussion_realm_ref`;
    // the canonical spec entry is `discussion_space_ref`.)
    "discussion_realm_ref",
    "discussion_space_ref",
    // CXP-0007 batch-renamed identifier fields. Spec
    // `identifier_suffix_ref_to_id_batch` lists the deleted `_ref`
    // forms that MUST NOT appear on the current v1 wire.
    "parent_ref",
    "default_realm_ref",
    "scope_ref",
    "default_scope_ref",
    "retention_policy_ref",
    "disclosure_policy_ref",
    "rate_limit_policy_ref",
    // policy_ref is keep on Realm itself (object-self id), but rejected
    // on Policy-object wire forms — TODO(circle-rollout-P1.5):
    // expose a context-aware checker once the schema layer can pass
    // the parent kind.
];

/// Returns `true` when `key` names a top-level wire field that MUST be
/// hard-rejected by SDK receivers per
/// `spec/v1/artifacts/registry/forbidden-wire-fields.json`.
pub fn is_forbidden_wire_field(key: &str) -> bool {
    FORBIDDEN_WIRE_FIELDS.contains(&key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_discussion_realm_ref() {
        assert!(is_forbidden_wire_field("discussion_realm_ref"));
    }

    #[test]
    fn rejects_discussion_space_ref() {
        assert!(is_forbidden_wire_field("discussion_space_ref"));
    }

    #[test]
    fn rejects_legacy_scope_ref_batch() {
        for field in
            ["parent_ref", "default_realm_ref", "scope_ref", "default_scope_ref"]
        {
            assert!(
                is_forbidden_wire_field(field),
                "field `{field}` must be in the hard-reject set"
            );
        }
    }

    #[test]
    fn accepts_canonical_replacements() {
        for field in
            ["scope_circle_id", "default_scope_circle_id", "parent_space_id"]
        {
            assert!(
                !is_forbidden_wire_field(field),
                "canonical replacement `{field}` must not be hard-rejected"
            );
        }
    }
}
