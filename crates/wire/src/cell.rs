//! Cell id parsing and composite-subject helpers.
//!
//! Per spec `event-auth-state-resolution.md` §2 a cell id is the smallest
//! protocol-level state unit identified as
//!
//! ```text
//! ak:cell:<component>:<subject>
//! ```
//!
//! - `<component>` is the cell family (e.g. `ak.component.member.state.v1`,
//!   `ak.component.capability.grant.v1`, `ak.component.consent.grant.v1`).
//! - `<subject>` may be a flat identifier (`did.web.alice.example`,
//!   `ak.grant.01js0gr0000000000000000000`) or a deterministic composite subject when the spec
//!   event-kind-registry's `cell_subject` declares `composite` form.
//!
//! Composite subjects are `base64url_nopad(sha256(canonical_json([...])))`
//! over an ordered components array. The order is fixed per cell family
//! (encoding.md §9.5). This module exposes:
//!
//! - [`CellId::parse`] — strict parser for `ak:cell:<component>:<subject>`.
//! - [`CellId::component`] / [`CellId::subject`] — accessors.
//! - [`composite_subject`] — produce the canonical composite subject hash for a fixed-order typed
//!   JSON scalar array (the wire-canonical form).
//! - [`composite_subject_pipe`] — produce the diagnostic `a|b|c` form (informational only; never
//!   wire-canonical).

use std::collections::BTreeSet;

use crate::{CellRef, Result, WireError, canonical};

const CELL_PREFIX: &str = "ak:cell:";

/// Canonical wire subject segment of a cell family declared with
/// `cell_subject: null` in the contract catalog (`encoding.md` section 4).
///
/// These families are located by the Event envelope `realm_id`. The literal
/// ASCII `null` is used rather than an empty segment because `ak:cell:<family>:`
/// cannot be told apart from a truncated wire id, and truncated ids must be
/// rejected. Implementations MUST NOT encode `realm_id`, a Realm role
/// classification, or any payload-derived value into this segment: the subject
/// is both the `state_root` leaf preimage content and the leaf sort key, so a
/// divergent spelling forks `state_root` across implementations.
pub const NULL_SUBJECT: &str = "null";

/// Build a canonical wire cell id from a registered family and its subject.
///
/// Callers should normally pass a [`crate::CellFamilyId`] associated constant,
/// keeping registered family spellings centralized in generated code.
pub fn subject_cell(component: &str, subject: &str) -> String {
    format!("{CELL_PREFIX}{component}:{subject}")
}

/// Build the canonical wire cell id of a `cell_subject: null` family.
pub fn null_subject_cell(component: &str) -> String {
    subject_cell(component, NULL_SUBJECT)
}

/// Canonical genesis-log cell of every `ak.realm.create` (`ordered_log`).
pub const REALM_CREATE_CELL: &str = "ak:cell:ak.component.realm.create.v1:null";
/// Canonical minimal Realm identity/security root written by `ak.realm.create`.
pub const REALM_GENESIS_CELL: &str = "ak:cell:ak.component.realm.genesis.v1:null";
/// Canonical Realm display profile written only by `ak.realm.profile`.
pub const REALM_PROFILE_CELL: &str = "ak:cell:ak.component.realm.profile.v1:null";
/// Canonical per-Realm notary control cell; its genesis value is an explicit
/// `ak.realm.create` effect and later values come from `ak.realm.notary`.
pub const REALM_NOTARY_CELL: &str = "ak:cell:ak.component.notary.v1:null";
/// Canonical per-Realm reducer-profile cell, seeded by `ak.realm.create`.
pub const REALM_REDUCER_PROFILE_CELL: &str = "ak:cell:ak.component.realm.reducer_profile.v1:null";
/// Canonical per-Realm authority root, written by `ak.realm.create` and the
/// only cell that carries Realm owner authority
/// (`models/realm-and-space.md` section 2.5). `(realm_id, this cell)` is the
/// Realm's lifetime authority identity; the value's `controller_id` is only who
/// holds it right now. It doubles as the closed `authorization_ref` constant an
/// Event uses to claim that authority, so it is spelled once here rather than
/// re-derived per consumer.
pub const REALM_AUTHORITY_ROOT_CELL: &str = "ak:cell:ak.component.realm.authority_root.v1:null";

/// Parsed cell id with its component family and subject substrings.
///
/// The wire string is held in [`CellRef`]; [`CellId`] is a borrow-style
/// view over it so we don't allocate copies for hot paths (validate / log /
/// project). The component must be a complete `ak.component.*.v<n>` family.
/// A family with a single instance per Realm does **not** use an empty subject:
/// its canonical subject segment is the literal ASCII [`NULL_SUBJECT`]
/// (`encoding.md` section 4), because an empty trailing segment cannot be told
/// apart from a truncated wire id.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CellId {
    component: String,
    subject: String,
}

impl CellId {
    /// Parse a `ak:cell:<component>:<subject>` string into typed parts.
    ///
    /// Both `<component>` and `<subject>` may contain dots and additional
    /// colons (subject can itself be a typed id like
    /// `ak.grant.01js0gr...`). The split happens on the **first** colon
    /// after the `ak:cell:` prefix to keep the component canonical.
    pub fn parse(value: &str) -> Result<Self> {
        let rest = value.strip_prefix(CELL_PREFIX).ok_or_else(|| {
            WireError::Protocol(format!("cell id missing 'ak:cell:' prefix: {value}"))
        })?;
        let (component, subject) = rest.split_once(':').ok_or_else(|| {
            WireError::Protocol(format!(
                "cell id missing component:subject separator: {value}"
            ))
        })?;
        if component.is_empty() {
            return Err(WireError::Protocol(format!(
                "cell id has empty component: {value}"
            )));
        }
        if !arkret_identifiers::is_cell_family(component) {
            return Err(WireError::Protocol(format!(
                "cell id component is not a canonical ak.component.*.v<n> family: {value}"
            )));
        }
        Ok(Self {
            component: component.to_owned(),
            subject: subject.to_owned(),
        })
    }

    /// Parse from a typed [`CellRef`].
    pub fn from_ref(value: &CellRef) -> Result<Self> {
        Self::parse(value.as_str())
    }

    /// The cell family / component portion (e.g. `ak.component.member.state.v1`).
    pub fn component(&self) -> &str {
        &self.component
    }

    /// The subject portion (may be empty for singleton cells).
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Re-emit the cell id as a wire string.
    pub fn to_wire(&self) -> String {
        if self.subject.is_empty() {
            format!("{CELL_PREFIX}{}:", self.component)
        } else {
            format!("{CELL_PREFIX}{}:{}", self.component, self.subject)
        }
    }
}

/// Canonical composite cell subject: `base64url_nopad(sha256(canonical_json([...])))`.
///
/// Component conversion accepted by [`composite_subject`].
///
/// String slices keep existing typed-ID and DID callers allocation-light;
/// [`serde_json::Value`] supports the complete v1 scalar set, including JSON
/// null for series-level RSVP subjects.
pub trait CompositeSubjectComponent {
    fn to_json_scalar(&self) -> serde_json::Value;
}

impl CompositeSubjectComponent for &str {
    fn to_json_scalar(&self) -> serde_json::Value {
        serde_json::Value::String((*self).to_owned())
    }
}

impl CompositeSubjectComponent for String {
    fn to_json_scalar(&self) -> serde_json::Value {
        serde_json::Value::String(self.clone())
    }
}

impl CompositeSubjectComponent for serde_json::Value {
    fn to_json_scalar(&self) -> serde_json::Value {
        self.clone()
    }
}

/// `parts` MUST be in the fixed order declared by the cell family's
/// `cell_subject` descriptor (spec encoding.md §9.5). Values retain their JSON
/// types; only string, integer, boolean, and null components are valid. Reorder
/// negative vectors MUST diverge from this form.
pub fn composite_subject<T: CompositeSubjectComponent>(parts: &[T]) -> Result<String> {
    let components = parts
        .iter()
        .map(CompositeSubjectComponent::to_json_scalar)
        .collect::<Vec<_>>();
    for component in &components {
        let valid = match component {
            serde_json::Value::String(_) | serde_json::Value::Bool(_) | serde_json::Value::Null => {
                true
            }
            serde_json::Value::Number(number) => number.is_i64() || number.is_u64(),
            serde_json::Value::Array(_) | serde_json::Value::Object(_) => false,
        };
        if !valid {
            return Err(WireError::Protocol(
                "composite subject components must be JSON string, integer, boolean, or null"
                    .to_owned(),
            ));
        }
    }
    let bytes = canonical::canonical_json_bytes(&components)?;
    Ok(canonical::sha256_base64url(&bytes))
}

/// Canonical cell subject for a registry `cell_subject.kind = "uri"` field
/// (`conformance/encoding.md` §4 subject-kind dispatch table).
///
/// Every octet outside the subject unreserved set (`ALPHA / DIGIT / - . _ ~`)
/// is percent-encoded with upper-case hex, **including `:`, `/` and `%`
/// itself**. The result therefore carries no CellRef structure character and
/// occupies a single subject segment.
///
/// Encoding `%` is what makes the transform injective. Keeping already-escaped
/// octets verbatim — the rule the `did` / `typed_id` / `string` kinds use —
/// would fold `…/rooms/a%2Fb` and `…/rooms/a/b` onto one subject; those are two
/// different rooms, so an external provider could mint an alias for, hijack or
/// block somebody else's binding cell. The caller MUST pass the already
/// canonical URI: this function addresses a cell, it does not normalize one.
pub fn uri_cell_subject(uri: &str) -> String {
    let mut subject = String::with_capacity(uri.len() * 3);
    for byte in uri.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            subject.push(char::from(*byte));
        } else {
            subject.push('%');
            subject.push(char::from(HEX_UPPER[usize::from(byte >> 4)]));
            subject.push(char::from(HEX_UPPER[usize::from(byte & 0x0f)]));
        }
    }
    subject
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// Canonical domain-separated digest for a closed, non-empty JSON string set.
///
/// This transformation happens before a value is passed to
/// [`composite_subject`]; arrays remain forbidden as ordinary composite
/// components.
pub fn string_set_digest_component(values: &[String], context: &str) -> Result<String> {
    if context.is_empty() || !context.is_ascii() {
        return Err(WireError::Protocol(
            "string-set digest context must be non-empty ASCII".to_owned(),
        ));
    }
    if values.is_empty() {
        return Err(WireError::Protocol(
            "string-set digest input must not be empty".to_owned(),
        ));
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(WireError::Protocol(
            "string-set digest input must contain unique values".to_owned(),
        ));
    }
    let mut canonical_values = values.to_vec();
    canonical_values.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    let mut preimage = context.as_bytes().to_vec();
    preimage.push(b'\n');
    preimage.extend(canonical::canonical_json_bytes(&canonical_values)?);
    Ok(canonical::sha256_base64url(preimage))
}

/// Pipe-joined diagnostic form (`a|b|c`, with `|` and `%` percent-encoded).
///
/// **Never wire-canonical.** Used only for human-readable logs / error
/// payloads. Wire-canonical composite subjects always go through
/// [`composite_subject`] (hash form). Equivalent to
/// [`canonical::encode_state_subject`].
pub fn composite_subject_pipe(parts: &[&str]) -> String {
    canonical::encode_state_subject(parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DomainSeparationId;

    #[test]
    fn parse_simple_cell_id() {
        let id =
            CellId::parse("ak:cell:ak.component.member.state.v1:did.web.alice.example").unwrap();
        assert_eq!(id.component(), crate::CellFamilyId::MEMBER_STATE_V1);
        assert_eq!(id.subject(), "did.web.alice.example");
    }

    #[test]
    fn parse_composite_typed_id_subject() {
        let id = CellId::parse(
            "ak:cell:ak.component.capability.grant.v1:ak.grant.01js0gr0000000000000000000",
        )
        .unwrap();
        assert_eq!(id.component(), crate::CellFamilyId::CAPABILITY_GRANT_V1);
        assert_eq!(id.subject(), "ak.grant.01js0gr0000000000000000000");
    }

    #[test]
    fn parse_subject_with_inner_colons_keeps_them_in_subject() {
        // Subject can include further colons (e.g. typed ids inside).
        let id = CellId::parse(&format!(
            "ak:cell:{}:ak:consent:01js0c00000000000000000000",
            crate::CellFamilyId::CONSENT_GRANT_V1
        ))
        .unwrap();
        assert_eq!(id.component(), crate::CellFamilyId::CONSENT_GRANT_V1);
        assert_eq!(id.subject(), "ak:consent:01js0c00000000000000000000");
    }

    #[test]
    fn parse_rejects_missing_prefix() {
        let err = CellId::parse("cell:foo:bar").unwrap_err();
        assert!(format!("{err}").contains("missing 'ak:cell:' prefix"));
    }

    #[test]
    fn parse_rejects_missing_separator() {
        let err = CellId::parse("ak:cell:ak.component.consent.v1").unwrap_err();
        assert!(format!("{err}").contains("missing component:subject separator"));
    }

    #[test]
    fn parse_rejects_empty_component() {
        let err = CellId::parse("ak:cell::sub").unwrap_err();
        assert!(format!("{err}").contains("empty component"));
    }

    #[test]
    fn parse_rejects_noncanonical_component_family() {
        let err = CellId::parse("ak:cell:component.consent.v1:subject").unwrap_err();
        assert!(format!("{err}").contains("canonical ak.component.*.v<n> family"));
    }

    #[test]
    fn round_trip_wire_string() {
        let original = "ak:cell:ak.component.member.state.v1:did.web.alice.example";
        let id = CellId::parse(original).unwrap();
        assert_eq!(id.to_wire(), original);
    }

    #[test]
    fn composite_subject_is_deterministic() {
        let a = composite_subject(&[
            "ak:strand:ASVmv_EqnFQR2CH9hi8puYlg1qolDsgTIxqerMVv-1oN",
            "main",
            "did:webvh:z6mkfixture:alice.example",
        ])
        .unwrap();
        let b = composite_subject(&[
            "ak:strand:ASVmv_EqnFQR2CH9hi8puYlg1qolDsgTIxqerMVv-1oN",
            "main",
            "did:webvh:z6mkfixture:alice.example",
        ])
        .unwrap();
        assert_eq!(a, b);
        // base64url no-pad of sha256 is 43 chars.
        assert_eq!(a.len(), 43);
    }

    #[test]
    fn composite_subject_reorder_diverges() {
        let canonical = composite_subject(&["a", "b", "c"]).unwrap();
        let reordered = composite_subject(&["b", "a", "c"]).unwrap();
        assert_ne!(
            canonical, reordered,
            "reorder must diverge from canonical hash"
        );
    }

    #[test]
    fn composite_subject_preserves_typed_json_null() {
        let components = vec![
            serde_json::json!("ak:strand:AQVC6IqFkbYCve-UUUa0ciJb36fBVkZWvlnEwgTs3Q15"),
            serde_json::Value::Null,
            serde_json::json!("did:webvh:z6mkfixture:alice.example"),
        ];
        assert_eq!(
            composite_subject(&components).unwrap(),
            "3wA08l3OH-6eUtki8S-UaZQf7eeWzjGrsfBrgW4F50s"
        );
    }

    #[test]
    fn composite_subject_preserves_integer_and_boolean_types() {
        let typed = vec![serde_json::json!(7), serde_json::json!(true)];
        let stringified = vec![serde_json::json!("7"), serde_json::json!("true")];
        assert_eq!(
            composite_subject(&typed).unwrap(),
            "ppr_xXNqzOg5Ocq2g7TqCXruLOXDcEJsm5RtEGE8wjw"
        );
        assert_eq!(
            composite_subject(&stringified).unwrap(),
            "DPiXtvkJYb-EJwwcCNiu2_bf7BY50wfh38zRmgSx9So"
        );
        assert_ne!(
            composite_subject(&typed).unwrap(),
            composite_subject(&stringified).unwrap()
        );
    }

    #[test]
    fn composite_subject_rejects_non_scalar_and_fractional_components() {
        for component in [
            serde_json::json!({"not": "scalar"}),
            serde_json::json!(["not", "scalar"]),
            serde_json::json!(1.5),
        ] {
            let error = composite_subject(&[component]).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("JSON string, integer, boolean, or null")
            );
        }
    }

    #[test]
    fn string_set_digest_is_order_independent_and_rejects_invalid_sets() {
        let left = vec!["employment".to_owned(), "agent_operator".to_owned()];
        let right = vec!["agent_operator".to_owned(), "employment".to_owned()];
        assert_eq!(
            string_set_digest_component(&left, DomainSeparationId::ACCOUNTABILITY_SCOPE_SET_V1,)
                .unwrap(),
            "AWANhOFZ5FNgAQMK9mqCeI3ATOZR6o7qwshmpk3ij3U"
        );
        assert_eq!(
            string_set_digest_component(&left, DomainSeparationId::ACCOUNTABILITY_SCOPE_SET_V1,)
                .unwrap(),
            string_set_digest_component(&right, DomainSeparationId::ACCOUNTABILITY_SCOPE_SET_V1,)
                .unwrap()
        );
        assert!(
            string_set_digest_component(&[], DomainSeparationId::ACCOUNTABILITY_SCOPE_SET_V1,)
                .is_err()
        );
        assert!(
            string_set_digest_component(
                &["employment".to_owned(), "employment".to_owned()],
                DomainSeparationId::ACCOUNTABILITY_SCOPE_SET_V1
            )
            .is_err()
        );
    }

    #[test]
    fn composite_subject_pipe_preserves_diagnostic_form() {
        assert_eq!(composite_subject_pipe(&["a", "b", "c"]), "a|b|c");
        // Percent-encoding of literal | and %.
        assert_eq!(composite_subject_pipe(&["a|b", "c%d"]), "a%7Cb|c%25d");
    }

    #[test]
    fn from_ref_uses_typed_cell_ref() {
        let cref = CellRef::new(format!(
            "ak:cell:{}:ak.consent.01js0cc0000000000000000000",
            crate::CellFamilyId::CONSENT_GRANT_V1
        ))
        .unwrap();
        let id = CellId::from_ref(&cref).unwrap();
        assert_eq!(id.component(), crate::CellFamilyId::CONSENT_GRANT_V1);
    }
}

#[cfg(test)]
mod null_subject_tests {
    use super::*;

    #[test]
    fn canonical_null_subject_cells_match_the_builder() {
        for (constant, family) in [
            (REALM_CREATE_CELL, crate::CellFamilyId::REALM_CREATE_V1),
            (REALM_GENESIS_CELL, crate::CellFamilyId::REALM_GENESIS_V1),
            (REALM_PROFILE_CELL, crate::CellFamilyId::REALM_PROFILE_V1),
            (REALM_NOTARY_CELL, crate::CellFamilyId::NOTARY_V1),
        ] {
            assert_eq!(constant, null_subject_cell(family));
            let parsed = CellId::parse(constant).expect("canonical null-subject cell parses");
            assert_eq!(parsed.component(), family);
            assert_eq!(parsed.subject(), NULL_SUBJECT);
        }
    }
}
