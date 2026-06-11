//! Cell id parsing and composite-subject helpers.
//!
//! Per spec `event-auth-state-resolution.md` §2 a cell id is the smallest
//! protocol-level state unit identified as
//!
//! ```text
//! ck:cell:<component>:<subject>
//! ```
//!
//! - `<component>` is the cell family (e.g. `ck.component.member.state.v1`,
//!   `ck.component.capability.grant.v1`, `ck.component.consent.v1`).
//! - `<subject>` may be a flat identifier (`did.web.alice.example`,
//!   `ck.grant.01js0gr0000000000000000000`) or a deterministic composite subject when the spec
//!   event-kind-registry's `cell_subject` declares `composite` form.
//!
//! Composite subjects are `base64url_nopad(sha256(canonical_json([...])))`
//! over an ordered components array. The order is fixed per cell family
//! (encoding.md §9.5). This module exposes:
//!
//! - [`CellId::parse`] — strict parser for `ck:cell:<component>:<subject>`.
//! - [`CellId::component`] / [`CellId::subject`] — accessors.
//! - [`composite_subject`] — produce the canonical composite subject hash for a fixed-order list of
//!   string parts (the wire-canonical form).
//! - [`composite_subject_pipe`] — produce the diagnostic `a|b|c` form (informational only; never
//!   wire-canonical).

use sha2::{Digest, Sha256};

use crate::base64url::base64url_encode;
use crate::{CellRef, Error, Result, canonical};

const CELL_PREFIX: &str = "ck:cell:";

/// Parsed cell id with its component family and subject substrings.
///
/// The wire string is held in [`CellRef`]; [`CellId`] is a borrow-style
/// view over it so we don't allocate copies for hot paths (validate / log /
/// project). The component must be non-empty; the subject may be empty
/// when a cell family has only one global instance per Space.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CellId {
    component: String,
    subject: String,
}

impl CellId {
    /// Parse a `ck:cell:<component>:<subject>` string into typed parts.
    ///
    /// Both `<component>` and `<subject>` may contain dots and additional
    /// colons (subject can itself be a typed id like
    /// `ck.grant.01js0gr...`). The split happens on the **first** colon
    /// after the `ck:cell:` prefix to keep the component canonical.
    pub fn parse(value: &str) -> Result<Self> {
        let rest = value.strip_prefix(CELL_PREFIX).ok_or_else(|| {
            Error::Protocol(format!("cell id missing 'ck:cell:' prefix: {value}"))
        })?;
        let (component, subject) = rest.split_once(':').ok_or_else(|| {
            Error::Protocol(format!(
                "cell id missing component:subject separator: {value}"
            ))
        })?;
        if component.is_empty() {
            return Err(Error::Protocol(format!(
                "cell id has empty component: {value}"
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

    /// The cell family / component portion (e.g. `ck.component.member.state.v1`).
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

    /// Construct a typed [`CellRef`] from this id.
    pub fn to_cell_ref(&self) -> Result<CellRef> {
        CellRef::new(self.to_wire())
            .map_err(|err| Error::Protocol(format!("invalid cell ref: {err}")))
    }
}

/// Canonical composite cell subject: `base64url_nopad(sha256(canonical_json([...])))`.
///
/// `parts` MUST be in the fixed order declared by the cell family's
/// `cell_subject` descriptor (spec encoding.md §9.5). Reorder negative
/// vectors MUST diverge from this form.
pub fn composite_subject(parts: &[&str]) -> Result<String> {
    let bytes = canonical::canonical_json_bytes(&parts)?;
    let digest = Sha256::digest(&bytes);
    Ok(base64url_encode(digest))
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

    #[test]
    fn parse_simple_cell_id() {
        let id =
            CellId::parse("ck:cell:ck.component.member.state.v1:did.web.alice.example").unwrap();
        assert_eq!(id.component(), "ck.component.member.state.v1");
        assert_eq!(id.subject(), "did.web.alice.example");
    }

    #[test]
    fn parse_composite_typed_id_subject() {
        let id = CellId::parse(
            "ck:cell:ck.component.capability.grant.v1:ck.grant.01js0gr0000000000000000000",
        )
        .unwrap();
        assert_eq!(id.component(), "ck.component.capability.grant.v1");
        assert_eq!(id.subject(), "ck.grant.01js0gr0000000000000000000");
    }

    #[test]
    fn parse_subject_with_inner_colons_keeps_them_in_subject() {
        // Subject can include further colons (e.g. typed ids inside).
        let id =
            CellId::parse("ck:cell:ck.component.consent.v1:ck:consent:01js0c00000000000000000000")
                .unwrap();
        assert_eq!(id.component(), "ck.component.consent.v1");
        assert_eq!(id.subject(), "ck:consent:01js0c00000000000000000000");
    }

    #[test]
    fn parse_rejects_missing_prefix() {
        let err = CellId::parse("cell:foo:bar").unwrap_err();
        assert!(format!("{err}").contains("missing 'ck:cell:' prefix"));
    }

    #[test]
    fn parse_rejects_missing_separator() {
        let err = CellId::parse("ck:cell:ck.component.consent.v1").unwrap_err();
        assert!(format!("{err}").contains("missing component:subject separator"));
    }

    #[test]
    fn parse_rejects_empty_component() {
        let err = CellId::parse("ck:cell::sub").unwrap_err();
        assert!(format!("{err}").contains("empty component"));
    }

    #[test]
    fn round_trip_wire_string() {
        let original = "ck:cell:ck.component.member.state.v1:did.web.alice.example";
        let id = CellId::parse(original).unwrap();
        assert_eq!(id.to_wire(), original);
    }

    #[test]
    fn composite_subject_is_deterministic() {
        let a = composite_subject(&[
            "ck:flow:7fd5ae82-44e2-7a8a-9a4b-8857991142f9",
            "main",
            "did:web:alice.example",
        ])
        .unwrap();
        let b = composite_subject(&[
            "ck:flow:7fd5ae82-44e2-7a8a-9a4b-8857991142f9",
            "main",
            "did:web:alice.example",
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
    fn composite_subject_pipe_preserves_diagnostic_form() {
        assert_eq!(composite_subject_pipe(&["a", "b", "c"]), "a|b|c");
        // Percent-encoding of literal | and %.
        assert_eq!(composite_subject_pipe(&["a|b", "c%d"]), "a%7Cb|c%25d");
    }

    #[test]
    fn from_ref_uses_typed_cell_ref() {
        let cref =
            CellRef::new("ck:cell:ck.component.consent.v1:ck.consent.01js0cc0000000000000000000")
                .unwrap();
        let id = CellId::from_ref(&cref).unwrap();
        assert_eq!(id.component(), "ck.component.consent.v1");
    }

    #[test]
    fn to_cell_ref_round_trips_through_ref_validator() {
        let id = CellId {
            component: "ck.component.member.state.v1".to_owned(),
            subject: "did.web.alice.example".to_owned(),
        };
        let cref = id.to_cell_ref().unwrap();
        assert_eq!(
            cref.as_str(),
            "ck:cell:ck.component.member.state.v1:did.web.alice.example"
        );
    }
}
