//! Holder-private **consent** as an or-set Lattice cell.
//!
//! Per [`identity/consent-model.md`](https://arkret.org/spec/v1/zh/identity/consent-model.md)
//! §3, consent lives on the holder's principal-control-Space cell
//! `ak:cell:ak.component.consent.grant.v1:<consent_id>` (or-set lattice).
//!
//! This module is receiver-side only. `ak.consent.grant` / `ak.consent.revoke`
//! are Control Moves whose or-set add / remove operations the receiver derives
//! from the registered reducer contract; a producer cannot supply them and
//! cannot name the element tags, which are canonical dots
//! (`event-and-patch.md` §2.4.2). What stays here is the cell-subject
//! derivation, the typed element value, and the query-time evaluation.
//!
//! Effective consent is derived by walking the cell's join value (a JSON
//! array of `{tag, value}` items) and asking whether any element's value
//! covers the requested `(peer, scope)` at the query time. There is no
//! per-cell "winner" — concurrent grants on different dots coexist; revokes
//! remove their target dots.
//!
//! Capability and invite are orthogonal: capability says "this actor MAY
//! do X to that resource"; consent says "I, as the contacted party,
//! accept this kind of contact from that peer".

use arkret_identifiers::{CellRef, ConsentId, Did};
use arkret_models_collaboration::governance::grant_constraint::GrantConstraint;
use arkret_wire::WireError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::lattice::CellState;

/// Cell family for consent grants. Used as the prefix in cell ids of the
/// form `ak:cell:ak.component.consent.grant.v1:<consent_id>`.
pub const CONSENT_CELL_FAMILY: &str = "ak.component.consent.grant.v1";

/// Scope of the consent grant. See spec consent-model §4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Peer MAY send Space / Strand invites to the holder.
    Invite,
    /// Peer MAY initiate a 1:1 message Space / DM with the holder.
    DirectMessage,
    /// Peer MAY initiate a WebRTC voice call to the holder.
    VoiceCall,
    /// Peer MAY initiate a WebRTC video call to the holder.
    VideoCall,
    /// Peer MAY observe the holder's presence.
    Presence,
    /// Convenience union — equivalent to granting every concrete scope.
    Any,
}

impl Scope {
    /// Whether this consent scope, as effective state, satisfies a request
    /// for `requested`.
    pub fn satisfies(self, requested: Scope) -> bool {
        if matches!(self, Scope::Any) {
            return true;
        }
        self == requested
    }

    /// Stable wire-form name (matches the `serde(rename_all = "snake_case")`).
    pub fn as_wire(self) -> &'static str {
        match self {
            Scope::Invite => "invite",
            Scope::DirectMessage => "direct_message",
            Scope::VoiceCall => "voice_call",
            Scope::VideoCall => "video_call",
            Scope::Presence => "presence",
            Scope::Any => "any",
        }
    }
}

/// Build the canonical consent cell id for a `consent_id`.
///
/// Returns a `CellRef` with the canonical wire form
/// `ak:cell:ak.component.consent.grant.v1:<consent_id>`.
pub fn consent_cell_id(consent_id: &ConsentId) -> Result<CellRef, WireError> {
    CellRef::new(format!("ak:cell:{CONSENT_CELL_FAMILY}:{consent_id}"))
        .map_err(|e| WireError::Protocol(format!("invalid consent cell id: {e}")))
}

/// Typed shape of the JSON `value` the reducer stores on an or-set element.
/// Mirrors the spec §3.2 `value` field.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConsentGrantValue {
    pub consent_id: ConsentId,
    pub peer: Did,
    pub scope: Scope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<GrantConstraint>,
}

/// Walk the consent cell's or-set join value and decide whether
/// `(peer, scope)` is currently consented at `now`.
///
/// `cell_state` is what [`crate::lattice::Lattice::join`] produced for the consent cell.
/// For an `or-set` Lattice, the `Value` form is a JSON array of
/// `{tag, value}` objects. Bottom states (which or-set never produces)
/// are treated as no-consent.
pub fn evaluate_consent(
    cell_state: &CellState,
    peer: &Did,
    requested: Scope,
    now: DateTime<Utc>,
) -> bool {
    let CellState::Value(value) = cell_state else {
        return false;
    };
    let Some(arr) = value.as_array() else {
        return false;
    };
    arr.iter().any(|item| {
        let Some(value_obj) = item.get("value") else {
            return false;
        };
        let Ok(grant) = serde_json::from_value::<ConsentGrantValue>(value_obj.clone()) else {
            return false;
        };
        if grant.peer != *peer {
            return false;
        }
        if !grant.scope.satisfies(requested) {
            return false;
        }
        if let Some(start) = grant.not_before
            && now < start
        {
            return false;
        }
        if let Some(end) = grant.expires_at
            && now > end
        {
            return false;
        }
        true
    })
}

#[cfg(test)]
mod tests {
    use arkret_wire::{LatticeOp, LatticeOpType};
    use chrono::TimeZone;

    use super::*;
    use crate::lattice::{Lattice, OrSet, SealedOp};

    fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
    }

    fn alice() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn bob() -> Did {
        Did::new("did:webvh:z6mkfixture:bob.example").unwrap()
    }

    fn consent_id() -> ConsentId {
        ConsentId::new("ak:consent:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn event_digest(byte: u8) -> arkret_identifiers::Hash {
        arkret_identifiers::Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32)))
            .unwrap()
    }

    /// The or-set `add` the registered `ak.consent.grant` contract projects:
    /// `tag` is the canonical dot, `value` is the grant payload. Producers
    /// cannot author either, so these fixtures stand in for the reducer.
    fn grant_op(
        dot: &str,
        peer: Did,
        scope: Scope,
        not_before: Option<DateTime<Utc>>,
        expires_at: Option<DateTime<Utc>>,
    ) -> LatticeOp {
        let value = ConsentGrantValue {
            consent_id: consent_id(),
            peer,
            scope,
            not_before,
            expires_at,
            evidence_ref: None,
            reason: None,
            constraints: vec![],
        };
        LatticeOp {
            op_type: LatticeOpType::Add,
            tag: Some(dot.to_owned()),
            value: Some(serde_json::to_value(&value).unwrap()),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        }
    }

    fn revoke_op(dot: &str) -> LatticeOp {
        LatticeOp {
            op_type: LatticeOpType::Remove,
            tag: Some(dot.to_owned()),
            value: None,
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        }
    }

    #[test]
    fn cell_id_is_canonical() {
        let cell = consent_cell_id(&consent_id()).unwrap();
        assert_eq!(
            cell.as_str(),
            "ak:cell:ak.component.consent.grant.v1:ak:consent:01904100-0000-7000-8000-000000000001"
        );
    }

    #[test]
    fn consent_id_rejects_non_typed_or_non_uuidv7_values() {
        assert!(ConsentId::new("").is_err());
        assert!(ConsentId::new("cs-001").is_err());
    }

    #[test]
    fn evaluate_consent_grants_with_no_window_active() {
        // Build a consent or-set state by joining a single grant op.
        let op = grant_op("ak:event:e1:0", bob(), Scope::Invite, None, None);
        let aop = SealedOp::new(event_digest(0x11), op);
        let state = OrSet.join(&consent_cell_id(&consent_id()).unwrap(), &[aop]);
        assert!(evaluate_consent(
            &state,
            &bob(),
            Scope::Invite,
            ts(2026, 6, 1)
        ));
        // Wrong peer.
        assert!(!evaluate_consent(
            &state,
            &alice(),
            Scope::Invite,
            ts(2026, 6, 1)
        ));
        // Wrong scope.
        assert!(!evaluate_consent(
            &state,
            &bob(),
            Scope::VoiceCall,
            ts(2026, 6, 1)
        ));
    }

    #[test]
    fn evaluate_consent_respects_window() {
        let op = grant_op(
            "ak:event:e1:0",
            bob(),
            Scope::Invite,
            Some(ts(2026, 1, 1)),
            Some(ts(2026, 12, 31)),
        );
        let aop = SealedOp::new(event_digest(0x11), op);
        let state = OrSet.join(&consent_cell_id(&consent_id()).unwrap(), &[aop]);
        assert!(evaluate_consent(
            &state,
            &bob(),
            Scope::Invite,
            ts(2026, 6, 1)
        ));
        // Before window.
        assert!(!evaluate_consent(
            &state,
            &bob(),
            Scope::Invite,
            ts(2025, 12, 31)
        ));
        // After window.
        assert!(!evaluate_consent(
            &state,
            &bob(),
            Scope::Invite,
            ts(2027, 1, 1)
        ));
    }

    #[test]
    fn revoke_after_grant_removes_consent() {
        // `ak.consent.revoke` removes the producer-named dots from
        // `payload.observed_dots`, so the revoke targets the grant's own dot.
        let cell = consent_cell_id(&consent_id()).unwrap();
        let aops = vec![
            SealedOp::new(
                event_digest(0x11),
                grant_op("ak:event:e1:0", bob(), Scope::Invite, None, None),
            ),
            SealedOp::new(event_digest(0x22), revoke_op("ak:event:e1:0")),
        ];
        let state = OrSet.join(&cell, &aops);
        assert!(!evaluate_consent(
            &state,
            &bob(),
            Scope::Invite,
            ts(2026, 6, 1)
        ));
    }

    #[test]
    fn revoking_one_dot_leaves_a_concurrent_grant_standing() {
        // consent-model §3.3: a revoke MUST NOT be generalized from one dot to
        // the others under the same `(consent_id, peer, scope)`.
        let cell = consent_cell_id(&consent_id()).unwrap();
        let aops = vec![
            SealedOp::new(
                event_digest(0x11),
                grant_op("ak:event:e1:0", bob(), Scope::Invite, None, None),
            ),
            SealedOp::new(
                event_digest(0x22),
                grant_op("ak:event:e2:0", bob(), Scope::Invite, None, None),
            ),
            SealedOp::new(event_digest(0x33), revoke_op("ak:event:e1:0")),
        ];
        let state = OrSet.join(&cell, &aops);
        assert!(evaluate_consent(
            &state,
            &bob(),
            Scope::Invite,
            ts(2026, 6, 1)
        ));
    }

    #[test]
    fn scope_any_grants_every_concrete_scope() {
        let op = grant_op("ak:event:e1:0", bob(), Scope::Any, None, None);
        let aop = SealedOp::new(event_digest(0x11), op);
        let state = OrSet.join(&consent_cell_id(&consent_id()).unwrap(), &[aop]);
        assert!(evaluate_consent(
            &state,
            &bob(),
            Scope::Invite,
            ts(2026, 6, 1)
        ));
        assert!(evaluate_consent(
            &state,
            &bob(),
            Scope::VoiceCall,
            ts(2026, 6, 1)
        ));
        assert!(evaluate_consent(
            &state,
            &bob(),
            Scope::DirectMessage,
            ts(2026, 6, 1)
        ));
    }

    #[test]
    fn empty_cell_state_denies_consent() {
        let cell = consent_cell_id(&consent_id()).unwrap();
        let state = OrSet.join(&cell, &[]);
        assert!(!evaluate_consent(
            &state,
            &bob(),
            Scope::Invite,
            ts(2026, 6, 1)
        ));
    }

    #[test]
    fn grant_value_round_trip_through_serde() {
        let v = ConsentGrantValue {
            consent_id: consent_id(),
            peer: bob(),
            scope: Scope::Invite,
            not_before: None,
            expires_at: Some(ts(2026, 12, 31)),
            evidence_ref: Some("ak:event:01904100-0000-7000-8000-4ad9d5ef0089".to_owned()),
            reason: None,
            constraints: vec![],
        };
        let s = serde_json::to_string(&v).unwrap();
        assert!(s.contains("\"invite\""));
        let r: ConsentGrantValue = serde_json::from_str(&s).unwrap();
        assert_eq!(r, v);
    }

    #[test]
    fn scope_wire_names_match_spec() {
        assert_eq!(Scope::Invite.as_wire(), "invite");
        assert_eq!(Scope::DirectMessage.as_wire(), "direct_message");
        assert_eq!(Scope::VoiceCall.as_wire(), "voice_call");
        assert_eq!(Scope::VideoCall.as_wire(), "video_call");
        assert_eq!(Scope::Presence.as_wire(), "presence");
        assert_eq!(Scope::Any.as_wire(), "any");
    }

    #[test]
    fn scope_satisfies_logic() {
        assert!(Scope::Any.satisfies(Scope::Invite));
        assert!(Scope::Invite.satisfies(Scope::Invite));
        assert!(!Scope::Invite.satisfies(Scope::VoiceCall));
        assert!(!Scope::VoiceCall.satisfies(Scope::Invite));
    }
}
