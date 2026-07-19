//! Holder-private **consent** as an or-set Lattice cell.
//!
//! Per [`identity/consent-model.md`](https://arkret.org/spec/v1/zh/identity/consent-model.md)
//! §3, consent is a Move on the holder's principal-control-Space cell
//! `ak:cell:ak.component.consent.grant.v1:<consent_id>` (or-set lattice).
//!
//! - `grant` = `add(tag, value)`, where `tag = "grant:<consent_id>:<peer>:<scope>"` (deterministic
//!   so identical intents idempotently dedupe), and `value` carries the typed
//!   [`ConsentGrantValue`].
//! - `revoke` = `remove(tag, reason)` on the same tag. Spec §3.3 also requires a `contains`
//!   precondition on the cell's current join — the builder produces it for you.
//!
//! Effective consent is derived by walking the cell's join value (a JSON
//! array of `{tag, value}` items) and asking whether any tag's value
//! covers the requested `(peer, scope)` at the query time. There is no
//! per-cell "winner" — concurrent grants on different tags coexist;
//! revokes remove their target tag.
//!
//! Capability and invite are orthogonal: capability says "this actor MAY
//! do X to that resource"; consent says "I, as the contacted party,
//! accept this kind of contact from that peer".

use arkret_identifiers::{CellRef, ConsentId, Did};
use arkret_models_collaboration::governance::grant_constraint::GrantConstraint;
use arkret_wire::{
    Effect, LatticeOp, LatticeOpType, Precondition, Predicate, PredicateOp, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

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

/// Deterministic tag for a `(consent_id, peer, scope)` grant.
///
/// Spec §3.2: same `(consent_id, peer, scope)` triple MUST produce the
/// same tag so duplicate grants idempotently dedupe in the or-set.
pub fn consent_tag(consent_id: &ConsentId, peer: &Did, scope: Scope) -> String {
    format!("grant:{consent_id}:{}:{}", peer.as_str(), scope.as_wire())
}

/// Optional fields for a consent grant.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ConsentGrantOptions {
    pub not_before: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub evidence_ref: Option<String>,
    pub reason: Option<String>,
    pub constraints: Vec<GrantConstraint>,
}

/// Typed shape of the JSON `value` payload carried inside the or-set
/// `add` op. Mirrors the spec §3.2 `value` field.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConsentGrantValue {
    pub consent_id: ConsentId,
    pub peer: Did,
    pub scope: Scope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<GrantConstraint>,
}

/// Typed shape of the JSON `value` payload carried inside the or-set
/// `remove` op. Mirrors the spec §3.3 `value` field.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRevokeValue {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Build the [`Effect`] that a consent.grant Move writes.
///
/// Spec §3.2: cell = `ak:cell:ak.component.consent.grant.v1:<consent_id>`,
/// op = `add(tag, value)`, tag = `grant:<consent_id>:<peer>:<scope>`,
/// value = [`ConsentGrantValue`].
pub fn grant_effect(
    consent_id: &ConsentId,
    peer: Did,
    scope: Scope,
    options: &ConsentGrantOptions,
) -> Result<Effect, WireError> {
    let cell = consent_cell_id(consent_id)?;
    let tag = consent_tag(consent_id, &peer, scope);
    let value = ConsentGrantValue {
        consent_id: consent_id.to_owned(),
        peer,
        scope,
        not_before: options.not_before,
        expires_at: options.expires_at,
        evidence_ref: options.evidence_ref.clone(),
        reason: options.reason.clone(),
        constraints: options.constraints.clone(),
    };
    let value_json = serde_json::to_value(&value)?;
    Ok(Effect {
        cell,
        op: LatticeOp {
            op_type: LatticeOpType::Add,
            tag: Some(tag),
            value: Some(value_json),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        },
    })
}

/// Build the [`Effect`] + [`Precondition`] that a consent.revoke Move
/// writes.
///
/// Per spec §3.3, the Move SHOULD also include a `contains` precondition
/// on the same tag for diagnostics (so a revoke targeting a never-granted
/// tag fails closed rather than silently no-ops). The first return value
/// is the precondition, the second is the effect.
pub fn revoke_effect_with_precondition(
    consent_id: &ConsentId,
    peer: &Did,
    scope: Scope,
    revoke_value: ConsentRevokeValue,
) -> Result<(Precondition, Effect), WireError> {
    let cell = consent_cell_id(consent_id)?;
    let tag = consent_tag(consent_id, peer, scope);

    let pre = Precondition {
        cell: cell.clone(),
        predicate: Predicate {
            op: PredicateOp::Contains,
            value: Some(Value::String(tag.clone())),
            values: None,
            predicate_id: None,
        },
    };

    let reason_for_op = revoke_value.reason.clone();
    let value_json = serde_json::to_value(&revoke_value)?;
    let eff = Effect {
        cell,
        op: LatticeOp {
            op_type: LatticeOpType::Remove,
            tag: Some(tag),
            value: Some(value_json),
            from: None,
            to: None,
            reason: reason_for_op,
            issuer_seq: None,
        },
    };
    Ok((pre, eff))
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

/// Helper: build a query-time `contains` precondition that asserts the
/// holder's consent cell still carries the `(consent_id, peer, scope)`
/// tag. Use this in invite / DM / call-init Moves to gate on consent
/// without re-deriving the tag at the call site.
pub fn require_consent_precondition(
    consent_id: &ConsentId,
    peer: &Did,
    scope: Scope,
) -> Result<Precondition, WireError> {
    let cell = consent_cell_id(consent_id)?;
    Ok(Precondition {
        cell,
        predicate: Predicate {
            op: PredicateOp::Contains,
            value: Some(Value::String(consent_tag(consent_id, peer, scope))),
            values: None,
            predicate_id: None,
        },
    })
}

#[cfg(test)]
mod tests {
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

    fn move_id(byte: u8) -> arkret_identifiers::MoveId {
        arkret_identifiers::MoveId::new(format!("sha256:{}", format!("{byte:02x}").repeat(32)))
            .unwrap()
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
    fn tag_is_deterministic() {
        let t1 = consent_tag(&consent_id(), &bob(), Scope::Invite);
        let t2 = consent_tag(&consent_id(), &bob(), Scope::Invite);
        assert_eq!(t1, t2);
        assert_eq!(
            t1,
            "grant:ak:consent:01904100-0000-7000-8000-000000000001:did:webvh:z6mkfixture:bob.example:invite"
        );
    }

    #[test]
    fn tag_distinguishes_scope() {
        assert_ne!(
            consent_tag(&consent_id(), &bob(), Scope::Invite),
            consent_tag(&consent_id(), &bob(), Scope::VoiceCall)
        );
    }

    #[test]
    fn grant_effect_produces_or_set_add() {
        let opts = ConsentGrantOptions {
            expires_at: Some(ts(2026, 12, 31)),
            evidence_ref: Some("ak:event:01904100-0000-7000-8000-4ad9d5ef0089".to_owned()),
            ..Default::default()
        };
        let eff = grant_effect(&consent_id(), bob(), Scope::Invite, &opts).unwrap();
        assert_eq!(eff.op.op_type, LatticeOpType::Add);
        assert_eq!(
            eff.op.tag.as_deref(),
            Some(
                "grant:ak:consent:01904100-0000-7000-8000-000000000001:did:webvh:z6mkfixture:bob.example:invite"
            )
        );
        let value = eff.op.value.as_ref().unwrap();
        assert_eq!(value.get("consent_id").unwrap(), consent_id().as_str());
        assert_eq!(value.get("scope").unwrap(), "invite");
        assert_eq!(
            value.get("peer").unwrap(),
            "did:webvh:z6mkfixture:bob.example"
        );
        assert!(value.get("expires_at").is_some());
    }

    #[test]
    fn revoke_effect_includes_contains_precondition() {
        let revoke = ConsentRevokeValue {
            revoked_at: Some(ts(2026, 6, 15)),
            reason: Some("incident".to_owned()),
        };
        let (pre, eff) =
            revoke_effect_with_precondition(&consent_id(), &bob(), Scope::Invite, revoke).unwrap();
        assert_eq!(pre.predicate.op, PredicateOp::Contains);
        assert_eq!(
            pre.predicate.value.as_ref().unwrap(),
            "grant:ak:consent:01904100-0000-7000-8000-000000000001:did:webvh:z6mkfixture:bob.example:invite"
        );
        assert_eq!(eff.op.op_type, LatticeOpType::Remove);
        assert_eq!(
            eff.op.tag.as_deref(),
            Some(
                "grant:ak:consent:01904100-0000-7000-8000-000000000001:did:webvh:z6mkfixture:bob.example:invite"
            )
        );
        assert_eq!(eff.op.reason.as_deref(), Some("incident"));
    }

    #[test]
    fn evaluate_consent_grants_with_no_window_active() {
        // Build a consent or-set state by joining a single grant op.
        let opts = ConsentGrantOptions::default();
        let grant = grant_effect(&consent_id(), bob(), Scope::Invite, &opts).unwrap();
        let aop = SealedOp::new(move_id(0x11), grant.op);
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
        let opts = ConsentGrantOptions {
            not_before: Some(ts(2026, 1, 1)),
            expires_at: Some(ts(2026, 12, 31)),
            ..Default::default()
        };
        let grant = grant_effect(&consent_id(), bob(), Scope::Invite, &opts).unwrap();
        let aop = SealedOp::new(move_id(0x11), grant.op);
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
        let opts = ConsentGrantOptions::default();
        let grant = grant_effect(&consent_id(), bob(), Scope::Invite, &opts).unwrap();
        let (_pre, revoke) = revoke_effect_with_precondition(
            &consent_id(),
            &bob(),
            Scope::Invite,
            ConsentRevokeValue::default(),
        )
        .unwrap();
        let cell = consent_cell_id(&consent_id()).unwrap();
        let aops = vec![
            SealedOp::new(move_id(0x11), grant.op),
            SealedOp::new(move_id(0x22), revoke.op),
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
    fn scope_any_grants_every_concrete_scope() {
        let opts = ConsentGrantOptions::default();
        let grant = grant_effect(&consent_id(), bob(), Scope::Any, &opts).unwrap();
        let aop = SealedOp::new(move_id(0x11), grant.op);
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
    fn idempotent_grant_dedupes_via_tag() {
        // Two identical grants with the same (consent_id, peer, scope)
        // produce the same tag → or-set sees them as duplicates after join.
        let opts = ConsentGrantOptions::default();
        let g1 = grant_effect(&consent_id(), bob(), Scope::Invite, &opts).unwrap();
        let g2 = grant_effect(&consent_id(), bob(), Scope::Invite, &opts).unwrap();
        assert_eq!(g1.op.tag, g2.op.tag);
        let cell = consent_cell_id(&consent_id()).unwrap();
        let aops = vec![
            SealedOp::new(move_id(0x11), g1.op),
            SealedOp::new(move_id(0x22), g2.op),
        ];
        let state = OrSet.join(&cell, &aops);
        // Join produced exactly one tag.
        let CellState::Value(v) = state else {
            panic!("expected value")
        };
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn require_consent_precondition_round_trip() {
        let pre = require_consent_precondition(&consent_id(), &bob(), Scope::Invite).unwrap();
        assert_eq!(
            pre.cell.as_str(),
            "ak:cell:ak.component.consent.grant.v1:ak:consent:01904100-0000-7000-8000-000000000001"
        );
        assert_eq!(pre.predicate.op, PredicateOp::Contains);
        assert_eq!(
            pre.predicate.value.as_ref().unwrap(),
            "grant:ak:consent:01904100-0000-7000-8000-000000000001:did:webvh:z6mkfixture:bob.example:invite"
        );
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
