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
//! derivation and the typed element value.
//!
//! Capability and invite are orthogonal: capability says "this actor MAY
//! do X to that resource"; consent says "I, as the contacted party,
//! accept this kind of contact from that peer".

use arkret_identifiers::{CellRef, ConsentId};
use arkret_models_collaboration::account_lifecycle::ConsentPeer;
use arkret_models_collaboration::governance::grant_constraint::GrantConstraint;
use arkret_wire::WireError;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Cell family for consent grants. Used as the prefix in cell ids of the
/// form `ak:cell:ak.component.consent.grant.v1:<consent_id>`.
pub const CONSENT_CELL_FAMILY: &str = arkret_wire::CellFamilyId::CONSENT_GRANT_V1;

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
    pub peer: ConsentPeer,
    pub scope: Scope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<GrantConstraint>,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
    }

    fn bob() -> ConsentPeer {
        ConsentPeer::Actor {
            actor_id: arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                arkret_wire::DidCoreId::new("ak:did_core:webvh:z6mkfixture:bob.example").unwrap(),
                arkret_wire::DidCoreId::new("ak:did_core:webvh:z6mkfixture:station.example")
                    .unwrap(),
            )),
        }
    }

    fn consent_id() -> ConsentId {
        ConsentId::new("ak:consent:01904100-0000-7000-8000-000000000001").unwrap()
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
    fn grant_value_round_trip_through_serde() {
        let v = ConsentGrantValue {
            consent_id: consent_id(),
            peer: bob(),
            scope: Scope::Invite,
            not_before: None,
            expires_at: Some(ts(2026, 12, 31)),
            evidence_ref: Some("ak:event:ARKLI7lMWiFeMi-XSWAxBMoVxJU4W8Zkwh74zLBqLpym".to_owned()),
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
