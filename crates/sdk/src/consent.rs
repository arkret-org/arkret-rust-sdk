//! Holder-private **consent** state machine (spec Phase 5).
//!
//! Consent is the protocol-level "I agree to receive `<scope>` from `<peer>`"
//! state, written in the holder's principal control Space and used as a gate
//! upstream of `cx.invite.*` / direct contact / WebRTC call initiation. It is
//! orthogonal to capability and invite — capability says "this actor MAY do X
//! to that resource"; consent says "I, as the contacted party, accept this
//! kind of contact from that peer". See
//! [`identity/consent-model.md`](https://contrix.io/spec/v1/zh/identity/consent-model.md).
//!
//! Wire kinds:
//!
//! - `cx.consent.grant` — issue or refresh a consent. State slot keyed by
//!   `payload.consent_id`; `state_subject_field=payload.consent_id`.
//! - `cx.consent.revoke` — supersede the same `consent_id` slot with a
//!   revoked record. Shares state slot + component_type
//!   (`cx.component.consent.grant.v1`) with `cx.consent.grant` via
//!   `component_slot_alias_of`.

use chrono::{DateTime, Utc};
use contrix_core::Did;
use serde::{Deserialize, Serialize};

/// Stable kind for consent grant events.
pub const CONSENT_GRANT_KIND: &str = "cx.consent.grant";
/// Stable kind for consent revoke events (shares slot with grant).
pub const CONSENT_REVOKE_KIND: &str = "cx.consent.revoke";

/// Scope of the consent grant. Each scope is an independent consent slot for
/// the same `(holder, peer)` pair (i.e. granting `Invite` does NOT imply
/// granting `DirectMessage`); use [`Scope::Any`] to express the union.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Peer MAY send Space / Flow invites to the holder.
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
    /// for `requested`. `Scope::Any` satisfies every concrete scope; every
    /// concrete scope only satisfies itself.
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

/// Payload of `cx.consent.grant`.
///
/// `actor_id` (the holder, on the envelope) MUST be the principal who owns
/// the consent decision. `peer` is the counterparty being consented to;
/// it MAY be a pairwise DID for pseudonymous deployments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentGrantPayload {
    /// Stable consent id; reducer state slot is keyed by this. Revokes MUST
    /// reuse the same id.
    pub consent_id: String,
    /// Counterparty DID (or pairwise DID) to whom consent is granted.
    pub peer: Did,
    /// Concrete scope (or [`Scope::Any`]) covered by this grant.
    pub scope: Scope,
    /// Optional time window — consent is only effective in `[not_before, valid_until]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    /// Optional list of consent-specific constraints (rate limits,
    /// time-of-day windows, device restrictions). v1 does not standardise
    /// constraint types beyond capability constraint vocabulary.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<serde_json::Value>,
    /// Optional reference (e.g. event id of the claim disclosure or invite
    /// proof that triggered this consent) — audit-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
    /// Free-form human-readable reason; audit-only, not authorising.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Payload of `cx.consent.revoke`.
///
/// MUST reference the same `consent_id` as the grant being revoked. Reducer
/// treats this as supersede on the consent slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentRevokePayload {
    /// MUST equal the `consent_id` of the `cx.consent.grant` being revoked.
    pub consent_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Effective consent state derived by the reducer from the latest accepted
/// event on the consent slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsentState {
    /// Slot has an accepted, unrevoked grant in its valid window.
    Granted {
        peer: Did,
        scope: Scope,
        not_before: Option<DateTime<Utc>>,
        valid_until: Option<DateTime<Utc>>,
    },
    /// Slot has been revoked (latest accepted event is `cx.consent.revoke`).
    Revoked {
        peer: Did,
        scope: Scope,
        revoked_at: Option<DateTime<Utc>>,
    },
    /// Slot does not exist (no accepted event ever written).
    Absent,
}

impl ConsentState {
    /// Whether this state currently grants `requested` scope at `now`.
    /// `now` is checked against the optional `not_before` / `valid_until`
    /// window; `None` window endpoints mean "no bound on that side".
    pub fn allows(&self, requested: Scope, now: DateTime<Utc>) -> bool {
        match self {
            ConsentState::Granted {
                scope,
                not_before,
                valid_until,
                ..
            } => {
                if !scope.satisfies(requested) {
                    return false;
                }
                if let Some(start) = not_before {
                    if now < *start {
                        return false;
                    }
                }
                if let Some(end) = valid_until {
                    if now > *end {
                        return false;
                    }
                }
                true
            }
            ConsentState::Revoked { .. } | ConsentState::Absent => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts(year: i32, month: u32, day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(year, month, day, 0, 0, 0).unwrap()
    }

    #[test]
    fn scope_any_satisfies_concrete() {
        assert!(Scope::Any.satisfies(Scope::Invite));
        assert!(Scope::Any.satisfies(Scope::VoiceCall));
        assert!(!Scope::Invite.satisfies(Scope::VoiceCall));
        assert!(Scope::Invite.satisfies(Scope::Invite));
    }

    #[test]
    fn granted_state_respects_window() {
        let peer = Did::new("did:web:bob.example").unwrap();
        let state = ConsentState::Granted {
            peer: peer.clone(),
            scope: Scope::Invite,
            not_before: Some(ts(2026, 1, 1)),
            valid_until: Some(ts(2026, 12, 31)),
        };
        assert!(state.allows(Scope::Invite, ts(2026, 6, 1)));
        assert!(!state.allows(Scope::Invite, ts(2025, 12, 31)));
        assert!(!state.allows(Scope::Invite, ts(2027, 1, 1)));
        // Wrong scope on a non-Any grant is denied.
        assert!(!state.allows(Scope::VoiceCall, ts(2026, 6, 1)));
    }

    #[test]
    fn revoked_and_absent_states_deny() {
        let peer = Did::new("did:web:bob.example").unwrap();
        let revoked = ConsentState::Revoked {
            peer,
            scope: Scope::Invite,
            revoked_at: Some(ts(2026, 6, 1)),
        };
        assert!(!revoked.allows(Scope::Invite, ts(2026, 6, 2)));
        assert!(!ConsentState::Absent.allows(Scope::Invite, ts(2026, 6, 1)));
    }

    #[test]
    fn payload_round_trip_through_serde() {
        let peer = Did::new("did:web:bob.example").unwrap();
        let payload = ConsentGrantPayload {
            consent_id: "cs-001".to_owned(),
            peer: peer.clone(),
            scope: Scope::Invite,
            not_before: None,
            valid_until: None,
            constraints: Vec::new(),
            evidence_ref: Some("cx:event:01js0pres000000000000000000".to_owned()),
            reason: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        // Wire scope name MUST be `invite`, not `Invite`.
        assert!(json.contains("\"invite\""));
        let round: ConsentGrantPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(round, payload);
    }

    #[test]
    fn revoke_payload_serializes_with_minimal_required_fields() {
        let payload = ConsentRevokePayload {
            consent_id: "cs-001".to_owned(),
            revoked_at: None,
            reason: None,
        };
        let json = serde_json::to_string(&payload).unwrap();
        assert_eq!(json, "{\"consent_id\":\"cs-001\"}");
    }
}
