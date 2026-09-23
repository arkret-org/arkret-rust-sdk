//! Query-local Agent signing state projected by the authoritative Station.
//!
//! This module intentionally contains no portable historical closure.
//! Authority is established by exact committed authorization/status Events and
//! the current stream revision; callers still verify the producer proof with
//! the returned key.

use arkret_wire::{CommittedEventRef, CurrentRevision, ErrorCode, Result, WireError};
use serde::{Deserialize, Serialize};

pub const SELF_SIGNER_REQUEST_MAX_BYTES: usize = 64 * 1024;
pub const SELF_SIGNER_RESULT_MAX_BYTES: usize = 64 * 1024;
pub const SELF_SIGNER_OUTCOME_MAX_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentCurrentStatus {
    Active,
    Paused,
    Deactivated,
}

/// Key material returned only to the authenticated self caller.
///
/// There is exactly one Station signing-key shape in the SDK and it is the one
/// `arkret-wire` owns. `signer-key-operations.schema.json#/$defs/station_signing_key`
/// is closed over `actor`, `verification_method`, `public_key_b64u` and an
/// `authorization_ref` that is a bare `event_id`; the revision an answer was
/// projected at belongs to the answer, not to the key, and is carried by
/// [`AgentSignerCurrentState::revision`].
pub use arkret_wire::StationSigningKey;

/// Closed current Agent state. Paused/deactivated rows remain auditable but
/// cannot be used as a current signing key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentSignerCurrentState {
    pub status: AgentCurrentStatus,
    pub signing_key: StationSigningKey,
    /// Revision of the projected current state this answer was read at. It
    /// bounds every committed reference the answer carries.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub revision: CurrentRevision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_ref: Option<CommittedEventRef>,
}

impl AgentSignerCurrentState {
    pub fn validate(&self) -> Result<()> {
        self.signing_key.validate()?;
        if let Some(status_ref) = &self.status_ref {
            if status_ref.stream_position > self.revision.stream_position
                || (status_ref.commit_id == self.revision.commit_id
                    && status_ref.stream_position != self.revision.stream_position)
            {
                return Err(self_signer_error(
                    ErrorCode::StateMismatch,
                    "Agent status Event is not covered by the answered current revision",
                ));
            }
        }
        if self.status != AgentCurrentStatus::Active && self.status_ref.is_none() {
            return Err(self_signer_error(
                ErrorCode::SchemaViolation,
                "a non-active Agent state requires its committed status Event",
            ));
        }
        Ok(())
    }

    pub fn active_key(&self) -> Result<&StationSigningKey> {
        self.validate()?;
        if self.status != AgentCurrentStatus::Active {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "Agent is not active at the returned current revision",
            ));
        }
        Ok(&self.signing_key)
    }
}

pub(crate) fn validate_ed25519_public_key(value: &str) -> Result<()> {
    let decoded = arkret_canonical::base64url::base64url_decode(value).map_err(|_| {
        self_signer_error(
            ErrorCode::SchemaViolation,
            "signer public key is not canonical unpadded base64url",
        )
    })?;
    if decoded.len() != 32 || arkret_canonical::base64url::base64url_encode(&decoded) != value {
        return Err(self_signer_error(
            ErrorCode::SchemaViolation,
            "signer public key must encode exactly 32 Ed25519 public-key bytes",
        ));
    }
    Ok(())
}

pub(crate) fn validate_self_signer_bytes<T: Serialize>(
    value: &T,
    maximum: usize,
    request: bool,
) -> Result<()> {
    if arkret_canonical::canonical_json_bytes(value)?.len() > maximum {
        // An oversized request is payload_too_large; only a response or one of
        // its items exceeding its budget is limit_exceeded.
        return Err(if request {
            self_signer_error(
                ErrorCode::PayloadTooLarge,
                "signer-key query exceeds its canonical byte limit",
            )
        } else {
            self_signer_error(
                ErrorCode::LimitExceeded,
                "signer-key result exceeds its canonical byte limit",
            )
        });
    }
    Ok(())
}

pub(crate) fn self_signer_error(code: ErrorCode, message: &str) -> WireError {
    WireError::ProtocolCode {
        code,
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::{
        AccountId, ActorId, Base64UrlString, CommitStreamRef, DidCoreId, DidUrl, EventId,
        RealmCommitId, RealmId,
    };
    use serde_json::json;

    use super::*;

    const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";

    fn realm_id() -> RealmId {
        RealmId::new(REALM).unwrap()
    }

    fn actor() -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ))
    }

    fn signing_key() -> StationSigningKey {
        StationSigningKey {
            actor: actor(),
            verification_method: DidUrl::new("did:web:agent.example#agent-key").unwrap(),
            public_key_b64u: Base64UrlString::new(arkret_wire::base64url::base64url_encode(
                [7_u8; 32],
            ))
            .unwrap(),
            authorization_ref: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [3; 32]),
        }
    }

    fn revision(position: u64, byte: u8) -> CurrentRevision {
        CurrentRevision {
            commit_id: RealmCommitId::from_digest([byte; 32]),
            stream_position: position,
        }
    }

    fn status_ref(position: u64, byte: u8) -> CommittedEventRef {
        CommittedEventRef {
            event_id: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [byte; 32]),
            commit_id: RealmCommitId::from_digest([byte; 32]),
            stream_ref: CommitStreamRef::Realm {
                realm_id: realm_id(),
            },
            stream_position: position,
        }
    }

    /// `station_signing_key` is closed over four members. A revision inside the
    /// key is exactly the shape the Spec forbids, and the deduplicated type
    /// cannot represent it at all.
    #[test]
    fn oversized_requests_and_results_use_distinct_registered_codes() {
        let code = |request| match validate_self_signer_bytes(&"x".repeat(8), 4, request) {
            Err(WireError::ProtocolCode { code, .. }) => code,
            other => panic!("expected a coded rejection, got {other:?}"),
        };
        assert_eq!(code(true), ErrorCode::PayloadTooLarge);
        assert_eq!(code(false), ErrorCode::LimitExceeded);
        assert!(validate_self_signer_bytes(&"x", 3, true).is_ok());
    }

    #[test]
    fn a_signing_key_carrying_a_revision_is_not_representable() {
        let mut value = serde_json::to_value(signing_key()).unwrap();
        value.as_object_mut().unwrap().insert(
            "revision".to_owned(),
            json!({"commit_id": "ak:realm_commit:1", "stream_position": 4}),
        );
        assert!(serde_json::from_value::<StationSigningKey>(value).is_err());
    }

    #[test]
    fn a_signing_key_names_its_authorization_by_bare_event_id() {
        let value = serde_json::to_value(signing_key()).unwrap();
        assert!(value["authorization_ref"].is_string());
        assert_eq!(
            value.as_object().unwrap().keys().collect::<Vec<_>>(),
            vec![
                "actor",
                "authorization_ref",
                "public_key_b64u",
                "verification_method"
            ]
        );
    }

    #[test]
    fn an_active_state_needs_no_status_event() {
        let state = AgentSignerCurrentState {
            status: AgentCurrentStatus::Active,
            signing_key: signing_key(),
            revision: revision(9, 0xfe),
            status_ref: None,
        };
        state.validate().unwrap();
        assert_eq!(state.active_key().unwrap(), &signing_key());
    }

    #[test]
    fn a_paused_state_without_its_status_event_is_refused() {
        let state = AgentSignerCurrentState {
            status: AgentCurrentStatus::Paused,
            signing_key: signing_key(),
            revision: revision(9, 0xfe),
            status_ref: None,
        };
        assert!(state.validate().is_err());
    }

    #[test]
    fn a_paused_state_is_auditable_but_yields_no_current_key() {
        let state = AgentSignerCurrentState {
            status: AgentCurrentStatus::Paused,
            signing_key: signing_key(),
            revision: revision(9, 0xfe),
            status_ref: Some(status_ref(4, 0x11)),
        };
        state.validate().unwrap();
        assert!(state.active_key().is_err());
    }

    #[test]
    fn a_status_event_past_the_answered_revision_is_refused() {
        let state = AgentSignerCurrentState {
            status: AgentCurrentStatus::Deactivated,
            signing_key: signing_key(),
            revision: revision(9, 0xfe),
            status_ref: Some(status_ref(11, 0x11)),
        };
        let error = state.validate().expect_err("an uncovered status must fail");
        assert!(error.to_string().contains("current revision"), "{error}");
    }

    /// One commit cannot sit at two stream positions, so a status Event that
    /// claims the answered commit at another position is incoherent.
    #[test]
    fn one_commit_at_two_stream_positions_is_refused() {
        let state = AgentSignerCurrentState {
            status: AgentCurrentStatus::Deactivated,
            signing_key: signing_key(),
            revision: revision(9, 0x11),
            status_ref: Some(status_ref(4, 0x11)),
        };
        assert!(state.validate().is_err());
    }
}
