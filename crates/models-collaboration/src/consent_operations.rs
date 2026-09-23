//! Holder-private consent self-management request/outcome DTOs.
//!
//! The consent state itself is a typed current result serialized by the current
//! governance Station. Grant and revoke carry one caller-signed Event through
//! the single Event submission DTO; the Station submits those exact bytes and
//! never co-signs, rebuilds or synthesizes the Event.

use arkret_wire::{
    AccountId, ConsentId, ConsentRequestScope, ConsentScope, CurrentRevision,
    EventAdmissionSubmission, EventKind, Result, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::events_payloads::consent::ConsentPeer;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentState {
    Active,
    Revoked,
}

// Field declaration order is byte-for-byte the properties order of
// consent-operations.schema.json#/$defs/consent_view.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentView {
    pub consent_id: ConsentId,
    pub peer: ConsentPeer,
    pub consent_scope: ConsentScope,
    pub state: ConsentState,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
    pub revision: CurrentRevision,
}

impl ConsentView {
    pub fn validate(&self) -> Result<()> {
        if self
            .expires_at
            .is_some_and(|expires_at| expires_at <= self.updated_at)
        {
            return Err(WireError::Protocol(
                "consent expires_at must follow updated_at".to_owned(),
            ));
        }
        Ok(())
    }
}

// Field declaration order is byte-for-byte the properties order of
// consent-operations.schema.json#/$defs/consent_list.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentList {
    pub consents: Vec<ConsentView>,
}

impl ConsentList {
    pub fn validate(&self) -> Result<()> {
        for consent in &self.consents {
            consent.validate()?;
        }
        Ok(())
    }
}

// Field declaration order is byte-for-byte the properties order of
// consent-operations.schema.json#/$defs/consent_grant_request_body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentGrantRequestBody {
    pub grant_event: EventAdmissionSubmission,
}

impl ConsentGrantRequestBody {
    pub fn validate(&self) -> Result<()> {
        validate_consent_command_event(&self.grant_event, EventKind::ConsentGrant)
    }
}

// Field declaration order is byte-for-byte the properties order of
// consent-operations.schema.json#/$defs/consent_revoke_request_body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentRevokeRequestBody {
    pub revoke_event: EventAdmissionSubmission,
}

impl ConsentRevokeRequestBody {
    pub fn validate(&self) -> Result<()> {
        validate_consent_command_event(&self.revoke_event, EventKind::ConsentRevoke)
    }
}

fn validate_consent_command_event(
    submission: &EventAdmissionSubmission,
    expected: EventKind,
) -> Result<()> {
    submission.event.validate_for_submit_structural()?;
    if submission.event.kind != expected {
        return Err(WireError::Protocol(format!(
            "consent command carries {} instead of {}",
            submission.event.kind.as_str(),
            expected.as_str()
        )));
    }
    Ok(())
}

// Field declaration order is byte-for-byte the properties order of
// consent-operations.schema.json#/$defs/consent_request_request_body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentRequestRequestBody {
    pub holder_account_id: AccountId,
    pub consent_scope: ConsentRequestScope,
}

impl ConsentRequestRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.holder_account_id.validate()?;
        Ok(())
    }
}

/// Constant anti-enumeration response. Missing holder, denial, rate-limit drop
/// and quarantine acceptance all return this exact shape.
// Field declaration order is byte-for-byte the properties order of
// consent-operations.schema.json#/$defs/consent_request_outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentRequestOutcome {
    pub accepted_for_processing: bool,
}

impl ConsentRequestOutcome {
    #[must_use]
    pub const fn accepted() -> Self {
        Self {
            accepted_for_processing: true,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !self.accepted_for_processing {
            return Err(WireError::Protocol(
                "consent request outcome is pinned to accepted_for_processing = true".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn consent_view_value() -> serde_json::Value {
        json!({
            "consent_id": "ak:consent:0198ff00-0000-7000-8000-000000000001",
            "peer": {
                "kind": "actor",
                "actor_id": {
                    "kind": "account",
                    "account_id": {
                        "principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
                        "station_id": "ak:did_core:web:station.example"
                    }
                }
            },
            "consent_scope": "voice_call",
            "state": "active",
            "updated_at": "2026-08-09T00:00:00.000Z",
            "revision": {
                "commit_id": arkret_wire::RealmCommitId::from_digest([2; 32]),
                "stream_position": 7
            }
        })
    }

    #[test]
    fn consent_view_round_trips_and_is_closed() {
        let value = consent_view_value();
        let parsed: ConsentView = serde_json::from_value(value.clone()).expect("closed view");
        assert_eq!(parsed.state, ConsentState::Active);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut revoked = value.clone();
        revoked["state"] = json!("revoked");
        let parsed_revoked: ConsentView =
            serde_json::from_value(revoked.clone()).expect("revoked current view");
        assert_eq!(parsed_revoked.state, ConsentState::Revoked);
        assert_eq!(serde_json::to_value(parsed_revoked).unwrap(), revoked);

        let mut retired = value.clone();
        retired["state"] = json!("no_consent");
        assert!(serde_json::from_value::<ConsentView>(retired).is_err());

        let mut inferred_pending = value.clone();
        inferred_pending["requested_at"] = json!("2026-08-09T00:00:00.000Z");
        assert!(serde_json::from_value::<ConsentView>(inferred_pending).is_err());

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("dots".to_owned(), json!([]));
        assert!(serde_json::from_value::<ConsentView>(unknown).is_err());

        for required in [
            "consent_id",
            "peer",
            "consent_scope",
            "state",
            "updated_at",
            "revision",
        ] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(required);
            assert!(
                serde_json::from_value::<ConsentView>(missing).is_err(),
                "{required} must not become optional"
            );
        }
    }

    #[test]
    fn consent_request_body_rejects_the_invite_scope() {
        let body = json!({
            "holder_account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
                "station_id": "ak:did_core:web:station.example"
            },
            "consent_scope": "invite"
        });
        assert!(
            serde_json::from_value::<ConsentRequestRequestBody>(body).is_err(),
            "invite has no consent-request carrier"
        );
    }

    #[test]
    fn consent_request_outcome_is_a_constant_shape() {
        let value = json!({"accepted_for_processing": true});
        let parsed: ConsentRequestOutcome =
            serde_json::from_value(value.clone()).expect("closed outcome");
        parsed.validate().expect("pinned outcome");
        assert_eq!(serde_json::to_value(parsed).unwrap(), value);

        let denied: ConsentRequestOutcome =
            serde_json::from_value(json!({"accepted_for_processing": false})).expect("closed");
        assert!(denied.validate().is_err());

        assert!(serde_json::from_value::<ConsentRequestOutcome>(json!({})).is_err());
    }

    #[test]
    fn consent_list_is_closed() {
        let value = json!({"consents": [consent_view_value()]});
        let parsed: ConsentList = serde_json::from_value(value.clone()).expect("closed list");
        parsed.validate().expect("valid list");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
        assert!(
            serde_json::from_value::<ConsentList>(json!({"consents": [], "next_cursor": "x"}))
                .is_err()
        );
    }
}
