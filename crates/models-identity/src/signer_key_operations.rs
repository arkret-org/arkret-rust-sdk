//! Own-Station signing-key results for `ak.self.signer_keys.read.resolve.v1`
//! (`POST /_arkret/self/signer-keys/query`).
//!
//! This is the single self-path signer surface. It replaced the separate
//! `self/current-signer-evidence/query` and `self/agent-signer-evidence/query`
//! operations, which the protocol no longer defines, and it answers both
//! current-invocation and exact locally accepted historical questions in one
//! closed result union.
//!
//! What it deliberately is not: portable evidence, a reusable current grant, or
//! anything a caller can hand to a third party. The receiver is the
//! authenticated recipient Station, never a caller-selected remote service.

use std::collections::BTreeSet;

use arkret_wire::{
    AccountId, ActorId, DeviceId, DidUrl, ErrorCode, EventId, RealmId, RequestId, Result,
    SignerEvidenceRef,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::agent_signer_evidence::{
    SELF_SIGNER_OUTCOME_MAX_BYTES, SELF_SIGNER_REQUEST_MAX_BYTES, SELF_SIGNER_RESULT_MAX_BYTES,
    SignerEvidenceResolvedStatus, SignerEvidenceUnavailableStatus, StationSigningKey,
    self_signer_error, validate_self_signer_bytes,
};

/// Upper bound on selectors per request and results per outcome.
pub const MAX_SIGNER_KEY_QUERIES: usize = 64;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CurrentAdmissionMode {
    #[serde(rename = "current_admission")]
    CurrentAdmission,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HistoricalEventMode {
    #[serde(rename = "historical_event")]
    HistoricalEvent,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountDeviceSenderKind {
    #[serde(rename = "account_device")]
    AccountDevice,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentSenderKind {
    #[serde(rename = "agent")]
    Agent,
}

fn validate_signing_actor(actor: &ActorId) -> Result<()> {
    let ActorId::Account { account_id } = actor else {
        return Err(self_signer_error(
            ErrorCode::SchemaViolation,
            "signer key actor must keep the complete account ActorId of the signer",
        ));
    };
    account_id.validate()
}

fn validate_ed25519_public_key(value: &str) -> Result<()> {
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

/// Historical device signing key. It carries no `authorization_ref`: the
/// authority question was already settled when the Event was accepted.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalDeviceSigningKey {
    pub actor: ActorId,
    pub verification_method: DidUrl,
    pub public_key_b64u: String,
}

impl HistoricalDeviceSigningKey {
    pub fn validate(&self) -> Result<()> {
        validate_signing_actor(&self.actor)?;
        validate_ed25519_public_key(&self.public_key_b64u)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentAccountDeviceSelector {
    pub verification_mode: CurrentAdmissionMode,
    pub sender_kind: AccountDeviceSenderKind,
    pub actor: ActorId,
    pub device_id: DeviceId,
    pub verification_method: DidUrl,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentAgentSelector {
    pub verification_mode: CurrentAdmissionMode,
    pub sender_kind: AgentSenderKind,
    pub actor: ActorId,
    pub verification_method: DidUrl,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalAccountDeviceSelector {
    pub verification_mode: HistoricalEventMode,
    pub sender_kind: AccountDeviceSenderKind,
    pub actor: ActorId,
    pub device_id: DeviceId,
    pub verification_method: DidUrl,
    pub event_id: EventId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalAgentSelector {
    pub verification_mode: HistoricalEventMode,
    pub sender_kind: AgentSenderKind,
    pub actor: ActorId,
    pub verification_method: DidUrl,
    pub event_id: EventId,
}

/// Closed selector union. The verification mode and sender kind are signed-in
/// constants rather than free enums, so a current question can never be
/// answered from historical state or the other way round.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SignerKeyQuerySelector {
    CurrentAccountDevice(CurrentAccountDeviceSelector),
    CurrentAgent(CurrentAgentSelector),
    HistoricalAccountDevice(HistoricalAccountDeviceSelector),
    HistoricalAgent(HistoricalAgentSelector),
}

impl SignerKeyQuerySelector {
    #[must_use]
    pub fn actor(&self) -> &ActorId {
        match self {
            Self::CurrentAccountDevice(selector) => &selector.actor,
            Self::CurrentAgent(selector) => &selector.actor,
            Self::HistoricalAccountDevice(selector) => &selector.actor,
            Self::HistoricalAgent(selector) => &selector.actor,
        }
    }

    #[must_use]
    pub fn verification_method(&self) -> &DidUrl {
        match self {
            Self::CurrentAccountDevice(selector) => &selector.verification_method,
            Self::CurrentAgent(selector) => &selector.verification_method,
            Self::HistoricalAccountDevice(selector) => &selector.verification_method,
            Self::HistoricalAgent(selector) => &selector.verification_method,
        }
    }

    /// The exact Event a historical question is about, if any.
    #[must_use]
    pub fn event_id(&self) -> Option<&EventId> {
        match self {
            Self::CurrentAccountDevice(_) | Self::CurrentAgent(_) => None,
            Self::HistoricalAccountDevice(selector) => Some(&selector.event_id),
            Self::HistoricalAgent(selector) => Some(&selector.event_id),
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_signing_actor(self.actor())
    }
}

/// Body of `ak.self.signer_keys.read.resolve.v1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerKeysQueryRequestBody {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub recipient_account_id: AccountId,
    pub queries: Vec<SignerKeyQuerySelector>,
}

impl SignerKeysQueryRequestBody {
    pub fn validate(&self) -> Result<()> {
        validate_self_signer_bytes(self, SELF_SIGNER_REQUEST_MAX_BYTES, true)?;
        self.recipient_account_id.validate()?;
        if self.queries.is_empty() || self.queries.len() > MAX_SIGNER_KEY_QUERIES {
            return Err(self_signer_error(
                ErrorCode::SchemaViolation,
                "signer keys query requires 1..=64 selectors",
            ));
        }
        let mut seen = BTreeSet::new();
        for selector in &self.queries {
            selector.validate()?;
            if !seen.insert(arkret_canonical::canonical_json_bytes(selector)?) {
                return Err(self_signer_error(
                    ErrorCode::SchemaViolation,
                    "duplicate signer keys selector",
                ));
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentSignerKeyOutcome {
    pub selector: SignerKeyQuerySelector,
    pub status: SignerEvidenceResolvedStatus,
    pub key: StationSigningKey,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub checked_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalAccountDeviceSignerKeyOutcome {
    pub selector: HistoricalAccountDeviceSelector,
    pub status: SignerEvidenceResolvedStatus,
    pub key: HistoricalDeviceSigningKey,
    /// The producer's admission time for the Event, never the local receiver's
    /// acceptance time.
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalAgentSignerKeyOutcome {
    pub selector: HistoricalAgentSelector,
    pub status: SignerEvidenceResolvedStatus,
    pub key: StationSigningKey,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub signer_evidence_ref: SignerEvidenceRef,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnavailableSignerKeyOutcome {
    pub selector: SignerKeyQuerySelector,
    pub status: SignerEvidenceUnavailableStatus,
}

/// Closed per-selector result union.
///
/// `unavailable` is one indistinguishable answer: it never says whether the
/// target is absent, invisible, revoked or merely unreachable this time, and it
/// is never rendered as a missing row.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SignerKeyQueryOutcome {
    Current(CurrentSignerKeyOutcome),
    HistoricalAgent(HistoricalAgentSignerKeyOutcome),
    HistoricalAccountDevice(HistoricalAccountDeviceSignerKeyOutcome),
    Unavailable(UnavailableSignerKeyOutcome),
}

impl SignerKeyQueryOutcome {
    #[must_use]
    pub fn selector(&self) -> SignerKeyQuerySelector {
        match self {
            Self::Current(result) => result.selector.clone(),
            Self::HistoricalAgent(result) => {
                SignerKeyQuerySelector::HistoricalAgent(result.selector.clone())
            }
            Self::HistoricalAccountDevice(result) => {
                SignerKeyQuerySelector::HistoricalAccountDevice(result.selector.clone())
            }
            Self::Unavailable(result) => result.selector.clone(),
        }
    }

    /// The resolved signing key, or `None` when the Station answered
    /// `unavailable`.
    #[must_use]
    pub fn verification_method(&self) -> Option<&DidUrl> {
        match self {
            Self::Current(result) => Some(&result.key.verification_method),
            Self::HistoricalAgent(result) => Some(&result.key.verification_method),
            Self::HistoricalAccountDevice(result) => Some(&result.key.verification_method),
            Self::Unavailable(_) => None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_self_signer_bytes(self, SELF_SIGNER_RESULT_MAX_BYTES, false)?;
        let selector = self.selector();
        selector.validate()?;
        match self {
            Self::Current(result) => {
                if matches!(
                    result.selector,
                    SignerKeyQuerySelector::HistoricalAccountDevice(_)
                        | SignerKeyQuerySelector::HistoricalAgent(_)
                ) {
                    return Err(self_signer_error(
                        ErrorCode::SchemaViolation,
                        "a current signer key result must answer a current selector",
                    ));
                }
                result.key.validate()?;
            }
            Self::HistoricalAgent(result) => result.key.validate()?,
            Self::HistoricalAccountDevice(result) => result.key.validate()?,
            Self::Unavailable(_) => return Ok(()),
        }
        // The answered key must be the exact method the selector asked about;
        // a Station that substitutes another key is not answering the question.
        if self.verification_method() != Some(selector.verification_method()) {
            return Err(self_signer_error(
                ErrorCode::SchemaViolation,
                "signer key result answers a different verification method than its selector",
            ));
        }
        Ok(())
    }
}

/// Success body of `ak.self.signer_keys.read.resolve.v1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerKeysQueryOutcome {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub recipient_account_id: AccountId,
    pub results: Vec<SignerKeyQueryOutcome>,
}

impl SignerKeysQueryOutcome {
    pub fn validate(&self) -> Result<()> {
        validate_self_signer_bytes(self, SELF_SIGNER_OUTCOME_MAX_BYTES, false)?;
        if self.results.is_empty() || self.results.len() > MAX_SIGNER_KEY_QUERIES {
            return Err(self_signer_error(
                ErrorCode::SchemaViolation,
                "signer keys outcome requires 1..=64 results",
            ));
        }
        let mut seen = BTreeSet::new();
        for result in &self.results {
            result.validate()?;
            if !seen.insert(arkret_canonical::canonical_json_bytes(&result.selector())?) {
                return Err(self_signer_error(
                    ErrorCode::SchemaViolation,
                    "duplicate signer keys result",
                ));
            }
        }
        Ok(())
    }

    /// Reject a late or foreign answer, then require exactly one result per
    /// selector the caller asked about.
    pub fn validate_for_request(&self, request: &SignerKeysQueryRequestBody) -> Result<()> {
        request.validate()?;
        self.validate()?;
        if self.request_id != request.request_id
            || self.realm_id != request.realm_id
            || self.recipient_account_id != request.recipient_account_id
        {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "signer keys result differs from the exact request, Realm or recipient",
            ));
        }
        let asked: BTreeSet<Vec<u8>> = request
            .queries
            .iter()
            .map(arkret_canonical::canonical_json_bytes)
            .collect::<std::result::Result<_, _>>()?;
        let answered: BTreeSet<Vec<u8>> = self
            .results
            .iter()
            .map(|result| arkret_canonical::canonical_json_bytes(&result.selector()))
            .collect::<std::result::Result<_, _>>()?;
        if asked != answered {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "signer keys result does not answer exactly the selectors that were asked",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::DidCoreId;

    use super::*;

    fn account() -> AccountId {
        AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
    }

    fn method() -> DidUrl {
        DidUrl::new("did:web:alice.example#device-1").unwrap()
    }

    fn current_selector() -> SignerKeyQuerySelector {
        SignerKeyQuerySelector::CurrentAccountDevice(CurrentAccountDeviceSelector {
            verification_mode: CurrentAdmissionMode::CurrentAdmission,
            sender_kind: AccountDeviceSenderKind::AccountDevice,
            actor: ActorId::account(account()),
            device_id: DeviceId::new("ak:device:019a0000-0000-7000-8000-000000000001").unwrap(),
            verification_method: method(),
        })
    }

    fn historical_selector() -> HistoricalAccountDeviceSelector {
        HistoricalAccountDeviceSelector {
            verification_mode: HistoricalEventMode::HistoricalEvent,
            sender_kind: AccountDeviceSenderKind::AccountDevice,
            actor: ActorId::account(account()),
            device_id: DeviceId::new("ak:device:019a0000-0000-7000-8000-000000000001").unwrap(),
            verification_method: method(),
            event_id: EventId::new("ak:event:Ae6YFfDokA1FLUx_l-MhAbSvTvoys2ZpRPmqFwrWjd9g")
                .unwrap(),
        }
    }

    fn station_key() -> StationSigningKey {
        StationSigningKey {
            actor: ActorId::account(account()),
            verification_method: method(),
            public_key_b64u: arkret_wire::Base64UrlString::new(
                "WnA82IwABQeTR4DCdDNIbwpCZAbc6nFs1BaTzKuN3Gs",
            )
            .unwrap(),
            authorization_ref: EventId::new(
                "ak:event:Ae6YFfDokA1FLUx_l-MhAbSvTvoys2ZpRPmqFwrWjd9g",
            )
            .unwrap(),
        }
    }

    fn request() -> SignerKeysQueryRequestBody {
        SignerKeysQueryRequestBody {
            request_id: RequestId::new("ak:request:01970000-0000-7000-8000-000000000081").unwrap(),
            realm_id: RealmId::new("ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5")
                .unwrap(),
            recipient_account_id: account(),
            queries: vec![
                current_selector(),
                SignerKeyQuerySelector::HistoricalAccountDevice(historical_selector()),
            ],
        }
    }

    #[test]
    fn selector_modes_survive_a_wire_round_trip_without_collapsing() {
        let request = request();
        request.validate().unwrap();
        let wire = serde_json::to_value(&request).unwrap();
        assert_eq!(wire["queries"][0]["verification_mode"], "current_admission");
        assert_eq!(wire["queries"][1]["verification_mode"], "historical_event");
        let decoded: SignerKeysQueryRequestBody = serde_json::from_value(wire).unwrap();
        assert_eq!(decoded, request);
        assert!(decoded.queries[0].event_id().is_none());
        assert!(decoded.queries[1].event_id().is_some());
    }

    #[test]
    fn outcome_must_answer_exactly_the_selectors_that_were_asked() {
        let request = request();
        let outcome = SignerKeysQueryOutcome {
            request_id: request.request_id.clone(),
            realm_id: request.realm_id.clone(),
            recipient_account_id: request.recipient_account_id.clone(),
            results: vec![
                SignerKeyQueryOutcome::Current(CurrentSignerKeyOutcome {
                    selector: current_selector(),
                    status: SignerEvidenceResolvedStatus::Resolved,
                    key: station_key(),
                    checked_at: "2026-09-10T00:00:00.000Z".parse().unwrap(),
                }),
                SignerKeyQueryOutcome::Unavailable(UnavailableSignerKeyOutcome {
                    selector: SignerKeyQuerySelector::HistoricalAccountDevice(historical_selector()),
                    status: SignerEvidenceUnavailableStatus::Unavailable,
                }),
            ],
        };
        outcome.validate_for_request(&request).unwrap();

        let mut short = outcome.clone();
        short.results.pop();
        assert!(short.validate_for_request(&request).is_err());

        let mut foreign = outcome;
        foreign.request_id =
            RequestId::new("ak:request:01970000-0000-7000-8000-000000000082").unwrap();
        assert!(foreign.validate_for_request(&request).is_err());
    }

    #[test]
    fn a_result_may_not_substitute_another_verification_method() {
        let swapped = SignerKeyQueryOutcome::Current(CurrentSignerKeyOutcome {
            selector: current_selector(),
            status: SignerEvidenceResolvedStatus::Resolved,
            key: StationSigningKey {
                verification_method: DidUrl::new("did:web:alice.example#device-2").unwrap(),
                ..station_key()
            },
            checked_at: "2026-09-10T00:00:00.000Z".parse().unwrap(),
        });
        assert!(swapped.validate().is_err());
    }

    #[test]
    fn a_current_result_may_not_answer_a_historical_selector() {
        let mismatched = SignerKeyQueryOutcome::Current(CurrentSignerKeyOutcome {
            selector: SignerKeyQuerySelector::HistoricalAccountDevice(historical_selector()),
            status: SignerEvidenceResolvedStatus::Resolved,
            key: station_key(),
            checked_at: "2026-09-10T00:00:00.000Z".parse().unwrap(),
        });
        assert!(mismatched.validate().is_err());
    }

    #[test]
    fn a_service_actor_is_not_a_signer_key_subject() {
        let mut selector = current_selector();
        if let SignerKeyQuerySelector::CurrentAccountDevice(inner) = &mut selector {
            inner.actor =
                ActorId::service(DidCoreId::new("ak:did_core:web:station.example").unwrap());
        }
        assert!(selector.validate().is_err());
    }
}
