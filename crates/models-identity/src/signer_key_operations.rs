//! Authenticated self-query for current or exact committed historical signing
//! keys. Results are query-local projections, not portable authority evidence.

use std::collections::BTreeSet;

use arkret_wire::{
    AccountId, ActorId, Base64UrlString, CommittedEventRef, CurrentRevision, DeviceId, DidUrl,
    ErrorCode, RealmId, RequestId, Result,
};
use serde::{Deserialize, Serialize};

use crate::agent_signer_state::{
    SELF_SIGNER_OUTCOME_MAX_BYTES, SELF_SIGNER_REQUEST_MAX_BYTES, SELF_SIGNER_RESULT_MAX_BYTES,
    SignerKeyResolutionStatus, StationSigningKey, self_signer_error, validate_ed25519_public_key,
    validate_self_signer_bytes,
};

pub const MAX_SIGNER_KEY_QUERIES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SignerSubjectKind {
    AccountDevice,
    Agent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SignerKeyQuerySelector {
    Current {
        subject_kind: SignerSubjectKind,
        actor: ActorId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<DeviceId>,
        verification_method: DidUrl,
    },
    HistoricalCommittedEvent {
        subject_kind: SignerSubjectKind,
        actor: ActorId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<DeviceId>,
        verification_method: DidUrl,
        committed_event_ref: CommittedEventRef,
    },
}

impl SignerKeyQuerySelector {
    pub fn actor(&self) -> &ActorId {
        match self {
            Self::Current { actor, .. } | Self::HistoricalCommittedEvent { actor, .. } => actor,
        }
    }

    pub fn verification_method(&self) -> &DidUrl {
        match self {
            Self::Current {
                verification_method,
                ..
            }
            | Self::HistoricalCommittedEvent {
                verification_method,
                ..
            } => verification_method,
        }
    }

    pub fn committed_event_ref(&self) -> Option<&CommittedEventRef> {
        match self {
            Self::Current { .. } => None,
            Self::HistoricalCommittedEvent {
                committed_event_ref,
                ..
            } => Some(committed_event_ref),
        }
    }

    pub fn validate(&self, realm_id: &RealmId) -> Result<()> {
        let (subject_kind, device_id) = match self {
            Self::Current {
                subject_kind,
                device_id,
                ..
            }
            | Self::HistoricalCommittedEvent {
                subject_kind,
                device_id,
                ..
            } => (subject_kind, device_id),
        };
        let ActorId::Account { account_id } = self.actor() else {
            return Err(self_signer_error(
                ErrorCode::SchemaViolation,
                "device and Agent signer selectors require a complete account ActorId",
            ));
        };
        account_id.validate()?;
        if matches!(subject_kind, SignerSubjectKind::AccountDevice) != device_id.is_some() {
            return Err(self_signer_error(
                ErrorCode::SchemaViolation,
                "device_id is required exactly for account-device signer selectors",
            ));
        }
        if self
            .committed_event_ref()
            .is_some_and(|reference| reference.stream_ref.realm_id() != realm_id)
        {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "historical signer Event belongs to another Realm",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
                "signer-key query requires 1..=64 selectors",
            ));
        }
        let mut seen = BTreeSet::new();
        for selector in &self.queries {
            selector.validate(&self.realm_id)?;
            if !seen.insert(arkret_canonical::canonical_json_bytes(selector)?) {
                return Err(self_signer_error(
                    ErrorCode::SchemaViolation,
                    "duplicate signer-key selector",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ResolvedSignerKey {
    pub public_key_b64u: Base64UrlString,
    pub authorization_ref: CommittedEventRef,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub revision: CurrentRevision,
}

impl ResolvedSignerKey {
    pub fn validate(&self) -> Result<()> {
        validate_ed25519_public_key(self.public_key_b64u.as_str())?;
        if self.authorization_ref.commit_id != self.revision.commit_id
            && self.authorization_ref.stream_position > self.revision.stream_position
        {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "resolved signing key is not covered by its authority-stream revision",
            ));
        }
        Ok(())
    }

    pub fn from_station_key(
        key: StationSigningKey,
        selector: &SignerKeyQuerySelector,
        realm_id: &RealmId,
    ) -> Result<Self> {
        key.validate()?;
        selector.validate(realm_id)?;
        if key.actor != *selector.actor()
            || key.verification_method != *selector.verification_method()
        {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "signing key does not match the exact selector",
            ));
        }
        let resolved = Self {
            public_key_b64u: key.public_key_b64u,
            authorization_ref: key.authorization_ref,
            revision: key.revision,
        };
        resolved.validate()?;
        Ok(resolved)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SignerKeyQueryResult {
    pub selector: SignerKeyQuerySelector,
    pub status: SignerKeyResolutionStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<ResolvedSignerKey>,
}

impl SignerKeyQueryResult {
    pub fn validate(&self, realm_id: &RealmId) -> Result<()> {
        validate_self_signer_bytes(self, SELF_SIGNER_RESULT_MAX_BYTES, false)?;
        self.selector.validate(realm_id)?;
        match (self.status, &self.key) {
            (SignerKeyResolutionStatus::Resolved, Some(key)) => key.validate(),
            (SignerKeyResolutionStatus::Unavailable, None) => Ok(()),
            _ => Err(self_signer_error(
                ErrorCode::SchemaViolation,
                "resolved status requires a key and unavailable status forbids one",
            )),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct SignerKeysQueryOutcome {
    pub request_id: RequestId,
    pub realm_id: RealmId,
    pub recipient_account_id: AccountId,
    pub results: Vec<SignerKeyQueryResult>,
}

impl SignerKeysQueryOutcome {
    pub fn validate(&self) -> Result<()> {
        validate_self_signer_bytes(self, SELF_SIGNER_OUTCOME_MAX_BYTES, false)?;
        if self.results.is_empty() || self.results.len() > MAX_SIGNER_KEY_QUERIES {
            return Err(self_signer_error(
                ErrorCode::SchemaViolation,
                "signer-key outcome requires 1..=64 results",
            ));
        }
        let mut seen = BTreeSet::new();
        for result in &self.results {
            result.validate(&self.realm_id)?;
            if !seen.insert(arkret_canonical::canonical_json_bytes(&result.selector)?) {
                return Err(self_signer_error(
                    ErrorCode::SchemaViolation,
                    "duplicate signer-key result",
                ));
            }
        }
        Ok(())
    }

    pub fn validate_for_request(&self, request: &SignerKeysQueryRequestBody) -> Result<()> {
        request.validate()?;
        self.validate()?;
        if self.request_id != request.request_id
            || self.realm_id != request.realm_id
            || self.recipient_account_id != request.recipient_account_id
        {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "signer-key outcome does not match its request",
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
            .map(|result| arkret_canonical::canonical_json_bytes(&result.selector))
            .collect::<std::result::Result<_, _>>()?;
        if asked != answered {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "signer-key outcome must answer every exact selector once",
            ));
        }
        Ok(())
    }
}
