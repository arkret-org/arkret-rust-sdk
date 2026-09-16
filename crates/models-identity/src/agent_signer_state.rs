//! Query-local Agent signing state projected by the authoritative Station.
//!
//! This module intentionally contains no portable historical closure.
//! Authority is established by exact committed authorization/status Events and
//! the current stream revision; callers still verify the producer proof with
//! the returned key.

use arkret_wire::{
    ActorId, Base64UrlString, CommittedEventRef, CurrentRevision, DidUrl, ErrorCode, Result,
    WireError,
};
use serde::{Deserialize, Serialize};

pub const SELF_SIGNER_REQUEST_MAX_BYTES: usize = 64 * 1024;
pub const SELF_SIGNER_RESULT_MAX_BYTES: usize = 64 * 1024;
pub const SELF_SIGNER_OUTCOME_MAX_BYTES: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum SignerKeyResolutionStatus {
    Resolved,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AgentCurrentStatus {
    Active,
    Paused,
    Deactivated,
}

/// Key material returned only to the authenticated self caller.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct StationSigningKey {
    pub actor: ActorId,
    pub verification_method: DidUrl,
    pub public_key_b64u: Base64UrlString,
    /// Exact committed authorization Event from the owning independent stream.
    pub authorization_ref: CommittedEventRef,
    /// Revision of the projected current state used for this answer.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub revision: CurrentRevision,
}

impl StationSigningKey {
    pub fn validate(&self) -> Result<()> {
        self.actor.validate()?;
        validate_ed25519_public_key(self.public_key_b64u.as_str())?;
        if self.authorization_ref.commit_id != self.revision.commit_id
            && self.authorization_ref.stream_position > self.revision.stream_position
        {
            return Err(self_signer_error(
                ErrorCode::StateMismatch,
                "signing-key authorization is newer than its current-state revision",
            ));
        }
        Ok(())
    }
}

/// Closed current Agent state. Paused/deactivated rows remain auditable but
/// cannot be used as a current signing key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AgentSignerCurrentState {
    pub status: AgentCurrentStatus,
    pub signing_key: StationSigningKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_ref: Option<CommittedEventRef>,
}

impl AgentSignerCurrentState {
    pub fn validate(&self) -> Result<()> {
        self.signing_key.validate()?;
        if let Some(status_ref) = &self.status_ref {
            if status_ref.stream_ref != self.signing_key.authorization_ref.stream_ref
                || status_ref.stream_position > self.signing_key.revision.stream_position
            {
                return Err(self_signer_error(
                    ErrorCode::StateMismatch,
                    "Agent status and authorization must come from the same committed stream revision",
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
                ErrorCode::AgentAuthorizationInactive,
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
        return Err(self_signer_error(
            ErrorCode::LimitExceeded,
            if request {
                "signer-key query exceeds its canonical byte limit"
            } else {
                "signer-key result exceeds its canonical byte limit"
            },
        ));
    }
    Ok(())
}

pub(crate) fn self_signer_error(code: ErrorCode, message: &str) -> WireError {
    WireError::ProtocolCode {
        code,
        message: message.to_owned(),
    }
}
