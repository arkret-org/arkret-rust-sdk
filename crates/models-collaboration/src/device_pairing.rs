//! Device-pairing challenge and target-possession DTOs.

use arkret_wire::{
    AccountId, Base64UrlString, CommittedEventRef, DeviceId, DidKey, EventCommitSubmission, Hash,
    NonEmptyString, Result, WireError, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::events_payloads::{DeviceAuthorizationBindingKind, SignatureMaterial};
use crate::governance::agent_artifacts::{DeviceMetadata, GrantSnapshot, PublicKey};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DevicePairingRequestId(String);

impl DevicePairingRequestId {
    pub fn new(value: String) -> Result<Self> {
        static PATTERN: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
            regex::Regex::new(r"^device_pairing_request:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
                .expect("device pairing request id regex")
        });
        if !PATTERN.is_match(&value) {
            return Err(WireError::Protocol(
                "device pairing request id must contain a canonical UUIDv7".into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DevicePairingRequestId {
    type Error = WireError;
    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<DevicePairingRequestId> for String {
    fn from(value: DevicePairingRequestId) -> Self {
        value.0
    }
}

impl std::fmt::Display for DevicePairingRequestId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DevicePairingCode(String);

impl DevicePairingCode {
    pub fn new(value: String) -> Result<Self> {
        if value.len() != 8
            || !value
                .bytes()
                .all(|byte| b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789".contains(&byte))
        {
            return Err(WireError::Protocol(
                "device pairing code must be 8 Crockford-style characters".into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DevicePairingCode {
    type Error = WireError;
    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<DevicePairingCode> for String {
    fn from(value: DevicePairingCode) -> Self {
        value.0
    }
}

impl std::fmt::Display for DevicePairingCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DevicePairingNonce(Base64UrlString);

impl DevicePairingNonce {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if !(22..=86).contains(&value.len()) {
            return Err(WireError::Protocol(
                "device pairing nonce must contain 22..=86 base64url characters".into(),
            ));
        }
        Ok(Self(
            Base64UrlString::new(value).map_err(|reason| WireError::Protocol(reason.into()))?,
        ))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl TryFrom<String> for DevicePairingNonce {
    type Error = WireError;
    fn try_from(value: String) -> Result<Self> {
        Self::new(value)
    }
}

impl From<DevicePairingNonce> for String {
    fn from(value: DevicePairingNonce) -> Self {
        value.0.into_string()
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingTargetProof {
    pub account_id: AccountId,
    pub device_id: DeviceId,
    pub device_public_key_did: DidKey,
    pub hpke_key: NonEmptyString,
    pub algorithms: Vec<NonEmptyString>,
    pub device_key_algorithm: DevicePairingTargetKeyAlgorithm,
    pub authorization_binding_kind: DeviceAuthorizationBindingKind,
    pub pairing_challenge_transcript_digest: Hash,
    pub device_signature: SignatureMaterial,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DevicePairingTargetKeyAlgorithm {
    #[serde(rename = "Ed25519")]
    Ed25519,
}

#[derive(Clone, Debug)]
pub struct UnsignedDevicePairingTargetProof {
    account_id: AccountId,
    device_id: DeviceId,
    device_public_key_did: DidKey,
    hpke_key: NonEmptyString,
    algorithms: Vec<NonEmptyString>,
    pairing_challenge_transcript_digest: Hash,
}

impl UnsignedDevicePairingTargetProof {
    pub fn new(
        account_id: AccountId,
        device_id: DeviceId,
        device_public_key_did: DidKey,
        hpke_key: NonEmptyString,
        algorithms: Vec<NonEmptyString>,
        pairing_challenge_transcript_digest: Hash,
    ) -> Result<Self> {
        account_id.validate()?;
        if algorithms.is_empty()
            || algorithms
                .windows(2)
                .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err(WireError::Protocol(
                "pairing target algorithms must be non-empty, sorted and unique".into(),
            ));
        }
        Ok(Self {
            account_id,
            device_id,
            device_public_key_did,
            hpke_key,
            algorithms,
            pairing_challenge_transcript_digest,
        })
    }

    pub fn signing_input(&self) -> Result<Vec<u8>> {
        device_pairing_target_proof_signing_input(
            &self.account_id,
            &self.algorithms,
            self.device_id.as_str(),
            self.device_public_key_did.as_str(),
            self.hpke_key.as_str(),
            self.pairing_challenge_transcript_digest.as_str(),
        )
    }

    pub fn attach_signature(self, device_signature: SignatureMaterial) -> DevicePairingTargetProof {
        DevicePairingTargetProof {
            account_id: self.account_id,
            device_id: self.device_id,
            device_public_key_did: self.device_public_key_did,
            hpke_key: self.hpke_key,
            algorithms: self.algorithms,
            device_key_algorithm: DevicePairingTargetKeyAlgorithm::Ed25519,
            authorization_binding_kind: DeviceAuthorizationBindingKind::AcceptedDevice,
            pairing_challenge_transcript_digest: self.pairing_challenge_transcript_digest,
            device_signature,
        }
    }
}

impl DevicePairingTargetProof {
    pub fn signing_input(&self) -> Result<Vec<u8>> {
        if self.authorization_binding_kind != DeviceAuthorizationBindingKind::AcceptedDevice {
            return Err(WireError::Protocol(
                "pairing target attestation must use accepted_device binding".into(),
            ));
        }
        UnsignedDevicePairingTargetProof::new(
            self.account_id.clone(),
            self.device_id.clone(),
            self.device_public_key_did.clone(),
            self.hpke_key.clone(),
            self.algorithms.clone(),
            self.pairing_challenge_transcript_digest.clone(),
        )?
        .signing_input()
    }
}

pub(crate) fn device_pairing_target_proof_signing_input(
    account_id: &AccountId,
    algorithms: &[NonEmptyString],
    device_id: &str,
    device_public_key_did: &str,
    hpke_key: &str,
    pairing_challenge_transcript_digest: &str,
) -> Result<Vec<u8>> {
    #[derive(Serialize)]
    struct SigningObject<'a> {
        account_id: &'a AccountId,
        algorithms: &'a [NonEmptyString],
        authorization_binding_kind: DeviceAuthorizationBindingKind,
        device_id: &'a str,
        device_key_algorithm: &'static str,
        device_public_key_did: &'a str,
        hpke_key: &'a str,
        pairing_challenge_transcript_digest: &'a str,
    }
    let object = SigningObject {
        account_id,
        algorithms,
        authorization_binding_kind: DeviceAuthorizationBindingKind::AcceptedDevice,
        device_id,
        device_key_algorithm: "Ed25519",
        device_public_key_did,
        hpke_key,
        pairing_challenge_transcript_digest,
    };
    let mut bytes = b"ak.device_authorize_accepted_device_possession_proof.v1\n".to_vec();
    bytes.extend(canonical::canonical_json_bytes(&object)?);
    Ok(bytes)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingStageRequestBody {
    pub new_device_pubkey: PublicKey,
    pub client_nonce: DevicePairingNonce,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_metadata: Option<DeviceMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingStageOutcome {
    pub device_pairing_request_id: DevicePairingRequestId,
    pub pairing_code: DevicePairingCode,
    pub gate_audience_uri: String,
    pub server_nonce: DevicePairingNonce,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingBootstrap {
    pub arkret_base_url: String,
    pub device_pairing_request_id: DevicePairingRequestId,
    pub pairing_code: DevicePairingCode,
    pub new_device_pubkey: PublicKey,
    pub client_nonce: DevicePairingNonce,
    pub gate_audience_uri: String,
    pub server_nonce: DevicePairingNonce,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_metadata: Option<DeviceMetadata>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePairingState {
    Staged,
    ReadyForClaim,
    Authorized,
    Expired,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingFinalizeRequestBody {
    pub device_pairing_request_id: DevicePairingRequestId,
    pub pairing_code: DevicePairingCode,
    pub target_proof: DevicePairingTargetProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingFinalizeOutcome {
    pub device_pairing_request_id: DevicePairingRequestId,
    pub state: DevicePairingState,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingResolveRequestBody {
    pub pairing_token: NonEmptyString,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingCodeClaimRequestBody {
    pub pairing_code: DevicePairingCode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingCodeClaimOutcome {
    pub device_pairing_request_id: DevicePairingRequestId,
    pub bootstrap: DevicePairingBootstrap,
    pub target_proof: DevicePairingTargetProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingStatusRequestBody {
    pub device_pairing_request_id: DevicePairingRequestId,
    pub pairing_code: DevicePairingCode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePairingStatusOutcome {
    pub state: DevicePairingState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_event_ref: Option<CommittedEventRef>,
}

impl DevicePairingStatusOutcome {
    pub fn validate(&self) -> Result<()> {
        let authorized = self.state == DevicePairingState::Authorized;
        if authorized != self.device_id.is_some() || authorized != self.authorized_event_ref.is_some()
        {
            return Err(WireError::Protocol(
                "authorized device pairing status requires device and committed Event refs".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDevicePairRequestBody {
    pub pairing_code: DevicePairingCode,
    pub new_device_pubkey: PublicKey,
    pub authorize_event: EventCommitSubmission,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_metadata: Option<DeviceMetadata>,
    pub device_pairing_request_id: DevicePairingRequestId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDevicePairOutcome {
    pub device_id: DeviceId,
    pub authorized_event_ref: CommittedEventRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_grant: Option<GrantSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_backup_hint: Option<serde_json::Value>,
}
