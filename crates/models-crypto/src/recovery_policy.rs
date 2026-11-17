//! PCR recovery policy: the single signed source of recovery acceptance.
//!
//! An accepted policy is bound through signed control Events to one exact
//! [`AccountId`] and its local PCR lineage. Receivers reject `ak.device.reanchor`
//! and `pcr_recovery` device authorization whose proof family or optional
//! DID-root factor the currently accepted policy does not allow.

use arkret_wire::{
    AccountId, Base64UrlString, DeviceId, DidCoreId, DidUrl, Event, EventAdmissionSubmission,
    EventId, EventKind, Hash, PolicyId, RealmCommitId, Result, SchemaId, TrustDomainId, WireError,
    XExtensionMap,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A policy carries at most one entry per recovery method kind.
pub const RECOVERY_POLICY_MAX_METHODS: usize = 4;
/// Maximum recovery signing keys inside one `recovery_unlock` entry.
pub const RECOVERY_UNLOCK_MAX_KEYS: usize = 32;
/// Maximum trusted recovery services inside one `trusted_recovery_service` entry.
pub const TRUSTED_RECOVERY_SERVICE_MAX_ENTRIES: usize = 32;

/// Signature algorithms a recovery policy or recovery proof may name.
/// `MlDsa65` additionally requires the PQ-capable implementation profile.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecoverySignatureAlgorithm {
    #[serde(rename = "Ed25519")]
    Ed25519,
    #[serde(rename = "ML-DSA-65")]
    MlDsa65,
}

/// The only key-agreement algorithm a backup-only HPKE recipient may name.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecoveryKeyAgreementAlgorithm {
    #[serde(rename = "X25519")]
    X25519,
}

/// The only `use` value a recovery key-agreement entry may carry.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryKeyAgreementUse {
    BackupHpke,
}

/// HPKE suites a backup-only recovery recipient may accept.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecoveryBackupHpkeSuite {
    #[serde(rename = "ak.hpke_x25519_aead_chacha20poly1305.v1")]
    X25519AeadChacha20Poly1305V1,
    #[serde(rename = "ak.hpke_x25519_aead_aes256gcm.v1")]
    X25519AeadAes256GcmV1,
}

// Field declaration order is byte-for-byte the properties order of
// recovery-policy.schema.json#/$defs/recovery_key_agreement_entry.

// Field declaration order is byte-for-byte the properties order of
// recovery-policy.schema.json#/$defs/recovery_key_entry.

// Field declaration order is byte-for-byte the properties order of
// recovery-policy.schema.json#/$defs/recovery_method (fourth branch) items.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRecoveryServiceEntry {
    pub service_id: DidCoreId,
    pub audience: String,
    pub authorization_verification_method: DidUrl,
}

/// The accepted recovery factors. Entries are independent OR alternatives and
/// each kind occurs at most once. An empty `methods` array is explicit policy
/// revocation; `DidRoot` is an opt-in to validated DID history authority and is
/// never an accepted device key.
// Field declaration order is byte-for-byte the properties order of
// recovery-policy.schema.json#/$defs/recovery_method.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryMethod {
    DidRoot,
    RecoveryUnlock {
        keys: Vec<RecoveryKeyEntry>,
    },
    DeviceQuorum {
        min_device_count: u32,
        member_ids: Vec<DeviceId>,
    },
    TrustedRecoveryService {
        services: Vec<TrustedRecoveryServiceEntry>,
    },
}

impl RecoveryMethod {
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::DidRoot => "did_root",
            Self::RecoveryUnlock { .. } => "recovery_unlock",
            Self::DeviceQuorum { .. } => "device_quorum",
            Self::TrustedRecoveryService { .. } => "trusted_recovery_service",
        }
    }

    pub fn validate_shape(&self) -> Result<()> {
        match self {
            Self::DidRoot => Ok(()),
            Self::RecoveryUnlock { keys } => {
                if keys.is_empty() || keys.len() > RECOVERY_UNLOCK_MAX_KEYS {
                    return Err(WireError::Protocol(
                        "recovery_unlock carries 1..=32 recovery keys".to_owned(),
                    ));
                }
                Ok(())
            }
            Self::DeviceQuorum {
                min_device_count,
                member_ids,
            } => {
                if *min_device_count < 2 || member_ids.len() < 2 {
                    return Err(WireError::Protocol(
                        "device_quorum requires min_device_count>=2 over at least two member devices".to_owned(),
                    ));
                }
                if *min_device_count as usize > member_ids.len() {
                    return Err(WireError::Protocol(
                        "device_quorum min_device_count must not exceed its member count"
                            .to_owned(),
                    ));
                }
                Ok(())
            }
            Self::TrustedRecoveryService { services } => {
                if services.is_empty() || services.len() > TRUSTED_RECOVERY_SERVICE_MAX_ENTRIES {
                    return Err(WireError::Protocol(
                        "trusted_recovery_service carries 1..=32 services".to_owned(),
                    ));
                }
                Ok(())
            }
        }
    }
}

// Field declaration order is byte-for-byte the properties order of
// recovery-policy.schema.json#/properties/signature_proof.

// Field declaration order is byte-for-byte the properties order of
// recovery-policy.schema.json#/properties.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPolicy {
    pub schema: String,
    pub policy_id: PolicyId,
    pub account_id: AccountId,
    pub version: u64,
    /// Predecessor policy. Null only for the genesis policy of an exact
    /// account, so the member is always serialized.
    pub supersedes_id: Option<PolicyId>,
    pub trust_domain: TrustDomainId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_seconds: Option<u64>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    pub signature_proof: RecoveryPolicySignatureProof,
    pub methods: Vec<RecoveryMethod>,
    #[serde(default, flatten)]
    pub extra: XExtensionMap,
}

impl RecoveryPolicy {
    pub fn validate_shape(&self) -> Result<()> {
        if self.schema != SchemaId::RECOVERY_POLICY_V1 {
            return Err(WireError::Protocol(
                "recovery policy schema is invalid".to_owned(),
            ));
        }
        if self.version == 0 {
            return Err(WireError::Protocol(
                "recovery policy version starts at 1".to_owned(),
            ));
        }
        if self.methods.len() > RECOVERY_POLICY_MAX_METHODS {
            return Err(WireError::Protocol(
                "recovery policy carries at most four method entries".to_owned(),
            ));
        }
        let mut seen: Vec<&'static str> = Vec::with_capacity(self.methods.len());
        for method in &self.methods {
            method.validate_shape()?;
            if seen.contains(&method.kind_str()) {
                return Err(WireError::Protocol(
                    "recovery policy carries each method kind at most once".to_owned(),
                ));
            }
            seen.push(method.kind_str());
        }
        Ok(())
    }

    /// An accepted policy whose `methods` is empty is explicit revocation of
    /// every recovery factor for this account.
    pub fn revokes_recovery(&self) -> bool {
        self.methods.is_empty()
    }
}

/// Build the formal RecoveryPolicy signature transcript.
///
/// The v1 transcript is
/// `UTF8("ak.identity.recovery_policy.signature.v1\n") || RFC8785_JCS(policy
/// without the top-level signature_proof member)`. Every present optional and `x_*`
/// top-level member remains covered; only `signature_proof` is excluded as one whole
/// top-level member.
pub fn recovery_policy_signature_transcript_bytes(policy: &RecoveryPolicy) -> Result<Vec<u8>> {
    policy.validate_shape()?;
    let mut value = serde_json::to_value(policy)?;
    let removed = value
        .as_object_mut()
        .ok_or_else(|| WireError::Protocol("recovery policy must be an object".to_owned()))?
        .remove("signature_proof");
    if removed.is_none() {
        return Err(WireError::Protocol(
            "recovery policy is missing signature_proof".to_owned(),
        ));
    }
    let canonical = arkret_canonical::canonical_json_bytes(&value)?;
    let domain = arkret_wire::RECOVERY_POLICY_SIGNATURE_TYPE.as_bytes();
    let mut transcript = Vec::with_capacity(domain.len() + 1 + canonical.len());
    transcript.extend_from_slice(domain);
    transcript.push(b'\n');
    transcript.extend(canonical);
    Ok(transcript)
}

// Field declaration order is byte-for-byte the properties order of
// recovery-policy.schema.json#/$defs/recovery_policy_set_payload.

impl RecoveryPolicySetPayload {
    pub fn validate_shape(&self) -> Result<()> {
        self.value.validate_shape()?;
        if self.policy_id != self.value.policy_id {
            return Err(WireError::Protocol(
                "recovery policy set payload policy_id must equal value.policy_id".to_owned(),
            ));
        }
        Ok(())
    }
}

// Field declaration order is byte-for-byte the properties order of
// recovery-policy.schema.json#/$defs/recovery_policy_ref.

// Field declaration order is byte-for-byte the properties order of
// recovery-policy.schema.json#/$defs/recovery_policy_summary.

impl RecoveryPolicySummary {
    pub fn validate_shape(&self) -> Result<()> {
        if let Some(reference) = &self.recovery_policy_ref
            && (reference.policy_id != self.policy_id || reference.policy_version != self.version)
        {
            return Err(WireError::Protocol(
                "recovery policy summary ref must match policy_id and version".to_owned(),
            ));
        }
        if let Some(policy) = &self.policy {
            policy.validate_shape()?;
            if policy.policy_id != self.policy_id || policy.version != self.version {
                return Err(WireError::Protocol(
                    "disclosed recovery policy must match the summary identity".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

// Field declaration order is byte-for-byte the properties order of
// recovery-policy.schema.json#/$defs/authority_stream_head.

// Field declaration order is byte-for-byte the properties order of
// recovery-policy.schema.json#/$defs/recovery_policy_status_view.

impl RecoveryPolicyStatusView {
    pub fn validate_shape(&self) -> Result<()> {
        match (&self.active_policy, &self.recovery_policy_ref) {
            (None, Some(_)) => Err(WireError::Protocol(
                "recovery policy ref must be absent when no policy is active".to_owned(),
            )),
            (Some(summary), reference) => {
                summary.validate_shape()?;
                if let Some(reference) = reference
                    && (reference.policy_id != summary.policy_id
                        || reference.policy_version != summary.version)
                {
                    return Err(WireError::Protocol(
                        "recovery policy ref must match the active policy".to_owned(),
                    ));
                }
                Ok(())
            }
            (None, None) => Ok(()),
        }
    }
}

// Field declaration order is byte-for-byte the properties order of
// recovery-policy.schema.json#/$defs/recovery_policy_publish_response_body.

#[cfg(test)]
pub(crate) mod fixtures;

#[cfg(test)]
mod tests;

/// Counterpart for
/// `recovery-policy.schema.json#/$defs/recovery_policy_publish_request_body`.
///
/// The schema is `EventAdmissionSubmission` narrowed to `ak.policy.set` carrying
/// a `recovery_policy_set_payload`, so publication uses the ordinary
/// first-publication Event ingress rather than a dedicated recovery endpoint.
/// The newtype keeps that narrowing on the deserialization path: a submission
/// of any other kind, or one whose payload is not a recovery policy, never
/// becomes a publish request.
// The single member is the `EventAdmissionSubmission` the schema composes with;
// `recovery-policy.schema.json#/$defs/recovery_policy_publish_request_body` adds no
// property of its own.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RecoveryPolicyPublishRequestBody {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    submission: EventAdmissionSubmission,
}

impl RecoveryPolicyPublishRequestBody {
    pub fn new(submission: EventAdmissionSubmission) -> Result<Self> {
        let request = Self { submission };
        request.validate()?;
        Ok(request)
    }

    #[must_use]
    pub fn submission(&self) -> &EventAdmissionSubmission {
        &self.submission
    }

    #[must_use]
    pub fn event(&self) -> &Event {
        &self.submission.event
    }

    pub fn into_submission(self) -> EventAdmissionSubmission {
        self.submission
    }

    /// Decode the carried recovery policy payload. The payload is re-read from
    /// the Event rather than mirrored beside it, so the signed Event bytes stay
    /// the only source of the published document.
    pub fn payload(&self) -> Result<RecoveryPolicySetPayload> {
        let value =
            serde_json::Value::Object(self.submission.event.payload.clone().into_iter().collect());
        serde_json::from_value(value).map_err(|source| {
            WireError::Protocol(format!(
                "recovery policy publish payload is not a recovery_policy_set_payload: {source}"
            ))
        })
    }

    /// The published document's account, which authorization must bind to the
    /// exact Principal Control Realm of that account.
    pub fn account_id(&self) -> Result<AccountId> {
        Ok(self.payload()?.value.account_id)
    }

    pub fn validate(&self) -> Result<()> {
        if self.submission.event.kind != EventKind::PolicySet {
            return Err(WireError::Protocol(
                "recovery policy publication requires an ak.policy.set Event".to_owned(),
            ));
        }
        self.payload()?.validate_shape()
    }
}

impl<'de> Deserialize<'de> for RecoveryPolicyPublishRequestBody {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(EventAdmissionSubmission::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod recovery_policy_publish_tests;

include!("generated/recovery_policy_contracts.rs");
