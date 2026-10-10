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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKeyAgreementEntry {
    pub key_agreement_ref: DidUrl,
    pub key_agreement_algorithm: RecoveryKeyAgreementAlgorithm,
    pub public_key_multibase: String,
    pub hpke_suites: Vec<RecoveryBackupHpkeSuite>,
    pub r#use: RecoveryKeyAgreementUse,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub revoked_at: Option<DateTime<Utc>>,
}

// Field declaration order is byte-for-byte the properties order of
// recovery-policy.schema.json#/$defs/recovery_key_entry.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKeyEntry {
    pub verification_method: DidUrl,
    pub public_key_multibase: String,
    pub signature_algorithm: RecoverySignatureAlgorithm,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub revoked_at: Option<DateTime<Utc>>,
    pub backup_hpke: RecoveryKeyAgreementEntry,
}

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
        k: u32,
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
            Self::DeviceQuorum { k, member_ids } => {
                if *k < 2 || member_ids.len() < 2 {
                    return Err(WireError::Protocol(
                        "device_quorum requires k>=2 over at least two member devices".to_owned(),
                    ));
                }
                if *k as usize > member_ids.len() {
                    return Err(WireError::Protocol(
                        "device_quorum k must not exceed its member count".to_owned(),
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
// recovery-policy.schema.json#/properties/auth_data.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyAuthData {
    pub verification_method: DidUrl,
    pub signature_algorithm: RecoverySignatureAlgorithm,
    pub signature: Base64UrlString,
}

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
    pub auth_data: RecoveryPolicyAuthData,
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
/// without the top-level auth_data member)`. Every present optional and `x_*`
/// top-level member remains covered; only `auth_data` is excluded as one whole
/// top-level member.
pub fn recovery_policy_signature_transcript_bytes(policy: &RecoveryPolicy) -> Result<Vec<u8>> {
    policy.validate_shape()?;
    let mut value = serde_json::to_value(policy)?;
    let removed = value
        .as_object_mut()
        .ok_or_else(|| WireError::Protocol("recovery policy must be an object".to_owned()))?
        .remove("auth_data");
    if removed.is_none() {
        return Err(WireError::Protocol(
            "recovery policy is missing auth_data".to_owned(),
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicySetPayload {
    pub policy_id: PolicyId,
    pub value: RecoveryPolicy,
}

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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyRef {
    pub policy_id: PolicyId,
    pub policy_version: u64,
}

// Field declaration order is byte-for-byte the properties order of
// recovery-policy.schema.json#/$defs/recovery_policy_summary.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicySummary {
    pub policy_id: PolicyId,
    pub account_id: AccountId,
    pub version: u64,
    pub acceptance_basis_ref: RealmCommitId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_policy_ref: Option<RecoveryPolicyRef>,
    pub trust_domain: TrustDomainId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_id: Option<PolicyId>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub accepted_at: Option<DateTime<Utc>>,
    /// Full accepted policy. Omitted only when the caller may learn that a
    /// policy exists but may not receive the accepted method entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<RecoveryPolicy>,
    pub methods: Vec<RecoveryMethod>,
}

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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAuthorityStreamHead {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_ids: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_commit_ref: Option<Hash>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub observed_at: Option<DateTime<Utc>>,
}

// Field declaration order is byte-for-byte the properties order of
// recovery-policy.schema.json#/$defs/recovery_policy_active_outcome.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyActiveOutcome {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<AccountId>,
    /// `None` is a successful read meaning the resolved exact account has no
    /// accepted recovery policy.
    pub active_policy: Option<RecoveryPolicySummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_policy_ref: Option<RecoveryPolicyRef>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub as_of: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_stream_head: Option<RecoveryAuthorityStreamHead>,
}

impl RecoveryPolicyActiveOutcome {
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
// recovery-policy.schema.json#/$defs/recovery_policy_publish_outcome.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicyPublishOutcome {
    pub policy_id: PolicyId,
    pub account_id: AccountId,
    pub version: u64,
    pub acceptance_basis_ref: RealmCommitId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
}

#[cfg(test)]
pub(crate) mod fixtures {
    use serde_json::json;

    pub(crate) const POLICY_ID: &str = "ak:policy:0198ff00-0000-7000-8000-000000000001";
    pub(crate) const TRUST_DOMAIN: &str = "ak:trust_domain:example.net";
    pub(crate) const RECOVERY_METHOD_URL: &str =
        "did:webvh:z6mkfixture:alice.example#recovery-key-1";

    pub(crate) fn account_id() -> serde_json::Value {
        json!({
            "principal_id": "ak:did_core:webvh:z6mkfixture:alice.example",
            "station_id": "ak:did_core:web:station.example"
        })
    }

    pub(crate) fn recovery_unlock_method() -> serde_json::Value {
        json!({
            "kind": "recovery_unlock",
            "keys": [{
                "verification_method": RECOVERY_METHOD_URL,
                "public_key_multibase": "z6MkfixtureRecoverySigningKey",
                "signature_algorithm": "Ed25519",
                "not_before": "2026-08-01T00:00:00.000Z",
                "expires_at": "2027-08-01T00:00:00.000Z",
                "backup_hpke": {
                    "key_agreement_ref": "did:webvh:z6mkfixture:alice.example#backup-hpke-1",
                    "key_agreement_algorithm": "X25519",
                    "public_key_multibase": "z6LSfixtureBackupRecipientKey",
                    "hpke_suites": ["ak.hpke_x25519_aead_chacha20poly1305.v1"],
                    "use": "backup_hpke",
                    "not_before": "2026-08-01T00:00:00.000Z",
                    "expires_at": "2027-08-01T00:00:00.000Z"
                }
            }]
        })
    }

    pub(crate) fn policy() -> serde_json::Value {
        json!({
            "schema": "ak.schema.recovery_policy.v1",
            "policy_id": POLICY_ID,
            "account_id": account_id(),
            "version": 1,
            "supersedes_id": null,
            "trust_domain": TRUST_DOMAIN,
            "issued_at": "2026-08-01T00:00:00.000Z",
            "auth_data": {
                "verification_method": "did:webvh:z6mkfixture:alice.example#founding-device",
                "signature_algorithm": "Ed25519",
                "signature": "Zml4dHVyZS1zaWduYXR1cmU"
            },
            "methods": [recovery_unlock_method()]
        })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{fixtures, *};

    #[test]
    fn recovery_policy_round_trips_and_keeps_null_supersedes() {
        let value = fixtures::policy();
        let parsed: RecoveryPolicy = serde_json::from_value(value.clone()).expect("closed policy");
        parsed.validate_shape().expect("valid policy");
        assert!(parsed.supersedes_id.is_none());
        assert!(!parsed.revokes_recovery());
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
    }

    #[test]
    fn recovery_policy_rejects_missing_required_members() {
        for member in ["schema", "policy_id", "account_id", "auth_data", "methods"] {
            let mut missing = fixtures::policy();
            missing.as_object_mut().unwrap().remove(member);
            assert!(
                serde_json::from_value::<RecoveryPolicy>(missing).is_err(),
                "{member} is a required policy member"
            );
        }
    }

    #[test]
    fn genesis_policy_serializes_its_null_predecessor() {
        let parsed: RecoveryPolicy =
            serde_json::from_value(fixtures::policy()).expect("closed policy");
        let encoded = serde_json::to_value(&parsed).unwrap();
        assert_eq!(encoded["supersedes_id"], serde_json::Value::Null);
        assert!(encoded.as_object().unwrap().contains_key("supersedes_id"));
    }

    #[test]
    fn recovery_policy_extension_members_stay_in_the_x_map() {
        let mut value = fixtures::policy();
        value
            .as_object_mut()
            .unwrap()
            .insert("x_deployment_note".to_owned(), json!("staged"));
        let parsed: RecoveryPolicy = serde_json::from_value(value.clone()).expect("x_ extension");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
    }

    #[test]
    fn recovery_policy_signature_transcript_matches_the_formal_known_answer() {
        use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};

        let mut value = fixtures::policy();
        value["methods"] = json!([]);
        value
            .as_object_mut()
            .unwrap()
            .insert("cooldown_seconds".to_owned(), json!(0));
        value
            .as_object_mut()
            .unwrap()
            .insert("x_deployment_note".to_owned(), json!("covered"));
        let policy: RecoveryPolicy = serde_json::from_value(value).unwrap();
        let transcript = recovery_policy_signature_transcript_bytes(&policy).unwrap();
        assert_eq!(
            String::from_utf8(transcript.clone()).unwrap(),
            concat!(
                "ak.identity.recovery_policy.signature.v1\n",
                "{\"account_id\":{\"principal_id\":\"ak:did_core:webvh:z6mkfixture:alice.example\",",
                "\"station_id\":\"ak:did_core:web:station.example\"},\"cooldown_seconds\":0,",
                "\"issued_at\":\"2026-08-01T00:00:00.000Z\",\"methods\":[],",
                "\"policy_id\":\"ak:policy:0198ff00-0000-7000-8000-000000000001\",",
                "\"schema\":\"ak.schema.recovery_policy.v1\",\"supersedes_id\":null,",
                "\"trust_domain\":\"ak:trust_domain:example.net\",\"version\":1,",
                "\"x_deployment_note\":\"covered\"}"
            )
        );

        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let signature = signing_key.sign(&transcript);
        assert_eq!(
            arkret_canonical::base64url_encode(signature.to_bytes()),
            "wx6-ox_ks4tQQj3sXRRMwQYZmbFIXne2C-UhfGEf3sOQW7Ex8jBfzbzNoxtwjSDgJdhsrOuY2fN1QbQDF8R_Bw"
        );
        signing_key
            .verifying_key()
            .verify(&transcript, &signature)
            .unwrap();

        let mut changed_auth = policy.clone();
        changed_auth.auth_data.verification_method =
            DidUrl::new("did:web:ignored.example#other".to_owned()).unwrap();
        changed_auth.auth_data.signature = Base64UrlString::new("aGVsbG8").unwrap();
        assert_eq!(
            recovery_policy_signature_transcript_bytes(&changed_auth).unwrap(),
            transcript,
            "the whole top-level auth_data member is excluded"
        );

        let mut tampered = policy;
        tampered
            .extra
            .insert("x_deployment_note".to_owned(), json!("tampered"))
            .unwrap();
        let tampered_transcript = recovery_policy_signature_transcript_bytes(&tampered).unwrap();
        assert!(
            signing_key
                .verifying_key()
                .verify(&tampered_transcript, &signature)
                .is_err()
        );
    }

    #[test]
    fn recovery_key_entry_is_closed() {
        let mut keys = fixtures::recovery_unlock_method();
        keys["keys"][0]
            .as_object_mut()
            .unwrap()
            .insert("or_set".to_owned(), json!(true));
        assert!(serde_json::from_value::<RecoveryMethod>(keys).is_err());

        let mut without_backup = fixtures::recovery_unlock_method();
        without_backup["keys"][0]
            .as_object_mut()
            .unwrap()
            .remove("backup_hpke");
        assert!(serde_json::from_value::<RecoveryMethod>(without_backup).is_err());
    }

    #[test]
    fn device_quorum_threshold_cannot_exceed_its_member_count() {
        let method: RecoveryMethod = serde_json::from_value(json!({
            "kind": "device_quorum",
            "k": 3,
            "member_ids": [
                "ak:device:0198ff00-0000-7000-8000-00000000000a",
                "ak:device:0198ff00-0000-7000-8000-00000000000b"
            ]
        }))
        .expect("quorum shape");
        assert!(method.validate_shape().is_err());
    }

    #[test]
    fn policy_rejects_repeated_method_kinds() {
        let mut value = fixtures::policy();
        value["methods"] = json!([
            fixtures::recovery_unlock_method(),
            fixtures::recovery_unlock_method()
        ]);
        let parsed: RecoveryPolicy = serde_json::from_value(value).expect("shape parses");
        assert!(parsed.validate_shape().is_err());
    }

    #[test]
    fn set_payload_binds_its_policy_id() {
        let value = json!({"policy_id": fixtures::POLICY_ID, "value": fixtures::policy()});
        let parsed: RecoveryPolicySetPayload =
            serde_json::from_value(value.clone()).expect("closed payload");
        parsed.validate_shape().expect("bound payload");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("state".to_owned(), json!("active"));
        assert!(serde_json::from_value::<RecoveryPolicySetPayload>(unknown).is_err());

        let mut missing = value;
        missing.as_object_mut().unwrap().remove("value");
        assert!(serde_json::from_value::<RecoveryPolicySetPayload>(missing).is_err());
    }

    fn summary_value() -> serde_json::Value {
        json!({
            "policy_id": fixtures::POLICY_ID,
            "account_id": fixtures::account_id(),
            "version": 1,
            "acceptance_basis_ref": RealmCommitId::from_digest([3; 32]),
            "trust_domain": fixtures::TRUST_DOMAIN,
            "issued_at": "2026-08-01T00:00:00.000Z",
            "methods": [fixtures::recovery_unlock_method()]
        })
    }

    #[test]
    fn policy_summary_round_trips_and_is_closed() {
        let value = summary_value();
        let parsed: RecoveryPolicySummary =
            serde_json::from_value(value.clone()).expect("closed summary");
        parsed.validate_shape().expect("valid summary");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("cas_revision".to_owned(), json!(4));
        assert!(serde_json::from_value::<RecoveryPolicySummary>(unknown).is_err());

        let mut missing = value;
        missing.as_object_mut().unwrap().remove("methods");
        assert!(serde_json::from_value::<RecoveryPolicySummary>(missing).is_err());
    }

    #[test]
    fn active_outcome_absent_policy_forbids_a_policy_ref() {
        let value = json!({"active_policy": null});
        let parsed: RecoveryPolicyActiveOutcome =
            serde_json::from_value(value.clone()).expect("closed outcome");
        parsed.validate_shape().expect("null read is a success");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let with_ref: RecoveryPolicyActiveOutcome = serde_json::from_value(json!({
            "active_policy": null,
            "recovery_policy_ref": {"policy_id": fixtures::POLICY_ID, "policy_version": 1}
        }))
        .expect("shape parses");
        assert!(with_ref.validate_shape().is_err());

        let mut unknown = json!({"active_policy": null});
        unknown
            .as_object_mut()
            .unwrap()
            .insert("observed_frontier".to_owned(), json!([]));
        assert!(serde_json::from_value::<RecoveryPolicyActiveOutcome>(unknown).is_err());
    }

    #[test]
    fn authority_stream_head_is_closed_and_fully_optional() {
        let value = json!({});
        let parsed: RecoveryAuthorityStreamHead =
            serde_json::from_value(value.clone()).expect("closed head");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        assert!(
            serde_json::from_value::<RecoveryAuthorityStreamHead>(json!({"security_frontier": []}))
                .is_err()
        );
    }

    #[test]
    fn publish_outcome_round_trips_and_is_closed() {
        let value = json!({
            "policy_id": fixtures::POLICY_ID,
            "account_id": fixtures::account_id(),
            "version": 2,
            "acceptance_basis_ref": RealmCommitId::from_digest([5; 32]),
            "accepted_at": "2026-08-02T00:00:00.000Z"
        });
        let parsed: RecoveryPolicyPublishOutcome =
            serde_json::from_value(value.clone()).expect("closed outcome");
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("accepted_frontier".to_owned(), json!([]));
        assert!(serde_json::from_value::<RecoveryPolicyPublishOutcome>(unknown).is_err());

        let mut missing = value;
        missing.as_object_mut().unwrap().remove("version");
        assert!(serde_json::from_value::<RecoveryPolicyPublishOutcome>(missing).is_err());
    }
}

/// Counterpart for
/// `recovery-policy.schema.json#/$defs/recovery_policy_publish_request`.
///
/// The schema is `EventAdmissionSubmission` narrowed to `ak.policy.set` carrying
/// a `recovery_policy_set_payload`, so publication uses the ordinary
/// first-publication Event ingress rather than a dedicated recovery endpoint.
/// The newtype keeps that narrowing on the deserialization path: a submission
/// of any other kind, or one whose payload is not a recovery policy, never
/// becomes a publish request.
// The single member is the `EventAdmissionSubmission` the schema composes with;
// `recovery-policy.schema.json#/$defs/recovery_policy_publish_request` adds no
// property of its own.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RecoveryPolicyPublishRequest {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    submission: EventAdmissionSubmission,
}

impl RecoveryPolicyPublishRequest {
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

impl<'de> Deserialize<'de> for RecoveryPolicyPublishRequest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(EventAdmissionSubmission::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod recovery_policy_publish_tests {
    use arkret_wire::{ActorId, DidCoreId, EventId, RealmId, ScopeRef, test_support};
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    const POLICY: &str = "ak:policy:0198ff00-0000-7000-8000-000000000001";
    const OTHER_POLICY: &str = "ak:policy:0198ff00-0000-7000-8000-000000000002";

    fn holder() -> AccountId {
        AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkholder").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        )
    }

    fn recovery_policy_payload_value() -> serde_json::Value {
        json!({
            "policy_id": POLICY,
            "value": {
                "schema": "ak.schema.recovery_policy.v1",
                "policy_id": POLICY,
                "account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkholder",
                    "station_id": "ak:did_core:web:station.example"
                },
                "version": 1,
                "supersedes_id": null,
                "trust_domain": "ak:trust_domain:station.example",
                "issued_at": "2026-09-16T00:00:00.000Z",
                "auth_data": {
                    "verification_method": "did:web:station.example#key-1",
                    "signature_algorithm": "Ed25519",
                    "signature": "c2lnbmF0dXJl"
                },
                "methods": []
            }
        })
    }

    fn submission_value(kind: &str, payload: serde_json::Value) -> serde_json::Value {
        let realm_id = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x31; 32],
        ));
        let event = test_support::raw_event_for_actor_at(
            kind,
            ScopeRef::Realm { realm_id },
            ActorId::account(holder()),
            payload,
            Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
        )
        .unwrap();
        json!({ "event": serde_json::to_value(&event).unwrap() })
    }

    #[test]
    fn a_recovery_policy_set_submission_round_trips() {
        let value = submission_value("ak.policy.set", recovery_policy_payload_value());
        let request: RecoveryPolicyPublishRequest = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(request.event().kind, EventKind::PolicySet);
        assert_eq!(request.account_id().unwrap(), holder());
        assert_eq!(request.payload().unwrap().value.policy_id.as_str(), POLICY);
        assert_eq!(serde_json::to_value(&request).unwrap(), value);
    }

    #[test]
    fn only_ak_policy_set_may_publish_a_recovery_policy() {
        let value = submission_value("ak.realm.policy_bundle", recovery_policy_payload_value());
        assert!(serde_json::from_value::<RecoveryPolicyPublishRequest>(value).is_err());
    }

    #[test]
    fn a_governance_policy_document_is_not_a_recovery_publication() {
        let governance = json!({
            "policy_id": POLICY,
            "value": {
                "schema": "ak.schema.policy.v1",
                "id": POLICY,
                "policy_kind": "access",
                "rules": [],
                "default_effect": "deny",
                "created_by": { "kind": "account", "account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkholder",
                    "station_id": "ak:did_core:web:station.example"
                }},
                "created_at": "2026-09-16T00:00:00.000Z"
            }
        });
        let value = submission_value("ak.policy.set", governance);
        assert!(serde_json::from_value::<RecoveryPolicyPublishRequest>(value).is_err());
    }

    #[test]
    fn the_payload_subject_must_equal_the_document_policy_id() {
        let mut mismatched = recovery_policy_payload_value();
        mismatched
            .as_object_mut()
            .unwrap()
            .insert("policy_id".to_owned(), json!(OTHER_POLICY));
        let value = submission_value("ak.policy.set", mismatched);
        assert!(serde_json::from_value::<RecoveryPolicyPublishRequest>(value).is_err());
    }

    #[test]
    fn a_publication_carries_exactly_one_event_and_no_sidecar() {
        let mut value = submission_value("ak.policy.set", recovery_policy_payload_value());
        value
            .as_object_mut()
            .unwrap()
            .insert("commit".to_owned(), json!({}));
        assert!(serde_json::from_value::<RecoveryPolicyPublishRequest>(value).is_err());
    }

    #[test]
    fn an_empty_method_set_publishes_an_explicit_revocation() {
        let value = submission_value("ak.policy.set", recovery_policy_payload_value());
        let request: RecoveryPolicyPublishRequest = serde_json::from_value(value).unwrap();
        assert!(request.payload().unwrap().value.revokes_recovery());
    }
}
