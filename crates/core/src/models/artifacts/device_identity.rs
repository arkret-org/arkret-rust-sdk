//! Device identity schema artifact counterparts.

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-publish.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CrossSigningPublish {
    pub principal_id: Did,
    pub trust_domain: String,
    pub principal_signing_key: PublishedKey,
    pub self_signing_key: SubordinateSignedKey,
    pub user_signing_key: SubordinateSignedKey,
    pub generation: u64,
    pub expected_previous_generation: u64,
    pub issued_at: DateTime<Utc>,
}

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-publish.schema.json#/$defs/alg`.
pub type Alg = String;

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-publish.schema.json#/$defs/key_format`.
pub type KeyFormat = String;

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-publish.schema.json#/$defs/kid`.
pub type Kid = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/cross-signing-publish.schema.json#/$defs/published_key`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PublishedKey {
    pub kid: Kid,
    pub alg: Alg,
    pub public_key: String,
    pub key_format: KeyFormat,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/cross-signing-publish.schema.json#/$defs/subordinate_signed_key`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SubordinateSignedKeyBinding {
    pub verification_method: String,
    pub alg: Alg,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SubordinateSignedKey {
    pub kid: Kid,
    pub alg: Alg,
    pub public_key: String,
    pub key_format: KeyFormat,
    pub binding: SubordinateSignedKeyBinding,
}

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-reset.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossSigningReset {
    pub trust_domain: String,
    pub reset_event_id: EventId,
    pub principal_id: Did,
    pub previous_generation: u64,
    pub new_generation: u64,
    pub reset_reason_code: String,
    pub proof: Value,
    pub issued_at: DateTime<Utc>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/cross-signing-reset.schema.json#/$defs/device_quorum_proof`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceQuorumSignature {
    pub device_id: String,
    pub verification_method: Did,
    pub alg: String,
    pub signature: SignatureB64u,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceQuorumProof {
    pub kind: String,
    pub threshold: u64,
    pub signatures: Vec<DeviceQuorumSignature>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/cross-signing-reset.schema.json#/$defs/principal_signing_proof`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalSigningProof {
    pub kind: String,
    pub verification_method: Value,
    pub alg: String,
    pub signature: SignatureB64u,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/cross-signing-reset.schema.json#/$defs/recovery_unlock_proof`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryUnlockProof {
    pub kind: String,
    pub recovery_session_id: RecoverySessionId,
    pub recovery_secret_ref: String,
    pub unlock_commitment: Value,
    pub alg: String,
    pub signature: SignatureB64u,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/cross-signing-reset.schema.json#/$defs/signature_b64u`.
pub type SignatureB64u = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/cross-signing-reset.schema.json#/$defs/
/// trusted_recovery_service_proof`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRecoveryServiceProof {
    pub kind: String,
    pub recovery_session_id: RecoverySessionId,
    pub service_id: Did,
    pub verification_method: Did,
    pub alg: String,
    pub signature: SignatureB64u,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_ref: Option<String>,
}

/// Counterpart for `spec/v1/artifacts/schemas/delivery-binding-stale.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryBindingStaleHandoverProof {
    pub frontier: Value,
    pub recipient_service_id: Value,
    pub actor_id: Value,
    pub witness: BTreeMap<String, Value>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryBindingStale {
    pub new_recipient_service_id: Value,
    pub handover_frontier: Value,
    pub handover_proof: DeliveryBindingStaleHandoverProof,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/delivery-binding-stale.schema.json#/$defs/event_id_list`.
pub type EventIdList = Vec<EventId>;

/// Counterpart for
/// `spec/v1/artifacts/schemas/device-message.schema.json#/$defs/key_verification_content`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyVerificationContentNewDevicePubkey {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyVerificationContent {
    pub transaction_id: String,
    pub from_device: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_device_pubkey: Option<KeyVerificationContentNewDevicePubkey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_audience: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_canonical_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_metadata: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_agreement_protocols: Option<StringList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hashes: Option<StringList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message_authentication_codes: Option<StringList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_authentication_string: Option<StringList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_keys: Option<StringList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `spec/v1/artifacts/schemas/device-message.schema.json#/$defs/string_list`.
pub type StringList = Vec<String>;

/// Counterpart for `spec/v1/artifacts/schemas/identity-receipt.schema.json`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityReceipt {
    pub schema: String,
    pub receipt_id: String,
    pub did: Did,
    pub seq: u64,
    pub head_event_digest: Hash,
    pub registry_service_id: Did,
    pub witness_role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    pub created_at: DateTime<Utc>,
    pub signature: Proof,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/key-backup-active-series.schema.json#/$defs/frontier_ref`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontierRef {
    pub frontier_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_ref: Option<Hash>,
    pub ssk_generation: u64,
}
