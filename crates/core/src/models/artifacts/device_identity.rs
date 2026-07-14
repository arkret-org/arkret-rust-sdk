//! Device identity schema artifact counterparts.

use std::num::NonZeroU64;

use arkret_canonical::binding_contexts;

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-publish.schema.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CrossSigningPublish {
    pub principal_id: Did,
    pub trust_domain: TypedTrustDomainId,
    pub principal_signing_key: PublishedKey,
    pub self_signing_key: SubordinateSignedKey,
    pub user_signing_key: SubordinateSignedKey,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = u64)))]
    pub generation: NonZeroU64,
    pub expected_previous_generation: u64,
    pub issued_at: DateTime<Utc>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CrossSigningPublishWire {
    principal_id: Did,
    trust_domain: TypedTrustDomainId,
    principal_signing_key: PublishedKey,
    self_signing_key: SubordinateSignedKey,
    user_signing_key: SubordinateSignedKey,
    generation: NonZeroU64,
    expected_previous_generation: u64,
    issued_at: DateTime<Utc>,
}

impl<'de> Deserialize<'de> for CrossSigningPublish {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = CrossSigningPublishWire::deserialize(deserializer)?;
        let publish = Self {
            principal_id: wire.principal_id,
            trust_domain: wire.trust_domain,
            principal_signing_key: wire.principal_signing_key,
            self_signing_key: wire.self_signing_key,
            user_signing_key: wire.user_signing_key,
            generation: wire.generation,
            expected_previous_generation: wire.expected_previous_generation,
            issued_at: wire.issued_at,
        };
        publish
            .validate_structure()
            .map_err(serde::de::Error::custom)?;
        Ok(publish)
    }
}

impl CrossSigningPublish {
    pub fn validate_structure(&self) -> Result<()> {
        if self.self_signing_key.public_key == self.user_signing_key.public_key {
            return Err(Error::Protocol(
                "cross-signing publish requires distinct SSK and USK public keys".to_owned(),
            ));
        }
        if self
            .expected_previous_generation
            .checked_add(1)
            .is_none_or(|expected| expected != self.generation.get())
        {
            return Err(Error::Protocol(
                "cross-signing publish generation must equal expected_previous_generation + 1"
                    .to_owned(),
            ));
        }
        if self.self_signing_key.binding.verification_method != self.principal_signing_key.kid {
            return Err(Error::Protocol(
                "self_signing_key binding must reference the published PSK kid".to_owned(),
            ));
        }
        if self.user_signing_key.binding.verification_method != self.principal_signing_key.kid {
            return Err(Error::Protocol(
                "user_signing_key binding must reference the published PSK kid".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn self_signing_binding_input(&self) -> Result<Vec<u8>> {
        self.subordinate_binding_input("self_signing", &self.self_signing_key)
    }

    pub fn user_signing_binding_input(&self) -> Result<Vec<u8>> {
        self.subordinate_binding_input("user_signing", &self.user_signing_key)
    }

    fn subordinate_binding_input(
        &self,
        subordinate_kind: &'static str,
        subordinate: &SubordinateSignedKey,
    ) -> Result<Vec<u8>> {
        let body = serde_json::json!({
            "principal_id": self.principal_id.as_str(),
            "trust_domain": self.trust_domain.as_str(),
            "subordinate_key_kind": subordinate_kind,
            "subordinate_kid": subordinate.kid.as_str(),
            "subordinate_alg": subordinate.alg.as_str(),
            "subordinate_public_key": subordinate.public_key.as_str(),
            "generation": self.generation.get(),
        });
        let mut output = binding_contexts::CROSS_SIGNING_BIND_PREFIX.to_vec();
        output.extend_from_slice(&canonical::canonical_json_bytes(&body)?);
        Ok(output)
    }
}

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-publish.schema.json#/$defs/key_format`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum KeyFormat {
    Multibase,
    Jwk,
    RawBase64url,
}

impl KeyFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Multibase => "multibase",
            Self::Jwk => "jwk",
            Self::RawBase64url => "raw_base64url",
        }
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/cross-signing-publish.schema.json#/$defs/published_key`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PublishedKey {
    pub kid: NonEmptyString,
    pub alg: NonEmptyString,
    pub public_key: NonEmptyString,
    pub key_format: KeyFormat,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/cross-signing-publish.schema.json#/$defs/subordinate_signed_key`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SubordinateSignedKeyBinding {
    pub verification_method: NonEmptyString,
    pub alg: NonEmptyString,
    pub signature: NonEmptyString,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SubordinateSignedKey {
    pub kid: NonEmptyString,
    pub alg: NonEmptyString,
    pub public_key: NonEmptyString,
    pub key_format: KeyFormat,
    pub binding: SubordinateSignedKeyBinding,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/cross-signing-reset.schema.json#/$defs/device_quorum_proof`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceQuorumSignature {
    pub device_id: DeviceId,
    pub verification_method: DidUrl,
    pub alg: NonEmptyString,
    pub signature: Base64UrlString,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceQuorumProof {
    pub kind: DeviceQuorumProofKind,
    pub threshold: NonZeroU64,
    pub signatures: Vec<DeviceQuorumSignature>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/cross-signing-reset.schema.json#/$defs/principal_signing_proof`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalSigningProof {
    pub kind: PrincipalSigningProofKind,
    pub verification_method: DidUrl,
    pub alg: NonEmptyString,
    pub signature: Base64UrlString,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/cross-signing-reset.schema.json#/$defs/recovery_unlock_proof`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryUnlockProof {
    pub kind: RecoveryUnlockProofKind,
    pub recovery_session_id: RecoverySessionId,
    pub recovery_secret_ref: NonEmptyString,
    pub unlock_commitment: Hash,
    pub alg: NonEmptyString,
    pub signature: Base64UrlString,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/cross-signing-reset.schema.json#/$defs/
/// trusted_recovery_service_proof`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRecoveryServiceProof {
    pub kind: TrustedRecoveryServiceProofKind,
    pub recovery_session_id: RecoverySessionId,
    pub service_id: Did,
    pub verification_method: DidUrl,
    pub alg: NonEmptyString,
    pub signature: Base64UrlString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_ref: Option<NonEmptyString>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceQuorumProofKind {
    DeviceQuorum,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalSigningProofKind {
    PrincipalSigning,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryUnlockProofKind {
    RecoveryUnlock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedRecoveryServiceProofKind {
    TrustedRecoveryService,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CrossSigningResetProof {
    PrincipalSigning(PrincipalSigningProof),
    RecoveryUnlock(RecoveryUnlockProof),
    DeviceQuorum(DeviceQuorumProof),
    TrustedRecoveryService(TrustedRecoveryServiceProof),
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/delivery-binding-stale.schema.json#/properties/handover_proof`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryBindingStaleHandoverProof {
    pub frontier: Vec<EventId>,
    pub recipient_service_id: Did,
    pub actor_id: Did,
    pub witness: NonEmptyJsonObject,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeliveryBindingStale {
    pub new_recipient_service_id: Did,
    pub handover_frontier: Vec<EventId>,
    pub handover_proof: DeliveryBindingStaleHandoverProof,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: XExtensionMap,
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
    pub transaction_id: TransactionId,
    pub from_device: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<KeyVerificationPurpose>,
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
    pub code: Option<KeyVerificationCancellationCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyVerificationPurpose {
    DeviceKeyVerification,
    SamePrincipalDeviceAuthorization,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyVerificationCancellationCode {
    UserCancelled,
    Timeout,
    UnknownTransaction,
    UnexpectedMessage,
    UnsupportedMethod,
    UnsupportedAlgorithm,
    MismatchedCommitment,
    MismatchedMac,
    DeviceRevoked,
    UntrustedDevice,
    PolicyDenied,
    AcceptedByOtherDevice,
    CrossSigningReset,
}

/// Counterpart for `spec/v1/artifacts/schemas/device-message.schema.json#/$defs/string_list`.
pub type StringList = Vec<String>;

/// Counterpart for `spec/v1/artifacts/schemas/identity-receipt.schema.json`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn publish_value() -> Value {
        json!({
            "principal_id": "did:webvh:z6mkfixture:alice.example",
            "trust_domain": "ak:trust_domain:example.net",
            "principal_signing_key": {
                "kid": "did:webvh:z6mkfixture:alice.example#psk",
                "alg": "EdDSA",
                "public_key": "z6MkPrincipal",
                "key_format": "multibase"
            },
            "self_signing_key": {
                "kid": "did:webvh:z6mkfixture:alice.example#ssk",
                "alg": "EdDSA",
                "public_key": "z6MkSelf",
                "key_format": "multibase",
                "binding": {
                    "verification_method": "did:webvh:z6mkfixture:alice.example#psk",
                    "alg": "EdDSA",
                    "signature": "c2ln"
                }
            },
            "user_signing_key": {
                "kid": "did:webvh:z6mkfixture:alice.example#usk",
                "alg": "EdDSA",
                "public_key": "z6MkUser",
                "key_format": "multibase",
                "binding": {
                    "verification_method": "did:webvh:z6mkfixture:alice.example#psk",
                    "alg": "EdDSA",
                    "signature": "c2ln"
                }
            },
            "generation": 1,
            "expected_previous_generation": 0,
            "issued_at": "2026-07-14T00:00:00Z"
        })
    }

    #[test]
    fn cross_signing_publish_rejects_closed_shape_and_relational_drift() {
        assert!(serde_json::from_value::<CrossSigningPublish>(publish_value()).is_ok());

        let mut zero_generation = publish_value();
        zero_generation["generation"] = json!(0);
        assert!(serde_json::from_value::<CrossSigningPublish>(zero_generation).is_err());

        let mut skipped_generation = publish_value();
        skipped_generation["generation"] = json!(3);
        assert!(serde_json::from_value::<CrossSigningPublish>(skipped_generation).is_err());

        let mut wrong_key_format = publish_value();
        wrong_key_format["principal_signing_key"]["key_format"] = json!("pem");
        assert!(serde_json::from_value::<CrossSigningPublish>(wrong_key_format).is_err());

        let mut empty_kid = publish_value();
        empty_kid["principal_signing_key"]["kid"] = json!("");
        assert!(serde_json::from_value::<CrossSigningPublish>(empty_kid).is_err());

        let mut wrong_binding = publish_value();
        wrong_binding["self_signing_key"]["binding"]["verification_method"] =
            json!("did:webvh:z6mkfixture:alice.example#other");
        assert!(serde_json::from_value::<CrossSigningPublish>(wrong_binding).is_err());

        let mut unknown = publish_value();
        unknown["legacy"] = json!(true);
        assert!(serde_json::from_value::<CrossSigningPublish>(unknown).is_err());
    }
}
