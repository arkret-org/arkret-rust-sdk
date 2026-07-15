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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceQuorumSignature {
    pub device_id: DeviceId,
    pub verification_method: DidUrl,
    pub alg: NonEmptyString,
    pub signature: Base64UrlString,
}

/// Device quorum threshold constrained by the reset schema minimum of two.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct DeviceQuorumThreshold(NonZeroU64);

impl DeviceQuorumThreshold {
    pub fn new(value: u64) -> std::result::Result<Self, &'static str> {
        if value < 2 {
            return Err("device quorum threshold must be at least 2");
        }
        Ok(Self(
            NonZeroU64::new(value).expect("value was checked as non-zero"),
        ))
    }

    pub fn get(self) -> u64 {
        self.0.get()
    }
}

impl<'de> Deserialize<'de> for DeviceQuorumThreshold {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// High-risk proof for `ak.cross_signing.reset`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CrossSigningResetProof {
    PrincipalSigning {
        verification_method: DidUrl,
        alg: NonEmptyString,
        signature: Base64UrlString,
    },
    RecoveryUnlock {
        recovery_session_id: RecoverySessionId,
        recovery_secret_ref: NonEmptyString,
        unlock_commitment: Hash,
        alg: NonEmptyString,
        signature: Base64UrlString,
    },
    DeviceQuorum {
        threshold: DeviceQuorumThreshold,
        signatures: Vec<DeviceQuorumSignature>,
    },
    TrustedRecoveryService {
        recovery_session_id: RecoverySessionId,
        service_id: Did,
        verification_method: DidUrl,
        alg: NonEmptyString,
        signature: Base64UrlString,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attestation_ref: Option<AttestationId>,
    },
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
    pub kid: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<NonEmptyString>,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyVerificationContent {
    pub transaction_id: TransactionId,
    pub from_device: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<ProtocolKindList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<ProtocolKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<KeyVerificationPurpose>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<KeyVerificationPairingCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_device_pubkey: Option<KeyVerificationContentNewDevicePubkey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_signature: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate_audience: Option<NonEmptyString>,
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
    pub commitment: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<BTreeMap<String, NonEmptyString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<BTreeMap<String, NonEmptyString>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_keys: Option<StringList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<KeyVerificationCancellationCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<KeyVerificationCancellationReason>,
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct StringList(Vec<NonEmptyString>);

impl StringList {
    pub fn new(values: Vec<NonEmptyString>) -> Result<Self> {
        if values.is_empty() {
            return Err(Error::Protocol("string list must not be empty".to_owned()));
        }
        let mut unique = BTreeSet::new();
        if values.iter().any(|value| !unique.insert(value.as_str())) {
            return Err(Error::Protocol(
                "string list values must be unique".to_owned(),
            ));
        }
        Ok(Self(values))
    }

    pub fn as_slice(&self) -> &[NonEmptyString] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<NonEmptyString> {
        self.0
    }
}

impl<'de> Deserialize<'de> for StringList {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let values = Vec::<NonEmptyString>::deserialize(deserializer)?;
        Self::new(values).map_err(serde::de::Error::custom)
    }
}

/// Non-empty unique list of Arkret protocol kinds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ProtocolKindList(Vec<ProtocolKind>);

impl ProtocolKindList {
    pub fn new(values: Vec<ProtocolKind>) -> Result<Self> {
        if values.is_empty() {
            return Err(Error::Protocol(
                "protocol kind list must not be empty".to_owned(),
            ));
        }
        let mut unique = BTreeSet::new();
        if values.iter().any(|value| !unique.insert(value.as_str())) {
            return Err(Error::Protocol(
                "protocol kind list values must be unique".to_owned(),
            ));
        }
        Ok(Self(values))
    }

    pub fn as_slice(&self) -> &[ProtocolKind] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<ProtocolKind> {
        self.0
    }
}

impl<'de> Deserialize<'de> for ProtocolKindList {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let values = Vec::<ProtocolKind>::deserialize(deserializer)?;
        Self::new(values).map_err(serde::de::Error::custom)
    }
}

macro_rules! bounded_key_verification_string {
    ($name:ident, $maximum:expr, $error:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
        #[serde(transparent)]
        pub struct $name(NonEmptyString);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = NonEmptyString::new(value)
                    .map_err(|reason| Error::Protocol(reason.to_owned()))?;
                if value.chars().count() > $maximum {
                    return Err(Error::Protocol($error.to_owned()));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(serde::de::Error::custom)
            }
        }
    };
}

bounded_key_verification_string!(
    KeyVerificationPairingCode,
    128,
    "key verification pairing code exceeds 128 characters"
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct KeyVerificationCancellationReason(String);

impl KeyVerificationCancellationReason {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.chars().count() > 256 {
            return Err(Error::Protocol(
                "key verification cancellation reason exceeds 256 characters".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for KeyVerificationCancellationReason {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Counterpart for `spec/v1/artifacts/schemas/identity-receipt.schema.json`.
pub const IDENTITY_RECEIPT_PROOF_BINDING_CONTEXT: &str = "ak.identity-receipt-proof-v1";

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
    #[serde(
        serialize_with = "crate::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "crate::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    pub signature: PayloadProof,
}

impl IdentityReceipt {
    pub const SCHEMA: &'static str = "ak.schema.identity_receipt.v1";

    /// `sha256(canonical_json(receipt with signature omitted))`.
    pub fn payload_digest(&self) -> Result<Hash> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("IdentityReceipt serializes to an object")
            .remove("signature");
        let bytes = canonical::canonical_json_bytes(&value)?;
        Ok(Hash::new(canonical::sha256_digest(&bytes))?)
    }

    /// Canonical detached-JWS binding bytes defined by `identity-did.md`
    /// section 4.3.
    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        let mut object = serde_json::Map::new();
        object.insert(
            "context".to_owned(),
            Value::String(IDENTITY_RECEIPT_PROOF_BINDING_CONTEXT.to_owned()),
        );
        object.insert(
            "payload_digest".to_owned(),
            Value::String(self.signature.payload_digest.as_str().to_owned()),
        );
        object.insert(
            "registry_service_id".to_owned(),
            Value::String(self.registry_service_id.as_str().to_owned()),
        );
        object.insert(
            "did".to_owned(),
            Value::String(self.did.as_str().to_owned()),
        );
        object.insert(
            "verification_method".to_owned(),
            Value::String(self.signature.verification_method.clone()),
        );
        object.insert(
            "created_at".to_owned(),
            Value::String(canonical::format_timestamp_canonical(
                self.signature.created_at,
            )),
        );
        if let Some(domain) = &self.signature.domain {
            object.insert("domain".to_owned(), Value::String(domain.clone()));
        }
        if let Some(audience) = &self.signature.audience {
            object.insert("audience".to_owned(), serde_json::to_value(audience)?);
        }
        canonical::canonical_json_bytes(&Value::Object(object)).map_err(Into::into)
    }

    /// Validate the receipt body and the plaintext proof bindings before JWS
    /// verification with the registry service key.
    pub fn validate_proof_binding(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(Error::Protocol(format!(
                "identity receipt schema '{}' is not {}",
                self.schema,
                Self::SCHEMA
            )));
        }
        ReceiptId::new(self.receipt_id.clone())?;
        if !matches!(self.witness_role.as_str(), "writer" | "witness" | "replica") {
            return Err(Error::Protocol(
                "identity receipt witness_role is not registered".to_owned(),
            ));
        }
        self.signature.validate()?;
        if self.signature.created_at != self.created_at {
            return Err(Error::Protocol(
                "identity receipt proof created_at must equal receipt created_at".to_owned(),
            ));
        }
        let expected_method_prefix = format!("{}#", self.registry_service_id);
        if !self
            .signature
            .verification_method
            .starts_with(&expected_method_prefix)
        {
            return Err(Error::Protocol(
                "identity receipt verification_method must be controlled by registry_service_id"
                    .to_owned(),
            ));
        }
        match (&self.audience, &self.signature.audience) {
            (None, None) => {}
            (Some(expected), Some(Audience::Single(actual))) if expected == actual => {}
            _ => {
                return Err(Error::Protocol(
                    "identity receipt and proof audience must be the same single value".to_owned(),
                ));
            }
        }
        if self.payload_digest()? != self.signature.payload_digest {
            return Err(Error::Protocol(
                "identity receipt payload_digest does not match canonical receipt bytes".to_owned(),
            ));
        }
        Ok(())
    }
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

    #[test]
    fn key_verification_content_enforces_schema_string_constraints() {
        let valid = json!({
            "transaction_id": "ak:transaction:01904100-0000-7000-8000-000000000001",
            "from_device": "ak:device:01904100-0000-7000-8000-000000000001",
            "methods": ["ak.key.verification.sas_v1"],
            "pairing_code": "482 913",
            "new_device_pubkey": {
                "kid": "ak:device:01904100-0000-7000-8000-000000000002",
                "alg": "EdDSA",
                "public_key": "z6MkDevice",
                "vendor_hint": true
            },
            "mac": {"ed25519:key": "c2ln"},
            "device_metadata": {"display_name": "Laptop"},
            "vendor_extension": {"opaque": true}
        });
        assert!(serde_json::from_value::<KeyVerificationContent>(valid.clone()).is_ok());

        let mut empty_methods = valid.clone();
        empty_methods["methods"] = json!([]);
        assert!(serde_json::from_value::<KeyVerificationContent>(empty_methods).is_err());

        let mut duplicate_methods = valid.clone();
        duplicate_methods["methods"] =
            json!(["ak.key.verification.sas_v1", "ak.key.verification.sas_v1"]);
        assert!(serde_json::from_value::<KeyVerificationContent>(duplicate_methods).is_err());

        let mut invalid_method = valid.clone();
        invalid_method["methods"] = json!(["legacy.verification"]);
        assert!(serde_json::from_value::<KeyVerificationContent>(invalid_method).is_err());

        let mut empty_mac = valid.clone();
        empty_mac["mac"] = json!({"ed25519:key": ""});
        assert!(serde_json::from_value::<KeyVerificationContent>(empty_mac).is_err());

        let mut long_pairing_code = valid.clone();
        long_pairing_code["pairing_code"] = json!("x".repeat(129));
        assert!(serde_json::from_value::<KeyVerificationContent>(long_pairing_code).is_err());

        let mut long_reason = valid;
        long_reason["reason"] = json!("x".repeat(257));
        assert!(serde_json::from_value::<KeyVerificationContent>(long_reason).is_err());
    }

    #[test]
    fn identity_receipt_uses_non_event_payload_proof() {
        let receipt = json!({
            "schema": "ak.schema.identity_receipt.v1",
            "receipt_id": "ak:receipt:019a6aa0-0000-7000-8000-0000000000cc",
            "did": "did:webvh:z6mkfixture:alice.example",
            "seq": 1,
            "head_event_digest":
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "registry_service_id": "did:webvh:z6mkfixture:registry.example",
            "witness_role": "writer",
            "created_at": "2026-07-15T00:00:00Z",
            "signature": {
                "kind": "detached_jws",
                "alg": "EdDSA",
                "verification_method": "did:webvh:z6mkfixture:registry.example#service-key",
                "payload_digest":
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "created_at": "2026-07-15T00:00:00Z",
                "jws": "a..b"
            }
        });

        let parsed = serde_json::from_value::<IdentityReceipt>(receipt.clone())
            .expect("identity receipt must accept the generic non-Event proof shape");
        let serialized = serde_json::to_value(parsed).expect("identity receipt must serialize");
        assert_eq!(serialized, receipt);

        let mut event_proof = receipt;
        event_proof["signature"]["event_digest"] =
            event_proof["signature"]["payload_digest"].take();
        assert!(serde_json::from_value::<IdentityReceipt>(event_proof).is_err());
    }

    #[test]
    fn identity_receipt_binding_is_context_separated_and_closed() {
        let mut receipt: IdentityReceipt = serde_json::from_value(json!({
            "schema": "ak.schema.identity_receipt.v1",
            "receipt_id": "ak:receipt:019a6aa0-0000-7000-8000-0000000000cc",
            "did": "did:webvh:z6mkfixture:alice.example",
            "seq": 1,
            "head_event_digest":
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "registry_service_id": "did:webvh:z6mkfixture:registry.example",
            "witness_role": "writer",
            "created_at": "2026-07-15T00:00:00Z",
            "signature": {
                "kind": "detached_jws",
                "alg": "EdDSA",
                "verification_method": "did:webvh:z6mkfixture:registry.example#service-key",
                "payload_digest":
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "created_at": "2026-07-15T00:00:00Z",
                "jws": "a..b"
            }
        }))
        .unwrap();
        receipt.signature.payload_digest = receipt.payload_digest().unwrap();
        receipt.validate_proof_binding().unwrap();
        let binding: Value =
            serde_json::from_slice(&receipt.proof_binding_bytes().unwrap()).unwrap();
        assert_eq!(binding["context"], IDENTITY_RECEIPT_PROOF_BINDING_CONTEXT);
        assert_eq!(
            binding["registry_service_id"],
            receipt.registry_service_id.as_str()
        );
        assert_eq!(binding["did"], receipt.did.as_str());

        receipt.signature.created_at = "2026-07-15T00:00:01Z".parse().unwrap();
        assert!(receipt.validate_proof_binding().is_err());
    }
}
