//! Device identity receipt and key-verification shapes.

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{
    Audience, Base64UrlString, DeviceId, DeviceMessageTransactionId, Did, DidCoreId, DidUrl, Hash,
    NonEmptyString, PayloadProof, ProofContextId, ProtocolKind, ReceiptId, Result, SchemaId,
    TrustDomainId, WireError, canonical, project_did_to_core_id,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Counterpart for `spec/v1/artifacts/schemas/identity-receipt.schema.json`.
pub const IDENTITY_RECEIPT_PROOF_BINDING_CONTEXT: &str = ProofContextId::IDENTITY_RECEIPT_PROOF_V1;

fn verification_method_controller_core(verification_method: &DidUrl) -> Result<DidCoreId> {
    let controller = verification_method
        .as_str()
        .split_once('#')
        .map(|(controller, _)| controller)
        .ok_or_else(|| {
            WireError::Protocol("verification_method requires a DID URL fragment".to_owned())
        })?;
    project_did_to_core_id(&Did::new(controller)?).map_err(Into::into)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityReceipt {
    pub schema: String,
    pub receipt_id: String,
    pub subject_did: Did,
    pub seq: u64,
    pub head_event_digest: Hash,
    pub registry_id: DidCoreId,
    pub witness_role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub signature: PayloadProof,
}

impl IdentityReceipt {
    pub const SCHEMA: &'static str = SchemaId::IDENTITY_RECEIPT_V1;
    /// `sha256(canonical_json(receipt with signature omitted))`.
    pub fn payload_digest(&self) -> Result<Hash> {
        let value = canonical::unsigned_value(self, &["signature"])?;
        let bytes = canonical::canonical_json_value_bytes(&value)?;
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
            "registry_id".to_owned(),
            Value::String(self.registry_id.as_str().to_owned()),
        );
        object.insert(
            "subject_did".to_owned(),
            Value::String(self.subject_did.as_str().to_owned()),
        );
        object.insert(
            "verification_method".to_owned(),
            Value::String(self.signature.verification_method.as_str().to_owned()),
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
        canonical::canonical_json_value_bytes(&Value::Object(object)).map_err(Into::into)
    }

    /// Validate the receipt body and the plaintext proof bindings before JWS
    /// verification with the registry service key.
    pub fn validate_proof_binding(&self) -> Result<()> {
        if self.schema != SchemaId::IDENTITY_RECEIPT_V1 {
            return Err(WireError::Protocol(format!(
                "identity receipt schema '{}' is not {schemaid_identity_receipt_v1}",
                self.schema,
                schemaid_identity_receipt_v1 = SchemaId::IDENTITY_RECEIPT_V1
            )));
        }
        ReceiptId::new(self.receipt_id.clone())?;
        if !matches!(self.witness_role.as_str(), "writer" | "witness" | "replica") {
            return Err(WireError::Protocol(
                "identity receipt witness_role is not registered".to_owned(),
            ));
        }
        self.signature.validate()?;
        if self.signature.created_at != self.created_at {
            return Err(WireError::Protocol(
                "identity receipt proof created_at must equal receipt created_at".to_owned(),
            ));
        }
        if verification_method_controller_core(&self.signature.verification_method)?
            != self.registry_id
        {
            return Err(WireError::Protocol(
                "identity receipt verification_method must be controlled by registry_id".to_owned(),
            ));
        }
        match (&self.audience, &self.signature.audience) {
            (None, None) => {}
            (Some(expected), Some(Audience::Single(actual))) if expected == actual => {}
            _ => {
                return Err(WireError::Protocol(
                    "identity receipt and proof audience must be the same single value".to_owned(),
                ));
            }
        }
        if self.payload_digest()? != self.signature.payload_digest {
            return Err(WireError::Protocol(
                "identity receipt payload_digest does not match canonical receipt bytes".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Arkret observation of one independently verified did:webvh method witness.
///
/// This object never replaces validation of `did.jsonl`, the controller
/// proof, or the separate `did-witness.json` proof set.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidWebvhWitnessReceipt {
    pub schema: String,
    pub receipt_id: String,
    pub subject_did: Did,
    pub version_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_head_digest: Option<Hash>,
    pub witness_did: Did,
    pub witness_verification_method: DidUrl,
    pub controlling_organization_did: Did,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub issuer_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_domain: Option<TrustDomainId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub signature: PayloadProof,
}

impl DidWebvhWitnessReceipt {
    pub const SCHEMA: &'static str = SchemaId::DID_WEBVH_WITNESS_RECEIPT_V1;
    pub const PROOF_BINDING_CONTEXT: &'static str =
        ProofContextId::DID_WEBVH_WITNESS_RECEIPT_PROOF_V1;

    pub fn payload_digest(&self) -> Result<Hash> {
        let value = canonical::unsigned_value(self, &["signature"])?;
        Ok(Hash::new(canonical::sha256_digest(
            canonical::canonical_json_value_bytes(&value)?,
        ))?)
    }

    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        let mut object = serde_json::Map::new();
        object.insert(
            "context".to_owned(),
            Value::String(Self::PROOF_BINDING_CONTEXT.to_owned()),
        );
        object.insert(
            "payload_digest".to_owned(),
            Value::String(self.signature.payload_digest.as_str().to_owned()),
        );
        object.insert(
            "issuer_id".to_owned(),
            Value::String(self.issuer_id.as_str().to_owned()),
        );
        object.insert(
            "subject_did".to_owned(),
            Value::String(self.subject_did.as_str().to_owned()),
        );
        object.insert(
            "version_id".to_owned(),
            Value::String(self.version_id.clone()),
        );
        object.insert(
            "witness_did".to_owned(),
            Value::String(self.witness_did.as_str().to_owned()),
        );
        object.insert(
            "verification_method".to_owned(),
            Value::String(self.signature.verification_method.as_str().to_owned()),
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

    pub fn validate_proof_binding(&self) -> Result<()> {
        if self.schema != SchemaId::DID_WEBVH_WITNESS_RECEIPT_V1 {
            return Err(WireError::Protocol(format!(
                "did:webvh witness receipt schema '{}' is not {schemaid_did_webvh_witness_receipt_v1}",
                self.schema,
                schemaid_did_webvh_witness_receipt_v1 = SchemaId::DID_WEBVH_WITNESS_RECEIPT_V1
            )));
        }
        ReceiptId::new(self.receipt_id.clone())?;
        if self.subject_did.method() != "webvh" {
            return Err(WireError::Protocol(
                "did:webvh witness receipt subject must use did:webvh".to_owned(),
            ));
        }
        if self.version_id.trim().is_empty() {
            return Err(WireError::Protocol(
                "did:webvh witness receipt version_id must not be empty".to_owned(),
            ));
        }
        if self.witness_did.method() != "key" {
            return Err(WireError::Protocol(
                "did:webvh witness receipt witness_did must use did:key".to_owned(),
            ));
        }
        let witness_key = self
            .witness_did
            .as_str()
            .strip_prefix("did:key:")
            .expect("did:key method was checked above");
        if self.witness_verification_method != format!("{}#{witness_key}", self.witness_did) {
            return Err(WireError::Protocol(
                "did:webvh witness receipt witness_verification_method must be the canonical did:key verification method".to_owned(),
            ));
        }
        if self.observed_at > self.created_at {
            return Err(WireError::Protocol(
                "did:webvh witness receipt observed_at must not be later than created_at"
                    .to_owned(),
            ));
        }
        if let Some(source) = &self.source {
            url::Url::parse(source).map_err(|error| {
                WireError::Protocol(format!(
                    "did:webvh witness receipt source must be an absolute URI: {error}"
                ))
            })?;
        }
        if self.expires_at <= self.created_at {
            return Err(WireError::Protocol(
                "did:webvh witness receipt expires_at must be later than created_at".to_owned(),
            ));
        }
        self.signature.validate()?;
        if self.signature.created_at != self.created_at {
            return Err(WireError::Protocol(
                "did:webvh witness receipt proof created_at must equal receipt created_at"
                    .to_owned(),
            ));
        }
        if verification_method_controller_core(&self.signature.verification_method)?
            != self.issuer_id
        {
            return Err(WireError::Protocol(
                "did:webvh witness receipt proof must be controlled by issuer_id".to_owned(),
            ));
        }
        match (&self.audience, &self.signature.audience) {
            (None, None) => {}
            (Some(expected), Some(Audience::Single(actual))) if expected == actual => {}
            _ => {
                return Err(WireError::Protocol(
                    "did:webvh witness receipt and proof audience must be the same single value"
                        .to_owned(),
                ));
            }
        }
        if self.payload_digest()? != self.signature.payload_digest {
            return Err(WireError::Protocol(
                "did:webvh witness receipt payload_digest does not match canonical receipt bytes"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// Closed discriminator for `ak.root.identity.receipts.read.list.v1`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum IdentityReceiptEvidence {
    Registry(IdentityReceipt),
    DidWebvhWitness(DidWebvhWitnessReceipt),
}

impl IdentityReceiptEvidence {
    pub fn validate_proof_binding(&self) -> Result<()> {
        match self {
            Self::Registry(receipt) => receipt.validate_proof_binding(),
            Self::DidWebvhWitness(receipt) => receipt.validate_proof_binding(),
        }
    }
}

impl<'de> Deserialize<'de> for IdentityReceiptEvidence {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value.get("schema").and_then(Value::as_str) {
            Some(SchemaId::IDENTITY_RECEIPT_V1) => serde_json::from_value(value)
                .map(Self::Registry)
                .map_err(serde::de::Error::custom),
            Some(SchemaId::DID_WEBVH_WITNESS_RECEIPT_V1) => serde_json::from_value(value)
                .map(Self::DidWebvhWitness)
                .map_err(serde::de::Error::custom),
            Some(schema) => Err(serde::de::Error::custom(format!(
                "unsupported identity receipt schema '{schema}'"
            ))),
            None => Err(serde::de::Error::custom(
                "identity receipt evidence is missing schema discriminator",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn witness_receipt() -> DidWebvhWitnessReceipt {
        let created_at = Utc.with_ymd_and_hms(2026, 7, 29, 0, 0, 0).unwrap();
        let mut receipt = DidWebvhWitnessReceipt {
            schema: SchemaId::DID_WEBVH_WITNESS_RECEIPT_V1.to_owned(),
            receipt_id: "ak:receipt:01984e00-0000-7000-8000-000000000001".to_owned(),
            subject_did: Did::new("did:webvh:z6mkfixture:subject.example").unwrap(),
            version_id: "1-QmFixtureVersion".to_owned(),
            log_head_digest: Some(
                Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            ),
            witness_did: Did::new(
                "did:key:z6Mkrv5Cm2XCLumMPTqooLTCw6YDf421d7VdTziwrZ8vNf4L",
            )
            .unwrap(),
            witness_verification_method: DidUrl::new("did:key:z6Mkrv5Cm2XCLumMPTqooLTCw6YDf421d7VdTziwrZ8vNf4L#z6Mkrv5Cm2XCLumMPTqooLTCw6YDf421d7VdTziwrZ8vNf4L").unwrap(),
            controlling_organization_did: Did::new("did:web:org.example").unwrap(),
            observed_at: created_at,
            source: Some("https://subject.example/.well-known/did-witness.json".to_owned()),
            issuer_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            trust_domain: Some(TrustDomainId::new("ak:trust_domain:example").unwrap()),
            audience: None,
            expires_at: created_at + chrono::Duration::hours(24),
            created_at,
            signature: PayloadProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new(
                    "did:webvh:z6mkfixture:starid.example#service-key",
                )
                .unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "e30..c2ln".to_owned(),
            },
        };
        receipt.signature.payload_digest = receipt.payload_digest().unwrap();
        receipt
    }

    #[test]
    fn witness_receipt_is_a_closed_distinct_receipt_family() {
        let receipt = witness_receipt();
        receipt.validate_proof_binding().unwrap();
        let mut invalid_wire_value = serde_json::to_value(&receipt).unwrap();
        invalid_wire_value["trust_domain"] = json!("example");
        assert!(serde_json::from_value::<DidWebvhWitnessReceipt>(invalid_wire_value).is_err());
        let evidence: IdentityReceiptEvidence =
            serde_json::from_value(serde_json::to_value(&receipt).unwrap()).unwrap();
        assert!(matches!(
            evidence,
            IdentityReceiptEvidence::DidWebvhWitness(_)
        ));

        let mut unknown = serde_json::to_value(receipt).unwrap();
        unknown["schema"] = json!("ak.schema.unregistered_receipt.v1");
        assert!(serde_json::from_value::<IdentityReceiptEvidence>(unknown).is_err());
    }

    #[test]
    fn identity_receipt_uses_non_event_payload_proof() {
        let receipt = json!({
            "schema": "ak.schema.identity_receipt.v1",
            "receipt_id": "ak:receipt:019a6aa0-0000-7000-8000-0000000000cc",
            "subject_did": "did:webvh:z6mkfixture:alice.example",
            "seq": 1,
            "head_event_digest":
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "registry_id": "ak:did_core:webvh:z6mkfixture",
            "witness_role": "writer",
            "created_at": "2026-07-15T00:00:00.000Z",
            "signature": {
                "kind": "detached_jws",
                "verification_method": "did:webvh:z6mkfixture:registry.example#service-key",
                "payload_digest":
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "created_at": "2026-07-15T00:00:00.000Z",
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
            "subject_did": "did:webvh:z6mkfixture:alice.example",
            "seq": 1,
            "head_event_digest":
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "registry_id": "ak:did_core:webvh:z6mkfixture",
            "witness_role": "writer",
            "created_at": "2026-07-15T00:00:00.000Z",
            "signature": {
                "kind": "detached_jws",
                "verification_method": "did:webvh:z6mkfixture:registry.example#service-key",
                "payload_digest":
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "created_at": "2026-07-15T00:00:00.000Z",
                "jws": "a..b"
            }
        }))
        .unwrap();
        receipt.signature.payload_digest = receipt.payload_digest().unwrap();
        receipt.validate_proof_binding().unwrap();
        let binding: Value =
            serde_json::from_slice(&receipt.proof_binding_bytes().unwrap()).unwrap();
        assert_eq!(binding["context"], IDENTITY_RECEIPT_PROOF_BINDING_CONTEXT);
        assert_eq!(binding["registry_id"], receipt.registry_id.as_str());
        assert_eq!(binding["subject_did"], receipt.subject_did.as_str());

        receipt.signature.created_at = "2026-07-15T00:00:01.000Z".parse().unwrap();
        assert!(receipt.validate_proof_binding().is_err());
    }
}

// ── Device-message / key-verification counterparts ───────────────────────
// The `arkret` umbrella re-exports these owner-defined shapes at its root.

/// Counterpart for
/// `spec/v1/artifacts/schemas/device-message.schema.json#/$defs/key_verification_content/
/// properties/new_device_pubkey`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyVerificationContentNewDevicePubkey {
    pub kty: NonEmptyString,
    pub kid: DeviceId,
    pub algorithm: NonEmptyString,
    pub key: Base64UrlString,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_digest: Option<Hash>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyVerificationContent {
    /// `device-message.schema.json` constrains this to
    /// `^[A-Za-z0-9._~=-]{1,128}$`, which no `ak:transaction:<uuidv7>` value can
    /// satisfy — the `:` is outside the charset. This is a different namespace
    /// from `TransactionId`, not a laxer spelling of it.
    pub transaction_id: DeviceMessageTransactionId,
    pub from_device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub methods: Option<ProtocolKindList>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<ProtocolKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub timestamp: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
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
    pub gate_audience_uri: Option<NonEmptyString>,
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

impl KeyVerificationContent {
    /// Start one key-verification device-message content object.
    ///
    /// The selected device-message marker determines which additional fields
    /// are required before sending; the typed target builder validates that
    /// branch and rejects an incomplete content object.
    pub fn new(transaction_id: DeviceMessageTransactionId, from_device_id: DeviceId) -> Self {
        Self {
            transaction_id,
            from_device_id,
            methods: None,
            method: None,
            timestamp: None,
            expires_at: None,
            purpose: None,
            pairing_code: None,
            new_device_pubkey: None,
            challenge_signature: None,
            gate_audience_uri: None,
            request_canonical_digest: None,
            device_metadata: None,
            key_agreement_protocols: None,
            hashes: None,
            message_authentication_codes: None,
            short_authentication_string: None,
            commitment: None,
            key: None,
            mac: None,
            keys: None,
            verified_keys: None,
            signatures: None,
            code: None,
            reason: None,
            extra: BTreeMap::new(),
        }
    }
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
}

/// Counterpart for `spec/v1/artifacts/schemas/device-message.schema.json#/$defs/string_list`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct StringList(Vec<NonEmptyString>);

impl StringList {
    pub fn new(values: Vec<NonEmptyString>) -> Result<Self> {
        if values.is_empty() {
            return Err(WireError::Protocol(
                "string list must not be empty".to_owned(),
            ));
        }
        let mut unique = BTreeSet::new();
        if values.iter().any(|value| !unique.insert(value.as_str())) {
            return Err(WireError::Protocol(
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
            return Err(WireError::Protocol(
                "protocol kind list must not be empty".to_owned(),
            ));
        }
        let mut unique = BTreeSet::new();
        if values.iter().any(|value| !unique.insert(value.as_str())) {
            return Err(WireError::Protocol(
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
                    .map_err(|reason| WireError::Protocol(reason.to_owned()))?;
                if value.chars().count() > $maximum {
                    return Err(WireError::Protocol($error.to_owned()));
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
            return Err(WireError::Protocol(
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

#[cfg(test)]
mod key_verification_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn key_verification_content_enforces_schema_string_constraints() {
        // `device-message.schema.json` constrains `transaction_id` to
        // `^[A-Za-z0-9._~=-]{1,128}$`, so the wire value is a bare UUIDv7. This
        // fixture used to carry `ak:transaction:<uuidv7>`, which that pattern
        // rejects — the fixture was as off-spec as the type it exercised.
        let valid = json!({
            "transaction_id": "01904100-0000-7000-8000-000000000001",
            "from_device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "methods": ["ak.key.verification.sas_v1"],
            "pairing_code": "482 913",
            // Canonical PublicKey spelling: `{kty, kid, algorithm, key}`. The
            // `{kid, alg, public_key}` shape is explicitly non-canonical wire
            // and is asserted below to be rejected.
            "new_device_pubkey": {
                "kty": "OKP",
                "kid": "ak:device:01904100-0000-7000-8000-000000000002",
                "algorithm": "Ed25519",
                "key": "ZGV2aWNlLWtleQ"
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
        invalid_method["methods"] = json!(["invalid.verification"]);
        assert!(serde_json::from_value::<KeyVerificationContent>(invalid_method).is_err());

        let mut empty_mac = valid.clone();
        empty_mac["mac"] = json!({"ed25519:key": ""});
        assert!(serde_json::from_value::<KeyVerificationContent>(empty_mac).is_err());

        let mut long_pairing_code = valid.clone();
        long_pairing_code["pairing_code"] = json!("x".repeat(129));
        assert!(serde_json::from_value::<KeyVerificationContent>(long_pairing_code).is_err());

        let mut long_reason = valid.clone();
        long_reason["reason"] = json!("x".repeat(257));
        assert!(serde_json::from_value::<KeyVerificationContent>(long_reason).is_err());

        let mut legacy_pubkey_spelling = valid.clone();
        legacy_pubkey_spelling["new_device_pubkey"] = json!({
            "kid": "ak:device:01904100-0000-7000-8000-000000000002",
            "alg": "Ed25519",
            "public_key": "ZGV2aWNlLWtleQ"
        });
        assert!(
            serde_json::from_value::<KeyVerificationContent>(legacy_pubkey_spelling).is_err(),
            "the {{kid, alg, public_key}} spelling is not canonical wire"
        );

        // The prefixed `ak:transaction:` form is not merely unusual here, it is
        // unrepresentable: `:` is outside the schema charset.
        let mut typed_transaction_id = valid;
        typed_transaction_id["transaction_id"] =
            json!("ak:transaction:01904100-0000-7000-8000-000000000001");
        assert!(serde_json::from_value::<KeyVerificationContent>(typed_transaction_id).is_err());
    }
}
