//! Device identity receipt shapes.

use arkret_wire::{
    Audience, Did, DidCoreId, DidUrl, Hash, PayloadProof, ProofContextId, ReceiptId, Result,
    SchemaId, TrustDomainId, WireError, canonical, project_did_to_core_id,
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
    pub accepted_entry_digest: Hash,
    pub registry_id: DidCoreId,
    pub witness_role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub signature: PayloadProof,
}

impl IdentityReceipt {
    /// Check the byte-consensus commitment against a complete native entry.
    pub fn validate_accepted_entry(
        &self,
        did: &Did,
        seq: u64,
        entry: &impl Serialize,
    ) -> Result<()> {
        if &self.subject_did != did
            || self.seq != seq
            || self.accepted_entry_digest.as_str() != canonical::canonical_sha256(entry)?
        {
            return Err(WireError::Protocol(
                "identity receipt does not commit to the exact accepted entry".to_owned(),
            ));
        }
        self.validate_proof_binding()
    }
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
        if !self.accepted_entry_digest.as_str().starts_with("sha256:") {
            return Err(WireError::Protocol(
                "accepted entry commitment requires SHA-256".to_owned(),
            ));
        }
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
            "accepted_entry_digest":
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
            "accepted_entry_digest":
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
