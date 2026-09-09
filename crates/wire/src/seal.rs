//! Arkret Seal typed model.
//!
//! A Seal is the notary-signed commitment for control-plane finality.
//! `delta[]` contains only the control-plane `event_digest` values newly
//! accepted by this Seal. Cumulative coverage is derived recursively from
//! `predecessor_refs[]`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    DidUrl, Hash, Hlc, NotarySignerDescriptor, RealmId, Result, SealId, WireError, canonical,
};

pub const MAX_SEAL_PREDECESSOR_REFS: usize = 128;
pub const MAX_SEAL_DELTA: usize = 4_096;
pub const MAX_SEAL_AVAILABILITY_RECEIPT_DIGESTS: usize = 65_536;
pub const MAX_SEAL_COVERED_EVENT_DIGESTS: usize = 1_048_576;

pub fn seal_canonical_bytes(seal: &Seal) -> Result<Vec<u8>> {
    seal.canonical_bytes_for_id()
}

pub fn compute_seal_id(
    canonical_bytes: &[u8],
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<SealId> {
    Seal::id_from_canonical_bytes(canonical_bytes, digest_suite)
}

/// Detached signature over the canonical bytes of a non-Event protocol object.
///
/// Seal is not an Event Envelope, so its signature uses the generic
/// `payload_digest` member rather than the Event-only `event_digest`
/// (`seal.schema.json#/$defs/signature`).
///
/// This is the single Rust implementation of
/// `seal.schema.json#/$defs/signature`; a second, incompatible copy used to
/// live in `arkret_models_collaboration::governance::agent_artifacts::Signature`
/// and was removed so the `$defs` cannot deserialize two different ways.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadSignature {
    pub verification_method: DidUrl,
    pub payload_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub jws: String,
}

/// Closed signature shape used only by a Seal.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealSignature {
    pub verification_method: DidUrl,
    pub payload_digest: Hash,
    pub jws: String,
}

impl From<PayloadSignature> for SealSignature {
    fn from(signature: PayloadSignature) -> Self {
        Self {
            verification_method: signature.verification_method,
            payload_digest: signature.payload_digest,
            jws: signature.jws,
        }
    }
}

impl SealSignature {
    pub fn validate_descriptor_binding(&self, descriptor: &NotarySignerDescriptor) -> Result<()> {
        descriptor.validate()?;
        if self.verification_method != descriptor.verification_method {
            return Err(WireError::Protocol(
                "Seal signature verification_method does not match frozen descriptor".to_owned(),
            ));
        }
        let mut segments = self.jws.split('.');
        let protected_b64u = segments.next().unwrap_or_default();
        let payload = segments.next().unwrap_or_default();
        let signature_b64u = segments.next().unwrap_or_default();
        if segments.next().is_some() || !payload.is_empty() {
            return Err(WireError::Protocol(
                "Seal signature must use compact detached JWS".to_owned(),
            ));
        }
        let protected = crate::base64url::base64url_decode(protected_b64u)
            .map_err(|error| WireError::Protocol(format!("invalid Seal JWS header: {error}")))?;
        if crate::base64url::base64url_encode(&protected) != protected_b64u {
            return Err(WireError::Protocol(
                "Seal JWS protected header is not canonical base64url".to_owned(),
            ));
        }
        let header: Value = serde_json::from_slice(&protected)?;
        if canonical::canonical_json_bytes(&header)? != protected {
            return Err(WireError::Protocol(
                "Seal JWS protected header is not canonical JSON".to_owned(),
            ));
        }
        let Some(header) = header.as_object() else {
            return Err(WireError::Protocol(
                "Seal JWS protected header must be an object".to_owned(),
            ));
        };
        if header.get("alg").and_then(Value::as_str) != Some(descriptor.jose_algorithm.as_str())
            || header.get("kid").and_then(Value::as_str)
                != Some(descriptor.verification_method.as_str())
            || header.contains_key("crit")
        {
            return Err(WireError::Protocol(
                "Seal JWS protected header does not match frozen descriptor".to_owned(),
            ));
        }
        let signature = crate::base64url::base64url_decode(signature_b64u)
            .map_err(|error| WireError::Protocol(format!("invalid Seal JWS signature: {error}")))?;
        if signature.len() != 64 || crate::base64url::base64url_encode(&signature) != signature_b64u
        {
            return Err(WireError::Protocol(
                "Seal JWS signature is not a canonical 64-byte encoding".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NotarySig {
    Single(SealSignature),
    Multi(MultiSignature),
}

/// `seal.schema.json#/$defs/multi_signature` is a closed object; `kind` is the
/// discriminator that keeps this branch disjoint from the other two.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiSignature {
    pub kind: MultiSigKind,
    pub signatures: Vec<SealSignature>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MultiSigKind {
    MultiSig,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SealKind {
    #[default]
    Normal,
    Compaction,
}

impl SealKind {
    pub fn is_compaction(&self) -> bool {
        matches!(self, SealKind::Compaction)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Seal {
    pub id: SealId,
    pub realm_id: RealmId,
    pub predecessor_refs: Vec<SealId>,
    pub delta: Vec<Hash>,
    pub control_event_set_root: Hash,
    pub state_root: Hash,
    pub completeness_root: Hash,
    pub notary_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_view_root: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_event_set_root: Option<Hash>,
    pub availability_receipt_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub covered_event_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_state_root: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub previous_digest_algorithm: Option<arkret_canonical::DigestSuite>,
    pub notary_signature: NotarySig,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub sealed_at: DateTime<Utc>,
    pub hlc: Hlc,
}

#[derive(Serialize)]
struct SealBody<'a> {
    realm_id: &'a RealmId,
    predecessor_refs: &'a [SealId],
    delta: &'a [Hash],
    control_event_set_root: &'a Hash,
    state_root: &'a Hash,
    completeness_root: &'a Hash,
    notary_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_view_root: &'a Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_event_set_root: &'a Option<Hash>,
    availability_receipt_digests: &'a [Hash],
    #[serde(skip_serializing_if = "move_slice_is_empty")]
    covered_event_digests: &'a [Hash],
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_state_root: &'a Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_digest_algorithm: &'a Option<arkret_canonical::DigestSuite>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    sealed_at: DateTime<Utc>,
    hlc: &'a Hlc,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedSeal {
    pub realm_id: RealmId,
    pub predecessor_refs: Vec<SealId>,
    pub delta: Vec<Hash>,
    pub control_event_set_root: Hash,
    pub state_root: Hash,
    pub completeness_root: Hash,
    pub notary_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_view_root: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_event_set_root: Option<Hash>,
    pub availability_receipt_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub covered_event_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_state_root: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub previous_digest_algorithm: Option<arkret_canonical::DigestSuite>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub sealed_at: DateTime<Utc>,
    pub hlc: Hlc,
}

impl Seal {
    /// Reconstruct a complete signed Seal from the exact canonical unsigned
    /// body retained by a multi-signature aggregator.
    pub fn from_canonical_body_and_signature(
        canonical_body: &[u8],
        notary_signature: NotarySig,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<Self> {
        let body: UnsignedSeal = serde_json::from_slice(canonical_body)?;
        if canonical::canonical_json_bytes(&body)? != canonical_body {
            return Err(WireError::Protocol(
                "Seal body bytes are not canonical JSON".to_owned(),
            ));
        }
        let id = Self::id_from_canonical_bytes(canonical_body, digest_suite)?;
        let seal = Self {
            id,
            realm_id: body.realm_id,
            predecessor_refs: body.predecessor_refs,
            delta: body.delta,
            control_event_set_root: body.control_event_set_root,
            state_root: body.state_root,
            completeness_root: body.completeness_root,
            notary_seq: body.notary_seq,
            data_view_root: body.data_view_root,
            data_event_set_root: body.data_event_set_root,
            availability_receipt_digests: body.availability_receipt_digests,
            covered_event_digests: body.covered_event_digests,
            previous_state_root: body.previous_state_root,
            previous_digest_algorithm: body.previous_digest_algorithm,
            notary_signature,
            sealed_at: body.sealed_at,
            hlc: body.hlc,
        };
        seal.validate_structural()?;
        seal.validate_signature_payload_digests(|bytes| {
            Hash::new(canonical::digest(digest_suite, bytes)).map_err(Into::into)
        })?;
        Ok(seal)
    }

    pub fn is_compaction(&self) -> bool {
        !self.covered_event_digests.is_empty()
    }

    /// Mint the single-leaf Control Move basis represented by this accepted
    /// Seal. Callers must only use the result after receiver acceptance.
    pub fn seal_basis(&self) -> crate::SealBasis {
        crate::SealBasis {
            leaves: vec![self.id.clone()],
        }
    }

    pub fn canonical_bytes_for_id(&self) -> Result<Vec<u8>> {
        let body = SealBody {
            realm_id: &self.realm_id,
            predecessor_refs: &self.predecessor_refs,
            delta: &self.delta,
            control_event_set_root: &self.control_event_set_root,
            state_root: &self.state_root,
            completeness_root: &self.completeness_root,
            notary_seq: self.notary_seq,
            data_view_root: &self.data_view_root,
            data_event_set_root: &self.data_event_set_root,
            availability_receipt_digests: &self.availability_receipt_digests,
            covered_event_digests: &self.covered_event_digests,
            previous_state_root: &self.previous_state_root,
            previous_digest_algorithm: &self.previous_digest_algorithm,
            sealed_at: self.sealed_at,
            hlc: &self.hlc,
        };
        Ok(canonical::canonical_json_bytes(&body)?)
    }

    /// Derive this Seal identity under the Realm's verified digest suite.
    pub fn derive_id(&self, digest_suite: arkret_canonical::DigestSuite) -> Result<SealId> {
        Self::id_from_canonical_bytes(&self.canonical_bytes_for_id()?, digest_suite)
    }

    /// Derive a Seal identity under an explicit trusted Realm digest suite.
    pub fn id_from_canonical_bytes(
        bytes: &[u8],
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<SealId> {
        let id = format!("ak:seal:{}", canonical::digest(digest_suite, bytes));
        SealId::new(id).map_err(|err| WireError::Protocol(format!("invalid Seal id: {err}")))
    }

    /// Validate the Seal identity under the Realm's verified digest suite.
    pub fn validate_id(&self, digest_suite: arkret_canonical::DigestSuite) -> Result<()> {
        let derived = self.derive_id(digest_suite)?;
        if derived != self.id {
            return Err(WireError::Protocol(format!(
                "Seal id mismatch: declared {} but canonical bytes hash to {}",
                self.id, derived
            )));
        }
        Ok(())
    }

    pub fn validate_structural(&self) -> Result<()> {
        if self.predecessor_refs.len() > MAX_SEAL_PREDECESSOR_REFS {
            return Err(WireError::Protocol(format!(
                "Seal.predecessor_refs exceeds maximum item count {MAX_SEAL_PREDECESSOR_REFS}"
            )));
        }
        if self.delta.len() > MAX_SEAL_DELTA {
            return Err(WireError::Protocol(format!(
                "Seal.delta exceeds maximum item count {MAX_SEAL_DELTA}"
            )));
        }
        if self.availability_receipt_digests.len() > MAX_SEAL_AVAILABILITY_RECEIPT_DIGESTS {
            return Err(WireError::Protocol(format!(
                "Seal.availability_receipt_digests exceeds maximum item count {MAX_SEAL_AVAILABILITY_RECEIPT_DIGESTS}"
            )));
        }
        if self.covered_event_digests.len() > MAX_SEAL_COVERED_EVENT_DIGESTS {
            return Err(WireError::Protocol(format!(
                "Seal.covered_event_digests exceeds maximum item count {MAX_SEAL_COVERED_EVENT_DIGESTS}"
            )));
        }
        validate_sorted_unique("Seal.predecessor_refs", &self.predecessor_refs)?;
        validate_sorted_unique("Seal.delta", &self.delta)?;
        validate_sorted_unique(
            "Seal.availability_receipt_digests",
            &self.availability_receipt_digests,
        )?;
        validate_sorted_unique("Seal.covered_event_digests", &self.covered_event_digests)?;
        if self.previous_state_root.is_some() != self.previous_digest_algorithm.is_some() {
            return Err(WireError::Protocol(
                "Seal previous_state_root and previous_digest_algorithm must be present together"
                    .to_owned(),
            ));
        }
        match &self.notary_signature {
            NotarySig::Single(signature) => validate_seal_signature(signature)?,
            NotarySig::Multi(multi) => {
                if multi.signatures.is_empty() {
                    return Err(WireError::Protocol(
                        "Seal multi_sig must have at least one signature".to_owned(),
                    ));
                }
                for signature in &multi.signatures {
                    validate_seal_signature(signature)?;
                }
                for pair in multi.signatures.windows(2) {
                    if pair[0].verification_method >= pair[1].verification_method {
                        return Err(WireError::Protocol(
                            "Seal multi_sig signatures must be sorted and unique by verification_method"
                                .to_owned(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub fn validate_signature_payload_digests<F>(&self, digest: F) -> Result<()>
    where
        F: FnOnce(&[u8]) -> Result<Hash>,
    {
        let expected = digest(&self.canonical_bytes_for_id()?)?;
        let matches = match &self.notary_signature {
            NotarySig::Single(signature) => signature.payload_digest == expected,
            NotarySig::Multi(multi) => multi
                .signatures
                .iter()
                .all(|signature| signature.payload_digest == expected),
        };
        if !matches {
            return Err(WireError::Protocol(
                "Seal signature payload_digest does not match canonical Seal bytes".to_owned(),
            ));
        }
        Ok(())
    }
}

fn validate_seal_signature(signature: &SealSignature) -> Result<()> {
    let mut segments = signature.jws.split('.');
    let valid = segments.next().is_some_and(|value| !value.is_empty())
        && segments.next().is_some()
        && segments.next().is_some_and(|value| !value.is_empty())
        && segments.next().is_none()
        && signature.jws.bytes().all(|byte| {
            byte == b'.' || byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
        });
    if !valid {
        return Err(WireError::Protocol(
            "Seal signature JWS is invalid".to_owned(),
        ));
    }
    Ok(())
}

fn validate_sorted_unique<T>(field: &str, values: &[T]) -> Result<()>
where
    T: AsRef<str>,
{
    for pair in values.windows(2) {
        let left = pair[0].as_ref();
        let right = pair[1].as_ref();
        if left >= right {
            return Err(WireError::Protocol(format!(
                "{field} must be canonical sorted and duplicate-free"
            )));
        }
    }
    Ok(())
}

fn move_slice_is_empty(values: &&[Hash]) -> bool {
    values.is_empty()
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn realm() -> RealmId {
        RealmId::new("ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN".to_owned()).unwrap()
    }

    fn seal_id(byte: u8) -> SealId {
        SealId::new(format!(
            "ak:seal:sha256:{}",
            format!("{byte:02x}").repeat(32)
        ))
        .unwrap()
    }

    fn move_id(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn hash(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn sig() -> PayloadSignature {
        PayloadSignature {
            verification_method: DidUrl::new("did:webvh:z6mkfixture:notary.example#k1").unwrap(),
            payload_digest: hash(0xaa),
            created_at: Utc.with_ymd_and_hms(2026, 6, 11, 0, 0, 0).unwrap(),
            jws: "AAAA.BBBB.CCCC".to_owned(),
        }
    }

    fn sample() -> Seal {
        let mut seal = Seal {
            id: seal_id(0x00),
            realm_id: realm(),
            predecessor_refs: vec![seal_id(0x11)],
            delta: vec![move_id(0x22)],
            control_event_set_root: hash(0x33),
            state_root: hash(0x44),
            completeness_root: hash(0x55),
            notary_seq: 7,
            data_view_root: None,
            data_event_set_root: None,
            availability_receipt_digests: Vec::new(),
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(sig().into()),
            sealed_at: Utc.with_ymd_and_hms(2026, 6, 11, 0, 0, 0).unwrap(),
            hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
        };
        seal.id = seal
            .derive_id(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        seal
    }

    #[test]
    fn seal_id_round_trips() {
        let seal = sample();
        seal.validate_id(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        seal.validate_structural().unwrap();
    }

    #[test]
    fn seal_id_uses_the_selected_realm_digest_suite() {
        let mut seal = sample();
        seal.id = seal
            .derive_id(arkret_canonical::DigestSuite::Blake3)
            .unwrap();
        assert!(seal.id.as_str().starts_with("ak:seal:blake3:"));
        seal.validate_id(arkret_canonical::DigestSuite::Blake3)
            .unwrap();
        assert!(
            seal.validate_id(arkret_canonical::DigestSuite::Sha256)
                .is_err()
        );
    }

    #[test]
    fn canonical_bytes_exclude_id_and_signature() {
        let seal = sample();
        let text = String::from_utf8(seal.canonical_bytes_for_id().unwrap()).unwrap();
        assert!(!text.contains("\"id\""));
        assert!(!text.contains("notary_signature"));
        assert!(text.contains("\"delta\""));
        assert!(text.contains("\"control_event_set_root\""));
    }

    #[test]
    fn reconstructs_from_exact_canonical_body_and_signature() {
        let mut seal = sample();
        let body = seal.canonical_bytes_for_id().unwrap();
        let payload_digest = Hash::new(canonical::sha256_digest(&body)).unwrap();
        match &mut seal.notary_signature {
            NotarySig::Single(signature) => signature.payload_digest = payload_digest,
            NotarySig::Multi(_) => unreachable!(),
        }
        let reconstructed = Seal::from_canonical_body_and_signature(
            &body,
            seal.notary_signature.clone(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        assert_eq!(reconstructed, seal);

        let mut noncanonical = body;
        noncanonical.push(b' ');
        assert!(
            Seal::from_canonical_body_and_signature(
                &noncanonical,
                seal.notary_signature,
                arkret_canonical::DigestSuite::Sha256,
            )
            .is_err()
        );
    }

    #[test]
    fn empty_predecessors_allow_a_canonical_non_empty_delta() {
        let mut seal = sample();
        seal.predecessor_refs.clear();
        seal.id = seal
            .derive_id(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        seal.validate_structural().unwrap();
    }

    #[test]
    fn signature_variants_decode() {
        let value = json!({
            "verification_method": "did:webvh:z6mkfixture:notary.example#k1",
            "payload_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "jws": "AAAA.BBBB.CCCC"
        });
        let decoded: NotarySig = serde_json::from_value(value).unwrap();
        assert!(matches!(decoded, NotarySig::Single(_)));
    }

    /// The `notary_signature` union is untagged, so its branches must stay
    /// mutually exclusive on the wire. `kind` discriminates the two aggregate
    /// forms, and both are closed, so an instance that also carries the
    /// single-signature members can only be the single-signature branch.
    #[test]
    fn notary_signature_branches_stay_mutually_exclusive() {
        let multi = json!({
            "kind": "multi_sig",
            "signatures": [{
                "verification_method": "did:webvh:z6mkfixture:notary.example#k1",
                "payload_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "jws": "AAAA.BBBB.CCCC"
            }]
        });
        let threshold = json!({
            "kind": "threshold_sig",
            "threshold": 2,
            "signers": ["ak:did_core:webvh:z6mkfixturea", "ak:did_core:webvh:z6mkfixtureb"],
            "proof": "AAAA"
        });
        assert!(matches!(
            serde_json::from_value::<NotarySig>(multi).unwrap(),
            NotarySig::Multi(_)
        ));
        assert!(serde_json::from_value::<NotarySig>(threshold.clone()).is_err());

        // A future member added to either aggregate form must fail its own
        // branch rather than silently widening the union.
        let mut widened = threshold;
        widened["future_member"] = json!(true);
        assert!(serde_json::from_value::<NotarySig>(widened).is_err());
    }

    #[test]
    fn predecessor_refs_enforce_schema_bound_before_set_validation() {
        let mut seal = sample();
        seal.predecessor_refs = vec![seal_id(0x11); MAX_SEAL_PREDECESSOR_REFS + 1];

        let error = seal.validate_structural().unwrap_err();
        assert!(error.to_string().contains("predecessor_refs exceeds"));
    }
}
