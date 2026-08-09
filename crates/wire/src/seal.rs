//! Arkret Seal typed model.
//!
//! A Seal is the notary-signed commitment for control-plane finality.
//! `delta[]` contains only the control-plane `event_digest` values newly
//! accepted by this Seal. Cumulative coverage is derived recursively from
//! `predecessor_refs[]`.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Did, DidUrl, Error, Hash, Hlc, RealmId, Result, SealId, canonical};

pub const MAX_SEAL_PREDECESSOR_REFS: usize = 128;
pub const MAX_SEAL_COVERED_EVENT_DIGESTS: usize = 1_048_576;

pub fn seal_canonical_bytes(seal: &Seal) -> Result<Vec<u8>> {
    seal.canonical_bytes_for_id()
}

pub fn compute_seal_id(canonical_bytes: &[u8]) -> Result<SealId> {
    Seal::id_from_canonical_bytes(canonical_bytes)
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
pub struct PayloadSignature {
    pub verification_method: DidUrl,
    pub payload_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    pub jws: String,
    /// `seal.schema.json#/$defs/signature` declares `additionalProperties: true`;
    /// unknown members are preserved so canonical re-serialization is lossless.
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub extra: BTreeMap<String, Value>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NotarySig {
    Single(PayloadSignature),
    Multi(MultiSignature),
    Threshold(ThresholdSignature),
}

/// `seal.schema.json#/$defs/multi_signature` is a closed object; `kind` is the
/// discriminator that keeps this branch disjoint from the other two.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultiSignature {
    pub kind: MultiSigKind,
    pub signatures: Vec<PayloadSignature>,
}

/// `seal.schema.json#/$defs/threshold_signature` is a closed object. Closing it
/// is what makes the `notary_signature` union decidable: an instance that also
/// carries the single-signature members no longer matches this branch.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdSignature {
    pub kind: ThresholdSigKind,
    pub threshold: u32,
    pub signers: Vec<Did>,
    pub proof: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MultiSigKind {
    MultiSig,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdSigKind {
    ThresholdSig,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability_root: Option<Hash>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_object"
    )]
    pub coverage_scope: Option<BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub covered_event_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_state_root: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_digest_algorithm: Option<String>,
    pub notary_signature: NotarySig,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub sealed_at: DateTime<Utc>,
    pub hlc: Hlc,
    #[serde(default, skip)]
    pub kind: SealKind,
}

fn deserialize_optional_object<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<BTreeMap<String, Value>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    BTreeMap::<String, Value>::deserialize(deserializer).map(Some)
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
    #[serde(skip_serializing_if = "Option::is_none")]
    availability_root: &'a Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    coverage_scope: &'a Option<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "move_slice_is_empty")]
    covered_event_digests: &'a [Hash],
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_state_root: &'a Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_digest_algorithm: &'a Option<String>,
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    sealed_at: DateTime<Utc>,
    hlc: &'a Hlc,
}

impl Seal {
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
            availability_root: &self.availability_root,
            coverage_scope: &self.coverage_scope,
            covered_event_digests: &self.covered_event_digests,
            previous_state_root: &self.previous_state_root,
            previous_digest_algorithm: &self.previous_digest_algorithm,
            sealed_at: self.sealed_at,
            hlc: &self.hlc,
        };
        Ok(canonical::canonical_json_bytes(&body)?)
    }

    pub fn derive_id(&self) -> Result<SealId> {
        Self::id_from_canonical_bytes(&self.canonical_bytes_for_id()?)
    }

    pub fn id_from_canonical_bytes(bytes: &[u8]) -> Result<SealId> {
        let id = format!("ak:seal:{}", canonical::sha256_digest(bytes));
        SealId::new(id).map_err(|err| Error::Protocol(format!("invalid Seal id: {err}")))
    }

    pub fn validate_id(&self) -> Result<()> {
        let derived = self.derive_id()?;
        if derived != self.id {
            return Err(Error::Protocol(format!(
                "Seal id mismatch: declared {} but canonical bytes hash to {}",
                self.id, derived
            )));
        }
        Ok(())
    }

    pub fn validate_structural(&self) -> Result<()> {
        if self.predecessor_refs.len() > MAX_SEAL_PREDECESSOR_REFS {
            return Err(Error::Protocol(format!(
                "Seal.predecessor_refs exceeds maximum item count {MAX_SEAL_PREDECESSOR_REFS}"
            )));
        }
        if self.covered_event_digests.len() > MAX_SEAL_COVERED_EVENT_DIGESTS {
            return Err(Error::Protocol(format!(
                "Seal.covered_event_digests exceeds maximum item count {MAX_SEAL_COVERED_EVENT_DIGESTS}"
            )));
        }
        validate_sorted_unique("Seal.predecessor_refs", &self.predecessor_refs)?;
        validate_sorted_unique("Seal.delta", &self.delta)?;
        validate_sorted_unique("Seal.covered_event_digests", &self.covered_event_digests)?;
        if self.previous_state_root.is_some() != self.previous_digest_algorithm.is_some() {
            return Err(Error::Protocol(
                "Seal previous_state_root and previous_digest_algorithm must be present together"
                    .to_owned(),
            ));
        }
        match &self.notary_signature {
            NotarySig::Single(_) => {}
            NotarySig::Multi(multi) => {
                if multi.signatures.is_empty() {
                    return Err(Error::Protocol(
                        "Seal multi_sig must have at least one signature".to_owned(),
                    ));
                }
            }
            NotarySig::Threshold(t) => {
                if t.threshold == 0 {
                    return Err(Error::Protocol(
                        "Seal threshold_sig threshold must be >= 1".to_owned(),
                    ));
                }
                if t.signers.is_empty() {
                    return Err(Error::Protocol(
                        "Seal threshold_sig must list at least one signer".to_owned(),
                    ));
                }
                if (t.threshold as usize) > t.signers.len() {
                    return Err(Error::Protocol(format!(
                        "Seal threshold_sig threshold {} exceeds signer count {}",
                        t.threshold,
                        t.signers.len()
                    )));
                }
                if t.proof.is_empty() {
                    return Err(Error::Protocol(
                        "Seal threshold_sig proof must not be empty".to_owned(),
                    ));
                }
            }
        }
        Ok(())
    }
}

fn validate_sorted_unique<T>(field: &str, values: &[T]) -> Result<()>
where
    T: AsRef<str>,
{
    for pair in values.windows(2) {
        let left = pair[0].as_ref();
        let right = pair[1].as_ref();
        if left >= right {
            return Err(Error::Protocol(format!(
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
            extra: BTreeMap::new(),
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
            availability_root: None,
            coverage_scope: None,
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(sig()),
            sealed_at: Utc.with_ymd_and_hms(2026, 6, 11, 0, 0, 0).unwrap(),
            hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
            kind: SealKind::Normal,
        };
        seal.id = seal.derive_id().unwrap();
        seal
    }

    #[test]
    fn seal_id_round_trips() {
        let seal = sample();
        seal.validate_id().unwrap();
        seal.validate_structural().unwrap();
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
    fn empty_predecessors_allow_a_canonical_non_empty_delta() {
        let mut seal = sample();
        seal.predecessor_refs.clear();
        seal.id = seal.derive_id().unwrap();
        seal.validate_structural().unwrap();
    }

    #[test]
    fn signature_variants_decode() {
        let value = json!({
            "verification_method": "did:webvh:z6mkfixture:notary.example#k1",
            "payload_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "created_at": "2026-06-11T00:00:00.000Z",
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
                "created_at": "2026-06-11T00:00:00.000Z",
                "jws": "AAAA.BBBB.CCCC"
            }]
        });
        let threshold = json!({
            "kind": "threshold_sig",
            "threshold": 2,
            "signers": ["did:webvh:z6mkfixture:a.example", "did:webvh:z6mkfixture:b.example"],
            "proof": "AAAA"
        });
        assert!(matches!(
            serde_json::from_value::<NotarySig>(multi).unwrap(),
            NotarySig::Multi(_)
        ));
        assert!(matches!(
            serde_json::from_value::<NotarySig>(threshold.clone()).unwrap(),
            NotarySig::Threshold(_)
        ));

        // A future member added to either aggregate form must fail its own
        // branch rather than silently widening the union.
        let mut widened = threshold;
        widened["future_member"] = json!(true);
        assert!(serde_json::from_value::<ThresholdSignature>(widened.clone()).is_err());
        assert!(serde_json::from_value::<NotarySig>(widened).is_err());
    }

    #[test]
    fn coverage_scope_rejects_explicit_null() {
        let mut value = serde_json::to_value(sample()).unwrap();
        value["coverage_scope"] = Value::Null;

        let error = serde_json::from_value::<Seal>(value).unwrap_err();
        assert!(error.to_string().contains("map"));
    }

    #[test]
    fn predecessor_refs_enforce_schema_bound_before_set_validation() {
        let mut seal = sample();
        seal.predecessor_refs = vec![seal_id(0x11); MAX_SEAL_PREDECESSOR_REFS + 1];

        let error = seal.validate_structural().unwrap_err();
        assert!(error.to_string().contains("predecessor_refs exceeds"));
    }
}
