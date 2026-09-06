//! CBA dependency evidence: [`AvailabilityReceipt`] and [`CbaProofBundle`].
//!
//! `zh/authz/cba-profiles.md`, `zh/authz/event-auth-state-resolution.md` §8.
//!
//! The bundle is an unsigned container. It is transport evidence, never an
//! Event field, and it is not authoritative on its own: a receiver
//! independently verifies every embedded object and reports the exact missing
//! dependencies. A bundle MAY be a bounded verifiable superset of what the
//! receiver needs.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Result, WireError};
use crate::event_envelope::{Event, SemanticRefProof};
use crate::seal::Seal;
use crate::{
    DidCoreId, EventId, Hash, PayloadProof, RealmId, SchemaId, SealId, SignerEvidenceRef, canonical,
};

pub const MAX_BUNDLE_SEALS: usize = 256;
pub const MAX_BUNDLE_CONTROL_MOVES: usize = 1024;
pub const MAX_BUNDLE_INCLUSION_PROOFS: usize = 2048;
pub const MAX_BUNDLE_AVAILABILITY_PROOFS: usize = 2048;
pub const MAX_BUNDLE_PROOFS: usize = 2048;
pub const MAX_BUNDLE_CANONICAL_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_BUNDLE_DEPENDENCY_DEPTH: usize = 4096;

/// Signed holder commitment that an Event's bytes stay retrievable until
/// `retention_expires_at`.
///
/// Digest membership roots prove that a digest is covered, never that anyone
/// still holds the bytes, so CBA models availability as its own signed fact.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AvailabilityReceipt {
    pub realm_id: RealmId,
    pub event_id: EventId,
    pub bytes_digest: Hash,
    pub holder_service_id: DidCoreId,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub retention_expires_at: DateTime<Utc>,
    pub holder_signer_evidence_ref: SignerEvidenceRef,
    pub signature: PayloadProof,
}

impl AvailabilityReceipt {
    pub const SCHEMA: &'static str = SchemaId::AVAILABILITY_RECEIPT_V1;
    pub fn canonical_receipt_bytes(&self) -> Result<Vec<u8>> {
        canonical::canonical_json_bytes(self).map_err(Into::into)
    }

    pub fn full_receipt_digest<F>(&self, digest: F) -> Result<Hash>
    where
        F: FnOnce(&[u8]) -> Result<Hash>,
    {
        digest(&self.canonical_receipt_bytes()?)
    }

    pub fn canonical_signature_payload_bytes(&self) -> Result<Vec<u8>> {
        let json = canonical::unsigned_value(self, &["signature"])?;
        canonical::canonical_json_bytes(&json).map_err(Into::into)
    }

    pub fn validate_signature_payload_digest<F>(&self, digest: F) -> Result<()>
    where
        F: FnOnce(&[u8]) -> Result<Hash>,
    {
        if digest(&self.canonical_signature_payload_bytes()?)? != self.signature.payload_digest {
            return Err(WireError::Protocol(
                "availability receipt signature payload digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical registered transcript signed by the holder proof.
    pub fn canonical_signature_binding_bytes(&self) -> Result<Vec<u8>> {
        let core_bytes = self.canonical_signature_payload_bytes()?;
        let core: Value = serde_json::from_slice(&core_bytes)?;
        let core = core.as_object().ok_or_else(|| {
            WireError::Protocol("availability receipt core must be an object".to_owned())
        })?;
        let mut binding = core.clone();
        binding.insert(
            "context".to_owned(),
            Value::String(crate::ProofContextId::AVAILABILITY_RECEIPT_PROOF_V1.to_owned()),
        );
        binding.insert(
            "payload_digest".to_owned(),
            serde_json::to_value(&self.signature.payload_digest)?,
        );
        binding.insert(
            "verification_method".to_owned(),
            serde_json::to_value(&self.signature.verification_method)?,
        );
        binding.insert(
            "created_at".to_owned(),
            Value::String(canonical::format_timestamp_canonical(
                self.signature.created_at,
            )),
        );
        canonical::canonical_json_bytes(&Value::Object(binding)).map_err(Into::into)
    }

    pub fn validate_structural(&self) -> Result<()> {
        self.signature.validate()?;
        self.holder_signer_evidence_ref.content_digest()?;
        Ok(())
    }

    pub fn event_bytes_digest_preimage(event: &Event) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(event)?;
        let Value::Object(map) = &mut value else {
            return Err(WireError::Protocol(
                "accepted Event must serialize as an object".to_owned(),
            ));
        };
        map.remove("unsigned");
        let mut preimage = b"ak.availability_event_bytes.v1".to_vec();
        preimage.push(0);
        preimage.extend(canonical::canonical_json_bytes(&value)?);
        Ok(preimage)
    }

    pub fn validate_event_bytes_digest<F>(&self, event: &Event, digest: F) -> Result<()>
    where
        F: FnOnce(&[u8]) -> Result<Hash>,
    {
        if event.event_id != self.event_id {
            return Err(WireError::Protocol(
                "availability receipt Event id mismatch".to_owned(),
            ));
        }
        if digest(&Self::event_bytes_digest_preimage(event)?)? != self.bytes_digest {
            return Err(WireError::Protocol(
                "availability receipt Event bytes digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Unsigned, receiver-relative dependency container for one target Seal.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CbaProofBundle {
    pub target_seal_ref: SealId,
    pub seals: Vec<Seal>,
    /// Control Moves are ordinary signed Events carrying `seal_basis`.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub control_moves: Vec<Event>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub inclusion_proofs: Vec<SemanticRefProof>,
    pub availability_proofs: Vec<AvailabilityReceipt>,
}

impl CbaProofBundle {
    /// Bound and shape checks only.
    ///
    /// This deliberately stops short of asserting closure: whether the bundle
    /// actually discharges a receiver's missing dependencies is decided by the
    /// receiver against its own accepted state, and treating the container as
    /// authoritative is exactly the mistake the bundle's unsigned status warns
    /// against.
    pub fn validate_structural(&self) -> Result<()> {
        if canonical::canonical_json_bytes(self)?.len() > MAX_BUNDLE_CANONICAL_BYTES {
            return Err(WireError::Protocol(format!(
                "CBA proof bundle exceeds {MAX_BUNDLE_CANONICAL_BYTES} canonical bytes"
            )));
        }
        if self.seals.is_empty() || self.seals.len() > MAX_BUNDLE_SEALS {
            return Err(WireError::Protocol(format!(
                "CBA proof bundle requires 1..={MAX_BUNDLE_SEALS} seals"
            )));
        }
        if self.control_moves.len() > MAX_BUNDLE_CONTROL_MOVES {
            return Err(WireError::Protocol(format!(
                "CBA proof bundle exceeds {MAX_BUNDLE_CONTROL_MOVES} control moves"
            )));
        }
        if self.inclusion_proofs.len() > MAX_BUNDLE_INCLUSION_PROOFS {
            return Err(WireError::Protocol(format!(
                "CBA proof bundle exceeds {MAX_BUNDLE_INCLUSION_PROOFS} inclusion proofs"
            )));
        }
        if self.availability_proofs.len() > MAX_BUNDLE_AVAILABILITY_PROOFS {
            return Err(WireError::Protocol(format!(
                "CBA proof bundle exceeds {MAX_BUNDLE_AVAILABILITY_PROOFS} availability proofs"
            )));
        }
        if self.inclusion_proofs.len() + self.availability_proofs.len() > MAX_BUNDLE_PROOFS {
            return Err(WireError::Protocol(format!(
                "CBA proof bundle exceeds {MAX_BUNDLE_PROOFS} combined proofs"
            )));
        }
        ensure_strictly_sorted(
            "CBA proof bundle seals",
            self.seals
                .iter()
                .map(|seal| Ok(seal.id.as_str().as_bytes().to_vec())),
        )?;
        ensure_strictly_sorted(
            "CBA proof bundle control_moves",
            self.control_moves
                .iter()
                .map(|event| Ok(event.event_id.as_str().as_bytes().to_vec())),
        )?;
        ensure_strictly_sorted(
            "CBA proof bundle inclusion_proofs",
            self.inclusion_proofs
                .iter()
                .map(|proof| canonical::canonical_json_bytes(proof).map_err(Into::into)),
        )?;
        ensure_strictly_sorted(
            "CBA proof bundle availability_proofs",
            self.availability_proofs
                .iter()
                .map(AvailabilityReceipt::canonical_receipt_bytes),
        )?;

        let seals_by_id = self
            .seals
            .iter()
            .map(|seal| (seal.id.clone(), seal))
            .collect::<BTreeMap<_, _>>();
        let Some(target) = seals_by_id.get(&self.target_seal_ref) else {
            return Err(WireError::Protocol(
                "CBA proof bundle must contain its target_seal_ref".to_owned(),
            ));
        };
        let target_realm = &target.realm_id;
        for seal in &self.seals {
            seal.validate_structural()?;
            if &seal.realm_id != target_realm {
                return Err(WireError::Protocol(
                    "CBA proof bundle contains a cross-Realm Seal".to_owned(),
                ));
            }
        }
        for control_move in &self.control_moves {
            if control_move.realm_id != *target_realm
                || !control_move.kind.is_control_plane()
                || control_move.seal_basis.is_none()
            {
                return Err(WireError::Protocol(
                    "CBA proof bundle control_moves must be same-Realm Control Events with seal_basis"
                        .to_owned(),
                ));
            }
            control_move.validate_for_accepted_structural()?;
        }
        for proof in &self.inclusion_proofs {
            proof.validate_structural()?;
        }
        for receipt in &self.availability_proofs {
            receipt.validate_structural()?;
            if receipt.realm_id != *target_realm {
                return Err(WireError::Protocol(
                    "CBA proof bundle contains a cross-Realm availability proof".to_owned(),
                ));
            }
        }

        let mut reachable = BTreeSet::new();
        let mut pending = vec![(self.target_seal_ref.clone(), 1usize)];
        while let Some((seal_id, depth)) = pending.pop() {
            if depth > MAX_BUNDLE_DEPENDENCY_DEPTH {
                return Err(WireError::Protocol(format!(
                    "CBA proof bundle dependency path exceeds {MAX_BUNDLE_DEPENDENCY_DEPTH}"
                )));
            }
            if !reachable.insert(seal_id.clone()) {
                continue;
            }
            if let Some(seal) = seals_by_id.get(&seal_id) {
                pending.extend(
                    seal.predecessor_refs
                        .iter()
                        .filter(|predecessor| seals_by_id.contains_key(*predecessor))
                        .cloned()
                        .map(|predecessor| (predecessor, depth + 1)),
                );
            }
        }
        if reachable.len() != self.seals.len() {
            return Err(WireError::Protocol(
                "CBA proof bundle contains a Seal unreachable from target_seal_ref".to_owned(),
            ));
        }
        let covered_control_digests = self
            .seals
            .iter()
            .flat_map(|seal| seal.delta.iter().chain(&seal.covered_event_digests))
            .collect::<BTreeSet<_>>();
        for control_move in &self.control_moves {
            let reachable = covered_control_digests.iter().any(|expected| {
                let suite = if expected.as_str().starts_with("sha256:") {
                    arkret_canonical::DigestSuite::Sha256
                } else if expected.as_str().starts_with("blake3:") {
                    arkret_canonical::DigestSuite::Blake3
                } else {
                    return false;
                };
                control_move
                    .event_digest_with_digest_suite(suite)
                    .ok()
                    .and_then(|digest| Hash::new(digest).ok())
                    .as_ref()
                    == Some(expected)
            });
            if !reachable {
                return Err(WireError::Protocol(
                    "CBA proof bundle contains a Control Move unreachable from target Seal coverage"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

fn ensure_strictly_sorted<I>(label: &str, values: I) -> Result<()>
where
    I: IntoIterator<Item = Result<Vec<u8>>>,
{
    let mut previous: Option<Vec<u8>> = None;
    for value in values {
        let value = value?;
        if previous.as_ref().is_some_and(|previous| previous >= &value) {
            return Err(WireError::Protocol(format!(
                "{label} must be strictly canonical-bytewise sorted and unique"
            )));
        }
        previous = Some(value);
    }
    Ok(())
}
