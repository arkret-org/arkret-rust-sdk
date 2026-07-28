//! CBA dependency evidence: [`AvailabilityReceipt`] and [`CbaProofBundle`].
//!
//! `zh/authz/cba-profiles.md`, `zh/authz/event-auth-state-resolution.md` §8.
//!
//! The bundle is an unsigned container. It is transport evidence, never an
//! Event field, and it is not authoritative on its own: a receiver
//! independently verifies every embedded object and reports the exact missing
//! dependencies. A bundle MAY be a bounded verifiable superset of what the
//! receiver needs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::event_envelope::{Event, SemanticRefProof};
use crate::seal::Seal;
use crate::{Did, EventId, Hash, PayloadSignature, RealmId, SealId, canonical};

pub const MAX_BUNDLE_SEALS: usize = 256;
pub const MAX_BUNDLE_CONTROL_MOVES: usize = 1024;
pub const MAX_BUNDLE_INCLUSION_PROOFS: usize = 2048;
pub const MAX_BUNDLE_AVAILABILITY_PROOFS: usize = 2048;

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
    pub holder_id: Did,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub retention_expires_at: DateTime<Utc>,
    pub signature: PayloadSignature,
}

impl AvailabilityReceipt {
    /// Hash of the canonical receipt bytes with `signature` omitted.
    pub fn payload_digest(&self) -> Result<Hash> {
        let mut json = serde_json::to_value(self)?;
        if let Value::Object(map) = &mut json {
            map.remove("signature");
        }
        Ok(Hash::new(canonical::canonical_sha256(&json)?)?)
    }

    pub fn validate_structural(&self) -> Result<()> {
        if self.signature.payload_digest != self.payload_digest()? {
            return Err(Error::Protocol(
                "availability receipt signature does not cover its canonical bytes".to_owned(),
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
        if self.seals.is_empty() || self.seals.len() > MAX_BUNDLE_SEALS {
            return Err(Error::Protocol(format!(
                "CBA proof bundle requires 1..={MAX_BUNDLE_SEALS} seals"
            )));
        }
        if self.control_moves.len() > MAX_BUNDLE_CONTROL_MOVES {
            return Err(Error::Protocol(format!(
                "CBA proof bundle exceeds {MAX_BUNDLE_CONTROL_MOVES} control moves"
            )));
        }
        if self.inclusion_proofs.len() > MAX_BUNDLE_INCLUSION_PROOFS {
            return Err(Error::Protocol(format!(
                "CBA proof bundle exceeds {MAX_BUNDLE_INCLUSION_PROOFS} inclusion proofs"
            )));
        }
        if self.availability_proofs.len() > MAX_BUNDLE_AVAILABILITY_PROOFS {
            return Err(Error::Protocol(format!(
                "CBA proof bundle exceeds {MAX_BUNDLE_AVAILABILITY_PROOFS} availability proofs"
            )));
        }
        for control_move in &self.control_moves {
            if control_move.seal_basis.is_none() {
                return Err(Error::Protocol(
                    "CBA proof bundle control_moves must carry seal_basis".to_owned(),
                ));
            }
        }
        for receipt in &self.availability_proofs {
            receipt.validate_structural()?;
        }
        Ok(())
    }
}
