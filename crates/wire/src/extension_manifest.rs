//! Declarative Extension Manifest (`zh/extensions/extension-manifest.md`).
//!
//! A manifest declares what an extension contributes — payload schemas,
//! reducer contracts, required actions, confidentiality, transport rails,
//! recovery and federation profiles, conformance vectors and resource limits —
//! as data.
//!
//! It carries no executable reducer DSL. Everything a loader may act on is a
//! digest-pinned registry symbol; an extension that needed arbitrary behaviour
//! would be a second Control wire, which v1 does not have.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::primitives::Proof;
use crate::{Did, Hash};

pub const MAX_MANIFEST_DEPENDENCY_REFS: usize = 64;
pub const MAX_MANIFEST_PAYLOAD_SCHEMA_REFS: usize = 256;
pub const MAX_MANIFEST_REDUCER_CONTRACT_REFS: usize = 256;
pub const MAX_MANIFEST_REQUIRED_ACTIONS: usize = 256;
pub const MAX_MANIFEST_TRANSPORT_RAIL_IDS: usize = 32;
pub const MAX_MANIFEST_CONFORMANCE_VECTOR_REFS: usize = 512;
pub const MAX_MANIFEST_PROOFS: usize = 16;

/// Protocol layer an extension may declare.
///
/// Kernel is not an option: an extension cannot add to the Kernel.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolLayerKind {
    CollaborationBase,
    Extension,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialityClass {
    PlaintextAllowed,
    RecipientEncrypted,
    E2eeRequired,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConcurrencyClass {
    MergeSafe,
    Exclusive,
    SecurityBarrier,
}

/// Digest-pinned reference to registry content.
///
/// `registry_id` plus `digest` identify the content; `retrieval_url` is a hint
/// only, so a moved or hostile mirror cannot change what was referenced.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryContentRef {
    pub registry_id: String,
    pub digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieval_url: Option<String>,
}

/// Digest-pinned reducer contract plus its declared lattice and concurrency
/// semantics. Implementations MUST NOT guess the class from the kind name.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReducerContractRef {
    pub reducer_contract_id: String,
    pub digest: Hash,
    pub lattice_profile_ref: String,
    pub concurrency_class: ConcurrencyClass,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestResourceLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_canonical_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_item_count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_operation_count_per_minute: Option<u32>,
}

impl ManifestResourceLimits {
    pub fn is_empty(&self) -> bool {
        self.max_canonical_bytes.is_none()
            && self.max_item_count.is_none()
            && self.max_depth.is_none()
            && self.max_operation_count_per_minute.is_none()
    }
}

/// Declarative description of one Collaboration Base or Extension package.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionManifest {
    pub manifest_id: String,
    pub extension_id: String,
    pub namespace: String,
    pub protocol_layer_kind: ProtocolLayerKind,
    pub manifest_digest: Hash,
    pub publisher_id: Did,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub published_at: DateTime<Utc>,
    pub dependency_refs: Vec<RegistryContentRef>,
    pub payload_schema_refs: Vec<RegistryContentRef>,
    pub reducer_contract_refs: Vec<ReducerContractRef>,
    pub required_actions: Vec<String>,
    pub confidentiality_class: ConfidentialityClass,
    pub transport_rail_ids: Vec<String>,
    pub recovery_profile_ref: Option<String>,
    pub federation_profile_ref: Option<String>,
    pub conformance_vector_refs: Vec<RegistryContentRef>,
    pub resource_limits: ManifestResourceLimits,
    pub proofs: Vec<Proof>,
}

fn validate_bound(name: &str, len: usize, max: usize) -> Result<()> {
    if len > max {
        return Err(Error::Protocol(format!(
            "extension manifest {name} exceeds {max} entries"
        )));
    }
    Ok(())
}

impl ExtensionManifest {
    /// `sha256(canonical_json(manifest_without_manifest_digest_and_proofs))`
    /// (`extension-manifest.md` §1). The digest never recursively contains
    /// itself or the proofs that cover it.
    pub fn expected_manifest_digest(&self) -> Result<Hash> {
        let mut json = serde_json::to_value(self)?;
        if let serde_json::Value::Object(map) = &mut json {
            map.remove("manifest_digest");
            map.remove("proofs");
        }
        Ok(Hash::new(crate::canonical::canonical_sha256(&json)?)?)
    }

    pub fn validate_structural(&self) -> Result<()> {
        validate_bound(
            "dependency_refs",
            self.dependency_refs.len(),
            MAX_MANIFEST_DEPENDENCY_REFS,
        )?;
        validate_bound(
            "payload_schema_refs",
            self.payload_schema_refs.len(),
            MAX_MANIFEST_PAYLOAD_SCHEMA_REFS,
        )?;
        validate_bound(
            "reducer_contract_refs",
            self.reducer_contract_refs.len(),
            MAX_MANIFEST_REDUCER_CONTRACT_REFS,
        )?;
        validate_bound(
            "required_actions",
            self.required_actions.len(),
            MAX_MANIFEST_REQUIRED_ACTIONS,
        )?;
        validate_bound(
            "transport_rail_ids",
            self.transport_rail_ids.len(),
            MAX_MANIFEST_TRANSPORT_RAIL_IDS,
        )?;
        validate_bound(
            "conformance_vector_refs",
            self.conformance_vector_refs.len(),
            MAX_MANIFEST_CONFORMANCE_VECTOR_REFS,
        )?;
        if self.conformance_vector_refs.is_empty() {
            return Err(Error::Protocol(
                "extension manifest must declare at least one conformance vector".to_owned(),
            ));
        }
        if self.proofs.is_empty() || self.proofs.len() > MAX_MANIFEST_PROOFS {
            return Err(Error::Protocol(format!(
                "extension manifest requires 1..={MAX_MANIFEST_PROOFS} proofs"
            )));
        }
        if self.resource_limits.is_empty() {
            return Err(Error::Protocol(
                "extension manifest must declare at least one resource limit".to_owned(),
            ));
        }
        if self.manifest_digest != self.expected_manifest_digest()? {
            return Err(Error::Protocol(
                "extension manifest_digest does not match its canonical content".to_owned(),
            ));
        }
        for proof in &self.proofs {
            proof.validate()?;
            if proof.event_digest != self.manifest_digest {
                return Err(Error::Protocol(
                    "extension manifest proof does not cover manifest_digest".to_owned(),
                ));
            }
            if proof.created_at != self.published_at {
                return Err(Error::Protocol(
                    "extension manifest proof created_at must equal published_at".to_owned(),
                ));
            }
        }
        Ok(())
    }
}
