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

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{Result, WireError};
use crate::primitives::ProducerEventProof;
use crate::{DidCoreId, Hash, ProofContextId};

pub const MAX_MANIFEST_DEPENDENCY_REFS: usize = 64;
pub const MAX_MANIFEST_PAYLOAD_SCHEMA_REFS: usize = 256;
pub const MAX_MANIFEST_REDUCER_CONTRACT_REFS: usize = 256;
pub const MAX_MANIFEST_REQUIRED_ACTIONS: usize = 256;
pub const MAX_MANIFEST_TRANSPORT_RAIL_IDS: usize = 32;
pub const MAX_MANIFEST_CONFORMANCE_VECTOR_REFS: usize = 512;
pub const MAX_MANIFEST_PROOFS: usize = 16;
pub const MAX_MANIFEST_CANONICAL_BYTES: u32 = 8_388_608;
pub const MAX_MANIFEST_ITEM_COUNT: u32 = 4_096;
pub const MAX_MANIFEST_DEPTH: u32 = 4_096;
pub const MAX_MANIFEST_OPERATIONS_PER_MINUTE: u32 = 100_000;

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
    pub publisher_id: DidCoreId,
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
    pub proofs: Vec<ProducerEventProof>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestDependencyLayer {
    Kernel,
    CollaborationBase,
    Extension,
}

impl From<ProtocolLayerKind> for ManifestDependencyLayer {
    fn from(value: ProtocolLayerKind) -> Self {
        match value {
            ProtocolLayerKind::CollaborationBase => Self::CollaborationBase,
            ProtocolLayerKind::Extension => Self::Extension,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestRegistryContentKind {
    Dependency(ManifestDependencyLayer),
    PayloadSchema,
    ReducerContract {
        lattice_profile_ref: String,
        concurrency_class: ConcurrencyClass,
    },
    ConformanceVector,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestRegistryContent {
    pub digest: Hash,
    pub kind: ManifestRegistryContentKind,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtensionManifestCatalog {
    pub content: BTreeMap<String, ManifestRegistryContent>,
    pub action_ids: BTreeSet<String>,
    pub transport_rail_ids: BTreeSet<String>,
    pub lattice_profile_ids: BTreeSet<String>,
    pub recovery_profile_ids: BTreeSet<String>,
    pub federation_profile_ids: BTreeSet<String>,
    pub passing_vector_ids: BTreeSet<String>,
    pub reserved_namespaces: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestKernelLimits {
    pub max_canonical_bytes: u32,
    pub max_item_count: u32,
    pub max_depth: u32,
    pub max_operation_count_per_minute: u32,
}

impl Default for ManifestKernelLimits {
    fn default() -> Self {
        Self {
            max_canonical_bytes: MAX_MANIFEST_CANONICAL_BYTES,
            max_item_count: MAX_MANIFEST_ITEM_COUNT,
            max_depth: MAX_MANIFEST_DEPTH,
            max_operation_count_per_minute: MAX_MANIFEST_OPERATIONS_PER_MINUTE,
        }
    }
}

pub trait ExtensionManifestProofVerifier {
    fn verify(
        &self,
        publisher_id: &DidCoreId,
        verification_method: &str,
        signing_bytes: &[u8],
        detached_jws: &str,
    ) -> Result<()>;
}

#[derive(Clone, Debug, PartialEq)]
pub struct LoadedExtensionManifests {
    pub manifests: BTreeMap<String, ExtensionManifest>,
    pub topological_manifest_ids: Vec<String>,
}

fn validate_bound(name: &str, len: usize, max: usize) -> Result<()> {
    if len > max {
        return Err(WireError::Protocol(format!(
            "extension manifest {name} exceeds {max} entries"
        )));
    }
    Ok(())
}

fn validate_unique<T: Serialize>(name: &str, values: &[T]) -> Result<()> {
    let mut canonical_values = BTreeSet::new();
    for value in values {
        let bytes = crate::canonical::canonical_json_bytes(value)?;
        if !canonical_values.insert(bytes) {
            return Err(WireError::Protocol(format!(
                "extension manifest {name} contains duplicate entries"
            )));
        }
    }
    Ok(())
}

fn validate_unique_ids<'a>(name: &str, values: impl IntoIterator<Item = &'a str>) -> Result<()> {
    let mut ids = BTreeSet::new();
    for value in values {
        if !ids.insert(value) {
            return Err(WireError::Protocol(format!(
                "extension manifest {name} contains duplicate registry identities"
            )));
        }
    }
    Ok(())
}

fn valid_symbol_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn validate_versioned_symbol(name: &str, value: &str, prefix: &str) -> Result<()> {
    let Some(body) = value
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(".v1"))
    else {
        return Err(WireError::Protocol(format!(
            "extension manifest {name} must use a versioned {prefix}*.v1 symbol"
        )));
    };
    if !body.split('.').all(valid_symbol_segment) {
        return Err(WireError::Protocol(format!(
            "extension manifest {name} contains an invalid registry symbol"
        )));
    }
    Ok(())
}

fn validate_registry_symbol(name: &str, value: &str) -> Result<()> {
    validate_versioned_symbol(name, value, "ak.")
}

fn validate_ak_symbol(name: &str, value: &str) -> Result<()> {
    let Some(body) = value.strip_prefix("ak.") else {
        return Err(WireError::Protocol(format!(
            "extension manifest {name} must start with ak."
        )));
    };
    if !body.split('.').all(valid_symbol_segment) {
        return Err(WireError::Protocol(format!(
            "extension manifest {name} contains an invalid symbol"
        )));
    }
    Ok(())
}

fn validate_namespace(namespace: &str) -> Result<()> {
    let Some(body) = namespace.strip_prefix("ak.") else {
        return Err(WireError::Protocol(
            "extension manifest namespace must start with ak.".to_owned(),
        ));
    };
    if !body.split('.').all(valid_symbol_segment) {
        return Err(WireError::Protocol(
            "extension manifest namespace contains an invalid segment".to_owned(),
        ));
    }
    Ok(())
}

fn validate_content_ref(name: &str, reference: &RegistryContentRef) -> Result<()> {
    validate_registry_symbol(name, &reference.registry_id)?;
    if let Some(url) = &reference.retrieval_url {
        url::Url::parse(url).map_err(|error| {
            WireError::Protocol(format!(
                "extension manifest {name} retrieval_url is invalid: {error}"
            ))
        })?;
    }
    Ok(())
}

fn validate_non_zero_limit(name: &str, value: Option<u32>, maximum: u32) -> Result<()> {
    if let Some(value) = value
        && (value == 0 || value > maximum)
    {
        return Err(WireError::Protocol(format!(
            "extension manifest resource limit {name} must be within 1..={maximum}"
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
        if let Value::Object(map) = &mut json {
            map.remove("manifest_digest");
            map.remove("proofs");
        }
        Ok(Hash::new(crate::canonical::canonical_sha256(&json)?)?)
    }

    pub fn expected_namespace(&self) -> Result<String> {
        validate_versioned_symbol("extension_id", &self.extension_id, "ak.extension.")?;
        let body = self
            .extension_id
            .strip_prefix("ak.extension.")
            .and_then(|value| value.strip_suffix(".v1"))
            .expect("validated extension id shape");
        Ok(format!("ak.{body}"))
    }

    pub fn proof_signing_bytes(&self, proof: &ProducerEventProof) -> Result<Vec<u8>> {
        let mut object = Map::new();
        object.insert(
            "context".to_owned(),
            Value::String(ProofContextId::EXTENSION_MANIFEST_PROOF_V1.to_owned()),
        );
        object.insert(
            "payload_digest".to_owned(),
            Value::String(self.manifest_digest.as_str().to_owned()),
        );
        object.insert(
            "extension_id".to_owned(),
            Value::String(self.extension_id.clone()),
        );
        object.insert(
            "publisher_id".to_owned(),
            Value::String(self.publisher_id.as_str().to_owned()),
        );
        object.insert(
            "verification_method".to_owned(),
            Value::String(proof.verification_method.as_str().to_owned()),
        );
        object.insert(
            "created_at".to_owned(),
            Value::String(crate::canonical::format_timestamp_canonical(
                proof.created_at,
            )),
        );
        if let Some(domain) = &proof.domain {
            object.insert("domain".to_owned(), Value::String(domain.clone()));
        }
        if let Some(audience) = &proof.audience {
            object.insert("audience".to_owned(), serde_json::to_value(audience)?);
        }
        crate::canonical::canonical_json_bytes(&Value::Object(object)).map_err(Into::into)
    }

    pub fn validate_structural(&self) -> Result<()> {
        validate_versioned_symbol("manifest_id", &self.manifest_id, "ak.manifest.")?;
        validate_versioned_symbol("extension_id", &self.extension_id, "ak.extension.")?;
        validate_namespace(&self.namespace)?;
        if self.namespace != self.expected_namespace()? {
            return Err(WireError::Protocol(
                "extension manifest namespace is not bound to extension_id".to_owned(),
            ));
        }
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
        validate_unique("dependency_refs", &self.dependency_refs)?;
        validate_unique("payload_schema_refs", &self.payload_schema_refs)?;
        validate_unique("reducer_contract_refs", &self.reducer_contract_refs)?;
        validate_unique("required_actions", &self.required_actions)?;
        validate_unique("transport_rail_ids", &self.transport_rail_ids)?;
        validate_unique("conformance_vector_refs", &self.conformance_vector_refs)?;
        validate_unique("proofs", &self.proofs)?;
        validate_unique_ids(
            "dependency_refs",
            self.dependency_refs
                .iter()
                .map(|reference| reference.registry_id.as_str()),
        )?;
        validate_unique_ids(
            "payload_schema_refs",
            self.payload_schema_refs
                .iter()
                .map(|reference| reference.registry_id.as_str()),
        )?;
        validate_unique_ids(
            "reducer_contract_refs",
            self.reducer_contract_refs
                .iter()
                .map(|reference| reference.reducer_contract_id.as_str()),
        )?;
        validate_unique_ids(
            "conformance_vector_refs",
            self.conformance_vector_refs
                .iter()
                .map(|reference| reference.registry_id.as_str()),
        )?;
        for reference in &self.dependency_refs {
            validate_content_ref("dependency_refs[]", reference)?;
        }
        for reference in &self.payload_schema_refs {
            validate_content_ref("payload_schema_refs[]", reference)?;
        }
        for reference in &self.conformance_vector_refs {
            validate_content_ref("conformance_vector_refs[]", reference)?;
        }
        for reference in &self.reducer_contract_refs {
            validate_registry_symbol(
                "reducer_contract_refs[].reducer_contract_id",
                &reference.reducer_contract_id,
            )?;
            validate_versioned_symbol(
                "reducer_contract_refs[].lattice_profile_ref",
                &reference.lattice_profile_ref,
                "ak.profile.",
            )?;
        }
        for action in &self.required_actions {
            validate_ak_symbol("required_actions[]", action)?;
        }
        for rail in &self.transport_rail_ids {
            validate_ak_symbol("transport_rail_ids[]", rail)?;
        }
        if let Some(profile) = &self.recovery_profile_ref {
            validate_versioned_symbol("recovery_profile_ref", profile, "ak.profile.")?;
        }
        if let Some(profile) = &self.federation_profile_ref {
            validate_versioned_symbol("federation_profile_ref", profile, "ak.profile.")?;
        }
        if self.conformance_vector_refs.is_empty() {
            return Err(WireError::Protocol(
                "extension manifest must declare at least one conformance vector".to_owned(),
            ));
        }
        if self.proofs.is_empty() || self.proofs.len() > MAX_MANIFEST_PROOFS {
            return Err(WireError::Protocol(format!(
                "extension manifest requires 1..={MAX_MANIFEST_PROOFS} proofs"
            )));
        }
        if self.resource_limits.is_empty() {
            return Err(WireError::Protocol(
                "extension manifest must declare at least one resource limit".to_owned(),
            ));
        }
        validate_non_zero_limit(
            "max_canonical_bytes",
            self.resource_limits.max_canonical_bytes,
            MAX_MANIFEST_CANONICAL_BYTES,
        )?;
        validate_non_zero_limit(
            "max_item_count",
            self.resource_limits.max_item_count,
            MAX_MANIFEST_ITEM_COUNT,
        )?;
        validate_non_zero_limit(
            "max_depth",
            self.resource_limits.max_depth,
            MAX_MANIFEST_DEPTH,
        )?;
        validate_non_zero_limit(
            "max_operation_count_per_minute",
            self.resource_limits.max_operation_count_per_minute,
            MAX_MANIFEST_OPERATIONS_PER_MINUTE,
        )?;
        if self.manifest_digest != self.expected_manifest_digest()? {
            return Err(WireError::Protocol(
                "extension manifest_digest does not match its canonical content".to_owned(),
            ));
        }
        for proof in &self.proofs {
            proof.validate()?;
            if proof.event_digest != self.manifest_digest {
                return Err(WireError::Protocol(
                    "extension manifest proof does not cover manifest_digest".to_owned(),
                ));
            }
            if proof.created_at != self.published_at {
                return Err(WireError::Protocol(
                    "extension manifest proof created_at must equal published_at".to_owned(),
                ));
            }
            if proof.proof_purpose.is_some() {
                return Err(WireError::Protocol(
                    "extension manifest proof must not carry Event payload proof_purpose"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

fn require_content<'a>(
    catalog: &'a ExtensionManifestCatalog,
    reference: &RegistryContentRef,
    expected_kind: ManifestRegistryContentKind,
) -> Result<&'a ManifestRegistryContent> {
    let content = catalog.content.get(&reference.registry_id).ok_or_else(|| {
        WireError::Protocol(format!(
            "extension manifest reference {} is missing from the active registry catalog",
            reference.registry_id
        ))
    })?;
    if content.digest != reference.digest || content.kind != expected_kind {
        return Err(WireError::Protocol(format!(
            "extension manifest reference {} has a digest or registry-kind mismatch",
            reference.registry_id
        )));
    }
    Ok(content)
}

fn enforce_kernel_limits(
    limits: &ManifestResourceLimits,
    kernel_limits: ManifestKernelLimits,
) -> Result<()> {
    for (name, declared, maximum) in [
        (
            "max_canonical_bytes",
            limits.max_canonical_bytes,
            kernel_limits.max_canonical_bytes,
        ),
        (
            "max_item_count",
            limits.max_item_count,
            kernel_limits.max_item_count,
        ),
        ("max_depth", limits.max_depth, kernel_limits.max_depth),
        (
            "max_operation_count_per_minute",
            limits.max_operation_count_per_minute,
            kernel_limits.max_operation_count_per_minute,
        ),
    ] {
        if declared.is_some_and(|value| value > maximum) {
            return Err(WireError::Protocol(format!(
                "extension manifest resource limit {name} exceeds the configured Kernel hard limit"
            )));
        }
    }
    Ok(())
}

pub fn load_extension_manifests(
    manifests: &[ExtensionManifest],
    catalog: &ExtensionManifestCatalog,
    kernel_limits: ManifestKernelLimits,
    proof_verifier: &impl ExtensionManifestProofVerifier,
) -> Result<LoadedExtensionManifests> {
    let mut by_id = BTreeMap::new();
    let mut extension_ids = BTreeSet::new();
    let mut namespaces = catalog.reserved_namespaces.clone();
    for manifest in manifests {
        manifest.validate_structural()?;
        if !extension_ids.insert(manifest.extension_id.clone()) {
            return Err(WireError::Protocol(format!(
                "extension id {} is declared more than once",
                manifest.extension_id
            )));
        }
        if !namespaces.insert(manifest.namespace.clone()) {
            return Err(WireError::Protocol(format!(
                "extension namespace {} is not unique",
                manifest.namespace
            )));
        }
        if by_id
            .insert(manifest.manifest_id.clone(), manifest.clone())
            .is_some()
        {
            return Err(WireError::Protocol(format!(
                "extension manifest id {} is declared more than once",
                manifest.manifest_id
            )));
        }
    }

    let mut outgoing: BTreeMap<String, BTreeSet<String>> = by_id
        .keys()
        .cloned()
        .map(|manifest_id| (manifest_id, BTreeSet::new()))
        .collect();
    let mut indegree: BTreeMap<String, usize> = by_id
        .keys()
        .cloned()
        .map(|manifest_id| (manifest_id, 0))
        .collect();

    for manifest in by_id.values() {
        for dependency in &manifest.dependency_refs {
            let Some(dependency_manifest) = by_id.get(&dependency.registry_id) else {
                continue;
            };
            if manifest.protocol_layer_kind == ProtocolLayerKind::CollaborationBase
                && dependency_manifest.protocol_layer_kind == ProtocolLayerKind::Extension
            {
                return Err(WireError::Protocol(
                    "Collaboration Base cannot depend on an Extension".to_owned(),
                ));
            }
            outgoing
                .get_mut(&dependency.registry_id)
                .expect("dependency manifest is indexed")
                .insert(manifest.manifest_id.clone());
            *indegree
                .get_mut(&manifest.manifest_id)
                .expect("manifest indegree is indexed") += 1;
        }
    }

    let mut ready: BTreeSet<String> = indegree
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(manifest_id, _)| manifest_id.clone())
        .collect();
    let mut topological_manifest_ids = Vec::with_capacity(by_id.len());
    while let Some(manifest_id) = ready.pop_first() {
        topological_manifest_ids.push(manifest_id.clone());
        for dependent in outgoing
            .get(&manifest_id)
            .expect("manifest dependency edges are indexed")
        {
            let count = indegree
                .get_mut(dependent)
                .expect("dependent manifest indegree is indexed");
            *count -= 1;
            if *count == 0 {
                ready.insert(dependent.clone());
            }
        }
    }
    if topological_manifest_ids.len() != by_id.len() {
        return Err(WireError::Protocol(
            "extension manifest dependency graph contains a cycle".to_owned(),
        ));
    }

    for manifest in by_id.values() {
        enforce_kernel_limits(&manifest.resource_limits, kernel_limits)?;
        for proof in &manifest.proofs {
            proof.validate_production()?;
            let signing_bytes = manifest.proof_signing_bytes(proof)?;
            proof_verifier.verify(
                &manifest.publisher_id,
                &proof.verification_method,
                &signing_bytes,
                &proof.jws,
            )?;
        }
        for reference in &manifest.payload_schema_refs {
            require_content(
                catalog,
                reference,
                ManifestRegistryContentKind::PayloadSchema,
            )?;
        }
        for reference in &manifest.reducer_contract_refs {
            let content_reference = RegistryContentRef {
                registry_id: reference.reducer_contract_id.clone(),
                digest: reference.digest.clone(),
                retrieval_url: None,
            };
            require_content(
                catalog,
                &content_reference,
                ManifestRegistryContentKind::ReducerContract {
                    lattice_profile_ref: reference.lattice_profile_ref.clone(),
                    concurrency_class: reference.concurrency_class,
                },
            )?;
            if !catalog
                .lattice_profile_ids
                .contains(&reference.lattice_profile_ref)
            {
                return Err(WireError::Protocol(format!(
                    "extension reducer {} references an unavailable lattice profile",
                    reference.reducer_contract_id
                )));
            }
        }
        for action in &manifest.required_actions {
            if !catalog.action_ids.contains(action) {
                return Err(WireError::Protocol(format!(
                    "extension manifest requires unavailable action {action}"
                )));
            }
        }
        for rail in &manifest.transport_rail_ids {
            if !catalog.transport_rail_ids.contains(rail) {
                return Err(WireError::Protocol(format!(
                    "extension manifest references unavailable transport rail {rail}"
                )));
            }
        }
        if manifest
            .recovery_profile_ref
            .as_ref()
            .is_some_and(|profile| !catalog.recovery_profile_ids.contains(profile))
        {
            return Err(WireError::Protocol(
                "extension manifest references an unavailable recovery profile".to_owned(),
            ));
        }
        if manifest
            .federation_profile_ref
            .as_ref()
            .is_some_and(|profile| !catalog.federation_profile_ids.contains(profile))
        {
            return Err(WireError::Protocol(
                "extension manifest references an unavailable federation profile".to_owned(),
            ));
        }
        for reference in &manifest.conformance_vector_refs {
            require_content(
                catalog,
                reference,
                ManifestRegistryContentKind::ConformanceVector,
            )?;
            if !catalog.passing_vector_ids.contains(&reference.registry_id) {
                return Err(WireError::Protocol(format!(
                    "extension conformance vector {} has not passed",
                    reference.registry_id
                )));
            }
        }

        for dependency in &manifest.dependency_refs {
            if let Some(dependency_manifest) = by_id.get(&dependency.registry_id) {
                if dependency_manifest.manifest_digest != dependency.digest {
                    return Err(WireError::Protocol(format!(
                        "extension manifest dependency {} has a digest mismatch",
                        dependency.registry_id
                    )));
                }
                if manifest.protocol_layer_kind == ProtocolLayerKind::CollaborationBase
                    && dependency_manifest.protocol_layer_kind == ProtocolLayerKind::Extension
                {
                    return Err(WireError::Protocol(
                        "Collaboration Base cannot depend on an Extension".to_owned(),
                    ));
                }
                continue;
            }

            let content = catalog
                .content
                .get(&dependency.registry_id)
                .ok_or_else(|| {
                    WireError::Protocol(format!(
                        "extension manifest dependency {} is missing",
                        dependency.registry_id
                    ))
                })?;
            if content.digest != dependency.digest {
                return Err(WireError::Protocol(format!(
                    "extension manifest dependency {} has a digest mismatch",
                    dependency.registry_id
                )));
            }
            let ManifestRegistryContentKind::Dependency(layer) = content.kind else {
                return Err(WireError::Protocol(format!(
                    "extension manifest dependency {} does not name a dependency package",
                    dependency.registry_id
                )));
            };
            if manifest.protocol_layer_kind == ProtocolLayerKind::CollaborationBase
                && layer == ManifestDependencyLayer::Extension
            {
                return Err(WireError::Protocol(
                    "Collaboration Base cannot depend on an Extension".to_owned(),
                ));
            }
        }
    }

    Ok(LoadedExtensionManifests {
        manifests: by_id,
        topological_manifest_ids,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::DidUrl;
    use crate::test_support::DETACHED_JWS_FIXTURE;

    struct TestProofVerifier {
        calls: AtomicUsize,
        reject: bool,
    }

    impl ExtensionManifestProofVerifier for TestProofVerifier {
        fn verify(
            &self,
            publisher_id: &DidCoreId,
            verification_method: &str,
            signing_bytes: &[u8],
            detached_jws: &str,
        ) -> Result<()> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            assert_eq!(publisher_id.as_str(), "ak:did_core:web:publisher.example");
            assert_eq!(
                verification_method,
                "did:web:publisher.example#manifest-signing"
            );
            assert_eq!(detached_jws, DETACHED_JWS_FIXTURE);
            let value: Value = crate::canonical::from_canonical_json_slice(signing_bytes)?;
            assert_eq!(
                value["context"],
                Value::String(ProofContextId::EXTENSION_MANIFEST_PROOF_V1.to_owned())
            );
            if self.reject {
                return Err(WireError::Protocol(
                    "publisher signature verification failed".to_owned(),
                ));
            }
            Ok(())
        }
    }

    fn hash(seed: u64) -> Hash {
        Hash::new(format!("sha256:{seed:064x}")).expect("fixture hash")
    }

    fn content_ref(registry_id: &str, digest: Hash) -> RegistryContentRef {
        RegistryContentRef {
            registry_id: registry_id.to_owned(),
            digest,
            retrieval_url: None,
        }
    }

    fn manifest(
        name: &str,
        layer: ProtocolLayerKind,
        dependency_refs: Vec<RegistryContentRef>,
        seed: u64,
    ) -> ExtensionManifest {
        let published_at = "2026-07-29T00:00:00Z".parse().expect("fixture timestamp");
        let mut manifest = ExtensionManifest {
            manifest_id: format!("ak.manifest.{name}.v1"),
            extension_id: format!("ak.extension.{name}.v1"),
            namespace: format!("ak.{name}"),
            protocol_layer_kind: layer,
            manifest_digest: hash(0),
            publisher_id: DidCoreId::new("ak:did_core:web:publisher.example".to_owned())
                .expect("fixture DID"),
            published_at,
            dependency_refs,
            payload_schema_refs: vec![content_ref(&format!("ak.schema.{name}.v1"), hash(seed + 1))],
            reducer_contract_refs: vec![ReducerContractRef {
                reducer_contract_id: format!("ak.reducer.{name}.v1"),
                digest: hash(seed + 2),
                lattice_profile_ref: "ak.profile.lattice.orset.v1".to_owned(),
                concurrency_class: ConcurrencyClass::MergeSafe,
            }],
            required_actions: vec![format!("ak.{name}.read")],
            confidentiality_class: ConfidentialityClass::E2eeRequired,
            transport_rail_ids: vec!["ak.rail.http_json.v1".to_owned()],
            recovery_profile_ref: Some("ak.profile.recovery.default.v1".to_owned()),
            federation_profile_ref: Some("ak.profile.federation.default.v1".to_owned()),
            conformance_vector_refs: vec![content_ref(
                &format!("ak.vector.{name}.v1"),
                hash(seed + 3),
            )],
            resource_limits: ManifestResourceLimits {
                max_canonical_bytes: Some(1_048_576),
                max_item_count: Some(512),
                max_depth: Some(64),
                max_operation_count_per_minute: Some(1_000),
            },
            proofs: vec![ProducerEventProof {
                kind: crate::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new("did:web:publisher.example#manifest-signing")
                    .unwrap(),
                event_digest: hash(0),
                signer_resolution_evidence_ref: None,
                signer_resolution_evidence_digest: None,
                created_at: published_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: DETACHED_JWS_FIXTURE.to_owned(),
            }],
        };
        manifest.manifest_digest = manifest
            .expected_manifest_digest()
            .expect("manifest digest");
        manifest.proofs[0].event_digest = manifest.manifest_digest.clone();
        manifest
    }

    fn add_manifest_content(catalog: &mut ExtensionManifestCatalog, manifest: &ExtensionManifest) {
        for reference in &manifest.payload_schema_refs {
            catalog.content.insert(
                reference.registry_id.clone(),
                ManifestRegistryContent {
                    digest: reference.digest.clone(),
                    kind: ManifestRegistryContentKind::PayloadSchema,
                },
            );
        }
        for reference in &manifest.reducer_contract_refs {
            catalog.content.insert(
                reference.reducer_contract_id.clone(),
                ManifestRegistryContent {
                    digest: reference.digest.clone(),
                    kind: ManifestRegistryContentKind::ReducerContract {
                        lattice_profile_ref: reference.lattice_profile_ref.clone(),
                        concurrency_class: reference.concurrency_class,
                    },
                },
            );
        }
        for reference in &manifest.conformance_vector_refs {
            catalog.content.insert(
                reference.registry_id.clone(),
                ManifestRegistryContent {
                    digest: reference.digest.clone(),
                    kind: ManifestRegistryContentKind::ConformanceVector,
                },
            );
            catalog
                .passing_vector_ids
                .insert(reference.registry_id.clone());
        }
        catalog
            .action_ids
            .extend(manifest.required_actions.iter().cloned());
        catalog
            .transport_rail_ids
            .extend(manifest.transport_rail_ids.iter().cloned());
        catalog.lattice_profile_ids.extend(
            manifest
                .reducer_contract_refs
                .iter()
                .map(|reference| reference.lattice_profile_ref.clone()),
        );
        if let Some(profile) = &manifest.recovery_profile_ref {
            catalog.recovery_profile_ids.insert(profile.clone());
        }
        if let Some(profile) = &manifest.federation_profile_ref {
            catalog.federation_profile_ids.insert(profile.clone());
        }
    }

    fn valid_manifest_set() -> (
        Vec<ExtensionManifest>,
        ExtensionManifestCatalog,
        TestProofVerifier,
    ) {
        let kernel_digest = hash(10);
        let base = manifest(
            "collaboration_base",
            ProtocolLayerKind::CollaborationBase,
            vec![content_ref("ak.kernel.core.v1", kernel_digest.clone())],
            100,
        );
        let extension = manifest(
            "calendar",
            ProtocolLayerKind::Extension,
            vec![content_ref(&base.manifest_id, base.manifest_digest.clone())],
            200,
        );
        let mut catalog = ExtensionManifestCatalog::default();
        catalog.content.insert(
            "ak.kernel.core.v1".to_owned(),
            ManifestRegistryContent {
                digest: kernel_digest,
                kind: ManifestRegistryContentKind::Dependency(ManifestDependencyLayer::Kernel),
            },
        );
        add_manifest_content(&mut catalog, &base);
        add_manifest_content(&mut catalog, &extension);
        (
            vec![extension, base],
            catalog,
            TestProofVerifier {
                calls: AtomicUsize::new(0),
                reject: false,
            },
        )
    }

    #[test]
    fn loader_admits_digest_pinned_dependency_closure_in_topological_order() {
        let (manifests, catalog, verifier) = valid_manifest_set();

        let loaded = load_extension_manifests(
            &manifests,
            &catalog,
            ManifestKernelLimits::default(),
            &verifier,
        )
        .expect("valid manifest closure");

        assert_eq!(
            loaded.topological_manifest_ids,
            vec![
                "ak.manifest.collaboration_base.v1",
                "ak.manifest.calendar.v1"
            ]
        );
        assert_eq!(loaded.manifests.len(), 2);
        assert_eq!(verifier.calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn loader_rejects_unverified_publisher_proof() {
        let (manifests, catalog, _) = valid_manifest_set();
        let verifier = TestProofVerifier {
            calls: AtomicUsize::new(0),
            reject: true,
        };

        let error = load_extension_manifests(
            &manifests,
            &catalog,
            ManifestKernelLimits::default(),
            &verifier,
        )
        .expect_err("invalid proof must fail closed");

        assert!(error.to_string().contains("signature verification failed"));
    }

    #[test]
    fn loader_rejects_namespace_collision_and_unpassed_vector() {
        let (manifests, mut catalog, verifier) = valid_manifest_set();
        catalog.reserved_namespaces.insert("ak.calendar".to_owned());
        let collision = load_extension_manifests(
            &manifests,
            &catalog,
            ManifestKernelLimits::default(),
            &verifier,
        )
        .expect_err("reserved namespace must fail closed");
        assert!(collision.to_string().contains("not unique"));

        catalog.reserved_namespaces.clear();
        catalog.passing_vector_ids.remove("ak.vector.calendar.v1");
        let vector = load_extension_manifests(
            &manifests,
            &catalog,
            ManifestKernelLimits::default(),
            &verifier,
        )
        .expect_err("unpassed vector must prevent advertising");
        assert!(vector.to_string().contains("has not passed"));
    }

    #[test]
    fn loader_rejects_dependency_cycles_and_layer_inversion() {
        let mut first = manifest("first", ProtocolLayerKind::Extension, Vec::new(), 300);
        let mut second = manifest("second", ProtocolLayerKind::Extension, Vec::new(), 400);
        first.dependency_refs = vec![content_ref(
            &second.manifest_id,
            second.manifest_digest.clone(),
        )];
        first.manifest_digest = first.expected_manifest_digest().expect("first digest");
        first.proofs[0].event_digest = first.manifest_digest.clone();
        second.dependency_refs = vec![content_ref(
            &first.manifest_id,
            first.manifest_digest.clone(),
        )];
        second.manifest_digest = second.expected_manifest_digest().expect("second digest");
        second.proofs[0].event_digest = second.manifest_digest.clone();
        first.dependency_refs[0].digest = second.manifest_digest.clone();
        first.manifest_digest = first
            .expected_manifest_digest()
            .expect("closed first digest");
        first.proofs[0].event_digest = first.manifest_digest.clone();
        second.dependency_refs[0].digest = first.manifest_digest.clone();
        second.manifest_digest = second
            .expected_manifest_digest()
            .expect("closed second digest");
        second.proofs[0].event_digest = second.manifest_digest.clone();
        first.dependency_refs[0].digest = second.manifest_digest.clone();
        first.manifest_digest = first
            .expected_manifest_digest()
            .expect("final first digest");
        first.proofs[0].event_digest = first.manifest_digest.clone();

        let mut catalog = ExtensionManifestCatalog::default();
        add_manifest_content(&mut catalog, &first);
        add_manifest_content(&mut catalog, &second);
        let verifier = TestProofVerifier {
            calls: AtomicUsize::new(0),
            reject: false,
        };
        let cycle = load_extension_manifests(
            &[first, second],
            &catalog,
            ManifestKernelLimits::default(),
            &verifier,
        )
        .expect_err("dependency cycle must fail closed");
        assert!(cycle.to_string().contains("cycle"));

        let extension_digest = hash(500);
        let base = manifest(
            "base",
            ProtocolLayerKind::CollaborationBase,
            vec![content_ref(
                "ak.extension_dependency.optional.v1",
                extension_digest.clone(),
            )],
            500,
        );
        let mut catalog = ExtensionManifestCatalog::default();
        add_manifest_content(&mut catalog, &base);
        catalog.content.insert(
            "ak.extension_dependency.optional.v1".to_owned(),
            ManifestRegistryContent {
                digest: extension_digest,
                kind: ManifestRegistryContentKind::Dependency(ManifestDependencyLayer::Extension),
            },
        );
        let inversion = load_extension_manifests(
            &[base],
            &catalog,
            ManifestKernelLimits::default(),
            &verifier,
        )
        .expect_err("layer inversion must fail closed");
        assert!(inversion.to_string().contains("cannot depend"));
    }

    #[test]
    fn loader_rejects_registry_kind_mismatch_and_local_limit_overflow() {
        let (manifests, mut catalog, verifier) = valid_manifest_set();
        catalog
            .content
            .get_mut("ak.schema.calendar.v1")
            .expect("calendar schema")
            .kind = ManifestRegistryContentKind::ReducerContract {
            lattice_profile_ref: "ak.profile.lattice.orset.v1".to_owned(),
            concurrency_class: ConcurrencyClass::MergeSafe,
        };
        let kind = load_extension_manifests(
            &manifests,
            &catalog,
            ManifestKernelLimits::default(),
            &verifier,
        )
        .expect_err("registry kind mismatch must fail closed");
        assert!(kind.to_string().contains("registry-kind mismatch"));

        catalog
            .content
            .get_mut("ak.schema.calendar.v1")
            .expect("calendar schema")
            .kind = ManifestRegistryContentKind::PayloadSchema;
        let limit = load_extension_manifests(
            &manifests,
            &catalog,
            ManifestKernelLimits {
                max_canonical_bytes: 512,
                ..ManifestKernelLimits::default()
            },
            &verifier,
        )
        .expect_err("deployment hard limit must fail closed");
        assert!(limit.to_string().contains("Kernel hard limit"));
    }

    #[test]
    fn structural_validation_rejects_non_schema_values() {
        let mut manifest = manifest("calendar", ProtocolLayerKind::Extension, Vec::new(), 600);
        manifest
            .required_actions
            .push("ak.calendar.read".to_owned());
        manifest.manifest_digest = manifest
            .expected_manifest_digest()
            .expect("manifest digest");
        manifest.proofs[0].event_digest = manifest.manifest_digest.clone();
        let duplicate = manifest
            .validate_structural()
            .expect_err("duplicate actions must fail closed");
        assert!(duplicate.to_string().contains("duplicate"));

        manifest.required_actions.pop();
        manifest.payload_schema_refs[0].retrieval_url = Some("not a valid URI".to_owned());
        manifest.manifest_digest = manifest
            .expected_manifest_digest()
            .expect("manifest digest");
        manifest.proofs[0].event_digest = manifest.manifest_digest.clone();
        let url = manifest
            .validate_structural()
            .expect_err("non-network retrieval hints must fail closed");
        assert!(url.to_string().contains("retrieval_url is invalid"));
    }
}
