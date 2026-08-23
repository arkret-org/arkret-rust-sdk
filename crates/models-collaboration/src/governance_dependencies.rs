//! Content-addressed dependencies required by historical `apply_seal` replay.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_identity::AuthenticatedSignerResolutionEvidence;
use arkret_wire::{
    AvailabilityReceipt, Event, EventProof, Hash, RealmId, Result, Seal, WireError, canonical,
};
use serde::{Deserialize, Serialize};

use crate::history_key::{
    HistoryKeyResponseLostRecord, HistoryKeyResponseRecord, HistoryKeyResponseSendRequest,
    MinimalMetadataMlsLeafSignerEvidence, PeerHistoryTraversalAccess, SelfHistoryTraversalAccess,
};

pub const MAX_GOVERNANCE_DEPENDENCY_SELECTORS: usize = 1_024;
pub const MAX_GOVERNANCE_DEPENDENCY_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_GOVERNANCE_ARTIFACT_BYTES: usize = 1024 * 1024;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "artifact_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GovernanceRegistryArtifactDescriptor {
    ContractRegistry {
        artifact_id: ContractRegistryArtifactId,
        content_digest: Hash,
    },
    ProofContextRegistry {
        artifact_id: ProofContextRegistryArtifactId,
        content_digest: Hash,
    },
    ReplaySchemaManifest {
        artifact_id: ReplaySchemaManifestArtifactId,
        content_digest: Hash,
    },
    ReplayJsonSchema {
        artifact_id: String,
        content_digest: Hash,
    },
}

macro_rules! fixed_artifact_id {
    ($name:ident, $value:literal) => {
        #[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum $name {
            #[serde(rename = $value)]
            Value,
        }
    };
}

fixed_artifact_id!(
    ContractRegistryArtifactId,
    "registry/contract-registry.json"
);
fixed_artifact_id!(
    ProofContextRegistryArtifactId,
    "registry/proof-context-registry.json"
);
fixed_artifact_id!(
    ReplaySchemaManifestArtifactId,
    "governance-replay-schema-manifest"
);

impl GovernanceRegistryArtifactDescriptor {
    pub fn artifact_id(&self) -> &str {
        match self {
            Self::ContractRegistry { .. } => "registry/contract-registry.json",
            Self::ProofContextRegistry { .. } => "registry/proof-context-registry.json",
            Self::ReplaySchemaManifest { .. } => "governance-replay-schema-manifest",
            Self::ReplayJsonSchema { artifact_id, .. } => artifact_id,
        }
    }

    pub fn content_digest(&self) -> &Hash {
        match self {
            Self::ContractRegistry { content_digest, .. }
            | Self::ProofContextRegistry { content_digest, .. }
            | Self::ReplaySchemaManifest { content_digest, .. }
            | Self::ReplayJsonSchema { content_digest, .. } => content_digest,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !self.content_digest().as_ref().starts_with("sha256:") {
            return Err(WireError::Protocol(
                "governance registry artifact digest must use sha256".to_owned(),
            ));
        }
        if let Self::ReplayJsonSchema { artifact_id, .. } = self {
            let name = artifact_id
                .strip_prefix("schemas/")
                .and_then(|value| value.strip_suffix(".schema.json"));
            let valid = artifact_id.len() > "schemas/.schema.json".len()
                && artifact_id.starts_with("schemas/")
                && artifact_id.ends_with(".schema.json")
                && name.is_some_and(|name| {
                    name.as_bytes()
                        .first()
                        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                        && name.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                        })
                });
            if !valid {
                return Err(WireError::Protocol(
                    "invalid replay JSON Schema artifact id".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceReplaySchemaManifest {
    pub kind: GovernanceReplaySchemaManifestKind,
    pub root_schema_artifact_ids: [ReplayRootSchemaArtifactId; 2],
    pub artifacts: Vec<GovernanceRegistryArtifactDescriptor>,
}

impl GovernanceReplaySchemaManifest {
    pub fn validate(&self) -> Result<()> {
        if self.root_schema_artifact_ids
            != [
                ReplayRootSchemaArtifactId::EventEnvelope,
                ReplayRootSchemaArtifactId::EventPayload,
            ]
        {
            return Err(WireError::Protocol(
                "governance replay manifest has invalid root schema order".to_owned(),
            ));
        }
        if !(2..=256).contains(&self.artifacts.len()) {
            return Err(WireError::Protocol(
                "governance replay manifest must contain 2..=256 artifacts".to_owned(),
            ));
        }
        let mut previous = None;
        for descriptor in &self.artifacts {
            let GovernanceRegistryArtifactDescriptor::ReplayJsonSchema { artifact_id, .. } =
                descriptor
            else {
                return Err(WireError::Protocol(
                    "governance replay manifest accepts replay_json_schema descriptors only"
                        .to_owned(),
                ));
            };
            descriptor.validate()?;
            if previous.is_some_and(|value: &str| value >= artifact_id.as_str()) {
                return Err(WireError::Protocol(
                    "governance replay manifest artifacts must be sorted and unique".to_owned(),
                ));
            }
            previous = Some(artifact_id.as_str());
        }
        for required in [
            "schemas/event-envelope.schema.json",
            "schemas/event-payload.schema.json",
        ] {
            if !self
                .artifacts
                .iter()
                .any(|descriptor| descriptor.artifact_id() == required)
            {
                return Err(WireError::Protocol(
                    "governance replay manifest omits a root schema artifact".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceReplaySchemaManifestKind {
    #[serde(rename = "ak.governance.replay_schema_manifest")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReplayRootSchemaArtifactId {
    #[serde(rename = "schemas/event-envelope.schema.json")]
    EventEnvelope,
    #[serde(rename = "schemas/event-payload.schema.json")]
    EventPayload,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceRegistrySnapshot {
    pub kind: GovernanceRegistrySnapshotKind,
    pub artifacts: [GovernanceRegistryArtifactDescriptor; 3],
    pub snapshot_digest: Hash,
}

impl GovernanceRegistrySnapshot {
    pub fn validate(&self) -> Result<()> {
        if !matches!(
            self.artifacts[0],
            GovernanceRegistryArtifactDescriptor::ContractRegistry { .. }
        ) || !matches!(
            self.artifacts[1],
            GovernanceRegistryArtifactDescriptor::ProofContextRegistry { .. }
        ) || !matches!(
            self.artifacts[2],
            GovernanceRegistryArtifactDescriptor::ReplaySchemaManifest { .. }
        ) {
            return Err(WireError::Protocol(
                "governance registry snapshot has an invalid artifact kind or order".to_owned(),
            ));
        }
        for descriptor in &self.artifacts {
            descriptor.validate()?;
        }
        let expected = Hash::new(canonical::sha256_digest(snapshot_digest_preimage(self)?))?;
        if self.snapshot_digest != expected {
            return Err(WireError::Protocol(
                "governance registry snapshot digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GovernanceRegistrySnapshotKind {
    #[serde(rename = "ak.governance.registry_snapshot")]
    Value,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceRegistryArtifact {
    pub descriptor: GovernanceRegistryArtifactDescriptor,
    pub canonical_bytes_b64u: String,
}

impl GovernanceRegistryArtifact {
    /// Decode and authenticate the canonical JSON bytes once. Callers that
    /// dispatch by descriptor kind reuse this result instead of decoding a
    /// second, potentially divergent value.
    pub fn decoded_canonical_bytes(&self) -> Result<Vec<u8>> {
        let decoded = arkret_canonical::base64url::base64url_decode(&self.canonical_bytes_b64u)?;
        if decoded.len() > MAX_GOVERNANCE_ARTIFACT_BYTES {
            return Err(WireError::Protocol(
                "governance registry artifact exceeds 1 MiB".to_owned(),
            ));
        }
        let value: serde_json::Value = serde_json::from_slice(&decoded)?;
        if canonical::canonical_json_bytes(&value)? != decoded {
            return Err(WireError::Protocol(
                "governance registry artifact bytes are not canonical JSON".to_owned(),
            ));
        }
        Ok(decoded)
    }

    pub fn decoded_canonical_value(&self) -> Result<serde_json::Value> {
        Ok(serde_json::from_slice(&self.decoded_canonical_bytes()?)?)
    }

    pub fn digest_preimage(&self) -> Result<Vec<u8>> {
        let decoded = self.decoded_canonical_bytes()?;
        let mut preimage = b"ak.governance-registry-artifact-v1".to_vec();
        preimage.push(0);
        preimage.extend(decoded);
        Ok(preimage)
    }

    pub fn validate(&self) -> Result<()> {
        self.descriptor.validate()?;
        let expected = Hash::new(canonical::sha256_digest(self.digest_preimage()?))?;
        if self.descriptor.content_digest() != &expected {
            return Err(WireError::Protocol(
                "governance registry artifact content digest mismatch".to_owned(),
            ));
        }
        let value = self.decoded_canonical_value()?;
        match &self.descriptor {
            GovernanceRegistryArtifactDescriptor::ReplaySchemaManifest { .. } => {
                serde_json::from_value::<GovernanceReplaySchemaManifest>(value)?.validate()?;
            }
            GovernanceRegistryArtifactDescriptor::ReplayJsonSchema { artifact_id, .. } => {
                let expected_id = format!("https://arkret.org/v1/{artifact_id}");
                if value.get("$schema").and_then(serde_json::Value::as_str)
                    != Some("https://json-schema.org/draft/2020-12/schema")
                    || value.get("$id").and_then(serde_json::Value::as_str)
                        != Some(expected_id.as_str())
                {
                    return Err(WireError::Protocol(
                        "replay JSON Schema does not declare its exact Draft 2020-12 artifact identity"
                            .to_owned(),
                    ));
                }
            }
            GovernanceRegistryArtifactDescriptor::ContractRegistry { .. }
            | GovernanceRegistryArtifactDescriptor::ProofContextRegistry { .. } => {}
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GovernanceDependencySelector {
    AvailabilityReceipt {
        content_digest: Hash,
    },
    AuthenticatedSignerResolutionEvidence {
        content_digest: Hash,
    },
    MinimalMetadataMlsLeafSignerEvidence {
        content_digest: Hash,
    },
    GovernanceRegistrySnapshot {
        content_digest: Hash,
    },
    GovernanceRegistryArtifact {
        descriptor: GovernanceRegistryArtifactDescriptor,
    },
}

impl GovernanceDependencySelector {
    fn kind(&self) -> &'static str {
        match self {
            Self::AvailabilityReceipt { .. } => "availability_receipt",
            Self::AuthenticatedSignerResolutionEvidence { .. } => {
                "authenticated_signer_resolution_evidence"
            }
            Self::MinimalMetadataMlsLeafSignerEvidence { .. } => {
                "minimal_metadata_mls_leaf_signer_evidence"
            }
            Self::GovernanceRegistrySnapshot { .. } => "governance_registry_snapshot",
            Self::GovernanceRegistryArtifact { .. } => "governance_registry_artifact",
        }
    }

    pub fn canonical_sort_key(&self) -> Result<(&'static str, Vec<u8>)> {
        Ok((self.kind(), canonical::canonical_json_bytes(self)?))
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::AvailabilityReceipt { .. } => Ok(()),
            Self::AuthenticatedSignerResolutionEvidence { content_digest }
            | Self::MinimalMetadataMlsLeafSignerEvidence { content_digest }
            | Self::GovernanceRegistrySnapshot { content_digest } => {
                if !content_digest.as_ref().starts_with("sha256:") {
                    return Err(WireError::Protocol(format!(
                        "{} selector content_digest must use sha256",
                        self.kind()
                    )));
                }
                Ok(())
            }
            Self::GovernanceRegistryArtifact { descriptor } => descriptor.validate(),
        }
    }
}

/// Discover the first-round dependency selectors required to replay exact
/// signed Seals and Events. Registry artifacts are discovered separately from
/// the resolved snapshot so callers never guess its transitive contents.
pub fn governance_dependency_selectors_for_replay(
    seals: &[Seal],
    events: &[Event],
    event_digest_suites: &[arkret_canonical::DigestSuite],
    registry_snapshot_digest: &Hash,
) -> Result<Vec<GovernanceDependencySelector>> {
    let mut selectors =
        governance_runtime_dependency_selectors_for_replay(seals, events, event_digest_suites)?;
    selectors.push(GovernanceDependencySelector::GovernanceRegistrySnapshot {
        content_digest: registry_snapshot_digest.clone(),
    });
    canonicalize_selectors(selectors)
}

/// Discover only runtime proof dependencies for a near-current replay against
/// the SDK's pinned generated registries. Unlike retained history traversal,
/// this surface does not invent or require a historical registry snapshot.
pub fn governance_runtime_dependency_selectors_for_replay(
    seals: &[Seal],
    events: &[Event],
    event_digest_suites: &[arkret_canonical::DigestSuite],
) -> Result<Vec<GovernanceDependencySelector>> {
    if events.len() != event_digest_suites.len() {
        return Err(WireError::Protocol(
            "replay Event and digest-suite cardinality must match".to_owned(),
        ));
    }
    for (event, digest_suite) in events.iter().zip(event_digest_suites.iter().copied()) {
        match event.proofs.as_slice() {
            [EventProof::Producer(_)] => event.validate_for_direct_history_structural()?,
            [
                EventProof::Producer(_),
                EventProof::PrincipalServerAdmission(_),
            ] => {
                event.validate_principal_server_admission_binding(digest_suite)?;
            }
            _ => {
                return Err(WireError::Protocol(
                    "replay dependency discovery requires a direct or admitted Event proof regime"
                        .to_owned(),
                ));
            }
        }
    }
    governance_runtime_dependency_selector_coordinates_for_acquisition(seals, events)
}

/// Read only the content-addressed dependency coordinates carried by signed
/// Seals and Event proofs before the dependencies needed for full replay have
/// been acquired. This does not authenticate an admitted Event or infer its
/// digest suite; callers must run the suite-aware replay verifier after
/// resolving the returned selectors.
pub fn governance_runtime_dependency_selector_coordinates_for_acquisition(
    seals: &[Seal],
    events: &[Event],
) -> Result<Vec<GovernanceDependencySelector>> {
    let mut selectors = Vec::new();
    for seal in seals {
        seal.validate_structural()?;
        selectors.extend(
            seal.availability_receipt_digests
                .iter()
                .cloned()
                .map(
                    |content_digest| GovernanceDependencySelector::AvailabilityReceipt {
                        content_digest,
                    },
                ),
        );
    }
    for event in events {
        match event.proofs.as_slice() {
            [EventProof::Producer(_)]
            | [
                EventProof::Producer(_),
                EventProof::PrincipalServerAdmission(_),
            ] => {}
            _ => {
                return Err(WireError::Protocol(
                    "dependency acquisition requires a direct or admitted Event proof regime"
                        .to_owned(),
                ));
            }
        }
        for proof in &event.proofs {
            match proof {
                EventProof::Producer(producer) => {
                    producer.validate_signer_resolution_evidence_pair()?;
                    if let Some(content_digest) = &producer.signer_resolution_evidence_digest {
                        selectors.push(
                            GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                                content_digest: content_digest.clone(),
                            },
                        );
                    }
                }
                EventProof::PrincipalServerAdmission(admission) => {
                    if admission.signer_resolution_evidence_ref.content_digest()?
                        != admission.signer_resolution_evidence_digest
                        || !admission
                            .signer_resolution_evidence_digest
                            .as_str()
                            .starts_with("sha256:")
                    {
                        return Err(WireError::Protocol(
                            "principal server admission signer evidence binding mismatch"
                                .to_owned(),
                        ));
                    }
                    selectors.push(
                        GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                            content_digest: admission.signer_resolution_evidence_digest.clone(),
                        },
                    );
                }
            }
        }
    }
    canonicalize_selectors(selectors)
}

/// Discover the exact second-round artifact selectors committed by a verified
/// governance registry snapshot.
pub fn governance_artifact_selectors_for_snapshot(
    snapshot: &GovernanceRegistrySnapshot,
) -> Result<Vec<GovernanceDependencySelector>> {
    snapshot.validate()?;
    canonicalize_selectors(
        snapshot
            .artifacts
            .iter()
            .cloned()
            .map(
                |descriptor| GovernanceDependencySelector::GovernanceRegistryArtifact {
                    descriptor,
                },
            )
            .collect(),
    )
}

/// Expand a verified replay-schema manifest into the exact third-round schema
/// selectors it commits. Other registry artifact kinds are terminal.
pub fn governance_artifact_selectors_for_artifact(
    artifact: &GovernanceRegistryArtifact,
) -> Result<Vec<GovernanceDependencySelector>> {
    artifact.validate()?;
    let GovernanceRegistryArtifactDescriptor::ReplaySchemaManifest { .. } = &artifact.descriptor
    else {
        return Ok(Vec::new());
    };
    let manifest = serde_json::from_value::<GovernanceReplaySchemaManifest>(
        artifact.decoded_canonical_value()?,
    )?;
    manifest.validate()?;
    canonicalize_selectors(
        manifest
            .artifacts
            .into_iter()
            .map(
                |descriptor| GovernanceDependencySelector::GovernanceRegistryArtifact {
                    descriptor,
                },
            )
            .collect(),
    )
}

#[derive(Clone, Debug)]
pub struct HistoricalReplaySchemaClosure {
    pub schemas: BTreeMap<String, serde_json::Value>,
}

/// Validate every-and-only the historical schema artifacts committed by a
/// snapshot and its decoded manifest. Absolute/external refs, path escape,
/// unresolved fragments, missing/surplus artifacts and duplicate descriptors
/// all fail before replay can inspect an Event.
pub fn validate_governance_replay_schema_closure(
    snapshot: &GovernanceRegistrySnapshot,
    artifacts: &[GovernanceRegistryArtifact],
) -> Result<HistoricalReplaySchemaClosure> {
    snapshot.validate()?;
    let mut actual = BTreeMap::<Vec<u8>, &GovernanceRegistryArtifact>::new();
    for artifact in artifacts {
        artifact.validate()?;
        let key = canonical::canonical_json_bytes(&artifact.descriptor)?;
        if actual.insert(key, artifact).is_some() {
            return Err(WireError::Protocol(
                "governance replay artifact descriptor is duplicated".to_owned(),
            ));
        }
    }
    let manifest_descriptor = snapshot
        .artifacts
        .iter()
        .find(|descriptor| {
            matches!(
                descriptor,
                GovernanceRegistryArtifactDescriptor::ReplaySchemaManifest { .. }
            )
        })
        .ok_or_else(|| {
            WireError::Protocol("governance snapshot has no replay schema manifest".to_owned())
        })?;
    let manifest_key = canonical::canonical_json_bytes(manifest_descriptor)?;
    let manifest_artifact = actual.get(&manifest_key).ok_or_else(|| {
        WireError::Protocol("governance replay schema manifest artifact is missing".to_owned())
    })?;
    let manifest = serde_json::from_value::<GovernanceReplaySchemaManifest>(
        manifest_artifact.decoded_canonical_value()?,
    )?;
    manifest.validate()?;

    let expected = snapshot
        .artifacts
        .iter()
        .chain(manifest.artifacts.iter())
        .map(|descriptor| canonical::canonical_json_bytes(descriptor).map_err(Into::into))
        .collect::<Result<BTreeSet<_>>>()?;
    if expected.len() != snapshot.artifacts.len() + manifest.artifacts.len()
        || actual.keys().cloned().collect::<BTreeSet<_>>() != expected
    {
        return Err(WireError::Protocol(
            "governance replay artifacts are not every-and-only snapshot plus manifest closure"
                .to_owned(),
        ));
    }

    let mut schemas = BTreeMap::new();
    for descriptor in &manifest.artifacts {
        let key = canonical::canonical_json_bytes(descriptor)?;
        let artifact = actual.get(&key).ok_or_else(|| {
            WireError::Protocol("governance replay JSON Schema artifact is missing".to_owned())
        })?;
        schemas.insert(
            descriptor.artifact_id().to_owned(),
            artifact.decoded_canonical_value()?,
        );
    }
    let mut reachable = BTreeSet::new();
    let mut pending = manifest
        .root_schema_artifact_ids
        .iter()
        .map(|root| match root {
            ReplayRootSchemaArtifactId::EventEnvelope => {
                "schemas/event-envelope.schema.json".to_owned()
            }
            ReplayRootSchemaArtifactId::EventPayload => {
                "schemas/event-payload.schema.json".to_owned()
            }
        })
        .collect::<Vec<_>>();
    while let Some(artifact_id) = pending.pop() {
        if !reachable.insert(artifact_id.clone()) {
            continue;
        }
        let schema = schemas.get(&artifact_id).ok_or_else(|| {
            WireError::Protocol(format!(
                "governance replay schema is unresolved: {artifact_id}"
            ))
        })?;
        for reference in schema_local_refs(schema) {
            let (path, fragment) = reference
                .split_once('#')
                .unwrap_or((reference.as_str(), ""));
            let target = if path.is_empty() {
                artifact_id.clone()
            } else {
                resolve_schema_artifact_id(&artifact_id, path)?
            };
            let target_schema = schemas.get(&target).ok_or_else(|| {
                WireError::Protocol(format!(
                    "governance replay schema ref is unresolved: {reference}"
                ))
            })?;
            if !fragment.is_empty()
                && (!fragment.starts_with('/') || target_schema.pointer(fragment).is_none())
            {
                return Err(WireError::Protocol(format!(
                    "governance replay schema fragment is unresolved: {reference}"
                )));
            }
            pending.push(target);
        }
    }
    let declared = manifest
        .artifacts
        .iter()
        .map(|descriptor| descriptor.artifact_id().to_owned())
        .collect::<BTreeSet<_>>();
    if reachable != declared {
        return Err(WireError::Protocol(
            "governance replay schema manifest is not the exact recursive local-ref closure"
                .to_owned(),
        ));
    }
    Ok(HistoricalReplaySchemaClosure { schemas })
}

fn schema_local_refs(value: &serde_json::Value) -> Vec<String> {
    let mut refs = Vec::new();
    let mut stack = vec![value];
    while let Some(value) = stack.pop() {
        match value {
            serde_json::Value::Object(object) => {
                if let Some(reference) = object.get("$ref").and_then(serde_json::Value::as_str) {
                    refs.push(reference.to_owned());
                }
                stack.extend(object.values());
            }
            serde_json::Value::Array(values) => stack.extend(values),
            _ => {}
        }
    }
    refs
}

fn resolve_schema_artifact_id(base: &str, reference: &str) -> Result<String> {
    if reference.contains("://")
        || reference.starts_with('/')
        || reference.contains('\\')
        || reference.split('/').any(|component| component == "..")
    {
        return Err(WireError::Protocol(
            "governance replay schema ref is external or escapes schemas/".to_owned(),
        ));
    }
    let name = reference.strip_prefix("./").unwrap_or(reference);
    if name.is_empty() || name.contains('/') || !name.ends_with(".schema.json") {
        return Err(WireError::Protocol(
            "governance replay schema ref is not a local schema artifact".to_owned(),
        ));
    }
    let _ = base;
    Ok(format!("schemas/{name}"))
}

/// Discover the next signer-evidence layer referenced by already resolved
/// principal or Native Agent evidence. Repeat until this returns an empty set;
/// service evidence is the self-authenticating terminal branch.
pub fn governance_attester_evidence_selectors<'a, E>(
    evidence: impl IntoIterator<Item = &'a E>,
) -> Result<Vec<GovernanceDependencySelector>>
where
    E: std::borrow::Borrow<AuthenticatedSignerResolutionEvidence> + ?Sized + 'a,
{
    let mut selectors = Vec::new();
    for item in evidence {
        let item = std::borrow::Borrow::borrow(item);
        item.validate_attester_binding()?;
        match item {
            AuthenticatedSignerResolutionEvidence::Service { .. } => {}
            AuthenticatedSignerResolutionEvidence::Principal {
                attester_signer_evidence_digest,
                ..
            } => selectors.push(
                GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                    content_digest: attester_signer_evidence_digest.clone(),
                },
            ),
            AuthenticatedSignerResolutionEvidence::NativeAgent {
                attester_signer_evidence_digest,
                controller_signer_evidence_digest,
                account_authority_signer_evidence_digest,
                receiver_signer_evidence_digest,
                ..
            } => selectors.extend(
                [
                    attester_signer_evidence_digest,
                    controller_signer_evidence_digest,
                    account_authority_signer_evidence_digest,
                    receiver_signer_evidence_digest,
                ]
                .into_iter()
                .map(|content_digest| {
                    GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                        content_digest: content_digest.clone(),
                    }
                }),
            ),
        }
    }
    canonicalize_selectors(selectors)
}

/// Discover the next content-addressed signer-evidence layer from already
/// resolved governance dependencies. In addition to authenticated evidence
/// attesters, minimal-metadata roots reference the Principal evidence that
/// verifies their embedded IdentityLink proof.
pub fn governance_transitive_signer_evidence_selectors(
    dependencies: &[GovernanceDependency],
) -> Result<Vec<GovernanceDependencySelector>> {
    let authenticated = dependencies
        .iter()
        .filter_map(|dependency| match dependency {
            GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                authenticated_signer_resolution_evidence,
                ..
            } => Some(authenticated_signer_resolution_evidence.as_ref()),
            _ => None,
        })
        .collect::<Vec<_>>();
    let mut selectors = governance_attester_evidence_selectors(authenticated)?;
    selectors.extend(dependencies.iter().filter_map(|dependency| {
        match dependency {
            GovernanceDependency::MinimalMetadataMlsLeafSignerEvidence {
                minimal_metadata_mls_leaf_signer_evidence,
                ..
            } => Some(
                GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                    content_digest: minimal_metadata_mls_leaf_signer_evidence
                        .identity_link_signer_evidence_digest
                        .clone(),
                },
            ),
            _ => None,
        }
    }));
    canonicalize_selectors(selectors)
}

/// Validate the exact signer-evidence closure used to admit one history
/// response source proof. The root must be either a Principal/Native Agent
/// evidence object or the dedicated minimal-metadata MLS evidence. Service
/// evidence is valid only as a recursively referenced attester leaf.
pub fn validate_history_source_signer_dependency_closure(
    source: &HistoryKeyResponseSendRequest,
    dependencies: &[GovernanceDependency],
) -> Result<()> {
    let mut authenticated = BTreeMap::new();
    let mut minimal = BTreeMap::new();
    for dependency in dependencies {
        match dependency {
            GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                selector:
                    GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                        content_digest,
                    },
                authenticated_signer_resolution_evidence,
            } => {
                authenticated_signer_resolution_evidence.validate_attester_binding()?;
                if authenticated_signer_resolution_evidence.canonical_sha256_digest()?
                    != *content_digest
                    || authenticated
                        .insert(
                            content_digest.clone(),
                            authenticated_signer_resolution_evidence.as_ref(),
                        )
                        .is_some()
                {
                    return Err(WireError::Protocol(
                        "source signer dependency closure has an invalid duplicate".to_owned(),
                    ));
                }
            }
            GovernanceDependency::MinimalMetadataMlsLeafSignerEvidence {
                selector:
                    GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence {
                        content_digest,
                    },
                minimal_metadata_mls_leaf_signer_evidence,
            } => {
                minimal_metadata_mls_leaf_signer_evidence.validate()?;
                if minimal_metadata_mls_leaf_signer_evidence.canonical_sha256_digest()?
                    != *content_digest
                    || minimal
                        .insert(
                            content_digest.clone(),
                            minimal_metadata_mls_leaf_signer_evidence,
                        )
                        .is_some()
                {
                    return Err(WireError::Protocol(
                        "minimal-metadata signer dependency closure has an invalid duplicate"
                            .to_owned(),
                    ));
                }
            }
            _ => {
                return Err(WireError::Protocol(
                    "source signer dependency closure contains a non-signer item".to_owned(),
                ));
            }
        }
    }
    let root = &source.source_signer_evidence_digest;
    if let Some(evidence) = minimal.get(root) {
        if minimal.len() != 1 || evidence.evidence_ref()? != source.source_signer_evidence_ref {
            return Err(WireError::Protocol(
                "minimal-metadata source signer closure contains surplus or mismatched evidence"
                    .to_owned(),
            ));
        }
        let identity_link = evidence.validate_identity_link_binding()?;
        let signer = authenticated
            .get(&evidence.identity_link_signer_evidence_digest)
            .ok_or_else(|| {
                WireError::Protocol(
                    "minimal-metadata source signer closure omits IdentityLink signer evidence"
                        .to_owned(),
                )
            })?;
        if signer.evidence_ref()? != evidence.identity_link_signer_evidence_ref
            || signer.signer_id() != &identity_link.principal_id
            || signer.verification_method() != &identity_link.proof.verification_method
            || !matches!(
                *signer,
                AuthenticatedSignerResolutionEvidence::Principal { .. }
            )
        {
            return Err(WireError::Protocol(
                "minimal-metadata IdentityLink signer evidence is mismatched or non-Principal"
                    .to_owned(),
            ));
        }
        validate_authenticated_evidence_reachability(
            &authenticated,
            &evidence.identity_link_signer_evidence_digest,
        )?;
        return Ok(());
    }
    let root_evidence = authenticated.get(root).ok_or_else(|| {
        WireError::Protocol("source signer dependency closure omits its root evidence".to_owned())
    })?;
    if !minimal.is_empty()
        || root_evidence.evidence_ref()? != source.source_signer_evidence_ref
        || matches!(
            *root_evidence,
            AuthenticatedSignerResolutionEvidence::Service { .. }
        )
    {
        return Err(WireError::Protocol(
            "source signer dependency closure has an invalid root kind or coordinate".to_owned(),
        ));
    }
    validate_authenticated_evidence_reachability(&authenticated, root)?;
    Ok(())
}

fn validate_authenticated_evidence_reachability(
    authenticated: &BTreeMap<Hash, &AuthenticatedSignerResolutionEvidence>,
    root: &Hash,
) -> Result<()> {
    let mut pending = vec![root.clone()];
    let mut reached = BTreeSet::new();
    while let Some(digest) = pending.pop() {
        if !reached.insert(digest.clone()) {
            continue;
        }
        let evidence = authenticated.get(&digest).ok_or_else(|| {
            WireError::Protocol("source signer dependency closure is incomplete".to_owned())
        })?;
        match evidence {
            AuthenticatedSignerResolutionEvidence::Service { .. } => {}
            AuthenticatedSignerResolutionEvidence::Principal {
                attester_signer_evidence_digest,
                ..
            } => pending.push(attester_signer_evidence_digest.clone()),
            AuthenticatedSignerResolutionEvidence::NativeAgent {
                attester_signer_evidence_digest,
                controller_signer_evidence_digest,
                account_authority_signer_evidence_digest,
                receiver_signer_evidence_digest,
                ..
            } => pending.extend([
                attester_signer_evidence_digest.clone(),
                controller_signer_evidence_digest.clone(),
                account_authority_signer_evidence_digest.clone(),
                receiver_signer_evidence_digest.clone(),
            ]),
        }
    }
    if reached.len() != authenticated.len() {
        return Err(WireError::Protocol(
            "source signer dependency closure contains surplus evidence".to_owned(),
        ));
    }
    Ok(())
}

/// Select the exact reachable signer-evidence closure for one response from a
/// page-level dependency superset, then run the canonical closure validator.
pub fn history_source_signer_dependency_closure(
    source: &HistoryKeyResponseSendRequest,
    dependencies: &[GovernanceDependency],
) -> Result<Vec<GovernanceDependency>> {
    let mut authenticated = BTreeMap::new();
    let mut minimal = BTreeMap::new();
    let mut kinds = BTreeMap::new();
    for dependency in dependencies {
        match dependency {
            GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                selector:
                    GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                        content_digest,
                    },
                ..
            } => {
                if kinds
                    .insert(content_digest.clone(), "authenticated")
                    .is_some()
                {
                    return Err(WireError::Protocol(
                        "page signer dependency digest is duplicated or ambiguous".to_owned(),
                    ));
                }
                if authenticated
                    .insert(content_digest.clone(), dependency)
                    .is_some()
                {
                    return Err(WireError::Protocol(
                        "page signer dependency set contains a duplicate digest".to_owned(),
                    ));
                }
            }
            GovernanceDependency::MinimalMetadataMlsLeafSignerEvidence {
                selector:
                    GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence {
                        content_digest,
                    },
                ..
            } => {
                if kinds
                    .insert(content_digest.clone(), "minimal_metadata")
                    .is_some()
                {
                    return Err(WireError::Protocol(
                        "page signer dependency digest is duplicated or ambiguous".to_owned(),
                    ));
                }
                if minimal.insert(content_digest.clone(), dependency).is_some() {
                    return Err(WireError::Protocol(
                        "page minimal-metadata signer dependency set contains a duplicate digest"
                            .to_owned(),
                    ));
                }
            }
            _ => {
                return Err(WireError::Protocol(
                    "page source signer dependency set contains a non-signer item".to_owned(),
                ));
            }
        }
    }
    let root = &source.source_signer_evidence_digest;
    let mut selected = Vec::new();
    if let Some(dependency) = minimal.get(root) {
        if authenticated.contains_key(root) {
            return Err(WireError::Protocol(
                "source signer evidence digest is ambiguous across kinds".to_owned(),
            ));
        }
        selected.push((*dependency).clone());
        let GovernanceDependency::MinimalMetadataMlsLeafSignerEvidence {
            minimal_metadata_mls_leaf_signer_evidence: evidence,
            ..
        } = dependency
        else {
            unreachable!("minimal dependency map contains only minimal evidence")
        };
        let mut pending = vec![evidence.identity_link_signer_evidence_digest.clone()];
        let mut reached = BTreeSet::new();
        while let Some(digest) = pending.pop() {
            if !reached.insert(digest.clone()) {
                continue;
            }
            let dependency = authenticated.get(&digest).ok_or_else(|| {
                WireError::Protocol(
                    "page minimal-metadata IdentityLink signer closure is incomplete".to_owned(),
                )
            })?;
            let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                authenticated_signer_resolution_evidence: evidence,
                ..
            } = dependency
            else {
                unreachable!("authenticated dependency map contains only authenticated evidence")
            };
            match evidence.as_ref() {
                AuthenticatedSignerResolutionEvidence::Service { .. } => {}
                AuthenticatedSignerResolutionEvidence::Principal {
                    attester_signer_evidence_digest,
                    ..
                } => pending.push(attester_signer_evidence_digest.clone()),
                AuthenticatedSignerResolutionEvidence::NativeAgent { .. } => {
                    return Err(WireError::Protocol(
                        "minimal-metadata IdentityLink signer closure contains Native Agent evidence"
                            .to_owned(),
                    ));
                }
            }
            selected.push((*dependency).clone());
        }
    } else {
        let mut pending = vec![root.clone()];
        let mut reached = BTreeSet::new();
        while let Some(digest) = pending.pop() {
            if !reached.insert(digest.clone()) {
                continue;
            }
            let dependency = authenticated.get(&digest).ok_or_else(|| {
                WireError::Protocol(
                    "page source signer dependency closure is incomplete".to_owned(),
                )
            })?;
            let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                authenticated_signer_resolution_evidence: evidence,
                ..
            } = dependency
            else {
                unreachable!("authenticated dependency map contains only authenticated evidence")
            };
            match evidence.as_ref() {
                AuthenticatedSignerResolutionEvidence::Service { .. } => {}
                AuthenticatedSignerResolutionEvidence::Principal {
                    attester_signer_evidence_digest,
                    ..
                } => pending.push(attester_signer_evidence_digest.clone()),
                AuthenticatedSignerResolutionEvidence::NativeAgent {
                    attester_signer_evidence_digest,
                    controller_signer_evidence_digest,
                    account_authority_signer_evidence_digest,
                    receiver_signer_evidence_digest,
                    ..
                } => pending.extend([
                    attester_signer_evidence_digest.clone(),
                    controller_signer_evidence_digest.clone(),
                    account_authority_signer_evidence_digest.clone(),
                    receiver_signer_evidence_digest.clone(),
                ]),
            }
            selected.push((*dependency).clone());
        }
    }
    selected.sort_by_key(|dependency| {
        dependency
            .selector()
            .canonical_sort_key()
            .expect("validated signer selector")
    });
    validate_history_source_signer_dependency_closure(source, &selected)?;
    Ok(selected)
}

/// Exact signer dependencies retained for one admitted response record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryResponseSignerDependencyClosure {
    pub source_signer_dependencies: Vec<GovernanceDependency>,
    pub release_service_signer_dependencies: Vec<GovernanceDependency>,
}

/// Partition a page-level signer dependency superset into the exact source
/// closure and the release-service root required by one response record.
pub fn history_response_record_signer_dependency_closure(
    record: &HistoryKeyResponseRecord,
    dependencies: &[GovernanceDependency],
) -> Result<HistoryResponseSignerDependencyClosure> {
    record.validate()?;
    validate_page_signer_digest_kinds(dependencies)?;
    Ok(HistoryResponseSignerDependencyClosure {
        source_signer_dependencies: history_source_signer_dependency_closure(
            &record.source_record,
            &signer_dependencies_only(dependencies),
        )?,
        release_service_signer_dependencies: release_service_signer_dependency_closure(
            &record.release_service_signer_evidence_ref,
            &record.release_service_signer_evidence_digest,
            &record.service_proof.verification_method,
            dependencies,
        )?,
    })
}

/// Select the exact release-service signer root required by one signed lost
/// descriptor from a page-level dependency superset.
pub fn history_response_lost_signer_dependency_closure(
    lost_record: &HistoryKeyResponseLostRecord,
    dependencies: &[GovernanceDependency],
) -> Result<Vec<GovernanceDependency>> {
    lost_record.validate()?;
    validate_page_signer_digest_kinds(dependencies)?;
    release_service_signer_dependency_closure(
        &lost_record.release_service_signer_evidence_ref,
        &lost_record.release_service_signer_evidence_digest,
        &lost_record.service_proof.verification_method,
        dependencies,
    )
}

fn signer_dependencies_only(dependencies: &[GovernanceDependency]) -> Vec<GovernanceDependency> {
    dependencies
        .iter()
        .filter(|dependency| {
            matches!(
                dependency,
                GovernanceDependency::AuthenticatedSignerResolutionEvidence { .. }
                    | GovernanceDependency::MinimalMetadataMlsLeafSignerEvidence { .. }
            )
        })
        .cloned()
        .collect()
}

fn validate_page_signer_digest_kinds(dependencies: &[GovernanceDependency]) -> Result<()> {
    let mut kinds = BTreeMap::new();
    for dependency in dependencies {
        let coordinate = match dependency {
            GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                selector:
                    GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                        content_digest,
                    },
                ..
            } => Some((content_digest, "authenticated")),
            GovernanceDependency::MinimalMetadataMlsLeafSignerEvidence {
                selector:
                    GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence {
                        content_digest,
                    },
                ..
            } => Some((content_digest, "minimal_metadata")),
            _ => None,
        };
        let Some((digest, kind)) = coordinate else {
            continue;
        };
        if kinds.insert(digest.clone(), kind).is_some() {
            return Err(WireError::Protocol(
                "page signer dependency digest is duplicated or ambiguous".to_owned(),
            ));
        }
    }
    Ok(())
}

fn release_service_signer_dependency_closure(
    evidence_ref: &arkret_wire::SignerEvidenceRef,
    evidence_digest: &Hash,
    verification_method: &arkret_wire::DidUrl,
    dependencies: &[GovernanceDependency],
) -> Result<Vec<GovernanceDependency>> {
    if evidence_ref.content_digest()? != *evidence_digest {
        return Err(WireError::Protocol(
            "release-service signer evidence ref and digest mismatch".to_owned(),
        ));
    }
    let mut selected = None;
    for dependency in dependencies {
        let GovernanceDependency::AuthenticatedSignerResolutionEvidence {
            selector:
                GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence { content_digest },
            authenticated_signer_resolution_evidence,
        } = dependency
        else {
            continue;
        };
        if content_digest != evidence_digest {
            continue;
        }
        authenticated_signer_resolution_evidence.validate_attester_binding()?;
        if authenticated_signer_resolution_evidence.canonical_sha256_digest()? != *content_digest
            || authenticated_signer_resolution_evidence.evidence_ref()? != *evidence_ref
            || authenticated_signer_resolution_evidence.verification_method() != verification_method
            || !matches!(
                authenticated_signer_resolution_evidence.as_ref(),
                AuthenticatedSignerResolutionEvidence::Service { .. }
            )
            || selected.replace(dependency.clone()).is_some()
        {
            return Err(WireError::Protocol(
                "release-service signer dependency is duplicate or does not bind its proof"
                    .to_owned(),
            ));
        }
    }
    selected.map(|dependency| vec![dependency]).ok_or_else(|| {
        WireError::Protocol("release-service signer dependency is missing".to_owned())
    })
}

fn canonicalize_selectors(
    selectors: Vec<GovernanceDependencySelector>,
) -> Result<Vec<GovernanceDependencySelector>> {
    let mut keyed = BTreeMap::new();
    for selector in selectors {
        selector.validate()?;
        keyed
            .entry(selector.canonical_sort_key()?)
            .or_insert(selector);
    }
    if keyed.len() > MAX_GOVERNANCE_DEPENDENCY_SELECTORS {
        return Err(WireError::Protocol(
            "governance dependency selector discovery exceeds 1024 entries".to_owned(),
        ));
    }
    Ok(keyed.into_values().collect())
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum GovernanceDependency {
    AvailabilityReceipt {
        selector: GovernanceDependencySelector,
        availability_receipt: AvailabilityReceipt,
    },
    AuthenticatedSignerResolutionEvidence {
        selector: GovernanceDependencySelector,
        authenticated_signer_resolution_evidence: Box<AuthenticatedSignerResolutionEvidence>,
    },
    MinimalMetadataMlsLeafSignerEvidence {
        selector: GovernanceDependencySelector,
        minimal_metadata_mls_leaf_signer_evidence: MinimalMetadataMlsLeafSignerEvidence,
    },
    GovernanceRegistrySnapshot {
        selector: GovernanceDependencySelector,
        governance_registry_snapshot: GovernanceRegistrySnapshot,
    },
    GovernanceRegistryArtifact {
        selector: GovernanceDependencySelector,
        governance_registry_artifact: GovernanceRegistryArtifact,
    },
}

impl Eq for GovernanceDependency {}

impl GovernanceDependency {
    pub fn selector(&self) -> &GovernanceDependencySelector {
        match self {
            Self::AvailabilityReceipt { selector, .. }
            | Self::AuthenticatedSignerResolutionEvidence { selector, .. }
            | Self::MinimalMetadataMlsLeafSignerEvidence { selector, .. }
            | Self::GovernanceRegistrySnapshot { selector, .. }
            | Self::GovernanceRegistryArtifact { selector, .. } => selector,
        }
    }

    fn validate_branch(&self) -> Result<()> {
        match self {
            Self::AvailabilityReceipt {
                selector: GovernanceDependencySelector::AvailabilityReceipt { content_digest },
                availability_receipt,
            } => {
                availability_receipt.validate_structural()?;
                if content_digest != &availability_receipt.receipt_digest {
                    return Err(WireError::Protocol(
                        "availability receipt dependency selector digest mismatch".to_owned(),
                    ));
                }
            }
            Self::AuthenticatedSignerResolutionEvidence {
                selector:
                    GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                        content_digest,
                    },
                authenticated_signer_resolution_evidence,
            } => {
                authenticated_signer_resolution_evidence.validate_attester_binding()?;
                if content_digest
                    != &authenticated_signer_resolution_evidence.canonical_sha256_digest()?
                {
                    return Err(WireError::Protocol(
                        "signer resolution evidence dependency selector digest mismatch".to_owned(),
                    ));
                }
            }
            Self::MinimalMetadataMlsLeafSignerEvidence {
                selector:
                    GovernanceDependencySelector::MinimalMetadataMlsLeafSignerEvidence {
                        content_digest,
                    },
                minimal_metadata_mls_leaf_signer_evidence,
            } => {
                minimal_metadata_mls_leaf_signer_evidence.validate()?;
                if content_digest
                    != &minimal_metadata_mls_leaf_signer_evidence.canonical_sha256_digest()?
                {
                    return Err(WireError::Protocol(
                        "minimal-metadata signer evidence dependency selector digest mismatch"
                            .to_owned(),
                    ));
                }
            }
            Self::GovernanceRegistrySnapshot {
                selector:
                    GovernanceDependencySelector::GovernanceRegistrySnapshot { content_digest },
                governance_registry_snapshot,
            } => {
                governance_registry_snapshot.validate()?;
                if content_digest != &governance_registry_snapshot.snapshot_digest {
                    return Err(WireError::Protocol(
                        "governance registry snapshot selector digest mismatch".to_owned(),
                    ));
                }
            }
            Self::GovernanceRegistryArtifact {
                selector: GovernanceDependencySelector::GovernanceRegistryArtifact { descriptor },
                governance_registry_artifact,
            } => {
                governance_registry_artifact.validate()?;
                if descriptor != &governance_registry_artifact.descriptor {
                    return Err(WireError::Protocol(
                        "governance registry artifact selector descriptor mismatch".to_owned(),
                    ));
                }
            }
            _ => {
                return Err(WireError::Protocol(
                    "governance dependency item does not match its selector kind".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

macro_rules! governance_dependency_resolve_request {
    ($name:ident, $history_access:ty) => {
        #[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            pub realm_id: RealmId,
            pub selectors: Vec<GovernanceDependencySelector>,
            pub byte_limit: u64,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub history_traversal_access: Option<$history_access>,
        }

        impl $name {
            pub fn validate(&self) -> Result<()> {
                validate_governance_dependency_resolve_request(&self.selectors, self.byte_limit)
            }
        }
    };
}

governance_dependency_resolve_request!(
    SelfGovernanceDependencyResolveRequest,
    SelfHistoryTraversalAccess
);
governance_dependency_resolve_request!(
    PeerGovernanceDependencyResolveRequest,
    PeerHistoryTraversalAccess
);

fn validate_governance_dependency_resolve_request(
    selectors: &[GovernanceDependencySelector],
    byte_limit: u64,
) -> Result<()> {
    if selectors.is_empty() || selectors.len() > MAX_GOVERNANCE_DEPENDENCY_SELECTORS {
        return Err(WireError::Protocol(
            "governance dependency request must contain 1..=1024 selectors".to_owned(),
        ));
    }
    if byte_limit == 0 || byte_limit > MAX_GOVERNANCE_DEPENDENCY_RESPONSE_BYTES {
        return Err(WireError::Protocol(
            "governance dependency request byte_limit must be 1..=8388608".to_owned(),
        ));
    }
    for selector in selectors {
        selector.validate()?;
    }
    for pair in selectors.windows(2) {
        if pair[0].canonical_sort_key()? >= pair[1].canonical_sort_key()? {
            return Err(WireError::Protocol(
                "governance dependency selectors must be sorted and unique".to_owned(),
            ));
        }
    }
    Ok(())
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GovernanceDependencyResolveOutcome {
    pub items: Vec<GovernanceDependency>,
    pub missing_selectors: Vec<GovernanceDependencySelector>,
}

impl Eq for GovernanceDependencyResolveOutcome {}

impl GovernanceDependencyResolveOutcome {
    pub fn validate(&self) -> Result<()> {
        if self.items.len() > MAX_GOVERNANCE_DEPENDENCY_SELECTORS
            || self.missing_selectors.len() > MAX_GOVERNANCE_DEPENDENCY_SELECTORS
        {
            return Err(WireError::Protocol(
                "governance dependency outcome exceeds 1024 entries".to_owned(),
            ));
        }
        for item in &self.items {
            item.validate_branch()?;
            item.selector().validate()?;
        }
        for pair in self.items.windows(2) {
            if pair[0].selector().canonical_sort_key()?
                >= pair[1].selector().canonical_sort_key()?
            {
                return Err(WireError::Protocol(
                    "governance dependency items must be sorted and unique".to_owned(),
                ));
            }
        }
        for pair in self.missing_selectors.windows(2) {
            if pair[0].canonical_sort_key()? >= pair[1].canonical_sort_key()? {
                return Err(WireError::Protocol(
                    "missing governance dependency selectors must be sorted and unique".to_owned(),
                ));
            }
        }
        for selector in &self.missing_selectors {
            selector.validate()?;
        }
        let mut accounted = BTreeSet::new();
        for selector in self
            .items
            .iter()
            .map(GovernanceDependency::selector)
            .chain(self.missing_selectors.iter())
        {
            if !accounted.insert(selector.canonical_sort_key()?) {
                return Err(WireError::Protocol(
                    "governance dependency selector is accounted for more than once".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub fn validate_for_self_request(
        &self,
        request: &SelfGovernanceDependencyResolveRequest,
    ) -> Result<()> {
        request.validate()?;
        self.validate_for_request_parts(&request.selectors, request.byte_limit)
    }

    pub fn validate_for_peer_request(
        &self,
        request: &PeerGovernanceDependencyResolveRequest,
    ) -> Result<()> {
        request.validate()?;
        self.validate_for_request_parts(&request.selectors, request.byte_limit)
    }

    fn validate_for_request_parts(
        &self,
        selectors: &[GovernanceDependencySelector],
        byte_limit: u64,
    ) -> Result<()> {
        self.validate()?;
        let accounted = self
            .items
            .iter()
            .map(GovernanceDependency::selector)
            .chain(self.missing_selectors.iter())
            .map(|selector| canonical::canonical_json_bytes(selector).map_err(Into::into))
            .collect::<Result<BTreeSet<_>>>()?;
        let requested = selectors
            .iter()
            .map(|selector| canonical::canonical_json_bytes(selector).map_err(Into::into))
            .collect::<Result<BTreeSet<_>>>()?;
        if accounted != requested || accounted.len() != selectors.len() {
            return Err(WireError::Protocol(
                "governance dependency outcome is not every-and-only the requested selectors"
                    .to_owned(),
            ));
        }
        let bytes = canonical::canonical_json_bytes(self)?;
        if bytes.len() as u64 > byte_limit
            || bytes.len() as u64 > MAX_GOVERNANCE_DEPENDENCY_RESPONSE_BYTES
        {
            return Err(WireError::Protocol(
                "governance dependency outcome exceeds request byte_limit".to_owned(),
            ));
        }
        Ok(())
    }
}

pub fn snapshot_digest_preimage(snapshot: &GovernanceRegistrySnapshot) -> Result<Vec<u8>> {
    let value = serde_json::json!({
        "kind": snapshot.kind,
        "artifacts": snapshot.artifacts,
    });
    let mut preimage = b"ak.governance-registry-snapshot-v1".to_vec();
    preimage.push(0);
    preimage.extend(canonical::canonical_json_bytes(&value)?);
    Ok(preimage)
}

#[cfg(test)]
mod tests {
    use std::any::TypeId;

    use super::*;

    #[test]
    fn governance_dependency_requests_have_distinct_wire_types() {
        assert_ne!(
            TypeId::of::<SelfGovernanceDependencyResolveRequest>(),
            TypeId::of::<PeerGovernanceDependencyResolveRequest>()
        );
    }

    fn fixture_hash(value: &serde_json::Value) -> Hash {
        let bytes = canonical::canonical_json_bytes(value).unwrap();
        let mut preimage = b"ak.governance-registry-artifact-v1".to_vec();
        preimage.push(0);
        preimage.extend(bytes);
        Hash::new(canonical::sha256_digest(preimage)).unwrap()
    }

    fn fixture_artifact(
        value: serde_json::Value,
        descriptor: impl FnOnce(Hash) -> GovernanceRegistryArtifactDescriptor,
    ) -> GovernanceRegistryArtifact {
        let digest = fixture_hash(&value);
        GovernanceRegistryArtifact {
            descriptor: descriptor(digest),
            canonical_bytes_b64u: arkret_canonical::base64url_encode(
                canonical::canonical_json_bytes(&value).unwrap(),
            ),
        }
    }

    fn replay_fixture(
        root_ref: &str,
    ) -> (GovernanceRegistrySnapshot, Vec<GovernanceRegistryArtifact>) {
        let envelope_value = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://arkret.org/v1/schemas/event-envelope.schema.json",
            "type": "object",
            "properties": {"payload": {"$ref": root_ref}},
            "additionalProperties": false
        });
        let payload_value = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://arkret.org/v1/schemas/event-payload.schema.json",
            "type": "object"
        });
        let envelope = fixture_artifact(envelope_value, |content_digest| {
            GovernanceRegistryArtifactDescriptor::ReplayJsonSchema {
                artifact_id: "schemas/event-envelope.schema.json".to_owned(),
                content_digest,
            }
        });
        let payload = fixture_artifact(payload_value, |content_digest| {
            GovernanceRegistryArtifactDescriptor::ReplayJsonSchema {
                artifact_id: "schemas/event-payload.schema.json".to_owned(),
                content_digest,
            }
        });
        let manifest_value = serde_json::to_value(GovernanceReplaySchemaManifest {
            kind: GovernanceReplaySchemaManifestKind::Value,
            root_schema_artifact_ids: [
                ReplayRootSchemaArtifactId::EventEnvelope,
                ReplayRootSchemaArtifactId::EventPayload,
            ],
            artifacts: vec![envelope.descriptor.clone(), payload.descriptor.clone()],
        })
        .unwrap();
        let manifest = fixture_artifact(manifest_value, |content_digest| {
            GovernanceRegistryArtifactDescriptor::ReplaySchemaManifest {
                artifact_id: ReplaySchemaManifestArtifactId::Value,
                content_digest,
            }
        });
        let contract =
            fixture_artifact(serde_json::json!({"kind": "contract"}), |content_digest| {
                GovernanceRegistryArtifactDescriptor::ContractRegistry {
                    artifact_id: ContractRegistryArtifactId::Value,
                    content_digest,
                }
            });
        let proof_context = fixture_artifact(
            serde_json::json!({"kind": "proof_context"}),
            |content_digest| GovernanceRegistryArtifactDescriptor::ProofContextRegistry {
                artifact_id: ProofContextRegistryArtifactId::Value,
                content_digest,
            },
        );
        let mut snapshot = GovernanceRegistrySnapshot {
            kind: GovernanceRegistrySnapshotKind::Value,
            artifacts: [
                contract.descriptor.clone(),
                proof_context.descriptor.clone(),
                manifest.descriptor.clone(),
            ],
            snapshot_digest: Hash::new(format!("sha256:{}", "00".repeat(32))).unwrap(),
        };
        snapshot.snapshot_digest = Hash::new(canonical::sha256_digest(
            snapshot_digest_preimage(&snapshot).unwrap(),
        ))
        .unwrap();
        (
            snapshot,
            vec![contract, proof_context, manifest, envelope, payload],
        )
    }

    #[test]
    fn replay_schema_manifest_expands_and_validates_exact_closure() {
        let (snapshot, artifacts) = replay_fixture("./event-payload.schema.json");
        let closure = validate_governance_replay_schema_closure(&snapshot, &artifacts).unwrap();
        assert_eq!(closure.schemas.len(), 2);
        let selectors = governance_artifact_selectors_for_artifact(&artifacts[2]).unwrap();
        assert_eq!(selectors.len(), 2);
    }

    #[test]
    fn replay_schema_closure_rejects_missing_surplus_digest_and_bad_refs() {
        let (snapshot, mut artifacts) = replay_fixture("./event-payload.schema.json");
        let missing = artifacts.pop().unwrap();
        assert!(validate_governance_replay_schema_closure(&snapshot, &artifacts).is_err());
        artifacts.push(missing);

        let surplus = fixture_artifact(
            serde_json::json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://arkret.org/v1/schemas/surplus.schema.json",
                "type": "object"
            }),
            |content_digest| GovernanceRegistryArtifactDescriptor::ReplayJsonSchema {
                artifact_id: "schemas/surplus.schema.json".to_owned(),
                content_digest,
            },
        );
        artifacts.push(surplus);
        assert!(validate_governance_replay_schema_closure(&snapshot, &artifacts).is_err());

        let (snapshot, mut artifacts) = replay_fixture("./event-payload.schema.json");
        artifacts[4].canonical_bytes_b64u.push('A');
        assert!(validate_governance_replay_schema_closure(&snapshot, &artifacts).is_err());

        for reference in [
            "./missing.schema.json",
            "../escape.schema.json",
            "https://evil.example/schema.json",
        ] {
            let (snapshot, artifacts) = replay_fixture(reference);
            assert!(validate_governance_replay_schema_closure(&snapshot, &artifacts).is_err());
        }
    }

    #[test]
    fn replay_schema_manifest_rejects_noncanonical_order() {
        let (_, artifacts) = replay_fixture("./event-payload.schema.json");
        let mut manifest = serde_json::from_value::<GovernanceReplaySchemaManifest>(
            artifacts[2].decoded_canonical_value().unwrap(),
        )
        .unwrap();
        manifest.artifacts.swap(0, 1);
        assert!(manifest.validate().is_err());
    }
}
