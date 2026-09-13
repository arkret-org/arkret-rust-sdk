//! Content-addressed dependencies required by historical `apply_seal` replay.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_identity::AuthenticatedSignerResolutionEvidence;
use arkret_wire::{
    AvailabilityReceipt, CollisionVariantRecordId, Event, Hash, RealmId, Result, Seal, SealId,
    WireError, canonical,
};
use serde::{Deserialize, Serialize};

use crate::events_payloads::state::{
    CollisionVariantRecord, ForkResolutionConflictEvidence, ForkResolutionPayload,
    ForkResolutionVariantLocator,
};
use crate::history_key::{
    HistoryKeyResponseLostRecord, HistoryKeyResponseRecord, HistoryKeyResponseSendRequestBody,
    MinimalMetadataMlsLeafSignerEvidence, PeerHistoryTraversalAccess, SelfHistoryTraversalAccess,
};

pub const MAX_GOVERNANCE_DEPENDENCY_SELECTORS: usize = 1_024;
pub const MAX_GOVERNANCE_DEPENDENCY_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GovernanceDependencySelector {
    AppletInstallationAuthority {
        content_digest: Hash,
    },
    AvailabilityReceipt {
        content_digest: Hash,
    },
    AuthenticatedSignerResolutionEvidence {
        content_digest: Hash,
    },
    MinimalMetadataMlsLeafSignerEvidence {
        content_digest: Hash,
    },
    CollisionVariantRecord {
        collision_variant_record_id: CollisionVariantRecordId,
    },
}

impl GovernanceDependencySelector {
    fn kind(&self) -> &'static str {
        match self {
            Self::AppletInstallationAuthority { .. } => "applet_installation_authority",
            Self::AvailabilityReceipt { .. } => "availability_receipt",
            Self::AuthenticatedSignerResolutionEvidence { .. } => {
                "authenticated_signer_resolution_evidence"
            }
            Self::MinimalMetadataMlsLeafSignerEvidence { .. } => {
                "minimal_metadata_mls_leaf_signer_evidence"
            }
            Self::CollisionVariantRecord { .. } => "collision_variant_record",
        }
    }

    pub fn canonical_sort_key(&self) -> Result<(&'static str, Vec<u8>)> {
        Ok((self.kind(), canonical::canonical_json_bytes(self)?))
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::AvailabilityReceipt { .. } | Self::CollisionVariantRecord { .. } => Ok(()),
            Self::AppletInstallationAuthority { content_digest }
            | Self::AuthenticatedSignerResolutionEvidence { content_digest }
            | Self::MinimalMetadataMlsLeafSignerEvidence { content_digest } => {
                if !content_digest.as_ref().starts_with("sha256:") {
                    return Err(WireError::Protocol(format!(
                        "{} selector content_digest must use sha256",
                        self.kind()
                    )));
                }
                Ok(())
            }
        }
    }
}

/// Discover the evidence dependencies required to replay exact signed Seals
/// and Events under the Realm's compiled profile.
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
        event.validate_for_accepted_structural()?;
        event.verify_event_id_matches_content_with_digest_suite(digest_suite)?;
        event.validate_proof_bindings_with_digest_suite(digest_suite)?;
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
        let [producer] = event.proofs.as_slice() else {
            return Err(WireError::Protocol(
                "dependency acquisition requires exactly one producer proof".to_owned(),
            ));
        };
        producer.validate_signer_resolution_evidence_ref()?;
        let evidence_ref = producer
            .signer_resolution_evidence_ref
            .as_ref()
            .expect("validation requires signer evidence");
        selectors.push(
            GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                content_digest: evidence_ref.content_digest()?,
            },
        );
        selectors.extend(fork_resolution_variant_record_selectors(event)?);
    }
    canonicalize_selectors(selectors)
}

/// Collision variant records an `ak.fork.resolution` Move references.
///
/// A receiver must hold every referenced record before `apply_seal`: a missing
/// one is a typed dependency miss, not a licence to adjudicate the collision on
/// the inline arm alone.
pub fn fork_resolution_variant_record_selectors(
    event: &Event,
) -> Result<Vec<GovernanceDependencySelector>> {
    if event.kind != arkret_wire::EventKind::ForkResolution {
        return Ok(Vec::new());
    }
    let payload: ForkResolutionPayload = serde_json::from_value(serde_json::Value::Object(
        event.payload.clone().into_iter().collect(),
    ))?;
    // `winner_index` selects one of these same two locators, so the verdict
    // never adds a third reference to resolve
    // (`authz/event-auth-state-resolution.md` collision adjudication).
    let mut locators: Vec<&ForkResolutionVariantLocator> = Vec::new();
    if let ForkResolutionConflictEvidence::FullHashCollision { variants } =
        &payload.conflict_evidence
    {
        locators.extend(variants.iter());
    }
    Ok(locators
        .into_iter()
        .filter_map(|locator| match locator {
            ForkResolutionVariantLocator::CollisionVariantRecord {
                collision_variant_record_id,
                ..
            } => Some(GovernanceDependencySelector::CollisionVariantRecord {
                collision_variant_record_id: collision_variant_record_id.clone(),
            }),
            ForkResolutionVariantLocator::InlineCanonicalBytes { .. } => None,
        })
        .collect())
}

/// Verify every referenced collision record before a fork-resolution Move is applied.
///
/// Both locator arms end at the same place: complete canonical Event bytes that
/// independently recompute to the subject `event_id` under this Realm's suite.
/// A referenced record additionally has to bind to the exact
/// `(collision_variant_record_id, collision_variant_record_digest)` the Move
/// signs and to carry a proof by the Move's own principal, which the caller
/// verifies against the key it already resolved for that principal.
pub fn validate_fork_resolution_collision_dependencies<VerifyRecordProof>(
    event: &Event,
    dependencies: &[GovernanceDependency],
    digest_suite: arkret_canonical::DigestSuite,
    mut verify_record_proof: VerifyRecordProof,
) -> Result<()>
where
    VerifyRecordProof: FnMut(&CollisionVariantRecord, &[u8]) -> Result<()>,
{
    if event.kind != arkret_wire::EventKind::ForkResolution {
        return Ok(());
    }
    let payload: ForkResolutionPayload = serde_json::from_value(serde_json::Value::Object(
        event.payload.clone().into_iter().collect(),
    ))
    .map_err(|error| {
        WireError::Protocol(format!(
            "fork resolution payload cannot be decoded for dependency validation: {error}"
        ))
    })?;
    let ForkResolutionConflictEvidence::FullHashCollision { variants } = &payload.conflict_evidence
    else {
        return Ok(());
    };
    let crate::events_payloads::ForkResolutionSubject::EventIdCollision {
        event_id: collision_event_id,
    } = &payload.subject
    else {
        return Err(WireError::Protocol(
            "full-hash collision evidence requires an Event-id collision subject".to_owned(),
        ));
    };

    for locator in variants {
        let canonical_event_bytes = match locator {
            ForkResolutionVariantLocator::InlineCanonicalBytes {
                canonical_event_bytes_b64u,
            } => {
                let event_bytes =
                    arkret_canonical::base64url_decode(canonical_event_bytes_b64u.as_str())?;
                if event_bytes.is_empty() || event_bytes.len() > 1_048_576 {
                    return Err(WireError::Protocol(
                        "inline collision variant Event byte length is invalid".to_owned(),
                    ));
                }
                event_bytes
            }
            ForkResolutionVariantLocator::CollisionVariantRecord {
                collision_variant_record_id,
                ..
            } => {
                let mut records = dependencies
                    .iter()
                    .filter_map(|dependency| match dependency {
                        GovernanceDependency::CollisionVariantRecord {
                            selector:
                                GovernanceDependencySelector::CollisionVariantRecord {
                                    collision_variant_record_id: selected_id,
                                },
                            collision_variant_record,
                        } if selected_id == collision_variant_record_id => {
                            Some(collision_variant_record)
                        }
                        _ => None,
                    });
                let record = records.next().ok_or_else(|| {
                    WireError::Protocol(format!(
                        "collision variant record dependency missing: {collision_variant_record_id}"
                    ))
                })?;
                if records.next().is_some() {
                    return Err(WireError::Protocol(format!(
                        "collision variant record dependency is ambiguous: {collision_variant_record_id}"
                    )));
                }
                let canonical_event_bytes =
                    record.canonical_event_bytes_for_locator(event, locator, digest_suite)?;
                let proof_binding_bytes = record.proof_binding_bytes()?;
                verify_record_proof(record, &proof_binding_bytes)?;
                canonical_event_bytes
            }
        };
        let collision_event =
            Event::from_digest_payload_bytes(&canonical_event_bytes, digest_suite)?;
        if collision_event.realm_id != event.realm_id
            || &collision_event.event_id != collision_event_id
        {
            return Err(WireError::Protocol(
                "collision variant Event identity or Realm binding mismatch".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Discover the next signer-evidence layer referenced by already resolved
/// principal or Agent evidence. Repeat until this returns an empty set;
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
            AuthenticatedSignerResolutionEvidence::Service { .. }
            | AuthenticatedSignerResolutionEvidence::AccountDeviceControl { .. } => {}
            AuthenticatedSignerResolutionEvidence::Principal {
                attester_signer_evidence_ref,
                ..
            }
            | AuthenticatedSignerResolutionEvidence::AccountDevice {
                attester_signer_evidence_ref,
                ..
            } => selectors.push(
                GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                    content_digest: attester_signer_evidence_ref.content_digest()?,
                },
            ),
            AuthenticatedSignerResolutionEvidence::Agent {
                attester_signer_evidence_ref,
                account_authority_signer_evidence_ref,
                agent_signer_evidence,
                ..
            } => {
                for evidence_ref in [
                    attester_signer_evidence_ref,
                    account_authority_signer_evidence_ref,
                ]
                .into_iter()
                .chain(agent_signer_evidence.required_historical_signer_refs())
                {
                    selectors.push(
                        GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                            content_digest: evidence_ref.content_digest()?,
                        },
                    );
                }
            }
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
    for dependency in dependencies {
        if let GovernanceDependency::MinimalMetadataMlsLeafSignerEvidence {
            minimal_metadata_mls_leaf_signer_evidence,
            ..
        } = dependency
        {
            selectors.push(
                GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                    content_digest: minimal_metadata_mls_leaf_signer_evidence
                        .identity_link_signer_evidence_ref
                        .content_digest()?,
                },
            )
        }
    }
    canonicalize_selectors(selectors)
}

/// Validate the exact signer-evidence closure used to admit one history
/// response source proof. The root must be either a Principal/Agent
/// evidence object or the dedicated minimal-metadata MLS evidence. Service
/// evidence is valid only as a recursively referenced attester leaf.
pub fn validate_history_source_signer_dependency_closure(
    source: &HistoryKeyResponseSendRequestBody,
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
    let root = source.source_signer_evidence_ref.content_digest()?;
    if let Some(evidence) = minimal.get(&root) {
        if minimal.len() != 1 || evidence.evidence_ref()? != source.source_signer_evidence_ref {
            return Err(WireError::Protocol(
                "minimal-metadata source signer closure contains surplus or mismatched evidence"
                    .to_owned(),
            ));
        }
        let identity_link = evidence.validate_identity_link_binding()?;
        let identity_link_signer_digest = evidence
            .identity_link_signer_evidence_ref
            .content_digest()?;
        let signer = authenticated
            .get(&identity_link_signer_digest)
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
        validate_authenticated_evidence_reachability(&authenticated, &identity_link_signer_digest)?;
        return Ok(());
    }
    let root_evidence = authenticated.get(&root).ok_or_else(|| {
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
    validate_authenticated_evidence_reachability(&authenticated, &root)?;
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
            AuthenticatedSignerResolutionEvidence::Service { .. }
            | AuthenticatedSignerResolutionEvidence::AccountDeviceControl { .. } => {}
            AuthenticatedSignerResolutionEvidence::Principal {
                attester_signer_evidence_ref,
                ..
            }
            | AuthenticatedSignerResolutionEvidence::AccountDevice {
                attester_signer_evidence_ref,
                ..
            } => pending.push(attester_signer_evidence_ref.content_digest()?),
            AuthenticatedSignerResolutionEvidence::Agent {
                attester_signer_evidence_ref,
                account_authority_signer_evidence_ref,
                agent_signer_evidence,
                ..
            } => {
                for evidence_ref in [
                    attester_signer_evidence_ref,
                    account_authority_signer_evidence_ref,
                ]
                .into_iter()
                .chain(agent_signer_evidence.required_historical_signer_refs())
                {
                    pending.push(evidence_ref.content_digest()?);
                }
            }
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
    source: &HistoryKeyResponseSendRequestBody,
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
    let root = source.source_signer_evidence_ref.content_digest()?;
    let mut selected = Vec::new();
    if let Some(dependency) = minimal.get(&root) {
        if authenticated.contains_key(&root) {
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
        let mut pending = vec![
            evidence
                .identity_link_signer_evidence_ref
                .content_digest()?,
        ];
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
                    attester_signer_evidence_ref,
                    ..
                } => pending.push(attester_signer_evidence_ref.content_digest()?),
                AuthenticatedSignerResolutionEvidence::Agent { .. }
                | AuthenticatedSignerResolutionEvidence::AccountDevice { .. }
                | AuthenticatedSignerResolutionEvidence::AccountDeviceControl { .. } => {
                    return Err(WireError::Protocol(
                        "minimal-metadata IdentityLink signer closure contains Agent evidence"
                            .to_owned(),
                    ));
                }
            }
            selected.push((*dependency).clone());
        }
    } else {
        let mut pending = vec![root];
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
                AuthenticatedSignerResolutionEvidence::Service { .. }
                | AuthenticatedSignerResolutionEvidence::AccountDeviceControl { .. } => {}
                AuthenticatedSignerResolutionEvidence::Principal {
                    attester_signer_evidence_ref,
                    ..
                }
                | AuthenticatedSignerResolutionEvidence::AccountDevice {
                    attester_signer_evidence_ref,
                    ..
                } => pending.push(attester_signer_evidence_ref.content_digest()?),
                AuthenticatedSignerResolutionEvidence::Agent {
                    attester_signer_evidence_ref,
                    account_authority_signer_evidence_ref,
                    agent_signer_evidence,
                    ..
                } => {
                    for evidence_ref in [
                        attester_signer_evidence_ref,
                        account_authority_signer_evidence_ref,
                    ]
                    .into_iter()
                    .chain(agent_signer_evidence.required_historical_signer_refs())
                    {
                        pending.push(evidence_ref.content_digest()?);
                    }
                }
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
    verification_method: &arkret_wire::DidUrl,
    dependencies: &[GovernanceDependency],
) -> Result<Vec<GovernanceDependency>> {
    let evidence_digest = evidence_ref.content_digest()?;
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
        if content_digest != &evidence_digest {
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
    AppletInstallationAuthority {
        selector: GovernanceDependencySelector,
        applet_installation_authority:
            Box<crate::applet_installation_authority::AppletInstallationAuthority>,
    },
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
    CollisionVariantRecord {
        selector: GovernanceDependencySelector,
        collision_variant_record: Box<CollisionVariantRecord>,
    },
}

impl Eq for GovernanceDependency {}

impl GovernanceDependency {
    /// Discover the standard dependencies embedded in this frozen object.
    /// This discovers coordinates only and never authenticates the evidence.
    pub fn dependency_selectors(&self) -> Result<Vec<GovernanceDependencySelector>> {
        self.validate_branch()?;
        match self {
            Self::AppletInstallationAuthority {
                applet_installation_authority,
                ..
            } => governance_runtime_dependency_selector_coordinates_for_acquisition(
                &[],
                &[
                    applet_installation_authority.registration_event.clone(),
                    applet_installation_authority.capability_grant_event.clone(),
                ],
            ),
            Self::AuthenticatedSignerResolutionEvidence {
                authenticated_signer_resolution_evidence,
                ..
            } => governance_attester_evidence_selectors(std::slice::from_ref(
                authenticated_signer_resolution_evidence,
            )),
            _ => Ok(Vec::new()),
        }
    }

    pub fn selector(&self) -> &GovernanceDependencySelector {
        match self {
            Self::AppletInstallationAuthority { selector, .. }
            | Self::AvailabilityReceipt { selector, .. }
            | Self::AuthenticatedSignerResolutionEvidence { selector, .. }
            | Self::MinimalMetadataMlsLeafSignerEvidence { selector, .. }
            | Self::CollisionVariantRecord { selector, .. } => selector,
        }
    }

    fn validate_branch(&self) -> Result<()> {
        match self {
            Self::AppletInstallationAuthority {
                selector:
                    GovernanceDependencySelector::AppletInstallationAuthority { content_digest },
                applet_installation_authority,
            } => {
                applet_installation_authority.validate_structural()?;
                if content_digest != &applet_installation_authority.canonical_sha256_digest()? {
                    return Err(WireError::Protocol(
                        "Applet installation authority digest mismatch".to_owned(),
                    ));
                }
            }
            Self::AvailabilityReceipt {
                selector: GovernanceDependencySelector::AvailabilityReceipt { content_digest },
                availability_receipt,
            } => {
                availability_receipt.validate_structural()?;
                let digest_suite = content_digest.digest_suite()?;
                if content_digest
                    != &availability_receipt.full_receipt_digest(|bytes| {
                        Ok(Hash::new(arkret_canonical::canonical::digest(
                            digest_suite,
                            bytes,
                        ))?)
                    })?
                {
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
            Self::CollisionVariantRecord {
                selector:
                    GovernanceDependencySelector::CollisionVariantRecord {
                        collision_variant_record_id,
                    },
                collision_variant_record,
            } => {
                collision_variant_record.validate_structural()?;
                if collision_variant_record_id
                    != &collision_variant_record.collision_variant_record_id
                {
                    return Err(WireError::Protocol(
                        "collision variant record dependency selector id mismatch".to_owned(),
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
    SelfGovernanceDependencyResolveRequestBody,
    SelfHistoryTraversalAccess
);
governance_dependency_resolve_request!(
    PeerGovernanceDependencyResolveRequestBody,
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
        request: &SelfGovernanceDependencyResolveRequestBody,
    ) -> Result<()> {
        request.validate()?;
        self.validate_for_request_parts(&request.selectors, request.byte_limit)
    }

    pub fn validate_for_peer_request(
        &self,
        request: &PeerGovernanceDependencyResolveRequestBody,
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

/// Bounded pending Control Move discovery at an exact current PCR basis.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcrPendingControlRequestBody {
    pub realm_id: RealmId,
    pub predecessor_ref: SealId,
    pub limit: u32,
}

impl PcrPendingControlRequestBody {
    pub fn validate(&self) -> Result<()> {
        if !(1..=1024).contains(&self.limit) {
            return Err(WireError::Protocol(
                "pending Control Move limit must be 1..=1024".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcrPendingControlOutcome {
    pub realm_id: RealmId,
    pub predecessor_ref: SealId,
    pub event_digests: Vec<Hash>,
    pub has_more: bool,
}

impl PcrPendingControlOutcome {
    pub fn validate_for_request(&self, request: &PcrPendingControlRequestBody) -> Result<()> {
        request.validate()?;
        if self.realm_id != request.realm_id
            || self.predecessor_ref != request.predecessor_ref
            || self.event_digests.len() > request.limit as usize
            || self.event_digests.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .event_digests
                .iter()
                .any(|digest| !digest.as_str().starts_with("sha256:"))
            || (self.has_more && self.event_digests.len() != request.limit as usize)
        {
            return Err(WireError::Protocol(
                "pending PCR result does not match the exact bounded request".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Exact successor PCR signing intent, frozen before preparation and retries.
///
/// # The signing-slot fence
///
/// The Station freezes one canonical request per
/// `(realm_id, signer slot, predecessor basis)` before it returns the first
/// signable body, so exactly one signable body ever leaves that signing
/// position. A *different* canonical request against the same slot is refused
/// with [`arkret_wire::error_codes::ErrorCode::SealSignerSlotFenced`] (HTTP
/// 409); the frozen request keeps replaying its byte-identical body across
/// timeouts, lease loss, failover and restart, because the device may already
/// have signed that body offline.
///
/// The operational consequence for every client is one rule: **a retry re-sends
/// the same canonical bytes.** The operation's registered idempotency is
/// `canonical_hash` over the full body, so a freshly generated `hlc`, a
/// re-ordered `delta` or a different `predecessor_ref` is not a retry —
/// it is a second request that the fence will refuse. On a 409
/// `seal_signer_slot_fenced`, the recovery is to re-send the *original*
/// request and take back the original body, never to vary the request until one
/// is accepted. [`Self::canonical_request_hash`] is that identity; hold the
/// request value itself and reuse it.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealPrepareRequestBody {
    pub realm_id: RealmId,
    pub predecessor_ref: SealId,
    pub event_digests: Vec<Hash>,
    pub hlc: arkret_wire::Hlc,
}

impl SealPrepareRequestBody {
    /// The request identity the signing-slot fence is keyed on: `sha256:` over
    /// the RFC 8785 JCS encoding of the complete request body, matching the
    /// operation registry's `canonical_hash` / `canonical_hash_input=full_body`
    /// declaration for `ak.self.seals.command.prepare.v1`.
    ///
    /// Two values that hash equal are the same retry; two that do not are two
    /// requests, and at most one of them can ever be signable.
    pub fn canonical_request_hash(&self) -> Result<Hash> {
        self.validate()?;
        Hash::new(canonical::sha256_digest(canonical::canonical_json_bytes(
            self,
        )?))
        .map_err(WireError::from)
    }

    /// Digest suite locked by the Realm that owns this successor.
    ///
    /// Digest-suite transitions do not use this operation, so every delta
    /// digest and every predecessor Seal must use one identical suite.
    pub fn digest_suite(&self) -> Result<arkret_canonical::DigestSuite> {
        let suite = self
            .event_digests
            .first()
            .ok_or_else(|| WireError::Protocol("event_digests must not be empty".to_owned()))?
            .digest_suite()?;
        if self
            .event_digests
            .iter()
            .any(|digest| digest.digest_suite().ok() != Some(suite))
        {
            return Err(WireError::Protocol(
                "PCR delta digests must use one Realm digest suite".to_owned(),
            ));
        }
        let digest = self
            .predecessor_ref
            .as_str()
            .strip_prefix("ak:seal:")
            .ok_or_else(|| WireError::Protocol("invalid predecessor Seal id".to_owned()))?;
        if Hash::new(digest)?.digest_suite()? != suite {
            return Err(WireError::Protocol(
                "PCR predecessor and delta must use the same Realm digest suite".to_owned(),
            ));
        }
        Ok(suite)
    }

    pub fn validate(&self) -> Result<()> {
        validate_sorted_unique_nonempty(&self.event_digests, 1_024, "event_digests")?;
        self.digest_suite()?;
        Ok(())
    }
}

/// Bounded unsigned body prepared by the caller's authenticated Account Station.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealPrepareOutcome {
    #[serde(deserialize_with = "deserialize_successor_pcr_body")]
    pub seal_body: arkret_wire::UnsignedSeal,
}

fn deserialize_successor_pcr_body<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<arkret_wire::UnsignedSeal, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    for field in [
        "covered_event_digests",
        "previous_state_root",
        "previous_digest_algorithm",
    ] {
        if value.get(field).is_some() {
            return Err(serde::de::Error::custom(format!(
                "successor PCR preparation forbids {field}"
            )));
        }
    }
    serde_json::from_value(value).map_err(serde::de::Error::custom)
}

impl SealPrepareOutcome {
    pub fn validate_for_request(&self, request: &SealPrepareRequestBody) -> Result<()> {
        request.validate()?;
        let digest_suite = request.digest_suite()?;
        let body = &self.seal_body;
        if body.realm_id != request.realm_id
            || body.predecessor_ref.as_ref() != Some(&request.predecessor_ref)
            || body.hlc != request.hlc
        {
            return Err(WireError::Protocol(
                "prepared Seal does not match the frozen signing intent".to_owned(),
            ));
        }
        if !body.covered_event_digests.is_empty()
            || body.previous_state_root.is_some()
            || body.previous_digest_algorithm.is_some()
            || body.notary_seq == 0
        {
            return Err(WireError::Protocol(
                "PCR preparation requires a successor Seal".to_owned(),
            ));
        }
        if body
            .command_results
            .iter()
            .map(|result| &result.event_digest)
            .ne(request.event_digests.iter())
        {
            return Err(WireError::Protocol(
                "prepared Seal command_results do not match requested execution order".to_owned(),
            ));
        }
        let mut committed = body
            .command_results
            .iter()
            .filter(|result| result.outcome == arkret_wire::CommandOutcome::Committed)
            .flat_map(|result| result.unit_event_digests.iter().cloned())
            .collect::<Vec<_>>();
        committed.sort();
        if committed != body.delta {
            return Err(WireError::Protocol(
                "prepared Seal delta must equal committed command unit members".to_owned(),
            ));
        }
        validate_sorted_unique_nonempty(
            &body.availability_receipt_digests,
            1_024,
            "availability_receipt_digests",
        )?;
        if [&body.control_event_set_root, &body.state_root]
            .into_iter()
            .chain(body.availability_receipt_digests.iter())
            .any(|digest| digest.digest_suite().ok() != Some(digest_suite))
        {
            return Err(WireError::Protocol(
                "PCR preparation roots and receipts must use the Realm digest suite".to_owned(),
            ));
        }
        Ok(())
    }

    /// Bind the exact request and sign its Station-prepared canonical body.
    /// Caller identity and local key selection remain the host's responsibility.
    pub fn sign<S: arkret_wire::PayloadSigner + ?Sized>(
        &self,
        request: &SealPrepareRequestBody,
        signer: &S,
    ) -> Result<Seal> {
        self.validate_for_request(request)?;
        let digest_suite = request.digest_suite()?;
        Seal::sign_with_signer(self.seal_body.clone(), digest_suite, signer)
    }
}

fn validate_sorted_unique_nonempty<T: Ord>(values: &[T], max: usize, field: &str) -> Result<()> {
    if values.is_empty() || values.len() > max {
        return Err(WireError::Protocol(format!(
            "{field} must contain 1..={max} values"
        )));
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(WireError::Protocol(format!(
            "{field} must be byte-wise sorted and duplicate-free"
        )));
    }
    Ok(())
}
