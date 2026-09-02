//! Content-addressed dependencies required by historical `apply_seal` replay.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_identity::AuthenticatedSignerResolutionEvidence;
use arkret_wire::{
    AvailabilityReceipt, Event, EventProof, Hash, RealmId, Result, Seal, SealId, WireError,
    canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::events_payloads::state::{
    CollisionVariantRecord, ForkResolutionConflictEvidence, ForkResolutionPayload,
    ForkResolutionVariantLocator, ForkResolutionVerdict,
};
use crate::history_key::{
    HistoryKeyResponseLostRecord, HistoryKeyResponseRecord, HistoryKeyResponseSendRequest,
    MinimalMetadataMlsLeafSignerEvidence, PeerHistoryTraversalAccess, SelfHistoryTraversalAccess,
};

pub const MAX_GOVERNANCE_DEPENDENCY_SELECTORS: usize = 1_024;
pub const MAX_GOVERNANCE_DEPENDENCY_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GovernanceDependencySelector {
    AvailabilityReceipt { content_digest: Hash },
    AuthenticatedSignerResolutionEvidence { content_digest: Hash },
    MinimalMetadataMlsLeafSignerEvidence { content_digest: Hash },
    CollisionVariantRecord { content_digest: Hash },
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
            Self::CollisionVariantRecord { .. } => "collision_variant_record",
        }
    }

    pub fn canonical_sort_key(&self) -> Result<(&'static str, Vec<u8>)> {
        Ok((self.kind(), canonical::canonical_json_bytes(self)?))
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            // The collision variant record is addressed under the Realm's
            // active digest suite, like the availability receipt, because the
            // locator that names it is signed inside a Realm-scoped Move.
            Self::AvailabilityReceipt { .. } | Self::CollisionVariantRecord { .. } => Ok(()),
            Self::AuthenticatedSignerResolutionEvidence { content_digest }
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
        match event.proofs.as_slice() {
            [EventProof::Producer(_)] => event.validate_for_direct_history_structural()?,
            [EventProof::Producer(_), EventProof::StationAdmission(_)] => {
                event.validate_station_admission_binding(digest_suite)?;
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
            | [EventProof::Producer(_), EventProof::StationAdmission(_)] => {}
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
                EventProof::StationAdmission(admission) => {
                    if admission.signer_resolution_evidence_ref.content_digest()?
                        != admission.signer_resolution_evidence_digest
                        || !admission
                            .signer_resolution_evidence_digest
                            .as_str()
                            .starts_with("sha256:")
                    {
                        return Err(WireError::Protocol(
                            "Station admission signer evidence binding mismatch".to_owned(),
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
    let mut locators: Vec<&ForkResolutionVariantLocator> = Vec::new();
    if let ForkResolutionConflictEvidence::FullHashCollision { variants } =
        &payload.conflict_evidence
    {
        locators.extend(variants.iter());
    }
    if let ForkResolutionVerdict::CollisionWinner {
        winner_preimage, ..
    } = &payload.verdict
    {
        locators.push(winner_preimage);
    }
    Ok(locators
        .into_iter()
        .filter_map(|locator| match locator {
            ForkResolutionVariantLocator::CollisionVariantRecord {
                collision_variant_record_digest,
                ..
            } => Some(GovernanceDependencySelector::CollisionVariantRecord {
                content_digest: collision_variant_record_digest.clone(),
            }),
            ForkResolutionVariantLocator::InlineCanonicalBytes { .. } => None,
        })
        .collect())
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
            AuthenticatedSignerResolutionEvidence::Service { .. } => {}
            AuthenticatedSignerResolutionEvidence::Principal {
                attester_signer_evidence_digest,
                ..
            } => selectors.push(
                GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                    content_digest: attester_signer_evidence_digest.clone(),
                },
            ),
            AuthenticatedSignerResolutionEvidence::Agent {
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
/// response source proof. The root must be either a Principal/Agent
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
            AuthenticatedSignerResolutionEvidence::Agent {
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
                AuthenticatedSignerResolutionEvidence::Agent { .. } => {
                    return Err(WireError::Protocol(
                        "minimal-metadata IdentityLink signer closure contains Agent evidence"
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
                AuthenticatedSignerResolutionEvidence::Agent {
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
    CollisionVariantRecord {
        selector: GovernanceDependencySelector,
        collision_variant_record: Box<CollisionVariantRecord>,
    },
}

impl Eq for GovernanceDependency {}

impl GovernanceDependency {
    pub fn selector(&self) -> &GovernanceDependencySelector {
        match self {
            Self::AvailabilityReceipt { selector, .. }
            | Self::AuthenticatedSignerResolutionEvidence { selector, .. }
            | Self::MinimalMetadataMlsLeafSignerEvidence { selector, .. }
            | Self::CollisionVariantRecord { selector, .. } => selector,
        }
    }

    fn validate_branch(&self) -> Result<()> {
        match self {
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
                selector: GovernanceDependencySelector::CollisionVariantRecord { content_digest },
                collision_variant_record,
            } => {
                // The Realm's active suite is the one that addressed this
                // record, so the same suite recomputes the colliding Event
                // identity the record claims.
                let digest_suite = content_digest.digest_suite()?;
                collision_variant_record.validate(digest_suite)?;
                if content_digest != &collision_variant_record.content_digest(digest_suite)? {
                    return Err(WireError::Protocol(
                        "collision variant record dependency selector digest mismatch".to_owned(),
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

/// Exact PCR-only request for the availability dependencies needed before a
/// device signs one successor Seal.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealAvailabilityReceiptIssueRequest {
    pub realm_id: RealmId,
    pub predecessor_refs: Vec<SealId>,
    pub event_digests: Vec<Hash>,
}

impl SealAvailabilityReceiptIssueRequest {
    pub fn validate(&self) -> Result<()> {
        validate_sorted_unique_nonempty(&self.predecessor_refs, 64, "predecessor_refs")?;
        validate_sorted_unique_nonempty(&self.event_digests, 1_024, "event_digests")?;
        Ok(())
    }
}

/// Server-timestamped PCR availability preparation copied verbatim into the
/// prospective successor Seal after the client verifies the complete typed
/// dependency closure.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealAvailabilityReceiptIssueOutcome {
    pub realm_id: RealmId,
    pub predecessor_refs: Vec<SealId>,
    pub event_digests: Vec<Hash>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub sealed_at: DateTime<Utc>,
    pub availability_receipt_digests: Vec<Hash>,
    pub governance_dependencies: Vec<GovernanceDependency>,
}

impl Eq for SealAvailabilityReceiptIssueOutcome {}

impl SealAvailabilityReceiptIssueOutcome {
    pub fn validate_for_request(
        &self,
        request: &SealAvailabilityReceiptIssueRequest,
    ) -> Result<()> {
        request.validate()?;
        if self.realm_id != request.realm_id
            || self.predecessor_refs != request.predecessor_refs
            || self.event_digests != request.event_digests
        {
            return Err(WireError::Protocol(
                "availability receipt issue outcome does not exactly echo the request basis"
                    .to_owned(),
            ));
        }
        validate_sorted_unique_nonempty(
            &self.availability_receipt_digests,
            1_024,
            "availability_receipt_digests",
        )?;
        if self.governance_dependencies.len() < 2 || self.governance_dependencies.len() > 2_048 {
            return Err(WireError::Protocol(
                "availability receipt issue outcome must contain 2..=2048 dependencies".to_owned(),
            ));
        }

        GovernanceDependencyResolveOutcome {
            items: self.governance_dependencies.clone(),
            missing_selectors: Vec::new(),
        }
        .validate()?;

        let requested_event_digests = request
            .event_digests
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut receipt_digests = BTreeSet::new();
        let mut receipt_event_digests = BTreeSet::new();
        let mut required_evidence_digests = BTreeSet::new();
        let mut returned_evidence_digests = BTreeSet::new();
        for dependency in &self.governance_dependencies {
            match dependency {
                GovernanceDependency::AvailabilityReceipt {
                    selector: GovernanceDependencySelector::AvailabilityReceipt { content_digest },
                    availability_receipt,
                } => {
                    if availability_receipt.realm_id != request.realm_id {
                        return Err(WireError::Protocol(
                            "availability receipt belongs to a different Realm".to_owned(),
                        ));
                    }
                    receipt_digests.insert(content_digest.clone());
                    receipt_event_digests.insert(availability_receipt.event_id.event_digest());
                    required_evidence_digests
                        .insert(availability_receipt.holder_signer_evidence_digest.clone());
                }
                GovernanceDependency::AuthenticatedSignerResolutionEvidence {
                    selector:
                        GovernanceDependencySelector::AuthenticatedSignerResolutionEvidence {
                            content_digest,
                        },
                    ..
                } => {
                    returned_evidence_digests.insert(content_digest.clone());
                }
                _ => {
                    return Err(WireError::Protocol(
                        "availability preparation contains an unrelated dependency kind".to_owned(),
                    ));
                }
            }
        }
        let declared_receipt_digests = self
            .availability_receipt_digests
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if receipt_digests != declared_receipt_digests
            || receipt_event_digests != requested_event_digests
            || receipt_digests.len() != request.event_digests.len()
            || required_evidence_digests != returned_evidence_digests
        {
            return Err(WireError::Protocol(
                "availability preparation is not every-and-only the requested receipts and signer evidence"
                    .to_owned(),
            ));
        }
        Ok(())
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
}
