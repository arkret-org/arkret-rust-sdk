//! Seal application and effective-view helpers.

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::DomainSeparationId;
use arkret_wire::event_envelope::{Event, EventSubmitContext};
use serde_json::Value;
use thiserror::Error;

use super::state_root::{
    compute_state_root, seal_merkle_audit_path_from_leaf_data, seal_merkle_root_from_leaf_data,
    verify_seal_merkle_audit_path_from_leaf_data,
};
use super::store::{CellRegistry, CellStore, ControlEventStore, SealStore};
use super::verify::{
    ControlMoveReject, ControlMoveVerificationContext, recovery_capability_is_active,
    verify_accepted_control_move_in_context, verify_control_move_in_context,
    verify_replayed_control_move_in_context,
};
use crate::lattice::ordered_log::IssuedOp;
use crate::lattice::{CellState, SealedOp};
use crate::{CellRef, Hash, ProjectedCellWrite, RealmId, Seal, SealId, canonical};

#[derive(Clone, Debug)]
pub struct SealEffect {
    pub seal: SealId,
    /// Accepted Control Events in **reducer apply order** — causal first, then
    /// digest-descending among concurrent Moves ([`deterministic_order`]).
    ///
    /// This is not the wire order. `Seal.delta` is byte-wise *ascending*, so for
    /// two independent Moves this vector is its exact reverse. Use
    /// [`SealEffect::wire_accepted_event_digests`] for anything a peer will
    /// compare against.
    pub accepted_event_digests: Vec<Hash>,
    pub post_state_root: Hash,
}

/// Fully verified Seal transition that has not mutated durable state yet.
///
/// Receivers that must persist additional evidence atomically with Seal
/// acceptance use this value as the immutable input to their single commit.
#[derive(Clone, Debug)]
pub struct PreparedSealEffect {
    pub effect: SealEffect,
    pub new_ops: Vec<(CellRef, IssuedOp)>,
    pub covered_event_digests: BTreeSet<Hash>,
}

/// Digest suites selected from the verified predecessor Realm state for one
/// Seal application. An ordinary Seal uses one suite everywhere. A Genesis
/// Seal uses `event_digest_suite` for every founding Event except the fixed
/// SHA-256 `ak.realm.create` bridge. A transition Seal authenticates its delta
/// Event under `event_digest_suite`, its pre-transition state under
/// `previous_state_digest_suite`, and the Seal plus post-transition roots under
/// `seal_digest_suite`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealDigestSuites {
    pub event_digest_suite: arkret_canonical::DigestSuite,
    pub seal_digest_suite: arkret_canonical::DigestSuite,
    pub previous_state_digest_suite: Option<arkret_canonical::DigestSuite>,
}

/// Seal-DAG and frozen-state dependencies required to verify one Event's
/// declared Seal basis.
#[derive(Clone, Copy)]
pub struct SealBasisVerificationContext<'a> {
    pub predecessor_closure: &'a BTreeSet<SealId>,
    pub realm_id: &'a RealmId,
    pub seals: &'a dyn SealStore,
    pub cells: &'a dyn CellStore,
    pub registry: &'a dyn CellRegistry,
    pub digest_suite: arkret_canonical::DigestSuite,
}

impl SealDigestSuites {
    pub const fn standard(digest_suite: arkret_canonical::DigestSuite) -> Self {
        Self {
            event_digest_suite: digest_suite,
            seal_digest_suite: digest_suite,
            previous_state_digest_suite: None,
        }
    }

    pub const fn transition(
        from_digest_suite: arkret_canonical::DigestSuite,
        to_digest_suite: arkret_canonical::DigestSuite,
    ) -> Self {
        Self {
            event_digest_suite: from_digest_suite,
            seal_digest_suite: to_digest_suite,
            previous_state_digest_suite: Some(from_digest_suite),
        }
    }
}

impl SealEffect {
    /// The accepted set in the one order a peer can reproduce.
    ///
    /// `service-operation-dtos.schema.json#/$defs/EventSealSubmitOutcome`
    /// defines `accepted_event_digests` as a *set*: byte-wise ascending and
    /// unique, the same normalization `Seal.delta` carries. Apply order is a
    /// local reducer detail and is deliberately not observable — a client cannot
    /// recompute it without the causal graph, so an order-sensitive comparison
    /// against it is a comparison between two different sequences.
    ///
    /// Both orders used to reach clients from the same field: this crate served
    /// apply order while the server's short-circuit paths served `seal.delta`,
    /// and three clients compared the result with `!=` against a `seal.delta`
    /// clone. For a two-Event bootstrap those agree exactly when the causal
    /// order happens to match ascending digest order — a coin flip per install.
    pub fn wire_accepted_event_digests(&self) -> Vec<Hash> {
        let mut digests = self.accepted_event_digests.clone();
        digests.sort();
        digests.dedup();
        digests
    }
}

#[derive(Debug, Error)]
pub enum SealReject {
    #[error("Seal structural / signature error: {0}")]
    Structural(String),

    #[error("Seal predecessor_refs contain unknown ids")]
    UnknownPredecessor,

    #[error("Seal.delta contains an event already covered by a predecessor")]
    DeltaAlreadyCovered,

    #[error("Control Event {event_digest} referenced in delta but not in store")]
    MissingControlEvent { event_digest: String },

    #[error("Control Move {event_digest} referenced in delta failed verification: {reason}")]
    ControlMoveRejected {
        event_digest: String,
        reason: String,
    },

    #[error("Control Move {event_digest} carries no seal_basis")]
    MissingSealBasis { event_digest: String },

    #[error(
        "Control Move {event_digest} seal_basis leaf {leaf} is outside the receiving Seal's \
         predecessor closure"
    )]
    SealBasisOutsideClosure { event_digest: String, leaf: String },

    #[error("declared control_event_set_root {declared} does not match recomputed {recomputed}")]
    ControlEventSetRootMismatch {
        declared: String,
        recomputed: String,
    },

    #[error("covered_event_digests does not equal predecessor coverage plus delta")]
    CoveredSetMismatch,

    #[error("declared completeness_root {declared} does not match recomputed {recomputed}")]
    CompletenessRootMismatch {
        declared: String,
        recomputed: String,
    },

    #[error("declared state_root {declared} does not match recomputed {recomputed}")]
    StateRootMismatch {
        declared: String,
        recomputed: String,
    },

    #[error("store error: {0}")]
    Store(String),
}

impl From<super::store::StoreError> for SealReject {
    fn from(e: super::store::StoreError) -> Self {
        SealReject::Store(e.to_string())
    }
}

/// Apply a Seal under an explicit CBA envelope context.
///
/// `AnchorUnit` is only valid for a first Seal after the caller has validated
/// the complete closed anchor unit. This layer cannot own that registry-backed
/// whitelist, but it still requires an empty predecessor view and applies all
/// other Seal and reducer checks.
// Four independent stores plus two caller-supplied verification closures; a
// bundling struct would only move the same arity behind a constructor.
#[allow(clippy::too_many_arguments)]
pub fn apply_seal_in_context<VerifyProofs, ProjectWrites>(
    seal: &Seal,
    events: &dyn ControlEventStore,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    digest_suites: SealDigestSuites,
    verify_proofs: VerifyProofs,
    project_writes: ProjectWrites,
    context: EventSubmitContext,
) -> Result<SealEffect, SealReject>
where
    VerifyProofs: Fn(&Event, arkret_canonical::DigestSuite) -> Result<(), String> + Copy,
    ProjectWrites:
        Fn(&Event, arkret_canonical::DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    let prepared = prepare_seal_with_proof_set(
        seal,
        events,
        seals,
        cells,
        registry,
        digest_suites,
        verify_proofs,
        project_writes,
        context,
        SealEventProofRegime::ProducerSubmission,
    )?;
    commit_prepared_seal(seal, events, seals, cells, digest_suites, prepared)
}

/// Verify an incoming producer-submission Seal without mutating its stores.
///
/// This is the validation half of [`apply_seal_in_context`]. It exists for
/// receivers whose acceptance transaction also persists typed dependency
/// evidence or other receiver-owned indexes.
#[allow(clippy::too_many_arguments)]
pub fn prepare_seal_in_context<VerifyProofs, ProjectWrites>(
    seal: &Seal,
    events: &dyn ControlEventStore,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    digest_suites: SealDigestSuites,
    verify_proofs: VerifyProofs,
    project_writes: ProjectWrites,
    context: EventSubmitContext,
) -> Result<PreparedSealEffect, SealReject>
where
    VerifyProofs: Fn(&Event, arkret_canonical::DigestSuite) -> Result<(), String> + Copy,
    ProjectWrites:
        Fn(&Event, arkret_canonical::DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    prepare_seal_with_proof_set(
        seal,
        events,
        seals,
        cells,
        registry,
        digest_suites,
        verify_proofs,
        project_writes,
        context,
        SealEventProofRegime::ProducerSubmission,
    )
}

/// Apply a Seal whose delta is loaded from the durable accepted-event lane.
/// Each Event must carry the closed Producer + StationAdmission proof
/// set; producer-submission Seals continue to use [`apply_seal_in_context`].
#[allow(clippy::too_many_arguments)]
pub fn apply_accepted_seal_in_context<VerifyProofs, ProjectWrites>(
    seal: &Seal,
    events: &dyn ControlEventStore,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    digest_suites: SealDigestSuites,
    verify_proofs: VerifyProofs,
    project_writes: ProjectWrites,
    context: EventSubmitContext,
) -> Result<SealEffect, SealReject>
where
    VerifyProofs: Fn(&Event, arkret_canonical::DigestSuite) -> Result<(), String> + Copy,
    ProjectWrites:
        Fn(&Event, arkret_canonical::DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    let prepared = prepare_seal_with_proof_set(
        seal,
        events,
        seals,
        cells,
        registry,
        digest_suites,
        verify_proofs,
        project_writes,
        context,
        SealEventProofRegime::FederationAccepted,
    )?;
    commit_prepared_seal(seal, events, seals, cells, digest_suites, prepared)
}

/// Apply a retained Seal whose Events may use either the historical
/// sole-Producer direct regime or the Producer + Admission federation regime.
/// The selected structural contract is derived from each exact Event proof
/// set; all remaining CBA, reducer, recovery, and state-root checks are shared.
#[allow(clippy::too_many_arguments)]
pub fn apply_replayed_seal_in_context<VerifyProofs, ProjectWrites>(
    seal: &Seal,
    events: &dyn ControlEventStore,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    digest_suites: SealDigestSuites,
    verify_proofs: VerifyProofs,
    project_writes: ProjectWrites,
    context: EventSubmitContext,
) -> Result<SealEffect, SealReject>
where
    VerifyProofs: Fn(&Event, arkret_canonical::DigestSuite) -> Result<(), String> + Copy,
    ProjectWrites:
        Fn(&Event, arkret_canonical::DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    let prepared = prepare_seal_with_proof_set(
        seal,
        events,
        seals,
        cells,
        registry,
        digest_suites,
        verify_proofs,
        project_writes,
        context,
        SealEventProofRegime::RetainedReplay,
    )?;
    commit_prepared_seal(seal, events, seals, cells, digest_suites, prepared)
}

#[derive(Clone, Copy)]
enum SealEventProofRegime {
    ProducerSubmission,
    FederationAccepted,
    RetainedReplay,
}

#[allow(clippy::too_many_arguments)]
fn prepare_seal_with_proof_set<VerifyProofs, ProjectWrites>(
    seal: &Seal,
    events: &dyn ControlEventStore,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    digest_suites: SealDigestSuites,
    verify_proofs: VerifyProofs,
    project_writes: ProjectWrites,
    context: EventSubmitContext,
    proof_regime: SealEventProofRegime,
) -> Result<PreparedSealEffect, SealReject>
where
    VerifyProofs: Fn(&Event, arkret_canonical::DigestSuite) -> Result<(), String> + Copy,
    ProjectWrites:
        Fn(&Event, arkret_canonical::DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    if context == EventSubmitContext::AnchorUnit && !seal.predecessor_refs.is_empty() {
        return Err(SealReject::Structural(
            "anchor-unit context is only valid for the first Seal".to_owned(),
        ));
    }
    seal.validate_id(digest_suites.seal_digest_suite)
        .map_err(|e| SealReject::Structural(format!("id: {e}")))?;
    seal.validate_structural()
        .map_err(|e| SealReject::Structural(e.to_string()))?;
    if !seals.predecessors_known(&seal.predecessor_refs)? {
        return Err(SealReject::UnknownPredecessor);
    }
    if seal.predecessor_refs.is_empty() && seal.delta.is_empty() {
        return Err(SealReject::Structural(
            "the first Seal must cover the complete non-empty Realm anchor unit".to_owned(),
        ));
    }

    let pred_covered = union_predecessor_covered_events(&seal.predecessor_refs, seals)?;
    if seal.delta.iter().any(|m| pred_covered.contains(m)) {
        return Err(SealReject::DeltaAlreadyCovered);
    }

    let mut covered = pred_covered.clone();
    covered.extend(seal.delta.iter().cloned());
    if !seal.covered_event_digests.is_empty() {
        let declared: BTreeSet<Hash> = seal.covered_event_digests.iter().cloned().collect();
        if declared != covered {
            return Err(SealReject::CoveredSetMismatch);
        }
    }
    let recomputed_control_root =
        control_event_set_root(&covered, digest_suites.seal_digest_suite)?;
    if recomputed_control_root.as_str() != seal.control_event_set_root.as_str() {
        return Err(SealReject::ControlEventSetRootMismatch {
            declared: seal.control_event_set_root.as_str().to_owned(),
            recomputed: recomputed_control_root.as_str().to_owned(),
        });
    }

    // The baseline every ordinary Control Move in this batch is evaluated
    // against is frozen at the predecessor view: same-batch writes MUST NOT
    // advance a later Move's precondition basis (§6.3.1
    // frozen-predecessor rule). The first closed anchor unit is the sole
    // exception: realm-and-space.md §2.5 requires ak.realm.create's registered
    // writes to be staged before its bootstrap follow-ups are evaluated.
    let pre_state =
        effective_state_for_covered_events(&pred_covered, &seal.realm_id, cells, registry)?;
    let pred_closure = predecessor_seal_closure(&seal.predecessor_refs, seals)?;

    let mut new_events: Vec<(Hash, Event)> = Vec::with_capacity(seal.delta.len());
    for digest in &seal.delta {
        let event = events
            .get(digest)?
            .ok_or_else(|| SealReject::MissingControlEvent {
                event_digest: digest.as_str().to_owned(),
            })?;
        let event_digest_suite = event_digest_suite_for_seal(&event, seal, digest_suites);
        let recomputed = Hash::new(
            event
                .event_digest_with_digest_suite(event_digest_suite)
                .map_err(|error| {
                    SealReject::Structural(format!("Control Event digest failed: {error}"))
                })?,
        )
        .map_err(|error| {
            SealReject::Structural(format!("Control Event digest is invalid: {error}"))
        })?;
        if recomputed != *digest {
            return Err(SealReject::Structural(format!(
                "Seal.delta digest {digest} does not match resolved Event digest {recomputed}"
            )));
        }
        new_events.push((digest.clone(), event));
    }
    validate_digest_suite_bridge(seal, &new_events, &pre_state, digest_suites)?;

    // Completeness authenticates the exact cumulative accepted Event set, not
    // just this Seal's delta. Resolve every covered digest before mutating any
    // cell state so a missing predecessor Event or a mismatched actor interval
    // fails without leaving partial reducer effects behind.
    let mut covered_events = Vec::with_capacity(covered.len());
    for digest in &covered {
        let event = events
            .get(digest)?
            .ok_or_else(|| SealReject::MissingControlEvent {
                event_digest: digest.as_str().to_owned(),
            })?;
        let event_digest_suite = events.digest_suite(digest)?.ok_or_else(|| {
            SealReject::Structural(format!("Control Event {digest} has no frozen digest suite"))
        })?;
        covered_events.push((event, event_digest_suite));
    }
    let recomputed_completeness = control_event_completeness_root(
        &covered_events,
        &covered,
        digest_suites.seal_digest_suite,
    )?;
    if recomputed_completeness != seal.completeness_root {
        return Err(SealReject::CompletenessRootMismatch {
            declared: seal.completeness_root.as_str().to_owned(),
            recomputed: recomputed_completeness.as_str().to_owned(),
        });
    }
    let ordered = deterministic_order(new_events);

    let mut accepted: Vec<(Hash, Event, Vec<crate::ProjectionEffect>)> =
        Vec::with_capacity(ordered.len());
    let mut staged_anchor_state = pre_state.clone();
    let mut staged_anchor_ops = BTreeMap::<CellRef, Vec<IssuedOp>>::new();
    for (digest, event) in ordered {
        let event_digest_suite = event_digest_suite_for_seal(&event, seal, digest_suites);
        if event.seal_basis.is_some() || context == EventSubmitContext::Standard {
            verify_seal_basis(
                &digest,
                &event,
                SealBasisVerificationContext {
                    predecessor_closure: &pred_closure,
                    realm_id: &seal.realm_id,
                    seals,
                    cells,
                    registry,
                    digest_suite: event_digest_suite,
                },
            )?;
        }
        let verification = match proof_regime {
            SealEventProofRegime::FederationAccepted => verify_accepted_control_move_in_context(
                &event,
                ControlMoveVerificationContext {
                    realm_id: &seal.realm_id,
                    pre_state: if context == EventSubmitContext::AnchorUnit {
                        &staged_anchor_state
                    } else {
                        &pre_state
                    },
                    registry,
                    digest_suite: event_digest_suite,
                    submit_context: context,
                },
                |event| verify_proofs(event, event_digest_suite),
                |event| project_writes(event, event_digest_suite),
            ),
            SealEventProofRegime::RetainedReplay => verify_replayed_control_move_in_context(
                &event,
                ControlMoveVerificationContext {
                    realm_id: &seal.realm_id,
                    pre_state: if context == EventSubmitContext::AnchorUnit {
                        &staged_anchor_state
                    } else {
                        &pre_state
                    },
                    registry,
                    digest_suite: event_digest_suite,
                    submit_context: context,
                },
                |event| verify_proofs(event, event_digest_suite),
                |event| project_writes(event, event_digest_suite),
            ),
            SealEventProofRegime::ProducerSubmission => verify_control_move_in_context(
                &event,
                ControlMoveVerificationContext {
                    realm_id: &seal.realm_id,
                    pre_state: if context == EventSubmitContext::AnchorUnit {
                        &staged_anchor_state
                    } else {
                        &pre_state
                    },
                    registry,
                    digest_suite: event_digest_suite,
                    submit_context: context,
                },
                |event| verify_proofs(event, event_digest_suite),
                |event| project_writes(event, event_digest_suite),
            ),
        };
        match verification {
            Ok(effects) => {
                verify_recovery_witness(
                    &event,
                    &effects,
                    &seal.realm_id,
                    &pre_state,
                    &pred_closure,
                    seals,
                    cells,
                    registry,
                    event_digest_suite,
                )
                .map_err(|reject| SealReject::ControlMoveRejected {
                    event_digest: digest.as_str().to_owned(),
                    reason: reject.to_string(),
                })?;
                if context == EventSubmitContext::AnchorUnit {
                    for effect in &effects {
                        let cell_ops = staged_anchor_ops.entry(effect.cell_id.clone()).or_default();
                        cell_ops.push(IssuedOp {
                            issuer_id: event.actor_id.clone(),
                            op: SealedOp::from_projection(digest.clone(), effect),
                        });
                        let binding = registry.resolve(&seal.realm_id, &effect.cell_id)?;
                        staged_anchor_state.insert(
                            effect.cell_id.clone(),
                            join_cell(binding.lattice.as_ref(), &effect.cell_id, cell_ops),
                        );
                    }
                }
                accepted.push((digest, event, effects));
            }
            Err(reject) => {
                return Err(SealReject::ControlMoveRejected {
                    event_digest: digest.as_str().to_owned(),
                    reason: reject.to_string(),
                });
            }
        }
    }

    let mut new_ops: Vec<(CellRef, IssuedOp)> = Vec::new();
    for (digest, event, effects) in &accepted {
        for effect in effects {
            // The actor travels with the op so ordered-log slots stay keyed by
            // the real actor rather than a synthetic one (9.3.1).
            new_ops.push((
                effect.cell_id.clone(),
                IssuedOp {
                    issuer_id: event.actor_id.clone(),
                    op: SealedOp::from_projection(digest.clone(), effect),
                },
            ));
        }
    }
    // Validate the candidate state before publishing any of its effects. A
    // durable backend may deliberately hide cell ops until their accepting
    // Seal exists (PostgreSQL does this with a JOIN against state_seals), so
    // re-reading the store after append_sealed_effects cannot portably expose
    // the candidate batch. Resolve the already-sealed predecessor batches and
    // layer this Seal's receiver-derived ops onto them in memory instead.
    let post_state = effective_state_for_covered_events_with_new_ops(
        &covered,
        &seal.realm_id,
        cells,
        registry,
        &new_ops,
    )?;
    let post_live_suite = live_digest_suite_from_state(&post_state)?;
    if post_live_suite != digest_suites.seal_digest_suite {
        return Err(SealReject::Structural(
            "post-state live digest suite does not match the Seal suite".to_owned(),
        ));
    }
    let recomputed_state = compute_state_root(&post_state, digest_suites.seal_digest_suite)
        .map_err(|e| SealReject::Store(format!("state_root recompute failed: {e}")))?;
    if recomputed_state.as_str() != seal.state_root.as_str() {
        return Err(SealReject::StateRootMismatch {
            declared: seal.state_root.as_str().to_owned(),
            recomputed: recomputed_state.as_str().to_owned(),
        });
    }

    Ok(PreparedSealEffect {
        effect: SealEffect {
            seal: seal.id.clone(),
            accepted_event_digests: accepted.iter().map(|(digest, ..)| digest.clone()).collect(),
            post_state_root: recomputed_state,
        },
        new_ops,
        covered_event_digests: covered,
    })
}

fn commit_prepared_seal(
    seal: &Seal,
    events: &dyn ControlEventStore,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    digest_suites: SealDigestSuites,
    prepared: PreparedSealEffect,
) -> Result<SealEffect, SealReject> {
    cells.append_sealed_effects(&seal.realm_id, &seal.id, &prepared.new_ops)?;
    if let Err(error) = seals.put(seal, digest_suites.seal_digest_suite) {
        let _ = cells.rollback_seal(&seal.realm_id, &seal.id);
        return Err(error.into());
    }
    for digest in &prepared.effect.accepted_event_digests {
        events.mark_sealed(digest, seal)?;
    }
    Ok(prepared.effect)
}

fn event_digest_suite_for_seal(
    event: &Event,
    seal: &Seal,
    digest_suites: SealDigestSuites,
) -> arkret_canonical::DigestSuite {
    if seal.predecessor_refs.is_empty() && event.kind == arkret_wire::EventKind::RealmCreate {
        arkret_canonical::DigestSuite::Sha256
    } else {
        digest_suites.event_digest_suite
    }
}

fn validate_digest_suite_bridge(
    seal: &Seal,
    delta_events: &[(Hash, Event)],
    pre_state: &BTreeMap<CellRef, CellState>,
    digest_suites: SealDigestSuites,
) -> Result<(), SealReject> {
    let transition_events = delta_events
        .iter()
        .filter(|(_, event)| event.kind == arkret_wire::EventKind::RealmDigestSuiteTransition)
        .map(|(_, event)| event)
        .collect::<Vec<_>>();

    if seal.predecessor_refs.is_empty() {
        if seal.previous_state_root.is_some()
            || seal.previous_digest_algorithm.is_some()
            || !transition_events.is_empty()
            || digest_suites.previous_state_digest_suite.is_some()
        {
            return Err(SealReject::Structural(
                "Genesis Seal must not use compaction or transition fields".to_owned(),
            ));
        }
        let create_events = delta_events
            .iter()
            .filter(|(_, event)| event.kind == arkret_wire::EventKind::RealmCreate)
            .map(|(_, event)| event)
            .collect::<Vec<_>>();
        let [create] = create_events.as_slice() else {
            return Err(SealReject::Structural(
                "Genesis Seal must contain exactly one ak.realm.create Event".to_owned(),
            ));
        };
        let declared = create
            .payload
            .get("object")
            .and_then(|object| object.get("digest_algorithm"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                SealReject::Structural(
                    "ak.realm.create payload omits object.digest_algorithm".to_owned(),
                )
            })
            .and_then(|value| {
                arkret_canonical::digest_suite(value).map_err(|error| {
                    SealReject::Structural(format!(
                        "ak.realm.create digest_algorithm is invalid: {error}"
                    ))
                })
            })?;
        if digest_suites.event_digest_suite != declared
            || digest_suites.seal_digest_suite != declared
        {
            return Err(SealReject::Structural(
                "Genesis Seal and non-create founding Events must use the create-declared digest suite"
                    .to_owned(),
            ));
        }
        return Ok(());
    }

    let live_suite = live_digest_suite_from_state(pre_state)?;
    match transition_events.as_slice() {
        [] => {
            if digest_suites.previous_state_digest_suite.is_some()
                || seal.previous_state_root.is_some()
                || seal.previous_digest_algorithm.is_some()
            {
                return Err(SealReject::Structural(
                    "non-transition Seal must omit previous digest fields".to_owned(),
                ));
            }
            if digest_suites.event_digest_suite != live_suite
                || digest_suites.seal_digest_suite != live_suite
            {
                return Err(SealReject::Structural(
                    "ordinary Seal digest suites do not match predecessor live suite".to_owned(),
                ));
            }
        }
        [transition] => {
            if seal.delta.len() != 1 || !seal.is_compaction() {
                return Err(SealReject::Structural(
                    "digest-suite transition Seal must be compaction and contain only the transition Move"
                        .to_owned(),
                ));
            }
            let from = transition
                .payload
                .get("from_digest_algorithm")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    SealReject::Structural(
                        "digest-suite transition omits from_digest_algorithm".to_owned(),
                    )
                })
                .and_then(parse_digest_suite)?;
            let to = transition
                .payload
                .get("to_digest_algorithm")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    SealReject::Structural(
                        "digest-suite transition omits to_digest_algorithm".to_owned(),
                    )
                })
                .and_then(parse_digest_suite)?;
            if from == to
                || matches!(
                    (from, to),
                    (
                        arkret_canonical::DigestSuite::Blake3,
                        arkret_canonical::DigestSuite::Sha256
                    )
                )
            {
                return Err(SealReject::Structural(
                    "digest-suite transition is a no-op or strength downgrade".to_owned(),
                ));
            }
            if live_suite != from
                || digest_suites.event_digest_suite != from
                || digest_suites.previous_state_digest_suite != Some(from)
                || digest_suites.seal_digest_suite != to
                || seal.previous_digest_algorithm != Some(from)
            {
                return Err(SealReject::Structural(
                    "digest-suite transition does not match predecessor, Event, or Seal suites"
                        .to_owned(),
                ));
            }
            let recomputed_previous = compute_state_root(pre_state, from)
                .map_err(|error| SealReject::Store(format!("previous_state_root: {error}")))?;
            if seal.previous_state_root.as_ref() != Some(&recomputed_previous) {
                return Err(SealReject::StateRootMismatch {
                    declared: seal
                        .previous_state_root
                        .as_ref()
                        .map_or_else(|| "<missing>".to_owned(), |root| root.as_str().to_owned()),
                    recomputed: recomputed_previous.as_str().to_owned(),
                });
            }
        }
        _ => {
            return Err(SealReject::Structural(
                "Seal contains more than one digest-suite transition Move".to_owned(),
            ));
        }
    }
    Ok(())
}

fn parse_digest_suite(value: &str) -> Result<arkret_canonical::DigestSuite, SealReject> {
    arkret_canonical::digest_suite(value)
        .map_err(|error| SealReject::Structural(format!("invalid digest suite: {error}")))
}

/// Resolve the Realm's live digest suite from its effective control state.
///
/// The transition cell is authoritative once present.  Before the first
/// transition, `ak.realm.create` carries the initial suite inside the
/// create-locked genesis cell and deliberately does not emit a separate
/// digest-suite-cell write.
pub fn live_digest_suite_from_state(
    state: &BTreeMap<CellRef, CellState>,
) -> Result<arkret_canonical::DigestSuite, SealReject> {
    let cell = arkret_wire::null_subject_cell(arkret_wire::CellFamilyId::REALM_DIGEST_SUITE_V1);
    match state.iter().find(|(cell_ref, _)| cell_ref.as_str() == cell) {
        Some((_, CellState::Value(Value::String(value)))) => parse_digest_suite(value),
        Some((_, CellState::Bottom(_))) => Err(SealReject::Structural(
            "predecessor digest-suite cell is Bottom".to_owned(),
        )),
        Some(_) => Err(SealReject::Structural(
            "predecessor digest-suite cell has a non-string value".to_owned(),
        )),
        None => {
            let genesis_cell =
                arkret_wire::null_subject_cell(arkret_wire::CellFamilyId::REALM_GENESIS_V1);
            match state
                .iter()
                .find(|(cell_ref, _)| cell_ref.as_str() == genesis_cell)
            {
                Some((_, CellState::Value(Value::Object(genesis)))) => genesis
                    .get("digest_algorithm")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        SealReject::Structural(
                            "Realm genesis cell omits digest_algorithm".to_owned(),
                        )
                    })
                    .and_then(parse_digest_suite),
                Some((_, CellState::Bottom(_))) => Err(SealReject::Structural(
                    "Realm genesis cell is Bottom".to_owned(),
                )),
                Some(_) => Err(SealReject::Structural(
                    "Realm genesis cell has a non-object value".to_owned(),
                )),
                None => Err(SealReject::Structural(
                    "effective Realm view omits both digest-suite and genesis cells".to_owned(),
                )),
            }
        }
    }
}

const DEFAULT_RECOVERY_WITNESS_FRESHNESS_WINDOW_MS: i64 = 86_400_000;
const MAX_RECOVERY_WITNESS_FRESHNESS_WINDOW_MS: i64 = 604_800_000;

/// Validate the Seal-DAG-dependent §9.5 conflict-recovery conditions.
///
/// [`verify_control_move_in_context`] owns the pure checks (registered reset,
/// target currently in `Bottom`, critical refs). This function owns the checks
/// that require accepted Seal and cell history: witness reconstruction,
/// pre-conflict ancestry, capability inclusion, freshness, and revoke lag.
#[allow(clippy::too_many_arguments)]
pub fn verify_recovery_witness(
    event: &Event,
    effects: &[crate::ProjectionEffect],
    realm_id: &RealmId,
    pre_state: &BTreeMap<CellRef, CellState>,
    predecessor_closure: &BTreeSet<SealId>,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    _event_digest_suite: arkret_canonical::DigestSuite,
) -> Result<(), ControlMoveReject> {
    let Some(reset) = effects.iter().find(|effect| effect.recovery_reset) else {
        return Ok(());
    };
    let reject = |reason: &str| ControlMoveReject::FailedPrecondition {
        cell: reset.cell_id.as_str().to_owned(),
        reason: reason.to_owned(),
    };
    let capability_ref = event
        .refs
        .iter()
        .find(|reference| reference.role == "recovery_capability" && reference.critical)
        .ok_or_else(|| reject(arkret_wire::ReasonCode::RECOVERY_CAPABILITY_NOT_SEALED))?;
    let witnesses = event
        .refs
        .iter()
        .filter(|reference| reference.role == "state_witness" && reference.critical)
        .map(|reference| {
            SealId::new(reference.id.as_str().to_owned())
                .map_err(|_| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if witnesses.is_empty() {
        return Err(reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_MISSING));
    }

    let CellState::Bottom(bottom) = pre_state
        .get(&reset.cell_id)
        .ok_or_else(|| reject(arkret_wire::ReasonCode::RECOVERY_TARGET_NOT_IN_BOTTOM))?
    else {
        return Err(reject(
            arkret_wire::ReasonCode::RECOVERY_TARGET_NOT_IN_BOTTOM,
        ));
    };
    if bottom.move_ids.is_empty() {
        return Err(reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID));
    }

    for witness_id in witnesses {
        if !predecessor_closure.contains(&witness_id) {
            return Err(reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID));
        }
        let witness = seals
            .get(&witness_id)
            .map_err(|_| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?
            .ok_or_else(|| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?;
        if &witness.realm_id != realm_id {
            return Err(reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID));
        }

        let witness_covered =
            union_predecessor_covered_events(std::slice::from_ref(&witness_id), seals)
                .map_err(|_| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?;
        let witness_state =
            effective_state_for_covered_events(&witness_covered, realm_id, cells, registry)
                .map_err(|_| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?;
        let witness_digest_suite = digest_suite_from_trusted_hash(&witness.state_root)
            .map_err(|_| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?;
        let witness_root = compute_state_root(&witness_state, witness_digest_suite)
            .map_err(|_| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?;
        if witness_root != witness.state_root
            || !matches!(witness_state.get(&reset.cell_id), Some(CellState::Value(_)))
        {
            return Err(reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID));
        }
        if !recovery_capability_is_active(
            capability_ref.id.as_str(),
            &event.actor_id,
            &witness_state,
        ) {
            return Err(reject(
                arkret_wire::ReasonCode::RECOVERY_CAPABILITY_NOT_SEALED,
            ));
        }

        for move_id in &bottom.move_ids {
            let conflict_seal = predecessor_closure
                .iter()
                .filter_map(|seal_id| {
                    seals
                        .get(seal_id)
                        .ok()
                        .flatten()
                        .filter(|seal| seal.delta.contains(move_id))
                })
                .next()
                .ok_or_else(|| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?;
            let conflict_closure =
                predecessor_seal_closure(std::slice::from_ref(&conflict_seal.id), seals)
                    .map_err(|_| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?;
            if witness_id == conflict_seal.id || !conflict_closure.contains(&witness_id) {
                return Err(reject(
                    arkret_wire::ReasonCode::RECOVERY_WITNESS_POST_CONFLICT,
                ));
            }
        }

        let basis = event
            .seal_basis
            .as_ref()
            .ok_or_else(|| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?;
        let mut latest_basis_time: Option<chrono::DateTime<chrono::Utc>> = None;
        for leaf in &basis.leaves {
            let leaf_closure = predecessor_seal_closure(std::slice::from_ref(leaf), seals)
                .map_err(|_| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?;
            if !leaf_closure.contains(&witness_id) {
                return Err(reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID));
            }
            let leaf_time = seals
                .get(leaf)
                .map_err(|_| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?
                .ok_or_else(|| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?
                .sealed_at;
            latest_basis_time = Some(match latest_basis_time {
                Some(current) => current.max(leaf_time),
                None => leaf_time,
            });
        }
        let age_ms = latest_basis_time
            .ok_or_else(|| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?
            .signed_duration_since(witness.sealed_at)
            .num_milliseconds();
        let freshness_window_ms = recovery_witness_freshness_window_ms(pre_state);
        if age_ms < 0 || age_ms > freshness_window_ms {
            return Err(reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID));
        }
    }

    if !recovery_capability_is_active(capability_ref.id.as_str(), &event.actor_id, pre_state) {
        return Err(reject(
            arkret_wire::ReasonCode::RECOVERY_WITNESS_REVOKE_LAGGING,
        ));
    }
    Ok(())
}

fn recovery_witness_freshness_window_ms(pre_state: &BTreeMap<CellRef, CellState>) -> i64 {
    pre_state
        .iter()
        .find_map(|(cell, state)| {
            let cell_id = crate::CellId::parse(cell.as_str()).ok()?;
            if cell_id.component() != arkret_wire::CellFamilyId::REALM_POLICY_BUNDLE_V1 {
                return None;
            }
            let CellState::Value(value) = state else {
                return None;
            };
            value
                .get("recovery_witness_freshness_window_ms")
                .and_then(Value::as_u64)
                .and_then(|value| i64::try_from(value).ok())
        })
        .unwrap_or(DEFAULT_RECOVERY_WITNESS_FRESHNESS_WINDOW_MS)
        .min(MAX_RECOVERY_WITNESS_FRESHNESS_WINDOW_MS)
}

/// §5.1 steps 2-4: the Control Move's `seal_basis` must name only Seals
/// inside the receiving Seal's predecessor closure. The receiver resolves
/// those leaves and recomputes the effective roots instead of trusting root
/// copies in the Event.
///
/// This is split out of `verify_control_move` because it is the only part
/// of §5.1 that needs the Seal DAG; the rest is a pure function of the Event
/// and the frozen pre-state.
pub fn verify_seal_basis(
    event_digest: &Hash,
    event: &Event,
    verification: SealBasisVerificationContext<'_>,
) -> Result<(), SealReject> {
    let SealBasisVerificationContext {
        predecessor_closure,
        realm_id,
        seals,
        cells,
        registry,
        digest_suite,
    } = verification;
    let basis = event
        .seal_basis
        .as_ref()
        .ok_or_else(|| SealReject::MissingSealBasis {
            event_digest: event_digest.as_str().to_owned(),
        })?;
    for leaf in &basis.leaves {
        if !predecessor_closure.contains(leaf) {
            return Err(SealReject::SealBasisOutsideClosure {
                event_digest: event_digest.as_str().to_owned(),
                leaf: leaf.as_str().to_owned(),
            });
        }
    }
    effective_seal_view(
        &basis.leaves,
        realm_id,
        seals,
        cells,
        registry,
        digest_suite,
    )?;
    Ok(())
}

/// Every Seal reachable from `predecessor_refs`, the roots included.
///
/// §6.3 step 5 scopes "already sealed" and §5.1 step 2 scopes an admissible
/// `seal_basis` leaf to exactly this set — never to the receiver's own global
/// accepted-Seal set, which would make acceptance depend on leaf arrival
/// order.
pub fn predecessor_seal_closure(
    predecessor_refs: &[SealId],
    seals: &dyn SealStore,
) -> Result<BTreeSet<SealId>, SealReject> {
    let mut out = BTreeSet::new();
    let mut queue: Vec<SealId> = predecessor_refs.to_vec();
    while let Some(id) = queue.pop() {
        if !out.insert(id.clone()) {
            continue;
        }
        let seal = seals
            .get(&id)?
            .ok_or_else(|| SealReject::Store(format!("predecessor {id} not in store")))?;
        queue.extend(seal.predecessor_refs);
    }
    Ok(out)
}

pub fn effective_seal_view(
    leaves: &[SealId],
    realm_id: &RealmId,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<EffectiveSealView, SealReject> {
    let mut sorted = leaves.to_vec();
    sorted.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let union_proof = leaf_union_proof(&sorted, seals)?;
    let covered = union_covered_from_proof(&union_proof);
    let covered_event_digests: Vec<Hash> = covered.iter().cloned().collect();
    let control_event_set_root = control_event_set_root(&covered, digest_suite)?;
    let post_state = effective_state_at(&sorted, realm_id, seals, cells, registry)?;
    let state_root = compute_state_root(&post_state, digest_suite)
        .map_err(|e| SealReject::Store(format!("state_root: {e}")))?;
    let view_hash = joined_control_view_hash(
        &sorted,
        &covered_event_digests,
        &control_event_set_root,
        &state_root,
    )?;

    Ok(EffectiveSealView {
        predecessor_refs: sorted,
        covered_event_digests,
        control_event_set_root,
        state_root,
        union_proof,
        view_hash,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveSealView {
    pub predecessor_refs: Vec<SealId>,
    pub covered_event_digests: Vec<Hash>,
    pub control_event_set_root: Hash,
    pub state_root: Hash,
    pub union_proof: Vec<SealLeafUnionProof>,
    pub view_hash: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealLeafUnionProof {
    pub leaf: SealId,
    pub covered_event_digests: Vec<Hash>,
    pub control_event_set_root: Hash,
}

pub fn union_predecessor_covered_events(
    predecessor_refs: &[SealId],
    seals: &dyn SealStore,
) -> Result<BTreeSet<Hash>, SealReject> {
    let mut out = BTreeSet::new();
    for predecessor in predecessor_refs {
        collect_covered_events(predecessor, seals, &mut out)?;
    }
    Ok(out)
}

pub fn leaf_union_proof(
    leaves: &[SealId],
    seals: &dyn SealStore,
) -> Result<Vec<SealLeafUnionProof>, SealReject> {
    let mut sorted = leaves.to_vec();
    sorted.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    sorted
        .into_iter()
        .map(|leaf| {
            let mut covered = BTreeSet::new();
            collect_covered_events(&leaf, seals, &mut covered)?;
            let covered_event_digests: Vec<Hash> = covered.iter().cloned().collect();
            let leaf_seal = seals
                .get(&leaf)?
                .ok_or_else(|| SealReject::Store(format!("predecessor {leaf} not in store")))?;
            let digest_suite = digest_suite_from_trusted_hash(&leaf_seal.control_event_set_root)?;
            let control_event_set_root = control_event_set_root(&covered, digest_suite)?;
            if control_event_set_root != leaf_seal.control_event_set_root {
                return Err(SealReject::ControlEventSetRootMismatch {
                    declared: leaf_seal.control_event_set_root.as_str().to_owned(),
                    recomputed: control_event_set_root.as_str().to_owned(),
                });
            }
            Ok(SealLeafUnionProof {
                leaf,
                covered_event_digests,
                control_event_set_root,
            })
        })
        .collect()
}

fn union_covered_from_proof(proof: &[SealLeafUnionProof]) -> BTreeSet<Hash> {
    proof
        .iter()
        .flat_map(|leaf| leaf.covered_event_digests.iter().cloned())
        .collect()
}

fn collect_covered_events(
    seal_id: &SealId,
    seals: &dyn SealStore,
    out: &mut BTreeSet<Hash>,
) -> Result<(), SealReject> {
    let seal = seals
        .get(seal_id)?
        .ok_or_else(|| SealReject::Store(format!("predecessor {seal_id} not in store")))?;
    if !seal.covered_event_digests.is_empty() {
        out.extend(seal.covered_event_digests);
        return Ok(());
    }
    for predecessor in &seal.predecessor_refs {
        collect_covered_events(predecessor, seals, out)?;
    }
    out.extend(seal.delta);
    Ok(())
}

/// Portable inclusion proof for one canonical Event digest in a Seal
/// observational/control digest set root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventDigestSetInclusionProof {
    /// The canonical Event digest used as the Merkle leaf data.
    pub leaf_digest: Hash,
    pub leaf_index: u64,
    pub leaf_count: u64,
    /// Sibling hashes ordered from the leaf layer toward the root.
    pub audit_path: Vec<Hash>,
}

fn event_digest_leaf_data(digests: &BTreeSet<Hash>) -> Result<Vec<Vec<u8>>, SealReject> {
    digests
        .iter()
        .map(|digest| {
            let (suite, encoded) = digest.as_str().split_once(':').ok_or_else(|| {
                SealReject::Structural(format!("Event digest has no suite: {digest}"))
            })?;
            arkret_canonical::digest_suite(suite).map_err(|error| {
                SealReject::Structural(format!("unsupported Event digest suite: {error}"))
            })?;
            hex::decode(encoded)
                .map_err(|error| {
                    SealReject::Structural(format!("invalid Event digest {digest}: {error}"))
                })
                .and_then(|decoded| {
                    if decoded.len() == 32 {
                        Ok(decoded)
                    } else {
                        Err(SealReject::Structural(format!(
                            "Event digest {digest} must decode to 32 bytes"
                        )))
                    }
                })
        })
        .collect()
}

/// Compute the shared Seal Merkle root for a canonical ordered set of Event
/// digests. This is the single implementation used by both
/// `control_event_set_root` and `data_event_set_root`.
pub fn event_digest_set_root(
    digests: &BTreeSet<Hash>,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, SealReject> {
    seal_merkle_root_from_leaf_data(&event_digest_leaf_data(digests)?, digest_suite)
        .map_err(|error| SealReject::Store(format!("event_digest_set_root: {error}")))
}

pub fn control_event_set_root(
    covered: &BTreeSet<Hash>,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, SealReject> {
    event_digest_set_root(covered, digest_suite)
}

/// Build an RFC 6962 audit path for `target` in a canonical Event digest set.
pub fn event_digest_set_inclusion_proof(
    digests: &BTreeSet<Hash>,
    target: &Hash,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<EventDigestSetInclusionProof, SealReject> {
    let leaf_index = digests
        .iter()
        .position(|digest| digest == target)
        .ok_or_else(|| {
            SealReject::Structural(format!("Event digest set does not contain target {target}"))
        })?;
    let leaf_data = event_digest_leaf_data(digests)?;
    let audit_path = seal_merkle_audit_path_from_leaf_data(&leaf_data, leaf_index, digest_suite)
        .map_err(|error| SealReject::Store(format!("event digest audit path: {error}")))?;
    Ok(EventDigestSetInclusionProof {
        leaf_digest: target.clone(),
        leaf_index: u64::try_from(leaf_index).map_err(|_| {
            SealReject::Structural("Event digest leaf index exceeds u64".to_owned())
        })?,
        leaf_count: u64::try_from(digests.len()).map_err(|_| {
            SealReject::Structural("Event digest leaf count exceeds u64".to_owned())
        })?,
        audit_path,
    })
}

/// Verify one Event digest-set audit path against its signed Seal root.
pub fn verify_event_digest_set_inclusion_proof(
    proof: &EventDigestSetInclusionProof,
    expected_root: &Hash,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<bool, SealReject> {
    let leaf_data = event_digest_leaf_data(&BTreeSet::from([proof.leaf_digest.clone()]))?
        .into_iter()
        .next()
        .expect("single digest produces one leaf");
    verify_seal_merkle_audit_path_from_leaf_data(
        &leaf_data,
        proof.leaf_index,
        proof.leaf_count,
        &proof.audit_path,
        expected_root,
        digest_suite,
    )
    .map_err(|error| SealReject::Store(format!("event digest inclusion proof: {error}")))
}

#[derive(serde::Serialize)]
struct CompletenessLeaf<'a> {
    actor_id: &'a arkret_wire::ActorId,
    from_seq: u64,
    to_seq: u64,
    event_digests: Vec<&'a Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedControlEvent {
    pub actor_id: arkret_wire::ActorId,
    pub actor_seq: u64,
    pub event_digest: Hash,
}

/// Compute the Seal `completeness_root` from the listed Control Events.
///
/// The caller supplies the exact cumulative covered set. Every covered digest
/// must resolve to exactly one Event; extra Events are ignored.
pub fn control_event_completeness_root(
    events: &[(Event, arkret_canonical::DigestSuite)],
    covered: &BTreeSet<Hash>,
    root_digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, SealReject> {
    let mut resolved = BTreeSet::new();
    let mut listed = Vec::new();
    for (event, event_digest_suite) in events {
        let digest = Hash::new(
            event
                .event_digest_with_digest_suite(*event_digest_suite)
                .map_err(|error| {
                    SealReject::Structural(format!("Control Event digest failed: {error}"))
                })?,
        )
        .map_err(|error| {
            SealReject::Structural(format!("Control Event digest is invalid: {error}"))
        })?;
        if !covered.contains(&digest) {
            continue;
        }
        if !resolved.insert(digest.clone()) {
            return Err(SealReject::Structural(
                "duplicate listed Control Event digest".to_owned(),
            ));
        }
        listed.push(ListedControlEvent {
            actor_id: event.actor_id.clone(),
            actor_seq: event.actor_seq,
            event_digest: digest,
        });
    }
    if &resolved != covered {
        return Err(SealReject::Structural(
            "Seal coverage contains an unresolved Control Event digest".to_owned(),
        ));
    }

    control_event_completeness_root_from_listed(&listed, root_digest_suite)
}

/// Compute `completeness_root` from an exact resolved listed Control Event set.
///
/// This lower-level form is for notary construction paths that already retain
/// authenticated actor/sequence descriptors beside Event digests. Callers must
/// supply every cumulatively covered Control Event exactly once.
pub fn control_event_completeness_root_from_listed(
    events: &[ListedControlEvent],
    root_digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, SealReject> {
    let mut by_actor = BTreeMap::<arkret_wire::ActorId, Vec<(u64, Hash)>>::new();
    let mut digests = BTreeSet::new();
    for event in events {
        if !digests.insert(event.event_digest.clone()) {
            return Err(SealReject::Structural(
                "duplicate listed Control Event digest".to_owned(),
            ));
        }
        by_actor
            .entry(event.actor_id.clone())
            .or_default()
            .push((event.actor_seq, event.event_digest.clone()));
    }

    let mut leaf_data = Vec::with_capacity(by_actor.len());
    for (actor_id, mut actor_events) in by_actor {
        actor_events.sort();
        let from_seq = actor_events
            .first()
            .map(|(sequence, _)| *sequence)
            .expect("actor group is non-empty");
        let to_seq = actor_events
            .last()
            .map(|(sequence, _)| *sequence)
            .expect("actor group is non-empty");
        let leaf = CompletenessLeaf {
            actor_id: &actor_id,
            from_seq,
            to_seq,
            event_digests: actor_events.iter().map(|(_, digest)| digest).collect(),
        };
        leaf_data.push(
            arkret_canonical::canonical_json_bytes(&leaf).map_err(|error| {
                SealReject::Structural(format!("completeness leaf encoding failed: {error}"))
            })?,
        );
    }
    seal_merkle_root_from_leaf_data(&leaf_data, root_digest_suite)
        .map_err(|error| SealReject::Store(format!("completeness_root: {error}")))
}

fn digest_suite_from_trusted_hash(
    hash: &Hash,
) -> Result<arkret_canonical::DigestSuite, SealReject> {
    let (suite, _) = hash.as_str().split_once(':').ok_or_else(|| {
        SealReject::Structural(format!("trusted hash has no digest suite: {hash}"))
    })?;
    arkret_canonical::digest_suite(suite)
        .map_err(|error| SealReject::Structural(format!("invalid trusted digest suite: {error}")))
}

pub fn effective_state_at(
    leaves: &[SealId],
    realm_id: &RealmId,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<BTreeMap<CellRef, CellState>, SealReject> {
    let covered = union_predecessor_covered_events(leaves, seals)?;
    effective_state_for_covered_events(&covered, realm_id, cells, registry)
}

fn effective_state_for_covered_events(
    covered: &BTreeSet<Hash>,
    realm_id: &RealmId,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<BTreeMap<CellRef, CellState>, SealReject> {
    let mut out = BTreeMap::new();
    for cell in cells.list_cells(realm_id)? {
        let batches: Vec<(SealId, Vec<IssuedOp>)> = cells
            .sealed_op_batches_for_cell(realm_id, &cell)?
            .into_iter()
            .filter_map(|(seal, ops)| {
                let covered_ops = ops
                    .into_iter()
                    .filter(|issued| covered.contains(&issued.op.move_id))
                    .collect::<Vec<_>>();
                (!covered_ops.is_empty()).then_some((seal, covered_ops))
            })
            .collect();
        if batches.is_empty() {
            continue;
        }
        let binding = registry.resolve(realm_id, &cell)?;
        out.insert(
            cell.clone(),
            join_cell_seal_batches(
                binding.lattice.as_ref(),
                &cell,
                &batches.into_iter().map(|(_, ops)| ops).collect::<Vec<_>>(),
            ),
        );
    }
    Ok(out)
}

/// Resolve a candidate post-state without requiring its cell ops to be
/// visible through the durable [`CellStore`] before the accepting Seal is
/// committed.
fn effective_state_for_covered_events_with_new_ops(
    covered: &BTreeSet<Hash>,
    realm_id: &RealmId,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    new_ops: &[(CellRef, IssuedOp)],
) -> Result<BTreeMap<CellRef, CellState>, SealReject> {
    let mut cells_to_resolve = cells
        .list_cells(realm_id)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    cells_to_resolve.extend(new_ops.iter().map(|(cell, _)| cell.clone()));

    let mut out = BTreeMap::new();
    for cell in cells_to_resolve {
        let mut batches = cells
            .sealed_op_batches_for_cell(realm_id, &cell)?
            .into_iter()
            .filter_map(|(_, ops)| {
                let covered_ops = ops
                    .into_iter()
                    .filter(|issued| covered.contains(&issued.op.move_id))
                    .collect::<Vec<_>>();
                (!covered_ops.is_empty()).then_some(covered_ops)
            })
            .collect::<Vec<_>>();
        let candidate = new_ops
            .iter()
            .filter(|(candidate_cell, issued)| {
                candidate_cell == &cell && covered.contains(&issued.op.move_id)
            })
            .map(|(_, issued)| issued.clone())
            .collect::<Vec<_>>();
        if !candidate.is_empty() {
            batches.push(candidate);
        }
        if batches.is_empty() {
            continue;
        }
        let binding = registry.resolve(realm_id, &cell)?;
        out.insert(
            cell.clone(),
            join_cell_seal_batches(binding.lattice.as_ref(), &cell, &batches),
        );
    }
    Ok(out)
}

/// Linearize one Seal's `delta[]` per §6.3.1 steps 2-3.
///
/// Each entry is a Control Move paired with the `event_digest` that
/// `Seal.delta[]` listed it under. Causally ordered Moves come first in
/// causal order; mutually unreachable ones are broken by the canonical
/// `event_digest`-greatest total order. That order fixes the *application*
/// sequence only — it never advances a precondition baseline, which is why
/// `apply_seal` evaluates every Move against one frozen pre-state.
pub fn deterministic_order(mut events: Vec<(Hash, Event)>) -> Vec<(Hash, Event)> {
    let mut out = Vec::with_capacity(events.len());
    while !events.is_empty() {
        let mut ready = Vec::new();
        // Dependencies are named by `event_id`, not by digest: `refs[].id`
        // cites the referenced Event's id, while the batch is keyed by digest.
        let remaining_ids: BTreeSet<String> = events
            .iter()
            .map(|(_, event)| event.event_id.as_str().to_owned())
            .collect();
        let mut blocked = Vec::new();
        for entry in events {
            if causal_dependencies(&entry.1)
                .iter()
                .any(|dep| remaining_ids.contains(dep))
            {
                blocked.push(entry);
            } else {
                ready.push(entry);
            }
        }
        if ready.is_empty() {
            blocked.sort_by(concurrent_control_move_order);
            out.extend(blocked);
            break;
        }
        ready.sort_by(concurrent_control_move_order);
        out.extend(ready);
        events = blocked;
    }
    out
}

fn concurrent_control_move_order(a: &(Hash, Event), b: &(Hash, Event)) -> std::cmp::Ordering {
    b.0.as_str()
        .cmp(a.0.as_str())
        .then_with(|| a.1.hlc.cmp(&b.1.hlc))
        .then_with(|| a.1.actor_id.cmp(&b.1.actor_id))
}

fn causal_dependencies(event: &Event) -> Vec<String> {
    event
        .prev_refs
        .iter()
        .map(|id| id.as_str().to_owned())
        .chain(
            event
                .refs
                .iter()
                .filter(|reference| {
                    matches!(
                        reference.role.as_str(),
                        "after" | "parent_event" | "recovery_capability"
                    )
                })
                .map(|reference| reference.id.clone()),
        )
        .collect()
}

fn joined_control_view_hash(
    leaves: &[SealId],
    covered_event_digests: &[Hash],
    control_event_set_root: &Hash,
    state_root: &Hash,
) -> Result<Hash, SealReject> {
    let json = serde_json::json!({
        "domain": DomainSeparationId::JOINED_CONTROL_VIEW_DIGEST_V1,
        "leaves": leaves.iter().map(|leaf| leaf.as_str()).collect::<Vec<_>>(),
        "covered_event_digests": covered_event_digests
            .iter()
            .map(|event| event.as_str())
            .collect::<Vec<_>>(),
        "control_event_set_root": control_event_set_root.as_str(),
        "state_root": state_root.as_str(),
    });
    let bytes = canonical::canonical_json_bytes(&json)
        .map_err(|e| SealReject::Store(format!("joined_control_view_hash: {e}")))?;
    Hash::new(canonical::sha256_digest(&bytes))
        .map_err(|e| SealReject::Structural(format!("invalid joined control view hash: {e}")))
}

pub fn view_hash(leaves: &[SealId]) -> Result<Hash, crate::WireError> {
    let mut sorted: Vec<&str> = leaves.iter().map(|a| a.as_str()).collect();
    sorted.sort();
    let json: Value = serde_json::to_value(&sorted)?;
    let bytes = canonical::canonical_json_bytes(&json)?;
    Hash::new(canonical::sha256_digest(&bytes))
        .map_err(|e| crate::WireError::Protocol(format!("invalid view_hash: {e}")))
}
/// Join one cell's ops, routing `ordered_log` to its issuer-aware entry point.
///
/// `event-auth-state-resolution.md` §9.3.1 scopes ordered-log sequences to
/// `(effect.cell_id, actor_id)`, so this lattice cannot be joined through the
/// issuer-free `Lattice::join`: that path has no way to separate sub-chains
/// and would stamp a synthetic issuer into the `state_root` leaf.
pub fn join_cell(
    lattice: &dyn crate::lattice::Lattice,
    cell: &CellRef,
    ops: &[IssuedOp],
) -> CellState {
    let ops = ops_since_last_recovery_reset(ops);
    if lattice.kind() == crate::lattice::LatticeKind::OrderedLog {
        return crate::lattice::OrderedLog.join_with_issuers(cell, ops);
    }
    let sealed: Vec<SealedOp> = ops.iter().map(|issued| issued.op.clone()).collect();
    lattice.join(cell, &sealed)
}

/// The cell's join input after `event-auth-state-resolution.md` §9.5: the
/// suffix beginning at the last accepted recovery reset.
///
/// A reset is not a lattice op and does not join. §9.5 exists precisely because
/// a `bottom=reject` cell in `⊥` cannot be converged by any further ordinary
/// Move — so a reset that stayed in the join input would be joined **with** the
/// concurrent branches that produced the `⊥` and the cell would still resolve
/// to `⊥`. Discarding the prior ops is what "resolve the cell to the single
/// legal value" means; it is also the only way to express "drop two concurrent
/// branches" in a model whose join is a least upper bound.
///
/// Admission is what keeps this narrow: `resolve_projected_write` accepts a
/// reset only against a cell already in `⊥`, and only from
/// `ak.conflict.recovery`.
fn ops_since_last_recovery_reset(ops: &[IssuedOp]) -> &[IssuedOp] {
    ops.iter()
        .rposition(|issued| issued.op.recovery_reset)
        .map_or(ops, |boundary| &ops[boundary..])
}

/// Join accepted operations while preserving frozen-predecessor Seal batches.
///
/// `mv_register` writes in a successor Seal causally replace the previous head,
/// and multiple writes inside one Seal share one predecessor view and therefore
/// remain sibling heads; that lattice carries no predecessor on the op, so the
/// Seal batch is the only causal signal it has. Every other core lattice —
/// `cas_register` included since §9.3.1 gave its `set` ops an explicit
/// `op.from` — consumes the full accepted history, because its join already
/// models ordered supersession, ordered transitions or commutative
/// accumulation. Truncating `cas_register` to the last batch would strip the
/// predecessors its chain walk needs and turn every replacement into a dangling
/// supersession.
pub fn join_cell_seal_batches(
    lattice: &dyn crate::lattice::Lattice,
    cell: &CellRef,
    batches: &[Vec<IssuedOp>],
) -> CellState {
    // §9.5 first: a recovery reset ends the cell's prior history, so every
    // batch before the one carrying it stops being an input. Batches accepted
    // *after* the reset are ordinary writes on the recovered value and stay —
    // `join_cell` then applies the same boundary inside the surviving batches.
    let batches = batches
        .iter()
        .rposition(|ops| ops.iter().any(|issued| issued.op.recovery_reset))
        .map_or(batches, |boundary| &batches[boundary..]);
    match lattice.kind() {
        crate::lattice::LatticeKind::MvRegister => batches
            .iter()
            .rev()
            .find(|ops| !ops.is_empty())
            .map_or_else(
                || lattice.join(cell, &[]),
                |ops| join_cell(lattice, cell, ops),
            ),
        _ => {
            let ops = batches
                .iter()
                .flat_map(|ops| ops.iter().cloned())
                .collect::<Vec<_>>();
            join_cell(lattice, cell, &ops)
        }
    }
}

#[cfg(test)]
#[path = "seal_tests.rs"]
mod tests;
