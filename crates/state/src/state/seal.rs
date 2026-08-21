//! Seal application and effective-view helpers.

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::DomainSeparationId;
use arkret_wire::event_envelope::{Event, EventSubmitContext};
use serde_json::Value;
use thiserror::Error;

use super::state_root::{compute_state_root, seal_merkle_root_from_leaf_data};
use super::store::{CellRegistry, CellStore, ControlEventStore, SealStore};
use super::verify::{
    ControlMoveReject, recovery_capability_is_active, verify_accepted_control_move_in_context,
    verify_control_move_in_context, verify_replayed_control_move_in_context,
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

/// Apply one Seal per `event-auth-state-resolution.md` §6.3.
///
/// `verify_proofs` and `project_writes` are injected for the same reasons
/// `verify_control_move` takes them: signature verification lives in
/// `arkret-signatures`, and the registry-driven projection evaluator lives in
/// `arkret-schema`, which this crate may not depend on. `project_writes` is
/// the *only* source of cell targets and lattice operations — step 10's
/// "atomically apply the reducer writes derived from kind + payload".
pub fn apply_seal<VerifyProofs, ProjectWrites>(
    seal: &Seal,
    events: &dyn ControlEventStore,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    digest_suites: SealDigestSuites,
    verify_proofs: VerifyProofs,
    project_writes: ProjectWrites,
) -> Result<SealEffect, SealReject>
where
    VerifyProofs: Fn(&Event, arkret_canonical::DigestSuite) -> Result<(), String> + Copy,
    ProjectWrites:
        Fn(&Event, arkret_canonical::DigestSuite) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
{
    apply_seal_in_context(
        seal,
        events,
        seals,
        cells,
        registry,
        digest_suites,
        verify_proofs,
        project_writes,
        EventSubmitContext::Standard,
    )
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
    apply_seal_with_proof_set(
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
/// Each Event must carry the closed Producer + PrincipalServerAdmission proof
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
    apply_seal_with_proof_set(
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
    )
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
    apply_seal_with_proof_set(
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
    )
}

#[derive(Clone, Copy)]
enum SealEventProofRegime {
    ProducerSubmission,
    FederationAccepted,
    RetainedReplay,
}

#[allow(clippy::too_many_arguments)]
fn apply_seal_with_proof_set<VerifyProofs, ProjectWrites>(
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
) -> Result<SealEffect, SealReject>
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
                &pred_closure,
                &seal.realm_id,
                seals,
                cells,
                registry,
                event_digest_suite,
            )?;
        }
        let verification = match proof_regime {
            SealEventProofRegime::FederationAccepted => verify_accepted_control_move_in_context(
                &event,
                &seal.realm_id,
                if context == EventSubmitContext::AnchorUnit {
                    &staged_anchor_state
                } else {
                    &pre_state
                },
                registry,
                event_digest_suite,
                |event| verify_proofs(event, event_digest_suite),
                |event| project_writes(event, event_digest_suite),
                context,
            ),
            SealEventProofRegime::RetainedReplay => verify_replayed_control_move_in_context(
                &event,
                &seal.realm_id,
                if context == EventSubmitContext::AnchorUnit {
                    &staged_anchor_state
                } else {
                    &pre_state
                },
                registry,
                event_digest_suite,
                |event| verify_proofs(event, event_digest_suite),
                |event| project_writes(event, event_digest_suite),
                context,
            ),
            SealEventProofRegime::ProducerSubmission => verify_control_move_in_context(
                &event,
                &seal.realm_id,
                if context == EventSubmitContext::AnchorUnit {
                    &staged_anchor_state
                } else {
                    &pre_state
                },
                registry,
                event_digest_suite,
                |event| verify_proofs(event, event_digest_suite),
                |event| project_writes(event, event_digest_suite),
                context,
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
                        let cell_ops = staged_anchor_ops.entry(effect.cell.clone()).or_default();
                        cell_ops.push(IssuedOp {
                            issuer: event.actor_id.clone(),
                            op: SealedOp::from_projection(digest.clone(), effect),
                        });
                        let binding = registry.resolve(&seal.realm_id, &effect.cell)?;
                        staged_anchor_state.insert(
                            effect.cell.clone(),
                            join_cell(binding.lattice.as_ref(), &effect.cell, cell_ops),
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
                effect.cell.clone(),
                IssuedOp {
                    issuer: event.actor_id.clone(),
                    op: SealedOp::from_projection(digest.clone(), effect),
                },
            ));
        }
    }
    cells.append_sealed_effects(&seal.realm_id, &seal.id, &new_ops)?;

    let post_state = effective_state_for_covered_events(&covered, &seal.realm_id, cells, registry)?;
    let post_live_suite = live_digest_suite_from_state(&post_state)?;
    if post_live_suite != digest_suites.seal_digest_suite {
        cells.rollback_seal(&seal.realm_id, &seal.id)?;
        return Err(SealReject::Structural(
            "post-state live digest suite does not match the Seal suite".to_owned(),
        ));
    }
    let recomputed_state = compute_state_root(&post_state, digest_suites.seal_digest_suite)
        .map_err(|e| SealReject::Store(format!("state_root recompute failed: {e}")))?;
    if recomputed_state.as_str() != seal.state_root.as_str() {
        cells.rollback_seal(&seal.realm_id, &seal.id)?;
        return Err(SealReject::StateRootMismatch {
            declared: seal.state_root.as_str().to_owned(),
            recomputed: recomputed_state.as_str().to_owned(),
        });
    }

    seals.put(seal, digest_suites.seal_digest_suite)?;
    for (digest, ..) in &accepted {
        events.mark_sealed(digest, seal)?;
    }

    Ok(SealEffect {
        seal: seal.id.clone(),
        accepted_event_digests: accepted.iter().map(|(digest, ..)| digest.clone()).collect(),
        post_state_root: recomputed_state,
    })
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

fn live_digest_suite_from_state(
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
        None => Err(SealReject::Structural(
            "predecessor view omits the live digest-suite cell".to_owned(),
        )),
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
        cell: reset.cell.as_str().to_owned(),
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
        .get(&reset.cell)
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
            || !matches!(witness_state.get(&reset.cell), Some(CellState::Value(_)))
        {
            return Err(reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID));
        }
        if !recovery_capability_is_active(
            capability_ref.id.as_str(),
            event.actor_id.as_str(),
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

    if !recovery_capability_is_active(
        capability_ref.id.as_str(),
        event.actor_id.as_str(),
        pre_state,
    ) {
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
    predecessor_closure: &BTreeSet<SealId>,
    realm_id: &RealmId,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<(), SealReject> {
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

pub fn control_event_set_root(
    covered: &BTreeSet<Hash>,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Hash, SealReject> {
    let leaves: Result<Vec<Vec<u8>>, SealReject> = covered
        .iter()
        .map(|m| {
            let (_, digest) = m.as_str().split_once(':').ok_or_else(|| {
                SealReject::Structural(format!("control event digest has no suite: {m}"))
            })?;
            let suite = m
                .as_str()
                .split_once(':')
                .map(|(suite, _)| suite)
                .expect("split checked above");
            arkret_canonical::digest_suite(suite).map_err(|error| {
                SealReject::Structural(format!("unsupported control event digest suite: {error}"))
            })?;
            hex::decode(digest)
                .map_err(|e| {
                    SealReject::Structural(format!("invalid control event digest {m}: {e}"))
                })
                .and_then(|decoded| {
                    if decoded.len() == 32 {
                        Ok(decoded)
                    } else {
                        Err(SealReject::Structural(format!(
                            "control event digest {m} must decode to 32 bytes"
                        )))
                    }
                })
        })
        .collect();
    seal_merkle_root_from_leaf_data(&leaves?, digest_suite)
        .map_err(|e| SealReject::Store(format!("control_event_set_root: {e}")))
}

#[derive(serde::Serialize)]
struct CompletenessLeaf<'a> {
    actor_id: &'a arkret_wire::DidCoreId,
    from_seq: u64,
    to_seq: u64,
    event_digests: Vec<&'a Hash>,
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
    let mut by_actor = BTreeMap::<arkret_wire::DidCoreId, Vec<(u64, Hash)>>::new();
    let mut resolved = BTreeSet::new();
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
        by_actor
            .entry(event.actor_id.clone())
            .or_default()
            .push((event.actor_seq, digest));
    }
    if &resolved != covered {
        return Err(SealReject::Structural(
            "Seal coverage contains an unresolved Control Event digest".to_owned(),
        ));
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
        .then_with(|| a.1.actor_id.as_str().cmp(b.1.actor_id.as_str()))
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

pub fn view_hash(leaves: &[SealId]) -> Result<Hash, crate::Error> {
    let mut sorted: Vec<&str> = leaves.iter().map(|a| a.as_str()).collect();
    sorted.sort();
    let json: Value = serde_json::to_value(&sorted)?;
    let bytes = canonical::canonical_json_bytes(&json)?;
    Hash::new(canonical::sha256_digest(&bytes))
        .map_err(|e| crate::Error::Protocol(format!("invalid view_hash: {e}")))
}
/// Join one cell's ops, routing `ordered_log` to its issuer-aware entry point.
///
/// `event-auth-state-resolution.md` §9.3.1 scopes ordered-log sequences to
/// `(effect.cell, actor_id)`, so this lattice cannot be joined through the
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
mod tests {
    use arkret_wire::{DidCoreId, DidUrl};

    /// Attach a fixed issuer to a sealed op. These fixtures exercise
    /// non-ordered-log lattices, where the issuer is carried but unused.
    fn issued(op: SealedOp) -> IssuedOp {
        IssuedOp {
            issuer: DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
            op,
        }
    }

    use arkret_wire::Proof;
    use arkret_wire::event_envelope::{EventRef, ScopeRef};
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;
    use crate::lattice::SealedOp;
    use crate::state::store::memory::{
        MemoryCellRegistry, MemoryCellStore, MemoryControlEventStore, MemorySealStore,
    };
    use crate::state::store::{
        AcklessSelfPrincipalIngress, BottomMode, CellStore, ControlEventStore,
        ControlProposalIngress, SealStore, control_event_digest,
    };
    use crate::{
        Event, EventId, Hlc, LatticeOp, LatticeOpType, NotarySig, Precondition, Predicate,
        PredicateOp, ProjectedOp, SealBasis, SealSignature,
    };

    const SUITE: arkret_canonical::DigestSuite = arkret_canonical::DigestSuite::Sha256;

    fn compute_state_root(cells: &BTreeMap<CellRef, CellState>) -> Result<Hash, crate::Error> {
        super::compute_state_root(cells, SUITE)
    }

    fn control_event_set_root(covered: &BTreeSet<Hash>) -> Result<Hash, SealReject> {
        super::control_event_set_root(covered, SUITE)
    }

    fn control_event_completeness_root(
        events: &[Event],
        covered: &BTreeSet<Hash>,
    ) -> Result<Hash, SealReject> {
        let events = events
            .iter()
            .cloned()
            .map(|event| (event, SUITE))
            .collect::<Vec<_>>();
        super::control_event_completeness_root(&events, covered, SUITE)
    }

    fn effective_seal_view(
        leaves: &[SealId],
        realm_id: &RealmId,
        seals: &dyn SealStore,
        cells: &dyn CellStore,
        registry: &dyn CellRegistry,
    ) -> Result<EffectiveSealView, SealReject> {
        super::effective_seal_view(leaves, realm_id, seals, cells, registry, SUITE)
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_recovery_witness(
        event: &Event,
        effects: &[crate::ProjectionEffect],
        realm_id: &RealmId,
        pre_state: &BTreeMap<CellRef, CellState>,
        predecessor_closure: &BTreeSet<SealId>,
        seals: &dyn SealStore,
        cells: &dyn CellStore,
        registry: &dyn CellRegistry,
    ) -> Result<(), ControlMoveReject> {
        super::verify_recovery_witness(
            event,
            effects,
            realm_id,
            pre_state,
            predecessor_closure,
            seals,
            cells,
            registry,
            SUITE,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_seal<VerifyProofs, ProjectWrites>(
        seal: &Seal,
        events: &dyn ControlEventStore,
        seals: &dyn SealStore,
        cells: &dyn CellStore,
        registry: &dyn CellRegistry,
        verify_proofs: VerifyProofs,
        project_writes: ProjectWrites,
    ) -> Result<SealEffect, SealReject>
    where
        VerifyProofs: Fn(&Event) -> Result<(), String> + Copy,
        ProjectWrites: Fn(&Event) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
    {
        super::apply_seal(
            seal,
            events,
            seals,
            cells,
            registry,
            SealDigestSuites::standard(SUITE),
            |event, _| verify_proofs(event),
            |event, _| project_writes(event),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_seal_in_context<VerifyProofs, ProjectWrites>(
        seal: &Seal,
        events: &dyn ControlEventStore,
        seals: &dyn SealStore,
        cells: &dyn CellStore,
        registry: &dyn CellRegistry,
        verify_proofs: VerifyProofs,
        project_writes: ProjectWrites,
        context: EventSubmitContext,
    ) -> Result<SealEffect, SealReject>
    where
        VerifyProofs: Fn(&Event) -> Result<(), String> + Copy,
        ProjectWrites: Fn(&Event) -> Result<Vec<ProjectedCellWrite>, String> + Copy,
    {
        super::apply_seal_in_context(
            seal,
            events,
            seals,
            cells,
            registry,
            SealDigestSuites::standard(SUITE),
            |event, _| verify_proofs(event),
            |event, _| project_writes(event),
            context,
        )
    }

    fn ackless_ingress() -> ControlProposalIngress {
        ControlProposalIngress::AcklessSelfPrincipal(AcklessSelfPrincipalIngress {
            device_id: "ak:device:fixture".to_owned(),
            device_authorize_event_id: "ak:event:fixture".to_owned(),
            device_generation_ref: 1,
            seal_basis_digest: "sha256:fixture".to_owned(),
        })
    }

    fn raw_genesis_create() -> Event {
        arkret_wire::test_support::raw_event_at(
            arkret_wire::EventKind::RealmCreate.to_string(),
            ScopeRef::RealmGenesis,
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureps".to_owned()).unwrap(),
            0,
            Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
            json!({"object": {"digest_algorithm": "sha256"}}),
            Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
        )
        .unwrap()
    }

    fn realm() -> RealmId {
        raw_genesis_create().realm_id
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

    fn member_cell() -> CellRef {
        CellRef::new("ak:cell:ak.component.member.state.v1:did.web.alice.example".to_owned())
            .unwrap()
    }

    /// A Control Move Event. `actor_seq` keeps siblings distinct so each one
    /// hashes to its own `event_digest`.
    fn control_move(
        actor_seq: u64,
        basis: SealBasis,
        prev_refs: Vec<EventId>,
        refs: Vec<EventRef>,
    ) -> Event {
        let created_at = Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap();
        let mut event = arkret_wire::test_support::raw_event_at(
            "ak.member.state",
            ScopeRef::Realm { realm_id: realm() },
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixtureps".to_owned()).unwrap(),
            actor_seq,
            Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
            json!({"state": "join"}),
            created_at,
        )
        .unwrap();
        event.prev_refs = prev_refs;
        event.refs = refs;
        event.seal_basis = Some(basis);
        event
            .refresh_content_bound_identity_with_digest_suite(SUITE)
            .unwrap();
        event.proofs.push(
            Proof {
                kind: "detached_jws".to_owned(),
                verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#k1").unwrap(),
                event_digest: Hash::new(event.event_digest_with_digest_suite(SUITE).unwrap())
                    .unwrap(),
                signer_resolution_evidence_ref: Some(
                    arkret_wire::SignerEvidenceRef::new(format!(
                        "ak:signer_evidence:sha256:{}",
                        "11".repeat(32)
                    ))
                    .unwrap(),
                ),
                signer_resolution_evidence_digest: Some(
                    Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
                ),
                created_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "AAAA.BBBB.CCCC".to_owned(),
            }
            .into(),
        );
        event
    }

    fn genesis_create() -> Event {
        let mut event = raw_genesis_create();
        event.proofs.push(
            Proof {
                kind: "detached_jws".to_owned(),
                verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#k1").unwrap(),
                event_digest: Hash::new(event.event_digest_with_digest_suite(SUITE).unwrap())
                    .unwrap(),
                signer_resolution_evidence_ref: Some(
                    arkret_wire::SignerEvidenceRef::new(format!(
                        "ak:signer_evidence:sha256:{}",
                        "11".repeat(32)
                    ))
                    .unwrap(),
                ),
                signer_resolution_evidence_digest: Some(
                    Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
                ),
                created_at: event.created_at,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "AAAA.BBBB.CCCC".to_owned(),
            }
            .into(),
        );
        event
    }

    fn digest_suite_cell() -> CellRef {
        CellRef::new(arkret_wire::null_subject_cell(
            arkret_wire::CellFamilyId::REALM_DIGEST_SUITE_V1,
        ))
        .unwrap()
    }

    fn digest_suite_set_op() -> LatticeOp {
        let mut op = LatticeOp::empty();
        op.op_type = LatticeOpType::Set;
        op.value = Some(json!("sha256"));
        op
    }

    fn state_with_digest_suite(
        extra: impl IntoIterator<Item = (CellRef, CellState)>,
    ) -> BTreeMap<CellRef, CellState> {
        let mut state = BTreeMap::from([(digest_suite_cell(), CellState::Value(json!("sha256")))]);
        state.extend(extra);
        state
    }

    fn hash(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn capability_cell() -> CellRef {
        CellRef::new(
            "ak:cell:ak.component.capability.grant.v1:ak:grant:Aam-wkD4GZDuqJ92ccjIGHTOT3JazvV5Z0uaBH7S5eFX"
                .to_owned(),
        )
        .unwrap()
    }

    fn add_op(tag: &str, marker: &str) -> LatticeOp {
        LatticeOp {
            op_type: LatticeOpType::Add,
            tag: Some(tag.to_owned()),
            value: Some(json!({ "marker": marker })),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        }
    }

    fn dummy_signature() -> SealSignature {
        SealSignature {
            verification_method: DidUrl::new("did:webvh:z6mkfixture:notary.example#k1").unwrap(),
            payload_digest: hash(0xff),
            jws: "AAAA.BBBB.CCCC".to_owned(),
        }
    }

    fn materialized_seal(id: SealId, covered: Vec<Hash>) -> Seal {
        let seed = u64::from_str_radix(&id.as_str()[15..17], 16).unwrap();
        let covered_set = covered.iter().cloned().collect::<BTreeSet<_>>();
        let mut seal = Seal {
            id,
            realm_id: realm(),
            predecessor_refs: Vec::new(),
            delta: Vec::new(),
            control_event_set_root: control_event_set_root(&covered_set).unwrap(),
            state_root: compute_state_root(&BTreeMap::new()).unwrap(),
            completeness_root: hash(0x33),
            notary_seq: seed,
            data_view_root: None,
            data_event_set_root: None,
            availability_receipt_digests: Vec::new(),
            covered_event_digests: covered,
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(dummy_signature()),
            sealed_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
            hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
        };
        seal.id = seal.derive_id(SUITE).unwrap();
        seal
    }

    #[test]
    fn control_event_set_root_uses_seal_merkle_domain_separation() {
        let mut one = BTreeSet::new();
        one.insert(move_id(0x11));
        let mut leaf_input = vec![0x00];
        leaf_input.extend([0x11; 32]);
        let expected_leaf = canonical::sha256_bytes(&leaf_input);
        assert_eq!(
            control_event_set_root(&one).unwrap().as_str(),
            format!("sha256:{}", hex::encode(expected_leaf))
        );

        let mut two = one;
        two.insert(move_id(0x22));
        let mut right_input = vec![0x00];
        right_input.extend([0x22; 32]);
        let expected_right = canonical::sha256_bytes(&right_input);
        let expected_root =
            canonical::sha256_bytes_from_slices(&[&[0x01], &expected_leaf, &expected_right]);
        assert_eq!(
            control_event_set_root(&two).unwrap().as_str(),
            format!("sha256:{}", hex::encode(expected_root))
        );
    }

    fn completeness_event(
        event_id: &str,
        actor_id: &str,
        verification_method: &str,
        actor_seq: u64,
    ) -> Event {
        serde_json::from_value(json!({
            "event_id": event_id,
            "kind": "ak.capability.grant",
            "realm_id": realm(),
            "scope_ref": {"kind": "realm", "realm_id": realm()},
            "actor_id": actor_id,
            "principal_server_id": "ak:did_core:web:principal.example",
            "actor_seq": actor_seq,
            "created_at": "2026-07-26T00:00:00.000Z",
            "prev_refs": [],
            "payload": {},
            "proofs": [{
                "kind": "detached_jws",
                "verification_method": verification_method,
                "event_digest": format!("sha256:{}", "a".repeat(64)),
                "created_at": "2026-07-26T00:00:00.000Z",
                "jws": "a..b"
            }]
        }))
        .unwrap()
    }

    #[test]
    fn completeness_root_is_actor_sequence_enveloped_and_requires_exact_coverage() {
        let alice = completeness_event(
            "ak:event:AR-4MwpAcHt7pmjO-Cab9s-33ymPZefvcpl666_jGxiY",
            "ak:did_core:webvh:z6mkfixturealice",
            "did:webvh:z6mkfixture:alice.example#device-1",
            7,
        );
        let bob = completeness_event(
            "ak:event:AUqzNZlfuL-7z087TbZhKOdYyKUNPAa2o_neyoFRh3o2",
            "ak:did_core:webvh:z6mkfixturebob",
            "did:webvh:z6mkfixture:bob.example#device-1",
            3,
        );
        let covered = [&alice, &bob]
            .into_iter()
            .map(|event| Hash::new(event.event_digest_with_digest_suite(SUITE).unwrap()).unwrap())
            .collect::<BTreeSet<_>>();
        let forward =
            control_event_completeness_root(&[alice.clone(), bob.clone()], &covered).unwrap();
        let reverse = control_event_completeness_root(&[bob, alice.clone()], &covered).unwrap();
        assert_eq!(forward, reverse);
        assert_ne!(forward, control_event_set_root(&covered).unwrap());
        assert!(control_event_completeness_root(&[alice], &covered).is_err());
    }

    #[test]
    fn effective_state_at_filters_ops_by_seal_coverage() {
        let seals = MemorySealStore::default();
        let cells = MemoryCellStore::default();
        let registry = MemoryCellRegistry::default();
        let realm = realm();
        let cell = capability_cell();
        let move_a = move_id(0xaa);
        let move_b = move_id(0xbb);
        let seal_a = materialized_seal(seal_id(0xa1), vec![move_a.clone()]);
        let seal_b = materialized_seal(seal_id(0xb1), vec![move_b.clone()]);

        cells
            .append_sealed_effects(
                &realm,
                &seal_a.id,
                &[(
                    cell.clone(),
                    issued(SealedOp::new(move_a, add_op("a", "visible-at-a"))),
                )],
            )
            .unwrap();
        cells
            .append_sealed_effects(
                &realm,
                &seal_b.id,
                &[(
                    cell.clone(),
                    issued(SealedOp::new(move_b, add_op("b", "visible-at-b"))),
                )],
            )
            .unwrap();
        seals.put(&seal_a, SUITE).unwrap();
        seals.put(&seal_b, SUITE).unwrap();

        let state_a = effective_state_at(
            std::slice::from_ref(&seal_a.id),
            &realm,
            &seals,
            &cells,
            &registry,
        )
        .unwrap();
        let value_a = state_a
            .get(&cell)
            .and_then(|state| state.clone().into_value())
            .unwrap();
        assert_eq!(
            value_a,
            json!([{ "tag": "a", "value": { "marker": "visible-at-a" } }])
        );

        let state_b = effective_state_at(
            std::slice::from_ref(&seal_b.id),
            &realm,
            &seals,
            &cells,
            &registry,
        )
        .unwrap();
        let value_b = state_b
            .get(&cell)
            .and_then(|state| state.clone().into_value())
            .unwrap();
        assert_eq!(
            value_b,
            json!([{ "tag": "b", "value": { "marker": "visible-at-b" } }])
        );
    }

    #[test]
    fn effective_seal_view_is_leaf_order_independent() {
        let seals = MemorySealStore::default();
        let cells = MemoryCellStore::default();
        let registry = MemoryCellRegistry::default();
        let realm = realm();
        let move_a = move_id(0xaa);
        let move_b = move_id(0xbb);
        let seal_a = materialized_seal(seal_id(0xa1), vec![move_a.clone()]);
        let seal_b = materialized_seal(seal_id(0xb1), vec![move_b.clone()]);
        seals.put(&seal_b, SUITE).unwrap();
        seals.put(&seal_a, SUITE).unwrap();

        let first = effective_seal_view(
            &[seal_b.id.clone(), seal_a.id.clone()],
            &realm,
            &seals,
            &cells,
            &registry,
        )
        .unwrap();
        let second = effective_seal_view(
            &[seal_a.id.clone(), seal_b.id.clone()],
            &realm,
            &seals,
            &cells,
            &registry,
        )
        .unwrap();

        let mut expected_predecessors = vec![seal_a.id, seal_b.id];
        expected_predecessors.sort();
        assert_eq!(first.predecessor_refs, expected_predecessors);
        assert_eq!(first.covered_event_digests, vec![move_a, move_b]);
        assert_eq!(first.union_proof.len(), 2);
        assert_eq!(first.view_hash, second.view_hash);
        assert_eq!(first.state_root, second.state_root);
    }

    /// The wire order is `Seal.delta`'s order, and it is *not* apply order.
    ///
    /// Pinned as an inequality on purpose: for two independent Moves apply order
    /// is digest-descending and the wire order is ascending, so a service that
    /// serves `SealEffect::accepted_event_digests` straight out of the reducer
    /// hands a client the reverse of what `Seal.delta` says. Three clients
    /// compared exactly that with `!=` against a `seal.delta` clone.
    #[test]
    fn wire_accepted_digests_are_ascending_not_apply_order() {
        let basis = SealBasis {
            leaves: vec![seal_id(0x11)],
        };
        let first = control_move(1, basis.clone(), Vec::new(), Vec::new());
        let second = control_move(2, basis, Vec::new(), Vec::new());
        let apply_order = deterministic_order(vec![
            (control_event_digest(&first, SUITE).unwrap(), first.clone()),
            (
                control_event_digest(&second, SUITE).unwrap(),
                second.clone(),
            ),
        ])
        .into_iter()
        .map(|(digest, _)| digest)
        .collect::<Vec<_>>();

        let effect = SealEffect {
            seal: seal_id(0x22),
            accepted_event_digests: apply_order.clone(),
            post_state_root: move_id(0x33),
        };

        let mut ascending = apply_order.clone();
        ascending.sort();
        assert_eq!(effect.wire_accepted_event_digests(), ascending);
        // Concurrent Moves are applied greatest-digest-first, so the two orders
        // are reverses of each other here.
        assert_ne!(effect.wire_accepted_event_digests(), apply_order);
    }

    #[test]
    fn deterministic_order_respects_causality_then_digest_desc() {
        // Digests are content-derived, so the fixture picks the causal edge and
        // then asserts against the digests the Events actually hash to.
        let basis = SealBasis {
            leaves: vec![seal_id(0x11)],
        };
        let first = control_move(1, basis.clone(), Vec::new(), Vec::new());
        let second = control_move(2, basis.clone(), Vec::new(), Vec::new());
        let dependent = control_move(
            3,
            basis,
            Vec::new(),
            vec![EventRef::new(first.event_id.as_str(), "after")],
        );
        let entry = |event: &Event| (control_event_digest(event, SUITE).unwrap(), event.clone());

        let ordered = deterministic_order(vec![entry(&dependent), entry(&second), entry(&first)]);
        let ids: Vec<&str> = ordered
            .iter()
            .map(|(_, event)| event.event_id.as_str())
            .collect();

        // `dependent` cites `first`, so it can only appear once `first` has been
        // emitted; the two independent Moves are ordered by greatest digest.
        assert_eq!(ids[2], dependent.event_id.as_str());
        let (independent_first, independent_second) =
            if entry(&first).0.as_str() > entry(&second).0.as_str() {
                (first.event_id.as_str(), second.event_id.as_str())
            } else {
                (second.event_id.as_str(), first.event_id.as_str())
            };
        assert_eq!(ids[0], independent_first);
        assert_eq!(ids[1], independent_second);
    }

    #[test]
    fn deterministic_order_is_input_permutation_independent() {
        let basis = SealBasis {
            leaves: vec![seal_id(0x11)],
        };
        let entries: Vec<(Hash, Event)> = (1..=3)
            .map(|seq| {
                let event = control_move(seq, basis.clone(), Vec::new(), Vec::new());
                (control_event_digest(&event, SUITE).unwrap(), event)
            })
            .collect();
        let mut reversed = entries.clone();
        reversed.reverse();
        assert_eq!(
            deterministic_order(entries)
                .iter()
                .map(|(digest, _)| digest.clone())
                .collect::<Vec<_>>(),
            deterministic_order(reversed)
                .iter()
                .map(|(digest, _)| digest.clone())
                .collect::<Vec<_>>()
        );
    }

    /// A Seal whose `id` is the hash of its own canonical bytes, so
    /// `apply_seal`'s `validate_id` gate passes.
    fn signed_seal(
        predecessor_refs: Vec<SealId>,
        delta: Vec<Hash>,
        control_event_set_root: Hash,
        state_root: Hash,
        notary_seq: u64,
    ) -> Seal {
        let mut seal = Seal {
            id: seal_id(0x00),
            realm_id: realm(),
            predecessor_refs,
            delta,
            control_event_set_root,
            state_root,
            completeness_root: hash(0x33),
            notary_seq,
            data_view_root: None,
            data_event_set_root: None,
            availability_receipt_digests: Vec::new(),
            covered_event_digests: Vec::new(),
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(dummy_signature()),
            sealed_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
            hlc: Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap(),
        };
        seal.id = seal.derive_id(SUITE).unwrap();
        seal
    }

    fn signed_seal_with_coverage(
        predecessor_refs: Vec<SealId>,
        delta: Vec<Hash>,
        covered_events: &[Event],
        post_state: &BTreeMap<CellRef, CellState>,
        notary_seq: u64,
    ) -> Seal {
        let covered = covered_events
            .iter()
            .map(|event| control_event_digest(event, SUITE))
            .collect::<Result<BTreeSet<_>, _>>()
            .unwrap();
        let mut seal = signed_seal(
            predecessor_refs,
            delta,
            control_event_set_root(&covered).unwrap(),
            compute_state_root(post_state).unwrap(),
            notary_seq,
        );
        seal.covered_event_digests = covered.iter().cloned().collect();
        seal.completeness_root = control_event_completeness_root(covered_events, &covered).unwrap();
        seal.id = seal.derive_id(SUITE).unwrap();
        seal
    }

    fn ok_proofs(_: &Event) -> Result<(), String> {
        Ok(())
    }

    fn join_transition_write(_: &Event) -> Result<Vec<ProjectedCellWrite>, String> {
        let mut op = LatticeOp::empty();
        op.op_type = LatticeOpType::Transition;
        op.from = Some(json!("invited"));
        op.to = Some(json!("join"));
        Ok(vec![ProjectedCellWrite {
            cell: member_cell(),
            op: ProjectedOp::Direct(op),
        }])
    }

    fn genesis_digest_suite_write(event: &Event) -> Result<Vec<ProjectedCellWrite>, String> {
        if event.kind != arkret_wire::EventKind::RealmCreate {
            return Err("only Realm create initializes the digest suite".to_owned());
        }
        Ok(vec![ProjectedCellWrite {
            cell: digest_suite_cell(),
            op: ProjectedOp::Direct(digest_suite_set_op()),
        }])
    }

    fn bootstrap_member_transition_write(event: &Event) -> Result<Vec<ProjectedCellWrite>, String> {
        let mut op = LatticeOp::empty();
        op.op_type = LatticeOpType::Transition;
        let state = if event.actor_seq == 0 {
            ("leave", "join")
        } else {
            ("join", "join")
        };
        op.from = Some(json!(state.0));
        op.to = Some(json!(state.1));
        let mut writes = vec![ProjectedCellWrite {
            cell: member_cell(),
            op: ProjectedOp::Direct(op),
        }];
        if event.kind == arkret_wire::EventKind::RealmCreate {
            writes.push(ProjectedCellWrite {
                cell: digest_suite_cell(),
                op: ProjectedOp::Direct(digest_suite_set_op()),
            });
        }
        Ok(writes)
    }

    #[test]
    fn apply_seal_rejects_an_empty_first_root() {
        let seal = signed_seal(
            Vec::new(),
            Vec::new(),
            control_event_set_root(&BTreeSet::new()).unwrap(),
            compute_state_root(&BTreeMap::new()).unwrap(),
            0,
        );
        let events = MemoryControlEventStore::default();
        let seals = MemorySealStore::default();
        let cells = MemoryCellStore::default();
        let registry = MemoryCellRegistry::new();
        let error = apply_seal(
            &seal,
            &events,
            &seals,
            &cells,
            &registry,
            ok_proofs,
            join_transition_write,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("complete non-empty Realm anchor")
        );
    }

    #[test]
    fn first_anchor_unit_can_apply_basisless_events_only_in_explicit_context() {
        let events = MemoryControlEventStore::default();
        let seals = MemorySealStore::default();
        let cells = MemoryCellStore::default();
        let registry = MemoryCellRegistry::default();
        let event = genesis_create();
        let digest = control_event_digest(&event, SUITE).unwrap();
        events
            .put_pending_with_ingress(&event, &ackless_ingress(), SUITE)
            .unwrap();
        let post_state = state_with_digest_suite([]);
        let seal = signed_seal_with_coverage(
            Vec::new(),
            vec![digest.clone()],
            std::slice::from_ref(&event),
            &post_state,
            0,
        );

        let standard_error = apply_seal(
            &seal,
            &events,
            &seals,
            &cells,
            &registry,
            ok_proofs,
            genesis_digest_suite_write,
        )
        .unwrap_err();
        assert!(matches!(
            standard_error,
            SealReject::MissingSealBasis { .. } | SealReject::ControlMoveRejected { .. }
        ));

        let effect = apply_seal_in_context(
            &seal,
            &events,
            &seals,
            &cells,
            &registry,
            ok_proofs,
            genesis_digest_suite_write,
            EventSubmitContext::AnchorUnit,
        )
        .unwrap();
        assert_eq!(effect.accepted_event_digests, vec![digest]);
        assert_eq!(effect.post_state_root, seal.state_root);
    }

    #[test]
    fn anchor_unit_stages_create_projection_before_creator_binding_transition() {
        let events = MemoryControlEventStore::default();
        let seals = MemorySealStore::default();
        let cells = MemoryCellStore::default();
        let mut registry = MemoryCellRegistry::new();
        registry.register_fsm(
            arkret_wire::CellFamilyId::MEMBER_STATE_V1,
            Some(json!("leave")),
            vec![
                (json!("leave"), json!("join")),
                (json!("join"), json!("join")),
            ],
            BottomMode::Reject,
        );
        let create = genesis_create();
        let create_digest = control_event_digest(&create, SUITE).unwrap();
        events
            .put_pending_with_ingress(&create, &ackless_ingress(), SUITE)
            .unwrap();

        let mut binding = control_move(
            1,
            SealBasis {
                leaves: vec![seal_id(0x01)],
            },
            vec![create.event_id.clone()],
            Vec::new(),
        );
        binding.seal_basis = None;
        binding.preconditions.push(Precondition {
            cell: member_cell(),
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(json!("join")),
                values: None,
                predicate_id: None,
            },
        });
        binding
            .refresh_content_bound_identity_with_digest_suite(SUITE)
            .unwrap();
        binding.proofs[0].as_producer_mut().unwrap().event_digest =
            Hash::new(binding.event_digest_with_digest_suite(SUITE).unwrap()).unwrap();
        let binding_digest = control_event_digest(&binding, SUITE).unwrap();
        events
            .put_pending_with_ingress(&binding, &ackless_ingress(), SUITE)
            .unwrap();

        let post_state =
            state_with_digest_suite([(member_cell(), CellState::Value(json!("join")))]);
        // `Seal.delta` is a canonical sorted, duplicate-free list — the staging
        // order the test is about lives in the Seal's covered set, not in this
        // wire field's order.
        let mut delta = vec![create_digest.clone(), binding_digest.clone()];
        delta.sort();
        let seal = signed_seal_with_coverage(
            Vec::new(),
            delta.clone(),
            &[create.clone(), binding.clone()],
            &post_state,
            0,
        );

        let effect = apply_seal_in_context(
            &seal,
            &events,
            &seals,
            &cells,
            &registry,
            ok_proofs,
            bootstrap_member_transition_write,
            EventSubmitContext::AnchorUnit,
        )
        .unwrap();
        // Acceptance order stays causal (create, then the binding that depends
        // on it) regardless of how `Seal.delta` sorts.
        assert_eq!(
            effect.accepted_event_digests,
            vec![create_digest, binding_digest]
        );
        assert_eq!(effect.post_state_root, seal.state_root);
    }

    #[test]
    fn anchor_unit_context_rejects_a_nonempty_predecessor_view() {
        let seal = signed_seal(
            vec![seal_id(0x01)],
            Vec::new(),
            control_event_set_root(&BTreeSet::new()).unwrap(),
            compute_state_root(&BTreeMap::new()).unwrap(),
            1,
        );
        let error = apply_seal_in_context(
            &seal,
            &MemoryControlEventStore::default(),
            &MemorySealStore::default(),
            &MemoryCellStore::default(),
            &MemoryCellRegistry::default(),
            ok_proofs,
            join_transition_write,
            EventSubmitContext::AnchorUnit,
        )
        .unwrap_err();
        assert!(error.to_string().contains("only valid for the first Seal"));
    }

    /// Install a fully replayable Genesis Seal and return the basis a
    /// successor Control Move must declare.
    fn install_genesis(
        events: &MemoryControlEventStore,
        seals: &MemorySealStore,
        cells: &MemoryCellStore,
        registry: &MemoryCellRegistry,
    ) -> (Seal, SealBasis, Event, Hash) {
        let create = genesis_create();
        let anchor = control_event_digest(&create, SUITE).unwrap();
        events
            .put_pending_with_ingress(&create, &ackless_ingress(), SUITE)
            .unwrap();
        let post_state = state_with_digest_suite([]);
        let genesis = signed_seal_with_coverage(
            Vec::new(),
            vec![anchor.clone()],
            std::slice::from_ref(&create),
            &post_state,
            0,
        );
        apply_seal_in_context(
            &genesis,
            events,
            seals,
            cells,
            registry,
            ok_proofs,
            genesis_digest_suite_write,
            EventSubmitContext::AnchorUnit,
        )
        .unwrap();
        let basis = SealBasis {
            leaves: vec![genesis.id.clone()],
        };
        (genesis, basis, create, anchor)
    }

    #[test]
    fn apply_seal_applies_only_projector_derived_writes() {
        let seals = MemorySealStore::default();
        let cells = MemoryCellStore::default();
        let events = MemoryControlEventStore::default();
        let registry = MemoryCellRegistry::default();
        let (genesis, basis, create, _) = install_genesis(&events, &seals, &cells, &registry);

        // The Event names no cell and no lattice op anywhere: the projector is
        // the sole source of the `invited -> join` write applied below.
        let event = control_move(1, basis, Vec::new(), Vec::new());
        let digest = control_event_digest(&event, SUITE).unwrap();
        events
            .put_pending_with_ingress(&event, &ackless_ingress(), SUITE)
            .unwrap();

        let post_state =
            state_with_digest_suite([(member_cell(), CellState::Value(json!("join")))]);
        let seal = signed_seal_with_coverage(
            vec![genesis.id],
            vec![digest.clone()],
            &[create, event.clone()],
            &post_state,
            2,
        );

        let effect = apply_seal(
            &seal,
            &events,
            &seals,
            &cells,
            &registry,
            ok_proofs,
            join_transition_write,
        )
        .unwrap();
        assert_eq!(effect.accepted_event_digests, vec![digest.clone()]);
        assert_eq!(effect.post_state_root, seal.state_root);

        let ops = cells.sealed_ops_for_cell(&realm(), &member_cell()).unwrap();
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].op.move_id, digest);
        assert_eq!(ops[0].issuer, event.actor_id);
        assert_eq!(events.covering_seals(&digest).unwrap(), vec![seal.id]);
    }

    #[test]
    fn apply_seal_rejects_a_projection_the_receiver_cannot_evaluate() {
        let seals = MemorySealStore::default();
        let cells = MemoryCellStore::default();
        let events = MemoryControlEventStore::default();
        let registry = MemoryCellRegistry::default();
        let (genesis, basis, create, _) = install_genesis(&events, &seals, &cells, &registry);
        let event = control_move(1, basis, Vec::new(), Vec::new());
        let digest = control_event_digest(&event, SUITE).unwrap();
        events
            .put_pending_with_ingress(&event, &ackless_ingress(), SUITE)
            .unwrap();

        let seal = signed_seal_with_coverage(
            vec![genesis.id],
            vec![digest],
            &[create, event],
            &state_with_digest_suite([(member_cell(), CellState::Value(json!("join")))]),
            2,
        );

        let error = apply_seal(
            &seal,
            &events,
            &seals,
            &cells,
            &registry,
            ok_proofs,
            |_: &Event| Err("registry declares no contract for this kind".to_owned()),
        )
        .unwrap_err();
        assert!(matches!(error, SealReject::ControlMoveRejected { .. }));
    }

    #[test]
    fn seal_basis_leaf_outside_the_predecessor_closure_rejects() {
        let seals = MemorySealStore::default();
        let cells = MemoryCellStore::default();
        let events = MemoryControlEventStore::default();
        let registry = MemoryCellRegistry::default();
        let (genesis, mut basis, create, _) = install_genesis(&events, &seals, &cells, &registry);
        // A concurrent Seal the receiving Seal does not descend from. Admitting
        // it would make acceptance depend on which leaves this receiver happens
        // to hold (§6.3 concurrent-leaf rule).
        basis.leaves = vec![seal_id(0xee)];
        let event = control_move(1, basis, Vec::new(), Vec::new());
        let digest = control_event_digest(&event, SUITE).unwrap();
        events
            .put_pending_with_ingress(&event, &ackless_ingress(), SUITE)
            .unwrap();

        let seal = signed_seal_with_coverage(
            vec![genesis.id],
            vec![digest],
            &[create, event],
            &state_with_digest_suite([(member_cell(), CellState::Value(json!("join")))]),
            2,
        );

        let error = apply_seal(
            &seal,
            &events,
            &seals,
            &cells,
            &registry,
            ok_proofs,
            join_transition_write,
        )
        .unwrap_err();
        assert!(matches!(error, SealReject::SealBasisOutsideClosure { .. }));
    }

    #[test]
    fn predecessor_seal_closure_is_transitive() {
        let seals = MemorySealStore::default();
        let empty_control_root = control_event_set_root(&BTreeSet::new()).unwrap();
        let empty_state_root = compute_state_root(&BTreeMap::new()).unwrap();
        let genesis = signed_seal(
            Vec::new(),
            Vec::new(),
            empty_control_root.clone(),
            empty_state_root.clone(),
            1,
        );
        let middle = signed_seal(
            vec![genesis.id.clone()],
            Vec::new(),
            empty_control_root,
            empty_state_root,
            2,
        );
        seals.put(&genesis, SUITE).unwrap();
        seals.put(&middle, SUITE).unwrap();

        let closure = predecessor_seal_closure(std::slice::from_ref(&middle.id), &seals).unwrap();
        assert_eq!(closure, BTreeSet::from([genesis.id, middle.id]));
    }

    #[test]
    fn effective_state_preserves_cross_seal_fsm_order() {
        let seals = MemorySealStore::default();
        let cells = MemoryCellStore::default();
        let registry = MemoryCellRegistry::default();
        let realm = realm();
        let cell =
            CellRef::new("ak:cell:ak.component.member.state.v1:did.web.alice.example".to_owned())
                .unwrap();
        let join_id = move_id(0x01);
        let ban_id = move_id(0xff);
        let seal = materialized_seal(seal_id(0xa1), vec![join_id.clone(), ban_id.clone()]);
        let transition = |from: &str, to: &str| LatticeOp {
            op_type: LatticeOpType::Transition,
            tag: None,
            value: None,
            from: Some(json!(from)),
            to: Some(json!(to)),
            reason: None,
            issuer_seq: None,
        };

        cells
            .append_sealed_effects(
                &realm,
                &seal.id,
                &[
                    (
                        cell.clone(),
                        issued(SealedOp::new(join_id, transition("invited", "join"))),
                    ),
                    (
                        cell.clone(),
                        issued(SealedOp::new(ban_id, transition("join", "ban"))),
                    ),
                ],
            )
            .unwrap();
        seals.put(&seal, SUITE).unwrap();

        let state = effective_state_at(
            std::slice::from_ref(&seal.id),
            &realm,
            &seals,
            &cells,
            &registry,
        )
        .unwrap();
        assert_eq!(state.get(&cell), Some(&CellState::Value(json!("ban"))));
    }

    #[test]
    fn mv_register_seal_batches_distinguish_successors_from_siblings() {
        let cell = CellRef::new(
            "ak:cell:ak.component.profile.v1:ak.realm.01js0sp00000000000000000aa".to_owned(),
        )
        .unwrap();
        let set = |id, value| {
            issued(SealedOp::new(
                move_id(id),
                LatticeOp {
                    op_type: LatticeOpType::Set,
                    tag: None,
                    value: Some(json!(value)),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            ))
        };
        let lattice = crate::lattice::MvRegister;

        let sequential = vec![vec![set(1, "open")], vec![set(2, "closed")]];
        assert_eq!(
            join_cell_seal_batches(&lattice, &cell, &sequential),
            CellState::Value(json!("closed"))
        );

        let siblings = vec![vec![set(3, "open"), set(4, "closed")]];
        assert!(matches!(
            join_cell_seal_batches(&lattice, &cell, &siblings),
            CellState::Bottom(_)
        ));
    }

    /// A `cas_register` cell is joined over its whole covered history, so the
    /// predecessors its chain walk binds to are still in the input.
    #[test]
    fn cas_register_seal_batches_join_the_whole_history() {
        let cell = CellRef::new(
            "ak:cell:ak.component.realm.policy.v1:ak.realm.01js0sp00000000000000000aa".to_owned(),
        )
        .unwrap();
        let set = |id, value: &str, from: Option<&str>| {
            issued(SealedOp::new(
                move_id(id),
                LatticeOp {
                    op_type: LatticeOpType::Set,
                    tag: None,
                    value: Some(json!(value)),
                    from: from.map(|from| json!(from)),
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            ))
        };
        let lattice = crate::lattice::CasRegister;

        let sequential = vec![
            vec![set(1, "open", None)],
            vec![set(2, "closed", Some("open"))],
        ];
        assert_eq!(
            join_cell_seal_batches(&lattice, &cell, &sequential),
            CellState::Value(json!("closed"))
        );

        let siblings = vec![vec![set(3, "open", None), set(4, "closed", None)]];
        assert!(matches!(
            join_cell_seal_batches(&lattice, &cell, &siblings),
            CellState::Bottom(_)
        ));
    }

    struct RecoveryWitnessFixture {
        event: Event,
        effects: Vec<crate::ProjectionEffect>,
        pre_state: BTreeMap<CellRef, CellState>,
        predecessor_closure: BTreeSet<SealId>,
        seals: MemorySealStore,
        cells: MemoryCellStore,
        registry: MemoryCellRegistry,
        conflict_a_id: SealId,
    }

    fn recovery_witness_fixture() -> RecoveryWitnessFixture {
        let seals = MemorySealStore::default();
        let cells = MemoryCellStore::default();
        let registry = MemoryCellRegistry::default();
        let target = CellRef::new(
            "ak:cell:ak.component.realm.policy.v1:ak.realm.01js0sp00000000000000000aa".to_owned(),
        )
        .unwrap();
        let grant_id = "ak:grant:Aam-wkD4GZDuqJ92ccjIGHTOT3JazvV5Z0uaBH7S5eFX";
        let target_move = move_id(0x41);
        let grant_move = move_id(0x42);
        let conflict_a_move = move_id(0x51);
        let conflict_b_move = move_id(0x52);
        let actor = DidCoreId::new("ak:did_core:webvh:z6mkfixturealice".to_owned()).unwrap();
        let target_value = json!({"policy_revision": 7});
        let grant_value = json!({
            "grant_id": grant_id,
            "subject": actor,
            "actions": ["ak.conflict.recovery"],
            "resources": [{"kind": "realm", "realm_id": realm()}]
        });

        let mut target_op = LatticeOp::empty();
        target_op.op_type = LatticeOpType::Set;
        target_op.value = Some(target_value.clone());
        let mut grant_op = LatticeOp::empty();
        grant_op.op_type = LatticeOpType::Add;
        grant_op.tag = Some(grant_id.to_owned());
        grant_op.value = Some(grant_value.clone());

        let witness_state = BTreeMap::from([
            (target.clone(), CellState::Value(target_value)),
            (
                capability_cell(),
                CellState::Value(json!([{"tag": grant_id, "value": grant_value}])),
            ),
        ]);
        let mut witness =
            materialized_seal(seal_id(0x40), vec![target_move.clone(), grant_move.clone()]);
        witness.delta = vec![target_move.clone(), grant_move.clone()];
        witness.state_root = compute_state_root(&witness_state).unwrap();
        witness.id = witness.derive_id(SUITE).unwrap();
        let witness_id = witness.id.clone();
        cells
            .append_sealed_effects(
                &realm(),
                &witness_id,
                &[
                    (
                        target.clone(),
                        issued(SealedOp::new(target_move.clone(), target_op)),
                    ),
                    (
                        capability_cell(),
                        issued(SealedOp::new(grant_move.clone(), grant_op)),
                    ),
                ],
            )
            .unwrap();
        seals.put(&witness, SUITE).unwrap();

        let mut conflict_a = materialized_seal(
            conflict_a_id(),
            vec![
                target_move.clone(),
                grant_move.clone(),
                conflict_a_move.clone(),
            ],
        );
        conflict_a.predecessor_refs = vec![witness_id.clone()];
        conflict_a.delta = vec![conflict_a_move.clone()];
        conflict_a.state_root = witness.state_root.clone();
        conflict_a.sealed_at += chrono::Duration::seconds(1);
        conflict_a.id = conflict_a.derive_id(SUITE).unwrap();
        seals.put(&conflict_a, SUITE).unwrap();
        let mut conflict_b = materialized_seal(
            seal_id(0x52),
            vec![target_move, grant_move, conflict_b_move.clone()],
        );
        conflict_b.predecessor_refs = vec![witness_id.clone()];
        conflict_b.delta = vec![conflict_b_move.clone()];
        conflict_b.state_root = witness.state_root;
        conflict_b.sealed_at += chrono::Duration::seconds(1);
        conflict_b.id = conflict_b.derive_id(SUITE).unwrap();
        seals.put(&conflict_b, SUITE).unwrap();

        let mut event = control_move(
            9,
            SealBasis {
                leaves: vec![conflict_a.id.clone(), conflict_b.id.clone()],
            },
            Vec::new(),
            vec![
                EventRef::new(grant_id, "recovery_capability"),
                EventRef::new(witness_id.as_str(), "state_witness"),
            ],
        );
        event.kind = "ak.conflict.recovery".into();
        let effects = vec![crate::ProjectionEffect::reset(
            target.clone(),
            LatticeOp {
                op_type: LatticeOpType::Set,
                tag: None,
                value: Some(json!({"policy_revision": 8})),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
        )];
        let mut bottom =
            crate::Bottom::new(arkret_wire::BottomKind::Conflict, vec![target.clone()]);
        bottom.move_ids = vec![conflict_a_move, conflict_b_move];
        let pre_state = BTreeMap::from([
            (target, CellState::Bottom(bottom)),
            (
                capability_cell(),
                CellState::Value(json!([{"tag": grant_id, "value": grant_value}])),
            ),
        ]);
        let predecessor_closure =
            predecessor_seal_closure(&[conflict_a.id.clone(), conflict_b.id.clone()], &seals)
                .unwrap();

        RecoveryWitnessFixture {
            event,
            effects,
            pre_state,
            predecessor_closure,
            seals,
            cells,
            registry,
            conflict_a_id: conflict_a.id,
        }
    }

    fn conflict_a_id() -> SealId {
        seal_id(0x51)
    }

    #[test]
    fn conflict_recovery_accepts_a_sealed_pre_conflict_witness() {
        let fixture = recovery_witness_fixture();
        verify_recovery_witness(
            &fixture.event,
            &fixture.effects,
            &realm(),
            &fixture.pre_state,
            &fixture.predecessor_closure,
            &fixture.seals,
            &fixture.cells,
            &fixture.registry,
        )
        .unwrap();
    }

    #[test]
    fn conflict_recovery_rejects_post_conflict_and_revoked_witnesses() {
        let mut post_conflict = recovery_witness_fixture();
        post_conflict
            .event
            .refs
            .iter_mut()
            .find(|reference| reference.role == "state_witness")
            .unwrap()
            .id = post_conflict.conflict_a_id.to_string();
        let error = verify_recovery_witness(
            &post_conflict.event,
            &post_conflict.effects,
            &realm(),
            &post_conflict.pre_state,
            &post_conflict.predecessor_closure,
            &post_conflict.seals,
            &post_conflict.cells,
            &post_conflict.registry,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ControlMoveReject::FailedPrecondition { reason, .. }
                if reason == arkret_wire::ReasonCode::RECOVERY_WITNESS_POST_CONFLICT
        ));

        let mut revoked = recovery_witness_fixture();
        revoked.pre_state.remove(&capability_cell());
        let error = verify_recovery_witness(
            &revoked.event,
            &revoked.effects,
            &realm(),
            &revoked.pre_state,
            &revoked.predecessor_closure,
            &revoked.seals,
            &revoked.cells,
            &revoked.registry,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ControlMoveReject::FailedPrecondition { reason, .. }
                if reason == arkret_wire::ReasonCode::RECOVERY_WITNESS_REVOKE_LAGGING
        ));
    }

    #[test]
    fn recovery_freshness_uses_the_realm_default_and_seven_day_ceiling() {
        assert_eq!(
            recovery_witness_freshness_window_ms(&BTreeMap::new()),
            DEFAULT_RECOVERY_WITNESS_FRESHNESS_WINDOW_MS
        );
        let metadata = CellRef::new(arkret_wire::null_subject_cell(
            arkret_wire::CellFamilyId::REALM_POLICY_BUNDLE_V1,
        ))
        .unwrap();
        let state = BTreeMap::from([(
            metadata,
            CellState::Value(json!({"recovery_witness_freshness_window_ms": 999_999_999_i64})),
        )]);
        assert_eq!(
            recovery_witness_freshness_window_ms(&state),
            MAX_RECOVERY_WITNESS_FRESHNESS_WINDOW_MS
        );
    }

    /// `event-auth-state-resolution.md` §9.5 — the recovery reset must produce
    /// a cell that has actually **left** `⊥`.
    ///
    /// Asserting the projected op's shape is not enough, and that is the exact
    /// gap this covers: the reset used to project as a plain `set` and was fed
    /// into the same join as the two concurrent branches that caused the `⊥`.
    /// The op-level assertion stayed green while the cell never recovered, so
    /// `bottom=reject` cells were permanently dead and the only escape §9.5
    /// defines did not exist.
    #[test]
    fn a_recovery_reset_lifts_a_cas_register_cell_out_of_bottom() {
        let cell = CellRef::new(
            "ak:cell:ak.component.realm.policy.v1:ak.realm.01js0sp00000000000000000aa".to_owned(),
        )
        .unwrap();
        let op = |value: &str, from: Option<&str>| LatticeOp {
            op_type: LatticeOpType::Set,
            tag: None,
            value: Some(json!(value)),
            from: from.map(|from| json!(from)),
            to: None,
            reason: None,
            issuer_seq: None,
        };
        let set = |id, value: &str, from: Option<&str>| {
            issued(SealedOp::new(move_id(id), op(value, from)))
        };
        let reset = |id, value: &str| {
            issued(SealedOp::from_projection(
                move_id(id),
                &crate::ProjectionEffect::reset(cell.clone(), op(value, None)),
            ))
        };
        let lattice = crate::lattice::CasRegister;

        let conflicted = vec![vec![set(1, "open", None), set(2, "closed", None)]];
        assert!(
            matches!(
                join_cell_seal_batches(&lattice, &cell, &conflicted),
                CellState::Bottom(_)
            ),
            "precondition: concurrent cas_register writes put the cell in ⊥"
        );

        let mut recovered = conflicted.clone();
        recovered.push(vec![reset(3, "closed")]);
        assert_eq!(
            join_cell_seal_batches(&lattice, &cell, &recovered),
            CellState::Value(json!("closed")),
            "the reset discards both conflicting branches and resolves the cell"
        );

        // The boundary is a floor, not a freeze: ordinary writes accepted after
        // the recovery still supersede it, chaining off the recovered value.
        let mut superseded = recovered.clone();
        superseded.push(vec![set(4, "archived", Some("closed"))]);
        assert_eq!(
            join_cell_seal_batches(&lattice, &cell, &superseded),
            CellState::Value(json!("archived"))
        );

        // And an unmarked op with the same shape must NOT recover the cell —
        // otherwise the gate would pass on a build where the reset marker was
        // dropped somewhere between projection and the op log.
        let mut unmarked = conflicted;
        unmarked.push(vec![set(5, "closed", None)]);
        assert!(matches!(
            join_cell_seal_batches(&lattice, &cell, &unmarked),
            CellState::Bottom(_)
        ));
    }
}
