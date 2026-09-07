//! Seal application and effective-view helpers.

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::DomainSeparationId;
use arkret_wire::event_envelope::{Event, EventSubmitContext};
use serde_json::Value;
use thiserror::Error;

use super::state_root::{
    CasHeadsByCell, GovernanceView, compute_state_root, seal_merkle_audit_path_from_leaf_data,
    seal_merkle_root_from_leaf_data, verify_seal_merkle_audit_path_from_leaf_data,
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
pub async fn apply_seal_in_context<VerifyProofs, ProjectWrites>(
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
    )
    .await?;
    commit_prepared_seal(seal, events, seals, cells, digest_suites, prepared).await
}

/// Verify an incoming producer-submission Seal without mutating its stores.
///
/// This is the validation half of [`apply_seal_in_context`]. It exists for
/// receivers whose acceptance transaction also persists typed dependency
/// evidence or other receiver-owned indexes.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_seal_in_context<VerifyProofs, ProjectWrites>(
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
    .await
}

/// Apply a Seal whose delta is loaded from the durable accepted-event lane.
/// Each Event must carry the closed Producer + StationAdmission proof
/// set; producer-submission Seals continue to use [`apply_seal_in_context`].
#[allow(clippy::too_many_arguments)]
pub async fn apply_accepted_seal_in_context<VerifyProofs, ProjectWrites>(
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
    )
    .await?;
    commit_prepared_seal(seal, events, seals, cells, digest_suites, prepared).await
}

/// Apply a retained Seal whose Events may use either the historical
/// sole-Producer direct regime or the Producer + Admission federation regime.
/// The selected structural contract is derived from each exact Event proof
/// set; all remaining CBA, reducer, recovery, and state-root checks are shared.
#[allow(clippy::too_many_arguments)]
pub async fn apply_replayed_seal_in_context<VerifyProofs, ProjectWrites>(
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
    )
    .await?;
    commit_prepared_seal(seal, events, seals, cells, digest_suites, prepared).await
}

#[derive(Clone, Copy)]
enum SealEventProofRegime {
    ProducerSubmission,
    FederationAccepted,
    RetainedReplay,
}

#[allow(clippy::too_many_arguments)]
async fn prepare_seal_with_proof_set<VerifyProofs, ProjectWrites>(
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
    if !seals.predecessors_known(&seal.predecessor_refs).await? {
        return Err(SealReject::UnknownPredecessor);
    }
    if seal.predecessor_refs.is_empty() && seal.delta.is_empty() {
        return Err(SealReject::Structural(
            "the first Seal must cover the complete non-empty Realm anchor unit".to_owned(),
        ));
    }

    let pred_covered = union_predecessor_covered_events(&seal.predecessor_refs, seals).await?;
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
    // Both halves of the frozen baseline come from one call, so the values the
    // preconditions read and the head identities §9.3.1.3 item 3 compares can
    // never be resolved against different op sets.
    let pre_state =
        effective_joined_view_for_covered_events(&pred_covered, &seal.realm_id, cells, registry)
            .await?;
    let pre_heads = &pre_state.cas_heads;
    let pred_closure = predecessor_seal_closure(&seal.predecessor_refs, seals).await?;

    let mut new_events: Vec<(Hash, Event)> = Vec::with_capacity(seal.delta.len());
    for digest in &seal.delta {
        let event = events
            .get(digest)
            .await?
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
            .get(digest)
            .await?
            .ok_or_else(|| SealReject::MissingControlEvent {
                event_digest: digest.as_str().to_owned(),
            })?;
        let event_digest_suite = events.digest_suite(digest).await?.ok_or_else(|| {
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
    let mut staged_anchor_state = pre_state.cells.clone();
    let mut staged_anchor_ops = BTreeMap::<CellRef, Vec<IssuedOp>>::new();
    let mut ordinary_batch = arkret_wire::control_seal_batch::ControlSealBatch::default();
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
            )
            .await?;
        }
        let verification = match proof_regime {
            SealEventProofRegime::FederationAccepted => verify_accepted_control_move_in_context(
                &event,
                ControlMoveVerificationContext {
                    realm_id: &seal.realm_id,
                    pre_state: if context == EventSubmitContext::AnchorUnit {
                        &staged_anchor_state
                    } else {
                        &pre_state.cells
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
                        &pre_state.cells
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
                        &pre_state.cells
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
                    &pre_state.cells,
                    &pred_closure,
                    seals,
                    cells,
                    registry,
                    event_digest_suite,
                )
                .await
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
                if context == EventSubmitContext::Standard {
                    ordinary_batch
                        .try_insert(
                            &event.kind,
                            effects.iter().map(|effect| effect.cell_id.as_str()),
                        )
                        .map_err(|error| SealReject::Structural(error.to_owned()))?;
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
    // One rebuild per distinct basis, not per Move. A Seal's Moves are usually
    // authored against the same frontier, and rebuilding the head view is a
    // whole-Realm pass: a `list_cells` plus one history read per cell. Nothing
    // in this loop writes to the store — new effects are collected into
    // `new_ops` and applied later — so the same leaf set answers the same way
    // every time, which is what makes reusing it sound rather than merely
    // faster. The key is order-insensitive because the rebuild unions its
    // leaves' covered sets.
    let mut basis_heads_by_leaves: BTreeMap<Vec<SealId>, CasHeadsByCell> = BTreeMap::new();
    for (digest, event, effects) in &accepted {
        // §9.3.1.3 item 1: the baseline is the Move's *own* signed `seal_basis`,
        // not the receiving Seal's predecessor set. Anchor units have no basis
        // to rebuild (§9.3.1.3 "two closed exceptions"), and their staged
        // context is what admission already used.
        let basis_heads = match event.seal_basis.as_ref() {
            Some(basis) => {
                let key: Vec<SealId> = basis
                    .leaves
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                match basis_heads_by_leaves.get(&key) {
                    Some(cached) => cached.clone(),
                    None => {
                        let heads = effective_cas_heads_at(
                            &basis.leaves,
                            &seal.realm_id,
                            seals,
                            cells,
                            registry,
                        )
                        .await?;
                        basis_heads_by_leaves.insert(key, heads.clone());
                        heads
                    }
                }
            }
            None => BTreeMap::new(),
        };
        for effect in effects {
            let binding = registry.resolve(&seal.realm_id, &effect.cell_id)?;
            let kind = binding.lattice.kind();
            if effect.recovery_reset {
                // §9.5.1 `fsm` additional admission. The recovery supersedes
                // every divergent head, so each of their `to` values is one of
                // its sources and each has to be a registered transition into
                // the resolved state. This is the one site with those values:
                // the pre-state the Move verifier sees is `⊥`, which carries no
                // usable head list, and the whole point of §9.5.1 item 1 is that
                // the proof comes from the write's *own* signed basis.
                let sources: Vec<Value> = basis_heads
                    .get(&effect.cell_id)
                    .into_iter()
                    .flatten()
                    .map(|head| head.value.clone())
                    .collect();
                binding
                    .lattice
                    .validate_recovery_sources(&sources, &effect.op)
                    .map_err(|error| SealReject::ControlMoveRejected {
                        event_digest: digest.as_str().to_owned(),
                        reason: format!(
                            "recovery write on {} is not admissible: {error}",
                            effect.cell_id.as_str()
                        ),
                    })?;
            }
            let supersedes = if is_causal_register(kind) {
                let observed = head_identities(basis_heads.get(&effect.cell_id));
                if event.seal_basis.is_some() {
                    let frozen = head_identities(pre_heads.get(&effect.cell_id));
                    // §9.3.1.3 item 3: identity-for-identity, and stale even when
                    // both sides settle to the same business value. That equality
                    // is the whole point — it is what a claim/release/claim slot
                    // needs and what a whole-value compare cannot express.
                    if !head_identities_match(&observed, &frozen) {
                        return Err(SealReject::ControlMoveRejected {
                            event_digest: digest.as_str().to_owned(),
                            reason: format!(
                                "cas_register cell {} basis heads {:?} are stale against the \
                                 frozen predecessor heads {:?}",
                                effect.cell_id.as_str(),
                                observed.iter().map(Hash::as_str).collect::<Vec<_>>(),
                                frozen.iter().map(Hash::as_str).collect::<Vec<_>>(),
                            ),
                        });
                    }
                }
                observed
            } else {
                Vec::new()
            };
            // The actor travels with the op so ordered-log slots stay keyed by
            // the real actor rather than a synthetic one (9.3.1).
            new_ops.push((
                effect.cell_id.clone(),
                IssuedOp {
                    issuer_id: event.actor_id.clone(),
                    op: SealedOp::from_projection(digest.clone(), effect)
                        .with_supersedes(supersedes),
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
    let post_state =
        effective_joined_view_with_new_ops(&covered, &seal.realm_id, cells, registry, &new_ops)
            .await?;
    let post_live_suite = live_digest_suite_from_state(&post_state.cells)?;
    if post_live_suite != digest_suites.seal_digest_suite {
        return Err(SealReject::Structural(
            "post-state live digest suite does not match the Seal suite".to_owned(),
        ));
    }
    let recomputed_state = post_state
        .state_root(digest_suites.seal_digest_suite)
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

async fn commit_prepared_seal(
    seal: &Seal,
    events: &dyn ControlEventStore,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    digest_suites: SealDigestSuites,
    prepared: PreparedSealEffect,
) -> Result<SealEffect, SealReject> {
    cells
        .append_sealed_effects(&seal.realm_id, &seal.id, &prepared.new_ops)
        .await?;
    if let Err(error) = seals.put(seal, digest_suites.seal_digest_suite).await {
        let _ = cells.rollback_seal(&seal.realm_id, &seal.id).await;
        return Err(error.into());
    }
    for digest in &prepared.effect.accepted_event_digests {
        events.mark_sealed(digest, seal).await?;
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
    pre_state: &JoinedView,
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

    let live_suite = live_digest_suite_from_state(&pre_state.cells)?;
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
            let recomputed_previous = pre_state
                .state_root(from)
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
pub async fn verify_recovery_witness(
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

    // §9.5.1: a causal-register recovery proves its target conflict from its own
    // signed basis and its authority from its registered capability path. Those
    // are two separate proofs and neither is a witness to a pre-conflict value —
    // a cell that conflicted on its *first* write never had one, so requiring a
    // `state_witness` here would make exactly the case that most needs repair
    // unrepairable. The freshness window goes with it: a conflict left standing
    // for a week must not age out of a still-valid authority's reach.
    //
    // `fsm` joined this branch when §9.3.1.5-§9.3.1.8 gave it the identity-based
    // supersession the argument rests on. Before that it had no way to say which
    // heads a recovery replaced, so it needed a witness to a prior value
    // instead. The three obligations 1610 names are all still checked: the
    // divergence in the Move's own basis and the active capability here, the
    // transition table through `validate_op`, and `H_c(B) = H_c(P)` in
    // `apply_seal`.
    let reset_lattice = registry
        .resolve(realm_id, &reset.cell_id)
        .map_err(|_| reject(arkret_wire::ReasonCode::RECOVERY_TARGET_NOT_IN_BOTTOM))?
        .lattice
        .kind();
    if is_causal_register(reset_lattice) {
        let basis = event
            .seal_basis
            .as_ref()
            .ok_or_else(|| reject(arkret_wire::ReasonCode::RECOVERY_TARGET_NOT_IN_BOTTOM))?;
        let basis_view = effective_joined_view_at(&basis.leaves, realm_id, seals, cells, registry)
            .await
            .map_err(|_| reject(arkret_wire::ReasonCode::RECOVERY_TARGET_NOT_IN_BOTTOM))?;
        // Item 1: the divergence must be visible in the *Move's own* basis, not
        // merely in the frozen predecessor. A recovery authored against a view
        // where the cell still resolved cleanly is repairing something it never
        // saw. (Item 3's `H_c(B) = H_c(P)` guard runs separately in `apply_seal`
        // and is what rejects a recovery whose branch set has since moved on.)
        if !matches!(
            basis_view.cells.get(&reset.cell_id),
            Some(CellState::Bottom(_))
        ) {
            return Err(reject(
                arkret_wire::ReasonCode::RECOVERY_TARGET_NOT_IN_BOTTOM,
            ));
        }
        // Item 2: authority is verified on its own, against the frozen
        // predecessor. Being in `⊥` never excuses a revoked capability.
        if !recovery_capability_is_active(capability_ref.id.as_str(), &event.actor_id, pre_state) {
            return Err(reject(
                arkret_wire::ReasonCode::RECOVERY_WITNESS_REVOKE_LAGGING,
            ));
        }
        return Ok(());
    }

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

    for witness_id in witnesses {
        if !predecessor_closure.contains(&witness_id) {
            return Err(reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID));
        }
        let witness = seals
            .get(&witness_id)
            .await
            .map_err(|_| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?
            .ok_or_else(|| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?;
        if &witness.realm_id != realm_id {
            return Err(reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID));
        }

        let witness_covered =
            union_predecessor_covered_events(std::slice::from_ref(&witness_id), seals)
                .await
                .map_err(|_| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?;
        let witness_state =
            effective_joined_view_for_covered_events(&witness_covered, realm_id, cells, registry)
                .await
                .map_err(|_| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?;
        let witness_digest_suite = digest_suite_from_trusted_hash(&witness.state_root)
            .map_err(|_| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?;
        let witness_root = witness_state
            .state_root(witness_digest_suite)
            .map_err(|_| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?;
        if witness_root != witness.state_root
            || !matches!(
                witness_state.cells.get(&reset.cell_id),
                Some(CellState::Value(_))
            )
        {
            return Err(reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID));
        }
        if !recovery_capability_is_active(
            capability_ref.id.as_str(),
            &event.actor_id,
            &witness_state.cells,
        ) {
            return Err(reject(
                arkret_wire::ReasonCode::RECOVERY_CAPABILITY_NOT_SEALED,
            ));
        }

        for move_id in &bottom.move_ids {
            let mut conflict_seal = None;
            for seal_id in predecessor_closure {
                if let Ok(Some(seal)) = seals.get(seal_id).await
                    && seal.delta.contains(move_id)
                {
                    conflict_seal = Some(seal);
                    break;
                }
            }
            let conflict_seal = conflict_seal
                .ok_or_else(|| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?;
            let conflict_closure =
                predecessor_seal_closure(std::slice::from_ref(&conflict_seal.id), seals)
                    .await
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
                .await
                .map_err(|_| reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID))?;
            if !leaf_closure.contains(&witness_id) {
                return Err(reject(arkret_wire::ReasonCode::RECOVERY_WITNESS_INVALID));
            }
            let leaf_time = seals
                .get(leaf)
                .await
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
pub async fn verify_seal_basis(
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
    )
    .await?;
    Ok(())
}

/// Every Seal reachable from `predecessor_refs`, the roots included.
///
/// §6.3 step 5 scopes "already sealed" and §5.1 step 2 scopes an admissible
/// `seal_basis` leaf to exactly this set — never to the receiver's own global
/// accepted-Seal set, which would make acceptance depend on leaf arrival
/// order.
pub async fn predecessor_seal_closure(
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
            .get(&id)
            .await?
            .ok_or_else(|| SealReject::Store(format!("predecessor {id} not in store")))?;
        queue.extend(seal.predecessor_refs);
    }
    Ok(out)
}

pub async fn effective_seal_view(
    leaves: &[SealId],
    realm_id: &RealmId,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<EffectiveSealView, SealReject> {
    let mut sorted = leaves.to_vec();
    sorted.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let union_proof = leaf_union_proof(&sorted, seals).await?;
    let covered = union_covered_from_proof(&union_proof);
    let covered_event_digests: Vec<Hash> = covered.iter().cloned().collect();
    let control_event_set_root = control_event_set_root(&covered, digest_suite)?;
    let post_state = effective_joined_view_at(&sorted, realm_id, seals, cells, registry).await?;
    let state_root = post_state
        .state_root(digest_suite)
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

pub async fn union_predecessor_covered_events(
    predecessor_refs: &[SealId],
    seals: &dyn SealStore,
) -> Result<BTreeSet<Hash>, SealReject> {
    let mut out = BTreeSet::new();
    for predecessor in predecessor_refs {
        collect_covered_events(predecessor, seals, &mut out).await?;
    }
    Ok(out)
}

pub async fn leaf_union_proof(
    leaves: &[SealId],
    seals: &dyn SealStore,
) -> Result<Vec<SealLeafUnionProof>, SealReject> {
    let mut sorted = leaves.to_vec();
    sorted.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let mut proof = Vec::with_capacity(sorted.len());
    for leaf in sorted {
        let mut covered = BTreeSet::new();
        collect_covered_events(&leaf, seals, &mut covered).await?;
        let covered_event_digests: Vec<Hash> = covered.iter().cloned().collect();
        let leaf_seal = seals
            .get(&leaf)
            .await?
            .ok_or_else(|| SealReject::Store(format!("predecessor {leaf} not in store")))?;
        let digest_suite = digest_suite_from_trusted_hash(&leaf_seal.control_event_set_root)?;
        let control_event_set_root = control_event_set_root(&covered, digest_suite)?;
        if control_event_set_root != leaf_seal.control_event_set_root {
            return Err(SealReject::ControlEventSetRootMismatch {
                declared: leaf_seal.control_event_set_root.as_str().to_owned(),
                recomputed: control_event_set_root.as_str().to_owned(),
            });
        }
        proof.push(SealLeafUnionProof {
            leaf,
            covered_event_digests,
            control_event_set_root,
        });
    }
    Ok(proof)
}

fn union_covered_from_proof(proof: &[SealLeafUnionProof]) -> BTreeSet<Hash> {
    proof
        .iter()
        .flat_map(|leaf| leaf.covered_event_digests.iter().cloned())
        .collect()
}

async fn collect_covered_events(
    seal_id: &SealId,
    seals: &dyn SealStore,
    out: &mut BTreeSet<Hash>,
) -> Result<(), SealReject> {
    let mut pending = vec![seal_id.clone()];
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !visited.insert(id.clone()) {
            continue;
        }
        let seal = seals
            .get(&id)
            .await?
            .ok_or_else(|| SealReject::Store(format!("predecessor {id} not in store")))?;
        if !seal.covered_event_digests.is_empty() {
            out.extend(seal.covered_event_digests);
            continue;
        }
        pending.extend(seal.predecessor_refs);
        out.extend(seal.delta);
    }
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

pub async fn effective_state_at(
    leaves: &[SealId],
    realm_id: &RealmId,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<BTreeMap<CellRef, CellState>, SealReject> {
    let covered = union_predecessor_covered_events(leaves, seals).await?;
    effective_state_for_covered_events(&covered, realm_id, cells, registry).await
}

/// The identity half of one cell's active heads, or an empty set when the cell
/// has never been written.
fn head_identities(heads: Option<&Vec<crate::lattice::cas_register::CasHead>>) -> Vec<Hash> {
    heads.map_or_else(Vec::new, |heads| {
        heads.iter().map(|head| head.move_id.clone()).collect()
    })
}

/// Whether two derived head-identity sets name the same writes.
///
/// Order and repetition are not part of the comparison: both sides come from
/// [`cas_heads`], which already deduplicates by identity and sorts by the
/// decoded `event_id` token, so this is a set equality that stays correct if
/// either producer ever changes its ordering.
fn head_identities_match(left: &[Hash], right: &[Hash]) -> bool {
    let left: BTreeSet<&str> = left.iter().map(Hash::as_str).collect();
    let right: BTreeSet<&str> = right.iter().map(Hash::as_str).collect();
    left == right
}

/// The active `cas_register` head identities of every written cell in the view
/// those Seal leaves cover.
///
/// This is `H_c(V)` of `event-auth-state-resolution.md` §9.3.1.1, reduced to the
/// identities. It is what a write's own signed `seal_basis` contributes to
/// admission: §9.3.1.3 item 3 compares the writer's `H_c(B)` against the frozen
/// predecessor `H_c(P)` identity-for-identity, and item 4 makes the accepted
/// write supersede exactly that set.
///
/// Cells whose lattice is not `cas_register`, and cells with no head, are
/// absent rather than present-and-empty: "no entry" and "no head" are the same
/// statement here, and a first write on an untouched cell supersedes nothing.
pub async fn effective_cas_heads_at(
    leaves: &[SealId],
    realm_id: &RealmId,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<CasHeadsByCell, SealReject> {
    let covered = union_predecessor_covered_events(leaves, seals).await?;
    cas_heads_for_covered_events(&covered, realm_id, cells, registry, &[]).await
}

/// The `cas_register` heads of a candidate post-state: an explicit covered set
/// layered with the ops a Seal is about to accept.
///
/// A durable backend may hide a cell op until its accepting Seal exists, so a
/// committer that has to recompute `state_root` before the commit assembles the
/// post-state in memory. This is the head half of that same assembly.
pub async fn effective_cas_heads_with_new_ops(
    covered: &BTreeSet<Hash>,
    realm_id: &RealmId,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    new_ops: &[(CellRef, IssuedOp)],
) -> Result<CasHeadsByCell, SealReject> {
    cas_heads_for_covered_events(covered, realm_id, cells, registry, new_ops).await
}

/// [`effective_cas_heads_at`] over an explicit covered set, optionally layered
/// with ops this Seal is about to accept.
///
/// The candidate ops are the same ones `apply_seal` layers onto the state: a
/// durable backend may hide a cell op until its accepting Seal exists, so the
/// post-state has to be assembled in memory rather than re-read.
/// Whether a lattice keeps its state as active write identities (§9.3.1.1 /
/// §9.3.1.5).
///
/// `cas_register` and `fsm` are the same causal register; they differ only in
/// what a head carries and in what makes a write well-shaped. Everything in this
/// module that derives `supersedes`, guards staleness or builds a head map
/// applies to both, so it asks this rather than naming one of them.
pub fn is_causal_register(kind: crate::lattice::LatticeKind) -> bool {
    matches!(
        kind,
        crate::lattice::LatticeKind::CasRegister | crate::lattice::LatticeKind::Fsm
    )
}

fn causal_heads_for_kind(
    kind: crate::lattice::LatticeKind,
    ops: &[SealedOp],
) -> Result<Vec<crate::lattice::cas_register::CasHead>, Box<crate::Bottom>> {
    match kind {
        crate::lattice::LatticeKind::Fsm => crate::lattice::fsm::fsm_heads(ops),
        _ => crate::lattice::cas_register::cas_heads(ops),
    }
}

async fn cas_heads_for_covered_events(
    covered: &BTreeSet<Hash>,
    realm_id: &RealmId,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    new_ops: &[(CellRef, IssuedOp)],
) -> Result<CasHeadsByCell, SealReject> {
    let mut targets = cells
        .list_cells(realm_id)
        .await?
        .into_iter()
        .collect::<BTreeSet<_>>();
    targets.extend(new_ops.iter().map(|(cell, _)| cell.clone()));

    let mut out = BTreeMap::new();
    for cell in targets {
        // `CellBinding` owns a `Box<dyn Lattice>`, which is not `Send`. Reading
        // the kind and dropping the binding *before* the first await is what
        // keeps this future `Send` for the axum/salvo handlers that call it.
        let kind = {
            let binding = registry.resolve(realm_id, &cell)?;
            binding.lattice.kind()
        };
        if !is_causal_register(kind) {
            continue;
        }
        let mut ops: Vec<SealedOp> = cells
            .sealed_op_batches_for_cell(realm_id, &cell)
            .await?
            .into_iter()
            .flat_map(|(_, batch)| batch)
            .filter(|issued| covered.contains(&issued.op.move_id))
            .map(|issued| issued.op)
            .collect();
        ops.extend(
            new_ops
                .iter()
                .filter(|(candidate, issued)| {
                    candidate == &cell && covered.contains(&issued.op.move_id)
                })
                .map(|(_, issued)| issued.op.clone()),
        );
        if ops.is_empty() {
            continue;
        }
        // A cell whose identities disagree is a store fault or a §6.3.3 digest
        // collision, not a state. Dropping it here used to be read as
        // "fails closed on the empty answer", which holds only for admission:
        // to a reader — the snapshot exporter above all — an absent cell is
        // indistinguishable from one that was never written, which is exactly
        // the reading `realm-state-snapshot-schema.md` §3 forbids. Both callers
        // are better served by the loud answer.
        let heads = causal_heads_for_kind(kind, &ops).map_err(|bottom| {
            SealReject::Store(format!(
                "cas_register cell {cell} carries one write identity with two canonical effects:                  {bottom:?}"
            ))
        })?;
        if heads.is_empty() {
            continue;
        }
        out.insert(cell, heads);
    }
    Ok(out)
}

/// One joined governance view: the settled values readers and preconditions
/// see, plus the `cas_register` head identities `state_root` needs.
///
/// The two halves are always derived from the same op set. Keeping them in one
/// value is what stops a caller from recomputing a root against a state whose
/// heads it never fetched — §6.2.1 hashes a different preimage for a CAS cell,
/// so a mismatched pair silently produces a wrong root rather than an error.
#[derive(Clone, Debug, Default)]
pub struct JoinedView {
    pub cells: BTreeMap<CellRef, CellState>,
    pub cas_heads: CasHeadsByCell,
}

impl JoinedView {
    pub fn as_governance_view(&self) -> GovernanceView<'_> {
        GovernanceView::new(&self.cells, &self.cas_heads)
    }

    pub fn state_root(
        &self,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<Hash, crate::WireError> {
        compute_state_root(self.as_governance_view(), digest_suite)
    }
}

/// [`effective_state_at`] paired with the head identities of the same view.
pub async fn effective_joined_view_at(
    leaves: &[SealId],
    realm_id: &RealmId,
    seals: &dyn SealStore,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<JoinedView, SealReject> {
    let covered = union_predecessor_covered_events(leaves, seals).await?;
    effective_joined_view_for_covered_events(&covered, realm_id, cells, registry).await
}

/// Both halves of the view from **one** pass over the cell store.
///
/// The two halves come from the same op set by construction — a caller that
/// builds one without the other has a bug rather than an option — so reading
/// the history twice was never buying independence, only a second
/// `list_cells` and a second `sealed_op_batches_for_cell` per cell. On a Realm
/// with `C` written cells that is `2 + 2C` round trips where `1 + C` do, and
/// `prepare_seal_with_proof_set` pays it several times per Seal.
async fn effective_joined_view_for_covered_events(
    covered: &BTreeSet<Hash>,
    realm_id: &RealmId,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<JoinedView, SealReject> {
    let mut view = JoinedView {
        cells: BTreeMap::new(),
        cas_heads: BTreeMap::new(),
    };
    for cell in cells.list_cells(realm_id).await? {
        // `CellBinding` owns a `Box<dyn Lattice>`, which is not `Send`. Reading
        // the kind and dropping the binding *before* the first await is what
        // keeps this future `Send` for the handlers that call it.
        let kind = {
            let binding = registry.resolve(realm_id, &cell)?;
            binding.lattice.kind()
        };
        let batches: Vec<Vec<IssuedOp>> = cells
            .sealed_op_batches_for_cell(realm_id, &cell)
            .await?
            .into_iter()
            .filter_map(|(_, ops)| {
                let covered_ops = ops
                    .into_iter()
                    .filter(|issued| covered.contains(&issued.op.move_id))
                    .collect::<Vec<_>>();
                (!covered_ops.is_empty()).then_some(covered_ops)
            })
            .collect();
        if batches.is_empty() {
            continue;
        }
        let binding = registry.resolve(realm_id, &cell)?;
        view.cells.insert(
            cell.clone(),
            join_cell_seal_batches(binding.lattice.as_ref(), &cell, &batches),
        );
        drop(binding);
        if !is_causal_register(kind) {
            continue;
        }
        // The head half reads the same ops flat: §9.3.1.1 / §9.3.1.5 derive
        // supersession from write identity, so batch boundaries carry no
        // information for it.
        let ops: Vec<SealedOp> = batches
            .into_iter()
            .flatten()
            .map(|issued| issued.op)
            .collect();
        // One identity with two canonical effects is a store fault or a §6.3.3
        // collision. Skipping the cell here used to read as failing closed; to
        // `state_root_leaves` it reads as a cell that has a value and no heads,
        // which is not a state §6.2.1 can encode.
        let heads = causal_heads_for_kind(kind, &ops).map_err(|bottom| {
            SealReject::Store(format!(
                "causal register cell {cell} carries one write identity with two canonical                  effects: {bottom:?}"
            ))
        })?;
        if heads.is_empty() {
            continue;
        }
        view.cas_heads.insert(cell, heads);
    }
    Ok(view)
}

async fn effective_state_for_covered_events(
    covered: &BTreeSet<Hash>,
    realm_id: &RealmId,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
) -> Result<BTreeMap<CellRef, CellState>, SealReject> {
    let mut out = BTreeMap::new();
    for cell in cells.list_cells(realm_id).await? {
        let batches: Vec<(SealId, Vec<IssuedOp>)> = cells
            .sealed_op_batches_for_cell(realm_id, &cell)
            .await?
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
async fn effective_state_for_covered_events_with_new_ops(
    covered: &BTreeSet<Hash>,
    realm_id: &RealmId,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    new_ops: &[(CellRef, IssuedOp)],
) -> Result<BTreeMap<CellRef, CellState>, SealReject> {
    let mut cells_to_resolve = cells
        .list_cells(realm_id)
        .await?
        .into_iter()
        .collect::<BTreeSet<_>>();
    cells_to_resolve.extend(new_ops.iter().map(|(cell, _)| cell.clone()));

    let mut out = BTreeMap::new();
    for cell in cells_to_resolve {
        let mut batches = cells
            .sealed_op_batches_for_cell(realm_id, &cell)
            .await?
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

/// [`effective_state_for_covered_events_with_new_ops`] paired with the head
/// identities of the same candidate view.
async fn effective_joined_view_with_new_ops(
    covered: &BTreeSet<Hash>,
    realm_id: &RealmId,
    cells: &dyn CellStore,
    registry: &dyn CellRegistry,
    new_ops: &[(CellRef, IssuedOp)],
) -> Result<JoinedView, SealReject> {
    Ok(JoinedView {
        cells: effective_state_for_covered_events_with_new_ops(
            covered, realm_id, cells, registry, new_ops,
        )
        .await?,
        cas_heads: cas_heads_for_covered_events(covered, realm_id, cells, registry, new_ops)
            .await?,
    })
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
    let ops = ops_since_last_recovery_reset(lattice.kind(), ops);
    if lattice.kind() == crate::lattice::LatticeKind::OrderedLog {
        return crate::lattice::OrderedLog.join_with_issuers(cell, ops);
    }
    let sealed: Vec<SealedOp> = ops.iter().map(|issued| issued.op.clone()).collect();
    lattice.join(cell, &sealed)
}

/// The cell's join input after a §9.5 conflict recovery.
///
/// **`cas_register` never truncates.** §9.5.1 makes its recovery an ordinary
/// identity write that supersedes exactly the divergent heads its own signed
/// basis observed, so the reset needs no special join input: a late branch the
/// recovery never covered stays a head and still merges, and two concurrent
/// recoveries with different values still conflict. §9.5.1 item 5 names this
/// `rposition` slice specifically and forbids it, because slicing the log by
/// arrival order makes the result depend on delivery.
///
/// `fsm` is the same causal register (§9.3.1.5-§9.3.1.8), so it is exempt for
/// the same reason: its recovery is an authorized new identity write that
/// supersedes exactly the heads its own basis saw. What still truncates here is
/// a `bottom=reject` lattice that is not causal -- today only `ordered_log` --
/// whose recovery is still the §9.5 `state_witness` form.
fn ops_since_last_recovery_reset(
    kind: crate::lattice::LatticeKind,
    ops: &[IssuedOp],
) -> &[IssuedOp] {
    if is_causal_register(kind) {
        return ops;
    }
    ops.iter()
        .rposition(|issued| issued.op.recovery_reset)
        .map_or(ops, |boundary| &ops[boundary..])
}

/// The active `cas_register` heads of one cell over its accepted Seal batches.
///
/// The batch structure carries no causal information for this lattice — heads
/// come from the identities each write superseded — so this simply flattens and
/// derives. It exists so a caller that already holds batches (the bootstrap and
/// Agent-PCR projectors do) can build the head half of a
/// [`crate::state::state_root::GovernanceView`] without going back to a store.
///
/// A cell whose identities disagree yields an empty head set: the caller is
/// about to reject the view anyway, and an empty set keeps it out of the
/// `state_root` rather than hashing a leaf nothing can verify.
pub fn cas_heads_for_batches(
    batches: &[Vec<IssuedOp>],
) -> Vec<crate::lattice::cas_register::CasHead> {
    causal_heads_for_batches(crate::lattice::LatticeKind::CasRegister, batches)
}

/// [`cas_heads_for_batches`] for whichever causal register the cell is.
///
/// `fsm` heads carry the transition's `to` rather than a written value
/// (§9.3.1.5), so a caller that asked for `cas_register` heads on an `fsm` cell
/// got an empty set — and an empty set is how §6.2.1 spells "never written".
pub fn causal_heads_for_batches(
    kind: crate::lattice::LatticeKind,
    batches: &[Vec<IssuedOp>],
) -> Vec<crate::lattice::cas_register::CasHead> {
    let ops: Vec<SealedOp> = batches
        .iter()
        .flat_map(|batch| batch.iter().map(|issued| issued.op.clone()))
        .collect();
    causal_heads_for_kind(kind, &ops).unwrap_or_default()
}

/// Join accepted operations while preserving frozen-predecessor Seal batches.
///
/// `mv_register` writes in a successor Seal causally replace the previous head,
/// and multiple writes inside one Seal share one predecessor view and therefore
/// remain sibling heads; that lattice carries no predecessor on the op, so the
/// Seal batch is the only causal signal it has. Every other core lattice
/// consumes the full accepted history, because its join already models causal
/// supersession, ordered transitions or commutative accumulation.
/// `cas_register` in particular MUST see the whole history: its heads are
/// derived from the identities each write superseded (§9.3.1.1), so a truncated
/// input would resurrect writes whose superseder was cut away.
pub fn join_cell_seal_batches(
    lattice: &dyn crate::lattice::Lattice,
    cell: &CellRef,
    batches: &[Vec<IssuedOp>],
) -> CellState {
    // A §9.5 recovery reset ends the prior history for the lattices that still
    // express recovery by truncation. Neither causal register is one of them:
    // their recovery is an ordinary identity write (§9.5.1), so every batch
    // stays. Truncating them would make the answer depend on batch order --
    // two concurrent recoveries with different values must stay two heads and
    // conflict, not collapse to whichever arrived last.
    let batches = if is_causal_register(lattice.kind()) {
        batches
    } else {
        batches
            .iter()
            .rposition(|ops| ops.iter().any(|issued| issued.op.recovery_reset))
            .map_or(batches, |boundary| &batches[boundary..])
    };
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
