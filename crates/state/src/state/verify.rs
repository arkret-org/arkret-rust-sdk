//! Control Move verifier pipeline.
//!
//! A Control Move is an [`Event`] carrying `seal_basis`
//! (`event-auth-state-resolution.md` §5); there is no standalone Move object
//! and no producer-authored effect array. §5.1 fixes the step order:
//!
//! | step | check | wire error_code on fail |
//! | --- | --- | --- |
//! | 1 structural | canonical bytes, envelope shape, `realm_id` | `schema_violation` |
//! | 2 proofs | `proofs[].event_digest` binds the recomputed digest; signature verify | `signature_invalid` |
//! | 3 critical refs | each `refs[role=authorized_by]` resolves to a covering grant | `capability_denied` |
//! | 4 preconditions | every `(cell, predicate)` evaluates true at its command execution position | `state_mismatch` |
//! | 5 derived writes | every projected write passes the cell's `validate_op` | `schema_violation` |
//!
//! §5.1 steps 2-4 (`seal_basis.leaves[]` inside the receiving Seal's
//! predecessor closure, and the two declared roots against that leaf view)
//! need the confirmed Seal chain, so they live in [`crate::state::seal::verify_seal_basis`]
//! and `apply_seal` runs them just before this function.
//!
//! Two dependencies are injected rather than imported. Signature verification
//! lives in `arkret-signatures`, and — the load-bearing one — the projection
//! evaluator that turns `kind + payload` into cell writes lives in
//! `arkret-schema`, which this crate is forbidden to depend on
//! (`tools/check-layering.py`). Both arrive as closures so the pipeline
//! orchestration stays pure and this crate keeps no registry of its own.

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::ActorId;
use arkret_wire::event_envelope::{EVENT_REF_ROLE_AUTHORIZED_BY, Event, EventSubmitContext};
use arkret_wire::patch::Patch;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use super::store::{CausalRegisterBottomPolicy, CellStateRegistry, StoreError};
use crate::state_model::ResolvedCellState;
use crate::{
    BottomKind, CellRef, LatticeOp, LatticeOpType, ObservedRemoveMatch, Predicate, PredicateOp,
    ProjectedCellWrite, ProjectedOp, ProjectionEffect, RealmId,
};

#[derive(Debug, Error)]
pub enum ControlMoveReject {
    #[error("schema violation: {0}")]
    SchemaViolation(String),

    #[error("invalid signature: {0}")]
    SignatureInvalid(String),

    #[error("capability denied: {0}")]
    CapabilityDenied(String),

    #[error("precondition failed on cell {cell}: {reason}")]
    FailedPrecondition { cell: String, reason: String },

    #[error("precondition reads cell {cell} which is bottom (kind={kind:?}); fail closed")]
    FailedBottom { cell: String, kind: BottomKind },

    #[error(
        "apply_patch prestate binding on cell {cell} expected {expected} but the frozen pre-state \
         digests to {observed}"
    )]
    PrestateBindingMismatch {
        cell: String,
        expected: String,
        observed: String,
    },

    #[error("reducer projection failed: {0}")]
    ProjectionFailed(String),

    #[error("verified signed causal data context unavailable for cell {cell}")]
    MissingDataContext { cell: String },

    #[error("verified ordinary publication context unavailable for approval Event {event_id}")]
    MissingPublicationContext { event_id: arkret_wire::EventId },

    #[error("registry error: {0}")]
    Registry(String),
}

/// Whether a verification failure is a durable command result or prevents a
/// decision at the current execution position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlMoveFailureDisposition {
    Rejected(crate::ReasonCode),
    Pending(crate::ReasonCode),
    Invalid,
    Infrastructure,
}

/// Classify a verifier failure for ordered Seal command execution.
///
/// Invalid Event bytes and proofs invalidate the proposed Seal. Missing
/// dependencies keep the command pending, and registry/backend failures abort
/// execution. Only deterministic authorization, precondition, and registered
/// reducer outcomes become durable `rejected` command results.
pub fn classify_control_move_reject(reject: &ControlMoveReject) -> ControlMoveFailureDisposition {
    match reject {
        ControlMoveReject::SchemaViolation(_) | ControlMoveReject::SignatureInvalid(_) => {
            ControlMoveFailureDisposition::Invalid
        }
        ControlMoveReject::CapabilityDenied(_) => {
            ControlMoveFailureDisposition::Rejected(crate::ReasonCode::PolicyDenied)
        }
        ControlMoveReject::FailedPrecondition { reason, .. } => {
            classify_registered_failure_reason(reason, crate::ReasonCode::StateMismatch)
        }
        ControlMoveReject::FailedBottom { .. } => {
            ControlMoveFailureDisposition::Rejected(crate::ReasonCode::CellInBottomState)
        }
        ControlMoveReject::PrestateBindingMismatch { .. } => {
            ControlMoveFailureDisposition::Rejected(crate::ReasonCode::StateMismatch)
        }
        ControlMoveReject::ProjectionFailed(reason) => {
            classify_registered_failure_reason(reason, crate::ReasonCode::ReducerProjectionFailed)
        }
        ControlMoveReject::MissingDataContext { .. }
        | ControlMoveReject::MissingPublicationContext { .. } => {
            ControlMoveFailureDisposition::Pending(crate::ReasonCode::DependencyMissing)
        }
        ControlMoveReject::Registry(_) => ControlMoveFailureDisposition::Infrastructure,
    }
}

fn classify_registered_failure_reason(
    reason: &str,
    fallback: crate::ReasonCode,
) -> ControlMoveFailureDisposition {
    let reason = crate::ReasonCode::from_wire(reason);
    let reason = if reason.descriptor().is_some() {
        reason
    } else {
        fallback
    };
    match reason {
        crate::ReasonCode::DependencyMissing
        | crate::ReasonCode::UnsupportedProfile
        | crate::ReasonCode::QuorumUnreachable => ControlMoveFailureDisposition::Pending(reason),
        crate::ReasonCode::BackendUnavailable => ControlMoveFailureDisposition::Infrastructure,
        reason => ControlMoveFailureDisposition::Rejected(reason),
    }
}

impl From<StoreError> for ControlMoveReject {
    fn from(e: StoreError) -> Self {
        ControlMoveReject::Registry(e.to_string())
    }
}

/// Frozen receiver state and protocol context shared by one Control Move
/// verification pass.
#[derive(Clone, Copy)]
pub struct ControlMoveVerificationContext<'a> {
    pub realm_id: &'a RealmId,
    pub pre_state: &'a BTreeMap<CellRef, ResolvedCellState>,
    /// Exact state reconstructed at the producer-signed Seal basis.
    pub signed_basis_state: &'a BTreeMap<CellRef, ResolvedCellState>,
    /// State before this registered atomic unit began execution.
    pub revision_state: &'a BTreeMap<CellRef, ResolvedCellState>,
    /// Additional actual security reads performed by the registered domain evaluator.
    pub additional_security_reads: &'a [CellRef],
    pub registry: &'a dyn CellStateRegistry,
    pub digest_suite: arkret_canonical::DigestSuite,
    pub submit_context: EventSubmitContext,
}

/// Map a [`ControlMoveReject`] variant to its wire-level `error_code`
/// constant (from `arkret-spec` `error-code-registry.json`).
pub fn reject_to_error_code(r: &ControlMoveReject) -> &'static str {
    match r {
        ControlMoveReject::SchemaViolation(_) => crate::ErrorCode::SCHEMA_VIOLATION,
        ControlMoveReject::SignatureInvalid(_) => crate::ErrorCode::SIGNATURE_INVALID,
        ControlMoveReject::CapabilityDenied(_) => crate::ErrorCode::CAPABILITY_DENIED,
        ControlMoveReject::FailedPrecondition { .. } => crate::ErrorCode::STATE_MISMATCH,
        // A precondition that reads a ⊥ cell fails closed. The registry has no
        // top-level `failed_bottom` code; the bottom semantics are a
        // `failed_precondition` sub-reason (`cell_in_bottom_state`). Surface the
        // registered top-level `state_mismatch` code (same family as
        // `FailedPrecondition`); the reason carries the ⊥ detail.
        ControlMoveReject::FailedBottom { .. } => crate::ErrorCode::STATE_MISMATCH,
        // §2.4.2 names the code for a broken `expected_prestate` binding
        // outright: when the binding does not byte-equal the frozen pre-state's
        // canonical digest, the whole Event MUST be rejected with
        // `failed_precondition`. That is a different registered code from the
        // §5.1 step-4 `state_mismatch` above, hence its own variant.
        ControlMoveReject::PrestateBindingMismatch { .. } => crate::ErrorCode::FAILED_PRECONDITION,
        // `reducer_projection_failed` is a reason_code, not a top-level code:
        // the Event's declared writes could not be derived, which is the same
        // family of failure as a malformed envelope.
        ControlMoveReject::ProjectionFailed(_) => crate::ErrorCode::SCHEMA_VIOLATION,
        ControlMoveReject::MissingDataContext { .. }
        | ControlMoveReject::MissingPublicationContext { .. } => {
            crate::ErrorCode::DEPENDENCY_MISSING
        }
        ControlMoveReject::Registry(_) => crate::ErrorCode::INTERNAL_ERROR,
    }
}

/// Verify a Control Move against its execution-position state and return the
/// receiver-derived writes.
///
/// The first command receives the confirmed predecessor state. Each later
/// command receives the staged state after every earlier committed registered
/// unit. Cells absent from the map are treated as
/// `ResolvedCellState::Value(Value::Null)`.
///
/// `verify_proofs` owns cryptographic signature verification; pass
/// `|_| Ok(())` when signatures are checked elsewhere (e.g. fixture replay).
///
/// `project_writes` MUST be the registered reducer contract's projection
/// evaluator (`arkret_schema::project_registered_cell_writes`). It is a
/// parameter because the registry lives one layer above this crate; nothing
/// here may guess a target or an operation from the Event kind name.
///
/// The returned [`ProjectionEffect`]s are the fully resolved writes, in
/// projection order, ready for `apply_seal` to append to the cell logs.
pub fn verify_control_move<VerifyProofs, ProjectWrites>(
    event: &Event,
    realm_id: &RealmId,
    pre_state: &BTreeMap<CellRef, ResolvedCellState>,
    signed_basis_state: &BTreeMap<CellRef, ResolvedCellState>,
    registry: &dyn CellStateRegistry,
    digest_suite: arkret_canonical::DigestSuite,
    verify_proofs: VerifyProofs,
    project_writes: ProjectWrites,
) -> Result<Vec<ProjectionEffect>, ControlMoveReject>
where
    VerifyProofs: Fn(&Event) -> Result<(), String>,
    ProjectWrites: Fn(&Event) -> Result<Vec<ProjectedCellWrite>, String>,
{
    verify_control_move_in_context(
        event,
        ControlMoveVerificationContext {
            realm_id,
            pre_state,
            signed_basis_state,
            revision_state: pre_state,
            additional_security_reads: &[],
            registry,
            digest_suite,
            submit_context: EventSubmitContext::Standard,
        },
        verify_proofs,
        project_writes,
    )
}

/// Verify a Control Move under an explicit CBS envelope context.
///
/// `AnchorUnit` is only valid after the caller has validated one of the
/// protocol's closed bootstrap/re-anchor units. It permits the unit's
/// basis-less Events while preserving the remaining proof, capability,
/// precondition, and reducer checks.
pub fn verify_control_move_in_context<VerifyProofs, ProjectWrites>(
    event: &Event,
    verification: ControlMoveVerificationContext<'_>,
    verify_proofs: VerifyProofs,
    project_writes: ProjectWrites,
) -> Result<Vec<ProjectionEffect>, ControlMoveReject>
where
    VerifyProofs: Fn(&Event) -> Result<(), String>,
    ProjectWrites: Fn(&Event) -> Result<Vec<ProjectedCellWrite>, String>,
{
    verify_control_move_with_proof_set(
        event,
        verification,
        verify_proofs,
        project_writes,
        StructuralProofRegime::ProducerSubmission,
    )
}

/// Verify a Control Move loaded from accepted federation history.
pub fn verify_accepted_control_move_in_context<VerifyProofs, ProjectWrites>(
    event: &Event,
    verification: ControlMoveVerificationContext<'_>,
    verify_proofs: VerifyProofs,
    project_writes: ProjectWrites,
) -> Result<Vec<ProjectionEffect>, ControlMoveReject>
where
    VerifyProofs: Fn(&Event) -> Result<(), String>,
    ProjectWrites: Fn(&Event) -> Result<Vec<ProjectedCellWrite>, String>,
{
    verify_control_move_with_proof_set(
        event,
        verification,
        verify_proofs,
        project_writes,
        StructuralProofRegime::FederationAccepted,
    )
}

/// Verify one retained producer-signed Control Move.
pub fn verify_replayed_control_move_in_context<VerifyProofs, ProjectWrites>(
    event: &Event,
    verification: ControlMoveVerificationContext<'_>,
    verify_proofs: VerifyProofs,
    project_writes: ProjectWrites,
) -> Result<Vec<ProjectionEffect>, ControlMoveReject>
where
    VerifyProofs: Fn(&Event) -> Result<(), String>,
    ProjectWrites: Fn(&Event) -> Result<Vec<ProjectedCellWrite>, String>,
{
    verify_control_move_with_proof_set(
        event,
        verification,
        verify_proofs,
        project_writes,
        StructuralProofRegime::RetainedReplay,
    )
}

#[derive(Clone, Copy)]
enum StructuralProofRegime {
    ProducerSubmission,
    FederationAccepted,
    RetainedReplay,
}

fn verify_control_move_with_proof_set<VerifyProofs, ProjectWrites>(
    event: &Event,
    verification: ControlMoveVerificationContext<'_>,
    verify_proofs: VerifyProofs,
    project_writes: ProjectWrites,
    proof_regime: StructuralProofRegime,
) -> Result<Vec<ProjectionEffect>, ControlMoveReject>
where
    VerifyProofs: Fn(&Event) -> Result<(), String>,
    ProjectWrites: Fn(&Event) -> Result<Vec<ProjectedCellWrite>, String>,
{
    let ControlMoveVerificationContext {
        realm_id,
        pre_state,
        signed_basis_state,
        revision_state,
        additional_security_reads,
        registry,
        digest_suite,
        submit_context: context,
    } = verification;
    // Step 1: structural. `validate_for_submit_structural` also enforces the
    // CBS envelope shape, so an ordinary Event with `auth_context` or an Event
    // with neither authorization context nor basis cannot reach this reducer.
    match proof_regime {
        StructuralProofRegime::ProducerSubmission => event
            .validate_for_submit_structural_in_context(context)
            .map_err(|e| ControlMoveReject::SchemaViolation(e.to_string()))?,
        StructuralProofRegime::FederationAccepted => event
            .validate_for_federation_structural_in_context(context, digest_suite)
            .map_err(|e| ControlMoveReject::SchemaViolation(e.to_string()))?,
        StructuralProofRegime::RetainedReplay => event
            .validate_for_direct_history_structural_in_context(context)
            .map_err(|e| ControlMoveReject::SchemaViolation(e.to_string()))?,
    }
    if event.realm_id != *realm_id {
        return Err(ControlMoveReject::SchemaViolation(format!(
            "Control Move realm_id {} does not match the receiving Realm {realm_id}",
            event.realm_id
        )));
    }
    if context == EventSubmitContext::Standard && event.seal_basis.is_none() {
        return Err(ControlMoveReject::SchemaViolation(
            "Control Move must carry seal_basis".to_owned(),
        ));
    }

    // Step 2: proof bindings. `validate_proof_bindings` recomputes the canonical
    // digest and rejects any proof that binds a different one, so a producer
    // cannot present a signature over bytes other than the ones we reduce.
    event
        .verify_event_id_matches_content_with_digest_suite(digest_suite)
        .map_err(|e| ControlMoveReject::SignatureInvalid(e.to_string()))?;
    event
        .validate_proof_bindings_with_digest_suite(digest_suite)
        .map_err(|e| ControlMoveReject::SignatureInvalid(e.to_string()))?;

    // Step 3: critical refs. Fork-resolution authorization is deliberately
    // established before the proof callback: that callback also validates
    // collision-variant records signed by the exact authorized resolution
    // principal, and must never run as an authority substitute.
    if event.actor_id.validate().is_err() {
        return Err(ControlMoveReject::CapabilityDenied(
            "actor identity is invalid".to_owned(),
        ));
    }
    verify_capability_refs(event, pre_state)?;
    if event.kind == arkret_wire::EventKind::ForkResolution {
        verify_fork_resolution_refs(event, pre_state)?;
    }
    verify_proofs(event).map_err(ControlMoveReject::SignatureInvalid)?;

    // The signed approval payload alone cannot prove its ordinary publication.
    // Every execution/replay entry point must also verify that exact Event and
    // its security read set; no such context is supplied by this API yet.
    if event.kind == arkret_wire::EventKind::AgentActionApprove {
        return Err(ControlMoveReject::MissingPublicationContext {
            event_id: event.event_id.clone(),
        });
    }

    let projected = project_writes(event).map_err(ControlMoveReject::ProjectionFailed)?;
    let mut dependencies = additional_security_reads
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    dependencies.extend(projected.iter().map(|write| write.cell_id.clone()));
    dependencies.extend(event.preconditions.iter().map(|pre| pre.cell_id.clone()));
    for reference in event.refs.iter().filter(|reference| {
        reference.role == EVENT_REF_ROLE_AUTHORIZED_BY || reference.role == "recovery_capability"
    }) {
        dependencies.insert(capability_grant_cell(reference.id.as_str())?);
    }
    verify_security_revision_guards(
        realm_id,
        signed_basis_state,
        revision_state,
        registry,
        &dependencies,
    )?;

    // Data predicates and patches cannot be evaluated against the Seal's
    // security-only state. Until a verified signed causal data context is
    // available, keep the complete command pending instead of manufacturing
    // a deterministic rejection from an absent or unrelated data value.
    if context != EventSubmitContext::AnchorUnit {
        for cell in projected
            .iter()
            .map(|write| &write.cell_id)
            .chain(event.preconditions.iter().map(|pre| &pre.cell_id))
        {
            let binding = registry
                .resolve(realm_id, cell)
                .map_err(|error| ControlMoveReject::Registry(error.to_string()))?;
            if binding.execution == arkret_wire::EventCellExecution::Data {
                return Err(ControlMoveReject::MissingDataContext {
                    cell: cell.as_str().to_owned(),
                });
            }
        }
    }

    // Step 4: preconditions
    for pre in &event.preconditions {
        // An unwritten cell reads `null` protocol-wide
        // (`event-auth-state-resolution.md` section 9.3.1.2). There is no
        // registered `initial_value` any more: a family that needs a reusable
        // free slot registers an explicit `set null` release write, and the
        // Seal-admission head-identity guard — not a distinguished sentinel
        // value — is what separates "never written" from "released".
        let cell_state = pre_state
            .get(&pre.cell_id)
            .cloned()
            .unwrap_or(ResolvedCellState::Value(Value::Null));
        // bottom=reject cells fail closed.
        if let ResolvedCellState::Bottom(b) = &cell_state {
            let binding = registry
                .resolve(realm_id, &pre.cell_id)
                .map_err(|e| ControlMoveReject::Registry(e.to_string()))?;
            if binding.bottom_policy != Some(CausalRegisterBottomPolicy::Expose) {
                return Err(ControlMoveReject::FailedBottom {
                    cell: pre.cell_id.as_str().to_owned(),
                    kind: b.kind,
                });
            }
        }
        evaluate_predicate(&pre.cell_id, &pre.predicate, &cell_state)?;
    }

    // Step 5: derive each security write and validate it against the frozen
    // predecessor state and the registered sequenced-state contract.
    let mut effects = Vec::with_capacity(projected.len());
    for write in &projected {
        for effect in resolve_projected_write(write, realm_id, pre_state, registry)? {
            let binding = registry
                .resolve(realm_id, &effect.cell_id)
                .map_err(|e| ControlMoveReject::Registry(e.to_string()))?;
            if binding.execution == arkret_wire::EventCellExecution::Security
                && binding.state_model != crate::state_model::StateModelKind::SequencedState
            {
                return Err(ControlMoveReject::SchemaViolation(format!(
                    "security cell {} must use sequenced_state",
                    effect.cell_id
                )));
            }
            if binding.execution == arkret_wire::EventCellExecution::Data
                && context != EventSubmitContext::AnchorUnit
            {
                return Err(ControlMoveReject::MissingDataContext {
                    cell: effect.cell_id.as_str().to_owned(),
                });
            }
            if let Some(ResolvedCellState::Bottom(bottom)) = pre_state.get(&effect.cell_id) {
                return Err(ControlMoveReject::FailedBottom {
                    cell: effect.cell_id.as_str().to_owned(),
                    kind: bottom.kind,
                });
            }
            binding.model.validate_op(&effect.op).map_err(|e| {
                ControlMoveReject::SchemaViolation(format!(
                    "derived write on {} invalid: {e}",
                    effect.cell_id
                ))
            })?;
            if let Some(rule) = &binding.domain_transition {
                let current = pre_state
                    .get(&effect.cell_id)
                    .and_then(ResolvedCellState::settled_value);
                rule.validate(current, &effect.op).map_err(|e| {
                    ControlMoveReject::FailedPrecondition {
                        cell: effect.cell_id.as_str().to_owned(),
                        reason: e.to_string(),
                    }
                })?;
            }
            effects.push(effect);
        }
    }
    Ok(effects)
}

/// Check identity CAS for the exact security Cells actually read or written.
/// An absent Cell and a written-null revision are distinct identities.
pub fn verify_security_revision_guards(
    realm_id: &RealmId,
    signed_basis_state: &BTreeMap<CellRef, ResolvedCellState>,
    revision_state: &BTreeMap<CellRef, ResolvedCellState>,
    registry: &dyn CellStateRegistry,
    dependencies: &BTreeSet<CellRef>,
) -> Result<(), ControlMoveReject> {
    for cell in dependencies {
        let binding = registry
            .resolve(realm_id, cell)
            .map_err(|error| ControlMoveReject::Registry(error.to_string()))?;
        if binding.execution != arkret_wire::EventCellExecution::Security {
            continue;
        }
        let revision = |state: &BTreeMap<CellRef, ResolvedCellState>| -> Result<Option<crate::EventId>, ControlMoveReject> {
            match state.get(cell) {
                None => Ok(None),
                Some(ResolvedCellState::Sequenced(state)) => Ok(Some(state.revision_event_id.clone())),
                Some(_) => Err(ControlMoveReject::Registry(format!("security Cell {cell} does not have a confirmed revision"))),
            }
        };
        if revision(signed_basis_state)? != revision(revision_state)? {
            return Err(ControlMoveReject::FailedPrecondition {
                cell: cell.as_str().to_owned(),
                reason: crate::ReasonCode::StateMismatch.as_str().to_owned(),
            });
        }
    }
    Ok(())
}

fn verify_fork_resolution_refs(
    event: &Event,
    pre_state: &BTreeMap<CellRef, ResolvedCellState>,
) -> Result<(), ControlMoveReject> {
    // Exactly one, never merely at least one: two grants would leave which
    // authority actually approved the resolution ambiguous.
    let mut capabilities = event
        .refs
        .iter()
        .filter(|reference| reference.role == "recovery_capability" && reference.critical);
    let capability = capabilities
        .next()
        .ok_or_else(|| ControlMoveReject::FailedPrecondition {
            cell: event.realm_id.as_str().to_owned(),
            reason: "failed_precondition".to_owned(),
        })?;
    if capabilities.next().is_some() {
        return Err(ControlMoveReject::FailedPrecondition {
            cell: event.realm_id.as_str().to_owned(),
            reason: "failed_precondition".to_owned(),
        });
    }
    // `state_witness` attests the single legal value a cell held before it
    // joined to Bottom. The fork-resolution cell has no head at all until this
    // very write, so the role has no referent here and must not be carried over
    // from the section 9.5 cell-recovery contract. Optional `attestation` /
    // `inclusion_proof` refs stay allowed as supporting evidence.
    if event
        .refs
        .iter()
        .any(|reference| reference.role == "state_witness")
    {
        return Err(ControlMoveReject::FailedPrecondition {
            cell: event.realm_id.as_str().to_owned(),
            reason: "schema_violation".to_owned(),
        });
    }
    // Section 6.3.2: an adjudication is final in one direction only. Without a
    // `head_eq: null` on the target cell, a causal successor whose basis already
    // contains the settled verdict satisfies the automatic revision identity guard
    // already agrees with the settled revision and could swap the
    // canonical winner or flip void_all, retroactively cutting an accepted actor
    // chain. The guard cannot catch it, so the assertion has to be carried.
    //
    // Only the shape is checked here; step 4 evaluates the predicate against the
    // frozen pre-state, so a cell that already holds a verdict rejects there.
    let mut slot_guards = event.preconditions.iter().filter(|precondition| {
        precondition.predicate.op == PredicateOp::HeadEq
            && precondition
                .cell_id
                .as_str()
                .strip_prefix("ak:cell:")
                .and_then(|rest| rest.strip_prefix(arkret_wire::CellFamilyId::FORK_RESOLUTION_V1))
                .is_some_and(|rest| rest.starts_with(':'))
    });
    let slot_guard = slot_guards
        .next()
        .ok_or_else(|| ControlMoveReject::FailedPrecondition {
            cell: event.realm_id.as_str().to_owned(),
            reason: "fork resolution must carry head_eq null for its target cell".to_owned(),
        })?;
    if slot_guards.next().is_some() {
        return Err(ControlMoveReject::FailedPrecondition {
            cell: slot_guard.cell_id.as_str().to_owned(),
            reason: "fork resolution must carry exactly one fork-resolution head_eq".to_owned(),
        });
    }
    if slot_guard.predicate.value.as_ref() != Some(&Value::Null) {
        return Err(ControlMoveReject::FailedPrecondition {
            cell: slot_guard.cell_id.as_str().to_owned(),
            reason: "fork resolution head_eq must be null; a settled subject is not re-adjudicated"
                .to_owned(),
        });
    }
    if !recovery_capability_is_active_for(
        capability.id.as_str(),
        &event.actor_id,
        pre_state,
        arkret_wire::event_kind_str::FORK_RESOLUTION,
    ) {
        return Err(ControlMoveReject::FailedPrecondition {
            cell: event.realm_id.as_str().to_owned(),
            reason: "failed_precondition".to_owned(),
        });
    }
    Ok(())
}

/// Resolve one projected write against the frozen pre-state.
///
/// Three of the registered projection grammars are deliberately not a pure
/// function of the signed Event (`event-and-patch.md` §2.4.2): they read the
/// pre-state so a producer cannot assert a prior state it never observed.
/// Resolving them here — after `seal_basis` has pinned the frontier — is what
/// makes the result identical on every receiver. It is public for exactly that
/// reason: a caller that needs the resolved writes outside `verify_control_move`
/// must reuse this, because a second implementation is a second answer.
pub fn resolve_projected_write(
    write: &ProjectedCellWrite,
    realm_id: &RealmId,
    pre_state: &BTreeMap<CellRef, ResolvedCellState>,
    registry: &dyn CellStateRegistry,
) -> Result<Vec<ProjectionEffect>, ControlMoveReject> {
    if let Some(direct) = write.as_direct() {
        return Ok(vec![direct]);
    }
    let observed = frozen_cell_value(&write.cell_id, realm_id, pre_state, registry)?;
    match &write.op {
        ProjectedOp::Direct(_) => unreachable!("direct writes are resolved before the pre-state"),
        ProjectedOp::TransitionTo { to } => {
            let mut op = LatticeOp::empty();
            op.op_type = LatticeOpType::Transition;
            op.from = Some(if pre_state.contains_key(&write.cell_id) {
                current_head(&observed)
            } else {
                let binding = registry
                    .resolve(realm_id, &write.cell_id)
                    .map_err(|error| ControlMoveReject::Registry(error.to_string()))?;
                binding
                    .domain_transition
                    .as_ref()
                    .and_then(|rule| rule.initial_state().cloned())
                    .unwrap_or(Value::Null)
            });
            op.to = Some(to.clone());
            Ok(vec![ProjectionEffect::new(write.cell_id.clone(), op)])
        }
        ProjectedOp::ApplyPatch {
            patch,
            expected_prestate,
        } => {
            // The binding is checked before the patch runs: §2.4.2 makes
            // `expected_prestate` a producer-signed claim about the very value
            // we are about to patch, so a mismatch must stop the Event rather
            // than produce a post-state derived from a pre-state the producer
            // never observed. The projector already guaranteed the source was
            // a `payload.*` field and that an absent path means "no binding"
            // — the one registered exception to fail-closed source resolution.
            if let Some(expected) = expected_prestate {
                let expected = expected.as_str().ok_or_else(|| {
                    ControlMoveReject::ProjectionFailed(format!(
                        "apply_patch expected_prestate on {} must evaluate to a canonical hash \
                         string, got {expected}",
                        write.cell_id
                    ))
                })?;
                let bytes = crate::canonical::canonical_json_bytes(&observed).map_err(|err| {
                    ControlMoveReject::ProjectionFailed(format!(
                        "frozen pre-state of {} is not canonicalizable: {err}",
                        write.cell_id
                    ))
                })?;
                // `verify_digest` reads the suite off the expected value's
                // `<suite>:<hex>` prefix, so a Realm on blake3 compares against
                // a blake3 digest without this arm naming a suite of its own.
                crate::canonical::verify_digest(&bytes, expected).map_err(|_| {
                    ControlMoveReject::PrestateBindingMismatch {
                        cell: write.cell_id.as_str().to_owned(),
                        expected: expected.to_owned(),
                        observed: crate::canonical::canonical_digest(&bytes),
                    }
                })?;
            }
            let patch: Patch = serde_json::from_value(patch.clone()).map_err(|err| {
                ControlMoveReject::ProjectionFailed(format!(
                    "apply_patch projection on {} did not derive a ak.schema.patch.v1 patch: {err}",
                    write.cell_id
                ))
            })?;
            // §4.3.1 step 3: `apply_patch` is only registered for
            // `causal_register`, and those produce a single `set`
            // whose value is the complete post-state — never the patch itself.
            let post_state = patch.apply(&observed).map_err(|err| {
                ControlMoveReject::ProjectionFailed(format!(
                    "apply_patch on {} failed against the frozen pre-state: {err}",
                    write.cell_id
                ))
            })?;
            let mut op = LatticeOp::empty();
            op.value = Some(post_state);
            // §9.3.1 makes a `causal_register` set carry the whole value it
            // supersedes. A direct `set` copies it off the Move's `head_eq`
            // precondition; here the frozen pre-state *is* that value — it is
            // what the patch was applied to — so the receiver derives it rather
            // than trusting a producer claim. A cell no write has reached yet
            // reads as `null`, which is the initial state, so such a write stays
            // a chain head.
            if registry
                .resolve(realm_id, &write.cell_id)
                .map_err(|error| ControlMoveReject::Registry(error.to_string()))?
                .model
                .kind()
                == crate::state_model::StateModelKind::CausalRegister
            {
                op.from = Some(observed);
            }
            Ok(vec![ProjectionEffect::new(write.cell_id.clone(), op)])
        }
        ProjectedOp::RemoveObserved { element_match } => Ok(observed_remove_ops(
            &write.cell_id,
            &observed,
            element_match.as_ref(),
        )),
    }
}

/// The cell's value under the frozen pre-state, failing closed on ⊥.
///
/// A pre-state-dependent projection reads this cell, so a `bottom=reject`
/// cell must stop the Control Move for the same reason a precondition on it
/// does: there is no defined value to derive the write from.
fn frozen_cell_value(
    cell: &CellRef,
    realm_id: &RealmId,
    pre_state: &BTreeMap<CellRef, ResolvedCellState>,
    registry: &dyn CellStateRegistry,
) -> Result<Value, ControlMoveReject> {
    match pre_state.get(cell) {
        None => Ok(Value::Null),
        Some(state) if state.settled_value().is_some() => {
            Ok(state.settled_value().expect("checked").clone())
        }
        Some(ResolvedCellState::Bottom(bottom)) => {
            let binding = registry
                .resolve(realm_id, cell)
                .map_err(|e| ControlMoveReject::Registry(e.to_string()))?;
            if binding.bottom_policy == Some(CausalRegisterBottomPolicy::Expose) {
                Ok(Value::Null)
            } else {
                Err(ControlMoveReject::FailedBottom {
                    cell: cell.as_str().to_owned(),
                    kind: bottom.kind,
                })
            }
        }
        Some(_) => Err(ControlMoveReject::FailedPrecondition {
            cell: cell.as_str().to_owned(),
            reason: "cell has no settled domain value".to_owned(),
        }),
    }
}

fn current_head(observed: &Value) -> Value {
    observed.clone()
}

/// Every surviving add dot on an or-set cell, narrowed by `element_match`.
///
/// `element_field` is a dotted path on the **element value**, not an Event
/// root path (§2.4.2); elements where the path is absent do not take part.
fn observed_remove_ops(
    cell: &CellRef,
    observed: &Value,
    element_match: Option<&ObservedRemoveMatch>,
) -> Vec<ProjectionEffect> {
    let Some(items) = observed.as_array() else {
        return Vec::new();
    };
    items
        .iter()
        .filter(|item| match element_match {
            None => true,
            Some(rule) => item
                .get("value")
                .and_then(|value| dotted_path(value, &rule.element_field))
                .is_some_and(|found| *found == rule.expected),
        })
        .filter_map(|item| item.get("tag_id").and_then(Value::as_str))
        .map(|tag| {
            let mut op = LatticeOp::empty();
            op.op_type = LatticeOpType::Remove;
            op.tag = Some(tag.to_owned());
            ProjectionEffect::new(cell.clone(), op)
        })
        .collect()
}

fn dotted_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .try_fold(value, |current, segment| current.get(segment))
}

const CAPABILITY_GRANT_CELL_FAMILY: &str = arkret_wire::CellFamilyId::CAPABILITY_GRANT_V1;

#[derive(Debug, Deserialize)]
struct CapabilityGrantCellValue {
    #[serde(default)]
    subject: Option<ActorId>,
    #[serde(default)]
    actions: Vec<String>,
    #[serde(default)]
    resources: Vec<Value>,
    #[serde(default)]
    revoked_at: Option<Value>,
    #[serde(default)]
    revoked_by: Option<Value>,
}

impl CapabilityGrantCellValue {
    fn subject(&self) -> Option<&ActorId> {
        self.subject.as_ref()
    }

    fn has_resources(&self) -> bool {
        !self.resources.is_empty()
    }

    fn is_revoked(&self) -> bool {
        self.revoked_at.is_some() || self.revoked_by.is_some()
    }
}

fn verify_capability_refs(
    event: &Event,
    pre_state: &BTreeMap<CellRef, ResolvedCellState>,
) -> Result<(), ControlMoveReject> {
    for reference in event
        .refs
        .iter()
        .filter(|reference| reference.role == EVENT_REF_ROLE_AUTHORIZED_BY)
    {
        let grant = find_capability_grant(reference.id.as_str(), pre_state)?;
        if grant.is_revoked() {
            return Err(ControlMoveReject::CapabilityDenied(format!(
                "authorized_by grant '{}' is revoked",
                reference.id
            )));
        }
        let subject = grant.subject().ok_or_else(|| {
            ControlMoveReject::CapabilityDenied(format!(
                "authorized_by grant '{}' has no subject",
                reference.id
            ))
        })?;
        if subject != &event.actor_id {
            return Err(ControlMoveReject::CapabilityDenied(format!(
                "authorized_by grant '{}' subject '{}' does not cover actor '{}'",
                reference.id, subject, event.actor_id
            )));
        }
        if grant.actions.is_empty() {
            return Err(ControlMoveReject::CapabilityDenied(format!(
                "authorized_by grant '{}' has no actions",
                reference.id
            )));
        }
        if !grant.has_resources() {
            return Err(ControlMoveReject::CapabilityDenied(format!(
                "authorized_by grant '{}' has no resources",
                reference.id
            )));
        }
    }
    Ok(())
}

fn capability_grant_cell(grant_id: &str) -> Result<CellRef, ControlMoveReject> {
    let grant_id = arkret_wire::GrantId::new(grant_id.to_owned())
        .map_err(|error| ControlMoveReject::CapabilityDenied(error.to_string()))?;
    CellRef::new(arkret_wire::subject_cell(
        CAPABILITY_GRANT_CELL_FAMILY,
        grant_id.as_str(),
    ))
    .map_err(|error| ControlMoveReject::CapabilityDenied(error.to_string()))
}

fn find_capability_grant(
    grant_id: &str,
    pre_state: &BTreeMap<CellRef, ResolvedCellState>,
) -> Result<CapabilityGrantCellValue, ControlMoveReject> {
    let cell = capability_grant_cell(grant_id)?;
    let unavailable = || {
        ControlMoveReject::CapabilityDenied(format!(
            "authorized_by grant '{grant_id}' is not active in its exact security Cell"
        ))
    };
    let Some(ResolvedCellState::Sequenced(state)) = pre_state.get(&cell) else {
        return Err(unavailable());
    };
    let entries = state.value.as_array().ok_or_else(unavailable)?;
    if entries.len() != 1 {
        return Err(unavailable());
    }
    let grant = entries[0]
        .get("value")
        .and_then(|body| body.get("grant"))
        .ok_or_else(unavailable)?;
    serde_json::from_value(grant.clone()).map_err(|error| {
        ControlMoveReject::CapabilityDenied(format!(
            "authorized_by grant '{grant_id}' has invalid typed value: {error}"
        ))
    })
}

fn recovery_capability_is_active_for(
    grant_id: &str,
    actor_id: &ActorId,
    pre_state: &BTreeMap<CellRef, ResolvedCellState>,
    action: &str,
) -> bool {
    find_capability_grant(grant_id, pre_state).is_ok_and(|grant| {
        !grant.is_revoked()
            && grant.subject() == Some(actor_id)
            && grant.actions.iter().any(|candidate| candidate == action)
            && grant.has_resources()
    })
}

fn evaluate_predicate(
    cell: &CellRef,
    pred: &Predicate,
    cell_state: &ResolvedCellState,
) -> Result<(), ControlMoveReject> {
    let observed = cell_state.settled_value().unwrap_or(&Value::Null);
    match pred.op {
        PredicateOp::HeadEq => {
            let expected = pred.value.as_ref().ok_or_else(|| {
                ControlMoveReject::SchemaViolation("predicate head_eq requires `value`".to_owned())
            })?;
            if observed == expected {
                return Ok(());
            }
            Err(ControlMoveReject::FailedPrecondition {
                cell: cell.as_str().to_owned(),
                reason: format!("head_eq: observed={observed}, expected={expected}"),
            })
        }
        PredicateOp::HeadIn => {
            let values = pred.values.as_ref().ok_or_else(|| {
                ControlMoveReject::SchemaViolation("predicate head_in requires `values`".to_owned())
            })?;
            if values.iter().any(|v| v == observed) {
                Ok(())
            } else {
                Err(ControlMoveReject::FailedPrecondition {
                    cell: cell.as_str().to_owned(),
                    reason: format!("head_in: observed={observed}, expected one of {values:?}"),
                })
            }
        }
        PredicateOp::Contains => {
            let needles: Vec<&Value> = if let Some(v) = pred.value.as_ref() {
                vec![v]
            } else if let Some(vs) = pred.values.as_ref() {
                vs.iter().collect()
            } else {
                return Err(ControlMoveReject::SchemaViolation(
                    "predicate contains requires `value` or `values`".to_owned(),
                ));
            };
            let observed_arr =
                observed
                    .as_array()
                    .ok_or_else(|| ControlMoveReject::FailedPrecondition {
                        cell: cell.as_str().to_owned(),
                        reason: format!("contains: observed value is not an array: {observed}"),
                    })?;
            for needle in needles {
                if !observed_arr.iter().any(|item| {
                    item == needle
                        || item.get("tag_id") == Some(needle)
                        || item.get("value") == Some(needle)
                }) {
                    return Err(ControlMoveReject::FailedPrecondition {
                        cell: cell.as_str().to_owned(),
                        reason: format!("contains: missing element {needle}"),
                    });
                }
            }
            Ok(())
        }
        PredicateOp::Satisfies => {
            // `satisfies` dispatches to a schema-registered deterministic
            // predicate identified by `predicate_id`. This SDK verifier ships
            // with no predicate registry, so per spec
            // `event-auth-state-resolution.md` §5.1 (missing proof MUST fail
            // closed; never trust unverified input) it MUST refuse to evaluate the
            // precondition rather than treat it as satisfied (SDK-SEC-01:
            // previously a fail-open no-op). A verifier that wires up a
            // predicate registry would extend this branch to evaluate against
            // the registered predicate; until then `satisfies` is fail-closed.
            let id = pred.predicate_id.as_deref().ok_or_else(|| {
                ControlMoveReject::SchemaViolation(
                    "predicate satisfies requires `predicate_id`".to_owned(),
                )
            })?;
            Err(ControlMoveReject::SchemaViolation(format!(
                "predicate satisfies('{id}') cannot be evaluated: no predicate \
                 registry is configured (fail-closed per event-auth §5.1)"
            )))
        }
    }
}
