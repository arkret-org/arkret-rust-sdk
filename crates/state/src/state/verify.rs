//! Control Move verifier pipeline.
//!
//! A Control Move is an [`Event`] carrying `seal_basis`
//! (`event-auth-state-resolution.md` §5); there is no standalone Move object
//! and no producer-authored effect array. §5.1 fixes the step order:
//!
//! | step | check | wire error_code on fail |
//! | --- | --- | --- |
//! | 1 structural | canonical bytes, envelope shape, `realm_id` | `schema_violation` |
//! | 2 proofs | `proofs[].event_digest` binds the recomputed digest; signature verify | `invalid_signature` |
//! | 3 critical refs | each `refs[role=authorized_by]` resolves to a covering grant | `capability_denied` |
//! | 4 preconditions | every `(cell, predicate)` evaluates true on the frozen `pre_state` | `state_mismatch` |
//! | 5 derived writes | every projected write passes the cell's `validate_op` | `schema_violation` |
//!
//! §5.1 steps 2-4 (`seal_basis.leaves[]` inside the receiving Seal's
//! predecessor closure, and the two declared roots against that leaf view)
//! need the Seal DAG, so they live in [`crate::state::seal::verify_seal_basis`]
//! and `apply_seal` runs them just before this function.
//!
//! Two dependencies are injected rather than imported. Signature verification
//! lives in `arkret-signatures`, and — the load-bearing one — the projection
//! evaluator that turns `kind + payload` into cell writes lives in
//! `arkret-schema`, which this crate is forbidden to depend on
//! (`tools/check-layering.py`). Both arrive as closures so the pipeline
//! orchestration stays pure and this crate keeps no registry of its own.

use std::collections::BTreeMap;

use arkret_wire::event_envelope::{EVENT_REF_ROLE_AUTHORIZED_BY, Event, EventSubmitContext};
use arkret_wire::patch::Patch;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use super::store::{BottomMode, CellRegistry, StoreError};
use crate::lattice::CellState;
use crate::{
    BottomKind, CellRef, Hash, LatticeOp, LatticeOpType, ObservedRemoveMatch, Predicate,
    PredicateOp, ProjectedCellWrite, ProjectedOp, ProjectionEffect, RealmId,
};

#[derive(Debug, Error)]
pub enum ControlMoveReject {
    #[error("schema violation: {0}")]
    SchemaViolation(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

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

    #[error("registry error: {0}")]
    Registry(String),
}

impl From<StoreError> for ControlMoveReject {
    fn from(e: StoreError) -> Self {
        ControlMoveReject::Registry(e.to_string())
    }
}

/// Map a [`ControlMoveReject`] variant to its wire-level `error_code`
/// constant (from `arkret-spec` `error-code-registry.json`).
pub fn reject_to_error_code(r: &ControlMoveReject) -> &'static str {
    match r {
        ControlMoveReject::SchemaViolation(_) => crate::ErrorCode::SCHEMA_VIOLATION,
        ControlMoveReject::InvalidSignature(_) => crate::ErrorCode::INVALID_SIGNATURE,
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
        ControlMoveReject::Registry(_) => crate::ErrorCode::INTERNAL_ERROR,
    }
}

/// Verify a Control Move against a frozen pre-state map and return the
/// receiver-derived writes.
///
/// `pre_state` MUST be the joined governance state of the receiving Seal's
/// predecessor view — never a baseline advanced by same-batch writes
/// (§6.3.1 frozen-predecessor rule). Cells absent from the map are treated
/// as `CellState::Value(Value::Null)`.
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
    pre_state: &BTreeMap<CellRef, CellState>,
    registry: &dyn CellRegistry,
    verify_proofs: VerifyProofs,
    project_writes: ProjectWrites,
) -> Result<Vec<ProjectionEffect>, ControlMoveReject>
where
    VerifyProofs: Fn(&Event) -> Result<(), String>,
    ProjectWrites: Fn(&Event) -> Result<Vec<ProjectedCellWrite>, String>,
{
    verify_control_move_in_context(
        event,
        realm_id,
        pre_state,
        registry,
        verify_proofs,
        project_writes,
        EventSubmitContext::Standard,
    )
}

/// Verify a Control Move under an explicit CBA envelope context.
///
/// `AnchorUnit` is only valid after the caller has validated one of the
/// protocol's closed bootstrap/re-anchor units. It permits the unit's
/// basis-less Events while preserving the remaining proof, capability,
/// precondition, and reducer checks.
pub fn verify_control_move_in_context<VerifyProofs, ProjectWrites>(
    event: &Event,
    realm_id: &RealmId,
    pre_state: &BTreeMap<CellRef, CellState>,
    registry: &dyn CellRegistry,
    verify_proofs: VerifyProofs,
    project_writes: ProjectWrites,
    context: EventSubmitContext,
) -> Result<Vec<ProjectionEffect>, ControlMoveReject>
where
    VerifyProofs: Fn(&Event) -> Result<(), String>,
    ProjectWrites: Fn(&Event) -> Result<Vec<ProjectedCellWrite>, String>,
{
    // Step 1: structural. `validate_for_submit_structural` also enforces the
    // CBA envelope shape, so a DataEvent (`seal_ref` + `auth_context`) or an
    // Event with neither basis cannot reach the control-plane reducer here.
    event
        .validate_for_submit_structural_in_context(context)
        .map_err(|e| ControlMoveReject::SchemaViolation(e.to_string()))?;
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

    // Step 2: proofs. `validate_proof_bindings` recomputes the canonical
    // digest and rejects any proof that binds a different one, so a producer
    // cannot present a signature over bytes other than the ones we reduce.
    event
        .validate_proof_bindings()
        .map_err(|e| ControlMoveReject::InvalidSignature(e.to_string()))?;
    verify_proofs(event).map_err(ControlMoveReject::InvalidSignature)?;

    // Step 3: critical refs.
    if event.actor_id.as_str().is_empty() {
        return Err(ControlMoveReject::CapabilityDenied(
            "actor DID is empty".to_owned(),
        ));
    }
    verify_capability_refs(event, pre_state)?;

    // Step 4: preconditions
    for pre in &event.preconditions {
        let cell_state = pre_state
            .get(&pre.cell)
            .cloned()
            .unwrap_or(CellState::Value(Value::Null));
        // bottom=reject cells fail closed.
        if let CellState::Bottom(b) = &cell_state {
            let binding = registry
                .resolve(realm_id, &pre.cell)
                .map_err(|e| ControlMoveReject::Registry(e.to_string()))?;
            if binding.bottom_mode != BottomMode::Expose {
                return Err(ControlMoveReject::FailedBottom {
                    cell: pre.cell.as_str().to_owned(),
                    kind: b.kind,
                });
            }
        }
        evaluate_predicate(&pre.cell, &pre.predicate, &cell_state)?;
    }

    // Step 5: derive every write from kind + payload, then validate its shape
    // against the target cell's lattice.
    let projected = project_writes(event).map_err(ControlMoveReject::ProjectionFailed)?;
    if projected
        .iter()
        .any(|write| matches!(write.op, ProjectedOp::Reset { .. }))
    {
        verify_recovery_refs(event)?;
    }
    let mut effects = Vec::with_capacity(projected.len());
    for write in &projected {
        for effect in resolve_projected_write(write, realm_id, pre_state, registry)? {
            let binding = registry
                .resolve(realm_id, &effect.cell)
                .map_err(|e| ControlMoveReject::Registry(e.to_string()))?;
            binding.lattice.validate_op(&effect.op).map_err(|e| {
                ControlMoveReject::SchemaViolation(format!(
                    "derived write on {} invalid: {e}",
                    effect.cell
                ))
            })?;
            effects.push(effect);
        }
    }
    Ok(effects)
}

/// `event-auth-state-resolution.md` §9.5 condition 1 — the recovery Move MUST
/// carry its authorization and its pre-conflict anchor as critical `refs[]`.
///
/// These are refs, not payload fields, so nothing in the payload schema can
/// enforce them; without this check a Move that merely names the right kind
/// resets a cell with no authorization and no anchor at all. Conditions 2–5
/// (witness inclusion proof, pre-conflict causality, capability sealed under
/// the witness, freshness / revoke lag) are frontier-dependent and belong to
/// the Seal-accepting caller, which is the only layer holding the Seal DAG.
fn verify_recovery_refs(event: &Event) -> Result<(), ControlMoveReject> {
    let critical_ref = |role: &str| {
        event
            .refs
            .iter()
            .any(|reference| reference.role == role && reference.critical)
    };
    if !critical_ref("recovery_capability") {
        return Err(ControlMoveReject::FailedPrecondition {
            cell: event
                .payload
                .get("target_cell")
                .and_then(Value::as_str)
                .unwrap_or(event.realm_id.as_str())
                .to_owned(),
            reason: arkret_wire::ReasonCode::RECOVERY_CAPABILITY_NOT_SEALED.to_owned(),
        });
    }
    if !critical_ref("state_witness") {
        return Err(ControlMoveReject::FailedPrecondition {
            cell: event.realm_id.as_str().to_owned(),
            reason: "recovery_witness_missing".to_owned(),
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
    pre_state: &BTreeMap<CellRef, CellState>,
    registry: &dyn CellRegistry,
) -> Result<Vec<ProjectionEffect>, ControlMoveReject> {
    if let Some(direct) = write.as_direct() {
        return Ok(vec![direct]);
    }
    // `event-auth-state-resolution.md` §9.5. A reset replaces the cell instead
    // of joining into it, so it is resolved before `frozen_cell_value` — that
    // helper rejects a `bottom=reject` cell in `⊥`, which is the only state a
    // reset is allowed to see. The target MUST already be in `⊥`: permitting it
    // on a live cell would turn recovery into a general overwrite channel that
    // bypasses every lattice and every precondition.
    if let ProjectedOp::Reset { value } = &write.op {
        match pre_state.get(&write.cell) {
            Some(CellState::Bottom(_)) => {}
            _ => {
                return Err(ControlMoveReject::FailedPrecondition {
                    cell: write.cell.as_str().to_owned(),
                    reason: "recovery_target_not_in_bottom".to_owned(),
                });
            }
        }
        let mut op = LatticeOp::empty();
        op.op_type = LatticeOpType::Set;
        op.value = Some(value.clone());
        // Marked as a reset, not merely projected as a `set`. The op vocabulary
        // is spec-registered and has no `reset` member, so an unmarked op is
        // indistinguishable from an ordinary write and would be *joined with*
        // the concurrent branches that put the cell in `⊥` — leaving it in `⊥`
        // and quietly removing the only escape §9.5 defines.
        return Ok(vec![ProjectionEffect::reset(write.cell.clone(), op)]);
    }
    let observed = frozen_cell_value(&write.cell, realm_id, pre_state, registry)?;
    match &write.op {
        // Both handled above, before the pre-state is read: a direct write does
        // not need it, and a reset is the one write allowed to see a cell in ⊥.
        ProjectedOp::Direct(_) => unreachable!("direct writes are resolved before the pre-state"),
        ProjectedOp::Reset { .. } => unreachable!("a reset is resolved before the pre-state"),
        ProjectedOp::TransitionTo { to } => {
            let mut op = LatticeOp::empty();
            op.op_type = LatticeOpType::Transition;
            // A cell no write has reached yet reads as its registered initial
            // state, not as null. The fsm join starts there, so deriving null
            // here would make every first transition join to Bottom.
            op.from = Some(if pre_state.contains_key(&write.cell) {
                current_head(&observed)
            } else {
                let binding = registry
                    .resolve(realm_id, &write.cell)
                    .map_err(|error| ControlMoveReject::Registry(error.to_string()))?;
                binding.lattice.initial_state().unwrap_or(Value::Null)
            });
            op.to = Some(to.clone());
            Ok(vec![ProjectionEffect::join(write.cell.clone(), op)])
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
                        write.cell
                    ))
                })?;
                let bytes = crate::canonical::canonical_json_bytes(&observed).map_err(|err| {
                    ControlMoveReject::ProjectionFailed(format!(
                        "frozen pre-state of {} is not canonicalizable: {err}",
                        write.cell
                    ))
                })?;
                // `verify_digest` reads the suite off the expected value's
                // `<suite>:<hex>` prefix, so a Realm on blake3 compares against
                // a blake3 digest without this arm naming a suite of its own.
                crate::canonical::verify_digest(&bytes, expected).map_err(|_| {
                    ControlMoveReject::PrestateBindingMismatch {
                        cell: write.cell.as_str().to_owned(),
                        expected: expected.to_owned(),
                        observed: crate::canonical::canonical_digest(&bytes),
                    }
                })?;
            }
            let patch: Patch = serde_json::from_value(patch.clone()).map_err(|err| {
                ControlMoveReject::ProjectionFailed(format!(
                    "apply_patch projection on {} did not derive a ak.schema.patch.v1 patch: {err}",
                    write.cell
                ))
            })?;
            // §4.3.1 step 3: `apply_patch` is only registered for
            // `mv_register` / `cas_register`, and those produce a single `set`
            // whose value is the complete post-state — never the patch itself.
            let post_state = patch.apply(&observed).map_err(|err| {
                ControlMoveReject::ProjectionFailed(format!(
                    "apply_patch on {} failed against the frozen pre-state: {err}",
                    write.cell
                ))
            })?;
            let mut op = LatticeOp::empty();
            op.value = Some(post_state);
            // §9.3.1 makes a `cas_register` set carry the whole value it
            // supersedes. A direct `set` copies it off the Move's `head_eq`
            // precondition; here the frozen pre-state *is* that value — it is
            // what the patch was applied to — so the receiver derives it rather
            // than trusting a producer claim. A cell no write has reached yet
            // reads as `null`, which is the initial state, so such a write stays
            // a chain head.
            if registry
                .resolve(realm_id, &write.cell)
                .map_err(|error| ControlMoveReject::Registry(error.to_string()))?
                .lattice
                .kind()
                == crate::lattice::LatticeKind::CasRegister
            {
                op.from = Some(observed);
            }
            Ok(vec![ProjectionEffect::join(write.cell.clone(), op)])
        }
        ProjectedOp::RemoveObserved { element_match } => Ok(observed_remove_ops(
            &write.cell,
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
    pre_state: &BTreeMap<CellRef, CellState>,
    registry: &dyn CellRegistry,
) -> Result<Value, ControlMoveReject> {
    match pre_state.get(cell) {
        None => Ok(Value::Null),
        Some(CellState::Value(value)) => Ok(value.clone()),
        Some(CellState::Bottom(bottom)) => {
            let binding = registry
                .resolve(realm_id, cell)
                .map_err(|e| ControlMoveReject::Registry(e.to_string()))?;
            if binding.bottom_mode == BottomMode::Expose {
                Ok(Value::Null)
            } else {
                Err(ControlMoveReject::FailedBottom {
                    cell: cell.as_str().to_owned(),
                    kind: bottom.kind,
                })
            }
        }
    }
}

/// The current head of a cell value.
///
/// Cells materialize either as the bare head (an `fsm` state string) or as a
/// composite object carrying it under `head`; `evaluate_predicate` accepts
/// both, and `transition_to`'s derived `from` must agree with what a
/// `head_eq` precondition on the same cell would have compared.
fn current_head(observed: &Value) -> Value {
    observed
        .get("head")
        .cloned()
        .unwrap_or_else(|| observed.clone())
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
        .filter_map(|item| item.get("tag").and_then(Value::as_str))
        .map(|tag| {
            let mut op = LatticeOp::empty();
            op.op_type = LatticeOpType::Remove;
            op.tag = Some(tag.to_owned());
            ProjectionEffect::join(cell.clone(), op)
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
    id: Option<String>,
    #[serde(default)]
    grant_id: Option<String>,
    #[serde(default)]
    capability_id: Option<String>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    actions: Vec<String>,
    #[serde(default)]
    resources: Vec<Value>,
    #[serde(default)]
    resource_selectors: Vec<Value>,
    #[serde(default)]
    revoked_at: Option<Value>,
    #[serde(default)]
    revoked_by: Option<Value>,
}

impl CapabilityGrantCellValue {
    fn grant_ids(&self) -> impl Iterator<Item = &str> {
        [
            self.id.as_deref(),
            self.grant_id.as_deref(),
            self.capability_id.as_deref(),
        ]
        .into_iter()
        .flatten()
    }

    fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    fn has_resources(&self) -> bool {
        !self.resources.is_empty() || !self.resource_selectors.is_empty()
    }

    fn is_revoked(&self) -> bool {
        self.revoked_at.is_some() || self.revoked_by.is_some()
    }
}

fn verify_capability_refs(
    event: &Event,
    pre_state: &BTreeMap<CellRef, CellState>,
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
        if subject != event.actor_id.as_str() {
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

fn find_capability_grant(
    grant_id: &str,
    pre_state: &BTreeMap<CellRef, CellState>,
) -> Result<CapabilityGrantCellValue, ControlMoveReject> {
    let mut saw_bottom = false;
    for (cell, state) in pre_state {
        if !is_capability_grant_cell(cell) {
            continue;
        }
        match state {
            CellState::Bottom(_) => {
                saw_bottom = true;
            }
            CellState::Value(value) => {
                if let Some(grant) = grant_from_cell_value(grant_id, value)? {
                    return Ok(grant);
                }
            }
        }
    }

    if saw_bottom {
        return Err(ControlMoveReject::CapabilityDenied(format!(
            "authorized_by grant '{grant_id}' is unavailable because a capability grant cell is bottom"
        )));
    }
    Err(ControlMoveReject::CapabilityDenied(format!(
        "authorized_by grant '{grant_id}' not found in pre-state capability grant cells"
    )))
}

pub(super) fn recovery_capability_is_active(
    grant_id: &str,
    actor_id: &str,
    pre_state: &BTreeMap<CellRef, CellState>,
) -> bool {
    find_capability_grant(grant_id, pre_state).is_ok_and(|grant| {
        !grant.is_revoked()
            && grant.subject() == Some(actor_id)
            && grant
                .actions
                .iter()
                .any(|action| action == arkret_wire::EventKind::STATE_CONFLICT_RECOVERY)
            && grant.has_resources()
    })
}

fn is_capability_grant_cell(cell: &CellRef) -> bool {
    crate::CellId::parse(cell.as_str())
        .map(|cell_id| cell_id.component() == CAPABILITY_GRANT_CELL_FAMILY)
        .unwrap_or(false)
}

fn grant_from_cell_value(
    grant_id: &str,
    value: &Value,
) -> Result<Option<CapabilityGrantCellValue>, ControlMoveReject> {
    let Some(items) = value.as_array() else {
        return Ok(None);
    };
    for item in items {
        let tag_matches = item.get("tag").and_then(Value::as_str) == Some(grant_id);
        let Some(raw_grant) = item
            .get("value")
            .or(if tag_matches { Some(item) } else { None })
        else {
            continue;
        };
        let grant: CapabilityGrantCellValue =
            serde_json::from_value(raw_grant.clone()).map_err(|err| {
                ControlMoveReject::CapabilityDenied(format!(
                    "authorized_by grant '{grant_id}' has invalid typed value: {err}"
                ))
            })?;
        if tag_matches || grant.grant_ids().any(|candidate| candidate == grant_id) {
            return Ok(Some(grant));
        }
    }
    Ok(None)
}

fn evaluate_predicate(
    cell: &CellRef,
    pred: &Predicate,
    cell_state: &CellState,
) -> Result<(), ControlMoveReject> {
    let observed: &Value = match cell_state {
        CellState::Value(v) => v,
        CellState::Bottom(_) => &Value::Null, // bottom already handled by caller
    };
    match pred.op {
        PredicateOp::HeadEq => {
            let expected = pred.value.as_ref().ok_or_else(|| {
                ControlMoveReject::SchemaViolation("predicate head_eq requires `value`".to_owned())
            })?;
            // For composite cell values like `{"head": ..., "value": ...}` (per spec),
            // the precondition compares against either the whole value or a `head`
            // sub-field. We accept both forms: equal to the value, OR equal to the
            // value at `.head` if present.
            if observed == expected {
                return Ok(());
            }
            if let Some(head) = observed.get("head")
                && head == expected
            {
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
            let observed_head = observed.get("head").unwrap_or(observed);
            if values.iter().any(|v| v == observed_head) {
                Ok(())
            } else {
                Err(ControlMoveReject::FailedPrecondition {
                    cell: cell.as_str().to_owned(),
                    reason: format!(
                        "head_in: observed={observed_head}, expected one of {values:?}"
                    ),
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
                        || item.get("tag") == Some(needle)
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

/// Convenience: collect a list of rejections keyed by `event_digest`.
pub type ControlMoveRejectMap = BTreeMap<Hash, ControlMoveReject>;

#[cfg(test)]
mod tests {
    use arkret_wire::event_envelope::{EventRef, ScopeRef};
    use arkret_wire::{DidUrl, Proof};
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;
    use crate::lattice::{CellState, SealedOp};
    use crate::state::store::memory::MemoryCellRegistry;
    use crate::{
        CellRef, Did, EventId, EventRequirements, Hash, Hlc, Precondition, PredicateOp, RealmId,
        SealBasis, SealId,
    };

    fn realm() -> RealmId {
        RealmId::new("ak:realm:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
    }

    fn cell_member() -> CellRef {
        CellRef::new("ak:cell:ak.component.member.state.v1:did.web.alice.example".to_owned())
            .unwrap()
    }

    fn cell_capability_grant() -> CellRef {
        CellRef::new(
            "ak:cell:ak.component.capability.grant.v1:ak.grant.01js0gr0000000000000000000"
                .to_owned(),
        )
        .unwrap()
    }

    fn actor() -> Did {
        Did::new("did:webvh:z6mkfixture:admin.example".to_owned()).unwrap()
    }

    fn control_move(preconditions: Vec<Precondition>, refs: Vec<EventRef>) -> Event {
        let mut event = Event {
            event_id: EventId::new("ak:event:0196419b-0000-7000-8000-000000000001").unwrap(),
            kind: "ak.member.state".into(),
            realm_id: realm(),
            scope_ref: ScopeRef::Realm { realm_id: realm() },
            actor_id: actor(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            actor_seq: 1,
            created_at: Utc.with_ymd_and_hms(2026, 5, 8, 0, 0, 0).unwrap(),
            hlc: Some(Hlc::new("0189c4d2af00-0000-aabbccdd".to_owned()).unwrap()),
            prev_refs: Vec::new(),
            refs,
            causal_refs: Vec::new(),
            preconditions,
            seal_ref: None,
            auth_context: None,
            seal_basis: Some(SealBasis {
                leaves: vec![SealId::new(format!("ak:seal:sha256:{}", "aa".repeat(32))).unwrap()],
            }),
            payload: BTreeMap::from([("state".to_owned(), json!("join"))]),
            redacts: None,
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
            requirements: EventRequirements::default(),
        };
        event.proofs.push(Proof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:admin.example#k1").unwrap(),
            event_digest: Hash::new(event.event_digest().unwrap()).unwrap(),
            created_at: event.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "AAAA.BBBB.CCCC".to_owned(),
        });
        event
    }

    fn authorized_ref(id: &str) -> EventRef {
        EventRef::new(id, EVENT_REF_ROLE_AUTHORIZED_BY)
    }

    fn grant_cell_state(grant_id: &str, subject: &str) -> CellState {
        CellState::Value(json!([
            {
                "tag": grant_id,
                "value": {
                    "id": grant_id,
                    "issuer": "did:webvh:z6mkfixture:owner.example",
                    "subject": subject,
                    "actions": ["ak.member.state"],
                    "resources": [{"kind": "Realm", "realm_id": realm().as_str()}]
                }
            }
        ]))
    }

    fn ok_proofs(_: &Event) -> Result<(), String> {
        Ok(())
    }

    fn fail_proofs(_: &Event) -> Result<(), String> {
        Err("dummy signature failure".to_owned())
    }

    /// Stand-in for the injected `arkret-schema` evaluator: it returns a fixed
    /// projection so these tests exercise the reducer pipeline, not the
    /// registry. The real projector is wired in by the caller.
    fn project(
        writes: Vec<ProjectedCellWrite>,
    ) -> impl Fn(&Event) -> Result<Vec<ProjectedCellWrite>, String> {
        move |_| Ok(writes.clone())
    }

    fn transition_write(from: Value, to: Value) -> ProjectedCellWrite {
        let mut op = LatticeOp::empty();
        op.op_type = LatticeOpType::Transition;
        op.from = Some(from);
        op.to = Some(to);
        ProjectedCellWrite {
            cell: cell_member(),
            op: ProjectedOp::Direct(op),
        }
    }

    #[test]
    fn a_transition_onto_an_absent_fsm_cell_derives_the_registered_initial_state() {
        // The reducer derives `from` from the frozen pre-state, and the fsm
        // join starts at the cell's registered `initial_state`. If an absent
        // cell derived `from = null` the two would never agree and the FIRST
        // transition onto any fsm cell with a declared initial state would
        // join to Bottom, so no member could ever leave that state.
        let event = control_move(vec![], vec![]);
        let effects = verify_control_move(
            &event,
            &realm(),
            &BTreeMap::new(),
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![ProjectedCellWrite {
                cell: cell_member(),
                op: ProjectedOp::TransitionTo { to: json!("join") },
            }]),
        )
        .expect("a first transition must be derivable");

        assert_eq!(effects.len(), 1);
        // The registry's declared initial state, not null.
        assert_eq!(effects[0].op.from, Some(json!("invited")));
        assert_eq!(effects[0].op.to, Some(json!("join")));
    }

    #[test]
    fn structural_pass_with_valid_control_move() {
        let pre = Precondition {
            cell: cell_member(),
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(json!("invited")),
                values: None,
                predicate_id: None,
            },
        };
        let event = control_move(vec![pre], vec![]);
        let mut pre_state = BTreeMap::new();
        pre_state.insert(cell_member(), CellState::Value(json!("invited")));
        let effects = verify_control_move(
            &event,
            &realm(),
            &pre_state,
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![transition_write(json!("invited"), json!("join"))]),
        )
        .unwrap();
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].cell, cell_member());
    }

    #[test]
    fn signature_failure_rejected() {
        let event = control_move(vec![], vec![]);
        let err = verify_control_move(
            &event,
            &realm(),
            &BTreeMap::new(),
            &MemoryCellRegistry::new(),
            fail_proofs,
            project(vec![transition_write(json!("invited"), json!("join"))]),
        )
        .unwrap_err();
        assert!(matches!(err, ControlMoveReject::InvalidSignature(_)));
    }

    #[test]
    fn realm_mismatch_rejected() {
        let event = control_move(vec![], vec![]);
        let other =
            RealmId::new("ak:realm:0196419b-0000-7000-8000-00000000ffff".to_owned()).unwrap();
        let err = verify_control_move(
            &event,
            &other,
            &BTreeMap::new(),
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![]),
        )
        .unwrap_err();
        assert!(matches!(err, ControlMoveReject::SchemaViolation(_)));
    }

    #[test]
    fn authorized_by_ref_resolves_capability_grant_cell() {
        let grant_id = "ak:grant:0196419b-0000-7000-8000-000000000111";
        let event = control_move(vec![], vec![authorized_ref(grant_id)]);
        let mut pre_state = BTreeMap::new();
        pre_state.insert(
            cell_capability_grant(),
            grant_cell_state(grant_id, event.actor_id.as_str()),
        );

        verify_control_move(
            &event,
            &realm(),
            &pre_state,
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![transition_write(json!("invited"), json!("join"))]),
        )
        .unwrap();
    }

    #[test]
    fn missing_authorized_by_grant_rejects() {
        let grant_id = "ak:grant:0196419b-0000-7000-8000-000000000111";
        let event = control_move(vec![], vec![authorized_ref(grant_id)]);
        let err = verify_control_move(
            &event,
            &realm(),
            &BTreeMap::new(),
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![transition_write(json!("invited"), json!("join"))]),
        )
        .unwrap_err();
        assert!(matches!(err, ControlMoveReject::CapabilityDenied(_)));
        assert_eq!(
            reject_to_error_code(&err),
            crate::ErrorCode::CAPABILITY_DENIED
        );
    }

    #[test]
    fn authorized_by_subject_mismatch_rejects() {
        let grant_id = "ak:grant:0196419b-0000-7000-8000-000000000111";
        let event = control_move(vec![], vec![authorized_ref(grant_id)]);
        let mut pre_state = BTreeMap::new();
        pre_state.insert(
            cell_capability_grant(),
            grant_cell_state(grant_id, "did:webvh:z6mkfixture:bob.example"),
        );

        let err = verify_control_move(
            &event,
            &realm(),
            &pre_state,
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![transition_write(json!("invited"), json!("join"))]),
        )
        .unwrap_err();
        assert!(matches!(err, ControlMoveReject::CapabilityDenied(_)));
    }

    #[test]
    fn precondition_head_eq_mismatch_rejects() {
        let pre = Precondition {
            cell: cell_member(),
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(json!("join")), // expects join
                values: None,
                predicate_id: None,
            },
        };
        let event = control_move(vec![pre], vec![]);
        let mut pre_state = BTreeMap::new();
        // Observed is invited, not join.
        pre_state.insert(cell_member(), CellState::Value(json!("invited")));
        let err = verify_control_move(
            &event,
            &realm(),
            &pre_state,
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![transition_write(json!("join"), json!("ban"))]),
        )
        .unwrap_err();
        assert!(matches!(err, ControlMoveReject::FailedPrecondition { .. }));
    }

    #[test]
    fn bottom_reject_cell_fails_closed() {
        let bottom = crate::Bottom::new(BottomKind::Conflict, vec![cell_member()]);
        let mut pre_state = BTreeMap::new();
        pre_state.insert(cell_member(), CellState::Bottom(bottom));

        let pre = Precondition {
            cell: cell_member(),
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(json!("anything")),
                values: None,
                predicate_id: None,
            },
        };
        let event = control_move(vec![pre], vec![]);
        let err = verify_control_move(
            &event,
            &realm(),
            &pre_state,
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![transition_write(json!("invited"), json!("join"))]),
        )
        .unwrap_err();
        assert!(matches!(err, ControlMoveReject::FailedBottom { .. }));
    }

    #[test]
    fn bottom_inert_cell_fails_closed_when_used_as_a_precondition() {
        let bottom = crate::Bottom::new(BottomKind::Conflict, vec![cell_member()]);
        let mut pre_state = BTreeMap::new();
        pre_state.insert(cell_member(), CellState::Bottom(bottom));

        let pre = Precondition {
            cell: cell_member(),
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(json!("anything")),
                values: None,
                predicate_id: None,
            },
        };
        let event = control_move(vec![pre], vec![]);
        let mut registry = MemoryCellRegistry::new();
        registry.register_fsm(
            arkret_wire::CellFamilyId::MEMBER_STATE_V1,
            Some(json!("invited")),
            vec![(json!("invited"), json!("join"))],
            BottomMode::Inert,
        );

        let err = verify_control_move(
            &event,
            &realm(),
            &pre_state,
            &registry,
            ok_proofs,
            project(vec![transition_write(json!("invited"), json!("join"))]),
        )
        .unwrap_err();
        assert!(matches!(err, ControlMoveReject::FailedBottom { .. }));
    }

    #[test]
    fn derived_write_shape_failure_rejects() {
        // FSM cell with a disallowed transition: invited -> ban is not in
        // MemoryCellRegistry's declared table.
        let event = control_move(vec![], vec![]);
        let err = verify_control_move(
            &event,
            &realm(),
            &BTreeMap::new(),
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![transition_write(json!("invited"), json!("ban"))]),
        )
        .unwrap_err();
        assert!(matches!(err, ControlMoveReject::SchemaViolation(_)));
    }

    #[test]
    fn transition_to_reads_from_off_the_frozen_pre_state() {
        // The Event never names `from`. A producer that had asserted
        // `invited -> join` while the frozen head was already `join` would be
        // signing a pre-state it did not observe; the reducer derives `from`.
        let event = control_move(vec![], vec![]);
        let mut pre_state = BTreeMap::new();
        pre_state.insert(cell_member(), CellState::Value(json!("invited")));
        let effects = verify_control_move(
            &event,
            &realm(),
            &pre_state,
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![ProjectedCellWrite {
                cell: cell_member(),
                op: ProjectedOp::TransitionTo { to: json!("join") },
            }]),
        )
        .unwrap();
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].op.from, Some(json!("invited")));
        assert_eq!(effects[0].op.to, Some(json!("join")));
    }

    #[test]
    fn transition_to_against_a_stale_head_fails_the_lattice_shape_check() {
        // Frozen head is already `join`, so the derived op is `join -> join`,
        // which the declared FSM table rejects. This is the check a
        // producer-supplied `from` would have bypassed.
        let event = control_move(vec![], vec![]);
        let mut pre_state = BTreeMap::new();
        pre_state.insert(cell_member(), CellState::Value(json!("join")));
        let err = verify_control_move(
            &event,
            &realm(),
            &pre_state,
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![ProjectedCellWrite {
                cell: cell_member(),
                op: ProjectedOp::TransitionTo { to: json!("join") },
            }]),
        )
        .unwrap_err();
        assert!(matches!(err, ControlMoveReject::SchemaViolation(_)));
    }

    #[test]
    fn remove_observed_removes_every_surviving_add_dot() {
        let event = control_move(vec![], vec![]);
        let mut pre_state = BTreeMap::new();
        pre_state.insert(
            cell_capability_grant(),
            CellState::Value(json!([
                {"tag": "ak:event:e1:0", "value": {"status": "active"}},
                {"tag": "ak:event:e2:0", "value": {"status": "active"}}
            ])),
        );
        let effects = verify_control_move(
            &event,
            &realm(),
            &pre_state,
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![ProjectedCellWrite {
                cell: cell_capability_grant(),
                op: ProjectedOp::RemoveObserved {
                    element_match: None,
                },
            }]),
        )
        .unwrap();
        let tags: Vec<&str> = effects
            .iter()
            .map(|effect| effect.op.tag.as_deref().unwrap())
            .collect();
        assert_eq!(tags, vec!["ak:event:e1:0", "ak:event:e2:0"]);
        assert!(
            effects
                .iter()
                .all(|effect| effect.op.op_type == LatticeOpType::Remove)
        );
    }

    #[test]
    fn remove_observed_match_narrows_to_the_named_element_field() {
        let event = control_move(vec![], vec![]);
        let mut pre_state = BTreeMap::new();
        pre_state.insert(
            cell_capability_grant(),
            CellState::Value(json!([
                {"tag": "keep", "value": {"scope": {"kind": "other"}}},
                {"tag": "drop", "value": {"scope": {"kind": "any"}}},
                // `scope.kind` absent: not a candidate for removal at all.
                {"tag": "absent", "value": {"unrelated": true}}
            ])),
        );
        let effects = verify_control_move(
            &event,
            &realm(),
            &pre_state,
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![ProjectedCellWrite {
                cell: cell_capability_grant(),
                op: ProjectedOp::RemoveObserved {
                    element_match: Some(ObservedRemoveMatch {
                        element_field: "scope.kind".to_owned(),
                        expected: json!("any"),
                    }),
                },
            }]),
        )
        .unwrap();
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].op.tag.as_deref(), Some("drop"));
    }

    fn cell_realm_policy() -> CellRef {
        CellRef::new("ak:cell:ak.component.realm.policy.v1:ak.realm.fixture".to_owned()).unwrap()
    }

    fn policy_prestate() -> Value {
        json!({"metadata": {"fields": {"review_status": "pending"}}})
    }

    fn apply_patch_write(patch: Value, expected_prestate: Option<Value>) -> ProjectedCellWrite {
        ProjectedCellWrite {
            cell: cell_realm_policy(),
            op: ProjectedOp::ApplyPatch {
                patch,
                expected_prestate,
            },
        }
    }

    fn reset_write(value: Value) -> ProjectedCellWrite {
        ProjectedCellWrite {
            cell: cell_realm_policy(),
            op: ProjectedOp::Reset { value },
        }
    }

    /// The `refs[]` §9.5 condition 1 requires on every recovery Move, matching
    /// `cba-lattice-fixture.json`'s `conflict_recovery_move` vector.
    fn recovery_refs() -> Vec<EventRef> {
        vec![
            EventRef::new(
                "ak:grant:019641d2-2000-7000-8000-000000000000",
                "recovery_capability",
            ),
            EventRef::new(
                format!("ak:seal:sha256:{}", "cc".repeat(32)),
                "state_witness",
            ),
        ]
    }

    fn recovery_move() -> Event {
        control_move(vec![], recovery_refs())
    }

    fn bottom_policy_cell() -> BTreeMap<CellRef, CellState> {
        BTreeMap::from([(
            cell_realm_policy(),
            CellState::Bottom(crate::Bottom::new(
                BottomKind::Conflict,
                vec![cell_realm_policy()],
            )),
        )])
    }

    /// Vector case `missing_state_witness`. The anchor is a critical ref, not a
    /// payload field, so nothing in the payload schema rejects its absence: a
    /// Move that only named the right kind would otherwise reset a cell with no
    /// pre-conflict anchor at all.
    #[test]
    fn a_reset_without_a_state_witness_ref_is_rejected() {
        let event = control_move(
            vec![],
            vec![EventRef::new(
                "ak:grant:019641d2-2000-7000-8000-000000000000",
                "recovery_capability",
            )],
        );

        let error = verify_control_move(
            &event,
            &realm(),
            &bottom_policy_cell(),
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![reset_write(json!({"policy_revision": 8}))]),
        )
        .expect_err("a recovery Move without a state_witness must fail closed");

        assert!(
            matches!(
                &error,
                ControlMoveReject::FailedPrecondition { reason, .. }
                    if reason == "recovery_witness_missing"
            ),
            "unexpected reject: {error:?}"
        );
    }

    /// The authorization half of the same condition.
    #[test]
    fn a_reset_without_a_recovery_capability_ref_is_rejected() {
        let event = control_move(
            vec![],
            vec![EventRef::new(
                format!("ak:seal:sha256:{}", "cc".repeat(32)),
                "state_witness",
            )],
        );

        let error = verify_control_move(
            &event,
            &realm(),
            &bottom_policy_cell(),
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![reset_write(json!({"policy_revision": 8}))]),
        )
        .expect_err("a recovery Move without a recovery_capability must fail closed");

        assert!(
            matches!(
                &error,
                ControlMoveReject::FailedPrecondition { reason, .. }
                    if reason == "recovery_capability_not_sealed"
            ),
            "unexpected reject: {error:?}"
        );
    }

    #[test]
    fn a_reset_resolves_a_cell_that_is_in_bottom() {
        let event = recovery_move();

        let effects = verify_control_move(
            &event,
            &realm(),
            &bottom_policy_cell(),
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![reset_write(json!({"policy_revision": 8}))]),
        )
        .unwrap();

        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].op.op_type, LatticeOpType::Set);
        assert_eq!(effects[0].op.value, Some(json!({"policy_revision": 8})));
        assert!(
            effects[0].recovery_reset,
            "the projected effect must be marked as the §9.5 reset; a plain `set` \
             joins with the branches that caused the ⊥ and never leaves it"
        );

        // The load-bearing assertion: the cell's resolved state, not the shape
        // of the projected op. The op shape stayed correct throughout the
        // period when recovery did not actually work.
        let registry = MemoryCellRegistry::new();
        let binding = registry.resolve(&realm(), &cell_realm_policy()).unwrap();
        let digest = |byte: &str| Hash::new(format!("sha256:{}", byte.repeat(32))).unwrap();
        let conflicting = |byte: &str, value: Value| crate::lattice::ordered_log::IssuedOp {
            issuer: event.actor_id.clone(),
            op: SealedOp::new(digest(byte), {
                let mut op = LatticeOp::empty();
                op.op_type = LatticeOpType::Set;
                op.value = Some(value);
                op
            }),
        };
        let log = vec![
            conflicting("ab", json!({"policy_revision": 6})),
            conflicting("cd", json!({"policy_revision": 7})),
            crate::lattice::ordered_log::IssuedOp {
                issuer: event.actor_id.clone(),
                op: SealedOp::from_projection(digest("ef"), &effects[0]),
            },
        ];
        assert!(
            crate::state::join_cell(binding.lattice.as_ref(), &cell_realm_policy(), &log[..2])
                .is_bottom(),
            "precondition: the two concurrent writes are what put the cell in ⊥"
        );
        assert_eq!(
            crate::state::join_cell(binding.lattice.as_ref(), &cell_realm_policy(), &log),
            CellState::Value(json!({"policy_revision": 8})),
            "the cell must leave ⊥ and equal the signed resolved_value"
        );
    }

    #[test]
    fn a_reset_on_a_live_cell_is_rejected() {
        // The converse of the case above, and the load-bearing half: without it
        // ak.state.conflict_recovery would be a general overwrite channel that
        // bypasses every lattice and precondition
        // (`event-auth-state-resolution.md` §9.5).
        let event = recovery_move();
        let mut pre_state = BTreeMap::new();
        pre_state.insert(cell_realm_policy(), CellState::Value(policy_prestate()));

        let error = verify_control_move(
            &event,
            &realm(),
            &pre_state,
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![reset_write(json!({"policy_revision": 8}))]),
        )
        .expect_err("a reset must not apply to a cell that is not in bottom");

        assert!(
            matches!(
                &error,
                ControlMoveReject::FailedPrecondition { reason, .. }
                    if reason == "recovery_target_not_in_bottom"
            ),
            "unexpected reject: {error:?}"
        );
    }

    #[test]
    fn a_reset_on_a_cell_with_no_prior_state_is_rejected() {
        // An absent cell is not a cell in bottom. Treating "no entry" as
        // recoverable would let a recovery mint a value for a cell that never
        // conflicted.
        let event = recovery_move();

        let error = verify_control_move(
            &event,
            &realm(),
            &BTreeMap::new(),
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![reset_write(json!({"policy_revision": 8}))]),
        )
        .expect_err("a reset must not apply to an absent cell");

        assert!(
            matches!(
                &error,
                ControlMoveReject::FailedPrecondition { reason, .. }
                    if reason == "recovery_target_not_in_bottom"
            ),
            "unexpected reject: {error:?}"
        );
    }

    #[test]
    fn apply_patch_projection_sets_the_whole_post_state() {
        let event = control_move(vec![], vec![]);
        let mut pre_state = BTreeMap::new();
        pre_state.insert(cell_realm_policy(), CellState::Value(policy_prestate()));

        let effects = verify_control_move(
            &event,
            &realm(),
            &pre_state,
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![apply_patch_write(
                json!({"metadata.fields.review_status": {"$op": "set", "value": "approved"}}),
                None,
            )]),
        )
        .unwrap();

        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].op.op_type, LatticeOpType::Set);
        // The cell value is the complete post-state, never the partial patch
        // (`event-and-patch.md` §4.3.1 step 3).
        assert_eq!(
            effects[0].op.value,
            Some(json!({"metadata": {"fields": {"review_status": "approved"}}}))
        );
    }

    #[test]
    fn apply_patch_accepts_a_matching_prestate_binding() {
        let event = control_move(vec![], vec![]);
        let mut pre_state = BTreeMap::new();
        pre_state.insert(cell_realm_policy(), CellState::Value(policy_prestate()));
        let binding = crate::canonical::canonical_sha256(&policy_prestate()).unwrap();

        let effects = verify_control_move(
            &event,
            &realm(),
            &pre_state,
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![apply_patch_write(
                json!({"metadata.fields.review_status": {"$op": "set", "value": "approved"}}),
                Some(json!(binding)),
            )]),
        )
        .unwrap();

        assert_eq!(
            effects[0].op.value,
            Some(json!({"metadata": {"fields": {"review_status": "approved"}}}))
        );
    }

    #[test]
    fn apply_patch_prestate_binding_mismatch_rejects_the_whole_event() {
        // The producer signed a binding for a different pre-state; §2.4.2
        // requires `failed_precondition` on the whole Event, not a patched
        // value derived from a state it never observed.
        let event = control_move(vec![], vec![]);
        let mut pre_state = BTreeMap::new();
        pre_state.insert(cell_realm_policy(), CellState::Value(policy_prestate()));
        let stale = crate::canonical::canonical_sha256(&json!({"metadata": {}})).unwrap();

        let err = verify_control_move(
            &event,
            &realm(),
            &pre_state,
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![apply_patch_write(
                json!({"metadata.fields.review_status": {"$op": "set", "value": "approved"}}),
                Some(json!(stale)),
            )]),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            ControlMoveReject::PrestateBindingMismatch { .. }
        ));
        assert_eq!(
            reject_to_error_code(&err),
            crate::ErrorCode::FAILED_PRECONDITION
        );
    }

    #[test]
    fn apply_patch_against_an_unresolvable_path_fails_closed() {
        // `unset` on a field the frozen pre-state does not carry: the patch
        // cannot be applied, so the projection cannot be evaluated.
        let event = control_move(vec![], vec![]);
        let mut pre_state = BTreeMap::new();
        pre_state.insert(cell_realm_policy(), CellState::Value(policy_prestate()));

        let err = verify_control_move(
            &event,
            &realm(),
            &pre_state,
            &MemoryCellRegistry::new(),
            ok_proofs,
            project(vec![apply_patch_write(
                json!({"metadata.fields.absent_field": {"$op": "unset"}}),
                None,
            )]),
        )
        .unwrap_err();

        assert!(matches!(err, ControlMoveReject::ProjectionFailed(_)));
    }

    #[test]
    fn projection_failure_rejects_the_whole_control_move() {
        let event = control_move(vec![], vec![]);
        let err = verify_control_move(
            &event,
            &realm(),
            &BTreeMap::new(),
            &MemoryCellRegistry::new(),
            ok_proofs,
            |_: &Event| Err("registry has no contract for this kind".to_owned()),
        )
        .unwrap_err();
        assert!(matches!(err, ControlMoveReject::ProjectionFailed(_)));
    }

    #[test]
    fn reject_to_error_code_full_mapping() {
        assert_eq!(
            reject_to_error_code(&ControlMoveReject::SchemaViolation("x".into())),
            crate::ErrorCode::SCHEMA_VIOLATION
        );
        assert_eq!(
            reject_to_error_code(&ControlMoveReject::InvalidSignature("x".into())),
            crate::ErrorCode::INVALID_SIGNATURE
        );
        assert_eq!(
            reject_to_error_code(&ControlMoveReject::CapabilityDenied("x".into())),
            crate::ErrorCode::CAPABILITY_DENIED
        );
        assert_eq!(
            reject_to_error_code(&ControlMoveReject::FailedPrecondition {
                cell: "x".into(),
                reason: "y".into()
            }),
            crate::ErrorCode::STATE_MISMATCH
        );
        assert_eq!(
            reject_to_error_code(&ControlMoveReject::FailedBottom {
                cell: "x".into(),
                kind: BottomKind::Conflict
            }),
            crate::ErrorCode::STATE_MISMATCH
        );
        assert_eq!(
            reject_to_error_code(&ControlMoveReject::PrestateBindingMismatch {
                cell: "x".into(),
                expected: "sha256:aa".into(),
                observed: "sha256:bb".into()
            }),
            crate::ErrorCode::FAILED_PRECONDITION
        );
        assert_eq!(
            reject_to_error_code(&ControlMoveReject::ProjectionFailed("x".into())),
            crate::ErrorCode::SCHEMA_VIOLATION
        );
        assert_eq!(
            reject_to_error_code(&ControlMoveReject::Registry("x".into())),
            crate::ErrorCode::INTERNAL_ERROR
        );
    }
}
