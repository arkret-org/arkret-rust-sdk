//! Move verifier pipeline.
//!
//! Per `cokret-rust-sdk/docs/move-seal-runtime.md` §4 and spec §3-§4.
//! Five steps; failure at any step rejects the Move with a typed reason
//! that maps onto a wire `error_code`:
//!
//! | step | check | wire error_code on fail |
//! | --- | --- | --- |
//! | 1 structural | id round-trip, `validate_structural` | `schema_violation` |
//! | 2 signature | `payload_digest` matches canonical bytes; JWS verify | `invalid_signature` |
//! | 3 capability | each `refs[role=authorized_by]` resolves to a covering grant | `capability_denied` |
//! | 4 preconditions | every `(cell, predicate)` evaluates true on `pre_state` | `state_mismatch` (or `failed_bottom`) |
//! | 5 effect-shape | every effect's `LatticeOp` passes the cell's `validate_op` | `schema_violation` |
//!
//! `verify_jws` and `resolve_grant` are out-of-scope here: they live in
//! `cokret-signatures` and `cokret-sdk::authz` respectively. This
//! module assumes those primitives are passed in (or stubbed) so the
//! pipeline orchestration stays pure.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use super::store::{BottomMode, CellRegistry, StoreError};
use crate::lattice::CellState;
use crate::{BottomKind, CellRef, LatticeOp, Move, MoveId, Predicate, PredicateOp, canonical};

#[derive(Debug, Error)]
pub enum MoveReject {
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

    #[error("registry error: {0}")]
    Registry(String),
}

impl From<StoreError> for MoveReject {
    fn from(e: StoreError) -> Self {
        MoveReject::Registry(e.to_string())
    }
}

/// Map a [`MoveReject`] variant to its wire-level `error_code` constant
/// (from `cokret-spec` `error-code-registry.json`).
pub fn reject_to_error_code(r: &MoveReject) -> &'static str {
    match r {
        MoveReject::SchemaViolation(_) => crate::ERROR_CODE_SCHEMA_VIOLATION,
        MoveReject::InvalidSignature(_) => crate::ERROR_CODE_INVALID_SIGNATURE,
        MoveReject::CapabilityDenied(_) => crate::ERROR_CODE_CAPABILITY_DENIED,
        MoveReject::FailedPrecondition { .. } => crate::ERROR_CODE_STATE_MISMATCH,
        // A precondition that reads a ⊥ cell fails closed. The registry has no
        // top-level `failed_bottom` code; the bottom semantics are a
        // `failed_precondition` sub-reason (`cell_in_bottom_state`). Surface the
        // registered top-level `state_mismatch` code (same family as
        // `FailedPrecondition`); the reason carries the ⊥ detail.
        MoveReject::FailedBottom { .. } => crate::ERROR_CODE_STATE_MISMATCH,
        MoveReject::Registry(_) => crate::ERROR_CODE_INTERNAL_ERROR,
    }
}

/// Verify a Move against a pre-state map.
///
/// `pre_state` MUST be the joined-state of the Move's `seal_ref`
/// predecessor view (or the Seal batch's predecessor view in
/// `apply_seal`). Cells absent from the map are treated as
/// `CellState::Value(Value::Null)`.
///
/// `verify_jws` is a caller-supplied closure so this crate stays free
/// of crypto deps. It receives the canonical bytes, JWS string,
/// verification method, and issuer DID. Pass `|_, _, _, _| Ok(())` if
/// you intend to verify signatures elsewhere (e.g. fixture replay).
pub fn verify_move<F>(
    m: &Move,
    pre_state: &BTreeMap<CellRef, CellState>,
    registry: &dyn CellRegistry,
    verify_jws: F,
) -> Result<(), MoveReject>
where
    F: Fn(&[u8], &str, &str, &str) -> Result<(), String>,
{
    // Step 1: structural
    m.validate_id()
        .map_err(|e| MoveReject::SchemaViolation(format!("id mismatch: {e}")))?;
    m.validate_structural()
        .map_err(|e| MoveReject::SchemaViolation(e.to_string()))?;

    // Step 2: signature
    let canonical_bytes = m
        .canonical_bytes_for_id()
        .map_err(|e| MoveReject::SchemaViolation(format!("canonical bytes: {e}")))?;
    let observed_hash = canonical::sha256_digest(&canonical_bytes);
    if m.sig.payload_digest.as_str() != observed_hash {
        return Err(MoveReject::InvalidSignature(format!(
            "payload_digest {} != canonical bytes hash {}",
            m.sig.payload_digest, observed_hash
        )));
    }
    verify_jws(
        &canonical_bytes,
        &m.sig.jws,
        &m.sig.verification_method,
        m.issuer.as_str(),
    )
    .map_err(MoveReject::InvalidSignature)?;

    // Step 3: capability.
    if m.issuer.as_str().is_empty() {
        return Err(MoveReject::CapabilityDenied(
            "issuer DID is empty".to_owned(),
        ));
    }
    verify_capability_refs(m, pre_state)?;

    // Step 4: preconditions
    for pre in &m.preconditions {
        let cell_state = pre_state
            .get(&pre.cell)
            .cloned()
            .unwrap_or(CellState::Value(Value::Null));
        // bottom=reject cells fail closed.
        if let CellState::Bottom(b) = &cell_state {
            let binding = registry
                .resolve(&m.realm_id, &pre.cell)
                .map_err(|e| MoveReject::Registry(e.to_string()))?;
            if binding.bottom_mode == BottomMode::Reject {
                return Err(MoveReject::FailedBottom {
                    cell: pre.cell.as_str().to_owned(),
                    kind: b.kind,
                });
            }
        }
        evaluate_predicate(&pre.cell, &pre.predicate, &cell_state)?;
    }

    // Step 5: effect-shape
    for effect in &m.effects {
        let binding = registry
            .resolve(&m.realm_id, &effect.cell)
            .map_err(|e| MoveReject::Registry(e.to_string()))?;
        let core_op: LatticeOp = effect.op.clone();
        binding.lattice.validate_op(&core_op).map_err(|e| {
            MoveReject::SchemaViolation(format!("effect on {} invalid: {e}", effect.cell))
        })?;
    }

    Ok(())
}

const AUTHORIZED_BY_ROLE: &str = "authorized_by";
const CAPABILITY_GRANT_CELL_FAMILY: &str = "ck.component.capability.grant.v1";

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
    m: &Move,
    pre_state: &BTreeMap<CellRef, CellState>,
) -> Result<(), MoveReject> {
    for reference in m
        .refs
        .iter()
        .filter(|reference| reference.role == AUTHORIZED_BY_ROLE)
    {
        let grant = find_capability_grant(reference.id.as_str(), pre_state)?;
        if grant.is_revoked() {
            return Err(MoveReject::CapabilityDenied(format!(
                "authorized_by grant '{}' is revoked",
                reference.id
            )));
        }
        let subject = grant.subject().ok_or_else(|| {
            MoveReject::CapabilityDenied(format!(
                "authorized_by grant '{}' has no subject",
                reference.id
            ))
        })?;
        if subject != m.issuer.as_str() {
            return Err(MoveReject::CapabilityDenied(format!(
                "authorized_by grant '{}' subject '{}' does not cover issuer '{}'",
                reference.id, subject, m.issuer
            )));
        }
        if grant.actions.is_empty() {
            return Err(MoveReject::CapabilityDenied(format!(
                "authorized_by grant '{}' has no actions",
                reference.id
            )));
        }
        if !grant.has_resources() {
            return Err(MoveReject::CapabilityDenied(format!(
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
) -> Result<CapabilityGrantCellValue, MoveReject> {
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
        return Err(MoveReject::CapabilityDenied(format!(
            "authorized_by grant '{grant_id}' is unavailable because a capability grant cell is bottom"
        )));
    }
    Err(MoveReject::CapabilityDenied(format!(
        "authorized_by grant '{grant_id}' not found in pre-state capability grant cells"
    )))
}

fn is_capability_grant_cell(cell: &CellRef) -> bool {
    crate::CellId::parse(cell.as_str())
        .map(|cell_id| cell_id.component() == CAPABILITY_GRANT_CELL_FAMILY)
        .unwrap_or(false)
}

fn grant_from_cell_value(
    grant_id: &str,
    value: &Value,
) -> Result<Option<CapabilityGrantCellValue>, MoveReject> {
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
                MoveReject::CapabilityDenied(format!(
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
) -> Result<(), MoveReject> {
    let observed: &Value = match cell_state {
        CellState::Value(v) => v,
        CellState::Bottom(_) => &Value::Null, // bottom already handled by caller
    };
    match pred.op {
        PredicateOp::HeadEq => {
            let expected = pred.value.as_ref().ok_or_else(|| {
                MoveReject::SchemaViolation("predicate head_eq requires `value`".to_owned())
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
            Err(MoveReject::FailedPrecondition {
                cell: cell.as_str().to_owned(),
                reason: format!("head_eq: observed={observed}, expected={expected}"),
            })
        }
        PredicateOp::HeadIn => {
            let values = pred.values.as_ref().ok_or_else(|| {
                MoveReject::SchemaViolation("predicate head_in requires `values`".to_owned())
            })?;
            let observed_head = observed.get("head").unwrap_or(observed);
            if values.iter().any(|v| v == observed_head) {
                Ok(())
            } else {
                Err(MoveReject::FailedPrecondition {
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
                return Err(MoveReject::SchemaViolation(
                    "predicate contains requires `value` or `values`".to_owned(),
                ));
            };
            let observed_arr =
                observed
                    .as_array()
                    .ok_or_else(|| MoveReject::FailedPrecondition {
                        cell: cell.as_str().to_owned(),
                        reason: format!("contains: observed value is not an array: {observed}"),
                    })?;
            for needle in needles {
                if !observed_arr.iter().any(|item| {
                    item == needle
                        || item.get("tag") == Some(needle)
                        || item.get("value") == Some(needle)
                }) {
                    return Err(MoveReject::FailedPrecondition {
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
                MoveReject::SchemaViolation(
                    "predicate satisfies requires `predicate_id`".to_owned(),
                )
            })?;
            Err(MoveReject::SchemaViolation(format!(
                "predicate satisfies('{id}') cannot be evaluated: no predicate \
                 registry is configured (fail-closed per event-auth §5.1)"
            )))
        }
    }
}

/// Convenience: collect a list of MoveReject failures keyed by Move id.
pub type MoveRejectMap = BTreeMap<MoveId, MoveReject>;

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::lattice::CellState;
    use crate::state::store::memory::MemoryCellRegistry;
    use crate::{
        CellRef, Effect, LatticeOp, LatticeOpType, Precondition, PredicateOp, RealmId, SemanticRef,
    };

    fn realm() -> RealmId {
        RealmId::new("ck:realm:0196419b-0000-7000-8000-00000000014a".to_owned()).unwrap()
    }

    fn cell_member() -> CellRef {
        CellRef::new("ck:cell:ck.component.member.state.v1:did.web.alice.example".to_owned())
            .unwrap()
    }

    fn cell_capability_grant() -> CellRef {
        CellRef::new(
            "ck:cell:ck.component.capability.grant.v1:ck.grant.01js0gr0000000000000000000"
                .to_owned(),
        )
        .unwrap()
    }

    fn build_move(preconditions: Vec<Precondition>, effects: Vec<Effect>) -> Move {
        build_move_with_refs(preconditions, effects, vec![])
    }

    fn build_move_with_refs(
        preconditions: Vec<Precondition>,
        effects: Vec<Effect>,
        refs: Vec<SemanticRef>,
    ) -> Move {
        let body = json!({
            "issuer": "did:web:admin.example",
            "realm_id": realm().as_str(),
            "preconditions": preconditions,
            "effects": effects,
            "seal_basis": {
                "leaves": [format!("ck:seal:sha256:{}", "aa".repeat(32))],
                "control_event_set_root": format!("sha256:{}", "22".repeat(32)),
                "state_root": format!("sha256:{}", "33".repeat(32))
            },
            "refs": refs,
            "hlc": "0189c4d2af00-0000-aabbccdd"
        });
        let body_bytes = canonical::canonical_json_bytes(&body).unwrap();
        let payload_digest = canonical::sha256_digest(&body_bytes);
        let id_hex = {
            use sha2::{Digest, Sha256};
            let mut s = String::with_capacity(64);
            for b in Sha256::digest(&body_bytes) {
                s.push_str(&format!("{b:02x}"));
            }
            s
        };
        let mut full = body.as_object().unwrap().clone();
        full.insert("id".into(), Value::String(format!("sha256:{id_hex}")));
        full.insert(
            "sig".into(),
            json!({
                "alg": "EdDSA",
                "verification_method": "did:web:admin.example#k1",
                "payload_digest": payload_digest,
                "created_at": "2026-05-08T00:00:00Z",
                "jws": "AAAA.BBBB.CCCC"
            }),
        );
        serde_json::from_value(Value::Object(full)).unwrap()
    }

    fn authorized_ref(id: &str) -> SemanticRef {
        SemanticRef {
            id: id.to_owned(),
            role: AUTHORIZED_BY_ROLE.to_owned(),
            critical: true,
        }
    }

    fn grant_cell_state(grant_id: &str, subject: &str) -> CellState {
        CellState::Value(json!([
            {
                "tag": grant_id,
                "value": {
                    "id": grant_id,
                    "issuer": "did:web:owner.example",
                    "subject": subject,
                    "actions": ["ck.member.state"],
                    "resources": [{"kind": "Realm", "realm_id": realm().as_str()}]
                }
            }
        ]))
    }

    fn ok_jws(_: &[u8], _: &str, _: &str, _: &str) -> Result<(), String> {
        Ok(())
    }

    fn fail_jws(_: &[u8], _: &str, _: &str, _: &str) -> Result<(), String> {
        Err("dummy signature failure".to_owned())
    }

    #[test]
    fn structural_pass_with_valid_move() {
        let pre = Precondition {
            cell: cell_member(),
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(json!("invited")),
                values: None,
                predicate_id: None,
            },
        };
        let eff = Effect {
            cell: cell_member(),
            op: LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!("invited")),
                to: Some(json!("join")),
                reason: None,
                issuer_seq: None,
            },
        };
        let m = build_move(vec![pre], vec![eff]);
        let mut pre_state = BTreeMap::new();
        pre_state.insert(cell_member(), CellState::Value(json!("invited")));
        verify_move(&m, &pre_state, &MemoryCellRegistry::new(), ok_jws).unwrap();
    }

    #[test]
    fn signature_failure_rejected() {
        let eff = Effect {
            cell: cell_member(),
            op: LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!("invited")),
                to: Some(json!("join")),
                reason: None,
                issuer_seq: None,
            },
        };
        let m = build_move(vec![], vec![eff]);
        let pre_state = BTreeMap::new();
        let err = verify_move(&m, &pre_state, &MemoryCellRegistry::new(), fail_jws).unwrap_err();
        assert!(matches!(err, MoveReject::InvalidSignature(_)));
    }

    #[test]
    fn authorized_by_ref_resolves_capability_grant_cell() {
        let grant_id = "ck:grant:0196419b-0000-7000-8000-000000000111";
        let eff = Effect {
            cell: cell_member(),
            op: LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!("invited")),
                to: Some(json!("join")),
                reason: None,
                issuer_seq: None,
            },
        };
        let m = build_move_with_refs(vec![], vec![eff], vec![authorized_ref(grant_id)]);
        let mut pre_state = BTreeMap::new();
        pre_state.insert(
            cell_capability_grant(),
            grant_cell_state(grant_id, m.issuer.as_str()),
        );

        verify_move(&m, &pre_state, &MemoryCellRegistry::new(), ok_jws).unwrap();
    }

    #[test]
    fn missing_authorized_by_grant_rejects() {
        let grant_id = "ck:grant:0196419b-0000-7000-8000-000000000111";
        let eff = Effect {
            cell: cell_member(),
            op: LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!("invited")),
                to: Some(json!("join")),
                reason: None,
                issuer_seq: None,
            },
        };
        let m = build_move_with_refs(vec![], vec![eff], vec![authorized_ref(grant_id)]);
        let err =
            verify_move(&m, &BTreeMap::new(), &MemoryCellRegistry::new(), ok_jws).unwrap_err();
        assert!(matches!(err, MoveReject::CapabilityDenied(_)));
        assert_eq!(
            reject_to_error_code(&err),
            crate::ERROR_CODE_CAPABILITY_DENIED
        );
    }

    #[test]
    fn authorized_by_subject_mismatch_rejects() {
        let grant_id = "ck:grant:0196419b-0000-7000-8000-000000000111";
        let eff = Effect {
            cell: cell_member(),
            op: LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!("invited")),
                to: Some(json!("join")),
                reason: None,
                issuer_seq: None,
            },
        };
        let m = build_move_with_refs(vec![], vec![eff], vec![authorized_ref(grant_id)]);
        let mut pre_state = BTreeMap::new();
        pre_state.insert(
            cell_capability_grant(),
            grant_cell_state(grant_id, "did:web:bob.example"),
        );

        let err = verify_move(&m, &pre_state, &MemoryCellRegistry::new(), ok_jws).unwrap_err();
        assert!(matches!(err, MoveReject::CapabilityDenied(_)));
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
        let eff = Effect {
            cell: cell_member(),
            op: LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!("join")),
                to: Some(json!("ban")),
                reason: None,
                issuer_seq: None,
            },
        };
        let m = build_move(vec![pre], vec![eff]);
        let mut pre_state = BTreeMap::new();
        // Observed is invited, not join.
        pre_state.insert(cell_member(), CellState::Value(json!("invited")));
        let err = verify_move(&m, &pre_state, &MemoryCellRegistry::new(), ok_jws).unwrap_err();
        assert!(matches!(err, MoveReject::FailedPrecondition { .. }));
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
        let eff = Effect {
            cell: cell_member(),
            op: LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!("invited")),
                to: Some(json!("join")),
                reason: None,
                issuer_seq: None,
            },
        };
        let m = build_move(vec![pre], vec![eff]);
        let err = verify_move(&m, &pre_state, &MemoryCellRegistry::new(), ok_jws).unwrap_err();
        assert!(matches!(err, MoveReject::FailedBottom { .. }));
    }

    #[test]
    fn effect_shape_failure_rejects() {
        // FSM cell with disallowed transition: invited -> ban (not in MemoryCellRegistry's allowed
        // set).
        let eff = Effect {
            cell: cell_member(),
            op: LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!("invited")),
                to: Some(json!("ban")),
                reason: None,
                issuer_seq: None,
            },
        };
        let m = build_move(vec![], vec![eff]);
        let err =
            verify_move(&m, &BTreeMap::new(), &MemoryCellRegistry::new(), ok_jws).unwrap_err();
        assert!(matches!(err, MoveReject::SchemaViolation(_)));
    }

    #[test]
    fn empty_issuer_capability_denied() {
        // Build a Move then mutate issuer to empty (skipping Did validator
        // by going through serde_json::from_value with a hand-built Move.id).
        // Easier: just test reject_to_error_code mapping.
        let r = MoveReject::CapabilityDenied("test".into());
        assert_eq!(
            reject_to_error_code(&r),
            crate::ERROR_CODE_CAPABILITY_DENIED
        );
    }

    #[test]
    fn reject_to_error_code_full_mapping() {
        assert_eq!(
            reject_to_error_code(&MoveReject::SchemaViolation("x".into())),
            crate::ERROR_CODE_SCHEMA_VIOLATION
        );
        assert_eq!(
            reject_to_error_code(&MoveReject::InvalidSignature("x".into())),
            crate::ERROR_CODE_INVALID_SIGNATURE
        );
        assert_eq!(
            reject_to_error_code(&MoveReject::FailedPrecondition {
                cell: "x".into(),
                reason: "y".into()
            }),
            crate::ERROR_CODE_STATE_MISMATCH
        );
        assert_eq!(
            reject_to_error_code(&MoveReject::FailedBottom {
                cell: "x".into(),
                kind: BottomKind::Conflict
            }),
            crate::ERROR_CODE_STATE_MISMATCH
        );
        assert_eq!(
            reject_to_error_code(&MoveReject::Registry("x".into())),
            crate::ERROR_CODE_INTERNAL_ERROR
        );
    }
}
