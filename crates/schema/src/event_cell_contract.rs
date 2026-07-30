//! Registry-driven validation of reducer-input Event cell contracts.
//!
//! The event-kind registry is the sole authority for reducer targets. There is
//! no producer-supplied cell write to compare against: the receiver recomputes
//! every target and every lattice operation from the signed envelope, the
//! schema-validated payload and the frozen pre-state
//! (`zh/models/event-and-patch.md` section 2.4.2).

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::OnceLock;

/// Canonical wire subject segment of a cell family declared with
/// `cell_subject: null` (`conformance/encoding.md` section 4).
///
/// Re-exported so this module and the wire layer cannot drift apart.
pub use arkret_wire::NULL_SUBJECT as NULL_CELL_SUBJECT;
use arkret_wire::{
    CellRef, Event, EventId, LatticeOp, LatticeOpType, ObservedRemoveMatch, ProjectedCellWrite,
    ProjectedOp,
};
use serde_json::Value;
use thiserror::Error;

/// Envelope context used while validating the registry-declared CBA plane.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EventCellContractContext {
    /// A post-genesis Event: control writes require `seal_basis`; data writes
    /// require `seal_ref` plus `auth_context`.
    #[default]
    Standard,
    /// A follow-up in the closed ordinary Realm genesis transaction. There is
    /// no accepted Seal yet, so the control write MUST use the spec's
    /// bootstrap exception and carry no CBA basis fields.
    OrdinaryRealmBootstrap,
}

/// Failure while matching an Event against its generated registry contract.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EventCellContractError {
    #[error("event kind {0} is not a registered reducer input")]
    UnregisteredReducerInput(String),
    #[error("event kind {0} has no single-target cell contract")]
    MissingCellContract(String),
    #[error("event kind {kind} is routed through the wrong CBA plane; expected {expected}")]
    PlaneMismatch { kind: String, expected: String },
    #[error("event kind {kind} requires exactly one effect, got {actual}")]
    EffectCount { kind: String, actual: usize },
    #[error("event kind {kind} has an invalid cell id: {message}")]
    InvalidCell { kind: String, message: String },
    #[error("event kind {kind} targeted {actual}, expected {expected}")]
    CellMismatch {
        kind: String,
        expected: String,
        actual: String,
    },
    #[error("event kind {kind} requires lattice op {expected}, got {actual}")]
    OperationMismatch {
        kind: String,
        expected: String,
        actual: String,
    },
    #[error("event kind {kind} effect value does not match its signed payload")]
    PayloadMismatch { kind: String },
    #[error("event kind {kind} has an invalid registered effect set: {message}")]
    EffectSetMismatch { kind: String, message: String },
    #[error("event kind {kind} cell subject cannot be derived: {message}")]
    SubjectDerivation { kind: String, message: String },
    #[error(
        "event kind {kind} failed frozen pre-state requirement ({code}/{reason_code}): {message}"
    )]
    PreStateRequirement {
        kind: String,
        code: String,
        reason_code: String,
        message: String,
    },
}

impl EventCellContractError {
    /// Normative reason code for a submit rejection.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::PlaneMismatch { .. } => "plane_cross_write",
            Self::PreStateRequirement { reason_code, .. }
                if reason_code == "invite_kind_requires_revoke" =>
            {
                "invite_kind_requires_revoke"
            }
            Self::PreStateRequirement { .. } => "reducer_projection_failed",
            _ => "effects_payload_mismatch",
        }
    }
}

/// Frozen cell values used while evaluating registry-declared pre-state
/// requirements. A missing entry is a failed requirement, never an implicit
/// bottom value.
pub type FrozenPreState = BTreeMap<CellRef, Value>;

static EMBEDDED_EVENT_KIND_REGISTRY: OnceLock<Result<Value, String>> = OnceLock::new();

fn event_kind_registry() -> Result<&'static Value, EventCellContractError> {
    EMBEDDED_EVENT_KIND_REGISTRY
        .get_or_init(|| {
            crate::embedded_json_artifact("registry/event-kind-registry.json")
                .map_err(|error| error.to_string())
        })
        .as_ref()
        .map_err(|message| EventCellContractError::EffectSetMismatch {
            kind: "<registry>".to_owned(),
            message: message.clone(),
        })
}

/// Project every active registry-declared cell write for `event`.
///
/// This is the single evaluator both producers and receivers use, so target
/// selection and operation payloads cannot drift into a parallel client
/// contract. It evaluates each write's `condition` first, then its
/// `effect_projection`, and rejects duplicate targets.
///
/// Writes whose grammar needs the frozen pre-state (`transition_to`,
/// `apply_patch`) come back as the corresponding [`ProjectedOp`] variant for
/// the reducer to resolve; nothing here invents a pre-state.
pub fn project_registered_cell_writes(
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Vec<ProjectedCellWrite>, EventCellContractError> {
    project_registered_cell_writes_with_pre_state(event, digest_suite, &FrozenPreState::new())
}

/// Project registered writes after evaluating every requirement against one
/// immutable pre-state snapshot.
///
/// Requirement failure returns before any write is exposed to the caller, so
/// an Event cannot partially apply its registered write set.
pub fn project_registered_cell_writes_with_pre_state(
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
    frozen_pre_state: &FrozenPreState,
) -> Result<Vec<ProjectedCellWrite>, EventCellContractError> {
    let kind = event.kind.as_str().to_owned();
    let registry = event_kind_registry()?;
    let row = registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .and_then(|rows| {
            rows.iter()
                .find(|row| row.get("event_kind").and_then(Value::as_str) == Some(kind.as_str()))
        })
        .ok_or_else(|| EventCellContractError::UnregisteredReducerInput(kind.clone()))?;
    validate_pre_state_requirements(event, row, frozen_pre_state, &kind)?;
    let Some(writes) = row.get("cell_writes").and_then(Value::as_array) else {
        // An active reducer-input kind MUST declare a complete contract
        // (`event-and-patch.md` §2.4.2). Returning an empty projection for one
        // would admit the Event while writing nothing, which is the opposite of
        // fail-closed: the registry gap would look like "this kind touches no
        // cell". A row that is not an active reducer input legitimately has no
        // writes and projects none.
        if row.get("status").and_then(Value::as_str) == Some("active")
            && row.get("reducer_input").and_then(Value::as_bool) == Some(true)
        {
            return Err(EventCellContractError::MissingCellContract(kind));
        }
        return Ok(Vec::new());
    };

    let mut projected = Vec::new();
    let mut seen = BTreeMap::<String, (String, String)>::new();
    for (write_index, write) in writes.iter().enumerate() {
        // `write_index` is the registry index, so a write skipped by its
        // `condition` still consumes one. The dot must be reproducible from the
        // registry alone; renumbering the surviving writes would make it depend
        // on payload shape.
        if !condition_matches(event, write.get("condition"), &kind)? {
            continue;
        }
        // `event-and-patch.md` §2.4.2: the one registered write whose target is
        // not statically addressable. A conflict recovery names one cell of an
        // arbitrary family, so the target is the signed `payload.target_cell`
        // and the projection is a reset rather than a lattice op. The grammar is
        // closed to `ak.state.conflict_recovery`; anything else declaring it is
        // a registry error, not a shape to interpret.
        if let Some(cell_ref_rule) = write.get("cell_ref") {
            if kind != CONFLICT_RECOVERY_KIND {
                return Err(effect_set_error(
                    &kind,
                    "cell_ref is reserved to ak.state.conflict_recovery",
                ));
            }
            let cell = conflict_recovery_cell(event, cell_ref_rule, &kind)?;
            let projection = write.get("effect_projection").ok_or_else(|| {
                effect_set_error(&kind, "conflict recovery write omits effect_projection")
            })?;
            if projection.get("kind").and_then(Value::as_str) != Some("reset") {
                return Err(effect_set_error(
                    &kind,
                    "conflict recovery effect_projection must be kind=reset",
                ));
            }
            let source = projection
                .get("value")
                .ok_or_else(|| effect_set_error(&kind, "reset effect_projection omits value"))?;
            let value = effect_source_value(
                event,
                write,
                source,
                &kind,
                &dot_for(event, write_index),
                digest_suite,
            )?;
            projected.push(ProjectedCellWrite {
                cell,
                op: ProjectedOp::Reset { value },
            });
            continue;
        }
        let family = write
            .get("cell_family")
            .and_then(Value::as_str)
            .ok_or_else(|| effect_set_error(&kind, "cell write omits cell_family"))?;
        let subject_rule = write.get("cell_subject");
        let subject_json = subject_rule
            .filter(|value| !value.is_null())
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| effect_set_error(&kind, &error.to_string()))?;
        let subject = derive_subject(event, subject_json.as_deref())?;
        let cell = CellRef::new(format!("ak:cell:{family}:{subject}")).map_err(|error| {
            EventCellContractError::InvalidCell {
                kind: kind.clone(),
                message: error.to_string(),
            }
        })?;
        let lattice = write
            .get("lattice")
            .and_then(Value::as_str)
            .ok_or_else(|| effect_set_error(&kind, "cell write omits lattice"))?;
        let projection = write
            .get("effect_projection")
            .ok_or_else(|| effect_set_error(&kind, "cell write omits effect_projection"))?;
        let projection_kind = projection.get("kind").and_then(Value::as_str).unwrap_or("");
        // Two active writes on one cell are a registry error in general, because
        // nothing orders them. The one registered exception is an or_set
        // observed-remove paired with an add, which `key-management.md` §3.6.1
        // requires be atomic on a single cell for agent-key re-authorization:
        // remove every active dot, then add the replacement. The pair is ordered
        // by construction (the remove reads the frozen pre-state, which the
        // sibling add cannot be part of), so it is well defined.
        if let Some((previous_lattice, previous_kind)) = seen.insert(
            cell.as_str().to_owned(),
            (lattice.to_owned(), projection_kind.to_owned()),
        ) {
            let atomic_or_set_pair = previous_lattice == "or_set"
                && lattice == "or_set"
                && is_or_set_remove(&previous_kind) != is_or_set_remove(projection_kind);
            if !atomic_or_set_pair {
                return Err(effect_set_error(
                    &kind,
                    &format!("two active targets derive the same cell {cell}"),
                ));
            }
        }
        let dot = or_set_dot(event.event_id.as_str(), write_index);
        for op in derive_effect_ops(event, write, projection, lattice, &kind, &dot, digest_suite)? {
            projected.push(ProjectedCellWrite {
                cell: cell.clone(),
                op,
            });
        }
    }
    Ok(projected)
}

fn validate_pre_state_requirements(
    event: &Event,
    row: &Value,
    frozen_pre_state: &FrozenPreState,
    kind: &str,
) -> Result<(), EventCellContractError> {
    let Some(requirements) = row.get("pre_state_requirements").and_then(Value::as_array) else {
        return Ok(());
    };
    for requirement in requirements {
        let family = requirement
            .get("cell_family")
            .and_then(Value::as_str)
            .ok_or_else(|| effect_set_error(kind, "pre-state requirement omits cell_family"))?;
        let subject_path = requirement
            .get("subject")
            .and_then(|value| value.get("field"))
            .and_then(Value::as_str)
            .ok_or_else(|| effect_set_error(kind, "pre-state requirement omits subject.field"))?;
        let subject = field_value(event, subject_path)
            .ok_or_else(|| effect_set_error(kind, "pre-state subject field is absent"))
            .and_then(|value| {
                scalar_subject(value).map_err(|message| effect_set_error(kind, &message))
            })?;
        let cell = CellRef::new(format!("ak:cell:{family}:{subject}")).map_err(|error| {
            EventCellContractError::InvalidCell {
                kind: kind.to_owned(),
                message: error.to_string(),
            }
        })?;
        let stored = frozen_pre_state.get(&cell);
        let predicate = requirement
            .get("predicate")
            .and_then(Value::as_object)
            .ok_or_else(|| effect_set_error(kind, "pre-state requirement omits predicate"))?;
        let field = predicate
            .get("field")
            .and_then(Value::as_str)
            .ok_or_else(|| effect_set_error(kind, "pre-state requirement predicate omits field"))?;
        let stored_value = stored.and_then(|value| nested_value(value, field));
        let satisfied = match predicate.get("kind").and_then(Value::as_str) {
            Some("stored_field_present") => stored_value.is_some_and(|value| !value.is_null()),
            Some("stored_field_equals_payload") => {
                let payload_path = predicate
                    .get("payload_field")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        effect_set_error(kind, "stored_field_equals_payload omits payload_field")
                    })?;
                stored_value == field_value(event, payload_path)
            }
            other => {
                return Err(effect_set_error(
                    kind,
                    &format!("unsupported pre-state predicate {other:?}"),
                ));
            }
        };
        if !satisfied {
            let failure = requirement
                .get("failure")
                .and_then(Value::as_object)
                .ok_or_else(|| effect_set_error(kind, "pre-state requirement omits failure"))?;
            return Err(EventCellContractError::PreStateRequirement {
                kind: kind.to_owned(),
                code: failure
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("failed_precondition")
                    .to_owned(),
                reason_code: failure
                    .get("reason_code")
                    .and_then(Value::as_str)
                    .unwrap_or("reducer_projection_failed")
                    .to_owned(),
                message: format!("predicate failed for {cell}"),
            });
        }
    }
    Ok(())
}

fn nested_value<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

/// Admission gate: the registered contract must be evaluable for this Event.
///
/// A source path that is missing, a selector that hits no branch or a
/// projection incompatible with the declared lattice all mean the reducer
/// cannot derive its writes, which fails the whole Event closed rather than
/// falling back to an implementation-private default.
pub fn validate_registered_cell_writes(event: &Event) -> Result<(), EventCellContractError> {
    validate_registered_cell_writes_in_context(event, EventCellContractContext::Standard)
}

/// [`validate_registered_cell_writes`] plus the CBA plane check for the given
/// envelope context.
///
/// The plane is read from the registry, never guessed from the kind name, and
/// the ordinary-Realm bootstrap context is the only one in which a control
/// write may carry no CBA basis at all.
pub fn validate_registered_cell_writes_in_context(
    event: &Event,
    context: EventCellContractContext,
) -> Result<(), EventCellContractError> {
    if let Some(descriptor) = event.kind.descriptor().filter(|row| row.reducer_input) {
        validate_plane(event, descriptor.plane, context)?;
    }
    project_registered_cell_writes(event, arkret_canonical::DigestSuite::Sha256).map(|_| ())
}

fn require_lattice(
    kind: &str,
    projection_kind: &str,
    lattice: &str,
    allowed: &[&str],
) -> Result<(), EventCellContractError> {
    if allowed.contains(&lattice) {
        return Ok(());
    }
    Err(effect_set_error(
        kind,
        &format!("effect_projection {projection_kind} is not valid for lattice {lattice}"),
    ))
}

/// The only kind whose registered write target is resolved from the payload.
const CONFLICT_RECOVERY_KIND: &str = "ak.state.conflict_recovery";

/// Canonical dot for the write at `write_index` of this Event.
fn dot_for(event: &Event, write_index: usize) -> String {
    or_set_dot(event.event_id.as_str(), write_index)
}

/// Resolve the recovery target from the signed payload.
///
/// The source is pinned to `payload.target_cell` rather than read from the
/// registry rule, so a registry that named some other field cannot silently
/// redirect which cell a recovery may reset.
fn conflict_recovery_cell(
    event: &Event,
    cell_ref_rule: &Value,
    kind: &str,
) -> Result<CellRef, EventCellContractError> {
    if cell_ref_rule.get("kind").and_then(Value::as_str) != Some("cell_ref")
        || cell_ref_rule.get("field").and_then(Value::as_str) != Some("payload.target_cell")
    {
        return Err(effect_set_error(
            kind,
            "conflict recovery cell_ref must be {kind: cell_ref, field: payload.target_cell}",
        ));
    }
    let raw = event
        .payload
        .get("target_cell")
        .and_then(Value::as_str)
        .ok_or_else(|| effect_set_error(kind, "payload.target_cell must be a cell id string"))?;
    CellRef::new(raw.to_owned()).map_err(|error| EventCellContractError::InvalidCell {
        kind: kind.to_owned(),
        message: error.to_string(),
    })
}

fn derive_effect_ops(
    event: &Event,
    write: &Value,
    projection: &Value,
    lattice: &str,
    kind: &str,
    dot: &str,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Vec<ProjectedOp>, EventCellContractError> {
    let projection_kind = projection
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| effect_set_error(kind, "effect_projection omits kind"))?;
    let source = |member: &str| -> Result<Value, EventCellContractError> {
        effect_source_value(
            event,
            write,
            projection.get(member).ok_or_else(|| {
                effect_set_error(
                    kind,
                    &format!("{projection_kind} projection omits {member}"),
                )
            })?,
            kind,
            dot,
            digest_suite,
        )
    };
    match projection_kind {
        "transition" => {
            require_lattice(kind, projection_kind, lattice, &["fsm"])?;
            let mut op = LatticeOp::empty();
            op.op_type = LatticeOpType::Transition;
            op.from = Some(source("from")?);
            op.to = Some(source("to")?);
            Ok(vec![ProjectedOp::Direct(op)])
        }
        "transition_to" => {
            require_lattice(kind, projection_kind, lattice, &["fsm"])?;
            Ok(vec![ProjectedOp::TransitionTo { to: source("to")? }])
        }
        "set" => {
            require_lattice(
                kind,
                projection_kind,
                lattice,
                &["cas_register", "mv_register"],
            )?;
            let mut op = LatticeOp::empty();
            op.value = Some(source("value")?);
            Ok(vec![ProjectedOp::Direct(op)])
        }
        "apply_patch" => {
            require_lattice(
                kind,
                projection_kind,
                lattice,
                &["cas_register", "mv_register"],
            )?;
            // `expected_prestate` is the only registered exception to "an
            // absent source path fails the Event closed" (`event-and-patch.md`
            // §2.4.2): the guard is optional by payload contract, so an absent
            // path means this write carries no prestate binding. The path is
            // still required to be `payload.*` — the binding is a
            // producer-signed claim about the frozen pre-state, which the other
            // source forms cannot express.
            let expected_prestate = match projection.get("expected_prestate") {
                None => None,
                Some(declared) => {
                    let path = declared
                        .as_object()
                        .and_then(|source| source.get("field"))
                        .and_then(Value::as_str)
                        .filter(|path| path.starts_with("payload."))
                        .ok_or_else(|| {
                            effect_set_error(
                                kind,
                                "apply_patch expected_prestate must be a payload.* field source",
                            )
                        })?;
                    field_value(event, path).cloned()
                }
            };
            Ok(vec![ProjectedOp::ApplyPatch {
                patch: source("patch")?,
                expected_prestate,
            }])
        }
        "append" => {
            require_lattice(kind, projection_kind, lattice, &["ordered_log"])?;
            let mut op = LatticeOp::empty();
            op.op_type = LatticeOpType::Append;
            op.value = Some(source("value")?);
            op.issuer_seq = Some(source("issuer_seq")?.as_u64().ok_or_else(|| {
                effect_set_error(kind, "append issuer_seq must derive an unsigned integer")
            })?);
            Ok(vec![ProjectedOp::Direct(op)])
        }
        "or_set_add" => {
            require_lattice(kind, projection_kind, lattice, &["or_set"])?;
            let mut op = LatticeOp::empty();
            op.op_type = LatticeOpType::Add;
            op.tag = Some(or_set_tag(
                event,
                write,
                projection.get("tag"),
                kind,
                dot,
                digest_suite,
            )?);
            op.value = Some(source("value")?);
            Ok(vec![ProjectedOp::Direct(op)])
        }
        "or_set_remove_observed" => {
            require_lattice(kind, projection_kind, lattice, &["or_set"])?;
            // The surviving add-dot set is read from the frozen pre-state, which
            // the Control Move's seal_basis has already pinned. That is what
            // makes it deterministic without the producer enumerating dots; a
            // producer-named subset is `or_set_delta`'s job instead.
            let element_match = match projection.get("match") {
                None => None,
                Some(rule) => {
                    let element_field = rule
                        .get("element_field")
                        .and_then(Value::as_str)
                        .ok_or_else(|| {
                            effect_set_error(
                                kind,
                                "or_set_remove_observed match omits element_field",
                            )
                        })?;
                    let expected = effect_source_value(
                        event,
                        write,
                        rule.get("source").ok_or_else(|| {
                            effect_set_error(kind, "or_set_remove_observed match omits source")
                        })?,
                        kind,
                        dot,
                        digest_suite,
                    )?;
                    Some(ObservedRemoveMatch {
                        element_field: element_field.to_owned(),
                        expected,
                    })
                }
            };
            Ok(vec![ProjectedOp::RemoveObserved { element_match }])
        }
        "or_set_remove_dots" => {
            require_lattice(kind, projection_kind, lattice, &["or_set"])?;
            let dots = source("dots")?;
            let dots = dots.as_array().ok_or_else(|| {
                effect_set_error(kind, "or_set_remove_dots dots must be an array")
            })?;
            if dots.is_empty() {
                return Err(effect_set_error(
                    kind,
                    "or_set_remove_dots dots must not be empty",
                ));
            }
            let mut seen = BTreeMap::new();
            dots.iter()
                .map(|value| {
                    let dot = value.as_str().ok_or_else(|| {
                        effect_set_error(kind, "or_set_remove_dots dots must be strings")
                    })?;
                    validate_or_set_dot(dot).map_err(|message| effect_set_error(kind, &message))?;
                    if seen.insert(dot, ()).is_some() {
                        return Err(effect_set_error(
                            kind,
                            "or_set_remove_dots dots must be unique",
                        ));
                    }
                    let mut op = LatticeOp::empty();
                    op.op_type = LatticeOpType::Remove;
                    op.tag = Some(dot.to_owned());
                    Ok(ProjectedOp::Direct(op))
                })
                .collect()
        }
        "or_set_batch_add" => {
            require_lattice(kind, projection_kind, lattice, &["or_set"])?;
            let tag_context = projection
                .get("tag_context")
                .and_then(Value::as_str)
                .ok_or_else(|| effect_set_error(kind, "or_set_batch_add omits tag_context"))?;
            let values = source("values")?;
            let mut sorted = values
                .as_array()
                .ok_or_else(|| effect_set_error(kind, "or_set_batch_add values must be an array"))?
                .clone();
            // Canonical value order, not payload order: independent receivers
            // MUST derive the same numbered tag set for the same value set.
            sorted.sort_by_cached_key(|value| {
                arkret_canonical::canonical_json_bytes(value).unwrap_or_default()
            });
            if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
                return Err(effect_set_error(
                    kind,
                    "or_set_batch_add values must be unique",
                ));
            }
            sorted
                .into_iter()
                .enumerate()
                .map(|(index, value)| {
                    let mut op = LatticeOp::empty();
                    op.op_type = LatticeOpType::Add;
                    let _ = index;
                    op.tag = Some(batch_add_tag(tag_context, dot, &value, kind)?);
                    op.value = Some(value);
                    Ok(ProjectedOp::Direct(op))
                })
                .collect()
        }
        "or_set_delta" => {
            require_lattice(kind, projection_kind, lattice, &["or_set"])?;
            let selector = projection
                .get("selector")
                .and_then(Value::as_str)
                .ok_or_else(|| effect_set_error(kind, "or_set_delta omits selector"))?;
            let discriminator = field_value(event, selector)
                .and_then(Value::as_str)
                .ok_or_else(|| effect_set_error(kind, "or_set_delta selector is missing"))?;
            let branch = projection
                .get("branches")
                .and_then(Value::as_object)
                .and_then(|branches| branches.get(discriminator))
                .ok_or_else(|| {
                    effect_set_error(
                        kind,
                        &format!("or_set_delta selector has no branch for {discriminator}"),
                    )
                })?;
            let branch_op = branch
                .get("op")
                .and_then(Value::as_str)
                .ok_or_else(|| effect_set_error(kind, "or_set_delta branch omits op"))?;
            let branch_source = |member: &str| -> Result<Value, EventCellContractError> {
                effect_source_value(
                    event,
                    write,
                    branch.get(member).ok_or_else(|| {
                        effect_set_error(kind, &format!("or_set_delta branch omits {member}"))
                    })?,
                    kind,
                    dot,
                    digest_suite,
                )
            };
            let mut op = LatticeOp::empty();
            op.tag = Some(or_set_tag(
                event,
                write,
                branch.get("tag"),
                kind,
                dot,
                digest_suite,
            )?);
            match branch_op {
                "add" => {
                    op.op_type = LatticeOpType::Add;
                    op.value = Some(branch_source("value")?);
                }
                "remove" => op.op_type = LatticeOpType::Remove,
                other => {
                    return Err(effect_set_error(
                        kind,
                        &format!("unknown or_set_delta op {other}"),
                    ));
                }
            }
            Ok(vec![ProjectedOp::Direct(op)])
        }
        other => Err(effect_set_error(
            kind,
            &format!("unknown effect_projection kind {other}"),
        )),
    }
}

fn validate_or_set_dot(dot: &str) -> Result<(), String> {
    let (event_id, write_index) = dot
        .rsplit_once(':')
        .ok_or_else(|| "or_set_remove_dots contains a non-canonical dot".to_owned())?;
    EventId::new(event_id.to_owned())
        .map_err(|_| "or_set_remove_dots contains a non-canonical dot".to_owned())?;
    let parsed = write_index
        .parse::<usize>()
        .map_err(|_| "or_set_remove_dots contains a non-canonical dot".to_owned())?;
    if parsed.to_string() != write_index {
        return Err("or_set_remove_dots contains a non-canonical dot".to_owned());
    }
    Ok(())
}

/// `dot = "ak:event:" + event_id + ":" + write_index`
/// (`zh/models/event-and-patch.md` section 2.4.2).
///
/// `write_index` is the 0-based index of the write in the registry
/// `cell_writes[]`, which is the only such quantity that survived the deletion
/// of the producer `effects[]` array and is still recomputable by a receiver
/// from the signed envelope plus the registry. It is `0` for every
/// single-target contract, so previously issued single-target dots keep their
/// value. A payload array index, arrival order or a local counter is
/// non-conforming.
///
/// Public because it is a normative encoding pinned by
/// `ak.vector.encoding.or_set_dot_and_batch_tag.v1`: a caller that needs the dot
/// must read it from here rather than re-deriving the format string.
pub fn or_set_dot(event_id: &str, write_index: usize) -> String {
    format!("{event_id}:{write_index}")
}

/// Evaluate an `or_set` op tag.
///
/// A bare `{"envelope_field":"event_id"}` is rejected: it is not unique when a
/// single Event writes several `or_set` targets, so it cannot identify an
/// element.
fn or_set_tag(
    event: &Event,
    write: &Value,
    source: Option<&Value>,
    kind: &str,
    dot: &str,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<String, EventCellContractError> {
    let source = source.ok_or_else(|| effect_set_error(kind, "or_set op omits its tag source"))?;
    if source.get("envelope_field").and_then(Value::as_str) == Some("event_id") {
        return Err(effect_set_error(
            kind,
            "or_set tag must use {\"dot\": true}; a bare event_id is not a dot",
        ));
    }
    effect_source_value(event, write, source, kind, dot, digest_suite)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| effect_set_error(kind, "or_set tag must derive a string"))
}

/// `batch_tag(i) = base64url_nopad(sha256(utf8(tag_context) || 0x0A ||
/// utf8(dot) || 0x0A || canonical_json(values[i])))`
/// (`zh/models/event-and-patch.md` section 2.4.2), isomorphic to the
/// `string_set_digest` construction of `encoding.md` section 9.5.1: inner
/// SHA-256, exactly one `0x0A` between parts, no length prefix, no trailing
/// newline. Pinned by `ak.vector.encoding.or_set_dot_and_batch_tag.v1`, which is
/// why it is public alongside [`or_set_dot`].
pub fn batch_add_tag(
    tag_context: &str,
    dot: &str,
    value: &Value,
    kind: &str,
) -> Result<String, EventCellContractError> {
    if tag_context.is_empty() || !tag_context.is_ascii() {
        return Err(effect_set_error(
            kind,
            "or_set_batch_add tag_context must be a non-empty ASCII string",
        ));
    }
    let canonical_value = arkret_canonical::canonical_json_bytes(value)
        .map_err(|error| effect_set_error(kind, &error.to_string()))?;
    let mut preimage =
        Vec::with_capacity(tag_context.len() + dot.len() + 2 + canonical_value.len());
    preimage.extend_from_slice(tag_context.as_bytes());
    preimage.push(b'\n');
    preimage.extend_from_slice(dot.as_bytes());
    preimage.push(b'\n');
    preimage.extend_from_slice(&canonical_value);
    Ok(arkret_canonical::sha256_base64url(preimage))
}

/// Evaluate one closed projection source.
///
/// The grammar admits exactly one of `field`, `envelope_field`, `const`,
/// `projected_value` or `dot`. `projected_value` is legal only when the same
/// cell write declares a closed `value_projection`; `dot` is legal only in an
/// `or_set` tag position, which [`or_set_tag`] is the only caller of. Anything
/// else means the registry and the Event cannot be evaluated together, which
/// fails closed.
/// Whether a projection kind removes from an `or_set` rather than adding to it.
fn is_or_set_remove(projection_kind: &str) -> bool {
    matches!(
        projection_kind,
        "or_set_remove_observed" | "or_set_remove_dots"
    )
}

fn effect_source_value(
    event: &Event,
    write: &Value,
    source: &Value,
    kind: &str,
    dot: &str,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Value, EventCellContractError> {
    let source = source
        .as_object()
        .ok_or_else(|| effect_set_error(kind, "effect source must be an object"))?;
    if source.len() != 1 {
        return Err(effect_set_error(
            kind,
            "effect source must contain exactly one member",
        ));
    }
    if source.get("dot").and_then(Value::as_bool) == Some(true) {
        return Ok(Value::String(dot.to_owned()));
    }
    if source.get("projected_value").and_then(Value::as_bool) == Some(true) {
        let rule = write.get("value_projection").ok_or_else(|| {
            effect_set_error(
                kind,
                "projected_value source requires a declared value_projection",
            )
        })?;
        let rule_json = serde_json::to_string(rule)
            .map_err(|error| effect_set_error(kind, &error.to_string()))?;
        return derive_value_projection(event, &rule_json, digest_suite);
    }
    if let Some(path) = source.get("field").and_then(Value::as_str) {
        // `"payload"` names the complete signed payload object, which is how
        // every facet cell that stores its payload verbatim is declared. It has
        // no dotted member suffix, so [`field_value`] — which walks members —
        // cannot resolve it and would fail the whole Event closed.
        if path == "payload" {
            return Ok(payload_root(event));
        }
        return field_value(event, path)
            .cloned()
            .ok_or_else(|| effect_set_error(kind, &format!("effect source {path} is missing")));
    }
    if let Some(field) = source.get("envelope_field").and_then(Value::as_str) {
        let envelope = serde_json::to_value(event)
            .map_err(|error| effect_set_error(kind, &error.to_string()))?;
        return envelope
            .get(field)
            .cloned()
            .ok_or_else(|| effect_set_error(kind, &format!("envelope field {field} is missing")));
    }
    if let Some(value) = source.get("const") {
        return Ok(value.clone());
    }
    Err(effect_set_error(
        kind,
        "effect source must declare field, envelope_field, const, projected_value, or dot",
    ))
}

fn condition_matches(
    event: &Event,
    condition: Option<&Value>,
    kind: &str,
) -> Result<bool, EventCellContractError> {
    let Some(condition) = condition else {
        return Ok(true);
    };
    let condition_kind = condition
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| effect_set_error(kind, "condition omits kind"))?;
    let present = |path: &str| field_value(event, path).is_some_and(|value| !value.is_null());
    match condition_kind {
        "field_present" => condition
            .get("field")
            .and_then(Value::as_str)
            .map(present)
            .ok_or_else(|| effect_set_error(kind, "field_present omits field")),
        "field_absent" => condition
            .get("field")
            .and_then(Value::as_str)
            .map(|path| !present(path))
            .ok_or_else(|| effect_set_error(kind, "field_absent omits field")),
        "field_equals" => {
            let path = condition
                .get("field")
                .and_then(Value::as_str)
                .ok_or_else(|| effect_set_error(kind, "field_equals omits field"))?;
            let expected = condition
                .get("const")
                .ok_or_else(|| effect_set_error(kind, "field_equals omits const"))?;
            if !matches!(
                expected,
                Value::String(_) | Value::Number(_) | Value::Bool(_)
            ) {
                return Err(effect_set_error(
                    kind,
                    "field_equals const must be a string, number, or boolean",
                ));
            }
            Ok(field_value(event, path) == Some(expected))
        }
        "any_field_present" => {
            let fields = condition
                .get("fields")
                .and_then(Value::as_array)
                .ok_or_else(|| effect_set_error(kind, "any_field_present omits fields"))?;
            if fields.len() < 2 || fields.iter().any(|field| field.as_str().is_none()) {
                return Err(effect_set_error(
                    kind,
                    "any_field_present requires at least two string fields",
                ));
            }
            Ok(fields.iter().filter_map(Value::as_str).any(present))
        }
        other => Err(effect_set_error(
            kind,
            &format!("unknown condition kind {other}"),
        )),
    }
}

fn effect_set_error(kind: &str, message: &str) -> EventCellContractError {
    EventCellContractError::EffectSetMismatch {
        kind: kind.to_owned(),
        message: message.to_owned(),
    }
}

/// Recompute a registry-declared `op.value` projection from the signed payload.
fn derive_value_projection(
    event: &Event,
    rule_json: &str,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Value, EventCellContractError> {
    let kind = event.kind.as_str().to_owned();
    let rule: Value = serde_json::from_str(rule_json).map_err(|error| {
        EventCellContractError::SubjectDerivation {
            kind: kind.clone(),
            message: error.to_string(),
        }
    })?;
    if rule.get("kind").and_then(Value::as_str) != Some("object") {
        return Err(projection_error(
            &kind,
            "value projection kind must be object",
        ));
    }
    let members = rule
        .get("members")
        .and_then(Value::as_array)
        .ok_or_else(|| projection_error(&kind, "value projection members are missing"))?;

    let mut projected = serde_json::Map::new();
    for member in members {
        let name = member
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| projection_error(&kind, "value projection member is unnamed"))?;
        let optional = member
            .get("optional")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        if let Some(literal) = member.get("literal") {
            projected.insert(name.to_owned(), literal.clone());
            continue;
        }
        let resolved = if let Some(path) = member.get("field").and_then(Value::as_str) {
            field_value(event, path).cloned()
        } else if let Some(component) = member.get("select") {
            let path = select_field_path(event, component, &kind)?;
            field_value(event, &path).cloned()
        } else if let Some(digest_of) = member.get("digest_of") {
            member_digest(event, digest_of, &kind, digest_suite)?
        } else {
            return Err(projection_error(
                &kind,
                &format!("member {name} declares no source"),
            ));
        };
        match resolved {
            // Absent optional members are omitted, never written as null.
            None if optional => continue,
            None => {
                return Err(projection_error(
                    &kind,
                    &format!("member {name} is missing"),
                ));
            }
            Some(value) => {
                projected.insert(name.to_owned(), value);
            }
        }
    }
    Ok(Value::Object(projected))
}

/// Compute a `digest_of` member over its declared input encoding.
fn member_digest(
    event: &Event,
    digest_of: &Value,
    kind: &str,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Option<Value>, EventCellContractError> {
    // The whole-payload input has no field path: it commits to every signed
    // byte, so a projection cannot silently lose a semantically relevant field
    // as the payload evolves (device-lifecycle.md 13.0.1).
    if digest_of.get("input").and_then(Value::as_str) == Some("event_payload_canonical_bytes") {
        let payload = payload_root(event);
        let bytes = arkret_canonical::canonical_json_bytes(&payload)
            .map_err(|error| projection_error(kind, &error.to_string()))?;
        return Ok(Some(Value::String(arkret_canonical::digest(
            digest_suite,
            &bytes,
        ))));
    }
    let path = digest_of
        .get("field")
        .and_then(Value::as_str)
        .ok_or_else(|| projection_error(kind, "digest_of field is missing"))?;
    let Some(source) = field_value(event, path) else {
        return Ok(None);
    };
    let bytes = match digest_of.get("input").and_then(Value::as_str) {
        // Digesting the base64url text instead of the decoded ciphertext is
        // explicitly forbidden by `conformance/encoding.md` §10.
        Some("base64url_decoded_bytes") => {
            let encoded = source
                .as_str()
                .ok_or_else(|| projection_error(kind, &format!("{path} must be a string")))?;
            arkret_canonical::base64url_decode(encoded)
                .map_err(|error| projection_error(kind, &error.to_string()))?
        }
        Some("canonical_json_bytes") => arkret_canonical::canonical_json_bytes(source)
            .map_err(|error| projection_error(kind, &error.to_string()))?,
        other => {
            return Err(projection_error(
                kind,
                &format!(
                    "unsupported digest_of input {}",
                    other.unwrap_or("<missing>")
                ),
            ));
        }
    };
    // device-lifecycle.md 13.0.1: the wire form follows the Realm's active
    // `digest_algorithm`. Hard-coding SHA-256 would make a blake3 Realm's
    // `op.value` — and therefore its state root — diverge from any conformant
    // implementation.
    Ok(Some(Value::String(arkret_canonical::digest(
        digest_suite,
        &bytes,
    ))))
}

fn projection_error(kind: &str, message: &str) -> EventCellContractError {
    EventCellContractError::SubjectDerivation {
        kind: kind.to_owned(),
        message: message.to_owned(),
    }
}

fn validate_plane(
    event: &Event,
    plane: Option<&str>,
    context: EventCellContractContext,
) -> Result<(), EventCellContractError> {
    let kind = event.kind.as_str().to_owned();
    let matches = match (plane, context) {
        (Some("control"), EventCellContractContext::Standard) => {
            event.seal_basis.is_some() && event.seal_ref.is_none() && event.auth_context.is_none()
        }
        (Some("data"), EventCellContractContext::Standard) => {
            event.seal_basis.is_none() && event.seal_ref.is_some() && event.auth_context.is_some()
        }
        (Some("control"), EventCellContractContext::OrdinaryRealmBootstrap) => {
            event.seal_basis.is_none() && event.seal_ref.is_none() && event.auth_context.is_none()
        }
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(EventCellContractError::PlaneMismatch {
            kind,
            expected: plane.unwrap_or("registered").to_owned(),
        })
    }
}

fn derive_subject(
    event: &Event,
    rule_json: Option<&str>,
) -> Result<String, EventCellContractError> {
    let kind = event.kind.as_str().to_owned();
    let Some(rule_json) = rule_json else {
        // `cell_subject: null` is a per-Realm singleton located by the Event
        // envelope `realm_id`. Its canonical wire subject segment is the literal
        // ASCII string `null` (`conformance/encoding.md` section 4). Encoding the
        // Realm id here instead would fork the `state_root` leaf set and leaf
        // order against any implementation that follows the spec.
        return Ok(NULL_CELL_SUBJECT.to_owned());
    };
    let rule: Value = serde_json::from_str(rule_json).map_err(|error| {
        EventCellContractError::SubjectDerivation {
            kind: kind.clone(),
            message: error.to_string(),
        }
    })?;
    let rule_kind = rule.get("kind").and_then(Value::as_str).unwrap_or_default();
    match rule_kind {
        "composite" => {
            let components = rule
                .get("components")
                .and_then(Value::as_array)
                .ok_or_else(|| subject_error(&kind, "composite components are missing"))?;
            derive_composite(event, components, &kind)
        }
        "tuple" => {
            let components = rule
                .get("components")
                .and_then(Value::as_array)
                .ok_or_else(|| subject_error(&kind, "tuple components are missing"))?;
            let fields = components
                .iter()
                .map(|component| {
                    component
                        .get("field")
                        .cloned()
                        .ok_or_else(|| subject_error(&kind, "tuple component field is missing"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            derive_composite(event, &fields, &kind)
        }
        "coalesce" => {
            let fields = rule
                .get("fields")
                .and_then(Value::as_array)
                .ok_or_else(|| subject_error(&kind, "coalesce fields are missing"))?;
            for field in fields {
                let Some(path) = field.as_str() else {
                    continue;
                };
                if let Some(value) = field_value(event, path) {
                    return scalar_subject(value).map_err(|message| subject_error(&kind, &message));
                }
                if let Some(value) = envelope_field(event, path) {
                    return Ok(value);
                }
            }
            Err(subject_error(&kind, "no coalesce field is present"))
        }
        _ => {
            let path = rule
                .get("field")
                .and_then(Value::as_str)
                .ok_or_else(|| subject_error(&kind, "cell subject field is missing"))?;
            if let Some(value) = field_value(event, path) {
                return scalar_subject(value).map_err(|message| subject_error(&kind, &message));
            }
            envelope_field(event, path)
                .ok_or_else(|| subject_error(&kind, &format!("{path} is missing")))
        }
    }
}

fn derive_composite(
    event: &Event,
    components: &[Value],
    kind: &str,
) -> Result<String, EventCellContractError> {
    let parts = components
        .iter()
        .map(|component| component_value(event, component, kind))
        .collect::<Result<Vec<_>, _>>()?;
    arkret_wire::cell::composite_subject(&parts)
        .map_err(|error| subject_error(kind, &error.to_string()))
}

/// Resolve one composite component: either a plain field path or a
/// discriminated `select` (`conformance/encoding.md` §9.5.1).
fn component_value(
    event: &Event,
    component: &Value,
    kind: &str,
) -> Result<Value, EventCellContractError> {
    if let Some(path) = component.as_str() {
        let value = subject_field_value(event, path)
            .ok_or_else(|| subject_error(kind, &format!("{path} is missing")))?;
        return composite_scalar(value.as_ref()).map_err(|message| subject_error(kind, &message));
    }
    if component.get("kind").and_then(Value::as_str) == Some("string_set_digest") {
        return string_set_digest_component_value(event, component, kind);
    }
    let path = select_field_path(event, component, kind)?;
    let value = subject_field_value(event, &path)
        .ok_or_else(|| subject_error(kind, &format!("{path} is missing")))?;
    composite_scalar(value.as_ref()).map_err(|message| subject_error(kind, &message))
}

fn string_set_digest_component_value(
    event: &Event,
    component: &Value,
    kind: &str,
) -> Result<Value, EventCellContractError> {
    let object = component
        .as_object()
        .ok_or_else(|| subject_error(kind, "string_set_digest component must be an object"))?;
    if object.len() != 3
        || !object.contains_key("kind")
        || !object.contains_key("field")
        || !object.contains_key("context")
    {
        return Err(subject_error(
            kind,
            "string_set_digest component must contain only kind, field, and context",
        ));
    }
    let path = object
        .get("field")
        .and_then(Value::as_str)
        .filter(|path| path.starts_with("payload."))
        .ok_or_else(|| {
            subject_error(
                kind,
                "string_set_digest component field must be an explicit payload path",
            )
        })?;
    let context = object
        .get("context")
        .and_then(Value::as_str)
        .ok_or_else(|| subject_error(kind, "string_set_digest component context is missing"))?;
    if kind == "ak.identity.accountability_grant" && context != "ak.accountability-scope-set-v1" {
        return Err(subject_error(
            kind,
            "accountability_scope string-set digest context is invalid",
        ));
    }
    let value = subject_field_value(event, path)
        .ok_or_else(|| subject_error(kind, &format!("{path} is missing")))?;
    let values = match value.as_ref() {
        Value::String(value) => vec![value.clone()],
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value.as_str().map(str::to_owned).ok_or_else(|| {
                    subject_error(kind, "string_set_digest array elements must be strings")
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        _ => {
            return Err(subject_error(
                kind,
                "string_set_digest source must be a string or string array",
            ));
        }
    };
    if kind == "ak.identity.accountability_grant"
        && values.iter().any(|value| {
            !matches!(
                value.as_str(),
                "employment" | "contracted_service" | "agent_operator"
            )
        })
    {
        return Err(subject_error(
            kind,
            "accountability_scope contains an unregistered value",
        ));
    }
    arkret_wire::string_set_digest_component(&values, context)
        .map(Value::String)
        .map_err(|error| subject_error(kind, &error.to_string()))
}

/// Evaluate a `select` component and return the selected field path.
///
/// The discriminator is read as the schema-validated raw string and matched
/// byte-for-byte against the closed branch map: no case folding, Unicode
/// normalisation or alias resolution.
///
/// Branch exclusivity comes only from the selected branch's declared
/// `forbidden_fields`. Treating "an unselected branch's field is present" as
/// ambiguity would be wrong in general: branches legitimately share fields —
/// an `effective_scope` with `kind="circle"` is required by schema to carry
/// `realm_id` as well, which is exactly the `realm` branch's value field.
fn select_field_path(
    event: &Event,
    component: &Value,
    kind: &str,
) -> Result<String, EventCellContractError> {
    if component.get("kind").and_then(Value::as_str) != Some("select") {
        return Err(subject_error(
            kind,
            "composite component has an unknown kind",
        ));
    }
    let selector = component
        .get("selector")
        .and_then(Value::as_str)
        .ok_or_else(|| subject_error(kind, "select component is missing selector"))?;
    let branches = component
        .get("branches")
        .and_then(Value::as_object)
        .ok_or_else(|| subject_error(kind, "select component is missing branches"))?;
    let discriminator_value = subject_field_value(event, selector)
        .ok_or_else(|| subject_error(kind, &format!("selector {selector} is missing")))?;
    let discriminator = discriminator_value
        .as_ref()
        .as_str()
        .ok_or_else(|| subject_error(kind, &format!("selector {selector} is not a string")))?;
    let branch = branches.get(discriminator).ok_or_else(|| {
        subject_error(
            kind,
            &format!("selector {selector} has no registered branch"),
        )
    })?;
    let selected = branch
        .get("field")
        .and_then(Value::as_str)
        .ok_or_else(|| subject_error(kind, "selected branch declares no field"))?;
    // Only the fields this branch explicitly forbids make the payload
    // ambiguous. The registry mirrors the wire schema's exclusivity here so
    // derivation still fails closed off the schema-validated path.
    for forbidden in branch
        .get("forbidden_fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if subject_field_value(event, forbidden).is_some() {
            return Err(subject_error(
                kind,
                &format!("forbidden field {forbidden} is present for branch {discriminator}"),
            ));
        }
    }
    Ok(selected.to_owned())
}

/// The complete signed payload as one JSON object.
fn payload_root(event: &Event) -> Value {
    Value::Object(event.payload.clone().into_iter().collect())
}

fn field_value<'a>(event: &'a Event, path: &str) -> Option<&'a Value> {
    let path = path.strip_prefix("payload.")?;
    let mut segments = path.split('.');
    let first = segments.next()?;
    let mut current = event.payload.get(first)?;
    for segment in segments {
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

/// Resolve a subject path that names a registered Event Envelope field.
///
/// `event-and-patch.md` section 2.4.2 derives a cell subject from "the Event
/// Envelope and payload", and `ak.invite.accept` relies on that: its
/// `ak.component.member.state.v1` subject is the envelope `actor_id`, the
/// invitee who submitted the acceptance. The namespace and set are closed: v1
/// accepts only the explicit `envelope.actor_id` source and never guesses from
/// a bare name or payload-first fallback.
fn envelope_field(event: &Event, path: &str) -> Option<String> {
    match path {
        "envelope.actor_id" => Some(event.actor_id.as_str().to_owned()),
        _ => None,
    }
}

fn subject_field_value<'a>(event: &'a Event, path: &str) -> Option<Cow<'a, Value>> {
    field_value(event, path)
        .map(Cow::Borrowed)
        .or_else(|| envelope_field(event, path).map(|value| Cow::Owned(Value::String(value))))
}

fn composite_scalar(value: &Value) -> Result<Value, String> {
    match value {
        Value::String(_) | Value::Bool(_) | Value::Null => Ok(value.clone()),
        Value::Number(number) if number.is_i64() || number.is_u64() => Ok(value.clone()),
        _ => Err(
            "composite subject component must be a JSON string, integer, boolean, or null"
                .to_owned(),
        ),
    }
}

fn scalar_subject(value: &Value) -> Result<String, String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        _ => Err("cell subject field must be a scalar".to_owned()),
    }
}

fn subject_error(kind: &str, message: &str) -> EventCellContractError {
    EventCellContractError::SubjectDerivation {
        kind: kind.to_owned(),
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::events::kinds::EventKind;
    use serde_json::json;

    use super::*;

    /// Every registered cell write a receiver derives for `event`.
    ///
    /// A producer supplies no effect at all, so this projection — not anything
    /// carried on the wire — is the subject of every assertion below.
    fn project(event: &Event) -> Vec<ProjectedCellWrite> {
        project_registered_cell_writes(event, arkret_canonical::DigestSuite::Sha256)
            .expect("the registered contract must be evaluable")
    }

    fn write(cell: &str, op: ProjectedOp) -> ProjectedCellWrite {
        ProjectedCellWrite {
            cell: CellRef::new(cell).unwrap(),
            op,
        }
    }

    fn set_op(value: Value) -> ProjectedOp {
        let mut op = LatticeOp::empty();
        op.value = Some(value);
        ProjectedOp::Direct(op)
    }

    fn transition_op(from: Value, to: Value) -> ProjectedOp {
        let mut op = LatticeOp::empty();
        op.op_type = LatticeOpType::Transition;
        op.from = Some(from);
        op.to = Some(to);
        ProjectedOp::Direct(op)
    }

    fn add_op(tag: &str, value: Value) -> ProjectedOp {
        let mut op = LatticeOp::empty();
        op.op_type = LatticeOpType::Add;
        op.tag = Some(tag.to_owned());
        op.value = Some(value);
        ProjectedOp::Direct(op)
    }

    fn remove_op(tag: &str) -> ProjectedOp {
        let mut op = LatticeOp::empty();
        op.op_type = LatticeOpType::Remove;
        op.tag = Some(tag.to_owned());
        ProjectedOp::Direct(op)
    }

    fn append_op(value: Value, issuer_seq: u64) -> ProjectedOp {
        let mut op = LatticeOp::empty();
        op.op_type = LatticeOpType::Append;
        op.value = Some(value);
        op.issuer_seq = Some(issuer_seq);
        ProjectedOp::Direct(op)
    }

    /// `event-auth-state-resolution.md` §9.5 recovery, built as a Control Move.
    fn conflict_recovery_event(target_cell: &str, resolved: Value) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:019f9e50-d787-74e0-8731-c9ad5eaa9190",
            "kind": "ak.state.conflict_recovery",
            "realm_id": "ak:realm:019f9e50-d787-74e0-8731-c9ad5eaa9180",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:019f9e50-d787-74e0-8731-c9ad5eaa9180"},
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "actor_seq": 9,
            "created_at": "2026-07-26T01:00:00.000Z",
            "hlc": "019f9e500000-0000-aabbccde",
            "prev_refs": [],
            "seal_basis": {
                "leaves": ["ak:seal:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"],
                "control_event_set_root": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "state_root": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "refs": [
                {"role": "recovery_capability", "critical": true,
                 "id": "ak:grant:019641d2-2000-7000-8000-000000000000"},
                {"role": "state_witness", "critical": true,
                 "id": "ak:seal:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
            ],
            "payload": {"target_cell": target_cell, "resolved_value": resolved},
            "proofs": []
        }))
        .expect("conflict recovery fixture must deserialize")
    }

    #[test]
    fn conflict_recovery_resets_the_cell_named_by_the_signed_payload() {
        // The target is not statically addressable: it comes from the payload,
        // so the same kind recovers cells of different families.
        for family in [
            "ak.component.realm.policy.v1",
            "ak.component.member.state.v1",
        ] {
            let cell = format!("ak:cell:{family}:null");
            let event = conflict_recovery_event(&cell, json!({"policy_revision": 8}));
            assert_eq!(
                project(&event),
                vec![write(
                    &cell,
                    ProjectedOp::Reset {
                        value: json!({"policy_revision": 8}),
                    },
                )],
            );
        }
    }

    #[test]
    fn conflict_recovery_without_a_target_cell_fails_closed() {
        let mut event =
            conflict_recovery_event("ak:cell:ak.component.realm.policy.v1:null", json!(1));
        event.payload.remove("target_cell");
        let error = project_registered_cell_writes(&event, arkret_canonical::DigestSuite::Sha256)
            .expect_err("a recovery with no target must not project a write");
        assert!(
            error.to_string().contains("target_cell"),
            "unexpected error: {error}"
        );
    }

    fn rsvp_event(occurrence: Value) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:019f9e50-d787-74e0-8731-c9ad5eaa9181",
            "kind": EventKind::RSVP_SET,
            "realm_id": "ak:realm:019f9e50-d787-74e0-8731-c9ad5eaa9180",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:019f9e50-d787-74e0-8731-c9ad5eaa9180"},
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "actor_seq": 7,
            "created_at": "2026-07-26T01:00:00.000Z",
            "hlc": "019f9e500000-0000-aabbccdd",
            "prev_refs": [],
            // `ak.rsvp.set` is registered on the data plane, so its CBA basis is
            // `seal_ref` plus `auth_context`, never a control `seal_basis`.
            "seal_ref": "ak:seal:sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "auth_context": {
                "did": "did:webvh:z6mkfixture:alice.example",
                "key_id": "ak:device:019f9e50-d787-74e0-8731-c9ad5eaa9183",
                "key_epoch": 1
            },
            "payload": {
                "event_ref": "ak:strand:019f9e50-d787-74e0-8731-c9ad5eaa9182",
                "occurrence": occurrence,
                "entry": {
                    "schedule_basis_refs": [
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    ],
                    "response": {"status": "accepted"}
                }
            },
            "proofs": []
        }))
        .unwrap()
    }

    #[test]
    fn rsvp_composite_preserves_null_and_explicit_envelope_actor() {
        let event = rsvp_event(Value::Null);
        let descriptor = event.kind.descriptor().unwrap();
        assert_eq!(
            derive_subject(&event, descriptor.cell_subject_rule).unwrap(),
            "3iBI9bjQLklvfcVhQeaxLajMskSVG4oZ5IMpU62GvRc"
        );
        validate_registered_cell_writes(&event).unwrap();

        // effect_projection = set(payload.entry): the lattice value is the whole
        // entry, so basis and response converge together as one head. A producer
        // cannot narrow it to the bare `"accepted"` status — it supplies no
        // effect at all, and the projection is what the reducer applies.
        assert_eq!(
            project(&event),
            vec![write(
                "ak:cell:ak.component.calendar.rsvp.v1:3iBI9bjQLklvfcVhQeaxLajMskSVG4oZ5IMpU62GvRc",
                set_op(event.payload.get("entry").unwrap().clone()),
            )]
        );

        let instance = rsvp_event(json!("2026-07-26T09:00:00[Asia/Shanghai]"));
        assert_eq!(
            derive_subject(&instance, descriptor.cell_subject_rule).unwrap(),
            "tc2S5LQybi5y3tI-hoyB6HoBWFepT_tDfFcmHJk_jd0"
        );
    }

    #[test]
    fn rsvp_composite_rejects_missing_invalid_and_unregistered_components() {
        let mut missing = rsvp_event(Value::Null);
        missing.payload.remove("occurrence");
        let rule = missing.kind.descriptor().unwrap().cell_subject_rule;
        assert!(matches!(
            derive_subject(&missing, rule),
            Err(EventCellContractError::SubjectDerivation { .. })
        ));

        for invalid in [
            json!({"not": "scalar"}),
            json!(["not", "scalar"]),
            json!(1.5),
        ] {
            let event = rsvp_event(invalid);
            assert!(matches!(
                derive_subject(&event, rule),
                Err(EventCellContractError::SubjectDerivation { .. })
            ));
        }

        let event = rsvp_event(Value::Null);
        assert!(matches!(
            component_value(&event, &json!("envelope.event_id"), EventKind::RSVP_SET),
            Err(EventCellContractError::SubjectDerivation { .. })
        ));
        assert!(matches!(
            component_value(&event, &json!("actor_id"), EventKind::RSVP_SET),
            Err(EventCellContractError::SubjectDerivation { .. })
        ));

        let mut shadow = rsvp_event(Value::Null);
        shadow.payload.insert(
            "actor_id".to_owned(),
            json!("did:webvh:z6mkfixture:mallory.example"),
        );
        assert_eq!(
            derive_subject(&shadow, rule).unwrap(),
            "3iBI9bjQLklvfcVhQeaxLajMskSVG4oZ5IMpU62GvRc"
        );

        let envelope_select = json!({
            "kind": "select",
            "selector": "envelope.actor_id",
            "branches": {
                "did:webvh:z6mkfixture:alice.example": {
                    "field": "envelope.actor_id"
                }
            }
        });
        assert_eq!(
            component_value(&event, &envelope_select, EventKind::RSVP_SET).unwrap(),
            json!("did:webvh:z6mkfixture:alice.example")
        );
    }

    fn subject_event(kind: &str, payload: Value) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:019f9e50-d787-74e0-8731-c9ad5eaa9181",
            "kind": kind,
            "realm_id": "ak:realm:019f9e50-d787-74e0-8731-c9ad5eaa9180",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:019f9e50-d787-74e0-8731-c9ad5eaa9180"},
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "actor_seq": 7,
            "created_at": "2026-07-26T01:00:00.000Z",
            "hlc": "019f9e500000-0000-aabbccdd",
            "prev_refs": [],
            "payload": payload,
            "proofs": []
        }))
        .unwrap()
    }

    fn registered_subject(kind: &str, payload: Value) -> String {
        let event = subject_event(kind, payload);
        derive_subject(&event, event.kind.descriptor().unwrap().cell_subject_rule).unwrap()
    }

    #[test]
    fn repaired_payload_paths_derive_every_registered_cell_subject() {
        for (kind, payload, expected) in [
            (
                "ak.organization.discovery",
                json!({"organization_did": "did:webvh:z6mkfixture:org.example"}),
                "did:webvh:z6mkfixture:org.example",
            ),
            (
                "ak.actor.discovery",
                json!({"resource_id": "did:webvh:z6mkfixture:actor.example"}),
                "did:webvh:z6mkfixture:actor.example",
            ),
            (
                "ak.applet.discovery",
                json!({"resource_id": "ak:applet:019f9e50-d787-74e0-8731-c9ad5eaa9182"}),
                "ak:applet:019f9e50-d787-74e0-8731-c9ad5eaa9182",
            ),
            (
                "ak.handle.discovery",
                json!({"resource_id": "@alice:example.org"}),
                "@alice:example.org",
            ),
            (
                "ak.did.proof",
                json!({"did": "did:webvh:z6mkfixture:alice.example"}),
                "did:webvh:z6mkfixture:alice.example",
            ),
            (
                "ak.identity.disclosure_policy",
                json!({"policy_id": "ak:policy:019f9e50-d787-74e0-8731-c9ad5eaa9182"}),
                "ak:policy:019f9e50-d787-74e0-8731-c9ad5eaa9182",
            ),
            (
                "ak.identity.disclosure_receipt",
                json!({"holder_did": "did:webvh:z6mkfixture:holder.example"}),
                "did:webvh:z6mkfixture:holder.example",
            ),
            (
                "ak.identity.presentation_request",
                json!({"request_id": "ak:request:019f9e50-d787-74e0-8731-c9ad5eaa9182"}),
                "ak:request:019f9e50-d787-74e0-8731-c9ad5eaa9182",
            ),
            (
                "ak.identity.presentation_response",
                json!({"request_id": "ak:request:019f9e50-d787-74e0-8731-c9ad5eaa9182"}),
                "ak:request:019f9e50-d787-74e0-8731-c9ad5eaa9182",
            ),
            (
                "ak.schema.define",
                json!({"schema_id": "ak.schema.fixture.v1"}),
                "ak.schema.fixture.v1",
            ),
            (
                "ak.schema.update",
                json!({"schema_id": "ak.schema.fixture.v1"}),
                "ak.schema.fixture.v1",
            ),
            (
                "ak.policy.set",
                json!({"policy_id": "ak:policy:019f9e50-d787-74e0-8731-c9ad5eaa9182"}),
                "ak:policy:019f9e50-d787-74e0-8731-c9ad5eaa9182",
            ),
            (
                "ak.policy.action",
                json!({"action_id": "ak:action:019f9e50-d787-74e0-8731-c9ad5eaa9182"}),
                "ak:action:019f9e50-d787-74e0-8731-c9ad5eaa9182",
            ),
            (
                "ak.sovereign.did_policy",
                json!({"trust_domain": "ak:trust_domain:fixture.example"}),
                "ak:trust_domain:fixture.example",
            ),
        ] {
            assert_eq!(registered_subject(kind, payload), expected);
        }

        assert_eq!(
            registered_subject(
                "ak.organization.moderation_policy",
                json!({"organization_id": "ak:organization:019f9e50-d787-74e0-8731-c9ad5eaa9182"})
            ),
            "ak:organization:019f9e50-d787-74e0-8731-c9ad5eaa9182"
        );
        // Only the object branch survives: arkret-spec 83341cc0 deleted the flat
        // {relation_id, kind, from_ref, to_ref} form, whose subject was
        // derivable but whose cell value was not — effect_projection is
        // `set value = payload.relation`, and §2.4.2 forbids assembling one.
        assert_eq!(
            registered_subject(
                "ak.relation.create",
                json!({"relation": {"id": "ak:relation:019f9e50-d787-74e0-8731-c9ad5eaa9182"}})
            ),
            "ak:relation:019f9e50-d787-74e0-8731-c9ad5eaa9182"
        );
        assert_eq!(
            registered_subject(
                "ak.profile.realm_override",
                json!({
                    "target_realm_id": "ak:realm:019f9e50-d787-74e0-8731-c9ad5eaa9180",
                    "target_ref": "ak:actor_profile:019f9e50-d787-74e0-8731-c9ad5eaa9182"
                })
            ),
            "S1MZHDKMf5kd80P1RGS85BD2prCffX7a3tNNg_Axy-4"
        );
    }

    fn accountability_event(scope: Value, status: &str) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:019f9e50-d787-74e0-8731-c9ad5eaa9190",
            "kind": EventKind::IDENTITY_ACCOUNTABILITY_GRANT,
            "realm_id": "ak:realm:019f9e50-d787-74e0-8731-c9ad5eaa9180",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:019f9e50-d787-74e0-8731-c9ad5eaa9180"},
            "actor_id": "did:web:issuer.example",
            "actor_seq": 7,
            "created_at": "2026-07-26T01:00:00.000Z",
            "hlc": "019f9e500000-0000-aabbccdd",
            "prev_refs": [],
            "payload": {
                "issuer": "did:web:issuer.example",
                "subject": "did:web:subject.example",
                "accountability_scope": scope,
                "grant_status": status
            },
            "proofs": []
        }))
        .unwrap()
    }

    fn accountability_subject(
        scope: Value,
        status: &str,
    ) -> Result<String, EventCellContractError> {
        let event = accountability_event(scope, status);
        derive_subject(&event, event.kind.descriptor().unwrap().cell_subject_rule)
    }

    #[test]
    fn accountability_string_set_subject_matches_kats_and_exact_set_semantics() {
        assert_eq!(
            accountability_subject(json!("employment"), "active").unwrap(),
            "0oP6kgegqj97KeJlIQS1HqrKqOlrC05vv5FbjOt26UI"
        );
        assert_eq!(
            accountability_subject(json!(["employment"]), "active").unwrap(),
            "0oP6kgegqj97KeJlIQS1HqrKqOlrC05vv5FbjOt26UI"
        );
        assert_eq!(
            accountability_subject(json!(["employment", "agent_operator"]), "active").unwrap(),
            "mpsZQ7e16PpEpIx5EzhcWbP75zwSFLxWVUhUci1Q_JQ"
        );
        assert_eq!(
            accountability_subject(json!(["agent_operator", "employment"]), "revoked").unwrap(),
            "mpsZQ7e16PpEpIx5EzhcWbP75zwSFLxWVUhUci1Q_JQ"
        );
        assert_eq!(
            accountability_subject(
                json!(["employment", "contracted_service", "agent_operator"]),
                "active"
            )
            .unwrap(),
            "_45SQjX2ZreUoyarM5jKLRPu718MCunon-ruoXbTRBw"
        );
        assert_ne!(
            accountability_subject(json!("employment"), "active").unwrap(),
            accountability_subject(json!("agent_operator"), "active").unwrap()
        );

        let baseline = accountability_subject(json!("employment"), "active").unwrap();
        let mut different_issuer = accountability_event(json!("employment"), "active");
        different_issuer
            .payload
            .insert("issuer".to_owned(), json!("did:web:other-issuer.example"));
        assert_ne!(
            derive_subject(
                &different_issuer,
                different_issuer
                    .kind
                    .descriptor()
                    .unwrap()
                    .cell_subject_rule
            )
            .unwrap(),
            baseline
        );
        let mut different_subject = accountability_event(json!("employment"), "active");
        different_subject
            .payload
            .insert("subject".to_owned(), json!("did:web:other-subject.example"));
        assert_ne!(
            derive_subject(
                &different_subject,
                different_subject
                    .kind
                    .descriptor()
                    .unwrap()
                    .cell_subject_rule
            )
            .unwrap(),
            baseline
        );
    }

    #[test]
    fn accountability_string_set_subject_fails_closed() {
        for invalid in [
            json!([]),
            json!(["employment", "employment"]),
            json!("administrator"),
            json!([1]),
            Value::Null,
            json!({"scope": "employment"}),
            json!([["employment"]]),
            json!("[\"employment\"]"),
        ] {
            assert!(matches!(
                accountability_subject(invalid, "active"),
                Err(EventCellContractError::SubjectDerivation { .. })
            ));
        }

        let event = accountability_event(json!("employment"), "active");
        let descriptor = json!({
            "kind": "string_set_digest",
            "field": "payload.accountability_scope",
            "context": "ak.accountability-scope-set-v1-wrong"
        });
        assert!(matches!(
            component_value(
                &event,
                &descriptor,
                EventKind::IDENTITY_ACCOUNTABILITY_GRANT
            ),
            Err(EventCellContractError::SubjectDerivation { .. })
        ));

        // The producer cannot name a grant cell of its own: the target follows
        // from the issuer, the subject and the exact accountability-scope set,
        // and the register value is the whole signed payload.
        assert_eq!(
            project(&event),
            vec![write(
                "ak:cell:ak.component.identity.accountability.v1:0oP6kgegqj97KeJlIQS1HqrKqOlrC05vv5FbjOt26UI",
                set_op(serde_json::to_value(&event.payload).unwrap()),
            )]
        );
    }

    fn realm_facet(kind: &str, payload: Value) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:019f9000-0000-7000-8000-000000000001",
            "kind": kind,
            "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002"},
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "actor_seq": 3,
            "created_at": "2026-07-20T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "preconditions": [],
            "seal_basis": {
                "leaves": ["ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                "control_event_set_root": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "state_root": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            },
            "payload": payload,
            "proofs": []
        }))
        .unwrap()
    }

    /// A member-device realm key share on the data plane.
    fn delivery_share_event() -> Event {
        let payload = json!({
            "share_kind": "member_device",
            "recipient_principal_id": "did:webvh:z6mkfixture:bob.example",
            "recipient_device_id": "ak:device:019f9000-0000-7000-8000-000000000003",
            "sender_device_id": "ak:device:019f9000-0000-7000-8000-000000000004",
            "source_authorization_ref": "ak:event:019f9000-0000-7000-8000-000000000005",
            "sender_device_signature": {
                "kid": "did:webvh:z6mkfixture:alice.example#ak:device:019f9000-0000-7000-8000-000000000004",
                "alg": "EdDSA",
                "sig": "AAAA"
            },
            "key_scope": {
                "effective_scope": {
                    "kind": "realm",
                    "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002"
                },
                "policy_digest": format!("sha256:{}", "aa".repeat(32)),
                "from_epoch": 1,
                "to_epoch": 3
            },
            "ciphertext": "Y2lwaGVy",
            "created_at": "2026-07-26T00:00:00.000Z"
        });
        serde_json::from_value(json!({
            "event_id": "ak:event:019f9000-0000-7000-8000-000000000001",
            "kind": EventKind::REALM_KEY_SHARE,
            "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002"},
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "actor_seq": 7,
            "created_at": "2026-07-26T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "seal_ref": "ak:seal:sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "auth_context": {
                "did": "did:webvh:z6mkfixture:alice.example",
                "key_id": "ak:device:019f9000-0000-7000-8000-000000000004",
                "key_epoch": 1
            },
            "payload": payload,
            "proofs": []
        }))
        .unwrap()
    }

    /// The delivery cell the member-device share KAT derives.
    const DELIVERY_CELL: &str =
        "ak:cell:ak.component.realm_key.delivery.v1:ks8W0G2dV6cCdf3LJSEVB5horGJplQNFyjP1qN5-FM4";

    #[test]
    fn validates_delivery_append_from_registry() {
        validate_registered_cell_writes(&delivery_share_event()).unwrap();
    }

    #[test]
    fn projects_delivery_append_from_registry() {
        // Was `materializes_delivery_append_from_registry`: nothing is stamped
        // onto the Event any more, so the assertion is on the derived append —
        // registry-projected value, envelope `actor_seq` as `issuer_seq`.
        let event = delivery_share_event();
        let rule = event
            .kind
            .descriptor()
            .unwrap()
            .value_projection_rule
            .unwrap();
        let value =
            derive_value_projection(&event, rule, arkret_canonical::DigestSuite::Sha256).unwrap();
        assert_eq!(
            project(&event),
            vec![write(DELIVERY_CELL, append_op(value, event.actor_seq))]
        );
    }

    fn invite_create_event(invitee: Option<&str>) -> Event {
        let mut payload = json!({
            "invite_id": "ak:invite:019f9000-0000-7000-8000-000000000010"
        });
        if let Some(invitee) = invitee {
            payload["invitee"] = json!(invitee);
        }
        serde_json::from_value(json!({
            "event_id": "ak:event:019f9000-0000-7000-8000-000000000011",
            "kind": EventKind::INVITE_CREATE,
            "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002"},
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "actor_seq": 4,
            "created_at": "2026-07-26T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "payload": payload,
            "proofs": []
        }))
        .unwrap()
    }

    const INVITE_LIFECYCLE_CELL: &str =
        "ak:cell:ak.component.invite.lifecycle.v1:ak:invite:019f9000-0000-7000-8000-000000000010";
    const BOB_MEMBER_CELL: &str =
        "ak:cell:ak.component.member.state.v1:did:webvh:z6mkfixture:bob.example";

    #[test]
    fn conditional_invite_member_target_is_exact() {
        // The producer picks neither the member cell nor the transition, so the
        // assertion is the exact projected set rather than a rejected mutation.
        // The lifecycle cell enters from null: `leave` is a member.state state,
        // and this Event's second write is the one that touches it.
        let directed = invite_create_event(Some("did:webvh:z6mkfixture:bob.example"));
        assert_eq!(
            project(&directed),
            vec![
                write(
                    INVITE_LIFECYCLE_CELL,
                    transition_op(json!(null), json!("pending")),
                ),
                write(
                    BOB_MEMBER_CELL,
                    ProjectedOp::TransitionTo {
                        to: json!("invite"),
                    },
                ),
            ]
        );

        // Without an invitee the conditional member write is inactive, so a
        // third-party invite touches the lifecycle cell only.
        let third_party = invite_create_event(None);
        assert_eq!(
            project(&third_party),
            vec![write(
                INVITE_LIFECYCLE_CELL,
                transition_op(json!(null), json!("pending")),
            )]
        );
    }

    #[test]
    fn invite_accept_member_target_uses_explicit_envelope_actor() {
        let event: Event = serde_json::from_value(json!({
            "event_id": "ak:event:019f9000-0000-7000-8000-000000000012",
            "kind": EventKind::INVITE_ACCEPT,
            "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002"},
            "actor_id": "did:webvh:z6mkfixture:bob.example",
            "actor_seq": 1,
            "created_at": "2026-07-26T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "payload": {
                "invite_id": "ak:invite:019f9000-0000-7000-8000-000000000010"
            },
            "proofs": []
        }))
        .unwrap();

        // The payload names no member at all: the joined member cell is the
        // envelope `actor_id`, the invitee who signed the acceptance.
        assert_eq!(
            project(&event),
            vec![
                write(
                    INVITE_LIFECYCLE_CELL,
                    transition_op(json!("pending"), json!("accepted")),
                ),
                write(
                    BOB_MEMBER_CELL,
                    ProjectedOp::TransitionTo { to: json!("join") }
                ),
            ]
        );
    }

    fn invite_terminal_event(kind: &str) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:019f9000-0000-7000-8000-000000000013",
            "kind": kind,
            "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002"},
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "actor_seq": 5,
            "created_at": "2026-07-26T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "payload": {
                "invite_id": "ak:invite:019f9000-0000-7000-8000-000000000010",
                "invitee": "did:webvh:z6mkfixture:bob.example",
                "target_state": "revoked"
            },
            "proofs": []
        }))
        .unwrap()
    }

    #[test]
    fn invite_terminal_member_transition_is_exact() {
        let expected = vec![
            write(
                INVITE_LIFECYCLE_CELL,
                ProjectedOp::TransitionTo {
                    to: json!("revoked"),
                },
            ),
            write(
                BOB_MEMBER_CELL,
                ProjectedOp::TransitionTo { to: json!("leave") },
            ),
        ];
        assert_eq!(
            project(&invite_terminal_event(EventKind::INVITE_REVOKE)),
            expected
        );

        let cancel = invite_terminal_event(EventKind::INVITE_CANCEL);
        let lifecycle = CellRef::new(INVITE_LIFECYCLE_CELL.to_owned()).unwrap();
        let mut pre_state = FrozenPreState::new();
        pre_state.insert(
            lifecycle.clone(),
            json!({"invitee": "did:webvh:z6mkfixture:bob.example"}),
        );
        assert_eq!(
            project_registered_cell_writes_with_pre_state(
                &cancel,
                arkret_canonical::DigestSuite::Sha256,
                &pre_state,
            )
            .unwrap(),
            expected
        );

        pre_state.clear();
        let missing = project_registered_cell_writes_with_pre_state(
            &cancel,
            arkret_canonical::DigestSuite::Sha256,
            &pre_state,
        )
        .unwrap_err();
        assert_eq!(missing.reason_code(), "invite_kind_requires_revoke");

        pre_state.insert(
            lifecycle,
            json!({"invitee": "did:webvh:z6mkfixture:mallory.example"}),
        );
        let mismatch = project_registered_cell_writes_with_pre_state(
            &cancel,
            arkret_canonical::DigestSuite::Sha256,
            &pre_state,
        )
        .unwrap_err();
        assert_eq!(mismatch.reason_code(), "reducer_projection_failed");
    }

    fn consent_revoke_event(observed_dots: Value) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:019f9000-0000-7000-8000-000000000015",
            "kind": EventKind::CONSENT_REVOKE,
            "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002"},
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "actor_seq": 6,
            "created_at": "2026-07-26T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "seal_basis": {
                "leaves": ["ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                "control_event_set_root": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "state_root": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            },
            "payload": {
                "consent_id": "ak:consent:019f9000-0000-7000-8000-000000000014",
                "observed_dots": observed_dots,
                "revoked_at": "2026-07-26T00:00:00.000Z"
            },
            "proofs": []
        }))
        .unwrap()
    }

    #[test]
    fn consent_revoke_projects_each_explicit_dot_in_payload_order() {
        let first = "ak:event:019f9000-0000-7000-8000-000000000011:0";
        let second = "ak:event:019f9000-0000-7000-8000-000000000012:3";
        assert_eq!(
            project(&consent_revoke_event(json!([first, second]))),
            vec![
                write(
                    "ak:cell:ak.component.consent.grant.v1:ak:consent:019f9000-0000-7000-8000-000000000014",
                    remove_op(first),
                ),
                write(
                    "ak:cell:ak.component.consent.grant.v1:ak:consent:019f9000-0000-7000-8000-000000000014",
                    remove_op(second),
                ),
            ],
        );
    }

    #[test]
    fn consent_revoke_rejects_empty_duplicate_and_noncanonical_dots() {
        for (dots, expected) in [
            (json!([]), "must not be empty"),
            (
                json!([
                    "ak:event:019f9000-0000-7000-8000-000000000011:0",
                    "ak:event:019f9000-0000-7000-8000-000000000011:0"
                ]),
                "must be unique",
            ),
            (
                json!(["ak:event:019f9000-0000-7000-8000-000000000011:00"]),
                "non-canonical dot",
            ),
            (json!(["not-a-dot"]), "non-canonical dot"),
        ] {
            let error = project_registered_cell_writes(
                &consent_revoke_event(dots),
                arkret_canonical::DigestSuite::Sha256,
            )
            .expect_err("invalid explicit dot arrays must fail closed");
            assert_eq!(error.reason_code(), "effects_payload_mismatch");
            assert!(
                error.to_string().contains(expected),
                "expected {expected}, got {error}"
            );
        }
    }

    #[test]
    fn fails_closed_when_a_projection_source_is_missing() {
        // `ak.invite.cancel` projects its lifecycle target state from
        // `payload.target_state`. A payload without it leaves the reducer with
        // no derivable write, which fails the whole Event closed rather than
        // falling back to an implementation-private default.
        let mut event = invite_terminal_event(EventKind::INVITE_CANCEL);
        event.payload.remove("target_state");
        let error = project_registered_cell_writes(&event, arkret_canonical::DigestSuite::Sha256)
            .unwrap_err();
        assert!(
            matches!(error, EventCellContractError::EffectSetMismatch { .. }),
            "got {error}"
        );
        assert_eq!(error.reason_code(), "effects_payload_mismatch");
    }

    #[test]
    fn realm_create_ordered_log_projection_is_exact() {
        let event: Event = serde_json::from_value(json!({
            "event_id": "ak:event:019f9000-0000-7000-8000-000000000021",
            "kind": EventKind::REALM_CREATE,
            "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000021",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000021"},
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "actor_seq": 7,
            "created_at": "2026-07-26T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "payload": {
                "object": {
                    "id": "ak:realm:019f9000-0000-7000-8000-000000000021",
                    "created_by": "did:webvh:z6mkfixture:alice.example",
                    "notary": {
                        "type": "single_did",
                        "did": "did:webvh:z6mkfixture:alice.example"
                    }
                }
            },
            "proofs": []
        }))
        .unwrap();

        let object = event.payload.get("object").unwrap().clone();
        // The genesis append carries the registry constant `issuer_seq: 0`, not
        // the envelope `actor_seq` of 7: it is the log's first entry by
        // construction, and a producer has no say in the sequence.
        assert_eq!(
            project(&event),
            vec![
                write(
                    "ak:cell:ak.component.realm.metadata.v1:null",
                    set_op(object.clone()),
                ),
                write(
                    "ak:cell:ak.component.member.state.v1:did:webvh:z6mkfixture:alice.example",
                    transition_op(json!("leave"), json!("join")),
                ),
                write(
                    arkret_wire::REALM_CREATE_CELL,
                    append_op(json!("ak:realm:019f9000-0000-7000-8000-000000000021"), 0),
                ),
                write(
                    "ak:cell:ak.component.notary.v1:null",
                    set_op(object["notary"].clone()),
                ),
            ]
        );
    }

    fn call_event(kind: &str, payload: Value) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:019f9000-0000-7000-8000-000000000021",
            "kind": kind,
            "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002"},
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "actor_seq": 5,
            "created_at": "2026-07-26T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "payload": payload,
            "proofs": []
        }))
        .unwrap()
    }

    #[test]
    fn conditional_call_axis_targets_are_exact() {
        let call_id = "ak:call:019f9000-0000-7000-8000-000000000022";
        let participant = json!({
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "device_id": "ak:device:019f9000-0000-7000-8000-000000000023"
        });
        let event = call_event(
            EventKind::CALL_STATE,
            json!({
                "call_id": call_id,
                "state_transition": {"from": "ringing", "to": "active"},
                "focus": {"mode": "sfu", "session_focus": "fra-1"},
                "roster_delta": {"op": "join", "participant": participant.clone()}
            }),
        );

        // Exactly the three axes the payload activates, in registry order. The
        // capture, moderation and mute axes stay out because their conditions
        // do not hold, and the roster tag is the registry dot for write index 7
        // — the producer chooses neither the tag nor the participant value.
        assert_eq!(
            project(&event),
            vec![
                write(
                    &format!("ak:cell:ak.component.call.state.v1:{call_id}"),
                    transition_op(json!("ringing"), json!("active")),
                ),
                write(
                    &format!("ak:cell:ak.component.call.focus.v1:{call_id}"),
                    set_op(json!({"mode": "sfu", "session_focus": "fra-1"})),
                ),
                write(
                    &format!("ak:cell:ak.component.call.roster.v1:{call_id}"),
                    add_op(
                        "ak:event:019f9000-0000-7000-8000-000000000021:7",
                        participant,
                    ),
                ),
            ]
        );
    }

    #[test]
    fn or_set_delta_rejects_an_unregistered_selector_branch() {
        let event = call_event(
            EventKind::CALL_STATE,
            json!({
                "call_id": "ak:call:019f9000-0000-7000-8000-000000000022",
                "roster_delta": {"op": "kick", "observed_dot": "ak:event:019f9000:0"}
            }),
        );
        let error = project_registered_cell_writes(&event, arkret_canonical::DigestSuite::Sha256)
            .unwrap_err();
        assert!(
            format!("{error}").contains("no branch for kick"),
            "closed branch map only; got {error}"
        );
    }

    #[test]
    fn capture_kind_selects_exactly_one_capture_family() {
        let call_id = "ak:call:019f9000-0000-7000-8000-000000000031";
        let recording_id = "capture-019f9000";
        let subject = arkret_wire::composite_subject(&[call_id, recording_id]).unwrap();
        let recording_result = json!({
            "recording_start_event_id": "ak:event:019f9000-0000-7000-8000-000000000021",
            "retention": {"consent_confirmed": true}
        });
        let recording = call_event(
            EventKind::CALL_RECORDING_START,
            json!({
                "call_id": call_id,
                "recording_id": recording_id,
                "capture_kind": "recording",
                "result": recording_result.clone()
            }),
        );
        assert_eq!(
            project(&recording),
            vec![
                write(
                    &format!("ak:cell:ak.component.call.recording.v1:{subject}"),
                    transition_op(Value::Null, json!("recording")),
                ),
                write(
                    &format!("ak:cell:ak.component.call.recording_result.v1:{subject}"),
                    set_op(recording_result),
                ),
            ]
        );

        // The `capture_kind` discriminator alone moves both writes onto the
        // transcript families; a producer cannot mix the two capture axes.
        let transcript_result = json!({
            "transcript_start_event_id": "ak:event:019f9000-0000-7000-8000-000000000021",
            "retention": {"consent_confirmed": true}
        });
        let transcript = call_event(
            EventKind::CALL_RECORDING_START,
            json!({
                "call_id": call_id,
                "recording_id": recording_id,
                "capture_kind": "transcript",
                "result": transcript_result.clone()
            }),
        );
        assert_eq!(
            project(&transcript),
            vec![
                write(
                    &format!("ak:cell:ak.component.call.transcript.v1:{subject}"),
                    transition_op(Value::Null, json!("transcribing")),
                ),
                write(
                    &format!("ak:cell:ak.component.call.transcript_result.v1:{subject}"),
                    set_op(transcript_result),
                ),
            ]
        );
    }

    #[test]
    fn projects_capability_grant_add_dot() {
        // Was `materializes_capability_grant_add_dot`.
        let grant_id = "ak:grant:019f9000-0000-7000-8000-000000000006";
        let grant = json!({
            "grant_id": grant_id,
            "issuer": "did:webvh:z6mkfixture:alice.example",
            "subject": "did:webvh:z6mkfixture:alice.example",
            "actions": ["ak.realm.admin"]
        });
        let event: Event = serde_json::from_value(json!({
            "event_id": "ak:event:019f9000-0000-7000-8000-000000000001",
            "kind": EventKind::CAPABILITY_GRANT,
            "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002"},
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "actor_seq": 3,
            "created_at": "2026-07-26T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "payload": {
                "grant_id": grant_id,
                "grant": grant
            },
            "proofs": []
        }))
        .unwrap();

        // The or_set tag is the registry dot `<event_id>:<write_index>`, and the
        // element is the whole signed payload.
        assert_eq!(
            project(&event),
            vec![write(
                &format!("ak:cell:ak.component.capability.grant.v1:{grant_id}"),
                add_op(
                    "ak:event:019f9000-0000-7000-8000-000000000001:0",
                    serde_json::to_value(&event.payload).unwrap(),
                ),
            )]
        );
    }

    #[test]
    fn delivery_subject_selects_the_share_kind_branch() {
        let event = delivery_share_event();
        let rule = event.kind.descriptor().unwrap().cell_subject_rule;
        let member_subject = derive_subject(&event, rule).unwrap();

        // The RRK branch derives from a different target field, so the same
        // recipient and scope MUST NOT collapse onto one delivery cell.
        let mut rrk = event.clone();
        rrk.payload.remove("recipient_device_id");
        rrk.payload
            .insert("share_kind".to_owned(), json!("realm_recovery_key"));
        rrk.payload.insert(
            "recipient_verification_method".to_owned(),
            json!("did:webvh:z6mkfixture:acme.example#realm-history-recovery-1"),
        );
        rrk.payload.insert(
            "recovery_recipient_id".to_owned(),
            // Deliberately spelled like a device id: without `share_kind` in
            // the components an RRK share could target a member device's cell.
            json!("ak:device:019f9000-0000-7000-8000-000000000003"),
        );
        let rrk_subject = derive_subject(&rrk, rule).unwrap();
        assert_ne!(member_subject, rrk_subject);
    }

    #[test]
    fn delivery_supports_circle_scope_which_also_carries_realm_id() {
        // `effective_scope.kind="circle"` is required by schema to carry
        // `realm_id` too — the `realm` branch's value field. A blanket
        // "unselected branch field present => ambiguous" rule would reject
        // every legitimate Circle key share.
        let mut event = delivery_share_event();
        event.payload.insert(
            "key_scope".to_owned(),
            json!({
                "effective_scope": {
                    "kind": "circle",
                    "realm_id": "ak:realm:019f9000-0000-7000-8000-000000000002",
                    "circle_id": "ak:circle:019f9000-0000-7000-8000-000000000007"
                },
                "policy_digest": format!("sha256:{}", "aa".repeat(32))
            }),
        );
        let descriptor = event.kind.descriptor().unwrap();
        let subject = derive_subject(&event, descriptor.cell_subject_rule).unwrap();
        let value = derive_value_projection(
            &event,
            descriptor.value_projection_rule.unwrap(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        assert_eq!(
            value["effective_scope_id"],
            json!("ak:circle:019f9000-0000-7000-8000-000000000007"),
            "circle branch must project the circle id"
        );
        validate_registered_cell_writes(&event).unwrap();

        // And a Realm-scoped share must still land on a different cell.
        assert_ne!(
            subject,
            derive_subject(&delivery_share_event(), descriptor.cell_subject_rule).unwrap()
        );
    }

    #[test]
    fn delivery_subject_rejects_cross_carried_branch_field() {
        let mut event = delivery_share_event();
        event
            .payload
            .insert("recovery_recipient_id".to_owned(), json!("rr-1"));
        let rule = event.kind.descriptor().unwrap().cell_subject_rule;
        let error = derive_subject(&event, rule).unwrap_err();
        assert!(
            format!("{error}").contains("forbidden field payload.recovery_recipient_id"),
            "got {error}"
        );
    }

    #[test]
    fn delivery_subject_rejects_unknown_discriminator() {
        let mut event = delivery_share_event();
        event
            .payload
            .insert("share_kind".to_owned(), json!("member-device"));
        let rule = event.kind.descriptor().unwrap().cell_subject_rule;
        let error = derive_subject(&event, rule).unwrap_err();
        assert!(
            format!("{error}").contains("no registered branch"),
            "byte-for-byte branch match only; got {error}"
        );
    }

    #[test]
    fn delivery_append_outcome_is_a_registry_literal() {
        // Was `delivery_append_rejects_producer_chosen_value`: a producer can no
        // longer smuggle `delivery_outcome: "withheld"` past the contract,
        // because the member is a registry literal rather than a payload field.
        let event = delivery_share_event();
        let projected = project(&event);
        let effect = projected[0]
            .as_direct()
            .expect("an append needs no pre-state");
        assert_eq!(
            effect.op.value.as_ref().unwrap()["delivery_outcome"],
            json!("shared")
        );
    }

    #[test]
    fn delivery_append_commits_to_every_signed_field() {
        // Regression: a projection that only committed to the ciphertext let
        // semantically different deliveries collapse into one idempotent
        // duplicate. Each of these differs only in a field that is signed and
        // changes delivery meaning.
        let base = delivery_share_event();
        let rule = base
            .kind
            .descriptor()
            .unwrap()
            .value_projection_rule
            .unwrap();
        let suite = arkret_canonical::DigestSuite::Sha256;
        let baseline = derive_value_projection(&base, rule, suite).unwrap();

        let mutations: [(&str, fn(&mut Event)); 4] = [
            ("expires_at", |event: &mut Event| {
                event
                    .payload
                    .insert("expires_at".to_owned(), json!("2026-08-01T00:00:00.000Z"));
            }),
            ("aad_digest", |event: &mut Event| {
                event.payload.insert(
                    "aad_digest".to_owned(),
                    json!(format!("sha256:{}", "cc".repeat(32))),
                );
            }),
            (
                "key_scope.membership_frontier_digest",
                |event: &mut Event| {
                    event
                        .payload
                        .get_mut("key_scope")
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .insert(
                            "membership_frontier_digest".to_owned(),
                            json!(format!("sha256:{}", "dd".repeat(32))),
                        );
                },
            ),
            ("ciphertext", |event: &mut Event| {
                event
                    .payload
                    .insert("ciphertext".to_owned(), json!("b3RoZXI"));
            }),
        ];
        for (label, mutate) in mutations {
            let mut mutated = base.clone();
            mutate(&mut mutated);
            let value = derive_value_projection(&mutated, rule, suite).unwrap();
            assert_ne!(
                baseline, value,
                "{label} is signed and changes delivery meaning; it must change op.value"
            );
        }
    }

    #[test]
    fn delivery_append_commits_to_the_material_digest() {
        // Two different sealed materials to the same recipient and scope must
        // not project to the same entry, or §9.3.1 would dedupe one away.
        let first = delivery_share_event();
        let first_value = project(&first)[0]
            .as_direct()
            .expect("an append needs no pre-state")
            .op
            .value
            .expect("an append projects a value");
        let mut second = first.clone();
        second
            .payload
            .insert("ciphertext".to_owned(), json!("b3RoZXI"));
        let rule = second.kind.descriptor().unwrap().value_projection_rule;
        let second_value = derive_value_projection(
            &second,
            rule.unwrap(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
        assert_ne!(first_value, second_value);

        // The commitment is over the complete canonical signed payload.
        let payload = Value::Object(first.payload.clone().into_iter().collect());
        let expected = arkret_canonical::sha256_digest(
            arkret_canonical::canonical_json_bytes(&payload).unwrap(),
        );
        assert_eq!(first_value["payload_digest"], json!(expected));
    }

    #[test]
    fn delivery_material_digest_follows_the_realm_digest_suite() {
        // A blake3 Realm must project a blake3 material digest; hard-coding
        // SHA-256 would diverge from every conformant implementation's state.
        let event = delivery_share_event();
        let rule = event
            .kind
            .descriptor()
            .unwrap()
            .value_projection_rule
            .unwrap();
        let blake3 =
            derive_value_projection(&event, rule, arkret_canonical::DigestSuite::Blake3).unwrap();
        let payload = Value::Object(event.payload.clone().into_iter().collect());
        assert_eq!(
            blake3["payload_digest"],
            json!(arkret_canonical::digest(
                arkret_canonical::DigestSuite::Blake3,
                arkret_canonical::canonical_json_bytes(&payload).unwrap()
            ))
        );
        // And the suite reaches the projected write, not just the standalone
        // value rule: the same Event on blake3 must not derive the sha256 op.
        assert_ne!(
            project_registered_cell_writes(&event, arkret_canonical::DigestSuite::Blake3).unwrap(),
            project(&event)
        );
    }

    #[test]
    fn delivery_append_omits_absent_optional_members() {
        let mut event = delivery_share_event();
        event
            .payload
            .get_mut("key_scope")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("to_epoch");
        let rule = event.kind.descriptor().unwrap().value_projection_rule;
        let value =
            derive_value_projection(&event, rule.unwrap(), arkret_canonical::DigestSuite::Sha256)
                .unwrap();
        let object = value.as_object().unwrap();
        assert!(object.contains_key("from_epoch"));
        assert!(
            !object.contains_key("to_epoch"),
            "absent optional members are omitted, never written as null"
        );
    }

    #[test]
    fn delivery_append_cell_is_derived_from_the_signed_payload() {
        // Was `delivery_append_rejects_producer_chosen_cell`: there is no
        // producer-named cell left to reject, so pin the one the composite
        // subject rule derives from `share_kind`, recipient and key scope.
        let projected = project(&delivery_share_event());
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].cell.as_str(), DELIVERY_CELL);
    }

    #[test]
    fn validates_realm_join_rule_from_registry() {
        let event = realm_facet(
            EventKind::REALM_JOIN_RULE,
            json!({"value": "knock_restricted"}),
        );
        validate_registered_cell_writes(&event).unwrap();
        assert_eq!(
            project(&event),
            vec![write(
                "ak:cell:ak.component.realm.join_rule.v1:null",
                set_op(json!({"value": "knock_restricted"})),
            )]
        );
    }

    #[test]
    fn realm_facet_family_and_value_come_only_from_the_registry() {
        // Was `rejects_producer_selected_family_and_payload_value`. A producer
        // can no longer aim a discovery Event at the join-rule cell, nor set the
        // register to a value its payload never carried: both the family and the
        // set value are read straight off the registry row.
        let event = realm_facet(EventKind::REALM_DISCOVERY, json!({"value": "listed"}));
        assert_eq!(
            project(&event),
            vec![write(
                "ak:cell:ak.component.realm.discovery.v1:null",
                set_op(json!({"value": "listed"})),
            )]
        );
    }

    #[test]
    fn accepts_only_basis_free_control_facets_in_realm_bootstrap_context() {
        let mut event = realm_facet(EventKind::REALM_JOIN_RULE, json!({"value": "invite"}));
        event.seal_basis = None;
        validate_registered_cell_writes_in_context(
            &event,
            EventCellContractContext::OrdinaryRealmBootstrap,
        )
        .unwrap();

        event.seal_ref = Some(
            arkret_wire::SealId::new(
                "ak:seal:sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            )
            .unwrap(),
        );
        assert_eq!(
            validate_registered_cell_writes_in_context(
                &event,
                EventCellContractContext::OrdinaryRealmBootstrap,
            )
            .unwrap_err()
            .reason_code(),
            "plane_cross_write"
        );
    }
}

#[cfg(test)]
mod or_set_dot_vector_tests {
    //! `ak.vector.encoding.or_set_dot_and_batch_tag.v1`.

    use serde_json::json;

    use super::*;

    const VECTOR_EVENT_ID: &str = "ak:event:01964185-0400-7000-8000-000000000000";

    #[test]
    fn dot_matches_the_encoding_vector() {
        assert_eq!(
            or_set_dot(VECTOR_EVENT_ID, 0),
            "ak:event:01964185-0400-7000-8000-000000000000:0"
        );
        assert_eq!(
            or_set_dot(VECTOR_EVENT_ID, 1),
            "ak:event:01964185-0400-7000-8000-000000000000:1"
        );
    }

    #[test]
    fn batch_add_tag_matches_the_encoding_vector() {
        let dot = or_set_dot(VECTOR_EVENT_ID, 0);
        for (value, expected) in [
            (
                "ak:seal:01964185-0400-7000-8000-00000000000a",
                "1iBmBx9eyxpIkSNfOAOpK85TXemME7YOfXe_MwkojTM",
            ),
            (
                "ak:seal:01964185-0400-7000-8000-00000000000b",
                "70hmv5IajqSpRoVHskF9M4V4h6nIZeftWLdvwWBlrhY",
            ),
        ] {
            let tag = batch_add_tag(
                "ak.covered-seal-tag-v1",
                &dot,
                &json!(value),
                "ak.mls.commit",
            )
            .unwrap();
            assert_eq!(tag, expected, "value {value}");
        }
    }

    #[test]
    fn batch_add_tag_is_bound_to_the_dot_and_the_context() {
        let value = json!("ak:seal:01964185-0400-7000-8000-00000000000a");
        let baseline = batch_add_tag(
            "ak.covered-seal-tag-v1",
            &or_set_dot(VECTOR_EVENT_ID, 0),
            &value,
            "ak.mls.commit",
        )
        .unwrap();

        // A different write on the same Event, and a different domain context,
        // must both produce a different tag; otherwise two or_set writes could
        // collide on one cell.
        let other_write = batch_add_tag(
            "ak.covered-seal-tag-v1",
            &or_set_dot(VECTOR_EVENT_ID, 1),
            &value,
            "ak.mls.commit",
        )
        .unwrap();
        let other_context = batch_add_tag(
            "ak.other-tag-v1",
            &or_set_dot(VECTOR_EVENT_ID, 0),
            &value,
            "ak.mls.commit",
        )
        .unwrap();

        assert_ne!(baseline, other_write);
        assert_ne!(baseline, other_context);
    }

    #[test]
    fn or_set_tag_rejects_a_bare_event_id() {
        // The negative case of the vector: a bare event_id is not a dot, and is
        // not unique across several or_set writes on one cell.
        let realm = "ak:realm:01964185-0400-7000-8000-000000000002";
        let event: Event = serde_json::from_value(json!({
            "event_id": VECTOR_EVENT_ID,
            "kind": "ak.capability.grant",
            "realm_id": realm,
            "scope_ref": {"kind": "realm", "realm_id": realm},
            "actor_id": "did:webvh:z6mkfixture:alice.example",
            "actor_seq": 1,
            "created_at": "2026-07-28T00:00:00.000Z",
            "prev_refs": [],
            "payload": {},
            "proofs": []
        }))
        .unwrap();
        let error = or_set_tag(
            &event,
            &json!({}),
            Some(&json!({"envelope_field": "event_id"})),
            event.kind.as_str(),
            &or_set_dot(event.event_id.as_str(), 0),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap_err();

        assert!(error.to_string().contains("not a dot"), "{error}");
    }
}
