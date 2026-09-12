//! Registry-driven validation of reducer-input Event cell contracts.
//!
//! The event-kind registry is the sole authority for reducer targets. There is
//! no producer-supplied cell write to compare against: the receiver recomputes
//! every target and every state-model operation from the signed envelope, the
//! schema-validated payload and the frozen pre-state
//! (`zh/models/event-and-patch.md` section 2.4.2).

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{
    AccountId, ActorId, CbsEffectPlane, CellRef, Event, EventCellExecution, EventCellRule,
    EventCellRuleKey, EventCellRuleOperator, EventCellValueShape, EventCellWriteDescriptor,
    EventId, EventKind, LatticeOp, LatticeOpType, NULL_SUBJECT, Precondition, Predicate,
    PredicateOp, ProjectedCellWrite, ProjectedEventInput, ProjectedOp,
};
use serde_json::Value;
use thiserror::Error;

/// Envelope context used while validating the registry-declared CBS plane.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum EventCellContractContext {
    /// A post-genesis Event: control writes require `seal_basis`; data writes
    /// require `auth_context`.
    #[default]
    Standard,
    /// A follow-up in the closed ordinary Realm genesis transaction. There is
    /// no accepted Seal yet, so both data and control initialization writes
    /// carry no CBS basis fields and share the unit's outcome. The caller MUST
    /// validate the complete closed unit's kinds, members and order; this
    /// context alone does not admit an individual basis-free Event.
    OrdinaryRealmBootstrap,
    /// The exact four-Event Direct Conversation founding unit. Its two joins
    /// is a basis-free control write and its initial Strand is the one
    /// registered basis-free data write because the same not-yet-created
    /// genesis Seal atomically covers all four Events.
    DirectConversationFounding,
}

/// Failure while matching an Event against its generated registry contract.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum EventCellContractError {
    #[error("event kind {0} is not a registered reducer input")]
    UnregisteredReducerInput(String),
    #[error("event kind {0} has no single-target cell contract")]
    MissingCellContract(String),
    #[error("event kind {kind} is routed through the wrong CBS plane; expected {expected}")]
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
    #[error("event kind {kind} cannot derive capability authority: {message}")]
    CapabilityAuthorityProjection { kind: String, message: String },
    #[error("event kind {kind} is waiting for referenced grant {grant_id}")]
    CapabilityAuthorityDependency { kind: String, grant_id: String },
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
            Self::CapabilityAuthorityProjection { .. } => "reducer_projection_failed",
            Self::CapabilityAuthorityDependency { .. } => "temporarily_unavailable",
            _ => "effects_payload_mismatch",
        }
    }
}

/// Immutable reducer-derived authority audit inherited by a child grant.
#[derive(Clone, Debug, PartialEq)]
pub struct CapabilityAuthorityAudit {
    pub authority_depth: u64,
    pub authority_root_refs: Vec<Value>,
}

type CapabilityAuthorityRootIdentity = (Vec<u8>, Vec<u8>, [u8; 8]);

/// Why the authority audit for a Capability Grant cannot be derived.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CapabilityAuthorityProjectionError {
    #[error("issuer_authority_refs must be a non-empty array")]
    InvalidRefs,
    #[error("issuer_authority_refs contains an invalid {0} reference")]
    InvalidRef(&'static str),
    #[error("referenced grant {0} has not been projected")]
    UnresolvedGrant(String),
    #[error("authority depth exceeds the v1 integer range")]
    DepthOverflow,
}

/// Derive the immutable authority audit for a Capability Grant body.
///
/// Direct roots have depth zero. The child depth is the maximum parent depth
/// plus one, and its roots are the direct roots union every parent's already
/// materialized roots. Missing parents are dependencies, never an invitation
/// to guess a depth or root.
pub fn derive_capability_authority_audit(
    grant: &Value,
    resolve: &dyn Fn(&str) -> Option<CapabilityAuthorityAudit>,
) -> Result<CapabilityAuthorityAudit, CapabilityAuthorityProjectionError> {
    let refs = grant
        .get("issuer_authority_refs")
        .and_then(Value::as_array)
        .filter(|refs| !refs.is_empty())
        .ok_or(CapabilityAuthorityProjectionError::InvalidRefs)?;
    let mut maximum_depth = 0_u64;
    let mut roots = BTreeMap::<CapabilityAuthorityRootIdentity, Value>::new();
    for authority_ref in refs {
        match authority_ref.get("kind").and_then(Value::as_str) {
            Some("realm_root") => {
                if authority_ref
                    .get("controller_epoch_at_issuance")
                    .and_then(Value::as_u64)
                    .is_none()
                {
                    return Err(CapabilityAuthorityProjectionError::InvalidRef("realm_root"));
                }
                insert_capability_authority_root(
                    &mut roots,
                    authority_ref,
                    CapabilityAuthorityProjectionError::InvalidRef("realm_root"),
                )?;
            }
            Some("grant") => {
                let grant_id = authority_ref
                    .get("grant_id")
                    .and_then(Value::as_str)
                    .filter(|grant_id| !grant_id.is_empty())
                    .ok_or(CapabilityAuthorityProjectionError::InvalidRef("grant"))?;
                let parent = resolve(grant_id).ok_or_else(|| {
                    CapabilityAuthorityProjectionError::UnresolvedGrant(grant_id.to_owned())
                })?;
                if parent.authority_depth == 0 {
                    return Err(CapabilityAuthorityProjectionError::InvalidRef(
                        "parent grant depth",
                    ));
                }
                maximum_depth = maximum_depth.max(parent.authority_depth);
                if parent.authority_root_refs.is_empty() {
                    return Err(CapabilityAuthorityProjectionError::InvalidRef(
                        "parent grant root",
                    ));
                }
                for root in &parent.authority_root_refs {
                    insert_capability_authority_root(
                        &mut roots,
                        root,
                        CapabilityAuthorityProjectionError::InvalidRef("parent grant root"),
                    )?;
                }
            }
            _ => return Err(CapabilityAuthorityProjectionError::InvalidRef("unknown")),
        }
    }
    if roots.is_empty() {
        return Err(CapabilityAuthorityProjectionError::InvalidRefs);
    }
    Ok(CapabilityAuthorityAudit {
        authority_depth: maximum_depth
            .checked_add(1)
            .ok_or(CapabilityAuthorityProjectionError::DepthOverflow)?,
        authority_root_refs: roots.into_values().collect(),
    })
}

fn insert_capability_authority_root(
    roots: &mut BTreeMap<CapabilityAuthorityRootIdentity, Value>,
    root: &Value,
    error: CapabilityAuthorityProjectionError,
) -> Result<(), CapabilityAuthorityProjectionError> {
    let realm_id = root
        .get("realm_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| error.clone())?;
    let cell_ref = root
        .get("cell_ref")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| error.clone())?;
    let authority_generation = root
        .get("authority_generation")
        .and_then(Value::as_u64)
        .ok_or_else(|| error.clone())?;
    let identity = (
        realm_id.as_bytes().to_vec(),
        cell_ref.as_bytes().to_vec(),
        authority_generation.to_be_bytes(),
    );
    roots.entry(identity).or_insert_with(|| {
        serde_json::json!({
            "kind": "realm_root",
            "realm_id": realm_id,
            "cell_ref": cell_ref,
            "authority_generation": authority_generation,
        })
    });
    Ok(())
}

type CapabilityAuthorityResolver<'a> = dyn Fn(&str) -> Option<CapabilityAuthorityAudit> + 'a;

/// Immutable Capability Grant bodies indexed by their Event-derived grant id.
///
/// Proof and history replay construct this index from the exact accepted Event
/// closure they are verifying. Resolution recursively uses only those signed
/// bodies and therefore produces the same audit as a live ProjectionState.
#[derive(Clone, Debug, Default)]
pub struct CapabilityAuthorityAuditIndex {
    grants: BTreeMap<String, Value>,
}

impl CapabilityAuthorityAuditIndex {
    /// Index Capability Grant authoring bodies from an accepted Event closure.
    pub fn from_events<'a>(events: impl IntoIterator<Item = &'a Event>) -> Self {
        let mut grants = BTreeMap::new();
        for event in events {
            if event.kind != EventKind::CapabilityGrant {
                continue;
            }
            let grant_id = arkret_identifiers::GrantId::from_event_id(&event.event_id).to_string();
            if let Some(grant) = event.payload.get("grant") {
                grants.entry(grant_id).or_insert_with(|| grant.clone());
            }
        }
        Self { grants }
    }

    /// Resolve one grant's immutable audit, rejecting missing/cyclic ancestry.
    pub fn resolve(&self, grant_id: &str) -> Option<CapabilityAuthorityAudit> {
        self.resolve_inner(grant_id, &BTreeSet::new())
    }

    fn resolve_inner(
        &self,
        grant_id: &str,
        visiting: &BTreeSet<String>,
    ) -> Option<CapabilityAuthorityAudit> {
        if visiting.contains(grant_id) {
            return None;
        }
        let grant = self.grants.get(grant_id)?;
        let mut next = visiting.clone();
        next.insert(grant_id.to_owned());
        derive_capability_authority_audit(grant, &|parent_id| self.resolve_inner(parent_id, &next))
            .ok()
    }
}

/// Frozen cell values used while evaluating registry-declared pre-state
/// requirements. A missing entry is a failed requirement, never an implicit
/// bottom value.
#[derive(Clone, Debug, Default)]
pub struct FrozenPreState {
    values: BTreeMap<CellRef, Value>,
    reads: std::sync::Arc<std::sync::Mutex<BTreeSet<CellRef>>>,
}

impl PartialEq for FrozenPreState {
    fn eq(&self, other: &Self) -> bool {
        self.values == other.values
    }
}

impl FrozenPreState {
    /// Create an empty pre-state snapshot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one frozen cell value while assembling the snapshot.
    pub fn insert(&mut self, cell: CellRef, value: Value) -> Option<Value> {
        self.values.insert(cell, value)
    }

    /// Read one value and retain the dependency, including an absent Cell.
    pub fn get(&self, cell: &CellRef) -> Option<&Value> {
        self.reads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(cell.clone());
        self.values.get(cell)
    }

    /// Cells actually consulted by registry pre-state requirements.
    pub fn read_cells(&self) -> BTreeSet<CellRef> {
        self.reads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl<const N: usize> From<[(CellRef, Value); N]> for FrozenPreState {
    fn from(entries: [(CellRef, Value); N]) -> Self {
        Self {
            values: BTreeMap::from(entries),
            ..Self::default()
        }
    }
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
    project_registered_operation_writes_with_pre_state(
        &ProjectedEventInput::from(event),
        digest_suite,
        None,
        None,
    )
}

/// Project registered writes with the immutable authority audit resolver used
/// by Capability Grant derived members.
pub fn project_registered_cell_writes_with_authority_resolver(
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
    resolve: &CapabilityAuthorityResolver<'_>,
) -> Result<Vec<ProjectedCellWrite>, EventCellContractError> {
    project_registered_operation_writes_with_pre_state(
        &ProjectedEventInput::from(event),
        digest_suite,
        None,
        Some(resolve),
    )
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
    project_registered_operation_writes_with_pre_state(
        &ProjectedEventInput::from(event),
        digest_suite,
        Some(frozen_pre_state),
        None,
    )
}

/// Project registered writes against one frozen pre-state and one immutable
/// Capability Grant authority resolver.
pub fn project_registered_cell_writes_with_pre_state_and_authority_resolver(
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
    frozen_pre_state: &FrozenPreState,
    resolve: &CapabilityAuthorityResolver<'_>,
) -> Result<Vec<ProjectedCellWrite>, EventCellContractError> {
    project_registered_operation_writes_with_pre_state(
        &ProjectedEventInput::from(event),
        digest_suite,
        Some(frozen_pre_state),
        Some(resolve),
    )
}

/// Project registry-declared writes from an accepted projection record without
/// reconstructing or re-admitting a synthetic signed Event.
pub fn project_registered_operation_writes(
    event: &ProjectedEventInput,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Vec<ProjectedCellWrite>, EventCellContractError> {
    project_registered_operation_writes_with_pre_state(event, digest_suite, None, None)
}

/// Project an accepted operation with its Capability Grant authority basis.
pub fn project_registered_operation_writes_with_authority_resolver(
    event: &ProjectedEventInput,
    digest_suite: arkret_canonical::DigestSuite,
    resolve: &CapabilityAuthorityResolver<'_>,
) -> Result<Vec<ProjectedCellWrite>, EventCellContractError> {
    project_registered_operation_writes_with_pre_state(event, digest_suite, None, Some(resolve))
}

fn project_registered_operation_writes_with_pre_state(
    event: &ProjectedEventInput,
    digest_suite: arkret_canonical::DigestSuite,
    frozen_pre_state: Option<&FrozenPreState>,
    authority_resolver: Option<&CapabilityAuthorityResolver<'_>>,
) -> Result<Vec<ProjectedCellWrite>, EventCellContractError> {
    let kind = event.kind.as_str().to_owned();
    arkret_wire::forbidden_wire::validate_event_payload_forbidden_fields(
        &event.kind,
        &Value::Object(event.payload.clone().into_iter().collect()),
    )
    .map_err(|error| projection_error(&kind, &error.to_string()))?;
    let descriptor = event
        .kind
        .descriptor()
        .ok_or_else(|| EventCellContractError::UnregisteredReducerInput(kind.clone()))?;
    let runtime_contract = crate::event_runtime_contract(&kind)
        .ok_or_else(|| EventCellContractError::UnregisteredReducerInput(kind.clone()))?;
    // Only the admitting receiver evaluates pre-state requirements, and only
    // against the snapshot it froze. `None` means the caller is projecting the
    // write set (pre-authoring, replay of an already accepted operation), not
    // admitting the Event; substituting an empty snapshot there would reject
    // every kind that declares a requirement.
    if let Some(frozen_pre_state) = frozen_pre_state {
        validate_pre_state_requirements(
            event,
            runtime_contract.pre_state_requirements,
            frozen_pre_state,
            &kind,
        )?;
    }
    let writes = descriptor.cell_writes;
    if writes.is_empty() {
        // An active reducer-input kind MUST declare a complete contract
        // (`event-and-patch.md` §2.4.2). Returning an empty projection for one
        // would admit the Event while writing nothing, which is the opposite of
        // fail-closed: the registry gap would look like "this kind touches no
        // cell". A row that is not an active reducer input legitimately has no
        // writes and projects none.
        if runtime_contract.reducer_input {
            return Err(EventCellContractError::MissingCellContract(kind));
        }
        return Ok(Vec::new());
    }

    let mut projected = Vec::new();
    let mut seen = BTreeMap::<String, (String, EventCellValueShape, EventCellRuleOperator)>::new();
    for (write_index, write) in writes.iter().enumerate() {
        // `write_index` is the registry index, so a write skipped by its
        // `condition` still consumes one. The dot must be reproducible from the
        // registry alone; renumbering the surviving writes would make it depend
        // on payload shape.
        if !write_applies(event, write, &kind)? {
            continue;
        }
        if write.for_each_rule.is_some() {
            if event.kind != EventKind::AgentKeyAuthorize || write_index != 0 {
                return Err(effect_set_error(&kind, "unregistered cell-write expansion"));
            }
            let removals = project_agent_supersedes(event, frozen_pre_state, &kind)?;
            for removal in removals {
                seen.insert(
                    removal.cell_id.as_str().to_owned(),
                    (
                        "sequenced_state".to_owned(),
                        EventCellValueShape::Set,
                        EventCellRuleOperator::OrSetRemoveDots,
                    ),
                );
                projected.push(removal);
            }
            continue;
        }
        if let Some(cell_ref_rule) = write.cell_ref_rule {
            return Err(effect_set_error(
                &kind,
                &format!("unsupported dynamic cell_ref rule {cell_ref_rule:?}"),
            ));
        }
        let family = write
            .cell_family
            .map(|family| family.as_str())
            .ok_or_else(|| effect_set_error(&kind, "cell write omits cell_family"))?;
        let subject = derive_subject_value(
            CellSubjectSource::from_event(event),
            write.cell_subject_rule,
        )?;
        let cell = CellRef::new(format!("ak:cell:{family}:{subject}")).map_err(|error| {
            EventCellContractError::InvalidCell {
                kind: kind.clone(),
                message: error.to_string(),
            }
        })?;
        let state_model = write
            .state_model
            .map(|state_model| state_model.as_str())
            .ok_or_else(|| effect_set_error(&kind, "cell write omits state_model"))?;
        let value_shape = write
            .value_shape
            .ok_or_else(|| effect_set_error(&kind, "cell write omits value_shape"))?;
        let projection = write
            .effect_projection_rule
            .ok_or_else(|| effect_set_error(&kind, "cell write omits effect_projection"))?;
        let projection_kind = projection
            .operator()
            .ok_or_else(|| effect_set_error(&kind, "effect_projection omits kind"))?;
        // Two active writes on one cell are a registry error in general, because
        // nothing orders them. The one registered exception is a set-shaped
        // observed-remove paired with an add, which `key-management.md` §3.6.1
        // permits for agent-key re-authorization when old and new key ids coincide:
        // remove only the named old authorization dot, then add the new one.
        // The remove is checked against frozen pre-state, so it cannot consume
        // the sibling add or any unrelated authorization or revocation dot.
        if let Some((previous_state_model, previous_value_shape, previous_kind)) = seen.insert(
            cell.as_str().to_owned(),
            (state_model.to_owned(), value_shape, projection_kind),
        ) {
            let atomic_or_set_pair = previous_state_model == state_model
                && previous_value_shape == EventCellValueShape::Set
                && value_shape == EventCellValueShape::Set
                && is_or_set_remove(previous_kind) != is_or_set_remove(projection_kind);
            if !atomic_or_set_pair {
                return Err(effect_set_error(
                    &kind,
                    &format!("two active targets derive the same cell {cell}"),
                ));
            }
        }
        let dot = or_set_dot(event.event_id.as_str(), write_index);
        for op in derive_effect_ops(
            event,
            write,
            projection,
            state_model,
            value_shape,
            &kind,
            &dot,
            digest_suite,
            authority_resolver,
        )? {
            projected.push(ProjectedCellWrite {
                cell_id: cell.clone(),
                op,
            });
        }
    }
    Ok(projected)
}

/// Expand only exact old authorization dots; never remove a whole old-key cell.
fn project_agent_supersedes(
    event: &ProjectedEventInput,
    frozen_pre_state: Option<&FrozenPreState>,
    kind: &str,
) -> Result<Vec<ProjectedCellWrite>, EventCellContractError> {
    let Some(value) = event.payload.get("supersedes") else {
        return Ok(Vec::new());
    };
    let entries = value
        .as_array()
        .filter(|entries| !entries.is_empty() && entries.len() <= 256)
        .ok_or_else(|| {
            effect_set_error(kind, "supersedes must contain 1..=256 exact authorizations")
        })?;
    let agent = event
        .payload
        .get("agent_id")
        .and_then(Value::as_str)
        .ok_or_else(|| effect_set_error(kind, "authorize omits agent_id"))?;
    let mut previous: Option<(&str, &str)> = None;
    let mut writes = Vec::with_capacity(entries.len());
    for entry in entries {
        let key = entry
            .get("key_id")
            .and_then(Value::as_str)
            .ok_or_else(|| effect_set_error(kind, "supersedes omits key_id"))?;
        let authorization = entry
            .get("authorized_event_ref")
            .and_then(Value::as_str)
            .ok_or_else(|| effect_set_error(kind, "supersedes omits authorization Event"))?;
        EventId::new(authorization.to_owned())
            .map_err(|error| effect_set_error(kind, &error.to_string()))?;
        if previous.is_some_and(|old| old >= (key, authorization)) {
            return Err(effect_set_error(
                kind,
                "supersedes must be sorted and unique",
            ));
        }
        previous = Some((key, authorization));
        let subject = arkret_wire::composite_subject(&[agent, key])
            .map_err(|error| effect_set_error(kind, &error.to_string()))?;
        let cell = CellRef::new(format!("ak:cell:ak.component.agent.key.v1:{subject}"))
            .map_err(|error| effect_set_error(kind, &error.to_string()))?;
        let tag = or_set_dot(authorization, 1);
        if let Some(state) = frozen_pre_state {
            let observed = state
                .get(&cell)
                .and_then(Value::as_array)
                .is_some_and(|entries| {
                    entries.iter().any(|entry| {
                        entry.get("tag").and_then(Value::as_str) == Some(tag.as_str())
                            && entry
                                .get("value")
                                .and_then(|value| value.get("agent_id"))
                                .and_then(Value::as_str)
                                == Some(agent)
                            && entry
                                .get("value")
                                .and_then(|value| value.get("key_id"))
                                .and_then(Value::as_str)
                                == Some(key)
                            && entry
                                .get("value")
                                .and_then(|value| value.get("verification_method"))
                                .is_some()
                    })
                });
            if !observed {
                return Err(effect_set_error(
                    kind,
                    "superseded authorization dot is not active in its exact old key cell",
                ));
            }
        }
        let mut op = LatticeOp::empty();
        op.op_type = LatticeOpType::Remove;
        op.tag = Some(tag);
        writes.push(ProjectedCellWrite {
            cell_id: cell,
            op: ProjectedOp::Direct(op),
        });
    }
    Ok(writes)
}

fn validate_pre_state_requirements(
    event: &ProjectedEventInput,
    requirements: &[crate::EventPreStateRequirementDescriptor],
    frozen_pre_state: &FrozenPreState,
    kind: &str,
) -> Result<(), EventCellContractError> {
    // A registered field counts as present only when it is there and not JSON
    // `null`, the same reading the closed payload-condition grammar uses.
    let present = |value: Option<&Value>| value.is_some_and(|value| !value.is_null());
    for requirement in requirements {
        // A requirement whose registered condition does not hold is not
        // evaluated (`event-and-patch.md` section 2.4.2). The condition is
        // drawn from the same closed payload grammar as a cell write's, so it
        // goes through the same evaluator rather than a second copy of it.
        if !condition_matches(event, requirement.condition, kind)? {
            continue;
        }
        let subject = field_value(event, requirement.subject_field)
            .ok_or_else(|| effect_set_error(kind, "pre-state subject field is absent"))
            .and_then(|value| {
                scalar_subject(value).map_err(|message| effect_set_error(kind, &message))
            })?;
        let cell = CellRef::new(format!(
            "ak:cell:{}:{subject}",
            requirement.cell_family.as_str()
        ))
        .map_err(|error| EventCellContractError::InvalidCell {
            kind: kind.to_owned(),
            message: error.to_string(),
        })?;
        let stored = frozen_pre_state.get(&cell);
        let stored_value = stored.and_then(|value| nested_value(value, requirement.stored_field));
        let satisfied = match requirement.predicate {
            crate::EventPreStatePredicateKind::StoredFieldPresent => present(stored_value),
            // Both comparisons read the payload field the registry names, and
            // both are byte comparisons of the stored and signed values. They
            // differ only in what an absence means: `equals` requires both
            // sides present, `matches` also admits both sides absent and
            // nothing else. That weaker form is what an optional payload field
            // needs, because it rejects a forged value against a stored
            // absence and an omitted value against a stored presence alike.
            crate::EventPreStatePredicateKind::StoredFieldEqualsPayload => {
                let payload_value = payload_comparand(event, requirement, kind)?;
                present(stored_value) && present(payload_value) && stored_value == payload_value
            }
            crate::EventPreStatePredicateKind::StoredFieldMatchesPayload => {
                let payload_value = payload_comparand(event, requirement, kind)?;
                match (present(stored_value), present(payload_value)) {
                    (false, false) => true,
                    (true, true) => stored_value == payload_value,
                    _ => false,
                }
            }
        };
        if !satisfied {
            return Err(EventCellContractError::PreStateRequirement {
                kind: kind.to_owned(),
                code: requirement.failure_code.to_owned(),
                reason_code: requirement.failure_reason_code.to_owned(),
                message: format!("predicate failed for {cell}"),
            });
        }
    }
    Ok(())
}

/// Resolve the signed payload value a stored-field comparison is measured
/// against. A predicate that compares against the payload without naming the
/// field is an invalid registration, not a comparison that trivially holds.
fn payload_comparand<'a>(
    event: &'a ProjectedEventInput,
    requirement: &crate::EventPreStateRequirementDescriptor,
    kind: &str,
) -> Result<Option<&'a Value>, EventCellContractError> {
    let payload_path = requirement
        .payload_field
        .ok_or_else(|| effect_set_error(kind, "stored-field comparison omits payload_field"))?;
    Ok(field_value(event, payload_path))
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
pub fn validate_registered_cell_writes(
    event: &Event,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<(), EventCellContractError> {
    validate_registered_cell_writes_in_context(
        event,
        EventCellContractContext::Standard,
        digest_suite,
    )
}

/// [`validate_registered_cell_writes`] plus the CBS plane check for the given
/// envelope context.
///
/// The plane is read from the registry, never guessed from the kind name, and
/// the ordinary-Realm bootstrap context is the only one in which a control
/// write may carry no CBS basis at all.
pub fn validate_registered_cell_writes_in_context(
    event: &Event,
    context: EventCellContractContext,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<(), EventCellContractError> {
    validate_registered_cell_plane_in_context(event, context)?;
    project_registered_cell_writes(event, digest_suite).map(|_| ())
}

/// Validate only the registry-declared CBS plane for an Event.
///
/// Admission lanes that evaluate `pre_state_requirements` from an
/// authoritative, lock-protected snapshot must perform this shape-independent
/// check before calling [`project_registered_cell_writes_with_pre_state`].
/// Keeping the two steps explicit prevents an empty placeholder pre-state
/// from rejecting a valid Event before the receiver can freeze its state.
pub fn validate_registered_cell_plane_in_context(
    event: &Event,
    context: EventCellContractContext,
) -> Result<(), EventCellContractError> {
    if event.kind.is_reducer_input() {
        validate_plane(event, classify_event_execution(event)?, context)?;
    }
    Ok(())
}

/// Classify the actual registered writes selected by this Event's signed
/// payload. Any selected security write makes the whole Event a control
/// command. Kind-level metadata is only an index of possible effects.
/// This evaluates the same conditions as projection without inventing a
/// frozen pre-state or requiring authority material merely to choose a lane.
/// Callers still validate the full payload, authorization and projected effects.
pub fn classify_event_execution(
    event: &Event,
) -> Result<Option<CbsEffectPlane>, EventCellContractError> {
    classify_registered_operation_execution(&ProjectedEventInput::from(event))
}

/// The same actual-write classifier for an immutable accepted operation.
pub fn classify_registered_operation_execution(
    event: &ProjectedEventInput,
) -> Result<Option<CbsEffectPlane>, EventCellContractError> {
    let kind = event.kind.as_str();
    if !event.kind.is_reducer_input() {
        return Ok(None);
    }
    let descriptor = event
        .kind
        .descriptor()
        .ok_or_else(|| EventCellContractError::UnregisteredReducerInput(kind.to_owned()))?;
    if descriptor.cell_writes.is_empty() {
        return Err(EventCellContractError::MissingCellContract(kind.to_owned()));
    }
    let mut plane = None;
    for write in descriptor.cell_writes {
        if !write_applies(event, write, kind)? {
            continue;
        }
        match write
            .execution
            .ok_or_else(|| effect_set_error(kind, "registered write omits execution"))?
        {
            EventCellExecution::Data => {
                if plane.is_none() {
                    plane = Some(CbsEffectPlane::Data);
                }
            }
            EventCellExecution::Security => {
                plane = Some(CbsEffectPlane::Control);
            }
        }
    }
    plane
        .map(Some)
        .ok_or_else(|| effect_set_error(kind, "reducer Event has no applicable registered writes"))
}

fn write_applies(
    event: &ProjectedEventInput,
    write: &EventCellWriteDescriptor,
    kind: &str,
) -> Result<bool, EventCellContractError> {
    if !condition_matches(event, write.condition_rule, kind)? {
        return Ok(false);
    }
    let Some(expansion) = write.for_each_rule else {
        return Ok(true);
    };
    let field = expansion
        .field(EventCellRuleKey::Field)
        .and_then(EventCellRule::as_str)
        .ok_or_else(|| effect_set_error(kind, "write expansion omits field"))?;
    let Some(value) = field_value(event, field) else {
        return Ok(false);
    };
    let max_items = expansion
        .field(EventCellRuleKey::MaxItems)
        .and_then(EventCellRule::as_u64)
        .ok_or_else(|| effect_set_error(kind, "write expansion omits max_items"))?;
    let entries = value
        .as_array()
        .ok_or_else(|| effect_set_error(kind, "write expansion requires an array"))?;
    if entries.is_empty() || entries.len() as u64 > max_items {
        return Err(effect_set_error(
            kind,
            "write expansion violates its registered bounds",
        ));
    }
    Ok(true)
}

/// Locate the registered `ak.component.invite.live_target.v1` write on one
/// invite kind.
///
/// Every caller below reads the slot's shape out of this one descriptor, so
/// there is no second, hand-written copy of the subject rule or the lattice
/// anywhere in the SDK. A registry that stopped declaring the write fails the
/// lookup instead of falling back.
fn invite_live_target_write(
    kind: &EventKind,
) -> Result<EventCellWriteDescriptor, EventCellContractError> {
    let descriptor = kind.descriptor().ok_or_else(|| {
        EventCellContractError::UnregisteredReducerInput(kind.as_str().to_owned())
    })?;
    descriptor
        .cell_writes
        .iter()
        .copied()
        .find(|write| write.cell_family == Some(arkret_wire::CellFamilyId::InviteLiveTargetV1))
        .ok_or_else(|| {
            EventCellContractError::MissingCellContract(format!(
                "{} declares no {} write",
                kind.as_str(),
                arkret_wire::CellFamilyId::InviteLiveTargetV1.as_str()
            ))
        })
}

/// Derive the Realm live-target cell for one invitee account.
///
/// The subject comes from the registered `ak.invite.create` `cell_subject`
/// rule, evaluated by the same code path a receiver uses on a signed Event, so
/// a producer building the `head_eq` precondition and a receiver projecting the
/// accepted Event cannot disagree. A producer needs this before its Event id
/// exists — `preconditions[]` is part of the preimage that id is computed from
/// — which is why the source here is payload-only.
///
/// There is deliberately no scan-the-Realm variant: `governance-objects.md`
/// section 5.3 makes this cell the sole truth source for live directed-invite
/// uniqueness, and an implementation-private index is not Realm state.
pub fn invite_live_target_cell(
    invitee_account_id: &AccountId,
) -> Result<CellRef, EventCellContractError> {
    let kind = EventKind::InviteCreate;
    let write = invite_live_target_write(&kind)?;
    let family = write
        .cell_family
        .map(|family| family.as_str())
        .ok_or_else(|| effect_set_error(kind.as_str(), "cell write omits cell_family"))?;
    let payload = BTreeMap::from([(
        "invitee_account_id".to_owned(),
        serde_json::to_value(invitee_account_id).map_err(|error| {
            subject_error(
                kind.as_str(),
                &format!("invitee_account_id is not serialisable: {error}"),
            )
        })?,
    )]);
    let subject = derive_subject_value(
        CellSubjectSource::from_payload(kind.as_str(), &payload),
        write.cell_subject_rule,
    )?;
    CellRef::new(format!("ak:cell:{family}:{subject}")).map_err(|error| {
        EventCellContractError::InvalidCell {
            kind: kind.as_str().to_owned(),
            message: error.to_string(),
        }
    })
}

/// The free value of the live-target slot: the register value that means "no
/// live directed invite for this account".
///
/// It is JSON `null`, and it is not a sentinel the registry declares. Since
/// `event-auth-state-resolution.md` section 9.3.1.2 a `sequenced_state` cell with
/// no active head reads `null` protocol-wide; the registry's `initial_value` /
/// `sentinel_writers` mechanism is gone. A released slot is *not* an unwritten
/// slot: the release Move writes `null` explicitly and keeps its own head, so
/// the two are the same business value but different protocol states, and the
/// signed precondition and sequenced reducer order are what stop an
/// older basis from claiming a slot that was freed by a *later* release.
pub fn invite_live_target_free_value() -> Value {
    Value::Null
}

/// The state of one Realm live-target slot.
///
/// "Occupied" *is* the definition of "a live directed invite exists for this
/// account" (`governance-objects.md` section 5.3). There is no second state
/// axis to consult and no wall-clock comparison to make: `expires_at` passing
/// does not free the slot, it only authorises somebody to submit the
/// `ak.invite.revoke` that does.
///
/// The occupied value is the occupying `ak.invite.create` Event id spelled
/// `ak:event:` **verbatim**, never the `ak:invite:` retype of the same 33-octet
/// token. That is why [`Self::HeldBy`] carries an [`EventId`] and why
/// [`Self::held_by_invite`] is the only way in from an `InviteId`: the retype
/// happens once, here. A release Move that asserted the `ak:invite:` spelling
/// as its `head_eq` value would compare unequal forever and strand the slot,
/// and the mistake only surfaces the next time somebody invites that account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InviteLiveTargetSlot {
    /// Free: the next `ak.invite.create` may claim it. The business value is
    /// `null` whether the slot was never written or explicitly released.
    Free,
    /// Claimed by the directed invite this `ak.invite.create` Event created.
    HeldBy(EventId),
}

impl InviteLiveTargetSlot {
    /// The slot value an existing invite holds, retyping its `ak:invite:`
    /// spelling into the `ak:event:` one the register actually stores.
    pub fn held_by_invite(invite_id: &arkret_wire::InviteId) -> Self {
        Self::HeldBy(invite_id.event_id())
    }

    /// Read a slot out of a frozen pre-state value.
    ///
    /// Anything that is neither `null` nor a valid Event id is a corrupted
    /// register, not an empty slot: reporting it as free would hand the next
    /// `ak.invite.create` a `head_eq` that silently overwrites a live invite.
    pub fn from_cell_value(value: &Value) -> Result<Self, EventCellContractError> {
        if *value == invite_live_target_free_value() {
            return Ok(Self::Free);
        }
        let occupant = value.as_str().ok_or_else(|| {
            effect_set_error(
                EventKind::InviteCreate.as_str(),
                "live-target slot value must be a string",
            )
        })?;
        EventId::new(occupant.to_owned())
            .map(Self::HeldBy)
            .map_err(|error| {
                effect_set_error(
                    EventKind::InviteCreate.as_str(),
                    &format!("live-target slot value is not a create Event id: {error}"),
                )
            })
    }

    /// The occupying `ak.invite.create` Event id, or `None` when free.
    pub fn create_event_id(&self) -> Option<&EventId> {
        match self {
            Self::Free => None,
            Self::HeldBy(event_id) => Some(event_id),
        }
    }

    /// The exact `head_eq` value a Move must assert on this slot.
    ///
    /// `ak.invite.create` asserts the free value; every registered release Move
    /// asserts the stored `create_event_id`, so a slot already re-claimed by a
    /// later invite cannot be freed by an older Move.
    pub fn head_eq_value(&self) -> Result<Value, EventCellContractError> {
        match self {
            Self::Free => Ok(invite_live_target_free_value()),
            Self::HeldBy(event_id) => Ok(Value::String(event_id.as_str().to_owned())),
        }
    }

    /// The complete `head_eq` precondition for one invitee's slot.
    pub fn precondition(
        &self,
        invitee_account_id: &AccountId,
    ) -> Result<Precondition, EventCellContractError> {
        Ok(Precondition {
            cell_id: invite_live_target_cell(invitee_account_id)?,
            predicate: Predicate {
                op: PredicateOp::HeadEq,
                value: Some(self.head_eq_value()?),
                values: None,
                predicate_id: None,
            },
        })
    }
}

fn require_state_model_shape(
    kind: &str,
    projection_kind: &str,
    state_model: &str,
    value_shape: EventCellValueShape,
    allowed: &[(&str, EventCellValueShape)],
) -> Result<(), EventCellContractError> {
    if allowed.contains(&(state_model, value_shape)) {
        return Ok(());
    }
    Err(effect_set_error(
        kind,
        &format!(
            "effect_projection {projection_kind} is not valid for state model {state_model} with value shape {value_shape:?}"
        ),
    ))
}

fn require_set_shape(
    kind: &str,
    projection_kind: &str,
    state_model: &str,
    value_shape: EventCellValueShape,
) -> Result<(), EventCellContractError> {
    require_state_model_shape(
        kind,
        projection_kind,
        state_model,
        value_shape,
        &[
            ("or_set", EventCellValueShape::Set),
            ("sequenced_state", EventCellValueShape::Set),
        ],
    )
}

// The registry descriptor is destructured into its parts by the caller, and
// each part is a separate lookup key here; re-bundling them would only move
// the same arity behind a constructor.
#[allow(clippy::too_many_arguments)]
fn derive_effect_ops(
    event: &ProjectedEventInput,
    write: &EventCellWriteDescriptor,
    projection: EventCellRule,
    state_model: &str,
    value_shape: EventCellValueShape,
    kind: &str,
    dot: &str,
    digest_suite: arkret_canonical::DigestSuite,
    authority_resolver: Option<&CapabilityAuthorityResolver<'_>>,
) -> Result<Vec<ProjectedOp>, EventCellContractError> {
    let projection_kind = projection
        .operator()
        .ok_or_else(|| effect_set_error(kind, "effect_projection omits kind"))?;
    let source = |key: EventCellRuleKey, member: &str| -> Result<Value, EventCellContractError> {
        effect_source_value(
            event,
            write,
            projection.field(key).ok_or_else(|| {
                effect_set_error(
                    kind,
                    &format!("{} projection omits {member}", projection_kind.as_str()),
                )
            })?,
            kind,
            dot,
            digest_suite,
            authority_resolver,
        )
    };
    match projection_kind {
        EventCellRuleOperator::Transition => {
            require_state_model_shape(
                kind,
                projection_kind.as_str(),
                state_model,
                value_shape,
                &[("sequenced_state", EventCellValueShape::Register)],
            )?;
            let mut op = LatticeOp::empty();
            op.op_type = LatticeOpType::Transition;
            op.from = Some(source(EventCellRuleKey::From, "from")?);
            op.to = Some(source(EventCellRuleKey::To, "to")?);
            Ok(vec![ProjectedOp::Direct(op)])
        }
        EventCellRuleOperator::TransitionTo => {
            require_state_model_shape(
                kind,
                projection_kind.as_str(),
                state_model,
                value_shape,
                &[("sequenced_state", EventCellValueShape::Register)],
            )?;
            Ok(vec![ProjectedOp::TransitionTo {
                to: source(EventCellRuleKey::To, "to")?,
            }])
        }
        EventCellRuleOperator::Set => {
            require_state_model_shape(
                kind,
                projection_kind.as_str(),
                state_model,
                value_shape,
                &[
                    ("causal_register", EventCellValueShape::Register),
                    ("sequenced_state", EventCellValueShape::Register),
                ],
            )?;
            let mut op = LatticeOp::empty();
            op.value = Some(source(EventCellRuleKey::Value, "value")?);
            // Register writes deliberately leave `op.from` absent.
            // `event-auth-state-resolution.md` §9.3.1.4 deleted the rule that had
            // the projector copy this Move's whole-value `head_eq` into `from`:
            // binding supersession to the business value cannot tell
            // `A -> B -> A` from `A -> B -> A -> B`. Causality now travels as the
            // derived head-identity set that acceptance puts on
            // `StateWrite::supersedes`, which the projector cannot compute because
            // it only sees `kind + payload`.
            Ok(vec![ProjectedOp::Direct(op)])
        }
        EventCellRuleOperator::ApplyPatch => {
            require_state_model_shape(
                kind,
                projection_kind.as_str(),
                state_model,
                value_shape,
                &[
                    ("causal_register", EventCellValueShape::Register),
                    ("sequenced_state", EventCellValueShape::Register),
                ],
            )?;
            // `expected_prestate` is the only registered exception to "an
            // absent source path fails the Event closed" (`event-and-patch.md`
            // §2.4.2): the guard is optional by payload contract, so an absent
            // path means this write carries no prestate binding. The path is
            // still required to be `payload.*` — the binding is a
            // producer-signed claim about the frozen pre-state, which the other
            // source forms cannot express.
            let expected_prestate = match projection.field(EventCellRuleKey::ExpectedPrestate) {
                None => None,
                Some(declared) => {
                    let path = declared
                        .field(EventCellRuleKey::Field)
                        .and_then(EventCellRule::as_str)
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
                patch: source(EventCellRuleKey::Patch, "patch")?,
                expected_prestate,
            }])
        }
        EventCellRuleOperator::Append => {
            require_state_model_shape(
                kind,
                projection_kind.as_str(),
                state_model,
                value_shape,
                &[
                    ("ordered_log", EventCellValueShape::Log),
                    ("sequenced_state", EventCellValueShape::Log),
                ],
            )?;
            let mut op = LatticeOp::empty();
            op.op_type = LatticeOpType::Append;
            op.value = Some(source(EventCellRuleKey::Value, "value")?);
            op.issuer_seq = Some(
                source(EventCellRuleKey::IssuerSeq, "issuer_seq")?
                    .as_u64()
                    .ok_or_else(|| {
                        effect_set_error(kind, "append issuer_seq must derive an unsigned integer")
                    })?,
            );
            Ok(vec![ProjectedOp::Direct(op)])
        }
        EventCellRuleOperator::OrSetAdd => {
            require_set_shape(kind, projection_kind.as_str(), state_model, value_shape)?;
            let mut op = LatticeOp::empty();
            op.op_type = LatticeOpType::Add;
            op.tag = Some(or_set_tag(
                event,
                write,
                projection.field(EventCellRuleKey::Tag),
                kind,
                dot,
                digest_suite,
                authority_resolver,
            )?);
            op.value = Some(source(EventCellRuleKey::Value, "value")?);
            Ok(vec![ProjectedOp::Direct(op)])
        }
        EventCellRuleOperator::OrSetRemoveObserved => {
            require_set_shape(kind, projection_kind.as_str(), state_model, value_shape)?;
            Ok(vec![ProjectedOp::RemoveObserved {
                element_match: None,
            }])
        }
        EventCellRuleOperator::OrSetRemoveDots => {
            require_set_shape(kind, projection_kind.as_str(), state_model, value_shape)?;
            let dots = source(EventCellRuleKey::Dots, "dots")?;
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
        EventCellRuleOperator::OrSetDelta => {
            require_set_shape(kind, projection_kind.as_str(), state_model, value_shape)?;
            let selector = projection
                .field(EventCellRuleKey::Selector)
                .and_then(EventCellRule::as_str)
                .ok_or_else(|| effect_set_error(kind, "or_set_delta omits selector"))?;
            let discriminator = field_value(event, selector)
                .and_then(Value::as_str)
                .ok_or_else(|| effect_set_error(kind, "or_set_delta selector is missing"))?;
            let branch = projection
                .field(EventCellRuleKey::Branches)
                .and_then(|branches| branches.field_named(discriminator))
                .ok_or_else(|| {
                    effect_set_error(
                        kind,
                        &format!("or_set_delta selector has no branch for {discriminator}"),
                    )
                })?;
            let branch_op = branch
                .field(EventCellRuleKey::Op)
                .and_then(EventCellRule::as_str)
                .ok_or_else(|| effect_set_error(kind, "or_set_delta branch omits op"))?;
            let branch_source =
                |key: EventCellRuleKey, member: &str| -> Result<Value, EventCellContractError> {
                    effect_source_value(
                        event,
                        write,
                        branch.field(key).ok_or_else(|| {
                            effect_set_error(kind, &format!("or_set_delta branch omits {member}"))
                        })?,
                        kind,
                        dot,
                        digest_suite,
                        authority_resolver,
                    )
                };
            let mut op = LatticeOp::empty();
            op.tag = Some(or_set_tag(
                event,
                write,
                branch.field(EventCellRuleKey::Tag),
                kind,
                dot,
                digest_suite,
                authority_resolver,
            )?);
            match branch_op {
                "add" => {
                    op.op_type = LatticeOpType::Add;
                    op.value = Some(branch_source(EventCellRuleKey::Value, "value")?);
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
            &format!("unsupported effect_projection kind {}", other.as_str()),
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
    event: &ProjectedEventInput,
    write: &EventCellWriteDescriptor,
    source: Option<EventCellRule>,
    kind: &str,
    dot: &str,
    digest_suite: arkret_canonical::DigestSuite,
    authority_resolver: Option<&CapabilityAuthorityResolver<'_>>,
) -> Result<String, EventCellContractError> {
    let source = source.ok_or_else(|| effect_set_error(kind, "or_set op omits its tag source"))?;
    if source
        .field(EventCellRuleKey::EnvelopeField)
        .and_then(EventCellRule::as_str)
        == Some("event_id")
    {
        return Err(effect_set_error(
            kind,
            "or_set tag must use {\"dot\": true}; a bare event_id is not a dot",
        ));
    }
    effect_source_value(
        event,
        write,
        source,
        kind,
        dot,
        digest_suite,
        authority_resolver,
    )?
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
fn is_or_set_remove(projection_kind: EventCellRuleOperator) -> bool {
    matches!(
        projection_kind,
        EventCellRuleOperator::OrSetRemoveObserved | EventCellRuleOperator::OrSetRemoveDots
    )
}

fn effect_source_value(
    event: &ProjectedEventInput,
    write: &EventCellWriteDescriptor,
    source: EventCellRule,
    kind: &str,
    dot: &str,
    digest_suite: arkret_canonical::DigestSuite,
    authority_resolver: Option<&CapabilityAuthorityResolver<'_>>,
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
    let source = EventCellRule::Object(source);
    if source
        .field(EventCellRuleKey::Dot)
        .and_then(EventCellRule::as_bool)
        == Some(true)
    {
        return Ok(Value::String(dot.to_owned()));
    }
    if source
        .field(EventCellRuleKey::ProjectedValue)
        .and_then(EventCellRule::as_bool)
        == Some(true)
    {
        let rule = write.value_projection_rule.ok_or_else(|| {
            effect_set_error(
                kind,
                "projected_value source requires a declared value_projection",
            )
        })?;
        return derive_value_projection_value(event, rule, digest_suite);
    }
    if let Some(path) = source
        .field(EventCellRuleKey::Field)
        .and_then(EventCellRule::as_str)
    {
        // `"payload"` names the complete signed payload object, which is how
        // every facet cell that stores its payload verbatim is declared. It has
        // no dotted member suffix, so [`field_value`] — which walks members —
        // cannot resolve it and would fail the whole Event closed.
        if path == "payload" {
            return materialized_payload_root(event, write, kind, authority_resolver);
        }
        return field_value(event, path)
            .cloned()
            .ok_or_else(|| effect_set_error(kind, &format!("effect source {path} is missing")));
    }
    if let Some(field) = source
        .field(EventCellRuleKey::EnvelopeField)
        .and_then(EventCellRule::as_str)
    {
        // `realm_id` is the one envelope field whose wire form and in-memory
        // form differ: `ak.realm.create` omits it on the wire because the Realm
        // id is receiver-derived (from the Event for collaboration, or from the
        // signed actor DID for PCR; zh/models/realm-and-space.md section 2.5.0),
        // while `Event` keeps it resolved. Reducer projections want the resolved
        // value — the genesis create log is keyed by it.
        if field == "realm_id" {
            return Ok(Value::String(event.realm_id.to_string()));
        }
        return projected_envelope_value(event, field)
            .ok_or_else(|| effect_set_error(kind, &format!("envelope field {field} is missing")));
    }
    if let Some(value) = source.field(EventCellRuleKey::Const) {
        return Ok(value.to_json_value());
    }
    Err(effect_set_error(
        kind,
        "effect source must declare field, envelope_field, const, projected_value, or dot",
    ))
}

fn projected_envelope_value(event: &ProjectedEventInput, field: &str) -> Option<Value> {
    match field {
        "event_id" => Some(Value::String(event.event_id.as_str().to_owned())),
        "kind" => Some(Value::String(event.kind.as_str().to_owned())),
        "actor_id" => serde_json::to_value(&event.actor_id).ok(),
        "authorization_ref" => event
            .authorization_ref
            .as_ref()
            .and_then(|value| serde_json::to_value(value).ok()),
        "actor_seq" => Some(Value::Number(event.actor_seq.into())),
        "realm_id" => Some(Value::String(event.realm_id.as_str().to_owned())),
        "created_at" => Some(Value::String(arkret_canonical::format_timestamp_canonical(
            event.created_at,
        ))),
        "seal_basis" => event
            .seal_basis
            .as_ref()
            .and_then(|value| serde_json::to_value(value).ok()),
        _ => None,
    }
}

/// Materialize receiver-derived members that belong to a complete cell value
/// but are forbidden in the producer-authored payload.
///
/// Capability Grant actor identities are complete `ActorId` values in the
/// signed payload. Retired split Station-coordinate members are rejected.
fn materialized_payload_root(
    event: &ProjectedEventInput,
    write: &EventCellWriteDescriptor,
    kind: &str,
    authority_resolver: Option<&CapabilityAuthorityResolver<'_>>,
) -> Result<Value, EventCellContractError> {
    let mut payload = payload_root(event);
    if event.kind != EventKind::CapabilityGrant {
        return Ok(payload);
    }

    let grant = payload
        .as_object_mut()
        .and_then(|payload| payload.get_mut("grant"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            effect_set_error(
                kind,
                "capability grant materialization requires payload.grant object",
            )
        })?;
    let derived_members = write
        .derived_members_rule
        .and_then(EventCellRule::as_array)
        .ok_or_else(|| effect_set_error(kind, "capability grant write omits derived_members"))?;
    for retired in ["issuer_station_id", "subject_station_id"] {
        if grant.contains_key(retired) {
            return Err(effect_set_error(
                kind,
                &format!("producer-authored payload.grant.{retired} is forbidden"),
            ));
        }
    }
    let mut authority_audit = None;
    for member in derived_members {
        let name = member
            .field(EventCellRuleKey::Name)
            .and_then(EventCellRule::as_str)
            .ok_or_else(|| effect_set_error(kind, "derived member omits name"))?;
        if grant.contains_key(name) {
            return Err(effect_set_error(
                kind,
                &format!("producer-authored payload.grant.{name} is forbidden"),
            ));
        }
        match member
            .field(EventCellRuleKey::Derivation)
            .and_then(EventCellRule::as_str)
        {
            Some("capability_authority_depth" | "capability_authority_root_refs") => {
                let audit = match authority_audit.as_ref() {
                    Some(audit) => audit,
                    None => {
                        let resolve = authority_resolver.ok_or_else(|| {
                            EventCellContractError::CapabilityAuthorityProjection {
                                kind: kind.to_owned(),
                                message: "an authority resolver is required".to_owned(),
                            }
                        })?;
                        authority_audit = Some(
                            match derive_capability_authority_audit(
                                &Value::Object(grant.clone()),
                                resolve,
                            ) {
                                Ok(audit) => audit,
                                Err(CapabilityAuthorityProjectionError::UnresolvedGrant(
                                    grant_id,
                                )) => {
                                    return Err(
                                        EventCellContractError::CapabilityAuthorityDependency {
                                            kind: kind.to_owned(),
                                            grant_id,
                                        },
                                    );
                                }
                                Err(error) => {
                                    return Err(
                                        EventCellContractError::CapabilityAuthorityProjection {
                                            kind: kind.to_owned(),
                                            message: error.to_string(),
                                        },
                                    );
                                }
                            },
                        );
                        authority_audit
                            .as_ref()
                            .expect("authority audit was just initialized")
                    }
                };
                let value = match member
                    .field(EventCellRuleKey::Derivation)
                    .and_then(EventCellRule::as_str)
                {
                    Some("capability_authority_depth") => {
                        Value::Number(audit.authority_depth.into())
                    }
                    Some("capability_authority_root_refs") => {
                        Value::Array(audit.authority_root_refs.clone())
                    }
                    _ => unreachable!("matched authority derivation"),
                };
                grant.insert(name.to_owned(), value);
            }
            Some(derivation) => {
                return Err(effect_set_error(
                    kind,
                    &format!("unsupported derived member {derivation}"),
                ));
            }
            None => return Err(effect_set_error(kind, "derived member omits derivation")),
        }
    }
    Ok(payload)
}

fn condition_matches(
    event: &ProjectedEventInput,
    condition: Option<EventCellRule>,
    kind: &str,
) -> Result<bool, EventCellContractError> {
    let Some(condition) = condition else {
        return Ok(true);
    };
    let condition_kind = condition
        .operator()
        .ok_or_else(|| effect_set_error(kind, "condition omits kind"))?;
    let present = |path: &str| field_value(event, path).is_some_and(|value| !value.is_null());
    match condition_kind {
        EventCellRuleOperator::FieldPresent => condition
            .field(EventCellRuleKey::Field)
            .and_then(EventCellRule::as_str)
            .map(present)
            .ok_or_else(|| effect_set_error(kind, "field_present omits field")),
        EventCellRuleOperator::FieldAbsent => condition
            .field(EventCellRuleKey::Field)
            .and_then(EventCellRule::as_str)
            .map(|path| !present(path))
            .ok_or_else(|| effect_set_error(kind, "field_absent omits field")),
        EventCellRuleOperator::FieldEquals => {
            let path = condition
                .field(EventCellRuleKey::Field)
                .and_then(EventCellRule::as_str)
                .ok_or_else(|| effect_set_error(kind, "field_equals omits field"))?;
            let expected = condition
                .field(EventCellRuleKey::Const)
                .ok_or_else(|| effect_set_error(kind, "field_equals omits const"))?;
            if !matches!(
                expected,
                EventCellRule::String(_) | EventCellRule::Integer(_) | EventCellRule::Bool(_)
            ) {
                return Err(effect_set_error(
                    kind,
                    "field_equals const must be a string, number, or boolean",
                ));
            }
            let expected = expected.to_json_value();
            Ok(field_value(event, path) == Some(&expected))
        }
        other => Err(effect_set_error(
            kind,
            &format!("unsupported condition kind {}", other.as_str()),
        )),
    }
}

fn effect_set_error(kind: &str, message: &str) -> EventCellContractError {
    EventCellContractError::EffectSetMismatch {
        kind: kind.to_owned(),
        message: message.to_owned(),
    }
}

fn derive_value_projection_value(
    event: &ProjectedEventInput,
    rule: EventCellRule,
    _digest_suite: arkret_canonical::DigestSuite,
) -> Result<Value, EventCellContractError> {
    let kind = event.kind.as_str().to_owned();
    if rule.operator() != Some(EventCellRuleOperator::Object) {
        return Err(projection_error(
            &kind,
            "value projection kind must be object",
        ));
    }
    let members = rule
        .field(EventCellRuleKey::Members)
        .and_then(EventCellRule::as_array)
        .ok_or_else(|| projection_error(&kind, "value projection members are missing"))?;

    let mut projected = serde_json::Map::new();
    for member in members {
        let name = member
            .field(EventCellRuleKey::Name)
            .and_then(EventCellRule::as_str)
            .ok_or_else(|| projection_error(&kind, "value projection member is unnamed"))?;
        let optional = member
            .field(EventCellRuleKey::Optional)
            .and_then(EventCellRule::as_bool)
            .unwrap_or(false);

        if let Some(literal) = member.field(EventCellRuleKey::Literal) {
            projected.insert(name.to_owned(), literal.to_json_value());
            continue;
        }
        let resolved = if let Some(path) = member
            .field(EventCellRuleKey::Field)
            .and_then(EventCellRule::as_str)
        {
            field_value(event, path).cloned()
        } else if let Some(path) = member
            .field(EventCellRuleKey::EnvelopeField)
            .and_then(EventCellRule::as_str)
        {
            projected_envelope_value(event, path)
        } else if let Some(derivation) = member
            .field(EventCellRuleKey::Derivation)
            .and_then(EventCellRule::as_str)
        {
            member_derivation(event, derivation, &kind)?
        } else if let Some(descriptor) = member.field(EventCellRuleKey::NormalizedStringSet) {
            normalized_string_set_member(event, descriptor, &kind)?
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

fn member_derivation(
    event: &ProjectedEventInput,
    derivation: &str,
    kind: &str,
) -> Result<Option<Value>, EventCellContractError> {
    match derivation {
        "event_digest_from_event_id" => Ok(Some(Value::String(
            event.event_id.event_digest().to_string(),
        ))),
        "mls_genesis_transition_digest" => {
            let digest = arkret_wire::mls_genesis_transition_digest(&payload_root(event))
                .map_err(|error| projection_error(kind, &error.to_string()))?;
            Ok(Some(Value::String(digest.to_string())))
        }
        "mls_commit_transition_digest" => {
            let encoded = event
                .payload
                .get("commit_bytes_b64")
                .and_then(Value::as_str)
                .ok_or_else(|| projection_error(kind, "payload.commit_bytes_b64 is missing"))?;
            let bytes = arkret_canonical::base64url_decode(encoded)
                .map_err(|error| projection_error(kind, &error.to_string()))?;
            Ok(Some(Value::String(arkret_canonical::sha256_digest(bytes))))
        }
        _ => Err(projection_error(
            kind,
            &format!("unsupported value projection derivation {derivation}"),
        )),
    }
}

/// Project a registered closed string set as its canonical array value.
///
/// The normalization is the one [`string_set_digest_component_value`] applies to
/// a cell subject (`conformance/encoding.md` section 9.5.1), and that is the
/// whole point of registering the member: `ak.component.identity.accountability.v1`
/// keys its cell by the digested scope set and carries the same set in the
/// value, so the two registered writers of that cell — the standalone
/// `ak.identity.accountability_grant` and the atomic `ak.agent.provision`
/// projection — cannot disagree about what the set is. A bare string is the
/// one-element set, so `"agent_operator"` and `["agent_operator"]` project one
/// value into one cell.
fn normalized_string_set_member(
    event: &ProjectedEventInput,
    descriptor: EventCellRule,
    kind: &str,
) -> Result<Option<Value>, EventCellContractError> {
    let object = descriptor
        .as_object()
        .ok_or_else(|| projection_error(kind, "normalized_string_set must be an object"))?;
    if object.len() != 2
        || descriptor.field(EventCellRuleKey::Field).is_none()
        || descriptor.field(EventCellRuleKey::Context).is_none()
    {
        return Err(projection_error(
            kind,
            "normalized_string_set must contain only field and context",
        ));
    }
    let path = descriptor
        .field(EventCellRuleKey::Field)
        .and_then(EventCellRule::as_str)
        .filter(|path| path.starts_with("payload."))
        .ok_or_else(|| {
            projection_error(
                kind,
                "normalized_string_set field must be an explicit payload path",
            )
        })?;
    // The normalization contexts are closed. An unregistered one would claim a
    // set-equality domain no cell subject actually keys by, which is exactly the
    // divergence between subject and value this member exists to prevent.
    if descriptor
        .field(EventCellRuleKey::Context)
        .and_then(EventCellRule::as_str)
        != Some(arkret_wire::DomainSeparationId::ACCOUNTABILITY_SCOPE_SET_V1)
    {
        return Err(projection_error(
            kind,
            "normalized_string_set context is not registered",
        ));
    }
    let Some(value) = field_value(event, path) else {
        return Ok(None);
    };
    let values = canonical_string_set(value).map_err(|message| projection_error(kind, &message))?;
    Ok(Some(Value::Array(
        values.into_iter().map(Value::String).collect(),
    )))
}

fn projection_error(kind: &str, message: &str) -> EventCellContractError {
    EventCellContractError::SubjectDerivation {
        kind: kind.to_owned(),
        message: message.to_owned(),
    }
}

fn validate_plane(
    event: &Event,
    plane: Option<CbsEffectPlane>,
    context: EventCellContractContext,
) -> Result<(), EventCellContractError> {
    let kind = event.kind.as_str().to_owned();
    let matches = match (plane, context) {
        (Some(CbsEffectPlane::Control), EventCellContractContext::Standard) => {
            event.seal_basis.is_some() && event.auth_context.is_none()
        }
        (Some(CbsEffectPlane::Data), EventCellContractContext::Standard) => {
            event.seal_basis.is_none() && event.auth_context.is_some()
        }
        (
            Some(CbsEffectPlane::Control | CbsEffectPlane::Data),
            EventCellContractContext::OrdinaryRealmBootstrap
            | EventCellContractContext::DirectConversationFounding,
        ) => event.seal_basis.is_none() && event.auth_context.is_none(),
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(EventCellContractError::PlaneMismatch {
            kind,
            expected: plane
                .map(CbsEffectPlane::as_str)
                .unwrap_or("registered")
                .to_owned(),
        })
    }
}

/// The closed set of Event sources a registered `cell_subject` rule may read.
///
/// `event-and-patch.md` section 2.4.2 derives a subject from the signed
/// envelope and the schema-validated payload, and v1's envelope namespace is
/// just `envelope.event_id` plus `envelope.actor_id`. Naming that set as its
/// own type lets a *producer* evaluate the registered rule before the Event id
/// exists — a `head_eq` precondition is part of the preimage the id is computed
/// from — without growing a second, hand-spelled copy of the subject grammar.
/// A rule that reaches for an envelope source the caller does not have fails
/// closed rather than falling back to a substitute.
#[derive(Clone, Copy)]
struct CellSubjectSource<'a> {
    kind: &'a str,
    event_id: Option<&'a EventId>,
    actor_id: Option<&'a ActorId>,
    payload: &'a BTreeMap<String, Value>,
}

impl<'a> CellSubjectSource<'a> {
    fn from_event(event: &'a ProjectedEventInput) -> Self {
        Self {
            kind: event.kind.as_str(),
            event_id: Some(&event.event_id),
            actor_id: Some(&event.actor_id),
            payload: &event.payload,
        }
    }

    /// Payload-only source for a rule the registry declares purely over
    /// `payload.*`. Both envelope sources are absent, so a registry change that
    /// introduced one would be rejected here instead of silently locating a
    /// different cell.
    fn from_payload(kind: &'a str, payload: &'a BTreeMap<String, Value>) -> Self {
        Self {
            kind,
            event_id: None,
            actor_id: None,
            payload,
        }
    }
}

#[cfg(test)]
fn derive_subject(
    event: &Event,
    rule: Option<EventCellRule>,
) -> Result<String, EventCellContractError> {
    let projected = ProjectedEventInput::from(event);
    derive_subject_value(CellSubjectSource::from_event(&projected), rule)
}

fn derive_subject_value(
    event: CellSubjectSource<'_>,
    rule: Option<EventCellRule>,
) -> Result<String, EventCellContractError> {
    let kind = event.kind.to_owned();
    let Some(rule) = rule else {
        // `cell_subject: null` is a per-Realm singleton located by the Event
        // envelope `realm_id`. Its canonical wire subject segment is the literal
        // ASCII string `null` (`conformance/encoding.md` section 4). Encoding the
        // Realm id here instead would fork the `state_root` leaf set and leaf
        // order against any implementation that follows the spec.
        return Ok(NULL_SUBJECT.to_owned());
    };
    let rule_kind = rule
        .operator()
        .ok_or_else(|| subject_error(&kind, "cell subject rule omits kind"))?;
    match rule_kind {
        EventCellRuleOperator::Composite => {
            let components = rule
                .field(EventCellRuleKey::Components)
                .and_then(EventCellRule::as_array)
                .ok_or_else(|| subject_error(&kind, "composite components are missing"))?;
            derive_composite(event, components, &kind)
        }
        EventCellRuleOperator::Tuple => {
            let components = rule
                .field(EventCellRuleKey::Components)
                .and_then(EventCellRule::as_array)
                .ok_or_else(|| subject_error(&kind, "tuple components are missing"))?;
            derive_composite(event, components, &kind)
        }
        EventCellRuleOperator::Coalesce => {
            let fields = rule
                .field(EventCellRuleKey::Fields)
                .and_then(EventCellRule::as_array)
                .ok_or_else(|| subject_error(&kind, "coalesce fields are missing"))?;
            for field in fields {
                let Some(path) = (*field).as_str() else {
                    continue;
                };
                if let Some(value) = payload_value(event.payload, path) {
                    return scalar_subject(value).map_err(|message| subject_error(&kind, &message));
                }
                if let Some(value) = envelope_field(event, path) {
                    return Ok(value);
                }
            }
            Err(subject_error(&kind, "no coalesce field is present"))
        }
        // `conformance/encoding.md` section 4 dispatches subject embedding on
        // the registry `cell_subject.kind`. A `uri` subject is percent-encoded
        // in full — `:`, `/` and `%` included — so the canonical URI occupies a
        // single CellRef subject segment and two different URIs can never fold
        // onto one cell. Every other simple kind (`did` / `typed_id` /
        // `string` / `id:<kind>`) embeds its canonical scalar verbatim.
        EventCellRuleOperator::Uri => {
            let path = rule
                .field(EventCellRuleKey::Field)
                .and_then(EventCellRule::as_str)
                .ok_or_else(|| subject_error(&kind, "cell subject field is missing"))?;
            let value = payload_value(event.payload, path)
                .ok_or_else(|| subject_error(&kind, &format!("{path} is missing")))?;
            let scalar = scalar_subject(value).map_err(|message| subject_error(&kind, &message))?;
            Ok(arkret_wire::uri_cell_subject(&scalar))
        }
        _ => {
            let path = rule
                .field(EventCellRuleKey::Field)
                .and_then(EventCellRule::as_str)
                .ok_or_else(|| subject_error(&kind, "cell subject field is missing"))?;
            // `envelope.event_id` is legal only under an `id:<kind>` rule, and
            // it never yields the raw `ak:event:` string: the subject is the
            // *derived object id* (spec `zh/models/common-fields.md` section
            // 6.0). It has to be, or a create would write a different cell than
            // every later update of the same object, which locates it by
            // `payload.<kind>_id`.
            if path == EVENT_ID_SUBJECT_SOURCE {
                let event_id = event.event_id.ok_or_else(|| {
                    subject_error(&kind, "envelope.event_id is not available to this caller")
                })?;
                return retype_event_id(event_id, rule_kind.as_str(), &kind);
            }
            if let Some(value) = payload_value(event.payload, path) {
                return scalar_subject(value).map_err(|message| subject_error(&kind, &message));
            }
            envelope_field(event, path)
                .ok_or_else(|| subject_error(&kind, &format!("{path} is missing")))
        }
    }
}

/// The one envelope subject source that resolves to a derived value rather
/// than a field: this Event's own object id.
const EVENT_ID_SUBJECT_SOURCE: &str = "envelope.event_id";

/// The sole object id this Event derives, when its registry row declares
/// exactly one `id_source: event_derived` target.
///
/// Returns `None` for every other kind and for a multi-output Event.  Use
/// [`derived_object_ids`] when an Event may derive several different typed ID
/// kinds (spec `zh/models/common-fields.md` section 6.0).
pub fn derived_object_id(event: &Event) -> Option<String> {
    let mut ids = derived_object_ids(event);
    (ids.len() == 1).then(|| ids.pop().expect("length checked"))
}

/// Every object id this Event derives, in the registry-declared order.
///
/// A multi-output Event retypes the same 33-byte Event token into distinct prefixes;
/// the full typed IDs are therefore distinct.  Registry lint guarantees that
/// the target kinds are non-empty, unique and event-derived.
pub fn derived_object_ids(event: &Event) -> Vec<String> {
    derived_object_ids_for_kind(event.kind.as_str(), &event.event_id)
}

/// [`derived_object_id`] for a receiver that has the envelope's `kind` and
/// `event_id` but no parsed [`Event`] — a projection folding raw sync JSON, for
/// example.
///
/// Same registry row, same retype, so a surface reading events off the wire can
/// never disagree with one holding the typed envelope. Realm creation uses the
/// same event-derived rule for every purpose.
pub fn derived_object_id_for_kind(kind: &str, event_id: &EventId) -> Option<String> {
    let mut ids = derived_object_ids_for_kind(kind, event_id);
    (ids.len() == 1).then(|| ids.pop().expect("length checked"))
}

/// [`derived_object_ids`] for a receiver that has only the envelope kind and
/// event ID. Returns an empty vector for non-derived kinds.
pub fn derived_object_ids_for_kind(kind: &str, event_id: &EventId) -> Vec<String> {
    event_derived_id_kinds_for_kind(kind)
        .into_iter()
        .filter_map(|id_kind| retype_event_id(event_id, &format!("id:{id_kind}"), kind).ok())
        .collect()
}

/// Registry-declared object-id kinds derived by an Event kind.
///
/// This is the receiver-side source for pre-schema checks which must reject a
/// producer-carried object id before a closed payload schema reduces the error
/// to a generic additional-property failure. Non-derived and unregistered
/// Event kinds return an empty vector.
pub fn event_derived_id_kinds_for_kind(kind: &str) -> Vec<String> {
    let Some(contract) = crate::event_runtime_contract(kind) else {
        return Vec::new();
    };
    if contract.id_source != Some(crate::EventIdSource::EventDerived) {
        return Vec::new();
    }
    // The target id kind is declared, never inferred: `ak.profile.create`
    // makes an `ak:actor_profile:`, and `ak.circle.create` appends to a
    // Realm-level ordered log whose subject says nothing about the object it
    // creates. Guessing from the event kind's middle segment would be wrong for
    // both.
    contract
        .derived_id_kinds
        .iter()
        .map(|id_kind| (*id_kind).to_owned())
        .collect()
}

/// Retype this create Event's `event_id` into the object-id kind the rule
/// declares (`{"kind": "id:strand", "field": "envelope.event_id"}`).
///
/// The 32-byte Event token is shared verbatim; only the typed prefix changes. The
/// target kind MUST be one whose registry `id_source` is `event_derived` — a
/// producer-allocated kind can never be named this way, and accepting one would
/// silently mint an id nobody can re-derive.
fn retype_event_id(
    event_id: &EventId,
    rule_kind: &str,
    kind: &str,
) -> Result<String, EventCellContractError> {
    let id_kind = rule_kind.strip_prefix("id:").ok_or_else(|| {
        subject_error(
            kind,
            "envelope.event_id subject MUST declare an `id:<kind>` target",
        )
    })?;
    let prefix = format!("ak:{id_kind}:");
    if !arkret_wire::EVENT_DERIVED_ID_KIND_PREFIXES.contains(&prefix.as_str()) {
        return Err(subject_error(
            kind,
            &format!("{prefix} is not an event-derived id kind"),
        ));
    }
    let token = event_id
        .as_str()
        .strip_prefix(EventId::KIND_PREFIX)
        .expect("validated EventId has its canonical kind prefix");
    Ok(format!("{prefix}{token}"))
}

fn derive_composite(
    event: CellSubjectSource<'_>,
    components: &[EventCellRule],
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
    event: CellSubjectSource<'_>,
    component: &EventCellRule,
    kind: &str,
) -> Result<Value, EventCellContractError> {
    if let Some(path) = (*component).as_str() {
        let value = subject_field_value(event, path)
            .ok_or_else(|| subject_error(kind, &format!("{path} is missing")))?;
        return composite_scalar(value.as_ref()).map_err(|message| subject_error(kind, &message));
    }
    if component.operator() == Some(EventCellRuleOperator::StringSetDigest) {
        return string_set_digest_component_value(event, *component, kind);
    }
    if component.operator() == Some(EventCellRuleOperator::CanonicalJson) {
        let path = component
            .field(EventCellRuleKey::Field)
            .and_then(EventCellRule::as_str)
            .ok_or_else(|| subject_error(kind, "canonical_json component field is missing"))?;
        let value = subject_field_value(event, path)
            .ok_or_else(|| subject_error(kind, &format!("{path} is missing")))?;
        let canonical =
            arkret_canonical::canonical_json_bytes(value.as_ref()).map_err(|error| {
                subject_error(kind, &format!("{path} is not canonical JSON: {error}"))
            })?;
        let canonical = String::from_utf8(canonical)
            .map_err(|error| subject_error(kind, &format!("{path} is not UTF-8: {error}")))?;
        return Ok(Value::String(canonical));
    }
    if let Some(path) = component
        .field(EventCellRuleKey::Field)
        .and_then(EventCellRule::as_str)
    {
        let value = subject_field_value(event, path)
            .ok_or_else(|| subject_error(kind, &format!("{path} is missing")))?;
        return composite_scalar(value.as_ref()).map_err(|message| subject_error(kind, &message));
    }
    let path = select_field_path(event, *component, kind)?;
    let value = subject_field_value(event, &path)
        .ok_or_else(|| subject_error(kind, &format!("{path} is missing")))?;
    composite_scalar(value.as_ref()).map_err(|message| subject_error(kind, &message))
}

fn string_set_digest_component_value(
    event: CellSubjectSource<'_>,
    component: EventCellRule,
    kind: &str,
) -> Result<Value, EventCellContractError> {
    let object = component
        .as_object()
        .ok_or_else(|| subject_error(kind, "string_set_digest component must be an object"))?;
    if object.len() != 3
        || component.operator() != Some(EventCellRuleOperator::StringSetDigest)
        || component.field(EventCellRuleKey::Field).is_none()
        || component.field(EventCellRuleKey::Context).is_none()
    {
        return Err(subject_error(
            kind,
            "string_set_digest component must contain only kind, field, and context",
        ));
    }
    let path = component
        .field(EventCellRuleKey::Field)
        .and_then(EventCellRule::as_str)
        .filter(|path| path.starts_with("payload."))
        .ok_or_else(|| {
            subject_error(
                kind,
                "string_set_digest component field must be an explicit payload path",
            )
        })?;
    let context = component
        .field(EventCellRuleKey::Context)
        .and_then(EventCellRule::as_str)
        .ok_or_else(|| subject_error(kind, "string_set_digest component context is missing"))?;
    if kind == arkret_wire::event_kind_str::IDENTITY_ACCOUNTABILITY_GRANT
        && context != arkret_wire::DomainSeparationId::ACCOUNTABILITY_SCOPE_SET_V1
    {
        return Err(subject_error(
            kind,
            "accountability_scope string-set digest context is invalid",
        ));
    }
    let value = subject_field_value(event, path)
        .ok_or_else(|| subject_error(kind, &format!("{path} is missing")))?;
    let values =
        canonical_string_set(value.as_ref()).map_err(|message| subject_error(kind, &message))?;
    if kind == arkret_wire::event_kind_str::IDENTITY_ACCOUNTABILITY_GRANT
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

/// The single normalization of a registered closed string set, shared by the
/// `string_set_digest` cell-subject component and the `normalized_string_set`
/// value-projection member.
///
/// A bare string is the one-element set; an array is a non-empty duplicate-free
/// set of strings; the canonical order is ascending raw UTF-8 bytes. Array order
/// carries no meaning on the wire, so equivalent spellings must normalize to one
/// sequence — otherwise the same endorsement would key two cells, or key one
/// cell with two values.
fn canonical_string_set(value: &Value) -> Result<Vec<String>, String> {
    let mut values = match value {
        Value::String(value) => vec![value.clone()],
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "string set elements must be strings".to_owned())
            })
            .collect::<Result<Vec<_>, String>>()?,
        _ => return Err("string set source must be a string or string array".to_owned()),
    };
    if values.is_empty() {
        return Err("string set must not be empty".to_owned());
    }
    if values.iter().collect::<BTreeSet<_>>().len() != values.len() {
        return Err("string set must contain unique values".to_owned());
    }
    values.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    Ok(values)
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
    event: CellSubjectSource<'_>,
    component: EventCellRule,
    kind: &str,
) -> Result<String, EventCellContractError> {
    if component.operator() != Some(EventCellRuleOperator::Select) {
        return Err(subject_error(
            kind,
            "composite component has an unknown kind",
        ));
    }
    let selector = component
        .field(EventCellRuleKey::Selector)
        .and_then(EventCellRule::as_str)
        .ok_or_else(|| subject_error(kind, "select component is missing selector"))?;
    let branches = component
        .field(EventCellRuleKey::Branches)
        .ok_or_else(|| subject_error(kind, "select component is missing branches"))?;
    let discriminator_value = subject_field_value(event, selector)
        .ok_or_else(|| subject_error(kind, &format!("selector {selector} is missing")))?;
    let discriminator = discriminator_value
        .as_ref()
        .as_str()
        .ok_or_else(|| subject_error(kind, &format!("selector {selector} is not a string")))?;
    let branch = branches.field_named(discriminator).ok_or_else(|| {
        subject_error(
            kind,
            &format!("selector {selector} has no registered branch"),
        )
    })?;
    let selected = branch
        .field(EventCellRuleKey::Field)
        .and_then(EventCellRule::as_str)
        .ok_or_else(|| subject_error(kind, "selected branch declares no field"))?;
    Ok(selected.to_owned())
}

/// The complete signed payload as one JSON object.
fn payload_root(event: &ProjectedEventInput) -> Value {
    Value::Object(event.payload.clone().into_iter().collect())
}

fn field_value<'a>(event: &'a ProjectedEventInput, path: &str) -> Option<&'a Value> {
    payload_value(&event.payload, path)
}

fn payload_value<'a>(payload: &'a BTreeMap<String, Value>, path: &str) -> Option<&'a Value> {
    let path = path.strip_prefix("payload.")?;
    let mut segments = path.split('.');
    let first = segments.next()?;
    let mut current = payload.get(first)?;
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
fn envelope_field(event: CellSubjectSource<'_>, path: &str) -> Option<String> {
    match path {
        "envelope.actor_id" => event.actor_id?.canonical_key().ok(),
        _ => None,
    }
}

fn subject_field_value<'a>(event: CellSubjectSource<'a>, path: &str) -> Option<Cow<'a, Value>> {
    payload_value(event.payload, path)
        .map(Cow::Borrowed)
        .or_else(|| {
            if path == "envelope.actor_id" {
                serde_json::to_value(event.actor_id?).ok().map(Cow::Owned)
            } else {
                envelope_field(event, path).map(|value| Cow::Owned(Value::String(value)))
            }
        })
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
    use arkret_wire::EventCellRuleField;
    use arkret_wire::events::kinds::{EventCellWriteDescriptor, EventKind};
    use serde_json::json;

    use super::*;

    #[test]
    fn one_event_can_derive_multiple_distinct_typed_ids() {
        let event_id = EventId::new("ak:event:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM")
            .expect("fixture event id");
        assert_eq!(
            derived_object_ids_for_kind("ak.self.moderation.report", &event_id),
            vec![
                "ak:report:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
                "ak:moderation_queue_item:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            ]
        );
        assert_eq!(
            derived_object_id_for_kind("ak.self.moderation.report", &event_id),
            None,
            "the singular helper must fail closed for a multi-output Event"
        );
    }

    #[test]
    fn event_derived_id_kinds_are_read_from_the_registry() {
        assert_eq!(
            event_derived_id_kinds_for_kind("ak.self.moderation.report"),
            vec!["report", "moderation_queue_item"]
        );
        assert_eq!(
            event_derived_id_kinds_for_kind("ak.circle.create"),
            vec!["circle"]
        );
        assert!(event_derived_id_kinds_for_kind("ak.message.update").is_empty());
    }

    #[test]
    fn newly_closed_genesis_kinds_derive_their_typed_ids() {
        let event_id = EventId::new("ak:event:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM")
            .expect("fixture event id");
        for (event_kind, expected) in [
            (
                "ak.audit.session.request",
                "ak:audit_session:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            ),
            (
                "ak.audit.release",
                "ak:audit_release:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            ),
            (
                "ak.invite.create",
                "ak:invite:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            ),
            (
                "ak.invite.third_party",
                "ak:invite:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            ),
        ] {
            assert_eq!(
                derived_object_id_for_kind(event_kind, &event_id).as_deref(),
                Some(expected),
                "{event_kind}"
            );
        }
    }

    /// Every registered cell write a receiver derives for `event`.
    ///
    /// A producer supplies no effect at all, so this projection — not anything
    /// carried on the wire — is the subject of every assertion below.
    fn project(event: &Event) -> Vec<ProjectedCellWrite> {
        project_registered_cell_writes(event, arkret_canonical::DigestSuite::Sha256)
            .expect("the registered contract must be evaluable")
    }

    fn sole_write(event: &Event) -> EventCellWriteDescriptor {
        let writes = event.kind.descriptor().unwrap().cell_writes;
        assert_eq!(
            writes.len(),
            1,
            "test fixture must target one registered write"
        );
        writes[0]
    }

    fn subject_rule(event: &Event) -> Option<EventCellRule> {
        sole_write(event).cell_subject_rule
    }

    fn write(cell: &str, op: ProjectedOp) -> ProjectedCellWrite {
        ProjectedCellWrite {
            cell_id: CellRef::new(cell).unwrap(),
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

    fn rsvp_event(occurrence: Value) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:AUf4Nwr-Lqj1RlqDi4awPbskicm37buT2CswWBfZbgLe",
            "kind": EventKind::RsvpSet,
            "realm_id": "ak:realm:AQOJcuEsMahV_eXZxrvKxOc_1fBMQCLgofI2jenpts5n",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AQOJcuEsMahV_eXZxrvKxOc_1fBMQCLgofI2jenpts5n"},
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:web:principal.example"
            }},
            "actor_seq": 7,
            "created_at": "2026-07-26T01:00:00.000Z",
            "hlc": "019f9e500000-0000-aabbccdd",
            "prev_refs": [],
            "auth_context": {
                "key_id": "device:019f9e50-d787-74e0-8731-c9ad5eaa9183",
                "key_epoch": 1,
                "authority_refs": ["ak:seal:sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"]
            },
            "payload": {
                "event_ref": "ak:strand:AQVC6IqFkbYCve-UUUa0ciJb36fBVkZWvlnEwgTs3Q15",
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
        assert_eq!(
            derive_subject(&event, subject_rule(&event)).unwrap(),
            "-9qLc7Kio2nqksl6UbozbVpH6BFDu_uurV0Lm_ey8SQ"
        );
        validate_registered_cell_writes(&event, arkret_canonical::DigestSuite::Sha256).unwrap();

        // effect_projection = set(payload.entry): the lattice value is the whole
        // entry, so basis and response converge together as one head. A producer
        // cannot narrow it to the bare `"accepted"` status — it supplies no
        // effect at all, and the projection is what the reducer applies.
        assert_eq!(
            project(&event),
            vec![write(
                "ak:cell:ak.component.calendar.rsvp.v1:-9qLc7Kio2nqksl6UbozbVpH6BFDu_uurV0Lm_ey8SQ",
                set_op(event.payload.get("entry").unwrap().clone()),
            )]
        );

        let instance = rsvp_event(json!("2026-07-26T09:00:00[Asia/Shanghai]"));
        assert_eq!(
            derive_subject(&instance, subject_rule(&instance)).unwrap(),
            "x0pWo5xOHb5m39hyuIKmDzGHSPXURlw1F4k3vQWgdes"
        );
    }

    #[test]
    fn rsvp_composite_rejects_missing_invalid_and_unregistered_components() {
        let mut missing = rsvp_event(Value::Null);
        missing.payload.remove("occurrence");
        let rule = subject_rule(&missing);
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
        let projected = ProjectedEventInput::from(&event);
        assert!(matches!(
            component_value(
                CellSubjectSource::from_event(&projected),
                &EventCellRule::String("envelope.event_id"),
                EventKind::RsvpSet.as_str(),
            ),
            Err(EventCellContractError::SubjectDerivation { .. })
        ));
        assert!(matches!(
            component_value(
                CellSubjectSource::from_event(&projected),
                &EventCellRule::String("actor_id"),
                EventKind::RsvpSet.as_str(),
            ),
            Err(EventCellContractError::SubjectDerivation { .. })
        ));

        let mut shadow = rsvp_event(Value::Null);
        shadow.payload.insert(
            "actor_id".to_owned(),
            json!("did:webvh:z6mkfixture:mallory.example"),
        );
        assert_eq!(
            derive_subject(&shadow, rule).unwrap(),
            "-9qLc7Kio2nqksl6UbozbVpH6BFDu_uurV0Lm_ey8SQ"
        );

        const ENVELOPE_ACTOR: EventCellRule = EventCellRule::Object(&[
            EventCellRuleField {
                key: EventCellRuleKey::Kind,
                value: EventCellRule::Operator(EventCellRuleOperator::CanonicalJson),
            },
            EventCellRuleField {
                key: EventCellRuleKey::Field,
                value: EventCellRule::String("envelope.actor_id"),
            },
        ]);
        assert_eq!(
            component_value(
                CellSubjectSource::from_event(&projected),
                &ENVELOPE_ACTOR,
                EventKind::RsvpSet.as_str(),
            )
            .unwrap(),
            json!(
                r#"{"account_id":{"principal_id":"ak:did_core:webvh:z6mkfixture","station_id":"ak:did_core:web:principal.example"},"kind":"account"}"#
            )
        );
    }

    fn subject_event(kind: &str, payload: Value) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:AUf4Nwr-Lqj1RlqDi4awPbskicm37buT2CswWBfZbgLe",
            "kind": kind,
            "realm_id": "ak:realm:AQOJcuEsMahV_eXZxrvKxOc_1fBMQCLgofI2jenpts5n",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AQOJcuEsMahV_eXZxrvKxOc_1fBMQCLgofI2jenpts5n"},
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:web:principal.example"
            }},
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
        let descriptor = event
            .kind
            .descriptor()
            .unwrap_or_else(|| panic!("{kind} must have a generated descriptor"));
        assert_eq!(
            descriptor.cell_writes.len(),
            1,
            "{kind} must have exactly one registered write"
        );
        derive_subject(&event, descriptor.cell_writes[0].cell_subject_rule)
            .unwrap_or_else(|error| panic!("{kind} subject derivation failed: {error}"))
    }

    /// The invitee account every live-target fixture below addresses.
    fn live_target_invitee() -> Value {
        json!({
            "principal_id": "ak:did_core:webvh:z6mkfixturebob",
            "station_id": "ak:did_core:web:principal.example"
        })
    }

    #[test]
    fn invite_live_target_cell_equals_the_projected_create_write() {
        // The producer-side helper and the receiver-side projection must name
        // one cell. If they could disagree, the `head_eq` a client signs would
        // guard a different slot than the one the reducer claims.
        let invitee = live_target_invitee();
        let event = subject_event(
            "ak.invite.create",
            json!({
                "invitee_account_id": invitee,
                "introduction_evidence_digest": format!("sha256:{}", "a".repeat(64)),
                "expires_at": "2026-08-02T01:00:00.000Z"
            }),
        );
        let projected = project(&event);
        let live_target = projected
            .iter()
            .find(|write| {
                write
                    .cell_id
                    .as_str()
                    .starts_with("ak:cell:ak.component.invite.live_target.v1:")
            })
            .expect("ak.invite.create must claim the live-target slot");
        let account: AccountId = serde_json::from_value(invitee).expect("fixture account");
        assert_eq!(
            invite_live_target_cell(&account).expect("registered subject rule"),
            live_target.cell_id
        );
        // The claim write stores the create Event id verbatim, in `ak:event:`
        // form. This is the value every release Move has to assert.
        assert_eq!(
            live_target.op,
            set_op(json!(
                "ak:event:AUf4Nwr-Lqj1RlqDi4awPbskicm37buT2CswWBfZbgLe"
            ))
        );
    }

    #[test]
    fn live_target_head_eq_is_always_the_event_prefix() {
        // `invite_id` and `create_event_id` are one 33-octet token under two
        // prefixes. Asserting the `ak:invite:` spelling as `head_eq` compares
        // unequal forever and strands the slot, and the mistake only surfaces
        // the second time somebody invites that account — so the only way in
        // from an InviteId retypes.
        let invite_id =
            arkret_wire::InviteId::new("ak:invite:AUf4Nwr-Lqj1RlqDi4awPbskicm37buT2CswWBfZbgLe")
                .expect("fixture invite id");
        let slot = InviteLiveTargetSlot::held_by_invite(&invite_id);
        assert_eq!(
            slot.head_eq_value().expect("registered initial value"),
            json!("ak:event:AUf4Nwr-Lqj1RlqDi4awPbskicm37buT2CswWBfZbgLe")
        );
        assert_ne!(
            slot.head_eq_value().expect("registered initial value"),
            json!(invite_id.as_str())
        );
        assert_eq!(
            slot.create_event_id().map(EventId::as_str),
            Some("ak:event:AUf4Nwr-Lqj1RlqDi4awPbskicm37buT2CswWBfZbgLe")
        );
    }

    #[test]
    fn live_target_slot_reads_only_registered_values() {
        // The free value is JSON null, not a registry sentinel, and it
        // round-trips: the release write sets exactly this, which is what makes
        // the next create's `head_eq` succeed.
        let free = invite_live_target_free_value();
        assert_eq!(free, Value::Null);
        assert_eq!(
            InviteLiveTargetSlot::from_cell_value(&free).expect("free slot"),
            InviteLiveTargetSlot::Free
        );
        assert_eq!(
            InviteLiveTargetSlot::Free
                .head_eq_value()
                .expect("free slot head_eq"),
            free
        );

        // An `ak:invite:` value in the register is a producer that spelled the
        // token by hand. Reporting it as free would let the next create
        // overwrite a live invite, so it fails closed instead.
        assert!(matches!(
            InviteLiveTargetSlot::from_cell_value(&json!(
                "ak:invite:AUf4Nwr-Lqj1RlqDi4awPbskicm37buT2CswWBfZbgLe"
            )),
            Err(EventCellContractError::EffectSetMismatch { .. })
        ));
        assert!(matches!(
            InviteLiveTargetSlot::from_cell_value(&json!({"head": null})),
            Err(EventCellContractError::EffectSetMismatch { .. })
        ));
    }

    #[test]
    fn live_target_precondition_targets_the_registered_cell() {
        let invitee = live_target_invitee();
        let account: AccountId = serde_json::from_value(invitee).expect("fixture account");
        let cell = invite_live_target_cell(&account).expect("registered subject rule");
        let precondition = InviteLiveTargetSlot::Free
            .precondition(&account)
            .expect("registered contract");
        assert_eq!(precondition.cell_id, cell);
        assert_eq!(precondition.predicate.op, PredicateOp::HeadEq);
        assert_eq!(precondition.predicate.value, Some(Value::Null));
    }

    #[test]
    fn repaired_payload_paths_derive_every_registered_cell_subject() {
        for (kind, payload, expected) in [
            (
                "ak.organization.discovery",
                json!({"organization_id": "ak:did_core:webvh:z6mkfixture"}),
                "ak:did_core:webvh:z6mkfixture",
            ),
            // `ak.actor.discovery` registers a composite rule over
            // `canonical_json(payload.resource_id)`, so its subject is the
            // composite digest rather than the raw id. The sibling
            // `ak.organization.discovery` above uses the `did` rule and does
            // echo the id — the two are not interchangeable.
            (
                "ak.actor.discovery",
                json!({"resource_id": "ak:did_core:webvh:z6mkfixture"}),
                "UsNeK-fwWrQE9Q_4ApTCiPTVi7y2LuGsZ-dCW4MkKb8",
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
                "ak.identity.disclosure_policy",
                json!({"policy_id": "ak:policy:019f9e50-d787-74e0-8731-c9ad5eaa9182"}),
                "ak:policy:019f9e50-d787-74e0-8731-c9ad5eaa9182",
            ),
            (
                "ak.identity.disclosure_receipt",
                json!({"holder_principal_id": "ak:did_core:webvh:z6mkfixture"}),
                "ak:did_core:webvh:z6mkfixture",
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
                json!({"value": {"$id": "ak.schema.fixture.v1"}}),
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
        // The subject is `retype(envelope.event_id)` — `subject_event` stamps
        // `ak:event:AUf4Nwr-Lqj1RlqDi4awPbskicm37buT2CswWBfZbgLe`, so a payload id (here
        // deliberately a different value) can never move the cell.
        assert_eq!(
            registered_subject(
                "ak.relation.create",
                json!({"relation": {"id": "ak:relation:AQVC6IqFkbYCve-UUUa0ciJb36fBVkZWvlnEwgTs3Q15"}})
            ),
            "ak:relation:AUf4Nwr-Lqj1RlqDi4awPbskicm37buT2CswWBfZbgLe"
        );
        assert_eq!(
            registered_subject(
                "ak.profile.realm_override",
                json!({
                    "target_realm_id": "ak:realm:AQOJcuEsMahV_eXZxrvKxOc_1fBMQCLgofI2jenpts5n",
                    "target_ref": "ak:actor_profile:AQVC6IqFkbYCve-UUUa0ciJb36fBVkZWvlnEwgTs3Q15"
                })
            ),
            "_pDLwotQ564Gi3g8c_fE1lJt5gsMsahwcbPmfgVwXbU"
        );
    }

    fn accountability_event(scope: Value, status: &str) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:AbTm4abxkmMcE7rkV-Wz8Uk_vFh-cUlesAd-EsJX395Y",
            "kind": EventKind::IdentityAccountabilityGrant,
            "realm_id": "ak:realm:AQOJcuEsMahV_eXZxrvKxOc_1fBMQCLgofI2jenpts5n",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AQOJcuEsMahV_eXZxrvKxOc_1fBMQCLgofI2jenpts5n"},
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": "ak:did_core:web:issuer.example",
                "station_id": "ak:did_core:web:principal.example"
            }},
            "actor_seq": 7,
            "created_at": "2026-07-26T01:00:00.000Z",
            "hlc": "019f9e500000-0000-aabbccdd",
            "prev_refs": [],
            "payload": {
                "issuer_id": "ak:did_core:web:issuer.example",
                "subject_id": "ak:did_core:web:subject.example",
                "accountability_scope": scope,
                "not_before": "2026-07-26T01:00:00.000Z",
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
        derive_subject(&event, subject_rule(&event))
    }

    #[test]
    fn object_value_projection_can_copy_the_accepted_event_id() {
        let event = accountability_event(json!("employment"), "active");
        let projected = ProjectedEventInput::from(&event);
        const RULE: EventCellRule = EventCellRule::Object(&[
            EventCellRuleField {
                key: EventCellRuleKey::Kind,
                value: EventCellRule::Operator(EventCellRuleOperator::Object),
            },
            EventCellRuleField {
                key: EventCellRuleKey::Members,
                value: EventCellRule::Array(&[EventCellRule::Object(&[
                    EventCellRuleField {
                        key: EventCellRuleKey::Name,
                        value: EventCellRule::String("resolution_event_ref"),
                    },
                    EventCellRuleField {
                        key: EventCellRuleKey::EnvelopeField,
                        value: EventCellRule::String("event_id"),
                    },
                ])]),
            },
        ]);
        let value =
            derive_value_projection_value(&projected, RULE, arkret_canonical::DigestSuite::Sha256)
                .expect("event_id is a registered envelope projection source");

        assert_eq!(
            value,
            json!({"resolution_event_ref": event.event_id.as_str()})
        );
    }

    #[test]
    fn accountability_string_set_subject_matches_kats_and_exact_set_semantics() {
        assert_eq!(
            accountability_subject(json!("employment"), "active").unwrap(),
            "W6mzmx7aBvbnvJN6X3mC07gxG-W_hGxxlfLoaSmaxD8"
        );
        assert_eq!(
            accountability_subject(json!(["employment"]), "active").unwrap(),
            "W6mzmx7aBvbnvJN6X3mC07gxG-W_hGxxlfLoaSmaxD8"
        );
        assert_eq!(
            accountability_subject(json!(["employment", "agent_operator"]), "active").unwrap(),
            "29WEeBQFbK1yg62tfYg52igsQYx92bIU11NzyScJhMY"
        );
        assert_eq!(
            accountability_subject(json!(["agent_operator", "employment"]), "revoked").unwrap(),
            "29WEeBQFbK1yg62tfYg52igsQYx92bIU11NzyScJhMY"
        );
        assert_eq!(
            accountability_subject(
                json!(["employment", "contracted_service", "agent_operator"]),
                "active"
            )
            .unwrap(),
            "6_sumS5Yn0of_lBwL5FMwkjpQQzh3uyEb7_UZa6OysA"
        );
        assert_ne!(
            accountability_subject(json!("employment"), "active").unwrap(),
            accountability_subject(json!("agent_operator"), "active").unwrap()
        );

        let baseline = accountability_subject(json!("employment"), "active").unwrap();
        let mut different_issuer = accountability_event(json!("employment"), "active");
        different_issuer.payload.insert(
            "issuer_id".to_owned(),
            json!("ak:did_core:web:other-issuer.example"),
        );
        assert_ne!(
            derive_subject(&different_issuer, subject_rule(&different_issuer)).unwrap(),
            baseline
        );
        let mut different_subject = accountability_event(json!("employment"), "active");
        different_subject.payload.insert(
            "subject_id".to_owned(),
            json!("ak:did_core:web:other-subject.example"),
        );
        assert_ne!(
            derive_subject(&different_subject, subject_rule(&different_subject)).unwrap(),
            baseline
        );
    }

    #[test]
    fn accountability_record_projection_normalizes_scopes_without_rewriting_payload() {
        for (left, right) in [
            (json!("employment"), json!(["employment"])),
            (
                json!(["employment", "agent_operator"]),
                json!(["agent_operator", "employment"]),
            ),
        ] {
            let event = accountability_event(left, "active");
            let mut equivalent = accountability_event(right.clone(), "active");
            equivalent
                .payload
                .insert("proof".into(), json!({"source": "must not enter the cell"}));
            assert_eq!(project(&event), project(&equivalent));
            assert_eq!(equivalent.payload.get("accountability_scope"), Some(&right));
        }
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
        const DESCRIPTOR: EventCellRule = EventCellRule::Object(&[
            EventCellRuleField {
                key: EventCellRuleKey::Kind,
                value: EventCellRule::Operator(EventCellRuleOperator::StringSetDigest),
            },
            EventCellRuleField {
                key: EventCellRuleKey::Field,
                value: EventCellRule::String("payload.accountability_scope"),
            },
            EventCellRuleField {
                key: EventCellRuleKey::Context,
                value: EventCellRule::String("ak.accountability_scope_set.v1-wrong"),
            },
        ]);
        let projected = ProjectedEventInput::from(&event);
        assert!(matches!(
            component_value(
                CellSubjectSource::from_event(&projected),
                &DESCRIPTOR,
                EventKind::IdentityAccountabilityGrant.as_str()
            ),
            Err(EventCellContractError::SubjectDerivation { .. })
        ));

        // The producer cannot name a grant cell of its own: the target follows
        // from the issuer, the subject and the exact accountability-scope set,
        // and the register value is the closed projection — not the raw payload,
        // so the same endorsement written by `ak.agent.provision` lands one
        // identical value on the same cell.
        assert_eq!(
            project(&event),
            vec![write(
                "ak:cell:ak.component.identity.accountability.v1:W6mzmx7aBvbnvJN6X3mC07gxG-W_hGxxlfLoaSmaxD8",
                set_op(json!({
                    "issuer_id": "ak:did_core:web:issuer.example",
                    "subject_id": "ak:did_core:web:subject.example",
                    "accountability_scope": ["employment"],
                    "not_before": "2026-07-26T01:00:00.000Z",
                    "grant_status": "active"
                })),
            )]
        );
    }

    fn agent_provision_event(created_at: &str) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:AbTm4abxkmMcE7rkV-Wz8Uk_vFh-cUlesAd-EsJX395Z",
            "kind": EventKind::AgentProvision,
            "realm_id": "ak:realm:AQOJcuEsMahV_eXZxrvKxOc_1fBMQCLgofI2jenpts5n",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AQOJcuEsMahV_eXZxrvKxOc_1fBMQCLgofI2jenpts5n"},
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": "ak:did_core:web:issuer.example",
                "station_id": "ak:did_core:web:principal.example"
            }},
            "actor_seq": 4,
            "created_at": created_at,
            "hlc": "019f9e500000-0000-aabbccdd",
            "prev_refs": [],
            "seal_basis": {
                "leaves": ["ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
            },
            "payload": {
                "schema": "ak.agent.provision.v1",
                "agent_id": "ak:did_core:web:subject.example",
                "controller_principal_id": "ak:did_core:web:issuer.example",
                "principal_control_realm_id": "ak:realm:AQOJcuEsMahV_eXZxrvKxOc_1fBMQCLgofI2jenpts5n",
                "controller_authorization_ref": "did:web:issuer.example#controller-1",
                "agent_slug": "scheduler",
                "accountability_scope": "agent_operator",
                "selector_visibility": "public",
                "created_at": created_at
            },
            "proofs": []
        }))
        .unwrap()
    }

    fn accountability_record(event: &Event) -> ProjectedCellWrite {
        let mut records = project(event)
            .into_iter()
            .filter(|write| {
                write
                    .cell_id
                    .as_str()
                    .starts_with("ak:cell:ak.component.identity.accountability.v1:")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            records.len(),
            1,
            "{} must project exactly one accountability record",
            event.kind.as_str()
        );
        records.pop().expect("length checked")
    }

    /// `ak.vector.identity.accountability_record_sources.v1`: the standalone
    /// `ak.identity.accountability_grant` and the atomic `ak.agent.provision`
    /// projection are the two registered writers of one accountability record.
    ///
    /// Both key the cell by issuer principal, subject principal and the digested
    /// scope set, and both project the same closed value — the provision reading
    /// `not_before` off its envelope and pinning `grant_status` to `active`, the
    /// grant reading both from its signed payload. A bare string and a
    /// one-element array are the same set, so the spelling cannot fork the record
    /// either. Were the two to disagree on subject or on value, the same
    /// endorsement would address two cells, or drive one `bottom=reject` cell
    /// into conflict.
    #[test]
    fn provision_and_grant_project_one_accountability_record() {
        const CREATED_AT: &str = "2026-07-26T01:00:00.000Z";
        let provisioned = accountability_record(&agent_provision_event(CREATED_AT));
        let granted =
            accountability_record(&accountability_event(json!(["agent_operator"]), "active"));

        assert_eq!(provisioned.cell_id, granted.cell_id);
        assert_eq!(provisioned.op, granted.op);
        assert_eq!(
            provisioned.op,
            set_op(json!({
                "issuer_id": "ak:did_core:web:issuer.example",
                "subject_id": "ak:did_core:web:subject.example",
                "accountability_scope": ["agent_operator"],
                "not_before": CREATED_AT,
                "grant_status": "active"
            })),
        );
    }

    fn agent_key_cell(key: &str) -> CellRef {
        let subject =
            arkret_wire::composite_subject(&["ak:did_core:web:agent.example", key]).unwrap();
        CellRef::new(format!("ak:cell:ak.component.agent.key.v1:{subject}")).unwrap()
    }

    fn agent_replacement_fixture() -> (Event, EventId, FrozenPreState) {
        let old = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [11; 32]);
        let revoked = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [12; 32]);
        let concurrent = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [13; 32]);
        let old_authorization = json!({"agent_id":"ak:did_core:web:agent.example","key_id":"K1",
            "verification_method":"did:web:agent.example#K1"});
        let state = FrozenPreState::from([(
            agent_key_cell("K1"),
            json!([
                {"tag":format!("{old}:1"),"value":old_authorization},
                {"tag":format!("{revoked}:0"),"value":{"agent_id":"ak:did_core:web:agent.example","key_id":"K1","revoked_by":"ak:did_core:web:controller.example"}},
                {"tag":format!("{concurrent}:1"),"value":old_authorization}
            ]),
        )]);
        let event = realm_facet(
            EventKind::AgentKeyAuthorize,
            json!({
                "agent_id":"ak:did_core:web:agent.example","key_id":"K2",
                "verification_method":"did:web:agent.example#K2",
                "public_key":{"kty":"OKP","kid":"did:web:agent.example#K2","algorithm":"Ed25519","key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
                "supersedes":[{"key_id":"K1","authorized_event_ref":old}]
            }),
        );
        (event, old, state)
    }

    #[test]
    fn agent_replacement_removes_only_the_exact_old_authorization_and_adds_new_dot_one() {
        let (event, old, state) = agent_replacement_fixture();
        let writes = project_registered_cell_writes_with_pre_state(
            &event,
            arkret_canonical::DigestSuite::Sha256,
            &state,
        )
        .unwrap();
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0].cell_id, agent_key_cell("K1"));
        assert_eq!(writes[1].cell_id, agent_key_cell("K2"));
        let ProjectedOp::Direct(remove) = &writes[0].op else {
            panic!("replacement must remove one explicit dot, never observed-remove the cell")
        };
        assert_eq!(remove.op_type, LatticeOpType::Remove);
        assert_eq!(remove.tag.as_deref(), Some(format!("{old}:1").as_str()));
        // Both the revoke marker and the other authorization instance survive:
        // the receiver sees one exact removal, with no bulk/observed removal.
        let untouched = state
            .get(&agent_key_cell("K1"))
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["tag"].as_str() != remove.tag.as_deref())
            .collect::<Vec<_>>();
        assert_eq!(untouched.len(), 2);
        assert!(
            untouched
                .iter()
                .any(|entry| entry["value"].get("revoked_by").is_some())
        );
        assert!(
            untouched
                .iter()
                .any(|entry| entry["value"].get("verification_method").is_some())
        );
        let ProjectedOp::Direct(add) = &writes[1].op else {
            panic!("new authorization must be an add")
        };
        assert_eq!(add.op_type, LatticeOpType::Add);
        assert_eq!(
            add.tag.as_deref(),
            Some(format!("{}:1", event.event_id).as_str())
        );
        assert_eq!(add.value.as_ref().unwrap()["key_id"], "K2");

        let mut first_authorization = event;
        first_authorization.payload.remove("supersedes");
        let first = project_registered_cell_writes_with_pre_state(
            &first_authorization,
            arkret_canonical::DigestSuite::Sha256,
            &FrozenPreState::new(),
        )
        .unwrap();
        assert_eq!(first.len(), 1);
        let ProjectedOp::Direct(add) = &first[0].op else {
            panic!("first authorization must add")
        };
        assert_eq!(
            add.tag.as_deref(),
            Some(format!("{}:1", first_authorization.event_id).as_str()),
            "skipped supersedes expansion must not renumber the add write"
        );
    }

    #[test]
    fn agent_replacement_rejects_missing_duplicate_wrong_cell_and_wrong_event_dots() {
        let (event, _, state) = agent_replacement_fixture();
        let project = |candidate: &Event, snapshot: &FrozenPreState| {
            project_registered_cell_writes_with_pre_state(
                candidate,
                arkret_canonical::DigestSuite::Sha256,
                snapshot,
            )
        };
        assert!(
            project(&event, &FrozenPreState::new()).is_err(),
            "missing old cell cannot authorize removal"
        );
        let mut duplicate = event.clone();
        let entry = duplicate.payload["supersedes"][0].clone();
        duplicate
            .payload
            .get_mut("supersedes")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .push(entry);
        assert!(
            project(&duplicate, &state).is_err(),
            "duplicate authorization pair must be rejected"
        );
        let mut wrong_key = event.clone();
        wrong_key.payload.get_mut("supersedes").unwrap()[0]["key_id"] = json!("another-key");
        assert!(
            project(&wrong_key, &state).is_err(),
            "Event must name the exact old key cell"
        );
        let mut wrong_event = event.clone();
        wrong_event.payload.get_mut("supersedes").unwrap()[0]["authorized_event_ref"] = json!(
            EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [14; 32])
        );
        assert!(
            project(&wrong_event, &state).is_err(),
            "a different authorization Event is not observed"
        );
        let mut wrong_index = state.get(&agent_key_cell("K1")).unwrap().clone();
        wrong_index[0]["tag"] = json!(format!(
            "{}:0",
            event.payload["supersedes"][0]["authorized_event_ref"]
                .as_str()
                .unwrap()
        ));
        assert!(
            project(
                &event,
                &FrozenPreState::from([(agent_key_cell("K1"), wrong_index)])
            )
            .is_err(),
            "index zero is never the authorization add dot"
        );
        let mut wrong_value = state.get(&agent_key_cell("K1")).unwrap().clone();
        wrong_value[0]["value"]["key_id"] = json!("another-key");
        assert!(
            project(
                &event,
                &FrozenPreState::from([(agent_key_cell("K1"), wrong_value)])
            )
            .is_err(),
            "a tag cannot smuggle a different key value"
        );
    }

    fn realm_facet(kind: EventKind, payload: Value) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            "kind": kind,
            "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy"},
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:web:principal.example"
            }},
            "actor_seq": 3,
            "created_at": "2026-07-20T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "preconditions": [],
            "seal_basis": {
                "leaves": ["ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
            },
            "payload": payload,
            "proofs": []
        }))
        .unwrap()
    }

    /// Realm history-access initialization facet.
    fn history_access_event() -> Event {
        realm_facet(
            EventKind::RealmHistoryAccess,
            json!({"from": null, "to": "since_join"}),
        )
    }

    /// The history-access cell derived by the registry.
    const HISTORY_ACCESS_CELL: &str = "ak:cell:ak.component.realm.history_access.v1:null";

    #[test]
    fn validates_history_access_transition_from_registry() {
        validate_registered_cell_writes(
            &history_access_event(),
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();
    }

    #[test]
    fn projects_history_access_transition_from_registry() {
        assert_eq!(
            project(&history_access_event()),
            vec![write(
                HISTORY_ACCESS_CELL,
                transition_op(Value::Null, json!("since_join")),
            )]
        );
    }

    /// `ak.invite.create` carries a required `invitee_account_id`; an Invite
    /// with no direct invitee is the separate `ak.invite.third_party` kind.
    fn invite_create_event(kind: EventKind) -> Event {
        let mut payload = json!({});
        if kind == EventKind::InviteCreate {
            payload["invitee_account_id"] = json!({
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:web:principal.example"
            });
        }
        serde_json::from_value(json!({
            "event_id": "ak:event:AVcbARXDOZuMaYlp1-g60cl4c6Y5NzY10J6VMsgtrakA",
            "kind": kind,
            "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy"},
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:web:principal.example"
            }},
            "actor_seq": 4,
            "created_at": "2026-07-26T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "payload": payload,
            "proofs": []
        }))
        .unwrap()
    }

    const INVITE_LIFECYCLE_CELL: &str = "ak:cell:ak.component.invite.lifecycle.v1:ak:invite:AVcbARXDOZuMaYlp1-g60cl4c6Y5NzY10J6VMsgtrakA";
    const BOB_MEMBER_CELL: &str =
        "ak:cell:ak.component.member.state.v1:-R4dRtD6CAwTRae2S7Pu2Y-yX68SpjNQkAPrG7HLvk4";
    /// `ak.component.invite.live_target.v1` keyed by the one-component
    /// composite over `payload.invitee_account_id`. Every invite fixture below
    /// addresses the same invitee, so they all claim and release this slot.
    const INVITE_LIVE_TARGET_CELL: &str =
        "ak:cell:ak.component.invite.live_target.v1:RMIat7Rg9OslR6WIHOjxCmCFnUVUGyoovN1ldcxev88";

    #[test]
    fn invite_create_claims_the_live_target_slot_with_the_create_event_id() {
        // The producer picks neither the Invite ID, the slot subject nor the
        // transition, so the assertion is the exact projected set rather than a
        // rejected mutation. The lifecycle subject is retyped from event_id;
        // the slot subject is the one-component composite over the invitee
        // AccountId, and the stored value is verbatim `envelope.event_id` --
        // the `ak:event:` spelling, never the `ak:invite:` one
        // (governance-objects.md section 5.3).
        let directed = invite_create_event(EventKind::InviteCreate);
        assert_eq!(
            project(&directed),
            vec![
                write(
                    INVITE_LIFECYCLE_CELL,
                    transition_op(json!(null), json!("pending")),
                ),
                write(
                    INVITE_LIVE_TARGET_CELL,
                    set_op(json!(
                        "ak:event:AVcbARXDOZuMaYlp1-g60cl4c6Y5NzY10J6VMsgtrakA"
                    )),
                ),
            ]
        );

        // `invitee_account_id` is required on invite_create_payload and the slot
        // write is unconditional, so a create without it cannot derive its
        // second subject and fails closed. A third-party invite is a different
        // kind (`ak.invite.third_party`), not this one with a field omitted.
        let mut without_invitee = invite_create_event(EventKind::InviteCreate);
        without_invitee.payload.remove("invitee_account_id");
        project_registered_cell_writes(&without_invitee, arkret_canonical::DigestSuite::Sha256)
            .expect_err("a create with no invitee cannot address the live-target slot");
    }

    #[test]
    fn invite_accept_member_target_uses_explicit_envelope_actor() {
        let event: Event = serde_json::from_value(json!({
            "event_id": "ak:event:AVoVBx7js38H0fUT57Q-OzdWFD9lkqs6-SHqacF1Z0kE",
            "kind": EventKind::InviteAccept,
            "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy"},
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:web:principal.example"
            }},
            "actor_seq": 1,
            "created_at": "2026-07-26T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "payload": {
                "invite_id": "ak:invite:AVcbARXDOZuMaYlp1-g60cl4c6Y5NzY10J6VMsgtrakA"
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
                    ProjectedOp::TransitionTo {
                        to: json!("accepted"),
                    },
                ),
                write(
                    BOB_MEMBER_CELL,
                    ProjectedOp::TransitionTo { to: json!("join") }
                ),
            ]
        );
    }

    fn invite_terminal_event(kind: EventKind) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:Ae88ZtS-5TAd47HF5YoHYlf7n9J0LovDSKxh6tVLAhQK",
            "kind": kind,
            "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy"},
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:web:principal.example"
            }},
            "actor_seq": 5,
            "created_at": "2026-07-26T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "payload": {
                "invite_id": "ak:invite:AVcbARXDOZuMaYlp1-g60cl4c6Y5NzY10J6VMsgtrakA",
                "invitee_account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkfixture",
                    "station_id": "ak:did_core:web:principal.example"
                },
                "target_state": "revoked"
            },
            "proofs": []
        }))
        .unwrap()
    }

    /// The invitee this fixture's terminal Events name, as the invite
    /// lifecycle cell stores it.
    fn fixture_invitee() -> Value {
        json!({
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "station_id": "ak:did_core:web:principal.example"
        })
    }

    fn project_terminal(event: &Event, pre_state: &FrozenPreState) -> Vec<ProjectedCellWrite> {
        project_registered_cell_writes_with_pre_state(
            event,
            arkret_canonical::DigestSuite::Sha256,
            pre_state,
        )
        .expect("the registered contract must be evaluable")
    }

    fn stored_invitee(invitee: Value) -> FrozenPreState {
        FrozenPreState::from([(
            CellRef::new(INVITE_LIFECYCLE_CELL.to_owned()).unwrap(),
            json!({"invitee_account_id": invitee}),
        )])
    }

    #[test]
    fn invite_terminal_member_transition_is_exact() {
        // Both kinds release the live-target slot in the same Move: the
        // lifecycle transition and the `set null` on the slot are one atomic
        // write set (governance-objects.md section 5.3).
        let expected = vec![
            write(
                INVITE_LIFECYCLE_CELL,
                ProjectedOp::TransitionTo {
                    to: json!("revoked"),
                },
            ),
            write(INVITE_LIVE_TARGET_CELL, set_op(Value::Null)),
        ];
        let lifecycle = CellRef::new(INVITE_LIFECYCLE_CELL.to_owned()).unwrap();
        let stored_invitee_value = json!({"invitee_account_id": {
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "station_id": "ak:did_core:web:principal.example"
        }});
        let mut pre_state = FrozenPreState::new();
        pre_state.insert(lifecycle, stored_invitee_value);

        // Both kinds carry a `stored_field_matches_payload(invitee_account_id)`
        // pre-state requirement, so neither is evaluable against an empty
        // pre-state: a signed `invitee_account_id` with nothing stored is the
        // forged 3PID release direction and MUST be rejected.
        let revoke = invite_terminal_event(EventKind::InviteRevoke);
        assert_eq!(
            project_registered_cell_writes_with_pre_state(
                &revoke,
                arkret_canonical::DigestSuite::Sha256,
                &pre_state,
            )
            .unwrap(),
            expected
        );
        let forged = project_registered_cell_writes_with_pre_state(
            &revoke,
            arkret_canonical::DigestSuite::Sha256,
            &FrozenPreState::new(),
        )
        .unwrap_err();
        assert_eq!(forged.reason_code(), "reducer_projection_failed");

        // Supplying no snapshot at all is a different thing from supplying an
        // empty one: pre-state admission is the receiver's step, so the
        // pre-authoring projection must still yield the whole write set.
        // Conflating the two would make every kind that declares a requirement
        // unauthorable on the client.
        assert_eq!(project(&revoke), expected);

        let cancel = invite_terminal_event(EventKind::InviteCancel);
        assert_eq!(
            project_registered_cell_writes_with_pre_state(
                &cancel,
                arkret_canonical::DigestSuite::Sha256,
                &pre_state,
            )
            .unwrap(),
            expected
        );

        let missing = project_registered_cell_writes_with_pre_state(
            &cancel,
            arkret_canonical::DigestSuite::Sha256,
            &FrozenPreState::new(),
        )
        .unwrap_err();
        assert_eq!(missing.reason_code(), "invite_kind_requires_revoke");

        let mismatch = project_registered_cell_writes_with_pre_state(
            &cancel,
            arkret_canonical::DigestSuite::Sha256,
            &stored_invitee(json!({
                "principal_id": "ak:did_core:webvh:z6mkmallory",
                "station_id": "ak:did_core:web:principal.example"
            })),
        )
        .unwrap_err();
        assert_eq!(mismatch.reason_code(), "reducer_projection_failed");
    }

    #[test]
    fn stored_field_matches_payload_closes_both_directions() {
        // `stored_field_matches_payload` holds when the stored field and the
        // payload field are both absent, or both present and byte-identical
        // (`event-and-patch.md` section 2.4.2). Both failing directions are
        // security-relevant: a forged `invitee_account_id` on a third-party
        // Invite must not release someone else's direct slot, and an omitted
        // one on a direct Invite must not leave that slot occupied forever.
        let revoke = invite_terminal_event(EventKind::InviteRevoke);
        let forged = project_registered_cell_writes_with_pre_state(
            &revoke,
            arkret_canonical::DigestSuite::Sha256,
            &FrozenPreState::from([(
                CellRef::new(INVITE_LIFECYCLE_CELL.to_owned()).unwrap(),
                json!({"state": "pending"}),
            )]),
        )
        .unwrap_err();
        assert_eq!(forged.reason_code(), "reducer_projection_failed");

        let mut omitted = invite_terminal_event(EventKind::InviteRevoke);
        omitted.payload.remove("invitee_account_id");
        let omitted_error = project_registered_cell_writes_with_pre_state(
            &omitted,
            arkret_canonical::DigestSuite::Sha256,
            &stored_invitee(fixture_invitee()),
        )
        .unwrap_err();
        assert_eq!(omitted_error.reason_code(), "reducer_projection_failed");

        // Both absent is the third-party lane, and it projects the lifecycle
        // move alone.
        assert_eq!(
            project_terminal(
                &omitted,
                &FrozenPreState::from([(
                    CellRef::new(INVITE_LIFECYCLE_CELL.to_owned()).unwrap(),
                    json!({"state": "pending"}),
                )]),
            ),
            vec![write(
                INVITE_LIFECYCLE_CELL,
                ProjectedOp::TransitionTo {
                    to: json!("revoked"),
                },
            )]
        );
    }

    #[test]
    fn send_failed_revoke_does_not_evaluate_the_conditional_pre_state() {
        // `ak.invite.revoke` registers its pre-state requirement once per
        // non-`send_failed` target_state. `send_failed` is schema-barred from
        // carrying `invitee_account_id`, releases no slot, and its requirement
        // condition therefore never holds -- so a direct Invite whose stored
        // invitee is present must still be movable to that state.
        let mut event = invite_terminal_event(EventKind::InviteRevoke);
        event
            .payload
            .insert("target_state".to_owned(), json!("send_failed"));
        event.payload.remove("invitee_account_id");
        assert_eq!(
            project_terminal(&event, &stored_invitee(fixture_invitee())),
            vec![write(
                INVITE_LIFECYCLE_CELL,
                ProjectedOp::TransitionTo {
                    to: json!("send_failed"),
                },
            )]
        );
    }

    fn consent_revoke_event(observed_dots: Value) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:AbZaFFVA6-wyHEXt0cn9FZyvdNAvqOLngkxh8qyrpg1Z",
            "kind": EventKind::ConsentRevoke,
            "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy"},
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:web:principal.example"
            }},
            "actor_seq": 6,
            "created_at": "2026-07-26T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "seal_basis": {
                "leaves": ["ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]
            },
            "payload": {
                "consent_id": "ak:consent:019f9000-0000-7000-8000-000000000014",
                "observed_dot_ids": observed_dots,
                "revoked_at": "2026-07-26T00:00:00.000Z"
            },
            "proofs": []
        }))
        .unwrap()
    }

    #[test]
    fn consent_revoke_projects_each_explicit_dot_in_payload_order() {
        let first = "ak:event:AVcbARXDOZuMaYlp1-g60cl4c6Y5NzY10J6VMsgtrakA:0";
        let second = "ak:event:AVoVBx7js38H0fUT57Q-OzdWFD9lkqs6-SHqacF1Z0kE:3";
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
                    "ak:event:AVcbARXDOZuMaYlp1-g60cl4c6Y5NzY10J6VMsgtrakA:0",
                    "ak:event:AVcbARXDOZuMaYlp1-g60cl4c6Y5NzY10J6VMsgtrakA:0"
                ]),
                "must be unique",
            ),
            (
                json!(["ak:event:AVcbARXDOZuMaYlp1-g60cl4c6Y5NzY10J6VMsgtrakA:00"]),
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
        let mut event = invite_terminal_event(EventKind::InviteCancel);
        event.payload.remove("target_state");
        let mut pre_state = FrozenPreState::new();
        pre_state.insert(
            CellRef::new(INVITE_LIFECYCLE_CELL.to_owned()).unwrap(),
            json!({"invitee_account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:web:principal.example"
            }}),
        );
        let error = project_registered_cell_writes_with_pre_state(
            &event,
            arkret_canonical::DigestSuite::Sha256,
            &pre_state,
        )
        .unwrap_err();
        assert!(
            matches!(error, EventCellContractError::EffectSetMismatch { .. }),
            "got {error}"
        );
        assert_eq!(error.reason_code(), "effects_payload_mismatch");
    }

    fn realm_create_event(refs: Value) -> Event {
        let mut wire = json!({
            "event_id": "ak:event:AWX8BSZeeRJJ_ipjlL7Ll7EGSQkGrOPbmXFP_UmHb16G",
            "kind": EventKind::RealmCreate,
            "scope_ref": {"kind": "realm_genesis"},
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:web:principal.example"
            }},
            "actor_seq": 7,
            "created_at": "2026-07-26T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "refs": refs,
            "payload": {
                "object": {
                    "schema": "ak.schema.realm_genesis.v1",
                    "purpose": "collaboration",
                    "genesis_salt": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "trust_domain": "ak:trust_domain:example.net",
                    "schema_refs": ["ak.schema.realm.v1"],
                    "reducer_profile": "ak.reducer.core.v1",
                    "digest_algorithm": "sha256",
                    "security_class": "standard",
                    "encryption_profile": "mls_rfc9420",
                    "notary": {
                        "signer": {
                            "actor_id": "ak:did_core:webvh:z6mkfixture:alice.example",
                            "verification_method": "did:webvh:z6mkfixture:alice.example#key-1",
                            "key_kind": "ed25519_raw32",
                            "jose_algorithm": "Ed25519",
                            "frozen_public_key_b64u": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",

                        },
                        "max_clock_error_ms": 0
                    }
                }
            },
            "proofs": []
        });
        if refs.as_array().is_some_and(Vec::is_empty) {
            wire.as_object_mut().unwrap().remove("refs");
        }
        serde_json::from_value(wire).unwrap()
    }

    #[test]
    fn realm_create_ordered_log_projection_is_exact() {
        let event = realm_create_event(json!([]));

        let object = event.payload.get("object").unwrap().clone();
        // The genesis append carries the envelope `actor_seq` of 7. The
        // registry pins `issuer_seq` to `actor_seq` for every ordered_log
        // append and forbids cell-local constants: the coordinate is sparse,
        // and a genesis entry is not special-cased into slot zero.
        assert_eq!(
            project(&event),
            vec![
                write(arkret_wire::REALM_GENESIS_CELL, set_op(object.clone()),),
                write(
                    arkret_wire::REALM_CREATE_CELL,
                    append_op(
                        json!("ak:realm:AWX8BSZeeRJJ_ipjlL7Ll7EGSQkGrOPbmXFP_UmHb16G"),
                        7
                    ),
                ),
                write(
                    "ak:cell:ak.component.notary.v1:null",
                    set_op(object["notary"].clone()),
                ),
                write(
                    arkret_wire::REALM_REDUCER_PROFILE_CELL,
                    set_op(json!("ak.reducer.core.v1")),
                ),
                // The authority root is reducer-derived. The controller comes
                // from the signed envelope; epoch and generation are frozen
                // genesis literals.
                write(
                    arkret_wire::REALM_AUTHORITY_ROOT_CELL,
                    set_op(json!({
                        "controller_actor_id": {"kind": "account", "account_id": {
                            "principal_id": "ak:did_core:webvh:z6mkfixture",
                            "station_id": "ak:did_core:web:principal.example"
                        }},
                        "controller_epoch": 0,
                        "authority_generation": 0
                    })),
                ),
            ]
        );
    }

    #[test]
    fn realm_create_initial_resolution_projects_its_event_reference() {
        let mut event = realm_create_event(json!([]));
        let object = event
            .payload
            .get_mut("object")
            .and_then(Value::as_object_mut)
            .expect("realm create object");
        object.insert("purpose".to_owned(), json!("principal_control"));
        object.insert(
            "initial_resolution".to_owned(),
            json!({
                "did": "did:webvh:z6mkfixture:alice.example",
                "method_history_head": format!("sha256:{}", "a".repeat(64)),
                "version_id": "1-fixture"
            }),
        );

        let writes = project(&event);
        let resolution = writes
            .iter()
            .find(|write| {
                write.cell_id.as_str() == "ak:cell:ak.component.identity.resolution.v1:null"
            })
            .expect("initial resolution cell write");
        assert_eq!(
            resolution.op,
            set_op(json!({
                "did": "did:webvh:z6mkfixture:alice.example",
                "method_history_head": format!("sha256:{}", "a".repeat(64)),
                "version_id": "1-fixture",
                "resolution_event_ref": event.event_id.as_str(),
                "updated_at": "2026-07-26T00:00:00.000Z"
            }))
        );
    }

    fn call_event(kind: EventKind, payload: Value) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:AWX8BSZeeRJJ_ipjlL7Ll7EGSQkGrOPbmXFP_UmHb16G",
            "kind": kind,
            "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy"},
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:web:principal.example"
            }},
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
        let call_id = "ak:call:AUnMkflaxtGFOx2-bF9-47QlulhbzBTMRIGsIQWQuRxw";
        let participant = json!({
            "actor_id": "ak:did_core:webvh:z6mkfixture",
            "device_id": "ak:device:019f9000-0000-7000-8000-000000000023"
        });
        let event = call_event(
            EventKind::CallState,
            json!({
                "call_id": call_id,
                "state_transition": {"from": "ringing", "to": "active"},
                "focus": {"mode": "sfu", "session_focus": "fra-1"},
                "roster_delta": {"op": "join", "participant": participant}
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
                        "ak:event:AWX8BSZeeRJJ_ipjlL7Ll7EGSQkGrOPbmXFP_UmHb16G:7",
                        participant,
                    ),
                ),
            ]
        );
    }

    #[test]
    fn or_set_delta_rejects_an_unregistered_selector_branch() {
        let event = call_event(
            EventKind::CallState,
            json!({
                "call_id": "ak:call:AUnMkflaxtGFOx2-bF9-47QlulhbzBTMRIGsIQWQuRxw",
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
        let call_id = "ak:call:AZwnlibEkSqtTJzWuUHAfHh8TspusG4RzdW5sdYgAZym";
        let recording_id = "capture-019f9000";
        let subject = arkret_wire::composite_subject(&[call_id, recording_id]).unwrap();
        let recording_result = json!({
            "recording_start_event_id": "ak:event:AWX8BSZeeRJJ_ipjlL7Ll7EGSQkGrOPbmXFP_UmHb16G",
            "retention": {"consent_confirmed": true}
        });
        let recording = call_event(
            EventKind::CallRecordingStart,
            json!({
                "call_id": call_id,
                "recording_id": recording_id,
                "capture_kind": "recording",
                "result": recording_result
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
                    set_op(json!({"status": "pending", "details": recording_result})),
                ),
            ]
        );

        // The `capture_kind` discriminator alone moves both writes onto the
        // transcript families; a producer cannot mix the two capture axes.
        let transcript_result = json!({
            "transcript_start_event_id": "ak:event:AWX8BSZeeRJJ_ipjlL7Ll7EGSQkGrOPbmXFP_UmHb16G",
            "retention": {"consent_confirmed": true}
        });
        let transcript = call_event(
            EventKind::CallRecordingStart,
            json!({
                "call_id": call_id,
                "recording_id": recording_id,
                "capture_kind": "transcript",
                "result": transcript_result
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
                    set_op(json!({"status": "pending", "details": transcript_result})),
                ),
            ]
        );
    }

    #[test]
    fn projects_capability_grant_add_dot() {
        // Was `materializes_capability_grant_add_dot`.
        let event_id = "ak:event:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM";
        let grant_id = "ak:grant:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM";
        let event: Event = serde_json::from_value(json!({
            "event_id": event_id,
            "kind": EventKind::CapabilityGrant,
            "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy"},
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:web:principal.example"
            }},
            "actor_seq": 3,
            "created_at": "2026-07-26T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "payload": {
                "grant": {
                    "issuer_id": {"kind": "account", "account_id": {
                        "principal_id": "ak:did_core:webvh:z6mkfixture",
                        "station_id": "ak:did_core:web:principal.example"
                    }},
                    "subject": {"kind": "account", "account_id": {
                        "principal_id": "ak:did_core:webvh:z6mkfixture",
                        "station_id": "ak:did_core:web:principal.example"
                    }},
                    "actions": ["ak.realm.admin"],
                    "issuer_authority_refs": [{
                        "kind": "realm_root",
                        "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy",
                        "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                        "controller_epoch_at_issuance": 7,
                        "authority_generation": 2
                    }]
                }
            },
            "proofs": []
        }))
        .unwrap();

        // The cell subject retypes the accepted Event ID. The security set tag is
        // `<event_id>:<write_index>`, and the element is the ID-free signed
        // genesis payload. The materialized Grant gains its issuer Station coordinate from the
        // accepted envelope, never from producer payload input.
        let mut materialized_payload = serde_json::to_value(&event.payload).unwrap();
        materialized_payload["grant"]["authority_depth"] = json!(1);
        materialized_payload["grant"]["authority_root_refs"] = json!([{
            "kind": "realm_root",
            "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy",
            "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
            "authority_generation": 2
        }]);
        let audit_index = CapabilityAuthorityAuditIndex::from_events([&event]);
        assert_eq!(
            audit_index.resolve(grant_id),
            Some(CapabilityAuthorityAudit {
                authority_depth: 1,
                authority_root_refs: materialized_payload["grant"]["authority_root_refs"]
                    .as_array()
                    .unwrap()
                    .clone(),
            })
        );
        assert_eq!(
            project_registered_cell_writes_with_authority_resolver(
                &event,
                arkret_canonical::DigestSuite::Sha256,
                &|_| None,
            )
            .unwrap(),
            vec![write(
                &format!("ak:cell:ak.component.capability.grant.v1:{grant_id}"),
                add_op(&format!("{event_id}:0"), materialized_payload),
            )]
        );

        let error = project_registered_cell_writes(&event, arkret_canonical::DigestSuite::Sha256)
            .expect_err("generic projection without an authority resolver must fail closed");
        assert!(matches!(
            error,
            EventCellContractError::CapabilityAuthorityProjection { .. }
        ));

        let mut child = event;
        child
            .payload
            .get_mut("grant")
            .and_then(Value::as_object_mut)
            .unwrap()
            .insert(
                "issuer_authority_refs".to_owned(),
                json!([{
                    "kind": "grant",
                    "grant_id": "ak:grant:AWX8BSZeeRJJ_ipjlL7Ll7EGSQkGrOPbmXFP_UmHb16G"
                }]),
            );
        let error = project_registered_cell_writes_with_authority_resolver(
            &child,
            arkret_canonical::DigestSuite::Sha256,
            &|_| None,
        )
        .expect_err("an unprojected parent must remain an availability dependency");
        assert!(matches!(
            error,
            EventCellContractError::CapabilityAuthorityDependency { .. }
        ));
        assert_eq!(error.reason_code(), "temporarily_unavailable");
    }

    #[test]
    fn capability_authority_audit_uses_max_parent_depth_and_canonical_root_union() {
        let root_a = json!({
            "kind": "realm_root",
            "realm_id": "ak:realm:a",
            "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
            "authority_generation": 10
        });
        let root_b = json!({
            "kind": "realm_root",
            "realm_id": "ak:realm:a",
            "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
            "authority_generation": 2
        });
        let root_c = json!({
            "kind": "realm_root",
            "realm_id": "ak:realm:b",
            "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
            "authority_generation": 0
        });
        let grant = json!({
            "issuer_authority_refs": [
                {"kind": "grant", "grant_id": "parent-shallow"},
                {"kind": "grant", "grant_id": "parent-deep"},
                {
                    "kind": "realm_root",
                    "realm_id": "ak:realm:a",
                    "cell_ref": "ak:cell:ak.component.realm.authority_root.v1:null",
                    "controller_epoch_at_issuance": 99,
                    "authority_generation": 2
                }
            ]
        });
        let audit = derive_capability_authority_audit(&grant, &|grant_id| match grant_id {
            "parent-shallow" => Some(CapabilityAuthorityAudit {
                authority_depth: 1,
                authority_root_refs: vec![root_c.clone(), root_b.clone()],
            }),
            "parent-deep" => Some(CapabilityAuthorityAudit {
                authority_depth: 3,
                authority_root_refs: vec![root_a.clone(), root_b.clone()],
            }),
            _ => None,
        })
        .unwrap();

        assert_eq!(audit.authority_depth, 4);
        assert_eq!(audit.authority_root_refs, vec![root_b, root_a, root_c]);
        assert!(
            audit
                .authority_root_refs
                .iter()
                .all(|root| { root.get("controller_epoch_at_issuance").is_none() })
        );
    }

    #[test]
    fn capability_authority_audit_rejects_an_unprojected_parent() {
        let error = derive_capability_authority_audit(
            &json!({
                "issuer_authority_refs": [{"kind": "grant", "grant_id": "missing"}]
            }),
            &|_| None,
        )
        .unwrap_err();
        assert_eq!(
            error,
            CapabilityAuthorityProjectionError::UnresolvedGrant("missing".to_owned())
        );
    }

    #[test]
    fn capability_grant_projection_rejects_producer_authored_issuer_station_id() {
        let mut event: Event = serde_json::from_value(json!({
            "event_id": "ak:event:AV1bzsPGpTD74Cq12d9EOrCkieTddiSndS0kDtK1W2hM",
            "kind": EventKind::CapabilityGrant,
            "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy",
            "scope_ref": {"kind": "realm", "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy"},
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:web:principal.example"
            }},
            "actor_seq": 3,
            "created_at": "2026-07-26T00:00:00.000Z",
            "hlc": "019f90000000-0000-aabbccdd",
            "prev_refs": [],
            "payload": {
                "grant": {
                    "issuer_id": {"kind": "account", "account_id": {
                        "principal_id": "ak:did_core:webvh:z6mkfixture",
                        "station_id": "ak:did_core:web:principal.example"
                    }},
                    "subject": {"kind": "account", "account_id": {
                        "principal_id": "ak:did_core:webvh:z6mkfixture",
                        "station_id": "ak:did_core:web:principal.example"
                    }},
                    "actions": ["ak.realm.admin"]
                }
            },
            "proofs": []
        }))
        .unwrap();
        event.payload.get_mut("grant").unwrap()["issuer_station_id"] =
            json!("ak:did_core:web:forged.example");

        let error = project_registered_cell_writes(&event, arkret_canonical::DigestSuite::Sha256)
            .expect_err("producer-authored derived issuer coordinate must fail closed");
        assert!(
            error
                .to_string()
                .contains("producer-authored payload.grant.issuer_station_id is forbidden")
        );
    }

    #[test]
    fn history_access_cell_is_registry_derived() {
        let projected = project(&history_access_event());
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].cell_id.as_str(), HISTORY_ACCESS_CELL);
    }

    #[test]
    fn validates_realm_join_rule_from_registry() {
        let event = realm_facet(
            EventKind::RealmJoinRule,
            json!({"value": "knock_restricted"}),
        );
        validate_registered_cell_writes(&event, arkret_canonical::DigestSuite::Sha256).unwrap();
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
        let event = realm_facet(EventKind::RealmDiscovery, json!({"value": "listed"}));
        assert_eq!(
            project(&event),
            vec![write(
                "ak:cell:ak.component.realm.discovery.v1:null",
                set_op(json!({"value": "listed"})),
            )]
        );
    }

    #[test]
    fn realm_bootstrap_control_facets_require_basis_free_envelopes() {
        let mut event = realm_facet(EventKind::RealmJoinRule, json!({"value": "invite"}));
        event.seal_basis = None;
        validate_registered_cell_writes_in_context(
            &event,
            EventCellContractContext::OrdinaryRealmBootstrap,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap();

        event.auth_context = Some(
            serde_json::from_value(serde_json::json!({
                "key_id": "device:019f9e50-d787-74e0-8731-c9ad5eaa9183",
                "key_epoch": 1,
                "authority_refs": ["ak:seal:sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"]
            }))
            .unwrap(),
        );
        assert_eq!(
            validate_registered_cell_writes_in_context(
                &event,
                EventCellContractContext::OrdinaryRealmBootstrap,
                arkret_canonical::DigestSuite::Sha256,
            )
            .unwrap_err()
            .reason_code(),
            "plane_cross_write"
        );
    }

    #[test]
    fn closed_bootstrap_contexts_allow_basis_free_data_initialization() {
        let mut event = realm_facet(EventKind::StrandCreate, json!({}));
        event.seal_basis = None;

        validate_plane(
            &event,
            Some(CbsEffectPlane::Data),
            EventCellContractContext::DirectConversationFounding,
        )
        .unwrap();
        validate_plane(
            &event,
            Some(CbsEffectPlane::Data),
            EventCellContractContext::OrdinaryRealmBootstrap,
        )
        .unwrap();
        assert_eq!(
            validate_plane(
                &event,
                Some(CbsEffectPlane::Data),
                EventCellContractContext::Standard,
            )
            .unwrap_err()
            .reason_code(),
            "plane_cross_write"
        );

        event.seal_basis = Some(arkret_wire::SealBasis {
            leaves: vec![arkret_wire::SealId::new(
                "ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap()],
        });
        assert_eq!(
            validate_plane(
                &event,
                Some(CbsEffectPlane::Data),
                EventCellContractContext::DirectConversationFounding,
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

    use arkret_wire::EventCellRuleField;
    use serde_json::json;

    use super::*;

    const VECTOR_EVENT_ID: &str = "ak:event:AdepBI0bqsJ7xaz5eUj88RSmcDsHFbnvOE2P-PrqDoIg";

    #[test]
    fn dot_matches_the_encoding_vector() {
        assert_eq!(
            or_set_dot(VECTOR_EVENT_ID, 0),
            "ak:event:AdepBI0bqsJ7xaz5eUj88RSmcDsHFbnvOE2P-PrqDoIg:0"
        );
        assert_eq!(
            or_set_dot(VECTOR_EVENT_ID, 1),
            "ak:event:AdepBI0bqsJ7xaz5eUj88RSmcDsHFbnvOE2P-PrqDoIg:1"
        );
    }

    #[test]
    fn batch_add_tag_matches_the_encoding_vector() {
        let dot = or_set_dot(VECTOR_EVENT_ID, 0);
        for (value, expected) in [
            (
                "ak:seal:01964185-0400-7000-8000-00000000000a",
                "MDy_Q-zHaOk4foYSaWWQ_hqLH64v1RBWaiyUmG6Ur2A",
            ),
            (
                "ak:seal:01964185-0400-7000-8000-00000000000b",
                "cJoKnkcAxgRnA9WUy2LYgVwhMxIWO8Wfz_G8wkPOm8o",
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
        let realm = "ak:realm:AWLfU0jPk3KqEwovCxTmw_5ovsD0ADwogBoi5VUfPne8";
        let event: Event = serde_json::from_value(json!({
            "event_id": VECTOR_EVENT_ID,
            "kind": "ak.capability.grant",
            "realm_id": realm,
            "scope_ref": {"kind": "realm", "realm_id": realm},
            "actor_id": {"kind": "account", "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:web:principal.example"
            }},
            "actor_seq": 1,
            "created_at": "2026-07-28T00:00:00.000Z",
            "prev_refs": [],
            "payload": {},
            "proofs": []
        }))
        .unwrap();
        let projected = ProjectedEventInput::from(&event);
        const BARE_EVENT_ID: EventCellRule = EventCellRule::Object(&[EventCellRuleField {
            key: EventCellRuleKey::EnvelopeField,
            value: EventCellRule::String("event_id"),
        }]);
        let write = event
            .kind
            .descriptor()
            .expect("capability grant must be registered")
            .cell_writes[0];
        let error = or_set_tag(
            &projected,
            &write,
            Some(BARE_EVENT_ID),
            event.kind.as_str(),
            &or_set_dot(event.event_id.as_str(), 0),
            arkret_canonical::DigestSuite::Sha256,
            None,
        )
        .unwrap_err();

        assert!(error.to_string().contains("not a dot"), "{error}");
    }
}
