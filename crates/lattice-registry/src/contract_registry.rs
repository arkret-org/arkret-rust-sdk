use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use serde_json::{Map, Value};
use thiserror::Error;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ContractRegistryError {
    #[error("embedded contract registry is unavailable: {0}")]
    Embedded(String),
    #[error("invalid canonical contract registry: {0}")]
    Invalid(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedFsmContract {
    pub cell_family: String,
    pub axis: String,
    pub states: Vec<String>,
    pub terminal_states: Vec<String>,
    pub initial_states: Vec<String>,
    pub allowed_transitions: Vec<(String, String)>,
    pub runtime_initial_state: Option<Value>,
    pub runtime_transitions: Vec<(Value, Value)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorPrivateMergeKind {
    ServerRevisionCas,
    FsmCas,
    CasRegister,
    CausalThenHlcThenDevice,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorPrivateTombstoneMode {
    ValueTombstone,
    VersionedTombstone,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorPrivateFamilyContract {
    pub cell_family: String,
    pub merge: ActorPrivateMergeKind,
    pub tombstone: Option<ActorPrivateTombstoneMode>,
    pub bottom_reject: bool,
    pub fsm: Option<ActorPrivateFsmContract>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorPrivateFsmContract {
    pub initial_state: String,
    pub states: Vec<String>,
    pub terminal_states: Vec<String>,
    pub allowed_transitions: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorPrivateEventWrite {
    pub event_kind: String,
    pub cell_family: String,
    pub cell_subject: Value,
    pub effect_projection: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorPrivateCandidate {
    pub value: Value,
    pub revision: Option<u64>,
    pub expected_revision: Option<u64>,
    pub causal_order: Option<u64>,
    pub hlc: Option<String>,
    pub device_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActorPrivateMergeOutcome {
    Accepted(ActorPrivateCandidate),
    Unchanged(ActorPrivateCandidate),
    Conflict,
}

#[derive(Clone, Debug)]
pub struct ActorPrivateRegistry {
    families: BTreeMap<String, ActorPrivateFamilyContract>,
    event_writes: BTreeMap<String, ActorPrivateEventWrite>,
}

impl ActorPrivateRegistry {
    pub fn families(&self) -> impl ExactSizeIterator<Item = &ActorPrivateFamilyContract> {
        self.families.values()
    }

    pub fn event_writes(&self) -> impl ExactSizeIterator<Item = &ActorPrivateEventWrite> {
        self.event_writes.values()
    }

    pub fn family(&self, family: &str) -> Option<&ActorPrivateFamilyContract> {
        self.families.get(family)
    }

    pub fn event_write(&self, event_kind: &str) -> Option<&ActorPrivateEventWrite> {
        self.event_writes.get(event_kind)
    }

    pub fn validate_private_event_shape(&self, event: &Value) -> Result<(), ContractRegistryError> {
        let object = event.as_object().ok_or_else(|| {
            ContractRegistryError::Invalid("actor-private event must be an object".to_owned())
        })?;
        let kind = object.get("kind").and_then(Value::as_str).ok_or_else(|| {
            ContractRegistryError::Invalid("actor-private event omits kind".to_owned())
        })?;
        if !self.event_writes.contains_key(kind) {
            return Err(ContractRegistryError::Invalid(format!(
                "{kind} is not a registered actor-private Event"
            )));
        }
        for forbidden in ["effects", "preconditions", "seal_basis", "realm_id"] {
            if object.contains_key(forbidden) {
                return Err(ContractRegistryError::Invalid(format!(
                    "actor-private event {kind} carries shared CBA field {forbidden}"
                )));
            }
        }
        Ok(())
    }

    pub fn derive_subject(
        &self,
        event_kind: &str,
        envelope_actor_id: &str,
        payload: &Value,
    ) -> Result<String, ContractRegistryError> {
        let write = self.event_write(event_kind).ok_or_else(|| {
            ContractRegistryError::Invalid(format!(
                "{event_kind} is not a registered actor-private Event"
            ))
        })?;
        let subject = write.cell_subject.as_object().ok_or_else(|| {
            ContractRegistryError::Invalid(format!("{event_kind} cell_subject must be an object"))
        })?;
        match subject.get("kind").and_then(Value::as_str) {
            Some("did") => {
                let field = subject
                    .get("field")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        ContractRegistryError::Invalid(format!(
                            "{event_kind} DID subject omits field"
                        ))
                    })?;
                resolve_private_field(field, envelope_actor_id, payload)
            }
            Some("composite") => {
                let components = subject
                    .get("components")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        ContractRegistryError::Invalid(format!(
                            "{event_kind} composite subject omits components"
                        ))
                    })?;
                let values = components
                    .iter()
                    .map(|component| {
                        let field = component.as_str().ok_or_else(|| {
                            ContractRegistryError::Invalid(format!(
                                "{event_kind} composite component must be a string"
                            ))
                        })?;
                        resolve_private_field(field, envelope_actor_id, payload)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                arkret_wire::composite_subject(
                    &values.iter().map(String::as_str).collect::<Vec<_>>(),
                )
                .map_err(|error| ContractRegistryError::Invalid(error.to_string()))
            }
            other => Err(ContractRegistryError::Invalid(format!(
                "{event_kind} has unsupported actor-private subject kind {other:?}"
            ))),
        }
    }

    pub fn apply(
        &self,
        family: &str,
        current: Option<&ActorPrivateCandidate>,
        incoming: ActorPrivateCandidate,
    ) -> Result<ActorPrivateMergeOutcome, ContractRegistryError> {
        let contract = self.family(family).ok_or_else(|| {
            ContractRegistryError::Invalid(format!(
                "{family} is not a registered actor-private family"
            ))
        })?;
        let Some(current) = current else {
            if let Some(fsm) = &contract.fsm
                && incoming.value.as_str() != Some(fsm.initial_state.as_str())
            {
                return Ok(ActorPrivateMergeOutcome::Conflict);
            }
            return Ok(ActorPrivateMergeOutcome::Accepted(incoming));
        };
        if current == &incoming
            || current.value == incoming.value && same_position(current, &incoming)
        {
            return Ok(ActorPrivateMergeOutcome::Unchanged(current.clone()));
        }
        match contract.merge {
            ActorPrivateMergeKind::ServerRevisionCas => {
                if valid_revision_successor(current, &incoming) {
                    Ok(ActorPrivateMergeOutcome::Accepted(incoming))
                } else {
                    Ok(ActorPrivateMergeOutcome::Conflict)
                }
            }
            ActorPrivateMergeKind::FsmCas => {
                let transition_allowed = contract.fsm.as_ref().is_some_and(|fsm| {
                    current
                        .value
                        .as_str()
                        .zip(incoming.value.as_str())
                        .is_some_and(|(from, to)| {
                            fsm.allowed_transitions
                                .iter()
                                .any(|edge| edge.0 == from && edge.1 == to)
                        })
                });
                if transition_allowed && valid_revision_successor(current, &incoming) {
                    Ok(ActorPrivateMergeOutcome::Accepted(incoming))
                } else {
                    Ok(ActorPrivateMergeOutcome::Conflict)
                }
            }
            ActorPrivateMergeKind::CasRegister => {
                if valid_revision_successor(current, &incoming) {
                    Ok(ActorPrivateMergeOutcome::Accepted(incoming))
                } else {
                    Ok(ActorPrivateMergeOutcome::Conflict)
                }
            }
            ActorPrivateMergeKind::CausalThenHlcThenDevice => {
                let current_causal = current.causal_order.ok_or_else(|| {
                    ContractRegistryError::Invalid(format!(
                        "{family} current value omits causal_order"
                    ))
                })?;
                let incoming_causal = incoming.causal_order.ok_or_else(|| {
                    ContractRegistryError::Invalid(format!(
                        "{family} incoming value omits causal_order"
                    ))
                })?;
                if incoming_causal > current_causal {
                    return Ok(ActorPrivateMergeOutcome::Accepted(incoming));
                }
                if incoming_causal < current_causal {
                    return Ok(ActorPrivateMergeOutcome::Unchanged(current.clone()));
                }
                let incoming_order = (
                    incoming.hlc.as_deref().unwrap_or_default(),
                    incoming.device_id.as_deref().unwrap_or_default(),
                );
                let current_order = (
                    current.hlc.as_deref().unwrap_or_default(),
                    current.device_id.as_deref().unwrap_or_default(),
                );
                if incoming_order > current_order {
                    Ok(ActorPrivateMergeOutcome::Accepted(incoming))
                } else if incoming_order < current_order {
                    Ok(ActorPrivateMergeOutcome::Unchanged(current.clone()))
                } else {
                    Ok(ActorPrivateMergeOutcome::Conflict)
                }
            }
        }
    }
}

pub fn build_actor_private_registry() -> Result<ActorPrivateRegistry, ContractRegistryError> {
    let registry = event_kind_registry()?;
    let private = object_member(registry, "actor_private_contracts")?;
    let raw_families = object_member(private, "cell_families")?;
    let raw_writes = object_member(private, "event_writes")?;
    let mut families = BTreeMap::new();
    for (family, raw) in raw_families {
        if !family.starts_with("ak.private.") {
            return Err(ContractRegistryError::Invalid(format!(
                "actor-private registry contains shared family {family}"
            )));
        }
        let raw = raw.as_object().ok_or_else(|| {
            ContractRegistryError::Invalid(format!(
                "actor-private family {family} must be an object"
            ))
        })?;
        let merge = match raw.get("merge").and_then(Value::as_str) {
            Some("server_revision_cas") => ActorPrivateMergeKind::ServerRevisionCas,
            Some("fsm_cas") => ActorPrivateMergeKind::FsmCas,
            Some("cas_register") => ActorPrivateMergeKind::CasRegister,
            Some("causal_then_hlc_then_device") => ActorPrivateMergeKind::CausalThenHlcThenDevice,
            other => {
                return Err(ContractRegistryError::Invalid(format!(
                    "actor-private family {family} has unknown merge {other:?}"
                )));
            }
        };
        let tombstone = match raw.get("tombstone").and_then(Value::as_str) {
            None => None,
            Some("value_tombstone") => Some(ActorPrivateTombstoneMode::ValueTombstone),
            Some("versioned_tombstone") => Some(ActorPrivateTombstoneMode::VersionedTombstone),
            other => {
                return Err(ContractRegistryError::Invalid(format!(
                    "actor-private family {family} has unknown tombstone {other:?}"
                )));
            }
        };
        families.insert(
            family.clone(),
            ActorPrivateFamilyContract {
                cell_family: family.clone(),
                merge,
                tombstone,
                bottom_reject: raw.get("bottom").and_then(Value::as_str) == Some("reject")
                    || matches!(merge, ActorPrivateMergeKind::FsmCas),
                fsm: parse_actor_private_fsm(family, raw.get("fsm"))?,
            },
        );
    }
    let mut event_writes = BTreeMap::new();
    for (event_kind, raw) in raw_writes {
        let raw = raw.as_object().ok_or_else(|| {
            ContractRegistryError::Invalid(format!(
                "actor-private Event {event_kind} write must be an object"
            ))
        })?;
        let family = raw
            .get("cell_family")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ContractRegistryError::Invalid(format!(
                    "actor-private Event {event_kind} omits cell_family"
                ))
            })?;
        if !families.contains_key(family) {
            return Err(ContractRegistryError::Invalid(format!(
                "actor-private Event {event_kind} references unknown family {family}"
            )));
        }
        event_writes.insert(
            event_kind.clone(),
            ActorPrivateEventWrite {
                event_kind: event_kind.clone(),
                cell_family: family.to_owned(),
                cell_subject: raw.get("cell_subject").cloned().ok_or_else(|| {
                    ContractRegistryError::Invalid(format!(
                        "actor-private Event {event_kind} omits cell_subject"
                    ))
                })?,
                effect_projection: raw.get("effect_projection").cloned().ok_or_else(|| {
                    ContractRegistryError::Invalid(format!(
                        "actor-private Event {event_kind} omits effect_projection"
                    ))
                })?,
            },
        );
    }
    Ok(ActorPrivateRegistry {
        families,
        event_writes,
    })
}

fn parse_actor_private_fsm(
    family: &str,
    value: Option<&Value>,
) -> Result<Option<ActorPrivateFsmContract>, ContractRegistryError> {
    let Some(fsm) = value.and_then(Value::as_object) else {
        return Ok(None);
    };
    let states = string_array(fsm, "states", family)?;
    let terminal_states = string_array(fsm, "terminal_states", family)?;
    let initial_state = fsm
        .get("initial_state")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ContractRegistryError::Invalid(format!(
                "actor-private FSM {family} omits initial_state"
            ))
        })?
        .to_owned();
    let allowed_transitions = transition_array(fsm, "allowed_transitions", family)?;
    if !states.contains(&initial_state)
        || terminal_states.iter().any(|state| !states.contains(state))
        || allowed_transitions
            .iter()
            .any(|(from, to)| !states.contains(from) || !states.contains(to))
    {
        return Err(ContractRegistryError::Invalid(format!(
            "actor-private FSM {family} references an undeclared state"
        )));
    }
    Ok(Some(ActorPrivateFsmContract {
        initial_state,
        states,
        terminal_states,
        allowed_transitions,
    }))
}

fn resolve_private_field(
    field: &str,
    envelope_actor_id: &str,
    payload: &Value,
) -> Result<String, ContractRegistryError> {
    if field == "envelope.actor_id" {
        return Ok(envelope_actor_id.to_owned());
    }
    let path = field.strip_prefix("payload.").ok_or_else(|| {
        ContractRegistryError::Invalid(format!(
            "actor-private subject field {field} is not envelope.actor_id or payload.*"
        ))
    })?;
    let mut value = payload;
    for segment in path.split('.') {
        value = value.get(segment).ok_or_else(|| {
            ContractRegistryError::Invalid(format!("actor-private subject field {field} is absent"))
        })?;
    }
    value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
        ContractRegistryError::Invalid(format!(
            "actor-private subject field {field} must resolve to a string"
        ))
    })
}

fn same_position(left: &ActorPrivateCandidate, right: &ActorPrivateCandidate) -> bool {
    left.revision == right.revision
        && left.causal_order == right.causal_order
        && left.hlc == right.hlc
        && left.device_id == right.device_id
}

fn valid_revision_successor(
    current: &ActorPrivateCandidate,
    incoming: &ActorPrivateCandidate,
) -> bool {
    let current_revision = current.revision.unwrap_or(0);
    incoming.expected_revision == Some(current_revision)
        && incoming.revision == current_revision.checked_add(1)
}

pub fn canonical_fsm_contracts() -> Result<Vec<ResolvedFsmContract>, ContractRegistryError> {
    let registry = event_kind_registry()?;
    let templates = object_member(registry, "fsm_templates")?;
    let contracts = object_member(registry, "fsm_contracts")?;
    let cell_contracts = object_member(registry, "cell_contracts")?;
    let mut resolved = Vec::with_capacity(contracts.len());
    for (family, contract) in contracts {
        if family.starts_with("ak.private.") {
            return Err(ContractRegistryError::Invalid(format!(
                "private FSM {family} is declared in the shared fsm_contracts map"
            )));
        }
        let contract = contract.as_object().ok_or_else(|| {
            ContractRegistryError::Invalid(format!("FSM contract {family} must be an object"))
        })?;
        let (source, parameters) = if let Some(template_id) =
            contract.get("template").and_then(Value::as_str)
        {
            let template = templates
                .get(template_id)
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    ContractRegistryError::Invalid(format!(
                        "FSM contract {family} references unknown template {template_id}"
                    ))
                })?;
            validate_template_parameters(family, template, contract.get("instance_parameters"))?;
            (
                template,
                contract
                    .get("instance_parameters")
                    .and_then(Value::as_object),
            )
        } else {
            (contract, None)
        };
        resolved.push(resolve_fsm(
            family,
            contract,
            source,
            parameters,
            cell_contracts,
        )?);
    }
    Ok(resolved)
}

fn resolve_fsm(
    family: &str,
    instance: &Map<String, Value>,
    source: &Map<String, Value>,
    parameters: Option<&Map<String, Value>>,
    cell_contracts: &Map<String, Value>,
) -> Result<ResolvedFsmContract, ContractRegistryError> {
    let axis = instance
        .get("axis")
        .and_then(Value::as_str)
        .ok_or_else(|| ContractRegistryError::Invalid(format!("FSM {family} omits axis")))?
        .to_owned();
    let states = string_array(source, "states", family)?;
    let state_set: BTreeSet<_> = states.iter().cloned().collect();
    if state_set.len() != states.len() {
        return Err(ContractRegistryError::Invalid(format!(
            "FSM {family} declares duplicate states"
        )));
    }
    let terminal_states = string_array(source, "terminal_states", family)?;
    let declared_transitions =
        transition_array_allowing_initial(source, "allowed_transitions", family)?;
    let mut explicit_initial_transitions = declared_transitions
        .iter()
        .filter_map(|(from, to)| from.is_none().then_some(to.clone()))
        .collect::<Vec<_>>();
    let mut allowed_transitions = declared_transitions
        .into_iter()
        .filter_map(|(from, to)| from.map(|from| (from, to)))
        .collect::<Vec<_>>();
    if let Some(conditionals) = source.get("conditional_transitions") {
        for conditional in conditionals.as_array().ok_or_else(|| {
            ContractRegistryError::Invalid(format!(
                "FSM template for {family} has non-array conditional_transitions"
            ))
        })? {
            let when = conditional
                .get("when")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    ContractRegistryError::Invalid(format!(
                        "FSM template conditional for {family} omits when"
                    ))
                })?;
            let parameter = when
                .get("parameter")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ContractRegistryError::Invalid(format!(
                        "FSM template conditional for {family} omits parameter"
                    ))
                })?;
            let expected = when.get("const").ok_or_else(|| {
                ContractRegistryError::Invalid(format!(
                    "FSM template conditional for {family} omits const"
                ))
            })?;
            if parameters.and_then(|values| values.get(parameter)) == Some(expected) {
                allowed_transitions.push(transition_value(conditional.get("transition"), family)?);
            }
        }
    }
    for terminal in &terminal_states {
        if !state_set.contains(terminal) {
            return Err(ContractRegistryError::Invalid(format!(
                "FSM {family} terminal state {terminal} is unknown"
            )));
        }
    }
    for (from, to) in &allowed_transitions {
        if !state_set.contains(from) || !state_set.contains(to) {
            return Err(ContractRegistryError::Invalid(format!(
                "FSM {family} transition {from}->{to} names an unknown state"
            )));
        }
    }
    let initial_states = if let Some(values) = source.get("initial_states") {
        value_string_array(values, "initial_states", family)?
    } else if !explicit_initial_transitions.is_empty() {
        explicit_initial_transitions.clone()
    } else {
        vec![
            source
                .get("initial_state")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    ContractRegistryError::Invalid(format!(
                        "FSM {family} omits initial_state/initial_states"
                    ))
                })?
                .to_owned(),
        ]
    };
    if initial_states
        .iter()
        .any(|initial| !state_set.contains(initial))
    {
        return Err(ContractRegistryError::Invalid(format!(
            "FSM {family} declares an unknown initial state"
        )));
    }
    if explicit_initial_transitions
        .iter()
        .any(|initial| !initial_states.contains(initial))
    {
        return Err(ContractRegistryError::Invalid(format!(
            "FSM {family} null transition names a non-initial state"
        )));
    }
    explicit_initial_transitions.sort();
    explicit_initial_transitions.dedup();

    let explicit_null_initial = cell_contracts.values().any(|contract| {
        contract
            .get("cell_writes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|write| {
                write.get("cell_family").and_then(Value::as_str) == Some(family)
                    && write
                        .pointer("/effect_projection/from/const")
                        .is_some_and(Value::is_null)
            })
    });
    let multiple_initials = source.get("initial_states").is_some();
    let runtime_uses_null =
        explicit_null_initial || multiple_initials || !explicit_initial_transitions.is_empty();
    let runtime_initial_state = Some(if runtime_uses_null {
        Value::Null
    } else {
        Value::String(initial_states[0].clone())
    });
    let mut runtime_transitions = Vec::new();
    if runtime_uses_null {
        let runtime_initials = if explicit_initial_transitions.is_empty() {
            &initial_states
        } else {
            &explicit_initial_transitions
        };
        runtime_transitions.extend(
            runtime_initials
                .iter()
                .cloned()
                .map(|initial| (Value::Null, Value::String(initial))),
        );
    }
    runtime_transitions.extend(
        allowed_transitions
            .iter()
            .cloned()
            .map(|(from, to)| (Value::String(from), Value::String(to))),
    );
    Ok(ResolvedFsmContract {
        cell_family: family.to_owned(),
        axis,
        states,
        terminal_states,
        initial_states,
        allowed_transitions,
        runtime_initial_state,
        runtime_transitions,
    })
}

fn validate_template_parameters(
    family: &str,
    template: &Map<String, Value>,
    values: Option<&Value>,
) -> Result<(), ContractRegistryError> {
    let schema = template
        .get("parameter_schema")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ContractRegistryError::Invalid(format!(
                "templated FSM {family} references a template without parameter_schema"
            ))
        })?;
    let values = values.and_then(Value::as_object).ok_or_else(|| {
        ContractRegistryError::Invalid(format!("templated FSM {family} omits instance_parameters"))
    })?;
    if values.keys().collect::<BTreeSet<_>>() != schema.keys().collect::<BTreeSet<_>>() {
        return Err(ContractRegistryError::Invalid(format!(
            "templated FSM {family} parameter closure does not match its template"
        )));
    }
    for (name, definition) in schema {
        match definition.get("value_shape").and_then(Value::as_str) {
            Some("boolean") if values.get(name).is_some_and(Value::is_boolean) => {}
            Some(shape) => {
                return Err(ContractRegistryError::Invalid(format!(
                    "templated FSM {family} parameter {name} does not satisfy {shape}"
                )));
            }
            None => {
                return Err(ContractRegistryError::Invalid(format!(
                    "templated FSM {family} parameter {name} omits value_shape"
                )));
            }
        }
    }
    Ok(())
}

fn event_kind_registry() -> Result<&'static Map<String, Value>, ContractRegistryError> {
    static REGISTRY: OnceLock<Result<Map<String, Value>, ContractRegistryError>> = OnceLock::new();
    REGISTRY
        .get_or_init(|| {
            let artifact = arkret_schema::embedded_json_artifact("registry/contract-registry.json")
                .map_err(|error| ContractRegistryError::Embedded(error.to_string()))?;
            artifact
                .get("event_kind_registry")
                .and_then(Value::as_object)
                .cloned()
                .ok_or_else(|| {
                    ContractRegistryError::Invalid(
                        "contract-registry omits event_kind_registry".to_owned(),
                    )
                })
        })
        .as_ref()
        .map_err(Clone::clone)
}

fn object_member<'a>(
    object: &'a Map<String, Value>,
    member: &str,
) -> Result<&'a Map<String, Value>, ContractRegistryError> {
    object
        .get(member)
        .and_then(Value::as_object)
        .ok_or_else(|| {
            ContractRegistryError::Invalid(format!("event_kind_registry omits object {member}"))
        })
}

fn string_array(
    object: &Map<String, Value>,
    member: &str,
    family: &str,
) -> Result<Vec<String>, ContractRegistryError> {
    value_string_array(
        object.get(member).ok_or_else(|| {
            ContractRegistryError::Invalid(format!("FSM {family} omits {member}"))
        })?,
        member,
        family,
    )
}

fn value_string_array(
    value: &Value,
    member: &str,
    family: &str,
) -> Result<Vec<String>, ContractRegistryError> {
    value
        .as_array()
        .ok_or_else(|| {
            ContractRegistryError::Invalid(format!("FSM {family} {member} must be an array"))
        })?
        .iter()
        .map(|value| {
            value.as_str().map(ToOwned::to_owned).ok_or_else(|| {
                ContractRegistryError::Invalid(format!(
                    "FSM {family} {member} must contain strings"
                ))
            })
        })
        .collect()
}

fn transition_array(
    object: &Map<String, Value>,
    member: &str,
    family: &str,
) -> Result<Vec<(String, String)>, ContractRegistryError> {
    object
        .get(member)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ContractRegistryError::Invalid(format!("FSM {family} omits array {member}"))
        })?
        .iter()
        .map(|value| transition_value(Some(value), family))
        .collect()
}

fn transition_array_allowing_initial(
    object: &Map<String, Value>,
    member: &str,
    family: &str,
) -> Result<Vec<(Option<String>, String)>, ContractRegistryError> {
    object
        .get(member)
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ContractRegistryError::Invalid(format!("FSM {family} omits array {member}"))
        })?
        .iter()
        .map(|value| {
            let pair = value.as_array().ok_or_else(|| {
                ContractRegistryError::Invalid(format!("FSM {family} transition must be an array"))
            })?;
            if pair.len() != 2 {
                return Err(ContractRegistryError::Invalid(format!(
                    "FSM {family} transition must have exactly two states"
                )));
            }
            let from = if pair[0].is_null() {
                None
            } else {
                Some(
                    pair[0]
                        .as_str()
                        .ok_or_else(|| {
                            ContractRegistryError::Invalid(format!(
                                "FSM {family} transition from must be null or a string"
                            ))
                        })?
                        .to_owned(),
                )
            };
            let to = pair[1].as_str().ok_or_else(|| {
                ContractRegistryError::Invalid(format!(
                    "FSM {family} transition to must be a string"
                ))
            })?;
            Ok((from, to.to_owned()))
        })
        .collect()
}

fn transition_value(
    value: Option<&Value>,
    family: &str,
) -> Result<(String, String), ContractRegistryError> {
    let pair = value.and_then(Value::as_array).ok_or_else(|| {
        ContractRegistryError::Invalid(format!("FSM {family} transition must be an array"))
    })?;
    if pair.len() != 2 {
        return Err(ContractRegistryError::Invalid(format!(
            "FSM {family} transition must have exactly two states"
        )));
    }
    let from = pair[0].as_str().ok_or_else(|| {
        ContractRegistryError::Invalid(format!("FSM {family} transition from must be a string"))
    })?;
    let to = pair[1].as_str().ok_or_else(|| {
        ContractRegistryError::Invalid(format!("FSM {family} transition to must be a string"))
    })?;
    Ok((from.to_owned(), to.to_owned()))
}
