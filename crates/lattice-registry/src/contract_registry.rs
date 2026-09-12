use std::collections::BTreeMap;

use serde_json::Value;
use thiserror::Error;

use crate::generated::{
    GENERATED_ACTOR_PRIVATE_FAMILIES, GENERATED_ACTOR_PRIVATE_WRITES,
    GENERATED_TRANSITION_CONTRACTS,
};

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ContractRegistryError {
    #[error("invalid canonical contract registry: {0}")]
    Invalid(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTransitionContract {
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
    pub transition_contract: Option<ActorPrivateTransitionContract>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorPrivateTransitionContract {
    pub initial_state: String,
    pub states: Vec<String>,
    pub terminal_states: Vec<String>,
    pub allowed_transitions: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActorPrivateEventWrite {
    pub event_kind: String,
    pub cell_family: String,
    pub cell_subject: ActorPrivateSubjectRule,
    pub effect_projection: ActorPrivateEffectProjection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorPrivateSubjectComponent {
    Field(&'static str),
    CanonicalJson(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorPrivateSubjectRule {
    Did(&'static str),
    Composite(&'static [ActorPrivateSubjectComponent]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorPrivateEffectProjection {
    Transition {
        from: Option<&'static str>,
        to: &'static str,
    },
    SetPayload,
    MergePayload,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GeneratedActorPrivateTransition {
    pub initial_state: &'static str,
    pub states: &'static [&'static str],
    pub terminal_states: &'static [&'static str],
    pub allowed_transitions: &'static [(&'static str, &'static str)],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GeneratedActorPrivateFamily {
    pub cell_family: &'static str,
    pub merge: ActorPrivateMergeKind,
    pub tombstone: Option<ActorPrivateTombstoneMode>,
    pub bottom_reject: bool,
    pub transition_contract: Option<GeneratedActorPrivateTransition>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GeneratedActorPrivateWrite {
    pub event_kind: &'static str,
    pub cell_family: &'static str,
    pub cell_subject: ActorPrivateSubjectRule,
    pub effect_projection: ActorPrivateEffectProjection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GeneratedState {
    Null,
    String(&'static str),
}

impl GeneratedState {
    fn to_value(self) -> Value {
        match self {
            Self::Null => Value::Null,
            Self::String(value) => Value::String(value.to_owned()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GeneratedTransitionContract {
    pub cell_family: &'static str,
    pub axis: &'static str,
    pub states: &'static [&'static str],
    pub terminal_states: &'static [&'static str],
    pub initial_states: &'static [&'static str],
    pub allowed_transitions: &'static [(&'static str, &'static str)],
    pub runtime_initial_state: GeneratedState,
    pub runtime_transitions: &'static [(GeneratedState, GeneratedState)],
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
                    "actor-private event {kind} carries shared CBS field {forbidden}"
                )));
            }
        }
        Ok(())
    }

    pub fn derive_subject(
        &self,
        event_kind: &str,
        envelope_actor_id: &Value,
        payload: &Value,
    ) -> Result<String, ContractRegistryError> {
        let write = self.event_write(event_kind).ok_or_else(|| {
            ContractRegistryError::Invalid(format!(
                "{event_kind} is not a registered actor-private Event"
            ))
        })?;
        match write.cell_subject {
            ActorPrivateSubjectRule::Did(field) => {
                resolve_private_string_field(field, envelope_actor_id, payload)
            }
            ActorPrivateSubjectRule::Composite(components) => {
                let values = components
                    .iter()
                    .map(|component| {
                        resolve_private_component(*component, envelope_actor_id, payload)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                arkret_wire::composite_subject(
                    &values.iter().map(String::as_str).collect::<Vec<_>>(),
                )
                .map_err(|error| ContractRegistryError::Invalid(error.to_string()))
            }
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
            if let Some(transition_contract) = &contract.transition_contract
                && incoming.value.as_str() != Some(transition_contract.initial_state.as_str())
            {
                return Ok(ActorPrivateMergeOutcome::Conflict);
            }
            if matches!(contract.merge, ActorPrivateMergeKind::ServerRevisionCas)
                && (incoming.expected_revision != Some(0) || incoming.revision != Some(1))
            {
                return Ok(ActorPrivateMergeOutcome::Conflict);
            }
            return Ok(ActorPrivateMergeOutcome::Accepted(incoming));
        };
        if current == &incoming
            || !matches!(contract.merge, ActorPrivateMergeKind::ServerRevisionCas)
                && current.value == incoming.value
                && same_position(current, &incoming)
        {
            return Ok(ActorPrivateMergeOutcome::Unchanged(current.clone()));
        }
        match contract.merge {
            ActorPrivateMergeKind::ServerRevisionCas => {
                let transition_allowed =
                    contract
                        .transition_contract
                        .as_ref()
                        .is_none_or(|contract| {
                            current
                                .value
                                .as_str()
                                .zip(incoming.value.as_str())
                                .is_some_and(|edge| {
                                    contract
                                        .allowed_transitions
                                        .iter()
                                        .any(|allowed| allowed.0 == edge.0 && allowed.1 == edge.1)
                                })
                        });
                if transition_allowed && valid_revision_successor(current, &incoming) {
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
    let families = GENERATED_ACTOR_PRIVATE_FAMILIES
        .iter()
        .map(|generated| {
            let transition_contract =
                generated
                    .transition_contract
                    .map(|contract| ActorPrivateTransitionContract {
                        initial_state: contract.initial_state.to_owned(),
                        states: owned_strings(contract.states),
                        terminal_states: owned_strings(contract.terminal_states),
                        allowed_transitions: owned_transitions(contract.allowed_transitions),
                    });
            (
                generated.cell_family.to_owned(),
                ActorPrivateFamilyContract {
                    cell_family: generated.cell_family.to_owned(),
                    merge: generated.merge,
                    tombstone: generated.tombstone,
                    bottom_reject: generated.bottom_reject,
                    transition_contract,
                },
            )
        })
        .collect();
    let event_writes = GENERATED_ACTOR_PRIVATE_WRITES
        .iter()
        .map(|generated| {
            (
                generated.event_kind.to_owned(),
                ActorPrivateEventWrite {
                    event_kind: generated.event_kind.to_owned(),
                    cell_family: generated.cell_family.to_owned(),
                    cell_subject: generated.cell_subject,
                    effect_projection: generated.effect_projection,
                },
            )
        })
        .collect();
    Ok(ActorPrivateRegistry {
        families,
        event_writes,
    })
}

fn owned_strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn owned_transitions(values: &[(&str, &str)]) -> Vec<(String, String)> {
    values
        .iter()
        .map(|(from, to)| ((*from).to_owned(), (*to).to_owned()))
        .collect()
}

fn resolve_private_component(
    component: ActorPrivateSubjectComponent,
    envelope_actor_id: &Value,
    payload: &Value,
) -> Result<String, ContractRegistryError> {
    match component {
        ActorPrivateSubjectComponent::Field(field) => {
            resolve_private_string_field(field, envelope_actor_id, payload)
        }
        ActorPrivateSubjectComponent::CanonicalJson(field) => {
            let value = resolve_private_value(field, envelope_actor_id, payload)?;
            let bytes = arkret_wire::canonical::canonical_json_bytes(value)
                .map_err(|error| ContractRegistryError::Invalid(error.to_string()))?;
            String::from_utf8(bytes)
                .map_err(|error| ContractRegistryError::Invalid(error.to_string()))
        }
    }
}

fn resolve_private_string_field(
    field: &str,
    envelope_actor_id: &Value,
    payload: &Value,
) -> Result<String, ContractRegistryError> {
    resolve_private_value(field, envelope_actor_id, payload)?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            ContractRegistryError::Invalid(format!(
                "actor-private subject field {field} must resolve to a string"
            ))
        })
}

fn resolve_private_value<'a>(
    field: &str,
    envelope_actor_id: &'a Value,
    payload: &'a Value,
) -> Result<&'a Value, ContractRegistryError> {
    if field == "envelope.actor_id" {
        return Ok(envelope_actor_id);
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
    Ok(value)
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

pub fn canonical_transition_contracts()
-> Result<Vec<ResolvedTransitionContract>, ContractRegistryError> {
    Ok(GENERATED_TRANSITION_CONTRACTS
        .iter()
        .map(resolved_transition_contract)
        .collect())
}

fn resolved_transition_contract(
    generated: &GeneratedTransitionContract,
) -> ResolvedTransitionContract {
    ResolvedTransitionContract {
        cell_family: generated.cell_family.to_owned(),
        axis: generated.axis.to_owned(),
        states: owned_strings(generated.states),
        terminal_states: owned_strings(generated.terminal_states),
        initial_states: owned_strings(generated.initial_states),
        allowed_transitions: owned_transitions(generated.allowed_transitions),
        runtime_initial_state: Some(generated.runtime_initial_state.to_value()),
        runtime_transitions: generated
            .runtime_transitions
            .iter()
            .map(|(from, to)| (from.to_value(), to.to_value()))
            .collect(),
    }
}
