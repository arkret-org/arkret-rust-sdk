use std::collections::BTreeSet;
use std::fmt::Write as _;

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value};

use crate::model::{EventKindRegistry, SpecInputs};
use crate::render::{associated_name, header, rust_string, string_slice};
use crate::runtime_contracts::GeneratedOutput;

#[derive(Debug)]
struct ResolvedTransition {
    family: String,
    axis: String,
    states: Vec<String>,
    terminal_states: Vec<String>,
    initial_states: Vec<String>,
    allowed_transitions: Vec<(String, String)>,
    runtime_uses_null: bool,
    runtime_transitions: Vec<(Option<String>, String)>,
}

pub fn generate(inputs: &SpecInputs) -> Result<GeneratedOutput> {
    let registry = object(&inputs.contracts.event_kind_registry, "event_kind_registry")?;
    let families = object_member(registry, "actor_private_contracts")?
        .get("cell_families")
        .and_then(Value::as_object)
        .context("actor_private_contracts.cell_families must be an object")?;
    let writes = object_member(registry, "actor_private_contracts")?
        .get("event_writes")
        .and_then(Value::as_object)
        .context("actor_private_contracts.event_writes must be an object")?;
    let transition_contracts = resolve_transitions(registry)?;
    let registered = registered_cell_families(&inputs.event_kinds)?;

    let mut body = String::new();
    render_actor_private_families(&mut body, families, &registered)?;
    render_actor_private_writes(&mut body, writes, families, &registered)?;
    render_transitions(&mut body, &transition_contracts, &registered);

    let mut output = header(
        &[&inputs.contracts_source],
        &format!(
            "actor_private_families={}, actor_private_writes={}, transition_contracts={}",
            families.len(),
            writes.len(),
            transition_contracts.len()
        ),
    );
    if body.contains(CELL_FAMILY_ID) {
        output.push_str("use arkret_wire::CellFamilyId;\n\n");
    }
    output.push_str(
        "use crate::contract_registry::{\n    ActorPrivateEffectProjection, ActorPrivateMergeKind,\n    ActorPrivateSubjectComponent, ActorPrivateSubjectRule, ActorPrivateTombstoneMode,\n    GeneratedActorPrivateFamily, GeneratedActorPrivateTransition, GeneratedActorPrivateWrite,\n    GeneratedTransitionContract, GeneratedState,\n};\n\n",
    );
    output.push_str(&body);
    Ok(GeneratedOutput {
        relative_path: "crates/lattice-registry/src/generated/contract_registry.rs".into(),
        contents: output,
    })
}

const CELL_FAMILY_ID: &str = "CellFamilyId::";

/// Registered `ak.component.*` families are spelled exactly once, in the
/// `arkret_wire::CellFamilyId` constants; every consumer — this registry
/// included — must reference those constants instead of repeating the literal,
/// which is what `tools/lint-cell-family-literals.py` enforces. The constants
/// are minted by `tools/generate-sdk-event-kinds.ps1` from the cell families
/// that active event kinds write, so this reads the same registry the same way;
/// anything else can drift and emit a constant that does not exist.
/// Actor-private (`ak.private.*`) families never get a constant, so they stay
/// literals.
fn registered_cell_families(registry: &EventKindRegistry) -> Result<BTreeSet<String>> {
    let mut registered = BTreeSet::new();
    for event in &registry.event_kinds {
        if event.status != "active" {
            continue;
        }
        let families = event.cell_family.iter().chain(
            event
                .cell_writes
                .iter()
                .filter_map(|write| write.cell_family.as_ref()),
        );
        for family in families {
            if family.starts_with("ak.component.") {
                registered.insert(family.clone());
            }
        }
    }
    if registered.is_empty() {
        bail!("the event-kind registry declares no registered cell family");
    }
    Ok(registered)
}

fn cell_family(family: &str, registered: &BTreeSet<String>) -> String {
    if registered.contains(family) {
        format!(
            "{CELL_FAMILY_ID}{}",
            associated_name(family, &["ak.component."])
        )
    } else {
        rust_string(family)
    }
}

fn render_actor_private_families(
    output: &mut String,
    families: &Map<String, Value>,
    registered: &BTreeSet<String>,
) -> Result<()> {
    output.push_str(
        "pub(crate) const GENERATED_ACTOR_PRIVATE_FAMILIES: &[GeneratedActorPrivateFamily] = &[\n",
    );
    for (family, raw) in families {
        let raw = object(raw, &format!("actor-private family {family}"))?;
        if !family.starts_with("ak.private.") {
            bail!("actor-private registry contains shared family {family}");
        }
        let merge = match required_str(raw, "merge", family)? {
            "server_revision_cas" => "ActorPrivateMergeKind::ServerRevisionCas",
            "causal_then_hlc_then_device" => "ActorPrivateMergeKind::CausalThenHlcThenDevice",
            other => bail!("actor-private family {family} has unknown merge {other}"),
        };
        let tombstone = match raw.get("tombstone").and_then(Value::as_str) {
            None => "None",
            Some("value_tombstone") => "Some(ActorPrivateTombstoneMode::ValueTombstone)",
            Some("versioned_tombstone") => "Some(ActorPrivateTombstoneMode::VersionedTombstone)",
            Some(other) => bail!("actor-private family {family} has unknown tombstone {other}"),
        };
        let transition_contract = match raw.get("transition_contract") {
            None => "None".to_owned(),
            Some(value) => render_private_transition(family, value)?,
        };
        writeln!(
            output,
            "    GeneratedActorPrivateFamily {{ cell_family: {}, merge: {merge}, tombstone: {tombstone}, bottom_reject: {}, transition_contract: {transition_contract} }},",
            cell_family(family, registered),
            raw.get("bottom").and_then(Value::as_str) == Some("reject")
                || transition_contract != "None"
        )?;
    }
    output.push_str("];\n\n");
    Ok(())
}

fn render_private_transition(family: &str, value: &Value) -> Result<String> {
    let contract = object(value, &format!("actor-private transition {family}"))?;
    let states = strings(contract, "states", family)?;
    let terminal_states = strings(contract, "terminal_states", family)?;
    let initial = required_str(contract, "initial_state", family)?;
    let transitions = transitions(contract, "allowed_transitions", family, false)?;
    let declared = states.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if !declared.contains(initial)
        || terminal_states
            .iter()
            .any(|state| !declared.contains(state.as_str()))
        || transitions.iter().any(|(from, to)| {
            from.as_ref()
                .is_none_or(|from| !declared.contains(from.as_str()))
                || !declared.contains(to.as_str())
        })
    {
        bail!("actor-private transition {family} references an undeclared state");
    }
    Ok(format!(
        "Some(GeneratedActorPrivateTransition {{ initial_state: {}, states: {}, terminal_states: {}, allowed_transitions: {} }})",
        rust_string(initial),
        string_slice(&states),
        string_slice(&terminal_states),
        render_string_transitions(&transitions)
    ))
}

fn render_actor_private_writes(
    output: &mut String,
    writes: &Map<String, Value>,
    families: &Map<String, Value>,
    registered: &BTreeSet<String>,
) -> Result<()> {
    output.push_str(
        "pub(crate) const GENERATED_ACTOR_PRIVATE_WRITES: &[GeneratedActorPrivateWrite] = &[\n",
    );
    for (event_kind, raw) in writes {
        let raw = object(raw, &format!("actor-private Event {event_kind}"))?;
        let family = required_str(raw, "cell_family", event_kind)?;
        if !families.contains_key(family) {
            bail!("actor-private Event {event_kind} references unknown family {family}");
        }
        let subject = render_private_subject(
            raw.get("cell_subject")
                .with_context(|| format!("actor-private Event {event_kind} omits cell_subject"))?,
            event_kind,
        )?;
        let effect = render_private_effect(
            raw.get("effect_projection").with_context(|| {
                format!("actor-private Event {event_kind} omits effect_projection")
            })?,
            event_kind,
        )?;
        writeln!(
            output,
            "    GeneratedActorPrivateWrite {{ event_kind: {}, cell_family: {}, cell_subject: {subject}, effect_projection: {effect} }},",
            rust_string(event_kind),
            cell_family(family, registered)
        )?;
    }
    output.push_str("];\n\n");
    Ok(())
}

fn render_private_subject(value: &Value, event_kind: &str) -> Result<String> {
    let subject = object(value, &format!("{event_kind} cell_subject"))?;
    match required_str(subject, "kind", event_kind)? {
        "did" => Ok(format!(
            "ActorPrivateSubjectRule::Did({})",
            rust_string(required_str(subject, "field", event_kind)?)
        )),
        "composite" => {
            let components = subject
                .get("components")
                .and_then(Value::as_array)
                .with_context(|| format!("{event_kind} composite subject omits components"))?;
            let rendered = components
                .iter()
                .map(|component| {
                    if let Some(field) = component.as_str() {
                        return Ok(format!(
                            "ActorPrivateSubjectComponent::Field({})",
                            rust_string(field)
                        ));
                    }
                    let descriptor = object(component, "actor-private subject component")?;
                    if required_str(descriptor, "kind", event_kind)? != "canonical_json" {
                        bail!("{event_kind} has unsupported composite component");
                    }
                    Ok(format!(
                        "ActorPrivateSubjectComponent::CanonicalJson({})",
                        rust_string(required_str(descriptor, "field", event_kind)?)
                    ))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(format!(
                "ActorPrivateSubjectRule::Composite(&[{}])",
                rendered.join(", ")
            ))
        }
        other => bail!("{event_kind} has unsupported actor-private subject kind {other}"),
    }
}

fn render_private_effect(value: &Value, event_kind: &str) -> Result<String> {
    let effect = object(value, &format!("{event_kind} effect_projection"))?;
    match required_str(effect, "kind", event_kind)? {
        "transition" => {
            let from = nested(effect, "from", "const")
                .with_context(|| format!("{event_kind} transition effect omits from.const"))?;
            let from = if from.is_null() {
                "None".to_owned()
            } else {
                format!(
                    "Some({})",
                    rust_string(from.as_str().with_context(|| {
                        format!("{event_kind} transition from.const must be null or string")
                    })?)
                )
            };
            let to = nested(effect, "to", "const")
                .and_then(Value::as_str)
                .with_context(|| format!("{event_kind} transition effect omits to.const"))?;
            Ok(format!(
                "ActorPrivateEffectProjection::Transition {{ from: {from}, to: {} }}",
                rust_string(to)
            ))
        }
        "set" if nested(effect, "value", "field").and_then(Value::as_str) == Some("payload") => {
            Ok("ActorPrivateEffectProjection::SetPayload".to_owned())
        }
        "merge" if nested(effect, "value", "field").and_then(Value::as_str) == Some("payload") => {
            Ok("ActorPrivateEffectProjection::MergePayload".to_owned())
        }
        other => bail!("{event_kind} has unsupported actor-private effect {other}"),
    }
}

fn render_transitions(output: &mut String, transition_contracts: &[ResolvedTransition], registered: &BTreeSet<String>) {
    output.push_str("pub(crate) const GENERATED_TRANSITION_CONTRACTS: &[GeneratedTransitionContract] = &[\n");
    for contract in transition_contracts {
        let initial = if contract.runtime_uses_null {
            "GeneratedState::Null".to_owned()
        } else {
            format!(
                "GeneratedState::String({})",
                rust_string(&contract.initial_states[0])
            )
        };
        let runtime_transitions = contract
            .runtime_transitions
            .iter()
            .map(|(from, to)| {
                let from = from.as_ref().map_or_else(
                    || "GeneratedState::Null".to_owned(),
                    |value| format!("GeneratedState::String({})", rust_string(value)),
                );
                format!("({from}, GeneratedState::String({}))", rust_string(to))
            })
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            output,
            "    GeneratedTransitionContract {{ cell_family: {}, axis: {}, states: {}, terminal_states: {}, initial_states: {}, allowed_transitions: {}, runtime_initial_state: {initial}, runtime_transitions: &[{runtime_transitions}] }},",
            cell_family(&contract.family, registered),
            rust_string(&contract.axis),
            string_slice(&contract.states),
            string_slice(&contract.terminal_states),
            string_slice(&contract.initial_states),
            render_owned_transitions(&contract.allowed_transitions),
        )
        .expect("write to String");
    }
    output.push_str("];\n");
}

fn resolve_transitions(registry: &Map<String, Value>) -> Result<Vec<ResolvedTransition>> {
    let templates = object_member(registry, "transition_templates")?;
    let contracts = object_member(registry, "transition_contracts")?;
    let mut result = Vec::with_capacity(contracts.len());
    for (family, instance_value) in contracts {
        if family.starts_with("ak.private.") {
            bail!("private transition {family} is declared in the shared transition_contracts map");
        }
        let instance = object(instance_value, &format!("transition contract {family}"))?;
        let (source, parameters) =
            if let Some(template_id) = instance.get("template").and_then(Value::as_str) {
                let template = templates
                    .get(template_id)
                    .and_then(Value::as_object)
                    .with_context(|| {
                        format!("transition contract {family} references unknown template {template_id}")
                    })?;
                let parameters = instance
                    .get("instance_parameters")
                    .and_then(Value::as_object)
                    .with_context(|| format!("templated transition {family} omits instance_parameters"))?;
                validate_parameters(family, template, parameters)?;
                (template, Some(parameters))
            } else {
                (instance, None)
            };
        result.push(resolve_transition(family, instance, source, parameters)?);
    }
    Ok(result)
}

fn resolve_transition(
    family: &str,
    instance: &Map<String, Value>,
    source: &Map<String, Value>,
    parameters: Option<&Map<String, Value>>,
) -> Result<ResolvedTransition> {
    let axis = required_str(instance, "axis", family)?.to_owned();
    let states = strings(source, "states", family)?;
    let state_set = states.iter().map(String::as_str).collect::<BTreeSet<_>>();
    if state_set.len() != states.len() {
        bail!("transition {family} declares duplicate states");
    }
    let terminal_states = strings(source, "terminal_states", family)?;
    let declared = transitions(source, "allowed_transitions", family, true)?;
    let mut explicit_initials = declared
        .iter()
        .filter_map(|(from, to)| from.is_none().then_some(to.clone()))
        .collect::<Vec<_>>();
    let mut allowed = declared
        .into_iter()
        .filter_map(|(from, to)| from.map(|from| (from, to)))
        .collect::<Vec<_>>();
    if let Some(conditionals) = source.get("conditional_transitions") {
        for conditional in conditionals
            .as_array()
            .with_context(|| format!("transition template for {family} has invalid conditionals"))?
        {
            let parameter = conditional
                .pointer("/when/parameter")
                .and_then(Value::as_str)
                .with_context(|| format!("transition conditional for {family} omits parameter"))?;
            let expected = conditional
                .pointer("/when/const")
                .with_context(|| format!("transition conditional for {family} omits const"))?;
            if parameters.and_then(|values| values.get(parameter)) == Some(expected) {
                let pair = transition_pair(
                    conditional.get("transition").with_context(|| {
                        format!("transition conditional for {family} omits transition")
                    })?,
                    family,
                    false,
                )?;
                allowed.push((
                    pair.0
                        .context("conditional transition cannot start at null")?,
                    pair.1,
                ));
            }
        }
    }
    if terminal_states
        .iter()
        .any(|state| !state_set.contains(state.as_str()))
        || allowed.iter().any(|(from, to)| {
            !state_set.contains(from.as_str()) || !state_set.contains(to.as_str())
        })
    {
        bail!("transition {family} references an unknown state");
    }
    let initial_states = if let Some(value) = source.get("initial_states") {
        value_strings(value, "initial_states", family)?
    } else if !explicit_initials.is_empty() {
        explicit_initials.clone()
    } else {
        vec![required_str(source, "initial_state", family)?.to_owned()]
    };
    if initial_states
        .iter()
        .any(|state| !state_set.contains(state.as_str()))
    {
        bail!("transition {family} declares an unknown initial state");
    }
    explicit_initials.sort();
    explicit_initials.dedup();
    let runtime_uses_null = source.get("initial_state").is_some_and(Value::is_null)
        || source.get("initial_states").is_some()
        || !explicit_initials.is_empty();
    let mut runtime_transitions = Vec::new();
    if runtime_uses_null {
        let runtime_initials = if explicit_initials.is_empty() {
            &initial_states
        } else {
            &explicit_initials
        };
        runtime_transitions.extend(runtime_initials.iter().cloned().map(|to| (None, to)));
    }
    runtime_transitions.extend(allowed.iter().cloned().map(|(from, to)| (Some(from), to)));
    Ok(ResolvedTransition {
        family: family.to_owned(),
        axis,
        states,
        terminal_states,
        initial_states,
        allowed_transitions: allowed,
        runtime_uses_null,
        runtime_transitions,
    })
}

fn validate_parameters(
    family: &str,
    template: &Map<String, Value>,
    values: &Map<String, Value>,
) -> Result<()> {
    let schema = object_member(template, "parameter_schema")?;
    if values.keys().collect::<BTreeSet<_>>() != schema.keys().collect::<BTreeSet<_>>() {
        bail!("templated transition {family} parameter closure does not match its template");
    }
    for (name, definition) in schema {
        match definition.get("value_shape").and_then(Value::as_str) {
            Some("boolean") if values.get(name).is_some_and(Value::is_boolean) => {}
            Some(shape) => {
                bail!("templated transition {family} parameter {name} does not satisfy {shape}")
            }
            None => bail!("templated transition {family} parameter {name} omits value_shape"),
        }
    }
    Ok(())
}

fn object<'a>(value: &'a Value, name: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .with_context(|| format!("{name} must be an object"))
}

fn object_member<'a>(
    object: &'a Map<String, Value>,
    member: &str,
) -> Result<&'a Map<String, Value>> {
    object
        .get(member)
        .and_then(Value::as_object)
        .with_context(|| format!("registry omits object {member}"))
}

fn required_str<'a>(object: &'a Map<String, Value>, member: &str, owner: &str) -> Result<&'a str> {
    object
        .get(member)
        .and_then(Value::as_str)
        .with_context(|| format!("{owner} omits string {member}"))
}

fn nested<'a>(object: &'a Map<String, Value>, outer: &str, inner: &str) -> Option<&'a Value> {
    object.get(outer)?.as_object()?.get(inner)
}

fn strings(object: &Map<String, Value>, member: &str, owner: &str) -> Result<Vec<String>> {
    value_strings(
        object
            .get(member)
            .with_context(|| format!("{owner} omits {member}"))?,
        member,
        owner,
    )
}

fn value_strings(value: &Value, member: &str, owner: &str) -> Result<Vec<String>> {
    value
        .as_array()
        .with_context(|| format!("{owner} {member} must be an array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .with_context(|| format!("{owner} {member} must contain strings"))
        })
        .collect()
}

fn transitions(
    object: &Map<String, Value>,
    member: &str,
    owner: &str,
    allow_null: bool,
) -> Result<Vec<(Option<String>, String)>> {
    object
        .get(member)
        .and_then(Value::as_array)
        .with_context(|| format!("{owner} omits array {member}"))?
        .iter()
        .map(|value| transition_pair(value, owner, allow_null))
        .collect()
}

fn transition_pair(
    value: &Value,
    owner: &str,
    allow_null: bool,
) -> Result<(Option<String>, String)> {
    let pair = value
        .as_array()
        .with_context(|| format!("{owner} transition must be an array"))?;
    if pair.len() != 2 {
        bail!("{owner} transition must have exactly two states");
    }
    let from = if allow_null && pair[0].is_null() {
        None
    } else {
        Some(
            pair[0]
                .as_str()
                .with_context(|| format!("{owner} transition from must be a string"))?
                .to_owned(),
        )
    };
    let to = pair[1]
        .as_str()
        .with_context(|| format!("{owner} transition to must be a string"))?
        .to_owned();
    Ok((from, to))
}

fn render_string_transitions(values: &[(Option<String>, String)]) -> String {
    format!(
        "&[{}]",
        values
            .iter()
            .map(|(from, to)| format!(
                "({}, {})",
                rust_string(
                    from.as_deref()
                        .expect("private transition transitions cannot start at null")
                ),
                rust_string(to)
            ))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn render_owned_transitions(values: &[(String, String)]) -> String {
    format!(
        "&[{}]",
        values
            .iter()
            .map(|(from, to)| format!("({}, {})", rust_string(from), rust_string(to)))
            .collect::<Vec<_>>()
            .join(", ")
    )
}
