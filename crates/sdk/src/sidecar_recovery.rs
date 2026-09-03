use std::collections::BTreeMap;

use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::agent_operations::{
    AgentSidecarContextRef, AgentSidecarRelationContextRef, AgentSidecarStrandContextRef,
    AgentSidecarView,
};
use arkret_models_collaboration::sidecar_operations::SidecarContextRef;
use arkret_wire::{Event, EventId, EventKind, Result, ScopeRef, SidecarId, WireError, event_spec};

/// A controller-local source-context locator recovered from complete accepted
/// native Sidecar history. It is not a wire projection and must never be uploaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentSidecarContextLocator {
    pub sidecar_id: SidecarId,
    pub source_context_ref: AgentSidecarContextRef,
    pub mapping_event_id: EventId,
    pub version: u64,
}

#[derive(Clone)]
struct MappingCandidate {
    event_id: EventId,
    version: u64,
    predecessor_event_ref: Option<EventId>,
    source_context_ref: AgentSidecarContextRef,
}

/// Recover native Sidecar context mappings from fully paginated Sidecar views
/// and accepted `ak.sidecar.context.attach` Events.
///
/// Missing, ambiguous, cross-scope, cross-controller, or broken predecessor
/// chains are omitted fail-closed. No Circle, Strand, or Relation is inferred
/// or synthesized by this helper.
pub fn recover_agent_sidecar_context_locators(
    sidecar_views: &[AgentSidecarView],
    accepted_events: &[Event],
) -> Result<Vec<AgentSidecarContextLocator>> {
    let mut sidecars_by_id = BTreeMap::new();
    for view in sidecar_views {
        view.validate()?;
        let sidecar = &view.sidecar;
        if let Some(previous) = sidecars_by_id.insert(sidecar.id.clone(), sidecar.clone())
            && previous != *sidecar
        {
            return Err(WireError::Protocol(
                "conflicting views for the same native Sidecar id".to_owned(),
            ));
        }
    }

    let mut candidates: BTreeMap<(SidecarId, String), Vec<MappingCandidate>> = BTreeMap::new();
    for event in accepted_events {
        if event.kind != EventKind::SidecarContextAttach {
            continue;
        }
        let Ok(payload) = event.typed_payload::<event_spec::SidecarContextAttach>() else {
            continue;
        };
        let Some(sidecar) = sidecars_by_id.get(&payload.sidecar_id) else {
            continue;
        };
        if event.actor_id.as_account_id() != Some(&sidecar.controller_account_id)
            || event.realm_id != sidecar.realm_id
            || event.scope_ref
                != (ScopeRef::Sidecar {
                    realm_id: sidecar.realm_id.clone(),
                    sidecar_id: sidecar.id.clone(),
                })
            || payload.version == 0
            || (payload.version == 1) == payload.predecessor_event_ref.is_some()
        {
            continue;
        }

        let source_context_ref =
            attach_ref_with_realm(sidecar.realm_id.clone(), payload.source_context_ref);
        let key = (
            sidecar.id.clone(),
            source_context_ref_sort_key(&source_context_ref),
        );
        let group = candidates.entry(key).or_default();
        if group.iter().any(|item| item.event_id == event.event_id) {
            continue;
        }
        group.push(MappingCandidate {
            event_id: event.event_id.clone(),
            version: payload.version,
            predecessor_event_ref: payload.predecessor_event_ref,
            source_context_ref,
        });
    }

    let mut recovered = Vec::new();
    for ((sidecar_id, _), mut group) in candidates {
        group.sort_by(|left, right| {
            left.version
                .cmp(&right.version)
                .then_with(|| left.event_id.cmp(&right.event_id))
        });
        let valid_chain = group
            .first()
            .is_some_and(|first| first.version == 1 && first.predecessor_event_ref.is_none())
            && group.windows(2).all(|pair| {
                pair[1].version == pair[0].version + 1
                    && pair[1].predecessor_event_ref.as_ref() == Some(&pair[0].event_id)
            });
        if !valid_chain {
            continue;
        }
        let winner = group.pop().expect("valid mapping chain is non-empty");
        recovered.push(AgentSidecarContextLocator {
            sidecar_id,
            source_context_ref: winner.source_context_ref,
            mapping_event_id: winner.event_id,
            version: winner.version,
        });
    }
    recovered.sort_by(|left, right| {
        left.sidecar_id.cmp(&right.sidecar_id).then_with(|| {
            source_context_ref_sort_key(&left.source_context_ref)
                .cmp(&source_context_ref_sort_key(&right.source_context_ref))
        })
    });
    Ok(recovered)
}

fn attach_ref_with_realm(
    realm_id: arkret_wire::RealmId,
    source_ref: SidecarContextRef,
) -> AgentSidecarContextRef {
    match source_ref {
        SidecarContextRef::Strand { strand_id } => {
            AgentSidecarContextRef::Strand(AgentSidecarStrandContextRef {
                realm_id,
                strand_id,
            })
        }
        SidecarContextRef::Relation { relation_id } => {
            AgentSidecarContextRef::Relation(AgentSidecarRelationContextRef {
                realm_id,
                relation_id,
            })
        }
    }
}

fn source_context_ref_sort_key(context_ref: &AgentSidecarContextRef) -> String {
    match context_ref {
        AgentSidecarContextRef::Strand(value) => format!("strand\0{}", value.strand_id),
        AgentSidecarContextRef::Relation(value) => format!("relation\0{}", value.relation_id),
    }
}
