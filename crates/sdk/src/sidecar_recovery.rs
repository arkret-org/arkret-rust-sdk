use std::collections::BTreeMap;

use arkret_models_collaboration::agent_operations::{
    AgentSidecar, AgentSidecarContextRef, AgentSidecarRelationContextRef,
    AgentSidecarStrandContextRef, AgentSidecarView,
};
use arkret_models_collaboration::events_payloads::StrandCreatePayload;
use arkret_models_collaboration::governance::membership_invite::RelationCreatePayload;
use arkret_wire::{
    CircleId, Error, Event, EventId, EventKind, Result, ScopeRef, SidecarId, StrandId,
};

const AGENT_SIDECAR_OF: &str = "agent_sidecar_of";
const EVENT_REF_ROLE_AFTER: &str = "after";

/// A controller-local locator recovered from complete accepted structural
/// Event history. It is not a wire projection and must never be uploaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentSidecarContextLocator {
    pub sidecar_id: SidecarId,
    pub backing_circle_id: CircleId,
    pub private_strand_id: StrandId,
    pub source_context_ref: AgentSidecarContextRef,
}

#[derive(Clone)]
struct PrivateStrandCandidate {
    event_id: EventId,
    private_strand_id: StrandId,
}

/// Recover Sidecar private context locators from fully paginated Sidecar views
/// and accepted structural Event Envelopes.
///
/// The caller must prove pagination completion before calling this helper.
/// Missing, ambiguous, cross-scope, cross-controller, or non-causal candidates
/// are omitted fail-closed. Conflicting Sidecar views for one backing Circle
/// reject the complete input set because accepting either would make recovery
/// depend on local order.
pub fn recover_agent_sidecar_context_locators(
    sidecar_views: &[AgentSidecarView],
    accepted_events: &[Event],
) -> Result<Vec<AgentSidecarContextLocator>> {
    let mut sidecars_by_circle = BTreeMap::new();
    for view in sidecar_views {
        view.validate()?;
        let sidecar = &view.sidecar;
        if let Some(previous) =
            sidecars_by_circle.insert(sidecar.backing_circle_id.clone(), sidecar.clone())
            && previous.id != sidecar.id
        {
            return Err(Error::Protocol(
                "multiple Sidecars map to the same backing Circle".to_owned(),
            ));
        }
    }

    let mut strand_candidates: BTreeMap<CircleId, Vec<PrivateStrandCandidate>> = BTreeMap::new();
    for event in accepted_events {
        if event.kind != EventKind::StrandCreate {
            continue;
        }
        let Some(circle_id) = matching_sidecar_circle(event, &sidecars_by_circle) else {
            continue;
        };
        let Ok(payload) = event.typed_payload::<StrandCreatePayload>(EventKind::STRAND_CREATE)
        else {
            continue;
        };
        if payload.object.realm_id != event.realm_id
            || payload.object.created_by != event.actor_id
            || payload.object.scope_circle_id.as_ref() != Some(&circle_id)
        {
            continue;
        }
        strand_candidates
            .entry(circle_id)
            .or_default()
            .push(PrivateStrandCandidate {
                event_id: event.event_id.clone(),
                // The create payload carries no id: derive it from the Event.
                private_strand_id: arkret_wire::StrandId::from_event_id(&event.event_id),
            });
    }

    let mut recovered = Vec::new();
    for (circle_id, sidecar) in sidecars_by_circle {
        let Some(strands) = strand_candidates.get(&circle_id) else {
            continue;
        };
        let mut matches = BTreeMap::new();
        for event in accepted_events {
            if event.kind != EventKind::RelationCreate
                || event.actor_id != sidecar.controller_id
                || event.realm_id != sidecar.realm_id
                || event.scope_ref
                    != (ScopeRef::Circle {
                        realm_id: sidecar.realm_id.clone(),
                        circle_id: circle_id.clone(),
                    })
            {
                continue;
            }
            let Ok(payload) =
                event.typed_payload::<RelationCreatePayload>(EventKind::RELATION_CREATE)
            else {
                continue;
            };
            if payload.relation.kind != AGENT_SIDECAR_OF {
                continue;
            }
            for strand in strands {
                if payload.relation.from_ref != strand.private_strand_id.as_str()
                    || !event.refs.iter().any(|reference| {
                        reference.role == EVENT_REF_ROLE_AFTER
                            && reference.id == strand.event_id.as_str()
                    })
                {
                    continue;
                }
                let Some(source_context_ref) =
                    parse_source_context_ref(&sidecar.realm_id, &payload.relation.to_ref)
                else {
                    continue;
                };
                let key = format!(
                    "{}\u{0}{}",
                    strand.private_strand_id,
                    source_context_ref_sort_key(&source_context_ref)
                );
                matches.insert(key, (strand.private_strand_id.clone(), source_context_ref));
            }
        }
        if matches.len() == 1 {
            let (_, (private_strand_id, source_context_ref)) =
                matches.into_iter().next().expect("single match");
            recovered.push(AgentSidecarContextLocator {
                sidecar_id: sidecar.id,
                backing_circle_id: circle_id,
                private_strand_id,
                source_context_ref,
            });
        }
    }
    recovered.sort_by(|left, right| {
        left.sidecar_id
            .as_str()
            .cmp(right.sidecar_id.as_str())
            .then_with(|| {
                left.private_strand_id
                    .as_str()
                    .cmp(right.private_strand_id.as_str())
            })
    });
    Ok(recovered)
}

fn matching_sidecar_circle(
    event: &Event,
    sidecars_by_circle: &BTreeMap<CircleId, AgentSidecar>,
) -> Option<CircleId> {
    let ScopeRef::Circle {
        realm_id,
        circle_id,
    } = &event.scope_ref
    else {
        return None;
    };
    let sidecar = sidecars_by_circle.get(circle_id)?;
    (event.realm_id == *realm_id
        && event.realm_id == sidecar.realm_id
        && event.actor_id == sidecar.controller_id)
        .then(|| circle_id.clone())
}

fn parse_source_context_ref(
    realm_id: &arkret_wire::RealmId,
    source_ref: &str,
) -> Option<AgentSidecarContextRef> {
    if let Ok(strand_id) = StrandId::new(source_ref.to_owned()) {
        return Some(AgentSidecarContextRef::Strand(
            AgentSidecarStrandContextRef {
                realm_id: realm_id.clone(),
                strand_id,
            },
        ));
    }
    arkret_wire::RelationId::new(source_ref.to_owned())
        .ok()
        .map(|relation_id| {
            AgentSidecarContextRef::Relation(AgentSidecarRelationContextRef {
                realm_id: realm_id.clone(),
                relation_id,
            })
        })
}

fn source_context_ref_sort_key(context_ref: &AgentSidecarContextRef) -> String {
    match context_ref {
        AgentSidecarContextRef::Strand(value) => value.strand_id.to_string(),
        AgentSidecarContextRef::Relation(value) => value.relation_id.to_string(),
    }
}
