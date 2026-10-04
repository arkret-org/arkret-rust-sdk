//! Direct-conversation lookup over current authority projections.

use std::collections::{BTreeMap, BTreeSet};

use arkret_wire::{
    Event, EventId, EventKind, Hash, RealmId, Result, StrandId, WireError, canonical,
};
use serde::{Deserialize, Serialize};

use crate::contact_operations::ContactPeer;
use crate::events_payloads::{RealmCreatePayload, StrandCreatePayload};
use crate::governance::membership_invite::{MembershipPayload, MembershipPayloadState};
use crate::objects::direct_conversation::{
    DirectConversationAuthorizationBasis, DirectConversationFoundingAuthorityEvidence,
    DirectConversationRealmRole,
};
use crate::objects::space::Space;
use crate::objects::strand::Strand;

/// The closed structure extension of the stable participant authority.
pub fn direct_conversation_structure_action(kind: &EventKind) -> bool {
    matches!(
        kind,
        EventKind::StrandCreate
            | EventKind::StrandUpdate
            | EventKind::StrandArchive
            | EventKind::StrandRestore
            | EventKind::SpaceCreate
            | EventKind::SpaceUpdate
            | EventKind::SpaceArchive
            | EventKind::SpaceRestore
            | EventKind::SpaceTombstone
    )
}

/// Validate structure at an independently verified authority cut. This pure
/// helper supplies no membership, device, MLS or delegation authorization.
pub fn direct_conversation_structure_admits(
    event: &Event,
    main_strand_id: &StrandId,
    strands: &BTreeMap<StrandId, Strand>,
    spaces: &BTreeMap<arkret_wire::SpaceId, Space>,
) -> bool {
    use arkret_models_crypto::encrypted_envelope::EncryptedEnvelope;
    use arkret_wire::patch::PatchOpKind;
    use arkret_wire::{ObjectState, SpaceId, SpaceState};

    use crate::events_payloads::{SpaceCreatePayload, SpacePatchPayload, StrandPatchPayload};
    use crate::objects::strand::StrandTopic;

    let chat = |strand: &Strand| direct_conversation_chat_in_realm(strand, &event.realm_id);
    let Some(main) = strands.get(main_strand_id) else {
        return false;
    };
    if main.id.as_ref() != Some(main_strand_id)
        || !chat(main)
        || main.state != Some(ObjectState::Active)
    {
        return false;
    }
    let topic = |space: &Space| {
        space.realm_id == event.realm_id
            && space.scope_circle_id.is_none()
            && space.kind == "list"
            && space.parent_space_id.is_none()
    };
    let active_topic = |id: &SpaceId| {
        spaces
            .get(id)
            .is_some_and(|space| topic(space) && space.state == Some(SpaceState::Active))
    };
    let payload = serde_json::to_value(&event.payload).unwrap_or(serde_json::Value::Null);
    let target_chat = |field: &str| {
        payload
            .get(field)
            .and_then(serde_json::Value::as_str)
            .and_then(|id| StrandId::new(id).ok())
            .and_then(|id| strands.get(&id))
    };
    let target_topic = || {
        payload
            .get("space_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|id| SpaceId::new(id).ok())
            .and_then(|id| spaces.get(&id))
            .is_some_and(&topic)
    };
    let metadata_op = |op: &arkret_wire::patch::PatchOp| {
        op.op() == PatchOpKind::Set
            && op.value().is_some_and(|value| {
                serde_json::from_value::<EncryptedEnvelope>(value.clone()).is_ok()
            })
    };
    match event.kind {
        EventKind::StrandCreate => serde_json::from_value::<StrandCreatePayload>(payload.clone())
            .is_ok_and(|body| {
                let strand = body.object;
                chat(&strand)
                    && strand.id.is_none()
                    && strand.schema_refs.is_none()
                    && strand.agent_participation.is_none()
                    && strand.topic.is_none()
                    && strand.metadata.is_none()
                    && strand.encrypted_metadata.is_some()
                    && strand.content.is_none()
                    && strand.encrypted_content.is_none()
                    && strand.tracks.len() == 1
                    && strand.stage.is_none()
                    && strand
                        .state
                        .is_none_or(|state| state == ObjectState::Active)
            }),
        EventKind::StrandUpdate => {
            let Some(current) = target_chat("target_ref") else {
                return false;
            };
            chat(current)
                && current.state == Some(ObjectState::Active)
                && serde_json::from_value::<StrandPatchPayload>(payload.clone()).is_ok_and(|body| {
                    !body.patch.is_empty()
                        && body.patch.iter().all(|(path, op)| match path.as_str() {
                            "encrypted_metadata" => metadata_op(op),
                            "topic" if body.expected_state_digest.is_some() => match op {
                                arkret_wire::patch::PatchOp::Explicit {
                                    op: PatchOpKind::Set,
                                    value: Some(value),
                                } => serde_json::from_value::<StrandTopic>(value.clone())
                                    .is_ok_and(|placement| active_topic(&placement.space_id)),
                                arkret_wire::patch::PatchOp::Explicit {
                                    op: PatchOpKind::Unset,
                                    value: None,
                                } => current.topic.is_some(),
                                _ => false,
                            },
                            _ => false,
                        })
                })
        }
        EventKind::StrandArchive | EventKind::StrandRestore => {
            target_chat("target_ref").is_some_and(&chat)
                && payload
                    .get("target_ref")
                    .and_then(serde_json::Value::as_str)
                    != Some(main_strand_id.as_str())
        }
        EventKind::SpaceCreate => serde_json::from_value::<SpaceCreatePayload>(payload.clone())
            .is_ok_and(|body| {
                let space = body.object;
                space.id.is_none()
                    && topic(&space)
                    && space.validate().is_ok()
                    && space.encrypted_metadata.is_some()
                    && space.fields.is_empty()
                    && space.schema_refs.is_empty()
                    && space.child_scope_policy.is_none()
            }),
        EventKind::SpaceUpdate => {
            target_topic()
                && serde_json::from_value::<SpacePatchPayload>(payload.clone()).is_ok_and(|body| {
                    body.child_scope_policy.is_none()
                        && body.patch.as_ref().is_some_and(|patch| {
                            !patch.is_empty()
                                && patch.iter().all(|(path, op)| match path.as_str() {
                                    "encrypted_metadata" => metadata_op(op),
                                    "rank" => {
                                        op.op() == PatchOpKind::Set
                                            && op
                                                .value()
                                                .and_then(serde_json::Value::as_str)
                                                .is_some_and(|rank| {
                                                    !rank.is_empty()
                                                        && rank.len() <= 128
                                                        && rank
                                                            .bytes()
                                                            .all(|b| b.is_ascii_alphanumeric())
                                                })
                                    }
                                    _ => false,
                                })
                        })
                })
        }
        EventKind::SpaceArchive | EventKind::SpaceRestore | EventKind::SpaceTombstone => {
            target_topic()
        }
        _ => false,
    }
}

fn direct_conversation_chat_in_realm(strand: &Strand, realm: &RealmId) -> bool {
    &strand.realm_id == realm
        && strand.scope_circle_id.is_none()
        && crate::objects::profiles::resolve_primary_track(&strand.tracks, None)
            .ok()
            .flatten()
            .is_some_and(|(name, _)| name == "discussion")
}

/// Personal watch is separate from the closed nine structure actions.
/// Membership, binding, MLS and delegation are checked by the authority caller.
pub fn direct_conversation_watch_admits(
    event: &Event,
    main_strand_id: &StrandId,
    strands: &BTreeMap<StrandId, Strand>,
) -> bool {
    let Ok(payload) = serde_json::from_value::<crate::events_payloads::strand::StrandWatchSetPayload>(
        serde_json::json!(&event.payload),
    ) else {
        return false;
    };
    event.kind == EventKind::StrandWatchSet
        && payload.watcher_actor_id == event.actor_id
        && [main_strand_id, &payload.strand_id].iter().all(|id| {
            strands.get(*id).is_some_and(|strand| {
                strand.id.as_ref() == Some(*id)
                    && direct_conversation_chat_in_realm(strand, &event.realm_id)
                    && strand.state == Some(arkret_wire::ObjectState::Active)
            })
        })
}

/// Coordinates derived from the exact four caller-authored founding Events.
/// The caller must supply accepted Events; this pure derivation does not assert
/// Station acceptance or replace admission's authoritative checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectConversationFoundingPlan {
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    pub founding_unit_digest: Hash,
}

impl DirectConversationFoundingPlan {
    pub fn from_events(events: [&Event; 4]) -> Result<Self> {
        let expected_kinds = [
            EventKind::RealmCreate,
            EventKind::MemberState,
            EventKind::MemberState,
            EventKind::StrandCreate,
        ];
        if events
            .iter()
            .zip(expected_kinds)
            .any(|(event, kind)| event.kind != kind)
        {
            return Err(WireError::Protocol(
                "Direct Conversation founding Events are not in the exact wire order".into(),
            ));
        }
        let realm_id = RealmId::from_event_id(&events[0].event_id);
        let main_strand_id = StrandId::from_event_id(&events[3].event_id);
        if events
            .iter()
            .any(|event| event.realm_id != realm_id || event.actor_id != events[0].actor_id)
        {
            return Err(WireError::Protocol(
                "Direct Conversation founding Events disagree on Realm or founder".into(),
            ));
        }
        if events
            .iter()
            .map(|event| &event.event_id)
            .collect::<BTreeSet<_>>()
            .len()
            != 4
        {
            return Err(WireError::Protocol(
                "Direct Conversation founding Event IDs must be distinct".into(),
            ));
        }
        let parse_payload = |event: &Event| -> Result<serde_json::Value> {
            serde_json::to_value(&event.payload).map_err(|error| {
                WireError::Protocol(format!(
                    "invalid Direct Conversation founding payload: {error}"
                ))
            })
        };
        let genesis: RealmCreatePayload = serde_json::from_value(parse_payload(events[0])?)
            .map_err(|error| {
                WireError::Protocol(format!("invalid Direct Conversation genesis: {error}"))
            })?;
        DirectConversationRealmRole::validate(&genesis.object)?;
        let founder: MembershipPayload = serde_json::from_value(parse_payload(events[1])?)
            .map_err(|error| WireError::Protocol(format!("invalid founder membership: {error}")))?;
        let peer: MembershipPayload = serde_json::from_value(parse_payload(events[2])?)
            .map_err(|error| WireError::Protocol(format!("invalid peer membership: {error}")))?;
        if founder.membership != MembershipPayloadState::Join
            || peer.membership != MembershipPayloadState::Join
            || founder.member_id != events[0].actor_id
            || peer.member_id == founder.member_id
            || founder.realm_id.as_ref() != Some(&realm_id)
            || peer.realm_id.as_ref() != Some(&realm_id)
        {
            return Err(WireError::Protocol(
                "Direct Conversation founding membership is not the exact founder/peer pair".into(),
            ));
        }
        let strand: StrandCreatePayload = serde_json::from_value(parse_payload(events[3])?)
            .map_err(|error| {
                WireError::Protocol(format!("invalid Direct Conversation main Strand: {error}"))
            })?;
        if strand.object.realm_id != realm_id || strand.object.id.is_some() {
            return Err(WireError::Protocol(
                "Direct Conversation main Strand must derive its ID in the founding Realm".into(),
            ));
        }
        let event_ids = events.map(|event| event.event_id.clone());
        let material = serde_json::json!({ "event_ids": event_ids });
        let canonical = canonical::canonical_json_bytes(&material)?;
        let mut transcript = b"ak.direct-conversation.founding-unit.v1\n".to_vec();
        transcript.extend_from_slice(&canonical);
        Ok(Self {
            realm_id,
            main_strand_id,
            founding_unit_digest: Hash::new(canonical::sha256_digest(transcript))?,
        })
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationResolveRequestBody {
    pub peer: ContactPeer,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationCoordinates {
    pub pair_key: Hash,
    pub realm_id: RealmId,
    pub main_strand_id: StrandId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_event_ref: Option<EventId>,
}

/// Current authoring material returned only to the deterministic founder.
///
/// This is a snapshot used to author the four-Event founding unit, not an
/// authority object and not a member of the self submission carrier.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectConversationFoundingInput {
    pub founding_authority_evidence: DirectConversationFoundingAuthorityEvidence,
}

/// Authority-evaluated reasons why an otherwise materialized conversation
/// cannot currently send. These values intentionally describe current state,
/// not a peer-reconciliation protocol.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectConversationSendBlocker {
    SessionMissing,
    PresenceOffline,
    KeypackageEmpty,
    GrantMissing,
    PolicyStale,
    ContactScopeStale,
    MlsReconcileRequired,
    AgentRuntimeUnavailable,
    PeerNotJoinedMls,
    MemberCountInvalid,
    PairMaterializationConflict,
    RealmTerminalFault,
    GovernanceStationUnavailable,
    UnsupportedProfile,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{DirectConversationResolveOutcome, DirectConversationSendBlocker};

    #[test]
    fn direct_conversation_send_blockers_match_the_closed_wire_literals() {
        let cases = [
            (
                DirectConversationSendBlocker::MemberCountInvalid,
                "member_count_invalid",
            ),
            (
                DirectConversationSendBlocker::ContactScopeStale,
                "contact_scope_stale",
            ),
            (
                DirectConversationSendBlocker::GovernanceStationUnavailable,
                "governance_station_unavailable",
            ),
            (
                DirectConversationSendBlocker::UnsupportedProfile,
                "unsupported_profile",
            ),
        ];
        for (blocker, expected) in cases {
            assert_eq!(serde_json::to_value(blocker).unwrap(), expected);
            assert_eq!(
                serde_json::from_value::<DirectConversationSendBlocker>(expected.into()).unwrap(),
                blocker
            );
        }
    }

    #[test]
    fn creation_required_carries_authoring_material_and_rejects_revision_mirror() {
        let current = json!({
            "state": "creation_required",
            "next_founding_input": {
                "founding_authority_evidence": {
                    "kind": "controller_agent",
                    "agent_provision_ref": "ak:event:ASo6zC5lXw3GKOieKXlXJYfKoQKng4sYXtvdUAaE9WRB",
                    "controller_binding_digest": format!("sha256:{}", "3".repeat(64))
                }
            }
        });
        let parsed: DirectConversationResolveOutcome =
            serde_json::from_value(current.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), current);

        assert!(
            serde_json::from_value::<DirectConversationResolveOutcome>(json!({
                "state": "creation_required",
                "expected_contact_revision": 7
            }))
            .is_err()
        );
    }

    #[test]
    fn found_uses_event_ids_and_rejects_legacy_binding_ref() {
        let current = json!({
            "state": "found",
            "coordinates": {
                "pair_key": format!("sha256:{}", "6".repeat(64)),
                "realm_id": "ak:realm:Af-BcSQlU1OLsK_s3qms1wnA0sSHd7tqhZUbndr27MIr",
                "main_strand_id": "ak:strand:AZ-m1WoJMcvcmuv8zYbD6W7EWy8CWdxsoD-QYgNkHZp3",
                "binding_event_ref": "ak:event:AamoRNGFU65QceSF_1sOMBzEncXa6v055qULEAVWcDYs"
            },
            "group_state_ref": "ak:event:AamoRNGFU65QceSF_1sOMBzEncXa6v055qULEAVWcDYs",
            "send_blockers": []
        });
        let parsed: DirectConversationResolveOutcome =
            serde_json::from_value(current.clone()).unwrap();
        parsed.validate_shape().unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), current);

        let mut legacy = current;
        let coordinates = legacy["coordinates"].as_object_mut().unwrap();
        let value = coordinates.remove("binding_event_ref").unwrap();
        coordinates.insert("binding_ref".to_owned(), value);
        assert!(serde_json::from_value::<DirectConversationResolveOutcome>(legacy).is_err());
    }
}

/// Holder-device-only blockers. This deliberately has no Serde surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DirectConversationClientLocalBlocker {
    PersonalBlocked,
}

impl DirectConversationClientLocalBlocker {
    pub const ALL: [Self; 1] = [Self::PersonalBlocked];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PersonalBlocked => "personal_blocked",
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectConversationPeerMlsAdmission {
    Missing,
    Pending,
    Durable,
    RepairRequired,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum DirectConversationResolveOutcome {
    CreationRequired {
        next_founding_input: DirectConversationFoundingInput,
    },
    CreationBlocked {
        blockers: Vec<DirectConversationSendBlocker>,
    },
    AwaitingFounder {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
    },
    Provisional {
        coordinates: DirectConversationCoordinates,
        authorization_basis: DirectConversationAuthorizationBasis,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group_state_ref: Option<EventId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        initial_exact_pair_group_state_ref: Option<EventId>,
        peer_mls_admission: DirectConversationPeerMlsAdmission,
    },
    Found {
        coordinates: DirectConversationCoordinates,
        group_state_ref: EventId,
        send_blockers: Vec<DirectConversationSendBlocker>,
    },
    Suspended {
        coordinates: DirectConversationCoordinates,
        blockers: Vec<DirectConversationSendBlocker>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        group_state_ref: Option<EventId>,
    },
    TemporarilyUnavailable {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        retry_after_ms: Option<u64>,
    },
}

impl DirectConversationResolveOutcome {
    #[must_use]
    pub fn coordinates(&self) -> Option<&DirectConversationCoordinates> {
        match self {
            Self::Provisional { coordinates, .. }
            | Self::Found { coordinates, .. }
            | Self::Suspended { coordinates, .. } => Some(coordinates),
            _ => None,
        }
    }

    pub fn validate_shape(&self) -> Result<()> {
        if let Self::Provisional {
            authorization_basis,
            group_state_ref,
            initial_exact_pair_group_state_ref,
            peer_mls_admission,
            ..
        } = self
        {
            authorization_basis.validate_shape()?;
            if (initial_exact_pair_group_state_ref.is_some() && group_state_ref.is_none())
                || (matches!(
                    peer_mls_admission,
                    DirectConversationPeerMlsAdmission::Durable
                ) && initial_exact_pair_group_state_ref.is_none())
            {
                return Err(WireError::Protocol(
                    "provisional admission omits its accepted group state".into(),
                ));
            }
        }
        if let Self::Found { coordinates, .. } = self
            && coordinates.binding_event_ref.is_none()
        {
            return Err(WireError::Protocol(
                "found conversation requires an authority-committed binding".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod resolve_material_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn provisional_requires_the_exact_binding_material() {
        let basis = json!({"kind":"agent_controller", "event_refs":[
            "ak:event:AWgGCEbMHnelRQfzqg1C_onV9Ej_FdpdAZyM_JoFgAd3",
            "ak:event:ASOv-EoZPg5yuM1Pv__u1K8vD3Q9342GxwoWmkKwjqOn"
        ]});
        let mut value = json!({"state":"provisional", "coordinates":{
            "pair_key":format!("sha256:{}", "ab".repeat(32)),
            "realm_id":"ak:realm:ASOv-EoZPg5yuM1Pv__u1K8vD3Q9342GxwoWmkKwjqOn",
            "main_strand_id":"ak:strand:AcoR1oH31En1_7UqsmGtCAr0ByQ_638Axv43HIC06sGg"
        }, "authorization_basis":basis, "peer_mls_admission":"missing"});
        let outcome: DirectConversationResolveOutcome =
            serde_json::from_value(value.clone()).unwrap();
        outcome.validate_shape().unwrap();
        assert_eq!(serde_json::to_value(&outcome).unwrap(), value);
        value.as_object_mut().unwrap().remove("authorization_basis");
        assert!(serde_json::from_value::<DirectConversationResolveOutcome>(value.clone()).is_err());
        value["authorization_basis"] = json!({"kind":"agent_controller", "event_refs":[]});
        let outcome: DirectConversationResolveOutcome = serde_json::from_value(value).unwrap();
        assert!(outcome.validate_shape().is_err());
    }
}
