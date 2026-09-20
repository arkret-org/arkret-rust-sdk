//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/event-kind-registry.json; version=2026-09-20.16;
//! sha256=f9945090c0614facaf6a065670451e3aead9ab82a2e47bdd7baf7968f332a325 Input: registry/
//! contract-registry.json; version=2026-09-20.25;
//! sha256=75427e307029abe6530b20b2d6df516b7c5fe94836568f8ab82f13d33ef98aaf
//! Entries: active_events=146

use arkret_wire::event_kind_str;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventIdSource {
    EventDerived,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventRuntimeContractDescriptor {
    pub event_kind: &'static str,
    pub id_source: Option<EventIdSource>,
    pub derived_id_kinds: &'static [&'static str],
}

pub const EVENT_RUNTIME_CONTRACTS: &[EventRuntimeContractDescriptor] = &[
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::ACCOUNT_BLOCKLIST,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::ACCOUNT_DATA_SET,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::ACTOR_DISCOVERY,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::AGENT_ACTION_APPROVE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::AGENT_ACTION_REJECT,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::AGENT_ACTION_REQUEST,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::AGENT_DRAFT_PROPOSE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::AGENT_KEY_AUTHORIZE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::AGENT_KEY_REVOKE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::AGENT_PROVISION,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::AGENT_SELECTOR_CLAIM,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::AGENT_SIDECAR_EXCHANGE_CONTROL,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::APPLET_BRIDGE_ERROR,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::APPLET_DISCOVERY,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::APPLET_MANAGED_ACTOR_PROVISION,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::APPLET_REGISTRATION,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::AUDIT_ACCESSED,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::AUDIT_ERASURE_RECEIPT,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CALL_CREATE,
        id_source: Some(EventIdSource::EventDerived),
        derived_id_kinds: &["call"],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CALL_RECORDING_START,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CALL_STATE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CALL_SUMMARY,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CAPABILITY_DERIVED,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CAPABILITY_GRANT,
        id_source: Some(EventIdSource::EventDerived),
        derived_id_kinds: &["grant"],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CAPABILITY_RELINQUISH,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CAPABILITY_REVOKE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CIRCLE_ARCHIVE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CIRCLE_CREATE,
        id_source: Some(EventIdSource::EventDerived),
        derived_id_kinds: &["circle"],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CIRCLE_HISTORY_ACCESS,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CIRCLE_MEMBER_STATE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CIRCLE_RESTORE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CIRCLE_TOMBSTONE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CIRCLE_UPDATE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CONSENT_GRANT,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CONSENT_REVOKE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CONTACT_ACCEPTED,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CONTACT_REJECTED,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CONTACT_REQUESTED,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CONTACT_SCOPE_UPDATE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CONTACT_TOMBSTONE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CONTAINER_MOVE_ITEM,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::CONTAINER_REBALANCE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::DEVICE_AUTHORIZE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::DEVICE_LIST_UPDATE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::DEVICE_PUSH_ROUTE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::DEVICE_REANCHOR,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::DEVICE_REVOKE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::DIRECT_CONVERSATION_BOUND,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::HANDLE_DISCOVERY,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::IDENTITY_ACCOUNTABILITY_GRANT,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::IDENTITY_RESOLUTION_UPDATE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::INVITE_ACCEPT,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::INVITE_CANCEL,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::INVITE_CLAIM,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::INVITE_CREATE,
        id_source: Some(EventIdSource::EventDerived),
        derived_id_kinds: &["invite"],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::INVITE_REVOKE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::INVITE_THIRD_PARTY,
        id_source: Some(EventIdSource::EventDerived),
        derived_id_kinds: &["invite"],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::KEY_BACKUP_ACTIVE_SERIES,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::MEMBER_IDENTITY_UPDATE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::MEMBER_STATE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::MESSAGE_CREATE,
        id_source: Some(EventIdSource::EventDerived),
        derived_id_kinds: &["message"],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::MESSAGE_REDACT,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::MESSAGE_REVISE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::MIMI_ROOM_BINDING,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::MLS_COMMIT,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::MLS_GENESIS,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::MODERATION_DECISION,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::MODERATION_DECISION_LIFT,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::MODERATION_FRANKING_PROOF,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::MORPH_ARCHIVE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::MORPH_CREATE,
        id_source: Some(EventIdSource::EventDerived),
        derived_id_kinds: &["morph"],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::MORPH_RESTORE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::MORPH_STAGE_SET,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::MORPH_UPDATE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::ORGANIZATION_DISCOVERY,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::ORGANIZATION_MODERATION_POLICY,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::PIN_ADD,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::PIN_REMOVE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::PIN_REORDER,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::POLICY_ACTION,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::POLICY_SET,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::PROFILE_CREATE,
        id_source: Some(EventIdSource::EventDerived),
        derived_id_kinds: &["actor_profile"],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::PROFILE_REALM_OVERRIDE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::PROFILE_UPDATE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REACTION_ADD,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REACTION_REMOVE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::READ_CURSOR_ADVANCE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_ALIAS,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_ARCHIVE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_ASSET_PRIVACY_POLICY,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_AUTHORITY_RESET,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_CREATE,
        id_source: Some(EventIdSource::EventDerived),
        derived_id_kinds: &["realm"],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_DESTROY,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_DISCOVERY,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_FREEZE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_GOVERNANCE_STATION_CHANGE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_HISTORY_ACCESS,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_INHERITANCE_POLICY,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_JOIN_RULE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_LINK,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_MEDIA_SERVICE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_ORGANIZATION,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_OWNER_TRANSFER,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_PLAINTEXT_VISIBLE_SERVICES,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_POLICY,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_POLICY_BUNDLE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_PREVIEW_POLICY,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_PROFILE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_READ_RECEIPT_POLICY,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_RESTORE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_SCHEMA,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_SEARCH_POLICY,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_SET_DEFAULT_STRAND,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_TOMBSTONE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REALM_UNFREEZE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::REDACTION,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::RELATION_CREATE,
        id_source: Some(EventIdSource::EventDerived),
        derived_id_kinds: &["relation"],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::RELATION_TOMBSTONE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::RELATION_UPDATE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::RSVP_SET,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::SCHEMA_DEFINE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::SELF_AGENT_DEACTIVATE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::SELF_AGENT_PAUSE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::SELF_AGENT_RESUME,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::SELF_MODERATION_REPORT,
        id_source: Some(EventIdSource::EventDerived),
        derived_id_kinds: &["report", "moderation_queue_item"],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::SIDECAR_CONTEXT_ATTACH,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::SIDECAR_CREATE,
        id_source: Some(EventIdSource::EventDerived),
        derived_id_kinds: &["sidecar"],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::SOVEREIGN_DID_POLICY,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::SPACE_ARCHIVE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::SPACE_CREATE,
        id_source: Some(EventIdSource::EventDerived),
        derived_id_kinds: &["space"],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::SPACE_PARENT,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::SPACE_RESTORE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::SPACE_TOMBSTONE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::SPACE_UPDATE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::STRAND_ARCHIVE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::STRAND_CREATE,
        id_source: Some(EventIdSource::EventDerived),
        derived_id_kinds: &["strand"],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::STRAND_MOVE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::STRAND_REORDER,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::STRAND_RESTORE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::STRAND_STAGE_SET,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::STRAND_TRACKS_UPDATE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::STRAND_UPDATE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::STRAND_WATCH_SET,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::VIEW_CREATE,
        id_source: Some(EventIdSource::EventDerived),
        derived_id_kinds: &["view"],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::VIEW_RECONCILE,
        id_source: None,
        derived_id_kinds: &[],
    },
    EventRuntimeContractDescriptor {
        event_kind: event_kind_str::VIEW_UPDATE,
        id_source: None,
        derived_id_kinds: &[],
    },
];

pub fn event_runtime_contract(event_kind: &str) -> Option<&'static EventRuntimeContractDescriptor> {
    EVENT_RUNTIME_CONTRACTS
        .binary_search_by_key(&event_kind, |descriptor| descriptor.event_kind)
        .ok()
        .map(|index| &EVENT_RUNTIME_CONTRACTS[index])
}
