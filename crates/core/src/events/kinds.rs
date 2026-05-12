use serde::{Deserialize, Serialize};

pub const ACCOUNT_BLOCKLIST: &str = "cx.account.blocklist";
pub const ACCOUNT_STATUS: &str = "cx.account.status";
pub const ACCOUNT_DATA_SET: &str = "cx.account_data.set";
pub const ACTOR_DISCOVERY: &str = "cx.actor.discovery";
pub const AGENT_ENDPOINT: &str = "cx.agent.endpoint";
pub const AGENT_PROTOCOL_SESSION_RESULT: &str = "cx.agent.protocol_session.result";
pub const AGENT_PROTOCOL_SESSION_START: &str = "cx.agent.protocol_session.start";
pub const AGENT_PROTOCOL_SESSION_STATUS: &str = "cx.agent.protocol_session.status";
pub const APPLET_BRIDGE_ERROR: &str = "cx.applet.bridge_error";
pub const APPLET_DISCOVERY: &str = "cx.applet.discovery";
pub const APPLET_PROTOCOL_SESSION_START: &str = "cx.applet.protocol_session.start";
pub const APPLET_PROTOCOL_SESSION_STATUS: &str = "cx.applet.protocol_session.status";
pub const APPLET_REGISTRATION: &str = "cx.applet.registration";
pub const AUDIT_ACCESSED: &str = "cx.audit.accessed";
pub const AUDIT_RYW_RECEIPT: &str = "cx.audit.ryw_receipt";
pub const CALL_RECORDING_START: &str = "cx.call.recording.start";
pub const CALL_SIGNAL: &str = "cx.call.signal";
pub const CALL_STATE: &str = "cx.call.state";
pub const CAPABILITY_DELEGATE: &str = "cx.capability.delegate";
pub const CAPABILITY_DERIVED: &str = "cx.capability.derived";
pub const CAPABILITY_GRANT: &str = "cx.capability.grant";
pub const CAPABILITY_REVOKE: &str = "cx.capability.revoke";
pub const CONSENT_GRANT: &str = "cx.consent.grant";
pub const CONSENT_REVOKE: &str = "cx.consent.revoke";
pub const CONTAINER_MOVE_ITEM: &str = "cx.container.move_item";
pub const CONTAINER_REBALANCE: &str = "cx.container.rebalance";
pub const DEVICE_AUTHORIZED: &str = "cx.device.authorized";
pub const DEVICE_LIST_UPDATE: &str = "cx.device.list_update";
pub const DEVICE_REVOKED: &str = "cx.device.revoked";
pub const DID_PROOF: &str = "cx.did.proof";
pub const FLOW_ARCHIVE: &str = "cx.flow.archive";
pub const FLOW_CREATE: &str = "cx.flow.create";
pub const FLOW_MOVE: &str = "cx.flow.move";
pub const FLOW_REORDER: &str = "cx.flow.reorder";
pub const FLOW_RESTORE: &str = "cx.flow.restore";
pub const FLOW_TRACK_DISABLE: &str = "cx.flow.track.disable";
pub const FLOW_TRACK_ENABLE: &str = "cx.flow.track.enable";
pub const FLOW_TRACK_SET_PRIMARY: &str = "cx.flow.track.set_primary";
pub const FLOW_TRACK_UPDATE: &str = "cx.flow.track.update";
pub const FLOW_UPDATE: &str = "cx.flow.update";
pub const HANDLE_DISCOVERY: &str = "cx.handle.discovery";
pub const IDENTITY_DISCLOSURE_POLICY: &str = "cx.identity.disclosure_policy";
pub const IDENTITY_DISCLOSURE_RECEIPT: &str = "cx.identity.disclosure_receipt";
pub const IDENTITY_PRESENTATION_REQUEST: &str = "cx.identity.presentation_request";
pub const IDENTITY_PRESENTATION_RESPONSE: &str = "cx.identity.presentation_response";
pub const INVITE_ACCEPT: &str = "cx.invite.accept";
pub const INVITE_CANCEL: &str = "cx.invite.cancel";
pub const INVITE_CLAIM: &str = "cx.invite.claim";
pub const INVITE_CREATE: &str = "cx.invite.create";
pub const INVITE_REVOKE: &str = "cx.invite.revoke";
pub const INVITE_THIRD_PARTY: &str = "cx.invite.third_party";
pub const KEY_VERIFICATION_ACCEPT: &str = "cx.key.verification.accept";
pub const KEY_VERIFICATION_CANCEL: &str = "cx.key.verification.cancel";
pub const KEY_VERIFICATION_DONE: &str = "cx.key.verification.done";
pub const KEY_VERIFICATION_KEY: &str = "cx.key.verification.key";
pub const KEY_VERIFICATION_MAC: &str = "cx.key.verification.mac";
pub const KEY_VERIFICATION_READY: &str = "cx.key.verification.ready";
pub const KEY_VERIFICATION_REQUEST: &str = "cx.key.verification.request";
pub const KEY_VERIFICATION_START: &str = "cx.key.verification.start";
pub const MEMBER_STATE: &str = "cx.member.state";
pub const MESSAGE_CREATE: &str = "cx.message.create";
pub const MESSAGE_REDACT: &str = "cx.message.redact";
pub const MESSAGE_REVISE: &str = "cx.message.revise";
pub const MIMI_ROOM_BINDING: &str = "cx.mimi.room_binding";
pub const MLS_COMMIT: &str = "cx.mls.commit";
pub const MLS_COMMIT_FAILED: &str = "cx.mls.commit_failed";
pub const MLS_GENESIS: &str = "cx.mls.genesis";
pub const MLS_KEYPACKAGE: &str = "cx.mls.keypackage";
pub const MLS_PROPOSAL: &str = "cx.mls.proposal";
pub const MLS_WELCOME: &str = "cx.mls.welcome";
pub const MODERATION_DECISION: &str = "cx.moderation.decision";
pub const MODERATION_DECISION_LIFT: &str = "cx.moderation.decision.lift";
pub const MODERATION_FRANK: &str = "cx.moderation.frank";
pub const MODERATION_REPORT: &str = "cx.moderation.report";
pub const MORPH_ARCHIVE: &str = "cx.morph.archive";
pub const MORPH_CREATE: &str = "cx.morph.create";
pub const MORPH_RESTORE: &str = "cx.morph.restore";
pub const MORPH_UPDATE: &str = "cx.morph.update";
pub const ORGANIZATION_DISCOVERY: &str = "cx.organization.discovery";
pub const ORGANIZATION_MODERATION_POLICY: &str = "cx.organization.moderation_policy";
pub const PLACE_ARCHIVE: &str = "cx.place.archive";
pub const PLACE_CREATE: &str = "cx.place.create";
pub const PLACE_PARENT: &str = "cx.place.parent";
pub const PLACE_TOMBSTONE: &str = "cx.place.tombstone";
pub const PLACE_UPDATE: &str = "cx.place.update";
pub const POLICY_ACTION: &str = "cx.policy.action";
pub const POLICY_RULE: &str = "cx.policy.rule";
pub const POLICY_SET: &str = "cx.policy.set";
pub const PRESENCE: &str = "cx.presence";
pub const PROFILE_CREATE: &str = "cx.profile.create";
pub const PROFILE_SPACE_OVERRIDE: &str = "cx.profile.space_override";
pub const PROFILE_UPDATE: &str = "cx.profile.update";
pub const REACTION_ADD: &str = "cx.reaction.add";
pub const REACTION_REMOVE: &str = "cx.reaction.remove";
pub const READ_MARKER: &str = "cx.read.marker";
pub const RECEIPT_READ: &str = "cx.receipt.read";
pub const REDACTION: &str = "cx.redaction";
pub const RELATION_CREATE: &str = "cx.relation.create";
pub const RELATION_DELETE: &str = "cx.relation.delete";
pub const RELATION_UPDATE: &str = "cx.relation.update";
pub const SCHEMA_DEFINE: &str = "cx.schema.define";
pub const SCHEMA_UPDATE: &str = "cx.schema.update";
pub const SESSION_GRANT: &str = "cx.session.grant";
pub const SOVEREIGN_DID_POLICY: &str = "cx.sovereign.did_policy";
pub const SPACE_ARCHIVE: &str = "cx.space.archive";
pub const SPACE_ASSET_PRIVACY_POLICY: &str = "cx.space.asset_privacy_policy";
pub const SPACE_CHILD: &str = "cx.space.child";
pub const SPACE_CREATE: &str = "cx.space.create";
pub const SPACE_DESTROY: &str = "cx.space.destroy";
pub const SPACE_DISCOVERY: &str = "cx.space.discovery";
pub const SPACE_FREEZE: &str = "cx.space.freeze";
pub const SPACE_HISTORY_SHARING_POLICY: &str = "cx.space.history_sharing_policy";
pub const SPACE_HISTORY_VISIBILITY: &str = "cx.space.history_visibility";
pub const SPACE_INHERITANCE_POLICY: &str = "cx.space.inheritance_policy";
pub const SPACE_JOIN_RULE: &str = "cx.space.join_rule";
pub const SPACE_MEDIA_SERVICE: &str = "cx.space.media_service";
pub const SPACE_MODERATION_POLICY: &str = "cx.space.moderation_policy";
pub const SPACE_ORGANIZATION: &str = "cx.space.organization";
pub const SPACE_PARENT: &str = "cx.space.parent";
pub const SPACE_PLAINTEXT_VISIBLE_SERVICES: &str = "cx.space.plaintext_visible_services";
pub const SPACE_POLICY: &str = "cx.space.policy";
pub const SPACE_POLICY_COMPONENTS: &str = "cx.space.policy_components";
pub const SPACE_POLICY_SERVER: &str = "cx.space.policy_server";
pub const SPACE_READ_RECEIPT_POLICY: &str = "cx.space.read_receipt_policy";
pub const SPACE_SCHEMA: &str = "cx.space.schema";
pub const SPACE_TOMBSTONE: &str = "cx.space.tombstone";
pub const SPACE_UPDATE: &str = "cx.space.update";
pub const SPACE_UPGRADE: &str = "cx.space.upgrade";
pub const SPACE_KEY_SHARE: &str = "cx.space_key.share";
pub const SPACE_KEY_SHARE_AUDIT: &str = "cx.space_key.share_audit";
pub const SPACE_KEY_WITHHELD: &str = "cx.space_key.withheld";
pub const TYPING: &str = "cx.typing";
pub const VIEW_CREATE: &str = "cx.view.create";
pub const VIEW_RECONCILE: &str = "cx.view.reconcile";
pub const VIEW_UPDATE: &str = "cx.view.update";

pub const STANDARD_EVENT_KINDS: &[&str] = &[
    ACCOUNT_BLOCKLIST,
    ACCOUNT_STATUS,
    ACCOUNT_DATA_SET,
    ACTOR_DISCOVERY,
    AGENT_ENDPOINT,
    AGENT_PROTOCOL_SESSION_RESULT,
    AGENT_PROTOCOL_SESSION_START,
    AGENT_PROTOCOL_SESSION_STATUS,
    APPLET_BRIDGE_ERROR,
    APPLET_DISCOVERY,
    APPLET_PROTOCOL_SESSION_START,
    APPLET_PROTOCOL_SESSION_STATUS,
    APPLET_REGISTRATION,
    AUDIT_ACCESSED,
    AUDIT_RYW_RECEIPT,
    CALL_RECORDING_START,
    CALL_SIGNAL,
    CALL_STATE,
    CAPABILITY_DELEGATE,
    CAPABILITY_DERIVED,
    CAPABILITY_GRANT,
    CAPABILITY_REVOKE,
    CONSENT_GRANT,
    CONSENT_REVOKE,
    CONTAINER_MOVE_ITEM,
    CONTAINER_REBALANCE,
    DEVICE_AUTHORIZED,
    DEVICE_LIST_UPDATE,
    DEVICE_REVOKED,
    DID_PROOF,
    FLOW_ARCHIVE,
    FLOW_CREATE,
    FLOW_MOVE,
    FLOW_REORDER,
    FLOW_RESTORE,
    FLOW_TRACK_DISABLE,
    FLOW_TRACK_ENABLE,
    FLOW_TRACK_SET_PRIMARY,
    FLOW_TRACK_UPDATE,
    FLOW_UPDATE,
    HANDLE_DISCOVERY,
    IDENTITY_DISCLOSURE_POLICY,
    IDENTITY_DISCLOSURE_RECEIPT,
    IDENTITY_PRESENTATION_REQUEST,
    IDENTITY_PRESENTATION_RESPONSE,
    INVITE_ACCEPT,
    INVITE_CANCEL,
    INVITE_CLAIM,
    INVITE_CREATE,
    INVITE_REVOKE,
    INVITE_THIRD_PARTY,
    KEY_VERIFICATION_ACCEPT,
    KEY_VERIFICATION_CANCEL,
    KEY_VERIFICATION_DONE,
    KEY_VERIFICATION_KEY,
    KEY_VERIFICATION_MAC,
    KEY_VERIFICATION_READY,
    KEY_VERIFICATION_REQUEST,
    KEY_VERIFICATION_START,
    MEMBER_STATE,
    MESSAGE_CREATE,
    MESSAGE_REDACT,
    MESSAGE_REVISE,
    MIMI_ROOM_BINDING,
    MLS_COMMIT,
    MLS_COMMIT_FAILED,
    MLS_GENESIS,
    MLS_KEYPACKAGE,
    MLS_PROPOSAL,
    MLS_WELCOME,
    MODERATION_DECISION,
    MODERATION_DECISION_LIFT,
    MODERATION_FRANK,
    MODERATION_REPORT,
    MORPH_ARCHIVE,
    MORPH_CREATE,
    MORPH_RESTORE,
    MORPH_UPDATE,
    ORGANIZATION_DISCOVERY,
    ORGANIZATION_MODERATION_POLICY,
    PLACE_ARCHIVE,
    PLACE_CREATE,
    PLACE_PARENT,
    PLACE_TOMBSTONE,
    PLACE_UPDATE,
    POLICY_ACTION,
    POLICY_RULE,
    POLICY_SET,
    PRESENCE,
    PROFILE_CREATE,
    PROFILE_SPACE_OVERRIDE,
    PROFILE_UPDATE,
    REACTION_ADD,
    REACTION_REMOVE,
    READ_MARKER,
    RECEIPT_READ,
    REDACTION,
    RELATION_CREATE,
    RELATION_DELETE,
    RELATION_UPDATE,
    SCHEMA_DEFINE,
    SCHEMA_UPDATE,
    SESSION_GRANT,
    SOVEREIGN_DID_POLICY,
    SPACE_ARCHIVE,
    SPACE_ASSET_PRIVACY_POLICY,
    SPACE_CHILD,
    SPACE_CREATE,
    SPACE_DESTROY,
    SPACE_DISCOVERY,
    SPACE_FREEZE,
    SPACE_HISTORY_SHARING_POLICY,
    SPACE_HISTORY_VISIBILITY,
    SPACE_INHERITANCE_POLICY,
    SPACE_JOIN_RULE,
    SPACE_MEDIA_SERVICE,
    SPACE_MODERATION_POLICY,
    SPACE_ORGANIZATION,
    SPACE_PARENT,
    SPACE_PLAINTEXT_VISIBLE_SERVICES,
    SPACE_POLICY,
    SPACE_POLICY_COMPONENTS,
    SPACE_POLICY_SERVER,
    SPACE_READ_RECEIPT_POLICY,
    SPACE_SCHEMA,
    SPACE_TOMBSTONE,
    SPACE_UPDATE,
    SPACE_UPGRADE,
    SPACE_KEY_SHARE,
    SPACE_KEY_SHARE_AUDIT,
    SPACE_KEY_WITHHELD,
    TYPING,
    VIEW_CREATE,
    VIEW_RECONCILE,
    VIEW_UPDATE,
];

pub const NON_REDUCER_EVENT_KINDS: &[&str] = &[
    ACCOUNT_BLOCKLIST,
    ACCOUNT_DATA_SET,
    AUDIT_RYW_RECEIPT,
    CALL_SIGNAL,
    KEY_VERIFICATION_ACCEPT,
    KEY_VERIFICATION_CANCEL,
    KEY_VERIFICATION_DONE,
    KEY_VERIFICATION_KEY,
    KEY_VERIFICATION_MAC,
    KEY_VERIFICATION_READY,
    KEY_VERIFICATION_REQUEST,
    KEY_VERIFICATION_START,
    PRESENCE,
    READ_MARKER,
    RECEIPT_READ,
    TYPING,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventWireScope {
    DurableEvent,
    ActorPrivateEvent,
    EphemeralEvent,
    Custom,
}

pub fn is_reducer_input_event_kind(kind: &str) -> bool {
    is_standard_event_kind(kind) && NON_REDUCER_EVENT_KINDS.binary_search(&kind).is_err()
}

pub fn event_wire_scope(kind: &str) -> EventWireScope {
    match kind {
        ACCOUNT_BLOCKLIST | ACCOUNT_DATA_SET | READ_MARKER => EventWireScope::ActorPrivateEvent,
        CALL_SIGNAL
        | KEY_VERIFICATION_ACCEPT
        | KEY_VERIFICATION_CANCEL
        | KEY_VERIFICATION_DONE
        | KEY_VERIFICATION_KEY
        | KEY_VERIFICATION_MAC
        | KEY_VERIFICATION_READY
        | KEY_VERIFICATION_REQUEST
        | KEY_VERIFICATION_START
        | PRESENCE
        | RECEIPT_READ
        | TYPING => EventWireScope::EphemeralEvent,
        _ if is_standard_event_kind(kind) => EventWireScope::DurableEvent,
        _ => EventWireScope::Custom,
    }
}

/// Broad class for routing, indexing and UI projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventClass {
    Account,
    Actor,
    Agent,
    Applet,
    Audit,
    Authz,
    Call,
    Consent,
    Device,
    E2ee,
    Flow,
    Handle,
    Identity,
    Invite,
    Membership,
    Message,
    Mimi,
    Moderation,
    Morph,
    Organization,
    Place,
    Policy,
    Profile,
    Read,
    Relation,
    Schema,
    Sovereign,
    Space,
    View,
    Custom(String),
}

pub fn is_standard_event_kind(kind: &str) -> bool {
    STANDARD_EVENT_KINDS.binary_search(&kind).is_ok()
}

/// Classify a protocol event kind without deserializing its content.
pub fn classify_event_kind(kind: &str) -> EventClass {
    match kind {
        ACCOUNT_BLOCKLIST | ACCOUNT_STATUS | ACCOUNT_DATA_SET | PRESENCE | TYPING => {
            EventClass::Account
        }
        ACTOR_DISCOVERY => EventClass::Actor,
        AGENT_ENDPOINT
        | AGENT_PROTOCOL_SESSION_RESULT
        | AGENT_PROTOCOL_SESSION_START
        | AGENT_PROTOCOL_SESSION_STATUS => EventClass::Agent,
        APPLET_BRIDGE_ERROR
        | APPLET_DISCOVERY
        | APPLET_PROTOCOL_SESSION_START
        | APPLET_PROTOCOL_SESSION_STATUS
        | APPLET_REGISTRATION => EventClass::Applet,
        AUDIT_ACCESSED | AUDIT_RYW_RECEIPT => EventClass::Audit,
        CAPABILITY_DELEGATE | CAPABILITY_DERIVED | CAPABILITY_GRANT | CAPABILITY_REVOKE
        | SESSION_GRANT => EventClass::Authz,
        CALL_RECORDING_START | CALL_SIGNAL | CALL_STATE => EventClass::Call,
        CONSENT_GRANT | CONSENT_REVOKE => EventClass::Consent,
        DEVICE_AUTHORIZED
        | DEVICE_LIST_UPDATE
        | DEVICE_REVOKED
        | KEY_VERIFICATION_ACCEPT
        | KEY_VERIFICATION_CANCEL
        | KEY_VERIFICATION_DONE
        | KEY_VERIFICATION_KEY
        | KEY_VERIFICATION_MAC
        | KEY_VERIFICATION_READY
        | KEY_VERIFICATION_REQUEST
        | KEY_VERIFICATION_START => EventClass::Device,
        MLS_COMMIT
        | MLS_COMMIT_FAILED
        | MLS_GENESIS
        | MLS_KEYPACKAGE
        | MLS_PROPOSAL
        | MLS_WELCOME
        | SPACE_KEY_SHARE
        | SPACE_KEY_SHARE_AUDIT
        | SPACE_KEY_WITHHELD => EventClass::E2ee,
        FLOW_ARCHIVE
        | FLOW_CREATE
        | FLOW_MOVE
        | FLOW_REORDER
        | FLOW_RESTORE
        | FLOW_TRACK_DISABLE
        | FLOW_TRACK_ENABLE
        | FLOW_TRACK_SET_PRIMARY
        | FLOW_TRACK_UPDATE
        | FLOW_UPDATE => EventClass::Flow,
        HANDLE_DISCOVERY => EventClass::Handle,
        DID_PROOF
        | IDENTITY_DISCLOSURE_POLICY
        | IDENTITY_DISCLOSURE_RECEIPT
        | IDENTITY_PRESENTATION_REQUEST
        | IDENTITY_PRESENTATION_RESPONSE => EventClass::Identity,
        INVITE_ACCEPT | INVITE_CANCEL | INVITE_CLAIM | INVITE_CREATE | INVITE_REVOKE
        | INVITE_THIRD_PARTY => EventClass::Invite,
        MEMBER_STATE => EventClass::Membership,
        MESSAGE_CREATE | MESSAGE_REDACT | MESSAGE_REVISE | REACTION_ADD | REACTION_REMOVE
        | REDACTION => EventClass::Message,
        MIMI_ROOM_BINDING => EventClass::Mimi,
        MODERATION_DECISION | MODERATION_DECISION_LIFT | MODERATION_FRANK | MODERATION_REPORT => {
            EventClass::Moderation
        }
        MORPH_ARCHIVE | MORPH_CREATE | MORPH_RESTORE | MORPH_UPDATE => EventClass::Morph,
        ORGANIZATION_DISCOVERY | ORGANIZATION_MODERATION_POLICY => EventClass::Organization,
        PLACE_ARCHIVE | PLACE_CREATE | PLACE_PARENT | PLACE_TOMBSTONE | PLACE_UPDATE => {
            EventClass::Place
        }
        POLICY_ACTION | POLICY_RULE | POLICY_SET => EventClass::Policy,
        PROFILE_CREATE | PROFILE_SPACE_OVERRIDE | PROFILE_UPDATE => EventClass::Profile,
        READ_MARKER | RECEIPT_READ => EventClass::Read,
        CONTAINER_MOVE_ITEM | CONTAINER_REBALANCE | RELATION_CREATE | RELATION_DELETE
        | RELATION_UPDATE => EventClass::Relation,
        SCHEMA_DEFINE | SCHEMA_UPDATE => EventClass::Schema,
        SOVEREIGN_DID_POLICY => EventClass::Sovereign,
        SPACE_ARCHIVE
        | SPACE_ASSET_PRIVACY_POLICY
        | SPACE_CHILD
        | SPACE_CREATE
        | SPACE_DESTROY
        | SPACE_DISCOVERY
        | SPACE_FREEZE
        | SPACE_HISTORY_SHARING_POLICY
        | SPACE_HISTORY_VISIBILITY
        | SPACE_INHERITANCE_POLICY
        | SPACE_JOIN_RULE
        | SPACE_MEDIA_SERVICE
        | SPACE_MODERATION_POLICY
        | SPACE_ORGANIZATION
        | SPACE_PARENT
        | SPACE_PLAINTEXT_VISIBLE_SERVICES
        | SPACE_POLICY
        | SPACE_POLICY_COMPONENTS
        | SPACE_POLICY_SERVER
        | SPACE_READ_RECEIPT_POLICY
        | SPACE_SCHEMA
        | SPACE_TOMBSTONE
        | SPACE_UPDATE
        | SPACE_UPGRADE => EventClass::Space,
        VIEW_CREATE | VIEW_RECONCILE | VIEW_UPDATE => EventClass::View,
        _ => EventClass::Custom(kind.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_active_spec_event_kinds() {
        assert!(is_standard_event_kind(MESSAGE_CREATE));
        assert_eq!(classify_event_kind(MESSAGE_CREATE), EventClass::Message);
        assert_eq!(classify_event_kind(SPACE_CREATE), EventClass::Space);
        assert_eq!(classify_event_kind(AGENT_PROTOCOL_SESSION_STATUS), EventClass::Agent);
        assert_eq!(classify_event_kind(CALL_SIGNAL), EventClass::Call);
        assert_eq!(
            classify_event_kind("vendor.example.widget"),
            EventClass::Custom("vendor.example.widget".to_owned())
        );
    }
}
