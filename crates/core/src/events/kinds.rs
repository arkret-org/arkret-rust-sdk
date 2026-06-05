use serde::{Deserialize, Serialize};

pub const ACCOUNT_BLOCKLIST: &str = "ck.account.blocklist";
pub const ACCOUNT_STATUS: &str = "ck.account.status";
pub const ACCOUNT_DATA_SET: &str = "ck.account_data.set";
pub const ACTOR_DISCOVERY: &str = "ck.actor.discovery";
pub const AGENT_ENDPOINT: &str = "ck.agent.endpoint";
pub const AGENT_KEY_AUTHORIZE: &str = "ck.agent.key.authorize";
pub const AGENT_KEY_REVOKE: &str = "ck.agent.key.revoke";
pub const AGENT_KEY_ROTATE: &str = "ck.agent.key.rotate";
pub const AGENT_KEY_AUTHORIZED: &str = AGENT_KEY_AUTHORIZE;
pub const AGENT_KEY_REVOKED: &str = AGENT_KEY_REVOKE;
pub const AGENT_KEY_ROTATED: &str = AGENT_KEY_ROTATE;
// CKP-0008 / CKP-0009 (spec head 37ce729) — personal-agent lifecycle event
// kinds (durable, reducer-input).
pub const AGENT_PAUSE: &str = "ck.self.agent.pause";
pub const AGENT_RESUME: &str = "ck.self.agent.resume";
pub const AGENT_DEACTIVATE: &str = "ck.self.agent.deactivate";
// CKP-0008 / CKP-0009 — agent action / draft event kinds (actor_private).
pub const AGENT_DRAFT_PROPOSE: &str = "ck.agent.draft.propose";
pub const AGENT_ACTION_REQUEST: &str = "ck.agent.action_request";
pub const AGENT_ACTION_APPROVE: &str = "ck.agent.action_approve";
pub const AGENT_ACTION_REJECT: &str = "ck.agent.action_reject";
pub const AGENT_PROTOCOL_SESSION_RESULT: &str = "ck.agent.protocol_session.result";
pub const AGENT_PROTOCOL_SESSION_START: &str = "ck.agent.protocol_session.start";
pub const AGENT_PROTOCOL_SESSION_STATUS: &str = "ck.agent.protocol_session.status";
pub const APPLET_BRIDGE_ERROR: &str = "ck.applet.bridge_error";
pub const APPLET_DISCOVERY: &str = "ck.applet.discovery";
pub const APPLET_PROTOCOL_SESSION_START: &str = "ck.applet.protocol_session.start";
pub const APPLET_PROTOCOL_SESSION_STATUS: &str = "ck.applet.protocol_session.status";
pub const APPLET_REGISTRATION: &str = "ck.applet.registration";
pub const ATTESTATION_RANGE_COMPLETENESS: &str = "ck.attestation.range_completeness";
pub const AUDIT_ACCESSED: &str = "ck.audit.accessed";
pub const AUDIT_EPOCH_KEY_DESTRUCTION: &str = "ck.audit.epoch_key_destruction";
pub const AUDIT_ERASURE_RECEIPT: &str = "ck.audit.erasure_receipt";
pub const AUDIT_RYW_RECEIPT: &str = "ck.audit.ryw_receipt";
pub const CALL_RECORDING_START: &str = "ck.call.recording.start";
pub const CALL_SIGNAL: &str = "ck.call.signal";
pub const CALL_STATE: &str = "ck.call.state";
pub const CAPABILITY_DELEGATE: &str = "ck.capability.delegate";
pub const CAPABILITY_DERIVED: &str = "ck.capability.derived";
pub const CAPABILITY_GRANT: &str = "ck.capability.grant";
pub const CAPABILITY_REVOKE: &str = "ck.capability.revoke";
// CKP-0007 (spec b7d35be) — Circle primitive event kinds. 7 active kinds
// registered in `event-kind-registry.json` v2026-05-08.
pub const CIRCLE_CREATE: &str = "ck.circle.create";
pub const CIRCLE_UPDATE: &str = "ck.circle.update";
pub const CIRCLE_ARCHIVE: &str = "ck.circle.archive";
pub const CIRCLE_RESTORE: &str = "ck.circle.restore";
pub const CIRCLE_TOMBSTONE: &str = "ck.circle.tombstone";
pub const CIRCLE_MEMBER_STATE: &str = "ck.circle.member.state";
pub const CIRCLE_ANCHOR_COMMIT: &str = "ck.circle.anchor_commit";
pub const CONSENT_GRANT: &str = "ck.consent.grant";
pub const CONSENT_REVOKE: &str = "ck.consent.revoke";
pub const CONTAINER_MOVE_ITEM: &str = "ck.container.move_item";
pub const CONTAINER_REBALANCE: &str = "ck.container.rebalance";
pub const CROSS_SIGNING_PUBLISH: &str = "ck.cross_signing.publish";
pub const CROSS_SIGNING_RESET: &str = "ck.cross_signing.reset";
pub const DEVICE_AUTHORIZE: &str = "ck.device.authorize";
pub const DEVICE_AUTHORIZED: &str = DEVICE_AUTHORIZE;
pub const DEVICE_LIST_UPDATE: &str = "ck.device.list_update";
pub const DEVICE_PUSH_ROUTE: &str = "ck.device.push_route";
pub const DEVICE_REVOKE: &str = "ck.device.revoke";
pub const DEVICE_REVOKED: &str = DEVICE_REVOKE;
pub const DID_PROOF: &str = "ck.did.proof";
pub const FLOW_ARCHIVE: &str = "ck.flow.archive";
pub const FLOW_CREATE: &str = "ck.flow.create";
pub const FLOW_MOVE: &str = "ck.flow.move";
pub const FLOW_REORDER: &str = "ck.flow.reorder";
pub const FLOW_RESTORE: &str = "ck.flow.restore";
pub const FLOW_STAGE_SET: &str = "ck.flow.stage.set";
pub const FLOW_TRACKS_UPDATE: &str = "ck.flow.tracks.update";
pub const FLOW_UPDATE: &str = "ck.flow.update";
pub const FLOW_WATCH_SET: &str = "ck.flow.watch.set";
pub const HANDLE_DISCOVERY: &str = "ck.handle.discovery";
pub const IDENTITY_ACCOUNTABILITY_GRANT: &str = "ck.identity.accountability_grant";
pub const IDENTITY_DISCLOSURE_POLICY: &str = "ck.identity.disclosure_policy";
pub const IDENTITY_DISCLOSURE_RECEIPT: &str = "ck.identity.disclosure_receipt";
pub const IDENTITY_PRESENTATION_REQUEST: &str = "ck.identity.presentation_request";
pub const IDENTITY_PRESENTATION_RESPONSE: &str = "ck.identity.presentation_response";
pub const INVITE_ACCEPT: &str = "ck.invite.accept";
pub const INVITE_CANCEL: &str = "ck.invite.cancel";
pub const INVITE_CLAIM: &str = "ck.invite.claim";
pub const INVITE_CREATE: &str = "ck.invite.create";
pub const INVITE_REVOKE: &str = "ck.invite.revoke";
pub const INVITE_THIRD_PARTY: &str = "ck.invite.third_party";
pub const KEY_VERIFICATION_ACCEPT: &str = "ck.key.verification.accept";
pub const KEY_VERIFICATION_CANCEL: &str = "ck.key.verification.cancel";
pub const KEY_VERIFICATION_DONE: &str = "ck.key.verification.done";
pub const KEY_VERIFICATION_KEY: &str = "ck.key.verification.key";
pub const KEY_VERIFICATION_MAC: &str = "ck.key.verification.mac";
pub const KEY_VERIFICATION_READY: &str = "ck.key.verification.ready";
pub const KEY_VERIFICATION_REQUEST: &str = "ck.key.verification.request";
pub const KEY_VERIFICATION_START: &str = "ck.key.verification.start";
pub const MEMBER_IDENTITY_UPDATE: &str = "ck.member.identity.update";
pub const MEMBER_STATE: &str = "ck.member.state";
pub const MESSAGE_CREATE: &str = "ck.message.create";
pub const MESSAGE_REDACT: &str = "ck.message.redact";
pub const MESSAGE_REVISE: &str = "ck.message.revise";
pub const MIMI_ROOM_BINDING: &str = "ck.mimi.room_binding";
pub const MLS_COMMIT: &str = "ck.mls.commit";
pub const MLS_COMMIT_FAILED: &str = "ck.mls.commit_failed";
pub const MLS_GENESIS: &str = "ck.mls.genesis";
pub const MLS_KEYPACKAGE: &str = "ck.mls.keypackage";
pub const MLS_PROPOSAL: &str = "ck.mls.proposal";
pub const MLS_WELCOME: &str = "ck.mls.welcome";
pub const MODERATION_APPEAL_CLOSE: &str = "ck.moderation.appeal.close";
pub const MODERATION_APPEAL_DECISION: &str = "ck.moderation.appeal.decision";
pub const MODERATION_APPEAL_REVIEW: &str = "ck.moderation.appeal.review";
pub const MODERATION_APPEAL_SUBMIT: &str = "ck.moderation.appeal.submit";
pub const MODERATION_DECISION: &str = "ck.moderation.decision";
pub const MODERATION_DECISION_LIFT: &str = "ck.moderation.decision.lift";
pub const MODERATION_FRANKING_PROOF: &str = "ck.moderation.franking_proof";
pub const MODERATION_FRANK: &str = MODERATION_FRANKING_PROOF;
pub const MODERATION_REPORT: &str = "ck.self.moderation.report";

/// Object-only schema id — `ck.event_batch_receipt` is NOT an Event.kind.
/// Returns `true` for kinds that may only appear as a separate object,
/// MUST NOT appear as `Event.kind` on the wire. Round R2/R3 (2026-05-20).
pub const RECEIPT_OBJECT_KINDS: &[&str] = &["ck.event_batch_receipt"];

/// Broadcast ephemeral signal kinds + the to-device key-verification family.
/// Round R2/R3 (2026-05-20). Items here MUST NOT be reduced into durable
/// state, MUST NOT advance Anchor frontier or Move state_root, MUST NOT
/// carry preconditions/effects/anchor_ref, and MUST NOT be submitted via
/// `ck.self.events.submit`. See zh/sync/operations-sync.md §3.6 and
/// schemas/ephemeral-envelope.schema.json (the 4 broadcast forms) and
/// schemas/device-message.schema.json (the to-device key.verification forms).
pub const EPHEMERAL_EVENT_KIND_PATTERNS: &[&str] = &[
    CALL_SIGNAL,
    PRESENCE,
    TYPING,
    RECEIPT_READ,
    // ck.key.verification.* — point-to-point to-device family.
    KEY_VERIFICATION_ACCEPT,
    KEY_VERIFICATION_CANCEL,
    KEY_VERIFICATION_DONE,
    KEY_VERIFICATION_KEY,
    KEY_VERIFICATION_MAC,
    KEY_VERIFICATION_READY,
    KEY_VERIFICATION_REQUEST,
    KEY_VERIFICATION_START,
];

/// True for the 12 wire-scope-ephemeral kinds — broadcast ephemerals
/// (`ck.call.signal`, `ck.presence`, `ck.typing`, `ck.receipt.read`) plus
/// the `ck.key.verification.*` to-device family. These MUST be rejected by
/// reducers if delivered as a durable Event (event-envelope.schema.json `not` branch).
pub fn is_ephemeral_kind(kind: &str) -> bool {
    if kind.starts_with("ck.key.verification.") {
        return true;
    }
    EPHEMERAL_EVENT_KIND_PATTERNS.contains(&kind)
}

/// True for receipt-style object-only schema ids that MUST NOT appear as
/// `Event.kind` on the wire (`ck.event_batch_receipt`). Round R2/R3.
pub fn is_receipt_object_only(kind: &str) -> bool {
    RECEIPT_OBJECT_KINDS.contains(&kind)
}

/// MID-7 — event payload schema-dispatcher.
///
/// Returns the JSON-Schema `$ref` fragment under
/// `event-payload.schema.json#/$defs/...` that validates the `payload`
/// for `kind`, or `None` when the SDK does not yet ship a typed payload
/// schema ref (callers fall back to the generic event envelope check).
///
/// R3.1 adds `ck.member.identity.update` →
/// `event-payload.schema.json#/$defs/member_identity_update_payload`.
pub fn event_payload_schema_ref(kind: &str) -> Option<&'static str> {
    match kind {
        MEMBER_IDENTITY_UPDATE => {
            Some("event-payload.schema.json#/$defs/member_identity_update_payload")
        }
        _ => None,
    }
}

/// Round R2/R3 (2026-05-20) — Realm lifecycle state classifier.
///
/// Returned by [`is_terminal_realm_state`]. After a Realm has emitted
/// `ck.realm.destroy`, no further state-changing events MUST be accepted
/// (rejected as `realm_terminal_state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmLifecycleState {
    Active,
    Frozen,
    Archived,
    Tombstoned,
    /// `ck.realm.destroy` has been applied. Terminal.
    Destroyed,
}

/// Round R2/R3 — true once the Realm has reached the destroyed terminal
/// state (`ck.realm.destroy` applied). Any subsequent state-changing
/// event MUST be rejected as `ERROR_CODE_REALM_TERMINAL_STATE`.
pub fn is_terminal_realm_state(state: RealmLifecycleState) -> bool {
    matches!(state, RealmLifecycleState::Destroyed)
}
pub const MORPH_ARCHIVE: &str = "ck.morph.archive";
pub const MORPH_CREATE: &str = "ck.morph.create";
pub const MORPH_RESTORE: &str = "ck.morph.restore";
pub const MORPH_SCHEMA_MIGRATE: &str = "ck.morph.schema_migrate";
pub const MORPH_STAGE_SET: &str = "ck.morph.stage.set";
pub const MORPH_UPDATE: &str = "ck.morph.update";
pub const ORGANIZATION_DISCOVERY: &str = "ck.organization.discovery";
pub const ORGANIZATION_MODERATION_POLICY: &str = "ck.organization.moderation_policy";
// Realm event kinds (security boundary; spec 59ac1d4 Realm/Space inversion).
// Top-level governance of the security boundary lives here.
pub const REALM_ARCHIVE: &str = "ck.realm.archive";
pub const REALM_ASSET_PRIVACY_POLICY: &str = "ck.realm.asset_privacy_policy";
pub const REALM_AUDIT_POLICY_DOWNGRADE: &str = "ck.realm.audit_policy_downgrade";
pub const REALM_CREATE: &str = "ck.realm.create";
pub const REALM_DELIVERY_BINDING_POLICY: &str = "ck.realm.delivery_binding_policy";
pub const REALM_DESTROY: &str = "ck.realm.destroy";
pub const REALM_DISCOVERY: &str = "ck.realm.discovery";
pub const REALM_FREEZE: &str = "ck.realm.freeze";
pub const REALM_HISTORY_SHARING_POLICY: &str = "ck.realm.history_sharing_policy";
pub const REALM_HISTORY_VISIBILITY: &str = "ck.realm.history_visibility";
pub const REALM_INHERITANCE_POLICY: &str = "ck.realm.inheritance_policy";
pub const REALM_KEY_SHARE: &str = "ck.realm_key.share";
pub const REALM_KEY_SHARE_AUDIT: &str = "ck.realm_key.share_audit";
pub const REALM_KEY_WITHHELD: &str = "ck.realm_key.withheld";
pub const REALM_JOIN_RULE: &str = "ck.realm.join_rule";
pub const REALM_LINK: &str = "ck.realm.link";
pub const REALM_MEDIA_SERVICE: &str = "ck.realm.media_service";
pub const REALM_MODERATION_POLICY: &str = "ck.realm.moderation_policy";
pub const REALM_ORGANIZATION: &str = "ck.realm.organization";
pub const REALM_PLAINTEXT_VISIBLE_SERVICES: &str = "ck.realm.plaintext_visible_services";
pub const REALM_POLICY: &str = "ck.realm.policy";
pub const REALM_POLICY_COMPONENTS: &str = "ck.realm.policy_components";
pub const REALM_POLICY_SERVER: &str = "ck.realm.policy_server";
pub const REALM_PREVIEW_POLICY: &str = "ck.realm.preview_policy";
pub const REALM_READ_RECEIPT_POLICY: &str = "ck.realm.read_receipt_policy";
pub const REALM_SCHEMA: &str = "ck.realm.schema";
pub const REALM_TOMBSTONE: &str = "ck.realm.tombstone";
pub const REALM_UPDATE: &str = "ck.realm.update";
pub const REALM_UPGRADE: &str = "ck.realm.upgrade";
pub const POLICY_ACTION: &str = "ck.policy.action";
pub const POLICY_RULE: &str = "ck.policy.rule";
pub const POLICY_SET: &str = "ck.policy.set";
pub const PRESENCE: &str = "ck.presence";
pub const PROFILE_CREATE: &str = "ck.profile.create";
pub const PROFILE_REALM_OVERRIDE: &str = "ck.profile.realm_override";
pub const PROFILE_UPDATE: &str = "ck.profile.update";
pub const REACTION_ADD: &str = "ck.reaction.add";
pub const REACTION_REMOVE: &str = "ck.reaction.remove";
pub const READ_CURSOR_ADVANCE: &str = "ck.read_cursor.advance";
pub const READ_MARKER: &str = READ_CURSOR_ADVANCE;
pub const RECEIPT_READ: &str = "ck.receipt.read";
pub const REDACTION: &str = "ck.redaction";
pub const RELATION_CREATE: &str = "ck.relation.create";
pub const RELATION_TOMBSTONE: &str = "ck.relation.tombstone";
pub const RELATION_DELETE: &str = RELATION_TOMBSTONE;
pub const RELATION_UPDATE: &str = "ck.relation.update";
pub const SCHEMA_DEFINE: &str = "ck.schema.define";
pub const SCHEMA_UPDATE: &str = "ck.schema.update";
pub const SESSION_GRANT: &str = "ck.session.grant";
pub const SOVEREIGN_DID_POLICY: &str = "ck.sovereign.did_policy";
// Space event kinds (container; spec 59ac1d4 Realm/Space inversion).
// Boards / lists / arbitrary nestable containers live here. Security
// policies are NOT in this family — see REALM_* above.
pub const SPACE_ARCHIVE: &str = "ck.space.archive";
pub const SPACE_CREATE: &str = "ck.space.create";
pub const SPACE_PARENT: &str = "ck.space.parent";
pub const SPACE_RESTORE: &str = "ck.space.restore";
pub const SPACE_TOMBSTONE: &str = "ck.space.tombstone";
pub const SPACE_UPDATE: &str = "ck.space.update";
pub const TYPING: &str = "ck.typing";
pub const VIEW_CREATE: &str = "ck.view.create";
pub const VIEW_RECONCILE: &str = "ck.view.reconcile";
pub const VIEW_UPDATE: &str = "ck.view.update";

pub const STANDARD_EVENT_KINDS: &[&str] = &[
    ACCOUNT_BLOCKLIST,
    ACCOUNT_STATUS,
    ACCOUNT_DATA_SET,
    ACTOR_DISCOVERY,
    AGENT_ACTION_APPROVE,
    AGENT_ACTION_REJECT,
    AGENT_ACTION_REQUEST,
    AGENT_DEACTIVATE,
    AGENT_DRAFT_PROPOSE,
    AGENT_ENDPOINT,
    AGENT_KEY_AUTHORIZED,
    AGENT_KEY_REVOKED,
    AGENT_KEY_ROTATED,
    AGENT_PAUSE,
    AGENT_PROTOCOL_SESSION_RESULT,
    AGENT_PROTOCOL_SESSION_START,
    AGENT_PROTOCOL_SESSION_STATUS,
    AGENT_RESUME,
    APPLET_BRIDGE_ERROR,
    APPLET_DISCOVERY,
    APPLET_PROTOCOL_SESSION_START,
    APPLET_PROTOCOL_SESSION_STATUS,
    APPLET_REGISTRATION,
    ATTESTATION_RANGE_COMPLETENESS,
    AUDIT_ACCESSED,
    AUDIT_EPOCH_KEY_DESTRUCTION,
    AUDIT_ERASURE_RECEIPT,
    AUDIT_RYW_RECEIPT,
    CALL_RECORDING_START,
    CALL_SIGNAL,
    CALL_STATE,
    CAPABILITY_DELEGATE,
    CAPABILITY_DERIVED,
    CAPABILITY_GRANT,
    CAPABILITY_REVOKE,
    CIRCLE_ANCHOR_COMMIT,
    CIRCLE_ARCHIVE,
    CIRCLE_CREATE,
    CIRCLE_MEMBER_STATE,
    CIRCLE_RESTORE,
    CIRCLE_TOMBSTONE,
    CIRCLE_UPDATE,
    CONSENT_GRANT,
    CONSENT_REVOKE,
    CONTAINER_MOVE_ITEM,
    CONTAINER_REBALANCE,
    CROSS_SIGNING_PUBLISH,
    CROSS_SIGNING_RESET,
    DEVICE_AUTHORIZED,
    DEVICE_LIST_UPDATE,
    DEVICE_PUSH_ROUTE,
    DEVICE_REVOKED,
    DID_PROOF,
    FLOW_ARCHIVE,
    FLOW_CREATE,
    FLOW_MOVE,
    FLOW_REORDER,
    FLOW_RESTORE,
    FLOW_STAGE_SET,
    FLOW_TRACKS_UPDATE,
    FLOW_UPDATE,
    FLOW_WATCH_SET,
    HANDLE_DISCOVERY,
    IDENTITY_ACCOUNTABILITY_GRANT,
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
    MEMBER_IDENTITY_UPDATE,
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
    MODERATION_APPEAL_CLOSE,
    MODERATION_APPEAL_DECISION,
    MODERATION_APPEAL_REVIEW,
    MODERATION_APPEAL_SUBMIT,
    MODERATION_DECISION,
    MODERATION_DECISION_LIFT,
    MODERATION_FRANK,
    MODERATION_REPORT,
    MORPH_ARCHIVE,
    MORPH_CREATE,
    MORPH_RESTORE,
    MORPH_SCHEMA_MIGRATE,
    MORPH_STAGE_SET,
    MORPH_UPDATE,
    ORGANIZATION_DISCOVERY,
    ORGANIZATION_MODERATION_POLICY,
    POLICY_ACTION,
    POLICY_RULE,
    POLICY_SET,
    PRESENCE,
    PROFILE_CREATE,
    PROFILE_REALM_OVERRIDE,
    PROFILE_UPDATE,
    REACTION_ADD,
    REACTION_REMOVE,
    READ_MARKER,
    REALM_ARCHIVE,
    REALM_ASSET_PRIVACY_POLICY,
    REALM_AUDIT_POLICY_DOWNGRADE,
    REALM_CREATE,
    REALM_DELIVERY_BINDING_POLICY,
    REALM_DESTROY,
    REALM_DISCOVERY,
    REALM_FREEZE,
    REALM_HISTORY_SHARING_POLICY,
    REALM_HISTORY_VISIBILITY,
    REALM_INHERITANCE_POLICY,
    REALM_JOIN_RULE,
    REALM_LINK,
    REALM_MEDIA_SERVICE,
    REALM_MODERATION_POLICY,
    REALM_ORGANIZATION,
    REALM_PLAINTEXT_VISIBLE_SERVICES,
    REALM_POLICY,
    REALM_POLICY_COMPONENTS,
    REALM_POLICY_SERVER,
    REALM_PREVIEW_POLICY,
    REALM_READ_RECEIPT_POLICY,
    REALM_SCHEMA,
    REALM_TOMBSTONE,
    REALM_UPDATE,
    REALM_UPGRADE,
    REALM_KEY_SHARE,
    REALM_KEY_SHARE_AUDIT,
    REALM_KEY_WITHHELD,
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
    SPACE_CREATE,
    SPACE_PARENT,
    SPACE_RESTORE,
    SPACE_TOMBSTONE,
    SPACE_UPDATE,
    TYPING,
    VIEW_CREATE,
    VIEW_RECONCILE,
    VIEW_UPDATE,
];

pub const NON_REDUCER_EVENT_KINDS: &[&str] = &[
    ACCOUNT_BLOCKLIST,
    ACCOUNT_DATA_SET,
    AGENT_ACTION_APPROVE,
    AGENT_ACTION_REJECT,
    AGENT_ACTION_REQUEST,
    AGENT_DRAFT_PROPOSE,
    ATTESTATION_RANGE_COMPLETENESS,
    AUDIT_ERASURE_RECEIPT,
    AUDIT_RYW_RECEIPT,
    CALL_SIGNAL,
    // CKP-0007: ck.circle.anchor_commit is reducer-derived (sub-anchor
    // commit emitted by the reducer on the Circle's profile cadence);
    // it is NOT a reducer-input event.
    CIRCLE_ANCHOR_COMMIT,
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
        ACCOUNT_BLOCKLIST | ACCOUNT_DATA_SET | AGENT_ACTION_APPROVE | AGENT_ACTION_REJECT
        | AGENT_ACTION_REQUEST | AGENT_DRAFT_PROPOSE | DEVICE_PUSH_ROUTE | READ_MARKER => {
            EventWireScope::ActorPrivateEvent
        }
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
    /// CKP-0007 (spec b7d35be) — Circle lifecycle / membership events.
    Circle,
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
    Policy,
    Profile,
    Read,
    Realm,
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
        AGENT_ACTION_APPROVE
        | AGENT_ACTION_REJECT
        | AGENT_ACTION_REQUEST
        | AGENT_DEACTIVATE
        | AGENT_DRAFT_PROPOSE
        | AGENT_ENDPOINT
        | AGENT_KEY_AUTHORIZED
        | AGENT_KEY_REVOKED
        | AGENT_KEY_ROTATED
        | AGENT_PAUSE
        | AGENT_PROTOCOL_SESSION_RESULT
        | AGENT_PROTOCOL_SESSION_START
        | AGENT_PROTOCOL_SESSION_STATUS
        | AGENT_RESUME => EventClass::Agent,
        APPLET_BRIDGE_ERROR
        | APPLET_DISCOVERY
        | APPLET_PROTOCOL_SESSION_START
        | APPLET_PROTOCOL_SESSION_STATUS
        | APPLET_REGISTRATION => EventClass::Applet,
        ATTESTATION_RANGE_COMPLETENESS
        | AUDIT_ACCESSED
        | AUDIT_EPOCH_KEY_DESTRUCTION
        | AUDIT_ERASURE_RECEIPT
        | AUDIT_RYW_RECEIPT
        | REALM_AUDIT_POLICY_DOWNGRADE => EventClass::Audit,
        CAPABILITY_DELEGATE | CAPABILITY_DERIVED | CAPABILITY_GRANT | CAPABILITY_REVOKE
        | SESSION_GRANT => EventClass::Authz,
        CALL_RECORDING_START | CALL_SIGNAL | CALL_STATE => EventClass::Call,
        CIRCLE_CREATE | CIRCLE_UPDATE | CIRCLE_ARCHIVE | CIRCLE_RESTORE | CIRCLE_TOMBSTONE
        | CIRCLE_MEMBER_STATE | CIRCLE_ANCHOR_COMMIT => EventClass::Circle,
        CONSENT_GRANT | CONSENT_REVOKE => EventClass::Consent,
        DEVICE_AUTHORIZED
        | CROSS_SIGNING_PUBLISH
        | CROSS_SIGNING_RESET
        | DEVICE_LIST_UPDATE
        | DEVICE_PUSH_ROUTE
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
        | REALM_KEY_SHARE
        | REALM_KEY_SHARE_AUDIT
        | REALM_KEY_WITHHELD => EventClass::E2ee,
        FLOW_ARCHIVE | FLOW_CREATE | FLOW_MOVE | FLOW_REORDER | FLOW_RESTORE | FLOW_STAGE_SET
        | FLOW_TRACKS_UPDATE | FLOW_UPDATE | FLOW_WATCH_SET => EventClass::Flow,
        HANDLE_DISCOVERY => EventClass::Handle,
        DID_PROOF
        | IDENTITY_ACCOUNTABILITY_GRANT
        | IDENTITY_DISCLOSURE_POLICY
        | IDENTITY_DISCLOSURE_RECEIPT
        | IDENTITY_PRESENTATION_REQUEST
        | IDENTITY_PRESENTATION_RESPONSE => EventClass::Identity,
        INVITE_ACCEPT | INVITE_CANCEL | INVITE_CLAIM | INVITE_CREATE | INVITE_REVOKE
        | INVITE_THIRD_PARTY => EventClass::Invite,
        MEMBER_IDENTITY_UPDATE | MEMBER_STATE => EventClass::Membership,
        MESSAGE_CREATE | MESSAGE_REDACT | MESSAGE_REVISE | REACTION_ADD | REACTION_REMOVE
        | REDACTION => EventClass::Message,
        MIMI_ROOM_BINDING => EventClass::Mimi,
        MODERATION_APPEAL_CLOSE
        | MODERATION_APPEAL_DECISION
        | MODERATION_APPEAL_REVIEW
        | MODERATION_APPEAL_SUBMIT
        | MODERATION_DECISION
        | MODERATION_DECISION_LIFT
        | MODERATION_FRANK
        | MODERATION_REPORT => EventClass::Moderation,
        MORPH_ARCHIVE | MORPH_CREATE | MORPH_RESTORE | MORPH_SCHEMA_MIGRATE | MORPH_STAGE_SET
        | MORPH_UPDATE => EventClass::Morph,
        ORGANIZATION_DISCOVERY | ORGANIZATION_MODERATION_POLICY => EventClass::Organization,
        POLICY_ACTION | POLICY_RULE | POLICY_SET => EventClass::Policy,
        PROFILE_CREATE | PROFILE_REALM_OVERRIDE | PROFILE_UPDATE => EventClass::Profile,
        READ_MARKER | RECEIPT_READ => EventClass::Read,
        REALM_ARCHIVE
        | REALM_ASSET_PRIVACY_POLICY
        | REALM_CREATE
        | REALM_DELIVERY_BINDING_POLICY
        | REALM_DESTROY
        | REALM_DISCOVERY
        | REALM_FREEZE
        | REALM_HISTORY_SHARING_POLICY
        | REALM_HISTORY_VISIBILITY
        | REALM_INHERITANCE_POLICY
        | REALM_JOIN_RULE
        | REALM_LINK
        | REALM_MEDIA_SERVICE
        | REALM_MODERATION_POLICY
        | REALM_ORGANIZATION
        | REALM_PLAINTEXT_VISIBLE_SERVICES
        | REALM_POLICY
        | REALM_POLICY_COMPONENTS
        | REALM_POLICY_SERVER
        | REALM_PREVIEW_POLICY
        | REALM_READ_RECEIPT_POLICY
        | REALM_SCHEMA
        | REALM_TOMBSTONE
        | REALM_UPDATE
        | REALM_UPGRADE => EventClass::Realm,
        CONTAINER_MOVE_ITEM | CONTAINER_REBALANCE | RELATION_CREATE | RELATION_DELETE
        | RELATION_UPDATE => EventClass::Relation,
        SCHEMA_DEFINE | SCHEMA_UPDATE => EventClass::Schema,
        SOVEREIGN_DID_POLICY => EventClass::Sovereign,
        SPACE_ARCHIVE | SPACE_CREATE | SPACE_PARENT | SPACE_RESTORE | SPACE_TOMBSTONE
        | SPACE_UPDATE => EventClass::Space,
        VIEW_CREATE | VIEW_RECONCILE | VIEW_UPDATE => EventClass::View,
        _ => EventClass::Custom(kind.to_owned()),
    }
}

// ── Typed `EventKind` wrapper ──────────────────────────────────────────
//
// Lightweight newtype over a known event-kind string. Callers can
// construct one only via [`EventKind::try_new`] (validated against
// [`STANDARD_EVENT_KINDS`]) or from one of the `pub const *` strings via
// [`EventKind::from_const`]; this keeps the wire form a `&'static str`
// and avoids the maintenance overhead of an exhaustive 155-variant
// enum while still giving function signatures a type-safe alternative
// to bare `&str`.

/// Validated wrapper around one of the canonical `ck.*` event kinds.
///
/// Use [`EventKind::try_new`] to parse an untrusted wire string, or
/// [`EventKind::from_const`] when you have one of the `pub const *`
/// kinds in scope (e.g. `EventKind::from_const(MESSAGE_CREATE)`).
/// Both routes guarantee `as_str()` returns a member of
/// [`STANDARD_EVENT_KINDS`].
///
/// Serialises / deserialises as the bare wire string, with the same
/// membership check on the deserialise path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EventKind(&'static str);

impl EventKind {
    /// Parse an untrusted wire string into an [`EventKind`]. Returns
    /// `None` if the value is not in [`STANDARD_EVENT_KINDS`]. Custom /
    /// vendor kinds are deliberately *not* accepted here — they belong
    /// in plain `String` fields, with [`is_standard_event_kind`] +
    /// [`classify_event_kind`] for routing.
    pub fn try_new(kind: &str) -> Option<Self> {
        STANDARD_EVENT_KINDS.iter().copied().find(|k| *k == kind).map(EventKind)
    }

    /// Convenience constructor from one of the `pub const *: &str`
    /// declarations in this module. Same membership check as
    /// [`Self::try_new`] but accepts `&'static str` directly so the result
    /// can be stored in `const` contexts that consume the wire string
    /// via `.as_str()`.
    pub fn from_const(kind: &'static str) -> Option<Self> {
        Self::try_new(kind)
    }

    /// Canonical wire-form string. Always a member of
    /// [`STANDARD_EVENT_KINDS`].
    pub const fn as_str(&self) -> &'static str {
        self.0
    }

    /// Class for routing / indexing.
    pub fn class(&self) -> EventClass {
        classify_event_kind(self.0)
    }

    /// Wire scope (durable / actor-private / ephemeral).
    pub fn wire_scope(&self) -> EventWireScope {
        event_wire_scope(self.0)
    }

    /// Whether this kind is a reducer-input event (the wire scope is
    /// `durable_event` and the kind is not in `NON_REDUCER_EVENT_KINDS`).
    pub fn is_reducer_input(&self) -> bool {
        is_reducer_input_event_kind(self.0)
    }
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl Serialize for EventKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0)
    }
}

impl<'de> Deserialize<'de> for EventKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let raw = String::deserialize(deserializer)?;
        Self::try_new(&raw).ok_or_else(|| {
            D::Error::custom(format!(
                "unknown Cokret event kind {raw:?} — not in STANDARD_EVENT_KINDS"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_active_spec_event_kinds() {
        assert!(is_standard_event_kind(MESSAGE_CREATE));
        assert_eq!(classify_event_kind(MESSAGE_CREATE), EventClass::Message);
        assert_eq!(classify_event_kind(REALM_CREATE), EventClass::Realm);
        assert_eq!(classify_event_kind(SPACE_CREATE), EventClass::Space);
        assert_eq!(classify_event_kind(AGENT_PROTOCOL_SESSION_STATUS), EventClass::Agent);
        assert_eq!(classify_event_kind(CALL_SIGNAL), EventClass::Call);
        assert_eq!(
            classify_event_kind("vendor.example.widget"),
            EventClass::Custom("vendor.example.widget".to_owned())
        );
    }

    #[test]
    fn event_kind_from_const_round_trips() {
        let kind = EventKind::from_const(MESSAGE_CREATE).expect("MESSAGE_CREATE is standard");
        assert_eq!(kind.as_str(), MESSAGE_CREATE);
        assert_eq!(kind.class(), EventClass::Message);
        assert!(kind.is_reducer_input());
    }

    #[test]
    fn event_kind_try_new_rejects_vendor_kinds() {
        assert!(EventKind::try_new(MESSAGE_CREATE).is_some());
        assert!(EventKind::try_new("vendor.example.widget").is_none());
        assert!(EventKind::try_new("").is_none());
    }

    #[test]
    fn event_kind_serde_round_trips() {
        let kind = EventKind::try_new(MESSAGE_CREATE).unwrap();
        let json_text = serde_json::to_string(&kind).unwrap();
        assert_eq!(json_text, format!(r#""{MESSAGE_CREATE}""#));
        let parsed: EventKind = serde_json::from_str(&json_text).unwrap();
        assert_eq!(parsed, kind);
    }

    #[test]
    fn event_kind_deserialise_rejects_unknown() {
        let err = serde_json::from_str::<EventKind>(r#""vendor.example.widget""#).unwrap_err();
        assert!(err.to_string().contains("unknown Cokret event kind"));
    }

    #[test]
    fn event_kind_wire_scope_matches_helper() {
        let presence = EventKind::try_new(PRESENCE).unwrap();
        assert_eq!(presence.wire_scope(), EventWireScope::EphemeralEvent);
        let create = EventKind::try_new(MESSAGE_CREATE).unwrap();
        assert_eq!(create.wire_scope(), EventWireScope::DurableEvent);
    }

    #[test]
    fn standard_event_kind_tables_are_binary_searchable() {
        assert!(
            STANDARD_EVENT_KINDS.windows(2).all(|pair| pair[0] < pair[1]),
            "STANDARD_EVENT_KINDS must stay sorted by wire string"
        );
        assert!(
            NON_REDUCER_EVENT_KINDS.windows(2).all(|pair| pair[0] < pair[1]),
            "NON_REDUCER_EVENT_KINDS must stay sorted by wire string"
        );
    }
}
