use serde::{Deserialize, Serialize};

pub const ACCOUNT_BLOCKLIST: &str = "ak.account.blocklist";
pub const ACCOUNT_STATUS: &str = "ak.account.status";
pub const ACCOUNT_DATA_SET: &str = "ak.account_data.set";
pub const ACTOR_DISCOVERY: &str = "ak.actor.discovery";
pub const AGENT_ENDPOINT: &str = "ak.agent.endpoint";
pub const AGENT_KEY_AUTHORIZE: &str = "ak.agent.key.authorize";
pub const AGENT_KEY_REVOKE: &str = "ak.agent.key.revoke";
pub const AGENT_KEY_ROTATE: &str = "ak.agent.key.rotate";
pub const AGENT_KEY_AUTHORIZED: &str = AGENT_KEY_AUTHORIZE;
pub const AGENT_KEY_REVOKED: &str = AGENT_KEY_REVOKE;
pub const AGENT_KEY_ROTATED: &str = AGENT_KEY_ROTATE;
// CKP-0008 / CKP-0009 (spec head 37ce729) — personal-agent lifecycle event
// kinds (durable, reducer-input).
pub const AGENT_PAUSE: &str = "ak.self.agent.pause";
pub const AGENT_RESUME: &str = "ak.self.agent.resume";
pub const AGENT_DEACTIVATE: &str = "ak.self.agent.deactivate";
// CKP-0008 / CKP-0009 — agent action / draft event kinds (actor_private).
pub const AGENT_DRAFT_PROPOSE: &str = "ak.agent.draft.propose";
pub const AGENT_ACTION_REQUEST: &str = "ak.agent.action_request";
pub const AGENT_ACTION_APPROVE: &str = "ak.agent.action_approve";
pub const AGENT_ACTION_REJECT: &str = "ak.agent.action_reject";
pub const AGENT_INTEROP_SESSION_RESULT: &str = "ak.agent.interop_session.result";
pub const AGENT_INTEROP_SESSION_START: &str = "ak.agent.interop_session.start";
pub const AGENT_INTEROP_SESSION_STATUS: &str = "ak.agent.interop_session.status";
pub const APPLET_BRIDGE_ERROR: &str = "ak.applet.bridge_error";
pub const APPLET_DISCOVERY: &str = "ak.applet.discovery";
pub const APPLET_INTEROP_SESSION_START: &str = "ak.applet.interop_session.start";
pub const APPLET_INTEROP_SESSION_STATUS: &str = "ak.applet.interop_session.status";
pub const APPLET_REGISTRATION: &str = "ak.applet.registration";
pub const ATTESTATION_RANGE_COMPLETENESS: &str = "ak.attestation.range_completeness";
pub const AUDIT_ACCESSED: &str = "ak.audit.accessed";
// Audit release session model (spec @ 2026-06-04): audit applets bind via
// ak.audit.applet_binding and stage sealed historical releases through the
// session lifecycle (request/authorize/notice/release/close). Replaces the
// retired standing audit-member events ak.audit.epoch_key_destruction and
// ak.realm.audit_policy_downgrade.
pub const AUDIT_APPLET_BINDING: &str = "ak.audit.applet_binding";
pub const AUDIT_ERASURE_RECEIPT: &str = "ak.audit.erasure_receipt";
pub const AUDIT_RELEASE: &str = "ak.audit.release";
pub const AUDIT_RYW_RECEIPT: &str = "ak.audit.ryw_receipt";
pub const AUDIT_SESSION_AUTHORIZE: &str = "ak.audit.session.authorize";
pub const AUDIT_SESSION_CLOSE: &str = "ak.audit.session.close";
pub const AUDIT_SESSION_NOTICE: &str = "ak.audit.session.notice";
pub const AUDIT_SESSION_REQUEST: &str = "ak.audit.session.request";
pub const CALL_RECORDING_START: &str = "ak.call.recording.start";
pub const CALL_SIGNAL: &str = "ak.call.signal";
pub const CALL_STATE: &str = "ak.call.state";
pub const CALL_SUMMARY: &str = "ak.call.summary";
pub const CAPABILITY_DELEGATE: &str = "ak.capability.delegate";
pub const CAPABILITY_DERIVED: &str = "ak.capability.derived";
pub const CAPABILITY_GRANT: &str = "ak.capability.grant";
pub const CAPABILITY_REVOKE: &str = "ak.capability.revoke";
// CKP-0007 (spec b7d35be) — Circle primitive event kinds. 7 active kinds
// registered in `event-kind-registry.json` v2026-05-08.
pub const CIRCLE_CREATE: &str = "ak.circle.create";
pub const CIRCLE_UPDATE: &str = "ak.circle.update";
pub const CIRCLE_ARCHIVE: &str = "ak.circle.archive";
pub const CIRCLE_RESTORE: &str = "ak.circle.restore";
pub const CIRCLE_TOMBSTONE: &str = "ak.circle.tombstone";
pub const CIRCLE_MEMBER_STATE: &str = "ak.circle.member.state";
pub const CIRCLE_SEAL_COMMIT: &str = "ak.circle.seal_commit";
pub const CONSENT_GRANT: &str = "ak.consent.grant";
pub const CONSENT_REVOKE: &str = "ak.consent.revoke";
// CKP-0015 contact enhancement — durable, reducer-input contact-request
// lifecycle and the direct-conversation Realm binding it produces.
pub const CONTACT_ACCEPTED: &str = "ak.contact.accepted";
pub const CONTACT_REJECTED: &str = "ak.contact.rejected";
pub const CONTACT_REQUESTED: &str = "ak.contact.requested";
pub const CONTACT_TOMBSTONED: &str = "ak.contact.tombstoned";
pub const CONTAINER_MOVE_ITEM: &str = "ak.container.move_item";
pub const CONTAINER_REBALANCE: &str = "ak.container.rebalance";
pub const CROSS_SIGNING_PUBLISH: &str = "ak.cross_signing.publish";
pub const CROSS_SIGNING_RESET: &str = "ak.cross_signing.reset";
pub const DEVICE_AUTHORIZE: &str = "ak.device.authorize";
pub const DEVICE_AUTHORIZED: &str = DEVICE_AUTHORIZE;
pub const DEVICE_LIST_UPDATE: &str = "ak.device.list_update";
pub const DEVICE_PUSH_ROUTE: &str = "ak.device.push_route";
pub const DEVICE_REVOKE: &str = "ak.device.revoke";
pub const DEVICE_REVOKED: &str = DEVICE_REVOKE;
pub const DID_PROOF: &str = "ak.did.proof";
// CKP-0015 contact enhancement — direct-conversation Realm binding emitted
// when a contact request is accepted (category `contact`).
pub const DIRECT_CONVERSATION_BOUND: &str = "ak.direct_conversation.bound";
pub const STRAND_ARCHIVE: &str = "ak.strand.archive";
pub const STRAND_CREATE: &str = "ak.strand.create";
pub const STRAND_MOVE: &str = "ak.strand.move";
pub const STRAND_REORDER: &str = "ak.strand.reorder";
pub const STRAND_RESTORE: &str = "ak.strand.restore";
pub const STRAND_STAGE_SET: &str = "ak.strand.stage.set";
pub const STRAND_TRACKS_UPDATE: &str = "ak.strand.tracks.update";
pub const STRAND_UPDATE: &str = "ak.strand.update";
pub const STRAND_WATCH_SET: &str = "ak.strand.watch.set";
pub const HANDLE_DISCOVERY: &str = "ak.handle.discovery";
pub const IDENTITY_ACCOUNTABILITY_GRANT: &str = "ak.identity.accountability_grant";
pub const IDENTITY_DISCLOSURE_POLICY: &str = "ak.identity.disclosure_policy";
pub const IDENTITY_DISCLOSURE_RECEIPT: &str = "ak.identity.disclosure_receipt";
pub const IDENTITY_PRESENTATION_REQUEST: &str = "ak.identity.presentation_request";
pub const IDENTITY_PRESENTATION_RESPONSE: &str = "ak.identity.presentation_response";
pub const INVITE_ACCEPT: &str = "ak.invite.accept";
pub const INVITE_CANCEL: &str = "ak.invite.cancel";
pub const INVITE_CLAIM: &str = "ak.invite.claim";
pub const INVITE_CREATE: &str = "ak.invite.create";
pub const INVITE_REVOKE: &str = "ak.invite.revoke";
pub const INVITE_THIRD_PARTY: &str = "ak.invite.third_party";
// Key-backup active-series pointer (durable, reducer-input; category `device`).
pub const KEY_BACKUP_ACTIVE_SERIES: &str = "ak.key_backup.active_series";
pub const KEY_VERIFICATION_ACCEPT: &str = "ak.key.verification.accept";
pub const KEY_VERIFICATION_CANCEL: &str = "ak.key.verification.cancel";
pub const KEY_VERIFICATION_DONE: &str = "ak.key.verification.done";
pub const KEY_VERIFICATION_KEY: &str = "ak.key.verification.key";
pub const KEY_VERIFICATION_MAC: &str = "ak.key.verification.mac";
pub const KEY_VERIFICATION_READY: &str = "ak.key.verification.ready";
pub const KEY_VERIFICATION_REQUEST: &str = "ak.key.verification.request";
pub const KEY_VERIFICATION_START: &str = "ak.key.verification.start";
pub const MEMBER_IDENTITY_UPDATE: &str = "ak.member.identity.update";
pub const MEMBER_STATE: &str = "ak.member.state";
pub const MESSAGE_CREATE: &str = "ak.message.create";
pub const MESSAGE_REDACT: &str = "ak.message.redact";
pub const MESSAGE_REVISE: &str = "ak.message.revise";
pub const MIMI_ROOM_BINDING: &str = "ak.mimi.room_binding";
pub const MLS_COMMIT: &str = "ak.mls.commit";
pub const MLS_COMMIT_FAILED: &str = "ak.mls.commit_failed";
pub const MLS_GENESIS: &str = "ak.mls.genesis";
pub const MLS_KEYPACKAGE: &str = "ak.mls.keypackage";
pub const MLS_PROPOSAL: &str = "ak.mls.proposal";
pub const MLS_WELCOME: &str = "ak.mls.welcome";
pub const MODERATION_APPEAL_CLOSE: &str = "ak.moderation.appeal.close";
pub const MODERATION_APPEAL_DECISION: &str = "ak.moderation.appeal.decision";
pub const MODERATION_APPEAL_REVIEW: &str = "ak.moderation.appeal.review";
pub const MODERATION_APPEAL_SUBMIT: &str = "ak.moderation.appeal.submit";
pub const MODERATION_DECISION: &str = "ak.moderation.decision";
pub const MODERATION_DECISION_LIFT: &str = "ak.moderation.decision.lift";
pub const MODERATION_FRANKING_PROOF: &str = "ak.moderation.franking_proof";
pub const MODERATION_FRANK: &str = MODERATION_FRANKING_PROOF;
pub const MODERATION_REPORT: &str = "ak.self.moderation.report";
pub const NOTARY_FAULT_CENSORSHIP: &str = "ak.notary.fault.censorship";
pub const NOTARY_FAULT_EQUIVOCATION: &str = "ak.notary.fault.equivocation";

/// Object-only schema id — `ak.event_batch_receipt` is NOT an Event.kind.
/// Returns `true` for kinds that may only appear as a separate object,
/// MUST NOT appear as `Event.kind` on the wire. Round R2/R3 (2026-05-20).
pub const RECEIPT_OBJECT_KINDS: &[&str] = &["ak.event_batch_receipt"];

/// Broadcast ephemeral signal kinds + the to-device key-verification family.
/// Round R2/R3 (2026-05-20). Items here MUST NOT be reduced into durable
/// state, MUST NOT advance Seal frontier or Move state_root, MUST NOT
/// carry preconditions/effects/seal_ref, and MUST NOT be submitted via
/// `ak.self.events.command.submit`. See zh/sync/operations-sync.md §3.6 and
/// schemas/ephemeral-envelope.schema.json (the 4 broadcast forms) and
/// schemas/device-message.schema.json (the to-device key.verification forms).
pub const EPHEMERAL_EVENT_KIND_PATTERNS: &[&str] = &[
    CALL_SIGNAL,
    PRESENCE,
    TYPING,
    RECEIPT_READ,
    // ak.key.verification.* — point-to-point to-device family.
    KEY_VERIFICATION_ACCEPT,
    KEY_VERIFICATION_CANCEL,
    KEY_VERIFICATION_DONE,
    KEY_VERIFICATION_KEY,
    KEY_VERIFICATION_MAC,
    KEY_VERIFICATION_READY,
    KEY_VERIFICATION_REQUEST,
    KEY_VERIFICATION_START,
    SECRET_REQUEST,
    SECRET_SEND,
    // ak.realm_key.request — point-to-point to-device history-key request,
    // relayed to the target source (device-lifecycle.md §13.2); ephemeral,
    // never a reducer-input durable event.
    REALM_KEY_REQUEST,
];

/// True for the wire-scope-ephemeral kinds — broadcast ephemerals
/// (`ak.call.signal`, `ak.presence`, `ak.typing`, `ak.receipt.read`) plus
/// the to-device key-verification and secret-share families. These MUST be rejected by
/// reducers if delivered as a durable Event (event-envelope.schema.json `not` branch).
pub fn is_ephemeral_kind(kind: &str) -> bool {
    if kind.starts_with("ak.key.verification.") {
        return true;
    }
    EPHEMERAL_EVENT_KIND_PATTERNS.contains(&kind)
}

/// True for receipt-style object-only schema ids that MUST NOT appear as
/// `Event.kind` on the wire (`ak.event_batch_receipt`). Round R2/R3.
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
/// R3.1 adds `ak.member.identity.update` →
/// `event-payload.schema.json#/$defs/member_identity_update_payload`.
pub fn event_payload_schema_ref(kind: &str) -> Option<&'static str> {
    match kind {
        MEMBER_IDENTITY_UPDATE => {
            Some("event-payload.schema.json#/$defs/member_identity_update_payload")
        }
        PIN_ADD => Some("event-payload.schema.json#/$defs/pin_add_payload"),
        PIN_REMOVE => Some("event-payload.schema.json#/$defs/pin_remove_payload"),
        PIN_REORDER => Some("event-payload.schema.json#/$defs/pin_reorder_payload"),
        REALM_DISAPPEARING_POLICY => {
            Some("event-payload.schema.json#/$defs/realm_disappearing_policy_payload")
        }
        REALM_SEARCH_POLICY => Some("event-payload.schema.json#/$defs/realm_search_policy_payload"),
        RSVP_SET => Some("event-payload.schema.json#/$defs/rsvp_set_payload"),
        _ => None,
    }
}

/// Round R2/R3 (2026-05-20) — Realm lifecycle state classifier.
///
/// Returned by [`is_terminal_realm_state`]. After a Realm has emitted
/// `ak.realm.destroy`, no further state-changing events MUST be accepted
/// (rejected as `realm_terminal_state`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmLifecycleState {
    Active,
    Frozen,
    Archived,
    Tombstoned,
    /// `ak.realm.destroy` has been applied. Terminal.
    Destroyed,
}

/// Round R2/R3 — true once the Realm has reached the destroyed terminal
/// state (`ak.realm.destroy` applied). Any subsequent state-changing
/// event MUST be rejected as `ERROR_CODE_REALM_TERMINAL_STATE`.
pub fn is_terminal_realm_state(state: RealmLifecycleState) -> bool {
    matches!(state, RealmLifecycleState::Destroyed)
}
pub const MORPH_ARCHIVE: &str = "ak.morph.archive";
pub const MORPH_CREATE: &str = "ak.morph.create";
pub const MORPH_RESTORE: &str = "ak.morph.restore";
pub const MORPH_SCHEMA_MIGRATE: &str = "ak.morph.schema_migrate";
pub const MORPH_STAGE_SET: &str = "ak.morph.stage.set";
pub const MORPH_UPDATE: &str = "ak.morph.update";
pub const ORGANIZATION_DISCOVERY: &str = "ak.organization.discovery";
pub const ORGANIZATION_MODERATION_POLICY: &str = "ak.organization.moderation_policy";
pub const PIN_ADD: &str = "ak.pin.add";
pub const PIN_REMOVE: &str = "ak.pin.remove";
pub const PIN_REORDER: &str = "ak.pin.reorder";
// Realm event kinds (security boundary).
// Top-level governance of the security boundary lives here.
pub const REALM_ARCHIVE: &str = "ak.realm.archive";
pub const REALM_ASSET_PRIVACY_POLICY: &str = "ak.realm.asset_privacy_policy";
pub const REALM_CREATE: &str = "ak.realm.create";
pub const REALM_DELIVERY_BINDING_POLICY: &str = "ak.realm.delivery_binding_policy";
pub const REALM_DISAPPEARING_POLICY: &str = "ak.realm.disappearing_policy";
pub const REALM_DESTROY: &str = "ak.realm.destroy";
pub const REALM_DISCOVERY: &str = "ak.realm.discovery";
pub const REALM_FREEZE: &str = "ak.realm.freeze";
pub const REALM_HISTORY_SHARING_POLICY: &str = "ak.realm.history_sharing_policy";
pub const REALM_HISTORY_VISIBILITY: &str = "ak.realm.history_visibility";
pub const REALM_INHERITANCE_POLICY: &str = "ak.realm.inheritance_policy";
pub const REALM_KEY_REQUEST: &str = "ak.realm_key.request";
pub const REALM_KEY_SHARE: &str = "ak.realm_key.share";
pub const REALM_KEY_SHARE_AUDIT: &str = "ak.realm_key.share_audit";
pub const REALM_KEY_WITHHELD: &str = "ak.realm_key.withheld";
pub const REALM_JOIN_RULE: &str = "ak.realm.join_rule";
pub const REALM_LINK: &str = "ak.realm.link";
pub const REALM_MEDIA_SERVICE: &str = "ak.realm.media_service";
pub const REALM_MODERATION_POLICY: &str = "ak.realm.moderation_policy";
pub const REALM_ORGANIZATION: &str = "ak.realm.organization";
pub const REALM_PLAINTEXT_VISIBLE_SERVICES: &str = "ak.realm.plaintext_visible_services";
pub const REALM_POLICY: &str = "ak.realm.policy";
pub const REALM_POLICY_COMPONENTS: &str = "ak.realm.policy_components";
pub const REALM_POLICY_SERVER: &str = "ak.realm.policy_server";
pub const REALM_PREVIEW_POLICY: &str = "ak.realm.preview_policy";
pub const REALM_READ_RECEIPT_POLICY: &str = "ak.realm.read_receipt_policy";
pub const REALM_SCHEMA: &str = "ak.realm.schema";
pub const REALM_SEARCH_POLICY: &str = "ak.realm.search_policy";
pub const REALM_SET_DEFAULT_STRAND: &str = "ak.realm.set_default_strand";
pub const REALM_TOMBSTONE: &str = "ak.realm.tombstone";
pub const REALM_UPDATE: &str = "ak.realm.update";
pub const REALM_UPGRADE: &str = "ak.realm.upgrade";
pub const POLICY_ACTION: &str = "ak.policy.action";
pub const POLICY_RULE: &str = "ak.policy.rule";
pub const POLICY_SET: &str = "ak.policy.set";
pub const PRESENCE: &str = "ak.presence";
pub const PROFILE_CREATE: &str = "ak.profile.create";
pub const PROFILE_REALM_OVERRIDE: &str = "ak.profile.realm_override";
pub const PROFILE_UPDATE: &str = "ak.profile.update";
pub const REACTION_ADD: &str = "ak.reaction.add";
pub const REACTION_REMOVE: &str = "ak.reaction.remove";
pub const READ_CURSOR_ADVANCE: &str = "ak.read_cursor.advance";
pub const READ_MARKER: &str = READ_CURSOR_ADVANCE;
pub const RECEIPT_READ: &str = "ak.receipt.read";
pub const REDACTION: &str = "ak.redaction";
pub const RELATION_CREATE: &str = "ak.relation.create";
pub const RELATION_TOMBSTONE: &str = "ak.relation.tombstone";
pub const RELATION_DELETE: &str = RELATION_TOMBSTONE;
pub const RELATION_UPDATE: &str = "ak.relation.update";
pub const RSVP_SET: &str = "ak.rsvp.set";
pub const SCHEMA_DEFINE: &str = "ak.schema.define";
pub const SCHEMA_UPDATE: &str = "ak.schema.update";
pub const SECRET_REQUEST: &str = "ak.secret.request";
pub const SECRET_SEND: &str = "ak.secret.send";
pub const SESSION_GRANT: &str = "ak.session.grant";
pub const SOVEREIGN_DID_POLICY: &str = "ak.sovereign.did_policy";
// Space event kinds (product container).
// Boards / lists / arbitrary nestable containers live here. Security
// policies are NOT in this family — see REALM_* above.
pub const SPACE_ARCHIVE: &str = "ak.space.archive";
pub const SPACE_CREATE: &str = "ak.space.create";
pub const SPACE_PARENT: &str = "ak.space.parent";
pub const SPACE_RESTORE: &str = "ak.space.restore";
pub const SPACE_TOMBSTONE: &str = "ak.space.tombstone";
pub const SPACE_UPDATE: &str = "ak.space.update";
pub const TYPING: &str = "ak.typing";
pub const VIEW_CREATE: &str = "ak.view.create";
pub const VIEW_RECONCILE: &str = "ak.view.reconcile";
pub const VIEW_UPDATE: &str = "ak.view.update";

pub const STANDARD_EVENT_KINDS: &[&str] = &[
    ACCOUNT_BLOCKLIST,
    ACCOUNT_STATUS,
    ACCOUNT_DATA_SET,
    ACTOR_DISCOVERY,
    AGENT_ACTION_APPROVE,
    AGENT_ACTION_REJECT,
    AGENT_ACTION_REQUEST,
    AGENT_DRAFT_PROPOSE,
    AGENT_ENDPOINT,
    AGENT_INTEROP_SESSION_RESULT,
    AGENT_INTEROP_SESSION_START,
    AGENT_INTEROP_SESSION_STATUS,
    AGENT_KEY_AUTHORIZED,
    AGENT_KEY_REVOKED,
    AGENT_KEY_ROTATED,
    APPLET_BRIDGE_ERROR,
    APPLET_DISCOVERY,
    APPLET_INTEROP_SESSION_START,
    APPLET_INTEROP_SESSION_STATUS,
    APPLET_REGISTRATION,
    ATTESTATION_RANGE_COMPLETENESS,
    AUDIT_ACCESSED,
    AUDIT_APPLET_BINDING,
    AUDIT_ERASURE_RECEIPT,
    AUDIT_RELEASE,
    AUDIT_RYW_RECEIPT,
    AUDIT_SESSION_AUTHORIZE,
    AUDIT_SESSION_CLOSE,
    AUDIT_SESSION_NOTICE,
    AUDIT_SESSION_REQUEST,
    CALL_RECORDING_START,
    CALL_SIGNAL,
    CALL_STATE,
    CALL_SUMMARY,
    CAPABILITY_DELEGATE,
    CAPABILITY_DERIVED,
    CAPABILITY_GRANT,
    CAPABILITY_REVOKE,
    CIRCLE_ARCHIVE,
    CIRCLE_CREATE,
    CIRCLE_MEMBER_STATE,
    CIRCLE_RESTORE,
    CIRCLE_SEAL_COMMIT,
    CIRCLE_TOMBSTONE,
    CIRCLE_UPDATE,
    CONSENT_GRANT,
    CONSENT_REVOKE,
    CONTACT_ACCEPTED,
    CONTACT_REJECTED,
    CONTACT_REQUESTED,
    CONTACT_TOMBSTONED,
    CONTAINER_MOVE_ITEM,
    CONTAINER_REBALANCE,
    CROSS_SIGNING_PUBLISH,
    CROSS_SIGNING_RESET,
    DEVICE_AUTHORIZED,
    DEVICE_LIST_UPDATE,
    DEVICE_PUSH_ROUTE,
    DEVICE_REVOKED,
    DID_PROOF,
    DIRECT_CONVERSATION_BOUND,
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
    KEY_BACKUP_ACTIVE_SERIES,
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
    MORPH_ARCHIVE,
    MORPH_CREATE,
    MORPH_RESTORE,
    MORPH_SCHEMA_MIGRATE,
    MORPH_STAGE_SET,
    MORPH_UPDATE,
    NOTARY_FAULT_CENSORSHIP,
    NOTARY_FAULT_EQUIVOCATION,
    ORGANIZATION_DISCOVERY,
    ORGANIZATION_MODERATION_POLICY,
    PIN_ADD,
    PIN_REMOVE,
    PIN_REORDER,
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
    REALM_CREATE,
    REALM_DELIVERY_BINDING_POLICY,
    REALM_DESTROY,
    REALM_DISAPPEARING_POLICY,
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
    REALM_SEARCH_POLICY,
    REALM_SET_DEFAULT_STRAND,
    REALM_TOMBSTONE,
    REALM_UPDATE,
    REALM_UPGRADE,
    REALM_KEY_REQUEST,
    REALM_KEY_SHARE,
    REALM_KEY_SHARE_AUDIT,
    REALM_KEY_WITHHELD,
    RECEIPT_READ,
    REDACTION,
    RELATION_CREATE,
    RELATION_DELETE,
    RELATION_UPDATE,
    RSVP_SET,
    SCHEMA_DEFINE,
    SCHEMA_UPDATE,
    SECRET_REQUEST,
    SECRET_SEND,
    AGENT_DEACTIVATE,
    AGENT_PAUSE,
    AGENT_RESUME,
    MODERATION_REPORT,
    SESSION_GRANT,
    SOVEREIGN_DID_POLICY,
    SPACE_ARCHIVE,
    SPACE_CREATE,
    SPACE_PARENT,
    SPACE_RESTORE,
    SPACE_TOMBSTONE,
    SPACE_UPDATE,
    STRAND_ARCHIVE,
    STRAND_CREATE,
    STRAND_MOVE,
    STRAND_REORDER,
    STRAND_RESTORE,
    STRAND_STAGE_SET,
    STRAND_TRACKS_UPDATE,
    STRAND_UPDATE,
    STRAND_WATCH_SET,
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
    // CKP-0007: ak.circle.seal_commit is reducer-derived (sub-seal
    // commit emitted by the reducer on the Circle's profile cadence);
    // it is NOT a reducer-input event.
    CIRCLE_SEAL_COMMIT,
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
    SECRET_REQUEST,
    SECRET_SEND,
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
    /// CKP-0015 contact enhancement — contact-request lifecycle and the
    /// direct-conversation Realm binding it produces.
    Contact,
    Device,
    E2ee,
    Strand,
    Handle,
    Identity,
    Invite,
    Membership,
    Message,
    Mimi,
    Moderation,
    Morph,
    Organization,
    Pin,
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
        | AGENT_INTEROP_SESSION_RESULT
        | AGENT_INTEROP_SESSION_START
        | AGENT_INTEROP_SESSION_STATUS
        | AGENT_RESUME => EventClass::Agent,
        APPLET_BRIDGE_ERROR
        | APPLET_DISCOVERY
        | APPLET_INTEROP_SESSION_START
        | APPLET_INTEROP_SESSION_STATUS
        | APPLET_REGISTRATION => EventClass::Applet,
        ATTESTATION_RANGE_COMPLETENESS
        | AUDIT_ACCESSED
        | AUDIT_APPLET_BINDING
        | AUDIT_ERASURE_RECEIPT
        | AUDIT_RELEASE
        | AUDIT_RYW_RECEIPT
        | AUDIT_SESSION_AUTHORIZE
        | AUDIT_SESSION_CLOSE
        | AUDIT_SESSION_NOTICE
        | AUDIT_SESSION_REQUEST => EventClass::Audit,
        CAPABILITY_DELEGATE | CAPABILITY_DERIVED | CAPABILITY_GRANT | CAPABILITY_REVOKE
        | SESSION_GRANT => EventClass::Authz,
        CALL_RECORDING_START | CALL_SIGNAL | CALL_STATE | CALL_SUMMARY => EventClass::Call,
        CIRCLE_CREATE | CIRCLE_UPDATE | CIRCLE_ARCHIVE | CIRCLE_RESTORE | CIRCLE_TOMBSTONE
        | CIRCLE_MEMBER_STATE | CIRCLE_SEAL_COMMIT => EventClass::Circle,
        CONSENT_GRANT | CONSENT_REVOKE => EventClass::Consent,
        CONTACT_REQUESTED
        | CONTACT_ACCEPTED
        | CONTACT_REJECTED
        | CONTACT_TOMBSTONED
        | DIRECT_CONVERSATION_BOUND => EventClass::Contact,
        DEVICE_AUTHORIZED
        | CROSS_SIGNING_PUBLISH
        | CROSS_SIGNING_RESET
        | DEVICE_LIST_UPDATE
        | DEVICE_PUSH_ROUTE
        | DEVICE_REVOKED
        | KEY_BACKUP_ACTIVE_SERIES
        | KEY_VERIFICATION_ACCEPT
        | KEY_VERIFICATION_CANCEL
        | KEY_VERIFICATION_DONE
        | KEY_VERIFICATION_KEY
        | KEY_VERIFICATION_MAC
        | KEY_VERIFICATION_READY
        | KEY_VERIFICATION_REQUEST
        | KEY_VERIFICATION_START
        | SECRET_REQUEST
        | SECRET_SEND => EventClass::Device,
        MLS_COMMIT
        | MLS_COMMIT_FAILED
        | MLS_GENESIS
        | MLS_KEYPACKAGE
        | MLS_PROPOSAL
        | MLS_WELCOME
        | REALM_KEY_REQUEST
        | REALM_KEY_SHARE
        | REALM_KEY_SHARE_AUDIT
        | REALM_KEY_WITHHELD => EventClass::E2ee,
        STRAND_ARCHIVE | STRAND_CREATE | STRAND_MOVE | STRAND_REORDER | STRAND_RESTORE
        | STRAND_STAGE_SET | STRAND_TRACKS_UPDATE | STRAND_UPDATE | STRAND_WATCH_SET => {
            EventClass::Strand
        }
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
        PIN_ADD | PIN_REMOVE | PIN_REORDER => EventClass::Pin,
        POLICY_ACTION | POLICY_RULE | POLICY_SET => EventClass::Policy,
        PROFILE_CREATE | PROFILE_REALM_OVERRIDE | PROFILE_UPDATE => EventClass::Profile,
        READ_MARKER | RECEIPT_READ => EventClass::Read,
        REALM_ARCHIVE
        | REALM_ASSET_PRIVACY_POLICY
        | REALM_CREATE
        | REALM_DELIVERY_BINDING_POLICY
        | REALM_DISAPPEARING_POLICY
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
        | REALM_SEARCH_POLICY
        | REALM_TOMBSTONE
        | REALM_UPDATE
        | REALM_UPGRADE
        | NOTARY_FAULT_CENSORSHIP
        | NOTARY_FAULT_EQUIVOCATION => EventClass::Realm,
        CONTAINER_MOVE_ITEM | CONTAINER_REBALANCE | RELATION_CREATE | RELATION_DELETE
        | RELATION_UPDATE => EventClass::Relation,
        RSVP_SET => EventClass::Strand,
        SCHEMA_DEFINE | SCHEMA_UPDATE => EventClass::Schema,
        SOVEREIGN_DID_POLICY => EventClass::Sovereign,
        SPACE_ARCHIVE | SPACE_CREATE | SPACE_PARENT | SPACE_RESTORE | SPACE_TOMBSTONE
        | SPACE_UPDATE => EventClass::Space,
        VIEW_CREATE | VIEW_RECONCILE | VIEW_UPDATE => EventClass::View,
        _ => EventClass::Custom(kind.to_owned()),
    }
}

pub fn is_audit_kind(kind: &str) -> bool {
    kind.starts_with("ak.audit.")
}

pub fn is_redaction_kind(kind: &str) -> bool {
    matches!(kind, MESSAGE_REDACT | REDACTION)
}

pub fn is_membership_kind(kind: &str) -> bool {
    matches!(classify_event_kind(kind), EventClass::Membership)
}

pub fn is_invite_kind(kind: &str) -> bool {
    matches!(classify_event_kind(kind), EventClass::Invite)
}

pub fn is_realm_lifecycle_kind(kind: &str) -> bool {
    matches!(
        kind,
        REALM_CREATE
            | REALM_UPDATE
            | REALM_ARCHIVE
            | REALM_FREEZE
            | REALM_DESTROY
            | REALM_TOMBSTONE
    )
}

pub fn is_pin_kind(kind: &str) -> bool {
    matches!(classify_event_kind(kind), EventClass::Pin)
}

pub fn is_space_lifecycle_kind(kind: &str) -> bool {
    matches!(kind, SPACE_ARCHIVE | SPACE_RESTORE | SPACE_TOMBSTONE)
}

pub fn is_strand_lifecycle_kind(kind: &str) -> bool {
    matches!(kind, STRAND_ARCHIVE | STRAND_RESTORE)
}

pub fn is_morph_lifecycle_kind(kind: &str) -> bool {
    matches!(kind, MORPH_ARCHIVE | MORPH_RESTORE)
}

pub fn is_strand_tracks_kind(kind: &str) -> bool {
    matches!(kind, STRAND_TRACKS_UPDATE)
}

// ── Typed `EventKind` ──────────────────────────────────────────────────
//
// The strongly-typed `EventKind` enum (one variant per active `ak.*` kind,
// plus an `Unknown(String)` forward-compat catch-all) is generated from
// `event-kind-registry.json` into `crate::generated::event_kinds`; see
// `tools/generate-sdk-event-kinds.ps1`. It is re-exported here so callers
// continue to reach it via `crate::events::kinds::EventKind`.
pub use crate::generated::event_kinds::{EVENT_KIND_COUNT, EventKind};

// Hand-written OpenAPI schema: `EventKind` serialises as the bare wire
// string, so expose it as a string schema carrying the registry kind
// pattern rather than a derive-from-variants object.
#[cfg(feature = "salvo")]
impl salvo::oapi::ToSchema for EventKind {
    fn to_schema(
        _components: &mut salvo::oapi::Components,
    ) -> salvo::oapi::RefOr<salvo::oapi::Schema> {
        salvo::oapi::Object::new()
            .schema_type(salvo::oapi::BasicType::String)
            .pattern(r"^ak\.[a-z0-9_]+(\.[a-z0-9_]+)*$")
            .into()
    }
}

#[cfg(feature = "salvo")]
impl salvo::oapi::ComposeSchema for EventKind {
    fn compose(
        components: &mut salvo::oapi::Components,
        _generics: Vec<salvo::oapi::RefOr<salvo::oapi::Schema>>,
    ) -> salvo::oapi::RefOr<salvo::oapi::Schema> {
        <Self as salvo::oapi::ToSchema>::to_schema(components)
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
        assert!(is_invite_kind(INVITE_CREATE));
        assert!(is_membership_kind(MEMBER_STATE));
        assert!(is_pin_kind(PIN_ADD));
        assert!(is_audit_kind(AUDIT_RYW_RECEIPT));
        assert!(is_redaction_kind(REDACTION));
        assert!(is_realm_lifecycle_kind(REALM_TOMBSTONE));
        assert!(is_space_lifecycle_kind(SPACE_ARCHIVE));
        assert!(is_strand_lifecycle_kind(STRAND_ARCHIVE));
        assert!(is_morph_lifecycle_kind(MORPH_ARCHIVE));
        assert!(is_strand_tracks_kind(STRAND_TRACKS_UPDATE));
        assert_eq!(
            classify_event_kind(AGENT_INTEROP_SESSION_STATUS),
            EventClass::Agent
        );
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
    fn event_kind_deserialise_preserves_unknown() {
        // Forward compatibility: an unrecognised kind deserialises into
        // `Unknown(raw)` instead of failing the parse. Rejecting unknown
        // standard kinds is the validation layer's job, not serde's.
        let parsed: EventKind = serde_json::from_str(r#""ak.future.kind""#).unwrap();
        assert_eq!(parsed, EventKind::Unknown("ak.future.kind".to_owned()));
        assert_eq!(parsed.as_str(), "ak.future.kind");
        assert!(!parsed.is_standard());
        // Round-trips back to the same wire string.
        assert_eq!(
            serde_json::to_string(&parsed).unwrap(),
            r#""ak.future.kind""#
        );
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
            STANDARD_EVENT_KINDS
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "STANDARD_EVENT_KINDS must stay sorted by wire string"
        );
        assert!(
            NON_REDUCER_EVENT_KINDS
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "NON_REDUCER_EVENT_KINDS must stay sorted by wire string"
        );
    }

    /// SDK-ARCH-01 guard: the three in-SDK materializations of the active
    /// event-kind set — the hand-written `STANDARD_EVENT_KINDS` table, the
    /// generated `EventKind` enum (`EVENT_KIND_COUNT`), and (transitively) the
    /// spec registry the generator reads — MUST stay in lock-step. Any kind
    /// added to one source but not the others trips this test, preventing the
    /// SDK-SPEC-03 class of drift from recurring silently.
    #[test]
    fn standard_kinds_match_generated_enum() {
        assert_eq!(
            STANDARD_EVENT_KINDS.len(),
            EVENT_KIND_COUNT,
            "STANDARD_EVENT_KINDS count must equal the generated EVENT_KIND_COUNT; \
             regenerate generated/event_kinds.rs and/or update STANDARD_EVENT_KINDS"
        );
        for kind in STANDARD_EVENT_KINDS {
            let parsed = EventKind::from_wire(kind);
            assert!(
                parsed.is_standard(),
                "STANDARD_EVENT_KINDS entry `{kind}` is not a generated EventKind variant; \
                 regenerate generated/event_kinds.rs"
            );
            assert_eq!(
                parsed.as_str(),
                *kind,
                "EventKind round-trip mismatch for `{kind}`"
            );
        }
    }
}
