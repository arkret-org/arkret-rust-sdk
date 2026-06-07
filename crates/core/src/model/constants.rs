pub const PROTOCOL_VERSION: &str = "1.0";
pub const CORE_SCHEMA_PROFILE: &str = "ck.schema.core.v1";
pub const CORE_REDUCER_PROFILE: &str = "ck.reducer.v1";
pub const BUILT_IN_CONFORMANCE_FIXTURES_VERSION: &str = "cokret-sdk-builtin-v1";

pub const CURSOR_SCHEMA: &str = "ck.schema.cursor.v1";
// Realm/Space schema ids:
//   - `ck.schema.realm.v1` is the security-boundary schema.
//   - `ck.schema.space.v1` is the product container schema.
pub const REALM_SCHEMA_ID: &str = "ck.schema.realm.v1";
pub const REALM_JOIN_CANDIDATE_SCHEMA: &str = "ck.schema.realm_join_candidate.v1";
pub const SPACE_SCHEMA: &str = "ck.schema.space.v1";
pub const ACTOR_PROFILE_SCHEMA: &str = "ck.schema.actor_profile.v1";
pub const FLOW_SCHEMA: &str = "ck.schema.flow.v1";
pub const RELATION_SCHEMA: &str = "ck.schema.relation.v1";
pub const EVENT_SCHEMA: &str = "ck.schema.event.v1";
pub const EVENT_PAYLOAD_SCHEMA: &str = "ck.schema.event_payload.v1";
pub const VIEW_SCHEMA: &str = "ck.schema.view.v1";
pub const POLICY_SCHEMA: &str = "ck.schema.policy.v1";
pub const CAPABILITY_SCHEMA: &str = "ck.schema.capability.v1";
pub const INVITE_SCHEMA: &str = "ck.schema.invite.v1";
pub const READ_CURSOR_SCHEMA: &str = "ck.schema.read_cursor.v1";
pub const NOTIFICATION_SCHEMA: &str = "ck.schema.notification.v1";
/// SDK-local operation draft schema marker.
///
/// Operation drafts are builder inputs only; they are not a Cokret wire
/// schema and must be materialized as Event envelopes before submission.
pub const OPERATION_SCHEMA: &str = "ck.local.operation_draft.v1";
pub const BLOB_SCHEMA: &str = "ck.schema.blob.v1";
pub const ANCHOR_SCHEMA: &str = "ck.schema.anchor.v1";
pub const BOTTOM_SCHEMA: &str = "ck.schema.bottom.v1";
pub const SNAPSHOT_SCHEMA: &str = "ck.schema.snapshot.v1";
pub const ENCRYPTED_ENVELOPE_SCHEMA: &str = "ck.schema.encrypted_envelope.v1";
pub const ACCOUNT_SUBSCRIBE_FRAME_SCHEMA: &str = "ck.schema.account_subscribe_frame.v1";
pub const RESOURCE_SELECTOR_SCHEMA: &str = "ck.schema.resource_selector.v1";
pub const GRANT_CONSTRAINT_SCHEMA: &str = "ck.schema.grant_constraint.v1";
pub const DEVICE_MESSAGE_SCHEMA: &str = "ck.schema.device_message.v1";
pub const KEY_BACKUP_SCHEMA: &str = "ck.schema.key_backup.v1";
pub const MORPH_SCHEMA: &str = "ck.schema.morph.v1";
/// CKP-0007 (2026-05-08) — Circle object schema id. See spec
/// `artifacts/schemas/circle.schema.json`.
pub const CIRCLE_SCHEMA_ID: &str = "ck.schema.circle.v1";
pub const MORPH_CUSTOMER_RISK_SCHEMA: &str = "ck.schema.morph.customer_risk.v1";
pub const MESSAGE_SCHEMA: &str = "ck.schema.message.v1";
pub const MODERATION_REPORT_SCHEMA: &str = "ck.schema.moderation_report.v1";
pub const MODERATION_QUEUE_ITEM_SCHEMA: &str = "ck.schema.moderation_queue_item.v1";
pub const DID_CONTINUITY_PROOF_SCHEMA: &str = "ck.schema.did_continuity_proof.v1";
pub const IDENTITY_LINK_SCHEMA: &str = "ck.schema.identity_link.v1";
pub const ERASURE_RECEIPT_SCHEMA: &str = "ck.schema.erasure_receipt.v1";
pub const ERASURE_VERIFICATION_STUB_SCHEMA: &str = "ck.schema.erasure_verification_stub.v1";
pub const PERSONAL_PRODUCTIVITY_SCHEMA: &str = "ck.schema.personal_productivity.v1";
pub const DRAFT_SYNC_SCHEMA: &str = "ck.schema.draft_sync.v1";
pub const CALENDAR_EVENT_SCHEMA: &str = "ck.schema.calendar_event.v1";
pub const DISAPPEARING_MESSAGES_SCHEMA: &str = "ck.schema.disappearing_messages.v1";
pub const SEARCH_SERVICE_SCHEMA: &str = "ck.schema.search_service.v1";

// Round R2/R3 (2026-05-20) — new schema ids for the moderation appeal flow,
// the broadcast ephemeral envelope, and structured attestation evidence.
pub const EPHEMERAL_ENVELOPE_SCHEMA: &str = "ck.schema.ephemeral_envelope.v1";
pub const MODERATION_APPEAL_SCHEMA: &str = "ck.schema.moderation_appeal.v1";
pub const ATTESTATION_EVIDENCE_SCHEMA: &str = "ck.schema.attestation_evidence.v1";
pub const CROSS_SIGNING_RESET_SCHEMA: &str = "ck.schema.cross_signing_reset.v1";

// ── Canonical ck.* event kinds ──────────────────────────────────────────────
/// Flow event kinds.
pub const OP_FLOW_CREATE: &str = "ck.flow.create";
pub const OP_FLOW_UPDATE: &str = "ck.flow.update";
pub const OP_FLOW_ARCHIVE: &str = "ck.flow.archive";
pub const OP_FLOW_RESTORE: &str = "ck.flow.restore";
pub const OP_FLOW_MOVE: &str = "ck.flow.move";
pub const OP_FLOW_REORDER: &str = "ck.flow.reorder";
pub const OP_FLOW_STAGE_SET: &str = "ck.flow.stage.set";

/// CKP-0007 (spec b7d35be) — Circle event kinds. The 7th kind
/// (`ck.circle.anchor_commit`) is reducer-derived and MUST NOT be
/// submitted by clients; it is exported for receiver-side dispatch only.
pub const OP_CIRCLE_CREATE: &str = "ck.circle.create";
pub const OP_CIRCLE_UPDATE: &str = "ck.circle.update";
pub const OP_CIRCLE_ARCHIVE: &str = "ck.circle.archive";
pub const OP_CIRCLE_RESTORE: &str = "ck.circle.restore";
pub const OP_CIRCLE_TOMBSTONE: &str = "ck.circle.tombstone";
pub const OP_CIRCLE_MEMBER_STATE: &str = "ck.circle.member.state";
pub const OP_CIRCLE_ANCHOR_COMMIT: &str = "ck.circle.anchor_commit";

/// CKP-0007 (spec b7d35be) — Circle capability action ids. Spec
/// `capability-action-registry.json`. `ck.circle.manage`,
/// `ck.circle.member.manage`, `ck.circle.member.add.others`, and
/// `ck.circle.audit` declare `required_constraints=["allowed_circle_ids"]`;
/// unconstrained Realm-wide grants for those actions MUST be rejected.
pub const CAP_ACTION_CIRCLE_CREATE: &str = "ck.circle.create";
pub const CAP_ACTION_CIRCLE_MANAGE: &str = "ck.circle.manage";
pub const CAP_ACTION_CIRCLE_MEMBER_ADD: &str = "ck.circle.member.add";
pub const CAP_ACTION_CIRCLE_MEMBER_MANAGE: &str = "ck.circle.member.manage";
pub const CAP_ACTION_CIRCLE_MEMBER_ADD_OTHERS: &str = "ck.circle.member.add.others";
pub const CAP_ACTION_CIRCLE_AUDIT: &str = "ck.circle.audit";

/// CKP-0007 capability action list (6 actions). Useful for downstream
/// services that want to iterate the Circle-management surface.
pub const CIRCLE_CAPABILITY_ACTIONS: &[&str] = &[
    CAP_ACTION_CIRCLE_CREATE,
    CAP_ACTION_CIRCLE_MANAGE,
    CAP_ACTION_CIRCLE_MEMBER_ADD,
    CAP_ACTION_CIRCLE_MEMBER_MANAGE,
    CAP_ACTION_CIRCLE_MEMBER_ADD_OTHERS,
    CAP_ACTION_CIRCLE_AUDIT,
];

/// CKP-0008 / CKP-0009 (spec head 37ce729) — personal-agent capability actions
/// registered in `capability-action-registry.json`. 14 actions: 8 lifecycle /
/// runtime actions on the agent itself, plus 3 sidecar-thread actions, plus
/// 3 aggregate actions that fan out to `target_event_kinds` (publish / write /
/// ensure trio carries the migration_group metadata in the spec; SDK consumers
/// MUST consult the registry artifact for the target_event_kinds expansion).
pub const CAP_ACTION_AGENT_PROVISION: &str = "ck.self.agent.provision";
pub const CAP_ACTION_AGENT_PAUSE: &str = "ck.self.agent.pause";
pub const CAP_ACTION_AGENT_RESUME: &str = "ck.self.agent.resume";
pub const CAP_ACTION_AGENT_DEACTIVATE: &str = "ck.self.agent.deactivate";
pub const CAP_ACTION_AGENT_DRAFT_PROPOSE: &str = "ck.agent.draft.propose";
pub const CAP_ACTION_AGENT_ACTION_REQUEST: &str = "ck.agent.action_request";
pub const CAP_ACTION_AGENT_ACTION_APPROVE: &str = "ck.agent.action_approve";
pub const CAP_ACTION_AGENT_ACTION_REJECT: &str = "ck.agent.action_reject";
pub const CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE: &str = "ck.self.agent.sidecar_thread.ensure";
pub const CAP_ACTION_AGENT_SIDECAR_THREAD_WRITE: &str = "ck.agent.sidecar_thread.write";
pub const CAP_ACTION_AGENT_SIDECAR_THREAD_PUBLISH: &str = "ck.agent.sidecar_thread.publish";

/// CKP-0008 / CKP-0009 — full capability-action list (11 base + 3 aggregate
/// = 14 entries per `_before_todos.md` §1.4).
pub const AGENT_CAPABILITY_ACTIONS: &[&str] = &[
    CAP_ACTION_AGENT_PROVISION,
    CAP_ACTION_AGENT_PAUSE,
    CAP_ACTION_AGENT_RESUME,
    CAP_ACTION_AGENT_DEACTIVATE,
    CAP_ACTION_AGENT_DRAFT_PROPOSE,
    CAP_ACTION_AGENT_ACTION_REQUEST,
    CAP_ACTION_AGENT_ACTION_APPROVE,
    CAP_ACTION_AGENT_ACTION_REJECT,
    CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE,
    CAP_ACTION_AGENT_SIDECAR_THREAD_WRITE,
    CAP_ACTION_AGENT_SIDECAR_THREAD_PUBLISH,
];

pub const AGENT_SIDECAR_THREAD_ENSURE_TARGET_EVENT_KINDS: &[&str] =
    &["ck.circle.create", "ck.circle.member.state", "ck.flow.create", "ck.relation.create"];
pub const AGENT_SIDECAR_THREAD_WRITE_TARGET_EVENT_KINDS: &[&str] = &["ck.message.create"];
pub const AGENT_SIDECAR_THREAD_PUBLISH_TARGET_EVENT_KINDS: &[&str] = &["ck.message.create"];

pub fn agent_capability_target_event_kinds(action: &str) -> &'static [&'static str] {
    match action {
        CAP_ACTION_AGENT_PROVISION => &[
            "ck.profile.create",
            "ck.identity.accountability_grant",
            "ck.agent.key.authorize",
            "ck.capability.grant",
        ],
        CAP_ACTION_AGENT_PAUSE => &["ck.self.agent.pause"],
        CAP_ACTION_AGENT_RESUME => &["ck.self.agent.resume"],
        CAP_ACTION_AGENT_DEACTIVATE => &["ck.self.agent.deactivate"],
        CAP_ACTION_AGENT_DRAFT_PROPOSE => &["ck.agent.draft.propose"],
        CAP_ACTION_AGENT_ACTION_REQUEST => &["ck.agent.action_request"],
        CAP_ACTION_AGENT_ACTION_APPROVE => &["ck.agent.action_approve"],
        CAP_ACTION_AGENT_ACTION_REJECT => &["ck.agent.action_reject"],
        CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE => AGENT_SIDECAR_THREAD_ENSURE_TARGET_EVENT_KINDS,
        CAP_ACTION_AGENT_SIDECAR_THREAD_WRITE => AGENT_SIDECAR_THREAD_WRITE_TARGET_EVENT_KINDS,
        CAP_ACTION_AGENT_SIDECAR_THREAD_PUBLISH => AGENT_SIDECAR_THREAD_PUBLISH_TARGET_EVENT_KINDS,
        _ => &[],
    }
}

/// CKP-0008 / CKP-0009 — personal-agent operation IDs (registered in
/// `operation-registry.json`). Used by the RPC dispatch layer; reducer-input
/// agent lifecycle events are registered separately under `AGENT_*`
/// event-kind constants above.
pub const OP_ACCOUNT_AGENT_KEY_PAIR: &str = "ck.gate.account.agent_key_pair";
pub const OP_AGENT_PROVISION: &str = "ck.self.agent.provision";
pub const OP_AGENT_LIST: &str = "ck.self.agent.list";
pub const OP_AGENT_GET: &str = "ck.self.agent.get";
pub const OP_AGENT_PAUSE: &str = "ck.self.agent.pause";
pub const OP_AGENT_RESUME: &str = "ck.self.agent.resume";
pub const OP_AGENT_DEACTIVATE: &str = "ck.self.agent.deactivate";
pub const OP_AGENT_ROTATE_KEY: &str = "ck.self.agent.rotate_key";
pub const OP_AGENT_GRANT_ATTACH: &str = "ck.self.agent.grant.attach";
pub const OP_AGENT_GRANT_DETACH: &str = "ck.self.agent.grant.detach";
pub const OP_AGENT_SIDECAR_THREAD_ENSURE: &str = "ck.self.agent.sidecar_thread.ensure";

/// CKP-0008 / CKP-0009 — controller-private account-data types. Reducer
/// MUST reject writes from non-controller actors.
pub const ACCOUNT_DATA_TYPE_AGENT_DRAFT: &str = "ck.agent.draft.v1";
pub const ACCOUNT_DATA_TYPE_AGENT_SIDECAR_PROJECTION: &str = "ck.agent.sidecar_projection.v1";
pub const ACCOUNT_DATA_TYPE_REMINDER: &str = "ck.reminders.v1";
pub const ACCOUNT_DATA_TYPE_SCHEDULED_SEND: &str = "ck.scheduled_send.v1";
pub const ACCOUNT_DATA_TYPE_SNOOZE: &str = "ck.snooze.v1";
pub const ACCOUNT_DATA_TYPE_SAVED: &str = "ck.saved.v1";
pub const ACCOUNT_DATA_TYPE_DRAFT: &str = "ck.draft.v1";
pub const ACCOUNT_DATA_TYPE_SEARCH_INDEX_MANIFEST: &str = "ck.search.index_manifest.v1";
pub const ACCOUNT_DATA_TYPE_CONTACTS_ACTOR: &str = "ck.contacts.actor";
pub const ACCOUNT_DATA_TYPE_CONTACTS_REALM: &str = "ck.contacts.realm";

/// Key-backup hardening (B-C) — new schema ids registered in
/// `schema-registry.json` for recovery policy and recovery receipts.
pub const RECOVERY_POLICY_SCHEMA: &str = "ck.schema.recovery_policy.v1";
pub const RECOVERY_RECEIPT_SCHEMA: &str = "ck.schema.recovery_receipt.v1";

/// CKP-0008 / CKP-0009 — agent sidecar thread profile id.
///
/// Per spec head 37ce729 §B-F, the default home policy for the
/// agent sidecar thread is **"context realm preferred"**: the sidecar
/// Circle is provisioned in the context Realm of the controller's
/// current focused conversation when available, falling back to the
/// controller's home Realm only when no context Realm exists.
///
pub const PROFILE_AGENT_SIDECAR_THREAD: &str = "ck.profile.agent_sidecar_thread.v1";
pub const AGENT_SIDECAR_HOME_POLICY_CONTEXT_REALM_PREFERRED: &str = "context_realm_preferred";

pub fn select_agent_sidecar_home_realm<'a>(
    context_realm_id: Option<&'a str>,
    controller_home_realm_id: &'a str,
) -> &'a str {
    context_realm_id.unwrap_or(controller_home_realm_id)
}

/// Morph event kinds.
pub const OP_MORPH_CREATE: &str = "ck.morph.create";
pub const OP_MORPH_UPDATE: &str = "ck.morph.update";
pub const OP_MORPH_ARCHIVE: &str = "ck.morph.archive";
pub const OP_MORPH_RESTORE: &str = "ck.morph.restore";
pub const OP_MORPH_STAGE_SET: &str = "ck.morph.stage.set";

/// Space (container) event kinds. Container events use `ck.space.*`; see the
/// security-boundary OP_REALM_* family for `ck.realm.*` events.
pub const OP_SPACE_CREATE: &str = "ck.space.create";
pub const OP_SPACE_UPDATE: &str = "ck.space.update";
pub const OP_SPACE_PARENT: &str = "ck.space.parent";
pub const OP_SPACE_ARCHIVE: &str = "ck.space.archive";
pub const OP_SPACE_RESTORE: &str = "ck.space.restore";
pub const OP_SPACE_TOMBSTONE: &str = "ck.space.tombstone";

/// Relation event kinds.
pub const OP_RELATION_CREATE: &str = "ck.relation.create";
pub const OP_RELATION_UPDATE: &str = "ck.relation.update";
pub const OP_RELATION_TOMBSTONE: &str = "ck.relation.tombstone";
pub const OP_CONTAINER_MOVE_ITEM: &str = "ck.container.move_item";
pub const OP_CONTAINER_REBALANCE: &str = "ck.container.rebalance";

/// View event kinds.
pub const OP_VIEW_CREATE: &str = "ck.view.create";
pub const OP_VIEW_UPDATE: &str = "ck.view.update";
pub const OP_VIEW_RECONCILE: &str = "ck.view.reconcile";

/// Realm event kinds (security boundary). The container-level OP_SPACE_* family
/// lives above.
pub const OP_REALM_CREATE: &str = "ck.realm.create";
pub const OP_REALM_UPDATE: &str = "ck.realm.update";
pub const OP_REALM_ORGANIZATION: &str = "ck.realm.organization";
pub const OP_REALM_LINK: &str = "ck.realm.link";
/// Per-Realm governance of member `delivery_binding`: which `binding_source`
/// values are admissible, which recipient services are allowed, whether DID
/// Document fallback is permitted, who may sign rebind. cell_family
/// `ck.component.realm.delivery_binding_policy.v1`, cas-register.
pub const OP_REALM_DELIVERY_BINDING_POLICY: &str = "ck.realm.delivery_binding_policy";
pub const OP_REALM_DISAPPEARING_POLICY: &str = "ck.realm.disappearing_policy";
pub const OP_REALM_INHERITANCE_POLICY: &str = "ck.realm.inheritance_policy";
pub const OP_REALM_AUDIT_POLICY_DOWNGRADE: &str = "ck.realm.audit_policy_downgrade";
pub const OP_REALM_PREVIEW_POLICY: &str = "ck.realm.preview_policy";
pub const OP_CAPABILITY_DERIVED: &str = "ck.capability.derived";
pub const OP_REALM_SEARCH_POLICY: &str = "ck.realm.search_policy";

/// Device event kinds.
///
/// Round C45 (2026-05-19; spec 0a5ab85) — actor-private push route binding
/// for the composite tuple `(recipient_service_did, principal, device,
/// push_route)`. MUST NOT be replicated outside the binding's
/// recipient_service_did context.
pub const OP_DEVICE_PUSH_ROUTE: &str = "ck.device.push_route";

/// Message event kinds.
pub const OP_MESSAGE_CREATE: &str = "ck.message.create";
pub const OP_MESSAGE_REVISE: &str = "ck.message.revise";
pub const OP_MESSAGE_REDACT: &str = "ck.message.redact";
pub const OP_RSVP_SET: &str = "ck.rsvp.set";
pub const OP_PIN_ADD: &str = "ck.pin.add";
pub const OP_PIN_REMOVE: &str = "ck.pin.remove";
pub const OP_PIN_REORDER: &str = "ck.pin.reorder";
/// High-risk capability required in addition to `ck.message.create` or
/// `ck.message.revise` whenever a Message introduces an `audience_mention`
/// node such as `@all` or v1 `@here` (`audience="flow_engaged"`).
pub const CAP_ACTION_MESSAGE_MENTION_BROADCAST: &str = "ck.message.mention.broadcast";
pub const CAP_ACTION_RSVP_SET: &str = "ck.rsvp.set";
pub const CAP_ACTION_PIN_ADD: &str = "ck.pin.add";
pub const CAP_ACTION_PIN_REMOVE: &str = "ck.pin.remove";
pub const CAP_ACTION_PIN_REORDER: &str = "ck.pin.reorder";
pub const CAP_ACTION_REALM_DISAPPEARING_POLICY: &str = "ck.realm.disappearing_policy";
pub const CAP_ACTION_REALM_SEARCH_POLICY: &str = "ck.realm.search_policy";

/// Capability constraint shorthand from `capability-action-registry.json`.
pub const CAP_CONSTRAINT_ALLOWED_WRITE_FIELDS: &str = "allowed_write_fields";

/// Capability-action IDs sampled in `_randmon.md` and promoted to SDK
/// constants so downstream grant builders do not hard-code raw strings.
pub const CAP_ACTION_OBJECT_ARCHIVE: &str = "ck.object.archive";
pub const CAP_ACTION_EVENT_READ: &str = "ck.event.read";
pub const CAP_ACTION_MODERATION_DECISION_LIFT: &str = "ck.moderation.decision.lift";
pub const CAP_ACTION_FLOW_UPDATE: &str = "ck.flow.update";
pub const CAP_ACTION_APPROVAL_VOTE: &str = "ck.approval.vote";
pub const CAP_ACTION_AUDIT_ACCESSED: &str = "ck.audit.accessed";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityRiskTier {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapabilityActionDefinition {
    pub action: &'static str,
    pub category: &'static str,
    pub risk_tier: CapabilityRiskTier,
    pub required_constraints: &'static [&'static str],
    pub target_event_kinds: &'static [&'static str],
    pub profile: Option<&'static str>,
    pub event_mapping_kind: &'static str,
}

pub const CAP_ACTION_OBJECT_ARCHIVE_TARGET_EVENT_KINDS: &[&str] =
    &[OP_FLOW_ARCHIVE, OP_MORPH_ARCHIVE];
pub const CAP_ACTION_EVENT_READ_TARGET_EVENT_KINDS: &[&str] = &[];
pub const CAP_ACTION_MODERATION_DECISION_LIFT_TARGET_EVENT_KINDS: &[&str] =
    &[CAP_ACTION_MODERATION_DECISION_LIFT];
pub const CAP_ACTION_FLOW_UPDATE_REQUIRED_CONSTRAINTS: &[&str] =
    &[CAP_CONSTRAINT_ALLOWED_WRITE_FIELDS];
pub const CAP_ACTION_FLOW_UPDATE_TARGET_EVENT_KINDS: &[&str] = &[OP_FLOW_UPDATE];
pub const CAP_ACTION_APPROVAL_VOTE_TARGET_EVENT_KINDS: &[&str] = &[];
pub const CAP_ACTION_AUDIT_ACCESSED_TARGET_EVENT_KINDS: &[&str] = &[CAP_ACTION_AUDIT_ACCESSED];

pub const REVIEWED_CAPABILITY_ACTION_DEFINITIONS: &[CapabilityActionDefinition] = &[
    CapabilityActionDefinition {
        action: CAP_ACTION_OBJECT_ARCHIVE,
        category: "general",
        risk_tier: CapabilityRiskTier::Medium,
        required_constraints: &[],
        target_event_kinds: CAP_ACTION_OBJECT_ARCHIVE_TARGET_EVENT_KINDS,
        profile: None,
        event_mapping_kind: "polymorphic_object",
    },
    CapabilityActionDefinition {
        action: CAP_ACTION_EVENT_READ,
        category: "discussion",
        risk_tier: CapabilityRiskTier::Low,
        required_constraints: &[],
        target_event_kinds: CAP_ACTION_EVENT_READ_TARGET_EVENT_KINDS,
        profile: None,
        event_mapping_kind: "non_event_surface",
    },
    CapabilityActionDefinition {
        action: CAP_ACTION_MODERATION_DECISION_LIFT,
        category: "management",
        risk_tier: CapabilityRiskTier::High,
        required_constraints: &[],
        target_event_kinds: CAP_ACTION_MODERATION_DECISION_LIFT_TARGET_EVENT_KINDS,
        profile: None,
        event_mapping_kind: "same_name",
    },
    CapabilityActionDefinition {
        action: CAP_ACTION_FLOW_UPDATE,
        category: "flow",
        risk_tier: CapabilityRiskTier::Medium,
        required_constraints: CAP_ACTION_FLOW_UPDATE_REQUIRED_CONSTRAINTS,
        target_event_kinds: CAP_ACTION_FLOW_UPDATE_TARGET_EVENT_KINDS,
        profile: None,
        event_mapping_kind: "same_name",
    },
    CapabilityActionDefinition {
        action: CAP_ACTION_APPROVAL_VOTE,
        category: "management",
        risk_tier: CapabilityRiskTier::Medium,
        required_constraints: &[],
        target_event_kinds: CAP_ACTION_APPROVAL_VOTE_TARGET_EVENT_KINDS,
        profile: None,
        event_mapping_kind: "non_event_surface",
    },
    CapabilityActionDefinition {
        action: CAP_ACTION_AUDIT_ACCESSED,
        category: "service",
        risk_tier: CapabilityRiskTier::Medium,
        required_constraints: &[],
        target_event_kinds: CAP_ACTION_AUDIT_ACCESSED_TARGET_EVENT_KINDS,
        profile: None,
        event_mapping_kind: "same_name",
    },
];

pub fn capability_action_definition(action: &str) -> Option<&'static CapabilityActionDefinition> {
    REVIEWED_CAPABILITY_ACTION_DEFINITIONS.iter().find(|definition| definition.action == action)
}

pub fn capability_action_target_event_kinds(action: &str) -> &'static [&'static str] {
    capability_action_definition(action)
        .map(|definition| definition.target_event_kinds)
        .unwrap_or(&[])
}

pub fn capability_action_required_constraints(action: &str) -> &'static [&'static str] {
    capability_action_definition(action)
        .map(|definition| definition.required_constraints)
        .unwrap_or(&[])
}

/// Membership and invite event kinds.
pub const OP_MEMBER_STATE: &str = "ck.member.state";
pub const OP_INVITE_CREATE: &str = "ck.invite.create";

/// Server and account/snapshot operations.
pub const OP_SERVER_DESCRIBE: &str = "ck.server.describe";
pub const OP_OPEN_INVITE_LOCATOR_RESOLVE: &str = "ck.open.invite_locator.resolve";
pub const OP_PEER_INVITES_SUBMIT: &str = "ck.peer.invites.submit";
pub const OP_IDENTITY_RESOLVE: &str = "ck.root.identity.resolve";
pub const OP_ACCOUNT_DESCRIBE: &str = "ck.self.account.describe";
pub const OP_ACCOUNT_CURSOR_REVOKE: &str = "ck.self.account.cursor_revoke";

/// Directory operations.
pub const OP_DIRECTORY_DESCRIBE: &str = "ck.find.directory.describe";

/// Blob operations.
pub const OP_BLOB_UPLOAD: &str = "ck.self.blob.upload";
pub const OP_BLOB_HEAD: &str = "ck.self.blob.head";
pub const OP_BLOB_GET: &str = "ck.self.blob.get";
/// Round C44 (2026-05-18; spec dc01ad7) — pre-signed blob URL surface.
/// `POST /blob/presign` returns a short-lived put/get URL pair so very
/// large blobs can be uploaded directly to object storage. Full signing
/// path is a soland TODO; SDK only needs the constant for client routing.
pub const OP_BLOB_PRESIGN: &str = "ck.self.blob.presign";

/// Push and key operations.
pub const OP_PUSH_NOTIFY: &str = "ck.edge.push.notify";
pub const OP_KEYS_UPLOAD: &str = "ck.self.keys.upload";
pub const OP_KEYS_QUERY: &str = "ck.self.keys.query";
pub const OP_KEYS_CLAIM: &str = "ck.self.keys.claim";
pub const OP_DEVICE_MESSAGES_PUT: &str = "ck.self.device_messages.put";
pub const OP_DEVICE_MESSAGES_GET: &str = "ck.self.device_messages.get";
pub const OP_KEYS_KEYPACKAGES_UPLOAD: &str = "ck.self.keys.keypackages.upload";
pub const OP_KEYS_KEYPACKAGES_CLAIM: &str = "ck.self.keys.keypackages.claim";
pub const OP_KEYS_KEYPACKAGES_CONSUME: &str = "ck.self.keys.keypackages.consume";
pub const OP_KEYS_KEYPACKAGES_REVOKE: &str = "ck.self.keys.keypackages.revoke";
pub const OP_KEYS_BACKUPS_PUT: &str = "ck.self.keys.backups.put";
pub const OP_KEYS_BACKUPS_LIST: &str = "ck.self.keys.backups.list";
pub const OP_KEYS_BACKUPS_GET: &str = "ck.self.keys.backups.get";
pub const OP_KEYS_BACKUPS_DELETE: &str = "ck.self.keys.backups.delete";

/// Authorization check.
pub const OP_AUTHZ_CHECK: &str = "ck.self.authz.check";
pub const OP_AUTHZ_GET_EFFECTIVE_GRANTS: &str = "ck.self.authz.get_effective_grants";
pub const OP_AUTHZ_GET_INVITES: &str = "ck.self.authz.get_invites";

/// Account / auth-server operations.
pub const OP_ACCOUNT_DEVICE_PAIR: &str = "ck.gate.account.device_pair";
pub const OP_ACCOUNT_ISSUE_SESSION_GRANT: &str = "ck.gate.account.issue_session_grant";
pub const OP_ACCOUNT_OIDC_CALLBACK: &str = "ck.gate.account.oidc_callback";

/// Admin / moderation-queue operations.
pub const OP_ADMIN_GET_MODERATION_QUEUE: &str = "ck.admin.get_moderation_queue";
pub const OP_ADMIN_GET_SERVER_STATUS: &str = "ck.admin.get_server_status";
pub const OP_ADMIN_REVOKE_DEVICE: &str = "ck.admin.revoke_device";
pub const OP_ADMIN_UPDATE_ACCOUNT_STATUS: &str = "ck.admin.update_account_status";

/// Applet / bridge operations.
pub const OP_APPLET_DESCRIBE: &str = "ck.edge.applet.describe";
pub const OP_APPLET_PING: &str = "ck.edge.applet.ping";
pub const OP_APPLET_PROTOCOL_METADATA: &str = "ck.edge.applet.protocol_metadata";
pub const OP_APPLET_RESOLVE_ACTOR: &str = "ck.edge.applet.resolve_actor";
pub const OP_APPLET_RESOLVE_REALM: &str = "ck.edge.applet.resolve_realm";
pub const OP_APPLET_THIRD_PARTY_LOCATIONS: &str = "ck.edge.applet.third_party_locations";
pub const OP_APPLET_THIRD_PARTY_USERS: &str = "ck.edge.applet.third_party_users";
pub const OP_APPLET_TRANSACTION: &str = "ck.edge.applet.transaction";

/// Applet protocol-session sub-events (round 13, 2026-05-16). Spec
/// `extensions/applet-integration.md` event-kind-registry rows. These
/// are durable reducer-input events (distinct from the RPC-style
/// `OP_APPLET_DESCRIBE` / `_PING` / `_TRANSACTION` ops above). SDK
/// reducer doesn't maintain per-session state — the applet bridge
/// state machine lives client-side — but operation-registry must
/// carry the required-fields shapes for downstream submit validation.
pub const OP_APPLET_BRIDGE_ERROR: &str = "ck.applet.bridge_error";
pub const OP_APPLET_DISCOVERY: &str = "ck.applet.discovery";
pub const OP_APPLET_PROTOCOL_SESSION_START: &str = "ck.applet.protocol_session.start";
pub const OP_APPLET_PROTOCOL_SESSION_STATUS: &str = "ck.applet.protocol_session.status";
pub const OP_APPLET_REGISTRATION: &str = "ck.applet.registration";

/// Agent protocol-session sub-events (round 13). Same shape as the
/// applet family but the terminal `*.result` event carries a signed
/// audit binding. Spec `extensions/agent-integration.md`.
pub const OP_AGENT_ENDPOINT: &str = "ck.agent.endpoint";
pub const OP_AGENT_KEY_AUTHORIZE: &str = "ck.agent.key.authorize";
pub const OP_AGENT_KEY_REVOKE: &str = "ck.agent.key.revoke";
pub const OP_AGENT_KEY_ROTATE: &str = "ck.agent.key.rotate";
pub const OP_AGENT_PROTOCOL_SESSION_RESULT: &str = "ck.agent.protocol_session.result";
pub const OP_AGENT_PROTOCOL_SESSION_START: &str = "ck.agent.protocol_session.start";
pub const OP_AGENT_PROTOCOL_SESSION_STATUS: &str = "ck.agent.protocol_session.status";

/// Directory operations beyond the bare `describe`.
pub const OP_DIRECTORY_PRIVATE_CONTACT_DISCOVERY: &str =
    "ck.find.directory.private_contact_discovery";
pub const OP_DIRECTORY_ANNOUNCE: &str = "ck.find.directory.announce";
pub const OP_DIRECTORY_RESOLVE_HANDLE: &str = "ck.find.directory.resolve_handle";
/// R3.2 (cokret-spec @ b56cab1) — subject/context → current visible
/// handle claims; the inverse of `resolve_handle`.
pub const OP_DIRECTORY_LIST_HANDLES_FOR_SUBJECT: &str =
    "ck.find.directory.list_handles_for_subject";
pub const OP_DIRECTORY_RESOLVE_ORGANIZATION: &str = "ck.find.directory.resolve_organization";
pub const OP_DIRECTORY_RESOLVE_REALM: &str = "ck.find.directory.resolve_realm";
/// R3.3 (CKP-0011, cokret-spec @ cced4b8) — resolve a client-agnostic
/// shareable object address (Realm / Flow / Message) to a preview. Pure ADD;
/// `resolve_realm` is retained and NOT deprecated.
pub const OP_DIRECTORY_RESOLVE_TARGET: &str = "ck.find.directory.resolve_target";
pub const OP_DIRECTORY_SEARCH_ACTORS: &str = "ck.find.directory.search_actors";
pub const OP_DIRECTORY_SEARCH_ORGANIZATIONS: &str = "ck.find.directory.search_organizations";
pub const OP_DIRECTORY_SEARCH_REALMS: &str = "ck.find.directory.search_realms";
pub const OP_DIRECTORY_SEARCH_USERS: &str = "ck.find.directory.search_users";
pub const OP_DIRECTORY_PUSH_REGISTER: &str = "ck.find.directory.push.register";
pub const OP_DIRECTORY_WITHDRAW: &str = "ck.find.directory.withdraw";

/// Events-API operations (low-level Event Envelope plane).
///
pub const OP_EVENTS_RESOLVE: &str = "ck.self.events.resolve";
pub const OP_EVENTS_DESCRIBE: &str = "ck.self.events.describe";
pub const OP_EVENTS_FRONTIER: &str = "ck.self.events.frontier";
pub const OP_EVENTS_GET: &str = "ck.self.events.get";
pub const OP_EVENTS_QUERY: &str = "ck.self.events.query";
/// Round C44 (2026-05-18; spec dc01ad7) — POST variant of
/// `ck.self.events.query` for selectors too long to fit in a `GET` query
/// string (large `spaces[]` / `actors[]` unions). HTTP path:
/// `POST /events/query`. Identical selector / range / response shape.
pub const OP_EVENTS_QUERY_POST: &str = "ck.self.events.query_post";
// DRIFT-ALLOW: constant declaring the operation-id string, not a payload type.
pub const OP_EVENTS_SUBSCRIBE: &str = "ck.self.events.subscribe";
pub const OP_EVENTS_SUBMIT: &str = "ck.self.events.submit";
pub const OP_EPHEMERAL_SEND: &str = "ck.self.ephemeral.send";

/// Contact and direct-conversation operations.
pub const OP_CONTACT_REQUEST: &str = "ck.self.contact.request";
pub const OP_CONTACT_RESPOND: &str = "ck.self.contact.respond";
pub const OP_CONTACT_LIST: &str = "ck.self.contact.list";
pub const OP_CONTACT_TOMBSTONE: &str = "ck.self.contact.tombstone";
pub const OP_DIRECT_CONVERSATION_RESOLVE: &str = "ck.self.direct_conversation.resolve";

/// Projection read-model operations.
pub const OP_PROJECTION_SPACES: &str = "ck.self.projection.spaces";
pub const OP_PROJECTION_FLOWS: &str = "ck.self.projection.flows";
pub const OP_PROJECTION_MORPHS: &str = "ck.self.projection.morphs";

/// Identity-registry operations.
pub const OP_IDENTITY_DESCRIBE_REGISTRY: &str = "ck.root.identity.describe_registry";
pub const OP_IDENTITY_GET_DOCUMENT: &str = "ck.root.identity.get_document";
pub const OP_IDENTITY_GET_LOG: &str = "ck.root.identity.get_log";
pub const OP_IDENTITY_GET_RECEIPTS: &str = "ck.root.identity.get_receipts";
pub const OP_IDENTITY_SUBMIT_DID_OPERATION: &str = "ck.root.identity.submit_did_operation";

/// Media / WebRTC ICE config.
pub const OP_MEDIA_ICE_CONFIG: &str = "ck.self.media.ice_config";

/// MIMI provider-facade operations.
pub const OP_MIMI_GROUP_INFO: &str = "ck.open.mimi.group_info";
pub const OP_MIMI_IDENTIFIER_QUERY: &str = "ck.open.mimi.identifier_query";
pub const OP_MIMI_KEY_MATERIAL: &str = "ck.open.mimi.key_material";
pub const OP_MIMI_NOTIFY: &str = "ck.open.mimi.notify";
pub const OP_MIMI_PROVIDER_DIRECTORY: &str = "ck.open.mimi.provider_directory";
pub const OP_MIMI_PROXY_DOWNLOAD: &str = "ck.open.mimi.proxy_download";
pub const OP_MIMI_REPORT_ABUSE: &str = "ck.open.mimi.report_abuse";
pub const OP_MIMI_REQUEST_CONSENT: &str = "ck.open.mimi.request_consent";
pub const OP_MIMI_ROOM_UPDATE: &str = "ck.open.mimi.room_update";
pub const OP_MIMI_SUBMIT_MESSAGE: &str = "ck.open.mimi.submit_message";
pub const OP_MIMI_UPDATE_CONSENT: &str = "ck.open.mimi.update_consent";

/// Moderation report submission.
pub const OP_MODERATION_REPORT: &str = "ck.self.moderation.report";

/// Round R2/R3 (2026-05-20) — capability actions for the moderation appeal
/// flow. `submit` is low-risk (any member may appeal); `review` is
/// medium-risk and gates the review / decision / close transitions.
/// Spec: capability-action-registry.json.
pub const CAP_ACTION_MODERATION_APPEAL_SUBMIT: &str = "ck.moderation.appeal.submit";
pub const CAP_ACTION_MODERATION_APPEAL_REVIEW: &str = "ck.moderation.appeal.review";

/// Round 4 (2026-05-20, spec a77b995) — capability action gating Morph
/// creation. Medium risk; the spec
/// `capability-action-registry.json` declares `required_constraints=[allowed_morph_types]`.
pub const CAP_ACTION_MORPH_CREATE: &str = "ck.morph.create";

/// CKP-0010 (R3 spec-sync 2026-05-27, cokret-spec b47ff6ec) — call /
/// media capability actions registered in
/// `capability-action-registry.json`. Five actions gate the join,
/// screen-share, recording, transcription, and moderation surfaces of
/// the ck.call.* feature.
pub const CAP_ACTION_CALL_JOIN: &str = "ck.call.join";
pub const CAP_ACTION_CALL_SCREEN_SHARE: &str = "ck.call.screen_share";
pub const CAP_ACTION_CALL_RECORD: &str = "ck.call.record";
pub const CAP_ACTION_CALL_TRANSCRIBE: &str = "ck.call.transcribe";
pub const CAP_ACTION_CALL_MODERATE: &str = "ck.call.moderate";

/// CKP-0010 — full call/media capability-action list.
pub const CALL_CAPABILITY_ACTIONS: &[&str] = &[
    CAP_ACTION_CALL_JOIN,
    CAP_ACTION_CALL_SCREEN_SHARE,
    CAP_ACTION_CALL_RECORD,
    CAP_ACTION_CALL_TRANSCRIBE,
    CAP_ACTION_CALL_MODERATE,
];

/// CKP-0010 — `ck.self.call.media.token_exchange` operation id. HTTP route:
/// `POST /rtc/token`. Surface tier `core_personal`. Registered in
/// `operation-registry.json` v2026-05-27.
pub const OP_CALL_MEDIA_TOKEN_EXCHANGE: &str = "ck.self.call.media.token_exchange";

/// CKP-0010 — schema id for the participant_binding signing envelope.
pub const PARTICIPANT_BINDING_SCHEMA: &str = "ck.media.participant_binding.v1";

/// CKP-0010 — maximum TTL bound for media tokens (600 seconds). Tokens
/// MUST be rejected when `expires_at - now > 600s`. SHOULD floor: 300s.
pub const MEDIA_TOKEN_TTL_MAX_SECS: u64 = 600;
/// CKP-0010 — SHOULD-bound (recommended) TTL for media tokens.
pub const MEDIA_TOKEN_TTL_SHOULD_SECS: u64 = 300;

/// CKP-0008 / CKP-0009 (R3 spec-sync 2026-05-27) — agent_runtime
/// surface tier: list of operations that live under the
/// `ck.profile.agent_runtime.v1` server-profile surface.
pub const AGENT_RUNTIME_SURFACE_OPERATIONS: &[&str] = &[
    OP_ACCOUNT_AGENT_KEY_PAIR,
    OP_AGENT_PROVISION,
    OP_AGENT_LIST,
    OP_AGENT_GET,
    OP_AGENT_PAUSE,
    OP_AGENT_RESUME,
    OP_AGENT_DEACTIVATE,
    OP_AGENT_ROTATE_KEY,
    OP_AGENT_GRANT_ATTACH,
    OP_AGENT_GRANT_DETACH,
    OP_AGENT_SIDECAR_THREAD_ENSURE,
];

/// Round 4 (2026-05-20) — canonical signal_type enum values carried in the
/// `ck.call.signal` ephemeral envelope payload. Wire-break: the
/// pre-round-4 6-value enum (`invite, answer, candidate, renegotiate,
/// hangup, ack`) is replaced by this 13-value set. Spec
/// `schemas/ephemeral-envelope.schema.json` (Round 4 commit 58c5926).
pub const CALL_SIGNAL_TYPE_INVITE: &str = "invite";
pub const CALL_SIGNAL_TYPE_ANSWER: &str = "answer";
pub const CALL_SIGNAL_TYPE_CANDIDATE: &str = "candidate";
pub const CALL_SIGNAL_TYPE_RENEGOTIATE: &str = "renegotiate";
pub const CALL_SIGNAL_TYPE_HANGUP: &str = "hangup";
pub const CALL_SIGNAL_TYPE_ACK: &str = "ack";
pub const CALL_SIGNAL_TYPE_REJECT: &str = "reject";
pub const CALL_SIGNAL_TYPE_MUTE_STATE: &str = "mute_state";
pub const CALL_SIGNAL_TYPE_MEDIA_STATE: &str = "media_state";
pub const CALL_SIGNAL_TYPE_SPEAKING: &str = "speaking";
pub const CALL_SIGNAL_TYPE_FOCUS_JOIN: &str = "focus_join";
pub const CALL_SIGNAL_TYPE_FOCUS_LEAVE: &str = "focus_leave";
pub const CALL_SIGNAL_TYPE_ERROR: &str = "error";

/// All canonical `ck.call.signal` signal_type values. Round 4 (spec a77b995).
/// Receivers MUST reject any envelope whose `payload.signal_type` is not in
/// this set with `ERROR_CODE_SCHEMA_VIOLATION`.
pub const CALL_SIGNAL_TYPES: &[&str] = &[
    CALL_SIGNAL_TYPE_INVITE,
    CALL_SIGNAL_TYPE_ANSWER,
    CALL_SIGNAL_TYPE_CANDIDATE,
    CALL_SIGNAL_TYPE_RENEGOTIATE,
    CALL_SIGNAL_TYPE_HANGUP,
    CALL_SIGNAL_TYPE_ACK,
    CALL_SIGNAL_TYPE_REJECT,
    CALL_SIGNAL_TYPE_MUTE_STATE,
    CALL_SIGNAL_TYPE_MEDIA_STATE,
    CALL_SIGNAL_TYPE_SPEAKING,
    CALL_SIGNAL_TYPE_FOCUS_JOIN,
    CALL_SIGNAL_TYPE_FOCUS_LEAVE,
    CALL_SIGNAL_TYPE_ERROR,
];

/// Round 4 (2026-05-20) — federation S2S HTTP message-signature headers.
/// MUST be present on every cross-trust-domain federation request and
/// MUST be included in the canonical signing transcript so a sender from
/// trust domain A cannot replay the same signed bytes into trust domain B.
/// Spec commit f9bd7eb (`harden protocol review closures`).
pub const HEADER_SOURCE_TRUST_DOMAIN: &str = "Source-Trust-Domain";
pub const HEADER_DESTINATION_TRUST_DOMAIN: &str = "Destination-Trust-Domain";
/// Round 4 — canonical digest of the request payload as bound into the
/// signing transcript. Carried alongside the signing headers so receivers
/// can detect transport-level body tampering after the signature was
/// computed. Spec commit f9bd7eb.
pub const HEADER_REQUEST_CANONICAL_DIGEST: &str = "Request-Canonical-Digest";

/// Policy server check.
pub const OP_POLICY_CHECK: &str = "ck.self.policy.check";

/// Push gateway register / unregister.
pub const OP_PUSH_REGISTER_DEVICE: &str = "ck.edge.push.register_device";
pub const OP_PUSH_UNREGISTER_DEVICE: &str = "ck.edge.push.unregister_device";

/// Account aggregate stream and snapshot head.
pub const OP_ACCOUNT_SUBSCRIBE: &str = "ck.self.account.subscribe";
pub const OP_SNAPSHOT_HEAD: &str = "ck.self.snapshot.head";

/// Canonical service operation IDs built into this SDK.
///
/// Event kinds live in `crate::events`; this list mirrors the spec
/// `operation-registry.json` service surface.
pub const BUILT_IN_OPERATION_KINDS: &[&str] = &[
    OP_ACCOUNT_AGENT_KEY_PAIR,
    OP_ACCOUNT_DESCRIBE,
    OP_ACCOUNT_DEVICE_PAIR,
    OP_ACCOUNT_ISSUE_SESSION_GRANT,
    OP_ACCOUNT_OIDC_CALLBACK,
    OP_ACCOUNT_SUBSCRIBE,
    OP_ACCOUNT_CURSOR_REVOKE,
    OP_AGENT_DEACTIVATE,
    OP_AGENT_GET,
    OP_AGENT_GRANT_ATTACH,
    OP_AGENT_GRANT_DETACH,
    OP_AGENT_LIST,
    OP_AGENT_PAUSE,
    OP_AGENT_PROVISION,
    OP_AGENT_RESUME,
    OP_AGENT_ROTATE_KEY,
    OP_AGENT_SIDECAR_THREAD_ENSURE,
    OP_ADMIN_GET_MODERATION_QUEUE,
    OP_ADMIN_GET_SERVER_STATUS,
    OP_ADMIN_REVOKE_DEVICE,
    OP_ADMIN_UPDATE_ACCOUNT_STATUS,
    OP_APPLET_DESCRIBE,
    OP_APPLET_PING,
    OP_APPLET_PROTOCOL_METADATA,
    OP_APPLET_RESOLVE_ACTOR,
    OP_APPLET_RESOLVE_REALM,
    OP_APPLET_THIRD_PARTY_LOCATIONS,
    OP_APPLET_THIRD_PARTY_USERS,
    OP_APPLET_TRANSACTION,
    // Note: OP_APPLET_REGISTRATION / OP_APPLET_DISCOVERY / OP_APPLET_PROTOCOL_SESSION_*
    // / OP_APPLET_BRIDGE_ERROR and OP_AGENT_* are reducer-input EVENTS
    // (registered in spec `event-kind-registry.json`), not service RPC
    // operations. They follow the same `OP_*` const naming for
    // ergonomic dispatch in registry.rs::required_fields_for_operation_kind
    // but are intentionally NOT in BUILT_IN_OPERATION_KINDS — that list
    // mirrors spec `operation-registry.json` (RPC service surface) and
    // the drift report (`SpecArtifactBundle::drift_report`) fails if
    // event kinds leak in. Same convention as the lifecycle event ops
    // (`OP_FLOW_CREATE`, etc.).
    OP_AUTHZ_CHECK,
    OP_AUTHZ_GET_EFFECTIVE_GRANTS,
    OP_AUTHZ_GET_INVITES,
    OP_BLOB_GET,
    OP_BLOB_HEAD,
    OP_BLOB_PRESIGN,
    OP_BLOB_UPLOAD,
    OP_CALL_MEDIA_TOKEN_EXCHANGE,
    OP_DEVICE_MESSAGES_GET,
    OP_DEVICE_MESSAGES_PUT,
    OP_DIRECTORY_ANNOUNCE,
    OP_SERVER_DESCRIBE,
    OP_DIRECTORY_DESCRIBE,
    OP_DIRECTORY_PRIVATE_CONTACT_DISCOVERY,
    OP_DIRECTORY_RESOLVE_HANDLE,
    OP_DIRECTORY_LIST_HANDLES_FOR_SUBJECT,
    OP_DIRECTORY_RESOLVE_ORGANIZATION,
    OP_DIRECTORY_RESOLVE_REALM,
    OP_DIRECTORY_RESOLVE_TARGET,
    OP_DIRECTORY_SEARCH_ACTORS,
    OP_DIRECTORY_SEARCH_ORGANIZATIONS,
    OP_DIRECTORY_SEARCH_REALMS,
    OP_DIRECTORY_SEARCH_USERS,
    OP_DIRECTORY_PUSH_REGISTER,
    OP_DIRECTORY_WITHDRAW,
    OP_EVENTS_DESCRIBE,
    OP_EVENTS_FRONTIER,
    OP_EVENTS_GET,
    OP_EVENTS_QUERY,
    OP_EVENTS_QUERY_POST,
    OP_EVENTS_RESOLVE,
    OP_EVENTS_SUBSCRIBE,
    OP_EVENTS_SUBMIT,
    OP_EPHEMERAL_SEND,
    OP_PROJECTION_SPACES,
    OP_PROJECTION_FLOWS,
    OP_PROJECTION_MORPHS,
    OP_IDENTITY_DESCRIBE_REGISTRY,
    OP_IDENTITY_GET_DOCUMENT,
    OP_IDENTITY_GET_LOG,
    OP_IDENTITY_GET_RECEIPTS,
    OP_IDENTITY_RESOLVE,
    OP_IDENTITY_SUBMIT_DID_OPERATION,
    OP_KEYS_BACKUPS_DELETE,
    OP_KEYS_BACKUPS_GET,
    OP_KEYS_BACKUPS_LIST,
    OP_KEYS_BACKUPS_PUT,
    OP_KEYS_CLAIM,
    OP_KEYS_KEYPACKAGES_CLAIM,
    OP_KEYS_KEYPACKAGES_CONSUME,
    OP_KEYS_KEYPACKAGES_REVOKE,
    OP_KEYS_KEYPACKAGES_UPLOAD,
    OP_KEYS_QUERY,
    OP_KEYS_UPLOAD,
    OP_MEDIA_ICE_CONFIG,
    OP_MIMI_GROUP_INFO,
    OP_MIMI_IDENTIFIER_QUERY,
    OP_MIMI_KEY_MATERIAL,
    OP_MIMI_NOTIFY,
    OP_MIMI_PROVIDER_DIRECTORY,
    OP_MIMI_PROXY_DOWNLOAD,
    OP_MIMI_REPORT_ABUSE,
    OP_MIMI_REQUEST_CONSENT,
    OP_MIMI_ROOM_UPDATE,
    OP_MIMI_SUBMIT_MESSAGE,
    OP_MIMI_UPDATE_CONSENT,
    OP_MODERATION_REPORT,
    OP_OPEN_INVITE_LOCATOR_RESOLVE,
    OP_PEER_INVITES_SUBMIT,
    OP_POLICY_CHECK,
    OP_PUSH_NOTIFY,
    OP_PUSH_REGISTER_DEVICE,
    OP_PUSH_UNREGISTER_DEVICE,
    OP_SNAPSHOT_HEAD,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_sidecar_actions_expand_to_target_event_kinds() {
        assert_eq!(
            agent_capability_target_event_kinds(CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE),
            AGENT_SIDECAR_THREAD_ENSURE_TARGET_EVENT_KINDS
        );
        assert_eq!(
            agent_capability_target_event_kinds(CAP_ACTION_AGENT_SIDECAR_THREAD_WRITE),
            &["ck.message.create"]
        );
    }

    #[test]
    fn agent_sidecar_home_prefers_context_realm() {
        assert_eq!(
            select_agent_sidecar_home_realm(Some("ck:realm:context"), "ck:realm:home"),
            "ck:realm:context"
        );
        assert_eq!(select_agent_sidecar_home_realm(None, "ck:realm:home"), "ck:realm:home");
    }

    #[test]
    fn reviewed_capability_action_definitions_cover_randmon_sample() {
        let flow_update = capability_action_definition(CAP_ACTION_FLOW_UPDATE)
            .expect("ck.flow.update definition");
        assert_eq!(flow_update.risk_tier, CapabilityRiskTier::Medium);
        assert_eq!(
            capability_action_required_constraints(CAP_ACTION_FLOW_UPDATE),
            &[CAP_CONSTRAINT_ALLOWED_WRITE_FIELDS]
        );
        assert_eq!(capability_action_target_event_kinds(CAP_ACTION_FLOW_UPDATE), &[OP_FLOW_UPDATE]);

        assert_eq!(
            capability_action_target_event_kinds(CAP_ACTION_OBJECT_ARCHIVE),
            &[OP_FLOW_ARCHIVE, OP_MORPH_ARCHIVE]
        );
        assert!(capability_action_target_event_kinds(CAP_ACTION_APPROVAL_VOTE).is_empty());
        assert!(capability_action_definition("ck.unknown.action").is_none());
    }
}
