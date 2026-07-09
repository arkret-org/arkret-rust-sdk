pub const PROTOCOL_VERSION: &str = "1.0";
pub const CORE_SCHEMA_PROFILE: &str = "ak.schema.core.v1";
pub const CORE_REDUCER_PROFILE: &str = "ak.reducer.v1";
pub const BUILT_IN_CONFORMANCE_FIXTURES_VERSION: &str = "arkret-sdk-builtin-v1";

pub const CURSOR_SCHEMA: &str = "ak.schema.cursor.v1";
// Realm/Space schema ids:
//   - `ck.schema.realm.v1` is the security-boundary schema.
//   - `ck.schema.space.v1` is the product container schema.
pub const REALM_SCHEMA_ID: &str = "ak.schema.realm.v1";
pub const REALM_JOIN_CANDIDATE_SCHEMA: &str = "ak.schema.realm_join_candidate.v1";
pub const SPACE_SCHEMA: &str = "ak.schema.space.v1";
pub const ACTOR_PROFILE_SCHEMA: &str = "ak.schema.actor_profile.v1";
pub const AGENT_SELECTOR_CLAIM_SCHEMA: &str = "ak.schema.agent_selector_claim.v1";
pub const STRAND_SCHEMA: &str = "ak.schema.strand.v1";
pub const RELATION_SCHEMA: &str = "ak.schema.relation.v1";
pub const EVENT_SCHEMA: &str = "ak.schema.event.v1";
pub const EVENT_PAYLOAD_SCHEMA: &str = "ak.schema.event_payload.v1";
pub const VIEW_SCHEMA: &str = "ak.schema.view.v1";
pub const POLICY_SCHEMA: &str = "ak.schema.policy.v1";
pub const CAPABILITY_SCHEMA: &str = "ak.schema.capability.v1";
pub const INVITE_SCHEMA: &str = "ak.schema.invite.v1";
pub const READ_CURSOR_SCHEMA: &str = "ak.schema.read_cursor.v1";
pub const READ_RECEIPT_SCHEMA: &str = "ak.schema.read_receipt.v1";
/// `receipt_type` const value of `read-receipt.schema.json`.
pub const READ_RECEIPT_TYPE: &str = "read";
pub const NOTIFICATION_SCHEMA: &str = "ak.schema.notification.v1";
/// SDK-local operation draft schema marker.
///
/// Operation drafts are builder inputs only; they are not a Arkret wire
/// schema and must be materialized as Event envelopes before submission.
pub const OPERATION_SCHEMA: &str = "ak.local.operation_draft.v1";
pub const BLOB_SCHEMA: &str = "ak.schema.blob.v1";
pub const CALL_RECORDING_ARTIFACT_SCHEMA: &str = "ak.schema.call_recording_artifact.v1";
pub const ANCHOR_SCHEMA: &str = "ak.schema.seal.v1";
pub const BOTTOM_SCHEMA: &str = "ak.schema.bottom.v1";
pub const SNAPSHOT_SCHEMA: &str = "ak.schema.snapshot.v1";
pub const ENCRYPTED_ENVELOPE_SCHEMA: &str = "ak.schema.encrypted_envelope.v1";
pub const ACCOUNT_SUBSCRIBE_FRAME_SCHEMA: &str = "ak.schema.account_subscribe_frame.v1";
pub const RESOURCE_SELECTOR_SCHEMA: &str = "ak.schema.resource_selector.v1";
pub const GRANT_CONSTRAINT_SCHEMA: &str = "ak.schema.grant_constraint.v1";
pub const DEVICE_MESSAGE_SCHEMA: &str = "ak.schema.device_message.v1";
pub const KEY_BACKUP_SCHEMA: &str = "ak.schema.key_backup.v1";
pub const MORPH_SCHEMA: &str = "ak.schema.morph.v1";
/// CKP-0007 (2026-05-08) — Circle object schema id. See spec
/// `artifacts/schemas/circle.schema.json`.
pub const CIRCLE_SCHEMA_ID: &str = "ak.schema.circle.v1";
pub const MORPH_CUSTOMER_RISK_SCHEMA: &str = "ak.schema.morph.customer_risk.v1";
pub const MESSAGE_SCHEMA: &str = "ak.schema.message.v1";
pub const MODERATION_REPORT_SCHEMA: &str = "ak.schema.moderation_report.v1";
pub const MODERATION_QUEUE_ITEM_SCHEMA: &str = "ak.schema.moderation_queue_item.v1";
pub const DID_CONTINUITY_PROOF_SCHEMA: &str = "ak.schema.did_continuity_proof.v1";
pub const IDENTITY_LINK_SCHEMA: &str = "ak.schema.identity_link.v1";
pub const ERASURE_RECEIPT_SCHEMA: &str = "ak.schema.erasure_receipt.v1";
pub const ERASURE_VERIFICATION_STUB_SCHEMA: &str = "ak.schema.erasure_verification_stub.v1";
pub const PERSONAL_PRODUCTIVITY_SCHEMA: &str = "ak.schema.personal_productivity.v1";
pub const DRAFT_SYNC_SCHEMA: &str = "ak.schema.draft_sync.v1";
pub const FILE_TRANSFER_SCHEMA: &str = "ak.schema.file_transfer.v1";
pub const CALENDAR_EVENT_SCHEMA: &str = "ak.schema.calendar_event.v1";
pub const DISAPPEARING_MESSAGES_SCHEMA: &str = "ak.schema.disappearing_messages.v1";
pub const SEARCH_SERVICE_SCHEMA: &str = "ak.schema.search_service.v1";

// Round R2/R3 (2026-05-20) — new schema ids for the moderation appeal strand,
// the broadcast ephemeral envelope, and structured attestation evidence.
pub const EPHEMERAL_ENVELOPE_SCHEMA: &str = "ak.schema.ephemeral_envelope.v1";
pub const MODERATION_APPEAL_SCHEMA: &str = "ak.schema.moderation_appeal.v1";
pub const ATTESTATION_EVIDENCE_SCHEMA: &str = "ak.schema.attestation_evidence.v1";
pub const CROSS_SIGNING_RESET_SCHEMA: &str = "ak.schema.cross_signing_reset.v1";

// ── Canonical ck.* event kinds ──────────────────────────────────────────────
/// Strand event kinds.
pub const OP_STRAND_CREATE: &str = "ak.strand.create";
pub const OP_STRAND_UPDATE: &str = "ak.strand.update";
pub const OP_STRAND_ARCHIVE: &str = "ak.strand.archive";
pub const OP_STRAND_RESTORE: &str = "ak.strand.restore";
pub const OP_STRAND_MOVE: &str = "ak.strand.move";
pub const OP_STRAND_REORDER: &str = "ak.strand.reorder";
pub const OP_STRAND_STAGE_SET: &str = "ak.strand.stage.set";

/// CKP-0007 (spec b7d35be) — Circle event kinds. The 7th kind
/// (`ck.circle.seal_commit`) is reducer-derived and MUST NOT be
/// submitted by clients; it is exported for receiver-side dispatch only.
pub const OP_CIRCLE_CREATE: &str = "ak.circle.create";
pub const OP_CIRCLE_UPDATE: &str = "ak.circle.update";
pub const OP_CIRCLE_ARCHIVE: &str = "ak.circle.archive";
pub const OP_CIRCLE_RESTORE: &str = "ak.circle.restore";
pub const OP_CIRCLE_TOMBSTONE: &str = "ak.circle.tombstone";
pub const OP_CIRCLE_MEMBER_STATE: &str = "ak.circle.member.state";
pub const OP_CIRCLE_SEAL_COMMIT: &str = "ak.circle.seal_commit";

/// CKP-0007 (spec b7d35be) — Circle capability action ids. Spec
/// `capability-action-registry.json`. `ck.circle.manage`,
/// `ck.circle.member.manage`, `ck.circle.member.add.others`, and
/// `ck.circle.audit` declare `required_constraints=["allowed_circle_ids"]`;
/// unconstrained Realm-wide grants for those actions MUST be rejected.
pub const CAP_ACTION_CIRCLE_CREATE: &str = "ak.circle.create";
pub const CAP_ACTION_CIRCLE_MANAGE: &str = "ak.circle.manage";
pub const CAP_ACTION_CIRCLE_MEMBER_ADD: &str = "ak.circle.member.add";
pub const CAP_ACTION_CIRCLE_MEMBER_MANAGE: &str = "ak.circle.member.manage";
pub const CAP_ACTION_CIRCLE_MEMBER_ADD_OTHERS: &str = "ak.circle.member.add.others";
pub const CAP_ACTION_CIRCLE_AUDIT: &str = "ak.circle.audit";

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
pub const CAP_ACTION_AGENT_PROVISION: &str = "ak.self.agent.command.provision";
pub const CAP_ACTION_AGENT_PAUSE: &str = "ak.self.agent.command.pause";
pub const CAP_ACTION_AGENT_RESUME: &str = "ak.self.agent.command.resume";
pub const CAP_ACTION_AGENT_DEACTIVATE: &str = "ak.self.agent.command.deactivate";
pub const CAP_ACTION_AGENT_DRAFT_PROPOSE: &str = "ak.agent.draft.propose";
pub const CAP_ACTION_AGENT_ACTION_REQUEST: &str = "ak.agent.action_request";
pub const CAP_ACTION_AGENT_ACTION_APPROVE: &str = "ak.agent.action_approve";
pub const CAP_ACTION_AGENT_ACTION_REJECT: &str = "ak.agent.action_reject";
pub const CAP_ACTION_AGENT_SIDECAR_THREAD_ENSURE: &str =
    "ak.self.agent.sidecar_thread.command.ensure";
pub const CAP_ACTION_AGENT_SIDECAR_THREAD_WRITE: &str = "ak.agent.sidecar_thread.write";
pub const CAP_ACTION_AGENT_SIDECAR_THREAD_PUBLISH: &str = "ak.agent.sidecar_thread.publish";

/// CKP-0008 / CKP-0009 — full capability-action list (11 base + 3 aggregate
/// = 14 entries per `capability-action-registry.json`).
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

pub const AGENT_SIDECAR_THREAD_ENSURE_TARGET_EVENT_KINDS: &[&str] = &[
    "ak.circle.create",
    "ak.circle.member.state",
    "ak.strand.create",
    "ak.relation.create",
];
pub const AGENT_SIDECAR_THREAD_WRITE_TARGET_EVENT_KINDS: &[&str] = &["ak.message.create"];
pub const AGENT_SIDECAR_THREAD_PUBLISH_TARGET_EVENT_KINDS: &[&str] = &["ak.message.create"];

pub fn agent_capability_target_event_kinds(action: &str) -> &'static [&'static str] {
    match action {
        CAP_ACTION_AGENT_PROVISION => &[
            "ak.profile.create",
            "ak.identity.accountability_grant",
            "ak.agent.key.authorize",
            "ak.capability.grant",
        ],
        CAP_ACTION_AGENT_PAUSE => &["ak.self.agent.pause"],
        CAP_ACTION_AGENT_RESUME => &["ak.self.agent.resume"],
        CAP_ACTION_AGENT_DEACTIVATE => &["ak.self.agent.deactivate"],
        CAP_ACTION_AGENT_DRAFT_PROPOSE => &["ak.agent.draft.propose"],
        CAP_ACTION_AGENT_ACTION_REQUEST => &["ak.agent.action_request"],
        CAP_ACTION_AGENT_ACTION_APPROVE => &["ak.agent.action_approve"],
        CAP_ACTION_AGENT_ACTION_REJECT => &["ak.agent.action_reject"],
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
pub const OP_ACCOUNT_AGENT_KEY_PAIR: &str = "ak.gate.account.command.pair_agent_key";
pub const OP_OPEN_AGENT_PAIRING_SUBMIT_RUNTIME_KEY_REQUEST: &str =
    "ak.open.agent_pairing.command.submit_runtime_key_request";
pub const OP_AGENT_PROVISION: &str = "ak.self.agent.command.provision";
pub const OP_AGENT_LIST: &str = "ak.self.agent.query.list";
pub const OP_AGENT_GET: &str = "ak.self.agent.resource.get";
pub const OP_AGENT_PAUSE: &str = "ak.self.agent.command.pause";
pub const OP_AGENT_RESUME: &str = "ak.self.agent.command.resume";
pub const OP_AGENT_DEACTIVATE: &str = "ak.self.agent.command.deactivate";
pub const OP_AGENT_ROTATE_KEY: &str = "ak.self.agent.command.rotate_key";
pub const OP_AGENT_GRANT_ATTACH: &str = "ak.self.agent.grant.command.attach";
pub const OP_AGENT_GRANT_DETACH: &str = "ak.self.agent.grant.resource.delete";
pub const OP_AGENT_SIDECAR_THREAD_ENSURE: &str = "ak.self.agent.sidecar_thread.command.ensure";

/// CKP-0008 / CKP-0009 — controller-private account-data types. Reducer
/// MUST reject writes from non-controller actors.
pub const ACCOUNT_DATA_TYPE_AGENT_DRAFT: &str = "ak.agent.draft.v1";
pub const ACCOUNT_DATA_TYPE_AGENT_SIDECAR_PROJECTION: &str = "ak.agent.sidecar_projection.v1";
pub const ACCOUNT_DATA_TYPE_REMINDER: &str = "ak.reminders.v1";
pub const ACCOUNT_DATA_TYPE_SCHEDULED_SEND: &str = "ak.scheduled_send.v1";
pub const ACCOUNT_DATA_TYPE_SNOOZE: &str = "ak.snooze.v1";
pub const ACCOUNT_DATA_TYPE_SAVED: &str = "ak.saved.v1";
pub const ACCOUNT_DATA_TYPE_DRAFT: &str = "ak.draft.v1";
pub const ACCOUNT_DATA_TYPE_FILE_TRANSFER: &str = "ak.file_transfer.v1";
pub const ACCOUNT_DATA_TYPE_SEARCH_INDEX_MANIFEST: &str = "ak.search.index_manifest.v1";
pub const ACCOUNT_DATA_TYPE_CONTACTS_ACTOR: &str = "ak.contacts.actor";
pub const ACCOUNT_DATA_TYPE_CONTACTS_REALM: &str = "ak.contacts.realm";

/// Key-backup hardening (B-C) — new schema ids registered in
/// `schema-registry.json` for recovery policy and recovery receipts.
pub const RECOVERY_POLICY_SCHEMA: &str = "ak.schema.recovery_policy.v1";
pub const RECOVERY_RECEIPT_SCHEMA: &str = "ak.schema.recovery_receipt.v1";

/// CKP-0008 / CKP-0009 — agent sidecar thread profile id.
///
/// Per CKP-0009, the sidecar home is derived from `context_ref.realm_id`.
/// The profile label remains `context_realm_preferred` for registry
/// compatibility, but v1 ensure requests carry a required context Realm and
/// do not fall back to the controller's home Realm.
pub const PROFILE_AGENT_SIDECAR_THREAD: &str = "ak.profile.agent_sidecar_thread.v1";
pub const AGENT_SIDECAR_HOME_POLICY_CONTEXT_REALM_PREFERRED: &str = "context_realm_preferred";

pub fn select_agent_sidecar_home_realm<'a>(
    context_realm_id: Option<&'a str>,
    _controller_home_realm_id: &'a str,
) -> Option<&'a str> {
    context_realm_id
}

fn base32_lower_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;
    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            let index = ((buffer >> (bits - 5)) & 0x1f) as usize;
            out.push(ALPHABET[index] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[index] as char);
    }
    out
}

pub fn agent_sidecar_circle_key(realm_id: &str, controller_principal_id: &str) -> String {
    let transcript = format!("ak.agent_sidecar_circle.v1\n{realm_id}\n{controller_principal_id}");
    let digest = crate::canonical::sha256_bytes(transcript.as_bytes());
    base32_lower_no_pad(&digest).chars().take(24).collect()
}

pub fn agent_sidecar_short_name(controller_agent_circle_key: &str) -> String {
    let suffix = controller_agent_circle_key
        .chars()
        .take(12)
        .collect::<String>()
        .to_ascii_uppercase();
    format!("AI-{suffix}")
}

/// Morph event kinds.
pub const OP_MORPH_CREATE: &str = "ak.morph.create";
pub const OP_MORPH_UPDATE: &str = "ak.morph.update";
pub const OP_MORPH_ARCHIVE: &str = "ak.morph.archive";
pub const OP_MORPH_RESTORE: &str = "ak.morph.restore";
pub const OP_MORPH_STAGE_SET: &str = "ak.morph.stage.set";

/// Space (container) event kinds. Container events use `ck.space.*`; see the
/// security-boundary OP_REALM_* family for `ck.realm.*` events.
pub const OP_SPACE_CREATE: &str = "ak.space.create";
pub const OP_SPACE_UPDATE: &str = "ak.space.update";
pub const OP_SPACE_PARENT: &str = "ak.space.parent";
pub const OP_SPACE_ARCHIVE: &str = "ak.space.archive";
pub const OP_SPACE_RESTORE: &str = "ak.space.restore";
pub const OP_SPACE_TOMBSTONE: &str = "ak.space.tombstone";

/// Relation event kinds.
pub const OP_RELATION_CREATE: &str = "ak.relation.create";
pub const OP_RELATION_UPDATE: &str = "ak.relation.update";
pub const OP_RELATION_TOMBSTONE: &str = "ak.relation.tombstone";
pub const OP_CONTAINER_MOVE_ITEM: &str = "ak.container.move_item";
pub const OP_CONTAINER_REBALANCE: &str = "ak.container.rebalance";

/// View event kinds.
pub const OP_VIEW_CREATE: &str = "ak.view.create";
pub const OP_VIEW_UPDATE: &str = "ak.view.update";
pub const OP_VIEW_RECONCILE: &str = "ak.view.reconcile";

/// Realm event kinds (security boundary). The container-level OP_SPACE_* family
/// lives above.
pub const OP_REALM_CREATE: &str = "ak.realm.create";
pub const OP_REALM_UPDATE: &str = "ak.realm.update";
pub const OP_REALM_ORGANIZATION: &str = "ak.realm.organization";
pub const OP_REALM_LINK: &str = "ak.realm.link";
/// Per-Realm governance of member `delivery_binding`: which `binding_source`
/// values are admissible, which recipient services are allowed, whether DID
/// Document fallback is permitted, who may sign rebind. cell_family
/// `ck.component.realm.delivery_binding_policy.v1`, cas-register.
pub const OP_REALM_DELIVERY_BINDING_POLICY: &str = "ak.realm.delivery_binding_policy";
pub const OP_REALM_DISAPPEARING_POLICY: &str = "ak.realm.disappearing_policy";
pub const OP_REALM_INHERITANCE_POLICY: &str = "ak.realm.inheritance_policy";
pub const OP_REALM_PREVIEW_POLICY: &str = "ak.realm.preview_policy";
pub const OP_CAPABILITY_DERIVED: &str = "ak.capability.derived";
pub const OP_REALM_SEARCH_POLICY: &str = "ak.realm.search_policy";

/// Device event kinds.
///
/// Round C45 (2026-05-19; spec 0a5ab85) — actor-private push route binding
/// for the composite tuple `(recipient_service_did, principal, device,
/// push_route)`. MUST NOT be replicated outside the binding's
/// recipient_service_did context.
pub const OP_DEVICE_PUSH_ROUTE: &str = "ak.device.push_route";

/// Message event kinds.
pub const OP_MESSAGE_CREATE: &str = "ak.message.create";
pub const OP_MESSAGE_REVISE: &str = "ak.message.revise";
pub const OP_MESSAGE_REDACT: &str = "ak.message.redact";
pub const OP_RSVP_SET: &str = "ak.rsvp.set";
pub const OP_PIN_ADD: &str = "ak.pin.add";
pub const OP_PIN_REMOVE: &str = "ak.pin.remove";
pub const OP_PIN_REORDER: &str = "ak.pin.reorder";
/// High-risk capability required in addition to `ck.message.create` or
/// `ck.message.revise` whenever a Message introduces an `audience_mention`
/// node such as `@all` or v1 `@here` (`audience="strand_engaged"`).
pub const CAP_ACTION_MESSAGE_MENTION_BROADCAST: &str = "ak.message.mention.broadcast";
pub const CAP_ACTION_RSVP_SET: &str = "ak.rsvp.set";
pub const CAP_ACTION_PIN_ADD: &str = "ak.pin.add";
pub const CAP_ACTION_PIN_REMOVE: &str = "ak.pin.remove";
pub const CAP_ACTION_PIN_REORDER: &str = "ak.pin.reorder";
pub const CAP_ACTION_REALM_DISAPPEARING_POLICY: &str = "ak.realm.disappearing_policy";
pub const CAP_ACTION_REALM_SEARCH_POLICY: &str = "ak.realm.search_policy";

/// Capability constraint shorthand from `capability-action-registry.json`.
pub const CAP_CONSTRAINT_ALLOWED_WRITE_FIELDS: &str = "allowed_write_fields";

/// Capability-action IDs sampled in `_randmon.md` and promoted to SDK
/// constants so downstream grant builders do not hard-code raw strings.
pub const CAP_ACTION_OBJECT_ARCHIVE: &str = "ak.object.archive";
pub const CAP_ACTION_EVENT_READ: &str = "ak.event.read";
pub const CAP_ACTION_MODERATION_DECISION_LIFT: &str = "ak.moderation.decision.lift";
pub const CAP_ACTION_STRAND_UPDATE: &str = "ak.strand.update";
pub const CAP_ACTION_APPROVAL_VOTE: &str = "ak.approval.vote";
pub const CAP_ACTION_AUDIT_ACCESSED: &str = "ak.audit.accessed";

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
    &[OP_STRAND_ARCHIVE, OP_MORPH_ARCHIVE];
pub const CAP_ACTION_EVENT_READ_TARGET_EVENT_KINDS: &[&str] = &[];
pub const CAP_ACTION_MODERATION_DECISION_LIFT_TARGET_EVENT_KINDS: &[&str] =
    &[CAP_ACTION_MODERATION_DECISION_LIFT];
pub const CAP_ACTION_STRAND_UPDATE_REQUIRED_CONSTRAINTS: &[&str] =
    &[CAP_CONSTRAINT_ALLOWED_WRITE_FIELDS];
pub const CAP_ACTION_STRAND_UPDATE_TARGET_EVENT_KINDS: &[&str] = &[OP_STRAND_UPDATE];
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
        action: CAP_ACTION_STRAND_UPDATE,
        category: "strand",
        risk_tier: CapabilityRiskTier::Medium,
        required_constraints: CAP_ACTION_STRAND_UPDATE_REQUIRED_CONSTRAINTS,
        target_event_kinds: CAP_ACTION_STRAND_UPDATE_TARGET_EVENT_KINDS,
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
    REVIEWED_CAPABILITY_ACTION_DEFINITIONS
        .iter()
        .find(|definition| definition.action == action)
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
pub const OP_MEMBER_STATE: &str = "ak.member.state";
pub const OP_INVITE_CREATE: &str = "ak.invite.create";

/// Server and account/snapshot operations.
pub const OP_SERVER_DESCRIBE: &str = "ak.server.query.describe";
pub const OP_OPEN_INVITE_LOCATOR_RESOLVE: &str = "ak.open.invite_locator.query.resolve";
pub const OP_PEER_INVITES_SUBMIT: &str = "ak.peer.invites.command.submit";
pub const OP_IDENTITY_RESOLVE: &str = "ak.root.identity.query.resolve";
pub const OP_ACCOUNT_DESCRIBE: &str = "ak.self.account.query.describe";
pub const OP_ACCOUNT_CURSOR_REVOKE: &str = "ak.self.account.command.revoke_cursor";

/// Directory operations.
pub const OP_DIRECTORY_DESCRIBE: &str = "ak.find.directory.query.describe";

/// Blob operations.
pub const OP_BLOB_UPLOAD: &str = "ak.self.blob.upload.create";
pub const OP_BLOB_HEAD: &str = "ak.self.blob.resource.head";
pub const OP_BLOB_GET: &str = "ak.self.blob.resource.get";
/// Round C44 (2026-05-18; spec dc01ad7) — pre-signed blob URL surface.
/// `POST /blob/presign` returns a short-lived put/get URL pair so very
/// large blobs can be uploaded directly to object storage. Full signing
/// enforcement is a server responsibility; SDK only needs the constant for
/// client routing.
pub const OP_BLOB_PRESIGN: &str = "ak.self.blob.command.presign";

/// Push and key operations.
pub const OP_PUSH_NOTIFY: &str = "ak.edge.push.command.notify";
pub const OP_KEYS_UPLOAD: &str = "ak.self.keys.upload.create";
pub const OP_KEYS_QUERY: &str = "ak.self.keys.query.lookup";
pub const OP_KEYS_CLAIM: &str = "ak.self.keys.command.claim";
pub const OP_DEVICE_MESSAGES_PUT: &str = "ak.self.device_messages.command.send";
pub const OP_DEVICE_MESSAGES_GET: &str = "ak.self.device_messages.query.list";
pub const OP_DEVICE_MESSAGES_ACK: &str = "ak.self.device_messages.command.ack";
pub const OP_KEYS_KEYPACKAGES_UPLOAD: &str = "ak.self.keys.keypackages.upload.create";
pub const OP_KEYS_KEYPACKAGES_CLAIM: &str = "ak.self.keys.keypackages.command.claim";
pub const OP_KEYS_KEYPACKAGES_CONSUME: &str = "ak.self.keys.keypackages.command.consume";
pub const OP_KEYS_KEYPACKAGES_REVOKE: &str = "ak.self.keys.keypackages.command.revoke";
pub const OP_KEYS_BACKUPS_PUT: &str = "ak.self.keys.backups.resource.replace";
pub const OP_KEYS_BACKUPS_LIST: &str = "ak.self.keys.backups.query.list";
// Renamed from `ck.self.keys.backups.command.unlock` on 2026-06-11
// (artifacts/migration/renames.json): backup retrieval is rebound to
// `POST /_arkret/self/keys/backups/{backup_id}/unlock` with a body-borne
// unlock proof.
pub const OP_KEYS_BACKUPS_UNLOCK: &str = "ak.self.keys.backups.command.unlock";
pub const OP_KEYS_BACKUPS_DELETE: &str = "ak.self.keys.backups.resource.delete";

/// Authorization check.
pub const OP_AUTHZ_CHECK: &str = "ak.self.authz.query.check";
pub const OP_AUTHZ_GET_EFFECTIVE_GRANTS: &str = "ak.self.authz.grants.query.effective";
pub const OP_AUTHZ_GET_INVITES: &str = "ak.self.authz.invites.query.list";

/// Account / auth-server operations.
pub const OP_ACCOUNT_DEVICE_PAIR: &str = "ak.gate.account.command.pair_device";
pub const OP_ACCOUNT_DEVICE_ENROLL: &str = "ak.gate.account.command.enroll_device";
pub const OP_ACCOUNT_ISSUE_SESSION_GRANT: &str = "ak.gate.account.command.issue_session_grant";
pub const OP_ACCOUNT_OIDC_CALLBACK: &str = "ak.gate.account.exchange.complete_oidc";

// Admin / operator APIs (moderation queue, server status, device revocation,
// account status) are product-local per spec @ 2026-06-04 and MUST NOT be
// registered under the Arkret protocol namespace; servers expose them on
// their own negative-space root such as /_soland/admin/*. They were removed
// from the operation registry (see migration/removed-operation-ids.json) and
// therefore carry no `OP_ADMIN_*` protocol constants here.

/// Applet / bridge operations.
pub const OP_APPLET_DESCRIBE: &str = "ak.edge.applet.query.describe";
pub const OP_APPLET_PING: &str = "ak.edge.applet.query.ping";
pub const OP_APPLET_PROTOCOL_METADATA: &str = "ak.edge.applet.query.protocol_metadata";
pub const OP_APPLET_RESOLVE_ACTOR: &str = "ak.edge.applet.actor.query.resolve";
pub const OP_APPLET_RESOLVE_REALM: &str = "ak.edge.applet.realm.query.resolve";
pub const OP_APPLET_THIRD_PARTY_LOCATIONS: &str = "ak.edge.applet.third_party_locations.query.list";
pub const OP_APPLET_THIRD_PARTY_USERS: &str = "ak.edge.applet.third_party_users.query.list";
pub const OP_APPLET_TRANSACTION: &str = "ak.edge.applet.command.transaction";

/// Applet protocol-session sub-events (round 13, 2026-05-16). Spec
/// `extensions/applet-integration.md` event-kind-registry rows. These
/// are durable reducer-input events (distinct from the RPC-style
/// `OP_APPLET_DESCRIBE` / `_PING` / `_TRANSACTION` ops above). SDK
/// reducer doesn't maintain per-session state — the applet bridge
/// state machine lives client-side — but operation-registry must
/// carry the required-fields shapes for downstream submit validation.
pub const OP_APPLET_BRIDGE_ERROR: &str = "ak.applet.bridge_error";
pub const OP_APPLET_DISCOVERY: &str = "ak.applet.discovery";
pub const OP_APPLET_INTEROP_SESSION_START: &str = "ak.applet.interop_session.start";
pub const OP_APPLET_INTEROP_SESSION_STATUS: &str = "ak.applet.interop_session.status";
pub const OP_APPLET_REGISTRATION: &str = "ak.applet.registration";

/// Agent protocol-session sub-events (round 13). Same shape as the
/// applet family but the terminal `*.result` event carries a signed
/// audit binding. Spec `extensions/agent-integration.md`.
pub const OP_AGENT_ENDPOINT: &str = "ak.agent.endpoint";
pub const OP_AGENT_KEY_AUTHORIZE: &str = "ak.agent.key.authorize";
pub const OP_AGENT_KEY_REVOKE: &str = "ak.agent.key.revoke";
pub const OP_AGENT_KEY_ROTATE: &str = "ak.agent.key.rotate";
pub const OP_AGENT_INTEROP_SESSION_RESULT: &str = "ak.agent.interop_session.result";
pub const OP_AGENT_INTEROP_SESSION_START: &str = "ak.agent.interop_session.start";
pub const OP_AGENT_INTEROP_SESSION_STATUS: &str = "ak.agent.interop_session.status";

/// Directory operations beyond the bare `describe`.
pub const OP_DIRECTORY_PRIVATE_CONTACT_DISCOVERY: &str =
    "ak.find.directory.query.private_contact_discovery";
pub const OP_DIRECTORY_ANNOUNCE: &str = "ak.find.directory.command.announce";
pub const OP_DIRECTORY_RESOLVE_AGENT_SELECTOR: &str =
    "ak.find.directory.query.resolve_agent_selector";
pub const OP_DIRECTORY_RESOLVE_HANDLE: &str = "ak.find.directory.query.resolve_handle";
/// R3.2 (arkret-spec @ b56cab1) — subject/context → current visible
/// handle claims; the inverse of `resolve_handle`.
pub const OP_DIRECTORY_LIST_HANDLES_FOR_SUBJECT: &str =
    "ak.find.directory.query.list_handles_for_subject";
pub const OP_DIRECTORY_RESOLVE_ORGANIZATION: &str = "ak.find.directory.query.resolve_organization";
pub const OP_DIRECTORY_RESOLVE_REALM: &str = "ak.find.directory.query.resolve_realm";
/// R3.3 (CKP-0011, arkret-spec @ cced4b8) — resolve a client-agnostic
/// shareable object address (Realm / Strand / Message) to a preview. Pure ADD;
/// `resolve_realm` is retained and NOT deprecated.
pub const OP_DIRECTORY_RESOLVE_TARGET: &str = "ak.find.directory.query.resolve_target";
pub const OP_DIRECTORY_SEARCH_ACTORS: &str = "ak.find.directory.query.search_actors";
pub const OP_DIRECTORY_SEARCH_ORGANIZATIONS: &str = "ak.find.directory.query.search_organizations";
pub const OP_DIRECTORY_SEARCH_REALMS: &str = "ak.find.directory.query.search_realms";
pub const OP_DIRECTORY_SEARCH_USERS: &str = "ak.find.directory.query.search_users";
pub const OP_DIRECTORY_PUSH_REGISTER: &str = "ak.find.directory.push.command.register";
pub const OP_DIRECTORY_WITHDRAW: &str = "ak.find.directory.command.withdraw";

/// Events-API operations (low-level Event Envelope plane).
pub const OP_EVENTS_RESOLVE: &str = "ak.self.events.query.resolve";
pub const OP_EVENTS_DESCRIBE: &str = "ak.self.events.query.describe";
pub const OP_EVENTS_FRONTIER: &str = "ak.self.events.query.frontier";
pub const OP_EVENTS_GET: &str = "ak.self.events.resource.get";
pub const OP_EVENTS_QUERY: &str = "ak.self.events.query.scan";
/// Round C44 (2026-05-18; spec dc01ad7) — POST variant of
/// `ck.self.events.query.scan` for selectors too long to fit in a `GET` query
/// string (large `spaces[]` / `actors[]` unions). HTTP path:
/// `POST /events/query`. Identical selector / range / response shape.
pub const OP_EVENTS_QUERY_POST: &str = "ak.self.events.query.scan_body";
// DRIFT-ALLOW: constant declaring the operation-id string, not a payload type.
pub const OP_EVENTS_SUBSCRIBE: &str = "ak.self.events.stream.subscribe";
pub const OP_EVENTS_SUBMIT: &str = "ak.self.events.command.submit";
pub const SERVICE_SCOPE_SELF_EVENTS_QUERY_DESCRIBE: &str = OP_EVENTS_DESCRIBE;
pub const SERVICE_SCOPE_SELF_EVENTS_QUERY_SCAN: &str = OP_EVENTS_QUERY;
pub const SERVICE_SCOPE_SELF_EVENTS_STREAM_SUBSCRIBE: &str = OP_EVENTS_SUBSCRIBE;
pub const SERVICE_SCOPE_SELF_EVENTS_QUERY_FRONTIER: &str = OP_EVENTS_FRONTIER;
pub const SERVICE_SCOPE_SELF_EVENTS_RESOURCE_GET: &str = OP_EVENTS_GET;
pub const SERVICE_SCOPE_SELF_EVENTS_COMMAND_SUBMIT: &str = OP_EVENTS_SUBMIT;
pub const PERSONAL_AGENT_RUNTIME_EVENT_SERVICE_SCOPES: &[&str] = &[
    SERVICE_SCOPE_SELF_EVENTS_QUERY_DESCRIBE,
    SERVICE_SCOPE_SELF_EVENTS_QUERY_SCAN,
    SERVICE_SCOPE_SELF_EVENTS_STREAM_SUBSCRIBE,
    SERVICE_SCOPE_SELF_EVENTS_QUERY_FRONTIER,
    SERVICE_SCOPE_SELF_EVENTS_RESOURCE_GET,
    SERVICE_SCOPE_SELF_EVENTS_COMMAND_SUBMIT,
];

pub fn is_personal_agent_runtime_event_service_scope(scope: &str) -> bool {
    matches!(
        scope,
        SERVICE_SCOPE_SELF_EVENTS_QUERY_DESCRIBE
            | SERVICE_SCOPE_SELF_EVENTS_QUERY_SCAN
            | SERVICE_SCOPE_SELF_EVENTS_STREAM_SUBSCRIBE
            | SERVICE_SCOPE_SELF_EVENTS_QUERY_FRONTIER
            | SERVICE_SCOPE_SELF_EVENTS_RESOURCE_GET
            | SERVICE_SCOPE_SELF_EVENTS_COMMAND_SUBMIT
    )
}
pub const OP_EPHEMERAL_SEND: &str = "ak.self.ephemeral.command.send";

/// Contact and direct-conversation operations.
pub const OP_CONTACT_REQUEST: &str = "ak.self.contact.command.request";
pub const OP_CONTACT_RESPOND: &str = "ak.self.contact.command.respond";
pub const OP_CONTACT_LIST: &str = "ak.self.contact.query.list";
pub const OP_CONTACT_TOMBSTONE: &str = "ak.self.contact.command.tombstone";
pub const OP_DIRECT_CONVERSATION_RESOLVE: &str = "ak.self.direct_conversation.command.resolve";

/// Account-private data operations.
pub const OP_SELF_ACCOUNT_DATA_LIST: &str = "ak.self.account_data.query.list";
pub const OP_SELF_ACCOUNT_DATA_GET: &str = "ak.self.account_data.resource.get";
pub const OP_SELF_ACCOUNT_DATA_REPLACE: &str = "ak.self.account_data.resource.replace";
pub const OP_SELF_ACCOUNT_DATA_DELETE: &str = "ak.self.account_data.resource.delete";

/// Holder-private consent operations.
pub const OP_SELF_CONSENT_LIST: &str = "ak.self.consent.query.list";
pub const OP_SELF_CONSENT_GET: &str = "ak.self.consent.resource.get";
pub const OP_SELF_CONSENT_GRANT: &str = "ak.self.consent.command.grant";
pub const OP_SELF_CONSENT_REVOKE: &str = "ak.self.consent.command.revoke";
pub const OP_SELF_CONSENT_REQUEST: &str = "ak.self.consent.command.request";

/// Read cursor self-service operations.
pub const OP_SELF_READ_CURSOR_ADVANCE: &str = "ak.self.read_cursor.command.advance";
pub const OP_SELF_READ_CURSOR_LIST: &str = "ak.self.read_cursor.query.list";

/// Circle self-service operations.
pub const OP_SELF_CIRCLE_CREATE: &str = "ak.self.circle.command.create";
pub const OP_SELF_CIRCLE_LIST: &str = "ak.self.circle.query.list";
pub const OP_SELF_CIRCLE_GET: &str = "ak.self.circle.resource.get";
pub const OP_SELF_CIRCLE_MEMBER_ADD: &str = "ak.self.circle.member.command.add";
pub const OP_SELF_CIRCLE_MEMBER_DELETE: &str = "ak.self.circle.member.resource.delete";
pub const OP_SELF_CIRCLE_ROTATE_SCOPE: &str = "ak.self.circle.command.rotate_scope";
pub const OP_SELF_CIRCLE_ARCHIVE: &str = "ak.self.circle.command.archive";
pub const OP_SELF_CIRCLE_RESTORE: &str = "ak.self.circle.command.restore";
pub const OP_SELF_CIRCLE_TOMBSTONE: &str = "ak.self.circle.command.tombstone";

/// Realm-scoped object read-model operations.
pub const OP_SPACE_QUERY_LIST: &str = "ak.self.space.query.list";
pub const OP_STRAND_QUERY_LIST: &str = "ak.self.strand.query.list";
pub const OP_MORPH_QUERY_LIST: &str = "ak.self.morph.query.list";
pub const OP_MORPH_RESOURCE_GET: &str = "ak.self.morph.resource.get";
pub const OP_VIEW_COLLECTION_PROJECTION: &str =
    "ak.self.views.collection_projection.command.materialize";
pub const OP_SELF_REALM_LINK_LIST: &str = "ak.self.realm_link.query.list";
pub const OP_SELF_REALM_LINK_CREATE: &str = "ak.self.realm_link.command.create";
pub const OP_SELF_REALM_LINK_DELETE: &str = "ak.self.realm_link.resource.delete";
pub const OP_SELF_REALM_LINK_EFFECTIVE_POLICY: &str = "ak.self.realm_link.query.effective_policy";
pub const OP_SELF_REALM_ORGANIZATION_LIST: &str = "ak.self.realm_organization.query.list";
pub const OP_SELF_REALM_POLICY_SERVER_GET: &str = "ak.self.realm_policy_server.resource.get";
pub const OP_SELF_REALM_POLICY_SERVER_REPLACE: &str =
    "ak.self.realm_policy_server.resource.replace";
pub const OP_SELF_REALM_POLICY_SERVER_DELETE: &str = "ak.self.realm_policy_server.resource.delete";
pub const OP_SELF_REALM_GET: &str = "ak.self.realm.resource.get";
pub const OP_SELF_REALM_ARCHIVE: &str = "ak.self.realm.command.archive";
pub const OP_SELF_REALM_FREEZE: &str = "ak.self.realm.command.freeze";
pub const OP_SELF_REALM_TOMBSTONE: &str = "ak.self.realm.command.tombstone";
pub const OP_SELF_REALM_DESTROY: &str = "ak.self.realm.command.destroy";
pub const OP_SELF_REALM_EXPORT: &str = "ak.self.realm.query.export";
pub const OP_SELF_REALM_MODERATION_POLICY_EFFECTIVE: &str =
    "ak.self.realm.moderation_policy.query.effective";
pub const OP_SELF_REALM_MODERATION_POLICY_REPLACE: &str =
    "ak.self.realm.moderation_policy.resource.replace";

/// Identity-registry operations.
pub const OP_IDENTITY_DESCRIBE_REGISTRY: &str = "ak.root.identity.registry.query.describe";
pub const OP_IDENTITY_GET_DOCUMENT: &str = "ak.root.identity.document.resource.get";
pub const OP_IDENTITY_GET_LOG: &str = "ak.root.identity.log.query.list";
pub const OP_IDENTITY_GET_RECEIPTS: &str = "ak.root.identity.receipts.query.list";
pub const OP_IDENTITY_RECOVERY_POLICY_GET: &str = "ak.root.identity.recovery_policy.resource.get";
pub const OP_IDENTITY_RECOVERY_POLICY_PUT: &str =
    "ak.root.identity.recovery_policy.command.publish";
pub const OP_IDENTITY_SUBMIT_DID_OPERATION: &str = "ak.root.identity.command.submit_did_operation";

/// Media / WebRTC ICE config.
pub const OP_MEDIA_ICE_CONFIG: &str = "ak.self.media.query.ice_config";

/// MIMI provider-facade operations.
pub const OP_MIMI_GROUP_INFO: &str = "ak.open.mimi.query.group_info";
pub const OP_MIMI_IDENTIFIER_QUERY: &str = "ak.open.mimi.query.identifiers";
pub const OP_MIMI_KEY_MATERIAL: &str = "ak.open.mimi.exchange.request_key_material";
pub const OP_MIMI_NOTIFY: &str = "ak.open.mimi.command.notify";
pub const OP_MIMI_PROVIDER_DIRECTORY: &str = "ak.open.mimi.query.provider_directory";
pub const OP_MIMI_PROXY_DOWNLOAD: &str = "ak.open.mimi.command.proxy_download";
pub const OP_MIMI_REPORT_ABUSE: &str = "ak.open.mimi.command.report_abuse";
pub const OP_MIMI_REQUEST_CONSENT: &str = "ak.open.mimi.command.request_consent";
pub const OP_MIMI_ROOM_UPDATE: &str = "ak.open.mimi.command.update_room";
pub const OP_MIMI_SUBMIT_MESSAGE: &str = "ak.open.mimi.command.submit_message";
pub const OP_MIMI_UPDATE_CONSENT: &str = "ak.open.mimi.command.update_consent";

/// Moderation report submission.
pub const OP_MODERATION_REPORT: &str = "ak.self.moderation.command.report";

/// Round R2/R3 (2026-05-20) — capability actions for the moderation appeal
/// strand. `submit` is low-risk (any member may appeal); `review` is
/// medium-risk and gates the review / decision / close transitions.
/// Spec: capability-action-registry.json.
pub const CAP_ACTION_MODERATION_APPEAL_SUBMIT: &str = "ak.moderation.appeal.submit";
pub const CAP_ACTION_MODERATION_APPEAL_REVIEW: &str = "ak.moderation.appeal.review";

/// Round 4 (2026-05-20, spec a77b995) — capability action gating Morph
/// creation. Medium risk; the spec
/// `capability-action-registry.json` declares `required_constraints=[allowed_morph_types]`.
pub const CAP_ACTION_MORPH_CREATE: &str = "ak.morph.create";

/// CKP-0010 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) — call /
/// media capability actions registered in
/// `capability-action-registry.json`. These actions gate the join,
/// screen-share, recording, transcription, moderation, and signal-send
/// surfaces of the ck.call.* feature.
pub const CAP_ACTION_CALL_JOIN: &str = "ak.call.join";
pub const CAP_ACTION_CALL_SCREEN_SHARE: &str = "ak.call.screen_share";
pub const CAP_ACTION_CALL_RECORD: &str = "ak.call.record";
pub const CAP_ACTION_CALL_TRANSCRIBE: &str = "ak.call.transcribe";
pub const CAP_ACTION_CALL_MODERATE: &str = "ak.call.moderate";
/// `service-http-binding.md` §162 — sending a `ck.call.signal` ephemeral
/// envelope via `POST /_arkret/self/ephemeral` requires the actor to hold
/// this realm-scoped capability. Registered in
/// `capability-action-registry.json`.
pub const CAP_CALL_SIGNAL_SEND: &str = "ak.call.signal.send";

/// CKP-0010 — full call/media capability-action list.
pub const CALL_CAPABILITY_ACTIONS: &[&str] = &[
    CAP_ACTION_CALL_JOIN,
    CAP_ACTION_CALL_SCREEN_SHARE,
    CAP_ACTION_CALL_RECORD,
    CAP_ACTION_CALL_TRANSCRIBE,
    CAP_ACTION_CALL_MODERATE,
    CAP_CALL_SIGNAL_SEND,
];

/// CKP-0010 — `ck.self.call.media.exchange.issue_token` operation id. HTTP route:
/// `POST /rtc/token`. Surface tier `core_personal`. Registered in
/// `operation-registry.json` v2026-05-27.
pub const OP_CALL_MEDIA_TOKEN_EXCHANGE: &str = "ak.self.call.media.exchange.issue_token";

/// CKP-0010 — schema id for the participant_binding signing envelope.
pub const PARTICIPANT_BINDING_SCHEMA: &str = "ak.media.participant_binding.v1";

/// CKP-0010 — maximum TTL bound for media tokens (600 seconds). Tokens
/// MUST be rejected when `expires_at - now > 600s`. SHOULD floor: 300s.
pub const MEDIA_TOKEN_TTL_MAX_SECS: u64 = 600;
/// CKP-0010 — SHOULD-bound (recommended) TTL for media tokens.
pub const MEDIA_TOKEN_TTL_SHOULD_SECS: u64 = 300;

/// MLS exporter label for the per-call recording artifact key
/// (`call-state.md` §5). Used as the `scheme` of the recording blob's
/// encryption descriptor.
pub const EXPORTER_LABEL_RTC_RECORDING_KEY: &str = "ak.rtc-recording-key/v1";
/// MLS exporter label for the per-call transcription artifact key
/// (`call-state.md` §5.1). Mirrors the recording-key label for the
/// transcription pipeline.
pub const EXPORTER_LABEL_RTC_TRANSCRIPT_KEY: &str = "ak.rtc-transcript-key/v1";

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
/// hangup, ack`) is replaced by this 14-value set. Spec
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
pub const CALL_SIGNAL_TYPE_MODERATION: &str = "moderation";
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
    CALL_SIGNAL_TYPE_MODERATION,
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
pub const OP_POLICY_CHECK: &str = "ak.self.policy.query.check";

/// Push gateway register / unregister.
pub const OP_PUSH_REGISTER_DEVICE: &str = "ak.edge.push.command.register_device";
pub const OP_PUSH_UNREGISTER_DEVICE: &str = "ak.edge.push.command.unregister_device";

/// Account aggregate stream and snapshot head.
pub const OP_ACCOUNT_SUBSCRIBE: &str = "ak.self.account.stream.subscribe";
pub const OP_SNAPSHOT_HEAD: &str = "ak.self.snapshot.query.manifest_head";

// Spec-sync (operation-registry.json) — service operations the registry ships
// that the SDK had not yet enumerated. Trust-surface segments: `gate` =
// pre-auth account onboarding, `self` = authenticated account-scoped surface,
// `peer` = inter-principal-server federation surface, `root` = identity-root
// recovery surface.
pub const OP_ACCOUNT_REGISTER: &str = "ak.gate.account.command.register";
pub const OP_ACCOUNT_SESSION_REVOKE: &str = "ak.gate.account.command.revoke_session";
pub const OP_ACCOUNT_SESSION_GRANT_REFRESH: &str = "ak.gate.account.command.refresh_session_grant";
pub const OP_ACCOUNT_AUTH_SESSION_LOGOUT: &str = "ak.gate.account.command.logout_auth_session";
pub const OP_ACCOUNT_SESSION_GRANT_INTROSPECT: &str =
    "ak.gate.account.command.introspect_session_grant";
pub const OP_ACCOUNT_LOGOUT: &str = "ak.gate.account.command.logout";
pub const OP_ACCOUNT_UPDATE_PROFILE: &str = "ak.self.account.command.update_profile";
pub const OP_ACCOUNT_VIEWER: &str = "ak.self.account.query.viewer";
pub const OP_AGENT_PARTICIPATION_GET: &str = "ak.self.agent.participation.resource.get";
pub const OP_AGENT_PARTICIPATION_SET: &str = "ak.self.agent.participation.resource.replace";
pub const OP_APPLET_INSTALL: &str = "ak.self.applet.command.install";
pub const OP_APPLET_INSTALL_PREVIEW: &str = "ak.self.applet.install.command.preview";
pub const OP_APPLET_GHOST_PROVISION: &str = "ak.self.applet.ghost.command.provision";
pub const OP_APPLET_REVOKE: &str = "ak.self.applet.command.revoke";
pub const OP_INVITE_RECEIVE_POLICY_GET: &str = "ak.self.invite_receive_policy.resource.get";
pub const OP_INVITE_RECEIVE_POLICY_SET: &str = "ak.self.invite_receive_policy.resource.replace";
pub const OP_PEER_CONTACTS_SUBMIT: &str = "ak.peer.contacts.command.submit";
pub const OP_PEER_EVENTS_DESCRIBE: &str = "ak.peer.events.query.describe";
pub const OP_PEER_EVENTS_FRONTIER: &str = "ak.peer.events.query.frontier";
pub const OP_PEER_EVENTS_QUERY: &str = "ak.peer.events.query.scan";
pub const OP_PEER_EVENTS_QUERY_POST: &str = "ak.peer.events.query.scan_body";
pub const OP_PEER_EVENTS_RESOLVE: &str = "ak.peer.events.query.resolve";
pub const OP_PEER_EVENTS_SUBMIT: &str = "ak.peer.events.command.submit";
pub const OP_PEER_SNAPSHOT_HEAD: &str = "ak.peer.snapshot.query.manifest_head";
pub const OP_RECOVERY_SESSION_COMPLETE: &str = "ak.root.identity.recovery_session.command.complete";
pub const OP_RECOVERY_SESSION_CREATE: &str = "ak.root.identity.recovery_session.command.create";
pub const OP_RECOVERY_SESSION_GET: &str = "ak.root.identity.recovery_session.resource.get";
pub const OP_RECOVERY_SESSION_SUBMIT_PROOF: &str =
    "ak.root.identity.recovery_session.command.submit_proof";
/// `POST /_arkret/self/agents/discover` — probe the `ck.agent.endpoint`
/// registry; authorized by `ck.agent.protocol.discover` capability under
/// `ck.profile.agent_runtime.v1`.
pub const OP_SELF_AGENT_PROTOCOL_DISCOVER: &str = "ak.self.agent.protocol.query.discover";
/// `POST /_arkret/find/directory/takedown/appeal` — resource-side appeal of an
/// operator takedown; returns a signed adjudication receipt.
pub const OP_DIRECTORY_TAKEDOWN_APPEAL: &str = "ak.find.directory.command.takedown_appeal";

/// Canonical service operation IDs built into this SDK.
///
/// Event kinds live in `crate::events`; this list mirrors the spec
/// `operation-registry.json` service surface.
pub const BUILT_IN_OPERATION_KINDS: &[&str] = &[
    OP_ACCOUNT_AGENT_KEY_PAIR,
    OP_OPEN_AGENT_PAIRING_SUBMIT_RUNTIME_KEY_REQUEST,
    OP_ACCOUNT_DESCRIBE,
    OP_ACCOUNT_DEVICE_PAIR,
    OP_ACCOUNT_DEVICE_ENROLL,
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
    OP_APPLET_DESCRIBE,
    OP_APPLET_PING,
    OP_APPLET_PROTOCOL_METADATA,
    OP_APPLET_RESOLVE_ACTOR,
    OP_APPLET_RESOLVE_REALM,
    OP_APPLET_THIRD_PARTY_LOCATIONS,
    OP_APPLET_THIRD_PARTY_USERS,
    OP_APPLET_TRANSACTION,
    // Note: OP_APPLET_REGISTRATION / OP_APPLET_DISCOVERY / OP_APPLET_INTEROP_SESSION_*
    // / OP_APPLET_BRIDGE_ERROR and OP_AGENT_* are reducer-input EVENTS
    // (registered in spec `event-kind-registry.json`), not service RPC
    // operations. They follow the same `OP_*` const naming for
    // ergonomic dispatch in registry.rs::required_fields_for_operation_kind
    // but are intentionally NOT in BUILT_IN_OPERATION_KINDS — that list
    // mirrors spec `operation-registry.json` (RPC service surface) and
    // the drift report (`SpecArtifactBundle::drift_report`) fails if
    // event kinds leak in. Same convention as the lifecycle event ops
    // (`OP_STRAND_CREATE`, etc.).
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
    OP_DEVICE_MESSAGES_ACK,
    OP_DIRECTORY_ANNOUNCE,
    OP_SERVER_DESCRIBE,
    OP_DIRECTORY_DESCRIBE,
    OP_DIRECTORY_PRIVATE_CONTACT_DISCOVERY,
    OP_DIRECTORY_RESOLVE_AGENT_SELECTOR,
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
    OP_SPACE_QUERY_LIST,
    OP_STRAND_QUERY_LIST,
    OP_MORPH_QUERY_LIST,
    OP_MORPH_RESOURCE_GET,
    OP_VIEW_COLLECTION_PROJECTION,
    OP_IDENTITY_DESCRIBE_REGISTRY,
    OP_IDENTITY_GET_DOCUMENT,
    OP_IDENTITY_GET_LOG,
    OP_IDENTITY_GET_RECEIPTS,
    OP_IDENTITY_RECOVERY_POLICY_GET,
    OP_IDENTITY_RECOVERY_POLICY_PUT,
    OP_IDENTITY_RESOLVE,
    OP_IDENTITY_SUBMIT_DID_OPERATION,
    OP_KEYS_BACKUPS_DELETE,
    OP_KEYS_BACKUPS_LIST,
    OP_KEYS_BACKUPS_PUT,
    OP_KEYS_BACKUPS_UNLOCK,
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
    // Spec-sync (operation-registry.json) additions.
    OP_ACCOUNT_REGISTER,
    OP_ACCOUNT_SESSION_REVOKE,
    OP_ACCOUNT_SESSION_GRANT_REFRESH,
    OP_ACCOUNT_AUTH_SESSION_LOGOUT,
    OP_ACCOUNT_SESSION_GRANT_INTROSPECT,
    OP_ACCOUNT_LOGOUT,
    OP_ACCOUNT_UPDATE_PROFILE,
    OP_ACCOUNT_VIEWER,
    OP_SELF_ACCOUNT_DATA_LIST,
    OP_SELF_ACCOUNT_DATA_GET,
    OP_SELF_ACCOUNT_DATA_REPLACE,
    OP_SELF_ACCOUNT_DATA_DELETE,
    OP_AGENT_PARTICIPATION_GET,
    OP_AGENT_PARTICIPATION_SET,
    OP_APPLET_INSTALL,
    OP_APPLET_INSTALL_PREVIEW,
    OP_APPLET_GHOST_PROVISION,
    OP_APPLET_REVOKE,
    OP_CONTACT_LIST,
    OP_CONTACT_REQUEST,
    OP_CONTACT_RESPOND,
    OP_CONTACT_TOMBSTONE,
    OP_DIRECT_CONVERSATION_RESOLVE,
    OP_SELF_CONSENT_LIST,
    OP_SELF_CONSENT_GET,
    OP_SELF_CONSENT_GRANT,
    OP_SELF_CONSENT_REVOKE,
    OP_SELF_CONSENT_REQUEST,
    OP_SELF_READ_CURSOR_ADVANCE,
    OP_SELF_READ_CURSOR_LIST,
    OP_SELF_CIRCLE_CREATE,
    OP_SELF_CIRCLE_LIST,
    OP_SELF_CIRCLE_GET,
    OP_SELF_CIRCLE_MEMBER_ADD,
    OP_SELF_CIRCLE_MEMBER_DELETE,
    OP_SELF_CIRCLE_ROTATE_SCOPE,
    OP_SELF_CIRCLE_ARCHIVE,
    OP_SELF_CIRCLE_RESTORE,
    OP_SELF_CIRCLE_TOMBSTONE,
    OP_SELF_REALM_LINK_LIST,
    OP_SELF_REALM_LINK_CREATE,
    OP_SELF_REALM_LINK_DELETE,
    OP_SELF_REALM_LINK_EFFECTIVE_POLICY,
    OP_SELF_REALM_ORGANIZATION_LIST,
    OP_SELF_REALM_POLICY_SERVER_GET,
    OP_SELF_REALM_POLICY_SERVER_REPLACE,
    OP_SELF_REALM_POLICY_SERVER_DELETE,
    OP_SELF_REALM_GET,
    OP_SELF_REALM_ARCHIVE,
    OP_SELF_REALM_FREEZE,
    OP_SELF_REALM_TOMBSTONE,
    OP_SELF_REALM_DESTROY,
    OP_SELF_REALM_EXPORT,
    OP_SELF_REALM_MODERATION_POLICY_EFFECTIVE,
    OP_SELF_REALM_MODERATION_POLICY_REPLACE,
    OP_INVITE_RECEIVE_POLICY_GET,
    OP_INVITE_RECEIVE_POLICY_SET,
    OP_PEER_CONTACTS_SUBMIT,
    OP_PEER_EVENTS_DESCRIBE,
    OP_PEER_EVENTS_FRONTIER,
    OP_PEER_EVENTS_QUERY,
    OP_PEER_EVENTS_QUERY_POST,
    OP_PEER_EVENTS_RESOLVE,
    OP_PEER_EVENTS_SUBMIT,
    OP_PEER_SNAPSHOT_HEAD,
    OP_RECOVERY_SESSION_COMPLETE,
    OP_RECOVERY_SESSION_CREATE,
    OP_RECOVERY_SESSION_GET,
    OP_RECOVERY_SESSION_SUBMIT_PROOF,
    OP_SELF_AGENT_PROTOCOL_DISCOVER,
    OP_DIRECTORY_TAKEDOWN_APPEAL,
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
            &["ak.message.create"]
        );
    }

    #[test]
    fn agent_sidecar_home_prefers_context_realm() {
        assert_eq!(
            select_agent_sidecar_home_realm(Some("ak:realm:context"), "ak:realm:home"),
            Some("ak:realm:context")
        );
        assert_eq!(select_agent_sidecar_home_realm(None, "ak:realm:home"), None);
    }

    #[test]
    fn agent_sidecar_circle_key_is_stable_and_short_name_derives() {
        let key = agent_sidecar_circle_key(
            "ak:realm:context",
            "did:webvh:z6mkfixture:example.com:users:alice",
        );
        assert_eq!(key.len(), 24);
        assert!(
            key.chars()
                .all(|ch| { ch.is_ascii_lowercase() || matches!(ch, '2'..='7') })
        );
        assert_eq!(
            agent_sidecar_short_name(&key),
            format!("AI-{}", key[..12].to_ascii_uppercase())
        );
    }

    #[test]
    fn reviewed_capability_action_definitions_cover_randmon_sample() {
        let strand_update = capability_action_definition(CAP_ACTION_STRAND_UPDATE)
            .expect("ak.strand.update definition");
        assert_eq!(strand_update.risk_tier, CapabilityRiskTier::Medium);
        assert_eq!(
            capability_action_required_constraints(CAP_ACTION_STRAND_UPDATE),
            &[CAP_CONSTRAINT_ALLOWED_WRITE_FIELDS]
        );
        assert_eq!(
            capability_action_target_event_kinds(CAP_ACTION_STRAND_UPDATE),
            &[OP_STRAND_UPDATE]
        );

        assert_eq!(
            capability_action_target_event_kinds(CAP_ACTION_OBJECT_ARCHIVE),
            &[OP_STRAND_ARCHIVE, OP_MORPH_ARCHIVE]
        );
        assert!(capability_action_target_event_kinds(CAP_ACTION_APPROVAL_VOTE).is_empty());
        assert!(capability_action_definition("ak.unknown.action").is_none());
    }
}
