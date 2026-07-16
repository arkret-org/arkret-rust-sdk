use crate::ServiceOperationId;

/// Service operations for which this SDK ships generated route and metadata support.
pub const SUPPORTED_OPERATION_IDS: &[ServiceOperationId] = ServiceOperationId::ALL;

pub const PROTOCOL_VERSION: &str = "1.0";
pub const CORE_SCHEMA_PROFILE: &str = "ak.schema.core.v1";
pub const CORE_REDUCER_PROFILE: &str = "ak.reducer.v1";
pub const BUILT_IN_CONFORMANCE_FIXTURES_VERSION: &str = "arkret-sdk-builtin-v1";

pub const CURSOR_SCHEMA: &str = "ak.schema.cursor.v1";
// Realm/Space schema ids:
//   - `ak.schema.realm.v1` is the security-boundary schema.
//   - `ak.schema.space.v1` is the product container schema.
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
/// AKP-0007 (2026-05-08) — Circle object schema id. See spec
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
pub const PRINCIPAL_LOCATOR_SCHEMA: &str = "ak.schema.principal_locator.v1";
pub const INVITE_DELIVERY_REQUEST_SCHEMA: &str = "ak.schema.invite_delivery_request.v1";
pub const INVITE_RECEIVE_POLICY_SCHEMA: &str = "ak.schema.invite_receive_policy.v1";

pub const PROFILE_DIRECTORY_SERVICE: &str = "ak.profile.directory_service.v1";
pub const PROFILE_E2EE_CLIENT: &str = "ak.profile.e2ee_client.v1";
pub const PROFILE_MLS_MINIMAL_METADATA_REALM: &str = "ak.profile.mls.minimal_metadata_realm.v1";
pub const PROFILE_ATTESTED_AUDIT_E2EE: &str = "ak.profile.attested_audit.e2ee.v1";
pub const PROFILE_DISCLOSED_AUDIT_E2EE: &str = "ak.profile.disclosed_audit.e2ee.v1";

// Round R2/R3 (2026-05-20) — new schema ids for the moderation appeal strand,
// the broadcast ephemeral envelope, and structured attestation evidence.
pub const EPHEMERAL_ENVELOPE_SCHEMA: &str = "ak.schema.ephemeral_envelope.v1";
pub const MODERATION_APPEAL_SCHEMA: &str = "ak.schema.moderation_appeal.v1";
pub const ATTESTATION_EVIDENCE_SCHEMA: &str = "ak.schema.attestation_evidence.v1";
pub const CROSS_SIGNING_RESET_SCHEMA: &str = "ak.schema.cross_signing_reset.v1";

// ── Canonical ak.* event kinds ──────────────────────────────────────────────
/// Strand event kinds.

/// AKP-0007 (spec b7d35be) — Circle event kinds. The 7th kind
/// (`ak.circle.seal_commit`) is reducer-derived and MUST NOT be
/// submitted by clients; it is exported for receiver-side dispatch only.

/// AKP-0007 (spec b7d35be) — Circle capability action ids. Spec
/// `capability-action-registry.json`. `ak.circle.manage`,
/// `ak.circle.member.manage`, `ak.circle.member.add.others`, and
/// `ak.circle.audit` declare `required_constraints=["allowed_circle_ids"]`;
/// unconstrained Realm-wide grants for those actions MUST be rejected.
pub const CAP_ACTION_CIRCLE_CREATE: &str = "ak.circle.create";
pub const CAP_ACTION_CIRCLE_MANAGE: &str = "ak.circle.manage";
pub const CAP_ACTION_CIRCLE_MEMBER_ADD: &str = "ak.circle.member.add";
pub const CAP_ACTION_CIRCLE_MEMBER_MANAGE: &str = "ak.circle.member.manage";
pub const CAP_ACTION_CIRCLE_MEMBER_ADD_OTHERS: &str = "ak.circle.member.add.others";
pub const CAP_ACTION_CIRCLE_AUDIT: &str = "ak.circle.audit";

/// AKP-0007 capability action list (6 actions). Useful for downstream
/// services that want to iterate the Circle-management surface.
pub const CIRCLE_CAPABILITY_ACTIONS: &[&str] = &[
    CAP_ACTION_CIRCLE_CREATE,
    CAP_ACTION_CIRCLE_MANAGE,
    CAP_ACTION_CIRCLE_MEMBER_ADD,
    CAP_ACTION_CIRCLE_MEMBER_MANAGE,
    CAP_ACTION_CIRCLE_MEMBER_ADD_OTHERS,
    CAP_ACTION_CIRCLE_AUDIT,
];

/// AKP-0008 / AKP-0009 (spec head 37ce729) — personal-agent capability actions
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

/// AKP-0008 / AKP-0009 — full capability-action list (11 base + 3 aggregate
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

/// AKP-0008 / AKP-0009 — personal-agent operation IDs (registered in
/// `operation-registry.json`). Used by the RPC dispatch layer; reducer-input
/// agent lifecycle events are registered separately under `AGENT_*`
/// event-kind constants above.

/// AKP-0008 / AKP-0009 — controller-private account-data types. Reducer
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

/// AKP-0008 / AKP-0009 — agent sidecar thread profile id.
///
/// Per AKP-0009, the sidecar home is derived from `context_ref.realm_id`.
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

pub fn agent_sidecar_circle_key(realm_id: &str, controller_id: &str) -> String {
    let transcript = format!("ak.agent_sidecar_circle.v1\n{realm_id}\n{controller_id}");
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

/// Space (container) event kinds. Container events use `ak.space.*`; see the
/// security-boundary OP_REALM_* family for `ak.realm.*` events.

/// Relation event kinds.

/// View event kinds.

/// Realm event kinds (security boundary). The container-level OP_SPACE_* family
/// lives above.

/// Per-Realm governance of member `delivery_binding`: which `binding_source`
/// values are admissible, which recipient services are allowed, whether DID
/// Document fallback is permitted, who may sign rebind. cell_family
/// `ak.component.realm.delivery_binding_policy.v1`, cas-register.

/// Device event kinds.
///
/// Round C45 (2026-05-19; spec 0a5ab85) — actor-private push route binding
/// for the composite tuple `(recipient_service_id, principal, device,
/// push_route)`. MUST NOT be replicated outside the binding's
/// recipient_service_id context.

/// Message event kinds.

/// High-risk capability required in addition to `ak.message.create` or
/// `ak.message.revise` whenever a Message introduces an `audience_mention`
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

/// Membership and invite event kinds.

/// Server and account/snapshot operations.

/// Directory operations.

/// Blob operations.

/// Round C44 (2026-05-18; spec dc01ad7) — pre-signed blob URL surface.
/// `POST /blob/presign` returns a short-lived put/get URL pair so very
/// large blobs can be uploaded directly to object storage. Full signing
/// enforcement is a server responsibility; SDK only needs the constant for
/// client routing.

/// Push and key operations.

// Renamed from `ak.self.keys.backups.command.unlock` on 2026-06-11
// (artifacts/migration/renames.json): backup retrieval is rebound to
// `POST /_arkret/self/keys/backups/{backup_id}/unlock` with a body-borne
// unlock proof.

/// Authorization check.

/// Account / auth-server operations.

// Admin / operator APIs (moderation queue, server status, device revocation,
// account status) are product-local per spec @ 2026-06-04 and MUST NOT be
// registered under the Arkret protocol namespace; servers expose them on
// their own negative-space root such as /_soland/admin/*. They were removed
// from the operation registry (see migration/removed-operation-ids.json) and
// therefore carry no `OP_ADMIN_*` protocol constants here.

/// Applet / bridge operations.

/// Applet durable event kinds, distinct from the RPC-style applet operations.

/// Directory operations beyond the bare `describe`.

/// R3.2 (arkret-spec @ b56cab1) — subject/context → current visible
/// handle claims; the inverse of `resolve_handle`.

/// R3.3 (AKP-0011, arkret-spec @ cced4b8) — resolve a client-agnostic
/// shareable object address (Realm / Strand / Message) to a preview. Pure ADD;
/// `resolve_realm` is retained and NOT deprecated.

/// Events-API operations (low-level Event Envelope plane).

/// Round C44 (2026-05-18; spec dc01ad7) — POST variant of
/// `ak.self.events.query.scan` for selectors too long to fit in a `GET` query
/// string (large `spaces[]` / `actors[]` unions). HTTP path:
/// `POST /events/query`. Identical selector / range / response shape.

// DRIFT-ALLOW: constant declaring the operation-id string, not a payload type.

pub const SERVICE_SCOPE_SELF_EVENTS_QUERY_DESCRIBE: &str =
    ServiceOperationId::SELF_EVENTS_QUERY_DESCRIBE;
pub const SERVICE_SCOPE_SELF_EVENTS_QUERY_SCAN: &str = ServiceOperationId::SELF_EVENTS_QUERY_SCAN;
pub const SERVICE_SCOPE_SELF_EVENTS_STREAM_SUBSCRIBE: &str =
    ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE;
pub const SERVICE_SCOPE_SELF_EVENTS_QUERY_FRONTIER: &str =
    ServiceOperationId::SELF_EVENTS_QUERY_FRONTIER;
pub const SERVICE_SCOPE_SELF_EVENTS_RESOURCE_GET: &str =
    ServiceOperationId::SELF_EVENTS_RESOURCE_GET;
pub const SERVICE_SCOPE_SELF_EVENTS_COMMAND_SUBMIT: &str =
    ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT;
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

/// Contact and direct-conversation operations.

/// Account-private data operations.

/// Holder-private consent operations.

/// Read cursor self-service operations.

/// Circle self-service operations.

/// Realm-scoped object read-model operations.

/// Identity-registry operations.

/// Media / WebRTC ICE config.

/// MIMI provider-facade operations.

/// Moderation report submission.

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

/// AKP-0010 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) — call /
/// media capability actions registered in
/// `capability-action-registry.json`. These actions gate the join,
/// screen-share, recording, transcription, moderation, and signal-send
/// surfaces of the ak.call.* feature.
pub const CAP_ACTION_CALL_JOIN: &str = "ak.call.join";
pub const CAP_ACTION_CALL_SCREEN_SHARE: &str = "ak.call.screen_share";
pub const CAP_ACTION_CALL_RECORD: &str = "ak.call.record";
pub const CAP_ACTION_CALL_TRANSCRIBE: &str = "ak.call.transcribe";
pub const CAP_ACTION_CALL_MODERATE: &str = "ak.call.moderate";
/// `service-http-binding.md` §162 — sending a `ak.call.signal` ephemeral
/// envelope via `POST /_arkret/self/ephemeral` requires the actor to hold
/// this realm-scoped capability. Registered in
/// `capability-action-registry.json`.
pub const CAP_CALL_SIGNAL_SEND: &str = "ak.call.signal.send";

/// AKP-0010 — full call/media capability-action list.
pub const CALL_CAPABILITY_ACTIONS: &[&str] = &[
    CAP_ACTION_CALL_JOIN,
    CAP_ACTION_CALL_SCREEN_SHARE,
    CAP_ACTION_CALL_RECORD,
    CAP_ACTION_CALL_TRANSCRIBE,
    CAP_ACTION_CALL_MODERATE,
    CAP_CALL_SIGNAL_SEND,
];

/// AKP-0010 — `ak.self.call.media.exchange.issue_token` operation id. HTTP route:
/// `POST /rtc/token`. Surface tier `core_personal`. Registered in
/// `operation-registry.json` v2026-05-27.

/// AKP-0010 — schema id for the participant_binding signing envelope.
pub const PARTICIPANT_BINDING_SCHEMA: &str = "ak.media.participant_binding.v1";

/// AKP-0010 — maximum TTL bound for media tokens (600 seconds). Tokens
/// MUST be rejected when `expires_at - now > 600s`. SHOULD floor: 300s.
pub const MEDIA_TOKEN_TTL_MAX_SECS: u64 = 600;
/// AKP-0010 — SHOULD-bound (recommended) TTL for media tokens.
pub const MEDIA_TOKEN_TTL_SHOULD_SECS: u64 = 300;

/// MLS exporter label for the per-call recording artifact key
/// (`call-state.md` §5). Used as the `scheme` of the recording blob's
/// encryption descriptor.
pub const EXPORTER_LABEL_RTC_RECORDING_KEY: &str = "ak.rtc-recording-key/v1";
/// MLS exporter label for the per-call transcription artifact key
/// (`call-state.md` §5.1). Mirrors the recording-key label for the
/// transcription pipeline.
pub const EXPORTER_LABEL_RTC_TRANSCRIPT_KEY: &str = "ak.rtc-transcript-key/v1";

/// AKP-0008 / AKP-0009 (R3 spec-sync 2026-05-27) — agent_runtime
/// surface tier: list of operations that live under the
/// `ak.profile.agent_runtime.v1` server-profile surface.
pub const AGENT_RUNTIME_SURFACE_OPERATIONS: &[&str] = &[
    ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_AGENT_KEY,
    ServiceOperationId::SELF_AGENT_COMMAND_PROVISION,
    ServiceOperationId::SELF_AGENT_COMMAND_RENEW_PAIRING,
    ServiceOperationId::SELF_AGENT_QUERY_LIST,
    ServiceOperationId::SELF_AGENT_RESOURCE_GET,
    ServiceOperationId::SELF_AGENT_COMMAND_PAUSE,
    ServiceOperationId::SELF_AGENT_COMMAND_RESUME,
    ServiceOperationId::SELF_AGENT_COMMAND_DEACTIVATE,
    ServiceOperationId::SELF_AGENT_GRANT_COMMAND_ATTACH,
    ServiceOperationId::SELF_AGENT_GRANT_RESOURCE_DELETE,
    ServiceOperationId::SELF_AGENT_SIDECAR_THREAD_COMMAND_ENSURE,
];

/// Round 4 (2026-05-20) — canonical signal_type enum values carried in the
/// `ak.call.signal` ephemeral envelope payload. Wire-break: the
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

/// All canonical `ak.call.signal` signal_type values. Round 4 (spec a77b995).
/// Receivers MUST reject any envelope whose `payload.signal_type` is not in
/// this set with `crate::ErrorCode::SCHEMA_VIOLATION`.
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

/// Push gateway register / unregister.

/// Account aggregate stream and snapshot head.

// Spec-sync (operation-registry.json) — service operations the registry ships
// that the SDK had not yet enumerated. Trust-surface segments: `gate` =
// pre-auth account onboarding, `self` = authenticated account-scoped surface,
// `peer` = inter-principal-server federation surface, `root` = identity-root
// recovery surface.

/// `POST /_arkret/find/directory/takedown/appeal` — resource-side appeal of an
/// operator takedown; returns a signed adjudication receipt.

/// Canonical service operation IDs built into this SDK.
///
/// Event kinds live in `crate::events`; this list mirrors the spec
/// `operation-registry.json` service surface.

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
}
