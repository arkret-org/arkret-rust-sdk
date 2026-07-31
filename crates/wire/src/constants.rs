use crate::{CapabilityActionId, ExporterLabelId, ServiceOperationId};

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
/// `receipt_kind` const value of `read-receipt.schema.json`.
pub const READ_RECEIPT_KIND: &str = "read";
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
pub const KEY_BACKUP_ACTIVE_SERIES_SCHEMA: &str = "ak.schema.key_backup_active_series.v1";
pub const KEY_BACKUP_PLAINTEXT_SCHEMA: &str = "ak.schema.key_backup_plaintext.v1";
pub const KEY_BACKUP_UNLOCK_PROOF_SCHEMA: &str = "ak.schema.key_backup_unlock_proof.v1";
pub const MORPH_SCHEMA: &str = "ak.schema.morph.v1";
/// AKP-0007 (2026-05-08) — Circle object schema id. See spec
/// `artifacts/schemas/circle.schema.json`.
pub const CIRCLE_SCHEMA_ID: &str = "ak.schema.circle.v1";
pub const MORPH_CUSTOMER_RISK_SCHEMA: &str = "ak.schema.morph.customer_risk.v1";
pub const MORPH_CUSTOMER_RISK_EXT_SCHEMA: &str = "ak.schema.morph.customer_risk.ext.v1";
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
pub const ACCOUNTABILITY_GRANT_SCHEMA: &str = "ak.schema.accountability_grant.v1";
pub const ACCOUNT_DATA_ENCRYPTED_VALUE_SCHEMA: &str = "ak.schema.account_data_encrypted_value.v1";
pub const ACCOUNT_DATA_OPERATIONS_SCHEMA: &str = "ak.schema.account_data_operations.v1";
pub const ACCOUNT_OPERATIONS_SCHEMA: &str = "ak.schema.account_operations.v1";
pub const AGENT_OPERATIONS_SCHEMA: &str = "ak.schema.agent_operations.v1";
pub const AGENT_PAIRING_BOOTSTRAP_SCHEMA: &str = "ak.schema.agent_pairing_bootstrap.v1";
pub const AGENT_REQUESTED_SCOPE_DISCLOSURE_SCHEMA: &str =
    "ak.schema.agent_requested_scope_disclosure.v1";
pub const APPLET_SCHEMA: &str = "ak.schema.applet.v1";
/// `schema` const of `applet-ghost-operations.schema.json`
/// `#/$defs/ghost_actor_provision_request_body`. Fixed by the DTO schema rather
/// than registered as a `schema-registry.json` row.
pub const GHOST_ACTOR_PROVISION_REQUEST_SCHEMA: &str = "ak.applet.ghost_actor.provision_request.v1";
pub const APPLET_EDGE_OPERATIONS_SCHEMA: &str = "ak.schema.applet_edge_operations.v1";
pub const APPLET_GHOST_OPERATIONS_SCHEMA: &str = "ak.schema.applet_ghost_operations.v1";
pub const APPLET_INSTALL_OPERATIONS_SCHEMA: &str = "ak.schema.applet_install_operations.v1";
pub const APPLET_INSTALL_PLAN_SCHEMA: &str = "ak.schema.applet_install_plan.v1";
pub const APPLET_PACKAGE_SCHEMA: &str = "ak.schema.applet_package.v1";
pub const APPLET_REGISTRATION_EPOCH_TRANSCRIPT_SCHEMA: &str =
    "ak.schema.applet_registration_epoch_transcript.v1";
pub const APPLET_WIDGET_DECLARATION_SCHEMA: &str = "ak.schema.applet_widget_declaration.v1";
pub const AUDIT_RYW_RECEIPT_SCHEMA: &str = "ak.schema.audit_ryw_receipt.v1";
pub const AUTHZ_OPERATIONS_SCHEMA: &str = "ak.schema.authz_operations.v1";
pub const AVAILABILITY_RECEIPT_SCHEMA: &str = "ak.schema.availability_receipt.v1";
pub const BLOB_OPERATIONS_SCHEMA: &str = "ak.schema.blob_operations.v1";
pub const CIRCLE_OPERATIONS_SCHEMA: &str = "ak.schema.circle_operations.v1";
pub const COMMON_IDS_SCHEMA: &str = "ak.schema.common_ids.v1";
pub const CONSENT_OPERATIONS_SCHEMA: &str = "ak.schema.consent_operations.v1";
pub const CONTACT_OPERATIONS_SCHEMA: &str = "ak.schema.contact_operations.v1";
pub const CONTENT_BLOCK_POLL_SCHEMA: &str = "ak.schema.content_block_poll.v1";
pub const DELIVERY_BINDING_STALE_SCHEMA: &str = "ak.schema.delivery_binding_stale.v1";
pub const DEVICE_REANCHOR_SCHEMA: &str = "ak.schema.device_reanchor.v1";
pub const DID_KEY_LOG_ENTRY_SCHEMA: &str = "ak.schema.did_key_log_entry.v1";
/// Arkret-layer observation that a named did:webvh witness attested a specific
/// log versionId. Distinct object family from `IDENTITY_RECEIPT_SCHEMA`; the two
/// are returned as a tagged union discriminated on `schema`.
pub const DID_WEBVH_WITNESS_RECEIPT_SCHEMA: &str = "ak.schema.did_webvh_witness_receipt.v1";
pub const DIRECTORY_OPERATIONS_SCHEMA: &str = "ak.schema.directory_operations.v1";
pub const EVENT_BATCH_RECEIPT_SCHEMA: &str = "ak.schema.event_batch_receipt.v1";
/// Canonical handle claim shape — matches `handle-claim.schema.json`.
pub const HANDLE_CLAIM_SCHEMA: &str = "ak.schema.handle_claim.v1";
pub const ICE_CONFIG_RESPONSE_SCHEMA: &str = "ak.schema.ice_config_response.v1";
pub const IDENTITY_RECEIPT_SCHEMA: &str = "ak.schema.identity_receipt.v1";
pub const INCLUSION_LIST_SCHEMA: &str = "ak.schema.inclusion_list.v1";
pub const KEYPACKAGE_OPERATIONS_SCHEMA: &str = "ak.schema.keypackage_operations.v1";
pub const KEYS_OPERATIONS_SCHEMA: &str = "ak.schema.keys_operations.v1";
pub const KEY_TRANSPARENCY_SCHEMA: &str = "ak.schema.key_transparency.v1";
pub const LIST_HANDLES_FOR_SUBJECT_RESPONSE_SCHEMA: &str =
    "ak.schema.list_handles_for_subject_response.v1";
pub const MEDIA_METADATA_SCHEMA: &str = "ak.schema.media_metadata.v1";
pub const MEDIA_OPERATIONS_SCHEMA: &str = "ak.schema.media_operations.v1";
pub const MEMBER_DELIVERY_BINDING_CANDIDATE_SCHEMA: &str =
    "ak.schema.member_delivery_binding_candidate.v1";
/// Schema discriminator carried by `MemberIdentity::schema`. Matches the
/// `ak.schema.member_identity.v1` constant in the spec schema.
pub const MEMBER_IDENTITY_SCHEMA: &str = "ak.schema.member_identity.v1";
pub const MIMI_INTEROP_SCHEMA: &str = "ak.schema.mimi_interop.v1";
pub const MIMI_OPERATIONS_SCHEMA: &str = "ak.schema.mimi_operations.v1";
pub const MLS_GOVERNANCE_PROOF_BUNDLE_SCHEMA: &str = "ak.schema.mls_governance_proof_bundle.v1";
pub const PEER_CONTACT_DELIVERY_REQUEST_SCHEMA: &str = "ak.schema.peer_contact_delivery_request.v1";
pub const PIN_SCHEMA: &str = "ak.schema.pin.v1";
pub const PUSH_OPERATIONS_SCHEMA: &str = "ak.schema.push_operations.v1";
pub const QUERY_SCHEMA: &str = "ak.schema.query.v1";
pub const RANGE_COMPLETENESS_ATTESTATION_SCHEMA: &str =
    "ak.schema.range_completeness_attestation.v1";
pub const READ_CURSOR_OPERATIONS_SCHEMA: &str = "ak.schema.read_cursor_operations.v1";
pub const REALM_LINK_OPERATIONS_SCHEMA: &str = "ak.schema.realm_link_operations.v1";
pub const REALM_ORGANIZATION_OPERATIONS_SCHEMA: &str = "ak.schema.realm_organization_operations.v1";
pub const REALM_POLICY_SERVER_OPERATIONS_SCHEMA: &str =
    "ak.schema.realm_policy_server_operations.v1";
pub const REALM_READ_OPERATIONS_SCHEMA: &str = "ak.schema.realm_read_operations.v1";
pub const RSVP_SCHEMA: &str = "ak.schema.rsvp.v1";
pub const SDK_CONFORMANCE_CLAIM_SCHEMA: &str = "ak.schema.sdk_conformance_claim.v1";
pub const SEAL_TRANSPARENCY_SCHEMA: &str = "ak.schema.seal_transparency.v1";
pub const SERVICE_DESCRIBE_SCHEMA: &str = "ak.schema.service_describe.v1";
pub const SERVICE_OPERATION_DTOS_SCHEMA: &str = "ak.schema.service_operation_dtos.v1";

pub const PROFILE_DIRECTORY_SERVICE: &str = "ak.profile.directory_service.v1";
pub const PROFILE_E2EE_CLIENT: &str = "ak.profile.e2ee_client.v1";
pub const PROFILE_MLS_MINIMAL_METADATA_REALM: &str = "ak.profile.mls.minimal_metadata_realm.v1";
pub const PROFILE_ATTESTED_AUDIT_E2EE: &str = "ak.profile.attested_audit.e2ee.v1";
pub const PROFILE_DISCLOSED_AUDIT_E2EE: &str = "ak.profile.disclosed_audit.e2ee.v1";

// Schema ids for the moderation appeal strand and structured attestation evidence.
pub const MODERATION_APPEAL_SCHEMA: &str = "ak.schema.moderation_appeal.v1";
pub const AUDIT_RELEASE_ATTESTATION_SCHEMA: &str = "ak.schema.audit_release_attestation.v1";
pub const CROSS_SIGNING_PUBLISH_SCHEMA: &str = "ak.schema.cross_signing_publish.v1";
pub const CROSS_SIGNING_RESET_SCHEMA: &str = "ak.schema.cross_signing_reset.v1";

// ── Canonical ak.* event kinds ──────────────────────────────────────────────
// Strand event kinds.

// AKP-0007 (spec b7d35be) — Circle event kinds. The 7th kind
// (`ak.circle.seal_commit`) is reducer-derived and MUST NOT be
// submitted by clients; it is exported for receiver-side dispatch only.

// AKP-0007 (spec b7d35be) — Circle capability action ids. Spec
// `capability-action-registry.json`. `ak.circle.manage`,
// `ak.circle.member.manage`, `ak.circle.member.add.others`, and
// `ak.circle.audit` declare `required_constraints=["allowed_circle_ids"]`;
// unconstrained Realm-wide grants for those actions MUST be rejected.

/// AKP-0007 capability action list (6 actions). Useful for downstream
/// services that want to iterate the Circle-management surface.
pub const CIRCLE_CAPABILITY_ACTIONS: &[&str] = &[
    CapabilityActionId::CIRCLE_CREATE,
    CapabilityActionId::CIRCLE_MANAGE,
    CapabilityActionId::CIRCLE_MEMBER_ADD,
    CapabilityActionId::CIRCLE_MEMBER_MANAGE,
    CapabilityActionId::CIRCLE_MEMBER_ADD_OTHERS,
    CapabilityActionId::CIRCLE_AUDIT,
];

// AKP-0008 / AKP-0009 — personal-agent operation IDs (registered in
// `operation-registry.json`). Used by the RPC dispatch layer; reducer-input
// agent lifecycle events are registered separately under `AGENT_*`
// event-kind constants above.

/// AKP-0008 / AKP-0009 — controller-private account-data keys. Reducer
/// MUST reject writes from non-controller actors.
pub const ACCOUNT_DATA_KEY_AGENT_DRAFT: &str = "ak.agent.draft.v1";
// `ak.agent.sidecar_projection.v1` was removed from the account-data registry
// on 2026-07-23: the exchange projection is a controller-device-local fold
// cache, never Account Data (zh/models/sidecar.md §7.2.4).
pub const ACCOUNT_DATA_KEY_AGENT_SIDECAR_VIEW_STATE: &str = "ak.agent.sidecar_view_state.v1";
pub const ACCOUNT_DATA_KEY_REMINDER: &str = "ak.reminders.v1";
pub const ACCOUNT_DATA_KEY_SCHEDULED_SEND: &str = "ak.scheduled_send.v1";
pub const ACCOUNT_DATA_KEY_SNOOZE: &str = "ak.snooze.v1";
pub const ACCOUNT_DATA_KEY_SAVED: &str = "ak.saved.v1";
pub const ACCOUNT_DATA_KEY_DRAFT: &str = "ak.draft.v1";
pub const ACCOUNT_DATA_KEY_FILE_TRANSFER: &str = "ak.file_transfer.v1";
pub const ACCOUNT_DATA_KEY_SEARCH_INDEX_MANIFEST: &str = "ak.search.index_manifest.v1";
pub const ACCOUNT_DATA_KEY_CONTACTS_ACTOR: &str = "ak.contacts.actor";
pub const ACCOUNT_DATA_KEY_CONTACTS_REALM: &str = "ak.contacts.realm";

/// Key-backup hardening (B-C) — new schema ids registered in
/// `schema-registry.json` for recovery policy and recovery receipts.
pub const RECOVERY_POLICY_SCHEMA: &str = "ak.schema.recovery_policy.v1";
pub const RECOVERY_RECEIPT_SCHEMA: &str = "ak.schema.recovery_receipt.v1";
pub const RECOVERY_SESSION_SCHEMA: &str = "ak.schema.recovery_session.v1";

pub const PROFILE_AGENT_SIDECAR: &str = "ak.profile.agent_sidecar.v1";

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

pub fn agent_sidecar_backing_circle_short_name(sidecar_id: &str) -> String {
    let transcript = format!("ak.sidecar.backing_circle.v1\n{sidecar_id}");
    let digest = crate::canonical::sha256_bytes(transcript.as_bytes());
    let suffix = base32_lower_no_pad(&digest)
        .chars()
        .take(16)
        .collect::<String>()
        .to_ascii_uppercase();
    format!("SC-{suffix}")
}

// Morph event kinds.

// Space (container) event kinds. Container events use `ak.space.*`; see the
// security-boundary `EventKind::REALM_*` family for `ak.realm.*` events.

// Relation event kinds.

// View event kinds.

// Realm event kinds (security boundary). The container-level `EventKind::SPACE_*` family
// lives above.

// Per-Realm governance of member `delivery_binding`: which `binding_source`
// values are admissible, which recipient services are allowed, whether DID
// Document fallback is permitted, who may sign rebind. cell_family
// `ak.component.realm.delivery_binding_policy.v1`, cas-register.

// Device event kinds.
//
// Round C45 (2026-05-19; spec 0a5ab85) — actor-private push route binding
// for the composite tuple `(recipient_service_id, principal, device,
// push_route)`. MUST NOT be replicated outside the binding's
// recipient_service_id context.

// Message event kinds.

// High-risk capability required in addition to `ak.message.create` or
// `ak.message.revise` whenever a Message introduces an `audience_mention`
// node such as `@all` or v1 `@here` (`audience="strand_engaged"`).

/// Capability constraint shorthand from `capability-action-registry.json`.
pub const CAP_CONSTRAINT_ALLOWED_WRITE_FIELDS: &str = "allowed_write_fields";

// Capability-action IDs sampled in `_randmon.md` and promoted to SDK
// constants so downstream grant builders do not hard-code raw strings.

// Membership and invite event kinds.

// Server and account/snapshot operations.

// Directory operations.

// Blob operations.

// Round C44 (2026-05-18; spec dc01ad7) — pre-signed blob URL surface.
// `POST /blob/presign` returns a short-lived put/get URL pair so very
// large blobs can be uploaded directly to object storage. Full signing
// enforcement is a server responsibility; SDK only needs the constant for
// client routing.

// Push and key operations.

// Renamed from `ak.self.keys.backups.command.unlock` on 2026-06-11
// (artifacts/migration/renames.json): backup retrieval is rebound to
// `POST /_arkret/self/keys/backups/{backup_id}/unlock` with a body-borne
// unlock proof.

// Authorization check.

// Account / auth-server operations.

// Admin / operator APIs (moderation queue, server status, device revocation,
// account status) are product-local per spec @ 2026-06-04 and MUST NOT be
// registered under the Arkret protocol namespace; servers expose them on
// their own negative-space root such as /_soland/admin/*. They were removed
// from the operation registry (see migration/removed-operation-ids.json) and
// therefore carry no separate admin protocol symbol family here.

// Applet / bridge operations.

// Applet durable event kinds, distinct from the RPC-style applet operations.

// Directory operations beyond the bare `describe`.

// R3.2 (arkret-spec @ b56cab1) — subject/context → current visible
// handle claims; the inverse of `resolve_handle`.

// R3.3 (AKP-0011, arkret-spec @ cced4b8) — resolve a client-agnostic
// shareable object address (Realm / Strand / Message) to a preview. Pure ADD;
// `resolve_realm` is retained and NOT deprecated.

// Events-API operations (low-level Event Envelope plane).

// Round C44 (2026-05-18; spec dc01ad7) — POST variant of
// `ak.self.events.query.scan` for selectors too long to fit in a `GET` query
// string (large `spaces[]` / `actors[]` unions). HTTP path:
// `POST /events/query`. Identical selector / range / response shape.

// DRIFT-ALLOW: constant declaring the operation-id string, not a payload type.

pub const PERSONAL_AGENT_RUNTIME_EVENT_SERVICE_SCOPES: &[&str] = &[
    ServiceOperationId::SELF_EVENTS_QUERY_DESCRIBE,
    ServiceOperationId::SELF_EVENTS_QUERY_SCAN,
    ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE,
    ServiceOperationId::SELF_EVENTS_QUERY_FRONTIER,
    ServiceOperationId::SELF_EVENTS_RESOURCE_GET,
    ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT,
];

pub fn is_personal_agent_runtime_event_service_scope(scope: &str) -> bool {
    matches!(
        scope,
        ServiceOperationId::SELF_EVENTS_QUERY_DESCRIBE
            | ServiceOperationId::SELF_EVENTS_QUERY_SCAN
            | ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE
            | ServiceOperationId::SELF_EVENTS_QUERY_FRONTIER
            | ServiceOperationId::SELF_EVENTS_RESOURCE_GET
            | ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT
    )
}

// Contact and direct-conversation operations.

// Account-private data operations.

// Holder-private consent operations.

// Read cursor self-service operations.

// Circle self-service operations.

// Realm-scoped object read-model operations.

// Identity-registry operations.

// Media / WebRTC ICE config.

// MIMI provider-facade operations.

// Moderation report submission.

// Round R2/R3 (2026-05-20) — capability actions for the moderation appeal
// strand. `submit` is low-risk (any member may appeal); `review` is
// medium-risk and gates the review / decision / close transitions.
// Spec: capability-action-registry.json.

// Round 4 (2026-05-20, spec a77b995) — capability action gating Morph
// creation. Medium risk; the spec
// `capability-action-registry.json` declares `required_constraints=[allowed_morph_kinds]`.

// AKP-0010 (R3 spec-sync 2026-05-27, arkret-spec b47ff6ec) — call /
// media capability actions registered in
// `capability-action-registry.json`. These actions gate the join,
// screen-share, recording, transcription, moderation, and signal-send
// surfaces of the ak.call.* feature.

// Sending call signalling inside the encrypted Signal Extension requires the
// actor to hold this realm-scoped capability. Registered in
// `capability-action-registry.json`.

/// AKP-0010 — full call/media capability-action list.
pub const CALL_CAPABILITY_ACTIONS: &[&str] = &[
    CapabilityActionId::CALL_JOIN,
    CapabilityActionId::CALL_SCREEN_SHARE,
    CapabilityActionId::CALL_RECORD,
    CapabilityActionId::CALL_TRANSCRIBE,
    CapabilityActionId::CALL_MODERATE,
    CapabilityActionId::CALL_SIGNAL_SEND,
];

// AKP-0010 — `ak.self.call.media.exchange.issue_token` operation id. HTTP route:
// `POST /rtc/token`. Surface tier `core_personal`. Registered in
// `operation-registry.json` v2026-05-27.

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
pub const EXPORTER_LABEL_RTC_RECORDING_KEY: &str = ExporterLabelId::RTC_RECORDING_KEY_V1;
/// MLS exporter label for the per-call transcription artifact key
/// (`call-state.md` §5.1). Mirrors the recording-key label for the
/// transcription pipeline.
pub const EXPORTER_LABEL_RTC_TRANSCRIPT_KEY: &str = ExporterLabelId::RTC_TRANSCRIPT_KEY_V1;

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
    ServiceOperationId::SELF_AGENT_SIDECAR_COMMAND_ENSURE,
    ServiceOperationId::SELF_AGENT_SIDECAR_QUERY_LIST,
    ServiceOperationId::SELF_AGENT_SIDECAR_RESOURCE_GET,
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

// Spec-sync (operation-registry.json) — service operations the registry ships
// that the SDK had not yet enumerated. Trust-surface segments: `gate` =
// pre-auth account onboarding, `self` = authenticated account-scoped surface,
// `peer` = inter-principal-server federation surface, `root` = identity-root
// recovery surface.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_sidecar_backing_circle_short_name_is_stable() {
        let short_name = agent_sidecar_backing_circle_short_name(
            "ak:sidecar:01964137-0000-7000-8000-000000000001",
        );
        assert_eq!(short_name.len(), 19);
        assert!(short_name.starts_with("SC-"));
        assert!(
            short_name[3..]
                .chars()
                .all(|ch| ch.is_ascii_uppercase() || matches!(ch, '2'..='7'))
        );
    }
}
