pub const PROTOCOL_VERSION: &str = "1.0";
pub const CORE_SCHEMA_PROFILE: &str = "cx.schema.core.v1";
pub const CORE_REDUCER_PROFILE: &str = "cx.reducer.v1";
pub const BUILT_IN_CONFORMANCE_FIXTURES_VERSION: &str = "contrix-sdk-builtin-v1";

pub const CURSOR_SCHEMA: &str = "cx.schema.cursor.v1";
pub const SPACE_SCHEMA: &str = "cx.schema.space.v1";
pub const ACTOR_PROFILE_SCHEMA: &str = "cx.schema.actor_profile.v1";
pub const FLOW_SCHEMA: &str = "cx.schema.flow.v1";
pub const PLACE_SCHEMA: &str = "cx.schema.place.v1";
pub const RELATION_SCHEMA: &str = "cx.schema.relation.v1";
pub const EVENT_SCHEMA: &str = "cx.schema.event.v1";
pub const EVENT_PAYLOAD_SCHEMA: &str = "cx.schema.event_payload.v1";
pub const VIEW_SCHEMA: &str = "cx.schema.view.v1";
pub const POLICY_SCHEMA: &str = "cx.schema.policy.v1";
pub const CAPABILITY_SCHEMA: &str = "cx.schema.capability.v1";
pub const INVITE_SCHEMA: &str = "cx.schema.invite.v1";
pub const READ_MARKER_SCHEMA: &str = "cx.schema.read_marker.v1";
pub const NOTIFICATION_SCHEMA: &str = "cx.schema.notification.v1";
/// SDK-local operation draft schema marker.
///
/// Operation drafts are builder inputs only; they are not a Contrix wire
/// schema and must be materialized as Event envelopes before submission.
pub const OPERATION_SCHEMA: &str = "cx.local.operation_draft.v1";
pub const BLOB_SCHEMA: &str = "cx.schema.blob.v1";
pub const ANCHOR_SCHEMA: &str = "cx.schema.anchor.v1";
pub const AGENT_AUTHORITY_SCHEMA: &str = "cx.schema.agent_authority.v1";
pub const BOTTOM_SCHEMA: &str = "cx.schema.bottom.v1";
pub const SNAPSHOT_SCHEMA: &str = "cx.schema.snapshot.v1";
pub const ENCRYPTED_PAYLOAD_SCHEMA: &str = "cx.schema.encrypted_payload.v1";
pub const CLIENT_SYNC_RESPONSE_SCHEMA: &str = "cx.schema.client_sync_response.v1";
pub const RESOURCE_SELECTOR_SCHEMA: &str = "cx.schema.resource_selector.v1";
pub const GRANT_CONSTRAINT_SCHEMA: &str = "cx.schema.grant_constraint.v1";
pub const DEVICE_MESSAGE_SCHEMA: &str = "cx.schema.device_message.v1";
pub const KEY_BACKUP_SCHEMA: &str = "cx.schema.key_backup.v1";
pub const MORPH_SCHEMA: &str = "cx.schema.morph.v1";
pub const MORPH_CUSTOMER_RISK_SCHEMA: &str = "cx.schema.morph.customer_risk.v1";
pub const MESSAGE_SCHEMA: &str = "cx.schema.message.v1";
pub const MODERATION_REPORT_SCHEMA: &str = "cx.schema.moderation_report.v1";
pub const MODERATION_QUEUE_ITEM_SCHEMA: &str = "cx.schema.moderation_queue_item.v1";
pub const DID_CONTINUITY_PROOF_SCHEMA: &str = "cx.schema.did_continuity_proof.v1";
pub const IDENTITY_LINK_SCHEMA: &str = "cx.schema.identity_link.v1";

// ── Canonical cx.* event kinds ──────────────────────────────────────────────
/// Flow event kinds.
pub const OP_FLOW_CREATE: &str = "cx.flow.create";
pub const OP_FLOW_UPDATE: &str = "cx.flow.update";
pub const OP_FLOW_ARCHIVE: &str = "cx.flow.archive";
pub const OP_FLOW_RESTORE: &str = "cx.flow.restore";
pub const OP_FLOW_MOVE: &str = "cx.flow.move";
pub const OP_FLOW_REORDER: &str = "cx.flow.reorder";
/// Flow track sub-event kinds (round 12, 2026-05-16). Manage individual
/// entries in `Flow.tracks: BTreeMap<String, FlowTrackConfig>` without
/// requiring a full `cx.flow.update`. State-machine guard: parent Flow
/// MUST be `Active` (per spec common-fields.md §5.1 update-on-non-active
/// rule); reject otherwise with `flow_not_active`.
pub const OP_FLOW_TRACK_DISABLE: &str = "cx.flow.track.disable";
pub const OP_FLOW_TRACK_ENABLE: &str = "cx.flow.track.enable";
pub const OP_FLOW_TRACK_SET_PRIMARY: &str = "cx.flow.track.set_primary";
pub const OP_FLOW_TRACK_UPDATE: &str = "cx.flow.track.update";

/// Morph event kinds.
pub const OP_MORPH_CREATE: &str = "cx.morph.create";
pub const OP_MORPH_UPDATE: &str = "cx.morph.update";
pub const OP_MORPH_ARCHIVE: &str = "cx.morph.archive";
pub const OP_MORPH_RESTORE: &str = "cx.morph.restore";

/// Place event kinds.
pub const OP_PLACE_CREATE: &str = "cx.place.create";
pub const OP_PLACE_UPDATE: &str = "cx.place.update";
pub const OP_PLACE_PARENT: &str = "cx.place.parent";
pub const OP_PLACE_ARCHIVE: &str = "cx.place.archive";
pub const OP_PLACE_RESTORE: &str = "cx.place.restore";
pub const OP_PLACE_TOMBSTONE: &str = "cx.place.tombstone";

/// Relation event kinds.
pub const OP_RELATION_CREATE: &str = "cx.relation.create";
pub const OP_RELATION_UPDATE: &str = "cx.relation.update";
pub const OP_RELATION_DELETE: &str = "cx.relation.delete";
pub const OP_CONTAINER_MOVE_ITEM: &str = "cx.container.move_item";
pub const OP_CONTAINER_REBALANCE: &str = "cx.container.rebalance";

/// View event kinds.
pub const OP_VIEW_CREATE: &str = "cx.view.create";
pub const OP_VIEW_UPDATE: &str = "cx.view.update";
pub const OP_VIEW_RECONCILE: &str = "cx.view.reconcile";

/// Space event kinds.
pub const OP_SPACE_CREATE: &str = "cx.space.create";
pub const OP_SPACE_UPDATE: &str = "cx.space.update";
pub const OP_SPACE_ORGANIZATION: &str = "cx.space.organization";
pub const OP_SPACE_CHILD: &str = "cx.space.child";

/// Message event kinds.
pub const OP_MESSAGE_CREATE: &str = "cx.message.create";
pub const OP_MESSAGE_REVISE: &str = "cx.message.revise";
pub const OP_MESSAGE_REDACT: &str = "cx.message.redact";

/// Membership and invite event kinds.
pub const OP_MEMBER_STATE: &str = "cx.member.state";
pub const OP_INVITE_CREATE: &str = "cx.invite.create";

/// Server and sync operations.
pub const OP_SERVER_DESCRIBE: &str = "cx.server.describe";
pub const OP_IDENTITY_RESOLVE: &str = "cx.identity.resolve";
pub const OP_SYNC_DESCRIBE: &str = "cx.sync.describe";

/// Directory operations.
pub const OP_DIRECTORY_DESCRIBE: &str = "cx.directory.describe";

/// Blob operations.
pub const OP_BLOB_UPLOAD: &str = "cx.blob.upload";
pub const OP_BLOB_HEAD: &str = "cx.blob.head";
pub const OP_BLOB_GET: &str = "cx.blob.get";
/// Round C44 (2026-05-18; spec dc01ad7) — pre-signed blob URL surface.
/// `POST /blob/presign` returns a short-lived put/get URL pair so very
/// large blobs can be uploaded directly to object storage. Full signing
/// path is a soland TODO; SDK only needs the constant for client routing.
pub const OP_BLOB_PRESIGN: &str = "cx.blob.presign";

/// Push and key operations.
pub const OP_PUSH_NOTIFY: &str = "cx.push.notify";
pub const OP_KEYS_UPLOAD: &str = "cx.keys.upload";
pub const OP_KEYS_QUERY: &str = "cx.keys.query";
pub const OP_KEYS_CLAIM: &str = "cx.keys.claim";
pub const OP_DEVICE_MESSAGES_PUT: &str = "cx.device_messages.put";
pub const OP_DEVICE_MESSAGES_GET: &str = "cx.device_messages.get";
pub const OP_KEYS_KEYPACKAGES_UPLOAD: &str = "cx.keys.keypackages.upload";
pub const OP_KEYS_KEYPACKAGES_CLAIM: &str = "cx.keys.keypackages.claim";
pub const OP_KEYS_KEYPACKAGES_CONSUME: &str = "cx.keys.keypackages.consume";
pub const OP_KEYS_KEYPACKAGES_REVOKE: &str = "cx.keys.keypackages.revoke";
pub const OP_KEYS_BACKUPS_PUT: &str = "cx.keys.backups.put";
pub const OP_KEYS_BACKUPS_LIST: &str = "cx.keys.backups.list";
pub const OP_KEYS_BACKUPS_GET: &str = "cx.keys.backups.get";
pub const OP_KEYS_BACKUPS_DELETE: &str = "cx.keys.backups.delete";

/// Authorization check.
pub const OP_AUTHZ_CHECK: &str = "cx.authz.check";
pub const OP_AUTHZ_GET_EFFECTIVE_GRANTS: &str = "cx.authz.get_effective_grants";
pub const OP_AUTHZ_GET_INVITES: &str = "cx.authz.get_invites";

/// Account / auth-server operations.
pub const OP_ACCOUNT_DEVICE_PAIR: &str = "cx.account.device_pair";
pub const OP_ACCOUNT_ISSUE_SESSION_GRANT: &str = "cx.account.issue_session_grant";
pub const OP_ACCOUNT_OIDC_CALLBACK: &str = "cx.account.oidc_callback";

/// Admin / moderation-queue operations.
pub const OP_ADMIN_GET_MODERATION_QUEUE: &str = "cx.admin.get_moderation_queue";
pub const OP_ADMIN_GET_SERVER_STATUS: &str = "cx.admin.get_server_status";
pub const OP_ADMIN_REVOKE_DEVICE: &str = "cx.admin.revoke_device";
pub const OP_ADMIN_UPDATE_ACCOUNT_STATUS: &str = "cx.admin.update_account_status";

/// Applet / bridge operations.
pub const OP_APPLET_DESCRIBE: &str = "cx.applet.describe";
pub const OP_APPLET_PING: &str = "cx.applet.ping";
pub const OP_APPLET_PROTOCOL_METADATA: &str = "cx.applet.protocol_metadata";
pub const OP_APPLET_QUERY_ACTOR: &str = "cx.applet.query_actor";
pub const OP_APPLET_QUERY_SPACE: &str = "cx.applet.query_space";
pub const OP_APPLET_THIRD_PARTY_LOCATIONS: &str = "cx.applet.third_party_locations";
pub const OP_APPLET_THIRD_PARTY_USERS: &str = "cx.applet.third_party_users";
pub const OP_APPLET_TRANSACTION: &str = "cx.applet.transaction";

/// Applet protocol-session sub-events (round 13, 2026-05-16). Spec
/// `extensions/applet-integration.md` event-kind-registry rows. These
/// are durable reducer-input events (distinct from the RPC-style
/// `OP_APPLET_DESCRIBE` / `_PING` / `_TRANSACTION` ops above). SDK
/// reducer doesn't maintain per-session state — the applet bridge
/// state machine lives client-side — but operation-registry must
/// carry the required-fields shapes for downstream submit validation.
pub const OP_APPLET_BRIDGE_ERROR: &str = "cx.applet.bridge_error";
pub const OP_APPLET_DISCOVERY: &str = "cx.applet.discovery";
pub const OP_APPLET_PROTOCOL_SESSION_START: &str = "cx.applet.protocol_session.start";
pub const OP_APPLET_PROTOCOL_SESSION_STATUS: &str = "cx.applet.protocol_session.status";
pub const OP_APPLET_REGISTRATION: &str = "cx.applet.registration";

/// Agent protocol-session sub-events (round 13). Same shape as the
/// applet family but the terminal `*.result` event carries a signed
/// audit binding. Spec `extensions/agent-integration.md`.
pub const OP_AGENT_ENDPOINT: &str = "cx.agent.endpoint";
pub const OP_AGENT_PROTOCOL_SESSION_RESULT: &str = "cx.agent.protocol_session.result";
pub const OP_AGENT_PROTOCOL_SESSION_START: &str = "cx.agent.protocol_session.start";
pub const OP_AGENT_PROTOCOL_SESSION_STATUS: &str = "cx.agent.protocol_session.status";

/// Agent Workspace service operations.
pub const OP_AGENT_WORKSPACE_LIST_PENDING_TASKS: &str = "cx.agent_workspace.list_pending_tasks";
pub const OP_AGENT_WORKSPACE_RESOLVE_MIRROR_FLOW: &str = "cx.agent_workspace.resolve_mirror_flow";

/// Directory operations beyond the bare `describe`.
pub const OP_DIRECTORY_PRIVATE_CONTACT_DISCOVERY: &str = "cx.directory.private_contact_discovery";
pub const OP_DIRECTORY_ANNOUNCE: &str = "cx.directory.announce";
pub const OP_DIRECTORY_RESOLVE_HANDLE: &str = "cx.directory.resolve_handle";
pub const OP_DIRECTORY_RESOLVE_ORGANIZATION: &str = "cx.directory.resolve_organization";
pub const OP_DIRECTORY_RESOLVE_SPACE: &str = "cx.directory.resolve_space";
pub const OP_DIRECTORY_SEARCH_ACTORS: &str = "cx.directory.search_actors";
pub const OP_DIRECTORY_SEARCH_ORGANIZATIONS: &str = "cx.directory.search_organizations";
pub const OP_DIRECTORY_SEARCH_SPACES: &str = "cx.directory.search_spaces";
pub const OP_DIRECTORY_SEARCH_USERS: &str = "cx.directory.search_users";
pub const OP_DIRECTORY_SUBSCRIBE: &str = "cx.directory.subscribe";
pub const OP_DIRECTORY_WITHDRAW: &str = "cx.directory.withdraw";

/// Events-API operations (low-level Event Envelope plane).
///
/// C17 (spec 2026-05-08, wire-breaking): the read surface was reorganised by
/// delivery shape. `cx.events.list` + `cx.sync.backfill` (forward / backward
/// unary reads) are folded into [`OP_EVENTS_QUERY`] (selector = `spaces[]` ∪
/// `actors[]`, range = `from?` + `until?` + `direction: forward|backward`).
/// `cx.sync.subscribe` becomes [`OP_EVENTS_SUBSCRIBE`] (multi-space / actor
/// stream, `include_history=true` flips to live after a `catchup_complete`
/// frame). `cx.sync.client_sync` is renamed to [`OP_SYNC_ACCOUNT`] — the path
/// `POST /api/v1/sync` does not change but the canonical operation_id does.
pub const OP_EVENTS_BATCH_GET: &str = "cx.events.batch_get";
pub const OP_EVENTS_DESCRIBE: &str = "cx.events.describe";
pub const OP_EVENTS_FRONTIER: &str = "cx.events.frontier";
pub const OP_EVENTS_GET: &str = "cx.events.get";
pub const OP_EVENTS_QUERY: &str = "cx.events.query";
/// Round C44 (2026-05-18; spec dc01ad7) — POST variant of
/// `cx.events.query` for selectors too long to fit in a `GET` query
/// string (large `spaces[]` / `actors[]` unions). HTTP path:
/// `POST /events/query`. Identical selector / range / response shape.
pub const OP_EVENTS_QUERY_POST: &str = "cx.events.query_post";
pub const OP_EVENTS_SUBSCRIBE: &str = "cx.events.subscribe";
pub const OP_EVENTS_SUBMIT: &str = "cx.events.submit";

/// Identity-registry operations.
pub const OP_IDENTITY_DESCRIBE_REGISTRY: &str = "cx.identity.describe_registry";
pub const OP_IDENTITY_GET_DOCUMENT: &str = "cx.identity.get_document";
pub const OP_IDENTITY_GET_LOG: &str = "cx.identity.get_log";
pub const OP_IDENTITY_GET_RECEIPTS: &str = "cx.identity.get_receipts";
pub const OP_IDENTITY_SUBMIT_DID_OPERATION: &str = "cx.identity.submit_did_operation";

/// Media / WebRTC ICE config.
pub const OP_MEDIA_ICE_CONFIG: &str = "cx.media.ice_config";

/// MIMI provider-facade operations.
pub const OP_MIMI_GROUP_INFO: &str = "cx.mimi.group_info";
pub const OP_MIMI_IDENTIFIER_QUERY: &str = "cx.mimi.identifier_query";
pub const OP_MIMI_KEY_MATERIAL: &str = "cx.mimi.key_material";
pub const OP_MIMI_NOTIFY: &str = "cx.mimi.notify";
pub const OP_MIMI_PROVIDER_DIRECTORY: &str = "cx.mimi.provider_directory";
pub const OP_MIMI_PROXY_DOWNLOAD: &str = "cx.mimi.proxy_download";
pub const OP_MIMI_REPORT_ABUSE: &str = "cx.mimi.report_abuse";
pub const OP_MIMI_REQUEST_CONSENT: &str = "cx.mimi.request_consent";
pub const OP_MIMI_ROOM_UPDATE: &str = "cx.mimi.room_update";
pub const OP_MIMI_SUBMIT_MESSAGE: &str = "cx.mimi.submit_message";
pub const OP_MIMI_UPDATE_CONSENT: &str = "cx.mimi.update_consent";

/// Moderation report submission.
pub const OP_MODERATION_REPORT: &str = "cx.moderation.report";

/// Policy server check.
pub const OP_POLICY_CHECK: &str = "cx.policy.check";
// Round C45 (2026-05-18 main; spec 346f347) — operation registry dropped
// `cx.policy.check_legacy`. The HTTP `POST /contrix/v1/check` legacy alias
// still has a 2028-06-01 sunset in the OpenAPI binding, but the operation
// catalog now exposes only `cx.policy.check`. Aggressive mode — v1 not
// released — so the SDK constant is dropped rather than shimmed.

/// Push gateway register / unregister.
pub const OP_PUSH_REGISTER_DEVICE: &str = "cx.push.register_device";
pub const OP_PUSH_UNREGISTER_DEVICE: &str = "cx.push.unregister_device";

/// Sync surface — account aggregate sync & snapshot head.
///
/// C17: `cx.sync.client_sync` → [`OP_SYNC_ACCOUNT`]. The path `POST /api/v1/sync`
/// is unchanged; only the canonical operation_id is renamed to clarify that this
/// op is the **account-view aggregate** (to_device / account_data /
/// device_lists / presence / cross-Space delta), distinct from raw Event
/// Envelope reads which now go through [`OP_EVENTS_QUERY`] /
/// [`OP_EVENTS_SUBSCRIBE`].
pub const OP_SYNC_ACCOUNT: &str = "cx.sync.account";
pub const OP_SYNC_GET_SNAPSHOT_HEAD: &str = "cx.sync.get_snapshot_head";

/// Canonical service operation IDs built into this SDK.
///
/// Event kinds live in `crate::events`; this list mirrors the spec
/// `operation-registry.json` service surface.
pub const BUILT_IN_OPERATION_KINDS: &[&str] = &[
    OP_ACCOUNT_DEVICE_PAIR,
    OP_AGENT_WORKSPACE_LIST_PENDING_TASKS,
    OP_AGENT_WORKSPACE_RESOLVE_MIRROR_FLOW,
    OP_ACCOUNT_ISSUE_SESSION_GRANT,
    OP_ACCOUNT_OIDC_CALLBACK,
    OP_ADMIN_GET_MODERATION_QUEUE,
    OP_ADMIN_GET_SERVER_STATUS,
    OP_ADMIN_REVOKE_DEVICE,
    OP_ADMIN_UPDATE_ACCOUNT_STATUS,
    OP_APPLET_DESCRIBE,
    OP_APPLET_PING,
    OP_APPLET_PROTOCOL_METADATA,
    OP_APPLET_QUERY_ACTOR,
    OP_APPLET_QUERY_SPACE,
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
    // event kinds leak in. Same convention as `OP_FLOW_TRACK_*` and
    // the lifecycle event ops (`OP_FLOW_CREATE`, etc.).
    OP_AUTHZ_CHECK,
    OP_AUTHZ_GET_EFFECTIVE_GRANTS,
    OP_AUTHZ_GET_INVITES,
    OP_BLOB_GET,
    OP_BLOB_HEAD,
    OP_BLOB_PRESIGN,
    OP_BLOB_UPLOAD,
    OP_DEVICE_MESSAGES_GET,
    OP_DEVICE_MESSAGES_PUT,
    OP_DIRECTORY_ANNOUNCE,
    OP_SERVER_DESCRIBE,
    OP_DIRECTORY_DESCRIBE,
    OP_DIRECTORY_PRIVATE_CONTACT_DISCOVERY,
    OP_DIRECTORY_RESOLVE_HANDLE,
    OP_DIRECTORY_RESOLVE_ORGANIZATION,
    OP_DIRECTORY_RESOLVE_SPACE,
    OP_DIRECTORY_SEARCH_ACTORS,
    OP_DIRECTORY_SEARCH_ORGANIZATIONS,
    OP_DIRECTORY_SEARCH_SPACES,
    OP_DIRECTORY_SEARCH_USERS,
    OP_DIRECTORY_SUBSCRIBE,
    OP_DIRECTORY_WITHDRAW,
    OP_EVENTS_BATCH_GET,
    OP_EVENTS_DESCRIBE,
    OP_EVENTS_FRONTIER,
    OP_EVENTS_GET,
    OP_EVENTS_QUERY,
    OP_EVENTS_QUERY_POST,
    OP_EVENTS_SUBSCRIBE,
    OP_EVENTS_SUBMIT,
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
    OP_POLICY_CHECK,
    OP_PUSH_NOTIFY,
    OP_PUSH_REGISTER_DEVICE,
    OP_PUSH_UNREGISTER_DEVICE,
    OP_SYNC_DESCRIBE,
    OP_SYNC_ACCOUNT,
    OP_SYNC_GET_SNAPSHOT_HEAD,
];
