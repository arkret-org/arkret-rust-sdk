//! Forbidden wire-field registry (CKP-0007 + earlier rounds).
//!
//! Single source of truth for the spec's
//! `artifacts/registry/forbidden-wire-fields.json` hard-reject set as it
//! lands in the SDK. Receivers (soland, sodmin, yougen, etc.) call
//! [`is_forbidden_wire_field`] to reject any Event payload that carries
//! one of these legacy field names at the wire layer.
//!
//! Three checker forms are exposed:
//!
//! 1. [`is_forbidden_wire_field`] — top-level / generic context. Returns `true` for any name
//!    forbidden in *some* commonly-relevant context. Suitable for a coarse scan; prefer
//!    [`is_forbidden_in_context`] when the caller knows the surrounding payload class.
//! 2. [`is_forbidden_in_context`] — context-aware variant. Pass the [`WireContext`] describing
//!    where the field appears (which payload class, whether it is a JSON-Patch op path, whether it
//!    is a typed-id prefix) and the checker returns only the entries that the spec forbids in that
//!    exact context.
//! 3. [`is_forbidden_id_prefix`] — typed-id prefix check (e.g. `ck:notif:` is forbidden as an id
//!    prefix anywhere on the wire; `ck:notification:` is canonical).

/// Surface a forbidden field can appear in. Mirrors the `context` field
/// in `forbidden-wire-fields.json` collapsed into the categories the SDK
/// actually consumes.
///
/// CKP-0007 P1.6 — replaces the previous coarse top-level-only checker so
/// callers can correctly distinguish e.g. `policy_ref` (forbidden on
/// `handle_claim` and `member_delivery_binding`, legal as a generic
/// reference name on a Policy object itself) and patch-path entries
/// (`patch:stage` on a JSON-Patch op path is forbidden, but a payload
/// field literally named `stage` is canonical).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireContext {
    /// Generic top-level Event Envelope / payload object property. Most
    /// callers use this for an initial coarse scan.
    EventEnvelopeOrPayloadTopLevel,
    /// Flow payload object property.
    FlowPayload,
    /// Morph payload object property.
    MorphPayload,
    /// Space payload object property.
    SpacePayload,
    /// Relation payload object property.
    RelationPayload,
    /// Message create payload object property.
    MessageCreatePayload,
    /// Notification payload (push gateway projection) property.
    NotificationPayload,
    /// Handle claim top-level property.
    HandleClaimTopLevel,
    /// Member delivery binding object property.
    MemberDeliveryBinding,
    /// Member delivery binding candidate property.
    MemberDeliveryBindingCandidate,
    /// Generic object_patch / object_lifecycle payload property.
    ObjectPatchPayload,
    ObjectLifecyclePayload,
    /// Encrypted Envelope property.
    EncryptedEnvelope,
    /// Capability delegate payload property.
    CapabilityDelegatePayload,
    /// Child scope policy `kind` value.
    ChildScopePolicyKind,
    /// Join policy payload property.
    JoinPolicyPayload,
    /// Frontier object property (range completeness / RYW receipt etc.).
    FrontierObjectProperty,
    /// Realm freeze payload property.
    RealmFreezePayload,
    /// Snapshot chunk descriptor property.
    SnapshotChunk,
    /// Moderation report payload property.
    ModerationReportPayload,
    /// Moderation queue item property.
    ModerationQueueItem,
    /// Moderation queue item evidence_policy property.
    ModerationQueueItemEvidencePolicy,
    /// Moderation franking proof payload property.
    ModerationFrankingProofPayload,
    /// Directory projection row property.
    DirectoryProjection,
    /// Directory search request property.
    DirectorySearchRequest,
    /// Account subscribe device-message container property.
    AccountSubscribeDeviceMessageContainer,
    /// Account subscribe frame schema definition property.
    AccountSubscribeFrameSchemaDef,
    /// Agent audit binding property.
    AgentAuditBinding,
    /// JSON-Patch op path on a Flow patch payload.
    /// Pass the patch *path* (e.g. "stage", "stage_changed_at"), NOT a
    /// `patch:` prefix; the checker re-prefixes internally.
    FlowPatchPath,
    /// JSON-Patch op path on a Morph patch payload.
    MorphPatchPath,
    /// Event proof property.
    EventProof,
    /// Generic detached-JWS proof property.
    GenericProof,
    /// Proof or cross-signing payload property.
    ProofOrCrossSigningPayload,
    /// Generic timeline-event top-level property (legacy 'branch' guard).
    TimelineEventTopLevel,
    /// Protocol responsibility subject field (actor_did / principal_did /
    /// subject_did guard).
    ProtocolSubjectField,
    /// Generic wire schema or payload property (validity / cache fields).
    WireSchemaOrPayload,
    /// CRDT lattice enum value (`or-set`, `mv-register`, …).
    CrdtLatticeEnumValue,
    /// Moderation queue item `visibility` enum value.
    ModerationQueueItemVisibility,
    /// Error code value.
    ErrorCode,
    /// Event kind string value.
    EventKind,
    /// Schema id string value.
    SchemaId,
    /// Capability action string value.
    CapabilityAction,
    /// Event payload field carrying sender identity.
    EventPayloadOrProjection,
    /// Service describe response property.
    ServiceDescribe,
    /// Blob metadata object property.
    BlobMetadata,
    /// Blob upload metadata object property.
    BlobUploadMetadata,
    /// Applet protocol metadata response property.
    AppletProtocolMetadata,
    /// MemberIdentity display_profile property.
    MemberIdentityDisplayProfile,
    /// Media metadata visibility enum / object value.
    MediaMetadataVisibility,
    /// Actor kind string value.
    ActorKindValue,
    /// Cursor body property.
    CursorBody,
    /// Capability grant constraint object property.
    GrantConstraint,
    /// Key backup `encryption.kdf.params` object property.
    KeyBackupKdfParams,
    /// PolicyCheck `bound_to` binding object property.
    PolicyCheckBoundTo,
    // 2026-06 registry sync — contexts the spec registry names that the
    // mirror previously collapsed away or lacked entirely (SDK-06-003).
    /// Flow track key field (registry `flow_track_key_field`).
    FlowTrackKeyField,
    /// Content carrier that has an encrypted-content counterpart
    /// (registry `content_carrier_with_content_counterpart`).
    ContentCarrierWithContentCounterpart,
    /// Flow or Morph payload top-level property
    /// (registry `flow_or_morph_payload_top_level`).
    FlowOrMorphPayloadTopLevel,
    /// Flow or Message payload top-level property
    /// (registry `flow_or_message_payload_top_level`).
    FlowOrMessagePayloadTopLevel,
    /// Composite content block container property
    /// (registry `content_block_composite`).
    ContentBlockComposite,
    /// Notification projection property (registry `notification_projection`).
    NotificationProjection,
    /// MIMI consent request body (`ck.open.mimi.request_consent`).
    MimiRequestConsentRequestBody,
    /// MIMI consent update body (`ck.open.mimi.update_consent`).
    MimiUpdateConsentRequestBody,
    /// Service describe `verified_profiles[]` entry property.
    ServiceDescribeVerifiedProfiles,
    /// Federation verification payload property.
    FederationVerificationPayload,
    /// Key backup `recovery_auth_data` property.
    KeyBackupRecoveryAuthData,
    /// Device authorize payload property.
    DeviceAuthorizePayload,
    /// Agent key payload property.
    AgentKeyPayload,
    /// Attestation evidence property.
    AttestationEvidence,
    /// Agent lifecycle payload property.
    AgentLifecyclePayload,
    /// Seal object property.
    Seal,
    /// DID continuity proof `transfer_evidence` property.
    DidContinuityProofTransferEvidence,
    /// DID continuity proof `signature_chain[]` entry property.
    DidContinuityProofSignatureChain,
    /// Recovery policy `share_commitment` property.
    RecoveryPolicyShareCommitment,
    /// Actor profile top-level property.
    ActorProfile,
    /// Reviewer quorum object property (registry `reviewer_quorum`).
    ReviewerQuorum,
    /// Membership payload property (registry `membership_payload`).
    MembershipPayload,
    /// Wire duration string format rule (registry `wire_duration_string`;
    /// the entry token names the rejected compact mini-DSL format, not a
    /// field name).
    WireDurationString,
}

/// Spec `forbidden-wire-fields.json` entries that name a single
/// top-level field. Receivers MUST hard-reject any Event payload that
/// carries one of these keys at the matching context.
///
/// Source of truth: `spec/v1/artifacts/registry/forbidden-wire-fields.json`
/// (CKP-0007 spec floor 2b0d70d, plus earlier rounds carried forward).
///
/// Kept as a flat list for the coarse [`is_forbidden_wire_field`] check;
/// the context-aware variant uses [`forbidden_entries`] below.
pub const FORBIDDEN_WIRE_FIELDS: &[&str] = &[
    // Removed timeline and scope fields.
    "branch",
    "room_kind",
    // CKP-0007 Flow scope field — spec renamed to `scope_circle_id`.
    "discussion_realm_ref",
    "discussion_space_ref",
    // CKP-0007 batch-renamed identifier fields.
    "parent_ref",
    "default_realm_ref",
    "scope_ref",
    "default_scope_ref",
    "retention_policy_ref",
    "disclosure_policy_ref",
    "rate_limit_policy_ref",
    "event_hashes",
    "cache_until",
    "signed_payload_hash",
    "avatar_ref",
    "icon_blob",
    "space_bound",
    "sha256",
    "size",
    "filter_hash",
    "derived_hash_prefix",
    "application_receipt_hash",
    "review_receipt_hash",
    "receipt_hash",
    "pattern_hash",
    "media_hash",
    "presentation_hash",
    "raw_document_hash",
    "signature_over_content_hash",
    "prev_frontier_hash",
    "constraint_hash",
    "allowed_view_refs",
    "allowed_flow_refs",
    "allowed_circle_refs",
    "denied_flow_refs",
    "allowed_space_refs",
    "denied_space_refs",
    "realm_refs",
    "approval_actor_refs",
    "signature_alg",
    "device_key_alg",
    "agent_did",
    "audit_agent_did",
    "accountable_actor",
    "accountable_to",
    "thumbnail_ref",
    "claim_type",
    "notary_sig",
    "track",
    "inception_pubkey_fingerprint",
    "commitment_b64",
    "changed_at",
    "via",
    "of",
    // policy_ref is canonical on a Policy object itself (object-self id)
    // and forbidden everywhere else; see context-aware checker below.
];

/// Returns `true` when `key` names a top-level wire field that MUST be
/// hard-rejected by SDK receivers per
/// `spec/v1/artifacts/registry/forbidden-wire-fields.json`.
///
/// This is the coarse check kept for callers that don't yet know the
/// surrounding payload context. Prefer [`is_forbidden_in_context`] when
/// the caller can supply a [`WireContext`].
pub fn is_forbidden_wire_field(key: &str) -> bool {
    FORBIDDEN_WIRE_FIELDS.contains(&key)
}

/// One context-bound forbidden-field rule. The flat table below is the
/// in-Rust mirror of the spec registry; it intentionally enumerates only
/// the `hard_reject` entries (`migration_only` / `docs_only` are not
/// receiver-side concerns).
struct ForbiddenEntry {
    field: &'static str,
    context: WireContext,
}

/// The hard-reject table sliced from `forbidden-wire-fields.json`. Order
/// matches the spec file for easy diff.
const FORBIDDEN_ENTRIES: &[ForbiddenEntry] = &[
    // Top-level / generic
    ForbiddenEntry {
        field: "branch",
        context: WireContext::TimelineEventTopLevel,
    },
    ForbiddenEntry {
        field: "track",
        context: WireContext::TimelineEventTopLevel,
    },
    ForbiddenEntry {
        field: "room_kind",
        context: WireContext::EventEnvelopeOrPayloadTopLevel,
    },
    // Flow / Morph / Space / Relation payload guards
    ForbiddenEntry {
        field: "title",
        context: WireContext::FlowPayload,
    },
    ForbiddenEntry {
        field: "summary",
        context: WireContext::FlowPayload,
    },
    ForbiddenEntry {
        field: "fields",
        context: WireContext::FlowPayload,
    },
    ForbiddenEntry {
        field: "encrypted_payload",
        context: WireContext::FlowPayload,
    },
    ForbiddenEntry {
        field: "title",
        context: WireContext::MorphPayload,
    },
    ForbiddenEntry {
        field: "summary",
        context: WireContext::MorphPayload,
    },
    ForbiddenEntry {
        field: "encrypted_payload",
        context: WireContext::MorphPayload,
    },
    ForbiddenEntry {
        field: "track",
        context: WireContext::MessageCreatePayload,
    },
    ForbiddenEntry {
        field: "encrypted_payload",
        context: WireContext::MessageCreatePayload,
    },
    ForbiddenEntry {
        field: "discussion_space_ref",
        context: WireContext::FlowPayload,
    },
    ForbiddenEntry {
        field: "discussion_realm_ref",
        context: WireContext::FlowPayload,
    },
    ForbiddenEntry {
        field: "fields.rank",
        context: WireContext::RelationPayload,
    },
    ForbiddenEntry {
        field: "fields.rank",
        context: WireContext::SpacePayload,
    },
    ForbiddenEntry {
        field: "metadata.fields.stage",
        context: WireContext::FlowPayload,
    },
    ForbiddenEntry {
        field: "metadata.fields.stage_changed_at",
        context: WireContext::FlowPayload,
    },
    ForbiddenEntry {
        field: "metadata.fields.stage_reason",
        context: WireContext::FlowPayload,
    },
    ForbiddenEntry {
        field: "metadata.fields.stage_note",
        context: WireContext::FlowPayload,
    },
    ForbiddenEntry {
        field: "metadata.fields.lifecycle",
        context: WireContext::FlowPayload,
    },
    ForbiddenEntry {
        field: "metadata.fields.progress_state",
        context: WireContext::FlowPayload,
    },
    ForbiddenEntry {
        field: "metadata.fields.assignee",
        context: WireContext::FlowPayload,
    },
    ForbiddenEntry {
        field: "metadata.fields.assignees",
        context: WireContext::FlowPayload,
    },
    ForbiddenEntry {
        field: "metadata.fields.assigned_to",
        context: WireContext::FlowPayload,
    },
    ForbiddenEntry {
        field: "metadata.fields.assigned_actor_ids",
        context: WireContext::FlowPayload,
    },
    ForbiddenEntry {
        field: "fields.stage",
        context: WireContext::MorphPayload,
    },
    ForbiddenEntry {
        field: "fields.stage_changed_at",
        context: WireContext::MorphPayload,
    },
    ForbiddenEntry {
        field: "fields.stage_reason",
        context: WireContext::MorphPayload,
    },
    ForbiddenEntry {
        field: "fields.stage_note",
        context: WireContext::MorphPayload,
    },
    ForbiddenEntry {
        field: "fields.lifecycle",
        context: WireContext::MorphPayload,
    },
    ForbiddenEntry {
        field: "fields.progress_state",
        context: WireContext::MorphPayload,
    },
    ForbiddenEntry {
        field: "security_class",
        context: WireContext::SpacePayload,
    },
    ForbiddenEntry {
        field: "join_rule",
        context: WireContext::SpacePayload,
    },
    ForbiddenEntry {
        field: "history_visibility",
        context: WireContext::SpacePayload,
    },
    ForbiddenEntry {
        field: "policy_server",
        context: WireContext::SpacePayload,
    },
    ForbiddenEntry {
        field: "delivery_binding_policy",
        context: WireContext::SpacePayload,
    },
    // Patch-path guards
    ForbiddenEntry {
        field: "stage",
        context: WireContext::FlowPatchPath,
    },
    ForbiddenEntry {
        field: "stage_changed_at",
        context: WireContext::FlowPatchPath,
    },
    ForbiddenEntry {
        field: "metadata.fields.assignee",
        context: WireContext::FlowPatchPath,
    },
    ForbiddenEntry {
        field: "metadata.fields.assignees",
        context: WireContext::FlowPatchPath,
    },
    ForbiddenEntry {
        field: "metadata.fields.assigned_to",
        context: WireContext::FlowPatchPath,
    },
    ForbiddenEntry {
        field: "metadata.fields.assigned_actor_ids",
        context: WireContext::FlowPatchPath,
    },
    ForbiddenEntry {
        field: "fields.assignee",
        context: WireContext::FlowPatchPath,
    },
    ForbiddenEntry {
        field: "fields.assignees",
        context: WireContext::FlowPatchPath,
    },
    ForbiddenEntry {
        field: "fields.assigned_to",
        context: WireContext::FlowPatchPath,
    },
    ForbiddenEntry {
        field: "fields.assigned_actor_ids",
        context: WireContext::FlowPatchPath,
    },
    ForbiddenEntry {
        field: "stage",
        context: WireContext::MorphPatchPath,
    },
    ForbiddenEntry {
        field: "stage_changed_at",
        context: WireContext::MorphPatchPath,
    },
    // Identifier rename batch (post-2026-05-25): single concrete object ids
    // use `_id`; `_ref` is reserved for causal / proof / polymorphic refs.
    ForbiddenEntry {
        field: "parent_ref",
        context: WireContext::EventEnvelopeOrPayloadTopLevel,
    },
    ForbiddenEntry {
        field: "default_realm_ref",
        context: WireContext::EventEnvelopeOrPayloadTopLevel,
    },
    ForbiddenEntry {
        field: "scope_ref",
        context: WireContext::EventEnvelopeOrPayloadTopLevel,
    },
    ForbiddenEntry {
        field: "default_scope_ref",
        context: WireContext::EventEnvelopeOrPayloadTopLevel,
    },
    ForbiddenEntry {
        field: "retention_policy_ref",
        context: WireContext::EventEnvelopeOrPayloadTopLevel,
    },
    ForbiddenEntry {
        field: "disclosure_policy_ref",
        context: WireContext::EventEnvelopeOrPayloadTopLevel,
    },
    ForbiddenEntry {
        field: "rate_limit_policy_ref",
        context: WireContext::EventEnvelopeOrPayloadTopLevel,
    },
    // policy_ref is keep on Realm itself (object-self id); forbidden on
    // handle_claim and member_delivery_binding scopes (context-aware).
    ForbiddenEntry {
        field: "policy_ref",
        context: WireContext::HandleClaimTopLevel,
    },
    ForbiddenEntry {
        field: "policy_ref",
        context: WireContext::MemberDeliveryBinding,
    },
    ForbiddenEntry {
        field: "service_acceptance_ref",
        context: WireContext::HandleClaimTopLevel,
    },
    ForbiddenEntry {
        field: "recipient_service_did",
        context: WireContext::HandleClaimTopLevel,
    },
    // Child scope policy / join policy
    ForbiddenEntry {
        field: "require_scope_ref",
        context: WireContext::ChildScopePolicyKind,
    },
    ForbiddenEntry {
        field: "parent_space_refs",
        context: WireContext::JoinPolicyPayload,
    },
    // Frontier object property
    ForbiddenEntry {
        field: "space_frontier",
        context: WireContext::FrontierObjectProperty,
    },
    // Validity / cache rename batch (any wire schema)
    ForbiddenEntry {
        field: "valid_from",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "valid_until",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "not_after",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "cache_valid_until",
        context: WireContext::WireSchemaOrPayload,
    },
    // Proof rename batch
    ForbiddenEntry {
        field: "signed_by",
        context: WireContext::ProofOrCrossSigningPayload,
    },
    ForbiddenEntry {
        field: "payload_hash",
        context: WireContext::EventProof,
    },
    ForbiddenEntry {
        field: "payload_hash",
        context: WireContext::GenericProof,
    },
    // Subject rename batch
    ForbiddenEntry {
        field: "actor_did",
        context: WireContext::ProtocolSubjectField,
    },
    ForbiddenEntry {
        field: "principal_did",
        context: WireContext::ProtocolSubjectField,
    },
    ForbiddenEntry {
        field: "subject_did",
        context: WireContext::ProtocolSubjectField,
    },
    // Notification payload
    ForbiddenEntry {
        field: "notification.space_name",
        context: WireContext::NotificationPayload,
    },
    ForbiddenEntry {
        field: "sender_display_name",
        context: WireContext::NotificationPayload,
    },
    // Event payload sender field
    ForbiddenEntry {
        field: "sender",
        context: WireContext::EventPayloadOrProjection,
    },
    // Directory projection / search
    ForbiddenEntry {
        field: "name",
        context: WireContext::DirectoryProjection,
    },
    ForbiddenEntry {
        field: "avatar",
        context: WireContext::DirectoryProjection,
    },
    ForbiddenEntry {
        field: "official_organizations",
        context: WireContext::DirectoryProjection,
    },
    ForbiddenEntry {
        field: "parent_realm_id",
        context: WireContext::DirectorySearchRequest,
    },
    // Encrypted envelope
    ForbiddenEntry {
        field: "cleartext_commitment",
        context: WireContext::EncryptedEnvelope,
    },
    // Capability delegate
    ForbiddenEntry {
        field: "source_capability",
        context: WireContext::CapabilityDelegatePayload,
    },
    // Object-patch payload
    ForbiddenEntry {
        field: "object_ref",
        context: WireContext::ObjectPatchPayload,
    },
    ForbiddenEntry {
        field: "object_ref",
        context: WireContext::ObjectLifecyclePayload,
    },
    // Message create payload
    ForbiddenEntry {
        field: "revision_root",
        context: WireContext::MessageCreatePayload,
    },
    // Realm freeze payload
    ForbiddenEntry {
        field: "until",
        context: WireContext::RealmFreezePayload,
    },
    // Account subscribe
    ForbiddenEntry {
        field: "events",
        context: WireContext::AccountSubscribeDeviceMessageContainer,
    },
    ForbiddenEntry {
        field: "space_entry",
        context: WireContext::AccountSubscribeFrameSchemaDef,
    },
    // Agent audit binding
    ForbiddenEntry {
        field: "actor",
        context: WireContext::AgentAuditBinding,
    },
    // Snapshot chunk
    ForbiddenEntry {
        field: "sha256",
        context: WireContext::SnapshotChunk,
    },
    // Moderation payloads
    ForbiddenEntry {
        field: "frank",
        context: WireContext::ModerationReportPayload,
    },
    ForbiddenEntry {
        field: "frank_id",
        context: WireContext::ModerationFrankingProofPayload,
    },
    ForbiddenEntry {
        field: "frank_only",
        context: WireContext::ModerationQueueItemVisibility,
    },
    ForbiddenEntry {
        field: "requires_frank_verification",
        context: WireContext::ModerationQueueItemEvidencePolicy,
    },
    ForbiddenEntry {
        field: "retention_until",
        context: WireContext::ModerationQueueItemEvidencePolicy,
    },
    ForbiddenEntry {
        field: "queue_item_id",
        context: WireContext::ModerationQueueItem,
    },
    // Member delivery binding candidate
    ForbiddenEntry {
        field: "delivery_binding_hint",
        context: WireContext::MemberDeliveryBindingCandidate,
    },
    // Error code
    ForbiddenEntry {
        field: "frank_unavailable",
        context: WireContext::ErrorCode,
    },
    // CRDT lattice enum values
    ForbiddenEntry {
        field: "or-set",
        context: WireContext::CrdtLatticeEnumValue,
    },
    ForbiddenEntry {
        field: "mv-register",
        context: WireContext::CrdtLatticeEnumValue,
    },
    ForbiddenEntry {
        field: "cas-register",
        context: WireContext::CrdtLatticeEnumValue,
    },
    ForbiddenEntry {
        field: "ordered-log",
        context: WireContext::CrdtLatticeEnumValue,
    },
    ForbiddenEntry {
        field: "lww-register",
        context: WireContext::CrdtLatticeEnumValue,
    },
    // Event kind / schema id / capability action values
    ForbiddenEntry {
        field: "cx.agent.key.authorized",
        context: WireContext::EventKind,
    },
    ForbiddenEntry {
        field: "cx.agent.key.revoked",
        context: WireContext::EventKind,
    },
    ForbiddenEntry {
        field: "cx.agent.key.rotated",
        context: WireContext::EventKind,
    },
    ForbiddenEntry {
        field: "cx.device.authorized",
        context: WireContext::EventKind,
    },
    ForbiddenEntry {
        field: "cx.device.revoked",
        context: WireContext::EventKind,
    },
    ForbiddenEntry {
        field: "cx.relation.delete",
        context: WireContext::EventKind,
    },
    ForbiddenEntry {
        field: "cx.read.marker",
        context: WireContext::EventKind,
    },
    ForbiddenEntry {
        field: "cx.read.marker",
        context: WireContext::CapabilityAction,
    },
    ForbiddenEntry {
        field: "cx.schema.read_marker.v1",
        context: WireContext::SchemaId,
    },
    // Flow kind value
    ForbiddenEntry {
        field: "kind=room",
        context: WireContext::FlowPayload,
    },
    // R3.4 naming hard rejects.
    ForbiddenEntry {
        field: "event_hashes",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "cache_until",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "signed_payload_hash",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "avatar_ref",
        context: WireContext::MemberIdentityDisplayProfile,
    },
    ForbiddenEntry {
        field: "icon_blob",
        context: WireContext::AppletProtocolMetadata,
    },
    ForbiddenEntry {
        field: "space_bound",
        context: WireContext::MediaMetadataVisibility,
    },
    ForbiddenEntry {
        field: "sha256",
        context: WireContext::BlobMetadata,
    },
    ForbiddenEntry {
        field: "sha256",
        context: WireContext::BlobUploadMetadata,
    },
    ForbiddenEntry {
        field: "size",
        context: WireContext::BlobUploadMetadata,
    },
    ForbiddenEntry {
        field: "filter_hash",
        context: WireContext::CursorBody,
    },
    ForbiddenEntry {
        field: "derived_hash_prefix",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "application_receipt_hash",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "review_receipt_hash",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "receipt_hash",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "pattern_hash",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "media_hash",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "presentation_hash",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "raw_document_hash",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "signature_over_content_hash",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "prev_frontier_hash",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "constraint_hash",
        context: WireContext::WireSchemaOrPayload,
    },
    // 2026-05-31: single-kind grant constraint identifiers use `_ids`, not `_refs`.
    ForbiddenEntry {
        field: "allowed_view_refs",
        context: WireContext::GrantConstraint,
    },
    ForbiddenEntry {
        field: "allowed_flow_refs",
        context: WireContext::GrantConstraint,
    },
    ForbiddenEntry {
        field: "allowed_circle_refs",
        context: WireContext::GrantConstraint,
    },
    ForbiddenEntry {
        field: "denied_flow_refs",
        context: WireContext::GrantConstraint,
    },
    ForbiddenEntry {
        field: "allowed_space_refs",
        context: WireContext::GrantConstraint,
    },
    ForbiddenEntry {
        field: "denied_space_refs",
        context: WireContext::GrantConstraint,
    },
    ForbiddenEntry {
        field: "realm_refs",
        context: WireContext::GrantConstraint,
    },
    ForbiddenEntry {
        field: "approval_actor_refs",
        context: WireContext::GrantConstraint,
    },
    // 2026-05-31: key-backup KDF algorithm selector.
    ForbiddenEntry {
        field: "hash",
        context: WireContext::KeyBackupKdfParams,
    },
    // 2026-05-31: algorithm / principal / accountability / proof naming.
    ForbiddenEntry {
        field: "signature_alg",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "device_key_alg",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "agent_did",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "audit_agent_did",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "accountable_actor",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "accountable_to",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "thumbnail_ref",
        context: WireContext::BlobMetadata,
    },
    ForbiddenEntry {
        field: "claim_type",
        context: WireContext::HandleClaimTopLevel,
    },
    ForbiddenEntry {
        field: "notary_sig",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "inception_pubkey_fingerprint",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "commitment_b64",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "changed_at",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "via",
        context: WireContext::WireSchemaOrPayload,
    },
    ForbiddenEntry {
        field: "of",
        context: WireContext::ReviewerQuorum,
    },
    ForbiddenEntry {
        field: "actor_kind=ghost",
        context: WireContext::ActorKindValue,
    },
    ForbiddenEntry {
        field: "actor_kind=agent_native",
        context: WireContext::ActorKindValue,
    },
    ForbiddenEntry {
        field: "actor_kind=agent_ghost",
        context: WireContext::ActorKindValue,
    },
    ForbiddenEntry {
        field: "actor_kind=device",
        context: WireContext::ActorKindValue,
    },
    // 2026-06-10: policy check chain bare `actor` → `actor_id`
    // (did_id_suffix rule). Registered under the dotted bound_to.actor
    // path — the bare token `actor` remains a legitimate enum value and
    // prose noun, so it MUST NOT enter the coarse flat list.
    ForbiddenEntry {
        field: "bound_to.actor",
        context: WireContext::PolicyCheckBoundTo,
    },
    // 2026-06 registry sync (SDK-06-003): entries the mirror previously
    // lacked or carried under a collapsed context. Pinned against the JSON
    // registry by `mirror_covers_spec_registry_hard_rejects` below.
    ForbiddenEntry {
        field: "track",
        context: WireContext::FlowTrackKeyField,
    },
    ForbiddenEntry {
        field: "encrypted_payload",
        context: WireContext::ContentCarrierWithContentCounterpart,
    },
    ForbiddenEntry {
        field: "title",
        context: WireContext::FlowOrMorphPayloadTopLevel,
    },
    ForbiddenEntry {
        field: "summary",
        context: WireContext::FlowOrMorphPayloadTopLevel,
    },
    ForbiddenEntry {
        field: "fields",
        context: WireContext::FlowOrMessagePayloadTopLevel,
    },
    ForbiddenEntry {
        field: "blocks",
        context: WireContext::ContentBlockComposite,
    },
    ForbiddenEntry {
        field: "sender_display_name",
        context: WireContext::NotificationProjection,
    },
    ForbiddenEntry {
        field: "actor",
        context: WireContext::MimiUpdateConsentRequestBody,
    },
    ForbiddenEntry {
        field: "requester",
        context: WireContext::MimiRequestConsentRequestBody,
    },
    ForbiddenEntry {
        field: "cotest_run_id",
        context: WireContext::ServiceDescribeVerifiedProfiles,
    },
    ForbiddenEntry {
        field: "cotest_issuer_did",
        context: WireContext::ServiceDescribeVerifiedProfiles,
    },
    ForbiddenEntry {
        field: "signed_payload_hash",
        context: WireContext::FederationVerificationPayload,
    },
    ForbiddenEntry {
        field: "signature_alg",
        context: WireContext::KeyBackupRecoveryAuthData,
    },
    ForbiddenEntry {
        field: "device_key_alg",
        context: WireContext::DeviceAuthorizePayload,
    },
    ForbiddenEntry {
        field: "agent_did",
        context: WireContext::AgentKeyPayload,
    },
    ForbiddenEntry {
        field: "accountable_actor",
        context: WireContext::AgentKeyPayload,
    },
    ForbiddenEntry {
        field: "audit_agent_did",
        context: WireContext::AttestationEvidence,
    },
    ForbiddenEntry {
        field: "changed_at",
        context: WireContext::AgentLifecyclePayload,
    },
    ForbiddenEntry {
        field: "notary_sig",
        context: WireContext::Seal,
    },
    ForbiddenEntry {
        field: "inception_pubkey_fingerprint",
        context: WireContext::DidContinuityProofTransferEvidence,
    },
    ForbiddenEntry {
        field: "by",
        context: WireContext::DidContinuityProofSignatureChain,
    },
    ForbiddenEntry {
        field: "commitment_b64",
        context: WireContext::RecoveryPolicyShareCommitment,
    },
    ForbiddenEntry {
        field: "accountable_to",
        context: WireContext::ActorProfile,
    },
    ForbiddenEntry {
        field: "via",
        context: WireContext::MembershipPayload,
    },
    ForbiddenEntry {
        field: "duration_compact_mini_dsl",
        context: WireContext::WireDurationString,
    },
];

/// Returns `true` when `field` is forbidden in the given `context` per the
/// in-Rust mirror of `forbidden-wire-fields.json`.
pub fn is_forbidden_in_context(field: &str, context: WireContext) -> bool {
    FORBIDDEN_ENTRIES
        .iter()
        .any(|entry| entry.field == field && entry.context == context)
}

/// Typed-id prefixes that MUST NOT appear anywhere on the wire.
///
/// Source of truth: `forbidden-wire-fields.json` entries with
/// `context: typed_id_prefix`. Receivers MUST hard-reject any typed id
/// whose prefix matches an entry here; the canonical replacement is
/// listed in the spec entry.
pub const FORBIDDEN_ID_PREFIXES: &[&str] = &[
    "ck:notif:",
    "ck:devmsg:",
    "ck:keyevt:",
    "ck:modq:",
    "ck:req:",
    "ck:txn:",
    "ck:frank:",
    "ck:rtcpart:",
];

/// Returns `true` when `id` starts with a forbidden typed-id prefix
/// (e.g. `ck:notif:01234...` — canonical is `ck:notification:`).
pub fn is_forbidden_id_prefix(id: &str) -> bool {
    FORBIDDEN_ID_PREFIXES
        .iter()
        .any(|prefix| id.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_replacements() {
        for field in [
            "scope_circle_id",
            "default_scope_circle_id",
            "parent_space_id",
        ] {
            assert!(
                !is_forbidden_wire_field(field),
                "canonical replacement `{field}` must not be hard-rejected"
            );
        }
    }

    #[test]
    fn context_aware_distinguishes_policy_ref_scopes() {
        // policy_ref is canonical on Realm itself (object-self id) but
        // forbidden on handle_claim / member_delivery_binding scopes.
        assert!(is_forbidden_in_context(
            "policy_ref",
            WireContext::HandleClaimTopLevel
        ));
        assert!(is_forbidden_in_context(
            "policy_ref",
            WireContext::MemberDeliveryBinding
        ));
        // Not flagged in a context the spec doesn't restrict.
        assert!(!is_forbidden_in_context(
            "policy_ref",
            WireContext::RealmFreezePayload
        ));
    }

    #[test]
    fn context_aware_patch_path_distinguishes_field_vs_path() {
        // `stage` as a JSON-Patch path on a Flow patch payload is
        // forbidden (single-source via ck.flow.stage.set).
        assert!(is_forbidden_in_context("stage", WireContext::FlowPatchPath));
        assert!(is_forbidden_in_context(
            "stage_changed_at",
            WireContext::FlowPatchPath
        ));
        assert!(is_forbidden_in_context(
            "stage",
            WireContext::MorphPatchPath
        ));
        // But `stage` as a top-level Flow payload field is canonical.
        assert!(!is_forbidden_in_context("stage", WireContext::FlowPayload));
    }

    #[test]
    fn context_aware_fields_dot_stage_rejected_on_flow_and_morph() {
        assert!(is_forbidden_in_context(
            "metadata.fields.stage",
            WireContext::FlowPayload
        ));
        assert!(is_forbidden_in_context(
            "fields.stage",
            WireContext::MorphPayload
        ));
        assert!(is_forbidden_in_context(
            "metadata.fields.stage_changed_at",
            WireContext::FlowPayload
        ));
        assert!(is_forbidden_in_context(
            "metadata.fields.assignee",
            WireContext::FlowPayload
        ));
        assert!(is_forbidden_in_context(
            "metadata.fields.assigned_to",
            WireContext::FlowPayload
        ));
        assert!(is_forbidden_in_context(
            "metadata.fields.assignee",
            WireContext::FlowPatchPath
        ));
        assert!(is_forbidden_in_context(
            "fields.assignee",
            WireContext::FlowPatchPath
        ));
        // Not flagged on unrelated payload contexts.
        assert!(!is_forbidden_in_context(
            "fields.stage",
            WireContext::SpacePayload
        ));
    }

    #[test]
    fn context_aware_crdt_lattice_enum_values_rejected() {
        // Hyphenated CRDT lattice values are forbidden; snake_case is the
        // canonical spelling.
        for value in ["or-set", "mv-register", "cas-register", "lww-register"] {
            assert!(
                is_forbidden_in_context(value, WireContext::CrdtLatticeEnumValue),
                "CRDT lattice value `{value}` must be in the hard-reject set"
            );
        }
        // snake_case canonical spellings pass.
        for value in ["or_set", "mv_register", "lww_register"] {
            assert!(!is_forbidden_in_context(
                value,
                WireContext::CrdtLatticeEnumValue
            ));
        }
    }

    /// Map a spec registry `context` string onto the [`WireContext`]
    /// variants the SDK mirror uses. A registry context that maps to more
    /// than one variant requires the field to be forbidden in *each* of
    /// them.
    fn registry_contexts(context: &str) -> Option<&'static [WireContext]> {
        use WireContext::*;
        Some(match context {
            "timeline_event_top_level" => &[TimelineEventTopLevel],
            "flow_track_key_field" => &[FlowTrackKeyField],
            "content_carrier_with_content_counterpart" => &[ContentCarrierWithContentCounterpart],
            "flow_or_morph_payload_top_level" => &[FlowOrMorphPayloadTopLevel],
            "flow_or_message_payload_top_level" => &[FlowOrMessagePayloadTopLevel],
            "event_envelope_or_payload" => &[EventEnvelopeOrPayloadTopLevel],
            // `kind=room` is checked against the Flow payload context by the
            // Event wire-surface validator.
            "flow_payload.kind" | "flow_payload" => &[FlowPayload],
            "morph_payload" => &[MorphPayload],
            "space_payload" => &[SpacePayload],
            "relation_payload" => &[RelationPayload],
            "message_create_payload" => &[MessageCreatePayload],
            "content_block_composite" => &[ContentBlockComposite],
            "encrypted_envelope" => &[EncryptedEnvelope],
            "flow_patch_payload" => &[FlowPatchPath],
            "morph_patch_payload" => &[MorphPatchPath],
            "wire_schema_or_payload" => &[WireSchemaOrPayload],
            "proof_or_cross_signing_payload" => &[ProofOrCrossSigningPayload],
            "event_payload_or_projection" => &[EventPayloadOrProjection],
            "notification_projection" => &[NotificationProjection],
            "notification_payload" => &[NotificationPayload],
            "event_proof" => &[EventProof],
            "generic_proof" => &[GenericProof],
            "event_kind" => &[EventKind],
            "event_kind_or_capability_action" => &[EventKind, CapabilityAction],
            "schema_id" => &[SchemaId],
            "join_policy_payload" => &[JoinPolicyPayload],
            "capability_delegate_payload" => &[CapabilityDelegatePayload],
            "directory_search_request" => &[DirectorySearchRequest],
            "directory_projection" => &[DirectoryProjection],
            "account_subscribe_frame_schema_def" => &[AccountSubscribeFrameSchemaDef],
            "account_subscribe_device_message_container" => {
                &[AccountSubscribeDeviceMessageContainer]
            }
            "member_delivery_binding" => &[MemberDeliveryBinding],
            "member_delivery_binding_candidate" => &[MemberDeliveryBindingCandidate],
            "moderation_report_payload" => &[ModerationReportPayload],
            "moderation_franking_proof_payload" => &[ModerationFrankingProofPayload],
            "moderation_queue_item" => &[ModerationQueueItem],
            "moderation_queue_item.visibility" => &[ModerationQueueItemVisibility],
            "moderation_queue_item.evidence_policy" => &[ModerationQueueItemEvidencePolicy],
            "error_code" => &[ErrorCode],
            "handle_claim_top_level" => &[HandleClaimTopLevel],
            "protocol_subject_field" => &[ProtocolSubjectField],
            "policy_check_bound_to" => &[PolicyCheckBoundTo],
            "mimi_update_consent_request_body" => &[MimiUpdateConsentRequestBody],
            "mimi_request_consent_request_body" => &[MimiRequestConsentRequestBody],
            "service_describe_verified_profiles" => &[ServiceDescribeVerifiedProfiles],
            "crdt_lattice_enum" => &[CrdtLatticeEnumValue],
            "realm_freeze_payload" => &[RealmFreezePayload],
            "agent.audit_binding" => &[AgentAuditBinding],
            "snapshot.chunks[]" => &[SnapshotChunk],
            "object_patch_payload" => &[ObjectPatchPayload],
            "object_lifecycle_payload" => &[ObjectLifecyclePayload],
            "federation_verification_payload" => &[FederationVerificationPayload],
            "member_identity.display_profile" => &[MemberIdentityDisplayProfile],
            "applet_protocol_metadata" => &[AppletProtocolMetadata],
            "media_metadata.visibility" => &[MediaMetadataVisibility],
            "blob_metadata" => &[BlobMetadata],
            "blob_upload_metadata" => &[BlobUploadMetadata],
            "key_backup.encryption.kdf.params" => &[KeyBackupKdfParams],
            "key_backup_recovery_auth_data" => &[KeyBackupRecoveryAuthData],
            "device_authorize_payload" => &[DeviceAuthorizePayload],
            "agent_key_payload" => &[AgentKeyPayload],
            "attestation_evidence" => &[AttestationEvidence],
            "agent_lifecycle_payload" => &[AgentLifecyclePayload],
            "seal" => &[Seal],
            "did_continuity_proof.transfer_evidence" => &[DidContinuityProofTransferEvidence],
            "did_continuity_proof.signature_chain" => &[DidContinuityProofSignatureChain],
            "recovery_policy.share_commitment" => &[RecoveryPolicyShareCommitment],
            "actor_profile.actor_kind" => &[ActorKindValue],
            "actor_profile" => &[ActorProfile],
            "reviewer_quorum" => &[ReviewerQuorum],
            "membership_payload" => &[MembershipPayload],
            "wire_duration_string" => &[WireDurationString],
            "frontier_object_property" => &[FrontierObjectProperty],
            "child_scope_policy.kind" => &[ChildScopePolicyKind],
            _ => return None,
        })
    }

    /// Drift guard (SDK-06-003): every `hard_reject` entry in the spec
    /// registry `forbidden-wire-fields.json` must be representable and
    /// rejected by this in-Rust mirror — same lockstep discipline as the
    /// generated event-kind / profile tables. Direction is registry ⊆
    /// mirror: the mirror may keep extra collapsed-context entries, but a
    /// spec entry the mirror does not reject is a drift failure.
    #[test]
    fn mirror_covers_spec_registry_hard_rejects() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let path = [
            manifest_dir
                .join("../../../cokret-spec/spec/v1/artifacts/registry/forbidden-wire-fields.json"),
            std::path::PathBuf::from(
                "../cokret-spec/spec/v1/artifacts/registry/forbidden-wire-fields.json",
            ),
        ]
        .into_iter()
        .find(|path| path.exists())
        .unwrap_or_else(|| {
            panic!(
                "spec forbidden-wire-fields registry is required for drift tests; \
                 looked next to {}",
                manifest_dir.display()
            )
        });
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        let registry: serde_json::Value = serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));
        let entries = registry
            .get("entries")
            .and_then(serde_json::Value::as_array)
            .expect("registry has an entries array");
        assert!(!entries.is_empty());

        for entry in entries {
            let id = entry
                .get("id")
                .and_then(serde_json::Value::as_str)
                .expect("entry id");
            let context = entry
                .get("context")
                .and_then(serde_json::Value::as_str)
                .expect("entry context");
            let level = entry
                .get("rejection_level")
                .and_then(serde_json::Value::as_str)
                .expect("entry rejection_level");
            if level != "hard_reject" {
                // The mirror intentionally enumerates only the hard_reject
                // set (`migration_only` / `docs_only` are not receiver-side
                // concerns).
                continue;
            }

            // Typed-id prefixes live in their own table.
            if context == "typed_id_prefix" {
                assert!(
                    FORBIDDEN_ID_PREFIXES.contains(&id),
                    "registry typed-id prefix {id:?} is missing from FORBIDDEN_ID_PREFIXES"
                );
                continue;
            }

            // Batch entries expand to the concrete field names the mirror
            // enumerates one by one.
            if id == "identifier_suffix_ref_to_id_batch" {
                for field in [
                    "parent_ref",
                    "default_realm_ref",
                    "scope_ref",
                    "default_scope_ref",
                    "retention_policy_ref",
                    "disclosure_policy_ref",
                    "rate_limit_policy_ref",
                ] {
                    assert!(
                        is_forbidden_in_context(field, WireContext::EventEnvelopeOrPayloadTopLevel),
                        "batch identifier rename field {field:?} is missing from the mirror"
                    );
                }
                // policy_ref stays canonical on a Policy object itself; the
                // mirror pins its two forbidden scopes explicitly.
                assert!(is_forbidden_in_context(
                    "policy_ref",
                    WireContext::HandleClaimTopLevel
                ));
                assert!(is_forbidden_in_context(
                    "policy_ref",
                    WireContext::MemberDeliveryBinding
                ));
                continue;
            }
            if id == "grant_constraint_single_kind_refs_to_ids" {
                for field in [
                    "allowed_view_refs",
                    "allowed_flow_refs",
                    "allowed_circle_refs",
                    "denied_flow_refs",
                    "allowed_space_refs",
                    "denied_space_refs",
                    "realm_refs",
                    "approval_actor_refs",
                ] {
                    assert!(
                        is_forbidden_in_context(field, WireContext::GrantConstraint),
                        "grant constraint rename field {field:?} is missing from the mirror"
                    );
                }
                continue;
            }

            // `patch:` ids are JSON-Patch op paths; the checker takes the
            // bare path and re-prefixes internally. `#`-suffixed ids carry a
            // registry-side disambiguator after the field name.
            let field = id.strip_prefix("patch:").unwrap_or(id);
            let field = field.split_once('#').map_or(field, |(field, _)| field);

            let contexts = registry_contexts(context).unwrap_or_else(|| {
                panic!("registry context {context:?} (id {id:?}) has no mirror mapping")
            });
            for mapped in contexts {
                assert!(
                    is_forbidden_in_context(field, *mapped),
                    "registry entry {id:?} (context {context:?}) is not rejected by the mirror \
                     in {mapped:?}"
                );
            }
        }
    }
}
