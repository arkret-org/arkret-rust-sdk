//! Public Rust counterparts for JSON Schema names that do not yet need
//! bespoke SDK structs.
//!
//! Concrete OpenAPI body DTOs and stable protocol resources live in the
//! surrounding model modules. The aliases here keep every named schema
//! addressable from `cokret-core` while reusing existing canonical SDK
//! types or preserving open/union JSON schema shapes as `Value`.

use super::*;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json`.
pub type AccountOperations = Value;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/device_summaries`.
pub type DeviceSummaries = Vec<DeviceSummary>;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/device_summary`.
pub type DeviceSummary = Value;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/did_url`.
pub type DidUrl = String;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/display_name`.
pub type DisplayName = String;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/handle_claim_digests`.
pub type HandleClaimDigests = Vec<Hash>;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/handle_claim_ref`.
pub type HandleClaimRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/non_empty_string`.
pub type NonEmptyString = String;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/profile_patch`.
pub type ProfilePatch = Value;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/sha256_digest`.
pub type Sha256Digest = Hash;

/// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/timestamp`.
pub type Timestamp = DateTime<Utc>;

/// Counterpart for `spec/v1/artifacts/schemas/account-subscribe-frame.schema.json#/$defs/cursor_or_data_or_control_payload_present`.
pub type CursorOrDataOrControlPayloadPresent = Value;

/// Counterpart for `spec/v1/artifacts/schemas/account-subscribe-frame.schema.json#/$defs/cursor_or_data_payload_present`.
pub type CursorOrDataPayloadPresent = Value;

/// Counterpart for `spec/v1/artifacts/schemas/account-subscribe-frame.schema.json#/$defs/cursor_value`.
pub type CursorValue = Value;

/// Counterpart for `spec/v1/artifacts/schemas/account-subscribe-frame.schema.json#/$defs/data_or_control_payload_present`.
pub type DataOrControlPayloadPresent = Value;

/// Counterpart for `spec/v1/artifacts/schemas/account-subscribe-frame.schema.json#/$defs/device_message_container`.
pub type DeviceMessageContainer = Value;

/// Counterpart for `spec/v1/artifacts/schemas/account-subscribe-frame.schema.json#/$defs/event_container`.
pub type EventContainer = Value;

/// Counterpart for `spec/v1/artifacts/schemas/account-subscribe-frame.schema.json#/$defs/realm_sync_entry`.
pub type RealmSyncEntry = Value;

/// Counterpart for `spec/v1/artifacts/schemas/account-subscribe-frame.schema.json#/$defs/reconnect_after_present`.
pub type ReconnectAfterPresent = Value;

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json`.
pub type AgentOperations = Value;

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/base64url`.
pub type Base64url = String;

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/grant_snapshot`.
pub type GrantSnapshot = Value;

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/key_state`.
pub type KeyState = Value;

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/opaque_local_id`.
pub type OpaqueLocalId = String;

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/operation_status_outcome`.
pub type OperationStatusOutcome = Value;

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/pending_member_reconciliation_item`.
pub type PendingMemberReconciliationItem = Value;

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/public_key`.
pub type PublicKey = Value;

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/runtime_attestation`.
pub type RuntimeAttestation = AgentKeyAuthorizePayload;

/// Counterpart for `spec/v1/artifacts/schemas/agent-operations.schema.json#/$defs/sidecar_exposure_ack`.
pub type SidecarExposureAck = AgentSidecarExposureAck;

/// Counterpart for `spec/v1/artifacts/schemas/agent.schema.json`.
pub type Agent = Value;

/// Counterpart for `spec/v1/artifacts/schemas/anchor.schema.json#/$defs/anchor_ref`.
pub type AnchorRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/anchor.schema.json#/$defs/event_digest`.
pub type EventDigest = Hash;

/// Counterpart for `spec/v1/artifacts/schemas/anchor.schema.json#/$defs/signature`.
pub type Signature = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-edge-operations.schema.json`.
pub type AppletEdgeOperations = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/external_ref`.
pub type ExternalRef = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/field_type`.
pub type FieldType = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/protocol`.
pub type Protocol = String;

/// Counterpart for `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/protocol_instance`.
pub type ProtocolInstance = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/rejected_item`.
pub type RejectedItem = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-edge-operations.schema.json#/$defs/third_party_query`.
pub type ThirdPartyQuery = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-install-operations.schema.json`.
pub type AppletInstallOperations = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-install-operations.schema.json#/$defs/e2ee_policy`.
pub type E2eePolicy = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-install-operations.schema.json#/$defs/scope_grant`.
pub type ScopeGrant = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-install-operations.schema.json#/$defs/typed_ref`.
pub type TypedRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/capability_constraint`.
pub type CapabilityConstraint = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/denied_scope`.
pub type DeniedScope = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/e2ee_effect`.
pub type E2eeEffect = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/event_submission`.
pub type EventSubmission = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/namespace_conflict`.
pub type NamespaceConflict = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-install-plan.schema.json#/$defs/widget_effect`.
pub type WidgetEffect = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/applet_namespaces`.
pub type AppletNamespaces = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/delegation_policy`.
pub type DelegationPolicy = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/detached_proof`.
pub type DetachedProof = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/endpoint_entry`.
pub type EndpointEntry = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/endpoint_set`.
pub type EndpointSet = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/ghost_policy`.
pub type GhostPolicy = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/limits`.
pub type Limits = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/namespace_entry`.
pub type NamespaceEntry = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/non_empty_string_array`.
pub type NonEmptyStringArray = Vec<NonEmptyString>;

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/profile_id`.
pub type ProfileId = String;

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/signature_alg`.
pub type SignatureAlg = String;

/// Counterpart for `spec/v1/artifacts/schemas/applet-package.schema.json#/$defs/widget`.
pub type Widget = Value;

/// Counterpart for `spec/v1/artifacts/schemas/applet.schema.json`.
pub type Applet = Value;

/// Counterpart for `spec/v1/artifacts/schemas/authz-operations.schema.json`.
pub type AuthzOperations = Value;

/// Counterpart for `spec/v1/artifacts/schemas/blob-operations.schema.json`.
pub type BlobOperations = Value;

/// Counterpart for `spec/v1/artifacts/schemas/blob-operations.schema.json#/$defs/media_type`.
pub type MediaType = String;

/// Counterpart for `spec/v1/artifacts/schemas/blob-operations.schema.json#/$defs/upload_receipt`.
pub type UploadReceipt = Value;

/// Counterpart for `spec/v1/artifacts/schemas/blob.schema.json`.
pub type Blob = Value;

/// Counterpart for `spec/v1/artifacts/schemas/calendar-event.schema.json`.
pub type CalendarEvent = CalendarEventFields;

/// Counterpart for `spec/v1/artifacts/schemas/calendar-event.schema.json#/$defs/attendee`.
pub type Attendee = CalendarAttendee;

/// Counterpart for `spec/v1/artifacts/schemas/circle.schema.json#/$defs/display`.
pub type Display = Value;

/// Counterpart for `spec/v1/artifacts/schemas/common-ids.schema.json`.
pub type CommonIds = Value;

/// Counterpart for `spec/v1/artifacts/schemas/contact-operations.schema.json`.
pub type ContactOperations = Value;

/// Counterpart for `spec/v1/artifacts/schemas/contact-operations.schema.json#/$defs/consent_scope`.
pub type ConsentScope = String;

/// Counterpart for `spec/v1/artifacts/schemas/contact-operations.schema.json#/$defs/consent_scope_list`.
pub type ConsentScopeList = Vec<ConsentScope>;

/// Counterpart for `spec/v1/artifacts/schemas/contact-operations.schema.json#/$defs/consent_scopes`.
pub type ConsentScopes = Vec<ConsentScope>;

/// Counterpart for `spec/v1/artifacts/schemas/contact-operations.schema.json#/$defs/event_refs`.
pub type EventRefs = Vec<EventId>;

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-publish.schema.json`.
pub type CrossSigningPublish = Value;

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-publish.schema.json#/$defs/alg`.
pub type Alg = String;

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-publish.schema.json#/$defs/key_format`.
pub type KeyFormat = String;

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-publish.schema.json#/$defs/kid`.
pub type Kid = String;

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-publish.schema.json#/$defs/published_key`.
pub type PublishedKey = Value;

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-publish.schema.json#/$defs/subordinate_signed_key`.
pub type SubordinateSignedKey = Value;

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-reset.schema.json`.
pub type CrossSigningReset = Value;

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-reset.schema.json#/$defs/device_quorum_proof`.
pub type DeviceQuorumProof = Value;

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-reset.schema.json#/$defs/principal_signing_proof`.
pub type PrincipalSigningProof = Value;

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-reset.schema.json#/$defs/recovery_unlock_proof`.
pub type RecoveryUnlockProof = Value;

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-reset.schema.json#/$defs/signature_b64u`.
pub type SignatureB64u = String;

/// Counterpart for `spec/v1/artifacts/schemas/cross-signing-reset.schema.json#/$defs/trusted_recovery_service_proof`.
pub type TrustedRecoveryServiceProof = Value;

/// Counterpart for `spec/v1/artifacts/schemas/delivery-binding-stale.schema.json`.
pub type DeliveryBindingStale = Value;

/// Counterpart for `spec/v1/artifacts/schemas/delivery-binding-stale.schema.json#/$defs/event_id_list`.
pub type EventIdList = Vec<EventId>;

/// Counterpart for `spec/v1/artifacts/schemas/device-message.schema.json#/$defs/key_verification_content`.
pub type KeyVerificationContent = Value;

/// Counterpart for `spec/v1/artifacts/schemas/device-message.schema.json#/$defs/string_list`.
pub type StringList = Vec<String>;

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json`.
pub type DirectoryOperations = Value;

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/blinded_contact`.
pub type BlindedContact = Value;

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/freshness_fields`.
pub type FreshnessFields = Value;

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/intent`.
pub type Intent = String;

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/invite_consent_handoff_stub`.
pub type InviteConsentHandoffStub = Value;

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/object_preview`.
pub type ObjectPreview = Value;

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/pagination_request`.
pub type PaginationRequest = Value;

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/private_contact_match`.
pub type PrivateContactMatch = Value;

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/proofs`.
pub type Proofs = Vec<Proof>;

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/source_refs`.
pub type SourceRefs = Vec<EventId>;

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/subscription_id`.
pub type SubscriptionId = String;

/// Counterpart for `spec/v1/artifacts/schemas/directory-operations.schema.json#/$defs/user_search_outcome`.
pub type UserSearchOutcome = Value;

/// Counterpart for `spec/v1/artifacts/schemas/disappearing-messages.schema.json`.
pub type DisappearingMessages = Value;

/// Counterpart for `spec/v1/artifacts/schemas/draft-sync.schema.json`.
pub type DraftSync = DraftSyncValue;

/// Counterpart for `spec/v1/artifacts/schemas/encrypted-envelope.schema.json`.
pub type EncryptedEnvelope = Value;

/// Counterpart for `spec/v1/artifacts/schemas/erasure-receipt.schema.json#/$defs/subject_ref`.
pub type SubjectRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/erasure-receipt.schema.json#/$defs/verification_stub`.
pub type VerificationStub = Value;

/// Counterpart for `spec/v1/artifacts/schemas/erasure-verification-stub.schema.json`.
pub type ErasureVerificationStub = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-batch-receipt.schema.json`.
pub type EventBatchReceipt = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/board_space_id`.
pub type BoardSpaceId = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/event_proof`.
pub type EventProof = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/feature_ref`.
pub type FeatureRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/grant_ref`.
pub type GrantRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/list_space_id`.
pub type ListSpaceId = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/profile_ref`.
pub type ProfileRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/rank`.
pub type Rank = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-envelope.schema.json#/$defs/track_name`.
pub type TrackName = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json`.
pub type EventPayload = GenericStandardPayload;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/account_status_payload`.
pub type AccountStatusPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/actor_profile_create_payload`.
pub type ActorProfileCreatePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_action_approve_payload`.
pub type AgentActionApprovePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_action_reject_payload`.
pub type AgentActionRejectPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_action_request_payload`.
pub type AgentActionRequestPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_action_target`.
pub type AgentActionTarget = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_deactivate_payload`.
pub type AgentDeactivatePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_draft_propose_payload`.
pub type AgentDraftProposePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_endpoint_payload`.
pub type AgentEndpointPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_interop_session_id`.
pub type AgentInteropSessionId = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_interop_session_result_payload`.
pub type AgentInteropSessionResultPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_interop_session_start_payload`.
pub type AgentInteropSessionStartPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_interop_session_status_payload`.
pub type AgentInteropSessionStatusPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_approval_evidence`.
pub type AgentKeyApprovalEvidence = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_authorize_payload`.
pub type AgentKeyAuthorizePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_revoke_payload`.
pub type AgentKeyRevokePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_key_rotate_payload`.
pub type AgentKeyRotatePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_lifecycle_frontier`.
pub type AgentLifecycleFrontier = BTreeMap<String, Value>;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_pause_payload`.
pub type AgentPausePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_resume_payload`.
pub type AgentResumePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/agent_sidecar_exposure_ack`.
pub type AgentSidecarExposureAck = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/anchor_frontier`.
pub type AnchorFrontier = Vec<Hash>;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/applet_bridge_error_payload`.
pub type AppletBridgeErrorPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/applet_interop_session_start_payload`.
pub type AppletInteropSessionStartPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/applet_interop_session_status_payload`.
pub type AppletInteropSessionStatusPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/applet_registration_payload`.
pub type AppletRegistrationPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_accessed_payload`.
pub type AuditAccessedPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_applet_binding_payload`.
pub type AuditAppletBindingPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_binding_id`.
pub type AuditBindingId = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_payload`.
pub type AuditPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_release_id`.
pub type AuditReleaseId = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_release_payload`.
pub type AuditReleasePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_session_authorize_payload`.
pub type AuditSessionAuthorizePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_session_close_payload`.
pub type AuditSessionClosePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_session_id`.
pub type AuditSessionId = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_session_notice_payload`.
pub type AuditSessionNoticePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_session_payload`.
pub type AuditSessionPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/audit_session_request_payload`.
pub type AuditSessionRequestPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/call_participant`.
pub type CallParticipant = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/call_payload`.
pub type CallPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/call_state_payload`.
pub type CallStatePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/capability_grant_payload`.
pub type CapabilityGrantPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/capability_revoke_payload`.
pub type CapabilityRevokePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_anchor_commit_payload`.
pub type CircleAnchorCommitPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_create_payload`.
pub type CircleCreatePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_member_state_payload`.
pub type CircleMemberStatePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/circle_patch_payload`.
pub type CirclePatchPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/consent_grant_payload`.
pub type ConsentGrantPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_accepted_payload`.
pub type ContactAcceptedPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_consent_scope`.
pub type ContactConsentScope = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_consent_scopes`.
pub type ContactConsentScopes = Vec<ContactConsentScope>;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_event_refs`.
pub type ContactEventRefs = Vec<EventRef>;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_rejected_payload`.
pub type ContactRejectedPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_requested_payload`.
pub type ContactRequestedPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/contact_tombstoned_payload`.
pub type ContactTombstonedPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/container_position_payload`.
pub type ContainerPositionPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/content_kind`.
pub type ContentKind = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/cross_signing_publish_payload`.
pub type CrossSigningPublishPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_authorize_payload`.
pub type DeviceAuthorizePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_cross_signing_binding`.
pub type DeviceCrossSigningBinding = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_list_update_payload`.
pub type DeviceListUpdatePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_or_principal_ref`.
pub type DeviceOrPrincipalRef = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/device_revoke_payload`.
pub type DeviceRevokePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/direct_conversation_bound_payload`.
pub type DirectConversationBoundPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/encrypted_metadata`.
pub type EncryptedMetadata = EncryptedEnvelope;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/erasure_receipt_payload`.
pub type ErasureReceiptPayload = ErasureReceipt;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/flow_create_payload`.
pub type FlowCreatePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/flow_move_payload`.
pub type FlowMovePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/flow_reorder_payload`.
pub type FlowReorderPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/flow_stage_set_payload`.
pub type FlowStageSetPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/flow_watch_set_payload`.
pub type FlowWatchSetPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/generic_standard_payload`.
pub type GenericStandardPayload = BTreeMap<String, Value>;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/hierarchy_link_status`.
pub type HierarchyLinkStatus = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/history_sharing_policy_payload`.
pub type HistorySharingPolicyPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/history_sharing_restricted_rule`.
pub type HistorySharingRestrictedRule = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/history_visibility_payload`.
pub type HistoryVisibilityPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/history_visibility_value`.
pub type HistoryVisibilityValue = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/inheritance_policy_status`.
pub type InheritancePolicyStatus = String;

// `invite_payload` anyOf branches now have strong types in
// `model::operation_payloads`: `InviteCreatePayload` (directed-create) and
// `InviteRefPayload` (invite_id ref, for accept/cancel). The full union is
// not modeled as one type (the remaining anyOf branches — `invite`,
// `third_party_id`, claim-proof — are not constructed by the client wire).

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/join_policy_payload`.
pub type JoinPolicyPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/key_backup_active_series_payload`.
pub type KeyBackupActiveSeriesPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/list_reorder_payload`.
pub type ListReorderPayload = Value;

// `membership_payload` now has a strong type:
// `model::operation_payloads::MembershipPayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration; carries the
// `MembershipPayloadState` enum and enforces the join/routable conditional
// required fields).

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/message_metadata_fields`.
pub type MessageMetadataFields = BTreeMap<String, Value>;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/message_redact_payload`.
pub type MessageRedactPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/message_revise_payload`.
pub type MessageRevisePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mimi_room_binding_payload`.
pub type MimiRoomBindingPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_commit_failed_payload`.
pub type MlsCommitFailedPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_epoch_range`.
pub type MlsEpochRange = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_genesis_payload`.
pub type MlsGenesisPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_governance_binding`.
pub type MlsGovernanceBinding = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_keypackage_payload`.
pub type MlsKeypackagePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_proposal_payload`.
pub type MlsProposalPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/mls_welcome_payload`.
pub type MlsWelcomePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/moderation_decision_lift_payload`.
pub type ModerationDecisionLiftPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/moderation_decision_payload`.
pub type ModerationDecisionPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/moderation_report_payload`.
pub type ModerationReportPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/morph_create_payload`.
pub type MorphCreatePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/morph_schema_migrate_payload`.
pub type MorphSchemaMigratePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/morph_stage_set_payload`.
pub type MorphStageSetPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/nullable_timestamp`.
pub type NullableTimestamp = Option<DateTime<Utc>>;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/object_lifecycle_payload`.
pub type ObjectLifecyclePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/object_snapshot`.
pub type ObjectSnapshot = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/object_stage_set_payload`.
pub type ObjectStageSetPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/patch_operation`.
pub type PatchOperation = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/patch_path`.
pub type PatchPath = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/patch_value`.
pub type PatchValue = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/plaintext_data_class`.
pub type PlaintextDataClass = String;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/plaintext_visible_services_payload`.
pub type PlaintextVisibleServicesPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/preview_policy_payload`.
pub type PreviewPolicyPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/profile_realm_override_payload`.
pub type ProfileRealmOverridePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/reaction_encrypted_payload_plaintext`.
pub type ReactionEncryptedPayloadPlaintext = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/reaction_payload`.
pub type ReactionPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/read_receipt_policy_payload`.
pub type ReadReceiptPolicyPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_archive_payload`.
pub type RealmArchivePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_create_payload`.
pub type RealmCreatePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_destroy_payload`.
pub type RealmDestroyPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_disappearing_policy_payload`.
pub type RealmDisappearingPolicyPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_freeze_payload`.
pub type RealmFreezePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_inheritance_policy_payload`.
pub type RealmInheritancePolicyPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_scope`.
pub type RealmKeyScope = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_share_audit_payload`.
pub type RealmKeyShareAuditPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_share_payload`.
pub type RealmKeySharePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_withheld_payload`.
pub type RealmKeyWithheldPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_search_policy_payload`.
pub type RealmSearchPolicyPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_tombstone_payload`.
pub type RealmTombstonePayload = Value;

// `relation_create_payload` now has a strong type:
// `model::operation_payloads::RelationCreatePayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration).

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/relation_update_payload`.
pub type RelationUpdatePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/signature_material`.
pub type SignatureMaterial = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/space_create_payload`.
pub type SpaceCreatePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/space_parent_payload`.
pub type SpaceParentPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/space_patch_payload`.
pub type SpacePatchPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/state_payload`.
pub type StatePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/view_payload`.
pub type ViewPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/flow.schema.json#/$defs/flow_track`.
pub type FlowTrack = Value;

/// Counterpart for `spec/v1/artifacts/schemas/flow.schema.json#/$defs/metadata_fields`.
pub type MetadataFields = BTreeMap<String, Value>;

/// Counterpart for `spec/v1/artifacts/schemas/ice-config-response.schema.json`.
pub type IceConfigOutcome = MediaIceConfigOutcome;

/// Counterpart for `spec/v1/artifacts/schemas/identity-receipt.schema.json`.
pub type IdentityReceipt = Value;

/// Counterpart for `spec/v1/artifacts/schemas/key-backup-active-series.schema.json#/$defs/frontier_ref`.
pub type FrontierRef = Value;

/// Counterpart for `spec/v1/artifacts/schemas/key-backup-plaintext.schema.json`.
pub type KeyBackupPlaintext = Value;

/// Counterpart for `spec/v1/artifacts/schemas/key-backup-plaintext.schema.json#/$defs/item_type`.
pub type ItemType = String;

/// Counterpart for `spec/v1/artifacts/schemas/key-backup-plaintext.schema.json#/$defs/plaintext_item`.
pub type PlaintextItem = Value;

/// Counterpart for `spec/v1/artifacts/schemas/key-backup-unlock-proof.schema.json`.
pub type KeyBackupUnlockProof = Value;

/// Counterpart for `spec/v1/artifacts/schemas/key-backup-unlock-proof.schema.json#/$defs/proof_kind`.
pub type ProofKind = String;

/// Counterpart for `spec/v1/artifacts/schemas/keypackage-operations.schema.json`.
pub type KeypackageOperations = Value;

/// Counterpart for `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/failure`.
pub type Failure = Value;

/// Counterpart for `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/keypackage_claim_record`.
pub type KeypackageClaimRecord = Value;

/// Counterpart for `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/keypackage_ref_array`.
pub type KeypackageRefArray = Vec<ObjectRef>;

/// Counterpart for `spec/v1/artifacts/schemas/keypackage-operations.schema.json#/$defs/keypackage_upload_entry`.
pub type KeypackageUploadEntry = Value;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json`.
pub type KeysOperations = Value;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/algorithm_counts`.
pub type AlgorithmCounts = BTreeMap<String, u64>;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/algorithm_key_records`.
pub type AlgorithmKeyRecords = BTreeMap<String, KeyRecord>;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/backup_metadata`.
pub type BackupMetadata = Value;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/device_algorithm_map`.
pub type DeviceAlgorithmMap = BTreeMap<String, NonEmptyString>;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/device_key_records`.
pub type DeviceKeyRecords = BTreeMap<String, AlgorithmKeyRecords>;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/key_record`.
pub type KeyRecord = Value;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/principal_device_algorithm_map`.
pub type PrincipalDeviceAlgorithmMap = BTreeMap<String, DeviceAlgorithmMap>;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/principal_device_key_records`.
pub type PrincipalDeviceKeyRecords = BTreeMap<String, DeviceKeyRecords>;

/// Counterpart for `spec/v1/artifacts/schemas/keys-operations.schema.json#/$defs/query_device_map`.
pub type QueryDeviceMap = BTreeMap<String, Vec<DeviceId>>;

/// Counterpart for `spec/v1/artifacts/schemas/list-handles-for-subject-response.schema.json`.
pub type ListHandlesForSubjectOutcome = DirectorySubjectHandleList;

/// Counterpart for `spec/v1/artifacts/schemas/media-operations.schema.json`.
pub type MediaOperations = Value;

/// Counterpart for `spec/v1/artifacts/schemas/message.schema.json`.
pub type Message = Value;

/// Counterpart for `spec/v1/artifacts/schemas/mimi-interop.schema.json`.
pub type MimiInterop = Value;

/// Counterpart for `spec/v1/artifacts/schemas/mimi-interop.schema.json#/$defs/content_mapping_receipt`.
pub type ContentMappingReceipt = Value;

/// Counterpart for `spec/v1/artifacts/schemas/mimi-interop.schema.json#/$defs/mimi_uri`.
pub type MimiUri = String;

/// Counterpart for `spec/v1/artifacts/schemas/mimi-interop.schema.json#/$defs/provider_directory`.
pub type ProviderDirectory = Value;

/// Counterpart for `spec/v1/artifacts/schemas/mimi-interop.schema.json#/$defs/room_binding`.
pub type RoomBinding = Value;

/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json`.
pub type MimiOperations = Value;

/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/ciphertext`.
pub type Ciphertext = Value;

/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/consent_id`.
pub type ConsentId = String;

/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/consent_target`.
pub type ConsentTarget = Value;

/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/group_info`.
pub type GroupInfo = Value;

/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/identifier`.
pub type Identifier = Value;

/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/key_package`.
pub type KeyPackage = Value;

/// Counterpart for `spec/v1/artifacts/schemas/mimi-operations.schema.json#/$defs/opaque_payload`.
pub type OpaquePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json`.
pub type ModerationAppeal = BTreeMap<String, Value>;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/actor_ref`.
pub type ActorRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/appeal_id`.
pub type AppealId = String;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/close_payload`.
pub type ClosePayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/decision_payload`.
pub type DecisionPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/decision_ref`.
pub type DecisionRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/evidence_visibility`.
pub type EvidenceVisibility = String;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/review_payload`.
pub type ReviewPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/submit_payload`.
pub type SubmitPayload = Value;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-appeal.schema.json#/$defs/target_ref`.
pub type TargetRef = String;

/// Counterpart for `spec/v1/artifacts/schemas/moderation-report.schema.json#/$defs/franking_proof`.
pub type FrankingProof = Value;

/// Counterpart for `spec/v1/artifacts/schemas/morph-customer-risk.schema.json`.
pub type MorphCustomerRisk = Value;

/// Counterpart for `spec/v1/artifacts/schemas/morph.schema.json#/$defs/facet_config`.
pub type FacetConfig = BTreeMap<String, Value>;

/// Counterpart for `spec/v1/artifacts/schemas/personal-productivity.schema.json`.
pub type PersonalProductivity = PersonalProductivityValue;

/// Counterpart for `spec/v1/artifacts/schemas/personal-productivity.schema.json#/$defs/reminder`.
pub type Reminder = ReminderValue;

/// Counterpart for `spec/v1/artifacts/schemas/personal-productivity.schema.json#/$defs/saved_item`.
pub type SavedItem = SavedItemValue;

/// Counterpart for `spec/v1/artifacts/schemas/personal-productivity.schema.json#/$defs/scheduled_send`.
pub type ScheduledSend = ScheduledSendValue;

/// Counterpart for `spec/v1/artifacts/schemas/personal-productivity.schema.json#/$defs/snooze`.
pub type Snooze = SnoozeValue;

/// Counterpart for `spec/v1/artifacts/schemas/pin.schema.json`.
pub type Pin = Value;

/// Counterpart for `spec/v1/artifacts/schemas/policy.schema.json#/$defs/domain_name`.
pub type DomainName = String;

/// Counterpart for `spec/v1/artifacts/schemas/policy.schema.json#/$defs/server_selector`.
pub type ServerSelector = Value;

/// Counterpart for `spec/v1/artifacts/schemas/policy.schema.json#/$defs/trust_domain`.
pub type TrustDomain = String;

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json`.
pub type PushOperations = Value;

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/blind_notification`.
pub type BlindNotification = Value;

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/counts`.
pub type Counts = Value;

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/device_route`.
pub type DeviceRoute = Value;

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/notify_rejection`.
pub type NotifyRejection = Value;

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/push_key`.
pub type PushKey = String;

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/push_target_id`.
pub type PushTargetId = String;

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/registration_id`.
pub type RegistrationId = String;

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/url`.
pub type Url = String;

/// Counterpart for `spec/v1/artifacts/schemas/push-operations.schema.json#/$defs/visible_notification`.
pub type VisibleNotification = Value;

/// Counterpart for `spec/v1/artifacts/schemas/query.schema.json`.
pub type Query = Value;

/// Counterpart for `spec/v1/artifacts/schemas/range-completeness-attestation.schema.json`.
pub type RangeCompletenessAttestation = Value;

/// Counterpart for `spec/v1/artifacts/schemas/realm.schema.json#/$defs/cell_lattice`.
pub type CellLattice = Value;

/// Counterpart for `spec/v1/artifacts/schemas/realm.schema.json#/$defs/sync_endpoint`.
pub type SyncEndpoint = Value;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-policy.schema.json#/$defs/share`.
pub type Share = Value;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json`.
pub type RecoverySession = RecoverySessionState;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/challenge`.
pub type Challenge = String;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/device_authorize_material`.
pub type DeviceAuthorizeMaterial = Value;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/generic_recovery_transcript`.
pub type GenericRecoveryTranscript = Value;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/principal_signing_transcript`.
pub type PrincipalSigningTranscript = Value;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/proof_summary`.
pub type ProofSummary = Value;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/recovery_policy_ref`.
pub type RecoveryPolicyRef = Value;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/recovery_session_complete_outcome`.
pub type RecoverySessionCompleteOutcome = Value;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/recovery_session_complete_request_body`.
pub type RecoverySessionCompleteRequestBody = Value;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/recovery_session_create_request_body`.
pub type RecoverySessionCreateRequestBody = Value;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/recovery_session_proof_submit_outcome`.
pub type RecoverySessionProofSubmitOutcome = Value;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/recovery_session_proof_submit_request_body`.
pub type RecoverySessionProofSubmitRequestBody = Value;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/recovery_session_state`.
pub type RecoverySessionState = Value;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/session_state`.
pub type SessionState = String;

/// Counterpart for `spec/v1/artifacts/schemas/recovery-session.schema.json#/$defs/threshold_recovery_proof`.
pub type ThresholdRecoveryProof = Value;

/// Counterpart for `spec/v1/artifacts/schemas/relation.schema.json#/$defs/ref`.
pub type Ref = String;

/// Counterpart for `spec/v1/artifacts/schemas/rsvp.schema.json`.
pub type Rsvp = RsvpSetPayload;

/// Counterpart for `spec/v1/artifacts/schemas/search-service.schema.json`.
pub type SearchService = Value;

/// Counterpart for `spec/v1/artifacts/schemas/service-describe.schema.json#/$defs/cidr`.
pub type Cidr = String;

/// Counterpart for `spec/v1/artifacts/schemas/service-operation-dtos.schema.json`.
pub type ServiceOperationDtos = Value;

/// Counterpart for `spec/v1/artifacts/schemas/snapshot.schema.json`.
pub type Snapshot = Value;

/// Counterpart for `spec/v1/artifacts/schemas/space.schema.json#/$defs/metadata_encryption_floor`.
pub type MetadataEncryptionFloor = String;

/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json#/$defs/collection_config`.
pub type CollectionConfig = Value;

/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json#/$defs/collection_grouping`.
pub type CollectionGrouping = Value;

/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json#/$defs/dashboard_config`.
pub type DashboardConfig = Value;

/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json#/$defs/document_config`.
pub type DocumentConfig = BTreeMap<String, Value>;

/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json#/$defs/field_path`.
pub type FieldPath = String;

/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json#/$defs/graph_config`.
pub type GraphConfig = BTreeMap<String, Value>;

/// Counterpart for `spec/v1/artifacts/schemas/view.schema.json#/$defs/timeline_config`.
pub type TimelineConfig = BTreeMap<String, Value>;
