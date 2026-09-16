//! Arkret v1 Rust SDK.
//!
//! This crate exposes Arkret protocol concepts directly. Producers sign
//! immutable Events; the current governance Station accepts and orders them in
//! the Realm, Circle, or Sidecar authority stream selected by `scope_ref`.
//!
//! # Examples
//!
//! Author a standard Event without supplying a separate runtime kind:
//!
//! ```rust
//! use arkret::canonical::DigestSuite;
//! use arkret::{
//!     AccountId, ActorId, ContentBlock, Did, DidCoreId, MessageCreatePayload, RealmId, ScopeRef,
//!     StrandId, TypedEventDraft, event_spec, project_did_to_core_id,
//! };
//!
//! # fn main() -> arkret::Result<()> {
//! let payload = MessageCreatePayload::with_content(
//!     StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9")?,
//!     "main",
//!     ContentBlock::text("hello"),
//! );
//! let event = TypedEventDraft::<event_spec::MessageCreate>::new(
//!     ScopeRef::Realm {
//!         realm_id: RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir")?,
//!     },
//!     ActorId::account(AccountId::new(
//!         DidCoreId::from(project_did_to_core_id(&Did::new(
//!             "did:webvh:z6mkfixture:alice.example",
//!         )?)?),
//!         DidCoreId::new("ak:did_core:web:station.example")?,
//!     )),
//!     payload,
//! )?
//! .author_with_digest_suite("2026-08-09T00:00:00Z".parse().unwrap(), DigestSuite::Sha256)?;
//! assert_eq!(event.payload["content"]["body"], "hello");
//! # Ok(())
//! # }
//! ```

//! Invalid typed IDs should be constructed with validators, not assigned from
//! raw strings:
//!
//! ```compile_fail
//! let did: arkret::Did = "did:webvh:z6mkfixture:alice.example";
//! ```

pub mod contact_authorization;
mod keypackage_claim_receipt;
pub mod managed_actor_authoring;
mod sdk_error;

pub use arkret_auth as auth;
pub use arkret_auth::session_grant;
pub use arkret_bootstrap as bootstrap;
pub use arkret_canonical as canonical;
pub use arkret_canonical::DigestSuite;
pub use arkret_canonical::base64url::{
    base64_standard_decode, base64_standard_encode, base64url_decode, base64url_encode,
};
pub use arkret_canonical::multibase::{
    MULTICODEC_ED25519_PUB, decode_base58btc, decode_ed25519_multibase,
    decode_ed25519_signature_multibase, decode_multibase_base58btc, decode_multicodec_varint,
    ed25519_pubkey_to_did_key_multibase, encode_base58btc, encode_multibase_base58btc,
    sha256_multihash_base58btc,
};
pub use arkret_crypto as crypto;
pub use arkret_crypto::{account_data_crypto, identity_root};
pub use arkret_egress_policy as network_policy;
pub use arkret_event_draft::{
    AppletBridgeErrorBuilder, ContainerRebalanceAssignment, EVENT_PAYLOAD_BINDINGS,
    EventAuthoringContext, EventDraftKindConformanceVector, EventDraftKindRegistry,
    EventDraftKindSpec, EventDraftKindValidation, EventIntent, EventPayloadBinding,
    EventPayloadExt, EventSpec, ExtensionPayloadValidator, GhostActorProfileRequest,
    LocalOperationDraft, LocalOperationSpec, MessageEventPayload, MlsEnvelopeOperationExt,
    ProjectedEventOperation, ProjectionContext, RsvpAuthoring, RsvpResponseBranch,
    StrandCreateObject, TypedEventDraft, ValidatedExtensionPayload, accountability_grant_intent,
    container_rebalance_assignments, event_draft_kind_conformance_vectors, local_operation_spec,
    rank_between, rank_exhausted, validate_event_payload,
};
pub use arkret_hlc::{
    CURSOR_HANDLE_MIN_LEN, Cursor, CursorPurpose, HlcGenerator, generate_cursor_handle,
};
#[cfg(feature = "client")]
pub use arkret_http_client as http_client;
#[cfg(feature = "client")]
pub use arkret_http_client::service_resolution_fetcher::{
    MaterializedServiceResolution, ServiceResolutionFetcher,
};
pub use arkret_identifiers as identifiers;
pub use arkret_identifiers::{
    ActorProfileId, AnnounceId, AppletId, BackupId, BackupSeriesId, BatchId, BlobId, BlobRef,
    BlockId, CallId, CapabilityId, ChunkId, CircleId, ClaimId, ConsentId, DeviceId,
    DeviceMessageId, DeviceMessageTransactionId, Did, DidCoreId, EventId, FilterId, FrameId,
    GrantId, Hash, Hlc, InviteId, InviteLocatorId, MessageId, MessageStreamId,
    ModerationQueueItemId, MorphId, NotificationId, NotificationProjectionId, OperationId,
    PolicyId, PresentationId, RealmAuthorityHandoffId, RealmCommitId, RealmId, RealmSnapshotId,
    ReceiptId, RecoverySessionId, RelationId, ReportId, RequestId, RtcParticipantId, SidecarId,
    SpaceId, StrandId, SubscriptionId, TransactionId, TrustDomainId, ViewId, WebOrigin,
    new_prefixed_uuid7, project_did_to_core_id,
};
pub use arkret_identity as identity;
pub use arkret_identity::jws;
pub use arkret_identity::service_identity::{
    DidCoreIdentityBundle, DidCoreIdentityDiagnostic, DidCoreIdentityKeyRef,
    DidCoreIdentityProviderRef, DidCoreIdentityState, FileIdentityBundleBackend,
    IdentityBundleBackend, IdentityBundleBackendAvailability, KeyStoreIdentityBundleBackend,
    LocalDidCoreIdentity, ResolvedService, StoredDidCoreIdentity,
};
pub use arkret_keystore::{
    KeyBytes, KeyStore, KeyStoreError, LinuxSecretServiceKeyStore, MacOsKeychainKeyStore,
    WindowsCredentialKeyStore, durable_platform_keystore,
};
pub use arkret_models_collaboration::account_lifecycle::*;
pub use arkret_models_collaboration::account_operations::*;
pub use arkret_models_collaboration::account_status::*;
pub use arkret_models_collaboration::actor_profile_resolution::*;
pub use arkret_models_collaboration::agent_operations::*;
pub use arkret_models_collaboration::agent_scope::{
    AGENT_RUNTIME_KEY_BINDING_KIND, AGENT_RUNTIME_KEY_POSSESSION_PROOF_CONTEXT,
    AgentKeyPairRequestBody, AgentRequestedScopeDisclosure, AgentRuntimeApprovalRequestBody,
    AgentRuntimeKeyAlgorithm, AgentRuntimeKeyPossessionProof, AgentRuntimeKeyPossessionProofKind,
    agent_requested_scope_digest, agent_runtime_key_binding_digest,
};
pub use arkret_models_collaboration::agent_sidecar::*;
pub use arkret_models_collaboration::applet_installation_authority::*;
pub use arkret_models_collaboration::call_signal::{
    CallAckSignalData, CallAnswerSignalData, CallCandidateSignalData, CallEndSignalData,
    CallErrorSignalData, CallFocusSignalData, CallInviteSignalData, CallMediaSelection,
    CallMediaStateSignalData, CallModerationAction, CallModerationSignalData,
    CallMuteStateSignalData, CallRenegotiateSignalData, CallSignalData, CallSignalKind,
    CallSignalPlaintext, CallSignalPlaintextKind, CallSpeakingSignalData, IceCandidate,
    MuteChangedBy, RenegotiationReason, ScreenMediaState, SessionDescription,
    SessionDescriptionType,
};
pub use arkret_models_collaboration::consent_operations::*;
pub use arkret_models_collaboration::contact_operations::*;
pub use arkret_models_collaboration::device_messages::*;
pub use arkret_models_collaboration::device_pairing::*;
pub use arkret_models_collaboration::direct_conversation::*;
pub use arkret_models_collaboration::event_query::*;
pub use arkret_models_collaboration::event_sync::*;
pub use arkret_models_collaboration::events_payloads::agent::*;
pub use arkret_models_collaboration::events_payloads::audit::*;
pub use arkret_models_collaboration::events_payloads::call::*;
pub use arkret_models_collaboration::events_payloads::event_wire::*;
pub use arkret_models_collaboration::events_payloads::mention::*;
pub use arkret_models_collaboration::events_payloads::message::MessageTrackName;
pub use arkret_models_collaboration::events_payloads::*;
pub use arkret_models_collaboration::governance::accountability::{
    ACCOUNTABILITY_SCOPE_SET_CONTEXT, AccountabilityGrantPayload, AccountabilityGrantStatus,
    AccountabilityScope, AccountabilityScopeKind,
};
pub use arkret_models_collaboration::governance::agent_artifacts::*;
pub use arkret_models_collaboration::governance::agent_membership_cascade::*;
pub use arkret_models_collaboration::governance::agent_participation::*;
pub use arkret_models_collaboration::governance::audit::{AccessKind, AuditPolicyAccessPayload};
pub use arkret_models_collaboration::governance::authorization::*;
pub use arkret_models_collaboration::governance::circle::*;
pub use arkret_models_collaboration::governance::erasure::*;
pub use arkret_models_collaboration::governance::grant_constraint::*;
pub use arkret_models_collaboration::governance::invite_addressing::*;
pub use arkret_models_collaboration::governance::membership_invite::*;
pub use arkret_models_collaboration::governance::moderation::*;
pub use arkret_models_collaboration::governance::moderation_queue::*;
pub use arkret_models_collaboration::governance::operation_wire::*;
pub use arkret_models_collaboration::governance::peer_contact::*;
pub use arkret_models_collaboration::governance::plaintext_visibility::*;
pub use arkret_models_collaboration::governance::realm_governance::*;
pub use arkret_models_collaboration::governance::realm_join_bootstrap::{
    RealmJoinBootstrapAssembly, RealmJoinBootstrapStreamScan,
};
pub use arkret_models_collaboration::governance::realm_join_intake::{
    AuthorityLocatorHint, AuthorityLocatorSource, PeerRealmJoinBootstrapOutcome,
    PeerRealmJoinBootstrapRequestBody, PeerRealmJoinPreviewOutcome,
    PeerRealmJoinPreviewRequestBody, RealmJoinApplicationStatus, RealmJoinApplicationStatusOutcome,
    RealmJoinApplicationStatusRequest, RealmJoinIntent, RealmJoinTarget, RealmPublicPreview,
    SelfRealmJoinPrepareOutcome, SelfRealmJoinPrepareRequestBody, SelfRealmJoinPreviewOutcome,
    SelfRealmJoinPreviewRequestBody,
};
pub use arkret_models_collaboration::governance::realm_lifecycle::*;
pub use arkret_models_collaboration::governance::third_party_invite::*;
pub use arkret_models_collaboration::governance_payloads::*;
pub use arkret_models_collaboration::message_authoring::{
    MessageAuthoringContent, MessageAuthoringIntent, MessageEncryptionContext,
};
pub use arkret_models_collaboration::mimi_operations::*;
pub use arkret_models_collaboration::mls_group_state_material::*;
pub use arkret_models_collaboration::object_lifecycle::*;
pub use arkret_models_collaboration::objects::account_status::{
    AccountStatus, AccountStatusTransitionRejection,
};
pub use arkret_models_collaboration::objects::blob::*;
pub use arkret_models_collaboration::objects::calendar_projection::*;
pub use arkret_models_collaboration::objects::calendar_recurrence::*;
pub use arkret_models_collaboration::objects::direct_conversation::*;
pub use arkret_models_collaboration::objects::interop::*;
pub use arkret_models_collaboration::objects::media::*;
pub use arkret_models_collaboration::objects::mimi::*;
pub use arkret_models_collaboration::objects::object_facets::*;
pub use arkret_models_collaboration::objects::productivity::*;
pub use arkret_models_collaboration::objects::profiles::*;
pub use arkret_models_collaboration::objects::queries::*;
pub use arkret_models_collaboration::objects::query_projection::*;
pub use arkret_models_collaboration::objects::read_receipts::*;
pub use arkret_models_collaboration::objects::realm::*;
pub use arkret_models_collaboration::objects::realm_alias::*;
pub use arkret_models_collaboration::objects::relation::*;
pub use arkret_models_collaboration::objects::space::*;
pub use arkret_models_collaboration::objects::strand::*;
pub use arkret_models_collaboration::objects::view::*;
pub use arkret_models_collaboration::prepared_event_draft::PreparedEventDraft;
pub use arkret_models_collaboration::principal_operations::*;
pub use arkret_models_collaboration::session_grant_bodies::*;
pub use arkret_models_collaboration::session_grants::*;
pub use arkret_models_collaboration::sidecar_operations::*;
pub use arkret_models_collaboration::signal_message_stream::*;
pub use arkret_models_collaboration::signal_operations::*;
pub use arkret_models_collaboration::signal_plaintext::*;
pub use arkret_models_collaboration::sync_frames::current_results::*;
pub use arkret_models_collaboration::sync_frames::websocket::*;
pub use arkret_models_collaboration::{contact_operations, direct_conversation};
pub use arkret_models_crypto::artifacts_keys::*;
pub use arkret_models_crypto::authority_set_policy::*;
pub use arkret_models_crypto::encrypted_attachment::*;
pub use arkret_models_crypto::encrypted_envelope::{
    EncryptedPayload, EventContentPreEncryptionHeader, EventContentRoutingContext,
};
pub use arkret_models_crypto::high_risk_authority_proof::*;
pub use arkret_models_crypto::http_bodies::*;
pub use arkret_models_crypto::key_backup::*;
pub use arkret_models_crypto::key_backup_operations::*;
pub use arkret_models_crypto::key_transparency::{
    KeyTransparencyEvidence, TransparencyConsistencyProof, TransparencyInclusionProof,
    TransparencyLogHead, TransparencyWitnessSignature,
};
pub use arkret_models_crypto::keypackage_capabilities::*;
pub use arkret_models_crypto::keys::*;
pub use arkret_models_crypto::mls_envelopes::MlsCommitEnvelope;
pub use arkret_models_crypto::mls_payloads::*;
pub use arkret_models_crypto::mls_records::{
    LocalMlsKeyPackageInventory, LocalMlsKeyPackageInventoryEntry, MlsEndpointIdentity,
    MlsKeyPackageRecord, MlsKeyPackageState, RealmPairwiseAcceptedGroupState,
    RealmPairwiseAcceptedLeaf, RealmPairwiseAuthorState, RealmPairwiseKeyScopeLedger,
};
pub use arkret_models_crypto::protected_payload::{
    MlsEncryptedPayload, MlsPayloadType, PlainPayload, ProtectedPayload,
};
pub use arkret_models_crypto::recovery_policy::*;
pub use arkret_models_crypto::recovery_session::*;
pub use arkret_models_crypto::secret_share::*;
pub use arkret_models_crypto::security_transaction::*;
pub use arkret_models_discovery::directory::*;
pub use arkret_models_discovery::directory_artifacts::*;
pub use arkret_models_discovery::http_bodies::*;
pub use arkret_models_discovery::ops;
pub use arkret_models_discovery::presence::{
    LAST_ACTIVE_BUCKET_FLOOR_SECONDS, ManualPresenceState, PresencePreference, PresenceStatus,
    PresenceValidationError, PresenceVisibility, PresenceVisibilityPreference,
    STATUS_MESSAGE_MAX_CODE_POINTS, aggregate_presence_states, validate_last_active_at,
    validate_status_message,
};
pub use arkret_models_discovery::realm_join_preview::{
    AuthorityLocatorHint as PreviewAuthorityLocatorHint,
    AuthorityLocatorSource as PreviewAuthorityLocatorSource, RealmJoinPeerPreviewOutcome,
    RealmJoinPeerPreviewRequestBody, RealmJoinSelfPreviewOutcome, RealmJoinSelfPreviewRequestBody,
    RealmJoinTarget as PreviewRealmJoinTarget, RealmPublicPreview as PreviewRealmPublicPreview,
};
pub use arkret_models_discovery::service_description::*;
pub use arkret_models_discovery::service_requirements::{
    ApiConventionMetadata, DidCoreIdAllowlist, HttpTraceMetadata, NotFoundPrivacy, QuotaKind,
    QuotaMetadata, RateLimitMetadata, RateLimitScopeKind, ServiceEndpointBinding,
    ServiceRequirements,
};
pub use arkret_models_discovery::station_connection::*;
pub use arkret_models_discovery::verified_profiles::*;
pub use arkret_models_discovery::websocket_binding::*;
pub use arkret_models_identity::account::*;
pub use arkret_models_identity::actor_profile::*;
pub use arkret_models_identity::actor_profile_operations::*;
pub use arkret_models_identity::admin_grant::{
    SessionGrantAdminIntrospectionStatus, SessionGrantIntrospection, admin_scopes,
};
pub use arkret_models_identity::agent_signer_state::*;
pub use arkret_models_identity::artifacts_account::*;
pub use arkret_models_identity::artifacts_device_identity::*;
pub use arkret_models_identity::authenticated_signer_resolution_evidence::*;
pub use arkret_models_identity::claim_presentation::{
    AgentSelectorClaim, DIRECTORY_RESTRICTED_CLAIM_PRESENTATION_KIND, DirectoryPresentedClaim,
    DirectoryRestrictedClaimPresentation, validate_agent_slug,
};
pub use arkret_models_identity::device_push_route::*;
pub use arkret_models_identity::device_verification::*;
pub use arkret_models_identity::did_webvh::*;
pub use arkret_models_identity::handle::*;
pub use arkret_models_identity::handle_claim::*;
pub use arkret_models_identity::http_bodies::*;
pub use arkret_models_identity::identity::*;
pub use arkret_models_identity::identity_resolution::*;
pub use arkret_models_identity::member_identity::*;
pub use arkret_models_identity::organization_registration::*;
pub use arkret_models_identity::primary_handle::*;
pub use arkret_models_identity::principal_registration_anchor::*;
pub use arkret_models_identity::service_binding_results::*;
pub use arkret_models_identity::service_identity::*;
pub use arkret_models_identity::session_credential::*;
pub use arkret_models_identity::signer_key_operations::*;
pub use arkret_models_identity::{DID_WEBVH_V1_METHOD, validate_did_webvh_v1_method};
pub use arkret_models_integration::applet::*;
pub use arkret_models_integration::applet_audit_payload::*;
pub use arkret_models_integration::applet_install_plan::*;
pub use arkret_models_integration::applet_models::*;
pub use arkret_models_integration::artifacts_applet::*;
pub use arkret_models_integration::integration::*;
pub use arkret_models_integration::models_push::*;
pub use arkret_models_integration::push::*;
pub use arkret_models_integration::push_vocab::*;
pub use arkret_models_integration::{integration, push};
pub use arkret_policy::authz::*;
pub use arkret_policy::profile_claim::{
    ClaimedProfile, ProfileClaim, ProfileClaimError, ProfileClaimKind, ProfileValidator,
};
pub use arkret_policy::profile_feature_guard::{
    ProfileFeatureGap, implied_features_for_profiles, verify_declared_profiles_against_features,
};
pub use arkret_policy::profile_semantics::{
    ProfileSemanticCoverageError, ProfileSemanticCoverageReport, ProfileSemanticRequirements,
    ProfileSemanticSurface, collect_profile_semantic_requirements,
    profile_capability_action_coverage_report, profile_semantic_coverage_report,
    validate_profile_semantic_coverage,
};
pub use arkret_policy::realm_organization::*;
pub use arkret_push_policy::blind_payload_sanitizer::*;
pub use arkret_push_policy::{blind_payload_sanitizer, push_rule_core};
pub use arkret_retry as retry;
pub use arkret_retry::{
    Jitter, RetryLadder, RetryPolicy, RetrySchedule, SPEC_FACTOR, SPEC_INITIAL_DELAY,
    SPEC_JITTER_RATIO, SPEC_MAX_DELAY, SPEC_MAX_RETRIES, SPEC_RETRY_WINDOW, apply_jitter,
};
pub use arkret_schema as schema;
pub use arkret_schema::EventSchemaExt;
pub use arkret_schema::protocol::*;
#[cfg(feature = "server")]
pub use arkret_server as server;
pub use arkret_signatures as signatures;
#[cfg(feature = "signer")]
pub use arkret_signatures::Ed25519PayloadSigner;
pub use arkret_signatures::contact_receipt::{
    contact_request_acceptance_receipt_signing_bytes, verify_contact_request_acceptance_receipt,
};
pub use arkret_signatures::device_pairing::{
    sign_device_pairing_target_proof, verify_device_pairing_target_proof,
};
pub use arkret_signatures::federation::*;
pub use arkret_signatures::keypackages::{
    KeyPackageSignatureError, KeyPackageSignatureResult, keypackage_signature_from_bytes,
    sign_keypackage_signing_input, sign_keypackages_consume_request,
    sign_keypackages_revoke_request, sign_keypackages_upload_request,
    verify_keypackage_signing_input,
};
// Shared `did:webvh` inception builder + organization statement signer, surfaced
// at the SDK root so clients (sodmin / inkson) and servers (soland / coauth)
// reach one implementation: `arkret_sdk::webvh::prepare_principal_inception`,
// `arkret_sdk::realm_organization_statement_sign`.
pub use arkret_signatures::{
    realm_organization, realm_organization_statement_sign, service_identity, webvh,
};
pub use arkret_state::*;
pub use arkret_wire::accepted_device_possession::*;
pub use arkret_wire::applet_revoke_mode::AppletRevokeMode;
pub use arkret_wire::authored_event::AuthoredEvent;
pub use arkret_wire::authority_commit::*;
pub use arkret_wire::consent_scope::*;
pub use arkret_wire::constants::*;
pub use arkret_wire::directory_source_ref_access::*;
pub use arkret_wire::error_codes::*;
pub use arkret_wire::event_envelope::*;
pub use arkret_wire::event_receipt::*;
pub use arkret_wire::event_submission::*;
pub use arkret_wire::extension_manifest::*;
pub use arkret_wire::ingress_budget::*;
pub use arkret_wire::invite_token::*;
pub use arkret_wire::mls_transition::mls_genesis_transition_digest;
pub use arkret_wire::notary::{
    NotaryJoseAlgorithm, NotaryKeyKind, NotarySignerDescriptor, NotaryValue,
};
pub use arkret_wire::object_address::*;
pub use arkret_wire::object_ref::is_object_ref;
pub use arkret_wire::operation_types::*;
pub use arkret_wire::pairwise_endpoint_possession::*;
pub use arkret_wire::patch::*;
pub use arkret_wire::peer_operation_paths::*;
pub use arkret_wire::plaintext::PlaintextDataClassKind;
pub use arkret_wire::platform::{WasmHttpRequestBody, WasmHttpResponseBody};
pub use arkret_wire::primitives::*;
pub use arkret_wire::problem_details::*;
pub use arkret_wire::receive_policy::{
    EffectiveNewSourceQuota, InviteReceiveAction, NewSourceQuotaConstraints,
    NewSourceQuotaOverride, ReceivePolicyConstraints, ReceivePolicySurface, UnknownInviteAction,
};
pub use arkret_wire::recovery_authority::*;
pub use arkret_wire::request_digest::framed_request_digest;
pub use arkret_wire::resource_selector::ObjectRef;
pub use arkret_wire::self_contact_paths::*;
pub use arkret_wire::service_kind::EvaluationClass;
pub use arkret_wire::signal::{
    MAX_SIGNAL_CIPHERTEXT_CHARS, MAX_SIGNAL_ENVELOPE_BYTES, MAX_SIGNAL_PLAINTEXT_BYTES,
    MAX_SIGNAL_RELAY_CANONICAL_BODY_BYTES, MAX_SIGNAL_RELAY_ITEMS, MAX_SIGNAL_STREAM_REASON_CHARS,
    MAX_SIGNAL_STREAM_RECONNECT_AFTER_MS, MAX_SIGNAL_TTL, SIGNAL_AEAD_PURPOSE, SIGNAL_AEAD_SCHEME,
    SIGNAL_EXPORTER_LABEL, SignalAeadBinding, SignalClass, SignalDeliveryAuthority,
    SignalEncryptedPayload, SignalEnvelope, SignalKeyRef, SignalProof, SignalRelayOutcome,
    SignalRelayRequest, SignalSenderEndpoint, SignalStreamFrame,
};
pub use arkret_wire::string_profiles::*;
pub use arkret_wire::websocket_binding::*;
pub use arkret_wire::webvh_parameters::{
    did_webvh_v1_effective_portable, validate_did_webvh_v1_parameter_names,
};
pub use arkret_wire::wire_presence::WirePresence;
pub use arkret_wire::wire_strings::*;
pub use arkret_wire::{
    AccountDataKey, BindingKind, CapabilityActionId, DIGEST_SUITES, DidFreshnessProfileId,
    DidFreshnessRiskTier, EXPORTER_LABELS, EventKind, ExporterLabelId, GenesisSalt, HPKE_SUITES,
    IdempotencyKey, KeyPackageClaimId, KeyPackageRef, MLS_CIPHERSUITES, MLS_EXTENSIONS,
    MlsCiphersuiteId, PROOF_CONTEXTS, PayloadSigner, ProfileId, ProfileRole, ProofContextId,
    ProtocolOpaqueId, ProtocolOperationId, ProtocolSignature, QUERY_AUTH_PARAMETER_NAMES,
    RELATION_KIND_DESCRIPTORS, ReservationHandle, ResourceMatchScope, ResourceSelectorKind,
    SERVICE_KIND_DESCRIPTORS, SERVICE_OPERATION_DESCRIPTORS, SIGNATURE_ALGORITHMS, SchemaId,
    ServiceKind, ServiceOperationDescriptor, ServiceOperationId, SignerEvidenceRef, WireError,
    WireResourceSelector, XExtensionMap, contains_query_auth_material, error_codes, event_spec,
    is_query_auth_parameter,
};
pub use keypackage_claim_receipt::verify_peer_keypackage_claim_receipt_signature;
pub use managed_actor_authoring::{
    APPLET_MANAGED_ACTOR_ACCOUNTABILITY_REF_ROLE, APPLET_MANAGED_ACTOR_PROVISION_REF_ROLE,
    AppletManagedActorBundleAuthoringInput, applet_managed_actor_unit_event_kinds,
    applet_managed_actor_unit_submissions, author_applet_managed_actor_bundle,
};
pub use sdk_error::{Error, Result};

pub mod events {
    pub use arkret_models_collaboration::events_payloads::redaction::*;
    pub use arkret_wire::events::*;
}

pub mod sync {
    pub use arkret_models_collaboration::sync_frames::account_subscribe::*;
    pub use arkret_models_collaboration::sync_frames::current_results::*;
    pub use arkret_models_collaboration::sync_frames::realm_state_snapshot::*;
    pub use arkret_models_discovery::presence::{PresenceStatus, aggregate_presence_states};
}

// Platform-native KeyStore backends. The glob import above already
// re-exports these symbols, but listing them explicitly keeps them
// visible in `cargo doc` and signals the supported surface to
// downstream crates that depend only on the `arkret` umbrella.
pub use arkret_hlc as hlc;
// RFC 9421 HTTP Message Signatures (Ed25519) + RFC 9530 Content-Digest.
// The single source of truth is `arkret-signatures`, surfaced here as
// `arkret::http_signature::*` / `arkret_sdk::http_signature::*`.
// HttpDidResolver leans on a live Tokio runtime, blocking off-thread
// scheduling, and reqwest's native ClientBuilder transport knobs — none
// of which are available on the wasm32 fetch backend. It is owned by
// arkret-http-client and surfaced here as `arkret::http_did_resolver::*`.
// Gated out on wasm32; web embedders should plug in a fetch-based resolver
// via the `DidResolver` trait directly.
#[cfg(all(feature = "client", not(target_arch = "wasm32")))]
pub use arkret_http_client::http_did_resolver;
/// RFC 7515 detached Ed25519 JWS verifier (see [`jws`] module docs).
/// Lives at the SDK root so station-style consumers (inkson,
/// floria, cotest, teabay, soland) all reach the same verifier. Depends
/// on `identity::DidResolver`.
pub use arkret_signatures::{dpop, http_signature};
// The MLS (RFC 9420) behavior layer lives in the standalone `arkret-mls` crate
// (the sole OpenMLS boundary), surfaced here as `arkret::mls::*` under the
// same feature gate.
#[cfg(feature = "mls")]
pub mod mls {
    pub use arkret_mls::*;
}
pub use arkret_crypto::{
    AEAD_NONCE_AES_GCM_LEN, AEAD_NONCE_COUNTER_LEN, AEAD_NONCE_XCHACHA20_POLY1305_LEN,
    AEAD_PROFILE_AES_256_GCM, AEAD_PROFILE_XCHACHA20_POLY1305, AeadNonceContext,
    AeadNonceReplayTracker, compose_aead_nonce, json_aad_digest, verify_aead_nonce_derivation,
    verify_aead_sender_nonce,
};
pub use arkret_identifiers::hlc::{
    EXPECTED_FUTURE_SKEW_MS, HARD_FUTURE_SKEW_MS, HlcComponents, HlcFutureDrift, compare_hlc,
    parse_hlc, time_until_hlc, validate_hlc_format, validate_hlc_future_drift,
};
// The narrow MLS persistence ports are part of the `CryptoStore` supertrait
// contract (owned by arkret-models-crypto, OpenMLS-free), so surface them on the
// umbrella independently of the heavier `mls` group-machine feature.
pub use arkret_models_crypto::{MlsCommitSource, MlsGroupStateSink};
#[cfg(feature = "server")]
pub use arkret_server::AppletHandler;
#[cfg(feature = "server")]
pub use arkret_server::{
    CursorAuthority, CursorAuthorityError, CursorBindingContext, CursorBindingRecord,
    IdempotencyClaim, IdempotencyDirection, IdempotencyIdentity, IdempotencyWindow,
    MemoryCursorAuthority, TransactionClaim, TransactionIdempotencyStore, cursor_filter_digest,
};
pub use arkret_signatures::media::{
    CallMediaTokenVerification, IceConfig, MediaBackendKind, MediaServiceAnchors,
    ParticipantBindingContext, call_media_token_exchange, participant_binding_signing_input,
    validate_token_ttl, verify_call_media_token_outcome, verify_ice_config_outcome,
};
#[cfg(feature = "client")]
pub use http_client::{
    AccountSubscribeFolder, Auth, Client, ClientBuilder, ClientRequestOptions, RetryConfig,
};
#[cfg(all(feature = "client", not(target_arch = "wasm32")))]
pub use http_did_resolver::{
    DEFAULT_HTTP_DID_RESOLVER_TIMEOUT_MS, DEFAULT_HTTP_DID_RESOLVER_TTL_SECS, HttpDidResolver,
};
pub use identity::{
    AuthorityDidHistoryResolver, AuthorityHistoryUnavailable, AuthorityHistoryVerificationError,
    CompositeDidResolver, DID_WEB_MAX_DOCUMENT_BYTES, DidDocument,
    DidDocumentVerificationMethodResolver, DidKeriResolver, DidKeyResolver, DidRegistryReceipt,
    DidResolver, DidWebDocumentOutcome, DidWebResolver, HandleAttestation,
    IdentityReceiptWitnessRole, ResolvedDid, ResolvedVerificationMethodKey,
    VerifiedAccountBindingReceipt, event_proof_verification_context_with_digest_suite,
    resolve_verification_method_key, resolve_verification_method_key_from_document,
    verification_method_did, verify_account_binding_receipt_at_issuance,
    verify_canonical_proof_with_did_resolver, verify_event_proof_with_did_resolver,
    verify_event_proof_with_did_resolver_context,
};
#[cfg(feature = "mls")]
pub use mls::*;
#[cfg(feature = "server")]
pub use server::reject_query_auth;
