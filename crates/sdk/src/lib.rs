//! Contrix v1 Rust SDK.
//!
//! This crate exposes Contrix protocol concepts directly. The source of truth
//! is signed Event Envelopes; Operations are SDK-local builders or offline
//! drafts that must be materialized as Events before network, sync, federation
//! or reducer use.
//!
//! # Examples
//!
//! Build a local operation draft and materialize it as an Event Envelope:
//!
//! ```rust
//! use contrix::{
//!     Did, Hlc, OP_MESSAGE_CREATE, OperationEnvelopeBuilder, OperationEventConversion,
//!     OperationId, OperationKindRegistry, SpaceId,
//! };
//! use serde_json::json;
//!
//! # fn main() -> contrix::Result<()> {
//! let draft = OperationEnvelopeBuilder::new(
//!     OperationId::new("cx:operation:example")?,
//!     SpaceId::new("cx:space:example")?,
//!     Did::new("did:web:alice.example")?,
//!     OP_MESSAGE_CREATE,
//!     1,
//!     Hlc::new("01970e589d21-00000001-a13f9c2e")?,
//! )
//! .with_content(json!({"body": "hello"}))
//! .build(&OperationKindRegistry::default())?;
//! let event = draft.into_event_envelope(OperationEventConversion::default())?;
//! assert_eq!(event.content["body"], "hello");
//! # Ok(())
//! # }
//! ```
//!
//! Run one in-memory sync-loop step:
//!
//! ```rust
//! use contrix::{SyncLoop, SyncLoopStep, SyncRequest, SyncResponse};
//!
//! # fn main() {
//! let mut sync_loop = SyncLoop::new();
//! let mut transport = |_request: SyncRequest| {
//!     Ok(SyncResponse {
//!         next_batch: "s1".to_owned(),
//!         spaces: Default::default(),
//!         to_device: Vec::new(),
//!         device_lists: Default::default(),
//!         presence: Vec::new(),
//!         account_data: Vec::new(),
//!         notifications: Vec::new(),
//!         partial: false,
//!     })
//! };
//! assert!(matches!(sync_loop.step(&mut transport), SyncLoopStep::Updates(_)));
//! # }
//! ```
//!
//! Invalid typed IDs should be constructed with validators, not assigned from
//! raw strings:
//!
//! ```compile_fail
//! let did: contrix::Did = "did:web:alice.example";
//! ```

pub use contrix_api as api;
pub use contrix_appservice_api as appservice_api;
#[cfg(feature = "client")]
pub use contrix_client as client;
pub use contrix_client_api as client_api;
pub use contrix_core::*;
pub use contrix_core::{canonical, cursor, error, identifiers, model, service, sync};
pub use contrix_crypto as crypto_protocol;
pub use contrix_events as events;
pub use contrix_federation_api as federation_api;
pub use contrix_ffi as ffi;
pub use contrix_html as html;
pub use contrix_identity_api as identity_api;
pub use contrix_operations as operations;
pub use contrix_push_gateway_api as push_gateway_api;
pub use contrix_schema as schema_contracts;
#[cfg(feature = "server")]
pub use contrix_server as server;
#[cfg(feature = "salvo-adapter")]
pub use contrix_server::salvo_adapter;
pub use contrix_signatures as signatures;
pub use contrix_state_res as state_res;
pub use contrix_store as store_contracts;
pub use contrix_testing as testing;
pub use contrix_ui as ui;

#[cfg(feature = "full-surface")]
pub mod account;
#[cfg(feature = "full-surface")]
pub mod agent;
#[cfg(all(feature = "full-surface", feature = "applet-runtime"))]
pub mod applet;
#[cfg(feature = "full-surface")]
pub mod auth;
#[cfg(feature = "full-surface")]
pub mod authz;
#[cfg(feature = "full-surface")]
pub mod base;
#[cfg(feature = "full-surface")]
pub mod content;
#[cfg(feature = "full-surface")]
pub mod crypto;
#[cfg(feature = "full-surface")]
pub mod crypto_store;
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub mod devices;
#[cfg(feature = "full-surface")]
pub mod discovery;
#[cfg(feature = "full-surface")]
pub mod e2ee;
#[cfg(feature = "full-surface")]
pub mod event_handler;
#[cfg(feature = "full-surface")]
pub mod federation;
#[cfg(feature = "full-surface")]
pub mod hlc;
#[cfg(feature = "full-surface")]
pub mod identity;
#[cfg(feature = "full-surface")]
pub mod media;
#[cfg(feature = "full-surface")]
pub mod membership;
#[cfg(all(feature = "full-surface", feature = "mls"))]
pub mod mls;
#[cfg(feature = "full-surface")]
pub mod notifications;
#[cfg(feature = "full-surface")]
pub mod performance;
#[cfg(feature = "full-surface")]
pub mod platform;
#[cfg(feature = "full-surface")]
pub mod presence;
#[cfg(feature = "full-surface")]
pub mod profile;
#[cfg(feature = "full-surface")]
pub mod push;
#[cfg(feature = "full-surface")]
pub mod receipts;
#[cfg(feature = "full-surface")]
pub mod resolver;
#[cfg(feature = "full-surface")]
pub mod search;
#[cfg(feature = "full-surface")]
pub mod settings;
#[cfg(feature = "full-surface")]
pub mod space;
#[cfg(feature = "full-surface")]
pub mod store;
#[cfg(all(feature = "full-surface", feature = "sync-runtime"))]
pub mod sync_client;
#[cfg(all(feature = "full-surface", feature = "timeline-runtime"))]
pub mod timeline;
#[cfg(feature = "full-surface")]
pub mod typing;
#[cfg(feature = "full-surface")]
pub mod webrtc;

#[cfg(feature = "full-surface")]
pub use account::AccountDataManager;
#[cfg(feature = "full-surface")]
pub use agent::{
    AgentBridgeMetadata, AgentMemory, AgentMemoryReview, AgentMemoryState, AgentMemoryStore,
    AgentPrincipal, AgentProtocol, AgentProtocolBridge, AgentProtocolEndpoint,
    AgentProtocolMessage, AgentRun, AgentRunManager, AgentRunState, AgentToolAuditAction,
    AgentToolAuditEntry, AgentToolAuditLog, DelegatedActor, ExternalAgent, MemoryLayer,
};
#[cfg(all(feature = "full-surface", feature = "applet-runtime"))]
pub use applet::{
    AppletNamespaceConflict, AppletNamespaceDeclaration, AppletNamespaceKind, AppletPermission,
    AppletPortal, AppletPortalManager, AppletRegistry, AppletSchema, AppserviceIntent,
    AppserviceRegistration, AppserviceRoute, AppserviceRouteSet, AppserviceTransaction,
    AppserviceTransactionRecord, AppserviceTransactionStore, BridgeMappingStore,
    GhostActorAccountability, OpenApiBinding, PortalMode, PortalSpaceMapping, RemoteSpaceMapping,
    RemoteUserMapping, SignedAppletRegistration, ThirdPartyLookupKind, ThirdPartyLookupRequest,
    ThirdPartyLookupResponse, VirtualActor,
};
#[cfg(feature = "full-surface")]
pub use auth::{
    AccountAuthState, AccountRecoveryMethod, AccountRecoveryRequest, AuthClaimType, AuthManager,
    AuthRateLimitAction, AuthRateLimitContext, AuthRateLimitHook, AuthSession, AuthStateSnapshot,
    CONTRIX_DEVICE_SCOPE_PREFIX, ClaimDisclosureRequirement, DidProofVerification,
    DidProofVerificationRequest, DidProofVerifier, DisclosurePolicy,
    DisclosureProofAdapterBoundary, DisclosureProofFormat, MemorySessionGrantOutbox, MfaChallenge,
    OidcAuthRequest, OidcCredential, OidcIssuerMetadata, OidcJwks, OidcVerificationRequest,
    OidcVerifiedIdentity, OidcVerifier, PasskeyChallenge, PasskeyVerification,
    PasskeyVerificationRequest, PasskeyVerifier, PasswordHashAlgorithm, PasswordHashVerifier,
    PasswordUser, PasswordVerification, PasswordVerificationRequest, PersistedAuthSession,
    PresentationRequest, PresentationValidation, PresentedClaim, PrincipalSessionGrantNotification,
    PrincipalSessionGrantNotificationResponse, PrincipalSessionGrantNotifier, RefreshTokenMetadata,
    RejectedClaim, SessionGrant, SessionGrantNotificationKind, SessionGrantOutboxEntry,
    SessionGrantOutboxState, SessionGrantPayload, SessionGrantRecord, SessionGrantRetryPolicy,
    SessionGrantSigner, SessionGrantVerification, SessionGrantVerifier, SessionPrincipalBinding,
    SessionRevocation, WebAuthnPasskeyResponse, contrix_device_scope, device_id_from_scope_token,
    issue_session_grant_with_signer, primary_device_id_from_scopes, validate_presentation,
    verify_session_grant_with_verifier,
};
#[cfg(feature = "full-surface")]
pub use authz::{
    ApprovalFlowManager, ApprovalMode, AuthzContext, AuthzDecision, AuthzEngine,
    CapabilityFrontierValidation, CapabilityGrant, ClaimRequirement, Constraint,
    ConstraintDuration, ConstraintEffect, ConstraintEntry, FieldScope, GrantProposal,
    ModerationReport, PolicyCheckRequest, PolicyCheckResponse, PolicyServerEffect,
    ProposalApproval, ProposalStatus, ProtocolGrantApprovalRelation, ProtocolGrantClaimRequirement,
    ProtocolGrantConstraint, ProtocolGrantConstraintBranch, ProtocolGrantConstraintEffect,
    ProtocolGrantConstraintType, ProtocolResourceSelector, ProtocolResourceSelectorKind,
    ProtocolResourceSelectorScope, RateLimitScope, Recurrence, Resource, ResourceSelector,
    ScopeLimitation, VerifiedClaim, apply_policy_response, capability_grants_from_space_state,
    grant_requires_approval, moderation_report_for_policy_outcome,
    reject_unknown_critical_constraints, validate_capability_frontier,
};
#[cfg(feature = "full-surface")]
pub use base::{
    BaseClient, BootstrapSequence, BootstrapStep, BootstrapStepKind, BootstrapStepStatus,
    ClientSpace, SessionMeta, SessionRestore, SpaceStateType,
};
#[cfg(feature = "client")]
pub use client::{Auth, Client, ClientBuilder, ClientRequestOptions, RetryConfig};
#[cfg(feature = "full-surface")]
pub use content::{
    LinkPreview, MarkdownDocument, Mention, MentionTarget, Reaction, ReactionManager,
    ReactionSummary, RichTextBlock, extract_link_previews, parse_mentions,
};
#[cfg(feature = "full-surface")]
pub use crypto::{
    AEAD_ALGORITHM, EncryptedEnvelopeAad, EncryptedEnvelopeDigestReport, FeatureSafetyReport,
    KeyLifecycleHook, KeyLifecyclePhase, REDACTED_SECRET, SecurityReviewItem, SecurityReviewStatus,
    UnsafeFeatureCombination, current_feature_safety_report, encrypted_envelope_digest_report,
    envelope_aad_digest, feature_safety_report, is_sensitive_log_key, json_aad_digest,
    redact_log_value, security_review_checklist, verify_envelope_aad_digest,
};
#[cfg(feature = "full-surface")]
pub use crypto_store::{
    CRYPTO_STORE_BACKUP_VERSION, CryptoStore, CryptoStoreBackupEnvelope, CryptoStoreKeyRotation,
    EncryptedMemoryCryptoStore, MemoryCryptoStore, MlsEpochSecretRecord, MlsGroupStateRecord,
    MlsRecoveryAction, MlsRecoveryPlan, PlatformKeyStoreDescriptor, PlatformKeyStoreKind,
    StoredDeviceVerification,
};
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub use devices::{
    Device, DeviceChange, DeviceManager, DeviceMessageEnvelope, DeviceMetadata,
    DeviceVerificationChallenge, DeviceVerificationMessageContent,
    DeviceVerificationMessageKind, KeyBackup, KeyBackupClass, KeyBackupContentItem,
    KeyBackupEncryption, ProtocolKeyBackup, QrVerificationPayload, ToDeviceEnvelope,
    device_verification_commitment,
};
#[cfg(feature = "full-surface")]
pub use discovery::{DirectoryService, DirectoryUser, OpenGraphPreview, UrlPreviewCache};
#[cfg(feature = "full-surface")]
pub use e2ee::{
    AuditAction, AuditEntry, E2eeGroup, E2eeKeyBackup, E2eeKeyRecord, E2eeManager, E2eeMessage,
    E2eeMessageValidation, E2eeMessageValidationFailure,
};
#[cfg(feature = "full-surface")]
pub use event_handler::{
    BotCommand, BotCommandParser, BotRuntime, BotRuntimeReport, BotRuntimeShutdown,
    BuiltInEventHandlers, ClientEvent, ClientEventFilter, ClientEventKind, EventHandlerRegistry,
    EventPipeline, HandlerGuard,
};
#[cfg(feature = "full-surface")]
pub use federation::{
    FederationBackfillAuthorization, FederationManager, FederationQuarantineKind,
    FederationQuarantineRecord, FederationReplayDecision, FederationReplayRecord,
    FederationReplayStore, FederationRequest, FederationTransaction, FederationTransactionEnvelope,
    HttpMessageSignature, HttpMessageSignatureInput, ServerInfo, ServiceEndpointDescriptor,
    SovereignDeployment, TrustAnchor, VerifyActorChallenge, VerifyActorChallengeSignature,
    WellKnownContrixServer, content_digest_sha256, did_document_service_endpoint_matches,
    duplicate_transaction_quarantine, fork_quarantine_record, http_message_signature_base,
    sign_http_message, sign_verify_actor_challenge, verify_actor_challenge_signature,
    verify_http_message_signature,
};
#[cfg(feature = "full-surface")]
pub use hlc::{
    HlcComponents, HlcGenerator, compare_hlc, is_clock_skew_acceptable, parse_hlc, time_until_hlc,
    validate_hlc_format,
};
#[cfg(feature = "full-surface")]
pub use identity::{
    CompositeDidResolver, DID_WEB_MAX_DOCUMENT_BYTES, DidDocument, DidKeriResolver, DidKeyLogEntry,
    DidKeyLogOperation, DidKeyResolver, DidMigration, DidRegistryReceipt, DidResolver,
    DidUuidResolver, DidVisibility, DidWebDocumentResponse, DidWebResolver, ExternalHandleProof,
    HandleAttestation, HandleClaim, HandleProofProfile, IdentityManager,
    InMemoryStaridRegistryAdapter, PairwiseDidBinding, PairwiseDidResolutionProof,
    PairwiseDidStore, StaridControlProofRequest, StaridControlProofVerification,
    StaridRegistryAdapter, StaridRegistryRecord, VerifiedDidKeyLog, did_key_log_proof,
    did_registry_receipt_signature, handle_claim_proof, handle_dns_txt_name, handle_well_known_url,
    pairwise_resolution_proof, starid_control_proof, verify_did_key_log,
};
#[cfg(feature = "full-surface")]
pub use media::{
    Attachment, AuthenticatedDownloadGrant, DownloadGrantScope, EncryptedAttachment, MediaMetadata,
    MemoryBlobStore, Thumbnail, safe_content_disposition, safe_content_type,
};
#[cfg(feature = "full-surface")]
pub use membership::{
    Invite, Member, MemberChange, MemberProfile, MemberRole, MembershipManager, MembershipState,
    ThirdPartyInvite,
};
#[cfg(all(feature = "full-surface", feature = "mls"))]
pub use mls::*;
#[cfg(feature = "full-surface")]
pub use notifications::{
    NotificationAction, NotificationCounts, NotificationItem, NotificationManager, NotificationRule,
};
#[cfg(feature = "full-surface")]
pub use performance::{
    BenchmarkHarness, BenchmarkMeasurement, BenchmarkPlan, BenchmarkTarget,
    CompileOptimizationPlan, MemoryMetricsCollector, MetricName, MetricSample, MetricsCollector,
    NoopMetricsCollector, ObjectPool, ParallelProcessor, PerformanceConfig, RequestBatch,
    RequestBatcher, RobustnessHarness, RobustnessOutcome, RobustnessPlan, RobustnessTarget,
    TraceContext, TraceSpanKind, ZeroCopyJson,
};
#[cfg(feature = "full-surface")]
pub use platform::{
    EmbeddingSupportLevel, EmbeddingTarget, EmbeddingTargetDecision, FFI_API_FREEZE_REVIEW_VERSION,
    FfiApiFreezeBlocker, FfiApiFreezeReview, FfiApiFreezeStatus, FfiApiSurfaceItem,
    FfiCallbackAction, FfiCallbackResult, FfiCancellationHandle, FfiError, FfiErrorCode, FfiEvent,
    FfiEventSink, FfiHandle, FfiHandleKind, IndexedDbStoreDescriptor, IndexedDbStoreKind,
    WasmBrowserHttpTransport, WasmHttpRequest, WasmHttpResponse, WasmRuntimeContract,
    WebCryptoKeyHandle, WebCryptoOperation, embedding_target_decisions, ffi_api_freeze_review,
};
#[cfg(feature = "full-surface")]
pub use presence::{Presence, PresenceManager};
#[cfg(feature = "full-surface")]
pub use profile::{
    DataClassification, ExternalDeviceApprovalMode, PairwiseControlMessage,
    PairwiseControlMessageKind, ProfileManager, ServiceReplacementPlan, SovereignDeploymentPolicy,
    SpaceExportManifest, SpaceImportValidation, TspTrustBinding, UserProfile,
    validate_space_import,
};
#[cfg(feature = "full-surface")]
pub use push::{
    CHIME_PUSH_REGISTRATION_VERSION, ChimePushRegistration, EncryptedPushPayload, PushEvent,
    PushGateway, PushPayload, PushPlatform, PushPriority, PushRule, PushToken,
};
#[cfg(feature = "full-surface")]
pub use receipts::{ReadMarker, ReadReceipt, ReceiptManager, ReceiptVisibility};
#[cfg(feature = "full-surface")]
pub use resolver::{
    REDUCER_SNAPSHOT_PROFILE, REDUCER_SNAPSHOT_SCHEMA, ReducerSnapshotManifest,
    SnapshotChunkManifest, SnapshotRestore, SnapshotRestoreSource, SnapshotSignature,
    SnapshotSignatureBindingPayload, SpaceState, StateSnapshot, merkle_root, state_merkle_root,
    verify_snapshot_chunks,
};
#[cfg(feature = "full-surface")]
pub use search::{SpaceSearchEntry, SpaceSearchIndex, SpaceSearchQuery};
#[cfg(all(feature = "full-surface", feature = "server"))]
pub use server::{
    AuthenticatedPrincipal, BearerTokenAuthenticator, EndpointContract, EndpointHandler,
    EndpointMethod, EndpointParameter, EndpointParameterLocation, EndpointSchemaBinding,
    HttpAdapterRequest, HttpAdapterResponse, MatchedEndpoint, MemoryIdempotencyStore,
    MemoryRateLimiter, OperationScopeAuthorizer, ProtocolFixtureFlow, ProtocolFixtureReport,
    ProtocolFixtureStep, ProtocolGoldenVector, ProtocolServerFixture, RoutedEndpointService,
    RoutedHttpAdapterRequest, ServerAuthenticationDecision, ServerAuthenticationScheme,
    ServerAuthenticator, ServerAuthorizationDecision, ServerAuthorizer, ServerIdempotencyDecision,
    ServerIdempotencyKey, ServerIdempotencyStore, ServerMiddlewareConfig,
    ServerMiddlewareRejection, ServerMiddlewareStack, ServerRateLimitDecision, ServerRateLimiter,
    ServerRequest, ServerRequestContext, ServerResponse, TowerLikeEndpointService,
    WireConformanceVector, default_public_operations, dispatch_routed_http_request,
    endpoint_contracts, endpoint_parameters, endpoint_schema_binding, endpoint_schema_bindings,
    match_endpoint, openapi_document, protocol_golden_vectors, reject_query_auth,
    wire_negative_vectors,
};
#[cfg(feature = "full-surface")]
pub use settings::{
    ClientSettings, NotificationPreferences, PrivacySettings, SettingsManager, ThemeSetting,
};
#[cfg(feature = "full-surface")]
pub use space::{
    BatchCreateEntity, BatchUpdateEntity, EntityAggregation, EntityQuery, EntityVersion,
    EntityVersionDiff, GraphTraversal, RelationOperationInput, Space,
};
#[cfg(feature = "full-surface")]
pub use store::{
    AcceptUnsignedCommitProofs, AccountSessionStore, AuditLogStore, BlobMetadataStore,
    CommitProofVerifier, EncryptedMemoryRepoStore, EventCacheStore, IndexedDbPersistentState,
    IndexedDbRepoStore, MemoryPersistenceStore, MemoryRepoStore, RepoObjectStore, RepoStore,
    RepoWriteBatch, RepoWriteReceipt, SharedSqliteRepoStore, SqliteRepoStore, StateSnapshotStore,
    StoreCache, StoreConformanceReport, StoreConformanceResult, StoreConformanceTarget,
    StoreConformanceVector, StoreEncryptionKey, StoreMigration, StoreMigrationMetadata,
    StoreSchemaMetadata, StoreSnapshot, StoredAccountData, TransactionalRepoStore,
    rebuild_space_state_from_events, restore_space_state_from_persistence,
    run_store_conformance_suite,
};
#[cfg(all(feature = "full-surface", feature = "sync-runtime"))]
pub use sync_client::{
    AsyncSyncTransport, BackoffConfig, BackpressureConfig, BoxSyncFuture, CancellationToken,
    ExponentialBackoff, LocalEcho, ProcessedSpace, SendQueue, SendQueueItem, SendQueueItemKind,
    SendQueueSnapshot, SendQueueStatus, SlidingSync, SlidingWindow, SpaceListChange,
    SpaceListEntry, SpaceListFilter, SpaceListService, SpaceListSnapshot, SpaceListSort,
    SyncGapStrategy, SyncLoop, SyncLoopControl, SyncLoopSnapshot, SyncLoopStep,
    SyncResponseProcessor, SyncSubscribeTransport, SyncTransport,
};
#[cfg(all(feature = "full-surface", feature = "timeline-runtime"))]
pub use timeline::{
    CachedEvent, EventCache, EventCacheInsert, EventCacheUpdate, FocusedTimeline, Timeline,
    TimelineDirection, TimelineEvent, TimelineFrom, TimelineGap, TimelineItem, TimelineItemKind,
    TimelineOptions, TimelineReactionSummary, TimelineReadReceipt, TimelineTypingUpdate,
};
#[cfg(feature = "full-surface")]
pub use typing::{TypingManager, TypingNotification};
#[cfg(feature = "full-surface")]
pub use webrtc::{
    CallState, ConferenceMode, ConferenceSession, IceCandidate, IceServer, IceServerKind,
    MediaTrack, MediaTrackKind, SdpType, SessionDescription, WebRtcCall, WebRtcManager,
    WebRtcSignalKind, WebRtcSignalMessage,
};
