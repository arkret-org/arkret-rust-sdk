//! Contrix v1 Rust SDK.
//!
//! This crate exposes Contrix protocol concepts directly. The source of truth
//! is signed Events / Operations in append-only Repos; Views are derived
//! projections.

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
#[cfg(all(feature = "full-surface", feature = "axum-adapter"))]
pub mod axum_adapter;
#[cfg(feature = "full-surface")]
pub mod base;
pub mod canonical;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "full-surface")]
pub mod content;
#[cfg(feature = "full-surface")]
pub mod crypto;
#[cfg(feature = "full-surface")]
pub mod crypto_store;
#[cfg(feature = "full-surface")]
pub mod cursor;
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub mod devices;
#[cfg(feature = "full-surface")]
pub mod discovery;
#[cfg(feature = "full-surface")]
pub mod e2ee;
pub mod error;
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
pub mod model;
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
#[cfg(all(feature = "full-surface", feature = "server"))]
pub mod server;
pub mod service;
#[cfg(feature = "full-surface")]
pub mod settings;
#[cfg(feature = "full-surface")]
pub mod space;
#[cfg(feature = "full-surface")]
pub mod store;
#[cfg(feature = "full-surface")]
pub mod sync;
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
    ClaimDisclosureRequirement, DidProofVerification, DidProofVerificationRequest,
    DidProofVerifier, DisclosurePolicy, MfaChallenge, OidcAuthRequest, OidcCredential,
    OidcIssuerMetadata, OidcJwks, OidcVerificationRequest, OidcVerifiedIdentity, OidcVerifier,
    PasskeyChallenge, PasskeyVerification, PasskeyVerificationRequest, PasskeyVerifier,
    PasswordHashAlgorithm, PasswordHashVerifier, PasswordUser, PasswordVerification,
    PasswordVerificationRequest, PersistedAuthSession, PresentationRequest, PresentationValidation,
    PresentedClaim, RefreshTokenMetadata, RejectedClaim, SessionPrincipalBinding,
    SessionRevocation, WebAuthnPasskeyResponse, validate_presentation,
};
#[cfg(feature = "full-surface")]
pub use authz::{
    ApprovalFlowManager, ApprovalMode, AuthzContext, AuthzDecision, AuthzEngine,
    CapabilityFrontierValidation, CapabilityGrant, ClaimRequirement, Constraint,
    ConstraintDuration, ConstraintEffect, ConstraintEntry, FieldScope, GrantProposal,
    ModerationReport, PolicyCheckRequest, PolicyCheckResponse, PolicyServerEffect,
    ProposalApproval, ProposalStatus, RateLimitScope, Recurrence, Resource, ResourceSelector,
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
pub use client::{Auth, Client, ClientBuilder};
#[cfg(feature = "full-surface")]
pub use content::{
    LinkPreview, MarkdownDocument, Mention, MentionTarget, Reaction, ReactionManager,
    ReactionSummary, RichTextBlock, extract_link_previews, parse_mentions,
};
#[cfg(feature = "full-surface")]
pub use crypto::{
    AEAD_ALGORITHM, EncryptedEnvelopeAad, EncryptedEnvelopeDigestReport, KeyLifecycleHook,
    KeyLifecyclePhase, SecurityReviewItem, SecurityReviewStatus, encrypted_envelope_digest_report,
    envelope_aad_digest, json_aad_digest, security_review_checklist, verify_envelope_aad_digest,
};
#[cfg(feature = "full-surface")]
pub use crypto_store::{
    CryptoStore, EncryptedMemoryCryptoStore, MemoryCryptoStore, MlsEpochSecretRecord,
    MlsGroupStateRecord, MlsRecoveryAction, MlsRecoveryPlan, StoredDeviceVerification,
};
#[cfg(feature = "full-surface")]
pub use cursor::{Cursor, SpacePosition, SyncPositions, SyncTracker};
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub use devices::{
    Device, DeviceChange, DeviceManager, DeviceMetadata, DeviceVerificationChallenge, KeyBackup,
    QrVerificationPayload, ToDeviceEnvelope, device_verification_commitment,
};
#[cfg(feature = "full-surface")]
pub use discovery::{DirectoryService, DirectoryUser, OpenGraphPreview, UrlPreviewCache};
#[cfg(feature = "full-surface")]
pub use e2ee::{
    AuditAction, AuditEntry, E2eeGroup, E2eeKeyBackup, E2eeKeyRecord, E2eeManager, E2eeMessage,
    E2eeMessageValidation, E2eeMessageValidationFailure,
};
pub use error::{Error, Result};
#[cfg(feature = "full-surface")]
pub use event_handler::{
    BotCommand, BotCommandParser, BotRuntime, BotRuntimeReport, BotRuntimeShutdown,
    BuiltInEventHandlers, ClientEvent, ClientEventFilter, ClientEventKind, EventHandlerRegistry,
    EventPipeline, HandlerGuard,
};
#[cfg(feature = "full-surface")]
pub use federation::{
    FederationBackfillAuthorization, FederationManager, FederationQuarantineKind,
    FederationQuarantineRecord, FederationReplayDecision, FederationRequest, FederationTransaction,
    FederationTransactionEnvelope, HttpMessageSignature, HttpMessageSignatureInput, ServerInfo,
    ServiceEndpointDescriptor, SovereignDeployment, TrustAnchor, VerifyActorChallenge,
    VerifyActorChallengeSignature, WellKnownContrixServer, content_digest_sha256,
    did_document_service_endpoint_matches, duplicate_transaction_quarantine,
    fork_quarantine_record, http_message_signature_base, sign_http_message,
    sign_verify_actor_challenge, verify_actor_challenge_signature, verify_http_message_signature,
};
#[cfg(feature = "full-surface")]
pub use hlc::{
    HlcComponents, HlcGenerator, compare_hlc, is_clock_skew_acceptable, parse_hlc, time_until_hlc,
    validate_hlc_format,
};
#[cfg(feature = "full-surface")]
pub use identity::{
    CompositeDidResolver, DidDocument, DidKeriResolver, DidKeyLogEntry, DidKeyLogOperation,
    DidKeyResolver, DidMigration, DidRegistryReceipt, DidResolver, DidUuidResolver, DidVisibility,
    DidWebResolver, HandleAttestation, HandleClaim, IdentityManager, PairwiseDidBinding,
    PairwiseDidResolutionProof, PairwiseDidStore, VerifiedDidKeyLog, did_key_log_proof,
    did_registry_receipt_signature, handle_claim_proof, pairwise_resolution_proof,
    verify_did_key_log,
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
pub use model::*;
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
    EmbeddingSupportLevel, EmbeddingTarget, EmbeddingTargetDecision, FfiCallbackAction,
    FfiCallbackResult, FfiCancellationHandle, FfiError, FfiErrorCode, FfiEvent, FfiEventSink,
    FfiHandle, FfiHandleKind, embedding_target_decisions,
};
#[cfg(feature = "full-surface")]
pub use presence::{Presence, PresenceManager};
#[cfg(feature = "full-surface")]
pub use profile::{
    AudiencePolicyBinding, DataClassification, ExternalDeviceApprovalMode, PairwiseControlMessage,
    PairwiseControlMessageKind, ProfileManager, ServiceReplacementPlan, SocialAction,
    SocialActionKind, SocialCircle, SocialFeed, SocialGraph, SocialTarget,
    SovereignDeploymentPolicy, SpaceExportManifest, SpaceImportValidation, TspTrustBinding,
    UserProfile, validate_space_import,
};
#[cfg(feature = "full-surface")]
pub use push::{
    EncryptedPushPayload, PushEvent, PushGateway, PushPayload, PushPlatform, PushPriority,
    PushRule, PushToken,
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
    EndpointContract, EndpointHandler, EndpointMethod, EndpointParameter,
    EndpointParameterLocation, EndpointSchemaBinding, HttpAdapterRequest, HttpAdapterResponse,
    MatchedEndpoint, ProtocolFixtureFlow, ProtocolFixtureReport, ProtocolFixtureStep,
    ProtocolGoldenVector, ProtocolServerFixture, ServerRequest, ServerResponse,
    TowerLikeEndpointService, WireConformanceVector, endpoint_contracts, endpoint_parameters,
    endpoint_schema_binding, endpoint_schema_bindings, match_endpoint, openapi_document,
    protocol_golden_vectors, reject_query_auth, wire_negative_vectors,
};
pub use service::{
    ApiConventionMetadata, HttpTraceMetadata, NotFoundPrivacy, QuotaKind, QuotaMetadata,
    RateLimitMetadata, RateLimitScopeKind, ServiceDidAllowlist, ServiceEndpointBinding,
    ServiceRequirements, ServiceType, privacy_preserving_not_found, quota_exceeded_error,
    rate_limited_error,
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
    CommitProofVerifier, EncryptedMemoryRepoStore, EventCacheStore, IndexedDbRepoStore,
    MemoryPersistenceStore, MemoryRepoStore, RepoObjectStore, RepoStore, RepoWriteBatch,
    RepoWriteReceipt, SqliteRepoStore, StateSnapshotStore, StoreCache, StoreEncryptionKey,
    StoreMigration, StoreMigrationMetadata, StoreSchemaMetadata, StoreSnapshot, StoredAccountData,
    TransactionalRepoStore, rebuild_space_state_from_events, restore_space_state_from_persistence,
};
#[cfg(feature = "full-surface")]
pub use sync::{
    BackfillDirection, BackfillFrom, BackfillRequest, BackfillResponse, BucketedSpaceUpdate,
    LimitedTimelineState, MembershipBucket, PresenceStatus, SpaceSubscription, SpaceUpdate,
    SubscriptionConfig, SyncClient, SyncFilter, SyncGap, SyncGapReason, SyncMode, SyncRequest,
    SyncResponse, SyncSemantics, SyncStreamPosition, SyncTokenBinding, SyncUpdates, TimelineFilter,
    TimelineOrderKey, ToDeviceAck, ToDeviceAckStatus, WaitForFrontier, sync_filter_hash,
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
