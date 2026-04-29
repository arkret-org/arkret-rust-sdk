//! Contrix v1 Rust SDK.
//!
//! This crate exposes Contrix protocol concepts directly. The source of truth
//! is signed Events / Operations in append-only Repos; Views are derived
//! projections.

pub mod account;
pub mod agent;
#[cfg(feature = "applet-runtime")]
pub mod applet;
pub mod auth;
pub mod authz;
pub mod base;
pub mod canonical;
#[cfg(feature = "client")]
pub mod client;
pub mod content;
pub mod crypto;
pub mod crypto_store;
pub mod cursor;
#[cfg(feature = "device-runtime")]
pub mod devices;
pub mod discovery;
pub mod e2ee;
pub mod error;
pub mod event_handler;
pub mod federation;
pub mod hlc;
pub mod identity;
pub mod media;
pub mod membership;
#[cfg(feature = "mls")]
pub mod mls;
pub mod model;
pub mod notifications;
pub mod performance;
pub mod presence;
pub mod profile;
pub mod push;
pub mod receipts;
pub mod resolver;
pub mod search;
#[cfg(feature = "server")]
pub mod server;
pub mod service;
pub mod settings;
pub mod space;
pub mod store;
pub mod sync;
#[cfg(feature = "sync-runtime")]
pub mod sync_client;
#[cfg(feature = "timeline-runtime")]
pub mod timeline;
pub mod typing;
pub mod webrtc;

pub use account::AccountDataManager;
pub use agent::{
    AgentBridgeMetadata, AgentMemory, AgentMemoryReview, AgentMemoryState, AgentMemoryStore,
    AgentPrincipal, AgentProtocol, AgentProtocolBridge, AgentProtocolEndpoint,
    AgentProtocolMessage, AgentRun, AgentRunManager, AgentRunState, AgentToolAuditAction,
    AgentToolAuditEntry, AgentToolAuditLog, DelegatedActor, ExternalAgent, MemoryLayer,
};
#[cfg(feature = "applet-runtime")]
pub use applet::{
    AppletNamespaceConflict, AppletNamespaceDeclaration, AppletNamespaceKind, AppletPermission,
    AppletPortal, AppletPortalManager, AppletRegistry, AppletSchema, AppserviceIntent,
    AppserviceRegistration, AppserviceRoute, AppserviceRouteSet, AppserviceTransaction,
    AppserviceTransactionRecord, AppserviceTransactionStore, BridgeMappingStore,
    GhostActorAccountability, OpenApiBinding, PortalMode, PortalSpaceMapping, RemoteSpaceMapping,
    RemoteUserMapping, SignedAppletRegistration, ThirdPartyLookupKind, ThirdPartyLookupRequest,
    ThirdPartyLookupResponse, VirtualActor,
};
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
pub use authz::{
    ApprovalMode, AuthzContext, AuthzDecision, AuthzEngine, CapabilityFrontierValidation,
    CapabilityGrant, ClaimRequirement, Constraint, ConstraintDuration, ConstraintEffect,
    ConstraintEntry, FieldScope, ModerationReport, PolicyCheckRequest, PolicyCheckResponse,
    PolicyServerEffect, RateLimitScope, Recurrence, Resource, ResourceSelector, ScopeLimitation,
    VerifiedClaim, apply_policy_response, capability_grants_from_space_state,
    moderation_report_for_policy_outcome, reject_unknown_critical_constraints,
    validate_capability_frontier,
};
pub use base::{
    BaseClient, BootstrapSequence, BootstrapStep, BootstrapStepKind, BootstrapStepStatus,
    ClientSpace, SessionMeta, SessionRestore, SpaceStateType,
};
#[cfg(feature = "client")]
pub use client::{Auth, Client, ClientBuilder};
pub use content::{
    LinkPreview, MarkdownDocument, Mention, Reaction, ReactionManager, ReactionSummary,
    RichTextBlock, extract_link_previews, parse_mentions,
};
pub use crypto::{
    AEAD_ALGORITHM, EncryptedEnvelopeAad, EncryptedEnvelopeDigestReport, KeyLifecycleHook,
    KeyLifecyclePhase, SecurityReviewItem, SecurityReviewStatus, encrypted_envelope_digest_report,
    envelope_aad_digest, json_aad_digest, security_review_checklist, verify_envelope_aad_digest,
};
pub use crypto_store::{
    CryptoStore, MemoryCryptoStore, MlsEpochSecretRecord, MlsGroupStateRecord, MlsRecoveryAction,
    MlsRecoveryPlan, StoredDeviceVerification,
};
pub use cursor::{Cursor, SpacePosition, SyncPositions, SyncTracker};
#[cfg(feature = "device-runtime")]
pub use devices::{
    Device, DeviceChange, DeviceManager, DeviceMetadata, DeviceVerificationChallenge,
    DeviceVerificationState, KeyBackup, QrVerificationPayload, ToDeviceEnvelope,
    device_verification_commitment,
};
pub use discovery::{DirectoryService, DirectoryUser, OpenGraphPreview, UrlPreviewCache};
pub use e2ee::{
    AuditAction, AuditEntry, E2eeGroup, E2eeKeyBackup, E2eeKeyRecord, E2eeManager, E2eeMessage,
    E2eeMessageValidation, E2eeMessageValidationFailure,
};
pub use error::{Error, Result};
pub use event_handler::{
    BotCommand, BotCommandParser, BotRuntime, BotRuntimeReport, BotRuntimeShutdown,
    BuiltInEventHandlers, ClientEvent, ClientEventFilter, ClientEventKind, EventHandlerRegistry,
    EventPipeline, HandlerGuard,
};
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
pub use hlc::{
    HlcComponents, HlcGenerator, compare_hlc, is_clock_skew_acceptable, parse_hlc, time_until_hlc,
    validate_hlc_format,
};
pub use identity::{
    CompositeDidResolver, DidDocument, DidKeriResolver, DidKeyLogEntry, DidKeyLogOperation,
    DidKeyResolver, DidMigration, DidResolver, DidUuidResolver, DidWebResolver, HandleAttestation,
    HandleClaim, IdentityManager, VerifiedDidKeyLog, did_key_log_proof, handle_claim_proof,
    verify_did_key_log,
};
pub use media::{Attachment, EncryptedAttachment, MediaMetadata, MemoryBlobStore, Thumbnail};
pub use membership::{
    Invite, Member, MemberChange, MemberProfile, MemberRole, MembershipManager, MembershipState,
    ThirdPartyInvite,
};
#[cfg(feature = "mls")]
pub use mls::*;
pub use model::*;
pub use notifications::{
    NotificationAction, NotificationCounts, NotificationItem, NotificationManager, NotificationRule,
};
pub use performance::{
    BenchmarkPlan, BenchmarkTarget, CompileOptimizationPlan, MetricName, MetricSample, ObjectPool,
    ParallelProcessor, PerformanceConfig, RequestBatch, RequestBatcher, RobustnessPlan,
    RobustnessTarget, TraceContext, TraceSpanKind, ZeroCopyJson,
};
pub use presence::{Presence, PresenceManager};
pub use profile::{
    AudiencePolicyBinding, DataClassification, ExternalDeviceApprovalMode, PairwiseControlMessage,
    PairwiseControlMessageKind, ProfileManager, ServiceReplacementPlan, SocialAction,
    SocialActionKind, SocialCircle, SocialFeed, SocialGraph, SocialTarget,
    SovereignDeploymentPolicy, SpaceExportManifest, SpaceImportValidation, TspTrustBinding,
    UserProfile, validate_space_import,
};
pub use push::{
    EncryptedPushPayload, PushEvent, PushGateway, PushPayload, PushPlatform, PushPriority,
    PushRule, PushToken,
};
pub use receipts::{ReadMarker, ReadReceipt, ReceiptManager, ReceiptVisibility};
pub use resolver::{
    REDUCER_SNAPSHOT_PROFILE, REDUCER_SNAPSHOT_SCHEMA, ReducerSnapshotManifest,
    SnapshotChunkManifest, SnapshotRestore, SnapshotRestoreSource, SnapshotSignature,
    SnapshotSignatureBindingPayload, SpaceState, StateSnapshot, merkle_root, state_merkle_root,
    verify_snapshot_chunks,
};
pub use search::{SpaceSearchEntry, SpaceSearchIndex, SpaceSearchQuery};
#[cfg(feature = "server")]
pub use server::{
    EndpointContract, EndpointHandler, EndpointMethod, EndpointParameter,
    EndpointParameterLocation, EndpointSchemaBinding, HttpAdapterRequest, HttpAdapterResponse,
    MatchedEndpoint, ProtocolGoldenVector, ServerRequest, ServerResponse, TowerLikeEndpointService,
    WireConformanceVector, endpoint_contracts, endpoint_parameters, endpoint_schema_binding,
    endpoint_schema_bindings, match_endpoint, openapi_document, protocol_golden_vectors,
    reject_query_auth, wire_negative_vectors,
};
pub use service::{
    ApiConventionMetadata, HttpTraceMetadata, NotFoundPrivacy, QuotaKind, QuotaMetadata,
    RateLimitMetadata, RateLimitScopeKind, ServiceDidAllowlist, ServiceEndpointBinding,
    ServiceRequirements, ServiceType, privacy_preserving_not_found, quota_exceeded_error,
    rate_limited_error,
};
pub use settings::{
    ClientSettings, NotificationPreferences, PrivacySettings, SettingsManager, ThemeSetting,
};
pub use space::{
    BatchCreateEntity, BatchUpdateEntity, EntityAggregation, EntityQuery, EntityVersion,
    EntityVersionDiff, GraphTraversal, RelationOperationInput, Space,
};
pub use store::{
    AcceptUnsignedCommitProofs, AccountSessionStore, AuditLogStore, BlobMetadataStore,
    CommitProofVerifier, EncryptedMemoryRepoStore, EventCacheStore, IndexedDbRepoStore,
    MemoryPersistenceStore, MemoryRepoStore, RepoObjectStore, RepoStore, RepoWriteBatch,
    RepoWriteReceipt, SqliteRepoStore, StateSnapshotStore, StoreCache, StoreEncryptionKey,
    StoreMigration, StoreMigrationMetadata, StoreSchemaMetadata, StoreSnapshot, StoredAccountData,
    TransactionalRepoStore, rebuild_space_state_from_events, restore_space_state_from_persistence,
};
pub use sync::{
    BackfillDirection, BackfillFrom, BackfillRequest, BackfillResponse, BucketedSpaceUpdate,
    LimitedTimelineState, MembershipBucket, PresenceStatus, SpaceSubscription, SpaceUpdate,
    SubscriptionConfig, SyncClient, SyncFilter, SyncGap, SyncGapReason, SyncMode, SyncRequest,
    SyncResponse, SyncSemantics, SyncStreamPosition, SyncTokenBinding, SyncUpdates, TimelineFilter,
    TimelineOrderKey, ToDeviceAck, ToDeviceAckStatus, WaitForFrontier, sync_filter_hash,
};
#[cfg(feature = "sync-runtime")]
pub use sync_client::{
    BackoffConfig, ExponentialBackoff, LocalEcho, ProcessedSpace, SendQueue, SendQueueItem,
    SendQueueItemKind, SendQueueSnapshot, SendQueueStatus, SlidingSync, SlidingWindow,
    SpaceListChange, SpaceListEntry, SpaceListFilter, SpaceListService, SpaceListSnapshot,
    SpaceListSort, SyncLoop, SyncLoopStep, SyncResponseProcessor, SyncTransport,
};
#[cfg(feature = "timeline-runtime")]
pub use timeline::{
    CachedEvent, EventCache, EventCacheInsert, EventCacheUpdate, FocusedTimeline, Timeline,
    TimelineDirection, TimelineEvent, TimelineFrom, TimelineGap, TimelineItem, TimelineItemKind,
    TimelineOptions, TimelineReactionSummary, TimelineReadReceipt, TimelineTypingUpdate,
};
pub use typing::{TypingManager, TypingNotification};
pub use webrtc::{
    CallState, ConferenceMode, ConferenceSession, IceCandidate, IceServer, IceServerKind,
    MediaTrack, MediaTrackKind, SdpType, SessionDescription, WebRtcCall, WebRtcManager,
};
