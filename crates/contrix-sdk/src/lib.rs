//! Contrix v1 Rust SDK.
//!
//! This crate exposes Contrix protocol concepts directly. The source of truth
//! is signed Events / Operations in append-only Repos; Views are derived
//! projections.

pub mod account;
pub mod agent;
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
pub mod sync_client;
pub mod timeline;
pub mod typing;
pub mod webrtc;

pub use account::AccountDataManager;
pub use agent::{
    AgentMemory, AgentMemoryReview, AgentMemoryState, AgentMemoryStore, AgentProtocol,
    AgentProtocolBridge, AgentProtocolMessage, ExternalAgent, MemoryLayer,
};
pub use applet::{
    AppletPermission, AppletPortal, AppletPortalManager, AppletRegistry, AppletSchema,
    OpenApiBinding, PortalMode,
};
pub use auth::{
    AccountRecoveryMethod, AccountRecoveryRequest, AuthManager, AuthRateLimitAction,
    AuthRateLimitContext, AuthRateLimitHook, AuthSession, DidProofVerification,
    DidProofVerificationRequest, DidProofVerifier, MfaChallenge, OidcAuthRequest, OidcCredential,
    OidcIssuerMetadata, OidcJwks, OidcVerificationRequest, OidcVerifiedIdentity, OidcVerifier,
    PasskeyChallenge, PasskeyVerification, PasskeyVerificationRequest, PasskeyVerifier,
    PasswordHashAlgorithm, PasswordHashVerifier, PasswordUser, PasswordVerification,
    PasswordVerificationRequest, SessionPrincipalBinding, WebAuthnPasskeyResponse,
};
pub use authz::{
    ApprovalMode, AuthzContext, AuthzDecision, AuthzEngine, CapabilityGrant, ClaimRequirement,
    Constraint, ConstraintDuration, ConstraintEffect, ConstraintEntry, FieldScope, RateLimitScope,
    Recurrence, Resource, ResourceSelector, ScopeLimitation, VerifiedClaim,
    capability_grants_from_space_state,
};
pub use base::{BaseClient, ClientSpace, SessionMeta, SpaceStateType};
#[cfg(feature = "client")]
pub use client::{Auth, Client, ClientBuilder};
pub use content::{
    LinkPreview, MarkdownDocument, Mention, Reaction, ReactionManager, ReactionSummary,
    RichTextBlock, extract_link_previews, parse_mentions,
};
pub use crypto::AEAD_ALGORITHM;
pub use crypto_store::{
    CryptoStore, MemoryCryptoStore, MlsEpochSecretRecord, MlsGroupStateRecord, MlsRecoveryAction,
    MlsRecoveryPlan, StoredDeviceVerification,
};
pub use cursor::{Cursor, SpacePosition, SyncPositions, SyncTracker};
pub use devices::{
    Device, DeviceChange, DeviceManager, DeviceMetadata, DeviceVerificationChallenge,
    DeviceVerificationState, KeyBackup, ToDeviceEnvelope,
};
pub use discovery::{DirectoryService, DirectoryUser, OpenGraphPreview, UrlPreviewCache};
pub use e2ee::{
    AuditAction, AuditEntry, E2eeGroup, E2eeKeyBackup, E2eeKeyRecord, E2eeManager, E2eeMessage,
};
pub use error::{Error, Result};
pub use event_handler::{BuiltInEventHandlers, ClientEvent, EventHandlerRegistry, HandlerGuard};
pub use federation::{
    FederationManager, FederationRequest, FederationTransaction, ServerInfo, SovereignDeployment,
    TrustAnchor,
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
pub use profile::{ProfileManager, UserProfile};
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
    EndpointContract, EndpointHandler, EndpointMethod, ServerRequest, ServerResponse,
    endpoint_contracts, openapi_document,
};
pub use service::{ServiceRequirements, ServiceType};
pub use settings::{
    ClientSettings, NotificationPreferences, PrivacySettings, SettingsManager, ThemeSetting,
};
pub use space::{
    BatchCreateEntity, BatchUpdateEntity, EntityAggregation, EntityQuery, EntityVersion,
    EntityVersionDiff, GraphTraversal, RelationOperationInput, Space,
};
pub use store::{
    AcceptUnsignedCommitProofs, CommitProofVerifier, EncryptedMemoryRepoStore, IndexedDbRepoStore,
    MemoryRepoStore, RepoStore, SqliteRepoStore, StoreCache, StoreEncryptionKey, StoreMigration,
    StoreSnapshot,
};
pub use sync::{
    BackfillDirection, BackfillFrom, BackfillRequest, BackfillResponse, PresenceStatus,
    SpaceSubscription, SpaceUpdate, SubscriptionConfig, SyncClient, SyncFilter, SyncRequest,
    SyncResponse, SyncUpdates, TimelineFilter,
};
pub use sync_client::{
    BackoffConfig, ExponentialBackoff, ProcessedSpace, SlidingSync, SlidingWindow, SyncLoop,
    SyncLoopStep, SyncResponseProcessor, SyncTransport,
};
pub use timeline::{
    Timeline, TimelineDirection, TimelineEvent, TimelineFrom, TimelineGap, TimelineOptions,
};
pub use typing::{TypingManager, TypingNotification};
pub use webrtc::{
    CallState, ConferenceMode, ConferenceSession, IceCandidate, IceServer, IceServerKind,
    MediaTrack, MediaTrackKind, SdpType, SessionDescription, WebRtcCall, WebRtcManager,
};
