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
    AgentProtocolBridge, AgentProtocolMessage, ExternalAgent,
};
pub use applet::{
    AppletPermission, AppletPortal, AppletPortalManager, AppletRegistry, AppletSchema,
    OpenApiBinding, PortalMode,
};
pub use auth::{
    AuthManager, AuthSession, MfaChallenge, OidcAuthRequest, PasskeyChallenge, PasswordUser,
};
pub use authz::{
    AuthzContext, AuthzDecision, AuthzEngine, CapabilityGrant, ClaimRequirement, Constraint,
    ConstraintDuration, ConstraintEffect, ConstraintEntry, FieldScope, RateLimitScope, Recurrence,
    Resource, ResourceSelector,
};
pub use base::{BaseClient, ClientSpace, SessionMeta, SpaceStateType};
#[cfg(feature = "client")]
pub use client::{Auth, Client, ClientBuilder};
pub use content::{
    LinkPreview, MarkdownDocument, Mention, Reaction, ReactionManager, ReactionSummary,
    RichTextBlock, extract_link_previews, parse_mentions,
};
pub use cursor::{Cursor, SpacePosition, SyncPositions, SyncTracker};
pub use devices::{
    Device, DeviceChange, DeviceManager, DeviceMetadata, DeviceVerificationState, KeyBackup,
    ToDeviceEnvelope,
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
    DidDocument, DidMigration, HandleAttestation, HandleClaim, IdentityManager, handle_claim_proof,
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
    CompileOptimizationPlan, ObjectPool, ParallelProcessor, PerformanceConfig, RequestBatch,
    RequestBatcher, ZeroCopyJson,
};
pub use presence::{Presence, PresenceManager};
pub use profile::{ProfileManager, UserProfile};
pub use push::{
    EncryptedPushPayload, PushEvent, PushGateway, PushPayload, PushPlatform, PushPriority,
    PushRule, PushToken,
};
pub use receipts::{ReadMarker, ReadReceipt, ReceiptManager, ReceiptVisibility};
pub use resolver::{SpaceState, StateSnapshot};
pub use search::{SpaceSearchEntry, SpaceSearchIndex, SpaceSearchQuery};
pub use service::{ServiceRequirements, ServiceType};
pub use settings::{
    ClientSettings, NotificationPreferences, PrivacySettings, SettingsManager, ThemeSetting,
};
pub use space::{
    BatchCreateEntity, BatchUpdateEntity, EntityAggregation, EntityQuery, EntityVersion,
    EntityVersionDiff, GraphTraversal, Space,
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
