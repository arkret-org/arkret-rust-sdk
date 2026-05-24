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
//!     OperationId, OperationKindRegistry, RealmId,
//! };
//! use serde_json::json;
//!
//! # fn main() -> contrix::Result<()> {
//! let draft = OperationEnvelopeBuilder::new(
//!     OperationId::new("cx:operation:01904100-0000-7000-8000-57d7d85564c5")?,
//!     RealmId::new("cx:realm:01904100-0000-7000-8000-668e2181b41d")?,
//!     Did::new("did:web:alice.example")?,
//!     OP_MESSAGE_CREATE,
//!     1,
//!     Hlc::new("01970e589d21-0001-a13f9c2e")?,
//! )
//! .with_content(json!({
//!     "flow_id": "cx:flow:01904100-0000-7000-8000-6c663fa0205f",
//!     "track": "main",
//!     "body": "hello"
//! }))
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
//! use contrix::{SyncLoop, SyncLoopStep, SyncReqBody, SyncResBody};
//!
//! # fn main() {
//! let mut sync_loop = SyncLoop::new();
//! let mut transport = |_request: SyncReqBody| {
//!     Ok(SyncResBody {
//!         cursor: "s1".to_owned(),
//!         spaces: Default::default(),
//!         left_spaces: Vec::new(),
//!         to_device: Vec::new(),
//!         device_lists: Default::default(),
//!         presence: Vec::new(),
//!         account_data: Vec::new(),
//!         notifications: serde_json::Value::Null,
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
pub use contrix_api::product::client as client_api;
pub use contrix_core::events;
pub use contrix_core::schema;
pub use contrix_core::state;
pub use contrix_core::*;
pub use contrix_core::{canonical, cursor, error, identifiers, keystore, model, service, sync};
#[cfg(feature = "client")]
pub use contrix_http_client as http_client;
// Platform-native KeyStore backends. The glob import above already
// re-exports these symbols, but listing them explicitly keeps them
// visible in `cargo doc` and signals the supported surface to
// downstream crates that depend only on `contrix` (not `contrix-core`).
#[cfg(feature = "full-surface")]
pub use crate::store as store_contracts;
pub use contrix_api::federation as federation_api;
pub use contrix_api::identity as identity_api;
pub use contrix_api::push as push_gateway_api;
pub use contrix_core::lattice;
pub use contrix_core::operations;
pub use contrix_core::schema as schema_contracts;
pub use contrix_core::state as state_res;
pub use contrix_core::{
    InMemoryKeyStore, KeyStore, KeyStoreError, LinuxSecretServiceKeyStore, MacOsKeychainKeyStore,
    WindowsCredentialKeyStore, platform_default_keystore,
};
pub use contrix_crypto as crypto_protocol;
pub use contrix_ffi as ffi;
pub use contrix_html as html;
#[cfg(feature = "server")]
pub use contrix_server as server;
pub use contrix_signatures as signatures;
#[cfg(feature = "signer")]
pub use contrix_signatures::Ed25519MoveSigner;
pub use contrix_testing as testing;
#[cfg(feature = "full-surface")]
pub mod account;
#[cfg(feature = "full-surface")]
pub mod agent;
#[cfg(feature = "full-surface")]
pub mod agent_binding;
#[cfg(feature = "full-surface")]
#[cfg(all(feature = "full-surface", feature = "applet-runtime"))]
pub mod applet;
#[cfg(feature = "full-surface")]
pub mod auth;
#[cfg(feature = "full-surface")]
pub mod authz;
#[cfg(feature = "full-surface")]
pub mod base;
#[cfg(feature = "full-surface")]
pub mod consent;
#[cfg(feature = "full-surface")]
pub mod crypto;
#[cfg(feature = "full-surface")]
pub mod crypto_store;
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub mod device_message;
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub mod devices;
#[cfg(feature = "full-surface")]
pub mod discovery;
#[cfg(feature = "full-surface")]
pub mod e2ee;
#[cfg(feature = "full-surface")]
pub mod federation;
#[cfg(feature = "full-surface")]
pub mod hlc;
// RFC 9421 HTTP Message Signatures (Ed25519) + RFC 9530
// Content-Digest. Pure-Rust (ed25519-dalek + sha2 + base64), no
// transport / runtime deps — safe on wasm32 (yougen).
#[cfg(feature = "full-surface")]
pub mod http_signature;
// HttpDidResolver leans on a live Tokio runtime, blocking off-thread
// scheduling, and reqwest's native ClientBuilder transport knobs — none
// of which are available on the wasm32 fetch backend. Gate the module out
// on wasm32; web embedders should plug in a fetch-based resolver via
// the `DidResolver` trait directly.
#[cfg(all(feature = "full-surface", feature = "client", not(target_arch = "wasm32")))]
pub mod http_did_resolver;
#[cfg(feature = "full-surface")]
pub mod identity;
#[cfg(feature = "full-surface")]
pub mod identity_link;
/// RFC 7515 detached Ed25519 JWS verifier (see [`jws`] module docs).
/// Lives at the SDK root so principal-server-style consumers (yougen,
/// floria, cotest, teabay, soland) all reach the same verifier. Depends
/// on `identity::DidResolver`, so it's gated on `full-surface`.
#[cfg(feature = "full-surface")]
pub mod jws;
#[cfg(all(feature = "full-surface", feature = "device-runtime", feature = "client"))]
pub mod key_backup_client;
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub mod key_verification;
// `lattice_registry` is intentionally NOT feature-gated: yougen Move
// pre-check + cotest fixtures need the spec-normative cell-family
// registry independently of the higher-level full-surface client
// runtime.
pub mod lattice_registry;
#[cfg(feature = "full-surface")]
pub mod media;
#[cfg(feature = "full-surface")]
pub mod membership;
#[cfg(all(feature = "full-surface", feature = "mls"))]
pub mod mls;
#[cfg(feature = "full-surface")]
pub mod mls_move;
#[cfg(feature = "full-surface")]
pub mod notifications;
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
pub use account::{ACCOUNT_DATA_BLOCKLIST, AccountBlocklist, AccountDataManager, BlocklistEntry};
#[cfg(feature = "full-surface")]
pub use agent::{
    AgentBridgeMetadata, AgentPrincipal, AgentProtocol, AgentProtocolEndpoint,
    AgentProtocolMessage, AgentRun, AgentRunState, AgentToolAuditAction, AgentToolAuditEntry,
    DelegatedActor, ExternalAgent,
};
#[cfg(all(feature = "full-surface", feature = "applet-runtime"))]
pub use applet::{
    AppletNamespaceConflict, AppletNamespaceDeclaration, AppletNamespaceKind, AppletPermission,
    AppletPortal, AppletSchema, AppletServiceIntent, AppletServiceTransaction,
    GhostActorAccountability, OpenApiBinding, PortalMode, PortalSpaceMapping, RemoteSpaceMapping,
    RemoteUserMapping, SignedAppletRegistration, ThirdPartyLookupKind, ThirdPartyLookupReqBody,
    ThirdPartyLookupResBody, VirtualActor,
};
#[cfg(feature = "full-surface")]
pub use auth::{
    AccountAuthState, AccountRecoveryMethod, AccountRecoveryReqBody, AuthClaimType, AuthManager,
    AuthRateLimitAction, AuthRateLimitContext, AuthRateLimitHook, AuthSession, AuthStateSnapshot,
    CONTRIX_DEVICE_SCOPE_PREFIX, ClaimDisclosureRequirement, DidProofVerification,
    DidProofVerificationReqBody, DidProofVerifier, DisclosurePolicy,
    DisclosureProofAdapterBoundary, DisclosureProofFormat, MemorySessionGrantOutbox, MfaChallenge,
    OidcAuthReqBody, OidcCredential, OidcIssuerMetadata, OidcJwks, OidcVerificationReqBody,
    OidcVerifiedIdentity, OidcVerifier, PasskeyChallenge, PasskeyVerification,
    PasskeyVerificationReqBody, PasskeyVerifier, PasswordHashAlgorithm, PasswordHashVerifier,
    PasswordUser, PasswordVerification, PasswordVerificationReqBody, PersistedAuthSession,
    PresentationReqBody, PresentationValidation, PresentedClaim, PrincipalSessionGrantNotification,
    PrincipalSessionGrantNotificationResBody, PrincipalSessionGrantNotifier, RefreshTokenMetadata,
    RejectedClaim, SessionGrant, SessionGrantNotificationKind, SessionGrantOutboxEntry,
    SessionGrantOutboxState, SessionGrantPayload, SessionGrantRecord, SessionGrantRetryPolicy,
    SessionGrantSigner, SessionGrantVerification, SessionGrantVerifier, SessionPrincipalBinding,
    SessionRevocation, WebAuthnPasskeyResBody, contrix_device_scope, device_id_from_scope_token,
    issue_session_grant_with_signer, primary_device_id_from_scopes, validate_presentation,
    verify_session_grant_with_verifier,
};
#[cfg(feature = "full-surface")]
pub use authz::{
    ApprovalFlowManager, ApprovalMode, AuthzContext, AuthzDecision, AuthzEngine,
    CapabilityFrontierValidation, CapabilityGrant, ClaimRequirement, Constraint,
    ConstraintDuration, ConstraintEffect, ConstraintEntry, FieldScope, GrantProposal,
    ModerationReport, PolicyCheckReqBody, PolicyCheckResBody, PolicyServerEffect, ProposalApproval,
    ProposalStatus, ProtocolGrantApprovalRelation, ProtocolGrantClaimRequirement,
    ProtocolGrantConstraint, ProtocolGrantConstraintEffect, ProtocolGrantConstraintTrack,
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
pub use device_message::{DeviceMessage, DeviceMessageBuilder, DeviceMessageReceipt};
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub use devices::{
    CrossSigningBinding, CrossSigningKeyKind, CrossSigningKeyRecord, CrossSigningPublishContent,
    CrossSigningResetContent, CrossSigningResetProof, Device, DeviceBootstrapBinding, DeviceChange,
    DeviceManager, DeviceMessageEnvelope, DeviceMetadata, DeviceQuorumSignature,
    DeviceTrustBinding, DeviceTrustChainOutcome, DeviceVerificationChallenge,
    DeviceVerificationMessageContent, DeviceVerificationMessageKind, KeyBackup, KeyBackupClass,
    KeyBackupContentItem, KeyBackupEncryption, ProtocolKeyBackup, QrVerificationPayload,
    SignedCrossSigningKey, ToDeviceEnvelope, cross_signing_publish_cell_subject,
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
pub use federation::{
    FederationBackfillAuthorization, FederationManager, FederationQuarantineKind,
    FederationQuarantineRecord, FederationReplayDecision, FederationReplayRecord,
    FederationReplayStore, FederationReqBody, FederationTransaction, FederationTransactionEnvelope,
    HttpMessageSignature, HttpMessageSignatureInput, ServerInfo, ServiceEndpointDescriptor,
    SovereignDeployment, TrustAnchor, VerifyActorChallenge, VerifyActorChallengeSignature,
    WellKnownContrixServer, content_digest_sha256, did_document_service_endpoint_matches,
    duplicate_transaction_quarantine, fork_quarantine_record, rfc9421_http_message_signature_base,
    sign_http_message, sign_verify_actor_challenge, verify_actor_challenge_signature,
    verify_http_message_signature,
};
#[cfg(feature = "full-surface")]
pub use hlc::{
    HlcComponents, HlcGenerator, compare_hlc, is_clock_skew_acceptable, parse_hlc, time_until_hlc,
    validate_hlc_format,
};
#[cfg(feature = "client")]
pub use http_client::{Auth, Client, ClientBuilder, ClientRequestOptions, RetryConfig};
#[cfg(all(feature = "full-surface", feature = "client", not(target_arch = "wasm32")))]
pub use http_did_resolver::{
    DEFAULT_HTTP_DID_RESOLVER_TIMEOUT_MS, DEFAULT_HTTP_DID_RESOLVER_TTL_SECS, HttpDidResolver,
};
#[cfg(feature = "full-surface")]
pub use identity::{
    CompositeDidResolver, DID_WEB_MAX_DOCUMENT_BYTES, DidDocument, DidKeriResolver, DidKeyLogEntry,
    DidKeyLogOperation, DidKeyResolver, DidMigration, DidRegistryReceipt, DidResolver,
    DidVisibility, DidWebDocumentResBody, DidWebResolver, ExternalHandleProof, HandleAttestation,
    HandleClaim, HandleProofProfile, IdentityManager, InMemoryStaridRegistryAdapter,
    PairwiseDidBinding, PairwiseDidResolutionProof, PairwiseDidStore, StaridControlProofReqBody,
    StaridControlProofVerification, StaridRegistryAdapter, StaridRegistryRecord, VerifiedDidKeyLog,
    did_key_log_proof, did_registry_receipt_signature, handle_claim_proof, handle_dns_txt_name,
    handle_well_known_url, pairwise_resolution_proof, starid_control_proof, verify_did_key_log,
};
#[cfg(feature = "full-surface")]
pub use identity_link::{IdentityLinkCache, IdentityLinkCacheEntry};
#[cfg(all(feature = "full-surface", feature = "device-runtime", feature = "client"))]
pub use key_backup_client::{
    KeyBackupClient, KeyBackupDeleteResBody, KeyBackupListResBody, KeyBackupPutResBody,
};
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub use key_verification::{
    KeyVerificationAccept, KeyVerificationCancel, KeyVerificationDone, KeyVerificationFlow,
    KeyVerificationKey, KeyVerificationMac, KeyVerificationStart, KeyVerificationState,
};
#[cfg(feature = "full-surface")]
pub use media::{
    Attachment, AuthenticatedDownloadGrant, DownloadGrantScope, EncryptedAttachment, MediaMetadata,
    MemoryBlobStore, Thumbnail, safe_content_disposition, safe_content_type,
};
#[cfg(feature = "full-surface")]
pub use membership::{
    Invite, Member, MemberChange, MemberProfile, MemberRole, MembershipManager, MembershipState,
    ThirdPartyInvite, is_legal_membership_transition,
};
#[cfg(all(feature = "full-surface", feature = "mls"))]
pub use mls::*;
#[cfg(feature = "full-surface")]
pub use notifications::{
    NotificationAction, NotificationCounts, NotificationItem, NotificationManager, NotificationRule,
};
#[cfg(feature = "full-surface")]
pub use platform::{
    FfiCallbackAction, FfiCallbackResult, FfiCancellationHandle, FfiError, FfiErrorCode, FfiEvent,
    FfiEventSink, FfiHandle, FfiHandleKind, IndexedDbStoreDescriptor, IndexedDbStoreKind,
    WasmBrowserHttpTransport, WasmHttpReqBody, WasmHttpResBody, WasmRuntimeContract,
    WebCryptoKeyHandle, WebCryptoOperation,
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
    PushGateway, PushPayload, PushPlatform, PushPriority, PushPrivacyPolicy, PushRule, PushToken,
};
#[cfg(feature = "full-surface")]
pub use receipts::{
    ReadMarker, ReadReceipt, ReadReceiptDisclosure, ReadReceiptPolicy, ReadReceiptPreferences,
    ReadReceiptVisibility, ReceiptDecision, ReceiptManager, ReceiptVisibility, ScopePref,
    should_send_receipt,
};
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
    EndpointHandler, ProtocolFixtureFlow, ProtocolFixtureReport, ProtocolFixtureStep,
    ProtocolGoldenVector, ProtocolServerFixture, ServerReqBody, ServerResBody,
    WireConformanceVector, protocol_golden_vectors, reject_query_auth, wire_negative_vectors,
};
#[cfg(feature = "full-surface")]
pub use settings::{
    ClientSettings, NotificationPreferences, PrivacySettings, SettingsManager, ThemeSetting,
};
#[cfg(feature = "full-surface")]
pub use space::{
    BatchCreateMorph, BatchUpdateMorph, GraphTraversal, MorphAggregation, MorphQuery, MorphVersion,
    MorphVersionDiff, RelationOperationInput, Space,
};
#[cfg(feature = "full-surface")]
pub use store::{
    AccountSessionStore, AuditLogStore, BlobMetadataStore, EventCacheStore, MemoryPersistenceStore,
    StateSnapshotStore, StoreCache, StoreEncryptionKey, StoredAccountData,
    rebuild_space_state_from_events, restore_space_state_from_persistence,
};
#[cfg(all(feature = "full-surface", feature = "sync-runtime"))]
pub use sync_client::{
    AsyncSyncTransport, BackoffConfig, BackpressureConfig, BoxSyncFuture, CancellationToken,
    EventsQueryDirection, EventsQueryReqBody, EventsQueryResBody, EventsQuerySelector,
    EventsSubscribeFrame, EventsSubscribeTransport, ExponentialBackoff, LocalEcho, ProcessedSpace,
    SendQueue, SendQueueItem, SendQueueItemKind, SendQueueSnapshot, SendQueueStatus, SlidingSync,
    SlidingWindow, SpaceListChange, SpaceListEntry, SpaceListFilter, SpaceListService,
    SpaceListSnapshot, SpaceListSort, SyncGapStrategy, SyncLoop, SyncLoopControl, SyncLoopSnapshot,
    SyncLoopStep, SyncResponseProcessor, SyncTransport,
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
