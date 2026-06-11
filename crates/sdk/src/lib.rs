//! Cokret v1 Rust SDK.
//!
//! This crate exposes Cokret protocol concepts directly. The source of truth
//! is signed Event Envelopes; Operations are SDK-local builders or offline
//! drafts that must be materialized as Events before network, sync, federation
//! or reducer use.
//!
//! # Examples
//!
//! Build a local operation draft and materialize it as an Event Envelope:
//!
//! ```rust
//! use cokret::{
//!     Did, Hlc, OP_MESSAGE_CREATE, OperationEnvelopeBuilder, OperationEventConversion,
//!     OperationId, OperationKindRegistry, RealmId,
//! };
//! use serde_json::json;
//!
//! # fn main() -> cokret::Result<()> {
//! let draft = OperationEnvelopeBuilder::new(
//!     OperationId::new("ck:operation:01904100-0000-7000-8000-57d7d85564c5")?,
//!     RealmId::new("ck:realm:01904100-0000-7000-8000-668e2181b41d")?,
//!     Did::new("did:web:alice.example")?,
//!     OP_MESSAGE_CREATE,
//!     1,
//!     Hlc::new("01970e589d21-0001-a13f9c2e")?,
//! )
//! .with_content(json!({
//!     "flow_id": "ck:flow:01904100-0000-7000-8000-6c663fa0205f",
//!     "track_name": "main",
//!     "content": {"kind": "ck.content.text", "body": "hello"}
//! }))
//! .build(&OperationKindRegistry::default())?;
//! let event = draft.into_event_envelope(OperationEventConversion::default())?;
//! assert_eq!(event.content["content"]["body"], "hello");
//! # Ok(())
//! # }
//! ```
//!
//! Run one in-memory sync-loop step:
//!
//! ```rust
//! use cokret::{SyncLoop, SyncLoopStep, SyncOutcome, SyncRequestBody};
//!
//! # fn main() {
//! let mut sync_loop = SyncLoop::new();
//! let mut transport = |_request: SyncRequestBody| {
//!     Ok(SyncOutcome {
//!         cursor: "s1".to_owned(),
//!         realms: Default::default(),
//!         left_realms: Vec::new(),
//!         to_device: Vec::new(),
//!         device_lists: Default::default(),
//!         presence: Vec::new(),
//!         account_data: Vec::new(),
//!         notifications: serde_json::Value::Null,
//!         partial: false,
//!     })
//! };
//! assert!(matches!(
//!     sync_loop.step(&mut transport),
//!     SyncLoopStep::Updates(_)
//! ));
//! # }
//! ```
//!
//! Invalid typed IDs should be constructed with validators, not assigned from
//! raw strings:
//!
//! ```compile_fail
//! let did: cokret::Did = "did:web:alice.example";
//! ```

pub use cokret_contracts as api;
pub use cokret_contracts::product::client as client_api;
pub use cokret_contracts::{
    federation as federation_api, identity as identity_api, integration as integration_api,
    principal as principal_api, push as push_gateway_api,
};
// The pure KeyStore contract (trait + in-memory backend + error type) lives
// in `cokret-core`; the OS-native backends and the platform-default
// constructor now live in the dedicated `cokret-keystore` crate.
pub use cokret_core::{InMemoryKeyStore, KeyRefObject, KeyStore, KeyStoreError};
pub use cokret_core::{
    canonical, cursor, error, events, identifiers, keystore, lattice, model, operations,
    push_rule_core, schema, schema as schema_contracts, service, state, state as state_res, sync,
    *,
};
pub use cokret_crypto as crypto_protocol;
pub use cokret_ffi as ffi;
pub use cokret_html as html;
#[cfg(feature = "client")]
pub use cokret_http_client as http_client;
pub use cokret_keystore::{
    LinuxSecretServiceKeyStore, MacOsKeychainKeyStore, WindowsCredentialKeyStore,
    platform_default_keystore,
};
#[cfg(feature = "server")]
pub use cokret_server as server;
pub use cokret_signatures as signatures;
#[cfg(feature = "signer")]
pub use cokret_signatures::Ed25519MoveSigner;
#[cfg(feature = "testing")]
pub use cokret_testing as testing;

// Platform-native KeyStore backends. The glob import above already
// re-exports these symbols, but listing them explicitly keeps them
// visible in `cargo doc` and signals the supported surface to
// downstream crates that depend only on `cokret` (not `cokret-core`).
#[cfg(feature = "full-surface")]
pub use crate::store as store_contracts;
#[cfg(feature = "full-surface")]
pub mod account;
#[cfg(feature = "full-surface")]
pub mod agent;
#[cfg(feature = "full-surface")]
pub mod agent_binding;
#[cfg(feature = "full-surface")]
#[cfg(all(feature = "full-surface", feature = "applet-runtime"))]
pub mod applet;
// S-8 (savfox SDK gap): salvo Router factory for the 6 Applet
// endpoints. Trait surface is always compiled (under `applet-runtime`)
// so callers can implement it without pulling salvo; the actual
// Router factory only links when the `salvo` feature is on.
#[cfg(all(feature = "full-surface", feature = "applet-runtime"))]
pub mod applet_server;
#[cfg(feature = "full-surface")]
pub mod auth;
#[cfg(feature = "full-surface")]
pub mod authz;
#[cfg(feature = "full-surface")]
pub mod base;
/// Canonical encrypted attachment codec (`ck.blob.stream_aead.v1` /
/// `ck.blob.whole_file_aead.v1`, `media-and-blob.md` §3.2/§3.3).
#[cfg(feature = "full-surface")]
pub mod blob_aead;
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
// S-5 (savfox SDK gap): `(source_service_did, Idempotency-Key)`
// deduplication window. Open to all profiles — Applets, gateways,
// any inbound handler can use it without dragging in `full-surface`.
pub mod idempotency;
// RFC 9421 HTTP Message Signatures (Ed25519) + RFC 9530 Content-Digest.
// 报告 03 #5 / 09 #2 收敛:唯一真源实现已下沉到 `cokret-signatures`;此处
// re-export 保持 `cokret::http_signature::*` / `cokret_sdk::http_signature::*`
// 调用路径不变(floria / teabay / chime 仍直接消费这一套)。
#[cfg(feature = "full-surface")]
pub use cokret_signatures::http_signature;
// HttpDidResolver leans on a live Tokio runtime, blocking off-thread
// scheduling, and reqwest's native ClientBuilder transport knobs — none
// of which are available on the wasm32 fetch backend. Gate the module out
// on wasm32; web embedders should plug in a fetch-based resolver via
// the `DidResolver` trait directly.
#[cfg(all(
    feature = "full-surface",
    feature = "client",
    not(target_arch = "wasm32")
))]
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
#[cfg(all(
    feature = "full-surface",
    feature = "device-runtime",
    feature = "client"
))]
pub mod key_backup_client;
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub mod key_verification;
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub mod secret_share;
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
pub mod realm;
#[cfg(feature = "full-surface")]
pub mod receipts;
#[cfg(feature = "full-surface")]
pub mod resolver;
#[cfg(feature = "full-surface")]
pub mod search;
#[cfg(feature = "full-surface")]
pub mod settings;
#[cfg(feature = "full-surface")]
pub mod snapshot_v1;
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
pub use account::{
    ACCOUNT_DATA_BLOCKLIST, AccountBlocklist, AccountBlocklistPayload,
    AccountBlocklistPayloadEntry, AccountDataManager, AccountDataSetPayload, BlocklistEntry,
};
#[cfg(feature = "full-surface")]
pub use agent::{
    AgentBridgeMetadata, AgentPrincipal, AgentProtocol, AgentProtocolEndpoint,
    AgentProtocolMessage, AgentRun, AgentRunState, AgentToolAuditAction, AgentToolAuditEntry,
    DelegatedActor, ExternalAgent,
};
#[cfg(all(feature = "full-surface", feature = "applet-runtime"))]
pub use applet::{
    AccountabilityGrantPayload, AccountabilityGrantStatus, AccountabilityScope, ActorPolicy,
    AppletBridgeErrorBuilder, AppletBridgeErrorVisibility, AppletDelegatedEventAuthorization,
    AppletNamespaceConflict, AppletNamespaceDomain, AppletNamespaceEntry, AppletPackage,
    AppletPortal, AppletServiceIntent, AppletServiceTransaction, AppletWireNamespaces,
    ApprovalRequest, ApprovedScope, EffectiveScope, GhostActorProfileFields,
    GhostActorProfileRequest, GhostActorProvisionOutcome, GhostActorProvisionRequestBody,
    InstallCommitOutcome, InstallCommitRequestBody, InstallE2eePolicy, InstallPlan,
    InstallPreviewRequestBody, InstallRevokeRequestBody, PortalMode, PortalRealmMapping,
    RemoteRealmMapping, RemoteUserMapping, ThirdPartyLookupKind, ThirdPartyLookupOutcome,
    ThirdPartyLookupRequestBody, VirtualActor, WebhookAuth, WidgetPolicy, WireAppletRegistration,
    namespace_pattern_matches, sign_registration,
};
#[cfg(all(
    feature = "full-surface",
    feature = "applet-runtime",
    feature = "salvo"
))]
pub use applet_server::router as applet_router;
#[cfg(all(feature = "full-surface", feature = "applet-runtime"))]
pub use applet_server::{AppletHandler, AppletService};
#[cfg(feature = "full-surface")]
pub use auth::{
    AccountAuthState, AccountRecoveryMethod, AccountRecoveryRequestBody, AuthClaimKind,
    AuthManager, AuthRateLimitAction, AuthRateLimitContext, AuthRateLimitHook, AuthSession,
    AuthStateSnapshot, COKRET_DEVICE_SCOPE_PREFIX, ClaimDisclosurePolicy,
    ClaimDisclosureRequirement, DidProofVerification, DidProofVerificationRequestBody,
    DidProofVerifier, DisclosureProofAdapterBoundary, DisclosureProofFormat,
    MemorySessionGrantOutbox, MfaChallenge, OidcAuthRequestBody, OidcCredential,
    OidcIssuerMetadata, OidcJwks, OidcVerificationRequestBody, OidcVerifiedIdentity, OidcVerifier,
    PasskeyChallenge, PasskeyVerification, PasskeyVerificationRequestBody, PasskeyVerifier,
    PasswordHashAlgorithm, PasswordHashVerifier, PasswordUser, PasswordVerification,
    PasswordVerificationRequestBody, PersistedAuthSession, PresentationRequestBody,
    PresentationValidation, PresentedClaim, PrincipalSessionGrantNotification,
    PrincipalSessionGrantNotificationOutcome, PrincipalSessionGrantNotifier, RefreshTokenMetadata,
    RejectedClaim, SessionGrant, SessionGrantNotificationKind, SessionGrantOutboxEntry,
    SessionGrantOutboxState, SessionGrantPayload, SessionGrantRecord, SessionGrantRetryPolicy,
    SessionGrantSigner, SessionGrantVerification, SessionGrantVerifier, SessionPrincipalBinding,
    SessionRevocation, WebAuthnPasskeyOutcome, cokret_device_scope, device_id_from_scope_token,
    issue_session_grant_with_signer, primary_device_id_from_scopes, validate_presentation,
    verify_presentation_with_adapter, verify_session_grant_with_verifier,
};
#[cfg(feature = "full-surface")]
pub use authz::{
    ApprovalFlowManager, ApprovalMode, AuthzContext, AuthzEngine, CapabilityFrontierValidation,
    CapabilityGrant, CapabilityGrantBuilder, ClaimRequirement, Constraint, ConstraintDuration,
    ConstraintEffect, ConstraintEntry, EngineDecision, FieldScope, GrantProposal, ModerationReport,
    PolicyEvaluationRequest, PolicyEvaluationResult, PolicyServerEffect, ProposalApproval,
    ProposalStatus, ProtocolGrantApprovalRelation, ProtocolGrantClaimRequirement,
    ProtocolGrantConstraint, ProtocolGrantConstraintEffect, ProtocolGrantConstraintTrack,
    ProtocolGrantConstraintType, ProtocolResourceSelector, ProtocolResourceSelectorKind,
    ProtocolResourceSelectorScope, RateLimitScope, Recurrence, Resource, ResourceSelector,
    ScopeLimitation, VerifiedClaim, apply_policy_response, capability_grants_from_realm_state,
    grant_requires_approval, moderation_report_for_policy_outcome,
    reject_unknown_critical_constraints, validate_capability_frontier,
};
#[cfg(feature = "full-surface")]
pub use base::{
    BaseClient, BootstrapSequence, BootstrapStep, BootstrapStepKind, BootstrapStepStatus,
    ClientRealm, RealmMembershipState, SessionMeta, SessionRestore,
};
#[cfg(feature = "full-surface")]
pub use blob_aead::{
    ALG_STREAM_XCHACHA, ALG_WHOLE_FILE_XCHACHA, DEFAULT_SEGMENT_SIZE, EncryptedAttachmentEnvelope,
    SCHEME_STREAM, SCHEME_WHOLE_FILE, StreamDecryptor, StreamEncryptParams, decrypt_stream,
    decrypt_whole_file, encrypt_stream, encrypt_whole_file,
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
    DeviceManager, DeviceMetadata, DeviceQuorumSignature, DeviceTrustBinding,
    DeviceTrustChainOutcome, DeviceVerificationChallenge, DeviceVerificationMessageContent,
    DeviceVerificationMessageKind, KeyBackupClass, KeyBackupContentItem, KeyBackupEncryption,
    ProtocolDeviceMessageEnvelope, ProtocolKeyBackup, QrVerificationPayload, SignedCrossSigningKey,
    ToDeviceEnvelope, cross_signing_publish_cell_subject, device_verification_commitment,
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
    FederationReplayStore, FederationTransactionEnvelope, HttpMessageSignature, ServerInfo,
    ServiceEndpointDescriptor, SovereignDeployment, VerifyActorChallenge,
    VerifyActorChallengeSignature, WellKnownCokretServer, content_digest_sha256,
    did_document_service_endpoint_matches, duplicate_transaction_quarantine,
    fork_quarantine_record, rfc9530_content_digest_sha256, verify_rfc9530_content_digest,
};
#[cfg(feature = "full-surface")]
pub use hlc::{
    HlcComponents, HlcGenerator, compare_hlc, is_clock_skew_acceptable, parse_hlc, time_until_hlc,
    validate_hlc_format,
};
#[cfg(feature = "client")]
pub use http_client::{Auth, Client, ClientBuilder, ClientRequestOptions, RetryConfig};
#[cfg(all(
    feature = "full-surface",
    feature = "client",
    not(target_arch = "wasm32")
))]
pub use http_did_resolver::{
    DEFAULT_HTTP_DID_RESOLVER_TIMEOUT_MS, DEFAULT_HTTP_DID_RESOLVER_TTL_SECS, HttpDidResolver,
};
pub use idempotency::{IdempotencyDecision, IdempotencyWindow};
#[cfg(feature = "full-surface")]
pub use identity::{
    CompositeDidResolver, DID_WEB_MAX_DOCUMENT_BYTES, DidDocument,
    DidDocumentVerificationMethodResolver, DidKeriResolver, DidKeyLogEntry, DidKeyLogOperation,
    DidKeyResolver, DidMigration, DidRegistryReceipt, DidResolver, DidVisibility,
    DidWebDocumentOutcome, DidWebResolver, ExternalHandleProof, HandleAttestation, HandleClaim,
    HandleProofProfile, IdentityManager, IdentityReceiptWitnessRole, InMemoryStaridRegistryAdapter,
    PairwiseDidBinding, PairwiseDidResolutionProof, PairwiseDidStore,
    ResolvedVerificationMethodKey, StaridControlProofRequestBody, StaridControlProofVerification,
    StaridRegistryAdapter, StaridRegistryRecord, VerifiedDidKeyLog, handle_claim_proof,
    handle_dns_txt_name, handle_well_known_url, pairwise_resolution_proof,
    resolve_verification_method_key, resolve_verification_method_key_from_document,
    starid_control_proof, verification_method_did, verify_canonical_proof_with_did_resolver,
    verify_did_key_log, verify_event_proof_with_did_resolver,
};
#[cfg(feature = "full-surface")]
pub use identity_link::{IdentityLinkCache, IdentityLinkCacheEntry};
#[cfg(all(
    feature = "full-surface",
    feature = "device-runtime",
    feature = "client"
))]
pub use key_backup_client::{
    KeyBackupClient, KeyBackupListOutcome, KeysBackupsDeleteOutcome, KeysBackupsPutOutcome,
};
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub use key_verification::{
    KeyVerificationAccept, KeyVerificationCancel, KeyVerificationDone, KeyVerificationFlow,
    KeyVerificationKey, KeyVerificationMac, KeyVerificationStart, KeyVerificationState,
    compute_key_commitment,
};
#[cfg(feature = "full-surface")]
pub use media::{
    Attachment, AuthenticatedDownloadGrant, DownloadGrantScope, EncryptedAttachment,
    MediaBackendType, MediaMetadata, MemoryBlobStore, Thumbnail, call_media_token_exchange,
    safe_content_disposition, safe_content_type, validate_token_ttl,
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
    WasmBrowserHttpTransport, WasmHttpRequestBody, WasmHttpResponseBody, WasmRuntimeContract,
    WebCryptoKeyHandle, WebCryptoOperation,
};
#[cfg(feature = "full-surface")]
pub use presence::{Presence, PresenceManager};
#[cfg(feature = "full-surface")]
pub use profile::{
    DataClassification, ExternalDeviceApprovalMode, PairwiseControlMessage,
    PairwiseControlMessageKind, ProfileCreateBuilder, ProfileEventKind, ProfileManager,
    RealmExportManifest, RealmImportValidation, ServiceReplacementPlan, SovereignDeploymentPolicy,
    TspTrustBinding, UserProfile, validate_realm_import,
};
#[cfg(feature = "full-surface")]
pub use push::{
    CHIME_PUSH_REGISTRATION_VERSION, ChimePushRegistration, EncryptedPushPayload, PushEvent,
    PushGateway, PushPayload, PushPlatform, PushPriority, PushPrivacyPolicy, PushRule, PushToken,
};
#[cfg(feature = "full-surface")]
pub use realm::{
    BatchCreateMorph, BatchUpdateMorph, GraphTraversal, MorphAggregation, MorphQuery, MorphVersion,
    MorphVersionDiff, Realm, RelationOperationInput,
};
#[cfg(feature = "full-surface")]
pub use receipts::{
    ReadMarker, ReadReceipt, ReadReceiptDisclosure, ReadReceiptPolicy, ReadReceiptPreferences,
    ReadReceiptVisibility, ReceiptDecision, ReceiptManager, ScopePref, should_send_receipt,
};
#[cfg(feature = "full-surface")]
pub use resolver::{
    REDUCER_SNAPSHOT_PROFILE, REDUCER_SNAPSHOT_SCHEMA, RealmState, ReducerSnapshotManifest,
    SnapshotChunkManifest, SnapshotRestore, SnapshotRestoreSource, SnapshotSignature,
    SnapshotSignatureBindingPayload, StateSnapshot, merkle_root, state_merkle_root,
    verify_snapshot_chunks,
};
#[cfg(feature = "full-surface")]
pub use search::{RealmSearchEntry, RealmSearchIndex, RealmSearchQuery};
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub use secret_share::{
    HPKE_SECRET_SHARE_SCHEME, SECRET_ID_MLS_ACCOUNT, SECRET_REQUEST_KIND, SECRET_SEND_KIND,
    SecretShareRequestContent, SecretShareSendContent,
};
#[cfg(all(feature = "full-surface", feature = "server"))]
pub use server::{
    EndpointHandler, ProtocolFixtureFlow, ProtocolFixtureReport, ProtocolFixtureStep,
    ProtocolGoldenVector, ProtocolServerFixture, ServerOutcome, ServerRequestBody,
    WireConformanceVector, protocol_golden_vectors, reject_query_auth, wire_negative_vectors,
};
#[cfg(feature = "full-surface")]
pub use settings::{
    ClientSettings, NotificationPreferences, PrivacySettings, SettingsManager, ThemeSetting,
};
#[cfg(feature = "full-surface")]
pub use snapshot_v1::{
    sign_snapshot_manifest_ed25519, verify_snapshot_manifest as verify_snapshot_manifest_v1,
    verify_snapshot_manifest_signature,
};
#[cfg(feature = "full-surface")]
pub use store::{
    AccountSessionStore, AuditLogStore, BlobMetadataStore, EventCacheStore, MemoryPersistenceStore,
    StateSnapshotStore, StoreCache, StoreEncryptionKey, StoredAccountData,
    rebuild_realm_state_from_events, restore_realm_state_from_persistence,
};
#[cfg(all(feature = "full-surface", feature = "sync-runtime"))]
pub use sync_client::{
    AsyncSyncTransport, BackoffConfig, BackpressureConfig, BoxSyncFuture, CancellationToken,
    EventsQueryOrder, EventsQueryOutcome, EventsQueryRequestBody, EventsQuerySelector,
    EventsSubscribeFrame, EventsSubscribeTransport, ExponentialBackoff, LocalEcho, ProcessedRealm,
    RealmListChange, RealmListEntry, RealmListFilter, RealmListService, RealmListSnapshot,
    RealmListSort, SendQueue, SendQueueItem, SendQueueItemKind, SendQueueSnapshot, SendQueueStatus,
    SlidingSync, SlidingWindow, SyncGapStrategy, SyncLoop, SyncLoopControl, SyncLoopSnapshot,
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
    CallSessionDescription, CallState, ConferenceMode, ConferenceSession, IceCandidate, IceServer,
    IceServerKind, MediaTrack, MediaTrackKind, SdpType, WebRtcCall, WebRtcManager,
    WebRtcSignalKind, WebRtcSignalMessage,
};
