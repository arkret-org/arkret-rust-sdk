//! Arkret v1 Rust SDK.
//!
//! This crate exposes Arkret protocol concepts directly. The source of truth
//! is signed Event Envelopes; Operations are SDK-local builders or offline
//! drafts that must be materialized as Events before network, sync, federation
//! or reducer use.
//!
//! # Examples
//!
//! Build a local operation draft and materialize it as an Event Envelope:
//!
//! ```rust
//! use arkret::{
//!     Did, Hlc, OP_MESSAGE_CREATE, OperationEnvelopeBuilder, OperationEventConversion,
//!     OperationId, OperationKindRegistry, RealmId,
//! };
//! use serde_json::json;
//!
//! # fn main() -> arkret::Result<()> {
//! let draft = OperationEnvelopeBuilder::new(
//!     OperationId::new("ak:operation:01904100-0000-7000-8000-57d7d85564c5")?,
//!     RealmId::new("ak:realm:01904100-0000-7000-8000-668e2181b41d")?,
//!     Did::new("did:webvh:z6mkfixture:alice.example")?,
//!     OP_MESSAGE_CREATE,
//!     1,
//!     Hlc::new("01970e589d21-0001-a13f9c2e")?,
//! )
//! .with_payload(json!({
//!     "strand_id": "ak:strand:01904100-0000-7000-8000-6c663fa0205f",
//!     "track_name": "main",
//!     "content": {"kind": "ak.content.text", "body": "hello"}
//! }))
//! .build(&OperationKindRegistry::default())?;
//! let event = draft.into_event_envelope(OperationEventConversion::default())?;
//! assert_eq!(event.payload["content"]["body"], "hello");
//! # Ok(())
//! # }
//! ```
//!
//! Run one in-memory sync-loop step with `sync-runtime` enabled:
//!
//! ```rust
//! # #[cfg(all(feature = "full-surface", feature = "sync-runtime"))]
//! # fn main() {
//! use arkret::{
//!     AccountSubscribeBatch, AccountSubscribeFrame, AccountSubscribeFrameKind, SyncLoop,
//!     SyncLoopStep, SyncRequestBody,
//! };
//!
//! let mut sync_loop = SyncLoop::new();
//! let mut transport = |_request: SyncRequestBody| {
//!     Ok(AccountSubscribeBatch {
//!         cursor: "s1".to_owned(),
//!         frames: vec![AccountSubscribeFrame {
//!             kind: AccountSubscribeFrameKind::Delta,
//!             cursor: Some("s1".to_owned()),
//!             realms: None,
//!             to_device: None,
//!             device_lists: None,
//!             account_data: None,
//!             presence: None,
//!             notifications: None,
//!             partial: None,
//!             priority: None,
//!             reconnect_after_ms: None,
//!         }],
//!     })
//! };
//! assert!(matches!(
//!     sync_loop.step(&mut transport),
//!     SyncLoopStep::Updates(_)
//! ));
//! # }
//! # #[cfg(not(all(feature = "full-surface", feature = "sync-runtime")))]
//! # fn main() {}
//! ```
//!
//! Invalid typed IDs should be constructed with validators, not assigned from
//! raw strings:
//!
//! ```compile_fail
//! let did: arkret::Did = "did:webvh:z6mkfixture:alice.example";
//! ```

// ---------------------------------------------------------------------------
// Compile-time feature-combination gates (SDK-FEAT-01).
//
// Today's Cargo feature graph already forces these implications at resolution
// time (`mls = ["full-surface", ...]`, `server = [..., "full-surface"]`,
// `salvo = ["server", ...]`, `*-runtime = ["full-surface"]`), so the guards
// below are unreachable. They exist as zero-cost regression armour: if a
// future Cargo.toml edit drops one of the implications, the build fails here
// instead of shipping a reviewed-unsafe feature combination. The runtime
// `feature_safety_report` in `crypto.rs` is NOT this gate — its scope is
// validating feature strings that downstream services self-report.
// ---------------------------------------------------------------------------
#[cfg(all(feature = "mls", not(feature = "full-surface")))]
compile_error!("feature `mls` requires `full-surface` (see crates/sdk/Cargo.toml feature graph)");
#[cfg(all(feature = "server", not(feature = "full-surface")))]
compile_error!(
    "feature `server` requires `full-surface` (see crates/sdk/Cargo.toml feature graph)"
);
#[cfg(all(feature = "salvo", not(feature = "server")))]
compile_error!("feature `salvo` requires `server` (see crates/sdk/Cargo.toml feature graph)");
#[cfg(all(
    any(
        feature = "applet-runtime",
        feature = "device-runtime",
        feature = "sync-runtime",
        feature = "timeline-runtime"
    ),
    not(feature = "full-surface")
))]
compile_error!(
    "runtime features (applet/device/sync/timeline) require `full-surface` \
     (see crates/sdk/Cargo.toml feature graph)"
);

// The pure KeyStore contract (trait + in-memory backend + error type) lives
// in `arkret-core`; the OS-native backends and the platform-default
// constructor now live in the dedicated `arkret-keystore` crate.
pub use arkret_core::{
    InMemoryKeyStore, KeyRefObject, KeyStore, KeyStoreError, canonical, cursor, error, events,
    identifiers, integration, keystore, lattice, models, operations, ops, push_rule_core, schema,
    service, sync, *,
};
pub use arkret_ffi as ffi;
#[cfg(feature = "client")]
pub use arkret_http_client as http_client;
pub use arkret_keystore::{
    BackendKind, LinuxSecretServiceKeyStore, MacOsKeychainKeyStore, WindowsCredentialKeyStore,
    durable_platform_keystore, platform_default_keystore_with_kind,
};
#[cfg(feature = "server")]
pub use arkret_server as server;
pub use arkret_signatures as signatures;
#[cfg(feature = "signer")]
pub use arkret_signatures::Ed25519MoveSigner;
// Shared `did:webvh` inception builder + organization statement signer, surfaced
// at the SDK root so clients (sodmin / inkson) and servers (soland / coauth)
// reach one implementation: `arkret_sdk::webvh::prepare_inception`,
// `arkret_sdk::realm_organization_statement_sign`.
pub use arkret_signatures::{realm_organization, realm_organization_statement_sign, webvh};
pub use arkret_state::{snapshot, state, *};

// Platform-native KeyStore backends. The glob import above already
// re-exports these symbols, but listing them explicitly keeps them
// visible in `cargo doc` and signals the supported surface to
// downstream crates that depend only on `arkret` (not `arkret-core`).
#[cfg(feature = "full-surface")]
pub mod account;
pub mod account_data_crypto;
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
/// Canonical encrypted attachment codec (`ak.blob.stream_aead.v1` /
/// `ak.blob.whole_file_aead.v1`, `media-and-blob.md` §3.2/§3.3).
#[cfg(feature = "full-surface")]
pub mod blob_aead;
#[cfg(feature = "full-surface")]
pub mod consent;
#[cfg(feature = "full-surface")]
pub mod crypto;
#[cfg(feature = "full-surface")]
pub mod crypto_store;
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub mod devices;
#[cfg(feature = "full-surface")]
pub mod discovery;
#[cfg(feature = "full-surface")]
pub mod e2ee;
#[cfg(feature = "full-surface")]
pub mod federation;
pub mod fixtures;
#[cfg(feature = "full-surface")]
pub mod hlc;
pub use arkret_signatures::dpop;
// Realm Recovery Key (RRK) durable history sealing — provider-initiated
// `ak.realm_key.share` to offline recovery recipients (encryption-and-audit.md
// §2.10.8). Resolves the RRK HPKE public key from a recipient's DID Document
// and HPKE-seals retained per-epoch history secrets to it. Reuses
// `secret_share`'s HPKE seal primitive, so it carries the same feature gate.
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub mod history_recovery;
// RFC 9421 HTTP Message Signatures (Ed25519) + RFC 9530 Content-Digest.
// The single source of truth now lives in `arkret-signatures`; this re-export
// keeps the existing `arkret::http_signature::*` / `arkret_sdk::http_signature::*`
// call paths stable.
#[cfg(feature = "full-surface")]
pub use arkret_signatures::http_signature;
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
/// Lives at the SDK root so principal-server-style consumers (inkson,
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
// `lattice_registry` is intentionally NOT feature-gated: inkson Move
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
pub mod session_grant;
#[cfg(feature = "full-surface")]
pub mod settings;
#[cfg(feature = "full-surface")]
pub mod sframe;
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
    AgentPrincipal, AgentRun, AgentRunState, AgentToolAuditAction, AgentToolAuditEntry,
    DelegatedActor,
};
#[cfg(all(feature = "full-surface", feature = "applet-runtime"))]
pub use applet::{
    AccountabilityGrantPayload, AccountabilityGrantStatus, AccountabilityScope,
    AppletAcceptedSigningKeyEvidence, AppletBridgeErrorBuilder, AppletBridgeErrorClass,
    AppletBridgeErrorVisibility, AppletDelegatedEventAuthorization, AppletEpochEvidenceError,
    AppletNamespaceConflict, AppletNamespaceDomain, AppletNamespaceEntry, AppletPackage,
    AppletPortal, AppletRegistrationEpochEvidence, AppletServiceIntent, AppletServiceTransaction,
    AppletWireNamespaces, GhostActorProfileFields, GhostActorProfileRequest,
    GhostActorProvisionOutcome, GhostActorProvisionRequestBody, PortalMode, PortalRealmMapping,
    WebhookAuth, WireAppletRegistration, applet_did_document_digest,
    applet_signing_key_material_digest, namespace_pattern_matches,
    normalize_applet_signing_key_ref, sign_registration,
};
#[cfg(all(
    feature = "full-surface",
    feature = "applet-runtime",
    feature = "salvo"
))]
pub use arkret_server::applet_router;
#[cfg(feature = "server")]
pub use arkret_server::{
    APPLET_TRANSACTION_OPERATION_ID, IdempotencyClaim, IdempotencyDirection, IdempotencyIdentity,
    IdempotencyWindow,
};
#[cfg(all(feature = "full-surface", feature = "applet-runtime"))]
pub use arkret_server::{
    AppletHandler, AppletService, ServiceRoute, TransactionDispatch, service_routes,
};
#[cfg(feature = "full-surface")]
pub use auth::{
    ARKRET_DEVICE_SCOPE_PREFIX, AccountAuthState, AccountRecoveryMethod,
    AccountRecoveryRequestBody, AuthClaimKind, AuthManager, AuthRateLimitAction,
    AuthRateLimitContext, AuthRateLimitHook, AuthSession, AuthStateSnapshot, ClaimDisclosurePolicy,
    ClaimDisclosureRequirement, DidProofVerification, DidProofVerificationRequestBody,
    DidProofVerifier, DisclosureProofAdapterBoundary, DisclosureProofFormat,
    MemorySessionGrantOutbox, MfaChallenge, OidcAuthRequestBody, OidcCredential,
    OidcIssuerMetadata, OidcVerificationRequestBody, OidcVerifiedIdentity, OidcVerifier,
    PasskeyChallenge, PasskeyVerification, PasskeyVerificationRequestBody, PasskeyVerifier,
    PasswordHashAlgorithm, PasswordHashVerifier, PasswordUser, PasswordVerification,
    PasswordVerificationRequestBody, PersistedAuthSession, PresentationRequestBody,
    PresentationValidation, PresentedClaim, PrincipalSessionGrantNotification,
    PrincipalSessionGrantNotificationOutcome, PrincipalSessionGrantNotifier, RejectedClaim,
    RenewalCredentialMetadata, SessionGrant, SessionGrantConfirmation,
    SessionGrantNotificationKind, SessionGrantOutboxEntry, SessionGrantOutboxState,
    SessionGrantPayload, SessionGrantRecord, SessionGrantRetryPolicy, SessionGrantSigner,
    SessionGrantVerification, SessionGrantVerifier, SessionPrincipalBinding, SessionRevocation,
    WebAuthnPasskeyOutcome, arkret_device_scope, device_id_from_scope_token,
    issue_session_grant_with_signer, primary_device_id_from_scopes, validate_presentation,
    verify_presentation_with_adapter, verify_session_grant_with_verifier,
};
#[cfg(feature = "full-surface")]
pub use authz::{
    ApprovalMode, ApprovalStrandManager, AuthzContext, AuthzEngine, CapabilityFrontierValidation,
    CapabilityGrantBuilder, ClaimRequirement, Constraint, ConstraintDuration, ConstraintEffect,
    ConstraintEntry, EngineDecision, FieldScope, GrantProposal, GrantRateLimitScope,
    PolicyEvaluationRequest, PolicyEvaluationResult, PolicyModerationReport, PolicyServerEffect,
    ProposalApproval, ProposalStatus, ProtocolResourceSelector, ProtocolResourceSelectorKind,
    ProtocolResourceSelectorScope, Recurrence, Resource, ResourceSelector, ScopeLimitation,
    VerifiedClaim, apply_policy_response, capability_grants_from_realm_state,
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
    MAX_SEGMENT_COUNT, MAX_SEGMENT_SIZE, MIN_SEGMENT_SIZE, SCHEME_STREAM, SCHEME_WHOLE_FILE,
    StreamDecryptor, StreamEncryptParams, decrypt_stream, decrypt_whole_file, encrypt_stream,
    encrypt_whole_file,
};
#[cfg(feature = "full-surface")]
pub use crypto::{
    AEAD_ALGORITHM, AEAD_NONCE_AES_GCM_LEN, AEAD_NONCE_COUNTER_LEN, AEAD_NONCE_EXPORTER_LABEL,
    AEAD_NONCE_XCHACHA20_POLY1305_LEN, AEAD_PROFILE_AES_256_GCM, AEAD_PROFILE_XCHACHA20_POLY1305,
    AeadNonceContext, AeadNonceReplayTracker, EncryptedEnvelopeDigestReport, FeatureSafetyReport,
    REDACTED_SECRET, UnsafeFeatureCombination, aead_sender_nonce_context_bytes, compose_aead_nonce,
    current_feature_safety_report, derive_aead_sender_nonce_prefix,
    encrypted_envelope_digest_report, envelope_aad_digest, feature_safety_report,
    is_sensitive_log_key, json_aad_digest, redact_log_value, verify_aead_nonce_derivation,
    verify_aead_sender_nonce, verify_envelope_aad_digest,
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
    CrossSigningResetPayload, CrossSigningResetProof, CrossSigningResetReason, Device,
    DeviceChange, DeviceCrossSigningChainVerification, DeviceManager, DeviceMetadata,
    DeviceQuorumSignature, DeviceQuorumThreshold, DeviceTrustBinding, DeviceTrustChainOutcome,
    DeviceTrustState, DeviceVerificationChallenge, DeviceVerificationMessageKind,
    QrVerificationPayload, ToDeviceEnvelope, cross_signing_publish_cell_subject,
    device_verification_commitment, verify_device_cross_signing_chain,
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
    VerifyActorChallengeSignature, WellKnownArkretServer, content_digest_sha256,
    did_document_service_endpoint_matches, duplicate_transaction_quarantine,
    fork_quarantine_record, rfc9530_content_digest_sha256, verify_rfc9530_content_digest,
};
pub use fixtures::{
    CANONICAL_FIXTURE_DEFAULT_KIND, CanonicalFixtureBuilder, CanonicalFixtureSuite,
    CanonicalFixtureVector,
};
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub use history_recovery::{
    REASON_DURABILITY_RECOVERY_RECIPIENT_UNVERIFIED, RRK_SERVICE_DOMAIN, RRK_SERVICE_TYPE,
    RealmHistoryRecoveryKeyError, ResolvedRealmHistoryRecoveryKey,
    resolve_realm_history_recovery_key, rrk_key_scope, seal_history_secrets_to_recovery_recipient,
};
#[cfg(feature = "full-surface")]
pub use hlc::{
    EXPECTED_FUTURE_SKEW_MS, HARD_FUTURE_SKEW_MS, HlcComponents, HlcFutureDrift, HlcGenerator,
    compare_hlc, parse_hlc, time_until_hlc, validate_hlc_format, validate_hlc_future_drift,
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
#[cfg(feature = "full-surface")]
pub use identity::{
    CompositeDidResolver, DID_WEB_MAX_DOCUMENT_BYTES, DidDocument,
    DidDocumentVerificationMethodResolver, DidKeriResolver, DidKeyLogEntry, DidKeyLogOperation,
    DidKeyResolver, DidMigration, DidRegistryReceipt, DidResolver, DidVisibility,
    DidWebDocumentOutcome, DidWebResolver, ExternalHandleProof, HandleAttestation,
    HandleClaimChallenge, HandleProofProfile, IdentityManager, IdentityReceiptWitnessRole,
    InMemoryStaridRegistryAdapter, PairwiseDidBinding, PairwiseDidResolutionProof,
    PairwiseDidStore, ResolvedVerificationMethodKey, StaridControlProofRequestBody,
    StaridControlProofVerification, StaridRegistryAdapter, StaridRegistryRecord, VerifiedDidKeyLog,
    attach_did_key_log_controller_proof, event_proof_verification_context, handle_claim_proof,
    handle_dns_txt_name, handle_well_known_url, pairwise_resolution_proof,
    resolve_verification_method_key, resolve_verification_method_key_from_document,
    starid_control_proof, verification_method_did, verify_canonical_proof_with_did_resolver,
    verify_did_key_log, verify_event_proof_with_did_resolver,
    verify_event_proof_with_did_resolver_context,
};
#[cfg(feature = "full-surface")]
pub use identity_link::{IdentityLinkCache, VerifiedLinkCacheEntry};
#[cfg(all(
    feature = "full-surface",
    feature = "device-runtime",
    feature = "client"
))]
pub use key_backup_client::KeyBackupClient;
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub use key_verification::{
    KeyVerificationAccept, KeyVerificationCancel, KeyVerificationDone, KeyVerificationKey,
    KeyVerificationMac, KeyVerificationStart, KeyVerificationState, KeyVerificationStrand,
    compute_key_commitment,
};
#[cfg(feature = "full-surface")]
pub use media::{
    Attachment, AuthenticatedDownloadGrant, CallMediaTokenVerification, DownloadGrantScope,
    EncryptedAttachment, MediaBackendType, MediaMetadata, MediaServiceAnchors, MemoryBlobStore,
    Thumbnail, call_media_token_exchange, participant_binding_signing_input,
    safe_content_disposition, safe_content_type, validate_token_ttl,
    verify_call_media_token_outcome,
};
#[cfg(all(feature = "full-surface", feature = "client"))]
pub use media::{MediaClient, VerifiedCallMediaTokenExchange, VerifiedMediaIceConfig};
#[cfg(feature = "full-surface")]
pub use membership::{
    Invite, Member, MemberChange, MemberProfile, MemberRole, MembershipManager,
    MembershipPayloadState, ThirdPartyInvite, is_legal_membership_transition,
};
#[cfg(all(feature = "full-surface", feature = "mls"))]
pub use mls::*;
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
    CHIME_PUSH_REGISTRATION_VERSION, ChimePushRegistration, EncryptedPushPayload,
    PushEventNotification, PushGateway, PushPayload, PushPlatform, PushPriority, PushPrivacyPolicy,
    PushRule, PushToken,
};
#[cfg(feature = "full-surface")]
pub use realm::{
    BatchCreateMorph, BatchUpdateMorph, GraphTraversal, MorphAggregation, MorphQuery, MorphVersion,
    MorphVersionDiff, Realm, RelationOperationInput,
};
#[cfg(feature = "full-surface")]
pub use receipts::{
    ReadReceipt, ReadReceiptDisclosure, ReadReceiptPolicy, ReadReceiptPolicyChildViolation,
    ReadReceiptPreferences, ReadReceiptVisibility, ReceiptDecision, ReceiptManager, ScopePref,
    should_send_receipt,
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
    SecretShareRequestContent, SecretShareSendContent, open_base_mode_with_x25519_privkey,
    open_history_secret_with_device_privkey, seal_base_mode_to_x25519_pubkey,
    seal_history_secret_to_device_pubkey,
};
#[cfg(all(feature = "full-surface", feature = "server"))]
pub use server::{
    EndpointHandler, ProtocolFixtureReport, ProtocolFixtureStep, ProtocolFixtureStrand,
    ProtocolGoldenVector, ProtocolServerFixture, ServerOutcome, ServerRequestBody,
    WireConformanceVector, protocol_golden_vectors, reject_query_auth, wire_negative_vectors,
};
#[cfg(feature = "full-surface")]
pub use settings::{
    ClientSettings, NotificationPreferences, PrivacySettings, SettingsManager, ThemeSetting,
};
#[cfg(feature = "full-surface")]
pub use sframe::{
    FRAME_KEY_LABEL, FrameKeyContext, MEDIA_KEY_LEN, MlsExporterSource, RECORDING_KEY_LABEL,
    RecordingKeyContext, TRANSCRIPT_KEY_LABEL, TranscriptKeyContext, derive_frame_key,
    derive_recording_key, derive_transcript_key,
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
    EventsSubscribeTransport, ExponentialBackoff, LocalEcho, ProcessedRealm, RealmListChange,
    RealmListEntry, RealmListFilter, RealmListService, RealmListSnapshot, RealmListSort, SendQueue,
    SendQueueItem, SendQueueItemKind, SendQueueSnapshot, SendQueueStatus, SlidingSync,
    SlidingWindow, SyncGapStrategy, SyncLoop, SyncLoopControl, SyncLoopSnapshot, SyncLoopStep,
    SyncRecoveryAction, SyncResponseProcessor, SyncTransport,
};
#[cfg(all(feature = "full-surface", feature = "timeline-runtime"))]
pub use timeline::{
    CachedEvent, EventCache, EventCacheInsert, EventCacheUpdate, FocusedTimeline,
    TimelineDirection, TimelineEvent, TimelineFrom, TimelineGap, TimelineItem, TimelineItemKind,
    TimelineOptions, TimelineReactionSummary, TimelineReadReceipt, TimelineStore,
    TimelineTypingUpdate,
};
#[cfg(feature = "full-surface")]
pub use typing::{TypingManager, TypingNotification};
#[cfg(feature = "full-surface")]
pub use webrtc::{
    CallSessionDescription, IceCandidate, IceConfig, MediaStateData, MediaTrackSet,
    ModeratePayload, ModerationAction, MuteSource, MuteStateData, RecordingCaptureKind,
    RecordingMode, RecordingResult, RecordingStartPayload, RecordingState, RenegotiateData,
    RenegotiateReason, ScreenShareState, SdpType, SpeakingData, TranscribePayload,
    WebRtcSignalKind, WebRtcSignalMessage, verify_ice_config_outcome,
};
