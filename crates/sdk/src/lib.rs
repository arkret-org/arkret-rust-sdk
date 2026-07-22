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
//!     Did, Hlc, OperationEnvelopeBuilder, OperationEventConversion, OperationId,
//!     EventDraftKindRegistry, RealmId, events::EventKind,
//! };
//! use serde_json::json;
//!
//! # fn main() -> arkret::Result<()> {
//! let draft = OperationEnvelopeBuilder::new(
//!     OperationId::new("ak:operation:01904100-0000-7000-8000-57d7d85564c5")?,
//!     RealmId::new("ak:realm:01904100-0000-7000-8000-668e2181b41d")?,
//!     Did::new("did:webvh:z6mkfixture:alice.example")?,
//!     EventKind::MESSAGE_CREATE,
//!     1,
//!     Hlc::new("01970e589d21-0001-a13f9c2e")?,
//! )
//! .with_payload(json!({
//!     "strand_id": "ak:strand:01904100-0000-7000-8000-6c663fa0205f",
//!     "track_name": "main",
//!     "content": {"kind": "ak.content.text", "body": "hello"}
//! }))
//! .build(&EventDraftKindRegistry::default())?;
//! let event = draft.into_event_envelope(OperationEventConversion::default())?;
//! assert_eq!(event.payload["content"]["body"], "hello");
//! # Ok(())
//! # }
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
    any(feature = "applet-runtime", feature = "device-runtime"),
    not(feature = "full-surface")
))]
compile_error!(
    "runtime features (applet/device) require `full-surface` \
     (see crates/sdk/Cargo.toml feature graph)"
);

mod sdk_error;
// The pure KeyStore contract (trait + in-memory backend + error type) lives
// in `arkret-core`; the OS-native backends and the platform-default
// constructor now live in the dedicated `arkret-keystore` crate.
pub use arkret_core::{
    InMemoryKeyStore, KeyRefObject, KeyStore, KeyStoreError, canonical, cursor, error, events,
    identifiers, integration, keystore, lattice, models, operations, ops, push_rule_core, schema,
    service, sync, *,
};
pub use arkret_crypto::identity_root;
pub use arkret_egress_policy as network_policy;
#[cfg(feature = "client")]
pub use arkret_http_client as http_client;
#[cfg(feature = "keystore-encrypted-file")]
pub use arkret_keystore::EncryptedFileKeyStore;
pub use arkret_keystore::{
    BackendKind, LinuxSecretServiceKeyStore, MacOsKeychainKeyStore, WindowsCredentialKeyStore,
    durable_platform_keystore, platform_default_keystore_with_kind,
};
pub use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeBatch, AccountSubscribeReconnectAfter, AccountSubscribeSnapshotResult,
    DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS, MAX_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS,
};
#[cfg(feature = "server")]
pub use arkret_server as server;
pub use arkret_signatures as signatures;
#[cfg(feature = "signer")]
pub use arkret_signatures::Ed25519MoveSigner;
// Shared `did:webvh` inception builder + organization statement signer, surfaced
// at the SDK root so clients (sodmin / inkson) and servers (soland / coauth)
// reach one implementation: `arkret_sdk::webvh::prepare_principal_inception`,
// `arkret_sdk::realm_organization_statement_sign`.
pub use arkret_signatures::{
    realm_organization, realm_organization_statement_sign, service_identity, webvh,
};
pub use arkret_state::{snapshot, state, *};
pub use arkret_wire::{
    QUERY_AUTH_PARAMETER_NAMES, contains_query_auth_material, is_query_auth_parameter,
};
pub use sdk_error::{Error, Result};

// Platform-native KeyStore backends. The glob import above already
// re-exports these symbols, but listing them explicitly keeps them
// visible in `cargo doc` and signals the supported surface to
// downstream crates that depend only on `arkret` (not `arkret-core`).
pub mod account_data_crypto;
#[cfg(feature = "full-surface")]
pub mod agent;
#[cfg(all(feature = "full-surface", feature = "applet-runtime"))]
pub mod applet;
#[cfg(feature = "full-surface")]
pub mod auth;
#[cfg(feature = "full-surface")]
pub mod authz;
/// Canonical encrypted attachment codec (`ak.blob.stream_aead.v1` /
/// `ak.blob.whole_file_aead.v1`, `media-and-blob.md` §3.2/§3.3).
#[cfg(feature = "full-surface")]
pub mod blob_aead;
#[cfg(feature = "full-surface")]
pub mod consent;
#[cfg(feature = "full-surface")]
pub mod crypto;
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub mod devices;
#[cfg(feature = "full-surface")]
#[cfg(feature = "full-surface")]
pub mod e2ee;
#[cfg(feature = "full-surface")]
pub mod federation;
pub mod fixtures;
pub use arkret_core::hlc;
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
// HttpDidResolver leans on a live Tokio runtime, blocking off-thread
// scheduling, and reqwest's native ClientBuilder transport knobs — none
// of which are available on the wasm32 fetch backend. It now lives in
// arkret-http-client; this shim keeps the `arkret::http_did_resolver::*`
// path stable. Gated out on wasm32; web embedders should plug in a
// fetch-based resolver via the `DidResolver` trait directly.
#[cfg(all(
    feature = "full-surface",
    feature = "client",
    not(target_arch = "wasm32")
))]
pub use arkret_http_client::http_did_resolver;
#[cfg(feature = "full-surface")]
pub use arkret_signatures::http_signature;
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
// `key_backup_client` now lives in arkret-http-client; this shim keeps the
// `arkret::key_backup_client::*` path stable.
#[cfg(all(
    feature = "full-surface",
    feature = "device-runtime",
    feature = "client"
))]
pub use arkret_http_client::key_backup_client;
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub mod key_verification;
// `secret_share` moved to `arkret-crypto` (HPKE base-mode seal). Re-exported
// here to keep the `arkret::secret_share::*` / `crate::secret_share::*` paths
// stable for `history_recovery` and the `mls` tests.
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub use arkret_crypto::secret_share;
// `lattice_registry` is intentionally NOT feature-gated: inkson Move
// pre-check + cotest fixtures need the spec-normative cell-family
// registry independently of the higher-level full-surface client
// runtime.
pub use arkret_lattice_registry as lattice_registry;
#[cfg(feature = "full-surface")]
pub mod media;
#[cfg(feature = "full-surface")]
pub mod membership;
// The MLS (RFC 9420) behavior layer lives in the standalone `arkret-mls` crate
// (the sole OpenMLS boundary). Keep the `arkret::mls::*` path stable by
// re-exporting it here under the same feature gate it always carried.
#[cfg(all(feature = "full-surface", feature = "mls"))]
pub mod mls {
    pub use arkret_mls::*;
}
#[cfg(feature = "full-surface")]
pub mod mls_move;
#[cfg(feature = "full-surface")]
pub mod push;
#[cfg(feature = "full-surface")]
// State resolution + snapshot runtime now lives in `arkret-state`. This shim
// keeps the historical `arkret::resolver::*` / `arkret_sdk::resolver::*` paths
// stable for downstream consumers.
#[cfg(feature = "full-surface")]
pub mod resolver {
    pub use arkret_state::resolver::*;
}
#[cfg(feature = "full-surface")]
#[cfg(feature = "full-surface")]
pub mod session_grant;
#[cfg(feature = "full-surface")]
#[cfg(feature = "full-surface")]
pub mod sframe;
#[cfg(feature = "full-surface")]
pub mod snapshot_v1;
#[cfg(feature = "full-surface")]
pub mod webrtc;
#[cfg(feature = "full-surface")]
#[cfg(feature = "full-surface")]
#[cfg(feature = "full-surface")]
pub use agent::{
    AgentPrincipal, AgentRun, AgentRunState, AgentToolAuditAction, AgentToolAuditEntry,
    DelegatedActor,
};
#[cfg(all(feature = "full-surface", feature = "applet-runtime"))]
pub use applet::{
    AccountabilityGrantPayload, AccountabilityGrantStatus, AccountabilityScope,
    AccountabilityScopeKind, AppletAcceptedSigningKeyEvidence, AppletBridgeErrorBuilder,
    AppletBridgeErrorClass, AppletBridgeErrorVisibility, AppletDelegatedEventAuthorization,
    AppletEpochEvidenceError, AppletNamespaceConflict, AppletNamespaceDomain, AppletNamespaceEntry,
    AppletPackage, AppletPortal, AppletRegistrationEpochEvidence, AppletServiceIntent,
    AppletServiceTransaction, AppletWireNamespaces, GhostActorProfileFields,
    GhostActorProfileRequest, GhostActorProvisionOutcome, GhostActorProvisionRequestBody,
    PortalMode, PortalRealmMapping, WebhookAuth, WireAppletRegistration,
    applet_did_document_digest, applet_signing_key_material_digest, namespace_pattern_matches,
    normalize_applet_signing_key_ref, sign_registration,
};
pub use arkret_core::hlc::{
    EXPECTED_FUTURE_SKEW_MS, HARD_FUTURE_SKEW_MS, HlcComponents, HlcFutureDrift, HlcGenerator,
    compare_hlc, parse_hlc, time_until_hlc, validate_hlc_format, validate_hlc_future_drift,
};
// The narrow MLS persistence ports are part of the `CryptoStore` supertrait
// contract (owned by arkret-models-crypto, OpenMLS-free), so surface them on the
// umbrella for any full-surface consumer (e.g. garth's crypto-store adapter),
// independent of the heavier `mls` group-machine feature.
#[cfg(feature = "full-surface")]
pub use arkret_models_crypto::{MlsCommitSource, MlsGroupStateSink};
#[cfg(all(
    feature = "full-surface",
    feature = "applet-runtime",
    feature = "salvo"
))]
pub use arkret_server::applet_router;
#[cfg(all(feature = "full-surface", feature = "applet-runtime"))]
pub use arkret_server::{
    AppletHandler, AppletService, ServiceRoute, TransactionDispatch, service_routes,
};
#[cfg(feature = "server")]
pub use arkret_server::{
    CursorAuthority, CursorAuthorityError, CursorBindingContext, CursorBindingRecord,
    IdempotencyClaim, IdempotencyDirection, IdempotencyIdentity, IdempotencyWindow,
    MemoryCursorAuthority, TransactionClaim, TransactionIdempotencyStore, cursor_filter_digest,
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
    ApprovalMode, ApprovalStrandManager, AuthzContext, AuthzEngine, AuthzEngineRealmStateExt,
    CapabilityFrontierValidation, CapabilityGrantBuilder, ClaimRequirement, Constraint,
    ConstraintDuration, ConstraintEffect, ConstraintEntry, EngineDecision, FieldScope,
    GrantProposal, GrantRateLimitScope, PolicyEvaluationRequest, PolicyEvaluationResult,
    PolicyModerationReport, PolicyServerEffect, ProposalApproval, ProposalStatus,
    ProtocolResourceSelector, ProtocolResourceSelectorKind, ProtocolResourceSelectorScope,
    Recurrence, Resource, ResourceSelector, ScopeLimitation, VerifiedClaim, apply_policy_response,
    capability_grants_from_realm_state, current_capability_action_registry_digest,
    grant_requires_approval, moderation_report_for_policy_outcome,
    reject_unknown_critical_constraints, validate_capability_action_registry_binding,
    validate_capability_frontier,
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
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub use devices::{
    CrossSigningResetPayload, CrossSigningResetProof, CrossSigningResetReason, Device,
    DeviceChange, DeviceCrossSigningChainVerification, DeviceManager, DeviceMetadata,
    DeviceQuorumSignature, DeviceQuorumThreshold, DeviceTrustBinding, DeviceTrustChainOutcome,
    DeviceTrustState, DeviceVerificationChallenge, DeviceVerificationMessageKind,
    QrVerificationPayload, ToDeviceEnvelope, build_cross_signing_publish_event_at,
    build_device_authorize_event_at, cross_signing_publish_cell_subject,
    device_verification_commitment, verify_device_cross_signing_chain,
};
#[cfg(feature = "full-surface")]
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
    fork_quarantine_record,
};
pub use fixtures::{
    CANONICAL_FIXTURE_DEFAULT_KIND, CanonicalFixtureBuilder, CanonicalFixtureSuite,
    CanonicalFixtureVector,
};
#[cfg(all(feature = "full-surface", feature = "device-runtime"))]
pub use history_recovery::{
    RRK_SERVICE_DOMAIN, RRK_SERVICE_TYPE, RealmHistoryRecoveryKeyError,
    ResolvedRealmHistoryRecoveryKey, resolve_realm_history_recovery_key, rrk_key_scope,
    seal_history_secrets_to_recovery_recipient,
};
#[cfg(feature = "client")]
pub use http_client::{
    AccountSubscribeFolder, Auth, Client, ClientBuilder, ClientRequestOptions, RetryConfig,
};
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
pub use push::{
    CHIME_PUSH_REGISTRATION_VERSION, ChimePushRegistration, DndPeriod, DndSchedule, DndSettings,
    EncryptedPushPayload, PushCondition, PushEventNotification, PushGateway, PushPayload,
    PushPlatform, PushPriority, PushPrivacyPolicy, PushRule, PushRulesConfig, PushToken,
};
#[cfg(feature = "full-surface")]
pub use resolver::{
    REDUCER_SNAPSHOT_PROFILE, REDUCER_SNAPSHOT_SCHEMA, RealmState, ReducerSnapshotManifest,
    SnapshotChunkManifest, SnapshotRestore, SnapshotRestoreSource, SnapshotSignature,
    SnapshotSignatureBindingPayload, StateSnapshot, merkle_root, state_merkle_root,
    verify_snapshot_chunks,
};
#[cfg(feature = "full-surface")]
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
pub use webrtc::{
    CallSessionDescription, IceCandidate, IceConfig, MediaStateData, MediaTrackSet,
    ModeratePayload, ModerationAction, MuteSource, MuteStateData, RecordingCaptureKind,
    RecordingMode, RecordingResult, RecordingStartPayload, RecordingState, RenegotiateData,
    RenegotiateReason, ScreenShareState, SdpType, SpeakingData, TranscribePayload,
    WebRtcSignalKind, WebRtcSignalMessage, verify_ice_config_outcome,
};
