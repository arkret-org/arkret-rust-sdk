//! Arkret v1 Rust SDK.
//!
//! This crate exposes Arkret protocol concepts directly. The source of truth
//! is signed Event Envelopes; standard authoring binds each Event marker to its
//! SDK payload type before erasing it into the wire envelope.
//!
//! # Examples
//!
//! Author a standard Event without supplying a separate runtime kind:
//!
//! ```rust
//! use arkret::{
//!     ContentBlock, DidCoreId, DidFullId, Hlc, MessageCreatePayload, RealmId, ScopeRef, StrandId,
//!     TypedEventDraft, event_spec, project_full_id_to_core_id,
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
//!     DidCoreId::from(project_full_id_to_core_id(&DidFullId::new(
//!         "did:webvh:z6mkfixture:alice.example",
//!     )?)?),
//!     payload,
//! )?
//! .author(
//!     1,
//!     Hlc::new("01970e589d21-0001-a13f9c2e")?,
//!     "2026-08-09T00:00:00Z".parse().unwrap(),
//! )?;
//! assert_eq!(event.payload["content"]["body"], "hello");
//! # Ok(())
//! # }
//! ```
//!
//! Invalid typed IDs should be constructed with validators, not assigned from
//! raw strings:
//!
//! ```compile_fail
//! let did: arkret::DidFullId = "did:webvh:z6mkfixture:alice.example";
//! ```

mod sdk_error;
mod sidecar_recovery;
mod verified_actor_binding;
pub use arkret_auth as auth;
pub use arkret_auth::{AdminKeyStore, session_grant};
pub use arkret_bootstrap as bootstrap;
pub use arkret_canonical as canonical;
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
    AppletBridgeErrorBuilder, CausalRef, ContainerRebalanceAssignment, DeviceMessageSpec,
    EventDraftKindConformanceVector, EventDraftKindRegistry, EventDraftKindSpec,
    EventDraftKindValidation, EventPayloadExt, EventSpec, ExtensionPayloadValidator,
    GhostActorProfileRequest, LocalOperationDraft, LocalOperationSpec, MessageEventPayload,
    MlsEnvelopeOperationExt, OperationEnvelope, OperationEnvelopeBuilder, OperationEventConversion,
    OperationSignature, ProjectedEventOperation, ProjectionContext, RsvpAuthoring,
    RsvpResponseBranch, StrandCreateObject, TypedDeviceMessageTarget, TypedEventDraft,
    ValidatedExtensionPayload, accountability_grant_event, container_rebalance_assignments,
    device_message_kind, device_message_spec, event_draft_kind_conformance_vectors, operations,
    rank_between, rank_exhausted,
};
pub use arkret_hlc::{
    CURSOR_HANDLE_MIN_LEN, Cursor, CursorPurpose, HlcGenerator, RealmSyncPosition, SyncPositions,
    SyncTracker, cursor, generate_cursor_handle,
};
#[cfg(feature = "client")]
pub use arkret_http_client as http_client;
pub use arkret_identifiers as identifiers;
pub use arkret_identifiers::{
    ActorProfileId, AnnounceId, AppletId, AttestationId, AuditBindingId, AuditReleaseId,
    AuditSessionId, BackupId, BackupSeriesId, BatchId, BlobId, BlobRef, BlockId, CallId,
    CapabilityId, CellRef, ChunkId, CircleId, ClaimId, ConsentId, DeviceId, DeviceMessageId,
    DeviceMessageTransactionId, DidCoreId, DidFullId, EventId, FilterId, FrameId, FrankingProofId,
    GrantId, Hash, Hlc, InviteId, InviteLocatorId, KeyEventId, MessageId, MessageStreamId,
    ModerationQueueItemId, MorphId, NotificationId, OperationId, PolicyId, PresentationId,
    ReadCursorId, RealmId, ReceiptId, RecoverySessionId, RelationId, ReportId, RequestId,
    RtcParticipantId, SealId, SidecarId, SnapshotId, SpaceId, StrandId, SubscriptionId,
    TransactionId, TrustDomainId, TypedAppealId, TypedTrustDomainId, ViewId, new_prefixed_uuid7,
    project_full_id_to_core_id,
};
pub use arkret_identity as identity;
pub use arkret_identity::jws;
pub use arkret_identity::service_identity::{
    DidCoreIdentityBundle, DidCoreIdentityDiagnostic, DidCoreIdentityKeyRef,
    DidCoreIdentityProviderRef, DidCoreIdentityState, FileIdentityBundleBackend,
    IdentityBundleBackend, IdentityBundleBackendAvailability, KeyStoreIdentityBundleBackend,
    LocalDidCoreIdentity, ResolvedService, StoredDidCoreIdentity,
};
#[cfg(feature = "keystore-encrypted-file")]
pub use arkret_keystore::EncryptedFileKeyStore;
pub use arkret_keystore::{
    BackendKind, InMemoryKeyStore, KeyBytes, KeyStore, KeyStoreError, LinuxSecretServiceKeyStore,
    MacOsKeychainKeyStore, WindowsCredentialKeyStore, durable_platform_keystore,
    platform_default_keystore_with_kind,
};
pub use arkret_models_collaboration::account_lifecycle::*;
pub use arkret_models_collaboration::agent_operations::*;
pub use arkret_models_collaboration::call_signal::{
    CallAckSignalData, CallAnswerSignalData, CallCandidateSignalData, CallEndSignalData,
    CallErrorSignalData, CallFocusSignalData, CallInviteSignalData, CallMediaSelection,
    CallMediaStateSignalData, CallMode as CallSignalMode, CallModerationAction,
    CallModerationSignalData, CallMuteStateSignalData, CallRenegotiateSignalData, CallSignalData,
    CallSignalKind, CallSignalPlaintext, CallSignalPlaintextKind, CallSpeakingSignalData,
    IceCandidate, MuteChangedBy, RenegotiationReason, ScreenMediaState, SessionDescription,
    SessionDescriptionType,
};
pub use arkret_models_collaboration::direct_conversation_ops::*;
pub use arkret_models_collaboration::direct_conversation_repair::*;
pub use arkret_models_collaboration::event_query::*;
pub use arkret_models_collaboration::event_sync::*;
pub use arkret_models_collaboration::events_payloads::agent::*;
pub use arkret_models_collaboration::events_payloads::audit::*;
pub use arkret_models_collaboration::events_payloads::call::*;
pub use arkret_models_collaboration::events_payloads::device_identity::*;
pub use arkret_models_collaboration::events_payloads::event_wire::*;
pub use arkret_models_collaboration::events_payloads::mention::*;
pub use arkret_models_collaboration::events_payloads::*;
pub use arkret_models_collaboration::federation::wire_dtos::*;
pub use arkret_models_collaboration::governance::accountability::{
    ACCOUNTABILITY_SCOPE_SET_CONTEXT, AccountabilityGrantPayload, AccountabilityGrantStatus,
    AccountabilityScope, AccountabilityScopeKind,
};
pub use arkret_models_collaboration::governance::agent_artifacts::*;
pub use arkret_models_collaboration::governance::agent_participation::*;
pub use arkret_models_collaboration::governance::audit::{
    ABSOLUTE_HARD_CEILING_MS, AccessKind, AuditAssurance, AuditPolicyAccessPayload,
    AuditRywReceipt, E2EE_RELAXED_INCOMPATIBLE_COMPLIANCE_PROFILES, ReceiptIndependence,
    RywActorFrontierEntry, RywFrontier, RywIssuerRole, is_e2ee_relaxed_compatible_with_compliance,
    validate_relaxed_window_ms,
};
pub use arkret_models_collaboration::governance::authorization::*;
pub use arkret_models_collaboration::governance::circle::*;
pub use arkret_models_collaboration::governance::delivery_binding::*;
pub use arkret_models_collaboration::governance::erasure::*;
pub use arkret_models_collaboration::governance::grant_constraint::*;
pub use arkret_models_collaboration::governance::handle_claim::*;
pub use arkret_models_collaboration::governance::history_visibility::*;
pub use arkret_models_collaboration::governance::invite_addressing::*;
pub use arkret_models_collaboration::governance::join_policy::*;
pub use arkret_models_collaboration::governance::member_delivery_binding_candidate::*;
pub use arkret_models_collaboration::governance::membership_invite::*;
pub use arkret_models_collaboration::governance::moderation::*;
pub use arkret_models_collaboration::governance::moderation_appeal::*;
pub use arkret_models_collaboration::governance::moderation_queue::*;
pub use arkret_models_collaboration::governance::operation_wire::*;
pub use arkret_models_collaboration::governance::peer_contact::*;
pub use arkret_models_collaboration::governance::plaintext_visibility::*;
pub use arkret_models_collaboration::governance::policy_check::*;
pub use arkret_models_collaboration::governance::realm_governance::*;
pub use arkret_models_collaboration::governance::realm_lifecycle::*;
pub use arkret_models_collaboration::governance::resource_selector::*;
pub use arkret_models_collaboration::governance::third_party_invite::*;
pub use arkret_models_collaboration::governance_payloads::*;
pub use arkret_models_collaboration::http_bodies::*;
pub use arkret_models_collaboration::mls_group_state_material::*;
pub use arkret_models_collaboration::object_lifecycle::*;
pub use arkret_models_collaboration::object_patch::*;
pub use arkret_models_collaboration::objects::account_status::{
    AccountStatus, AccountStatusProjection, AccountStatusProjectionCandidate,
    AccountStatusProjectionRejected, AccountStatusTransitionRejection,
    project_account_status_heads,
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
pub use arkret_models_collaboration::runtime_identity::*;
pub use arkret_models_collaboration::seal_transparency::*;
pub use arkret_models_collaboration::session_grant_bodies::*;
pub use arkret_models_collaboration::signal_message_stream::*;
pub use arkret_models_collaboration::signal_plaintext::*;
pub use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountStreamInterrupt, AccountSubscribeBatch, AccountSubscribeFrame,
    AccountSubscribeFrameKind, AccountSubscribeRealms, AccountSubscribeReconnectAfter,
    AccountSubscribeSnapshotResult, DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS,
    MAX_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS,
};
pub use arkret_models_collaboration::sync_frames::account_sync::*;
pub use arkret_models_collaboration::sync_frames::client_sync::{
    BackfillDirection, BackfillFrom, BackfillOutcome, BackfillRequestBody, LimitedTimelineState,
    MembershipBucket, RealmSubscription, RealmUpdate, SubscriptionConfig, SyncFilter, SyncGap,
    SyncGapReason, SyncMode, SyncRequestBody, SyncSemantics, SyncStreamPosition, SyncTokenBinding,
    SyncUpdates, TimelineFilter, TimelineOrderKey, ToDeviceAck, ToDeviceAckStatus, WaitForFrontier,
    sync_filter_digest,
};
pub use arkret_models_collaboration::sync_frames::snapshot::*;
pub use arkret_models_collaboration::sync_frames::stream_trace::{
    StreamTraceError, StreamTraceFrame, StreamTraceFrameKind, StreamTraceUpdate,
    StreamTraceValidator,
};
pub use arkret_models_collaboration::{
    contact_operations, direct_conversation_ops, direct_conversation_repair, federation,
    history_operations, sidecar_operations,
};
pub use arkret_models_crypto::artifacts_keys::*;
pub use arkret_models_crypto::encrypted_envelope::{
    AadVisibilityCeiling, EncryptedPayload, KeyRefObject,
};
pub use arkret_models_crypto::http_bodies::*;
pub use arkret_models_crypto::key_backup::*;
pub use arkret_models_crypto::key_transparency::{
    KeyTransparencyError, KeyTransparencyEvidence, TransparencyConsistencyProof,
    TransparencyInclusionProof, TransparencyLogHead, TransparencyWitnessSignature,
};
pub use arkret_models_crypto::keys::*;
pub use arkret_models_crypto::mls_envelopes::{
    MlsCommitEnvelope, MlsProposalEnvelope, MlsWelcomeEnvelope,
};
pub use arkret_models_crypto::mls_payloads::*;
pub use arkret_models_crypto::mls_records::{
    MlsEndpointIdentity, MlsKeyPackageRecord, RealmPairwiseAcceptedGroupState,
    RealmPairwiseAcceptedLeaf, RealmPairwiseAuthorState, RealmPairwiseKeyScopeLedger,
};
pub use arkret_models_crypto::protected_payload::{
    MlsEncryptedPayload, MlsPayloadType, PlainPayload, ProtectedPayload,
};
pub use arkret_models_discovery::directory::*;
pub use arkret_models_discovery::directory_artifacts::*;
pub use arkret_models_discovery::http_bodies::*;
pub use arkret_models_discovery::presence::{
    LAST_ACTIVE_BUCKET_FLOOR_SECONDS, PresencePreference, PresenceStatus, PresenceValidationError,
    PresenceVisibility, PresenceVisibilityPreference, STATUS_MESSAGE_MAX_CODE_POINTS,
    aggregate_presence_states, validate_last_active_at, validate_status_message,
};
pub use arkret_models_discovery::service_description::*;
pub use arkret_models_discovery::service_requirements::{
    ApiConventionMetadata, DidCoreIdAllowlist, HttpTraceMetadata, NotFoundPrivacy, QuotaKind,
    QuotaMetadata, RateLimitMetadata, RateLimitScopeKind, ServiceEndpointBinding,
    ServiceRequirements,
};
pub use arkret_models_discovery::{ops, service_requirements as service};
pub use arkret_models_identity::account::*;
pub use arkret_models_identity::actor_profile::*;
pub use arkret_models_identity::admin_grant::{
    SessionGrantAdminIntrospectionStatus, SessionGrantIntrospection, admin_scopes,
};
pub use arkret_models_identity::agent_signer_evidence::*;
pub use arkret_models_identity::artifacts_account::*;
pub use arkret_models_identity::artifacts_device_identity::*;
pub use arkret_models_identity::attestation::*;
pub use arkret_models_identity::claim_presentation::{
    AgentSelectorClaim, DIRECTORY_RESTRICTED_CLAIM_PRESENTATION_KIND, DirectoryPresentedClaim,
    DirectoryRestrictedClaimPresentation, validate_agent_slug,
};
pub use arkret_models_identity::device_verification::*;
pub use arkret_models_identity::handle::*;
pub use arkret_models_identity::http_bodies::*;
pub use arkret_models_identity::identity::*;
pub use arkret_models_identity::identity_link_cache::*;
pub use arkret_models_identity::identity_resolution::*;
pub use arkret_models_identity::member_identity::*;
pub use arkret_models_identity::service_identity::*;
pub use arkret_models_identity::session_credential::*;
pub use arkret_models_identity::{DID_WEBVH_V1_METHOD, validate_did_webvh_v1_method};
pub use arkret_models_integration::applet::*;
pub use arkret_models_integration::applet_audit_payload::*;
pub use arkret_models_integration::applet_install_plan::*;
pub use arkret_models_integration::applet_models::*;
pub use arkret_models_integration::artifacts_applet::*;
pub use arkret_models_integration::http_bodies::*;
pub use arkret_models_integration::integration::*;
pub use arkret_models_integration::models_push::*;
pub use arkret_models_integration::{integration, push};
pub use arkret_policy::authz::*;
pub use arkret_policy::generated::profiles::{
    PROFILE_ROLES, ProfileRole, profile_ids_with_role, profile_role,
};
pub use arkret_policy::history_visibility::*;
pub use arkret_policy::profile_claim::{
    ProfileClaim, ProfileClaimError, ProfileClaimKind, ProfileValidator,
};
pub use arkret_policy::profile_feature_guard::{
    ProfileFeatureGap, implied_features_for_profiles,
    verify_declared_profiles_against_core_features, verify_declared_profiles_against_features,
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
pub use arkret_schema as schema;
pub use arkret_schema::protocol::*;
pub use arkret_schema::{
    EventSchemaExt, PreparedControlMove, PreparedDataEvent, PreparedEventPlane,
    PreparedNonReducerEvent, PreparedStandardEvent,
};
#[cfg(feature = "server")]
pub use arkret_server as server;
pub use arkret_signatures as signatures;
#[cfg(feature = "signer")]
pub use arkret_signatures::Ed25519PayloadSigner;
pub use arkret_signatures::contact_receipt::{
    contact_request_acceptance_receipt_signing_bytes, verify_contact_request_acceptance_receipt,
};
pub use arkret_signatures::device_pairing::{
    sign_device_pairing_target_attestation, verify_device_pairing_target_attestation,
};
pub use arkret_signatures::federation::*;
pub use arkret_signatures::keypackages::{
    KeyPackageSignatureError, KeyPackageSignatureResult, keypackage_signature_from_bytes,
    sign_keypackage_signing_input, sign_keypackage_upload_entry, sign_keypackages_consume_request,
    sign_keypackages_revoke_request, sign_keypackages_upload_request,
    verify_keypackage_signing_input,
};
pub use arkret_signatures::service_resolution::{
    sign_service_resolution_record, verify_authenticated_service_resolution,
};
// Shared `did:webvh` inception builder + organization statement signer, surfaced
// at the SDK root so clients (sodmin / inkson) and servers (soland / coauth)
// reach one implementation: `arkret_sdk::webvh::prepare_principal_inception`,
// `arkret_sdk::realm_organization_statement_sign`.
pub use arkret_signatures::{
    realm_organization, realm_organization_statement_sign, service_identity, webvh,
};
pub use arkret_state::mls_governance_proof::*;
pub use arkret_state::{lattice, snapshot, state, *};
pub use arkret_wire::bottom::{Bottom, BottomDetails, BottomKind, SealView, bottom_details};
pub use arkret_wire::cba::{
    LatticeOp, LatticeOpType, ObservedRemoveMatch, Precondition, Predicate, PredicateOp,
    ProjectedCellWrite, ProjectedOp, ProjectionEffect, SealBasis,
};
pub use arkret_wire::cell::{CellId, composite_subject, composite_subject_pipe};
pub use arkret_wire::constants::*;
pub use arkret_wire::error_codes::*;
pub use arkret_wire::event_envelope::*;
pub use arkret_wire::http_signature::HttpMessageSignature;
pub use arkret_wire::notary::{ForensicAttribution, NotaryValue};
pub use arkret_wire::object_address::*;
pub use arkret_wire::patch::*;
pub use arkret_wire::plaintext::PlaintextDataClassKind;
pub use arkret_wire::primitives::*;
pub use arkret_wire::problem_details::*;
pub use arkret_wire::receive_policy::{
    InviteReceiveAction, ReceivePolicyConstraints, ReceivePolicySurface, UnknownInviteAction,
};
pub use arkret_wire::seal::{
    MultiSigKind, MultiSignature, NotarySig, Seal, SealKind, ThresholdSigKind, ThresholdSignature,
    compute_seal_id, seal_canonical_bytes,
};
pub use arkret_wire::self_contact_paths::*;
pub use arkret_wire::signer::{PartialSignature, PayloadSigner, ThresholdAggregator};
pub use arkret_wire::string_profiles::*;
pub use arkret_wire::wire_strings::*;
pub use arkret_wire::{
    AccountDataKey, BindingKind, CapabilityActionId, DIGEST_SUITES, DidFreshnessProfileId,
    DidFreshnessRiskTier, EXPORTER_LABELS, EffectId, EvaluationClass, EventInitialSubmission,
    EventKind, ExporterLabelId, GenesisSalt, HPKE_SUITES, IdempotencyKey, KeyPackageClaimId,
    KeyPackageRef, MLS_CIPHERSUITES, MLS_EXTENSIONS, MlsCiphersuiteId, PROOF_CONTEXTS, ProfileId,
    ProofContextId, ProtocolOpaqueId, ProtocolOperationId, ProtocolSignature,
    QUERY_AUTH_PARAMETER_NAMES, RELATION_KIND_DESCRIPTORS, ReservationHandle,
    SERVICE_KIND_DESCRIPTORS, SERVICE_OPERATION_DESCRIPTORS, SIGNATURE_ALGORITHMS, SchemaId,
    ServiceKind, ServiceOperationDescriptor, ServiceOperationId, WireError, XExtensionMap,
    contains_query_auth_material, error_codes as error, event_spec, is_query_auth_parameter,
};
pub use sdk_error::{Error, Result};
pub use sidecar_recovery::{AgentSidecarContextLocator, recover_agent_sidecar_context_locators};
pub use verified_actor_binding::*;

pub mod events {
    pub use arkret_models_collaboration::events_payloads::redaction::*;
    pub use arkret_wire::Event as RawEvent;
    pub use arkret_wire::events::*;
}

pub mod sync {
    pub use arkret_models_collaboration::sync_frames::client_sync::*;
    pub use arkret_models_discovery::presence::{PresenceStatus, aggregate_presence_states};
}

// Platform-native KeyStore backends. The glob import above already
// re-exports these symbols, but listing them explicitly keeps them
// visible in `cargo doc` and signals the supported surface to
// downstream crates that depend only on the `arkret` umbrella.
pub use arkret_hlc as hlc;
// Realm Recovery Key (RRK) durable history sealing — provider-initiated
// `ak.realm_key.share` to offline recovery recipients (encryption-and-audit.md
// §2.10.8). Resolves the RRK HPKE public key from a recipient's DID Document
// and HPKE-seals retained per-epoch history secrets to it. Reuses
// `secret_share`'s HPKE seal primitive, so it carries the same feature gate.
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
#[cfg(all(feature = "client", not(target_arch = "wasm32")))]
pub use arkret_http_client::http_did_resolver;
/// RFC 7515 detached Ed25519 JWS verifier (see [`jws`] module docs).
/// Lives at the SDK root so principal-server-style consumers (inkson,
/// floria, cotest, teabay, soland) all reach the same verifier. Depends
/// on `identity::DidResolver`.
// `key_backup_client` now lives in arkret-http-client; this shim keeps the
// `arkret::key_backup_client::*` path stable.
#[cfg(feature = "client")]
pub use arkret_http_client::key_backup_client;
// `lattice_registry` is intentionally NOT feature-gated: inkson Move
// pre-check + cotest fixtures need the spec-normative cell-family
// registry independently of the HTTP and MLS runtime integrations.
pub use arkret_lattice_registry as lattice_registry;
pub use arkret_signatures::{dpop, http_signature};
pub use arkret_state::{consent, mls_cells, resolver};
// The MLS (RFC 9420) behavior layer lives in the standalone `arkret-mls` crate
// (the sole OpenMLS boundary). Keep the `arkret::mls::*` path stable by
// re-exporting it here under the same feature gate it always carried.
#[cfg(feature = "mls")]
pub mod mls {
    pub use arkret_mls::*;
}
pub use arkret_crypto::{
    AEAD_NONCE_AES_GCM_LEN, AEAD_NONCE_COUNTER_LEN, AEAD_NONCE_EXPORTER_LABEL,
    AEAD_NONCE_XCHACHA20_POLY1305_LEN, AEAD_PROFILE_AES_256_GCM, AEAD_PROFILE_XCHACHA20_POLY1305,
    AeadNonceContext, AeadNonceReplayTracker, EncryptedEnvelopeDigestReport,
    aead_sender_nonce_context_bytes, compose_aead_nonce, derive_aead_sender_nonce_prefix,
    encrypted_envelope_digest_report, envelope_aad_digest, json_aad_digest,
    verify_aead_nonce_derivation, verify_aead_sender_nonce, verify_envelope_aad_digest,
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
pub use arkret_server::{
    AppletHandler, AppletService, ServiceRoute, TransactionDispatch, service_routes,
};
#[cfg(feature = "server")]
pub use arkret_server::{
    CursorAuthority, CursorAuthorityError, CursorBindingContext, CursorBindingRecord,
    IdempotencyClaim, IdempotencyDirection, IdempotencyIdentity, IdempotencyWindow,
    MemoryCursorAuthority, TransactionClaim, TransactionIdempotencyStore, cursor_filter_digest,
};
pub use arkret_signatures::media::{
    CallMediaTokenVerification, IceConfig, MediaBackendType, MediaServiceAnchors,
    call_media_token_exchange, participant_binding_signing_input, validate_token_ttl,
    verify_call_media_token_outcome, verify_ice_config_outcome,
};
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
    RenewalCredentialMetadata, SessionGrant, SessionGrantNotificationKind, SessionGrantOutboxEntry,
    SessionGrantOutboxState, SessionGrantPayload, SessionGrantProjectionState, SessionGrantRecord,
    SessionGrantRetryPolicy, SessionGrantSigner, SessionGrantVerification, SessionGrantVerifier,
    SessionPrincipalBinding, SessionRevocation, WebAuthnPasskeyOutcome, arkret_device_scope,
    device_id_from_scope_token, issue_session_grant_with_signer, primary_device_id_from_scopes,
    validate_presentation, verify_presentation_with_adapter, verify_session_grant_with_verifier,
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
    DidResolver, DidVisibility, DidWebDocumentOutcome, DidWebResolver, ExternalHandleProof,
    HandleAttestation, HandleClaimChallenge, HandleProofProfile, IdentityManager,
    IdentityReceiptWitnessRole, PairwiseActorBinding, PairwiseActorResolutionProof,
    PairwiseActorStore, ResolvedDid, ResolvedVerificationMethodKey, VerifiedAccountBindingReceipt,
    event_proof_verification_context, event_proof_verification_context_with_digest_suite,
    handle_claim_proof, handle_dns_txt_name, handle_well_known_url,
    pairwise_actor_resolution_proof, resolve_verification_method_key,
    resolve_verification_method_key_from_document, verification_method_did,
    verify_account_binding_receipt_at_issuance, verify_canonical_proof_with_did_resolver,
    verify_event_proof_with_did_resolver, verify_event_proof_with_did_resolver_context,
};
#[cfg(feature = "client")]
pub use key_backup_client::KeyBackupClient;
#[cfg(feature = "mls")]
pub use mls::*;
pub use resolver::{
    REDUCER_SNAPSHOT_PROFILE, REDUCER_SNAPSHOT_SCHEMA, RealmState, ReducerSnapshotManifest,
    SnapshotChunkManifest, SnapshotRestore, SnapshotRestoreSource, SnapshotSignature,
    SnapshotSignatureBindingPayload, StateSnapshot, merkle_root, state_merkle_root,
    verify_snapshot_chunks,
};
#[cfg(feature = "server")]
pub use server::{
    EndpointHandler, ProtocolFixtureReport, ProtocolFixtureStep, ProtocolFixtureStrand,
    ProtocolGoldenVector, ProtocolServerFixture, ServerOutcome, ServerRequestBody,
    WireConformanceVector, protocol_golden_vectors, reject_query_auth, wire_negative_vectors,
};

/// Calendar RSVP authoring.
///
/// [`arkret_event_draft::RsvpAuthoring`] builds the validated payload; this
/// module adds the half that needs the event-kind registry — running the
/// `ak.component.calendar.rsvp.v1` contract's `effect_projection =
/// set(payload.entry)` over the finished Event, which is the same projection a
/// receiver runs. A producer states no writes in v1, so this is a self-check,
/// not a stamping step: a payload the contract cannot project fails here
/// instead of reaching the wire and being rejected with
/// `effects_payload_mismatch`. It deliberately checks the projection only, not
/// the DataEvent-vs-Control-Move plane routing — the draft has no `seal_ref`
/// yet, so that check belongs to the submit gate, not to authoring.
pub mod calendar {
    use arkret_event_draft::RsvpAuthoring;
    use arkret_models_collaboration::objects::productivity::CalendarEventFields;
    use arkret_schema::project_registered_cell_writes;
    use arkret_wire::{DidCoreId, Error, Event, Hash, Hlc, Result, ScopeRef};

    /// Builds a complete, self-verified `ak.rsvp.set` Event.
    ///
    /// `causal_refs` MUST already contain every entry of
    /// `schedule_basis_refs`; the subset rule is enforced here because a
    /// producer, unlike a JSON Schema, can see both sides.
    #[allow(clippy::too_many_arguments)]
    pub fn build_rsvp_set_event(
        authoring: RsvpAuthoring,
        calendar: &CalendarEventFields,
        schedule: &crate::CalendarScheduleProjection,
        scope_ref: ScopeRef,
        actor_id: DidCoreId,
        actor_seq: u64,
        hlc: Hlc,
        causal_refs: Vec<Hash>,
    ) -> Result<Event> {
        let payload = authoring.into_payload(calendar, schedule)?;
        for basis in &payload.entry.schedule_basis_refs {
            if !causal_refs
                .iter()
                .any(|value| value.as_str() == basis.as_str())
            {
                return Err(Error::Protocol(
                    "rsvp schedule_basis_refs must be a subset of the envelope causal_refs"
                        .to_owned(),
                ));
            }
        }
        let event = arkret_event_draft::TypedEventDraft::<arkret_wire::event_spec::RsvpSet>::new(
            scope_ref, actor_id, payload,
        )
        .map_err(|error| Error::Protocol(error.to_string()))?
        .with_causal_refs(causal_refs)
        .author_now(actor_seq, hlc)
        .map_err(|error| Error::Protocol(error.to_string()))?;
        // No materialization step: v1 has no producer-written effect array, so
        // there is nothing for the builder to stamp. The check below is the
        // producer running the same registry projection a receiver will run,
        // which is what makes an unprojectable payload fail here instead of on
        // the wire.
        project_registered_cell_writes(&event, arkret_canonical::DigestSuite::Sha256)
            .map_err(|error| Error::Protocol(format!("rsvp cell contract failed: {error}")))?;
        Ok(event)
    }
}
