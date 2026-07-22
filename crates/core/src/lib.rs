//! Core Arkret v1 protocol types and helpers.
//!
//! This crate is the stable foundation shared by clients, servers and higher
//! level SDK state machines. It intentionally contains no HTTP transport,
//! framework adapter, mutable reducer, store, or snapshot runtime.

pub mod account_subscribe;
pub mod admin_signer;
pub mod agent;
pub mod applet;
pub mod authz {
    pub use arkret_policy::authz::*;
}
pub mod base64url {
    pub use arkret_canonical::base64url::*;
}
pub mod binding_contexts {
    pub use arkret_canonical::binding_contexts::*;
}
pub mod blind_payload_sanitizer {
    pub use arkret_policy::blind_payload_sanitizer::*;
}
pub mod bottom {
    pub use arkret_wire::bottom::*;
}
pub mod canonical {
    pub use arkret_canonical::canonical::*;
    pub use arkret_canonical::serde_helpers::*;
}
pub mod cell {
    pub use arkret_wire::cell::*;
}
pub mod cursor;
pub mod error;
pub mod events;
pub mod federation;
pub mod generated;
pub mod hlc;
pub mod http;
pub mod identity;
pub mod identity_key_log {
    pub use arkret_models_identity::identity_key_log::*;
}
pub mod integration {
    pub use arkret_models_integration::integration::*;
}
pub mod key_transparency {
    pub use arkret_models_crypto::key_transparency::*;
}
pub mod keystore;
pub mod lattice {
    pub use arkret_state::lattice::*;
}
pub mod models;
pub mod move_event {
    pub use arkret_wire::move_event::*;
}
pub mod multibase {
    pub use arkret_canonical::multibase::*;
}
pub mod notary {
    pub use arkret_wire::notary::*;
}
pub mod operations;
pub mod ops {
    pub use arkret_models_discovery::ops::*;
}
pub mod platform;
pub mod presence {
    pub use arkret_models_discovery::presence::*;
}
pub mod profile_claim {
    pub use arkret_policy::profile_claim::*;
}
pub mod profile_feature_guard {
    pub use arkret_policy::profile_feature_guard::*;
}
pub mod profile_semantics {
    pub use arkret_policy::profile_semantics::*;
}
pub mod query_auth;
pub mod push {
    pub use arkret_models_integration::push::*;
}
pub mod push_rule_core {
    pub use arkret_policy::push_rule_core::*;
}
pub mod schema {
    pub use arkret_schema::*;
}
pub mod seal {
    pub use arkret_wire::seal::*;
}
pub mod serde_helpers {
    pub use arkret_canonical::serde_helpers::*;
}
pub mod service;
pub mod service_identity;
pub mod signer {
    pub use arkret_wire::signer::*;
}
pub mod stream_trace;
pub mod sync {
    pub use arkret_models_collaboration::sync_frames::client_sync::*;
    pub use arkret_models_discovery::presence::{PresenceStatus, aggregate_presence_states};
}

pub use account_subscribe::{
    AccountSubscribeBatch, AccountSubscribeReconnectAfter, AccountSubscribeSnapshotResult,
    DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS, MAX_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS,
};
pub use admin_signer::{AdminKeyStore, SessionGrantIntrospection, admin_scopes};
pub use agent::{
    agent_key_pair_proof_request_binding_digest, agent_key_pairing_request_binding_digest,
    agent_requested_scope_digest, agent_runtime_attestation_digest,
    agent_runtime_key_binding_digest, agent_runtime_key_binding_digest_from_digests,
    agent_runtime_public_key_digest,
};
pub use applet::*;
pub use arkret_identifiers as identifiers;
pub use arkret_wire::string_profiles::*;
pub use arkret_wire::{
    CapabilityActionId, DIGEST_SUITES, EXPORTER_LABELS, EvaluationClass, ExporterLabelId,
    HPKE_SUITES, MLS_CIPHERSUITES, MLS_EXTENSIONS, PROOF_CONTEXTS, ProofContextId,
    RELATION_KIND_DESCRIPTORS, SERVICE_OPERATION_DESCRIPTORS, SERVICE_TYPE_DESCRIPTORS,
    SIGNATURE_ALGORITHMS, ServiceOperationDescriptor, ServiceOperationId, ServiceType, WireError,
    XExtensionMap,
};
pub use authz::*;
pub use base64url::{
    base64_standard_decode, base64_standard_encode, base64url_decode, base64url_encode,
};
pub use blind_payload_sanitizer::{
    ALLOWED_BLIND_FIELDS, ALLOWED_PUSH_HINTS, ALLOWED_TIMING_PROFILE_HINTS, ALLOWED_WAKEUP_KINDS,
    BlindPayloadError, BlindPayloadReasonCode, MAX_COUNT_VALUE, SanitizerMode,
    is_allowed_blind_field, is_forbidden_payload_key, is_valid_custom_wakeup_kind,
    is_valid_push_hint, is_valid_push_target_id, is_valid_timing_profile_hint,
    is_valid_wakeup_kind, sanitize_blind_payload, sanitize_blind_payload_strict,
    sanitize_blind_payload_with,
};
pub use bottom::{Bottom, BottomDetails, BottomKind, SealView, bottom_details};
pub use cell::{CellId, composite_subject, composite_subject_pipe};
pub use cursor::{Cursor, CursorPurpose, SyncPositions, SyncTracker};
pub use error::*;
pub use generated::profiles::{PROFILE_ROLES, ProfileRole, profile_ids_with_role, profile_role};
pub use hlc::{
    EXPECTED_FUTURE_SKEW_MS, HARD_FUTURE_SKEW_MS, HlcComponents, HlcFutureDrift, HlcGenerator,
    compare_hlc, parse_hlc, time_until_hlc, validate_hlc_format, validate_hlc_future_drift,
};
pub use http::*;
pub use identifiers::{
    ActorProfileId, AnnounceId, AppletId, AttestationId, AuditBindingId, AuditReleaseId,
    AuditSessionId, BackupId, BackupSeriesId, BatchId, BlobId, BlobRef, BlockId, CallId,
    CapabilityId, CellRef, ChunkId, CircleId, ClaimId, DeviceId, DeviceMessageId, Did, EventId,
    FilterId, FrameId, FrankingProofId, GrantId, Hash, Hlc, InviteId, KeyEventId, MessageId,
    ModerationQueueItemId, MorphId, MoveId, NotificationId, OperationId, PolicyId, PresentationId,
    ReadCursorId, RealmId, ReceiptId, RecoverySessionId, RelationId, ReportId, RequestId,
    RtcParticipantId, SealId, SnapshotId, SpaceId, StrandId, TransactionId, TypedAppealId,
    TypedTrustDomainId, ViewId,
};
pub use identity::{DID_WEBVH_V1_METHOD, principal_control_realm_id, validate_did_webvh_v1_method};
pub use identity_key_log::{DidKeyLogEntry, DidKeyLogOperation};
pub use key_transparency::{
    KEY_TRANSPARENCY_SCHEMA, KeyTransparencyError, KeyTransparencyEvidence,
    TransparencyConsistencyProof, TransparencyInclusionProof, TransparencyLogHead,
    TransparencyWitnessSignature,
};
pub use keystore::{InMemoryKeyStore, KeyBytes, KeyStore, KeyStoreError};
pub use models::*;
pub use move_event::{
    Effect, LatticeOp, LatticeOpType, MOVE_SIGNATURE_ALGS, Move, MoveSignature, Precondition,
    Predicate, PredicateOp, SealBasis, SemanticRef,
};
pub use multibase::{
    MULTICODEC_ED25519_PUB, decode_base58btc, decode_ed25519_multibase,
    decode_ed25519_signature_multibase, decode_multibase_base58btc, decode_multicodec_varint,
    ed25519_pubkey_to_did_key_multibase, encode_base58btc, encode_multibase_base58btc,
    sha256_multihash_base58btc,
};
pub use notary::{ForensicAttribution, NotaryValue};
pub use platform::{WasmHttpRequestBody, WasmHttpResponseBody};
pub use presence::{
    LAST_ACTIVE_BUCKET_FLOOR_SECONDS, PRESENCE_PREFERENCE_ACCOUNT_DATA_KEY,
    PRESENCE_VISIBILITY_ACCOUNT_DATA_KEY, PresencePreference, PresenceValidationError,
    STATUS_MESSAGE_MAX_CODE_POINTS, aggregate_presence_states, validate_last_active_at,
    validate_status_message,
};
pub use profile_claim::{ProfileClaim, ProfileClaimError, ProfileClaimKind, ProfileValidator};
pub use profile_feature_guard::{
    ProfileFeatureGap, implied_features_for_profiles,
    verify_declared_profiles_against_core_features, verify_declared_profiles_against_features,
};
pub use profile_semantics::{
    ProfileSemanticCoverageError, ProfileSemanticCoverageReport, ProfileSemanticRequirements,
    ProfileSemanticSurface, collect_profile_semantic_requirements,
    profile_capability_action_coverage_report, profile_semantic_coverage_report,
    validate_profile_semantic_coverage,
};
pub use query_auth::{
    QUERY_AUTH_PARAMETER_NAMES, contains_query_auth_material, is_query_auth_parameter,
};
pub use seal::{
    MultiSigKind, MultiSignature, NotarySig, SEAL_SIGNATURE_ALGS, Seal, SealKind, ThresholdSigKind,
    ThresholdSignature, compute_seal_id, seal_canonical_bytes,
};
pub use service::{
    ApiConventionMetadata, HttpTraceMetadata, NotFoundPrivacy, QuotaKind, QuotaMetadata,
    RateLimitMetadata, RateLimitScopeKind, ServiceEndpointBinding, ServiceIdAllowlist,
    ServiceRequirements, privacy_preserving_not_found, quota_exceeded_error, rate_limited_error,
};
pub use service_identity::*;
pub use signer::{MoveSigner, PartialSignature, ThresholdAggregator, UnsignedMove};
pub use stream_trace::{
    StreamTraceError, StreamTraceFrame, StreamTraceFrameKind, StreamTraceUpdate,
    StreamTraceValidator,
};
pub use sync::{
    BackfillDirection, BackfillFrom, BackfillOutcome, BackfillRequestBody, LimitedTimelineState,
    MembershipBucket, PresenceStatus, RealmSubscription, RealmUpdate, SubscriptionConfig,
    SyncFilter, SyncGap, SyncGapReason, SyncMode, SyncRequestBody, SyncSemantics,
    SyncStreamPosition, SyncTokenBinding, SyncUpdates, TimelineFilter, TimelineOrderKey,
    ToDeviceAck, ToDeviceAckStatus, WaitForFrontier, sync_filter_digest,
};

#[cfg(test)]
#[path = "schema/tests.rs"]
mod schema_compat_tests;
