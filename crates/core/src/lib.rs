//! Core Arkret v1 protocol types and helpers.
//!
//! This crate is the stable foundation shared by clients, servers and higher
//! level SDK state machines. It intentionally contains no HTTP transport,
//! framework adapter, mutable reducer, store, or snapshot runtime.

pub mod admin_signer;
pub mod agent;
pub mod applet;
pub mod base64url {
    pub use arkret_canonical::base64url::*;
}
pub mod canonical {
    pub use arkret_canonical::canonical::*;
    pub use arkret_canonical::serde_helpers::*;
}
pub mod error;
pub mod events;
pub mod federation;
pub mod generated;
pub mod http;
pub mod identity;
pub mod models;
pub mod multibase {
    pub use arkret_canonical::multibase::*;
}
pub mod schema {
    pub use arkret_schema::*;
}
pub mod service;
pub mod service_identity;
pub mod stream_trace;

pub use admin_signer::{AdminKeyStore, SessionGrantIntrospection, admin_scopes};
pub use agent::{
    agent_key_pair_proof_request_binding_digest, agent_key_pairing_request_binding_digest,
    agent_requested_scope_digest, agent_runtime_attestation_digest,
    agent_runtime_key_binding_digest, agent_runtime_key_binding_digest_from_digests,
    agent_runtime_public_key_digest,
};
pub use applet::*;
pub use arkret_identifiers as identifiers;
pub use arkret_models_collaboration::sync_frames::client_sync::{
    BackfillDirection, BackfillFrom, BackfillOutcome, BackfillRequestBody, LimitedTimelineState,
    MembershipBucket, RealmSubscription, RealmUpdate, SubscriptionConfig, SyncFilter, SyncGap,
    SyncGapReason, SyncMode, SyncRequestBody, SyncSemantics, SyncStreamPosition, SyncTokenBinding,
    SyncUpdates, TimelineFilter, TimelineOrderKey, ToDeviceAck, ToDeviceAckStatus, WaitForFrontier,
    sync_filter_digest,
};
pub use arkret_models_crypto::key_transparency::{
    KEY_TRANSPARENCY_SCHEMA, KeyTransparencyError, KeyTransparencyEvidence,
    TransparencyConsistencyProof, TransparencyInclusionProof, TransparencyLogHead,
    TransparencyWitnessSignature,
};
pub use arkret_models_discovery::presence::{
    LAST_ACTIVE_BUCKET_FLOOR_SECONDS, PRESENCE_PREFERENCE_ACCOUNT_DATA_KEY,
    PRESENCE_VISIBILITY_ACCOUNT_DATA_KEY, PresencePreference, PresenceStatus,
    PresenceValidationError, STATUS_MESSAGE_MAX_CODE_POINTS, aggregate_presence_states,
    validate_last_active_at, validate_status_message,
};
pub use arkret_models_identity::identity_key_log::{DidKeyLogEntry, DidKeyLogOperation};
pub use arkret_policy::authz::*;
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
pub use arkret_signatures::keypackages::{
    KeyPackageSignatureError, KeyPackageSignatureResult, keypackage_signature_from_bytes,
    sign_keypackage_signing_input, sign_keypackage_upload_entry, sign_keypackages_consume_request,
    sign_keypackages_revoke_request, sign_keypackages_upload_request,
    verify_keypackage_signing_input,
};
pub use arkret_wire::bottom::{Bottom, BottomDetails, BottomKind, SealView, bottom_details};
pub use arkret_wire::cell::{CellId, composite_subject, composite_subject_pipe};
pub use arkret_wire::move_event::{
    Effect, LatticeOp, LatticeOpType, MOVE_SIGNATURE_ALGS, Move, MoveSignature, Precondition,
    Predicate, PredicateOp, SealBasis, SemanticRef,
};
pub use arkret_wire::notary::{ForensicAttribution, NotaryValue};
pub use arkret_wire::seal::{
    MultiSigKind, MultiSignature, NotarySig, SEAL_SIGNATURE_ALGS, Seal, SealKind, ThresholdSigKind,
    ThresholdSignature, compute_seal_id, seal_canonical_bytes,
};
pub use arkret_wire::signer::{MoveSigner, PartialSignature, ThresholdAggregator, UnsignedMove};
pub use arkret_wire::string_profiles::*;
pub use arkret_wire::{
    CapabilityActionId, DIGEST_SUITES, EXPORTER_LABELS, EvaluationClass, ExporterLabelId,
    HPKE_SUITES, MLS_CIPHERSUITES, MLS_EXTENSIONS, PROOF_CONTEXTS, ProofContextId,
    RELATION_KIND_DESCRIPTORS, SERVICE_OPERATION_DESCRIPTORS, SERVICE_TYPE_DESCRIPTORS,
    SIGNATURE_ALGORITHMS, ServiceOperationDescriptor, ServiceOperationId, ServiceType, WireError,
    XExtensionMap,
};
pub use base64url::{
    base64_standard_decode, base64_standard_encode, base64url_decode, base64url_encode,
};
pub use error::*;
pub use generated::profiles::{PROFILE_ROLES, ProfileRole, profile_ids_with_role, profile_role};
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
pub use models::*;
pub use multibase::{
    MULTICODEC_ED25519_PUB, decode_base58btc, decode_ed25519_multibase,
    decode_ed25519_signature_multibase, decode_multibase_base58btc, decode_multicodec_varint,
    ed25519_pubkey_to_did_key_multibase, encode_base58btc, encode_multibase_base58btc,
    sha256_multihash_base58btc,
};
pub use service::{
    ApiConventionMetadata, HttpTraceMetadata, NotFoundPrivacy, QuotaKind, QuotaMetadata,
    RateLimitMetadata, RateLimitScopeKind, ServiceEndpointBinding, ServiceIdAllowlist,
    ServiceRequirements,
};
pub use service_identity::*;
pub use stream_trace::{
    StreamTraceError, StreamTraceFrame, StreamTraceFrameKind, StreamTraceUpdate,
    StreamTraceValidator,
};
