//! Core Arkret v1 protocol types and helpers.
//!
//! This crate is the stable foundation shared by clients, servers and higher
//! level SDK state machines. It intentionally contains no HTTP transport,
//! framework adapter, mutable reducer, store, or snapshot runtime.

pub mod account_subscribe;
pub mod admin_signer;
pub mod agent;
pub mod applet;
pub mod authz;
pub mod base64url;
pub mod binding_contexts;
pub mod blind_payload_sanitizer;
pub mod bottom;
pub mod canonical;
pub mod cell;
pub mod cursor;
pub mod error;
pub mod events;
pub mod federation;
pub mod generated;
pub mod http;
pub mod identity;
pub mod identity_key_log;
mod inbound;
pub mod integration;
pub mod key_transparency;
pub mod keystore;
pub mod lattice;
pub mod models;
pub mod move_event;
pub mod multibase;
pub mod notary;
pub mod operations;
pub mod ops;
pub mod platform;
pub mod presence;
pub mod profile_claim;
pub mod profile_feature_guard;
pub mod profile_semantics;
pub mod push;
pub mod push_rule_core;
pub mod schema;
pub mod sdk_conformance;
pub mod seal;
pub mod serde_helpers;
pub mod service;
pub mod signer;
pub mod stream_trace;
pub mod sync;

pub use account_subscribe::{
    AccountSubscribeFolder, AccountSubscribeReconnectAfter, AccountSubscribeSnapshotResult,
    DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS, MAX_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS,
};
pub use admin_signer::{AdminKeyStore, SessionGrantIntrospection, admin_scopes};
pub use agent::{
    agent_key_pair_proof_request_binding_digest, agent_key_pairing_request_binding_digest,
    agent_runtime_public_key_digest,
};
pub use applet::*;
pub use arkret_identifiers as identifiers;
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
pub use inbound::{DecodedInbound, DecodedMessage, InboundDecoder};
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
    MULTICODEC_ED25519_PUB, decode_base58btc, decode_ed25519_multibase, decode_multibase_base58btc,
    decode_multicodec_varint, ed25519_pubkey_to_did_key_multibase, encode_base58btc,
    encode_multibase_base58btc,
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
pub use sdk_conformance::{
    SDK_CONFORMANCE_CLAIM_DOMAIN, SdkArtifactSubject, SdkClaimIssuer, SdkClauseClaim,
    SdkClauseResult, SdkConformanceClaim, SdkConformanceClaimError, SdkConformanceEvidence,
    SdkConformanceProof, SdkConformanceProofAlgorithm, SdkEvidenceKind,
};
pub use seal::{
    MultiSigKind, MultiSignature, NotarySig, SEAL_SIGNATURE_ALGS, Seal, SealKind, ThresholdSigKind,
    ThresholdSignature, compute_seal_id, seal_canonical_bytes,
};
pub use service::{
    ApiConventionMetadata, HttpTraceMetadata, NotFoundPrivacy, QuotaKind, QuotaMetadata,
    RateLimitMetadata, RateLimitScopeKind, ServiceEndpointBinding, ServiceIdAllowlist,
    ServiceRequirements, ServiceType, privacy_preserving_not_found, quota_exceeded_error,
    rate_limited_error,
};
pub use signer::{MoveSigner, PartialSignature, ThresholdAggregator, UnsignedMove};
pub use stream_trace::{
    StreamTraceError, StreamTraceFrame, StreamTraceFrameKind, StreamTraceUpdate,
    StreamTraceValidator,
};
pub use sync::{
    AccountData, BackfillDirection, BackfillFrom, BackfillOutcome, BackfillRequestBody,
    BucketedRealmUpdate, DeviceListChanges, LimitedTimelineState, MembershipBucket,
    NotificationDelta, PresenceEvent, PresenceStatus, RealmSubscription, RealmUpdate,
    SubscriptionConfig, SyncClient, SyncFilter, SyncGap, SyncGapReason, SyncMode, SyncRealm,
    SyncRequestBody, SyncSemantics, SyncStreamPosition, SyncTimeline, SyncTokenBinding,
    SyncUpdates, TimelineFilter, TimelineOrderKey, ToDeviceAck, ToDeviceAckStatus, ToDeviceMessage,
    WaitForFrontier, sync_filter_digest,
};
// `SyncOutcome` is the wire-shape projection in [`models::api`]; the typed
// per-event helpers above (SyncRealm, ToDeviceMessage, AccountData,
// NotificationDelta, PresenceEvent, DeviceListChanges, UnreadCounts,
// SyncTimeline) are typed views that consumers parse per-field from the
// loose `BTreeMap<String, Value>` / `Vec<Value>` carried by the wire
// type. `pub use models::*;` re-exports `SyncOutcome` at the crate root.
