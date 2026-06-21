//! Core Cokret v1 protocol types and helpers.
//!
//! This crate is the stable foundation shared by clients, servers and higher
//! level SDK state machines. It intentionally contains no HTTP transport,
//! framework adapter or runtime state manager.

pub mod admin_signer;
pub mod base64url;
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
pub mod integration;
pub mod keystore;
pub mod lattice;
pub mod models;
pub mod move_event;
pub mod multibase;
pub mod notary;
pub mod operations;
pub mod ops;
pub mod platform;
pub mod profile_claim;
pub mod push;
pub mod push_rule_core;
pub mod schema;
pub mod seal;
pub mod service;
pub mod signer;
pub mod snapshot;
pub mod state;
pub mod sync;

pub use admin_signer::{AdminKeyStore, SessionGrantIntrospection, admin_scopes};
pub use base64url::{
    base64_standard_decode, base64_standard_encode, base64url_decode, base64url_encode,
};
pub use blind_payload_sanitizer::{
    ALLOWED_BLIND_FIELDS, ALLOWED_PUSH_HINTS, ALLOWED_WAKEUP_KINDS, BlindPayloadError,
    BlindPayloadReasonCode, MAX_COUNT_VALUE, SanitizerMode, is_allowed_blind_field,
    is_forbidden_payload_key, is_valid_custom_wakeup_kind, is_valid_push_hint,
    is_valid_push_target_id, is_valid_wakeup_kind, sanitize_blind_payload,
    sanitize_blind_payload_strict, sanitize_blind_payload_with,
};
pub use bottom::{Bottom, BottomKind, SealView};
pub use cell::{CellId, composite_subject, composite_subject_pipe};
pub use cokret_identifiers as identifiers;
pub use cursor::{Cursor, CursorPurpose, CursorTarget, RealmPosition, SyncPositions, SyncTracker};
pub use error::*;
pub use generated::profiles::{PROFILE_ROLES, ProfileRole, profile_ids_with_role, profile_role};
pub use http::*;
pub use identifiers::{
    ActorProfileId, AgentInteropSessionId, AnnounceId, AppletId, AttestationId, AuditBindingId,
    AuditReleaseId, AuditSessionId, BackupId, BackupSeriesId, BatchId, BlobId, BlobRef, BlockId,
    CallId, CapabilityId, CellRef, ChunkId, CircleId, ClaimId, DeviceId, DeviceMessageId, Did,
    EventId, FilterId, FrameId, FrankingProofId, GrantId, Hash, Hlc, InviteId, KeyEventId,
    MessageId, ModerationQueueItemId, MorphId, MoveId, NotificationId, OperationId, PolicyId,
    PresentationId, ReadCursorId, RealmId, ReceiptId, RecoverySessionId, RelationId, ReportId,
    RequestId, RtcParticipantId, SealId, SnapshotId, SpaceId, StrandId, TransactionId,
    TypedAppealId, TypedTrustDomainId, ViewId,
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
pub use notary::NotaryValue;
pub use platform::{WasmHttpRequestBody, WasmHttpResponseBody};
pub use profile_claim::{ProfileClaim, ProfileClaimError, ProfileClaimKind, ProfileValidator};
pub use seal::{
    MultiSigKind, MultiSignature, NotarySig, SEAL_SIGNATURE_ALGS, Seal, SealKind, ThresholdSigKind,
    ThresholdSignature, compute_seal_id, seal_canonical_bytes,
};
pub use service::{
    ApiConventionMetadata, HttpTraceMetadata, NotFoundPrivacy, QuotaKind, QuotaMetadata,
    RateLimitMetadata, RateLimitScopeKind, ServiceDidAllowlist, ServiceEndpointBinding,
    ServiceRequirements, ServiceType, privacy_preserving_not_found, quota_exceeded_error,
    rate_limited_error,
};
pub use signer::{MoveSigner, PartialSignature, ThresholdAggregator, UnsignedMove};
pub use snapshot::{
    ActorSeqRangeCommitment, AuthorityBinding, BuiltSnapshotChunk, DEFAULT_SNAPSHOT_CHUNK_BYTES,
    DETACHED_JWS_ALG_EDDSA, DETACHED_JWS_PROOF_KIND, DetachedJwsProof, EMPTY_SHA256_DIGEST,
    EVENT_SET_ALGORITHM_MERKLE_V1, EVENT_SET_ALGORITHM_ORDERED_SHA256_V1, EventSetCommitment,
    EventSetCommitmentAlgorithm, EventSetLeaf, GeneratorProof, SNAPSHOT_CHUNK_TYPE,
    SNAPSHOT_MANIFEST_SCHEMA_V1, SNAPSHOT_REDUCER_PROFILE_V1, SNAPSHOT_SECURITY_HIGH_ASSURANCE,
    SNAPSHOT_SECURITY_STANDARD, SNAPSHOT_V1_HIGH_ASSURANCE_MAX_ACCEPTANCE_AGE_MS,
    SNAPSHOT_V1_STANDARD_MAX_ACCEPTANCE_AGE_MS, SnapshotAuthorityKind, SnapshotChunk,
    SnapshotChunkDescriptor, SnapshotChunkPayload, SnapshotChunker, SnapshotFrontier,
    SnapshotManifest, SnapshotMaterializedItem, SnapshotMerkleTree, SnapshotSecurityClass,
    SnapshotValidationCode, SnapshotValidationError, SnapshotVerificationHints,
    SnapshotVerifyOptions, SnapshotVerifyReport, UnsignedSnapshotManifest, build_snapshot_chunks,
    build_snapshot_chunks_with_nonaccepted, event_id_sets_equal, event_set_commitment,
    event_set_root, manifest_frontiers_match, merkle_root_from_hashes,
    parse_verified_snapshot_chunk_bytes, snapshot_chunk_payload_bytes, snapshot_state_leaf_hash,
    state_digest_from_items, verify_snapshot_chunk_bytes, verify_snapshot_chunk_descriptors,
    verify_snapshot_manifest,
};
pub use state::{
    BottomMode, CellLatticeBinding, CellRegistry, CellStore, CompactionPolicy, EMPTY_STATE_ROOT,
    MemoryCellRegistry, MemoryCellStore, MemoryMoveStore, MemorySealStore, MoveReject,
    MoveRejectMap, MoveStore, PruneCandidate, PruneEligibility, SealEffect, SealReject, SealStore,
    SealedMoveRecord, StoreError, StoreResult, apply_seal, compute_state_root, deterministic_order,
    effective_seal_view, leaf_hash, reject_to_error_code, union_predecessor_covered_events,
    verify_move, view_hash,
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
