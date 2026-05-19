//! Core Contrix v1 protocol types and helpers.
//!
//! This crate is the stable foundation shared by clients, servers and higher
//! level SDK state machines. It intentionally contains no HTTP transport,
//! framework adapter or runtime state manager.

pub mod admin_signer;
pub mod anchor;
pub mod anchorer;
pub mod bottom;
pub mod canonical;
pub mod cell;
pub mod cursor;
pub mod error;
pub mod events;
pub mod generated;
pub mod http;
pub mod keystore;
pub mod lattice;
pub mod model;
pub mod move_event;
pub mod operations;
pub mod schema;
pub mod service;
pub mod signer;
pub mod snapshot;
pub mod state;
pub mod sync;

pub use admin_signer::{AdminKeyStore, SessionGrantIntrospection, admin_scopes};
pub use anchor::{
    ANCHOR_SIGNATURE_ALGS, Anchor, AnchorKind, AnchorerSig, MultiSigKind, MultiSignature,
    ThresholdSigKind, ThresholdSignature,
};
pub use anchorer::AnchorerValue;
pub use bottom::{AnchorView, Bottom, BottomKind};
pub use cell::{CellId, composite_subject, composite_subject_pipe};
pub use contrix_identifiers as identifiers;
pub use cursor::{Cursor, CursorPurpose, CursorTarget, SpacePosition, SyncPositions, SyncTracker};
pub use error::{
    ERROR_CODE_AAD_DIGEST_MISMATCH, ERROR_CODE_ANCHORER_RECOVERY_MISSING,
    ERROR_CODE_AUDIT_RECEIPT_INVALIDATED, ERROR_CODE_AUTH_EXPIRED, ERROR_CODE_BAD_JSON,
    ERROR_CODE_BAD_QUERY, ERROR_CODE_CAPABILITY_DENIED, ERROR_CODE_CAS_CONFLICT,
    ERROR_CODE_CAUSAL_CONFLICT, ERROR_CODE_CLAIM_REQUIRED, ERROR_CODE_CONFLICT,
    ERROR_CODE_CURSOR_EXPIRED, ERROR_CODE_DEPENDENCY_MISSING, ERROR_CODE_DIGEST_MISMATCH,
    ERROR_CODE_DISCUSSION_TRACK_DISABLED, ERROR_CODE_DUPLICATE_CONFLICT, ERROR_CODE_EPOCH_MISMATCH,
    ERROR_CODE_HLC_LOGICAL_OVERFLOW, ERROR_CODE_INTERNAL_ERROR, ERROR_CODE_INVALID_PARAM,
    ERROR_CODE_INVALID_SIGNATURE, ERROR_CODE_KEY_UNAVAILABLE, ERROR_CODE_METHOD_NOT_ALLOWED,
    ERROR_CODE_MISSING_PARAM, ERROR_CODE_NOT_FOUND, ERROR_CODE_PAYLOAD_DIGEST_MISMATCH,
    ERROR_CODE_PAYLOAD_TOO_LARGE, ERROR_CODE_POLICY_COMBINATION_INVALID,
    ERROR_CODE_POLICY_VIOLATION, ERROR_CODE_PROJECTION_INCOMPLETE, ERROR_CODE_QUOTA_EXCEEDED,
    ERROR_CODE_RANK_EXHAUSTED, ERROR_CODE_RATE_LIMITED, ERROR_CODE_SCHEMA_VIOLATION,
    ERROR_CODE_SOFT_LOGGED_OUT, ERROR_CODE_SPACE_FROZEN, ERROR_CODE_STALE_FRONTIER,
    ERROR_CODE_STATE_MISMATCH, ERROR_CODE_SYNC_TOKEN_EXPIRED, ERROR_CODE_TEMPORARILY_UNAVAILABLE,
    ERROR_CODE_TIMEOUT, ERROR_CODE_UNAUTHENTICATED, ERROR_CODE_UNKNOWN_DID,
    ERROR_CODE_UNRECOGNIZED_ENDPOINT, ERROR_CODE_UNSUPPORTED_EVENT_KIND,
    ERROR_CODE_UNSUPPORTED_FEATURE, ERROR_CODE_UNSUPPORTED_LATTICE_TYPE, Error, KNOWN_ERROR_CODES,
    Result, error_code_http_status, is_known_error_code,
};
pub use http::*;
pub use identifiers::{
    ActorProfileId, AgentSessionId, AgentTaskId, AnchorId, AppletId, BackupId, BatchId, BlobId,
    BlobRef, BlockId, CallId, CapabilityId, CellRef, ChunkId, ClaimId, DeviceId, DevmsgId, Did,
    EventId, FilterId, FlowId, FrameId, FrankId, GrantId, Hash, Hlc, InviteId, KeyevtId, MessageId,
    ModqId, MorphId, MoveId, NotifId, OperationId, PlaceId, PolicyId, PresentationId, ReceiptId,
    RelationId, ReportId, ReqId, SnapshotId, SpaceId, TxnId, ViewId,
};
pub use keystore::{
    InMemoryKeyStore, KeyStore, KeyStoreError, LinuxSecretServiceKeyStore, MacOsKeychainKeyStore,
    WindowsCredentialKeyStore, platform_default_keystore,
};
pub use model::*;
pub use move_event::{
    Effect, LatticeOp, LatticeOpType, MOVE_SIGNATURE_ALGS, Move, MoveSignature, Precondition,
    Predicate, PredicateOp, SemanticRef,
};
pub use service::{
    ApiConventionMetadata, HttpTraceMetadata, NotFoundPrivacy, QuotaKind, QuotaMetadata,
    RateLimitMetadata, RateLimitScopeKind, ServiceDidAllowlist, ServiceEndpointBinding,
    ServiceRequirements, ServiceType, privacy_preserving_not_found, quota_exceeded_error,
    rate_limited_error,
};
pub use signer::{MoveSigner, PartialSignature, ThresholdAggregator, UnsignedMove};
pub use snapshot::{
    DEFAULT_SNAPSHOT_CHUNK_BYTES, GeneratorProof, SnapshotChunk, SnapshotChunker,
    SnapshotMerkleTree,
};
pub use state::{
    AnchorEffect, AnchorReject, AnchorStore, AnchoredMoveRecord, BottomMode, CellLatticeBinding,
    CellRegistry, CellStore, CompactionPolicy, MemoryAnchorStore, MemoryCellRegistry,
    MemoryCellStore, MemoryMoveStore, MoveReject, MoveRejectMap, MoveStore, PruneCandidate,
    PruneEligibility, StoreError, StoreResult, apply_anchor, compute_state_root,
    deterministic_order, effective_anchor_view, leaf_hash, reject_to_error_code,
    union_predecessor_frontiers, verify_move, view_hash,
};
pub use sync::{
    AccountData, BackfillDirection, BackfillFrom, BackfillReqBody, BackfillResBody,
    BucketedSpaceUpdate, DeviceListChanges, LimitedTimelineState, MembershipBucket,
    NotificationDelta, PresenceEvent, PresenceStatus, SpaceSubscription, SpaceUpdate,
    SubscriptionConfig, SyncClient, SyncFilter, SyncGap, SyncGapReason, SyncMode, SyncReqBody,
    SyncResBody, SyncSemantics, SyncSpace, SyncStreamPosition, SyncTimeline, SyncTokenBinding,
    SyncUpdates, TimelineFilter, TimelineOrderKey, ToDeviceAck, ToDeviceAckStatus, ToDeviceMessage,
    WaitForFrontier, sync_filter_hash,
};
