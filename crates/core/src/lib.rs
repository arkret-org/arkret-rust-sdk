//! Core Contrix v1 protocol types and helpers.
//!
//! This crate is the stable foundation shared by clients, servers and higher
//! level SDK state machines. It intentionally contains no HTTP transport,
//! framework adapter or runtime state manager.

pub mod canonical;
pub mod cursor;
pub mod error;
pub mod model;
pub mod service;
pub mod sync;

pub use cursor::{Cursor, SpacePosition, SyncPositions, SyncTracker};
pub use error::{Error, Result};
pub use model::*;
pub use service::{
    ApiConventionMetadata, HttpTraceMetadata, NotFoundPrivacy, QuotaKind, QuotaMetadata,
    RateLimitMetadata, RateLimitScopeKind, ServiceDidAllowlist, ServiceEndpointBinding,
    ServiceRequirements, ServiceType, privacy_preserving_not_found, quota_exceeded_error,
    rate_limited_error,
};
pub use sync::{
    AccountData, BackfillDirection, BackfillFrom, BackfillRequest, BackfillResponse,
    BucketedSpaceUpdate, DeviceListChanges, LimitedTimelineState, MembershipBucket,
    NotificationDelta, PresenceEvent, PresenceStatus, SpaceSubscription, SpaceUpdate,
    SubscriptionConfig, SyncClient, SyncFilter, SyncGap, SyncGapReason, SyncMode, SyncRequest,
    SyncResponse, SyncSemantics, SyncSpace, SyncStreamPosition, SyncTimeline, SyncTokenBinding,
    SyncUpdates, TimelineFilter, TimelineOrderKey, ToDeviceAck, ToDeviceAckStatus, ToDeviceMessage,
    WaitForFrontier, sync_filter_hash,
};
