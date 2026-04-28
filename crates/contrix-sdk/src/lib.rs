//! Contrix v1 Rust SDK.
//!
//! This crate exposes Contrix protocol concepts directly. The source of truth
//! is signed Events / Operations in append-only Repos; Views are derived
//! projections.

pub mod account;
pub mod base;
pub mod canonical;
#[cfg(feature = "client")]
pub mod client;
pub mod authz;
pub mod cursor;
pub mod error;
pub mod hlc;
#[cfg(feature = "mls")]
pub mod mls;
pub mod model;
pub mod resolver;
pub mod service;
pub mod space;
pub mod store;
pub mod sync;
pub mod timeline;
pub mod presence;

pub use authz::{
    AuthzContext, AuthzDecision, AuthzEngine, CapabilityGrant, ClaimRequirement,
    Constraint, ConstraintDuration, ConstraintEffect, ConstraintEntry, FieldScope,
    RateLimitScope, Recurrence, Resource, ResourceSelector,
};
pub use account::AccountDataManager;
pub use base::{BaseClient, ClientSpace, SessionMeta, SpaceStateType};
#[cfg(feature = "client")]
pub use client::{Auth, Client, ClientBuilder};
pub use cursor::{Cursor, SpacePosition, SyncPositions, SyncTracker};
pub use error::{Error, Result};
pub use hlc::{compare_hlc, is_clock_skew_acceptable, parse_hlc, time_until_hlc, validate_hlc_format, HlcComponents, HlcGenerator};
#[cfg(feature = "mls")]
pub use mls::*;
pub use model::*;
pub use resolver::{SpaceState, StateSnapshot};
pub use service::{ServiceRequirements, ServiceType};
pub use space::Space;
pub use store::{MemoryRepoStore, RepoStore};
pub use sync::{
    BackfillDirection, BackfillFrom, BackfillRequest, BackfillResponse, PresenceStatus,
    SpaceSubscription, SpaceUpdate, SubscriptionConfig, SyncClient, SyncFilter, SyncRequest,
    SyncResponse, SyncUpdates, TimelineFilter,
};
pub use timeline::{Timeline, TimelineDirection, TimelineEvent, TimelineFrom, TimelineGap, TimelineOptions};
pub use presence::{Presence, PresenceManager};
