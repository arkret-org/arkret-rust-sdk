//! Stateful sync client utilities.
//!
//! The protocol types live in [`crate::sync`]. This module adds the client-side
//! control plane: retry/backoff state, response processing and sliding-window
//! subscription helpers.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::sync::{
    AccountData, DeviceListChanges, LimitedTimelineState, MembershipBucket, PresenceEvent,
    RealmSubscription, RealmUpdate, SubscriptionConfig, SyncFilter, SyncRealm, SyncRequestBody,
    SyncTimeline, SyncUpdates, TimelineFilter, TimelineOrderKey, ToDeviceAck, ToDeviceAckStatus,
    ToDeviceMessage, WaitForFrontier, project_typed_vec,
};
use crate::{
    AccountStreamInterrupt, DeviceId, Error, Event, EventId, NotificationDelta,
    NotificationDeltaAction, RealmId, Result, SyncOutcome, canonical,
};

mod loop_control;
mod processor;
mod realm_list;
mod send_queue;
#[cfg(test)]
mod tests;

pub use loop_control::*;
pub use processor::*;
pub use realm_list::*;
pub use send_queue::*;
