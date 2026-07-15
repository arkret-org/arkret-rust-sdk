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

#[cfg(test)]
use crate::AccountSubscribeFrame;
use crate::sync::{
    LimitedTimelineState, MembershipBucket, RealmSubscription, RealmUpdate, SubscriptionConfig,
    SyncFilter, SyncRequestBody, SyncUpdates, TimelineFilter, TimelineOrderKey, ToDeviceAck,
    ToDeviceAckStatus, WaitForFrontier,
};
use crate::{
    AccountStreamInterrupt, AccountSubscribeBatch, AccountSubscribeDeviceListChanges,
    AccountSubscribeFrameKind, AccountSubscribeRealmSummary, DeviceId, DeviceMessageEnvelope, Did,
    Error, Event, EventId, NotificationDelta, NotificationDeltaAction, RealmId, Result, Timeline,
    canonical,
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
