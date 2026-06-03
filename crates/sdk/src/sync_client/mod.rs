//! Stateful sync client utilities.
//!
//! The protocol types live in [`crate::sync`]. This module adds the client-side
//! control plane: retry/backoff state, response processing and sliding-window
//! subscription helpers.

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    DeviceId, Error, Event, EventId, RealmId, Result, SyncResBody, canonical,
    sync::{
        AccountData, DeviceListChanges, LimitedTimelineState, MembershipBucket, NotificationDelta,
        PresenceEvent, PresenceStatus, SpaceSubscription, SpaceUpdate, SubscriptionConfig,
        SyncFilter, SyncReqBody, SyncSpace, SyncTimeline, SyncUpdates, TimelineFilter,
        TimelineOrderKey, ToDeviceAck, ToDeviceAckStatus, ToDeviceMessage, WaitForFrontier,
        project_typed_vec, project_typed_vec_from_value,
    },
};

mod loop_control;
mod processor;
mod send_queue;
mod space_list;
#[cfg(test)]
mod tests;
mod wire;

pub use loop_control::*;
pub use processor::*;
pub use send_queue::*;
pub use space_list::*;
pub use wire::*;
