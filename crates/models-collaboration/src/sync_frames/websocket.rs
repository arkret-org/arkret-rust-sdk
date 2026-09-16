//! WebSocket multiplexing frames for account updates and transient Signals.
//!
//! The socket is a delivery rail only. Durable coordinates remain the
//! independent Realm, Circle, and Sidecar commit-stream references embedded in
//! account frames.

use arkret_wire::{Cursor, FrameId, SignalEnvelope, SubscriptionId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::account_subscribe::{AccountSubscribeFrame, SyncFilter};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSocketSubscribeRequest {
    pub subscription_id: SubscriptionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Cursor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<SyncFilter>,
    #[serde(default)]
    pub include_signals: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WebSocketClientFrame {
    Subscribe {
        request: WebSocketSubscribeRequest,
    },
    Ack {
        subscription_id: SubscriptionId,
        frame_id: FrameId,
    },
    Ping {
        nonce: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WebSocketServerFrame {
    Subscribed {
        subscription_id: SubscriptionId,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
    },
    Account {
        subscription_id: SubscriptionId,
        frame_id: FrameId,
        frame: AccountSubscribeFrame,
    },
    Signal {
        subscription_id: SubscriptionId,
        frame_id: FrameId,
        envelope: SignalEnvelope,
    },
    Reconnect {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        after: Option<Cursor>,
        retry_after_ms: u64,
    },
    Pong {
        nonce: String,
    },
}
