//! Account-subscribe frame family re-exports.
//!
//! The frame / validated-batch result types live in
//! `arkret-models-collaboration` (`sync_frames::account_subscribe`),
//! re-exported here for `arkret_core::` path stability. The client-side
//! `AccountSubscribeFolder`
//! consumption state machine moved to the transport crate
//! (`arkret-http-client`), which owns the client `Error` channel it folds
//! frames through.

pub use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeBatch, AccountSubscribeReconnectAfter, AccountSubscribeSnapshotResult,
    DEFAULT_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS, MAX_ACCOUNT_SUBSCRIBE_RECONNECT_AFTER_MS,
};
