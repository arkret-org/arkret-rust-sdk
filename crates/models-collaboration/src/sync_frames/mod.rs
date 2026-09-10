//! Sync and subscription frame wire models.
//!
//! Client sync request/filter/subscription/backfill shapes, the
//! account-subscribe NDJSON frame family and its validated batch results,
//! the shared stream-trace sequence validator, account-subscribe frame
//! containers, and snapshot/range-attestation artifact counterparts.

pub mod account_subscribe;
pub mod account_sync;
pub mod client_sync;
pub mod current_results;
pub mod demand_sync;
pub mod realm_state_snapshot;
pub mod stream_trace;
pub mod websocket_binding;
pub mod websocket_session;
