//! Account-subscribe frame shim.
//!
//! The `ak.self.account.stream.subscribe` NDJSON frame family migrated to
//! `arkret-models-collaboration` (`sync_frames::account_subscribe`,
//! re-exported below), together with its fixture conformance coverage.

pub use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountStreamInterrupt, AccountSubscribeFrame, AccountSubscribeFrameKind,
    AccountSubscribeRealms,
};
