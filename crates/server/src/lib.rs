//! Server-side protocol contract types.
//!
//! This module is intentionally framework-free. HTTP servers can use these
//! contracts without pulling a web stack into the SDK.

pub use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeFrame, AccountSubscribeFrameKind, AccountSubscribeRealms,
};
pub use arkret_signatures as signatures;

pub mod applet;
pub mod authorization;
pub mod cursor_authority;
pub mod idempotency;
mod registry;
pub mod rejection;
#[cfg(test)]
mod tests;

pub use applet::AppletHandler;
pub use arkret_rate_limit::{FixedWindowConfig, MemoryFixedWindowRateLimiter, RateLimitRejection};
pub use authorization::{
    AuthorizationCredential, AuthorizationHeaderError, AuthorizationScheme,
    authorization_credential, parse_authorization,
};
pub use cursor_authority::{
    CursorAuthority, CursorAuthorityError, CursorBindingContext, CursorBindingRecord,
    MemoryCursorAuthority, cursor_filter_digest,
};
pub use idempotency::{
    IdempotencyClaim, IdempotencyDirection, IdempotencyIdentity, IdempotencyWindow,
    TransactionClaim, TransactionIdempotencyStore,
};
pub use registry::reject_query_auth;
pub use rejection::ProtocolRejection;
