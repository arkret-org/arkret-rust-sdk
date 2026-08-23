//! Arkret v1 session-grant request construction.
//!
//! Depends only on the wire / model / signature data crates; the umbrella
//! `arkret` crate re-exports this surface under `arkret::auth::*`.

mod error;
pub mod session_grant;
pub use error::{AuthError, Result};
