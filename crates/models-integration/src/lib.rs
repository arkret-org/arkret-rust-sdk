//! Arkret v1 push gateway, webhook, and external integration exchange models.
//!
//! Owner of the edge interaction wire shapes consumed by push gateways
//! (floria), gateway clients (chime), and integration services. Behavior
//! (blind-payload sanitization, push-rule evaluation) lives in
//! `arkret-policy`; this crate holds data shapes and type-local
//! invariants only.

pub mod integration;
pub mod models_push;
pub mod push;
pub mod push_vocab;

pub use integration::*;
pub use models_push::*;
pub use push::*;
pub use push_vocab::*;
