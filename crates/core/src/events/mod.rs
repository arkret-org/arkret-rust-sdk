//! Cokret-native event taxonomy, reaction helpers, and redaction helpers.
//!
//! Rich text parsing/sanitizing lives in the `cokret-html` crate, which is
//! the single authoritative implementation.

pub mod kinds;
pub mod reaction;
pub mod redaction;

pub use kinds::*;
pub use reaction::*;
pub use redaction::*;

pub use crate::models::Event as RawEvent;
