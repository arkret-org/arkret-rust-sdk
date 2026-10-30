//! Pure HTTP carriers shared by independently deployed products.
//!
//! This crate owns no database, key store, service runtime, or business handler.
//! Its private HTTP contracts are not canonical Arkret operations or evidence.

pub mod account_projection;
pub mod admin;
pub mod agent_session_authority;

pub use account_projection::*;
