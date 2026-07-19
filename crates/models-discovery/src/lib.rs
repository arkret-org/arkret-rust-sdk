//! Arkret v1 service description, capability advertisement, and discovery models.
//!
//! Owner of the service-discovery wire shapes consumed by directory
//! services (teabay) and client bootstrap. HTTP discovery, caching, and
//! profile enforcement live with their behavior owners; this crate holds
//! data shapes and type-local invariants only.

pub mod ops;
pub mod service_description;

pub use ops::*;
pub use service_description::*;
