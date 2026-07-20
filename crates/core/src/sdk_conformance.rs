//! SDK conformance claim wire types and validation.
//!
//! The conformance claim family (claim, build variants, clause claims,
//! evidence, proof algorithms) and its structural / binding / signing
//! validation migrated to `arkret_schema::sdk_conformance` and are
//! re-exported here transitionally so `arkret_core::<T>` paths stay stable.

pub use arkret_schema::sdk_conformance::*;
