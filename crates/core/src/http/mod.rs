//! Salvo OpenAPI-facing HTTP DTOs for the Arkret service binding.
//!
//! These types model endpoint transport roles explicitly:
//! - path, query-string and header inputs are grouped as `<Operation>Params`;
//! - JSON request bodies are `<Operation>RequestBody`;
//! - successful responses are `<Operation>Outcome`.

mod bodies;
mod params;
mod paths;

#[cfg(test)]
mod tests;

// Wire envelope moved to `arkret-wire`; re-exported here until the core
// facade retires (phase 5).
pub use arkret_wire::HttpMessageSignature;
pub use bodies::*;
pub use params::*;
pub use paths::*;
