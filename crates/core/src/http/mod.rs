//! Salvo OpenAPI-facing HTTP DTOs for the Cokret service binding.
//!
//! These types model endpoint transport roles explicitly:
//! - path, query-string and header inputs are grouped as `<Operation>Params`;
//! - JSON request bodies are `<Operation>RequestBody`;
//! - successful responses are `<Operation>Outcome`.

mod bodies;
mod params;
mod paths;
mod signature;

#[cfg(test)]
mod tests;

pub use bodies::*;
pub use params::*;
pub use paths::*;
pub use signature::*;
