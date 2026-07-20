//! Unified Arkret v1 protocol-model surface.
//!
//! This crate is a pure aggregation and documentation boundary. Protocol
//! definitions remain owned by the five consumer-profile model crates. SDK
//! implementation crates must depend on those owners directly instead of
//! depending on this aggregate.

/// Collaboration, governance, event, sync, and federation wire models.
pub use arkret_models_collaboration as collaboration;
/// Cryptographic envelope, key-distribution, backup, and MLS wire models.
pub use arkret_models_crypto as crypto;
/// Service-description, capability-advertisement, and discovery wire models.
pub use arkret_models_discovery as discovery;
/// Identity, account, device, DID-continuity, and handle wire models.
pub use arkret_models_identity as identity;
/// Push, webhook, applet, and external-integration wire models.
pub use arkret_models_integration as integration;
