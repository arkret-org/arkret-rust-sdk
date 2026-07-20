//! Handle-claim wire shapes relocated to `arkret-models-identity`.
//!
//! `HandleClaim` and `DeliveryBindingHint` moved to the identity domain
//! alongside the handle vocabulary and delivery-binding types they embed, so
//! `arkret-models-discovery` can host the directory resolution outcomes that
//! carry them. Re-exported here so the historical
//! `governance::handle_claim::*` path stays stable.

pub use arkret_models_identity::handle_claim::*;
