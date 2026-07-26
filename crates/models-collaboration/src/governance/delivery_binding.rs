//! Delivery-binding wire shapes relocated to `arkret-models-identity`.
//!
//! `RecipientServiceKind`, `DeliveryMode`, `MemberDeliveryBinding`, and the
//! rest of the per-Realm delivery-binding vocabulary moved to the identity /
//! delivery domain so both `arkret-models-discovery` (directory user-search
//! outcomes) and this crate can reach them without a discovery -> collab
//! edge. Re-exported here so the historical
//! `governance::delivery_binding::*` path stays stable.

pub use arkret_models_identity::delivery_binding::*;
