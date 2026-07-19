//! Governance wire shapes: realm governance payloads, circle boundary
//! types, invite addressing and delivery, moderation, grant constraints,
//! capability wire records, and member delivery bindings. Receive-policy
//! and plaintext-classification shapes live in `arkret-wire`
//! (cross-domain: consumed by governance invite processing and discovery
//! service descriptions).

pub mod agent_participation;
pub mod audit;
pub mod circle;
pub mod delivery_binding;
pub mod erasure;
pub mod grant_constraint;
pub mod handle_claim;
pub mod history_visibility;
pub mod invite_addressing;
pub mod member_delivery_binding_candidate;
pub mod membership_invite;
pub mod moderation;
pub mod moderation_appeal;
pub mod moderation_queue;
pub mod operation_wire;
pub mod plaintext_visibility;
pub mod realm_governance;
pub mod realm_lifecycle;
pub mod resource_selector;
pub mod third_party_invite;
