//! Governance wire shapes: realm governance payloads, circle boundary
//! types, invite addressing and delivery, moderation, grant constraints,
//! capability wire records, and member delivery bindings. Receive-policy
//! and plaintext-classification shapes live in `arkret-wire`
//! (cross-domain: consumed by governance invite processing and discovery
//! service descriptions).

pub mod accountability;
pub mod agent_artifacts;
pub mod agent_membership_cascade;
pub mod agent_participation;
pub mod audit;
pub mod authorization;
pub mod circle;
pub mod erasure;
pub mod grant_constraint;
pub mod invite_addressing;
pub mod join_policy;
pub mod member_delivery_binding_candidate;
pub mod membership_invite;
pub mod moderation;
pub mod moderation_appeal;
pub mod moderation_queue;
pub mod operation_wire;
pub mod peer_contact;
pub mod plaintext_visibility;
pub mod policy_check;
pub mod realm_governance;
pub mod realm_lifecycle;
pub mod third_party_invite;
