//! Arkret v1 push gateway, webhook, applet, and external integration
//! exchange models.
//!
//! Owner of the edge interaction wire shapes consumed by push gateways
//! (floria), gateway clients (chime), applet services / bridges, and
//! integration services. Behavior (blind-payload sanitization, push-rule
//! evaluation) lives in `arkret-policy`; behavior that needs schema
//! validation, state reduction, or signature verification lives in
//! the `arkret` umbrella. This crate holds data shapes and type-local
//! invariants only.

pub mod applet;
pub mod applet_audit_payload;
pub mod applet_install_plan;
pub mod applet_models;
pub mod artifacts_applet;
pub mod integration;
pub mod managed_actor_resolution_update;
pub mod management_review;
pub mod models_push;
pub mod push;
pub mod push_vocab;

pub use applet::*;
pub use applet_audit_payload::*;
pub use applet_install_plan::*;
pub use applet_models::*;
pub use arkret_wire::PushTargetId;
pub use artifacts_applet::*;
pub use integration::*;
pub use managed_actor_resolution_update::*;
pub use management_review::*;
pub use models_push::*;
pub use push::*;
pub use push_vocab::*;
