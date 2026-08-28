//! Arkret v1 service description, capability advertisement, and discovery models.
//!
//! Owner of the service-discovery wire shapes consumed by directory
//! services (teabay) and client bootstrap. HTTP discovery, caching, and
//! profile enforcement live with their behavior owners; this crate holds
//! data shapes and type-local invariants only.

pub mod directory;
pub mod directory_artifacts;
pub mod http_bodies;
pub mod ops;
pub mod presence;
pub mod service_description;
pub mod service_requirements;
pub mod verified_profiles;
pub mod websocket_binding;

pub use directory::*;
pub use directory_artifacts::*;
pub use http_bodies::*;
pub use ops::*;
pub use presence::*;
pub use service_description::*;
pub use service_requirements::*;
pub use verified_profiles::*;
pub use websocket_binding::{
    WebSocketBindingAuthentication, WebSocketBindingProfile, WebSocketBindingSubprotocol,
    select_websocket_binding, validate_websocket_transport, websocket_operations_reachable,
};
