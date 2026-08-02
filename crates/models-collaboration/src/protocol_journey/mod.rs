//! Strongly typed counterparts of `protocol-journey-wire.schema.json`.
//!
//! These models are deliberately closed. Product crates must consume them
//! instead of rebuilding protocol DTOs with `serde_json::Value`.

mod attestation;
mod bootstrap_contact;
mod history;
mod operation_control;
mod participation_sidecar;

pub use arkret_wire::{ProtocolOpaqueId, ProtocolOperationId, ProtocolSignature};
pub use attestation::*;
pub use bootstrap_contact::*;
pub use history::*;
pub use operation_control::*;
pub use participation_sidecar::*;

macro_rules! string_marker {
    ($name:ident, $variant:ident, $wire:literal) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
        pub enum $name {
            #[serde(rename = $wire)]
            $variant,
        }
    };
}

pub(crate) use string_marker;
