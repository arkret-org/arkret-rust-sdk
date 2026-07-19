//! Generated counterparts for v1 JSON Schema artifact names that do not
//! have a more specific canonical model module.
//!
//! Concrete OpenAPI body DTOs and stable protocol resources live in sibling
//! domain modules such as `api`, `operation_payloads`, `objects`, and
//! `registry`. These modules keep remaining artifact-local schema names
//! addressable from `arkret-core` while reusing those canonical SDK types
//! where possible; open extension fields remain `serde_json::Value` or
//! `BTreeMap<String, Value>` where the schema explicitly permits arbitrary
//! JSON.

use super::*;

mod account {
    pub use arkret_models_identity::artifacts_account::*;
}
mod account_sync;
mod agent;
mod applet;
mod authorization;
mod blob;
mod contact_directory;
mod device_identity;
mod event_payload;
mod event_wire;
mod interop;
mod keys;
mod moderation;
mod object_facets;
mod push;
mod self_ops;
mod service;
mod sync;
mod view;

pub use account::*;
pub use account_sync::*;
pub use agent::*;
pub use applet::*;
pub use authorization::*;
pub use blob::*;
pub use contact_directory::*;
pub use device_identity::*;
pub use event_payload::*;
pub use event_wire::*;
pub use interop::*;
pub use keys::*;
pub use moderation::*;
pub use object_facets::*;
pub use push::*;
pub use self_ops::*;
pub use service::*;
pub use sync::*;
pub use view::*;
