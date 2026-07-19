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
mod account_sync {
    //! The sync-frame containers migrated to `arkret-models-collaboration`
    //! (`sync_frames::account_sync`, re-exported below). The
    //! account-operations aggregation stays: it composes the core account
    //! HTTP body DTOs.

    pub use arkret_models_collaboration::sync_frames::account_sync::*;

    use super::*;

    /// Counterpart for `spec/v1/artifacts/schemas/account-operations.schema.json`.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(untagged)]
    pub enum AccountOperations {
        AccountView(AccountView),
        AccountHandoffRequestBody(AccountHandoffRequestBody),
        AccountHandoffOutcome(AccountHandoffOutcome),
        IdentityBindingChallengeRequestBody(IdentityBindingChallengeRequestBody),
        IdentityBindingChallengeOutcome(IdentityBindingChallengeOutcome),
        AccountRegisterRequestBody(AccountRegisterRequestBody),
        AccountRegisterOutcome(AccountRegisterOutcome),
        AccountUpdateProfileRequestBody(AccountUpdateProfileRequestBody),
        AccountUpdateProfileOutcome(AccountUpdateProfileOutcome),
        SessionRevokeRequestBody(SessionRevokeRequestBody),
        SessionRevokeOutcome(SessionRevokeOutcome),
    }

    /// Counterpart for
    /// `spec/v1/artifacts/schemas/account-operations.schema.json#/$defs/profile_patch`.
    pub type ProfilePatch = Patch;
}
mod agent;
mod applet;
mod authorization;
mod blob;
mod contact_directory;
mod device_identity;
mod event_payload;
mod event_wire {
    pub use arkret_models_collaboration::events_payloads::event_wire::*;
}
mod interop;
mod keys;
mod moderation {
    pub use arkret_models_collaboration::events_payloads::moderation::*;
}
mod object_facets {
    pub use arkret_models_collaboration::objects::object_facets::*;
}
mod push;
mod self_ops;
mod service;
mod sync {
    pub use arkret_models_collaboration::sync_frames::snapshot::*;
}
mod view {
    pub use arkret_models_collaboration::objects::view::*;
}

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
