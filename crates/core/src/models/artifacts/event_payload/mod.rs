//! Event payload schema artifact counterparts.
//!
//! The payload counterpart submodules migrated to
//! `arkret-models-collaboration` (`events_payloads`); every public item is
//! re-exported here so the canonical path
//! `crate::models::artifacts::event_payload::Name` is preserved. The
//! applet-domain payloads are re-exported from their integration owner.

mod account_misc {
    pub use arkret_models_collaboration::events_payloads::account_misc::*;
}
mod agent {
    pub use arkret_models_collaboration::events_payloads::agent::*;
}
mod call {
    pub use arkret_models_collaboration::events_payloads::call::*;
}
mod capability_circle_consent_contact {
    pub use arkret_models_collaboration::events_payloads::capability_circle_consent_contact::*;
}
mod device_identity {
    pub use arkret_models_collaboration::events_payloads::device_identity::*;
}
mod list_message_mimi_mls {
    pub use arkret_models_collaboration::events_payloads::list_message_mimi_mls::*;
}
mod moderation_morph_misc {
    pub use arkret_models_collaboration::events_payloads::moderation_morph_misc::*;
}
mod preview_realm_reaction {
    pub use arkret_models_collaboration::events_payloads::preview_realm_reaction::*;
}
mod strand_history_join {
    pub use arkret_models_collaboration::events_payloads::strand_history_join::*;
}
mod applet_audit;

pub use account_misc::*;
pub use agent::*;
pub use applet_audit::*;
pub use call::*;
pub use capability_circle_consent_contact::*;
pub use device_identity::*;
pub use list_message_mimi_mls::*;
pub use moderation_morph_misc::*;
pub use preview_realm_reaction::*;
pub use strand_history_join::*;
