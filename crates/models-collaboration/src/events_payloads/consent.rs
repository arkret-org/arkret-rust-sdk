//! Consent event payloads.

use arkret_wire::ConsentScope;

use crate::internal_prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ConsentPeer {
    Actor { actor_id: ActorId },
}

include!("generated/consent_contracts.rs");
