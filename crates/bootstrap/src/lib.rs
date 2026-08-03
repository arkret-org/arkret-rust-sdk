//! Arkret bootstrap: the closed genesis units a Realm may be created with.
//!
//! Three branches share one derivation path — the self-principal PCR bootstrap
//! unit ([`self_principal`]), its device-signed Seals ([`self_principal_seal`]),
//! and the controller-delegated managed Agent PCR ([`managed_agent`]) — plus
//! the controller-owned provisioning drafts ([`agent_provision`]). Everything a
//! bootstrap Event writes comes from the injected
//! [`CellWriteProjector`][projection::CellWriteProjector]; see [`projection`]
//! for why the evaluator is injected rather than linked.

mod agent_provision;
mod managed_agent;
mod projection;
mod self_principal;
mod self_principal_seal;
#[cfg(test)]
mod tests;

pub use agent_provision::{
    AgentProvisionEventDraftOptions, AgentProvisionEventDrafts, build_agent_provision_event_drafts,
};
pub use managed_agent::{
    ManagedAgentPcrControlMaterial, ManagedAgentPcrGenesisAuthority,
    build_managed_agent_pcr_event_seal, materialize_managed_agent_pcr_control,
};
pub use projection::{CellWriteProjector, expected_realm_create_cells};
pub use self_principal::{
    SelfPrincipalPcrCreateInput, build_self_principal_pcr_create,
    self_principal_bootstrap_submit_request, validate_self_principal_bootstrap_unit,
};
pub use self_principal_seal::{
    build_self_principal_bootstrap_seal, build_self_principal_event_seal,
    build_self_principal_first_successor_seal, build_self_principal_linear_successor_seal,
};

pub const DID_INCEPTION_REF_ROLE: &str = "did_inception";

// The Realm role markers are owned by the Realm model, next to the sibling
// Direct Conversation role constants, so the profile id and the `purpose`
// discriminator are each spelled exactly once in the SDK. Re-exported here
// because this crate's public bootstrap API has always carried the profile id.
pub use arkret_models_collaboration::objects::realm::PRINCIPAL_CONTROL_PURPOSE;
// The canonical `cell_subject: null` cell ids live in `arkret_wire::cell`, the
// lowest crate that owns cell identity, so every consumer (this crate, soland's
// reducer and its HTTP proof path) spells them once. The Realm role
// classification (`principal_control`, `collaboration`, ...) is a prose term
// only (`models/realm-and-space.md` section 2.8.3) and MUST NOT appear in a cell
// id: doing so both forks the `state_root` leaf set and turns the per-Realm
// genesis singleton into a deployment-wide shared key.
pub use arkret_wire::{
    REALM_AUTHORITY_ROOT_CELL, REALM_CREATE_CELL, REALM_METADATA_CELL, REALM_NOTARY_CELL,
    REALM_REDUCER_PROFILE_CELL,
};
