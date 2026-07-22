use super::*;

mod events_operations;
mod objects_field_order;
mod proofs_signatures;

// Shared helper used by multiple submodules.
pub(crate) fn test_realm_id() -> RealmId {
    RealmId::new("ak:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap()
}
