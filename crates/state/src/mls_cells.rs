//! Canonical MLS group cell identifiers.

use arkret_identifiers::CellRef;
use arkret_wire::{ScopeRef, WireError};

pub const MLS_EPOCH_CELL_FAMILY: &str = arkret_wire::CellFamilyId::MLS_EPOCH_V1;
pub const KEY_SCHEDULE_CELL_FAMILY: &str = arkret_wire::CellFamilyId::MLS_KEY_SCHEDULE_V1;

/// Cell id of the winning epoch register for `scope`.
///
/// `event-kind-registry.json` declares the `cell_subject` of both
/// `ak.component.mls.epoch.v1` and `ak.component.mls.key_schedule.v1` as
/// `composite([select(effective_scope.kind -> realm_id | circle_id |
/// sidecar_id), payload.mls_group_id])`. Addressing either family by the bare
/// group id produces a cell that no reducer ever writes.
pub fn mls_epoch_cell_id(scope: &ScopeRef, mls_group_id: &str) -> Result<CellRef, WireError> {
    group_cell_id(MLS_EPOCH_CELL_FAMILY, scope, mls_group_id, "mls_epoch")
}

/// Cell id of the key-schedule register for `scope`. See
/// [`mls_epoch_cell_id`] for the subject derivation.
pub fn key_schedule_cell_id(scope: &ScopeRef, mls_group_id: &str) -> Result<CellRef, WireError> {
    group_cell_id(
        KEY_SCHEDULE_CELL_FAMILY,
        scope,
        mls_group_id,
        "key_schedule",
    )
}

fn group_cell_id(
    family: &str,
    scope: &ScopeRef,
    mls_group_id: &str,
    label: &str,
) -> Result<CellRef, WireError> {
    let canonical_group_id = scope
        .canonical_mls_group_id()
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    if mls_group_id != canonical_group_id {
        return Err(WireError::Protocol(format!(
            "{label} cell scope does not derive the supplied mls_group_id"
        )));
    }
    let scope_id = scope
        .cell_subject_scope_id()
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    let subject = arkret_wire::cell::composite_subject(&[scope_id, mls_group_id])
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    CellRef::new(arkret_wire::subject_cell(family, &subject))
        .map_err(|error| WireError::Protocol(format!("invalid {label} cell id: {error}")))
}

#[cfg(test)]
mod tests {
    use arkret_wire::RealmId;

    use super::*;

    const REALM_ID: &str = "ak:realm:AYw-PHWIOTuZhm-EenZx-cCbOziC8pNCrh10oRfqiEmN";

    fn realm_scope() -> ScopeRef {
        ScopeRef::Realm {
            realm_id: RealmId::new(REALM_ID).unwrap(),
        }
    }

    #[test]
    fn cell_ids_use_the_registry_composite_subject() {
        let scope = realm_scope();
        let group_id = scope.canonical_mls_group_id().unwrap();
        let expected_subject =
            arkret_wire::cell::composite_subject(&[REALM_ID, group_id.as_str()]).unwrap();

        assert_eq!(
            mls_epoch_cell_id(&scope, &group_id).unwrap().as_str(),
            format!("ak:cell:ak.component.mls.epoch.v1:{expected_subject}")
        );
        assert_eq!(
            key_schedule_cell_id(&scope, &group_id).unwrap().as_str(),
            format!("ak:cell:ak.component.mls.key_schedule.v1:{expected_subject}")
        );
    }

    #[test]
    fn cell_ids_reject_a_group_id_the_scope_does_not_derive() {
        let scope = realm_scope();
        let error = mls_epoch_cell_id(&scope, "not-the-derived-group-id").unwrap_err();
        assert!(error.to_string().contains("does not derive"));
    }

    #[test]
    fn realm_genesis_has_no_mls_cell() {
        assert!(mls_epoch_cell_id(&ScopeRef::RealmGenesis, "anything").is_err());
    }
}
