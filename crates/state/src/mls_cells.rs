//! Canonical MLS group cell identifiers.

use arkret_identifiers::CellRef;
use arkret_wire::WireError;

pub const MLS_EPOCH_CELL_FAMILY: &str = arkret_wire::CellFamilyId::MLS_EPOCH_V1;
pub const KEY_SCHEDULE_CELL_FAMILY: &str = arkret_wire::CellFamilyId::MLS_KEY_SCHEDULE_V1;

pub fn mls_epoch_cell_id(group_id: &str) -> Result<CellRef, WireError> {
    group_cell_id(MLS_EPOCH_CELL_FAMILY, group_id, "mls_epoch")
}

pub fn key_schedule_cell_id(group_id: &str) -> Result<CellRef, WireError> {
    group_cell_id(KEY_SCHEDULE_CELL_FAMILY, group_id, "key_schedule")
}

fn group_cell_id(family: &str, group_id: &str, label: &str) -> Result<CellRef, WireError> {
    if group_id.is_empty() {
        return Err(WireError::Protocol(
            "MLS group_id must not be empty".to_owned(),
        ));
    }
    CellRef::new(arkret_wire::subject_cell(family, group_id))
        .map_err(|error| WireError::Protocol(format!("invalid {label} cell id: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_ids_use_canonical_prefixes() {
        let group = "group.01js0mls0000000000000000";
        assert_eq!(
            mls_epoch_cell_id(group).unwrap().as_str(),
            format!("ak:cell:ak.component.mls.epoch.v1:{group}")
        );
        assert_eq!(
            key_schedule_cell_id(group).unwrap().as_str(),
            format!("ak:cell:ak.component.mls.key_schedule.v1:{group}")
        );
    }
}
