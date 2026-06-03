use cokret::{
    MemoryPersistenceStore, RealmId, SpaceState, StateSnapshotStore,
    restore_space_state_from_persistence,
};

fn main() -> cokret::Result<()> {
    let space_id = RealmId::new("ck:space:01904100-0000-7000-8000-9b64700c6ee8")?;
    let state = SpaceState::new(space_id.clone(), "1".to_owned());

    let mut store = MemoryPersistenceStore::new();
    store.put_state_snapshot(state.snapshot())?;

    let restored = restore_space_state_from_persistence(&store, &space_id, "1")?;
    assert_eq!(restored.state.space_id, space_id);

    Ok(())
}
