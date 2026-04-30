use contrix::{
    MemoryPersistenceStore, SpaceId, SpaceState, StateSnapshotStore,
    restore_space_state_from_persistence,
};

fn main() -> contrix::Result<()> {
    let space_id = SpaceId::new("cx:space:01JS0SP000000000000000000")?;
    let state = SpaceState::new(space_id.clone(), "1".to_owned());

    let mut store = MemoryPersistenceStore::new();
    store.put_state_snapshot(state.snapshot())?;

    let restored = restore_space_state_from_persistence(&store, &space_id, "1")?;
    assert_eq!(restored.state.space_id, space_id);

    Ok(())
}
