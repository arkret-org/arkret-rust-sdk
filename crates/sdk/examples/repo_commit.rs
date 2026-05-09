use contrix::{
    Commit, CommitId, Did, Hlc, MemoryRepoStore, Operation, OperationId, RepoStore, SpaceId,
};
use serde_json::json;

fn main() -> contrix::Result<()> {
    let actor = Did::new("did:web:alice.example")?;
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-65c7feb295d7")?;

    let event = contrix::Event::new(
        "cx.message.create",
        space_id.clone(),
        actor.clone(),
        1,
        Hlc::new("01970e589d21-0004-a13f9c2e")?,
        json!({ "body": "hello" }),
    )?;
    let event_digest = event.event_digest()?;

    let operation = Operation::create(
        OperationId::new("cx:operation:01904100-0000-7000-8000-0198d483044c")?,
        space_id,
        "event",
        serde_json::to_value(&event)?,
    );

    let mut commit = Commit::new(
        CommitId::new("cx:commit:01904100-0000-7000-8000-e5dae9001942")?,
        actor.to_string(),
        actor,
        1,
    );
    commit.operations.push(operation.operation_digest()?.parse()?);

    let mut store = MemoryRepoStore::new();
    store.put_operation(operation)?;
    store.put_commit(commit)?;

    println!("event_digest={event_digest}");
    println!("repo_head={}", store.head().expect("commit was stored"));

    Ok(())
}
