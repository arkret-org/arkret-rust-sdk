use std::collections::BTreeMap;

use crate::{Commit, CommitId, Error, Hash, Operation, OperationId, Result};

pub trait RepoStore {
    fn put_operation(&mut self, operation: Operation) -> Result<()>;
    fn put_commit(&mut self, commit: Commit) -> Result<()>;
    fn operation(&self, operation_id: &OperationId) -> Option<&Operation>;
    fn commit(&self, commit_id: &CommitId) -> Option<&Commit>;
    fn head(&self) -> Option<&Hash>;
}

#[derive(Debug, Default)]
pub struct MemoryRepoStore {
    operations: BTreeMap<OperationId, (String, Operation)>,
    commits: BTreeMap<CommitId, (String, Commit)>,
    head: Option<Hash>,
}

impl MemoryRepoStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn operations_len(&self) -> usize {
        self.operations.len()
    }

    pub fn commits_len(&self) -> usize {
        self.commits.len()
    }
}

impl RepoStore for MemoryRepoStore {
    fn put_operation(&mut self, operation: Operation) -> Result<()> {
        let digest = operation.operation_digest()?;
        match self.operations.get(&operation.operation_id) {
            Some((existing_digest, _)) if existing_digest == &digest => Ok(()),
            Some(_) => Err(Error::IdempotencyConflict(operation.operation_id.to_string())),
            None => {
                self.operations.insert(operation.operation_id.clone(), (digest, operation));
                Ok(())
            }
        }
    }

    fn put_commit(&mut self, commit: Commit) -> Result<()> {
        let digest = commit.commit_digest()?;
        match self.commits.get(&commit.commit_id) {
            Some((existing_digest, _)) if existing_digest == &digest => Ok(()),
            Some(_) => Err(Error::IdempotencyConflict(commit.commit_id.to_string())),
            None => {
                self.head = Some(Hash::new(digest.clone())?);
                self.commits.insert(commit.commit_id.clone(), (digest, commit));
                Ok(())
            }
        }
    }

    fn operation(&self, operation_id: &OperationId) -> Option<&Operation> {
        self.operations.get(operation_id).map(|(_, operation)| operation)
    }

    fn commit(&self, commit_id: &CommitId) -> Option<&Commit> {
        self.commits.get(commit_id).map(|(_, commit)| commit)
    }

    fn head(&self) -> Option<&Hash> {
        self.head.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use serde_json::json;

    use super::*;
    use crate::{COMMIT_SCHEMA, Did, SpaceId};

    #[test]
    fn operation_put_is_idempotent_for_same_bytes() {
        let mut store = MemoryRepoStore::new();
        let operation = Operation::create(
            OperationId::new("cx:operation:01").unwrap(),
            SpaceId::new("cx:space:01").unwrap(),
            "entity",
            json!({"id":"cx:entity:01"}),
        );

        store.put_operation(operation.clone()).unwrap();
        store.put_operation(operation).unwrap();

        assert_eq!(store.operations_len(), 1);
    }

    #[test]
    fn operation_put_rejects_same_id_with_different_payload() {
        let mut store = MemoryRepoStore::new();
        let mut operation = Operation::create(
            OperationId::new("cx:operation:01").unwrap(),
            SpaceId::new("cx:space:01").unwrap(),
            "entity",
            json!({"id":"cx:entity:01"}),
        );
        store.put_operation(operation.clone()).unwrap();

        operation.payload = json!({"id":"cx:entity:02"});
        assert!(matches!(store.put_operation(operation), Err(Error::IdempotencyConflict(_))));
    }

    #[test]
    fn commit_put_updates_head_to_commit_digest() {
        let mut store = MemoryRepoStore::new();
        let commit = Commit {
            schema: COMMIT_SCHEMA.to_owned(),
            commit_id: CommitId::new("cx:commit:01").unwrap(),
            object_type: "commit".to_owned(),
            repo_id: "did:web:alice.example".to_owned(),
            author: Did::new("did:web:alice.example").unwrap(),
            author_seq: 1,
            prev_commit: None,
            operations: Vec::new(),
            created_at: Utc::now(),
            proofs: Vec::new(),
        };
        let expected = commit.commit_digest().unwrap();

        store.put_commit(commit).unwrap();

        assert_eq!(store.head().unwrap().as_str(), expected);
    }
}
