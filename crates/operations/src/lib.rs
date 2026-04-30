//! Operation registry, builder and DAG validation contracts.

use std::collections::{BTreeMap, BTreeSet};

use contrix_core::{
    BUILT_IN_OPERATION_KINDS, Error, OP_AUTHZ_CHECK, OP_BLOB_GET, OP_BLOB_HEAD, OP_BLOB_UPLOAD,
    OP_CONTAINER_MOVE_ITEM, OP_CONTAINER_REBALANCE, OP_DIRECTORY_DESCRIBE, OP_ENTITY_CREATE,
    OP_ENTITY_DELETE, OP_ENTITY_REDACT, OP_ENTITY_RESTORE, OP_ENTITY_UPDATE,
    OP_FEDERATION_TRANSACTION, OP_FIELD_POSITION_MOVE, OP_FIELD_POSITION_REORDER,
    OP_IDENTITY_RESOLVE, OP_INDEX_DESCRIBE, OP_INDEX_INBOX, OP_INDEX_NOTIFICATIONS, OP_INDEX_QUERY,
    OP_INDEX_SEARCH, OP_INDEX_THREAD, OP_KEYS_CLAIM, OP_KEYS_QUERY, OP_KEYS_UPLOAD,
    OP_MESSAGE_CREATE, OP_PUSH_NOTIFY, OP_RELATION_CREATE, OP_RELATION_DELETE, OP_REPO_DESCRIBE,
    OP_REPO_SYNC, OP_SERVER_DESCRIBE, OP_SPACE_CHILD, OP_SPACE_CREATE, OP_SPACE_ORGANIZATION,
    OP_SPACE_UPDATE, OP_SYNC_BACKFILL, OP_SYNC_DESCRIBE, OP_SYNC_SUBSCRIBE, OP_TASK_CREATE,
    OP_TASK_UPDATE, OP_VIEW_CREATE, OP_VIEW_RECONCILE, OP_VIEW_UPDATE, OperationEnvelope,
    OperationId, OperationKindConformanceVector, OperationKindRegistry, Result,
    operation_kind_conformance_vectors,
};
use serde::{Deserialize, Serialize};

pub use contrix_core::{CausalRef, Operation, OperationSignature, OperationType};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationSurface {
    Entity,
    Relation,
    Position,
    Container,
    Task,
    View,
    Space,
    Message,
    Server,
    Identity,
    Repo,
    Sync,
    Federation,
    Index,
    Directory,
    Blob,
    Push,
    Keys,
    Authz,
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationCatalogRow {
    pub kind: String,
    pub surface: OperationSurface,
    pub schema: String,
    pub required_content_fields: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationCatalogReport {
    pub total: usize,
    pub rows: Vec<OperationCatalogRow>,
    pub missing_surfaces: Vec<OperationSurface>,
}

impl OperationCatalogReport {
    pub fn validate(&self) -> Result<()> {
        if self.total != BUILT_IN_OPERATION_KINDS.len() {
            return Err(Error::Protocol("operation catalog does not cover built-ins".to_owned()));
        }
        if !self.missing_surfaces.is_empty() {
            return Err(Error::Protocol(format!(
                "operation catalog is missing surfaces: {:?}",
                self.missing_surfaces
            )));
        }
        Ok(())
    }
}

pub fn classify_operation_kind(kind: &str) -> OperationSurface {
    match kind {
        OP_ENTITY_CREATE | OP_ENTITY_UPDATE | OP_ENTITY_DELETE | OP_ENTITY_RESTORE
        | OP_ENTITY_REDACT => OperationSurface::Entity,
        OP_RELATION_CREATE | OP_RELATION_DELETE => OperationSurface::Relation,
        OP_FIELD_POSITION_MOVE | OP_FIELD_POSITION_REORDER => OperationSurface::Position,
        OP_CONTAINER_MOVE_ITEM | OP_CONTAINER_REBALANCE => OperationSurface::Container,
        OP_TASK_CREATE | OP_TASK_UPDATE => OperationSurface::Task,
        OP_VIEW_CREATE | OP_VIEW_UPDATE | OP_VIEW_RECONCILE => OperationSurface::View,
        OP_SPACE_CREATE | OP_SPACE_UPDATE | OP_SPACE_ORGANIZATION | OP_SPACE_CHILD => {
            OperationSurface::Space
        }
        OP_MESSAGE_CREATE => OperationSurface::Message,
        OP_SERVER_DESCRIBE => OperationSurface::Server,
        OP_IDENTITY_RESOLVE => OperationSurface::Identity,
        OP_REPO_DESCRIBE | OP_REPO_SYNC => OperationSurface::Repo,
        OP_SYNC_DESCRIBE | OP_SYNC_SUBSCRIBE | OP_SYNC_BACKFILL => OperationSurface::Sync,
        OP_FEDERATION_TRANSACTION => OperationSurface::Federation,
        OP_INDEX_DESCRIBE
        | OP_INDEX_QUERY
        | OP_INDEX_THREAD
        | OP_INDEX_NOTIFICATIONS
        | OP_INDEX_INBOX
        | OP_INDEX_SEARCH => OperationSurface::Index,
        OP_DIRECTORY_DESCRIBE => OperationSurface::Directory,
        OP_BLOB_UPLOAD | OP_BLOB_HEAD | OP_BLOB_GET => OperationSurface::Blob,
        OP_PUSH_NOTIFY => OperationSurface::Push,
        OP_KEYS_UPLOAD | OP_KEYS_QUERY | OP_KEYS_CLAIM => OperationSurface::Keys,
        OP_AUTHZ_CHECK => OperationSurface::Authz,
        _ => OperationSurface::Custom(kind.to_owned()),
    }
}

pub fn operation_catalog() -> OperationCatalogReport {
    let registry = OperationKindRegistry::default();
    let rows = BUILT_IN_OPERATION_KINDS
        .iter()
        .map(|kind| {
            let spec = registry.spec(kind).expect("built-in operation kind is registered");
            OperationCatalogRow {
                kind: (*kind).to_owned(),
                surface: classify_operation_kind(kind),
                schema: spec.schema.clone(),
                required_content_fields: spec.required_content_fields.clone(),
            }
        })
        .collect::<Vec<_>>();
    let covered = rows.iter().map(|row| row.surface.clone()).collect::<BTreeSet<_>>();
    let required_surfaces = [
        OperationSurface::Entity,
        OperationSurface::Relation,
        OperationSurface::Position,
        OperationSurface::Container,
        OperationSurface::Task,
        OperationSurface::View,
        OperationSurface::Space,
        OperationSurface::Message,
        OperationSurface::Server,
        OperationSurface::Identity,
        OperationSurface::Repo,
        OperationSurface::Sync,
        OperationSurface::Federation,
        OperationSurface::Index,
        OperationSurface::Directory,
        OperationSurface::Blob,
        OperationSurface::Push,
        OperationSurface::Keys,
        OperationSurface::Authz,
    ];
    let missing_surfaces =
        required_surfaces.into_iter().filter(|surface| !covered.contains(surface)).collect();
    OperationCatalogReport { total: rows.len(), rows, missing_surfaces }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OperationDag {
    operations: BTreeMap<OperationId, OperationEnvelope>,
}

impl OperationDag {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, operation: OperationEnvelope) -> Result<()> {
        if self.operations.contains_key(&operation.operation_id) {
            return Err(Error::IdempotencyConflict(operation.operation_id.to_string()));
        }
        self.operations.insert(operation.operation_id.clone(), operation);
        Ok(())
    }

    pub fn validate(&self) -> Result<OperationDagReport> {
        let mut missing_dependencies = Vec::new();
        for operation in self.operations.values() {
            for dependency in &operation.causal.deps {
                if !self.operations.contains_key(dependency) {
                    missing_dependencies.push(OperationDependencyIssue {
                        operation_id: operation.operation_id.clone(),
                        dependency: dependency.clone(),
                    });
                }
            }
        }
        if !missing_dependencies.is_empty() {
            return Ok(OperationDagReport {
                operation_count: self.operations.len(),
                missing_dependencies,
                has_cycle: false,
            });
        }

        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        for operation_id in self.operations.keys() {
            if self.visit(operation_id, &mut visiting, &mut visited)? {
                return Ok(OperationDagReport {
                    operation_count: self.operations.len(),
                    missing_dependencies: Vec::new(),
                    has_cycle: true,
                });
            }
        }
        Ok(OperationDagReport {
            operation_count: self.operations.len(),
            missing_dependencies: Vec::new(),
            has_cycle: false,
        })
    }

    fn visit(
        &self,
        operation_id: &OperationId,
        visiting: &mut BTreeSet<OperationId>,
        visited: &mut BTreeSet<OperationId>,
    ) -> Result<bool> {
        if visited.contains(operation_id) {
            return Ok(false);
        }
        if !visiting.insert(operation_id.clone()) {
            return Ok(true);
        }
        let operation = self
            .operations
            .get(operation_id)
            .ok_or_else(|| Error::Protocol("operation DAG references missing node".to_owned()))?;
        for dependency in &operation.causal.deps {
            if self.visit(dependency, visiting, visited)? {
                return Ok(true);
            }
        }
        visiting.remove(operation_id);
        visited.insert(operation_id.clone());
        Ok(false)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationDependencyIssue {
    pub operation_id: OperationId,
    pub dependency: OperationId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationDagReport {
    pub operation_count: usize,
    pub missing_dependencies: Vec<OperationDependencyIssue>,
    pub has_cycle: bool,
}

impl OperationDagReport {
    pub fn validate_acyclic_complete(&self) -> Result<()> {
        if self.has_cycle {
            return Err(Error::Protocol("operation DAG contains a cycle".to_owned()));
        }
        if !self.missing_dependencies.is_empty() {
            return Err(Error::Protocol("operation DAG has missing dependencies".to_owned()));
        }
        Ok(())
    }
}

pub fn conformance_vectors() -> Vec<OperationKindConformanceVector> {
    operation_kind_conformance_vectors()
}

pub mod protocol {
    pub use contrix_core::{
        Operation, OperationEnvelope, OperationEnvelopeBuilder, OperationKindConformanceVector,
        OperationKindRegistry, OperationKindSpec, OperationKindValidation, OperationType,
    };
}

#[cfg(test)]
mod tests {
    use contrix_core::{Did, Hlc, OP_MESSAGE_CREATE, OperationEnvelopeBuilder, SpaceId};
    use serde_json::json;

    use super::*;

    fn envelope(id: &str, deps: Vec<&str>) -> OperationEnvelope {
        let mut builder = OperationEnvelopeBuilder::new(
            OperationId::new(id).unwrap(),
            SpaceId::new("cx:space:operations").unwrap(),
            Did::new("did:web:alice.example").unwrap(),
            OP_MESSAGE_CREATE,
            1,
            Hlc::new("01970e589d21-00000001-a13f9c2e").unwrap(),
        )
        .with_content(json!({"body": "hello"}));
        for dep in deps {
            builder = builder.with_dependency(OperationId::new(dep).unwrap());
        }
        builder.build(&OperationKindRegistry::default()).unwrap()
    }

    #[test]
    fn catalog_covers_builtin_operation_surfaces() {
        let catalog = operation_catalog();
        catalog.validate().unwrap();
        assert!(catalog.rows.iter().any(|row| row.surface == OperationSurface::Federation));
        assert_eq!(conformance_vectors().len(), BUILT_IN_OPERATION_KINDS.len());
    }

    #[test]
    fn dag_accepts_complete_acyclic_dependencies() {
        let mut dag = OperationDag::new();
        dag.insert(envelope("cx:operation:1", Vec::new())).unwrap();
        dag.insert(envelope("cx:operation:2", vec!["cx:operation:1"])).unwrap();
        dag.validate().unwrap().validate_acyclic_complete().unwrap();
    }

    #[test]
    fn dag_reports_missing_dependencies() {
        let mut dag = OperationDag::new();
        dag.insert(envelope("cx:operation:2", vec!["cx:operation:missing"])).unwrap();
        let report = dag.validate().unwrap();
        assert_eq!(report.missing_dependencies.len(), 1);
        assert!(report.validate_acyclic_complete().is_err());
    }

    #[test]
    fn registry_requires_semantic_content_fields() {
        let result = OperationEnvelopeBuilder::new(
            OperationId::new("cx:operation:bad").unwrap(),
            SpaceId::new("cx:space:operations").unwrap(),
            Did::new("did:web:alice.example").unwrap(),
            OP_MESSAGE_CREATE,
            1,
            Hlc::new("01970e589d21-00000001-a13f9c2e").unwrap(),
        )
        .with_content(json!({}))
        .build(&OperationKindRegistry::default());
        assert!(matches!(result, Err(Error::Protocol(_))));
    }
}
