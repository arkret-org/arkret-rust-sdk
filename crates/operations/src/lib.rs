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
    OP_SPACE_UPDATE, OP_SUBJECT_ARCHIVE, OP_SUBJECT_CREATE, OP_SUBJECT_LINK_SURFACE,
    OP_SUBJECT_RESTORE, OP_SUBJECT_SET_PRIMARY_SURFACE, OP_SUBJECT_UNLINK_SURFACE,
    OP_SUBJECT_UPDATE, OP_SYNC_BACKFILL, OP_SYNC_DESCRIBE, OP_SYNC_SUBSCRIBE, OP_TASK_CREATE,
    OP_TASK_UPDATE, OP_VIEW_CREATE, OP_VIEW_RECONCILE, OP_VIEW_UPDATE, OperationEnvelope,
    OperationId, OperationKindConformanceVector, OperationKindRegistry, Result,
    operation_kind_conformance_vectors,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use contrix_core::{CausalRef, Operation, OperationSignature, OperationType};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationSurface {
    Subject,
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
        OP_SUBJECT_CREATE
        | OP_SUBJECT_UPDATE
        | OP_SUBJECT_ARCHIVE
        | OP_SUBJECT_RESTORE
        | OP_SUBJECT_LINK_SURFACE
        | OP_SUBJECT_UNLINK_SURFACE
        | OP_SUBJECT_SET_PRIMARY_SURFACE => OperationSurface::Subject,
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
        OperationSurface::Subject,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationMutation {
    Read,
    Create,
    Update,
    Delete,
    Redact,
    External,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationSemanticEffect {
    pub operation_id: OperationId,
    pub surface: OperationSurface,
    pub mutation: OperationMutation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_id: Option<String>,
    #[serde(default)]
    pub requires_authz: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationSemanticIssue {
    pub operation_id: OperationId,
    pub kind: String,
    pub message: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationSemanticReport {
    pub applied: Vec<OperationSemanticEffect>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejected: Vec<OperationSemanticIssue>,
}

impl OperationSemanticReport {
    pub fn validate_clean(&self) -> Result<()> {
        if self.rejected.is_empty() {
            Ok(())
        } else {
            Err(Error::Protocol(format!(
                "operation semantic reducer rejected {} operation(s)",
                self.rejected.len()
            )))
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct OperationSemanticReducer {
    active_targets: BTreeMap<String, OperationId>,
    tombstoned_targets: BTreeMap<String, OperationId>,
}

impl OperationSemanticReducer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn reduce(&mut self, operations: &[OperationEnvelope]) -> OperationSemanticReport {
        let mut report = OperationSemanticReport::default();
        for operation in operations {
            let effect = semantic_effect(operation);
            if let Some(issue) = self.validate_effect(&effect, operation) {
                report.rejected.push(issue);
                continue;
            }
            self.apply_effect(&effect);
            report.applied.push(effect);
        }
        report
    }

    fn validate_effect(
        &self,
        effect: &OperationSemanticEffect,
        operation: &OperationEnvelope,
    ) -> Option<OperationSemanticIssue> {
        if effect.requires_authz && operation.authz_ref.is_none() {
            return Some(OperationSemanticIssue {
                operation_id: operation.operation_id.clone(),
                kind: "missing_authz".to_owned(),
                message: "mutating operation requires an authorization reference".to_owned(),
            });
        }
        let Some(target_id) = effect.target_id.as_deref() else {
            return None;
        };
        match effect.mutation {
            OperationMutation::Create if self.active_targets.contains_key(target_id) => {
                Some(OperationSemanticIssue {
                    operation_id: operation.operation_id.clone(),
                    kind: "duplicate_create".to_owned(),
                    message: format!("target '{target_id}' is already active"),
                })
            }
            OperationMutation::Create if self.tombstoned_targets.contains_key(target_id) => {
                Some(OperationSemanticIssue {
                    operation_id: operation.operation_id.clone(),
                    kind: "create_after_tombstone".to_owned(),
                    message: format!("target '{target_id}' was tombstoned"),
                })
            }
            OperationMutation::Update | OperationMutation::Redact
                if self.tombstoned_targets.contains_key(target_id) =>
            {
                Some(OperationSemanticIssue {
                    operation_id: operation.operation_id.clone(),
                    kind: "mutation_after_tombstone".to_owned(),
                    message: format!("target '{target_id}' was tombstoned"),
                })
            }
            _ => None,
        }
    }

    fn apply_effect(&mut self, effect: &OperationSemanticEffect) {
        let Some(target_id) = effect.target_id.clone() else {
            return;
        };
        match effect.mutation {
            OperationMutation::Create | OperationMutation::Update | OperationMutation::External => {
                self.active_targets.insert(target_id, effect.operation_id.clone());
            }
            OperationMutation::Delete | OperationMutation::Redact => {
                self.active_targets.remove(&target_id);
                self.tombstoned_targets.insert(target_id, effect.operation_id.clone());
            }
            OperationMutation::Read => {}
        }
    }
}

pub fn semantic_effect(operation: &OperationEnvelope) -> OperationSemanticEffect {
    let surface = classify_operation_kind(&operation.kind);
    let mutation = mutation_for_kind(&operation.kind);
    let target_id = target_id_for_operation(&operation.kind, &operation.content);
    let requires_authz = !matches!(mutation, OperationMutation::Read);
    OperationSemanticEffect {
        operation_id: operation.operation_id.clone(),
        surface,
        mutation,
        target_id,
        requires_authz,
    }
}

pub fn reduce_operation_semantics(operations: &[OperationEnvelope]) -> OperationSemanticReport {
    OperationSemanticReducer::new().reduce(operations)
}

fn mutation_for_kind(kind: &str) -> OperationMutation {
    match kind {
        OP_ENTITY_CREATE | OP_SUBJECT_CREATE | OP_RELATION_CREATE | OP_TASK_CREATE
        | OP_VIEW_CREATE | OP_SPACE_CREATE => OperationMutation::Create,
        OP_ENTITY_DELETE | OP_SUBJECT_ARCHIVE | OP_RELATION_DELETE => OperationMutation::Delete,
        OP_ENTITY_REDACT => OperationMutation::Redact,
        OP_SERVER_DESCRIBE
        | OP_REPO_DESCRIBE
        | OP_SYNC_DESCRIBE
        | OP_INDEX_DESCRIBE
        | OP_DIRECTORY_DESCRIBE
        | OP_BLOB_HEAD
        | OP_BLOB_GET
        | OP_KEYS_QUERY
        | OP_KEYS_CLAIM
        | OP_AUTHZ_CHECK => OperationMutation::Read,
        OP_FEDERATION_TRANSACTION | OP_PUSH_NOTIFY | OP_KEYS_UPLOAD => OperationMutation::External,
        _ => OperationMutation::Update,
    }
}

fn target_id_for_operation(kind: &str, content: &Value) -> Option<String> {
    let fields: &[&str] = match kind {
        OP_ENTITY_CREATE
        | OP_ENTITY_UPDATE
        | OP_ENTITY_DELETE
        | OP_ENTITY_RESTORE
        | OP_ENTITY_REDACT
        | OP_FIELD_POSITION_MOVE
        | OP_FIELD_POSITION_REORDER
        | OP_CONTAINER_MOVE_ITEM => &["entity_id"],
        OP_SUBJECT_CREATE
        | OP_SUBJECT_UPDATE
        | OP_SUBJECT_ARCHIVE
        | OP_SUBJECT_RESTORE
        | OP_SUBJECT_LINK_SURFACE
        | OP_SUBJECT_UNLINK_SURFACE
        | OP_SUBJECT_SET_PRIMARY_SURFACE => &["subject_id"],
        OP_RELATION_CREATE | OP_RELATION_DELETE => &["relation_id"],
        OP_TASK_CREATE | OP_TASK_UPDATE => &["task_id", "entity_id"],
        OP_VIEW_CREATE | OP_VIEW_UPDATE | OP_VIEW_RECONCILE => &["view_id"],
        OP_SPACE_CREATE | OP_SPACE_UPDATE | OP_SPACE_ORGANIZATION | OP_SPACE_CHILD => {
            &["space_id", "child_space_id"]
        }
        OP_MESSAGE_CREATE => &["event_id", "message_id"],
        _ => &[],
    };
    fields.iter().find_map(|field| {
        content.get(*field).and_then(Value::as_str).map(|value| format!("{field}:{value}"))
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationDagNegativeKind {
    MissingDependency,
    Cycle,
    DuplicateOperationId,
    MutationAfterTombstone,
    MissingAuthz,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationDagNegativeVector {
    pub name: &'static str,
    pub issue: OperationDagNegativeKind,
}

pub fn negative_dag_vectors() -> Vec<OperationDagNegativeVector> {
    vec![
        OperationDagNegativeVector {
            name: "operation references an unknown dependency",
            issue: OperationDagNegativeKind::MissingDependency,
        },
        OperationDagNegativeVector {
            name: "operation dependency graph contains a cycle",
            issue: OperationDagNegativeKind::Cycle,
        },
        OperationDagNegativeVector {
            name: "operation id is inserted twice",
            issue: OperationDagNegativeKind::DuplicateOperationId,
        },
        OperationDagNegativeVector {
            name: "operation mutates a tombstoned target",
            issue: OperationDagNegativeKind::MutationAfterTombstone,
        },
        OperationDagNegativeVector {
            name: "mutating operation lacks authorization reference",
            issue: OperationDagNegativeKind::MissingAuthz,
        },
    ]
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
    use contrix_core::{
        Did, GrantId, Hlc, OP_ENTITY_CREATE, OP_ENTITY_DELETE, OP_ENTITY_UPDATE, OP_MESSAGE_CREATE,
        OperationEnvelopeBuilder, SpaceId,
    };
    use serde_json::json;

    use super::*;

    fn envelope(id: &str, deps: Vec<&str>) -> OperationEnvelope {
        envelope_for(id, OP_MESSAGE_CREATE, json!({"body": "hello"}), deps, false)
    }

    fn envelope_for(
        id: &str,
        kind: &str,
        content: Value,
        deps: Vec<&str>,
        authz: bool,
    ) -> OperationEnvelope {
        let mut builder = OperationEnvelopeBuilder::new(
            OperationId::new(id).unwrap(),
            SpaceId::new("cx:space:operations").unwrap(),
            Did::new("did:web:alice.example").unwrap(),
            kind,
            1,
            Hlc::new("01970e589d21-00000001-a13f9c2e").unwrap(),
        )
        .with_content(content);
        for dep in deps {
            builder = builder.with_dependency(OperationId::new(dep).unwrap());
        }
        if authz {
            builder = builder.with_authz_ref(GrantId::new("cx:grant:operations").unwrap());
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
    fn dag_reports_cycles_and_negative_vectors_cover_failure_modes() {
        let mut dag = OperationDag::new();
        dag.insert(envelope("cx:operation:1", vec!["cx:operation:2"])).unwrap();
        dag.insert(envelope("cx:operation:2", vec!["cx:operation:1"])).unwrap();
        let report = dag.validate().unwrap();
        assert!(report.has_cycle);
        assert!(report.validate_acyclic_complete().is_err());

        let issues =
            negative_dag_vectors().into_iter().map(|vector| vector.issue).collect::<BTreeSet<_>>();
        assert!(issues.contains(&OperationDagNegativeKind::Cycle));
        assert!(issues.contains(&OperationDagNegativeKind::MutationAfterTombstone));
        assert!(issues.contains(&OperationDagNegativeKind::MissingAuthz));
    }

    #[test]
    fn semantic_reducer_rejects_tombstone_mutations_and_missing_authz() {
        let create = envelope_for(
            "cx:operation:1",
            OP_ENTITY_CREATE,
            json!({"entity_id": "cx:entity:1"}),
            Vec::new(),
            true,
        );
        let delete = envelope_for(
            "cx:operation:2",
            OP_ENTITY_DELETE,
            json!({"entity_id": "cx:entity:1"}),
            vec!["cx:operation:1"],
            true,
        );
        let update_after_delete = envelope_for(
            "cx:operation:3",
            OP_ENTITY_UPDATE,
            json!({"entity_id": "cx:entity:1"}),
            vec!["cx:operation:2"],
            true,
        );
        let report = reduce_operation_semantics(&[create, delete, update_after_delete]);
        assert_eq!(report.applied.len(), 2);
        assert_eq!(report.rejected[0].kind, "mutation_after_tombstone");

        let missing_authz = envelope_for(
            "cx:operation:4",
            OP_ENTITY_CREATE,
            json!({"entity_id": "cx:entity:2"}),
            Vec::new(),
            false,
        );
        let report = reduce_operation_semantics(&[missing_authz]);
        assert_eq!(report.rejected[0].kind, "missing_authz");
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
