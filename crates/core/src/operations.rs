//! Operation registry, builder and DAG validation contracts.

use std::collections::{BTreeMap, BTreeSet};

use crate::*;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use crate::{CausalRef, Operation, OperationSignature, OperationType};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationSurface {
    Account,
    Admin,
    Applet,
    Authz,
    Blob,
    DeviceMessages,
    Directory,
    Events,
    Identity,
    Keys,
    Media,
    Mimi,
    Moderation,
    Policy,
    Push,
    Server,
    Sync,
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
        OP_ACCOUNT_DEVICE_PAIR | OP_ACCOUNT_ISSUE_SESSION_GRANT | OP_ACCOUNT_OIDC_CALLBACK => {
            OperationSurface::Account
        }
        OP_ADMIN_GET_MODERATION_QUEUE
        | OP_ADMIN_GET_SERVER_STATUS
        | OP_ADMIN_REVOKE_DEVICE
        | OP_ADMIN_UPDATE_ACCOUNT_STATUS => OperationSurface::Admin,
        OP_APPLET_DESCRIBE
        | OP_APPLET_PING
        | OP_APPLET_PROTOCOL_METADATA
        | OP_APPLET_QUERY_ACTOR
        | OP_APPLET_QUERY_REALM
        | OP_APPLET_THIRD_PARTY_LOCATIONS
        | OP_APPLET_THIRD_PARTY_USERS
        | OP_APPLET_TRANSACTION => OperationSurface::Applet,
        OP_AUTHZ_CHECK | OP_AUTHZ_GET_EFFECTIVE_GRANTS | OP_AUTHZ_GET_INVITES => {
            OperationSurface::Authz
        }
        OP_BLOB_UPLOAD | OP_BLOB_HEAD | OP_BLOB_GET => OperationSurface::Blob,
        OP_DEVICE_MESSAGES_PUT | OP_DEVICE_MESSAGES_GET => OperationSurface::DeviceMessages,
        OP_DIRECTORY_ANNOUNCE
        | OP_DIRECTORY_DESCRIBE
        | OP_DIRECTORY_PRIVATE_CONTACT_DISCOVERY
        | OP_DIRECTORY_RESOLVE_HANDLE
        | OP_DIRECTORY_LIST_HANDLES_FOR_SUBJECT
        | OP_DIRECTORY_RESOLVE_ORGANIZATION
        | OP_DIRECTORY_RESOLVE_REALM
        | OP_DIRECTORY_RESOLVE_TARGET
        | OP_DIRECTORY_SEARCH_ACTORS
        | OP_DIRECTORY_SEARCH_ORGANIZATIONS
        | OP_DIRECTORY_SEARCH_REALMS
        | OP_DIRECTORY_SEARCH_USERS
        | OP_DIRECTORY_SUBSCRIBE
        | OP_DIRECTORY_WITHDRAW => OperationSurface::Directory,
        OP_EVENTS_DESCRIBE | OP_EVENTS_FRONTIER | OP_EVENTS_GET | OP_EVENTS_QUERY
        | OP_EVENTS_RESOLVE | OP_EVENTS_SUBSCRIBE | OP_EVENTS_SUBMIT => OperationSurface::Events,
        OP_IDENTITY_DESCRIBE_REGISTRY
        | OP_IDENTITY_GET_DOCUMENT
        | OP_IDENTITY_GET_LOG
        | OP_IDENTITY_GET_RECEIPTS
        | OP_IDENTITY_RESOLVE
        | OP_IDENTITY_SUBMIT_DID_OPERATION => OperationSurface::Identity,
        OP_KEYS_UPLOAD
        | OP_KEYS_QUERY
        | OP_KEYS_CLAIM
        | OP_KEYS_KEYPACKAGES_UPLOAD
        | OP_KEYS_KEYPACKAGES_CLAIM
        | OP_KEYS_KEYPACKAGES_CONSUME
        | OP_KEYS_KEYPACKAGES_REVOKE
        | OP_KEYS_BACKUPS_PUT
        | OP_KEYS_BACKUPS_LIST
        | OP_KEYS_BACKUPS_GET
        | OP_KEYS_BACKUPS_DELETE => OperationSurface::Keys,
        OP_MEDIA_ICE_CONFIG => OperationSurface::Media,
        OP_MIMI_GROUP_INFO
        | OP_MIMI_IDENTIFIER_QUERY
        | OP_MIMI_KEY_MATERIAL
        | OP_MIMI_NOTIFY
        | OP_MIMI_PROVIDER_DIRECTORY
        | OP_MIMI_PROXY_DOWNLOAD
        | OP_MIMI_REPORT_ABUSE
        | OP_MIMI_REQUEST_CONSENT
        | OP_MIMI_ROOM_UPDATE
        | OP_MIMI_SUBMIT_MESSAGE
        | OP_MIMI_UPDATE_CONSENT => OperationSurface::Mimi,
        OP_MODERATION_REPORT => OperationSurface::Moderation,
        OP_POLICY_CHECK => OperationSurface::Policy,
        OP_PUSH_NOTIFY | OP_PUSH_REGISTER_DEVICE | OP_PUSH_UNREGISTER_DEVICE => {
            OperationSurface::Push
        }
        OP_SERVER_DESCRIBE => OperationSurface::Server,
        OP_ACCOUNT_DESCRIBE
        | OP_ACCOUNT_SUBSCRIBE
        | OP_ACCOUNT_CURSOR_REVOKE
        | OP_SNAPSHOT_HEAD => OperationSurface::Sync,
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
        OperationSurface::Account,
        OperationSurface::Admin,
        OperationSurface::Applet,
        OperationSurface::Keys,
        OperationSurface::DeviceMessages,
        OperationSurface::Authz,
        OperationSurface::Blob,
        OperationSurface::Directory,
        OperationSurface::Events,
        OperationSurface::Identity,
        OperationSurface::Media,
        OperationSurface::Mimi,
        OperationSurface::Moderation,
        OperationSurface::Policy,
        OperationSurface::Push,
        OperationSurface::Server,
        OperationSurface::Sync,
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
        let target_id = effect.target_id.as_deref()?;
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
        OP_PUSH_REGISTER_DEVICE
        | OP_KEYS_BACKUPS_PUT
        | OP_KEYS_KEYPACKAGES_UPLOAD
        | OP_DIRECTORY_SUBSCRIBE => OperationMutation::Create,
        OP_PUSH_UNREGISTER_DEVICE | OP_KEYS_BACKUPS_DELETE => OperationMutation::Delete,
        OP_SERVER_DESCRIBE
        | OP_ACCOUNT_DESCRIBE
        | OP_DIRECTORY_DESCRIBE
        | OP_EVENTS_DESCRIBE
        | OP_EVENTS_GET
        | OP_EVENTS_RESOLVE
        | OP_EVENTS_FRONTIER
        | OP_EVENTS_QUERY
        | OP_EVENTS_SUBSCRIBE
        | OP_SNAPSHOT_HEAD
        | OP_IDENTITY_DESCRIBE_REGISTRY
        | OP_IDENTITY_RESOLVE
        | OP_IDENTITY_GET_DOCUMENT
        | OP_IDENTITY_GET_LOG
        | OP_IDENTITY_GET_RECEIPTS
        | OP_BLOB_HEAD
        | OP_BLOB_GET
        | OP_DIRECTORY_RESOLVE_HANDLE
        | OP_DIRECTORY_LIST_HANDLES_FOR_SUBJECT
        | OP_DIRECTORY_RESOLVE_ORGANIZATION
        | OP_DIRECTORY_RESOLVE_REALM
        | OP_DIRECTORY_RESOLVE_TARGET
        | OP_DIRECTORY_SEARCH_ACTORS
        | OP_DIRECTORY_SEARCH_ORGANIZATIONS
        | OP_DIRECTORY_SEARCH_REALMS
        | OP_DIRECTORY_SEARCH_USERS
        | OP_AUTHZ_GET_EFFECTIVE_GRANTS
        | OP_AUTHZ_GET_INVITES
        | OP_KEYS_BACKUPS_LIST
        | OP_KEYS_BACKUPS_GET
        | OP_KEYS_QUERY
        | OP_AUTHZ_CHECK => OperationMutation::Read,
        OP_EVENTS_SUBMIT
        | OP_ACCOUNT_SUBSCRIBE
        | OP_ACCOUNT_CURSOR_REVOKE
        | OP_PUSH_NOTIFY
        | OP_KEYS_UPLOAD
        | OP_KEYS_CLAIM
        | OP_DEVICE_MESSAGES_PUT
        | OP_DEVICE_MESSAGES_GET
        | OP_MEDIA_ICE_CONFIG
        | OP_MIMI_PROVIDER_DIRECTORY
        | OP_MIMI_GROUP_INFO
        | OP_MIMI_KEY_MATERIAL
        | OP_MIMI_SUBMIT_MESSAGE
        | OP_MIMI_ROOM_UPDATE
        | OP_MIMI_REQUEST_CONSENT
        | OP_MIMI_UPDATE_CONSENT
        | OP_MIMI_IDENTIFIER_QUERY
        | OP_MIMI_NOTIFY
        | OP_MIMI_REPORT_ABUSE
        | OP_MIMI_PROXY_DOWNLOAD
        | OP_POLICY_CHECK => OperationMutation::External,
        _ => OperationMutation::Update,
    }
}

fn target_id_for_operation(kind: &str, content: &Value) -> Option<String> {
    let fields: &[&str] = match kind {
        OP_EVENTS_GET | OP_EVENTS_RESOLVE => &["event_id"],
        OP_EVENTS_FRONTIER | OP_SNAPSHOT_HEAD | OP_AUTHZ_GET_INVITES => &["space_id"],
        OP_IDENTITY_RESOLVE
        | OP_IDENTITY_GET_DOCUMENT
        | OP_IDENTITY_GET_LOG
        | OP_IDENTITY_GET_RECEIPTS
        | OP_IDENTITY_SUBMIT_DID_OPERATION => &["did"],
        OP_KEYS_BACKUPS_PUT | OP_KEYS_BACKUPS_GET | OP_KEYS_BACKUPS_DELETE => &["backup_id"],
        OP_KEYS_KEYPACKAGES_CLAIM => &["target_principal_id"],
        OP_KEYS_KEYPACKAGES_CONSUME => &["claim_id"],
        OP_KEYS_KEYPACKAGES_REVOKE => &["principal_id", "keypackage_ref"],
        OP_PUSH_REGISTER_DEVICE | OP_PUSH_UNREGISTER_DEVICE => &["device_id"],
        OP_DIRECTORY_RESOLVE_TARGET => &["address"],
        OP_DIRECTORY_SUBSCRIBE => &["subscriber_did", "webhook_endpoint"],
        OP_DEVICE_MESSAGES_PUT | OP_DEVICE_MESSAGES_GET => {
            &["recipient_principal_id", "recipient_device_id"]
        }
        OP_ADMIN_REVOKE_DEVICE | OP_ADMIN_UPDATE_ACCOUNT_STATUS => &["principal_id"],
        OP_ACCOUNT_DEVICE_PAIR | OP_ACCOUNT_ISSUE_SESSION_GRANT => &["principal_id"],
        OP_MODERATION_REPORT => &["target_ref"],
        OP_POLICY_CHECK => &["resource"],
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
    pub use crate::{
        Operation, OperationEnvelope, OperationEnvelopeBuilder, OperationKindConformanceVector,
        OperationKindRegistry, OperationKindSpec, OperationKindValidation, OperationType,
    };
}

#[cfg(test)]
mod tests {
    use crate::{
        Did, GrantId, Hlc, OP_EVENTS_QUERY, OP_PUSH_REGISTER_DEVICE, OP_PUSH_UNREGISTER_DEVICE,
        OperationEnvelopeBuilder,
    };
    use serde_json::json;

    use super::*;

    fn envelope(id: &str, deps: Vec<&str>) -> OperationEnvelope {
        envelope_for(id, OP_EVENTS_QUERY, json!({}), deps, false)
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
            RealmId::new("cx:realm:01904100-0000-7000-8000-6b91994c774d").unwrap(),
            Did::new("did:web:alice.example").unwrap(),
            kind,
            1,
            Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        )
        .with_content(content);
        for dep in deps {
            builder = builder.with_dependency(OperationId::new(dep).unwrap());
        }
        if authz {
            builder = builder.with_authz_ref(
                GrantId::new("cx:grant:01904100-0000-7000-8000-e78463d5d984").unwrap(),
            );
        }
        builder.build(&OperationKindRegistry::default()).unwrap()
    }

    #[test]
    fn catalog_covers_builtin_operation_surfaces() {
        let catalog = operation_catalog();
        catalog.validate().unwrap();
        assert!(catalog.rows.iter().any(|row| row.surface == OperationSurface::Events));
        assert_eq!(conformance_vectors().len(), BUILT_IN_OPERATION_KINDS.len());
    }

    #[test]
    fn dag_accepts_complete_acyclic_dependencies() {
        let mut dag = OperationDag::new();
        dag.insert(envelope("cx:operation:01904100-0000-7000-8000-b24c1b0f1a32", Vec::new()))
            .unwrap();
        dag.insert(envelope(
            "cx:operation:01904100-0000-7000-8000-bc16402a117e",
            vec!["cx:operation:01904100-0000-7000-8000-b24c1b0f1a32"],
        ))
        .unwrap();
        dag.validate().unwrap().validate_acyclic_complete().unwrap();
    }

    #[test]
    fn dag_reports_missing_dependencies() {
        let mut dag = OperationDag::new();
        dag.insert(envelope(
            "cx:operation:01904100-0000-7000-8000-bc16402a117e",
            vec!["cx:operation:01904100-0000-7000-8000-74849cf4e138"],
        ))
        .unwrap();
        let report = dag.validate().unwrap();
        assert_eq!(report.missing_dependencies.len(), 1);
        assert!(report.validate_acyclic_complete().is_err());
    }

    #[test]
    fn dag_reports_cycles_and_negative_vectors_cover_failure_modes() {
        let mut dag = OperationDag::new();
        dag.insert(envelope(
            "cx:operation:01904100-0000-7000-8000-b24c1b0f1a32",
            vec!["cx:operation:01904100-0000-7000-8000-bc16402a117e"],
        ))
        .unwrap();
        dag.insert(envelope(
            "cx:operation:01904100-0000-7000-8000-bc16402a117e",
            vec!["cx:operation:01904100-0000-7000-8000-b24c1b0f1a32"],
        ))
        .unwrap();
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
            "cx:operation:01904100-0000-7000-8000-b24c1b0f1a32",
            OP_PUSH_REGISTER_DEVICE,
            json!({
                "device_id": "cx:device:01904100-0000-7000-8000-c89a39a907e5",
                "endpoint": "https://push.example/device"
            }),
            Vec::new(),
            true,
        );
        let delete = envelope_for(
            "cx:operation:01904100-0000-7000-8000-bc16402a117e",
            OP_PUSH_UNREGISTER_DEVICE,
            json!({"device_id": "cx:device:01904100-0000-7000-8000-c89a39a907e5"}),
            vec!["cx:operation:01904100-0000-7000-8000-b24c1b0f1a32"],
            true,
        );
        let update_after_delete = envelope_for(
            "cx:operation:01904100-0000-7000-8000-57ea8fc8ec0b",
            OP_PUSH_REGISTER_DEVICE,
            json!({
                "device_id": "cx:device:01904100-0000-7000-8000-c89a39a907e5",
                "endpoint": "https://push.example/device"
            }),
            vec!["cx:operation:01904100-0000-7000-8000-bc16402a117e"],
            true,
        );
        let report = reduce_operation_semantics(&[create, delete, update_after_delete]);
        assert_eq!(report.applied.len(), 2);
        assert_eq!(report.rejected[0].kind, "create_after_tombstone");

        let missing_authz = envelope_for(
            "cx:operation:01904100-0000-7000-8000-a8e5d315a094",
            OP_PUSH_REGISTER_DEVICE,
            json!({
                "device_id": "cx:device:01904100-0000-7000-8000-9160607cbd81",
                "endpoint": "https://push.example/other"
            }),
            Vec::new(),
            false,
        );
        let report = reduce_operation_semantics(&[missing_authz]);
        assert_eq!(report.rejected[0].kind, "missing_authz");
    }

    #[test]
    fn registry_requires_semantic_content_fields() {
        let result = OperationEnvelopeBuilder::new(
            OperationId::new("cx:operation:01904100-0000-7000-8000-e0d2820b21e0").unwrap(),
            RealmId::new("cx:realm:01904100-0000-7000-8000-6b91994c774d").unwrap(),
            Did::new("did:web:alice.example").unwrap(),
            OP_PUSH_REGISTER_DEVICE,
            1,
            Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        )
        .with_content(json!({}))
        .build(&OperationKindRegistry::default());
        assert!(matches!(result, Err(Error::Protocol(_))));
    }
}
