//! Operation registry, catalog, DAG validation, and semantic-reduction
//! contracts layered over the SDK-local [`OperationEnvelope`] draft record.

use std::collections::{BTreeMap, BTreeSet};

pub use arkret_wire::OperationKind;
use arkret_wire::constants::SUPPORTED_OPERATION_IDS;
use arkret_wire::events::kinds::EventKind;
use arkret_wire::{OperationId, ServiceOperationId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::operation::OperationEnvelope;
use crate::registry::{EventDraftKindConformanceVector, event_draft_kind_conformance_vectors};
pub use crate::{CausalRef, Operation, OperationSignature};
use crate::{EventDraftError, Result};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationSurface {
    Account,
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
    AccountStream,
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
        if self.total != SUPPORTED_OPERATION_IDS.len() {
            return Err(EventDraftError::Protocol(
                "operation catalog does not cover built-ins".to_owned(),
            ));
        }
        if !self.missing_surfaces.is_empty() {
            return Err(EventDraftError::Protocol(format!(
                "operation catalog is missing surfaces: {:?}",
                self.missing_surfaces
            )));
        }
        Ok(())
    }
}

pub fn classify_operation_kind(kind: &str) -> OperationSurface {
    match kind {
        ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_DEVICE
        | ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT
        | ServiceOperationId::GATE_ACCOUNT_EXCHANGE_COMPLETE_OIDC
        | ServiceOperationId::GATE_ACCOUNT_COMMAND_REGISTER
        | ServiceOperationId::GATE_ACCOUNT_COMMAND_REVOKE_SESSION
        | ServiceOperationId::SELF_ACCOUNT_COMMAND_UPDATE_PROFILE
        | ServiceOperationId::SELF_ACCOUNT_QUERY_VIEWER => OperationSurface::Account,
        ServiceOperationId::EDGE_APPLET_QUERY_DESCRIBE
        | ServiceOperationId::EDGE_APPLET_QUERY_PING
        | ServiceOperationId::EDGE_APPLET_QUERY_PROTOCOL_METADATA
        | ServiceOperationId::EDGE_APPLET_ACTOR_QUERY_RESOLVE
        | ServiceOperationId::EDGE_APPLET_REALM_QUERY_RESOLVE
        | ServiceOperationId::EDGE_APPLET_THIRD_PARTY_LOCATIONS_QUERY_LIST
        | ServiceOperationId::EDGE_APPLET_THIRD_PARTY_USERS_QUERY_LIST
        | ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION
        | ServiceOperationId::SELF_APPLET_COMMAND_INSTALL
        | ServiceOperationId::SELF_APPLET_INSTALL_COMMAND_PREVIEW
        | ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PROVISION
        | ServiceOperationId::SELF_APPLET_COMMAND_REVOKE => OperationSurface::Applet,
        ServiceOperationId::SELF_AUTHZ_QUERY_CHECK
        | ServiceOperationId::SELF_AUTHZ_GRANTS_QUERY_EFFECTIVE
        | ServiceOperationId::SELF_AUTHZ_INVITES_QUERY_LIST => OperationSurface::Authz,
        ServiceOperationId::SELF_BLOB_UPLOAD_CREATE
        | ServiceOperationId::SELF_BLOB_RESOURCE_HEAD
        | ServiceOperationId::SELF_BLOB_RESOURCE_GET => OperationSurface::Blob,
        ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_SEND
        | ServiceOperationId::SELF_DEVICE_MESSAGES_QUERY_LIST
        | ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_ACK => OperationSurface::DeviceMessages,
        ServiceOperationId::FIND_DIRECTORY_COMMAND_ANNOUNCE
        | ServiceOperationId::FIND_DIRECTORY_QUERY_DESCRIBE
        | ServiceOperationId::FIND_DIRECTORY_QUERY_PRIVATE_CONTACT_DISCOVERY
        | ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_HANDLE
        | ServiceOperationId::FIND_DIRECTORY_QUERY_LIST_HANDLES_FOR_SUBJECT
        | ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_ORGANIZATION
        | ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_REALM
        | ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_TARGET
        | ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_ACTORS
        | ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_ORGANIZATIONS
        | ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_REALMS
        | ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_USERS
        | ServiceOperationId::FIND_DIRECTORY_PUSH_COMMAND_REGISTER
        | ServiceOperationId::FIND_DIRECTORY_COMMAND_WITHDRAW => OperationSurface::Directory,
        ServiceOperationId::SELF_EVENTS_READ_DESCRIBE
        | ServiceOperationId::SELF_EVENTS_READ_FRONTIER
        | ServiceOperationId::SELF_EVENTS_RESOURCE_GET
        | ServiceOperationId::SELF_EVENTS_READ_SCAN
        | ServiceOperationId::SELF_EVENTS_READ_RESOLVE
        | ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE
        | ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT
        | ServiceOperationId::PEER_EVENTS_READ_DESCRIBE
        | ServiceOperationId::PEER_EVENTS_READ_FRONTIER
        // `POST /_arkret/peer/events/query` stopped being its own operation:
        // it is a compatibility binding of `ak.peer.events.read.scan`.
        | ServiceOperationId::PEER_EVENTS_READ_SCAN
        | ServiceOperationId::PEER_EVENTS_READ_RESOLVE
        | ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT => OperationSurface::Events,
        ServiceOperationId::ROOT_IDENTITY_REGISTRY_QUERY_DESCRIBE
        | ServiceOperationId::ROOT_IDENTITY_DOCUMENT_RESOURCE_GET
        | ServiceOperationId::ROOT_IDENTITY_LOG_QUERY_LIST
        | ServiceOperationId::ROOT_IDENTITY_RECEIPTS_QUERY_LIST
        | ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET
        | ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_COMMAND_PUBLISH
        | ServiceOperationId::ROOT_IDENTITY_QUERY_RESOLVE
        | ServiceOperationId::ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION
        | ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_CREATE
        | ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_RESOURCE_GET
        | ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_SUBMIT_PROOF => {
            OperationSurface::Identity
        }
        ServiceOperationId::SELF_KEYS_UPLOAD_CREATE
        | ServiceOperationId::SELF_KEYS_QUERY_LOOKUP
        | ServiceOperationId::SELF_KEYS_COMMAND_CLAIM
        | ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE
        | ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM
        | ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME
        | ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_REVOKE
        | ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_REPLACE
        | ServiceOperationId::SELF_KEYS_BACKUPS_QUERY_LIST
        | ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_UNLOCK
        | ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_DELETE => OperationSurface::Keys,
        ServiceOperationId::SELF_MEDIA_QUERY_ICE_CONFIG => OperationSurface::Media,
        ServiceOperationId::OPEN_MIMI_QUERY_GROUP_INFO
        | ServiceOperationId::OPEN_MIMI_QUERY_IDENTIFIERS
        | ServiceOperationId::OPEN_MIMI_EXCHANGE_REQUEST_KEY_MATERIAL
        | ServiceOperationId::OPEN_MIMI_COMMAND_NOTIFY
        | ServiceOperationId::OPEN_MIMI_QUERY_PROVIDER_DIRECTORY
        | ServiceOperationId::OPEN_MIMI_COMMAND_PROXY_DOWNLOAD
        | ServiceOperationId::OPEN_MIMI_COMMAND_REPORT_ABUSE
        | ServiceOperationId::OPEN_MIMI_COMMAND_REQUEST_CONSENT
        | ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_ROOM
        | ServiceOperationId::OPEN_MIMI_COMMAND_SUBMIT_MESSAGE
        | ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_CONSENT => OperationSurface::Mimi,
        ServiceOperationId::SELF_MODERATION_COMMAND_REPORT => OperationSurface::Moderation,
        ServiceOperationId::SELF_POLICY_QUERY_CHECK => OperationSurface::Policy,
        ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY
        | ServiceOperationId::EDGE_PUSH_COMMAND_REGISTER_DEVICE
        | ServiceOperationId::EDGE_PUSH_COMMAND_UNREGISTER_DEVICE => OperationSurface::Push,
        ServiceOperationId::SERVER_QUERY_DESCRIBE => OperationSurface::Server,
        ServiceOperationId::SELF_ACCOUNT_QUERY_DESCRIBE
        | ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE
        | ServiceOperationId::SELF_ACCOUNT_COMMAND_REVOKE_CURSOR
        | ServiceOperationId::SELF_SNAPSHOT_QUERY_MANIFEST_HEAD
        | ServiceOperationId::PEER_SNAPSHOT_QUERY_MANIFEST_HEAD => OperationSurface::AccountStream,
        _ => OperationSurface::Custom(kind.to_owned()),
    }
}

pub fn operation_catalog() -> OperationCatalogReport {
    let rows = SUPPORTED_OPERATION_IDS
        .iter()
        .map(|kind| {
            let descriptor = kind.descriptor();
            OperationCatalogRow {
                kind: kind.as_str().to_owned(),
                surface: classify_operation_kind(kind.as_str()),
                schema: descriptor.request_schema_ref.unwrap_or_default().to_owned(),
                required_content_fields: Vec::new(),
            }
        })
        .collect::<Vec<_>>();
    let covered = rows
        .iter()
        .map(|row| row.surface.clone())
        .collect::<BTreeSet<_>>();
    let required_surfaces = [
        OperationSurface::Account,
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
        OperationSurface::AccountStream,
    ];
    let missing_surfaces = required_surfaces
        .into_iter()
        .filter(|surface| !covered.contains(surface))
        .collect();
    OperationCatalogReport {
        total: rows.len(),
        rows,
        missing_surfaces,
    }
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
            return Err(EventDraftError::Protocol(format!(
                "operation {} is already present in the DAG",
                operation.operation_id
            )));
        }
        self.operations
            .insert(operation.operation_id.clone(), operation);
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
        let operation = self.operations.get(operation_id).ok_or_else(|| {
            EventDraftError::Protocol("operation DAG references missing node".to_owned())
        })?;
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
            return Err(EventDraftError::Protocol(
                "operation DAG contains a cycle".to_owned(),
            ));
        }
        if !self.missing_dependencies.is_empty() {
            return Err(EventDraftError::Protocol(
                "operation DAG has missing dependencies".to_owned(),
            ));
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
            Err(EventDraftError::Protocol(format!(
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
                self.active_targets
                    .insert(target_id, effect.operation_id.clone());
            }
            OperationMutation::Delete | OperationMutation::Redact => {
                self.active_targets.remove(&target_id);
                self.tombstoned_targets
                    .insert(target_id, effect.operation_id.clone());
            }
            OperationMutation::Read => {}
        }
    }
}

pub fn semantic_effect(operation: &OperationEnvelope) -> OperationSemanticEffect {
    let event_kind = EventKind::from_wire(&operation.kind);
    let surface = if matches!(event_kind, EventKind::Unknown(_)) {
        OperationSurface::Custom(operation.kind.clone())
    } else {
        OperationSurface::Events
    };
    let mutation = mutation_for_event_kind(&event_kind);
    let target_id = target_id_for_event_draft(operation, &event_kind);
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

fn mutation_for_event_kind(kind: &EventKind) -> OperationMutation {
    match kind {
        EventKind::SpaceCreate
        | EventKind::StrandCreate
        | EventKind::MorphCreate
        | EventKind::RelationCreate => OperationMutation::Create,
        EventKind::SpaceTombstone | EventKind::RelationTombstone => OperationMutation::Delete,
        EventKind::MessageRedact => OperationMutation::Redact,
        EventKind::Unknown(_) => OperationMutation::External,
        _ => OperationMutation::Update,
    }
}

fn target_id_for_event_draft(operation: &OperationEnvelope, kind: &EventKind) -> Option<String> {
    if let Some(target_ref) = &operation.target_ref {
        return Some(target_ref.clone());
    }
    let fields: &[&str] = match kind {
        EventKind::SpaceCreate
        | EventKind::SpaceUpdate
        | EventKind::SpaceParent
        | EventKind::SpaceArchive
        | EventKind::SpaceRestore
        | EventKind::SpaceTombstone => &["space_id"],
        EventKind::StrandCreate
        | EventKind::StrandUpdate
        | EventKind::StrandArchive
        | EventKind::StrandRestore => &["strand_id"],
        EventKind::MorphCreate
        | EventKind::MorphUpdate
        | EventKind::MorphArchive
        | EventKind::MorphRestore => &["morph_id"],
        EventKind::RelationCreate | EventKind::RelationUpdate | EventKind::RelationTombstone => {
            &["relation_id"]
        }
        _ => &[],
    };
    fields.iter().find_map(|field| {
        operation
            .payload
            .get(*field)
            .and_then(Value::as_str)
            .map(str::to_owned)
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

pub fn conformance_vectors() -> Vec<EventDraftKindConformanceVector> {
    event_draft_kind_conformance_vectors()
}

pub mod protocol {
    pub use arkret_wire::OperationKind;

    pub use crate::{
        EventDraftKindConformanceVector, EventDraftKindRegistry, EventDraftKindSpec,
        EventDraftKindValidation, Operation, OperationEnvelope, OperationEnvelopeBuilder,
    };
}

#[cfg(test)]
mod tests {
    use arkret_wire::{Did, GrantId, Hlc, RealmId, ScopeRef};
    use serde_json::json;

    use super::*;
    use crate::OperationEnvelopeBuilder;
    use crate::registry::EventDraftKindRegistry;

    fn scope() -> ScopeRef {
        ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:01904100-0000-8000-8000-6b91994c774d").unwrap(),
        }
    }

    fn envelope(id: &str, deps: Vec<&str>) -> OperationEnvelope {
        envelope_for(id, EventKind::REALM_CREATE, json!({}), deps, false)
    }

    fn envelope_for(
        id: &str,
        kind: &str,
        payload: Value,
        deps: Vec<&str>,
        authz: bool,
    ) -> OperationEnvelope {
        let mut builder = OperationEnvelopeBuilder::new(
            OperationId::new(id).unwrap(),
            scope(),
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            kind,
            1,
            Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        )
        .with_payload(payload);
        for dep in deps {
            builder = builder.with_dependency(OperationId::new(dep).unwrap());
        }
        if authz {
            builder = builder.with_authz_ref(
                GrantId::new("ak:grant:01904100-0000-7000-8000-e78463d5d984").unwrap(),
            );
        }
        builder.build(&EventDraftKindRegistry::default()).unwrap()
    }

    #[test]
    fn catalog_covers_builtin_operation_surfaces() {
        let catalog = operation_catalog();
        catalog.validate().unwrap();
        assert!(
            catalog
                .rows
                .iter()
                .any(|row| row.surface == OperationSurface::Events)
        );
        assert_eq!(conformance_vectors().len(), EventKind::ALL.len());
    }

    #[test]
    fn dag_accepts_complete_acyclic_dependencies() {
        let mut dag = OperationDag::new();
        dag.insert(envelope(
            "ak:operation:01904100-0000-7000-8000-b24c1b0f1a32",
            Vec::new(),
        ))
        .unwrap();
        dag.insert(envelope(
            "ak:operation:01904100-0000-7000-8000-bc16402a117e",
            vec!["ak:operation:01904100-0000-7000-8000-b24c1b0f1a32"],
        ))
        .unwrap();
        dag.validate().unwrap().validate_acyclic_complete().unwrap();
    }

    #[test]
    fn dag_reports_missing_dependencies() {
        let mut dag = OperationDag::new();
        dag.insert(envelope(
            "ak:operation:01904100-0000-7000-8000-bc16402a117e",
            vec!["ak:operation:01904100-0000-7000-8000-74849cf4e138"],
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
            "ak:operation:01904100-0000-7000-8000-b24c1b0f1a32",
            vec!["ak:operation:01904100-0000-7000-8000-bc16402a117e"],
        ))
        .unwrap();
        dag.insert(envelope(
            "ak:operation:01904100-0000-7000-8000-bc16402a117e",
            vec!["ak:operation:01904100-0000-7000-8000-b24c1b0f1a32"],
        ))
        .unwrap();
        let report = dag.validate().unwrap();
        assert!(report.has_cycle);
        assert!(report.validate_acyclic_complete().is_err());

        let issues = negative_dag_vectors()
            .into_iter()
            .map(|vector| vector.issue)
            .collect::<BTreeSet<_>>();
        assert!(issues.contains(&OperationDagNegativeKind::Cycle));
        assert!(issues.contains(&OperationDagNegativeKind::MutationAfterTombstone));
        assert!(issues.contains(&OperationDagNegativeKind::MissingAuthz));
    }

    #[test]
    fn semantic_reducer_rejects_tombstone_mutations_and_missing_authz() {
        let create = envelope_for(
            "ak:operation:01904100-0000-7000-8000-b24c1b0f1a32",
            EventKind::SPACE_CREATE,
            json!({
                "object": {},
                "space_id": "ak:space:01904100-0000-8000-8000-c89a39a907e5"
            }),
            Vec::new(),
            true,
        );
        let delete = envelope_for(
            "ak:operation:01904100-0000-7000-8000-bc16402a117e",
            EventKind::SPACE_TOMBSTONE,
            json!({"space_id": "ak:space:01904100-0000-8000-8000-c89a39a907e5"}),
            vec!["ak:operation:01904100-0000-7000-8000-b24c1b0f1a32"],
            true,
        );
        let update_after_delete = envelope_for(
            "ak:operation:01904100-0000-7000-8000-57ea8fc8ec0b",
            EventKind::SPACE_CREATE,
            json!({
                "object": {},
                "space_id": "ak:space:01904100-0000-8000-8000-c89a39a907e5"
            }),
            vec!["ak:operation:01904100-0000-7000-8000-bc16402a117e"],
            true,
        );
        let report = reduce_operation_semantics(&[create, delete, update_after_delete]);
        assert_eq!(report.applied.len(), 2);
        assert_eq!(report.rejected[0].kind, "create_after_tombstone");

        let missing_authz = envelope_for(
            "ak:operation:01904100-0000-7000-8000-a8e5d315a094",
            EventKind::SPACE_CREATE,
            json!({
                "object": {},
                "space_id": "ak:space:01904100-0000-8000-8000-9160607cbd81"
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
            OperationId::new("ak:operation:01904100-0000-7000-8000-e0d2820b21e0").unwrap(),
            scope(),
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            EventKind::SPACE_CREATE,
            1,
            Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        )
        .with_payload(json!({}))
        .build(&EventDraftKindRegistry::default());
        assert!(matches!(result, Err(EventDraftError::Protocol(_))));
    }
}
