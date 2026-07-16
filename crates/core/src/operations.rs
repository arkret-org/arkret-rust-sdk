//! Operation registry, builder and DAG validation contracts.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::*;
pub use crate::{CausalRef, Operation, OperationSignature, OperationType};

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
            return Err(Error::Protocol(
                "operation catalog does not cover built-ins".to_owned(),
            ));
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
        crate::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_DEVICE
        | crate::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT
        | crate::ServiceOperationId::GATE_ACCOUNT_EXCHANGE_COMPLETE_OIDC
        | crate::ServiceOperationId::GATE_ACCOUNT_COMMAND_REGISTER
        | crate::ServiceOperationId::GATE_ACCOUNT_COMMAND_REVOKE_SESSION
        | crate::ServiceOperationId::SELF_ACCOUNT_COMMAND_UPDATE_PROFILE
        | crate::ServiceOperationId::SELF_ACCOUNT_QUERY_VIEWER => OperationSurface::Account,
        crate::ServiceOperationId::EDGE_APPLET_QUERY_DESCRIBE
        | crate::ServiceOperationId::EDGE_APPLET_QUERY_PING
        | crate::ServiceOperationId::EDGE_APPLET_QUERY_PROTOCOL_METADATA
        | crate::ServiceOperationId::EDGE_APPLET_ACTOR_QUERY_RESOLVE
        | crate::ServiceOperationId::EDGE_APPLET_REALM_QUERY_RESOLVE
        | crate::ServiceOperationId::EDGE_APPLET_THIRD_PARTY_LOCATIONS_QUERY_LIST
        | crate::ServiceOperationId::EDGE_APPLET_THIRD_PARTY_USERS_QUERY_LIST
        | crate::ServiceOperationId::EDGE_APPLET_COMMAND_TRANSACTION
        | crate::ServiceOperationId::SELF_APPLET_COMMAND_INSTALL
        | crate::ServiceOperationId::SELF_APPLET_INSTALL_COMMAND_PREVIEW
        | crate::ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PROVISION
        | crate::ServiceOperationId::SELF_APPLET_COMMAND_REVOKE => OperationSurface::Applet,
        crate::ServiceOperationId::SELF_AUTHZ_QUERY_CHECK
        | crate::ServiceOperationId::SELF_AUTHZ_GRANTS_QUERY_EFFECTIVE
        | crate::ServiceOperationId::SELF_AUTHZ_INVITES_QUERY_LIST => OperationSurface::Authz,
        crate::ServiceOperationId::SELF_BLOB_UPLOAD_CREATE
        | crate::ServiceOperationId::SELF_BLOB_RESOURCE_HEAD
        | crate::ServiceOperationId::SELF_BLOB_RESOURCE_GET => OperationSurface::Blob,
        crate::ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_SEND
        | crate::ServiceOperationId::SELF_DEVICE_MESSAGES_QUERY_LIST
        | crate::ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_ACK => {
            OperationSurface::DeviceMessages
        }
        crate::ServiceOperationId::FIND_DIRECTORY_COMMAND_ANNOUNCE
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_DESCRIBE
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_PRIVATE_CONTACT_DISCOVERY
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_HANDLE
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_LIST_HANDLES_FOR_SUBJECT
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_ORGANIZATION
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_REALM
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_TARGET
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_ACTORS
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_ORGANIZATIONS
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_REALMS
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_USERS
        | crate::ServiceOperationId::FIND_DIRECTORY_PUSH_COMMAND_REGISTER
        | crate::ServiceOperationId::FIND_DIRECTORY_COMMAND_WITHDRAW => OperationSurface::Directory,
        crate::ServiceOperationId::SELF_EVENTS_QUERY_DESCRIBE
        | crate::ServiceOperationId::SELF_EVENTS_QUERY_FRONTIER
        | crate::ServiceOperationId::SELF_EVENTS_RESOURCE_GET
        | crate::ServiceOperationId::SELF_EVENTS_QUERY_SCAN
        | crate::ServiceOperationId::SELF_EVENTS_QUERY_RESOLVE
        | crate::ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE
        | crate::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT
        | crate::ServiceOperationId::PEER_EVENTS_QUERY_DESCRIBE
        | crate::ServiceOperationId::PEER_EVENTS_QUERY_FRONTIER
        | crate::ServiceOperationId::PEER_EVENTS_QUERY_SCAN
        | crate::ServiceOperationId::PEER_EVENTS_QUERY_SCAN_BODY
        | crate::ServiceOperationId::PEER_EVENTS_QUERY_RESOLVE
        | crate::ServiceOperationId::PEER_EVENTS_COMMAND_SUBMIT => OperationSurface::Events,
        crate::ServiceOperationId::ROOT_IDENTITY_REGISTRY_QUERY_DESCRIBE
        | crate::ServiceOperationId::ROOT_IDENTITY_DOCUMENT_RESOURCE_GET
        | crate::ServiceOperationId::ROOT_IDENTITY_LOG_QUERY_LIST
        | crate::ServiceOperationId::ROOT_IDENTITY_RECEIPTS_QUERY_LIST
        | crate::ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET
        | crate::ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_COMMAND_PUBLISH
        | crate::ServiceOperationId::ROOT_IDENTITY_QUERY_RESOLVE
        | crate::ServiceOperationId::ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION
        | crate::ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_CREATE
        | crate::ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_RESOURCE_GET
        | crate::ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_SUBMIT_PROOF
        | crate::ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_COMPLETE => {
            OperationSurface::Identity
        }
        crate::ServiceOperationId::SELF_KEYS_UPLOAD_CREATE
        | crate::ServiceOperationId::SELF_KEYS_QUERY_LOOKUP
        | crate::ServiceOperationId::SELF_KEYS_COMMAND_CLAIM
        | crate::ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE
        | crate::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM
        | crate::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME
        | crate::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_REVOKE
        | crate::ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_REPLACE
        | crate::ServiceOperationId::SELF_KEYS_BACKUPS_QUERY_LIST
        | crate::ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_UNLOCK
        | crate::ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_DELETE => OperationSurface::Keys,
        crate::ServiceOperationId::SELF_MEDIA_QUERY_ICE_CONFIG => OperationSurface::Media,
        crate::ServiceOperationId::OPEN_MIMI_QUERY_GROUP_INFO
        | crate::ServiceOperationId::OPEN_MIMI_QUERY_IDENTIFIERS
        | crate::ServiceOperationId::OPEN_MIMI_EXCHANGE_REQUEST_KEY_MATERIAL
        | crate::ServiceOperationId::OPEN_MIMI_COMMAND_NOTIFY
        | crate::ServiceOperationId::OPEN_MIMI_QUERY_PROVIDER_DIRECTORY
        | crate::ServiceOperationId::OPEN_MIMI_COMMAND_PROXY_DOWNLOAD
        | crate::ServiceOperationId::OPEN_MIMI_COMMAND_REPORT_ABUSE
        | crate::ServiceOperationId::OPEN_MIMI_COMMAND_REQUEST_CONSENT
        | crate::ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_ROOM
        | crate::ServiceOperationId::OPEN_MIMI_COMMAND_SUBMIT_MESSAGE
        | crate::ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_CONSENT => OperationSurface::Mimi,
        crate::ServiceOperationId::SELF_MODERATION_COMMAND_REPORT => OperationSurface::Moderation,
        crate::ServiceOperationId::SELF_POLICY_QUERY_CHECK => OperationSurface::Policy,
        crate::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY
        | crate::ServiceOperationId::EDGE_PUSH_COMMAND_REGISTER_DEVICE
        | crate::ServiceOperationId::EDGE_PUSH_COMMAND_UNREGISTER_DEVICE => OperationSurface::Push,
        crate::ServiceOperationId::SERVER_QUERY_DESCRIBE => OperationSurface::Server,
        crate::ServiceOperationId::SELF_ACCOUNT_QUERY_DESCRIBE
        | crate::ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE
        | crate::ServiceOperationId::SELF_ACCOUNT_COMMAND_REVOKE_CURSOR
        | crate::ServiceOperationId::SELF_SNAPSHOT_QUERY_MANIFEST_HEAD
        | crate::ServiceOperationId::PEER_SNAPSHOT_QUERY_MANIFEST_HEAD => {
            OperationSurface::AccountStream
        }
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
            return Err(Error::IdempotencyConflict(
                operation.operation_id.to_string(),
            ));
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
            return Err(Error::Protocol(
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
    let surface = classify_operation_kind(&operation.kind);
    let mutation = mutation_for_kind(&operation.kind);
    let target_id = target_id_for_operation(&operation.kind, &operation.payload);
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
        crate::ServiceOperationId::EDGE_PUSH_COMMAND_REGISTER_DEVICE
        | crate::ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_REPLACE
        | crate::ServiceOperationId::SELF_KEYS_KEYPACKAGES_UPLOAD_CREATE
        | crate::ServiceOperationId::FIND_DIRECTORY_PUSH_COMMAND_REGISTER => OperationMutation::Create,
        crate::ServiceOperationId::EDGE_PUSH_COMMAND_UNREGISTER_DEVICE | crate::ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_DELETE => OperationMutation::Delete,
        crate::ServiceOperationId::SERVER_QUERY_DESCRIBE
        | crate::ServiceOperationId::SELF_ACCOUNT_QUERY_DESCRIBE
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_DESCRIBE
        | crate::ServiceOperationId::SELF_EVENTS_QUERY_DESCRIBE
        | crate::ServiceOperationId::SELF_EVENTS_RESOURCE_GET
        | crate::ServiceOperationId::SELF_EVENTS_QUERY_RESOLVE
        | crate::ServiceOperationId::SELF_EVENTS_QUERY_FRONTIER
        | crate::ServiceOperationId::SELF_EVENTS_QUERY_SCAN
        | crate::ServiceOperationId::SELF_EVENTS_STREAM_SUBSCRIBE
        | crate::ServiceOperationId::SELF_SNAPSHOT_QUERY_MANIFEST_HEAD
        | crate::ServiceOperationId::SELF_MORPH_RESOURCE_GET
        | crate::ServiceOperationId::SELF_VIEWS_COLLECTION_PROJECTION_COMMAND_MATERIALIZE
        | crate::ServiceOperationId::ROOT_IDENTITY_REGISTRY_QUERY_DESCRIBE
        | crate::ServiceOperationId::ROOT_IDENTITY_QUERY_RESOLVE
        | crate::ServiceOperationId::ROOT_IDENTITY_DOCUMENT_RESOURCE_GET
        | crate::ServiceOperationId::ROOT_IDENTITY_LOG_QUERY_LIST
        | crate::ServiceOperationId::ROOT_IDENTITY_RECEIPTS_QUERY_LIST
        | crate::ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET
        | crate::ServiceOperationId::SELF_BLOB_RESOURCE_HEAD
        | crate::ServiceOperationId::SELF_BLOB_RESOURCE_GET
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_HANDLE
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_LIST_HANDLES_FOR_SUBJECT
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_ORGANIZATION
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_REALM
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_TARGET
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_ACTORS
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_ORGANIZATIONS
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_REALMS
        | crate::ServiceOperationId::FIND_DIRECTORY_QUERY_SEARCH_USERS
        | crate::ServiceOperationId::SELF_AUTHZ_GRANTS_QUERY_EFFECTIVE
        | crate::ServiceOperationId::SELF_AUTHZ_INVITES_QUERY_LIST
        | crate::ServiceOperationId::OPEN_INVITE_LOCATOR_QUERY_RESOLVE
        | crate::ServiceOperationId::SELF_KEYS_BACKUPS_QUERY_LIST
        // `unlock` is the proof-gated retrieval of a backup (POST wire shape,
        // read semantics — it returns the stored ak.schema.key_backup.v1
        // envelope without mutating it).
        | crate::ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_UNLOCK
        | crate::ServiceOperationId::SELF_KEYS_QUERY_LOOKUP
        | crate::ServiceOperationId::SELF_AUTHZ_QUERY_CHECK => OperationMutation::Read,
        crate::ServiceOperationId::SELF_EVENTS_COMMAND_SUBMIT
        | crate::ServiceOperationId::SELF_ACCOUNT_STREAM_SUBSCRIBE
        | crate::ServiceOperationId::SELF_ACCOUNT_COMMAND_REVOKE_CURSOR
        | crate::ServiceOperationId::EDGE_PUSH_COMMAND_NOTIFY
        | crate::ServiceOperationId::SELF_KEYS_UPLOAD_CREATE
        | crate::ServiceOperationId::SELF_KEYS_COMMAND_CLAIM
        | crate::ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_SEND
        | crate::ServiceOperationId::SELF_DEVICE_MESSAGES_QUERY_LIST
        | crate::ServiceOperationId::SELF_MEDIA_QUERY_ICE_CONFIG
        | crate::ServiceOperationId::OPEN_MIMI_QUERY_PROVIDER_DIRECTORY
        | crate::ServiceOperationId::OPEN_MIMI_QUERY_GROUP_INFO
        | crate::ServiceOperationId::OPEN_MIMI_EXCHANGE_REQUEST_KEY_MATERIAL
        | crate::ServiceOperationId::OPEN_MIMI_COMMAND_SUBMIT_MESSAGE
        | crate::ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_ROOM
        | crate::ServiceOperationId::OPEN_MIMI_COMMAND_REQUEST_CONSENT
        | crate::ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_CONSENT
        | crate::ServiceOperationId::OPEN_MIMI_QUERY_IDENTIFIERS
        | crate::ServiceOperationId::OPEN_MIMI_COMMAND_NOTIFY
        | crate::ServiceOperationId::OPEN_MIMI_COMMAND_REPORT_ABUSE
        | crate::ServiceOperationId::OPEN_MIMI_COMMAND_PROXY_DOWNLOAD
        | crate::ServiceOperationId::PEER_INVITES_COMMAND_SUBMIT
        | crate::ServiceOperationId::SELF_POLICY_QUERY_CHECK => OperationMutation::External,
        _ => OperationMutation::Update,
    }
}

fn target_id_for_operation(kind: &str, payload: &Value) -> Option<String> {
    let fields: &[&str] = match kind {
        crate::ServiceOperationId::SELF_EVENTS_RESOURCE_GET
        | crate::ServiceOperationId::SELF_EVENTS_QUERY_RESOLVE => &["event_id"],
        crate::ServiceOperationId::SELF_EVENTS_QUERY_FRONTIER
        | crate::ServiceOperationId::SELF_SNAPSHOT_QUERY_MANIFEST_HEAD
        | crate::ServiceOperationId::SELF_AUTHZ_INVITES_QUERY_LIST => &["realm_id"],
        crate::ServiceOperationId::ROOT_IDENTITY_QUERY_RESOLVE
        | crate::ServiceOperationId::ROOT_IDENTITY_DOCUMENT_RESOURCE_GET
        | crate::ServiceOperationId::ROOT_IDENTITY_LOG_QUERY_LIST
        | crate::ServiceOperationId::ROOT_IDENTITY_RECEIPTS_QUERY_LIST
        | crate::ServiceOperationId::ROOT_IDENTITY_COMMAND_SUBMIT_DID_OPERATION => &["did"],
        crate::ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_REPLACE
        | crate::ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_UNLOCK
        | crate::ServiceOperationId::SELF_KEYS_BACKUPS_RESOURCE_DELETE => &["backup_id"],
        crate::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CLAIM => &["target_principal_id"],
        crate::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_CONSUME => &["claim_id"],
        crate::ServiceOperationId::SELF_KEYS_KEYPACKAGES_COMMAND_REVOKE => {
            &["principal_id", "keypackage_ref"]
        }
        crate::ServiceOperationId::EDGE_PUSH_COMMAND_REGISTER_DEVICE
        | crate::ServiceOperationId::EDGE_PUSH_COMMAND_UNREGISTER_DEVICE => &["device_id"],
        crate::ServiceOperationId::FIND_DIRECTORY_QUERY_RESOLVE_TARGET => &["address"],
        crate::ServiceOperationId::FIND_DIRECTORY_PUSH_COMMAND_REGISTER => {
            &["subscriber_did", "webhook_endpoint"]
        }
        crate::ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_SEND
        | crate::ServiceOperationId::SELF_DEVICE_MESSAGES_QUERY_LIST => {
            &["recipient_principal_id", "recipient_device_id"]
        }
        crate::ServiceOperationId::SELF_DEVICE_MESSAGES_COMMAND_ACK => &["ack_token"],
        crate::ServiceOperationId::SELF_APPLET_GHOST_COMMAND_PROVISION => {
            &["applet_id", "ghost_actor_id", "external_user_id"]
        }
        crate::ServiceOperationId::GATE_ACCOUNT_COMMAND_PAIR_DEVICE
        | crate::ServiceOperationId::GATE_ACCOUNT_COMMAND_ISSUE_SESSION_GRANT => &["principal_id"],
        crate::ServiceOperationId::SELF_MODERATION_COMMAND_REPORT => &["target_ref"],
        crate::ServiceOperationId::OPEN_INVITE_LOCATOR_QUERY_RESOLVE => &["locator_token"],
        crate::ServiceOperationId::PEER_INVITES_COMMAND_SUBMIT => &["idempotency_key"],
        crate::ServiceOperationId::SELF_POLICY_QUERY_CHECK => &["resource"],
        crate::ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET
        | crate::ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_COMMAND_PUBLISH => {
            &["principal_id"]
        }
        crate::ServiceOperationId::SELF_MORPH_RESOURCE_GET => &["realm_id", "morph_id"],
        crate::ServiceOperationId::SELF_VIEWS_COLLECTION_PROJECTION_COMMAND_MATERIALIZE => {
            &["view_id"]
        }
        _ => &[],
    };
    fields.iter().find_map(|field| {
        payload
            .get(*field)
            .and_then(Value::as_str)
            .map(|value| format!("{field}:{value}"))
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
    pub use crate::{
        EventDraftKindConformanceVector, EventDraftKindRegistry, EventDraftKindSpec,
        EventDraftKindValidation, Operation, OperationEnvelope, OperationEnvelopeBuilder,
        OperationType,
    };
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::{Did, GrantId, Hlc, OperationEnvelopeBuilder};

    fn envelope(id: &str, deps: Vec<&str>) -> OperationEnvelope {
        envelope_for(
            id,
            crate::ServiceOperationId::SELF_EVENTS_QUERY_SCAN,
            json!({}),
            deps,
            false,
        )
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
            RealmId::new("ak:realm:01904100-0000-7000-8000-6b91994c774d").unwrap(),
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
        assert_eq!(
            conformance_vectors().len(),
            crate::events::EventKind::ALL.len()
        );
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
            crate::ServiceOperationId::EDGE_PUSH_COMMAND_REGISTER_DEVICE,
            json!({
                "device_id": "ak:device:01904100-0000-7000-8000-c89a39a907e5",
                "endpoint": "https://push.example/device"
            }),
            Vec::new(),
            true,
        );
        let delete = envelope_for(
            "ak:operation:01904100-0000-7000-8000-bc16402a117e",
            crate::ServiceOperationId::EDGE_PUSH_COMMAND_UNREGISTER_DEVICE,
            json!({"device_id": "ak:device:01904100-0000-7000-8000-c89a39a907e5"}),
            vec!["ak:operation:01904100-0000-7000-8000-b24c1b0f1a32"],
            true,
        );
        let update_after_delete = envelope_for(
            "ak:operation:01904100-0000-7000-8000-57ea8fc8ec0b",
            crate::ServiceOperationId::EDGE_PUSH_COMMAND_REGISTER_DEVICE,
            json!({
                "device_id": "ak:device:01904100-0000-7000-8000-c89a39a907e5",
                "endpoint": "https://push.example/device"
            }),
            vec!["ak:operation:01904100-0000-7000-8000-bc16402a117e"],
            true,
        );
        let report = reduce_operation_semantics(&[create, delete, update_after_delete]);
        assert_eq!(report.applied.len(), 2);
        assert_eq!(report.rejected[0].kind, "create_after_tombstone");

        let missing_authz = envelope_for(
            "ak:operation:01904100-0000-7000-8000-a8e5d315a094",
            crate::ServiceOperationId::EDGE_PUSH_COMMAND_REGISTER_DEVICE,
            json!({
                "device_id": "ak:device:01904100-0000-7000-8000-9160607cbd81",
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
            OperationId::new("ak:operation:01904100-0000-7000-8000-e0d2820b21e0").unwrap(),
            RealmId::new("ak:realm:01904100-0000-7000-8000-6b91994c774d").unwrap(),
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            crate::ServiceOperationId::EDGE_PUSH_COMMAND_REGISTER_DEVICE,
            1,
            Hlc::new("01970e589d21-0001-a13f9c2e").unwrap(),
        )
        .with_payload(json!({}))
        .build(&EventDraftKindRegistry::default());
        assert!(matches!(result, Err(Error::Protocol(_))));
    }
}
