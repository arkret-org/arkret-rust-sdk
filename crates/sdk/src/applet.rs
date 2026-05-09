//! Applet schema, OpenAPI binding and portal helpers.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ulid::Ulid;

use crate::{
    Did, Error, Event, Result, SpaceId, canonical,
    model::{
        AppletActorResponse, AppletSpaceResponse, AppletTransactionRequest,
        AppletTransactionResponse,
    },
};

/// Applet permission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletPermission {
    pub resource: String,
    pub actions: BTreeSet<String>,
}

/// OpenAPI binding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenApiBinding {
    pub base_url: String,
    pub operations: BTreeMap<String, String>,
}

/// Applet schema.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppletSchema {
    pub applet_id: String,
    pub name: String,
    pub version: String,
    pub permissions: Vec<AppletPermission>,
    pub openapi: Option<OpenApiBinding>,
    pub schema: Value,
}

impl AppletSchema {
    /// Validate required fields.
    pub fn validate(&self) -> Result<()> {
        if self.applet_id.is_empty() || self.name.is_empty() || self.version.is_empty() {
            return Err(Error::Protocol("applet schema missing required fields".to_owned()));
        }
        Ok(())
    }

    /// Check permission.
    pub fn allows(&self, resource: &str, action: &str) -> bool {
        self.permissions.iter().any(|permission| {
            permission.resource == resource && permission.actions.contains(action)
        })
    }
}

/// Namespace domain declared by an applet or appservice.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletNamespaceKind {
    Actor,
    Alias,
    Space,
    Event,
    Entity,
    Command,
}

/// Namespace declaration for applet ownership and bridge routing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletNamespaceDeclaration {
    pub kind: AppletNamespaceKind,
    pub pattern: String,
    #[serde(default)]
    pub exclusive: bool,
}

impl AppletNamespaceDeclaration {
    /// Create an exclusive namespace declaration.
    pub fn exclusive(kind: AppletNamespaceKind, pattern: impl Into<String>) -> Self {
        Self { kind, pattern: pattern.into(), exclusive: true }
    }

    /// Return whether two declarations conflict.
    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.kind == other.kind
            && (self.exclusive || other.exclusive)
            && namespace_patterns_overlap(&self.pattern, &other.pattern)
    }
}

/// Namespace conflict detected during applet registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletNamespaceConflict {
    pub kind: AppletNamespaceKind,
    pub pattern: String,
    pub conflicting_applet_id: String,
    pub conflicting_pattern: String,
}

/// Signed applet registration with namespace declarations.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedAppletRegistration {
    pub registration_id: String,
    pub applet_id: String,
    pub service_did: Did,
    pub schema: AppletSchema,
    #[serde(default)]
    pub namespaces: Vec<AppletNamespaceDeclaration>,
    pub signature: String,
    pub created_at: DateTime<Utc>,
}

impl SignedAppletRegistration {
    /// Build a new signed registration model.
    pub fn new(
        applet_id: impl Into<String>,
        service_did: Did,
        schema: AppletSchema,
        namespaces: Vec<AppletNamespaceDeclaration>,
        signature: impl Into<String>,
    ) -> Self {
        let applet_id = applet_id.into();
        Self {
            registration_id: format!("applet_reg_{}", Ulid::new()),
            applet_id,
            service_did,
            schema,
            namespaces,
            signature: signature.into(),
            created_at: Utc::now(),
        }
    }

    /// Validate required registration fields.
    pub fn validate(&self) -> Result<()> {
        self.schema.validate()?;
        if self.applet_id != self.schema.applet_id {
            return Err(Error::Protocol("applet registration id mismatch".to_owned()));
        }
        if self.signature.is_empty() {
            return Err(Error::Protocol("applet registration missing signature".to_owned()));
        }
        for namespace in &self.namespaces {
            if namespace.pattern.is_empty() {
                return Err(Error::Protocol("applet namespace pattern is empty".to_owned()));
            }
        }
        Ok(())
    }
}

/// Applet registry.
#[derive(Clone, Debug, Default)]
pub struct AppletRegistry {
    applets: BTreeMap<String, AppletSchema>,
    signed_registrations: BTreeMap<String, SignedAppletRegistration>,
    namespaces: Vec<(String, AppletNamespaceDeclaration)>,
}

impl AppletRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse and register an applet schema from JSON.
    pub fn register_from_value(&mut self, value: Value) -> Result<AppletSchema> {
        let schema: AppletSchema = serde_json::from_value(value)?;
        schema.validate()?;
        self.applets.insert(schema.applet_id.clone(), schema.clone());
        Ok(schema)
    }

    /// Register an applet schema.
    pub fn register(&mut self, schema: AppletSchema) -> Result<()> {
        schema.validate()?;
        self.applets.insert(schema.applet_id.clone(), schema);
        Ok(())
    }

    /// Get an applet.
    pub fn get(&self, applet_id: &str) -> Option<&AppletSchema> {
        self.applets.get(applet_id)
    }

    /// Register a signed applet and reject conflicting exclusive namespaces.
    pub fn register_signed(&mut self, registration: SignedAppletRegistration) -> Result<()> {
        registration.validate()?;
        let conflicts = self.namespace_conflicts(&registration.namespaces);
        if !conflicts.is_empty() {
            return Err(Error::Protocol("applet namespace conflict".to_owned()));
        }

        self.register(registration.schema.clone())?;
        for namespace in &registration.namespaces {
            self.namespaces.push((registration.applet_id.clone(), namespace.clone()));
        }
        self.signed_registrations.insert(registration.registration_id.clone(), registration);
        Ok(())
    }

    /// Get a signed registration.
    pub fn signed_registration(&self, registration_id: &str) -> Option<&SignedAppletRegistration> {
        self.signed_registrations.get(registration_id)
    }

    /// Find namespace conflicts for a proposed registration.
    pub fn namespace_conflicts(
        &self,
        namespaces: &[AppletNamespaceDeclaration],
    ) -> Vec<AppletNamespaceConflict> {
        namespaces
            .iter()
            .flat_map(|candidate| {
                self.namespaces.iter().filter_map(move |(applet_id, existing)| {
                    if candidate.conflicts_with(existing) {
                        Some(AppletNamespaceConflict {
                            kind: candidate.kind.clone(),
                            pattern: candidate.pattern.clone(),
                            conflicting_applet_id: applet_id.clone(),
                            conflicting_pattern: existing.pattern.clone(),
                        })
                    } else {
                        None
                    }
                })
            })
            .collect()
    }
}

/// Appservice registration model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppserviceRegistration {
    pub registration_id: String,
    pub service_did: Did,
    pub sender_localpart: String,
    #[serde(default)]
    pub namespaces: Vec<AppletNamespaceDeclaration>,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default)]
    pub receive_ephemeral: bool,
    #[serde(default)]
    pub rate_limited: bool,
}

impl AppserviceRegistration {
    /// Create a registration with a generated id.
    pub fn new(service_did: Did, sender_localpart: impl Into<String>) -> Self {
        Self {
            registration_id: format!("as_{}", Ulid::new()),
            service_did,
            sender_localpart: sender_localpart.into(),
            namespaces: Vec::new(),
            protocols: Vec::new(),
            receive_ephemeral: false,
            rate_limited: true,
        }
    }

    /// Validate required fields.
    pub fn validate(&self) -> Result<()> {
        if self.sender_localpart.is_empty() {
            return Err(Error::Protocol("appservice sender localpart is empty".to_owned()));
        }
        Ok(())
    }
}

/// Framework-neutral appservice route declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppserviceRoute {
    pub method: String,
    pub path: String,
    pub description: String,
}

/// Route set expected from appservice framework adapters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppserviceRouteSet {
    pub routes: Vec<AppserviceRoute>,
}

impl AppserviceRouteSet {
    /// Standard appservice routes for transactions and third-party lookups.
    pub fn contrix_default() -> Self {
        Self {
            routes: vec![
                AppserviceRoute {
                    method: "PUT".to_owned(),
                    path: "/_contrix/appservice/v1/transactions/{txn_id}".to_owned(),
                    description: "receive appservice transaction".to_owned(),
                },
                AppserviceRoute {
                    method: "GET".to_owned(),
                    path: "/_contrix/appservice/v1/users/{protocol}/{external_id}".to_owned(),
                    description: "query third-party user".to_owned(),
                },
                AppserviceRoute {
                    method: "GET".to_owned(),
                    path: "/_contrix/appservice/v1/locations/{protocol}/{external_id}".to_owned(),
                    description: "query third-party location".to_owned(),
                },
                AppserviceRoute {
                    method: "GET".to_owned(),
                    path: "/_contrix/appservice/v1/protocols/{protocol}".to_owned(),
                    description: "query protocol metadata".to_owned(),
                },
            ],
        }
    }
}

/// Appservice transaction with an explicit idempotency key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppserviceTransaction {
    pub transaction_id: String,
    pub request: AppletTransactionRequest,
}

/// Result of recording an idempotent transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AppserviceTransactionRecord {
    New(AppletTransactionResponse),
    Duplicate(AppletTransactionResponse),
}

/// In-memory idempotent appservice transaction store.
#[derive(Clone, Debug, Default)]
pub struct AppserviceTransactionStore {
    transactions: BTreeMap<String, (String, AppletTransactionResponse)>,
}

impl AppserviceTransactionStore {
    /// Create an empty transaction store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a transaction or return the prior response for an exact duplicate.
    pub fn record(
        &mut self,
        transaction: &AppserviceTransaction,
        response: AppletTransactionResponse,
    ) -> Result<AppserviceTransactionRecord> {
        let digest = canonical::canonical_sha256(&transaction.request)?;
        if let Some((existing_digest, existing_response)) =
            self.transactions.get(&transaction.transaction_id)
        {
            if existing_digest == &digest {
                return Ok(AppserviceTransactionRecord::Duplicate(existing_response.clone()));
            }
            return Err(Error::IdempotencyConflict(transaction.transaction_id.clone()));
        }

        self.transactions.insert(transaction.transaction_id.clone(), (digest, response.clone()));
        Ok(AppserviceTransactionRecord::New(response))
    }
}

/// Virtual actor controlled by an appservice.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VirtualActor {
    pub actor_id: Did,
    pub service_did: Did,
    pub localpart: String,
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accountable_to: Vec<Did>,
}

/// Appservice intent for acting as a virtual actor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppserviceIntent {
    pub service_did: Did,
    pub actor_id: Did,
    pub transaction_prefix: String,
}

impl AppserviceIntent {
    /// Create a virtual actor intent.
    pub fn new(service_did: Did, actor_id: Did) -> Self {
        Self { service_did, actor_id, transaction_prefix: "as_txn".to_owned() }
    }

    /// Build an idempotent transaction envelope for events produced by this intent.
    pub fn transaction(
        &self,
        idempotency_key: impl AsRef<str>,
        events: Vec<Event>,
    ) -> AppserviceTransaction {
        AppserviceTransaction {
            transaction_id: format!("{}:{}", self.transaction_prefix, idempotency_key.as_ref()),
            request: AppletTransactionRequest {
                source_service_did: self.service_did.clone(),
                events,
                ephemeral: Value::Null,
            },
        }
    }
}

/// Third-party lookup kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThirdPartyLookupKind {
    User,
    Location,
}

/// Third-party user or location lookup request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThirdPartyLookupRequest {
    pub kind: ThirdPartyLookupKind,
    pub protocol: String,
    #[serde(default)]
    pub fields: BTreeMap<String, Value>,
}

/// Third-party lookup response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ThirdPartyLookupResponse {
    User(AppletActorResponse),
    Location(AppletSpaceResponse),
}

/// Bridge mapping from a remote user to a Contrix virtual actor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RemoteUserMapping {
    pub protocol: String,
    pub remote_user_id: String,
    pub actor_id: Did,
    pub ghost_actor: Option<Did>,
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
}

/// Bridge mapping from a remote location to a Contrix space.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RemoteSpaceMapping {
    pub protocol: String,
    pub remote_space_id: String,
    pub space_id: SpaceId,
    pub portal_id: Option<String>,
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
}

/// In-memory bridge mapping storage.
#[derive(Clone, Debug, Default)]
pub struct BridgeMappingStore {
    users: BTreeMap<String, RemoteUserMapping>,
    spaces: BTreeMap<String, RemoteSpaceMapping>,
}

impl BridgeMappingStore {
    /// Create an empty mapping store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store or replace a remote user mapping.
    pub fn upsert_user(&mut self, mapping: RemoteUserMapping) {
        self.users.insert(remote_key(&mapping.protocol, &mapping.remote_user_id), mapping);
    }

    /// Store or replace a remote space mapping.
    pub fn upsert_space(&mut self, mapping: RemoteSpaceMapping) {
        self.spaces.insert(remote_key(&mapping.protocol, &mapping.remote_space_id), mapping);
    }

    /// Resolve a remote user mapping.
    pub fn user(&self, protocol: &str, remote_user_id: &str) -> Option<&RemoteUserMapping> {
        self.users.get(&remote_key(protocol, remote_user_id))
    }

    /// Resolve a remote space mapping.
    pub fn space(&self, protocol: &str, remote_space_id: &str) -> Option<&RemoteSpaceMapping> {
        self.spaces.get(&remote_key(protocol, remote_space_id))
    }
}

/// Accountability metadata for a ghost actor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GhostActorAccountability {
    pub ghost_actor: Did,
    pub service_did: Did,
    pub accountable_to: Vec<Did>,
    pub reason: String,
}

/// Mapping between an applet portal and a bridged remote space.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PortalSpaceMapping {
    pub portal_id: String,
    pub space_id: SpaceId,
    pub protocol: String,
    pub remote_space_id: String,
}

/// Portal mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortalMode {
    Native,
    Bridge,
}

/// Applet portal space.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletPortal {
    pub portal_id: String,
    pub space_id: SpaceId,
    pub mode: PortalMode,
    pub applets: BTreeSet<String>,
    pub ghost_actor: Option<Did>,
}

/// Applet portal manager.
#[derive(Clone, Debug, Default)]
pub struct AppletPortalManager {
    portals: BTreeMap<String, AppletPortal>,
}

impl AppletPortalManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a portal.
    pub fn create_portal(&mut self, space_id: SpaceId) -> AppletPortal {
        let portal = AppletPortal {
            portal_id: format!("portal_{}", Ulid::new()),
            space_id,
            mode: PortalMode::Native,
            applets: BTreeSet::new(),
            ghost_actor: None,
        };
        self.portals.insert(portal.portal_id.clone(), portal.clone());
        portal
    }

    /// Install an applet into a portal.
    pub fn install_applet(&mut self, portal_id: &str, applet_id: impl Into<String>) -> Result<()> {
        let portal = self
            .portals
            .get_mut(portal_id)
            .ok_or_else(|| Error::Protocol("portal not found".to_owned()))?;
        portal.applets.insert(applet_id.into());
        Ok(())
    }

    /// Enable bridge mode.
    pub fn enable_bridge(&mut self, portal_id: &str) -> Result<()> {
        let portal = self
            .portals
            .get_mut(portal_id)
            .ok_or_else(|| Error::Protocol("portal not found".to_owned()))?;
        portal.mode = PortalMode::Bridge;
        Ok(())
    }

    /// Set ghost actor.
    pub fn set_ghost_actor(&mut self, portal_id: &str, actor: Did) -> Result<()> {
        let portal = self
            .portals
            .get_mut(portal_id)
            .ok_or_else(|| Error::Protocol("portal not found".to_owned()))?;
        portal.ghost_actor = Some(actor);
        Ok(())
    }

    /// Get a portal.
    pub fn portal(&self, portal_id: &str) -> Option<&AppletPortal> {
        self.portals.get(portal_id)
    }
}

fn namespace_patterns_overlap(left: &str, right: &str) -> bool {
    if left == right || left == "*" || right == "*" {
        return true;
    }
    let left_prefix = left.strip_suffix('*').unwrap_or(left);
    let right_prefix = right.strip_suffix('*').unwrap_or(right);
    left_prefix.starts_with(right_prefix) || right_prefix.starts_with(left_prefix)
}

fn remote_key(protocol: &str, remote_id: &str) -> String {
    format!("{protocol}:{remote_id}")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn applet_registry_parses_openapi_schema_and_permissions() {
        let mut registry = AppletRegistry::new();
        let schema = registry
            .register_from_value(json!({
                "applet_id": "todo",
                "name": "Todo",
                "version": "1.0.0",
                "permissions": [{"resource": "task", "actions": ["read", "write"]}],
                "openapi": {
                    "base_url": "https://api.example",
                    "operations": {"createTask": "POST /tasks"}
                },
                "schema": {"type": "object"}
            }))
            .unwrap();

        assert!(schema.allows("task", "write"));
        assert_eq!(schema.openapi.unwrap().operations["createTask"], "POST /tasks");
        assert!(registry.get("todo").is_some());
    }

    #[test]
    fn applet_portal_manages_space_bridge_and_ghost_actor() {
        let mut manager = AppletPortalManager::new();
        let portal =
            manager.create_portal(SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap());
        manager.install_applet(&portal.portal_id, "todo").unwrap();
        manager.enable_bridge(&portal.portal_id).unwrap();
        manager.set_ghost_actor(&portal.portal_id, did("ghost")).unwrap();

        let portal = manager.portal(&portal.portal_id).unwrap();
        assert_eq!(portal.mode, PortalMode::Bridge);
        assert!(portal.applets.contains("todo"));
        assert!(portal.ghost_actor.is_some());
    }

    #[test]
    fn signed_applet_registration_rejects_namespace_conflicts() {
        let mut registry = AppletRegistry::new();
        let schema = AppletSchema {
            applet_id: "todo".to_owned(),
            name: "Todo".to_owned(),
            version: "1.0.0".to_owned(),
            permissions: Vec::new(),
            openapi: None,
            schema: json!({"type": "object"}),
        };
        let registration = SignedAppletRegistration::new(
            "todo",
            did("svc"),
            schema.clone(),
            vec![AppletNamespaceDeclaration::exclusive(AppletNamespaceKind::Command, "!todo*")],
            "sig",
        );
        registry.register_signed(registration).unwrap();

        let conflict = SignedAppletRegistration::new(
            "todo2",
            did("svc2"),
            AppletSchema { applet_id: "todo2".to_owned(), ..schema },
            vec![AppletNamespaceDeclaration::exclusive(AppletNamespaceKind::Command, "!todo add")],
            "sig",
        );
        assert!(registry.namespace_conflicts(&conflict.namespaces).len() == 1);
        assert!(registry.register_signed(conflict).is_err());
    }

    #[test]
    fn appservice_transactions_are_idempotent() {
        let intent = AppserviceIntent::new(did("svc"), did("ghost"));
        let transaction = intent.transaction("k1", Vec::new());
        let response =
            AppletTransactionResponse { ok: true, rejected: Vec::new(), retry_after_ms: None };
        let mut store = AppserviceTransactionStore::new();

        assert!(matches!(
            store.record(&transaction, response.clone()).unwrap(),
            AppserviceTransactionRecord::New(_)
        ));
        assert!(matches!(
            store.record(&transaction, response).unwrap(),
            AppserviceTransactionRecord::Duplicate(_)
        ));

        let mut changed = transaction.clone();
        changed.request.ephemeral = json!({"changed": true});
        assert!(matches!(
            store.record(
                &changed,
                AppletTransactionResponse { ok: true, rejected: Vec::new(), retry_after_ms: None },
            ),
            Err(Error::IdempotencyConflict(_))
        ));
    }

    #[test]
    fn appservice_routes_and_bridge_mappings_cover_queries() {
        let registration = AppserviceRegistration::new(did("svc"), "bridge");
        registration.validate().unwrap();
        assert_eq!(AppserviceRouteSet::contrix_default().routes.len(), 4);

        let mut mappings = BridgeMappingStore::new();
        mappings.upsert_user(RemoteUserMapping {
            protocol: "slack".to_owned(),
            remote_user_id: "U1".to_owned(),
            actor_id: did("u1"),
            ghost_actor: Some(did("ghost")),
            display_name: Some("User One".to_owned()),
            external_ref: json!({"team": "T1"}),
        });
        mappings.upsert_space(RemoteSpaceMapping {
            protocol: "slack".to_owned(),
            remote_space_id: "C1".to_owned(),
            space_id: SpaceId::new("cx:space:01904100-0000-7000-8000-f949e0272316").unwrap(),
            portal_id: Some("portal".to_owned()),
            title: Some("general".to_owned()),
            external_ref: Value::Null,
        });

        assert_eq!(mappings.user("slack", "U1").unwrap().display_name, Some("User One".to_owned()));
        assert!(mappings.space("slack", "C1").is_some());
    }
}
