//! Contrix appservice, bot and bridge protocol models.
//!
//! This crate is the appservice API boundary. It does not own a web framework
//! adapter; Salvo and other server integrations should build on these models.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use contrix_core::{
    AppletActorResponse, AppletProtocolResponse, AppletSpaceResponse, AppletTransactionRequest,
    AppletTransactionResponse, Did, Error, Event, Result, SpaceId, canonical,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ulid::Ulid;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppserviceNamespaceKind {
    Actor,
    Alias,
    Space,
    Event,
    Entity,
    Command,
    Protocol,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppserviceNamespace {
    pub kind: AppserviceNamespaceKind,
    pub pattern: String,
    #[serde(default)]
    pub exclusive: bool,
}

impl AppserviceNamespace {
    pub fn exclusive(kind: AppserviceNamespaceKind, pattern: impl Into<String>) -> Self {
        Self { kind, pattern: pattern.into(), exclusive: true }
    }

    pub fn non_exclusive(kind: AppserviceNamespaceKind, pattern: impl Into<String>) -> Self {
        Self { kind, pattern: pattern.into(), exclusive: false }
    }

    pub fn conflicts_with(&self, other: &Self) -> bool {
        self.kind == other.kind
            && (self.exclusive || other.exclusive)
            && namespace_patterns_overlap(&self.pattern, &other.pattern)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppservicePermission {
    ManageVirtualActors,
    SendEvents,
    SendState,
    ReceiveTransactions,
    QueryThirdPartyUsers,
    QueryThirdPartyLocations,
    QueryProtocolMetadata,
    QueryKeys,
    ClaimKeys,
    BridgeRemoteUsers,
    BridgeRemoteSpaces,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppserviceRegistration {
    pub registration_id: String,
    pub service_did: Did,
    pub sender_localpart: String,
    #[serde(default)]
    pub namespaces: Vec<AppserviceNamespace>,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default)]
    pub receive_ephemeral: bool,
    #[serde(default = "default_rate_limited")]
    pub rate_limited: bool,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub permissions: BTreeSet<AppservicePermission>,
    pub created_at: DateTime<Utc>,
}

impl AppserviceRegistration {
    pub fn new(service_did: Did, sender_localpart: impl Into<String>) -> Self {
        Self {
            registration_id: format!("as_{}", Ulid::new()),
            service_did,
            sender_localpart: sender_localpart.into(),
            namespaces: Vec::new(),
            protocols: Vec::new(),
            receive_ephemeral: false,
            rate_limited: true,
            permissions: BTreeSet::new(),
            created_at: Utc::now(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.sender_localpart.is_empty() {
            return Err(Error::Protocol("appservice sender localpart is empty".to_owned()));
        }
        if self.namespaces.iter().any(|namespace| namespace.pattern.is_empty()) {
            return Err(Error::Protocol("appservice namespace pattern is empty".to_owned()));
        }
        Ok(())
    }

    pub fn allows(&self, permission: AppservicePermission) -> bool {
        self.permissions.contains(&permission)
    }
}

fn default_rate_limited() -> bool {
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AppserviceMethod {
    Get,
    Put,
    Post,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppserviceEndpoint {
    pub operation_id: &'static str,
    pub method: AppserviceMethod,
    pub path: &'static str,
    pub request_schema: &'static str,
    pub response_schema: &'static str,
}

pub const APPSERVICE_ENDPOINTS: &[AppserviceEndpoint] = &[
    AppserviceEndpoint {
        operation_id: "cx.appservice.transaction",
        method: AppserviceMethod::Put,
        path: "/_contrix/appservice/v1/transactions/{txn_id}",
        request_schema: "AppletTransactionRequest",
        response_schema: "AppletTransactionResponse",
    },
    AppserviceEndpoint {
        operation_id: "cx.appservice.query_user",
        method: AppserviceMethod::Get,
        path: "/_contrix/appservice/v1/users/{protocol}/{external_id}",
        request_schema: "ThirdPartyUserPath",
        response_schema: "AppletActorResponse",
    },
    AppserviceEndpoint {
        operation_id: "cx.appservice.query_location",
        method: AppserviceMethod::Get,
        path: "/_contrix/appservice/v1/locations/{protocol}/{external_id}",
        request_schema: "ThirdPartyLocationPath",
        response_schema: "AppletSpaceResponse",
    },
    AppserviceEndpoint {
        operation_id: "cx.appservice.protocol_metadata",
        method: AppserviceMethod::Get,
        path: "/_contrix/appservice/v1/protocols/{protocol}",
        request_schema: "ProtocolMetadataPath",
        response_schema: "AppletProtocolResponse",
    },
    AppserviceEndpoint {
        operation_id: "cx.appservice.keys.query",
        method: AppserviceMethod::Post,
        path: "/_contrix/appservice/v1/keys/query",
        request_schema: "KeysQueryRequest",
        response_schema: "KeysQueryResponse",
    },
    AppserviceEndpoint {
        operation_id: "cx.appservice.keys.claim",
        method: AppserviceMethod::Post,
        path: "/_contrix/appservice/v1/keys/claim",
        request_schema: "KeysClaimRequest",
        response_schema: "KeysClaimResponse",
    },
];

pub fn appservice_endpoints() -> &'static [AppserviceEndpoint] {
    APPSERVICE_ENDPOINTS
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppserviceTransaction {
    pub transaction_id: String,
    pub request: AppletTransactionRequest,
}

impl AppserviceTransaction {
    pub fn digest(&self) -> Result<String> {
        canonical::canonical_sha256(&self.request)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum AppserviceTransactionOutcome {
    New(AppletTransactionResponse),
    Duplicate(AppletTransactionResponse),
}

#[derive(Clone, Debug, Default)]
pub struct AppserviceTransactionSlot {
    transactions: BTreeMap<String, (String, AppletTransactionResponse)>,
}

impl AppserviceTransactionSlot {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(
        &mut self,
        transaction: &AppserviceTransaction,
        response: AppletTransactionResponse,
    ) -> Result<AppserviceTransactionOutcome> {
        let digest = transaction.digest()?;
        if let Some((existing_digest, existing_response)) =
            self.transactions.get(&transaction.transaction_id)
        {
            if existing_digest == &digest {
                return Ok(AppserviceTransactionOutcome::Duplicate(existing_response.clone()));
            }
            return Err(Error::IdempotencyConflict(transaction.transaction_id.clone()));
        }

        self.transactions.insert(transaction.transaction_id.clone(), (digest, response.clone()));
        Ok(AppserviceTransactionOutcome::New(response))
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VirtualActor {
    pub actor_id: Did,
    pub service_did: Did,
    pub localpart: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accountable_to: Vec<Did>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppserviceIntent {
    pub service_did: Did,
    pub actor_id: Did,
    pub transaction_prefix: String,
}

impl AppserviceIntent {
    pub fn new(service_did: Did, actor_id: Did) -> Self {
        Self { service_did, actor_id, transaction_prefix: "as_txn".to_owned() }
    }

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThirdPartyLookupKind {
    User,
    Location,
    ProtocolMetadata,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ThirdPartyLookupRequest {
    pub kind: ThirdPartyLookupKind,
    pub protocol: String,
    #[serde(default)]
    pub fields: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "content", rename_all = "snake_case")]
pub enum ThirdPartyLookupResponse {
    User(AppletActorResponse),
    Location(AppletSpaceResponse),
    ProtocolMetadata(AppletProtocolResponse),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RemoteUserMapping {
    pub protocol: String,
    pub remote_user_id: String,
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ghost_actor: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RemoteSpaceMapping {
    pub protocol: String,
    pub remote_space_id: String,
    pub space_id: SpaceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portal_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
}

#[derive(Clone, Debug, Default)]
pub struct BridgeMappingStore {
    users: BTreeMap<String, RemoteUserMapping>,
    spaces: BTreeMap<String, RemoteSpaceMapping>,
}

impl BridgeMappingStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert_user(&mut self, mapping: RemoteUserMapping) {
        self.users.insert(remote_key(&mapping.protocol, &mapping.remote_user_id), mapping);
    }

    pub fn upsert_space(&mut self, mapping: RemoteSpaceMapping) {
        self.spaces.insert(remote_key(&mapping.protocol, &mapping.remote_space_id), mapping);
    }

    pub fn user(&self, protocol: &str, remote_user_id: &str) -> Option<&RemoteUserMapping> {
        self.users.get(&remote_key(protocol, remote_user_id))
    }

    pub fn space(&self, protocol: &str, remote_space_id: &str) -> Option<&RemoteSpaceMapping> {
        self.spaces.get(&remote_key(protocol, remote_space_id))
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
    fn registration_validates_namespaces_and_permissions() {
        let mut registration = AppserviceRegistration::new(did("svc"), "bridge");
        registration
            .namespaces
            .push(AppserviceNamespace::exclusive(AppserviceNamespaceKind::Command, "!bridge*"));
        registration.permissions.insert(AppservicePermission::ReceiveTransactions);

        registration.validate().unwrap();
        assert!(registration.allows(AppservicePermission::ReceiveTransactions));
    }

    #[test]
    fn namespace_conflicts_detect_overlap() {
        let left = AppserviceNamespace::exclusive(AppserviceNamespaceKind::Actor, "@slack_*");
        let right = AppserviceNamespace::non_exclusive(AppserviceNamespaceKind::Actor, "@slack_a");
        assert!(left.conflicts_with(&right));
    }

    #[test]
    fn endpoint_catalog_includes_transactions_queries_and_keys() {
        let operations = appservice_endpoints()
            .iter()
            .map(|endpoint| endpoint.operation_id)
            .collect::<BTreeSet<_>>();
        assert!(operations.contains("cx.appservice.transaction"));
        assert!(operations.contains("cx.appservice.query_user"));
        assert!(operations.contains("cx.appservice.keys.query"));
        assert!(operations.contains("cx.appservice.keys.claim"));
    }

    #[test]
    fn transaction_slot_is_idempotent() {
        let intent = AppserviceIntent::new(did("svc"), did("ghost"));
        let transaction = intent.transaction("k1", Vec::new());
        let response =
            AppletTransactionResponse { ok: true, rejected: Vec::new(), retry_after_ms: None };
        let mut slot = AppserviceTransactionSlot::new();

        assert!(matches!(
            slot.record(&transaction, response.clone()).unwrap(),
            AppserviceTransactionOutcome::New(_)
        ));
        assert!(matches!(
            slot.record(&transaction, response).unwrap(),
            AppserviceTransactionOutcome::Duplicate(_)
        ));

        let mut changed = transaction.clone();
        changed.request.ephemeral = json!({"changed": true});
        assert!(matches!(
            slot.record(
                &changed,
                AppletTransactionResponse { ok: true, rejected: Vec::new(), retry_after_ms: None },
            ),
            Err(Error::IdempotencyConflict(_))
        ));
    }

    #[test]
    fn bridge_mapping_store_resolves_remote_entities() {
        let mut store = BridgeMappingStore::new();
        store.upsert_user(RemoteUserMapping {
            protocol: "slack".to_owned(),
            remote_user_id: "U1".to_owned(),
            actor_id: did("u1"),
            ghost_actor: Some(did("ghost")),
            display_name: Some("User One".to_owned()),
            external_ref: json!({"team": "T1"}),
        });
        store.upsert_space(RemoteSpaceMapping {
            protocol: "slack".to_owned(),
            remote_space_id: "C1".to_owned(),
            space_id: SpaceId::new("cx:space:01JS0SP000000000000000001").unwrap(),
            portal_id: Some("portal".to_owned()),
            title: Some("general".to_owned()),
            external_ref: Value::Null,
        });

        assert_eq!(store.user("slack", "U1").unwrap().display_name, Some("User One".to_owned()));
        assert!(store.space("slack", "C1").is_some());
    }
}
