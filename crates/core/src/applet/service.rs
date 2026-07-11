use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::models::{AppletActorView, AppletRealmView, AppletTransactionRequestBody};
use crate::{Did, Event, RealmId};

/// Framework-neutral applet endpoint route declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletEndpointRoute {
    pub method: String,
    pub path: String,
    pub description: String,
}

/// Route set expected from applet service framework adapters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletEndpointRouteSet {
    pub routes: Vec<AppletEndpointRoute>,
}

impl AppletEndpointRouteSet {
    /// Standard applet service routes from the Arkret service binding.
    pub fn arkret_default() -> Self {
        Self {
            routes: vec![
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_arkret/edge/applet/ping".to_owned(),
                    description: "applet liveness and public metadata".to_owned(),
                },
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_arkret/edge/applet/describe".to_owned(),
                    description: "applet capabilities and namespace metadata".to_owned(),
                },
                AppletEndpointRoute {
                    method: "POST".to_owned(),
                    path: "/_arkret/edge/applet/transactions".to_owned(),
                    description: "receive applet transaction".to_owned(),
                },
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_arkret/edge/applet/actors/{actor_id}".to_owned(),
                    description: "query applet actor".to_owned(),
                },
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_arkret/edge/applet/realms/{realm_id_or_alias}".to_owned(),
                    description: "query applet realm".to_owned(),
                },
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_arkret/edge/applet/protocols/{protocol}".to_owned(),
                    description: "query protocol metadata".to_owned(),
                },
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_arkret/edge/applet/third_party/users".to_owned(),
                    description: "query third-party user".to_owned(),
                },
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_arkret/edge/applet/third_party/locations".to_owned(),
                    description: "query third-party location".to_owned(),
                },
            ],
        }
    }
}

/// Applet service transaction with an explicit idempotency key.
///
/// Deduplication of these deliveries lives in one place:
/// [`arkret_server::IdempotencyWindow`], keyed by the spec 5-tuple
/// [`arkret_server::IdempotencyIdentity`] (`applet-integration.md`
/// §7.3).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletServiceTransaction {
    pub idempotency_key: String,
    pub request: AppletTransactionRequestBody,
}

/// Virtual actor controlled by an applet service.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VirtualActor {
    pub actor_id: Did,
    pub service_id: Did,
    pub localpart: String,
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accountable_principal_ids: Vec<Did>,
}

/// Applet service intent for acting as a virtual actor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletServiceIntent {
    pub service_id: Did,
    pub actor_id: Did,
    pub idempotency_prefix: String,
}

impl AppletServiceIntent {
    /// Create a virtual actor intent.
    pub fn new(service_id: Did, actor_id: Did) -> Self {
        Self {
            service_id,
            actor_id,
            idempotency_prefix: "applet_txn".to_owned(),
        }
    }

    /// Build an idempotent transaction envelope for events produced by this intent.
    pub fn transaction(
        &self,
        idempotency_key: impl AsRef<str>,
        events: Vec<Event>,
    ) -> AppletServiceTransaction {
        AppletServiceTransaction {
            idempotency_key: format!("{}:{}", self.idempotency_prefix, idempotency_key.as_ref()),
            request: AppletTransactionRequestBody {
                source_service_id: self.service_id.clone(),
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
pub struct ThirdPartyLookupRequestBody {
    pub kind: ThirdPartyLookupKind,
    pub protocol: String,
    #[serde(default)]
    pub fields: BTreeMap<String, Value>,
}

/// Third-party lookup response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ThirdPartyLookupOutcome {
    User(AppletActorView),
    Location(AppletRealmView),
}

/// Bridge mapping from a remote user to a Arkret virtual actor.
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

/// Bridge mapping from a remote location to a Arkret Realm.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RemoteRealmMapping {
    pub protocol: String,
    pub remote_realm_id: String,
    pub realm_id: RealmId,
    pub portal_id: Option<String>,
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub external_ref: Value,
}

/// In-memory bridge mapping storage.
#[derive(Clone, Debug, Default)]
pub struct BridgeMappingStore {
    users: BTreeMap<String, RemoteUserMapping>,
    realms: BTreeMap<String, RemoteRealmMapping>,
}

impl BridgeMappingStore {
    /// Create an empty mapping store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store or replace a remote user mapping.
    pub fn upsert_user(&mut self, mapping: RemoteUserMapping) {
        self.users.insert(
            remote_key(&mapping.protocol, &mapping.remote_user_id),
            mapping,
        );
    }

    /// Store or replace a remote location mapping.
    pub fn upsert_realm(&mut self, mapping: RemoteRealmMapping) {
        self.realms.insert(
            remote_key(&mapping.protocol, &mapping.remote_realm_id),
            mapping,
        );
    }

    /// Resolve a remote user mapping.
    pub fn user(&self, protocol: &str, remote_user_id: &str) -> Option<&RemoteUserMapping> {
        self.users.get(&remote_key(protocol, remote_user_id))
    }

    /// Resolve a remote location mapping.
    pub fn realm(&self, protocol: &str, remote_realm_id: &str) -> Option<&RemoteRealmMapping> {
        self.realms.get(&remote_key(protocol, remote_realm_id))
    }
}

fn remote_key(protocol: &str, remote_id: &str) -> String {
    format!("{protocol}:{remote_id}")
}
