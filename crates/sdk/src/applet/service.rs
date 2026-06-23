use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(test)]
use crate::models::AppletTransactionOutcome;
use crate::models::{AppletActorView, AppletRealmView, AppletTransactionRequestBody};
use crate::{Did, Event, RealmId};
#[cfg(test)]
use crate::{Error, Result, canonical};

/// Framework-neutral applet endpoint route declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg(test)]
pub(crate) struct AppletEndpointRoute {
    pub method: String,
    pub path: String,
    pub description: String,
}

/// Route set expected from applet service framework adapters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg(test)]
pub(crate) struct AppletEndpointRouteSet {
    pub routes: Vec<AppletEndpointRoute>,
}

#[cfg(test)]
impl AppletEndpointRouteSet {
    /// Standard applet service routes from the Cokret service binding.
    pub fn cokret_default() -> Self {
        Self {
            routes: vec![
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_cokret/edge/applet/ping".to_owned(),
                    description: "applet liveness and public metadata".to_owned(),
                },
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_cokret/edge/applet/describe".to_owned(),
                    description: "applet capabilities and namespace metadata".to_owned(),
                },
                AppletEndpointRoute {
                    method: "POST".to_owned(),
                    path: "/_cokret/edge/applet/transactions".to_owned(),
                    description: "receive applet transaction".to_owned(),
                },
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_cokret/edge/applet/actors/{actor_id}".to_owned(),
                    description: "query applet actor".to_owned(),
                },
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_cokret/edge/applet/realms/{realm_id_or_alias}".to_owned(),
                    description: "query applet realm".to_owned(),
                },
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_cokret/edge/applet/protocols/{protocol}".to_owned(),
                    description: "query protocol metadata".to_owned(),
                },
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_cokret/edge/applet/third_party/users".to_owned(),
                    description: "query third-party user".to_owned(),
                },
                AppletEndpointRoute {
                    method: "GET".to_owned(),
                    path: "/_cokret/edge/applet/third_party/locations".to_owned(),
                    description: "query third-party location".to_owned(),
                },
            ],
        }
    }
}

/// Applet service transaction with an explicit idempotency key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppletServiceTransaction {
    pub idempotency_key: String,
    pub request: AppletTransactionRequestBody,
}

/// Result of recording an idempotent transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg(test)]
pub(crate) enum AppletServiceTransactionRecord {
    New(AppletTransactionOutcome),
    Duplicate(AppletTransactionOutcome),
}

/// In-memory idempotent applet service transaction store.
#[derive(Clone, Debug, Default)]
#[cfg(test)]
pub(crate) struct AppletServiceTransactionStore {
    transactions: BTreeMap<String, (String, AppletTransactionOutcome)>,
}

#[cfg(test)]
impl AppletServiceTransactionStore {
    /// Create an empty transaction store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a transaction or return the prior response for an exact duplicate.
    pub fn record(
        &mut self,
        transaction: &AppletServiceTransaction,
        response: AppletTransactionOutcome,
    ) -> Result<AppletServiceTransactionRecord> {
        let digest = canonical::canonical_sha256(&transaction.request)?;
        if let Some((existing_digest, existing_response)) =
            self.transactions.get(&transaction.idempotency_key)
        {
            if existing_digest == &digest {
                return Ok(AppletServiceTransactionRecord::Duplicate(
                    existing_response.clone(),
                ));
            }
            return Err(Error::IdempotencyConflict(
                transaction.idempotency_key.clone(),
            ));
        }

        self.transactions.insert(
            transaction.idempotency_key.clone(),
            (digest, response.clone()),
        );
        Ok(AppletServiceTransactionRecord::New(response))
    }
}

/// Virtual actor controlled by an applet service.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VirtualActor {
    pub actor_id: Did,
    pub service_did: Did,
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
    pub service_did: Did,
    pub actor_id: Did,
    pub idempotency_prefix: String,
}

impl AppletServiceIntent {
    /// Create a virtual actor intent.
    pub fn new(service_did: Did, actor_id: Did) -> Self {
        Self {
            service_did,
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

/// Bridge mapping from a remote user to a Cokret virtual actor.
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

/// Bridge mapping from a remote location to a Cokret Realm.
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
#[cfg(test)]
pub(crate) struct BridgeMappingStore {
    users: BTreeMap<String, RemoteUserMapping>,
    realms: BTreeMap<String, RemoteRealmMapping>,
}

#[cfg(test)]
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

#[cfg(test)]
fn remote_key(protocol: &str, remote_id: &str) -> String {
    format!("{protocol}:{remote_id}")
}
