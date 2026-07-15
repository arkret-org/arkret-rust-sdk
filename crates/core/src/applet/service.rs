use serde::{Deserialize, Serialize};

use crate::models::AppletTransactionRequestBody;
use crate::{Did, Event};

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
                ephemeral: None,
            },
        }
    }
}
