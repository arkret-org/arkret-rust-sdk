use serde::{Deserialize, Serialize};

/// Framework-neutral applet endpoint route declaration.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletEndpointRoute {
    pub method: String,
    pub path: String,
    pub description: String,
}

/// Route set expected from applet service framework adapters.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
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
