//! Principal-server bridge describe contracts.
//!
//! These DTOs describe the producer/consumer bridge between a principal server
//! and clients that need session-grant exchange plus push registration
//! metadata. The shape is shared by soland and yougen today.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PrincipalAuthBridgeDescribeResponse {
    pub contract: String,
    pub version: String,
    pub api_base_path: String,
    pub auth: PrincipalAuthBridgeAuthDescriptor,
    pub push: PrincipalAuthBridgePushDescriptor,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default)]
    pub examples: PrincipalAuthBridgeExamples,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub todos: Vec<String>,
}

impl PrincipalAuthBridgeDescribeResponse {
    pub fn session_grant_exchange_path(&self) -> &str {
        &self.auth.session_grant_exchange_path
    }

    pub fn register_device_path(&self) -> &str {
        &self.push.register_device_path
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PrincipalAuthBridgeAuthDescriptor {
    pub dev_login_path: String,
    pub session_grant_exchange_path: String,
    pub bearer_auth_scheme: String,
    pub principal_id_body_field: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PrincipalAuthBridgePushDescriptor {
    pub register_device_path: String,
    pub unregister_device_path: String,
    pub session_grant_header: String,
    pub principal_id_body_field: String,
    pub register_device_mode: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PrincipalAuthBridgeExamples {
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default)]
    pub session_grant_exchange_request: Value,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default)]
    pub register_device_request: Value,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(default)]
    pub unregister_device_request: Value,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn principal_auth_bridge_decodes_soland_yougen_shape() {
        let value = json!({
            "contract": "cokret.rest.principal_bridge.v1",
            "version": "2026-05-12-oauth-introspection",
            "api_base_path": "/api/v1",
            "auth": {
                "dev_login_path": "/api/v1/auth/dev-login",
                "session_grant_exchange_path": "/api/v1/auth/session-grant/exchange",
                "bearer_auth_scheme": "Authorization: Bearer <token>",
                "principal_id_body_field": "principal_id"
            },
            "push": {
                "register_device_path": "/api/v1/push/register-device",
                "unregister_device_path": "/api/v1/push/unregister-device",
                "session_grant_header": "X-Cokret-Session-Grant",
                "principal_id_body_field": "principal_id",
                "register_device_mode": "bearer_session_or_oauth_bearer_introspection"
            },
            "examples": {
                "session_grant_exchange_request": {"principal_id": "did:web:alice.example"},
                "register_device_request": {"platform": "web"},
                "unregister_device_request": {"registration_id": "reg"}
            }
        });

        let describe: PrincipalAuthBridgeDescribeResponse =
            serde_json::from_value(value).expect("principal bridge decodes");
        assert_eq!(describe.session_grant_exchange_path(), "/api/v1/auth/session-grant/exchange");
        assert_eq!(describe.register_device_path(), "/api/v1/push/register-device");

        let encoded = serde_json::to_value(describe).expect("principal bridge encodes");
        assert!(encoded.get("todos").is_none());
        assert_eq!(encoded["push"]["principal_id_body_field"], "principal_id");
    }
}
