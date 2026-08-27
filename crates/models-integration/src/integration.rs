//! Shared integration describe contract.
//!
//! This manifest shape is emitted by multiple services (for example floria,
//! soland, and coauth) and consumed by SDKs/admin UIs to discover dependent
//! contracts and advertised REST surfaces. It is intentionally generic: service
//! specific bridge payloads live in their own modules.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationDescribeOutcome {
    pub contract: String,
    pub version: String,
    pub service: String,
    pub service_kind: String,
    pub api_base_path: String,
    pub describe_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<IntegrationDependencyDescriptor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub surfaces: Vec<IntegrationSurfaceDescriptor>,
    #[serde(default)]
    pub examples: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub todos: Vec<String>,
}

impl IntegrationDescribeOutcome {
    pub fn surface(&self, name: &str) -> Option<&IntegrationSurfaceDescriptor> {
        self.surfaces.iter().find(|surface| surface.name == name)
    }

    pub fn requires(&self, service: &str, purpose: &str) -> bool {
        self.dependencies
            .iter()
            .any(|dep| dep.service == service && dep.purpose == purpose)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationDependencyDescriptor {
    pub service: String,
    pub purpose: String,
    pub required_contract: String,
    pub discovery_path: String,
    pub mode: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationSurfaceDescriptor {
    pub name: String,
    pub method: String,
    pub path: String,
    pub contract: String,
    pub stability: String,
    pub todo: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn integration_describe_round_trips_common_wire_shape() {
        let value = json!({
            "contract": "ak.integration.manifest.v1",
            "version": "2026-05-07",
            "service": "floria",
            "service_kind": "push_gateway",
            "api_base_path": "/_floria",
            "describe_path": "/_floria/integration/describe",
            "dependencies": [],
            "surfaces": [{
                "name": "gateway_describe",
                "method": "GET",
                "path": "/_arkret/describe",
                "contract": "ak.server.read.describe.v1",
                "stability": "active",
                "todo": ""
            }],
            "examples": {"compose_strand": {"step_1": {"service": "soland"}}}
        });

        let manifest: IntegrationDescribeOutcome =
            serde_json::from_value(value).expect("integration manifest decodes");
        assert!(manifest.dependencies.is_empty());
        assert_eq!(manifest.surface("gateway_describe").unwrap().method, "GET");

        let encoded = serde_json::to_value(manifest).expect("integration manifest encodes");
        assert!(encoded.get("todos").is_none());
        assert!(encoded["examples"].get("compose_strand").is_some());
    }
}
