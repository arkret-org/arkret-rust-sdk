//! Applet schema, OpenAPI binding and portal helpers.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use ulid::Ulid;

use crate::{Did, Error, Result, SpaceId};

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

/// Applet registry.
#[derive(Clone, Debug, Default)]
pub struct AppletRegistry {
    applets: BTreeMap<String, AppletSchema>,
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
            manager.create_portal(SpaceId::new("cx:space:01JS0SP000000000000000000").unwrap());
        manager.install_applet(&portal.portal_id, "todo").unwrap();
        manager.enable_bridge(&portal.portal_id).unwrap();
        manager.set_ghost_actor(&portal.portal_id, did("ghost")).unwrap();

        let portal = manager.portal(&portal.portal_id).unwrap();
        assert_eq!(portal.mode, PortalMode::Bridge);
        assert!(portal.applets.contains("todo"));
        assert!(portal.ghost_actor.is_some());
    }
}
