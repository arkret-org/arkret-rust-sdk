#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{Did, RealmId};
#[cfg(test)]
use crate::{Error, Result};

/// Mapping between an applet portal and a bridged remote location.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PortalRealmMapping {
    pub portal_id: String,
    pub realm_id: RealmId,
    pub protocol: String,
    pub remote_realm_id: String,
}

/// Portal mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortalMode {
    Native,
    Bridge,
}

/// Applet portal Realm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppletPortal {
    pub portal_id: String,
    pub realm_id: RealmId,
    pub mode: PortalMode,
    pub applets: BTreeSet<String>,
    pub ghost_actor: Option<Did>,
}

/// Applet portal manager.
#[derive(Clone, Debug, Default)]
#[cfg(test)]
pub(crate) struct AppletPortalManager {
    portals: BTreeMap<String, AppletPortal>,
}

#[cfg(test)]
impl AppletPortalManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a portal.
    pub fn create_portal(&mut self, realm_id: RealmId) -> AppletPortal {
        let portal = AppletPortal {
            portal_id: format!("portal_{}", uuid::Uuid::now_v7()),
            realm_id,
            mode: PortalMode::Native,
            applets: BTreeSet::new(),
            ghost_actor: None,
        };
        self.portals
            .insert(portal.portal_id.clone(), portal.clone());
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
