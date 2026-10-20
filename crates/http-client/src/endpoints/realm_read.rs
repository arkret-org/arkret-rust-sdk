//! Registered, caller-authorized Realm reads using the shared wire DTOs.
use arkret_models_collaboration::governance::realm_governance::{
    RealmExport, RealmLifecycleView, RealmLinkDirection, RealmLinkKind, RealmLinkList,
};
use arkret_wire::RealmId;

use crate::{Client, Error, Result};

impl Client {
    pub async fn realm_get(&self, realm: &RealmId) -> Result<RealmLifecycleView> {
        let view: RealmLifecycleView = self.get(&format!("/_arkret/self/realms/{realm}")).await?;
        view.validate_for_realm(realm)?;
        Ok(view)
    }

    pub async fn realm_export(&self, realm: &RealmId) -> Result<RealmExport> {
        let export: RealmExport = self
            .get(&format!("/_arkret/self/realms/{realm}/export"))
            .await?;
        export.validate_for_realm(realm)?;
        Ok(export)
    }

    pub async fn realm_links_list(
        &self,
        realm: &RealmId,
        direction: RealmLinkDirection,
        allow: Option<&[RealmLinkKind]>,
    ) -> Result<RealmLinkList> {
        let direction_name = match direction {
            RealmLinkDirection::Outbound => "outbound",
            RealmLinkDirection::Inbound => "inbound",
            RealmLinkDirection::Both => "both",
        };
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("direction", direction_name);
        if let Some(allow) = allow {
            let mut kinds = allow.iter().map(|kind| kind.as_str()).collect::<Vec<_>>();
            kinds.sort_unstable();
            kinds.dedup();
            if kinds.is_empty() {
                return Err(Error::Protocol("link_kind_allow must not be empty".into()));
            }
            query.append_pair("link_kind_allow", &kinds.join(","));
        }
        let list: RealmLinkList = self
            .get(&format!(
                "/_arkret/self/realms/{realm}/links?{}",
                query.finish()
            ))
            .await?;
        list.validate_for_request(realm, direction, allow)?;
        Ok(list)
    }
}
