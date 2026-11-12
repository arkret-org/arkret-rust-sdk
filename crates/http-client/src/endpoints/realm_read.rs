//! Registered, caller-authorized Realm reads using the shared wire DTOs.
use arkret_models_collaboration::governance::realm_governance::{
    RealmExport, RealmLifecycleView, RealmLinkDirection, RealmLinkKind, RealmLinkList,
    RealmLinkListQuery,
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
        let typed_query = RealmLinkListQuery {
            direction,
            allowed_link_kinds: allow.map(<[RealmLinkKind]>::to_vec),
        };
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in typed_query
            .to_query_pairs()
            .map_err(|error| Error::Protocol(error.to_string()))?
        {
            query.append_pair(key, &value);
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
