//! Circle governance endpoint methods on [`Client`].

use arkret_models_collaboration::governance::circle::{
    CircleArchiveRequestBody, CircleCreateRequestBody, CircleList, CircleMemberRequestBody,
    CircleMembershipOutcome, CircleRestoreRequestBody, CircleScopeRotateOutcome,
    CircleScopeRotateRequestBody, CircleTombstoneRequestBody, CircleView,
};
use reqwest::Method;

use crate::{Client, ClientRequestOptions, Result, reject_path_segment};

impl Client {
    pub async fn circle_list(&self, realm_id: &str) -> Result<CircleList> {
        let builder = self
            .request(Method::GET, "/_arkret/self/circles")?
            .query(&[("realm_id", realm_id)]);
        self.send_json(builder).await
    }

    pub async fn circle_get(&self, circle_id: &str) -> Result<CircleView> {
        reject_path_segment(circle_id)?;
        self.get(&format!("/_arkret/self/circles/{circle_id}"))
            .await
    }

    pub async fn circle_create(&self, request: &CircleCreateRequestBody) -> Result<CircleView> {
        self.post("/_arkret/self/circles", request).await
    }

    pub async fn circle_member_add(
        &self,
        circle_id: &str,
        request: &CircleMemberRequestBody,
    ) -> Result<CircleMembershipOutcome> {
        reject_path_segment(circle_id)?;
        self.post(
            &format!("/_arkret/self/circles/{circle_id}/members"),
            request,
        )
        .await
    }

    pub async fn circle_member_remove(
        &self,
        circle_id: &str,
        actor_id: &str,
    ) -> Result<CircleMembershipOutcome> {
        reject_path_segment(circle_id)?;
        reject_path_segment(actor_id)?;
        self.delete(&format!(
            "/_arkret/self/circles/{circle_id}/members/{actor_id}"
        ))
        .await
    }

    /// The three lifecycle actions differ only in the Event kind their body pins,
    /// so the transport is shared and each caller keeps its own request type.
    async fn circle_lifecycle<B: serde::Serialize>(
        &self,
        circle_id: &str,
        action: &str,
        request: &B,
    ) -> Result<CircleView> {
        reject_path_segment(circle_id)?;
        reject_path_segment(action)?;
        self.post(
            &format!("/_arkret/self/circles/{circle_id}/{action}"),
            request,
        )
        .await
    }

    pub async fn circle_archive(
        &self,
        circle_id: &str,
        request: &CircleArchiveRequestBody,
    ) -> Result<CircleView> {
        self.circle_lifecycle(circle_id, "archive", request).await
    }

    pub async fn circle_restore(
        &self,
        circle_id: &str,
        request: &CircleRestoreRequestBody,
    ) -> Result<CircleView> {
        self.circle_lifecycle(circle_id, "restore", request).await
    }

    pub async fn circle_tombstone(
        &self,
        circle_id: &str,
        request: &CircleTombstoneRequestBody,
    ) -> Result<CircleView> {
        self.circle_lifecycle(circle_id, "tombstone", request).await
    }

    pub async fn circle_scope_rotate(
        &self,
        circle_id: &str,
        idempotency_key: &str,
        request: &CircleScopeRotateRequestBody,
    ) -> Result<CircleScopeRotateOutcome> {
        reject_path_segment(circle_id)?;
        let path = format!("/_arkret/self/circles/{circle_id}/scope-rotate");
        let options = ClientRequestOptions::new()
            .request_id(idempotency_key)
            .idempotency_key(idempotency_key);
        self.post_with_options(&path, request, &options).await
    }
}
