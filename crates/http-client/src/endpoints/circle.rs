//! Circle governance endpoint methods on [`Client`].

use arkret_models_collaboration::governance::circle::{
    CircleCreateRequestBody, CircleList, CircleMemberDeleteRequestBody, CircleMemberRequestBody,
    CircleMembershipOutcome, CircleScopeRotateOutcome, CircleScopeRotateRequestBody, CircleView,
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
        request: &CircleMemberDeleteRequestBody,
    ) -> Result<CircleMembershipOutcome> {
        reject_path_segment(circle_id)?;
        reject_path_segment(actor_id)?;
        let path = format!("/_arkret/self/circles/{circle_id}/members/{actor_id}");
        let builder = self.canonical_json_body(self.request(Method::DELETE, &path)?, request)?;
        self.send_json(builder).await
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
