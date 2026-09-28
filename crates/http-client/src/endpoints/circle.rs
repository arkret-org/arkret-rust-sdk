//! Circle governance endpoint methods on [`Client`].

use arkret_models_collaboration::governance::circle::{
    CircleCreateRequestBody, CircleList, CircleMemberDeleteRequestBody, CircleMemberRequestBody,
    CircleMembershipOutcome, CircleReadView, CircleScopeRotateOutcome,
    CircleScopeRotateRequestBody, CircleView,
};
use arkret_wire::ActorId;
use reqwest::Method;

use crate::{Client, ClientRequestOptions, Result, reject_path_segment};

impl Client {
    pub async fn circle_list(&self, realm_id: &str) -> Result<CircleList> {
        let builder = self
            .request(Method::GET, "/_arkret/self/circles")?
            .query(&[("realm_id", realm_id)]);
        self.send_json(builder).await
    }

    pub async fn circle_get(&self, circle_id: &str) -> Result<CircleReadView> {
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
        actor_id: &ActorId,
        request: &CircleMemberDeleteRequestBody,
    ) -> Result<CircleMembershipOutcome> {
        reject_path_segment(circle_id)?;
        let actor_id = circle_member_actor_path_segment(actor_id);
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

fn circle_member_actor_path_segment(actor: &ActorId) -> String {
    let mut encoded = String::new();
    for byte in actor.to_string().bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(&mut encoded, "%{byte:02X}");
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn circle_member_path_encodes_the_full_actor_in_one_segment() {
        let principal = arkret_wire::DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let mut segments = Vec::new();
        for station in [
            "ak:did_core:web:first.example",
            "ak:did_core:web:second.example",
        ] {
            let actor = ActorId::account(arkret_wire::AccountId::new(
                principal.clone(),
                arkret_wire::DidCoreId::new(station).unwrap(),
            ));
            let segment = circle_member_actor_path_segment(&actor);
            assert!(!segment.contains(['/', '?', '#', '{', '"']));
            let query = format!("actor={segment}");
            let (_, decoded) = url::form_urlencoded::parse(query.as_bytes())
                .next()
                .unwrap();
            assert_eq!(decoded, actor.to_string());
            segments.push(segment);
        }
        assert_ne!(segments[0], segments[1]);
    }
}
