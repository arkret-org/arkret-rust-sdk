//! Smoke test for the framework-independent endpoint adapter shape.
//!
//! **Not a reference protocol implementation.** The handler below returns a
//! hard-coded `{"ok":true}` body — the example exists to exercise the
//! request/response adapter types and the `TowerLikeEndpointService` trait,
//! not to implement Contrix server semantics. A production deployment plugs
//! in its own service implementation (`soland` is the canonical one today).

use std::collections::BTreeMap;

use contrix::{EndpointMethod, HttpAdapterRequest, HttpAdapterResponse, TowerLikeEndpointService};

fn main() -> contrix::Result<()> {
    let mut service = |_request: HttpAdapterRequest| {
        Ok(HttpAdapterResponse {
            status: 200,
            headers: BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]),
            body: br#"{"ok":true}"#.to_vec(),
        })
    };

    let response = TowerLikeEndpointService::call(
        &mut service,
        HttpAdapterRequest {
            method: EndpointMethod::Get,
            path: "/api/v1/server/describe".to_owned(),
            query: BTreeMap::new(),
            headers: BTreeMap::new(),
            body: Vec::new(),
        },
    )?;

    assert_eq!(response.status, 200);
    Ok(())
}
