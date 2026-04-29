use std::collections::BTreeMap;

use contrix_sdk::{
    EndpointMethod, HttpAdapterRequest, HttpAdapterResponse, TowerLikeEndpointService,
};

fn main() -> contrix_sdk::Result<()> {
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
