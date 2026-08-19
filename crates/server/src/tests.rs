use std::collections::BTreeMap;

use serde_json::Value;

use crate::registry::service_routes;
use crate::reject_query_auth;

#[test]
fn query_auth_material_is_rejected() {
    let query = BTreeMap::from([("access_token".to_owned(), "secret".to_owned())]);
    assert!(reject_query_auth(&query).is_err());

    let clean = BTreeMap::from([("limit".to_owned(), "10".to_owned())]);
    assert!(reject_query_auth(&clean).is_ok());
}

#[test]
fn service_routes_match_embedded_operation_registry() {
    let registry = arkret_schema::SpecArtifactBundle::load_embedded()
        .unwrap()
        .operation_registry;
    let mut expected: Vec<(String, String, String)> = registry
        .get("operations")
        .and_then(Value::as_array)
        .expect("operation registry missing operations")
        .iter()
        .map(|operation| {
            let operation_id = operation
                .get("operation_id")
                .and_then(Value::as_str)
                .expect("operation missing operation_id");
            let http = operation
                .get("http")
                .and_then(Value::as_str)
                .expect("operation missing http binding");
            let (method, path) = http
                .split_once(' ')
                .expect("operation http binding must be '<METHOD> <path>'");
            (
                operation_id.to_owned(),
                method.to_ascii_lowercase(),
                path.to_owned(),
            )
        })
        .collect();
    let mut actual: Vec<(String, String, String)> = service_routes()
        .iter()
        .map(|route| {
            (
                route.operation_id.to_owned(),
                route.method.to_owned(),
                route.path.to_owned(),
            )
        })
        .collect();
    expected.sort_unstable();
    actual.sort_unstable();
    assert_eq!(actual, expected);
}
