use std::collections::BTreeMap;

use crate::reject_query_auth;

#[test]
fn query_auth_material_is_rejected() {
    let query = BTreeMap::from([("access_token".to_owned(), "secret".to_owned())]);
    assert!(reject_query_auth(&query).is_err());

    let clean = BTreeMap::from([("limit".to_owned(), "10".to_owned())]);
    assert!(reject_query_auth(&clean).is_ok());
}
