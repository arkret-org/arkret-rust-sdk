use arkret_models_identity::service_identity::ServiceDidEndpoint;
use serde_json::json;

#[test]
fn arkret_service_extension_uses_owned_spelling_beside_w3c_members() {
    let value = json!({
        "id": "did:web:station.example#coland",
        "type": "ArkretService",
        "service_kind": "station",
        "serviceEndpoint": "https://station.example/"
    });
    let endpoint: ServiceDidEndpoint = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(endpoint).unwrap(), value);

    let mut previous_name = value.clone();
    previous_name
        .as_object_mut()
        .unwrap()
        .remove("service_kind");
    previous_name["serviceKind"] = json!("station");
    assert!(serde_json::from_value::<ServiceDidEndpoint>(previous_name).is_err());

    let mut mixed = value;
    mixed["serviceKind"] = json!("station");
    assert!(serde_json::from_value::<ServiceDidEndpoint>(mixed).is_err());
}
