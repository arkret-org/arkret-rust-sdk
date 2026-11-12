use arkret_models_identity::handle_claim::HandleClaimVariant;
use serde_json::json;

#[test]
fn organization_handle_claim_uses_the_organization_did_core_identity() {
    let body =
        json!({"kind":"organization_handle","organization_id":"ak:did_core:web:org.example"});
    let parsed: HandleClaimVariant = serde_json::from_value(body.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), body);
    for invalid in [
        "",
        "deployment-label",
        "org.example",
        "did:web:org.example",
        "ak:event:wrong_kind",
    ] {
        assert!(
            serde_json::from_value::<HandleClaimVariant>(
                json!({"kind":"organization_handle","organization_id":invalid})
            )
            .is_err(),
            "{invalid}"
        );
    }
}
