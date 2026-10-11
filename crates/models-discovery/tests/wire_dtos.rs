use arkret_models_discovery::{
    DirectoryRealmSearchOutcome, DirectorySearchRealmsRequestBody, InteropSurfaceEntry,
    InteropSurfaceKind, ServiceDescribe,
};
use arkret_wire::{Did, ServiceKind, TrustDomainId};
use serde_json::json;

#[test]
fn interop_surface_entry_is_closed_and_supports_delegated_resolver() {
    let surface = InteropSurfaceEntry::delegated_resolver("station_did_resolver")
        .with_notes("delegated DID document surface");
    let encoded = serde_json::to_value(&surface).unwrap();
    assert_eq!(encoded["kind"], "delegated_resolver");
    assert_eq!(surface.kind, InteropSurfaceKind::DelegatedResolver);
    assert!(
        serde_json::from_value::<InteropSurfaceEntry>(json!({
            "name": "private_routes", "kind": "external_interop", "base_path": "/_product"
        }))
        .is_err()
    );
}

#[test]
fn service_describe_round_trips_interop_surfaces() {
    let mut description = ServiceDescribe::development(
        Did::new("did:webvh:z6mkfixture:service.example").unwrap(),
        TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        ServiceKind::Station,
        vec!["ak.operation_bundle.station.describe.v1".to_owned()],
        vec![arkret_models_discovery::TransportBinding::HttpJson {
            base_url: "https://service.example".to_owned(),
            extension_profile_required: (),
        }],
    );
    description.interop_surfaces = vec![
        InteropSurfaceEntry::delegated_resolver("station_did_resolver"),
        InteropSurfaceEntry::matrix_passthrough("matrix_bridge"),
    ];
    let decoded: ServiceDescribe =
        serde_json::from_value(serde_json::to_value(&description).unwrap()).unwrap();
    assert_eq!(decoded.interop_surfaces, description.interop_surfaces);
}

#[test]
fn public_realm_search_models_are_closed() {
    let request: DirectorySearchRealmsRequestBody =
        serde_json::from_value(json!({"query": "engineering", "limit": 20})).unwrap();
    request.validate().unwrap();
    assert!(
        serde_json::from_value::<DirectorySearchRealmsRequestBody>(json!({
            "query": "engineering", "source_realm_id": "ak:realm:legacy"
        }))
        .is_err()
    );
    let outcome: DirectoryRealmSearchOutcome =
        serde_json::from_value(json!({"realms": [], "has_more": false})).unwrap();
    outcome.validate().unwrap();
}

#[test]
fn public_realm_entry_rejects_old_member_metadata() {
    let entry = json!({
        "realm_id": "ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir",
        "public_metadata": {"display_name": "Engineering"},
        "indexed_at": "2026-09-20T00:00:00Z",
        "expires_at": "2026-09-21T00:00:00Z",
        "member_count": 42
    });
    assert!(
        serde_json::from_value::<arkret_models_discovery::PublicRealmDirectoryEntry>(entry)
            .is_err()
    );
}
