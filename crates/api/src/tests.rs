use super::*;
use std::collections::BTreeSet;

#[test]
fn operation_ids_are_unique() {
    let mut ids = BTreeSet::new();
    for endpoint in endpoints() {
        assert!(ids.insert(endpoint.operation_id), "duplicate {}", endpoint.operation_id);
    }
}

#[test]
fn catalog_covers_protocol_surfaces() {
    for surface in [
        ApiSurface::Server,
        ApiSurface::Identity,
        ApiSurface::Sync,
        ApiSurface::Directory,
        ApiSurface::Blob,
        ApiSurface::Push,
        ApiSurface::DeviceMessages,
        ApiSurface::Keys,
        ApiSurface::Authz,
        ApiSurface::Policy,
        ApiSurface::Media,
        ApiSurface::Moderation,
        ApiSurface::Mimi,
        ApiSurface::Account,
        ApiSurface::Admin,
        ApiSurface::Applet,
    ] {
        assert!(endpoints_for_surface(surface).next().is_some(), "{surface:?}");
    }
}

#[test]
fn matcher_routes_post_applet_transactions() {
    let matched = match_endpoint(EndpointMethod::Post, "/api/v1/applet/transactions").unwrap();
    assert_eq!(matched.endpoint.operation_id, "cx.applet.transaction");
    assert!(matched.path_parameters.is_empty());
}

#[test]
fn endpoint_parameters_include_common_tracing_headers() {
    let endpoint = endpoint_by_operation("cx.blob.upload").unwrap();
    let parameters = endpoint_parameters(*endpoint);
    assert!(parameters.iter().any(|parameter| parameter.name == "X-Contrix-Request-Id"));
    assert!(parameters.iter().any(|parameter| parameter.name == "Traceparent"));
    assert!(parameters.iter().any(|parameter| parameter.name == "X-Contrix-Blob-Metadata"));
}
