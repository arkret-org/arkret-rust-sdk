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
fn catalog_covers_builtin_operation_registry() {
    let endpoint_ids =
        endpoints().iter().map(|endpoint| endpoint.operation_id).collect::<BTreeSet<_>>();
    let registry_ids =
        contrix_core::BUILT_IN_OPERATION_KINDS.iter().copied().collect::<BTreeSet<_>>();

    let missing = registry_ids.difference(&endpoint_ids).copied().collect::<Vec<_>>();
    let extra = endpoint_ids.difference(&registry_ids).copied().collect::<Vec<_>>();

    assert!(missing.is_empty(), "missing catalog endpoints for {missing:?}");
    assert!(extra.is_empty(), "catalog endpoints not in built-in registry {extra:?}");
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
fn matcher_routes_key_backup_delete() {
    let matched = match_endpoint(
        EndpointMethod::Delete,
        "/api/v1/keys/backups/cx:backup:01964137-0000-7000-8000-000000000000",
    )
    .unwrap();
    assert_eq!(matched.endpoint.operation_id, "cx.keys.backups.delete");
    assert_eq!(
        matched.path_parameters.get("backup_id").map(String::as_str),
        Some("cx:backup:01964137-0000-7000-8000-000000000000")
    );
}

#[test]
fn endpoint_parameters_include_common_tracing_headers() {
    let endpoint = endpoint_by_operation("cx.blob.upload").unwrap();
    let parameters = endpoint_parameters(*endpoint);
    assert!(parameters.iter().any(|parameter| parameter.name == "X-Contrix-Request-Id"));
    assert!(parameters.iter().any(|parameter| parameter.name == "Traceparent"));
    assert!(parameters.iter().any(|parameter| parameter.name == "X-Contrix-Blob-Metadata"));
}
