use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[test]
fn builtin_operation_ids_are_unique() {
    let ids = contrix_core::BUILT_IN_OPERATION_KINDS.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(ids.len(), contrix_core::BUILT_IN_OPERATION_KINDS.len());
}

#[test]
fn core_registry_matches_spec_operation_registry_when_available() {
    let path = spec_operation_registry_path();

    let registry = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    let registry: serde_json::Value = serde_json::from_str(&registry)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()));

    let spec_ids = registry
        .get("operations")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| panic!("{} has no operations array", path.display()))
        .iter()
        .map(|operation| {
            operation
                .get("operation_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_else(|| panic!("operation without operation_id in {}", path.display()))
        })
        .collect::<BTreeSet<_>>();
    let builtin_ids =
        contrix_core::BUILT_IN_OPERATION_KINDS.iter().copied().collect::<BTreeSet<_>>();

    let missing_from_core = spec_ids.difference(&builtin_ids).copied().collect::<Vec<_>>();
    let extra_in_core = builtin_ids.difference(&spec_ids).copied().collect::<Vec<_>>();

    assert!(
        missing_from_core.is_empty(),
        "core registry missing spec operations {missing_from_core:?}"
    );
    assert!(
        extra_in_core.is_empty(),
        "core registry has operations outside spec {extra_in_core:?}"
    );
}

fn spec_operation_registry_path() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    [
        manifest_dir
            .join("../../../contrix-spec/spec/v1/artifacts/registry/operation-registry.json"),
        PathBuf::from("../contrix-spec/spec/v1/artifacts/registry/operation-registry.json"),
    ]
    .into_iter()
    .find(|path| path.exists())
    .unwrap_or_else(|| {
        panic!(
            "spec operation registry artifact is required for drift tests; looked next to {}",
            manifest_dir.display()
        )
    })
}
