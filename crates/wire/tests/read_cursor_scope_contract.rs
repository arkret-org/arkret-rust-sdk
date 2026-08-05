use arkret_wire::ReadCursorScope;

#[test]
fn read_scope_strand_track_uses_explicit_track_field() {
    let scope = ReadCursorScope::strand(
        "ak:strand:01904100-0000-8000-8000-58754cf88c25",
        Some("discussion"),
    );
    scope.validate().unwrap();

    let value = serde_json::to_value(&scope).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "kind": "strand",
            "container_ref": "ak:strand:01904100-0000-8000-8000-58754cf88c25",
            "track_name": "discussion"
        })
    );
}

#[test]
fn read_scope_rejects_removed_track_kind_variants() {
    let old = serde_json::json!("strand_discussion");
    assert!(serde_json::from_value::<ReadCursorScope>(old).is_err());
}
