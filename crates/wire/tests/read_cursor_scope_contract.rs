use arkret_wire::ReadCursorScope;

#[test]
fn read_scope_strand_track_uses_explicit_track_field() {
    let scope = ReadCursorScope::strand(
        "ak:strand:AT_TSQZlyY7Fu85J33nzo3fSau9RjJOeu21RspghP1gC",
        Some("discussion"),
    );
    scope.validate().unwrap();

    let value = serde_json::to_value(&scope).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "kind": "strand",
            "container_ref": "ak:strand:AT_TSQZlyY7Fu85J33nzo3fSau9RjJOeu21RspghP1gC",
            "track_name": "discussion"
        })
    );
}
