use serde_json::json;

use super::*;

#[test]
fn error_envelope_serializes_to_spec_canonical_shape() {
    let envelope = ErrorEnvelope::new("capability_denied", "session grant is revoked")
        .with_request_id("ck:request:test")
        .with_retry_after_ms(None);

    let value = serde_json::to_value(envelope).unwrap();

    assert_eq!(
        value,
        json!({
            "ok": false,
            "error": {
                "code": "capability_denied",
                "message": "session grant is revoked"
            },
            "request_id": "ck:request:test"
        })
    );
}

#[test]
fn compat_surface_entry_serializes_schema_shape() {
    let surface = CompatSurfaceEntry::external_interop("soland_private_local_routes")
        .with_notes("local compatibility surface")
        .with_extra_string("base_path", "/_soland")
        .with_extra_string("status", "soland_private_local");

    let value = serde_json::to_value(surface).unwrap();

    assert_eq!(value["name"], "soland_private_local_routes");
    assert_eq!(value["kind"], "external_interop");
    assert_eq!(value["notes"], "local compatibility surface");
    assert_eq!(value["base_path"], "/_soland");
    assert_eq!(value["status"], "soland_private_local");
}

#[test]
fn compat_surface_kind_rejects_removed_wire_values() {
    for value in ["legacy_alias", "deprecated_alias"] {
        let parsed: std::result::Result<CompatSurfaceKind, _> =
            serde_json::from_value(serde_json::json!(value));
        assert!(parsed.is_err(), "{value} is not a v1 compat_surface kind");
    }
}

#[test]
fn key_backup_recipient_method_rejects_removed_wire_values() {
    for value in [
        "device_snapshot_secret",
        "threshold_recovery",
        "hardware_wrapped_key",
    ] {
        let parsed: std::result::Result<KeyBackupRecipientMethod, _> =
            serde_json::from_value(serde_json::json!(value));
        assert!(
            parsed.is_err(),
            "{value} must not be a key-backup recipient_method"
        );
    }
}

#[test]
fn directory_realm_search_outcome_decodes_typed_preview_fields() {
    let value = serde_json::json!({
        "realms": [
            {
                "realm_id": "ck:realm:01904100-0000-7000-8000-000000000001",
                "title": "Public Realm",
                "member_count_bucket": "51-100",
                "as_of": "2026-06-13T00:00:00Z",
                "source_refs": ["ck:event:01904100-0000-7000-8000-000000000002"],
                "policy_revision": "rev-1"
            },
            {
                "realm_id": "ck:realm:01904100-0000-7000-8000-000000000003",
                "member_count_bucket": 342,
                "as_of": "2026-06-13T00:00:00Z",
                "source_refs": ["ck:event:01904100-0000-7000-8000-000000000004"],
                "policy_revision": "rev-2"
            }
        ],
        "next_cursor": null,
        "has_more": false
    });

    let outcome: DirectoryRealmSearchOutcome = serde_json::from_value(value).unwrap();

    assert!(!outcome.has_more);
    assert!(matches!(
        outcome.realms[0].member_count_bucket,
        Some(RealmMemberCountBucket::Bucket(
            RealmMemberCountBucketLabel::FiftyOneToOneHundred
        ))
    ));
    assert!(matches!(
        outcome.realms[1].member_count_bucket,
        Some(RealmMemberCountBucket::Exact(342))
    ));
}
