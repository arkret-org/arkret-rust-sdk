//! Object-patch payload for `event-payload.schema.json#/$defs/object_patch_payload`.
//!
//! The `ak.schema.patch.v1` container grammar (`Patch` / `PatchOp` and the
//! path / semantic-safety validators) is owned by `arkret_wire::patch`, and
//! the payload-shaped `ObjectPatchPayload` migrated to
//! `arkret-models-collaboration` (`object_patch`). Both are re-exported here
//! to preserve the `arkret_core::` path. The cross-layer conformance tests
//! (which need the core schema validator catalog and reason codes) stay in
//! core.

pub use arkret_models_collaboration::object_patch::*;
pub use arkret_wire::patch::*;

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn object_patch_payload_serializes_canonical_shape() {
        let mut patch = Patch::new();
        patch
            .insert_op("fields.document", PatchOp::set(json!({ "blocks": [] })))
            .unwrap();

        let payload =
            ObjectPatchPayload::for_target("ak:strand:0196419b-0000-7000-8000-000000000001", patch)
                .unwrap();
        let value = payload.to_value().unwrap();

        assert_eq!(
            value,
            json!({
                "target_ref": "ak:strand:0196419b-0000-7000-8000-000000000001",
                "patch": {
                    "fields.document": {
                        "$op": "set",
                        "value": { "blocks": [] }
                    }
                }
            })
        );
    }

    #[test]
    fn object_patch_payload_matches_registered_event_payload_schema() {
        let mut patch = Patch::new();
        patch.insert_op("title", PatchOp::set("Roadmap")).unwrap();
        let payload =
            ObjectPatchPayload::for_target("ak:morph:0196419b-0000-7000-8000-000000000002", patch)
                .unwrap()
                .to_value()
                .unwrap();

        crate::schema::event_payload_validator_catalog()
            .unwrap()
            .validate_payload("ak.morph.update", &payload)
            .unwrap();
    }

    #[test]
    fn object_patch_payload_deserialize_rejects_empty_patch() {
        let err = serde_json::from_value::<ObjectPatchPayload>(json!({
            "target_ref": "ak:strand:0196419b-0000-7000-8000-000000000003",
            "patch": {}
        }))
        .unwrap_err();
        assert!(err.to_string().contains("minProperties"));
    }

    #[test]
    fn object_patch_payload_rejects_non_schema_object_ref() {
        let mut patch = Patch::new();
        patch.insert_op("title", PatchOp::set("Roadmap")).unwrap();
        let err = ObjectPatchPayload::for_target("ak:strand:not-a-uuid7", patch).unwrap_err();
        assert!(err.to_string().contains("object_ref"));
    }

    #[test]
    fn object_patch_payload_rejects_reducer_managed_path() {
        let mut patch = Patch::new();
        patch
            .insert_op("state", PatchOp::set(json!("archived")))
            .unwrap();

        let err =
            ObjectPatchPayload::for_target("ak:strand:0196419b-0000-7000-8000-000000000004", patch)
                .unwrap_err();
        assert!(
            err.to_string()
                .contains(crate::error::ReasonCode::PATCH_PATH_REDUCER_MANAGED)
        );
    }

    #[test]
    fn object_patch_payload_rejects_direct_redactable_unset() {
        let mut patch = Patch::new();
        patch
            .insert_op("encrypted_content", PatchOp::unset())
            .unwrap();

        let err = ObjectPatchPayload::for_target(
            "ak:message:0196419b-0000-7000-8000-000000000005",
            patch,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains(crate::error::ReasonCode::PATCH_UNSET_REDACTABLE_FIELD)
        );
    }

    #[test]
    fn object_patch_payload_allows_non_redactable_metadata_unset() {
        let mut patch = Patch::new();
        patch.insert_op("metadata.title", PatchOp::unset()).unwrap();

        ObjectPatchPayload::for_target("ak:strand:0196419b-0000-7000-8000-000000000006", patch)
            .unwrap();
    }
}
