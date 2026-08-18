//! Object-patch payload for `event-payload.schema.json#/$defs/object_patch_payload`.
//!
//! The `arkret` umbrella re-exports `ObjectPatchPayload` at its root.
//! The `ak.schema.patch.v1` container grammar (`Patch` / `PatchOp` and the
//! path / semantic-safety validators) is owned by `arkret_wire::patch` and
//! re-exported through the umbrella unchanged. This module keeps only the
//! payload-shaped `ObjectPatchPayload`, whose `target_ref` validation is
//! defined by the event-payload schema rather than the patch container
//! itself.

use std::sync::OnceLock;

use arkret_wire::patch::{Patch, PatchTargetKind, validate_patch_semantic_safety};
use arkret_wire::{Error, Hash, Result};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Payload shape shared by all event kinds registered against
/// `event-payload.schema.json#/$defs/object_patch_payload`.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ObjectPatchPayload {
    pub target_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<String>,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

impl ObjectPatchPayload {
    /// Build the minimal object-patch payload.
    pub fn new(_patch: Patch) -> Result<Self> {
        Err(Error::Protocol(
            "object_patch_payload requires target_ref; use ObjectPatchPayload::for_target"
                .to_owned(),
        ))
    }

    /// Build an object-patch payload that targets a specific object.
    pub fn for_target(target_ref: impl Into<String>, patch: Patch) -> Result<Self> {
        let payload = Self {
            target_ref: target_ref.into(),
            object_ref: None,
            patch,
            expected_state_digest: None,
        };
        payload.validate()?;
        Ok(payload)
    }

    /// Build an object-patch payload using the schema's `object_ref`
    /// alias.
    pub fn for_object(object_ref: impl Into<String>, patch: Patch) -> Result<Self> {
        let _ = (object_ref.into(), patch);
        Err(Error::Protocol(
            "object_patch_payload.object_ref is not canonical; use target_ref".to_owned(),
        ))
    }

    /// Attach an expected-state hash for CAS-style object updates.
    pub fn with_expected_state_digest(mut self, expected_state_digest: Hash) -> Self {
        self.expected_state_digest = Some(expected_state_digest);
        self
    }

    /// Validate the typed payload's wire-level invariants.
    pub fn validate(&self) -> Result<()> {
        validate_object_patch_ref("target_ref", &self.target_ref)?;
        if let Some(object_ref) = &self.object_ref {
            validate_object_patch_ref("object_ref", object_ref)?;
            return Err(Error::Protocol(
                "object_patch_payload.object_ref is not canonical; use target_ref".to_owned(),
            ));
        }
        // `target_ref` was just validated as this payload's typed patch target, so
        // it is the proven object kind for the reducer-managed path decision.
        validate_patch_semantic_safety(
            &self.patch,
            PatchTargetKind::from_typed_target(&self.target_ref),
        )
    }

    /// Serialize after validating the same constraints enforced by the
    /// shared type constructors.
    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        serde_json::to_value(self).map_err(Error::from)
    }
}

impl<'de> Deserialize<'de> for ObjectPatchPayload {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            target_ref: String,
            #[serde(default)]
            object_ref: Option<String>,
            patch: Patch,
            #[serde(default)]
            expected_state_digest: Option<Hash>,
        }

        let wire = Wire::deserialize(deserializer)?;
        let payload = Self {
            target_ref: wire.target_ref,
            object_ref: wire.object_ref,
            patch: wire.patch,
            expected_state_digest: wire.expected_state_digest,
        };
        payload.validate().map_err(de::Error::custom)?;
        Ok(payload)
    }
}

fn validate_object_patch_ref(field: &str, value: &str) -> Result<()> {
    static OBJECT_REF: OnceLock<regex::Regex> = OnceLock::new();
    let object_ref = OBJECT_REF.get_or_init(|| {
        regex::Regex::new(
            r"^((?:ak:(realm|circle|space|actor_profile|strand|message|morph|relation|view|event):[A-Za-z0-9_-]{44}|ak:(policy|grant|invite|call|audit_binding|audit_session|audit_release|blob|snapshot|franking_proof|report):[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})|ak:blob:(sha256|blake3):[0-9a-f]{64}|did:[^\s]+|(sha256|blake3):[0-9a-f]{64})$",
        )
        .expect("object_ref regex compiles")
    });
    if object_ref.is_match(value) {
        Ok(())
    } else {
        Err(Error::Protocol(format!(
            "object_patch_payload.{field} must match event-payload.schema.json#/$defs/object_ref"
        )))
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::ReasonCode;
    use arkret_wire::patch::PatchOp;
    use serde_json::json;

    use super::*;

    #[test]
    fn object_patch_payload_serializes_canonical_shape() {
        let mut patch = Patch::new();
        patch
            .insert_op("fields.document", PatchOp::set(json!({ "blocks": [] })))
            .unwrap();

        let payload = ObjectPatchPayload::for_target(
            "ak:strand:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
            patch,
        )
        .unwrap();
        assert_eq!(
            payload.to_value().unwrap(),
            json!({
                "target_ref": "ak:strand:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-",
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
    fn object_patch_payload_deserialize_rejects_empty_patch() {
        let error = serde_json::from_value::<ObjectPatchPayload>(json!({
            "target_ref": "ak:strand:AV624IkuHj3HmxAYE6uyYmBa4Est3gGGdnOsjn71z5L2",
            "patch": {}
        }))
        .unwrap_err();
        assert!(error.to_string().contains("minProperties"));
    }

    #[test]
    fn object_patch_payload_rejects_non_schema_object_ref() {
        let mut patch = Patch::new();
        patch.insert_op("title", PatchOp::set("Roadmap")).unwrap();
        let error = ObjectPatchPayload::for_target("ak:strand:not-a-uuid7", patch).unwrap_err();
        assert!(error.to_string().contains("object_ref"));
    }

    #[test]
    fn object_patch_payload_rejects_reducer_managed_path() {
        let mut patch = Patch::new();
        patch
            .insert_op("state", PatchOp::set(json!("archived")))
            .unwrap();

        let error = ObjectPatchPayload::for_target(
            "ak:strand:ASc_XP_IqOBAY6GgbPMLFCeZmi0uBNaWvHazHgmn-B8K",
            patch,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains(ReasonCode::PATCH_PATH_REDUCER_MANAGED)
        );
    }

    #[test]
    fn object_patch_payload_rejects_direct_redactable_unset() {
        let mut patch = Patch::new();
        patch
            .insert_op("encrypted_content", PatchOp::unset())
            .unwrap();

        let error = ObjectPatchPayload::for_target(
            "ak:message:AdIeygO8cj8jUpcxH6i4a15i1zh2wq8eNKz5RgGEItdA",
            patch,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains(ReasonCode::PATCH_UNSET_REDACTABLE_FIELD)
        );
    }

    #[test]
    fn object_patch_payload_allows_non_redactable_metadata_unset() {
        let mut patch = Patch::new();
        patch.insert_op("metadata.title", PatchOp::unset()).unwrap();

        ObjectPatchPayload::for_target(
            "ak:strand:AX4pprTs5cf0KoXS7V-RcP3IeADDYrKM4o5DL-u47otn",
            patch,
        )
        .unwrap();
    }
}
