//! Event payload schema artifact counterparts.
//!
//! The payload counterpart submodules migrated to
//! `arkret-models-collaboration` (`events_payloads`); every public item is
//! re-exported here so the canonical path
//! `crate::models::artifacts::event_payload::Name` is preserved. The
//! applet-domain payloads stay pending the applet carve-out, and the
//! morph-schema migration fixture test stays with the embedded spec
//! artifacts.

mod account_misc {
    pub use arkret_models_collaboration::events_payloads::account_misc::*;
}
mod agent {
    pub use arkret_models_collaboration::events_payloads::agent::*;
}
mod call {
    pub use arkret_models_collaboration::events_payloads::call::*;
}
mod capability_circle_consent_contact {
    pub use arkret_models_collaboration::events_payloads::capability_circle_consent_contact::*;
}
mod device_identity {
    pub use arkret_models_collaboration::events_payloads::device_identity::*;
}
mod list_message_mimi_mls {
    pub use arkret_models_collaboration::events_payloads::list_message_mimi_mls::*;
}
mod moderation_morph_misc {
    pub use arkret_models_collaboration::events_payloads::moderation_morph_misc::*;
}
mod preview_realm_reaction {
    pub use arkret_models_collaboration::events_payloads::preview_realm_reaction::*;
}
mod strand_history_join {
    pub use arkret_models_collaboration::events_payloads::strand_history_join::*;
}
mod applet_audit;

pub use account_misc::*;
pub use agent::*;
pub use applet_audit::*;
pub use call::*;
pub use capability_circle_consent_contact::*;
pub use device_identity::*;
pub use list_message_mimi_mls::*;
pub use moderation_morph_misc::*;
pub use preview_realm_reaction::*;
pub use strand_history_join::*;

#[cfg(test)]
mod morph_schema_fixture_tests {
    use std::collections::BTreeMap;

    use serde_json::Value;

    use super::*;
    use crate::models::MorphId;
    use crate::{canonical, schema};

    #[test]
    fn morph_transformation_fixture_executes_all_registered_rules() {
        let fixture =
            schema::embedded_json_artifact("fixtures/morph-schema-migration-fixture.json").unwrap();
        for vector in fixture["vectors"].as_array().unwrap() {
            let input = &vector["input"];
            let payload = &input["payload"];
            let migrate = MorphSchemaMigratePayload {
                morph_id: MorphId::new("ak:morph:0196419b-0000-7000-8000-000000000001").unwrap(),
                from_schema_refs: serde_json::from_value(payload["from_schema_refs"].clone())
                    .unwrap(),
                to_schema_refs: serde_json::from_value(payload["to_schema_refs"].clone()).unwrap(),
                compatibility_class: payload["compatibility_class"].as_str().unwrap().to_owned(),
                transformation_rules: Some(
                    serde_json::from_value(payload["transformation_rules"].clone()).unwrap(),
                ),
                migration_evidence: None,
            };
            let fields: BTreeMap<String, Value> =
                serde_json::from_value(input["fields"].clone()).unwrap();
            let output = migrate
                .apply_transformation(&fields)
                .unwrap_or_else(|error| panic!("{} failed: {error}", vector["vector_id"]));
            assert_eq!(
                serde_json::to_value(&output).unwrap(),
                vector["expected_output"],
                "{} output drifted",
                vector["vector_id"]
            );
            assert_eq!(
                canonical::canonical_sha256(&output).unwrap(),
                vector["expected_output_digest"].as_str().unwrap(),
                "{} digest drifted",
                vector["vector_id"]
            );
        }
    }
}
