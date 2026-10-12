//! Optional Strand titles must follow the canonical metadata schema.

use arkret_models_collaboration::objects::strand::Strand;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use arkret_wire::{ActorId, SchemaId};
use serde_json::{Value, json};

fn strand() -> Value {
    let actor: ActorId = serde_json::from_value(json!({
        "kind": "account",
        "account_id": {
            "principal_id": "ak:did_core:webvh:QmTnpRaadxso9gmuqCaoT54ib4kWKNt1F5UuqXN6i5hwey",
            "station_id": "ak:did_core:web:station.example"
        }
    }))
    .unwrap();
    serde_json::to_value(Strand::discussion(
        "ak:strand:AdP2S6y0Ms7yp9-GNvXZ3sVfvTEo8mtnV3G_RfApIOn0"
            .parse()
            .unwrap(),
        "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            .parse()
            .unwrap(),
        "Title",
        actor,
    ))
    .unwrap()
}

#[test]
fn omitted_metadata_and_untitled_metadata_are_canonical_strands() {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    for metadata in [
        None,
        Some(json!({})),
        Some(json!({"summary": "An untitled discussion"})),
    ] {
        let mut wire = strand();
        wire.as_object_mut().unwrap().remove("metadata");
        if let Some(value) = metadata {
            wire["metadata"] = value;
        }
        registry.validate_value(SchemaId::STRAND_V1, &wire).unwrap();
        let value: Strand = serde_json::from_value(wire.clone()).unwrap();
        value.validate_title().unwrap();
        value.validate_profile_activation().unwrap();
        value.validate_content_surfaces().unwrap();
        assert_eq!(serde_json::to_value(value).unwrap(), wire);
    }
}

#[test]
fn present_title_retains_the_canonical_display_text_profile() {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let registry = schema_registry_from_spec_artifacts(&artifacts).unwrap();
    for (title, accepted) in [
        ("Title".to_owned(), true),
        ("界".repeat(512), true),
        ("".to_owned(), false),
        ("   ".to_owned(), false),
        ("界".repeat(513), false),
        ("line\nbreak".to_owned(), false),
        ("e\u{301}".to_owned(), false),
        ("x\u{202e}y".to_owned(), false),
    ] {
        let mut wire = strand();
        wire["metadata"]["title"] = json!(title);
        assert_eq!(
            registry.validate_value(SchemaId::STRAND_V1, &wire).is_ok(),
            accepted
        );
        let value: Strand = serde_json::from_value(wire).unwrap();
        assert_eq!(value.validate_title().is_ok(), accepted);
    }
}
