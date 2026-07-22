//! Transitional applet and audit payload re-exports.

pub use arkret_models_collaboration::events_payloads::audit::*;
pub use arkret_models_integration::applet_audit_payload::*;

#[cfg(test)]
mod applet_builder_tests {
    use std::collections::BTreeMap;

    use arkret_wire::{AppletIdentifier, Did, Hash};
    use serde_json::{Value, json};

    use super::*;
    use crate::schema::event_payload_validator_catalog_from_embedded_spec_artifacts;

    fn did(value: &str) -> Did {
        Did::new(value).unwrap()
    }

    fn applet_id() -> AppletIdentifier {
        AppletIdentifier::Did(did("did:webvh:z6mkfixture:applet.example"))
    }

    #[test]
    fn applet_registration_builder_validates_against_catalog() {
        let webhook_auth: BTreeMap<String, Value> = [(
            "key_ref".to_owned(),
            json!("did:webvh:z6mkfixture:applet.example#svc"),
        )]
        .into_iter()
        .collect();
        let proof: BTreeMap<String, Value> = [("signature".to_owned(), json!("c2ln"))]
            .into_iter()
            .collect();
        let payload = AppletRegistrationPayload::new(
            applet_id(),
            did("did:webvh:z6mkfixture:svc.example"),
            did("did:webvh:z6mkfixture:controller.example"),
            "https://applet.example",
            did("did:webvh:z6mkfixture:bot.example"),
            Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            webhook_auth,
            proof,
            "2026-07-08T10:05:00.000Z".parse().unwrap(),
        )
        .with_protocols(vec!["a2a".to_owned()])
        .with_requested_scopes(vec!["ak.message.create".to_owned()])
        .with_receive_events(true);
        let value = payload.to_value().unwrap();
        assert_eq!(
            value["service_id"],
            json!("did:webvh:z6mkfixture:svc.example")
        );
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        catalog
            .validate_payload("ak.applet.registration", &value)
            .unwrap();
    }

    #[test]
    fn applet_registration_builder_rejects_empty_proof() {
        let payload = AppletRegistrationPayload::new(
            applet_id(),
            did("did:webvh:z6mkfixture:svc.example"),
            did("did:webvh:z6mkfixture:controller.example"),
            "https://applet.example",
            did("did:webvh:z6mkfixture:bot.example"),
            Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            BTreeMap::new(),
            BTreeMap::new(),
            "2026-07-08T10:05:00.000Z".parse().unwrap(),
        );
        assert!(payload.to_value().is_err());
    }
}
