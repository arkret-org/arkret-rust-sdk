//! Verified Applet delivery authentication and its stable idempotency binding.

use arkret_wire::{DidCoreId, DidUrl, Hash, ServiceOperationId};
use serde::{Deserialize, Serialize};

use super::HttpMessageSignatureAlgorithm;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppletDeliveryDirection {
    NodeToApplet,
    AppletToArkretInbound,
}

/// Receiver-derived authentication after verifying the current HTTP signature.
/// It is not an input supplied by the request author and does not itself prove
/// freshness, possession of a signing key, or an active registration/install.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppletDeliveryAuthenticationRecord {
    pub operation_id: ServiceOperationId,
    pub direction: AppletDeliveryDirection,
    pub source_id: DidCoreId,
    pub destination_id: DidCoreId,
    pub signature_label: String,
    pub verification_method: DidUrl,
    pub verification_key_digest: Hash,
    pub signature_algorithm: HttpMessageSignatureAlgorithm,
    pub registration_epoch: Hash,
    pub idempotency_key: String,
    pub content_digest: String,
    pub covered_components: Vec<String>,
    pub created: i64,
    pub expires: i64,
}

impl AppletDeliveryAuthenticationRecord {
    /// The stable §7.3.1 binding excludes only the two per-delivery time
    /// parameters. The full record remains available for audit; callers must
    /// verify each new signature's current authority and window before using
    /// this digest to recover a previous outcome.
    pub fn stable_digest(&self) -> Result<Hash, String> {
        let mut binding = serde_json::to_value(self).map_err(|error| error.to_string())?;
        let object = binding
            .as_object_mut()
            .ok_or("delivery record is not an object")?;
        object.remove("created");
        object.remove("expires");
        let bytes =
            arkret_canonical::canonical_json_bytes(&binding).map_err(|error| error.to_string())?;
        Hash::new(arkret_canonical::sha256_digest_from_slices(&[
            b"ak.applet.delivery_authentication_record.v1\n",
            &bytes,
        ]))
        .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn record() -> AppletDeliveryAuthenticationRecord {
        serde_json::from_value(json!({
            "operation_id": "ak.edge.applet.command.transaction.v1",
            "direction": "applet_to_arkret_inbound",
            "source_id": "ak:did_core:web:applet.example",
            "destination_id": "ak:did_core:web:station.example",
            "signature_label": "sig1",
            "verification_method": "did:web:applet.example#key-1",
            "verification_key_digest": format!("sha256:{}", "a".repeat(64)),
            "signature_algorithm": "ed25519",
            "registration_epoch": format!("sha256:{}", "b".repeat(64)),
            "idempotency_key": "delivery-1",
            "content_digest": "sha-256=:Zm94:",
            "covered_components": [
                "@method", "@target-uri", "@authority", "content-digest",
                "arkret-operation", "source-service-id", "destination-service-id",
                "idempotency-key"
            ],
            "created": 1_800_000_000,
            "expires": 1_800_000_060
        }))
        .unwrap()
    }

    #[test]
    fn fresh_signature_times_preserve_stable_binding_and_full_audit() {
        let first = record();
        let mut retry = first.clone();
        retry.created += 60;
        retry.expires += 60;
        assert_ne!(first, retry);
        assert_eq!(
            first.stable_digest().unwrap(),
            retry.stable_digest().unwrap()
        );
        let full = serde_json::to_value(&retry).unwrap();
        assert_eq!(full["created"], retry.created);
        assert_eq!(full["expires"], retry.expires);
        let mut expected = full;
        expected.as_object_mut().unwrap().remove("created");
        expected.as_object_mut().unwrap().remove("expires");
        assert_eq!(
            retry.stable_digest().unwrap().as_str(),
            arkret_canonical::sha256_digest_from_slices(&[
                b"ak.applet.delivery_authentication_record.v1\n",
                &arkret_canonical::canonical_json_bytes(&expected).unwrap()
            ])
        );
    }

    #[test]
    fn every_other_authenticated_coordinate_remains_in_stable_binding() {
        let first = record();
        let digest = first.stable_digest().unwrap();
        for (field, value) in [
            ("operation_id", json!("ak.edge.applet.read.ping.v1")),
            ("direction", json!("node_to_applet")),
            ("source_id", json!("ak:did_core:web:another.example")),
            ("destination_id", json!("ak:did_core:web:another.example")),
            ("signature_label", json!("sig2")),
            ("verification_method", json!("did:web:applet.example#key-2")),
            (
                "verification_key_digest",
                json!(format!("sha256:{}", "c".repeat(64))),
            ),
            ("signature_algorithm", json!("ecdsa-p256-sha256")),
            (
                "registration_epoch",
                json!(format!("sha256:{}", "c".repeat(64))),
            ),
            ("idempotency_key", json!("delivery-2")),
            ("content_digest", json!("sha-256=:YmFy:")),
            ("covered_components", json!(["@method", "@authority"])),
        ] {
            let mut value_record = serde_json::to_value(&first).unwrap();
            value_record[field] = value;
            let changed: AppletDeliveryAuthenticationRecord =
                serde_json::from_value(value_record).unwrap();
            assert_ne!(
                digest,
                changed.stable_digest().unwrap(),
                "{field} must remain bound"
            );
        }
    }

    #[test]
    fn delivery_record_rejects_unknown_missing_and_invalid_direction_fields() {
        let first = serde_json::to_value(record()).unwrap();
        let mut unknown = first.clone();
        unknown["domain"] = json!("private");
        assert!(serde_json::from_value::<AppletDeliveryAuthenticationRecord>(unknown).is_err());
        let mut missing = first.clone();
        missing.as_object_mut().unwrap().remove("created");
        assert!(serde_json::from_value::<AppletDeliveryAuthenticationRecord>(missing).is_err());
        let mut direction = first;
        direction["direction"] = json!("peer_to_peer");
        assert!(serde_json::from_value::<AppletDeliveryAuthenticationRecord>(direction).is_err());
    }
}
