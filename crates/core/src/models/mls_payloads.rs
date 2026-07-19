//! MLS event payloads, re-exported from `arkret_models_crypto::mls_payloads`.
//!
//! The payload shapes, deterministic CBOR codec, and type-local validation
//! live in `arkret-models-crypto`. This module keeps the re-export panel and
//! the schema-registry conformance test (which needs `arkret-schema`).

pub use arkret_models_crypto::mls_payloads::*;

#[cfg(test)]
mod schema_tests {
    use super::*;
    use crate::{EventId, Hash, RealmId, base64url_encode};

    fn realm() -> RealmId {
        RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000001").unwrap()
    }

    fn event(n: u8) -> EventId {
        EventId::new(format!("ak:event:0196419b-0000-7000-8000-00000000000{n}")).unwrap()
    }

    fn hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn group_id() -> String {
        base64url_encode(b"arkret-mls-test-group")
    }

    #[test]
    fn mls_commit_payload_matches_registered_event_schema() {
        let binding = MlsGovernanceBindingPayload::realm(
            realm(),
            group_id(),
            0,
            1,
            vec![event(2)],
            hash('2'),
            hash('3'),
            hash('4'),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "ak.reducer.v1",
        )
        .unwrap();
        let payload = MlsCommitPayload::new(
            group_id(),
            0,
            event(1).to_string(),
            Vec::new(),
            1,
            hash('7'),
            binding,
        )
        .unwrap();
        let value = serde_json::to_value(&payload).unwrap();

        crate::schema::event_payload_validator_catalog()
            .unwrap()
            .validate_payload(payload.event_kind(), &value)
            .unwrap();
        assert!(value.get("group_id").is_none());
        assert!(value.get("expected_prev_epoch").is_none());
        assert!(value.get("commit_bytes_b64").is_none());
    }
}
