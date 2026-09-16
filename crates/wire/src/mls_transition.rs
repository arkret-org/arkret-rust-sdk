use serde_json::Value;

use crate::{Hash, Result, WireError};

/// Compute the registered Arkret v1 MLS Genesis transition digest.
pub fn mls_genesis_transition_digest(payload: &Value) -> Result<Hash> {
    let Value::Object(mut core) = payload.clone() else {
        return Err(WireError::Protocol(
            "MLS Genesis transition payload must be an object".to_owned(),
        ));
    };
    // The accepted v1 payload carries scope, deterministic group identity and
    // epoch only through `governance_binding`.  Do not resurrect the removed
    // outer mirrors here: this helper receives the already schema-validated
    // closed payload core and only freezes the transition preimage.
    for required in [
        "cipher_suite",
        "group_info_ref",
        "ratchet_tree_ref",
        "governance_binding",
        "created_at",
    ] {
        if !core.contains_key(required) {
            return Err(WireError::Protocol(format!(
                "MLS Genesis transition payload lacks {required}"
            )));
        }
    }
    core.remove("organization_recovery_archive");
    let mut preimage = b"ak.mls-genesis-transition-v1".to_vec();
    preimage.push(0);
    preimage.extend(arkret_canonical::canonical_json_bytes(&core)?);
    Ok(Hash::new(arkret_canonical::sha256_digest(preimage))?)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn schema_shaped_genesis() -> Value {
        json!({
            "cipher_suite": "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
            "group_info_ref": "ak:blob:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ratchet_tree_ref": "ak:blob:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "governance_binding": {
                "effective_scope": {
                    "kind": "realm",
                    "realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
                },
                "previous_epoch": 0,
                "next_epoch": 0
            },
            "created_at": "2026-09-14T00:00:00.000Z"
        })
    }

    #[test]
    fn genesis_transition_uses_the_closed_payload_without_outer_mirrors() {
        let payload = schema_shaped_genesis();
        let digest = mls_genesis_transition_digest(&payload).unwrap();

        let mut with_archive = payload;
        with_archive.as_object_mut().unwrap().insert(
            "organization_recovery_archive".to_owned(),
            json!({"excluded": "from-transition-preimage"}),
        );

        assert_eq!(
            mls_genesis_transition_digest(&with_archive).unwrap(),
            digest
        );
    }
}
