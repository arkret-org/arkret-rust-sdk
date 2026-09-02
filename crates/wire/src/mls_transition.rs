use serde_json::Value;

use crate::{Hash, Result, WireError};

/// Compute the registered Arkret v1 MLS Genesis transition digest.
pub fn mls_genesis_transition_digest(payload: &Value) -> Result<Hash> {
    let Value::Object(mut core) = payload.clone() else {
        return Err(WireError::Protocol(
            "MLS Genesis transition payload must be an object".to_owned(),
        ));
    };
    for required in [
        "mls_group_id",
        "effective_scope",
        "epoch",
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
    if core.get("epoch").and_then(Value::as_u64) != Some(0) {
        return Err(WireError::Protocol(
            "MLS Genesis transition payload epoch must equal zero".to_owned(),
        ));
    }
    core.remove("organization_recovery_archive");
    let mut preimage = b"ak.mls-genesis-transition-v1".to_vec();
    preimage.push(0);
    preimage.extend(arkret_canonical::canonical_json_bytes(&core)?);
    Ok(Hash::new(arkret_canonical::sha256_digest(preimage))?)
}
