use serde_json::Value;

use crate::{Hash, Result, WireError};

/// Public RFC 9420 leaf intent bound by a signed MLS governance digest.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsSecurityFrontierLeaf {
    pub leaf_index: u32,
    pub actor_id: crate::ActorId,
    pub credential_ref: crate::NonEmptyString,
}

pub const MLS_FRONTIER_MAX_LEAVES: usize = 65_536;

/// Shared count, ordering and identity bounds for query and admission inputs.
pub fn validate_mls_frontier_leaves(leaves: &[MlsSecurityFrontierLeaf]) -> Result<()> {
    if leaves.is_empty() || leaves.len() > MLS_FRONTIER_MAX_LEAVES {
        return Err(WireError::Protocol(
            "MLS frontier leaves must contain 1..=65536 entries (schema_violation)".to_owned(),
        ));
    }
    let mut previous = None;
    let mut credentials = std::collections::BTreeSet::new();
    for leaf in leaves {
        leaf.actor_id.validate()?;
        if leaf.credential_ref.as_str().chars().count() > 2048
            || previous.is_some_and(|index| index >= leaf.leaf_index)
            || !credentials.insert(leaf.credential_ref.as_str())
        {
            return Err(WireError::Protocol("MLS frontier leaves have an oversized credential, duplicate credential or noncanonical index order (schema_violation)".to_owned()));
        }
        previous = Some(leaf.leaf_index);
    }
    Ok(())
}

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
