//! Agent key-pairing canonical binding helpers.

use serde::Serialize;
use serde_json::Value;

use crate::{
    Did, Error, Hash, OP_ACCOUNT_AGENT_KEY_PAIR, PublicKey, Result, base64url_decode, canonical,
};

#[derive(Serialize)]
struct AgentKeyPairingRequestBinding<'a> {
    kind: &'static str,
    operation_id: &'static str,
    controller_id: &'a str,
    agent_id: &'a str,
    verification_method: &'a str,
    runtime_public_key_digest: &'a str,
    pairing_request_id: &'a str,
    pairing_code: &'a str,
    expires_at: &'a str,
    audience: &'a str,
}

#[derive(Serialize)]
struct AgentKeyPairProofRequestBinding<'a> {
    kind: &'static str,
    operation_id: &'static str,
    pairing_request_id: &'a str,
    agent_id: &'a str,
    verification_method: &'a str,
    public_key: &'a Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_attestation: Option<&'a Value>,
}

#[derive(Serialize)]
struct AgentRuntimeKeyBinding<'a> {
    agent_id: &'a str,
    attestation_digest: &'a str,
    kind: &'static str,
    pairing_request_id: &'a str,
    public_key_digest: &'a str,
    verification_method: &'a str,
}

pub fn agent_runtime_public_key_digest(public_key: &Value) -> Result<Hash> {
    let key: PublicKey = serde_json::from_value(public_key.clone()).map_err(|error| {
        Error::Protocol(format!(
            "agent runtime public_key must match public_key schema: {error}"
        ))
    })?;
    if key.kty != "OKP" {
        return Err(Error::Protocol(
            "agent runtime public_key.kty must be OKP".to_owned(),
        ));
    }
    if key.alg != "Ed25519" && key.alg != "EdDSA" {
        return Err(Error::Protocol(
            "agent runtime public_key.alg must be Ed25519 or EdDSA".to_owned(),
        ));
    }
    if key.kid.trim().is_empty() {
        return Err(Error::Protocol(
            "agent runtime public_key.kid must not be empty".to_owned(),
        ));
    }
    if base64url_decode(key.key.as_bytes())?.len() != 32 {
        return Err(Error::Protocol(
            "agent runtime public_key.key must be a 32-byte Ed25519 key".to_owned(),
        ));
    }
    Hash::new(canonical::canonical_sha256(public_key)?).map_err(Error::from)
}

/// Digest the runtime attestation value used by the stable approval binding.
/// An absent attestation is represented by canonical JSON `null`.
pub fn agent_runtime_attestation_digest(runtime_attestation: Option<&Value>) -> Result<Hash> {
    Hash::new(canonical::canonical_sha256(
        runtime_attestation.unwrap_or(&Value::Null),
    )?)
    .map_err(Error::from)
}

/// Compute the stable runtime-key approval binding from source key material.
pub fn agent_runtime_key_binding_digest(
    agent_id: &Did,
    pairing_request_id: &str,
    verification_method: &str,
    public_key: &Value,
    runtime_attestation: Option<&Value>,
) -> Result<Hash> {
    let public_key_digest = agent_runtime_public_key_digest(public_key)?;
    let attestation_digest = agent_runtime_attestation_digest(runtime_attestation)?;
    agent_runtime_key_binding_digest_from_digests(
        agent_id,
        pairing_request_id,
        verification_method,
        &public_key_digest,
        &attestation_digest,
    )
}

/// Compute the stable runtime-key approval binding from persisted digests.
pub fn agent_runtime_key_binding_digest_from_digests(
    agent_id: &Did,
    pairing_request_id: &str,
    verification_method: &str,
    public_key_digest: &Hash,
    attestation_digest: &Hash,
) -> Result<Hash> {
    Hash::new(canonical::canonical_sha256(&AgentRuntimeKeyBinding {
        agent_id: agent_id.as_str(),
        attestation_digest: attestation_digest.as_str(),
        kind: "ak.agent.runtime_key_binding.v1",
        pairing_request_id,
        public_key_digest: public_key_digest.as_str(),
        verification_method,
    })?)
    .map_err(Error::from)
}

#[allow(clippy::too_many_arguments)]
pub fn agent_key_pairing_request_binding_digest(
    controller_id: &Did,
    agent_id: &Did,
    verification_method: &str,
    runtime_public_key_digest: &Hash,
    pairing_request_id: &str,
    pairing_code: &str,
    pairing_expires_at: &str,
    audience: &str,
) -> Result<Hash> {
    Hash::new(canonical::canonical_sha256(
        &AgentKeyPairingRequestBinding {
            kind: "ak.agent.key_pairing_request_binding.v1",
            operation_id: OP_ACCOUNT_AGENT_KEY_PAIR,
            controller_id: controller_id.as_str(),
            agent_id: agent_id.as_str(),
            verification_method,
            runtime_public_key_digest: runtime_public_key_digest.as_str(),
            pairing_request_id,
            pairing_code,
            expires_at: pairing_expires_at,
            audience,
        },
    )?)
    .map_err(Error::from)
}

pub fn agent_key_pair_proof_request_binding_digest(
    pairing_request_id: &str,
    agent_id: &Did,
    verification_method: &str,
    public_key: &Value,
    runtime_attestation: Option<&Value>,
) -> Result<Hash> {
    Hash::new(canonical::canonical_sha256(
        &AgentKeyPairProofRequestBinding {
            kind: "ak.agent.key_pair_proof_of_possession_request.v1",
            operation_id: OP_ACCOUNT_AGENT_KEY_PAIR,
            pairing_request_id,
            agent_id: agent_id.as_str(),
            verification_method,
            public_key,
            runtime_attestation,
        },
    )?)
    .map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn runtime_key_binding_matches_normative_vector() {
        let agent_id = Did::new("did:webvh:z6mkagent:agent.example").unwrap();
        let public_key = json!({
            "alg": "EdDSA",
            "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "kid": "runtime-1",
            "kty": "OKP"
        });

        let public_key_digest = agent_runtime_public_key_digest(&public_key).unwrap();
        let attestation_digest = agent_runtime_attestation_digest(None).unwrap();
        let binding_digest = agent_runtime_key_binding_digest(
            &agent_id,
            "pairing_request:01964137-0000-7000-8000-000000000000",
            "did:webvh:z6mkagent:agent.example#runtime-1",
            &public_key,
            None,
        )
        .unwrap();

        assert_eq!(
            public_key_digest.as_str(),
            "sha256:7bfcb9251367ab71fd32c19fc23c11b46ddbc371b52fcb5a75eaa1a79f5f463b"
        );
        assert_eq!(
            attestation_digest.as_str(),
            "sha256:74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b"
        );
        assert_eq!(
            binding_digest.as_str(),
            "sha256:1dd1a4f03dfc6086a43ae3f0e1eca877c9040c25fd95fc48d1b278568306fb06"
        );
    }

    #[test]
    fn runtime_key_binding_changes_when_key_material_changes() {
        let agent_id = Did::new("did:webvh:z6mkagent:agent.example").unwrap();
        let first = json!({
            "alg": "EdDSA",
            "key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "kid": "runtime-1",
            "kty": "OKP"
        });
        let second = json!({
            "alg": "EdDSA",
            "key": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "kid": "runtime-1",
            "kty": "OKP"
        });
        let digest = |public_key: &Value| {
            agent_runtime_key_binding_digest(
                &agent_id,
                "pairing_request:01964137-0000-7000-8000-000000000000",
                "did:webvh:z6mkagent:agent.example#runtime-1",
                public_key,
                None,
            )
            .unwrap()
        };
        assert_ne!(digest(&first), digest(&second));
    }
}
