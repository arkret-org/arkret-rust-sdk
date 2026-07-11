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
