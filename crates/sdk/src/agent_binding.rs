//! Ed25519 `audit_binding` for the `ck.agent.interop_session.result`
//! envelope.
//!
//! An agent runtime proves that a result envelope came from a runtime
//! holding the configured signing key. The signature is computed over
//! a canonical subject string; verifiers confirm origin via
//! [`verify_ed25519_audit_binding`] using the public key carried
//! in-band on the envelope.
//!
//! ## Envelope shape
//!
//! ```jsonc
//! "audit_binding": {
//!   "binding_kind": "ed25519_v1",
//!   "actor_id": "did:web:alice.example",
//!   "key_id": "did:web:agent.example#key-1",
//!   "public_key_b64": "<base64-no-pad Ed25519 verifying key, 32 bytes>",
//!   "signature": "<base64-no-pad Ed25519 signature, 64 bytes>",
//!   "canonical_subject": "session_id=...\nagent_principal_id=...\necho=...\nactor_id=...\nbinding_kind=ed25519_v1"
//! }
//! ```
//!
//! `public_key_b64` is carried in-band so verifiers can confirm the
//! signature without an out-of-band fetch. Production deployments
//! SHOULD additionally check that `public_key_b64` matches the
//! `verificationMethod` published in the agent's DID document.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed25519SignedAuditBinding {
    /// Base64 (URL-safe, no padding) of the 64-byte Ed25519 signature.
    pub signature_b64: String,
    /// Base64 (URL-safe, no padding) of the 32-byte verifying key.
    pub public_key_b64: String,
    /// Canonical subject the signature commits to.
    pub canonical_subject: String,
}

/// Build the canonical subject for an Ed25519 binding. Pins the four
/// fields a verifier needs to bind a result to its originating
/// request: session_id, agent_principal_id, the result echo body
/// (canonical-JSON compact form), and the actor id that authored the
/// start event. The trailing `binding_kind=ed25519_v1` line scopes
/// the signature to this scheme so a hypothetical future
/// alternative binding cannot re-use the same bytes.
pub fn build_ed25519_canonical_subject(
    session_id: &str,
    agent_principal_id: &str,
    echo: &Value,
    actor_id: &str,
) -> String {
    let echo_canonical = serde_json::to_string(echo).unwrap_or_else(|_| "null".to_owned());
    format!(
        "session_id={session_id}\n\
         agent_principal_id={agent_principal_id}\n\
         echo={echo_canonical}\n\
         actor_id={actor_id}\n\
         binding_kind=ed25519_v1"
    )
}

/// Sign an Ed25519 agent `audit_binding`. The `signing_key_seed` is
/// the 32-byte Ed25519 secret seed (matches `SigningKey::from_bytes`).
/// Returns the wire-ready signature + public key encoded base64
/// URL-safe no-pad.
pub fn sign_ed25519_audit_binding(
    signing_key_seed: &[u8; 32],
    session_id: &str,
    agent_principal_id: &str,
    echo: &Value,
    actor_id: &str,
) -> Ed25519SignedAuditBinding {
    let signing_key = SigningKey::from_bytes(signing_key_seed);
    let canonical_subject =
        build_ed25519_canonical_subject(session_id, agent_principal_id, echo, actor_id);
    let signature: Signature = signing_key.sign(canonical_subject.as_bytes());
    Ed25519SignedAuditBinding {
        signature_b64: base64_url_no_pad_encode(&signature.to_bytes()),
        public_key_b64: base64_url_no_pad_encode(signing_key.verifying_key().as_bytes()),
        canonical_subject,
    }
}

/// Outcome of `verify_ed25519_audit_binding`. Distinguishes subject
/// mismatch (envelope describes inputs the verifier disagrees with),
/// public-key/signature decoding failures, and signature mismatch
/// (decoded fine, but the math does not verify).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ed25519AuditBindingVerifyOutcome {
    Valid,
    SubjectMismatch,
    SignatureMismatch,
    MalformedSignature,
    MalformedPublicKey,
}

/// Verify an Ed25519 agent `audit_binding`. Public key is supplied
/// explicitly (typically pulled out of the envelope's
/// `public_key_b64` field after the caller cross-checks it against
/// the agent's DID document).
pub fn verify_ed25519_audit_binding(
    public_key_b64: &str,
    session_id: &str,
    agent_principal_id: &str,
    echo: &Value,
    actor_id: &str,
    signature_b64: &str,
    canonical_subject_from_envelope: &str,
) -> Ed25519AuditBindingVerifyOutcome {
    let expected_subject =
        build_ed25519_canonical_subject(session_id, agent_principal_id, echo, actor_id);
    if expected_subject != canonical_subject_from_envelope {
        return Ed25519AuditBindingVerifyOutcome::SubjectMismatch;
    }
    let Some(public_key_bytes) = base64_url_no_pad_decode(public_key_b64) else {
        return Ed25519AuditBindingVerifyOutcome::MalformedPublicKey;
    };
    if public_key_bytes.len() != 32 {
        return Ed25519AuditBindingVerifyOutcome::MalformedPublicKey;
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&public_key_bytes);
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_arr) else {
        return Ed25519AuditBindingVerifyOutcome::MalformedPublicKey;
    };
    let Some(sig_bytes) = base64_url_no_pad_decode(signature_b64) else {
        return Ed25519AuditBindingVerifyOutcome::MalformedSignature;
    };
    if sig_bytes.len() != 64 {
        return Ed25519AuditBindingVerifyOutcome::MalformedSignature;
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);
    match verifying_key.verify_strict(expected_subject.as_bytes(), &signature) {
        Ok(_) => Ed25519AuditBindingVerifyOutcome::Valid,
        Err(_) => Ed25519AuditBindingVerifyOutcome::SignatureMismatch,
    }
}

/// Verify outcome for [`verify_audit_binding_by_kind`].
///
/// Higher-level than [`Ed25519AuditBindingVerifyOutcome`]: collapses
/// the two `Malformed*` Ed25519 outcomes into one and adds states for
/// the cases where the dispatcher cannot reach a scheme-specific
/// verifier at all (no `audit_binding` block, unknown `binding_kind`,
/// or required envelope fields missing).
///
/// Downstream services (yougen audit timeline, floria policy hooks)
/// call [`verify_audit_binding_by_kind`] and map this outcome to a
/// UI badge or policy decision. New binding schemes plug into the
/// dispatcher here so callers don't have to re-implement the kind
/// switch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditBindingVerifyOutcome {
    /// Signature recomputes against the carried key.
    Valid,
    /// `canonical_subject` field disagrees with the per-field
    /// (session_id, agent_principal_id, echo, actor_id) tuple.
    SubjectMismatch,
    /// Signature decoded fine but does not verify against the
    /// declared public key.
    SignatureMismatch,
    /// `signature` or `public_key_b64` was not a valid encoding.
    Malformed,
    /// `binding_kind` is not one of the supported values, or a
    /// required envelope field is missing.
    Unsupported,
    /// No `audit_binding` block at all (e.g. soland fail-closed result
    /// for an unknown agent).
    Absent,
}

/// Verify a `ck.agent.interop_session.result` payload's
/// `audit_binding` block, dispatched by `binding_kind`.
///
/// The `payload` is the projection event's `payload` field as
/// returned by `/_cokret/self/events`. The dispatcher reads the binding
/// plus the four canonical-subject inputs (`session_id`,
/// `result.agent_principal_id`, `result.echo`, `audit_binding.actor_id`) and
/// routes to the scheme-specific verifier:
///
///   * `ed25519_v1` → [`verify_ed25519_audit_binding`] using the
///     `public_key_b64` carried in the envelope.
///   * anything else → [`AuditBindingVerifyOutcome::Unsupported`].
///
/// Deployments wanting an alternative scheme ship their own
/// `binding_kind` and extend this dispatcher in the SDK so all
/// downstream consumers (yougen, floria, cotest fixtures) pick up
/// the new scheme uniformly.
pub fn verify_audit_binding_by_kind(payload: &Value) -> AuditBindingVerifyOutcome {
    let Some(binding) = payload.get("audit_binding") else {
        return AuditBindingVerifyOutcome::Absent;
    };
    let kind = binding.get("binding_kind").and_then(Value::as_str).unwrap_or("");
    match kind {
        "ed25519_v1" => verify_ed25519_audit_binding_from_payload(payload, binding),
        _ => AuditBindingVerifyOutcome::Unsupported,
    }
}

/// Per-scheme helper for the Ed25519 branch of
/// [`verify_audit_binding_by_kind`]. Kept private; callers go through
/// the dispatcher.
fn verify_ed25519_audit_binding_from_payload(
    payload: &Value,
    binding: &Value,
) -> AuditBindingVerifyOutcome {
    let Some(session_id) = payload.get("session_id").and_then(Value::as_str) else {
        return AuditBindingVerifyOutcome::Malformed;
    };
    let agent_principal_id = payload
        .get("result")
        .and_then(|r| r.get("agent_principal_id"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let echo = payload.get("result").and_then(|r| r.get("echo")).cloned().unwrap_or(Value::Null);
    let actor = binding.get("actor_id").and_then(Value::as_str).unwrap_or("");
    let canonical_subject = binding.get("canonical_subject").and_then(Value::as_str).unwrap_or("");
    let signature = binding.get("signature").and_then(Value::as_str).unwrap_or("");
    let Some(public_key_b64) = binding.get("public_key_b64").and_then(Value::as_str) else {
        return AuditBindingVerifyOutcome::Malformed;
    };
    let outcome = verify_ed25519_audit_binding(
        public_key_b64,
        session_id,
        agent_principal_id,
        &echo,
        actor,
        signature,
        canonical_subject,
    );
    match outcome {
        Ed25519AuditBindingVerifyOutcome::Valid => AuditBindingVerifyOutcome::Valid,
        Ed25519AuditBindingVerifyOutcome::SubjectMismatch => {
            AuditBindingVerifyOutcome::SubjectMismatch
        }
        Ed25519AuditBindingVerifyOutcome::SignatureMismatch => {
            AuditBindingVerifyOutcome::SignatureMismatch
        }
        Ed25519AuditBindingVerifyOutcome::MalformedSignature
        | Ed25519AuditBindingVerifyOutcome::MalformedPublicKey => {
            AuditBindingVerifyOutcome::Malformed
        }
    }
}

/// URL-safe base64 without padding. Mirrors the encoding the rest of
/// the SDK uses for compact wire fields (MLS key packages, X25519
/// public keys, etc.) so audit_binding fields play nicely with the
/// rest of the protocol.
fn base64_url_no_pad_encode(bytes: &[u8]) -> String {
    cokret_core::base64url_encode(bytes)
}

fn base64_url_no_pad_decode(s: &str) -> Option<Vec<u8>> {
    cokret_core::base64url_decode(s).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Fixed 32-byte test seed so every run computes the same
    /// `public_key_b64` — useful for diffing wire fixtures.
    const TEST_ED25519_SEED: &[u8; 32] = &[7u8; 32];

    #[test]
    fn ed25519_sign_and_verify_round_trip_succeeds() {
        let echo = json!({"op": "ping", "payload": "hello"});
        let signed = sign_ed25519_audit_binding(
            TEST_ED25519_SEED,
            "ck:session:e1",
            "did:web:agent.example",
            &echo,
            "did:web:alice.example",
        );
        let pk_bytes = base64_url_no_pad_decode(&signed.public_key_b64).expect("pk decodes");
        assert_eq!(pk_bytes.len(), 32);
        let sig_bytes = base64_url_no_pad_decode(&signed.signature_b64).expect("sig decodes");
        assert_eq!(sig_bytes.len(), 64);
        let outcome = verify_ed25519_audit_binding(
            &signed.public_key_b64,
            "ck:session:e1",
            "did:web:agent.example",
            &echo,
            "did:web:alice.example",
            &signed.signature_b64,
            &signed.canonical_subject,
        );
        assert_eq!(outcome, Ed25519AuditBindingVerifyOutcome::Valid);
    }

    #[test]
    fn ed25519_canonical_subject_scopes_to_binding_kind() {
        // The trailing `binding_kind=ed25519_v1` line prevents a
        // hypothetical future scheme from re-using these bytes.
        let echo = json!({"k": "v"});
        let subject = build_ed25519_canonical_subject(
            "ck:session:cross",
            "did:web:agent.example",
            &echo,
            "did:web:alice.example",
        );
        assert!(subject.ends_with("binding_kind=ed25519_v1"));
        assert!(subject.contains("session_id=ck:session:cross"));
        assert!(subject.contains("agent_principal_id=did:web:agent.example"));
        assert!(subject.contains("actor_id=did:web:alice.example"));
    }

    #[test]
    fn ed25519_verify_fails_with_subject_mismatch_when_actor_differs() {
        let echo = json!({"op": "ping"});
        let signed = sign_ed25519_audit_binding(
            TEST_ED25519_SEED,
            "ck:session:e2",
            "did:web:agent.example",
            &echo,
            "did:web:alice.example",
        );
        let outcome = verify_ed25519_audit_binding(
            &signed.public_key_b64,
            "ck:session:e2",
            "did:web:agent.example",
            &echo,
            "did:web:carol.example",
            &signed.signature_b64,
            &signed.canonical_subject,
        );
        assert_eq!(outcome, Ed25519AuditBindingVerifyOutcome::SubjectMismatch);
    }

    #[test]
    fn ed25519_verify_fails_with_signature_mismatch_under_different_public_key() {
        let echo = json!({});
        let signed = sign_ed25519_audit_binding(
            TEST_ED25519_SEED,
            "ck:session:e3",
            "did:web:agent.example",
            &echo,
            "did:web:alice.example",
        );
        let other_signed = sign_ed25519_audit_binding(
            &[0xAAu8; 32],
            "ck:session:e3",
            "did:web:agent.example",
            &echo,
            "did:web:alice.example",
        );
        let outcome = verify_ed25519_audit_binding(
            &other_signed.public_key_b64,
            "ck:session:e3",
            "did:web:agent.example",
            &echo,
            "did:web:alice.example",
            &signed.signature_b64,
            &signed.canonical_subject,
        );
        assert_eq!(outcome, Ed25519AuditBindingVerifyOutcome::SignatureMismatch);
    }

    #[test]
    fn ed25519_verify_rejects_malformed_signature() {
        let echo = json!({});
        let signed = sign_ed25519_audit_binding(
            TEST_ED25519_SEED,
            "ck:session:e4",
            "did:web:agent.example",
            &echo,
            "did:web:alice.example",
        );
        let outcome = verify_ed25519_audit_binding(
            &signed.public_key_b64,
            "ck:session:e4",
            "did:web:agent.example",
            &echo,
            "did:web:alice.example",
            "!!!not-base64!!!",
            &signed.canonical_subject,
        );
        assert_eq!(outcome, Ed25519AuditBindingVerifyOutcome::MalformedSignature);
    }

    #[test]
    fn ed25519_verify_rejects_malformed_public_key() {
        let echo = json!({});
        let signed = sign_ed25519_audit_binding(
            TEST_ED25519_SEED,
            "ck:session:e5",
            "did:web:agent.example",
            &echo,
            "did:web:alice.example",
        );
        let outcome = verify_ed25519_audit_binding(
            "AA",
            "ck:session:e5",
            "did:web:agent.example",
            &echo,
            "did:web:alice.example",
            &signed.signature_b64,
            &signed.canonical_subject,
        );
        assert_eq!(outcome, Ed25519AuditBindingVerifyOutcome::MalformedPublicKey);
    }

    fn build_signed_payload(session_id: &str, actor: &str, echo: Value) -> Value {
        let agent_principal_id = "did:web:agent.example";
        let signed = sign_ed25519_audit_binding(
            TEST_ED25519_SEED,
            session_id,
            agent_principal_id,
            &echo,
            actor,
        );
        json!({
            "session_id": session_id,
            "result": { "agent_principal_id": agent_principal_id, "echo": echo },
            "audit_binding": {
                "binding_kind": "ed25519_v1",
                "actor_id": actor,
                "public_key_b64": signed.public_key_b64,
                "signature": signed.signature_b64,
                "canonical_subject": signed.canonical_subject,
            },
        })
    }

    #[test]
    fn verify_by_kind_returns_valid_for_well_formed_ed25519_payload() {
        let payload = build_signed_payload(
            "ck:session:dispatch-ok",
            "did:web:alice.example",
            json!({"op": "ping"}),
        );
        assert_eq!(verify_audit_binding_by_kind(&payload), AuditBindingVerifyOutcome::Valid);
    }

    #[test]
    fn verify_by_kind_returns_absent_when_audit_binding_missing() {
        let payload = json!({
            "session_id": "ck:session:no-binding",
            "result": { "agent_principal_id": "did:web:agent.example", "echo": {} },
        });
        assert_eq!(verify_audit_binding_by_kind(&payload), AuditBindingVerifyOutcome::Absent);
    }

    #[test]
    fn verify_by_kind_returns_unsupported_for_unknown_binding_kind() {
        let payload = json!({
            "session_id": "ck:session:future",
            "result": { "agent_principal_id": "did:web:agent.example", "echo": {} },
            "audit_binding": {
                "binding_kind": "future_scheme_v9",
                "actor_id": "did:web:alice.example",
                "signature": "sig",
                "public_key_b64": "pk",
                "canonical_subject": "subject"
            }
        });
        assert_eq!(verify_audit_binding_by_kind(&payload), AuditBindingVerifyOutcome::Unsupported);
    }

    #[test]
    fn verify_by_kind_returns_unsupported_when_binding_kind_missing() {
        // A binding block without a `binding_kind` field is treated as
        // a future/unknown scheme — same outcome as an explicit
        // unrecognized kind so callers don't have to special-case it.
        let payload = json!({
            "session_id": "ck:session:no-kind",
            "result": { "agent_principal_id": "did:web:agent.example", "echo": {} },
            "audit_binding": {
                "actor_id": "did:web:alice.example",
                "signature": "sig"
            }
        });
        assert_eq!(verify_audit_binding_by_kind(&payload), AuditBindingVerifyOutcome::Unsupported);
    }

    #[test]
    fn verify_by_kind_returns_malformed_for_invalid_signature_encoding() {
        let mut payload = build_signed_payload(
            "ck:session:malformed-sig",
            "did:web:alice.example",
            json!({"op": "ping"}),
        );
        payload["audit_binding"]["signature"] = json!("!!!not-base64!!!");
        assert_eq!(verify_audit_binding_by_kind(&payload), AuditBindingVerifyOutcome::Malformed);
    }

    #[test]
    fn verify_by_kind_returns_subject_mismatch_when_actor_field_differs() {
        let mut payload = build_signed_payload(
            "ck:session:actor-drift",
            "did:web:alice.example",
            json!({"op": "ping"}),
        );
        payload["audit_binding"]["actor_id"] = json!("did:web:carol.example");
        assert_eq!(
            verify_audit_binding_by_kind(&payload),
            AuditBindingVerifyOutcome::SubjectMismatch
        );
    }
}
