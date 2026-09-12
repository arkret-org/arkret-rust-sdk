//! Realm History Recovery Key (RHRK) DID method resolution for offline recovery
//! recipients
//! (`crypto-media/encryption-and-audit.md` §2.10.8, `identity/identity-did.md`
//! §8.3, `models/realm-and-space.md` §2.3.1).
//!
//! Given a recovery recipient reference and the recipient principal's raw DID
//! Document JSON, this module verifies that the named verification method is
//! named by the accepted register/rotate tuple, referenced by `keyAgreement`,
//! and encoded as an X25519 Multikey. Resolution
//! is fail-closed and never falls back to an arbitrary key.

use arkret_canonical::multibase::{decode_multibase_base58btc, decode_multicodec_varint};
use arkret_wire::{DidCoreId, DidUrl};
use serde_json::Value;

/// X25519 public-key multicodec prefix (`0xec 0x01` unsigned-varint), the wire
/// form a `Multikey` `publicKeyMultibase` RHRK key uses for HPKE key agreement.
const MULTICODEC_X25519_PUB: u64 = 0xec;

/// Fail-closed outcome of [`resolve_realm_history_recovery_key`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RealmHistoryRecoveryKeyError {
    /// The accepted tuple's exact `verification_method` cannot be resolved as
    /// an eligible current key-agreement method, or the DID Document /
    /// key material is unparseable, revoked, or malformed.
    Unverified(String),
}

impl RealmHistoryRecoveryKeyError {
    /// Human-readable diagnostic detail.
    pub fn detail(&self) -> &str {
        match self {
            Self::Unverified(detail) => detail,
        }
    }
}

impl std::fmt::Display for RealmHistoryRecoveryKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.detail())
    }
}

impl std::error::Error for RealmHistoryRecoveryKeyError {}

fn unverified(detail: impl Into<String>) -> RealmHistoryRecoveryKeyError {
    RealmHistoryRecoveryKeyError::Unverified(detail.into())
}

/// A verified RHRK public key resolved from a recipient's DID Document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRealmHistoryRecoveryKey {
    /// The recipient stable id (`durability_policy.recovery_recipients[].recipient_id`).
    pub recipient_id: String,
    /// The principal controlling the accepted RHRK key-agreement method.
    pub principal_id: DidCoreId,
    /// The exact verification method id frozen by the accepted RHRK tuple.
    pub verification_method: DidUrl,
    /// Decoded raw 32-byte X25519 HPKE public key the provider seals to.
    pub hpke_public_key: [u8; 32],
}

/// Resolve and verify the offline RHRK HPKE public key for `recipient` from its
/// principal's `did_document` (the raw W3C DID Document JSON, e.g. the
/// raw DID Document value or a freshly resolved document).
///
/// Verification (`identity-did.md` §8.3, `encryption-and-audit.md` §2.10.8),
/// all fail-closed:
///
/// 1. `did_document.id` MUST equal `recipient.principal_id`.
/// 2. The exact VM frozen by the accepted register/rotate tuple MUST appear in `keyAgreement[]` (it
///    is an encryption / key-agreement key).
/// 3. The VM MUST resolve to exactly one `verificationMethod[]` entry whose `controller` equals the
///    recipient principal and whose `type == "Multikey"` carries a `publicKeyMultibase` X25519 key.
/// 4. The `publicKeyMultibase` MUST decode to the X25519-pub multicodec (`0xec 0x01`) + a 32-byte
///    key.
///
/// Any miss returns [`RealmHistoryRecoveryKeyError::Unverified`]
/// (`durability_recovery_recipient_unverified`); the function MUST NOT fall back
/// to any other key. Point-in-time resolution (validating the RHRK active at a
/// historical seal Event's accepted-at) is the caller's responsibility — pass
/// the DID Document resolved as of that instant.
pub fn resolve_realm_history_recovery_key(
    recipient_id: &str,
    principal_id: &DidCoreId,
    verification_method: &DidUrl,
    did_document: &Value,
) -> Result<ResolvedRealmHistoryRecoveryKey, RealmHistoryRecoveryKeyError> {
    let document = did_document
        .as_object()
        .ok_or_else(|| unverified("DID Document is not a JSON object"))?;

    // (1) The document MUST belong to the recipient principal.
    let document_id = document
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| unverified("DID Document missing string `id`"))?;
    if document_id != principal_id.as_str() {
        return Err(unverified(format!(
            "DID Document id {document_id} does not match recipient principal_id {}",
            principal_id.as_str()
        )));
    }

    // (2) The tuple-frozen VM MUST be referenced by keyAgreement (encryption-to).
    let key_agreement_refs = document
        .get("keyAgreement")
        .and_then(Value::as_array)
        .ok_or_else(|| unverified("DID Document has no `keyAgreement` array"))?;
    let in_key_agreement = key_agreement_refs
        .iter()
        .any(|reference| reference.as_str() == Some(verification_method));
    if !in_key_agreement {
        return Err(unverified(format!(
            "RHRK verification method {} is not referenced by keyAgreement",
            verification_method
        )));
    }

    // (3) Resolve the exact VM entry and require a Multikey publicKeyMultibase.
    let verification_methods = document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .ok_or_else(|| unverified("DID Document has no `verificationMethod` array"))?;
    let mut methods = verification_methods
        .iter()
        .filter_map(Value::as_object)
        .filter(|method| method.get("id").and_then(Value::as_str) == Some(verification_method));
    let method = methods.next().ok_or_else(|| {
        unverified(format!(
            "RHRK verification method {} not present in verificationMethod",
            verification_method
        ))
    })?;
    if methods.next().is_some() {
        return Err(unverified(format!(
            "RHRK verification method {} is not unique in verificationMethod",
            verification_method
        )));
    }
    if method.get("controller").and_then(Value::as_str) != Some(principal_id.as_str()) {
        return Err(unverified(format!(
            "RHRK verification method {} is not controlled by {}",
            verification_method, principal_id
        )));
    }
    if method.get("type").and_then(Value::as_str) != Some("Multikey") {
        return Err(unverified(format!(
            "RHRK verification method {} is not a Multikey",
            verification_method
        )));
    }
    let multibase = method
        .get("publicKeyMultibase")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            unverified(format!(
                "RHRK verification method {} has no publicKeyMultibase",
                verification_method
            ))
        })?;

    // (4) Decode the X25519-pub multicodec key.
    let hpke_public_key = decode_x25519_multibase(multibase)?;

    Ok(ResolvedRealmHistoryRecoveryKey {
        recipient_id: recipient_id.to_owned(),
        principal_id: principal_id.clone(),
        verification_method: verification_method.clone(),
        hpke_public_key,
    })
}

/// Decode a `z<base58btc(0xec01 || key)>` multibase string into the raw 32-byte
/// X25519 public key, fail-closed to the RHRK reason code on any malformation.
fn decode_x25519_multibase(multibase: &str) -> Result<[u8; 32], RealmHistoryRecoveryKeyError> {
    let decoded = decode_multibase_base58btc(multibase)
        .map_err(|err| unverified(format!("RHRK publicKeyMultibase decode failed: {err}")))?;
    let (code, header_len) = decode_multicodec_varint(&decoded)
        .ok_or_else(|| unverified("RHRK publicKeyMultibase has a truncated multicodec header"))?;
    if code != MULTICODEC_X25519_PUB {
        return Err(unverified(format!(
            "RHRK publicKeyMultibase multicodec is 0x{code:x}, expected x25519-pub (0xec)"
        )));
    }
    let key = &decoded[header_len..];
    key.try_into().map_err(|_| {
        unverified(format!(
            "RHRK X25519 public key must be 32 bytes, got {}",
            key.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use arkret_canonical::multibase::encode_multibase_base58btc;

    use super::*;

    struct TestRecipient {
        recipient_id: String,
        principal_id: DidCoreId,
        verification_method: DidUrl,
    }

    fn recipient() -> TestRecipient {
        TestRecipient {
            recipient_id: "acme-org-rhrk-1".to_owned(),
            principal_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            verification_method: DidUrl::new(
                "did:webvh:z6mkfixture:acme.example#realm-history-recovery-1",
            )
            .unwrap(),
        }
    }

    fn x25519_multibase(pubkey: &[u8; 32]) -> String {
        let mut bytes = Vec::with_capacity(34);
        bytes.push(0xec);
        bytes.push(0x01);
        bytes.extend_from_slice(pubkey);
        encode_multibase_base58btc(bytes)
    }

    fn did_document(recipient: &TestRecipient, pubkey: &[u8; 32]) -> Value {
        serde_json::json!({
            "id": recipient.principal_id.as_str(),
            "verificationMethod": [
                {
                    "id": recipient.verification_method,
                    "type": "Multikey",
                    "controller": recipient.principal_id.as_str(),
                    "publicKeyMultibase": x25519_multibase(pubkey),
                }
            ],
            "keyAgreement": [recipient.verification_method]
        })
    }

    fn resolve(
        recipient: &TestRecipient,
        document: &Value,
    ) -> Result<ResolvedRealmHistoryRecoveryKey, RealmHistoryRecoveryKeyError> {
        resolve_realm_history_recovery_key(
            &recipient.recipient_id,
            &recipient.principal_id,
            &recipient.verification_method,
            document,
        )
    }

    #[test]
    fn resolves_tuple_frozen_rhrk_method_to_hpke_pubkey() {
        let recipient = recipient();
        let rhrk_pub = [5u8; 32];
        let document = did_document(&recipient, &rhrk_pub);

        let resolved = resolve(&recipient, &document).unwrap();
        assert_eq!(resolved.hpke_public_key, rhrk_pub);
        assert_eq!(resolved.recipient_id, "acme-org-rhrk-1");
        assert_eq!(resolved.verification_method, recipient.verification_method);
    }

    #[test]
    fn service_designation_is_not_required() {
        let recipient = recipient();
        let rhrk_pub = [5u8; 32];
        let mut document = did_document(&recipient, &rhrk_pub);
        document["service"] = serde_json::json!([{"type": "UnrelatedService"}]);
        assert_eq!(
            resolve(&recipient, &document).unwrap().hpke_public_key,
            rhrk_pub
        );
    }

    #[test]
    fn rejects_vm_not_in_key_agreement() {
        let recipient = recipient();
        let rhrk_pub = [5u8; 32];
        let mut document = did_document(&recipient, &rhrk_pub);
        document["keyAgreement"] = serde_json::json!([]);

        let err = resolve(&recipient, &document).unwrap_err();
        assert!(!err.detail().is_empty());
    }

    #[test]
    fn rejects_non_x25519_multicodec_key() {
        let recipient = recipient();
        let mut document = did_document(&recipient, &[5u8; 32]);
        // Ed25519-pub multicodec (0xed 0x01) instead of x25519-pub.
        let mut bytes = vec![0xedu8, 0x01];
        bytes.extend_from_slice(&[0u8; 32]);
        document["verificationMethod"][0]["publicKeyMultibase"] =
            serde_json::json!(encode_multibase_base58btc(bytes));

        let err = resolve(&recipient, &document).unwrap_err();
        assert!(!err.detail().is_empty());
    }

    #[test]
    fn rejects_verification_method_controlled_by_another_principal() {
        let recipient = recipient();
        let mut document = did_document(&recipient, &[5u8; 32]);
        document["verificationMethod"][0]["controller"] =
            serde_json::json!("did:webvh:z6mkfixture:evil.example");

        let err = resolve(&recipient, &document).unwrap_err();
        assert!(err.detail().contains("not controlled by"));
    }

    #[test]
    fn rejects_duplicate_exact_verification_method_entries() {
        let recipient = recipient();
        let mut document = did_document(&recipient, &[5u8; 32]);
        let duplicate = document["verificationMethod"][0].clone();
        document["verificationMethod"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);

        let err = resolve(&recipient, &document).unwrap_err();
        assert!(err.detail().contains("is not unique"));
    }

    #[test]
    fn rejects_document_for_wrong_principal() {
        let recipient = recipient();
        let rhrk_pub = [5u8; 32];
        let mut document = did_document(&recipient, &rhrk_pub);
        document["id"] = serde_json::json!("did:webvh:z6mkfixture:evil.example");

        let err = resolve(&recipient, &document).unwrap_err();
        assert!(!err.detail().is_empty());
    }

    #[test]
    fn shared_rhrk_fixture_runs_through_the_production_resolver() {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/history-key-recovery-fixture.json",
        )
        .unwrap();
        let kat = &fixture["rhrk_registration_rotation_kat"];
        let key_tuple = &kat["events"]["register"]["payload"]["new_key_tuple"];
        let principal_id = DidCoreId::new(
            key_tuple["method_controller_principal_id"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let verification_method =
            DidUrl::new(key_tuple["key_agreement_ref"].as_str().unwrap()).unwrap();
        let document = &kat["did_documents"]["register"];
        let resolved = resolve_realm_history_recovery_key(
            key_tuple["recovery_key_id"].as_str().unwrap(),
            &principal_id,
            &verification_method,
            document,
        )
        .unwrap();
        assert_eq!(
            arkret_wire::base64url::base64url_encode(resolved.hpke_public_key),
            key_tuple["frozen_public_key_b64u"].as_str().unwrap(),
        );
        assert!(
            kat["explicit_non_requirement"]
                .as_str()
                .unwrap()
                .contains("service designation")
        );

        use arkret_state::state_model::{
            CausalRegister, ResolvedCellState, StateModel, StateWrite,
        };
        use arkret_wire::{Event, Hash, ProjectedOp};

        let register_event: Event =
            serde_json::from_value(kat["events"]["register"].clone()).unwrap();
        let rotate_event: Event = serde_json::from_value(kat["events"]["rotate"].clone()).unwrap();
        let register_write = arkret_schema::project_registered_cell_writes(
            &register_event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
        let rotate_write = arkret_schema::project_registered_cell_writes(
            &rotate_event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
        let ProjectedOp::Direct(register_op) = register_write.op else {
            panic!("RHRK register must project a direct causal-register set");
        };
        let ProjectedOp::Direct(rotate_op) = rotate_write.op else {
            panic!("RHRK rotate must project a direct causal-register set");
        };
        // Section 9.3.1.4 deleted the rule that copied this Move's head_eq into
        // `op.from`, so a projected register set carries no predecessor
        // value. The signed whole-value `head_eq` is still on the Event and is
        // still enforced; what changed is that causality no longer rides on the
        // business value.
        assert!(rotate_op.from.is_none());
        assert_eq!(
            rotate_op.value.as_ref(),
            Some(&kat["projected_rotate_op"]["to"])
        );

        let register_move_id =
            Hash::new(register_event.proofs[0].event_digest.as_str().to_owned()).unwrap();
        let rotate_move_id =
            Hash::new(rotate_event.proofs[0].event_digest.as_str().to_owned()).unwrap();
        // The rotate's signed precondition covered the register write, so
        // acceptance derives that identity as what it supersedes and the cell
        // settles on the rotated tuple.
        let writes = vec![
            StateWrite::new(register_move_id.clone(), register_op.clone()),
            StateWrite::superseding(
                rotate_move_id.clone(),
                rotate_op,
                vec![register_move_id.clone()],
            ),
        ];
        assert_eq!(
            CausalRegister
                .resolve(&register_write.cell_id, &writes)
                .unwrap()
                .settled_value(),
            Some(&kat["projected_rotate_op"]["to"])
        );

        // A rotate that superseded nothing is concurrent with the register
        // write, not a replacement of it, so the cell is in conflict. This is
        // where "stale" lives now: dropping the signed `head_eq` no longer
        // changes the projected op at all — §9.3.1.3 item 3 rejects the write at
        // acceptance by comparing head identities, and the resolution below is the
        // defensive backstop for an op that somehow reached the log anyway.
        let mut stale_event = rotate_event;
        stale_event.preconditions.clear();
        let stale_write = arkret_schema::project_registered_cell_writes(
            &stale_event,
            arkret_canonical::DigestSuite::Sha256,
        )
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
        let ProjectedOp::Direct(stale_op) = stale_write.op else {
            panic!("RHRK mutation must remain a direct causal-register set");
        };
        assert!(stale_op.from.is_none());
        assert!(matches!(
            CausalRegister
                .resolve(
                    &register_write.cell_id,
                    &[
                        StateWrite::new(register_move_id, register_op),
                        StateWrite::new(rotate_move_id, stale_op),
                    ],
                )
                .unwrap(),
            ResolvedCellState::Bottom(_)
        ));
    }
}
