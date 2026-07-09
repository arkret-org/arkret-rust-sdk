//! Realm Recovery Key (RRK) durable history sealing — provider-initiated
//! `ck.realm_key.share` to offline recovery recipients
//! (`crypto-media/encryption-and-audit.md` §2.10.8, `identity/identity-did.md`
//! §8.3, `models/realm-and-space.md` §2.3.1).
//!
//! Two responsibilities live here:
//!
//! 1. [`resolve_realm_history_recovery_key`] — given a [`RealmRecoveryRecipient`] and the recipient
//!    principal's raw DID Document JSON, verify the recipient's `verification_method` is designated
//!    by an active `CokretRealmHistoryRecoveryKey` service entry (`serviceEndpoint`
//!    `verificationMethod` points at it, `domain == "mls_history"`), that the VM is referenced by
//!    `keyAgreement`, and return the decoded raw X25519 RRK public key. Any resolution /
//!    designation failure is fail-closed with
//!    [`durability_recovery_recipient_unverified`](RealmHistoryRecoveryKeyError::Unverified) — it
//!    MUST NOT fall back to an arbitrary key.
//! 2. [`seal_history_secrets_to_recovery_recipient`] — HPKE-seal a retained `{(epoch,
//!    history_secret)}` set to that RRK public key and assemble the provider-initiated
//!    [`RealmKeySharePayload`]. Reuses the same HPKE seal primitive
//!    (`ck.hpke_x25519_aead_chacha20poly1305.v1`) as the member device key-share path
//!    ([`crate::secret_share`]).
//!
//! Unlike the §2.10.4 join-time request/response path, RRK sealing is
//! provider-initiated: the recipient never claims; the provider seals each epoch
//! eagerly after the advancing commit is accepted and before GC of the
//! `history_secret` (§2.10.8 eager timing). The recovery recipient is an offline
//! HPKE public key, NOT an MLS member or member device.

use arkret_core::multibase::{decode_multibase_base58btc, decode_multicodec_varint};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::secret_share::seal_history_secret_to_device_pubkey;
use crate::{
    Did, HistoryVisibilityValue, RealmKeyScope, RealmKeyShareClass, RealmKeySharePayload,
    RealmRecoveryRecipient, Result,
};

/// DID service entry `type` designating an offline RRK (`identity-did.md` §8.3).
pub const RRK_SERVICE_TYPE: &str = "CokretRealmHistoryRecoveryKey";
/// `serviceEndpoint.domain` an RRK service entry MUST carry (history-recovery
/// domain, separate from `did_recovery`).
pub const RRK_SERVICE_DOMAIN: &str = "mls_history";
/// Reason code (`error-code-registry.json`) surfaced when a recovery recipient's
/// verification method cannot be resolved to an active RRK service entry.
pub const REASON_DURABILITY_RECOVERY_RECIPIENT_UNVERIFIED: &str =
    "durability_recovery_recipient_unverified";

/// X25519 public-key multicodec prefix (`0xec 0x01` unsigned-varint), the wire
/// form a `Multikey` `publicKeyMultibase` RRK key uses for HPKE key agreement.
const MULTICODEC_X25519_PUB: u64 = 0xec;

/// Fail-closed outcome of [`resolve_realm_history_recovery_key`]. Every variant
/// maps to the spec reason code
/// [`REASON_DURABILITY_RECOVERY_RECIPIENT_UNVERIFIED`]; the inner string is a
/// human-readable diagnostic only (never relax the fail-closed contract).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RealmHistoryRecoveryKeyError {
    /// The recipient's `verification_method` is not designated by an active
    /// `CokretRealmHistoryRecoveryKey` service entry, or the DID Document /
    /// key material is unparseable, revoked, or malformed.
    Unverified(String),
}

impl RealmHistoryRecoveryKeyError {
    /// Spec reason code for this failure (always
    /// [`REASON_DURABILITY_RECOVERY_RECIPIENT_UNVERIFIED`]).
    pub fn reason_code(&self) -> &'static str {
        REASON_DURABILITY_RECOVERY_RECIPIENT_UNVERIFIED
    }

    /// Human-readable diagnostic detail.
    pub fn detail(&self) -> &str {
        match self {
            Self::Unverified(detail) => detail,
        }
    }
}

impl std::fmt::Display for RealmHistoryRecoveryKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {}",
            REASON_DURABILITY_RECOVERY_RECIPIENT_UNVERIFIED,
            self.detail()
        )
    }
}

impl std::error::Error for RealmHistoryRecoveryKeyError {}

fn unverified(detail: impl Into<String>) -> RealmHistoryRecoveryKeyError {
    RealmHistoryRecoveryKeyError::Unverified(detail.into())
}

/// A verified RRK public key resolved from a recipient's DID Document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRealmHistoryRecoveryKey {
    /// The recipient stable id (`durability_policy.recovery_recipients[].recipient_id`).
    pub recipient_id: String,
    /// The principal that published the RRK service entry.
    pub principal_id: Did,
    /// The verification method id the RRK service entry designates.
    pub verification_method: String,
    /// Decoded raw 32-byte X25519 HPKE public key the provider seals to.
    pub hpke_public_key: [u8; 32],
}

/// Resolve and verify the offline RRK HPKE public key for `recipient` from its
/// principal's `did_document` (the raw W3C DID Document JSON, e.g. the
/// `DidDocumentRef.document` value or a freshly resolved document).
///
/// Verification (`identity-did.md` §8.3, `encryption-and-audit.md` §2.10.8),
/// all fail-closed:
///
/// 1. `did_document.id` MUST equal `recipient.principal_id`.
/// 2. Some entry in `service[]` MUST have `type == "CokretRealmHistoryRecoveryKey"`,
///    `serviceEndpoint.verificationMethod == recipient.verification_method`, and
///    `serviceEndpoint.domain == "mls_history"`.
/// 3. The designated VM MUST appear in `keyAgreement[]` (it is an encryption / key-agreement key)
///    and MUST resolve to a `verificationMethod[]` entry of `type == "Multikey"` carrying a
///    `publicKeyMultibase` X25519 key.
/// 4. The `publicKeyMultibase` MUST decode to the X25519-pub multicodec (`0xec 0x01`) + a 32-byte
///    key.
///
/// Any miss returns [`RealmHistoryRecoveryKeyError::Unverified`]
/// (`durability_recovery_recipient_unverified`); the function MUST NOT fall back
/// to any other key. Point-in-time resolution (validating the RRK active at a
/// historical seal Event's accepted-at) is the caller's responsibility — pass
/// the DID Document resolved as of that instant.
pub fn resolve_realm_history_recovery_key(
    recipient: &RealmRecoveryRecipient,
    did_document: &Value,
) -> std::result::Result<ResolvedRealmHistoryRecoveryKey, RealmHistoryRecoveryKeyError> {
    let document = did_document
        .as_object()
        .ok_or_else(|| unverified("DID Document is not a JSON object"))?;

    // (1) The document MUST belong to the recipient principal.
    let document_id = document
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| unverified("DID Document missing string `id`"))?;
    if document_id != recipient.principal_id.as_str() {
        return Err(unverified(format!(
            "DID Document id {document_id} does not match recipient principal_id {}",
            recipient.principal_id.as_str()
        )));
    }

    // (2) An active CokretRealmHistoryRecoveryKey service entry MUST designate
    // exactly recipient.verification_method with domain == mls_history.
    let services = document
        .get("service")
        .and_then(Value::as_array)
        .ok_or_else(|| unverified("DID Document has no `service` array"))?;
    let designates = services.iter().any(|entry| {
        let Some(entry) = entry.as_object() else {
            return false;
        };
        if entry.get("type").and_then(Value::as_str) != Some(RRK_SERVICE_TYPE) {
            return false;
        }
        let Some(endpoint) = entry.get("serviceEndpoint").and_then(Value::as_object) else {
            return false;
        };
        endpoint.get("verificationMethod").and_then(Value::as_str)
            == Some(recipient.verification_method.as_str())
            && endpoint.get("domain").and_then(Value::as_str) == Some(RRK_SERVICE_DOMAIN)
    });
    if !designates {
        return Err(unverified(format!(
            "no active CokretRealmHistoryRecoveryKey service entry designates {} with domain {RRK_SERVICE_DOMAIN}",
            recipient.verification_method
        )));
    }

    // (3a) The designated VM MUST be referenced by keyAgreement (encryption-to).
    let key_agreement_refs = document
        .get("keyAgreement")
        .and_then(Value::as_array)
        .ok_or_else(|| unverified("DID Document has no `keyAgreement` array"))?;
    let in_key_agreement = key_agreement_refs
        .iter()
        .any(|reference| reference.as_str() == Some(recipient.verification_method.as_str()));
    if !in_key_agreement {
        return Err(unverified(format!(
            "RRK verification method {} is not referenced by keyAgreement",
            recipient.verification_method
        )));
    }

    // (3b) Resolve the VM entry and require a Multikey publicKeyMultibase.
    let verification_methods = document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .ok_or_else(|| unverified("DID Document has no `verificationMethod` array"))?;
    let method = verification_methods
        .iter()
        .filter_map(Value::as_object)
        .find(|method| {
            method.get("id").and_then(Value::as_str) == Some(recipient.verification_method.as_str())
        })
        .ok_or_else(|| {
            unverified(format!(
                "RRK verification method {} not present in verificationMethod",
                recipient.verification_method
            ))
        })?;
    if method.get("type").and_then(Value::as_str) != Some("Multikey") {
        return Err(unverified(format!(
            "RRK verification method {} is not a Multikey",
            recipient.verification_method
        )));
    }
    let multibase = method
        .get("publicKeyMultibase")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            unverified(format!(
                "RRK verification method {} has no publicKeyMultibase",
                recipient.verification_method
            ))
        })?;

    // (4) Decode the X25519-pub multicodec key.
    let hpke_public_key = decode_x25519_multibase(multibase)?;

    Ok(ResolvedRealmHistoryRecoveryKey {
        recipient_id: recipient.recipient_id.clone(),
        principal_id: recipient.principal_id.clone(),
        verification_method: recipient.verification_method.clone(),
        hpke_public_key,
    })
}

/// Decode a `z<base58btc(0xec01 || key)>` multibase string into the raw 32-byte
/// X25519 public key, fail-closed to the RRK reason code on any malformation.
fn decode_x25519_multibase(
    multibase: &str,
) -> std::result::Result<[u8; 32], RealmHistoryRecoveryKeyError> {
    let decoded = decode_multibase_base58btc(multibase)
        .map_err(|err| unverified(format!("RRK publicKeyMultibase decode failed: {err}")))?;
    let (code, header_len) = decode_multicodec_varint(&decoded)
        .ok_or_else(|| unverified("RRK publicKeyMultibase has a truncated multicodec header"))?;
    if code != MULTICODEC_X25519_PUB {
        return Err(unverified(format!(
            "RRK publicKeyMultibase multicodec is 0x{code:x}, expected x25519-pub (0xec)"
        )));
    }
    let key = &decoded[header_len..];
    key.try_into().map_err(|_| {
        unverified(format!(
            "RRK X25519 public key must be 32 bytes, got {}",
            key.len()
        ))
    })
}

/// HPKE-seal a retained per-epoch `history_secrets` set to a resolved RRK and
/// assemble the provider-initiated `ck.realm_key.share` payload
/// (`encryption-and-audit.md` §2.10.8 sealing obligation).
///
/// `history_secrets` is the `{(epoch, history_secret[epoch])}` set covering the
/// `key_scope.from_epoch..=to_epoch` range (e.g.
/// [`crate::mls::CokretMlsGroup::export_history_secret_range`]). The recovery
/// recipient is offline, so unlike the member key-share path there is no
/// `recipient_device_id` device queue: the recipient principal is the RRK
/// holder and `recipient_device_id` carries the recipient's stable
/// `recipient_id` (the share is addressed to the RRK, not a member device).
///
/// `sender_device_id` / `sender_device_signature` are supplied by the caller —
/// the committing member's device authors the share (§2.10.3 author auth via the
/// outer Event signature; the `sender_device_signature` over
/// [`RealmKeySharePayload::sender_signing_input`] is computed by the caller's
/// signing layer and threaded in here).
///
/// Returns the durable `RealmKeySharePayload` with `ciphertext` populated; the
/// caller wraps it in a `ck.realm_key.share` Event and submits it.
#[allow(clippy::too_many_arguments)]
pub fn seal_history_secrets_to_recovery_recipient(
    recovery_key: &ResolvedRealmHistoryRecoveryKey,
    history_secrets: &[(u64, Vec<u8>)],
    realm_id: &str,
    key_scope: RealmKeyScope,
    sender_device_id: impl Into<String>,
    sender_device_signature: Value,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<RealmKeySharePayload> {
    if history_secrets.is_empty() {
        return Err(crate::Error::Protocol(
            "RRK seal refusing an empty history_secret set".to_owned(),
        ));
    }
    // The realm_id is mixed into the scope's effective_scope by the caller; we
    // require it here only to bind the seal diagnostically and to reject a scope
    // that names a different Realm.
    if let Some(scope_realm) = key_scope
        .effective_scope
        .get("realm_id")
        .and_then(Value::as_str)
        && scope_realm != realm_id
    {
        return Err(crate::Error::Protocol(format!(
            "RRK seal realm_id {realm_id} does not match key_scope.effective_scope.realm_id {scope_realm}"
        )));
    }

    let ciphertext =
        seal_history_secret_to_device_pubkey(&recovery_key.hpke_public_key, history_secrets)?;

    Ok(RealmKeySharePayload {
        // The RRK is offline and not a member device; the durable share is
        // addressed by verification_method + recovery_recipient_id, never a
        // device id (event-payload.schema.json share_class discriminator).
        share_class: RealmKeyShareClass::RealmRecoveryKey,
        recipient_principal_id: recovery_key.principal_id.clone(),
        recipient_device_id: None,
        recipient_verification_method: Some(recovery_key.verification_method.clone()),
        recovery_recipient_id: Some(recovery_key.recipient_id.clone()),
        sender_device_id: sender_device_id.into(),
        sender_device_signature,
        key_scope,
        ciphertext: Some(ciphertext),
        encrypted_key_ref: None,
        aad_digest: None,
        expires_at,
        created_at,
    })
}

/// Build the durable [`RealmKeyScope`] for an RRK seal covering
/// `from_epoch..=to_epoch` of `realm_id`. `policy_digest` binds the effective
/// history-sharing policy at seal time; `history_visibility` is the effective
/// value. Provider-initiated RRK seals always name an explicit epoch range.
pub fn rrk_key_scope(
    realm_id: &str,
    from_epoch: u64,
    to_epoch: u64,
    policy_digest: Value,
    history_visibility: Option<HistoryVisibilityValue>,
) -> RealmKeyScope {
    RealmKeyScope {
        effective_scope: serde_json::json!({ "kind": "realm", "realm_id": realm_id }),
        policy_digest,
        membership_frontier_digest: None,
        from_epoch: Some(from_epoch),
        to_epoch: Some(to_epoch),
        history_visibility,
    }
}

#[cfg(test)]
mod tests {
    use arkret_core::multibase::encode_multibase_base58btc;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    use super::*;
    use crate::secret_share::open_history_secret_with_device_privkey;

    fn recipient() -> RealmRecoveryRecipient {
        RealmRecoveryRecipient {
            recipient_id: "acme-org-rrk-1".to_owned(),
            principal_id: Did::new("did:webvh:z6mkfixture:acme.example").unwrap(),
            verification_method: "did:webvh:z6mkfixture:acme.example#realm-history-recovery-1"
                .to_owned(),
            controller_organization: None,
        }
    }

    fn x25519_multibase(pubkey: &[u8; 32]) -> String {
        let mut bytes = Vec::with_capacity(34);
        bytes.push(0xec);
        bytes.push(0x01);
        bytes.extend_from_slice(pubkey);
        encode_multibase_base58btc(bytes)
    }

    fn did_document(recipient: &RealmRecoveryRecipient, pubkey: &[u8; 32]) -> Value {
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
            "keyAgreement": [recipient.verification_method],
            "service": [
                {
                    "id": "did:webvh:z6mkfixture:acme.example#realm-history-recovery",
                    "type": RRK_SERVICE_TYPE,
                    "serviceEndpoint": {
                        "verificationMethod": recipient.verification_method,
                        "kem": "hpke",
                        "domain": RRK_SERVICE_DOMAIN,
                    }
                }
            ]
        })
    }

    #[test]
    fn resolves_active_rrk_service_entry_to_hpke_pubkey() {
        let recipient = recipient();
        let rrk_priv = StaticSecret::from([5u8; 32]);
        let rrk_pub = *X25519PublicKey::from(&rrk_priv).as_bytes();
        let document = did_document(&recipient, &rrk_pub);

        let resolved = resolve_realm_history_recovery_key(&recipient, &document).unwrap();
        assert_eq!(resolved.hpke_public_key, rrk_pub);
        assert_eq!(resolved.recipient_id, "acme-org-rrk-1");
        assert_eq!(resolved.verification_method, recipient.verification_method);
    }

    #[test]
    fn rejects_when_service_entry_absent() {
        let recipient = recipient();
        let rrk_pub = *X25519PublicKey::from(&StaticSecret::from([5u8; 32])).as_bytes();
        let mut document = did_document(&recipient, &rrk_pub);
        document["service"] = serde_json::json!([]);

        let err = resolve_realm_history_recovery_key(&recipient, &document).unwrap_err();
        assert_eq!(
            err.reason_code(),
            REASON_DURABILITY_RECOVERY_RECIPIENT_UNVERIFIED
        );
    }

    #[test]
    fn rejects_wrong_domain() {
        let recipient = recipient();
        let rrk_pub = *X25519PublicKey::from(&StaticSecret::from([5u8; 32])).as_bytes();
        let mut document = did_document(&recipient, &rrk_pub);
        document["service"][0]["serviceEndpoint"]["domain"] = serde_json::json!("did_recovery");

        let err = resolve_realm_history_recovery_key(&recipient, &document).unwrap_err();
        assert_eq!(
            err.reason_code(),
            REASON_DURABILITY_RECOVERY_RECIPIENT_UNVERIFIED
        );
    }

    #[test]
    fn rejects_vm_not_in_key_agreement() {
        let recipient = recipient();
        let rrk_pub = *X25519PublicKey::from(&StaticSecret::from([5u8; 32])).as_bytes();
        let mut document = did_document(&recipient, &rrk_pub);
        document["keyAgreement"] = serde_json::json!([]);

        let err = resolve_realm_history_recovery_key(&recipient, &document).unwrap_err();
        assert_eq!(
            err.reason_code(),
            REASON_DURABILITY_RECOVERY_RECIPIENT_UNVERIFIED
        );
    }

    #[test]
    fn rejects_service_designating_a_different_vm() {
        let recipient = recipient();
        let rrk_pub = *X25519PublicKey::from(&StaticSecret::from([5u8; 32])).as_bytes();
        let mut document = did_document(&recipient, &rrk_pub);
        // Service points at a different VM than the recipient names — MUST NOT
        // fall back to whatever key the document happens to carry.
        document["service"][0]["serviceEndpoint"]["verificationMethod"] =
            serde_json::json!("did:webvh:z6mkfixture:acme.example#some-other-key");

        let err = resolve_realm_history_recovery_key(&recipient, &document).unwrap_err();
        assert_eq!(
            err.reason_code(),
            REASON_DURABILITY_RECOVERY_RECIPIENT_UNVERIFIED
        );
    }

    #[test]
    fn rejects_non_x25519_multicodec_key() {
        let recipient = recipient();
        let mut document = did_document(
            &recipient,
            X25519PublicKey::from(&StaticSecret::from([5u8; 32])).as_bytes(),
        );
        // Ed25519-pub multicodec (0xed 0x01) instead of x25519-pub.
        let mut bytes = vec![0xedu8, 0x01];
        bytes.extend_from_slice(&[0u8; 32]);
        document["verificationMethod"][0]["publicKeyMultibase"] =
            serde_json::json!(encode_multibase_base58btc(bytes));

        let err = resolve_realm_history_recovery_key(&recipient, &document).unwrap_err();
        assert_eq!(
            err.reason_code(),
            REASON_DURABILITY_RECOVERY_RECIPIENT_UNVERIFIED
        );
    }

    #[test]
    fn rejects_document_for_wrong_principal() {
        let recipient = recipient();
        let rrk_pub = *X25519PublicKey::from(&StaticSecret::from([5u8; 32])).as_bytes();
        let mut document = did_document(&recipient, &rrk_pub);
        document["id"] = serde_json::json!("did:webvh:z6mkfixture:evil.example");

        let err = resolve_realm_history_recovery_key(&recipient, &document).unwrap_err();
        assert_eq!(
            err.reason_code(),
            REASON_DURABILITY_RECOVERY_RECIPIENT_UNVERIFIED
        );
    }

    #[test]
    fn seal_round_trips_to_rrk_private_key() {
        let recipient = recipient();
        let rrk_priv = StaticSecret::from([9u8; 32]);
        let rrk_pub = *X25519PublicKey::from(&rrk_priv).as_bytes();
        let document = did_document(&recipient, &rrk_pub);
        let resolved = resolve_realm_history_recovery_key(&recipient, &document).unwrap();

        let realm_id = "ak:realm:01904100-0000-7000-8000-e2eeae0d0001";
        let secrets: Vec<(u64, Vec<u8>)> = vec![(4, vec![0x11; 32]), (5, vec![0x22; 32])];
        let scope = rrk_key_scope(
            realm_id,
            4,
            5,
            serde_json::json!("sha256:policy"),
            Some(HistoryVisibilityValue::Shared),
        );

        let payload = seal_history_secrets_to_recovery_recipient(
            &resolved,
            &secrets,
            realm_id,
            scope,
            "ak:device:01904100-0000-7000-8000-00000000ae01",
            serde_json::json!("base64url-sender-sig"),
            Utc::now(),
            None,
        )
        .unwrap();

        assert_eq!(payload.recipient_principal_id, recipient.principal_id);
        assert_eq!(payload.recipient_device_id, None);
        assert_eq!(
            payload.recovery_recipient_id.as_deref(),
            Some("acme-org-rrk-1")
        );
        assert_eq!(payload.key_scope.from_epoch, Some(4));
        assert_eq!(payload.key_scope.to_epoch, Some(5));

        // The RRK holder unseals with its private key and recovers every epoch
        // secret in the range.
        let opened = open_history_secret_with_device_privkey(
            rrk_priv.to_bytes().as_slice(),
            payload.ciphertext.as_ref().unwrap(),
        )
        .unwrap();
        assert_eq!(opened, secrets);
    }

    #[test]
    fn seal_rejects_empty_history_set() {
        let recipient = recipient();
        let rrk_pub = *X25519PublicKey::from(&StaticSecret::from([9u8; 32])).as_bytes();
        let resolved =
            resolve_realm_history_recovery_key(&recipient, &did_document(&recipient, &rrk_pub))
                .unwrap();
        let realm_id = "ak:realm:01904100-0000-7000-8000-e2eeae0d0001";
        let scope = rrk_key_scope(realm_id, 4, 4, serde_json::json!("sha256:policy"), None);
        let err = seal_history_secrets_to_recovery_recipient(
            &resolved,
            &[],
            realm_id,
            scope,
            "ak:device:01904100-0000-7000-8000-00000000ae01",
            serde_json::json!("sig"),
            Utc::now(),
            None,
        );
        assert!(err.is_err());
    }
}
