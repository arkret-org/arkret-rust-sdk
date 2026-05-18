//! Production typed device-message API per `crypto-media/device-lifecycle.md`.
//!
//! Production-shape `DeviceMessage` struct + builder + signer-aware
//! `verify()` against the SDK [`contrix_core::MoveSigner`] trait, built
//! on top of [`crate::devices::DeviceMessageEnvelope`].
//!
//! Wire shape mirrors the spec contract — `recipient`, `sender`,
//! `message_type`, `body`, `hlc`, `sig` — with canonical bytes covering
//! every load-bearing field. Signatures are detached JWS strings
//! produced by [`MoveSigner::sign_payload`] over canonical JSON bytes
//! that exclude only the `sig` field itself.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{DeviceId, Did, Error, Hlc, MoveSignature, MoveSigner, Result, canonical};

/// Canonical signed device message envelope shipped over the
/// `cx.device.message.v1` device-message transport.
///
/// `sig` is a detached JWS over canonical-JSON bytes covering
/// `recipient`, `sender`, `message_type`, `body` and `hlc` — the `sig`
/// field itself is excluded so the bytes are stable across the
/// produce-then-sign step.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceMessage {
    /// Receiving principal (the user the message is delivered to).
    pub recipient: Did,
    /// Receiving device, when the message targets a single device.
    /// `None` means "broadcast to all devices for this principal".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_device_id: Option<DeviceId>,
    /// Sending principal.
    pub sender: Did,
    /// Sending device.
    pub sender_device_id: DeviceId,
    /// Spec event-kind string, e.g. `cx.keys.room_key` or
    /// `cx.key.verification.start`.
    pub message_type: String,
    /// Encrypted-or-plain body payload.
    pub body: Value,
    /// Hybrid logical clock at the time of send.
    pub hlc: Hlc,
    /// Detached-JWS signature over canonical bytes.
    pub sig: MoveSignature,
}

/// Body view used for canonical-bytes derivation (excludes `sig`).
#[derive(Serialize)]
struct DeviceMessageBody<'a> {
    recipient: &'a Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient_device_id: &'a Option<DeviceId>,
    sender: &'a Did,
    sender_device_id: &'a DeviceId,
    message_type: &'a str,
    body: &'a Value,
    hlc: &'a Hlc,
}

impl DeviceMessage {
    /// Compute canonical-JSON bytes covering every field except `sig`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let view = DeviceMessageBody {
            recipient: &self.recipient,
            recipient_device_id: &self.recipient_device_id,
            sender: &self.sender,
            sender_device_id: &self.sender_device_id,
            message_type: self.message_type.as_str(),
            body: &self.body,
            hlc: &self.hlc,
        };
        canonical::canonical_json_bytes(&view)
    }

    /// Verify the detached JWS signature against the supplied signer's
    /// public verification material.
    ///
    /// The check is intentionally narrow: it confirms the sig was produced
    /// by the same keypair the signer would use *now* by re-signing the
    /// canonical bytes and comparing the JWS / verification method. Bench
    /// scenarios that need offline verification (no live signer) should
    /// instead recompute canonical bytes and check `sig.payload_hash`
    /// against the canonical SHA-256.
    pub fn verify<S: MoveSigner + ?Sized>(&self, signer: &S) -> Result<()> {
        if signer.signer_did() != &self.sender {
            return Err(Error::Protocol(
                "device message sender does not match signer DID".to_owned(),
            ));
        }
        if signer.verification_method_id() != self.sig.verification_method {
            return Err(Error::Protocol(
                "device message sig verification_method mismatch".to_owned(),
            ));
        }
        let bytes = self.canonical_bytes()?;
        let expected = signer.sign_payload(&bytes)?;
        if expected.alg != self.sig.alg {
            return Err(Error::Protocol("device message sig alg mismatch".to_owned()));
        }
        if expected.payload_hash != self.sig.payload_hash {
            return Err(Error::Protocol("device message sig payload_hash mismatch".to_owned()));
        }
        if expected.jws != self.sig.jws {
            return Err(Error::Protocol("device message sig jws mismatch".to_owned()));
        }
        Ok(())
    }

    /// Verify only the `payload_hash` against canonical bytes — useful
    /// when no live signer is available but the producer's signature
    /// algorithm is known to be deterministic over canonical bytes.
    pub fn verify_payload_hash(&self) -> Result<()> {
        let bytes = self.canonical_bytes()?;
        let actual = canonical::sha256_digest(&bytes);
        if actual != self.sig.payload_hash.as_str() {
            return Err(Error::Protocol(
                "device message canonical hash does not match sig.payload_hash".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Production builder that produces a fully-signed [`DeviceMessage`].
///
/// All required fields must be set before [`Self::sign`]; missing fields
/// surface as `Error::Protocol` with a clear message rather than a panic.
#[derive(Default, Debug)]
pub struct DeviceMessageBuilder {
    recipient: Option<Did>,
    recipient_device_id: Option<DeviceId>,
    sender: Option<Did>,
    sender_device_id: Option<DeviceId>,
    message_type: Option<String>,
    body: Option<Value>,
    hlc: Option<Hlc>,
}

impl DeviceMessageBuilder {
    /// New empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the recipient principal DID.
    pub fn recipient(mut self, did: Did) -> Self {
        self.recipient = Some(did);
        self
    }

    /// Set a specific recipient device (omit for principal-wide broadcast).
    pub fn recipient_device(mut self, device_id: DeviceId) -> Self {
        self.recipient_device_id = Some(device_id);
        self
    }

    /// Set the sender principal DID.
    pub fn sender(mut self, did: Did) -> Self {
        self.sender = Some(did);
        self
    }

    /// Set the sender device (must match an active device of the sender).
    pub fn sender_device(mut self, device_id: DeviceId) -> Self {
        self.sender_device_id = Some(device_id);
        self
    }

    /// Set the spec event-kind string for this message.
    pub fn message_type(mut self, kind: impl Into<String>) -> Self {
        self.message_type = Some(kind.into());
        self
    }

    /// Set the message body.
    pub fn body(mut self, body: Value) -> Self {
        self.body = Some(body);
        self
    }

    /// Set the HLC at send time.
    pub fn hlc(mut self, hlc: Hlc) -> Self {
        self.hlc = Some(hlc);
        self
    }

    /// Build canonical bytes + sign with the supplied signer, returning
    /// a fully-formed [`DeviceMessage`].
    ///
    /// Returns `Err` when:
    /// - any required field is missing,
    /// - the supplied signer's DID does not match `sender`, or
    /// - canonical-bytes serialization or signing fails.
    pub fn sign<S: MoveSigner + ?Sized>(self, signer: &S) -> Result<DeviceMessage> {
        let recipient = self.recipient.ok_or_else(|| {
            Error::Protocol("device message builder missing recipient".to_owned())
        })?;
        let sender = self
            .sender
            .ok_or_else(|| Error::Protocol("device message builder missing sender".to_owned()))?;
        let sender_device_id = self.sender_device_id.ok_or_else(|| {
            Error::Protocol("device message builder missing sender_device_id".to_owned())
        })?;
        let message_type = self.message_type.ok_or_else(|| {
            Error::Protocol("device message builder missing message_type".to_owned())
        })?;
        let body = self
            .body
            .ok_or_else(|| Error::Protocol("device message builder missing body".to_owned()))?;
        let hlc = self
            .hlc
            .ok_or_else(|| Error::Protocol("device message builder missing hlc".to_owned()))?;
        if message_type.trim().is_empty() {
            return Err(Error::Protocol(
                "device message message_type must not be empty".to_owned(),
            ));
        }
        if signer.signer_did() != &sender {
            return Err(Error::Protocol(
                "device message sender does not match signer DID".to_owned(),
            ));
        }

        let view = DeviceMessageBody {
            recipient: &recipient,
            recipient_device_id: &self.recipient_device_id,
            sender: &sender,
            sender_device_id: &sender_device_id,
            message_type: message_type.as_str(),
            body: &body,
            hlc: &hlc,
        };
        let bytes = canonical::canonical_json_bytes(&view)?;
        let sig = signer.sign_payload(&bytes)?;

        Ok(DeviceMessage {
            recipient,
            recipient_device_id: self.recipient_device_id,
            sender,
            sender_device_id,
            message_type,
            body,
            hlc,
            sig,
        })
    }
}

/// Cleartext receipt scaffolded over a successfully-decrypted device
/// message — used by clients to thread an inbound delivery into the
/// account-data ack pipeline. The `received_at` is set by the receiver,
/// not by the wire.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DeviceMessageReceipt {
    pub message: DeviceMessage,
    pub received_at: DateTime<Utc>,
}

impl DeviceMessageReceipt {
    /// Wrap a verified [`DeviceMessage`] with a fresh receive timestamp.
    pub fn now(message: DeviceMessage) -> Self {
        Self { message, received_at: Utc::now() }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;
    use crate::{DeviceId, Did, Hash, Hlc, MoveSignature, MoveSigner, UnsignedMove};

    /// Deterministic test signer mirroring `contrix-core::signer::StubSigner`.
    /// Local to this module so tests stay self-contained without pulling in
    /// the optional `signer` feature.
    struct TestSigner {
        did: Did,
        kid: String,
    }

    impl MoveSigner for TestSigner {
        fn sign_move(&self, _unsigned: &UnsignedMove) -> Result<contrix_core::Move> {
            // Not exercised by these tests — the production builder calls
            // `sign_payload` directly.
            unimplemented!("sign_move not used by device-message tests")
        }

        fn signer_did(&self) -> &Did {
            &self.did
        }

        fn verification_method_id(&self) -> &str {
            &self.kid
        }

        fn sign_payload(&self, canonical_bytes: &[u8]) -> Result<MoveSignature> {
            let payload_hash = Hash::new(canonical::sha256_digest(canonical_bytes)).unwrap();
            Ok(MoveSignature {
                alg: "EdDSA".to_owned(),
                verification_method: self.kid.clone(),
                payload_hash,
                created_at: Utc.with_ymd_and_hms(2026, 5, 9, 0, 0, 0).unwrap(),
                jws: "AAAA.BBBB.CCCC".to_owned(),
            })
        }
    }

    fn signer(name: &str) -> TestSigner {
        TestSigner {
            did: Did::new(format!("did:web:{name}.example")).unwrap(),
            kid: format!("did:web:{name}.example#k1"),
        }
    }

    fn hlc() -> Hlc {
        Hlc::new("01970e589d21-00000001-a13f9c2e").unwrap()
    }

    #[test]
    fn builder_signs_and_verifies_round_trip() {
        let alice = signer("alice");
        let msg = DeviceMessageBuilder::new()
            .sender(alice.signer_did().clone())
            .sender_device(DeviceId::new("cx:device:01904100-0000-7000-8000-00000000000a").unwrap())
            .recipient(Did::new("did:web:bob.example").unwrap())
            .recipient_device(
                DeviceId::new("cx:device:01904100-0000-7000-8000-00000000000b").unwrap(),
            )
            .message_type("cx.keys.room_key")
            .body(json!({"session": "abc"}))
            .hlc(hlc())
            .sign(&alice)
            .unwrap();

        msg.verify(&alice).unwrap();
        msg.verify_payload_hash().unwrap();
    }

    #[test]
    fn builder_rejects_sender_signer_mismatch() {
        let alice = signer("alice");
        let bob = signer("bob");
        let err = DeviceMessageBuilder::new()
            .sender(bob.signer_did().clone())
            .sender_device(DeviceId::new("cx:device:01904100-0000-7000-8000-00000000000c").unwrap())
            .recipient(Did::new("did:web:carol.example").unwrap())
            .message_type("cx.keys.room_key")
            .body(json!({}))
            .hlc(hlc())
            .sign(&alice)
            .unwrap_err();
        assert!(format!("{err}").contains("sender"));
    }

    #[test]
    fn builder_requires_all_fields() {
        let alice = signer("alice");
        let err = DeviceMessageBuilder::new()
            .sender(alice.signer_did().clone())
            .sender_device(DeviceId::new("cx:device:01904100-0000-7000-8000-00000000000a").unwrap())
            .message_type("cx.keys.room_key")
            .body(json!({}))
            .hlc(hlc())
            .sign(&alice)
            .unwrap_err();
        assert!(format!("{err}").contains("recipient"));
    }

    #[test]
    fn verify_detects_tampered_body() {
        let alice = signer("alice");
        let mut msg = DeviceMessageBuilder::new()
            .sender(alice.signer_did().clone())
            .sender_device(DeviceId::new("cx:device:01904100-0000-7000-8000-00000000000a").unwrap())
            .recipient(Did::new("did:web:bob.example").unwrap())
            .message_type("cx.keys.room_key")
            .body(json!({"session": "abc"}))
            .hlc(hlc())
            .sign(&alice)
            .unwrap();
        msg.body = json!({"session": "EVIL"});
        assert!(msg.verify(&alice).is_err());
        assert!(msg.verify_payload_hash().is_err());
    }
}
