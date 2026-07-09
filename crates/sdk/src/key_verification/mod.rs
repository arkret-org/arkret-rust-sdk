//! Production typed key-verification strand per `crypto-media/device-lifecycle.md` §4.
//!
//! Provides a typed envelope-per-step API on top of
//! [`crate::devices::DeviceVerificationMessageContent`], plus a state
//! machine that enforces the protocol's strict step ordering.
//!
//! Mirrors the Matrix-style `start → accept → key → mac → done` strand with
//! a typed envelope per step:
//!
//! - [`KeyVerificationStart`]
//! - [`KeyVerificationAccept`]
//! - [`KeyVerificationKey`]
//! - [`KeyVerificationMac`]
//! - [`KeyVerificationDone`]
//! - [`KeyVerificationCancel`]
//!
//! and a [`KeyVerificationStrand`] state machine that consumes them in
//! strict order. Every transition is validated and an out-of-order
//! call returns `Error::Protocol(...)` rather than silently accepting it.
//!
//! Beyond step ordering the strand enforces the two cryptographic binding
//! points of `device-lifecycle.md` §10.3:
//!
//! - **Commitment** — `accept.commitment` is a SHA-256 commitment over the responder's ephemeral
//!   public key and the canonical `start` message (see [`compute_key_commitment`]). When the
//!   responder's `key` envelope arrives, [`KeyVerificationStrand::on_key`] recomputes the
//!   commitment and cancels with `code=mismatched_commitment` on mismatch.
//! - **MAC** — [`KeyVerificationStrand::on_mac`] verifies the sender's MAC envelope against the
//!   full negotiated transcript (both parties, transaction id, method, algorithm selection, both
//!   ephemeral keys and the verified key ids/values) using an HKDF-derived MAC key, and cancels
//!   with `code=mismatched_mac` on any mismatch. Producers build matching envelopes with
//!   [`KeyVerificationStrand::build_mac`].

mod commitment;
mod envelopes;
mod key_agreement;
mod strand;

pub use commitment::*;
pub use envelopes::*;
pub use key_agreement::*;
pub use strand::*;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{DateTime, Utc};
    use cokret_core::base64url::base64url_encode;

    use super::*;
    use crate::{DeviceId, Did};

    /// `derive_sas_bytes` MUST be a pure function of
    /// `(shared_secret, info)`. Same inputs → same outputs, two
    /// different infos → distinct outputs. Pin the shapes (7 emoji
    /// indices in `[0, 64)`, 3 decimals in `[1000, 9999]`) so a future
    /// regression that flips MASK_6_BITS or the bit layout fails
    /// loudly.
    #[test]
    fn derive_sas_bytes_is_deterministic_and_bounded() {
        let secret = b"shared-ECDH-secret-bytes-32-long-pad";
        let info_a = b"strand-1|alice|alice-device|bob|bob-device";
        let info_b = b"strand-2|alice|alice-device|bob|bob-device";

        let sas_a1 = derive_sas_bytes(secret, info_a);
        let sas_a2 = derive_sas_bytes(secret, info_a);
        let sas_b = derive_sas_bytes(secret, info_b);

        // Determinism.
        assert_eq!(sas_a1, sas_a2);
        // Different info → different SAS (with overwhelming probability).
        assert_ne!(sas_a1, sas_b);

        // Emoji indices fit in [0, 64).
        for idx in sas_a1.emoji_indices {
            assert!(idx < 64);
        }
        // Decimal digits fit in [1000, 9999].
        for d in sas_a1.decimal_digits {
            assert!((1000..=9999).contains(&d));
        }
        // emoji_pairs MUST return 7 valid entries.
        let pairs = sas_a1.emoji_pairs();
        assert_eq!(pairs.len(), 7);
        for (codepoint, label) in pairs.iter() {
            assert!(!codepoint.is_empty());
            assert!(!label.is_empty());
        }
    }

    /// The SAS computation MUST behave like a real HKDF — change one
    /// byte of `shared_secret`, the output changes. This guards
    /// against a regression that ignores the secret and only hashes
    /// `info`.
    #[test]
    fn derive_sas_bytes_depends_on_secret() {
        let info = b"transaction-id-only";
        let sas_a = derive_sas_bytes(b"secret-A", info);
        let sas_b = derive_sas_bytes(b"secret-B", info);
        assert_ne!(sas_a, sas_b);
    }

    /// X25519 key agreement is symmetric — given two ephemeral
    /// keypairs, each side computes the same 32-byte shared secret
    /// from its private key + the peer's public key. This pins the
    /// protocol's core invariant.
    #[test]
    fn ephemeral_x25519_keypair_yields_symmetric_shared_secret() {
        let alice = EphemeralX25519Keypair::generate().unwrap();
        let bob = EphemeralX25519Keypair::generate().unwrap();
        let alice_to_bob = alice
            .compute_shared_secret(&bob.public_base64())
            .expect("compute alice -> bob");
        let bob_to_alice = bob
            .compute_shared_secret(&alice.public_base64())
            .expect("compute bob -> alice");
        assert_eq!(alice_to_bob, bob_to_alice);
    }

    /// The SAS pair derived from the X25519 shared secret MUST match
    /// on both sides — that's the whole point of the verification
    /// strand. The `info` parameter here is the canonical binding
    /// string both sides agree on (transaction id + per-party DIDs +
    /// per-party device ids).
    #[test]
    fn sas_derived_from_ecdh_shared_secret_matches_on_both_sides() {
        let alice = EphemeralX25519Keypair::generate().unwrap();
        let bob = EphemeralX25519Keypair::generate().unwrap();
        let alice_shared = alice
            .compute_shared_secret(&bob.public_base64())
            .expect("alice shared");
        let bob_shared = bob
            .compute_shared_secret(&alice.public_base64())
            .expect("bob shared");
        let info = b"strand-7|did:webvh:z6mkfixture:alice|alice-device|did:webvh:z6mkfixture:bob|bob-device";
        let sas_alice = derive_sas_bytes(&alice_shared[..], info);
        let sas_bob = derive_sas_bytes(&bob_shared[..], info);
        assert_eq!(sas_alice, sas_bob);
        assert_eq!(sas_alice.emoji_indices, sas_bob.emoji_indices);
        assert_eq!(sas_alice.decimal_digits, sas_bob.decimal_digits);
    }

    /// Malformed peer public keys surface as `Error::Protocol`
    /// rather than panicking, so the verify-device UI can render a
    /// "cancel" outcome instead of crashing. Full integration test:
    /// two `KeyVerificationStrand` instances install their own
    /// ephemeral keypairs, swap the public halves through `on_key`,
    /// and `compute_sas` on both sides yields **the same** SAS pair.
    /// This is the contract the verify-device UI relies on.
    #[test]
    fn key_verification_strand_compute_sas_matches_across_both_sides() {
        let alice_did = did("alice");
        let alice_dev = dev("alice-dev");
        let bob_did = did("bob");
        let bob_dev = dev("bob-dev");
        let txn = "txn-strand-7";

        let alice_kp = EphemeralX25519Keypair::generate().unwrap();
        let bob_kp = EphemeralX25519Keypair::generate().unwrap();
        let alice_public_b64 = alice_kp.public_base64();
        let bob_public_b64 = bob_kp.public_base64();

        let mut alice = KeyVerificationStrand::new().with_ephemeral_key(alice_kp);
        let mut bob = KeyVerificationStrand::new().with_ephemeral_key(bob_kp);

        // Drive both strands through start -> accept -> key.
        let start = KeyVerificationStart {
            transaction_id: txn.to_owned(),
            from_user: alice_did.clone(),
            from_device: alice_dev.clone(),
            method: "sas_v1".to_owned(),
            key_agreement_protocols: vec!["curve25519-hkdf-sha256".to_owned()],
            message_authentication_codes: vec!["hkdf-hmac-sha256".to_owned()],
            short_authentication_string: vec!["decimal".to_owned(), "emoji".to_owned()],
            sent_at: now(),
        };
        alice.on_start(&start).unwrap();
        bob.on_start(&start).unwrap();

        let accept = KeyVerificationAccept {
            transaction_id: txn.to_owned(),
            from_user: bob_did.clone(),
            from_device: bob_dev.clone(),
            method: "sas_v1".to_owned(),
            key_agreement_protocol: "curve25519-hkdf-sha256".to_owned(),
            message_authentication_code: "hkdf-hmac-sha256".to_owned(),
            short_authentication_string: vec!["decimal".to_owned(), "emoji".to_owned()],
            // Real §10.3 commitment: responder (bob) commits to its
            // ephemeral public key + the canonical start message.
            commitment: compute_key_commitment(&bob_public_b64, &start).unwrap(),
            sent_at: now(),
        };
        alice.on_accept(&accept).unwrap();
        bob.on_accept(&accept).unwrap();

        // Each side ships its own public key as the `key` field.
        let alice_key_msg = KeyVerificationKey {
            transaction_id: txn.to_owned(),
            from_user: alice_did.clone(),
            from_device: alice_dev.clone(),
            key: alice_public_b64,
            sent_at: now(),
        };
        let bob_key_msg = KeyVerificationKey {
            transaction_id: txn.to_owned(),
            from_user: bob_did.clone(),
            from_device: bob_dev.clone(),
            key: bob_public_b64,
            sent_at: now(),
        };
        // Each side records its own key + the peer's key (the strand
        // state machine accepts both `on_key` envelopes regardless of
        // order; `keys_exchanged` ends up keyed by device_id).
        alice.on_key(&alice_key_msg).unwrap();
        alice.on_key(&bob_key_msg).unwrap();
        bob.on_key(&alice_key_msg).unwrap();
        bob.on_key(&bob_key_msg).unwrap();

        // Canonical SAS info — both sides MUST construct the same
        // bytes. In production the verify-device view computes this
        // from `(transaction_id, initiator_did, initiator_device,
        // responder_did, responder_device)`.
        let info = format!(
            "{txn}|{}|{}|{}|{}",
            alice_did.as_str(),
            alice_dev.as_str(),
            bob_did.as_str(),
            bob_dev.as_str(),
        );
        let sas_alice = alice.compute_sas(&alice_dev, info.as_bytes()).unwrap();
        let sas_bob = bob.compute_sas(&bob_dev, info.as_bytes()).unwrap();
        assert_eq!(sas_alice, sas_bob, "SAS must match on both sides");
    }

    /// `compute_sas` MUST refuse cleanly when prerequisites are
    /// missing (no keypair installed / no peer key received yet).
    #[test]
    fn compute_sas_refuses_when_prerequisites_missing() {
        let alice_dev = dev("alice-dev");
        let strand = KeyVerificationStrand::new();
        let err = strand
            .compute_sas(&alice_dev, b"info")
            .expect_err("no keypair installed");
        assert!(format!("{err}").contains("ephemeral keypair"));

        let strand = KeyVerificationStrand::new()
            .with_ephemeral_key(EphemeralX25519Keypair::generate().unwrap());
        let err = strand
            .compute_sas(&alice_dev, b"info")
            .expect_err("no peer key received");
        assert!(format!("{err}").contains("peer public key not received"));
    }

    #[test]
    fn compute_shared_secret_rejects_malformed_peer_public_key() {
        let alice = EphemeralX25519Keypair::generate().unwrap();
        // base64 of 31 bytes — wrong length.
        let too_short = base64url_encode(&[0u8; 31][..]);
        let err = alice
            .compute_shared_secret(&too_short)
            .expect_err("31 bytes must reject");
        assert!(format!("{err}").contains("32"));
        let err = alice
            .compute_shared_secret("not-base64-@@!!")
            .expect_err("invalid base64 must reject");
        assert!(format!("{err}").contains("base64"));
        let zero_public = base64url_encode([0u8; 32]);
        let err = alice
            .compute_shared_secret(&zero_public)
            .expect_err("all-zero shared secret must reject");
        assert!(format!("{err}").contains("all zero"));
    }

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    fn dev(name: &str) -> DeviceId {
        let mut acc = 0xcbf29ce484222325u64;
        for byte in name.bytes() {
            acc = (acc ^ u64::from(byte)).wrapping_mul(0x100000001b3);
        }
        DeviceId::new(format!(
            "ak:device:01904100-0000-7000-8000-{:012x}",
            acc & 0x0000_ffff_ffff_ffff
        ))
        .unwrap()
    }

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    fn start(txn: &str) -> KeyVerificationStart {
        KeyVerificationStart {
            transaction_id: txn.to_owned(),
            from_user: did("alice"),
            from_device: dev("alice_phone"),
            method: "sas_v1".to_owned(),
            key_agreement_protocols: vec!["curve25519-hkdf-sha256".to_owned()],
            message_authentication_codes: vec!["hkdf-hmac-sha256".to_owned()],
            short_authentication_string: vec!["decimal".to_owned()],
            sent_at: now(),
        }
    }

    fn accept(txn: &str) -> KeyVerificationAccept {
        KeyVerificationAccept {
            transaction_id: txn.to_owned(),
            from_user: did("bob"),
            from_device: dev("bob_laptop"),
            method: "sas_v1".to_owned(),
            key_agreement_protocol: "curve25519-hkdf-sha256".to_owned(),
            message_authentication_code: "hkdf-hmac-sha256".to_owned(),
            short_authentication_string: vec!["decimal".to_owned()],
            commitment: "sha256:cafe".to_owned(),
            sent_at: now(),
        }
    }

    fn key(txn: &str, who: &Did, dvc: &DeviceId, k: &str) -> KeyVerificationKey {
        KeyVerificationKey {
            transaction_id: txn.to_owned(),
            from_user: who.clone(),
            from_device: dvc.clone(),
            key: k.to_owned(),
            sent_at: now(),
        }
    }

    fn done(txn: &str, who: &Did, dvc: &DeviceId) -> KeyVerificationDone {
        KeyVerificationDone {
            transaction_id: txn.to_owned(),
            from_user: who.clone(),
            from_device: dvc.clone(),
            sent_at: now(),
        }
    }

    fn verify_keys() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                "ed25519:alice_phone".to_owned(),
                "alice-device-verify-key".to_owned(),
            ),
            (
                "ed25519:bob_laptop".to_owned(),
                "bob-device-verify-key".to_owned(),
            ),
        ])
    }

    /// Drive a strand (holding alice's ephemeral keypair) through
    /// start -> accept -> key/key with a real commitment, ending in
    /// `KeysExchanged`. Returns the strand plus bob's public key.
    fn strand_at_keys_exchanged(txn: &str) -> (KeyVerificationStrand, String) {
        let alice_kp = EphemeralX25519Keypair::generate().unwrap();
        let bob_kp = EphemeralX25519Keypair::generate().unwrap();
        let alice_pub = alice_kp.public_base64();
        let bob_pub = bob_kp.public_base64();
        let start_msg = start(txn);
        let mut accept_msg = accept(txn);
        accept_msg.commitment = compute_key_commitment(&bob_pub, &start_msg).unwrap();
        let mut strand = KeyVerificationStrand::new().with_ephemeral_key(alice_kp);
        strand.on_start(&start_msg).unwrap();
        strand.on_accept(&accept_msg).unwrap();
        strand
            .on_key(&key(txn, &did("alice"), &dev("alice_phone"), &alice_pub))
            .unwrap();
        strand
            .on_key(&key(txn, &did("bob"), &dev("bob_laptop"), &bob_pub))
            .unwrap();
        assert_eq!(strand.state(), KeyVerificationState::KeysExchanged);
        (strand, bob_pub)
    }

    #[test]
    fn full_strand_runs_to_done() {
        let txn = "txn-1";
        let (mut strand, _) = strand_at_keys_exchanged(txn);
        let keys = verify_keys();
        // The shared secret is symmetric, so one strand can produce both
        // sides' MAC envelopes for the round trip.
        let alice_mac = strand
            .build_mac(&did("alice"), &dev("alice_phone"), &keys)
            .unwrap();
        let bob_mac = strand
            .build_mac(&did("bob"), &dev("bob_laptop"), &keys)
            .unwrap();
        strand.on_mac(&alice_mac, &keys).unwrap();
        strand.on_mac(&bob_mac, &keys).unwrap();
        assert_eq!(strand.state(), KeyVerificationState::MacsReceived);
        strand
            .on_done(&done(txn, &did("alice"), &dev("alice_phone")))
            .unwrap();
        strand
            .on_done(&done(txn, &did("bob"), &dev("bob_laptop")))
            .unwrap();
        assert_eq!(strand.state(), KeyVerificationState::Done);
        assert!(strand.state().is_terminal());
    }

    /// §10.3: a responder key that does not match `accept.commitment`
    /// MUST cancel with `code=mismatched_commitment`.
    #[test]
    fn on_key_rejects_mismatched_commitment() {
        let txn = "txn-commit";
        let mut strand = KeyVerificationStrand::new();
        strand.on_start(&start(txn)).unwrap();
        // accept() carries a bogus commitment ("sha256:cafe").
        strand.on_accept(&accept(txn)).unwrap();
        strand
            .on_key(&key(txn, &did("alice"), &dev("alice_phone"), "AKEY"))
            .unwrap();
        let bob_kp = EphemeralX25519Keypair::generate().unwrap();
        let err = strand
            .on_key(&key(
                txn,
                &did("bob"),
                &dev("bob_laptop"),
                &bob_kp.public_base64(),
            ))
            .unwrap_err();
        assert!(format!("{err}").contains("mismatched_commitment"));
        assert_eq!(strand.state(), KeyVerificationState::Cancelled);
        assert_eq!(
            strand.cancel_record().unwrap().code,
            "mismatched_commitment"
        );
    }

    /// §10.3: a tampered MAC MUST cancel with `code=mismatched_mac`.
    #[test]
    fn on_mac_rejects_tampered_mac() {
        let txn = "txn-mac";
        let (mut strand, _) = strand_at_keys_exchanged(txn);
        let keys = verify_keys();
        let mut tampered = strand
            .build_mac(&did("alice"), &dev("alice_phone"), &keys)
            .unwrap();
        tampered.keys = base64url_encode([0u8; 32]);
        let err = strand.on_mac(&tampered, &keys).unwrap_err();
        assert!(format!("{err}").contains("mismatched_mac"));
        assert_eq!(strand.state(), KeyVerificationState::Cancelled);
        assert_eq!(strand.cancel_record().unwrap().code, "mismatched_mac");
    }

    /// §10.3: a per-key MAC over a key value the receiver does not
    /// expect MUST cancel with `code=mismatched_mac`.
    #[test]
    fn on_mac_rejects_unexpected_key_value() {
        let txn = "txn-mac-key";
        let (mut strand, _) = strand_at_keys_exchanged(txn);
        let mut forged_keys = verify_keys();
        forged_keys.insert(
            "ed25519:bob_laptop".to_owned(),
            "attacker-substituted-key".to_owned(),
        );
        // Sender MACs the forged key; receiver checks against its own view.
        let mac = strand
            .build_mac(&did("bob"), &dev("bob_laptop"), &forged_keys)
            .unwrap();
        let err = strand.on_mac(&mac, &verify_keys()).unwrap_err();
        assert!(format!("{err}").contains("mismatched_mac"));
        assert_eq!(strand.state(), KeyVerificationState::Cancelled);
    }

    /// Without an ephemeral keypair the MAC cannot be verified — the
    /// strand MUST fail closed instead of passing unverified MACs.
    #[test]
    fn on_mac_fails_closed_without_ephemeral_keypair() {
        let txn = "txn-mac-eph";
        let (reference_strand, bob_pub) = strand_at_keys_exchanged(txn);
        let keys = verify_keys();
        let mac = reference_strand
            .build_mac(&did("bob"), &dev("bob_laptop"), &keys)
            .unwrap();
        // Rebuild the same transcript in a strand with no keypair installed.
        let alice_pub = reference_strand
            .keys_exchanged
            .get(&dev("alice_phone"))
            .unwrap()
            .clone();
        let start_msg = start(txn);
        let mut accept_msg = accept(txn);
        accept_msg.commitment = compute_key_commitment(&bob_pub, &start_msg).unwrap();
        let mut observer = KeyVerificationStrand::new();
        observer.on_start(&start_msg).unwrap();
        observer.on_accept(&accept_msg).unwrap();
        observer
            .on_key(&key(txn, &did("alice"), &dev("alice_phone"), &alice_pub))
            .unwrap();
        observer
            .on_key(&key(txn, &did("bob"), &dev("bob_laptop"), &bob_pub))
            .unwrap();
        let err = observer.on_mac(&mac, &keys).unwrap_err();
        assert!(format!("{err}").contains("mismatched_mac"));
        assert_eq!(observer.state(), KeyVerificationState::Cancelled);
    }

    #[test]
    fn rejects_out_of_order_accept_without_start() {
        let mut strand = KeyVerificationStrand::new();
        let err = strand.on_accept(&accept("txn-x")).unwrap_err();
        assert!(format!("{err}").contains("invalid_transition"));
        assert_eq!(strand.state(), KeyVerificationState::Cancelled);
    }

    #[test]
    fn rejects_transaction_id_mismatch() {
        let mut strand = KeyVerificationStrand::new();
        strand.on_start(&start("txn-1")).unwrap();
        let err = strand.on_accept(&accept("txn-2")).unwrap_err();
        assert!(format!("{err}").contains("transaction_id"));
    }

    #[test]
    fn rejects_unknown_party_key() {
        let txn = "txn-1";
        let mut strand = KeyVerificationStrand::new();
        strand.on_start(&start(txn)).unwrap();
        strand.on_accept(&accept(txn)).unwrap();
        let err = strand
            .on_key(&key(txn, &did("eve"), &dev("eve_box"), "EKEY"))
            .unwrap_err();
        assert!(format!("{err}").contains("not part of this strand"));
        assert_eq!(strand.state(), KeyVerificationState::Cancelled);
    }

    #[test]
    fn cancel_records_reason_and_terminates() {
        let txn = "txn-1";
        let mut strand = KeyVerificationStrand::new();
        strand.on_start(&start(txn)).unwrap();
        strand
            .on_cancel(&KeyVerificationCancel {
                transaction_id: txn.to_owned(),
                from_user: did("alice"),
                from_device: dev("alice_phone"),
                code: "user_cancel".to_owned(),
                reason: "user pressed cancel".to_owned(),
                sent_at: now(),
            })
            .unwrap();
        assert_eq!(strand.state(), KeyVerificationState::Cancelled);
        assert_eq!(strand.cancel_record().unwrap().code, "user_cancel");
    }

    #[test]
    fn cannot_cancel_terminal_strand() {
        let txn = "txn-1";
        let mut strand = KeyVerificationStrand::new();
        strand.on_start(&start(txn)).unwrap();
        strand
            .on_cancel(&KeyVerificationCancel {
                transaction_id: txn.to_owned(),
                from_user: did("alice"),
                from_device: dev("alice_phone"),
                code: "x".to_owned(),
                reason: "x".to_owned(),
                sent_at: now(),
            })
            .unwrap();
        let err = strand
            .on_cancel(&KeyVerificationCancel {
                transaction_id: txn.to_owned(),
                from_user: did("alice"),
                from_device: dev("alice_phone"),
                code: "y".to_owned(),
                reason: "y".to_owned(),
                sent_at: now(),
            })
            .unwrap_err();
        assert!(format!("{err}").contains("terminal"));
    }
}
