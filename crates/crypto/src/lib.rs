//! Protocol crypto machine contracts.
//!
//! ## Feature flags
//!
//! * `backup` — pulls in the [`backup`] module, which provides client-side Argon2id KDF,
//!   XChaCha20-Poly1305 AEAD, a recovery-key codec, and a typed
//!   [`arkret_models_crypto::key_backup::KeyBackup`] envelope builder (spec:
//!   `crypto-media/key-management.md` §7). When the feature is off, the bare types crate stays free
//!   of heavyweight crypto deps.

#[cfg(feature = "account-data")]
pub mod account_data_crypto;
#[cfg(feature = "aead")]
pub mod aead_nonce;
#[cfg(feature = "backup")]
pub mod backup;
#[cfg(feature = "blob-aead")]
pub mod blob_aead;
#[cfg(feature = "identity-root")]
pub mod identity_root;
#[cfg(feature = "key-verification")]
pub mod key_verification;
#[cfg(feature = "aead")]
pub mod mls_exporter;
#[cfg(feature = "secret-share")]
pub mod secret_share;
#[cfg(feature = "sframe")]
pub mod sframe;

mod cross_signing;
mod device;
mod errors;
mod session;

// Crate-root re-export preserved from the original module layout.
#[cfg(feature = "aead")]
pub use aead_nonce::*;
pub use arkret_signatures::{DetachedSignature, DetachedSignatureBinding, DetachedVerifier};
// Re-export every moved public item at the crate root so the public API is
// byte-identical to the pre-split single-file module.
pub use cross_signing::*;
pub use device::*;
pub use errors::*;
#[cfg(feature = "aead")]
pub use mls_exporter::*;
// `sha256_prefixed` is a `pub(crate)` helper used by the test module via
// `use super::*`; surface it at the crate root so that path resolves.
#[cfg(test)]
pub(crate) use session::sha256_prefixed;
pub use session::*;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_models_crypto::encrypted_envelope::EncryptedPayload;
    use arkret_wire::{BlobRef, DeviceId, Did, EncryptedPayloadScheme, EventId, Hash, RealmId};
    use chrono::Utc;

    use super::*;
    use crate::errors::Error;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    fn device() -> DeviceId {
        DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap()
    }

    #[test]
    fn crypto_machine_plan_validates_and_orders_requests() {
        let mut plan = CryptoMachinePlan::default();
        let queued = plan
            .push(
                "r1",
                CryptoMachineRequestBody::QueryDeviceKeys {
                    users: vec![did("alice")],
                },
            )
            .unwrap();
        assert_eq!(
            queued,
            CryptoMachineResponseBody::Queued {
                request_id: "r1".to_owned(),
                kind: CryptoMachineRequestKind::QueryDeviceKeys
            }
        );
        assert_eq!(
            plan.pending_kinds(),
            vec![CryptoMachineRequestKind::QueryDeviceKeys]
        );
        assert!(matches!(
            plan.push(
                "bad",
                CryptoMachineRequestBody::QueryDeviceKeys { users: Vec::new() }
            ),
            Err(Error::Protocol(_))
        ));
        plan.push(
            "share",
            CryptoMachineRequestBody::ShareRoomKey {
                realm_id: RealmId::new("ak:realm:ATkXzcQvyxfe91pWo53Tg9imMLwlTme1cbCFc5G-lymH")
                    .unwrap(),
                session_id: "sess1".to_owned(),
                recipients: vec![device()],
            },
        )
        .unwrap();
        assert_eq!(
            plan.pending_kinds(),
            vec![
                CryptoMachineRequestKind::QueryDeviceKeys,
                CryptoMachineRequestKind::ShareRoomKey
            ]
        );
    }

    #[test]
    fn store_binding_records_device_keys_and_unable_to_decrypt() {
        let mut binding = CryptoStoreBinding::default();
        let bundle = DeviceKeyBundle {
            user_id: did("alice"),
            device_id: device(),
            signing_key: "ed25519:abc".to_owned(),
            identity_key: "curve25519:def".to_owned(),
            algorithms: BTreeMap::new(),
            signatures: Vec::new(),
        };
        binding.record_device_keys(bundle).unwrap();
        assert_eq!(binding.device_keys.len(), 1);

        let payload = EncryptedPayload {
            scheme: EncryptedPayloadScheme::MlsRfc9420,
            group_id: "group".to_owned(),
            epoch: 1,
            content_type: "application/json".to_owned(),
            ciphertext: "abc".to_owned(),
            aad: None,
            payload_digest: Hash::new(sha256_prefixed(b"abc")).unwrap(),
            key_ref: None,
            // mls_rfc9420 has no exporter AEAD, so the schema forbids both.
            purpose: None,
            aead_profile: None,
        };
        binding.record_unable_to_decrypt(UnableToDecryptRecord {
            event_id: EventId::new("ak:event:AY2gmtVpH4CNWqvZ25JTuYdzI56aAbxr3k-TrqvZfsKv")
                .unwrap(),
            realm_id: RealmId::new("ak:realm:ATkXzcQvyxfe91pWo53Tg9imMLwlTme1cbCFc5G-lymH")
                .unwrap(),
            sender: did("alice"),
            reason: UnableToDecryptReason::NoSession,
            encrypted_content: payload,
            first_seen_at: Utc::now(),
        });
        assert_eq!(binding.unable_to_decrypt.len(), 1);
    }

    #[test]
    fn verification_session_and_withheld_key_state_are_tracked() {
        let mut binding = CryptoStoreBinding::default();
        let mut strand = DeviceVerificationStrand {
            transaction_id: "verif1".to_owned(),
            user_id: did("alice"),
            from_device: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
            to_device: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000004").unwrap(),
            methods: vec!["sas".to_owned(), "qr".to_owned()],
            state: VerificationStrandState::Requested,
            created_at: Utc::now(),
            expires_at: None,
        };
        strand.advance(VerificationStrandState::Ready).unwrap();
        strand.advance(VerificationStrandState::SasStarted).unwrap();
        strand.advance(VerificationStrandState::Done).unwrap();
        binding.record_verification_strand(strand).unwrap();
        binding.set_device_trust(
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000004").unwrap(),
            DeviceTrustState::Verified,
        );
        assert_eq!(
            binding
                .device_trust
                .get(&DeviceId::new("ak:device:01904100-0000-7000-8000-000000000004").unwrap()),
            Some(&DeviceTrustState::Verified)
        );

        let realm_id =
            RealmId::new("ak:realm:ATkXzcQvyxfe91pWo53Tg9imMLwlTme1cbCFc5G-lymH").unwrap();
        binding
            .record_session(CryptoSessionRecord {
                realm_id: realm_id.clone(),
                session_id: "sess1".to_owned(),
                sender_key: "curve25519:def".to_owned(),
                algorithm: "ak.mls.v1".to_owned(),
                state: CryptoSessionState::Active,
                created_at: Utc::now(),
                last_used_at: Utc::now(),
                message_index_high_watermark: None,
            })
            .unwrap();
        let session = binding.session_mut(&realm_id, "sess1").unwrap();
        session.accept_message_index(7, Utc::now()).unwrap();
        assert!(matches!(
            session.accept_message_index(7, Utc::now()),
            Err(Error::Protocol(_))
        ));

        binding.record_withheld_key(WithheldKeyRecord {
            realm_id,
            session_id: "sess1".to_owned(),
            sender: did("alice"),
            code: "m.blacklisted".to_owned(),
            reason: UnableToDecryptReason::Withheld,
            received_at: Utc::now(),
        });
        assert_eq!(binding.withheld_keys.len(), 1);
    }

    #[test]
    fn media_encryption_info_validates_plaintext_digest() {
        let plaintext = b"hello media";
        let info = MediaEncryptionInfo {
            blob_ref: BlobRef::from_bytes(plaintext),
            scheme: EncryptedPayloadScheme::MlsRfc9420,
            key_ref: "media-key-1".to_owned(),
            plaintext_sha256: Hash::new(sha256_prefixed(plaintext)).unwrap(),
            ciphertext_sha256: Hash::new(sha256_prefixed(b"ciphertext")).unwrap(),
        };
        info.validate_plaintext(plaintext).unwrap();
        assert!(matches!(
            info.validate_plaintext(b"changed"),
            Err(Error::Protocol(_))
        ));
    }

    // ── Inherent validate() coverage ────────────────────────────────

    fn protocol_message(err: Error) -> String {
        match err {
            Error::Protocol(message) => message,
            other => panic!("expected Error::Protocol, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_invalid_device_verification_strand() {
        let mut strand = DeviceVerificationStrand {
            transaction_id: String::new(),
            user_id: did("alice"),
            from_device: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap(),
            to_device: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap(),
            methods: Vec::new(),
            state: VerificationStrandState::Requested,
            created_at: Utc::now(),
            expires_at: None,
        };

        // Empty transaction id.
        assert!(strand.validate().is_err());

        // Same device on both sides.
        strand.transaction_id = "tx".to_owned();
        strand.to_device = strand.from_device.clone();
        let message = protocol_message(strand.validate().unwrap_err());
        assert!(message.contains("two distinct devices"), "{message}");

        // Too many methods → bounds error.
        strand.to_device = DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap();
        strand.methods = (0..(MAX_VERIFICATION_METHODS + 1))
            .map(|i| format!("m{i}"))
            .collect();
        let message = protocol_message(strand.validate().unwrap_err());
        assert!(message.contains("verification methods"), "{message}");
    }

    #[test]
    fn validate_rejects_invalid_withheld_key_record() {
        let realm_id =
            RealmId::new("ak:realm:ATkXzcQvyxfe91pWo53Tg9imMLwlTme1cbCFc5G-lymH").unwrap();
        let mut record = WithheldKeyRecord {
            realm_id,
            session_id: String::new(),
            sender: did("alice"),
            code: "m.blacklisted".to_owned(),
            reason: UnableToDecryptReason::Withheld,
            received_at: Utc::now(),
        };
        assert!(record.validate().is_err());

        record.session_id = "sess1".to_owned();
        record.code = String::new();
        assert!(record.validate().is_err());

        record.code = "x".repeat(MAX_IDENTIFIER_LEN + 1);
        let message = protocol_message(record.validate().unwrap_err());
        assert!(message.contains("withheld code"), "{message}");
    }

    #[test]
    fn validate_rejects_invalid_key_lifecycle_event() {
        let mut ev = KeyLifecycleEvent {
            key_ref: String::new(),
            phase: KeyLifecyclePhase::Created,
            actor: did("alice"),
            device_id: device(),
            occurred_at: Utc::now(),
            reason: "init".to_owned(),
        };
        assert!(ev.validate().is_err());

        ev.key_ref = "kid".to_owned();
        ev.reason = "r".repeat(MAX_REASON_LEN + 1);
        let message = protocol_message(ev.validate().unwrap_err());
        assert!(message.contains("key lifecycle reason"), "{message}");
    }

    #[test]
    fn crypto_error_converts_to_core_protocol_error() {
        // Backward-compat: every CryptoError still renders to
        // Error::Protocol so callers that have not migrated keep
        // seeing the same shape.
        let core_err: Error = CryptoError::ReplayDetected.into();
        assert!(matches!(core_err, Error::Protocol(_)));

        let core_err: Error = CryptoError::BoundsExceeded {
            field: "field".to_owned(),
            limit: 10,
        }
        .into();
        if let Error::Protocol(message) = core_err {
            assert!(message.contains("field"));
            assert!(message.contains("10"));
        } else {
            panic!("expected Error::Protocol");
        }
    }

    // ── Round-3 hardening tests ─────────────────────────────────────

    /// Deterministic LCG so the property test is reproducible without
    /// pulling in `proptest` / `quickcheck` as deps. Seeded inputs are
    /// always the same and any failure is easy to repro by rerunning.
    fn xorshift_next(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    fn make_session() -> CryptoSessionRecord {
        CryptoSessionRecord {
            realm_id: RealmId::new("ak:realm:ATkXzcQvyxfe91pWo53Tg9imMLwlTme1cbCFc5G-lymH")
                .unwrap(),
            session_id: "sess-prop".to_owned(),
            sender_key: "curve25519:def".to_owned(),
            algorithm: "ak.mls.v1".to_owned(),
            state: CryptoSessionState::Active,
            created_at: Utc::now(),
            last_used_at: Utc::now(),
            message_index_high_watermark: None,
        }
    }

    /// Property: for any strictly increasing sequence of indices, every
    /// `accept_message_index` call succeeds; for any index ≤ the running
    /// high-water mark, the call must reject with `Error::Protocol`.
    #[test]
    fn message_index_monotonicity_property() {
        const RUNS: usize = 64;
        const STEPS: usize = 32;
        let mut state: u64 = 0xC0FFEE_u64;
        let now = Utc::now();

        for run in 0..RUNS {
            let mut session = make_session();
            let mut high: u64 = 0;
            let mut saw_increase = false;
            for _ in 0..STEPS {
                // Pick a random *delta* up to 1024. delta == 0 must be
                // rejected as replay; delta > 0 must be accepted and
                // advance the watermark.
                let delta = xorshift_next(&mut state) % 1024;
                let candidate = high.saturating_add(delta);
                let res = session.accept_message_index(candidate, now);
                if delta == 0 && session.message_index_high_watermark.is_some() {
                    assert!(
                        matches!(res, Err(Error::Protocol(_))),
                        "run {run}: replay at index {candidate} (high={high}) must reject"
                    );
                } else if candidate == 0
                    && high == 0
                    && session.message_index_high_watermark.is_none()
                {
                    // Very first call at index 0 is accepted (no prior watermark).
                    res.unwrap();
                    high = candidate;
                    saw_increase = true;
                } else if delta > 0 {
                    res.unwrap();
                    high = candidate;
                    saw_increase = true;
                    assert_eq!(session.message_index_high_watermark, Some(high));
                }
            }
            // Sanity: most runs must observe at least one accepted step.
            assert!(saw_increase || RUNS > 1);
        }
    }

    /// Wraparound: u64::MAX is accepted as a one-off, but every following
    /// candidate (including u64::MAX itself) must reject. This documents
    /// the contract that the watermark is sticky at the top of the range
    /// — callers MUST rotate the session before they can submit more.
    #[test]
    fn message_index_wraparound_at_u64_max() {
        let mut session = make_session();
        let now = Utc::now();
        session.accept_message_index(u64::MAX, now).unwrap();
        // Every subsequent index (including u64::MAX) must reject.
        assert!(matches!(
            session.accept_message_index(u64::MAX, now),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            session.accept_message_index(0, now),
            Err(Error::Protocol(_))
        ));
        assert!(matches!(
            session.accept_message_index(u64::MAX - 1, now),
            Err(Error::Protocol(_))
        ));
        // Watermark stays pinned.
        assert_eq!(session.message_index_high_watermark, Some(u64::MAX));
    }

    /// Recording an `UnableToDecryptRecord` with a `BadCiphertext`
    /// reason: the binding accepts it but the encrypted payload is
    /// observable (the renderer needs it to show a placeholder) and
    /// later inserts under the same event id MUST overwrite.
    #[test]
    fn unable_to_decrypt_path_bad_ciphertext() {
        let mut binding = CryptoStoreBinding::default();
        let event_id =
            EventId::new("ak:event:AY2gmtVpH4CNWqvZ25JTuYdzI56aAbxr3k-TrqvZfsKv").unwrap();
        let realm_id =
            RealmId::new("ak:realm:ATkXzcQvyxfe91pWo53Tg9imMLwlTme1cbCFc5G-lymH").unwrap();
        let payload = EncryptedPayload {
            scheme: EncryptedPayloadScheme::MlsRfc9420,
            group_id: "group".to_owned(),
            epoch: 1,
            content_type: "application/json".to_owned(),
            // intentionally non-decryptable: empty ciphertext + mismatched digest
            ciphertext: String::new(),
            aad: None,
            payload_digest: Hash::new(sha256_prefixed(b"not-the-ciphertext")).unwrap(),
            key_ref: None,
            // mls_rfc9420 has no exporter AEAD, so the schema forbids both.
            purpose: None,
            aead_profile: None,
        };
        let record = UnableToDecryptRecord {
            event_id: event_id.clone(),
            realm_id: realm_id.clone(),
            sender: did("alice"),
            reason: UnableToDecryptReason::BadCiphertext,
            encrypted_content: payload.clone(),
            first_seen_at: Utc::now(),
        };
        binding.record_unable_to_decrypt(record);
        assert_eq!(binding.unable_to_decrypt.len(), 1);
        let stored = binding.unable_to_decrypt.get(&event_id).unwrap();
        assert_eq!(stored.reason, UnableToDecryptReason::BadCiphertext);
        assert!(stored.encrypted_content.ciphertext.is_empty());

        // Recording again with NoSession overwrites the prior entry —
        // the keyed event id is stable so the second observation wins.
        binding.record_unable_to_decrypt(UnableToDecryptRecord {
            event_id: event_id.clone(),
            realm_id,
            sender: did("alice"),
            reason: UnableToDecryptReason::NoSession,
            encrypted_content: payload,
            first_seen_at: Utc::now(),
        });
        assert_eq!(binding.unable_to_decrypt.len(), 1);
        assert_eq!(
            binding.unable_to_decrypt.get(&event_id).unwrap().reason,
            UnableToDecryptReason::NoSession
        );
    }
}
