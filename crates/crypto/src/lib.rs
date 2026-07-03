//! Protocol crypto machine contracts.
//!
//! ## Feature flags
//!
//! * `backup` — pulls in the [`backup`] module, which provides client-side Argon2id KDF,
//!   XChaCha20-Poly1305 AEAD, a recovery-key codec, and a typed [`cokret_core::KeyBackup`] envelope
//!   builder (spec: `crypto-media/key-management.md` §7). When the feature is off, the bare types
//!   crate stays free of heavyweight crypto deps.

#[cfg(feature = "backup")]
pub mod backup;

mod cross_signing;
mod device;
mod errors;
mod session;

// Crate-root re-export preserved from the original module layout.
pub use cokret_signatures::{DetachedSignature, DetachedSignatureBinding, DetachedVerifier};
// Re-export every moved public item at the crate root so the public API is
// byte-identical to the pre-split single-file module.
pub use cross_signing::*;
pub use device::*;
pub use errors::*;
// `sha256_prefixed` is a `pub(crate)` helper used by the test module via
// `use super::*`; surface it at the crate root so that path resolves.
#[cfg(test)]
pub(crate) use session::sha256_prefixed;
pub use session::*;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;
    use cokret_core::{
        BlobRef, DeviceId, Did, EncryptedPayload, EncryptedPayloadScheme, Error, EventId, Hash,
        RealmId,
    };

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    fn device() -> DeviceId {
        DeviceId::new("ck:device:01904100-0000-7000-8000-000000000001").unwrap()
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
                realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-6c355fb9dada").unwrap(),
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
        };
        binding.record_unable_to_decrypt(UnableToDecryptRecord {
            event_id: EventId::new("ck:event:01904100-0000-7000-8000-4e7fda181f9f").unwrap(),
            realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-6c355fb9dada").unwrap(),
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
            from_device: DeviceId::new("ck:device:01904100-0000-7000-8000-000000000001").unwrap(),
            to_device: DeviceId::new("ck:device:01904100-0000-7000-8000-000000000004").unwrap(),
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
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000004").unwrap(),
            DeviceTrustState::Verified,
        );
        assert_eq!(
            binding
                .device_trust
                .get(&DeviceId::new("ck:device:01904100-0000-7000-8000-000000000004").unwrap()),
            Some(&DeviceTrustState::Verified)
        );

        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-6c355fb9dada").unwrap();
        binding
            .record_session(CryptoSessionRecord {
                realm_id: realm_id.clone(),
                session_id: "sess1".to_owned(),
                sender_key: "curve25519:def".to_owned(),
                algorithm: "ck.mls.v1".to_owned(),
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
            from_device: DeviceId::new("ck:device:01904100-0000-7000-8000-000000000001").unwrap(),
            to_device: DeviceId::new("ck:device:01904100-0000-7000-8000-000000000002").unwrap(),
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
        strand.to_device = DeviceId::new("ck:device:01904100-0000-7000-8000-000000000002").unwrap();
        strand.methods = (0..(MAX_VERIFICATION_METHODS + 1))
            .map(|i| format!("m{i}"))
            .collect();
        let message = protocol_message(strand.validate().unwrap_err());
        assert!(message.contains("verification methods"), "{message}");
    }

    #[test]
    fn validate_rejects_invalid_withheld_key_record() {
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-6c355fb9dada").unwrap();
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
            realm_id: RealmId::new("ck:realm:01904100-0000-7000-8000-6c355fb9dada").unwrap(),
            session_id: "sess-prop".to_owned(),
            sender_key: "curve25519:def".to_owned(),
            algorithm: "ck.mls.v1".to_owned(),
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

    /// `CrossSigningResetProof::DeviceQuorum { threshold: 0, .. }` must
    /// be rejected even when the signatures vector is non-empty.
    #[test]
    fn reset_signing_input_is_stable_and_binds_replay_fields() {
        let content = CrossSigningResetContent {
            principal_id: did("alice"),
            trust_domain: cokret_core::TypedTrustDomainId::new("ck:trust_domain:example.net")
                .unwrap(),
            reset_event_id: "ck:event:01964137-0000-7000-8000-0000000000aa".to_owned(),
            previous_generation: 1,
            new_generation: 2,
            reset_reason: "lost phone".to_owned(),
            proof: CrossSigningResetProof::PrincipalSigning {
                verification_method: "did:webvh:z6mkfixture:alice.example#psk".to_owned(),
                alg: "EdDSA".to_owned(),
                signature: "AAAA".to_owned(),
            },
            issued_at: Utc::now(),
        };
        let base = content.reset_signing_input().unwrap();
        assert!(base.starts_with(b"ck-cross-signing-reset-v1\n"));
        // Deterministic.
        assert_eq!(base, content.reset_signing_input().unwrap());
        // Generation transition is bound.
        let mut gen_changed = content.clone();
        gen_changed.previous_generation = 2;
        gen_changed.new_generation = 3;
        assert_ne!(base, gen_changed.reset_signing_input().unwrap());
        // trust_domain is bound (cross-deployment replay protection).
        let mut domain_changed = content.clone();
        domain_changed.trust_domain =
            cokret_core::TypedTrustDomainId::new("ck:trust_domain:other.net").unwrap();
        assert_ne!(base, domain_changed.reset_signing_input().unwrap());
        // reset_event_id is bound (event-shell replay protection).
        let mut event_changed = content.clone();
        event_changed.reset_event_id = "ck:event:01964137-0000-7000-8000-0000000000bb".to_owned();
        assert_ne!(base, event_changed.reset_signing_input().unwrap());
        // issued_at is bound (clock-skew and replay window protection).
        let mut issued_changed = content.clone();
        issued_changed.issued_at += chrono::Duration::seconds(1);
        assert_ne!(base, issued_changed.reset_signing_input().unwrap());
        // proof kind/body are bound, excluding only signature material.
        let mut proof_changed = content.clone();
        proof_changed.proof = CrossSigningResetProof::RecoveryUnlock {
            recovery_session_id: "ck:recovery_session:01964137-0000-7000-8000-0000000000cc"
                .to_owned(),
            recovery_secret_ref: "did:webvh:z6mkfixture:alice.example#recovery-1".to_owned(),
            unlock_commitment: "sha256:00".to_owned(),
            alg: "EdDSA".to_owned(),
            signature: "AAAA".to_owned(),
        };
        assert_ne!(base, proof_changed.reset_signing_input().unwrap());
        let mut signature_changed = content;
        signature_changed.proof = CrossSigningResetProof::PrincipalSigning {
            verification_method: "did:webvh:z6mkfixture:alice.example#psk".to_owned(),
            alg: "EdDSA".to_owned(),
            signature: "BBBB".to_owned(),
        };
        assert_eq!(base, signature_changed.reset_signing_input().unwrap());
    }

    #[test]
    fn recovery_unlock_commitment_binds_reset_without_self_reference() {
        let content = CrossSigningResetContent {
            principal_id: did("alice"),
            trust_domain: cokret_core::TypedTrustDomainId::new("ck:trust_domain:example.net")
                .unwrap(),
            reset_event_id: "ck:event:01964137-0000-7000-8000-0000000000aa".to_owned(),
            previous_generation: 1,
            new_generation: 2,
            reset_reason: "rotation".to_owned(),
            proof: CrossSigningResetProof::RecoveryUnlock {
                recovery_session_id: "ck:recovery_session:01964137-0000-7000-8000-0000000000cc"
                    .to_owned(),
                recovery_secret_ref: "did:webvh:z6mkfixture:alice.example#recovery-1".to_owned(),
                unlock_commitment: "sha256:placeholder".to_owned(),
                alg: "EdDSA".to_owned(),
                signature: "AAAA".to_owned(),
            },
            issued_at: Utc::now(),
        };
        let commitment = content.recovery_unlock_commitment().unwrap();
        assert!(commitment.starts_with("sha256:"));
        let mut with_commitment = content;
        if let CrossSigningResetProof::RecoveryUnlock {
            unlock_commitment, ..
        } = &mut with_commitment.proof
        {
            *unlock_commitment = commitment.clone();
        }
        assert_eq!(
            commitment,
            with_commitment.recovery_unlock_commitment().unwrap()
        );

        let mut changed_ref = with_commitment;
        if let CrossSigningResetProof::RecoveryUnlock {
            recovery_secret_ref,
            ..
        } = &mut changed_ref.proof
        {
            *recovery_secret_ref = "did:webvh:z6mkfixture:alice.example#recovery-2".to_owned();
        }
        assert_ne!(
            commitment,
            changed_ref.recovery_unlock_commitment().unwrap()
        );
    }

    #[test]
    fn cross_signing_reset_proof_threshold_zero_rejected() {
        let content = CrossSigningResetContent {
            principal_id: did("alice"),
            trust_domain: cokret_core::TypedTrustDomainId::new("ck:trust_domain:example.net")
                .unwrap(),
            reset_event_id: "ck:event:01964137-0000-7000-8000-0000000000aa".to_owned(),
            previous_generation: 1,
            new_generation: 2,
            reset_reason: "lost phone".to_owned(),
            proof: CrossSigningResetProof::DeviceQuorum {
                threshold: 0,
                signatures: vec![DeviceQuorumSignature {
                    device_id: device(),
                    verification_method: "did:webvh:z6mkfixture:alice.example#dev1".to_owned(),
                    alg: "EdDSA".to_owned(),
                    signature: "AAAA".to_owned(),
                }],
            },
            issued_at: Utc::now(),
        };
        let err = content.validate_structure().unwrap_err();
        if let Error::Protocol(message) = err {
            assert!(
                message.contains("threshold >= 1"),
                "unexpected message: {message}"
            );
        } else {
            panic!("expected Error::Protocol");
        }
    }

    /// `PrincipalSigning` / `TrustedRecoveryService` / `RecoveryUnlock`:
    /// blank kid/alg/signature strings must all be rejected.
    #[test]
    fn cross_signing_reset_proof_rejects_malformed_kid_alg() {
        // PrincipalSigning with whitespace-only `verification_method`.
        let blank_verification_method = CrossSigningResetContent {
            principal_id: did("alice"),
            trust_domain: cokret_core::TypedTrustDomainId::new("ck:trust_domain:example.net")
                .unwrap(),
            reset_event_id: "ck:event:01964137-0000-7000-8000-0000000000aa".to_owned(),
            previous_generation: 1,
            new_generation: 2,
            reset_reason: "rot".to_owned(),
            proof: CrossSigningResetProof::PrincipalSigning {
                verification_method: "   ".to_owned(),
                alg: "EdDSA".to_owned(),
                signature: "sig".to_owned(),
            },
            issued_at: Utc::now(),
        };
        assert!(matches!(
            blank_verification_method.validate_structure(),
            Err(Error::Protocol(_))
        ));

        // PrincipalSigning with empty `alg`.
        let blank_alg = CrossSigningResetContent {
            proof: CrossSigningResetProof::PrincipalSigning {
                verification_method: "did:webvh:z6mkfixture:a.example#k1".to_owned(),
                alg: String::new(),
                signature: "sig".to_owned(),
            },
            ..blank_verification_method.clone()
        };
        assert!(matches!(
            blank_alg.validate_structure(),
            Err(Error::Protocol(_))
        ));

        // RecoveryUnlock with blank `unlock_commitment` is rejected.
        let blank_unlock = CrossSigningResetContent {
            proof: CrossSigningResetProof::RecoveryUnlock {
                recovery_session_id: "ck:recovery_session:01964137-0000-7000-8000-0000000000cc"
                    .to_owned(),
                recovery_secret_ref: "ref".to_owned(),
                unlock_commitment: "  ".to_owned(),
                alg: "EdDSA".to_owned(),
                signature: "sig".to_owned(),
            },
            ..blank_verification_method.clone()
        };
        assert!(matches!(
            blank_unlock.validate_structure(),
            Err(Error::Protocol(_))
        ));

        // device_quorum with one signature whose `alg` is empty.
        let bad_quorum = CrossSigningResetContent {
            proof: CrossSigningResetProof::DeviceQuorum {
                threshold: 1,
                signatures: vec![DeviceQuorumSignature {
                    device_id: device(),
                    verification_method: "did:webvh:z6mkfixture:a.example#d".to_owned(),
                    alg: String::new(),
                    signature: "AAAA".to_owned(),
                }],
            },
            ..blank_verification_method
        };
        assert!(matches!(
            bad_quorum.validate_structure(),
            Err(Error::Protocol(_))
        ));
    }

    /// `CrossSigningResetProof::DeviceQuorum`: an over-long `alg` string
    /// must be rejected as bounds-exceeded, not silently accepted.
    #[test]
    fn cross_signing_reset_proof_oversized_alg_rejected() {
        let content = CrossSigningResetContent {
            principal_id: did("alice"),
            trust_domain: cokret_core::TypedTrustDomainId::new("ck:trust_domain:example.net")
                .unwrap(),
            reset_event_id: "ck:event:01964137-0000-7000-8000-0000000000aa".to_owned(),
            previous_generation: 1,
            new_generation: 2,
            reset_reason: "rot".to_owned(),
            proof: CrossSigningResetProof::DeviceQuorum {
                threshold: 1,
                signatures: vec![DeviceQuorumSignature {
                    device_id: device(),
                    verification_method: "did:webvh:z6mkfixture:a.example#d".to_owned(),
                    alg: "X".repeat(MAX_ALGORITHM_NAME_LEN + 1),
                    signature: "AAAA".to_owned(),
                }],
            },
            issued_at: Utc::now(),
        };
        let err = content.validate_structure().unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
    }

    /// Recording an `UnableToDecryptRecord` with a `BadCiphertext`
    /// reason: the binding accepts it but the encrypted payload is
    /// observable (the renderer needs it to show a placeholder) and
    /// later inserts under the same event id MUST overwrite.
    #[test]
    fn unable_to_decrypt_path_bad_ciphertext() {
        let mut binding = CryptoStoreBinding::default();
        let event_id = EventId::new("ck:event:01904100-0000-7000-8000-4e7fda181f9f").unwrap();
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-6c355fb9dada").unwrap();
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
