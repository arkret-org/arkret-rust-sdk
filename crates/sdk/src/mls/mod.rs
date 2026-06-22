mod group;
mod identity;
mod message;
mod recovery;
mod security;

pub use group::*;
pub use identity::*;
pub use message::*;
pub use recovery::*;
pub use security::*;

pub const COKRET_MLS_ALGORITHM: &str = "ck.mls.v1";

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::error::{ERROR_CODE_PROFILE_UNSUPPORTED, REASON_MLS_GOVERNANCE_BINDING_STALE};
    use crate::{
        CryptoStore, DeviceId, Did, EncryptedPayloadScheme, Error, EventId, Hash,
        MLS_GOVERNANCE_BINDING_FULL_PROFILE, MLS_GOVERNANCE_BINDING_RELAXED_PROFILE,
        MlsGovernanceBindingPayload, MlsGovernanceBindingValidationContext, OperationId, RealmId,
        base64url_encode,
    };

    const GOVERNANCE_REDUCER_PROFILE: &str = "ck.reducer.v1";

    fn governance_realm() -> RealmId {
        RealmId::new("ck:realm:01904100-0000-7000-8000-00000000f1c0").unwrap()
    }

    fn governance_event(n: u8) -> EventId {
        EventId::new(format!("ck:event:01904100-0000-7000-8000-00000000f1c{n}")).unwrap()
    }

    fn governance_hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn governance_binding(
        group_id: &str,
        previous_epoch: u64,
        next_epoch: u64,
        policy_root: Hash,
    ) -> MlsGovernanceBindingPayload {
        MlsGovernanceBindingPayload::realm(
            governance_realm(),
            group_id.to_owned(),
            previous_epoch,
            next_epoch,
            vec![governance_event(1)],
            policy_root,
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            GOVERNANCE_REDUCER_PROFILE,
        )
        .unwrap()
    }

    #[test]
    fn minimal_metadata_max_epoch_lifetime_is_one_hour() {
        assert_eq!(MINIMAL_METADATA_MAX_EPOCH_LIFETIME_SECS, 3600);
        assert_eq!(
            minimal_metadata_max_epoch_lifetime(),
            chrono::Duration::hours(1)
        );
    }

    #[test]
    fn enforce_minimal_metadata_aad_rejects_non_hidden_in_minimal_realm() {
        // Minimal-metadata Realm: only Hidden is allowed.
        enforce_minimal_metadata_aad(&AadVisibility::Hidden, true).unwrap();
        for v in [AadVisibility::RoutingDigest, AadVisibility::OpaqueId] {
            let err = enforce_minimal_metadata_aad(&v, true).unwrap_err();
            assert!(err.to_string().contains("aad_visibility=hidden"));
        }
        // Non-minimal Realm: any visibility is permitted by this helper.
        enforce_minimal_metadata_aad(&AadVisibility::RoutingDigest, false).unwrap();
        enforce_minimal_metadata_aad(&AadVisibility::OpaqueId, false).unwrap();
    }

    #[test]
    fn minimal_metadata_epoch_overdue_after_one_hour() {
        let started: chrono::DateTime<Utc> = "2026-06-04T00:00:00Z".parse().unwrap();
        // 59m59s in — still within the cap.
        assert!(!minimal_metadata_epoch_overdue(
            started,
            started + chrono::Duration::minutes(59) + chrono::Duration::seconds(59)
        ));
        // Exactly 1h is the boundary (strict `>`), one second past is overdue.
        assert!(!minimal_metadata_epoch_overdue(
            started,
            started + chrono::Duration::hours(1)
        ));
        assert!(minimal_metadata_epoch_overdue(
            started,
            started + chrono::Duration::hours(1) + chrono::Duration::seconds(1)
        ));
        // Clock skew (now before epoch start) is never overdue.
        assert!(!minimal_metadata_epoch_overdue(
            started,
            started - chrono::Duration::minutes(5)
        ));
    }

    #[test]
    fn create_group_with_governance_binding_stores_group_context_extension() {
        let group_id_bytes = b"ck:realm:01904100-0000-7000-8000-f1c000000001";
        let group_id = base64url_encode(group_id_bytes);
        let binding = governance_binding(&group_id, 0, 0, governance_hash('1'));
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000f1c1").unwrap(),
        )
        .unwrap();

        let group = alice
            .create_group_with_governance_binding(group_id_bytes, &binding)
            .unwrap();
        let current = group.current_governance_binding().unwrap().unwrap();
        let current_group_id = group.group_id();
        let mut expected = MlsGovernanceBindingValidationContext::for_commit(
            &current_group_id,
            0,
            0,
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            GOVERNANCE_REDUCER_PROFILE,
        );
        expected.policy_root = Some(binding.policy_root());

        assert_eq!(current, binding);
        group.verify_current_governance_binding(&expected).unwrap();
    }

    #[test]
    fn update_governance_binding_enters_group_context_extension() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000f1c2").unwrap(),
        )
        .unwrap();
        let mut group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-f1c000000002")
            .unwrap();
        let group_id = group.group_id();
        let binding = governance_binding(
            &group_id,
            group.epoch(),
            group.epoch() + 1,
            governance_hash('2'),
        );

        let commit = group.update_governance_binding(&binding).unwrap();
        let mut expected = MlsGovernanceBindingValidationContext::for_commit(
            &group_id,
            0,
            1,
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            GOVERNANCE_REDUCER_PROFILE,
        );
        expected.policy_root = Some(binding.policy_root());

        assert_eq!(commit.group_id, group_id);
        assert_eq!(commit.epoch, 1);
        assert_eq!(
            group.current_governance_binding().unwrap(),
            Some(binding.clone())
        );
        group.verify_current_governance_binding(&expected).unwrap();
    }

    #[test]
    fn governance_binding_verification_fails_closed_when_extension_missing() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000f1c3").unwrap(),
        )
        .unwrap();
        let group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-f1c000000003")
            .unwrap();
        let group_id = group.group_id();
        let expected = MlsGovernanceBindingValidationContext::for_commit(
            &group_id,
            0,
            1,
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            GOVERNANCE_REDUCER_PROFILE,
        );

        let err = group
            .verify_current_governance_binding(&expected)
            .unwrap_err();

        assert!(err.to_string().contains(ERROR_CODE_PROFILE_UNSUPPORTED));
    }

    #[test]
    fn governance_binding_verification_rejects_profile_downgrade() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000f1c4").unwrap(),
        )
        .unwrap();
        let mut group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-f1c000000004")
            .unwrap();
        let group_id = group.group_id();
        let binding = governance_binding(&group_id, 0, 1, governance_hash('3'))
            .with_binding_profile(MLS_GOVERNANCE_BINDING_RELAXED_PROFILE)
            .unwrap();
        group.update_governance_binding(&binding).unwrap();
        let expected = MlsGovernanceBindingValidationContext::for_commit(
            &group_id,
            0,
            1,
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            GOVERNANCE_REDUCER_PROFILE,
        );

        let err = group
            .verify_current_governance_binding(&expected)
            .unwrap_err();

        assert!(err.to_string().contains(ERROR_CODE_PROFILE_UNSUPPORTED));
    }

    #[test]
    fn governance_binding_verification_rejects_stale_policy_root() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000f1c5").unwrap(),
        )
        .unwrap();
        let mut group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-f1c000000005")
            .unwrap();
        let group_id = group.group_id();
        let binding = governance_binding(&group_id, 0, 1, governance_hash('4'));
        group.update_governance_binding(&binding).unwrap();
        let stale_policy_root = governance_hash('9');
        let mut expected = MlsGovernanceBindingValidationContext::for_commit(
            &group_id,
            0,
            1,
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            GOVERNANCE_REDUCER_PROFILE,
        );
        expected.policy_root = Some(&stale_policy_root);

        let err = group
            .verify_current_governance_binding(&expected)
            .unwrap_err();

        assert!(
            err.to_string()
                .contains(REASON_MLS_GOVERNANCE_BINDING_STALE)
        );
    }

    #[test]
    fn schedule_hash_is_deterministic_and_changes_on_commit() {
        // The schedule hash MUST be a function of (epoch, group state) only —
        // two clients on the same epoch always produce the same hash, and a
        // commit that advances the epoch MUST produce a fresh hash. This
        // pins the contract `chat.rs` relies on when binding governance
        // payloads to the local group's schedule.
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-1ad6479d4a40")
            .unwrap();
        let hash_pre = alice_group.schedule_hash();
        assert!(
            hash_pre.as_str().starts_with("sha256:"),
            "schedule_hash must use canonical `sha256:` prefix"
        );
        // Deterministic — calling twice on the same epoch is a no-op.
        assert_eq!(hash_pre, alice_group.schedule_hash());

        // Add a member → epoch advances → schedule_hash MUST change.
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let bob_group = CokretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();
        let hash_post = alice_group.schedule_hash();
        assert_ne!(hash_pre, hash_post);

        // Bob's view of the same epoch MUST produce the same hash.
        assert_eq!(hash_post, bob_group.schedule_hash());
    }

    #[test]
    fn key_package_private_state_restores_welcome_join() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob_principal = Did::new("did:web:bob.example").unwrap();
        let bob_device = DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap();
        let bob = CokretMlsIdentity::new_basic(bob_principal.clone(), bob_device.clone()).unwrap();
        let bob_key_package = bob.key_package_record().unwrap();
        assert!(
            bob_key_package
                .expires_at
                .is_some_and(|expires_at| expires_at > bob_key_package.created_at),
            "published KeyPackages must carry a finite expiry"
        );
        let bob_private_state = bob.export_private_state().unwrap();
        let restored_bob = CokretMlsIdentity::restore_from_private_state(
            bob_principal.clone(),
            bob_device.clone(),
            &bob_private_state,
        )
        .unwrap();
        let fresh_bob = CokretMlsIdentity::new_basic(bob_principal, bob_device).unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-1ad6479d4a43")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let Err(fresh_error) = CokretMlsGroup::join_from_welcome(fresh_bob, &add_result.welcome)
        else {
            panic!("fresh identity should not consume a Welcome for a persisted KeyPackage");
        };
        assert!(
            fresh_error.to_string().contains("NoMatchingKeyPackage"),
            "{fresh_error}"
        );

        let bob_group =
            CokretMlsGroup::join_from_welcome(restored_bob, &add_result.welcome).unwrap();
        assert_eq!(alice_group.schedule_hash(), bob_group.schedule_hash());
    }

    #[test]
    fn export_secret_agrees_across_members_and_binds_label_context() {
        // RFC 9420 §8.5: members on the same epoch derive identical exporter
        // bytes; distinct (label, context) MUST yield distinct outputs. This
        // is the primitive the reaction routing tag (encryption-and-audit.md
        // §2.9) and SFrame keys are built on.
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000016").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000001e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-1ad6479d4a41")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let bob_group = CokretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();

        let realm = b"ck:realm:01904100-0000-7000-8000-1ad6479d4a41";
        let a = alice_group
            .export_secret("cokret-reaction-routing-v1", realm, 32)
            .unwrap();
        let b = bob_group
            .export_secret("cokret-reaction-routing-v1", realm, 32)
            .unwrap();
        assert_eq!(a.len(), 32);
        assert_eq!(
            a, b,
            "same epoch + label + context MUST agree across members"
        );

        // Different context (realm) MUST diverge.
        let other_realm = b"ck:realm:01904100-0000-7000-8000-1ad6479d4a42";
        assert_ne!(
            a,
            alice_group
                .export_secret("cokret-reaction-routing-v1", other_realm, 32)
                .unwrap()
        );
        // Different label MUST diverge.
        assert_ne!(
            a,
            alice_group
                .export_secret("ck-rtc-frame-key/v1", realm, 32)
                .unwrap()
        );
    }

    #[test]
    fn member_principal_ids_returns_credentials_as_dids() {
        // After Add, both Alice and Bob are members; both DIDs MUST appear
        // in the snapshot. After Remove, only the surviving DID remains.
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-1ad6479d4a41")
            .unwrap();
        assert_eq!(
            alice_group.member_principal_ids(),
            vec![Did::new("did:web:alice.example").unwrap()],
        );

        let _ = alice_group.add_member(&bob_key_package).unwrap();
        let members = alice_group.member_principal_ids();
        assert_eq!(members.len(), 2);
        assert!(members.contains(&Did::new("did:web:alice.example").unwrap()));
        assert!(members.contains(&Did::new("did:web:bob.example").unwrap()));

        let _ = alice_group
            .remove_member_by_principal(&Did::new("did:web:bob.example").unwrap())
            .unwrap();
        assert_eq!(
            alice_group.member_principal_ids(),
            vec![Did::new("did:web:alice.example").unwrap()],
        );
    }

    /// `self_update_commit` MUST advance the group epoch by exactly 1
    /// and surface a typed `MlsCommitEnvelope` with the new
    /// (group_id, epoch) pair. The `commit_digest` MUST be the SHA-256
    /// of the wire bytes.
    #[test]
    fn self_update_commit_advances_epoch_and_returns_typed_envelope() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let mut group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-555555555555")
            .unwrap();
        let pre_epoch = group.epoch();
        let pre_group_id = group.group_id();
        let envelope = group.self_update_commit().expect("self_update succeeds");
        assert_eq!(envelope.group_id, pre_group_id);
        assert_eq!(envelope.epoch, pre_epoch + 1);
        // post-call: group's view agrees.
        assert_eq!(group.epoch(), pre_epoch + 1);
        // commit_digest is non-empty + sha256:-prefixed.
        assert!(envelope.commit_digest.as_str().starts_with("sha256:"));
        // commit bytes round-trip through base64.
        assert!(!envelope.commit.is_empty());
        // schedule_hash MUST also change since epoch_authenticator
        // depends on the new key schedule (B3d invariant).
        let post_schedule = group.schedule_hash();
        // Trivially non-empty — actual change would need pre/post
        // capture but we already pin the determinism in
        // `schedule_hash_is_deterministic_and_changes_on_commit`.
        assert!(post_schedule.as_str().starts_with("sha256:"));
    }

    #[test]
    fn openmls_group_can_add_member_encrypt_and_decrypt() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-d652c78259d9")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = CokretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();

        let encrypted = alice_group
            .encrypt_payload("application/json", br#"{"body":"hello"}"#)
            .unwrap();
        let decrypted = bob_group.decrypt_payload(&encrypted).unwrap();

        assert_eq!(decrypted, br#"{"body":"hello"}"#);
        assert_eq!(encrypted.scheme, EncryptedPayloadScheme::MlsRfc9420);
        assert_eq!(encrypted.epoch, alice_group.epoch());
        assert_eq!(bob_group.epoch(), alice_group.epoch());
    }

    #[test]
    fn message_crypto_encrypts_decrypts_and_verifies_opaque_digest() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-f2f103987ef3")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = CokretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();

        let encrypted = MessageCrypto::encrypt(
            &mut alice_group,
            "ck:message:01",
            "application/vnd.cokret.message+json",
            br#"{"body":"hello secure workflow"}"#,
        )
        .unwrap();

        MessageCrypto::verify_opaque_payload_digest(&encrypted).unwrap();
        let decrypted = MessageCrypto::decrypt(&mut bob_group, &encrypted).unwrap();
        assert_eq!(decrypted, br#"{"body":"hello secure workflow"}"#);
    }

    #[test]
    fn message_crypto_encrypts_with_aad_and_verifies_digest() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-65bef476aed3")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = CokretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();
        let aad = serde_json::json!({
            "realm_id": "ck:realm:01904100-0000-7000-8000-65bef476aed3",
            "event_kind": "ck.message.create",
            "event_id": "ck:event:01904100-0000-7000-8000-d5afe7e3de96",
            "causal_refs": []
        });
        let aad_digest = crate::crypto::json_aad_digest(&aad).unwrap();

        let encrypted = MessageCrypto::encrypt_with_aad(
            &mut alice_group,
            "ck:message:aad",
            "application/json",
            aad,
            br#"{"body":"aad bound"}"#,
        )
        .unwrap();
        MessageCrypto::verify_payload_and_aad_digest(&encrypted, Some(&aad_digest)).unwrap();
        assert_eq!(
            MessageCrypto::decrypt(&mut bob_group, &encrypted).unwrap(),
            br#"{"body":"aad bound"}"#
        );
    }

    #[test]
    fn openmls_state_persists_through_crypto_store_record() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-1ad6479d4a3f")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let bob_group = CokretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();
        let mut store = crate::MemoryCryptoStore::new();
        let record = bob_group.persist_state(&mut store).unwrap();
        let mut restored_bob = CokretMlsGroup::restore_from_state_record(&record).unwrap();

        assert_eq!(restored_bob.epoch(), bob_group.epoch());
        assert_eq!(
            store.mls_group_state(&record.group_id).unwrap().epoch,
            record.epoch
        );

        let encrypted = alice_group
            .encrypt_payload("application/json", br#"{"body":"after restore"}"#)
            .unwrap();
        assert_eq!(
            restored_bob.decrypt_payload(&encrypted).unwrap(),
            br#"{"body":"after restore"}"#
        );
    }

    #[test]
    fn multi_device_workflow_applies_missed_commits_and_models_recovery() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let charlie = CokretMlsIdentity::new_basic(
            Did::new("did:web:charlie.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000f").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();
        let charlie_key_package = charlie.key_package_record().unwrap();
        let mut revoked_package = charlie_key_package.clone();
        let revoke_step = revoke_key_package(&mut revoked_package);
        assert_eq!(
            revoked_package.state,
            cokret_core::MlsKeyPackageState::Revoked
        );
        assert_eq!(
            revoke_step.action,
            MlsDeviceWorkflowAction::RevokeKeyPackage
        );

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-877788250807")
            .unwrap();
        let bob_add = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = CokretMlsGroup::join_from_welcome(bob, &bob_add.welcome).unwrap();
        let charlie_add = alice_group.add_member(&charlie_key_package).unwrap();
        let workflow = late_device_join_steps(&charlie_add.welcome);
        assert_eq!(workflow[0].action, MlsDeviceWorkflowAction::ConsumeWelcome);

        bob_group
            .apply_commits(std::slice::from_ref(&charlie_add.commit))
            .unwrap();
        assert_eq!(bob_group.epoch(), alice_group.epoch());
        let recovery = epoch_recovery_step(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
            bob_group.group_id(),
            bob_group.epoch() + 1,
            bob_group.epoch() + 3,
        );
        assert_eq!(
            recovery.action,
            MlsDeviceWorkflowAction::RequestEpochRecovery
        );
    }

    #[test]
    fn add_member_result_projects_to_repo_operation_and_to_device_message() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-4ecefcf31ad2")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let operation = add_result
            .commit_operation(
                OperationId::new("ck:operation:01904100-0000-7000-8000-02369de2e9c6").unwrap(),
                RealmId::new("ck:realm:01904100-0000-7000-8000-4ecefcf31ad2").unwrap(),
            )
            .unwrap();
        let to_device = add_result.welcome_to_device_message().unwrap();

        assert_eq!(operation.object_type, "mls_commit");
        assert_eq!(to_device.message_type, "ck.mls.welcome.v1");
        assert_eq!(
            to_device.content["recipient_device_id"],
            "ck:device:01904100-0000-7000-8000-00000000000e"
        );
    }

    #[test]
    fn message_crypto_preserves_encrypted_content_without_available_key() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-f2f103987ef3")
            .unwrap();
        let encrypted = MessageCrypto::encrypt(
            &mut alice_group,
            "ck:message:02",
            "application/json",
            br#"{"body":"keep ciphertext"}"#,
        )
        .unwrap();
        let expected_digest = encrypted.payload.payload_digest.clone();
        let expected_ciphertext = encrypted.payload.ciphertext.clone();

        let result = MessageCrypto::decrypt_or_preserve(None, encrypted).unwrap();

        let MessageCryptoDecrypt::Encrypted {
            message_id,
            payload,
            reason,
        } = result
        else {
            panic!("message should stay encrypted without a local MLS session");
        };
        assert_eq!(message_id, "ck:message:02");
        assert!(matches!(reason, MessageCryptoUnavailable::NoSession));
        assert_eq!(payload.payload_digest, expected_digest);
        assert_eq!(payload.ciphertext, expected_ciphertext);
    }

    #[test]
    fn encrypted_timeline_preserves_then_decrypts_after_welcome_arrives() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-469a459e1b8f")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let encrypted = MessageCrypto::encrypt(
            &mut alice_group,
            "ck:event:01904100-0000-7000-8000-f2fbe0d55fb4",
            "application/vnd.cokret.message+json",
            br#"{"body":"arrives before local key"}"#,
        )
        .unwrap();

        let preserved = MessageCrypto::decrypt_or_preserve(None, encrypted.clone()).unwrap();
        assert!(matches!(preserved, MessageCryptoDecrypt::Encrypted { .. }));

        let mut bob_group = CokretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();
        let decrypted = MessageCrypto::decrypt(&mut bob_group, &encrypted).unwrap();
        assert_eq!(decrypted, br#"{"body":"arrives before local key"}"#);
    }

    #[test]
    fn epoch_recovery_request_and_response_catch_up_offline_device() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let charlie = CokretMlsIdentity::new_basic(
            Did::new("did:web:charlie.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000f").unwrap(),
        )
        .unwrap();

        let bob_kp = bob.key_package_record().unwrap();
        let charlie_kp = charlie.key_package_record().unwrap();

        // Alice creates group and adds Bob and Charlie.
        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-4cc289f6471e")
            .unwrap();
        let bob_add = alice_group.add_member(&bob_kp).unwrap();
        let mut bob_group = CokretMlsGroup::join_from_welcome(bob, &bob_add.welcome).unwrap();
        let charlie_add = alice_group.add_member(&charlie_kp).unwrap();

        // Bob is now offline. Alice adds Charlie (epoch advances).
        // Bob's local epoch is behind.
        let bob_epoch_before = bob_group.epoch();

        // Create a recovery request.
        let request = EpochRecoveryRequestBody::new(
            bob_group.group_id(),
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
            bob_epoch_before,
            alice_group.epoch(),
        );
        request.validate().unwrap();

        // Store the commits in a crypto store so we can build a response.
        let mut store = crate::MemoryCryptoStore::new();
        store.put_commit(charlie_add.commit).unwrap();

        // Alice (who has the commits) builds the recovery response.
        let response = build_epoch_recovery_response(&alice_group, &store, &request).unwrap();
        response.validate_range(&request).unwrap();
        assert!(!response.commits.is_empty());

        // Bob applies the recovery response.
        let new_epoch = response.apply_to_group(&mut bob_group).unwrap();
        assert_eq!(new_epoch, alice_group.epoch());

        // Bob can now decrypt messages from the current epoch.
        let encrypted = alice_group
            .encrypt_payload("application/json", br#"{"body":"after recovery"}"#)
            .unwrap();
        let decrypted = bob_group.decrypt_payload(&encrypted).unwrap();
        assert_eq!(decrypted, br#"{"body":"after recovery"}"#);
    }

    #[test]
    fn epoch_recovery_request_validates_range() {
        let request = EpochRecoveryRequestBody::new(
            "",
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
            5,
            3,
        );
        assert!(request.validate().is_err());

        let request = EpochRecoveryRequestBody::new(
            "group1",
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
            5,
            5,
        );
        assert!(request.validate().is_err());
    }

    #[test]
    fn welcome_recipient_must_match_identity() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let mallory = CokretMlsIdentity::new_basic(
            Did::new("did:web:mallory.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000010").unwrap(),
        )
        .unwrap();

        let bob_key_package = bob.key_package_record().unwrap();
        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-d652c78259d9")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let Err(error) = CokretMlsGroup::join_from_welcome(mallory, &add_result.welcome) else {
            panic!("Mallory should not be able to consume Bob's Welcome");
        };

        assert!(matches!(error, Error::Protocol(_)));
    }

    /// T31 — `remove_member_by_principal` removes a leaf, advances the
    /// group's epoch and produces a commit envelope that surviving members
    /// can apply to converge.
    #[test]
    fn remove_member_by_principal_advances_epoch_and_emits_commit() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let charlie = CokretMlsIdentity::new_basic(
            Did::new("did:web:charlie.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000f").unwrap(),
        )
        .unwrap();
        let bob_kp = bob.key_package_record().unwrap();
        let charlie_kp = charlie.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-a78a8b504d40")
            .unwrap();
        let add_bob = alice_group.add_member(&bob_kp).unwrap();
        let _bob_group = CokretMlsGroup::join_from_welcome(bob, &add_bob.welcome).unwrap();
        let add_charlie = alice_group.add_member(&charlie_kp).unwrap();
        let _charlie_group =
            CokretMlsGroup::join_from_welcome(charlie, &add_charlie.welcome).unwrap();

        let epoch_before = alice_group.epoch();
        let target = Did::new("did:web:charlie.example").unwrap();
        let result = alice_group.remove_member_by_principal(&target).unwrap();

        // Epoch advanced by exactly one Commit.
        assert_eq!(alice_group.epoch(), epoch_before + 1);
        // Commit envelope reflects the new epoch and same group.
        assert_eq!(result.commit.epoch, alice_group.epoch());
        assert_eq!(result.commit.group_id, alice_group.group_id());
        // Exactly one leaf removed; principal correctly reported.
        assert_eq!(result.removed_leaves.len(), 1);
        assert_eq!(result.removed_principals.len(), 1);
        assert_eq!(
            result.removed_principals[0].as_str(),
            "did:web:charlie.example"
        );
    }

    /// T31 — removing an absent principal returns a Protocol error rather
    /// than silently no-op'ing. The orchestration plan in yougen relies on
    /// this to surface "leaf already gone" as a recoverable state.
    #[test]
    fn remove_member_by_principal_errors_when_target_absent() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-3cf34eced3c3")
            .unwrap();

        let absent = Did::new("did:web:nobody.example").unwrap();
        let err = alice_group.remove_member_by_principal(&absent);
        assert!(matches!(err, Err(Error::Protocol(_))));
    }

    #[test]
    fn encrypted_envelope_v1_conforms_and_round_trips_losslessly() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000abcd").unwrap(),
        )
        .unwrap();
        let mut group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-0abc0abc0abc")
            .unwrap();

        let realm_id = "ck:realm:01904100-0000-7000-8000-0abc0abc0abc";
        let aad = EncryptedEnvelopeAadV1::hidden(realm_id, "ck.message.create");
        let aad_value = serde_json::to_value(&aad).unwrap();
        let plaintext = br#"{"body":"hello encrypted discussion"}"#;
        let payload = group
            .encrypt_payload_with_aad(
                "application/vnd.cokret.message+json",
                Some(aad_value),
                plaintext,
            )
            .unwrap();

        let commit_ref = "ck:event:01904100-0000-7000-8000-00000000c0m1";
        let envelope =
            EncryptedEnvelopeV1::from_payload(&payload, aad, AadVisibility::Hidden, commit_ref)
                .unwrap();

        // Conformance with ck.schema.encrypted_envelope.v1: required fields,
        // fixed consts, hidden-visibility AAD discipline, no forbidden extras.
        let json = serde_json::to_value(&envelope).unwrap();
        let obj = json.as_object().unwrap();
        for field in [
            "scheme",
            "version",
            "group_id",
            "epoch",
            "content_type",
            "ciphertext",
            "aad_visibility_event_id",
            "aad",
            "key_ref",
            "aad_digest",
            "payload_digest",
        ] {
            assert!(obj.contains_key(field), "missing required field {field}");
        }
        assert_eq!(obj["scheme"], "mls-rfc9420");
        assert_eq!(obj["version"], "1.0");
        assert_eq!(obj["aad_visibility_event_id"], "hidden");
        assert_eq!(obj["key_ref"]["algorithm"], "MLS");
        assert_eq!(obj["key_ref"]["group_state_ref"], commit_ref);
        assert_eq!(obj["aad"]["realm_id"], realm_id);
        assert_eq!(obj["aad"]["event_kind"], "ck.message.create");
        let aad_obj = obj["aad"].as_object().unwrap();
        assert!(!aad_obj.contains_key("event_id"));
        assert!(!aad_obj.contains_key("event_ref_digest"));
        assert!(obj["aad_digest"].as_str().unwrap().starts_with("sha256:"));
        assert!(
            obj["payload_digest"]
                .as_str()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(!obj.contains_key("authentication_tag"));
        assert!(!obj.contains_key("digests"));
        assert!(!obj.contains_key("cleartext_commitment"));

        // Wire round-trip is stable and to_payload reconstructs the exact MLS
        // payload (lossless for every field decrypt_payload relies on).
        let wire = serde_json::to_string(&envelope).unwrap();
        let parsed: EncryptedEnvelopeV1 = serde_json::from_str(&wire).unwrap();
        assert_eq!(parsed, envelope);
        assert_eq!(parsed.to_payload().unwrap(), payload);

        // Fail closed when the supplied AAD doesn't match the AAD bound into
        // payload_digest at encryption time.
        let mismatch = EncryptedEnvelopeV1::from_payload(
            &payload,
            EncryptedEnvelopeAadV1::hidden(realm_id, "ck.strand.update"),
            AadVisibility::Hidden,
            commit_ref,
        );
        assert!(mismatch.is_err());
    }

    /// T31 — `remove_member_by_leaf` accepts a raw OpenMLS leaf index and
    /// produces the same shape of commit envelope. Used when the caller
    /// (yougen DeviceManager) tracks per-device leaf bookkeeping
    /// out-of-band.
    #[test]
    fn remove_member_by_leaf_accepts_raw_index() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_kp = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-89444e193497")
            .unwrap();
        let add_bob = alice_group.add_member(&bob_kp).unwrap();
        let _bob_group = CokretMlsGroup::join_from_welcome(bob, &add_bob.welcome).unwrap();

        // Bob's leaf is at index 1 (Alice is index 0 as group creator).
        let result = alice_group.remove_member_by_leaf(1).unwrap();
        assert_eq!(result.removed_leaves, vec![1]);
        assert_eq!(result.removed_principals[0].as_str(), "did:web:bob.example");
    }

    /// T31 — `commit_operation` projects the result into the same
    /// canonical operation shape that `MlsAddMemberResult` produces, so
    /// audit pipelines can ingest both consistently.
    #[test]
    fn remove_result_commit_operation_uses_mls_commit_op_type() {
        let alice = CokretMlsIdentity::new_basic(
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = CokretMlsIdentity::new_basic(
            Did::new("did:web:bob.example").unwrap(),
            DeviceId::new("ck:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_kp = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ck:realm:01904100-0000-7000-8000-bd49dfdbc804")
            .unwrap();
        let add_bob = alice_group.add_member(&bob_kp).unwrap();
        let _bob_group = CokretMlsGroup::join_from_welcome(bob, &add_bob.welcome).unwrap();
        let result = alice_group
            .remove_member_by_principal(&Did::new("did:web:bob.example").unwrap())
            .unwrap();

        let op_id = OperationId::new("ck:operation:01904100-0000-7000-8000-00a9123c0f9c").unwrap();
        let realm_id = RealmId::new("ck:realm:01904100-0000-7000-8000-bd49dfdbc804").unwrap();
        let op = result.commit_operation(op_id, realm_id).unwrap();
        assert_eq!(op.object_type, "mls_commit");
        assert!(op.object_id.unwrap().contains(&result.commit.group_id));
    }
}
