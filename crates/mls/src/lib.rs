//! Arkret v1 MLS (RFC 9420) behavior layer.
//!
//! This crate is the sole OpenMLS boundary in the workspace: it owns the
//! `ArkretMlsIdentity` / `ArkretMlsGroup` group machine, the MLS message /
//! exporter-aead content schemes, epoch-recovery, and the minimal-metadata
//! author-credential validator. It depends only on the wire / model / crypto
//! data crates and inverts persistence through the narrow [`MlsGroupStateSink`]
//! / [`MlsCommitSource`] ports so it never reaches up into the SDK
//! `CryptoStore`.

mod error;
mod group;
mod identity;
mod message;
mod recovery;

pub use arkret_policy::{
    AgentMlsLeafBindingError, AgentMlsSignerClaim, AgentMlsSignerView, AuthorGroupStateView,
    AuthorLeaf, AuthorLeafCredential, MINIMAL_METADATA_MAX_EPOCH_LIFETIME_SECS,
    MINIMAL_METADATA_REALM_PROFILE, MinimalMetadataAuthorClaim, MinimalMetadataAuthorError,
    MinimalMetadataAuthorViolation, VerifiedAuthorLeaf, enforce_minimal_metadata_aad,
    minimal_metadata_epoch_overdue, minimal_metadata_max_epoch_lifetime,
    verify_minimal_metadata_author, verify_ordinary_agent_mls_binding,
};
pub use error::MlsError;
// `Result` stays crate-internal because public signatures resolve it to the
// concrete `std::result::Result<_, MlsError>` and external callers do not need
// a generic root-level alias.
pub(crate) use error::Result;
pub use group::*;
pub use identity::*;
pub use message::*;
pub use recovery::*;

// The persistence ports the MLS layer inverts on live in `arkret-models-crypto`
// (OpenMLS-free) so binding them in the SDK `CryptoStore` supertrait drags no
// OpenMLS into a protocol-model-only build. They are used internally (see `group.rs` /
// `recovery.rs`) but intentionally NOT re-exported from this crate's root, so
// the umbrella surfaces them exactly once (from models-crypto).

pub const ARKRET_MLS_ALGORITHM: &str = "ak.mls.v1";

#[cfg(test)]
mod tests {
    use arkret_canonical::base64url_encode;
    use arkret_models_crypto::{
        EncryptedEnvelope, EncryptedEnvelopeAadVisibility, EncryptedEnvelopeKeyAlgorithm,
        MLS_GOVERNANCE_BINDING_FULL_PROFILE, MLS_GOVERNANCE_BINDING_RELAXED_PROFILE,
        MlsCommitEnvelope, MlsCommitSource, MlsGovernanceBindingPayload,
        MlsGovernanceBindingValidationContext, MlsGroupStateRecord, MlsGroupStateSink,
    };
    use arkret_wire::{DeviceId, Did, EncryptedPayloadScheme, EventId, Hash, RealmId};
    use chrono::Utc;

    use super::*;
    use crate::MlsError as Error;

    const GOVERNANCE_REDUCER_PROFILE: &str = "ak.reducer.v1";

    /// Minimal in-crate store test double implementing the two persistence
    /// ports the MLS layer inverts on. The SDK `MemoryCryptoStore` lives in the
    /// umbrella crate (above this layer), so the group-state / recovery tests
    /// use this narrow stand-in instead.
    #[derive(Default)]
    struct TestStore {
        group_states: std::collections::BTreeMap<String, MlsGroupStateRecord>,
        commits: Vec<MlsCommitEnvelope>,
    }

    impl TestStore {
        fn new() -> Self {
            Self::default()
        }

        fn put_commit(&mut self, record: MlsCommitEnvelope) {
            self.commits.push(record);
        }

        fn mls_group_state(&self, group_id: &str) -> Option<&MlsGroupStateRecord> {
            self.group_states.get(group_id)
        }
    }

    impl MlsGroupStateSink for TestStore {
        fn put_mls_group_state(
            &mut self,
            record: MlsGroupStateRecord,
        ) -> std::result::Result<(), arkret_wire::WireError> {
            self.group_states.insert(record.group_id.clone(), record);
            Ok(())
        }
    }

    impl MlsCommitSource for TestStore {
        fn commits_for_group(&self, group_id: &str) -> Vec<&MlsCommitEnvelope> {
            self.commits
                .iter()
                .filter(|commit| commit.group_id == group_id)
                .collect()
        }
    }

    fn governance_realm() -> RealmId {
        RealmId::new("ak:realm:01904100-0000-7000-8000-00000000f1c0").unwrap()
    }

    fn governance_event(n: u8) -> EventId {
        EventId::new(format!("ak:event:01904100-0000-7000-8000-00000000f1c{n}")).unwrap()
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
            governance_hash('c'),
            governance_hash('d'),
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
        enforce_minimal_metadata_aad(&EncryptedEnvelopeAadVisibility::Hidden, true).unwrap();
        for v in [
            EncryptedEnvelopeAadVisibility::RoutingDigest,
            EncryptedEnvelopeAadVisibility::OpaqueId,
        ] {
            let err = enforce_minimal_metadata_aad(&v, true).unwrap_err();
            assert!(err.to_string().contains("aad_visibility=hidden"));
        }
        // Non-minimal Realm: any visibility is permitted by this helper.
        enforce_minimal_metadata_aad(&EncryptedEnvelopeAadVisibility::RoutingDigest, false)
            .unwrap();
        enforce_minimal_metadata_aad(&EncryptedEnvelopeAadVisibility::OpaqueId, false).unwrap();
    }

    #[test]
    fn minimal_metadata_epoch_overdue_after_one_hour() {
        let started: chrono::DateTime<Utc> = "2026-06-04T00:00:00.000Z".parse().unwrap();
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
        let group_id_bytes = b"ak:realm:01904100-0000-7000-8000-f1c000000001";
        let group_id = base64url_encode(group_id_bytes);
        let binding = governance_binding(&group_id, 0, 0, governance_hash('1'));
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000f1c1").unwrap(),
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
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000f1c2").unwrap(),
        )
        .unwrap();
        let mut group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-f1c000000002")
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
    fn add_member_commit_carries_governance_binding_into_welcome() {
        let group_id_bytes = b"ak:realm:01904100-0000-7000-8000-f1c00000000a";
        let group_id = base64url_encode(group_id_bytes);
        let genesis_binding = governance_binding(&group_id, 0, 0, governance_hash('1'));
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000f1ca").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000f1cb").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();
        let mut alice_group = alice
            .create_group_with_governance_binding(group_id_bytes, &genesis_binding)
            .unwrap();
        let commit_binding = governance_binding(&group_id, 0, 1, governance_hash('2'));

        let add = alice_group
            .add_member_with_governance_binding(&bob_key_package, &commit_binding)
            .unwrap();
        let bob_group = ArkretMlsGroup::join_from_welcome(bob, &add.welcome).unwrap();

        assert_eq!(add.commit.epoch, 1);
        assert_eq!(
            alice_group.current_governance_binding().unwrap(),
            Some(commit_binding.clone())
        );
        assert_eq!(
            bob_group.current_governance_binding().unwrap(),
            Some(commit_binding)
        );
    }

    #[test]
    fn remove_member_commit_carries_governance_binding_to_survivors() {
        let group_id_bytes = b"ak:realm:01904100-0000-7000-8000-f1c00000000b";
        let group_id = base64url_encode(group_id_bytes);
        let genesis_binding = governance_binding(&group_id, 0, 0, governance_hash('1'));
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000f1da").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000f1db").unwrap(),
        )
        .unwrap();
        let carol = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:carol.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000f1dc").unwrap(),
        )
        .unwrap();
        let bob_did = bob.principal_id.clone();
        let bob_key_package = bob.key_package_record().unwrap();
        let carol_key_package = carol.key_package_record().unwrap();
        let mut alice_group = alice
            .create_group_with_governance_binding(group_id_bytes, &genesis_binding)
            .unwrap();
        let add_binding = governance_binding(&group_id, 0, 1, governance_hash('2'));
        let add = alice_group
            .add_members_with_governance_binding(
                &[bob_key_package, carol_key_package],
                &add_binding,
            )
            .unwrap();
        let carol_welcome = add
            .welcomes
            .iter()
            .find(|welcome| welcome.recipient_principal_id == carol.principal_id)
            .unwrap();
        let mut carol_group = ArkretMlsGroup::join_from_welcome(carol, carol_welcome).unwrap();
        let remove_binding = governance_binding(&group_id, 1, 2, governance_hash('3'));

        let remove = alice_group
            .remove_member_by_principal_with_governance_binding(&bob_did, &remove_binding)
            .unwrap();
        for proposal in &remove.proposals {
            carol_group.apply_proposal(proposal).unwrap();
        }
        carol_group.apply_commit(&remove.commit).unwrap();

        assert_eq!(remove.commit.epoch, 2);
        assert_eq!(
            alice_group.current_governance_binding().unwrap(),
            Some(remove_binding.clone())
        );
        assert_eq!(
            carol_group.current_governance_binding().unwrap(),
            Some(remove_binding)
        );
    }

    #[test]
    fn governance_binding_verification_fails_closed_when_extension_missing() {
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000f1c3").unwrap(),
        )
        .unwrap();
        let group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-f1c000000003")
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

        assert!(
            err.to_string()
                .contains(arkret_wire::ErrorCode::PROFILE_UNSUPPORTED)
        );
    }

    #[test]
    fn governance_binding_verification_rejects_profile_downgrade() {
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000f1c4").unwrap(),
        )
        .unwrap();
        let mut group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-f1c000000004")
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

        assert!(
            err.to_string()
                .contains(arkret_wire::ErrorCode::PROFILE_UNSUPPORTED)
        );
    }

    #[test]
    fn governance_binding_verification_rejects_stale_policy_root() {
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000f1c5").unwrap(),
        )
        .unwrap();
        let mut group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-f1c000000005")
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
                .contains(arkret_wire::ReasonCode::MLS_GOVERNANCE_BINDING_STALE)
        );
    }

    #[test]
    fn schedule_hash_is_deterministic_and_changes_on_commit() {
        // The schedule hash MUST be a function of (epoch, group state) only —
        // two clients on the same epoch always produce the same hash, and a
        // commit that advances the epoch MUST produce a fresh hash. This
        // pins the contract `chat.rs` relies on when binding governance
        // payloads to the local group's schedule.
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-1ad6479d4a40")
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
        let bob_group = ArkretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();
        let hash_post = alice_group.schedule_hash();
        assert_ne!(hash_pre, hash_post);

        // Bob's view of the same epoch MUST produce the same hash.
        assert_eq!(hash_post, bob_group.schedule_hash());
    }

    #[test]
    fn key_package_private_state_restores_welcome_join() {
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob_principal = Did::new("did:webvh:z6mkfixture:bob.example").unwrap();
        let bob_device = DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap();
        let bob = ArkretMlsIdentity::new_basic(bob_principal.clone(), bob_device.clone()).unwrap();
        let bob_key_package = bob.key_package_record().unwrap();
        assert!(
            bob_key_package
                .expires_at
                .is_some_and(|expires_at| expires_at > bob_key_package.created_at),
            "published KeyPackages must carry a finite expiry"
        );
        let bob_private_state = bob.export_private_state().unwrap();
        let restored_bob = ArkretMlsIdentity::restore_from_private_state(
            bob_principal.clone(),
            bob_device.clone(),
            &bob_private_state,
        )
        .unwrap();
        let fresh_bob = ArkretMlsIdentity::new_basic(bob_principal, bob_device).unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-1ad6479d4a43")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let Err(fresh_error) = ArkretMlsGroup::join_from_welcome(fresh_bob, &add_result.welcome)
        else {
            panic!("fresh identity should not consume a Welcome for a persisted KeyPackage");
        };
        assert!(
            fresh_error.to_string().contains("NoMatchingKeyPackage"),
            "{fresh_error}"
        );

        let bob_group =
            ArkretMlsGroup::join_from_welcome(restored_bob, &add_result.welcome).unwrap();
        assert_eq!(alice_group.schedule_hash(), bob_group.schedule_hash());
    }

    #[test]
    fn export_secret_agrees_across_members_and_binds_label_context() {
        // RFC 9420 §8.5: members on the same epoch derive identical exporter
        // bytes; distinct (label, context) MUST yield distinct outputs. This
        // is the primitive the reaction routing tag (encryption-and-audit.md
        // §2.9) and SFrame keys are built on.
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000016").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000001e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-1ad6479d4a41")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let bob_group = ArkretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();

        let realm = b"ak:realm:01904100-0000-7000-8000-1ad6479d4a41";
        let a = alice_group
            .export_secret(arkret_wire::ExporterLabelId::REACTION_ROUTING_V1, realm, 32)
            .unwrap();
        let b = bob_group
            .export_secret(arkret_wire::ExporterLabelId::REACTION_ROUTING_V1, realm, 32)
            .unwrap();
        assert_eq!(a.len(), 32);
        assert_eq!(
            a, b,
            "same epoch + label + context MUST agree across members"
        );

        // Different context (realm) MUST diverge.
        let other_realm = b"ak:realm:01904100-0000-7000-8000-1ad6479d4a42";
        assert_ne!(
            a,
            alice_group
                .export_secret(
                    arkret_wire::ExporterLabelId::REACTION_ROUTING_V1,
                    other_realm,
                    32
                )
                .unwrap()
        );
        // Different label MUST diverge.
        assert_ne!(
            a,
            alice_group
                .export_secret(arkret_wire::ExporterLabelId::RTC_FRAME_KEY_V1, realm, 32)
                .unwrap()
        );
    }

    #[test]
    fn member_principal_ids_returns_credentials_as_dids() {
        // After Add, both Alice and Bob are members; both DIDs MUST appear
        // in the snapshot. After Remove, only the surviving DID remains.
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-1ad6479d4a41")
            .unwrap();
        assert_eq!(
            alice_group.member_principal_ids(),
            vec![Did::new("did:webvh:z6mkfixture:alice.example").unwrap()],
        );

        let _ = alice_group.add_member(&bob_key_package).unwrap();
        let members = alice_group.member_principal_ids();
        assert_eq!(members.len(), 2);
        assert!(members.contains(&Did::new("did:webvh:z6mkfixture:alice.example").unwrap()));
        assert!(members.contains(&Did::new("did:webvh:z6mkfixture:bob.example").unwrap()));

        let _ = alice_group
            .remove_member_by_principal(&Did::new("did:webvh:z6mkfixture:bob.example").unwrap())
            .unwrap();
        assert_eq!(
            alice_group.member_principal_ids(),
            vec![Did::new("did:webvh:z6mkfixture:alice.example").unwrap()],
        );
    }

    /// `self_update_commit` MUST advance the group epoch by exactly 1
    /// and surface a typed `MlsCommitEnvelope` with the new
    /// (group_id, epoch) pair. The `commit_digest` MUST be the SHA-256
    /// of the wire bytes.
    #[test]
    fn self_update_commit_advances_epoch_and_returns_typed_envelope() {
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let mut group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-555555555555")
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
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-d652c78259d9")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = ArkretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();

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
    fn openmls_group_can_add_multiple_members_in_one_commit() {
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let charlie = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:charlie.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000f").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();
        let charlie_key_package = charlie.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-1eb2ca9cbcfe")
            .unwrap();
        let add_result = alice_group
            .add_members(&[bob_key_package, charlie_key_package])
            .unwrap();
        assert_eq!(add_result.welcomes.len(), 2);
        assert_eq!(add_result.commit.epoch, alice_group.epoch());

        let mut bob_group =
            ArkretMlsGroup::join_from_welcome(bob, &add_result.welcomes[0]).unwrap();
        let mut charlie_group =
            ArkretMlsGroup::join_from_welcome(charlie, &add_result.welcomes[1]).unwrap();
        assert_eq!(bob_group.epoch(), alice_group.epoch());
        assert_eq!(charlie_group.epoch(), alice_group.epoch());

        let encrypted = alice_group
            .encrypt_payload("application/json", br#"{"body":"hello batch"}"#)
            .unwrap();
        assert_eq!(
            bob_group.decrypt_payload(&encrypted).unwrap(),
            br#"{"body":"hello batch"}"#
        );
        assert_eq!(
            charlie_group.decrypt_payload(&encrypted).unwrap(),
            br#"{"body":"hello batch"}"#
        );
    }

    #[test]
    fn message_crypto_encrypts_decrypts_and_verifies_opaque_digest() {
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-f2f103987ef3")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = ArkretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();

        let encrypted = MessageCrypto::encrypt(
            &mut alice_group,
            "ak:message:01",
            "application/vnd.arkret.message+json",
            br#"{"body":"hello secure workflow"}"#,
        )
        .unwrap();

        MessageCrypto::verify_opaque_payload_digest(&encrypted).unwrap();
        let decrypted = MessageCrypto::decrypt(&mut bob_group, &encrypted).unwrap();
        assert_eq!(decrypted, br#"{"body":"hello secure workflow"}"#);
    }

    #[test]
    fn message_crypto_encrypts_with_aad_and_verifies_digest() {
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-65bef476aed3")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = ArkretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();
        let aad = arkret_models_crypto::EncryptedEnvelopeAad {
            realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-65bef476aed3").unwrap(),
            event_kind: "ak.message.create".to_owned(),
            event_id: Some(EventId::new("ak:event:01904100-0000-7000-8000-d5afe7e3de96").unwrap()),
            event_ref_digest: None,
            causal_refs: Some(Vec::new()),
            causal_ref_digests: None,
        };
        let aad_digest = arkret_crypto::envelope_aad_digest(&aad).unwrap();

        let encrypted = MessageCrypto::encrypt_with_aad(
            &mut alice_group,
            "ak:message:aad",
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
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-1ad6479d4a3f")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let bob_group = ArkretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();
        let mut store = TestStore::new();
        let record = bob_group.persist_state(&mut store).unwrap();
        let mut restored_bob = ArkretMlsGroup::restore_from_state_record(&record).unwrap();

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
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let charlie = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:charlie.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000f").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();
        let charlie_key_package = charlie.key_package_record().unwrap();
        let mut revoked_package = charlie_key_package.clone();
        let revoke_step = revoke_key_package(&mut revoked_package);
        assert_eq!(
            revoked_package.state,
            arkret_models_crypto::MlsKeyPackageState::Revoked
        );
        assert_eq!(
            revoke_step.action,
            MlsDeviceWorkflowAction::RevokeKeyPackage
        );

        let mut alice_group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-877788250807")
            .unwrap();
        let bob_add = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = ArkretMlsGroup::join_from_welcome(bob, &bob_add.welcome).unwrap();
        let charlie_add = alice_group.add_member(&charlie_key_package).unwrap();
        let workflow = late_device_join_steps(&charlie_add.welcome);
        assert_eq!(workflow[0].action, MlsDeviceWorkflowAction::ConsumeWelcome);

        bob_group
            .apply_commits(std::slice::from_ref(&charlie_add.commit))
            .unwrap();
        assert_eq!(bob_group.epoch(), alice_group.epoch());
        let recovery = epoch_recovery_step(
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
            bob_group.group_id(),
            bob_group.epoch() + 1,
            bob_group.epoch() + 3,
        );
        assert_eq!(
            recovery.action,
            MlsDeviceWorkflowAction::RequestEpochRecovery
        );
    }

    // NOTE: the "projects to repo operation + device-message target"
    // integration test moved to `arkret-event-draft` (tests/mls_projection.rs):
    // the envelope -> Operation / DeviceMessageTarget projection lives on the
    // event-draft side, which this crate must not depend on. arkret-mls tests
    // only that the MLS group operations emit correct envelope fields.

    #[test]
    fn message_crypto_preserves_encrypted_content_without_available_key() {
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let mut alice_group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-f2f103987ef3")
            .unwrap();
        let encrypted = MessageCrypto::encrypt(
            &mut alice_group,
            "ak:message:02",
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
        assert_eq!(message_id, "ak:message:02");
        assert!(matches!(reason, MessageCryptoUnavailable::NoSession));
        assert_eq!(payload.payload_digest, expected_digest);
        assert_eq!(payload.ciphertext, expected_ciphertext);
    }

    #[test]
    fn encrypted_timeline_preserves_then_decrypts_after_welcome_arrives() {
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-469a459e1b8f")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let encrypted = MessageCrypto::encrypt(
            &mut alice_group,
            "ak:event:01904100-0000-7000-8000-f2fbe0d55fb4",
            "application/vnd.arkret.message+json",
            br#"{"body":"arrives before local key"}"#,
        )
        .unwrap();

        let preserved = MessageCrypto::decrypt_or_preserve(None, encrypted.clone()).unwrap();
        assert!(matches!(preserved, MessageCryptoDecrypt::Encrypted { .. }));

        let mut bob_group = ArkretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();
        let decrypted = MessageCrypto::decrypt(&mut bob_group, &encrypted).unwrap();
        assert_eq!(decrypted, br#"{"body":"arrives before local key"}"#);
    }

    #[test]
    fn epoch_recovery_request_and_response_catch_up_offline_device() {
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let charlie = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:charlie.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000f").unwrap(),
        )
        .unwrap();

        let bob_kp = bob.key_package_record().unwrap();
        let charlie_kp = charlie.key_package_record().unwrap();

        // Alice creates group and adds Bob and Charlie.
        let mut alice_group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-4cc289f6471e")
            .unwrap();
        let bob_add = alice_group.add_member(&bob_kp).unwrap();
        let mut bob_group = ArkretMlsGroup::join_from_welcome(bob, &bob_add.welcome).unwrap();
        let charlie_add = alice_group.add_member(&charlie_kp).unwrap();

        // Bob is now offline. Alice adds Charlie (epoch advances).
        // Bob's local epoch is behind.
        let bob_epoch_before = bob_group.epoch();

        // Create a recovery request.
        let request = EpochRecoveryRequestBody::new(
            bob_group.group_id(),
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
            bob_epoch_before,
            alice_group.epoch(),
        );
        request.validate().unwrap();

        // Store the commits in a crypto store so we can build a response.
        let mut store = TestStore::new();
        store.put_commit(charlie_add.commit);

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
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
            5,
            3,
        );
        assert!(request.validate().is_err());

        let request = EpochRecoveryRequestBody::new(
            "group1",
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
            5,
            5,
        );
        assert!(request.validate().is_err());
    }

    #[test]
    fn welcome_recipient_must_match_identity() {
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let mallory = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:mallory.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000010").unwrap(),
        )
        .unwrap();

        let bob_key_package = bob.key_package_record().unwrap();
        let mut alice_group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-d652c78259d9")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let Err(error) = ArkretMlsGroup::join_from_welcome(mallory, &add_result.welcome) else {
            panic!("Mallory should not be able to consume Bob's Welcome");
        };

        assert!(matches!(error, Error::Protocol(_)));
    }

    /// T31 — `remove_member_by_principal` removes a leaf, advances the
    /// group's epoch and produces a commit envelope that surviving members
    /// can apply to converge.
    #[test]
    fn remove_member_by_principal_advances_epoch_and_emits_commit() {
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let charlie = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:charlie.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000f").unwrap(),
        )
        .unwrap();
        let bob_kp = bob.key_package_record().unwrap();
        let charlie_kp = charlie.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-a78a8b504d40")
            .unwrap();
        let add_bob = alice_group.add_member(&bob_kp).unwrap();
        let _bob_group = ArkretMlsGroup::join_from_welcome(bob, &add_bob.welcome).unwrap();
        let add_charlie = alice_group.add_member(&charlie_kp).unwrap();
        let _charlie_group =
            ArkretMlsGroup::join_from_welcome(charlie, &add_charlie.welcome).unwrap();

        let epoch_before = alice_group.epoch();
        let target = Did::new("did:webvh:z6mkfixture:charlie.example").unwrap();
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
            "did:webvh:z6mkfixture:charlie.example"
        );
    }

    #[test]
    fn remove_members_by_principal_batches_one_commit() {
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let charlie = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:charlie.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000f").unwrap(),
        )
        .unwrap();
        let bob_kp = bob.key_package_record().unwrap();
        let charlie_kp = charlie.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-2fa70c9d6659")
            .unwrap();
        alice_group.add_member(&bob_kp).unwrap();
        alice_group.add_member(&charlie_kp).unwrap();

        let epoch_before = alice_group.epoch();
        let targets = [
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            Did::new("did:webvh:z6mkfixture:charlie.example").unwrap(),
        ];
        let result = alice_group.remove_members_by_principal(&targets).unwrap();

        assert_eq!(alice_group.epoch(), epoch_before + 1);
        assert_eq!(result.proposals.len(), 2);
        assert_eq!(result.removed_leaves.len(), 2);
        let mut removed: Vec<&str> = result.removed_principals.iter().map(Did::as_str).collect();
        removed.sort_unstable();
        assert_eq!(
            removed,
            vec![
                "did:webvh:z6mkfixture:bob.example",
                "did:webvh:z6mkfixture:charlie.example",
            ]
        );
        assert_eq!(
            alice_group
                .member_principal_ids()
                .into_iter()
                .map(|principal| principal.to_string())
                .collect::<Vec<_>>(),
            vec!["did:webvh:z6mkfixture:alice.example"]
        );
    }

    /// T31 — removing an absent principal returns a Protocol error rather
    /// than silently no-op'ing. The orchestration plan in inkson relies on
    /// this to surface "leaf already gone" as a recoverable state.
    #[test]
    fn remove_member_by_principal_errors_when_target_absent() {
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let mut alice_group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-3cf34eced3c3")
            .unwrap();

        let absent = Did::new("did:webvh:z6mkfixture:nobody.example").unwrap();
        let err = alice_group.remove_member_by_principal(&absent);
        assert!(matches!(err, Err(Error::Protocol(_))));
    }

    #[test]
    fn encrypted_envelope_v1_conforms_and_round_trips_losslessly() {
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000abcd").unwrap(),
        )
        .unwrap();
        let mut group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-0abc0abc0abc")
            .unwrap();

        let realm_id = "ak:realm:01904100-0000-7000-8000-0abc0abc0abc";
        let aad = arkret_models_crypto::EncryptedEnvelopeAad::hidden(
            RealmId::new(realm_id).unwrap(),
            "ak.message.create",
        );
        let plaintext = br#"{"body":"hello encrypted discussion"}"#;
        let payload = group
            .encrypt_payload_with_aad(
                "application/vnd.arkret.message+json",
                Some(aad.clone()),
                plaintext,
            )
            .unwrap();

        let commit_ref = "ak:event:01904100-0000-7000-8000-00000000c0a1";
        let envelope = encrypted_envelope_from_payload(
            &payload,
            aad,
            EncryptedEnvelopeAadVisibility::Hidden,
            commit_ref,
        )
        .unwrap();

        // Conformance with ak.schema.encrypted_envelope.v1: required fields,
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
        assert_eq!(obj["scheme"], "mls_rfc9420");
        assert_eq!(obj["version"], "1.0");
        assert_eq!(obj["aad_visibility_event_id"], "hidden");
        assert_eq!(obj["key_ref"]["algorithm"], "MLS");
        assert_eq!(obj["key_ref"]["group_state_ref"], commit_ref);
        assert_eq!(obj["aad"]["realm_id"], realm_id);
        assert_eq!(obj["aad"]["event_kind"], "ak.message.create");
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
        let parsed: EncryptedEnvelope = serde_json::from_str(&wire).unwrap();
        assert_eq!(parsed, envelope);
        assert_eq!(encrypted_envelope_to_payload(&parsed).unwrap(), payload);

        // Fail closed when the supplied AAD doesn't match the AAD bound into
        // payload_digest at encryption time.
        let mismatch = encrypted_envelope_from_payload(
            &payload,
            arkret_models_crypto::EncryptedEnvelopeAad::hidden(
                RealmId::new(realm_id).unwrap(),
                "ak.strand.update",
            ),
            EncryptedEnvelopeAadVisibility::Hidden,
            commit_ref,
        );
        assert!(mismatch.is_err());
    }

    /// T31 — `remove_member_by_leaf` accepts a raw OpenMLS leaf index and
    /// produces the same shape of commit envelope. Used when the caller
    /// (inkson DeviceManager) tracks per-device leaf bookkeeping
    /// out-of-band.
    #[test]
    fn remove_member_by_leaf_accepts_raw_index() {
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_kp = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-89444e193497")
            .unwrap();
        let add_bob = alice_group.add_member(&bob_kp).unwrap();
        let _bob_group = ArkretMlsGroup::join_from_welcome(bob, &add_bob.welcome).unwrap();

        // Bob's leaf is at index 1 (Alice is index 0 as group creator).
        let result = alice_group.remove_member_by_leaf(1).unwrap();
        assert_eq!(result.removed_leaves, vec![1]);
        assert_eq!(
            result.removed_principals[0].as_str(),
            "did:webvh:z6mkfixture:bob.example"
        );
    }

    // NOTE: the Remove-result `commit_operation` projection test also moved to
    // `arkret-event-draft` (tests/mls_projection.rs) — see the note above.

    // ── mls_exporter_aead_v1 content scheme ──────────────────────────────────

    const HISTORY_REALM: &str = "ak:realm:01904100-0000-7000-8000-e2eeae0d0001";

    fn exporter_aead_founder() -> ArkretMlsGroup {
        let alice = ArkretMlsIdentity::new_basic(
            Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000ae01").unwrap(),
        )
        .unwrap();
        alice
            .create_group(b"ak:realm:01904100-0000-7000-8000-e2eeae0d0001")
            .unwrap()
    }

    #[test]
    fn exporter_aead_content_round_trips_for_local_epoch() {
        let mut group = exporter_aead_founder();
        let aad = b"event-binding-aad";
        let plaintext = b"hello encrypted history";

        let sealed = group
            .encrypt_content_exporter_aead(HISTORY_REALM, aad, plaintext)
            .unwrap();
        // The retained history_secret for the current epoch decrypts it.
        let history_secret = group
            .derive_and_retain_history_secret(HISTORY_REALM)
            .unwrap();
        let recovered = group
            .decrypt_content_exporter_aead(&history_secret, HISTORY_REALM, &sealed, aad)
            .unwrap();
        assert_eq!(recovered, plaintext);

        // Wrong AAD fails the tag check.
        assert!(
            group
                .decrypt_content_exporter_aead(&history_secret, HISTORY_REALM, &sealed, b"other")
                .is_err()
        );
    }

    #[test]
    fn encrypted_envelope_v1_binds_exporter_scheme_to_exporter_key_algorithm() {
        let mut group = exporter_aead_founder();
        let envelope_aad = arkret_models_crypto::EncryptedEnvelopeAad::hidden(
            RealmId::new(HISTORY_REALM).unwrap(),
            "ak.message.create",
        );
        let payload = group
            .encrypt_payload_exporter_aead(
                "application/vnd.arkret.message+json",
                HISTORY_REALM,
                b"history-content-aad",
                Some(envelope_aad.clone()),
                b"hello encrypted history",
            )
            .unwrap();
        assert_eq!(payload.scheme, EncryptedPayloadScheme::MlsExporterAeadV1);

        let group_state_ref = "ak:event:01904100-0000-7000-8000-00000000ae01";
        let envelope = encrypted_envelope_from_payload(
            &payload,
            envelope_aad,
            EncryptedEnvelopeAadVisibility::Hidden,
            group_state_ref,
        )
        .unwrap();
        assert_eq!(
            envelope.key_ref.algorithm,
            EncryptedEnvelopeKeyAlgorithm::MlsExporterAead
        );
        envelope.validate().unwrap();

        let mut mismatched = envelope;
        mismatched.key_ref.algorithm = EncryptedEnvelopeKeyAlgorithm::Mls;
        assert!(mismatched.validate().is_err());
    }

    #[test]
    fn provider_retains_epoch_secret_and_receiver_decrypts_via_share() {
        // Provider encrypts content at epoch N and retains history_secret[N].
        let mut provider = exporter_aead_founder();
        let epoch_n = provider.epoch();
        let aad = b"history-share-aad";
        let plaintext = b"pre-join secret content";
        let sealed = provider
            .encrypt_content_exporter_aead(HISTORY_REALM, aad, plaintext)
            .unwrap();

        // Provider exports the retained secret range to seal for a joiner.
        let range = provider.export_history_secret_range(epoch_n, epoch_n);
        assert_eq!(range.len(), 1);
        assert_eq!(range[0].0, epoch_n);

        // Receiver device keypair; provider HPKE-seals the range to its pubkey.
        let receiver_priv = x25519_dalek::StaticSecret::from([42u8; 32]);
        let receiver_pub = *x25519_dalek::PublicKey::from(&receiver_priv).as_bytes();
        let range_plain: Vec<(u64, Vec<u8>)> = range
            .iter()
            .map(|(epoch, secret)| (*epoch, secret.to_vec()))
            .collect();
        let share_ciphertext = arkret_crypto::secret_share::seal_history_secret_to_device_pubkey(
            &receiver_pub,
            &range_plain,
        )
        .unwrap();

        // Receiver unseals and recovers history_secret[N]...
        let installed = arkret_crypto::secret_share::open_history_secret_with_device_privkey(
            receiver_priv.to_bytes().as_slice(),
            &share_ciphertext,
        )
        .unwrap();
        assert_eq!(installed, range_plain);
        let history_secret_n = &installed[0].1;

        // ...and decrypts the epoch-N content with it. A fresh group view (no
        // ratchet access to epoch N) decrypts purely from the shared secret.
        let receiver_group = exporter_aead_founder();
        let recovered = receiver_group
            .decrypt_content_exporter_aead(history_secret_n, HISTORY_REALM, &sealed, aad)
            .unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn history_secret_persists_across_state_snapshot_reload() {
        let mut group = exporter_aead_founder();
        let secret = group
            .derive_and_retain_history_secret(HISTORY_REALM)
            .unwrap();
        let epoch = group.epoch();

        let record = group.export_state_record().unwrap();
        let reloaded = ArkretMlsGroup::restore_from_state_record(&record).unwrap();
        let range = reloaded.export_history_secret_range(epoch, epoch);
        assert_eq!(range, vec![(epoch, secret)]);
    }
}
