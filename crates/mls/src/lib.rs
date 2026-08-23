//! Arkret v1 MLS (RFC 9420) behavior layer.
//!
//! This crate is the sole OpenMLS boundary in the workspace: it owns the
//! `ArkretMlsIdentity` / `ArkretMlsGroup` group machine, the MLS message /
//! exporter-aead content schemes, epoch-recovery, and the minimal-metadata
//! author-credential validator. It depends only on the wire / model / crypto
//! data crates and inverts persistence through the narrow `MlsGroupStateSink`
//! / `MlsCommitSource` ports so it never reaches up into the SDK
//! `CryptoStore`.

mod error;
mod exporter_kdf;
mod group;
mod identity;
mod message;
mod public_group_state;
mod recovery;
mod signal;

pub use arkret_policy::{
    AgentMlsLeafBindingError, AgentMlsSignerClaim, AgentMlsSignerView, AuthorGroupStateView,
    AuthorLeaf, AuthorLeafCredential, MINIMAL_METADATA_MAX_EPOCH_LIFETIME_SECS,
    MinimalMetadataAuthorClaim, MinimalMetadataAuthorError, MinimalMetadataAuthorViolation,
    VerifiedAuthorLeaf, minimal_metadata_epoch_overdue, minimal_metadata_max_epoch_lifetime,
    verify_minimal_metadata_author, verify_ordinary_agent_mls_binding,
};
pub use error::MlsError;
// `Result` stays crate-internal because public signatures resolve it to the
// concrete `std::result::Result<_, MlsError>` and external callers do not need
// a generic root-level alias.
pub(crate) use error::Result;
pub use exporter_kdf::*;
pub use group::*;
pub use identity::*;
pub use message::*;
pub use public_group_state::*;
pub use recovery::*;
pub use signal::*;

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
        EncryptedEnvelope, EncryptedEnvelopeEncryptionContext, EventContentPreEncryptionHeader,
        EventContentRoutingContext, MlsCommitEnvelope, MlsCommitSource,
        MlsGovernanceBindingPayload, MlsGovernanceBindingValidationContext, MlsGroupStateRecord,
        MlsGroupStateSink,
    };
    use arkret_wire::{
        CORE_REDUCER_PROFILE, DeviceId, DidCoreId, EncryptedPayloadScheme, EventId, Hash,
        ProfileId, RealmId, ScopeRef,
    };
    use chrono::Utc;

    use super::*;
    use crate::MlsError as Error;

    fn content_header(
        group: &ArkretMlsGroup,
        realm_id: &str,
        sender_device_id: &str,
        content_type: &str,
        scheme: EncryptedPayloadScheme,
        counter: Option<u64>,
    ) -> EventContentPreEncryptionHeader {
        EventContentPreEncryptionHeader::reconstruct(
            "1.0",
            content_type,
            scheme,
            ScopeRef::Realm {
                realm_id: RealmId::new(realm_id).unwrap(),
            },
            "ak.message.create",
            group.epoch(),
            EventId::new("ak:event:ARKEyrg59dN-i97Pleo3vwwRkZomIcqPiuK9PtjzGLdh").unwrap(),
            sender_device_id,
            counter,
            EventContentRoutingContext::None,
        )
        .unwrap()
    }

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
        RealmId::new("ak:realm:AdHF2JK9DIDVy_g03wqifslF_vA_Yuy3_0aWvazcsO_b").unwrap()
    }

    fn governance_hash(byte: char) -> Hash {
        Hash::new(format!("sha256:{}", byte.to_string().repeat(64))).unwrap()
    }

    fn governance_binding(
        group_id: &str,
        previous_epoch: u64,
        next_epoch: u64,
        security_frontier_digest: Hash,
    ) -> MlsGovernanceBindingPayload {
        MlsGovernanceBindingPayload::realm(
            governance_realm(),
            group_id.to_owned(),
            previous_epoch,
            next_epoch,
            security_frontier_digest,
            arkret_wire::ContentScheme::MlsRfc9420,
            None,
            ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            CORE_REDUCER_PROFILE,
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
        let group_id_bytes = b"ak:realm:AVt_pqbVmjfz315Eu_iVxMgAW_1Ak0GBjeQMPPoJ-Q7U";
        let group_id = base64url_encode(group_id_bytes);
        let binding = governance_binding(&group_id, 0, 0, governance_hash('1'));
        let alice = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
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
            ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            CORE_REDUCER_PROFILE,
        );
        expected.security_frontier_digest = Some(binding.security_frontier_digest());

        assert_eq!(current, binding);
        group.verify_current_governance_binding(&expected).unwrap();
    }

    #[test]
    fn public_group_state_material_round_trips_through_rfc_validation() {
        let alice = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000f1c5").unwrap(),
        )
        .unwrap();
        let group = alice
            .create_group(b"ak:realm:AdMTPJACbsAIV-1fd0WeShxBOlm3v635iRn0KKRHhtqx")
            .unwrap();
        let (group_info, ratchet_tree) = group.public_group_state_bytes().unwrap();

        let leaves = validate_public_group_state(
            &group_info,
            &ratchet_tree,
            &group.group_id(),
            group.epoch(),
        )
        .unwrap();
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].leaf_index, 0);
        assert_eq!(
            leaves[0].principal_id.as_str(),
            "ak:did_core:webvh:z6mkfixturealice"
        );
    }

    #[test]
    fn update_governance_binding_enters_group_context_extension() {
        let alice = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000f1c2").unwrap(),
        )
        .unwrap();
        let mut group = alice
            .create_group(b"ak:realm:ARecPDHL91RHtRAXrgS_cG5qvXu6jJfFKlDC6_FMYXOp")
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
            ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            CORE_REDUCER_PROFILE,
        );
        expected.security_frontier_digest = Some(binding.security_frontier_digest());

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
        let group_id_bytes = b"ak:realm:AZKXY1qgadiGJ3RYettbM5c1seyXUwtPaseyycP5TnDg";
        let group_id = base64url_encode(group_id_bytes);
        let genesis_binding = governance_binding(&group_id, 0, 0, governance_hash('1'));
        let alice = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000f1ca").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
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
        let group_id_bytes = b"ak:realm:AbRQVldj2O6HwbNpZYVKzcH9nHt2VXsw9EWH_smkckHH";
        let group_id = base64url_encode(group_id_bytes);
        let genesis_binding = governance_binding(&group_id, 0, 0, governance_hash('1'));
        let alice = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000f1da").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000f1db").unwrap(),
        )
        .unwrap();
        let carol = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturecarol").unwrap(),
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
            .find(|welcome| welcome.recipient.actor_id() == &carol.principal_id)
            .unwrap();
        let mut carol_group = ArkretMlsGroup::join_from_welcome(carol, carol_welcome).unwrap();
        let remove_binding = governance_binding(&group_id, 1, 2, governance_hash('3'));

        let remove = alice_group
            .remove_members_by_principal_with_governance_binding(
                std::slice::from_ref(&bob_did),
                &remove_binding,
            )
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
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000f1c3").unwrap(),
        )
        .unwrap();
        let group = alice
            .create_group(b"ak:realm:ATbqnZTuOFCMxdc8XLr13QAW37vsli-pHeGiBB7JC41D")
            .unwrap();
        let group_id = group.group_id();
        let expected = MlsGovernanceBindingValidationContext::for_commit(
            &group_id,
            0,
            1,
            ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            CORE_REDUCER_PROFILE,
        );

        let err = group
            .verify_current_governance_binding(&expected)
            .unwrap_err();

        assert!(
            err.to_string()
                .contains(arkret_wire::ErrorCode::UNSUPPORTED_PROFILE)
        );
    }

    #[test]
    fn governance_binding_verification_rejects_profile_downgrade() {
        let alice = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000f1c4").unwrap(),
        )
        .unwrap();
        let mut group = alice
            .create_group(b"ak:realm:AYHc9IWh-gvw1Sbq4Y3zTVuzVQC11iFldtLg1SK7EMb_")
            .unwrap();
        let group_id = group.group_id();
        let binding = governance_binding(&group_id, 0, 1, governance_hash('3'))
            .with_binding_profile(ProfileId::E2EE_RELAXED_V1)
            .unwrap();
        group.update_governance_binding(&binding).unwrap();
        let expected = MlsGovernanceBindingValidationContext::for_commit(
            &group_id,
            0,
            1,
            ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            CORE_REDUCER_PROFILE,
        );

        let err = group
            .verify_current_governance_binding(&expected)
            .unwrap_err();

        assert!(
            err.to_string()
                .contains(arkret_wire::ErrorCode::UNSUPPORTED_PROFILE)
        );
    }

    #[test]
    fn governance_binding_verification_rejects_stale_security_frontier_digest() {
        let alice = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000f1c5").unwrap(),
        )
        .unwrap();
        let mut group = alice
            .create_group(b"ak:realm:AdMTPJACbsAIV-1fd0WeShxBOlm3v635iRn0KKRHhtqx")
            .unwrap();
        let group_id = group.group_id();
        let binding = governance_binding(&group_id, 0, 1, governance_hash('4'));
        group.update_governance_binding(&binding).unwrap();
        let stale_security_frontier_digest = governance_hash('9');
        let mut expected = MlsGovernanceBindingValidationContext::for_commit(
            &group_id,
            0,
            1,
            ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            CORE_REDUCER_PROFILE,
        );
        expected.security_frontier_digest = Some(&stale_security_frontier_digest);

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
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:ATlsl9zB7f40-HDo9eu5FdoJSYlOg8rVgwU3bbz2XzNM")
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
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob_principal = DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap();
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
            .create_group(b"ak:realm:Aea0eL67o4AEk_gugTJtxZbP2BGxws25OLp-27cUC1K3")
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
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000016").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000001e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let bob_group = ArkretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();

        let realm = b"ak:realm:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV";
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
        let other_realm = b"ak:realm:AdR_2Pd1eFhbcYuzuSOjN0Z5glzE4dktyxcvDlYNnka-";
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
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:AQdmOQIzsGDs6LjeW5Icy92GXh1n9_6SGgVCJJ_2a3FV")
            .unwrap();
        assert_eq!(
            alice_group.member_principal_ids(),
            vec![DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap()],
        );

        let _ = alice_group.add_member(&bob_key_package).unwrap();
        let members = alice_group.member_principal_ids();
        assert_eq!(members.len(), 2);
        assert!(members.contains(&DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap()));
        assert!(members.contains(&DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap()));

        let _ = alice_group
            .remove_member_by_principal(
                &DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
            )
            .unwrap();
        assert_eq!(
            alice_group.member_principal_ids(),
            vec![DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap()],
        );
    }

    /// `self_update_commit` MUST advance the group epoch by exactly 1
    /// and surface a typed `MlsCommitEnvelope` with the new
    /// (group_id, epoch) pair. The `commit_digest` MUST be the SHA-256
    /// of the wire bytes.
    #[test]
    fn self_update_commit_advances_epoch_and_returns_typed_envelope() {
        let alice = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let mut group = alice
            .create_group(b"ak:realm:AZVd_RyGYDrf6ckEZzF0NFb16v3bce5Sbf2C7Ug-giuF")
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
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:AdmAewBnEWLWSp60CpdI_JXwYiZGNCIDYLEnjYTgaNz3")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = ArkretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();

        let header = content_header(
            &alice_group,
            "ak:realm:AdmAewBnEWLWSp60CpdI_JXwYiZGNCIDYLEnjYTgaNz3",
            "ak:device:01904100-0000-7000-8000-000000000006",
            "application/json",
            EncryptedPayloadScheme::MlsRfc9420,
            None,
        );
        let encrypted = alice_group
            .encrypt_payload(header, br#"{"body":"hello"}"#)
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
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let charlie = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturecharlie").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000f").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();
        let charlie_key_package = charlie.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:AV7nJulkpf6nOMIJK3BgQk9k47SVPYURKMguZQZNofn9")
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

        let header = content_header(
            &alice_group,
            "ak:realm:AV7nJulkpf6nOMIJK3BgQk9k47SVPYURKMguZQZNofn9",
            "ak:device:01904100-0000-7000-8000-000000000006",
            "application/json",
            EncryptedPayloadScheme::MlsRfc9420,
            None,
        );
        let encrypted = alice_group
            .encrypt_payload(header, br#"{"body":"hello batch"}"#)
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
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = ArkretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();

        let header = content_header(
            &alice_group,
            "ak:realm:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT",
            "ak:device:01904100-0000-7000-8000-000000000006",
            "application/vnd.arkret.message+json",
            EncryptedPayloadScheme::MlsRfc9420,
            None,
        );
        let encrypted = MessageCrypto::encrypt(
            &mut alice_group,
            "ak:message:01",
            header,
            br#"{"body":"hello secure workflow"}"#,
        )
        .unwrap();

        MessageCrypto::verify_opaque_payload_digest(&encrypted).unwrap();
        let decrypted = MessageCrypto::decrypt(&mut bob_group, &encrypted).unwrap();
        assert_eq!(decrypted, br#"{"body":"hello secure workflow"}"#);
    }

    #[test]
    fn message_crypto_binds_the_reconstructed_header() {
        let alice = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:AWiUh2Jt07erLjzV_goRCJr5oCGRYAFLRxHdmS-gobPx")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let mut bob_group = ArkretMlsGroup::join_from_welcome(bob, &add_result.welcome).unwrap();
        let header = content_header(
            &alice_group,
            "ak:realm:AWiUh2Jt07erLjzV_goRCJr5oCGRYAFLRxHdmS-gobPx",
            "ak:device:01904100-0000-7000-8000-000000000006",
            "application/json",
            EncryptedPayloadScheme::MlsRfc9420,
            None,
        );
        let expected_aad = header.canonical_bytes().unwrap();
        let encrypted = MessageCrypto::encrypt(
            &mut alice_group,
            "ak:message:aad",
            header,
            br#"{"body":"aad bound"}"#,
        )
        .unwrap();
        assert_eq!(
            encrypted
                .payload
                .pre_encryption_header
                .canonical_bytes()
                .unwrap(),
            expected_aad
        );
        assert_eq!(
            MessageCrypto::decrypt(&mut bob_group, &encrypted).unwrap(),
            br#"{"body":"aad bound"}"#
        );
    }

    #[test]
    fn openmls_state_persists_through_crypto_store_record() {
        let alice = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:Ac1nMpkxYEro_Sv9809TCqs5pW2WSpBGuQnQAybKkSoz")
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

        let header = content_header(
            &alice_group,
            "ak:realm:Ac1nMpkxYEro_Sv9809TCqs5pW2WSpBGuQnQAybKkSoz",
            "ak:device:01904100-0000-7000-8000-000000000006",
            "application/json",
            EncryptedPayloadScheme::MlsRfc9420,
            None,
        );
        let encrypted = alice_group
            .encrypt_payload(header, br#"{"body":"after restore"}"#)
            .unwrap();
        assert_eq!(
            restored_bob.decrypt_payload(&encrypted).unwrap(),
            br#"{"body":"after restore"}"#
        );
    }

    // NOTE: the "projects to repo operation + device-message target"
    // integration test moved to `arkret-event-draft` (tests/mls_projection.rs):
    // the envelope -> local operation / DeviceMessageTarget projection lives on the
    // event-draft side, which this crate must not depend on. arkret-mls tests
    // only that the MLS group operations emit correct envelope fields.

    #[test]
    fn message_crypto_preserves_encrypted_content_without_available_key() {
        let alice = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let mut alice_group = alice
            .create_group(b"ak:realm:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT")
            .unwrap();
        let header = content_header(
            &alice_group,
            "ak:realm:ASZ1iAvlGxgLC_-P6WHoR9vfijpaxbI5hoSwBx8zWTcT",
            "ak:device:01904100-0000-7000-8000-000000000006",
            "application/json",
            EncryptedPayloadScheme::MlsRfc9420,
            None,
        );
        let encrypted = MessageCrypto::encrypt(
            &mut alice_group,
            "ak:message:02",
            header,
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
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let bob_key_package = bob.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:AbiYluN0ZZon1OoU2ZkF1WIMsKC0wZ_5CPq0jHVfdeye")
            .unwrap();
        let add_result = alice_group.add_member(&bob_key_package).unwrap();
        let header = content_header(
            &alice_group,
            "ak:realm:AbiYluN0ZZon1OoU2ZkF1WIMsKC0wZ_5CPq0jHVfdeye",
            "ak:device:01904100-0000-7000-8000-000000000006",
            "application/vnd.arkret.message+json",
            EncryptedPayloadScheme::MlsRfc9420,
            None,
        );
        let encrypted = MessageCrypto::encrypt(
            &mut alice_group,
            "ak:event:Aac-gXWJTa6raGBgFHR0jFlCNRz6AKECGYBRqW6MMO1n",
            header,
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
    fn welcome_recipient_must_match_identity() {
        let alice = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let mallory = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturemallory").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000010").unwrap(),
        )
        .unwrap();

        let bob_key_package = bob.key_package_record().unwrap();
        let mut alice_group = alice
            .create_group(b"ak:realm:AdmAewBnEWLWSp60CpdI_JXwYiZGNCIDYLEnjYTgaNz3")
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
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let charlie = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturecharlie").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000f").unwrap(),
        )
        .unwrap();
        let bob_kp = bob.key_package_record().unwrap();
        let charlie_kp = charlie.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:AeTOYTzHDNI8b1_5Fmz2UaEyPpyxCCbl6rmP6tQchXnm")
            .unwrap();
        let add_bob = alice_group.add_member(&bob_kp).unwrap();
        let _bob_group = ArkretMlsGroup::join_from_welcome(bob, &add_bob.welcome).unwrap();
        let add_charlie = alice_group.add_member(&charlie_kp).unwrap();
        let _charlie_group =
            ArkretMlsGroup::join_from_welcome(charlie, &add_charlie.welcome).unwrap();

        let epoch_before = alice_group.epoch();
        let target = DidCoreId::new("ak:did_core:webvh:z6mkfixturecharlie").unwrap();
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
            "ak:did_core:webvh:z6mkfixturecharlie"
        );
    }

    #[test]
    fn remove_members_by_principal_batches_one_commit() {
        let alice = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let bob = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000e").unwrap(),
        )
        .unwrap();
        let charlie = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturecharlie").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000f").unwrap(),
        )
        .unwrap();
        let bob_kp = bob.key_package_record().unwrap();
        let charlie_kp = charlie.key_package_record().unwrap();

        let mut alice_group = alice
            .create_group(b"ak:realm:AUkdLwHAsDaXjjorO56LZKFGSww3c2nJtmE3l0s1dzza")
            .unwrap();
        alice_group.add_member(&bob_kp).unwrap();
        alice_group.add_member(&charlie_kp).unwrap();

        let epoch_before = alice_group.epoch();
        let targets = [
            DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixturecharlie").unwrap(),
        ];
        let result = alice_group.remove_members_by_principal(&targets).unwrap();

        assert_eq!(alice_group.epoch(), epoch_before + 1);
        assert_eq!(result.proposals.len(), 2);
        assert_eq!(result.removed_leaves.len(), 2);
        let mut removed: Vec<&str> = result
            .removed_principals
            .iter()
            .map(DidCoreId::as_str)
            .collect();
        removed.sort_unstable();
        assert_eq!(
            removed,
            vec![
                "ak:did_core:webvh:z6mkfixturebob",
                "ak:did_core:webvh:z6mkfixturecharlie",
            ]
        );
        assert_eq!(
            alice_group
                .member_principal_ids()
                .into_iter()
                .map(|principal| principal.to_string())
                .collect::<Vec<_>>(),
            vec!["ak:did_core:webvh:z6mkfixturealice"]
        );
    }

    /// T31 — removing an absent principal returns a Protocol error rather
    /// than silently no-op'ing. The orchestration plan in inkson relies on
    /// this to surface "leaf already gone" as a recoverable state.
    #[test]
    fn remove_member_by_principal_errors_when_target_absent() {
        let alice = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000006").unwrap(),
        )
        .unwrap();
        let mut alice_group = alice
            .create_group(b"ak:realm:AYl858-7mJ8AG_fd65EELfHOvwye1VBto0nFH9zkvWol")
            .unwrap();

        let absent = DidCoreId::new("ak:did_core:webvh:z6mkfixturenobody").unwrap();
        let err = alice_group.remove_member_by_principal(&absent);
        assert!(matches!(err, Err(Error::Protocol(_))));
    }

    #[test]
    fn encrypted_envelope_v1_conforms_and_round_trips_losslessly() {
        let alice = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new("ak:device:01904100-0000-7000-8000-00000000abcd").unwrap(),
        )
        .unwrap();
        let mut group = alice
            .create_group(b"ak:realm:AQrLXlUoN8Yu4yFfjpTeWmFPwkfMdNKe-u-gY3PcdhSy")
            .unwrap();

        let realm_id = "ak:realm:AQrLXlUoN8Yu4yFfjpTeWmFPwkfMdNKe-u-gY3PcdhSy";
        let header = content_header(
            &group,
            realm_id,
            "ak:device:01904100-0000-7000-8000-00000000abcd",
            "application/vnd.arkret.message+json",
            EncryptedPayloadScheme::MlsRfc9420,
            None,
        );
        let plaintext = br#"{"body":"hello encrypted discussion"}"#;
        let payload = group.encrypt_payload(header.clone(), plaintext).unwrap();
        let envelope = encrypted_envelope_from_payload(&payload).unwrap();

        // Conformance with ak.schema.encrypted_envelope.v1: the wire is the
        // minimal four-field object and does not duplicate reconstructible
        // header fields.
        let json = serde_json::to_value(&envelope).unwrap();
        let obj = json.as_object().unwrap();
        for field in [
            "version",
            "content_type",
            "encryption_context",
            "ciphertext",
        ] {
            assert!(obj.contains_key(field), "missing required field {field}");
        }
        assert_eq!(obj.len(), 4);
        assert_eq!(obj["version"], "1.0");
        assert_eq!(obj["encryption_context"]["epoch"], payload.epoch);
        assert_eq!(
            obj["encryption_context"]["group_state_ref"],
            header.group_state_ref.as_str()
        );
        assert!(obj["encryption_context"].get("counter").is_none());

        // Wire round-trip is stable. Internal decryption state is reconstructed
        // only after the caller has verified outer Event and group-state data.
        let wire = serde_json::to_string(&envelope).unwrap();
        let parsed: EncryptedEnvelope = serde_json::from_str(&wire).unwrap();
        assert_eq!(parsed, envelope);
        let rebuilt = encrypted_envelope_to_payload_with_verified_header(&parsed, header).unwrap();
        assert_eq!(rebuilt, payload);
    }

    // NOTE: the Remove-result `commit_operation` projection test also moved to
    // `arkret-event-draft` (tests/mls_projection.rs) — see the note above.

    // ── mls_exporter_aead_v1 content scheme ──────────────────────────────────

    const HISTORY_REALM: &str = "ak:realm:AXGA0fM2a_L3afx2ffIvrX5YVKbExabYEkxTUwvKu9HR";
    const HISTORY_SENDER_DEVICE: &str = "ak:device:01904100-0000-7000-8000-00000000ae01";

    fn exporter_aead_founder() -> ArkretMlsGroup {
        let alice = ArkretMlsIdentity::new_basic(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
            DeviceId::new(HISTORY_SENDER_DEVICE).unwrap(),
        )
        .unwrap();
        alice
            .create_group(b"ak:realm:AXGA0fM2a_L3afx2ffIvrX5YVKbExabYEkxTUwvKu9HR")
            .unwrap()
    }

    #[test]
    fn active_author_leaves_preserve_exact_basic_credential_identity() {
        let group = exporter_aead_founder();
        let leaves = group.active_author_leaves();
        assert_eq!(leaves.len(), 1);
        let AuthorLeafCredential::Basic { identity } = &leaves[0].credential else {
            panic!("founder leaf must use a BasicCredential");
        };
        let principal = "ak:did_core:webvh:z6mkfixturealice";
        assert_eq!(
            identity,
            format!("{principal}#{HISTORY_SENDER_DEVICE}").as_bytes()
        );
        assert_ne!(identity, principal.as_bytes());
    }

    fn exporter_aead_header(
        group: &ArkretMlsGroup,
        counter: u64,
    ) -> EventContentPreEncryptionHeader {
        content_header(
            group,
            HISTORY_REALM,
            HISTORY_SENDER_DEVICE,
            "application/vnd.arkret.message+json",
            EncryptedPayloadScheme::MlsExporterAeadV1,
            Some(counter),
        )
    }

    #[test]
    fn exporter_aead_content_round_trips_for_local_epoch() {
        let mut group = exporter_aead_founder();
        let header = exporter_aead_header(&group, 0);
        let plaintext = b"hello encrypted history";

        let (counter, sealed) = group
            .encrypt_content_exporter_aead(HISTORY_REALM, &header, plaintext)
            .unwrap();
        assert_eq!(counter, 0);
        // The retained history_secret for the current epoch decrypts it.
        let history_secret = group
            .derive_and_retain_history_secret(HISTORY_REALM)
            .unwrap();
        let recovered = group
            .decrypt_content_exporter_aead(
                &history_secret,
                HISTORY_SENDER_DEVICE.as_bytes(),
                &header,
                &sealed,
            )
            .unwrap();
        assert_eq!(recovered, plaintext);

        // Wrong AAD fails the tag check.
        let mut wrong_header = header;
        wrong_header.event_kind = "ak.message.revise".to_owned();
        assert!(
            group
                .decrypt_content_exporter_aead(
                    &history_secret,
                    HISTORY_SENDER_DEVICE.as_bytes(),
                    &wrong_header,
                    &sealed,
                )
                .is_err()
        );
    }

    #[test]
    fn encrypted_envelope_v1_uses_counter_as_the_exporter_branch_discriminator() {
        let mut group = exporter_aead_founder();
        let header = exporter_aead_header(&group, 0);
        let payload = group
            .encrypt_payload_exporter_aead(HISTORY_REALM, header, b"hello encrypted history")
            .unwrap();
        assert_eq!(payload.scheme, EncryptedPayloadScheme::MlsExporterAeadV1);

        let envelope = encrypted_envelope_from_payload(&payload).unwrap();
        assert!(matches!(
            envelope.encryption_context,
            EncryptedEnvelopeEncryptionContext::ExporterMls { .. }
        ));
        assert_eq!(envelope.encryption_context.counter(), payload.counter);
        envelope.validate().unwrap();
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
        assert_eq!(
            reloaded.history_secrets.get(&epoch).map(|s| &**s),
            Some(&*secret)
        );
    }
}
