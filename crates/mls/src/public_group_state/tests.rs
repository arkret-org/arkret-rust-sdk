use tls_codec::Serialize as _;

use super::*;
use crate::{ArkretMlsGroup, ArkretMlsIdentity};
fn identity(n: u8) -> ArkretMlsIdentity {
    ArkretMlsIdentity::new_test_human_device(
        DidCoreId::new(format!("ak:did_core:web:public{n}.example")).unwrap(),
        DeviceId::new(format!("ak:device:01904100-0000-7000-8000-{n:012x}")).unwrap(),
    )
    .unwrap()
}
fn tracker(group: &ArkretMlsGroup) -> MlsPublicGroupTracker {
    let (info, tree) = group.public_group_state_bytes().unwrap();
    MlsPublicGroupTracker::from_external(&info, &tree, &group.group_id(), group.epoch(), None)
        .unwrap()
}
fn bytes(value: &str) -> Vec<u8> {
    arkret_canonical::base64url_decode(value).unwrap()
}
fn proposals(
    tracker: &mut MlsPublicGroupTracker,
    items: &[arkret_models_crypto::MlsProposalEnvelope],
) {
    for proposal in items {
        let MlsPublicHandshakeTransition::Proposal {
            proposal_type,
            sender_leaf,
            add_key_package_bytes,
            remove_leaf_index,
            ..
        } = tracker
            .process_public_handshake(&bytes(&proposal.proposal))
            .unwrap()
        else {
            panic!("expected Proposal");
        };
        assert!(sender_leaf.is_some());
        match proposal.proposal_type.as_str() {
            "add" => {
                assert_eq!(proposal_type, 1);
                assert!(add_key_package_bytes.is_some());
                assert!(remove_leaf_index.is_none());
            }
            "remove" => {
                assert_eq!(proposal_type, 3);
                assert!(add_key_package_bytes.is_none());
                assert!(remove_leaf_index.is_some());
            }
            _ => {}
        }
    }
}

#[test]
fn public_tracker_add_update_remove_and_cold_restore() {
    for group_id in [
        b"ak:realm:AdmAewBnEWLWSp60CpdI_JXwYiZGNCIDYLEnjYTgaNz3".as_slice(),
        b"ak:circle:AdmAewBnEWLWSp60CpdI_JXwYiZGNCIDYLEnjYTgaNz3".as_slice(),
    ] {
        let mut group = identity(1).create_group(group_id).unwrap();
        let mut observer = tracker(&group);
        let bob = identity(2);
        let added = group
            .add_member(&bob.key_package_record().unwrap())
            .unwrap();
        proposals(&mut observer, &added.proposals);
        let transition = observer
            .process_public_handshake(&bytes(&added.commit.commit))
            .unwrap();
        let MlsPublicHandshakeTransition::Commit {
            added_leaves,
            added_leaf_proposal_refs,
            removed_leaf_indices,
            ..
        } = transition
        else {
            panic!("commit")
        };
        assert_eq!(added_leaves.len(), 1);
        assert_eq!(added_leaves[0].leaf_index, 1);
        assert_eq!(added_leaf_proposal_refs.len(), 1);
        assert_eq!(added_leaf_proposal_refs[0].0, 1);
        assert!(removed_leaf_indices.is_empty());
        let snapshot = observer.export_state().unwrap();
        observer =
            MlsPublicGroupTracker::restore(&snapshot, &group.group_id(), group.epoch()).unwrap();
        assert!(
            MlsPublicGroupTracker::restore(&snapshot, &group.group_id(), group.epoch() + 1)
                .is_err()
        );
        let update = group.self_update_commit().unwrap();
        let MlsPublicHandshakeTransition::Commit {
            updated_leaf_indices,
            added_leaves,
            ..
        } = observer
            .process_public_handshake(&bytes(&update.commit))
            .unwrap()
        else {
            panic!("commit")
        };
        assert_eq!(updated_leaf_indices, vec![0]);
        assert!(added_leaves.is_empty());
        assert_eq!(
            observer.ratchet_tree_bytes().unwrap(),
            group.public_group_state_bytes().unwrap().1
        );
        let removal = group.remove_members_by_leaf_indices(&[1]).unwrap();
        proposals(&mut observer, &removal.proposals);
        let MlsPublicHandshakeTransition::Commit {
            removed_leaf_indices,
            ..
        } = observer
            .process_public_handshake(&bytes(&removal.commit.commit))
            .unwrap()
        else {
            panic!("commit")
        };
        assert_eq!(removed_leaf_indices, vec![1]);
    }
}

#[test]
fn public_tracker_preserves_queued_refs_and_rejects_missing_proposal_atomically() {
    let mut group = identity(1)
        .create_group(b"ak:realm:AdmAewBnEWLWSp60CpdI_JXwYiZGNCIDYLEnjYTgaNz3")
        .unwrap();
    let mut observer = tracker(&group);
    let package = identity(2).key_package_record().unwrap();
    let key_package =
        crate::identity::decode_key_package(&group.identity.provider, &package).unwrap();
    let (proposal, _) = group
        .group
        .propose_add_member(
            &group.identity.provider,
            &group.identity.signer,
            &key_package,
        )
        .unwrap();
    let (commit, ..) = group
        .group
        .commit_to_pending_proposals(&group.identity.provider, &group.identity.signer)
        .unwrap();
    let commit = commit.tls_serialize_detached().unwrap();
    let before = observer.export_state().unwrap();
    assert!(observer.process_public_handshake(&commit).is_err());
    assert_eq!(before, observer.export_state().unwrap());
    observer
        .process_public_handshake(&proposal.tls_serialize_detached().unwrap())
        .unwrap();
    observer = MlsPublicGroupTracker::restore(
        &observer.export_state().unwrap(),
        &observer.group_id(),
        observer.epoch(),
    )
    .unwrap();
    let MlsPublicHandshakeTransition::Commit {
        consumed_proposal_refs,
        added_leaves,
        ..
    } = observer.process_public_handshake(&commit).unwrap()
    else {
        panic!("commit")
    };
    assert_eq!(consumed_proposal_refs.len(), 1);
    assert_eq!(added_leaves.len(), 1);
}

#[test]
fn public_tracker_exposes_same_index_same_credential_replacement() {
    let mut group = identity(1)
        .create_group(b"ak:realm:AdmAewBnEWLWSp60CpdI_JXwYiZGNCIDYLEnjYTgaNz3")
        .unwrap();
    let bob = identity(2);
    group
        .add_member(&bob.key_package_record().unwrap())
        .unwrap();
    let mut observer = tracker(&group);
    let old = observer.leaves().unwrap()[1].clone();
    let package = bob.key_package_record().unwrap();
    let actor = group
        .verified_leaf_bindings()
        .unwrap()
        .into_iter()
        .find(|b| b.endpoint == package.endpoint)
        .unwrap()
        .actor_id;
    let replacement = group
        .replace_member_endpoint(&package, &actor, None)
        .unwrap();
    proposals(&mut observer, &replacement.proposals);
    let MlsPublicHandshakeTransition::Commit {
        removed_leaf_indices,
        added_leaves,
        ..
    } = observer
        .process_public_handshake(&bytes(&replacement.commit.commit))
        .unwrap()
    else {
        panic!("commit")
    };
    assert_eq!(removed_leaf_indices, vec![old.leaf_index]);
    assert_eq!(added_leaves, vec![old]);
}

#[test]
fn public_tracker_rejects_private_and_bad_signature_but_does_not_claim_secret_mac_validation() {
    let mut group = identity(1)
        .create_group(b"ak:realm:AdmAewBnEWLWSp60CpdI_JXwYiZGNCIDYLEnjYTgaNz3")
        .unwrap();
    let bob = identity(2);
    let added = group
        .add_member(&bob.key_package_record().unwrap())
        .unwrap();
    let mut bob_group = ArkretMlsGroup::join_from_welcome(bob, &added.welcome).unwrap();
    let mut observer = tracker(&group);
    let private = group
        .group
        .create_message(
            &group.identity.provider,
            &group.identity.signer,
            b"private application",
        )
        .unwrap()
        .tls_serialize_detached()
        .unwrap();
    let before = observer.export_state().unwrap();
    assert!(observer.process_public_handshake(&private).is_err());
    assert_eq!(before, observer.export_state().unwrap());
    let update = group.self_update_commit().unwrap();
    let wire = bytes(&update.commit);
    let parsed = MlsMessageIn::tls_deserialize_exact(&wire).unwrap();
    let MlsMessageBodyIn::PublicMessage(public) = parsed.extract() else {
        panic!("public")
    };
    let json = serde_json::to_value(public).unwrap();
    let signature = json["auth"]["signature"]["value"]["vec"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u8)
        .collect::<Vec<_>>();
    let offset = wire
        .windows(signature.len())
        .position(|window| window == signature)
        .unwrap();
    let mut bad = wire.clone();
    bad[offset] ^= 1;
    assert!(observer.process_public_handshake(&bad).is_err());
    assert_eq!(before, observer.export_state().unwrap());
    // Membership MAC is the trailing public-message field, outside the public
    // signature. A public observer cannot authenticate this secret MAC.
    let mut bad_mac = wire;
    *bad_mac.last_mut().unwrap() ^= 1;
    observer.process_public_handshake(&bad_mac).unwrap();
    let message = MlsMessageIn::tls_deserialize_exact(&bad_mac)
        .unwrap()
        .try_into_protocol_message()
        .unwrap();
    let error = bob_group
        .group
        .process_message(&bob_group.identity.provider, message)
        .unwrap_err();
    assert!(
        format!("{error:?}").to_lowercase().contains("membership"),
        "{error:?}"
    );
}

#[test]
fn public_tracker_resolves_referenced_update_without_treating_it_as_replacement() {
    let mut alice = identity(1)
        .create_group(b"ak:realm:AdmAewBnEWLWSp60CpdI_JXwYiZGNCIDYLEnjYTgaNz3")
        .unwrap();
    let bob = identity(2);
    let added = alice
        .add_member(&bob.key_package_record().unwrap())
        .unwrap();
    let mut bob = ArkretMlsGroup::join_from_welcome(bob, &added.welcome).unwrap();
    let mut observer = tracker(&alice);
    let (proposal, _) = bob
        .group
        .propose_self_update(
            &bob.identity.provider,
            &bob.identity.signer,
            openmls::prelude::LeafNodeParameters::default(),
        )
        .unwrap();
    let wire = proposal.tls_serialize_detached().unwrap();
    observer.process_public_handshake(&wire).unwrap();
    let message = MlsMessageIn::tls_deserialize_exact(&wire)
        .unwrap()
        .try_into_protocol_message()
        .unwrap();
    let processed = alice
        .group
        .process_message(&alice.identity.provider, message)
        .unwrap();
    let ProcessedMessageContent::ProposalMessage(proposal) = processed.into_content() else {
        panic!("proposal")
    };
    alice
        .group
        .store_pending_proposal(alice.identity.provider.storage(), *proposal)
        .unwrap();
    let (commit, ..) = alice
        .group
        .commit_to_pending_proposals(&alice.identity.provider, &alice.identity.signer)
        .unwrap();
    let MlsPublicHandshakeTransition::Commit {
        updated_leaf_indices,
        added_leaves,
        removed_leaf_indices,
        referenced_proposal_refs,
        ..
    } = observer
        .process_public_handshake(&commit.tls_serialize_detached().unwrap())
        .unwrap()
    else {
        panic!("commit")
    };
    assert!(updated_leaf_indices.contains(&1));
    assert!(added_leaves.is_empty());
    assert!(removed_leaf_indices.is_empty());
    assert_eq!(referenced_proposal_refs.len(), 1);
}
