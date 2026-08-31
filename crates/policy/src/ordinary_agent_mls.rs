//! Ordinary-Realm Agent MLS membership/key cross-binding.

use arkret_wire::{DidCoreId, EventId};

use crate::{AuthorGroupStateView, AuthorLeafCredential};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentMlsSignerView {
    pub group_state: AuthorGroupStateView,
    pub leaf_authorization_refs: Vec<(u32, EventId)>,
}

pub struct AgentMlsSignerClaim<'a> {
    pub group_id: &'a str,
    pub epoch: u64,
    pub group_state_ref: &'a str,
    pub signer_id: &'a DidCoreId,
    pub signing_key: &'a [u8],
    pub agent_key_authorize_event_id: &'a EventId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("agent_mls_leaf_binding_mismatch")]
pub struct AgentMlsLeafBindingError;

pub fn verify_ordinary_agent_mls_binding(
    view: &AgentMlsSignerView,
    claim: &AgentMlsSignerClaim<'_>,
) -> Result<u32, AgentMlsLeafBindingError> {
    let reject = || Err(AgentMlsLeafBindingError);
    if view.group_state.group_id != claim.group_id
        || view.group_state.epoch != claim.epoch
        || view.group_state.group_state_ref != claim.group_state_ref
    {
        return reject();
    }
    let mut matches = view.group_state.active_leaves.iter().filter(|leaf| {
        matches!(
            &leaf.credential,
            AuthorLeafCredential::Basic { identity }
                if identity.as_slice() == claim.signer_id.as_str().as_bytes()
        )
    });
    let Some(leaf) = matches.next() else {
        return reject();
    };
    if matches.next().is_some() || leaf.signature_key.as_slice() != claim.signing_key {
        return reject();
    }
    let mut refs = view
        .leaf_authorization_refs
        .iter()
        .filter(|(leaf_index, _)| *leaf_index == leaf.leaf_index);
    let Some((_, authorization_ref)) = refs.next() else {
        return reject();
    };
    if refs.next().is_some() || authorization_ref != claim.agent_key_authorize_event_id {
        return reject();
    }
    Ok(leaf.leaf_index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthorLeaf;

    fn fixture() -> (DidCoreId, EventId, Vec<u8>, AgentMlsSignerView) {
        let signer = DidCoreId::new("ak:did_core:webvh:z6mkagent:agent.example").unwrap();
        let authorization =
            EventId::new("ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5").unwrap();
        let key = vec![7; 32];
        let view = AgentMlsSignerView {
            group_state: AuthorGroupStateView {
                group_id: "group".to_owned(),
                epoch: 4,
                group_state_ref: "ak:event:ATrYU3cGlcWkAcHXWgJ8sIYfraoV9pIwEHNNStEqHvFh".to_owned(),
                active_leaves: vec![AuthorLeaf {
                    leaf_index: 1,
                    credential: AuthorLeafCredential::Basic {
                        identity: signer.as_str().as_bytes().to_vec(),
                    },
                    signature_key: key.clone(),
                    leaf_node_canonical_bytes: vec![0xA1],
                }],
            },
            leaf_authorization_refs: vec![(1, authorization.clone())],
        };
        (signer, authorization, key, view)
    }

    fn verify_fixture(
        view: &AgentMlsSignerView,
        signer: &DidCoreId,
        authorization: &EventId,
        key: &[u8],
    ) -> Result<u32, AgentMlsLeafBindingError> {
        verify_ordinary_agent_mls_binding(
            view,
            &AgentMlsSignerClaim {
                group_id: "group",
                epoch: 4,
                group_state_ref: "ak:event:ATrYU3cGlcWkAcHXWgJ8sIYfraoV9pIwEHNNStEqHvFh",
                signer_id: signer,
                signing_key: key,
                agent_key_authorize_event_id: authorization,
            },
        )
    }

    #[test]
    fn ordinary_agent_requires_exact_historical_group_state_leaf_and_lineage() {
        let (signer, authorization, key, view) = fixture();
        assert_eq!(verify_fixture(&view, &signer, &authorization, &key), Ok(1));

        let mut missing_leaf = view.clone();
        missing_leaf.group_state.active_leaves.clear();
        assert!(verify_fixture(&missing_leaf, &signer, &authorization, &key).is_err());

        let mut wrong_key = view.clone();
        wrong_key.group_state.active_leaves[0].signature_key = vec![8; 32];
        assert!(verify_fixture(&wrong_key, &signer, &authorization, &key).is_err());

        let mut wrong_lineage = view.clone();
        wrong_lineage.leaf_authorization_refs[0].1 =
            EventId::new("ak:event:ASlHbbnJj2aIvNxwyukjGz90ltQwXHCbjIihxsRDrRR5").unwrap();
        assert!(verify_fixture(&wrong_lineage, &signer, &authorization, &key).is_err());

        let mut duplicate_lineage = view.clone();
        duplicate_lineage
            .leaf_authorization_refs
            .push((1, authorization.clone()));
        assert!(verify_fixture(&duplicate_lineage, &signer, &authorization, &key).is_err());

        let mut wrong_group = view.clone();
        wrong_group.group_state.group_id = "other-group".to_owned();
        assert!(verify_fixture(&wrong_group, &signer, &authorization, &key).is_err());

        let mut wrong_epoch = view.clone();
        wrong_epoch.group_state.epoch = 5;
        assert!(verify_fixture(&wrong_epoch, &signer, &authorization, &key).is_err());

        let mut non_winning_state = view;
        non_winning_state.group_state.group_state_ref =
            "ak:event:AQ4lJ43jR05ytJIf7AGNbPU_MuY1FqT_ny_e8MhCCnwc".to_owned();
        assert!(verify_fixture(&non_winning_state, &signer, &authorization, &key).is_err());
    }

    #[test]
    fn duplicate_agent_leaf_is_rejected() {
        let signer = DidCoreId::new("ak:did_core:webvh:z6mkagent:agent.example").unwrap();
        let authorization =
            EventId::new("ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5").unwrap();
        let key = vec![7; 32];
        let leaf = |leaf_index| AuthorLeaf {
            leaf_index,
            credential: AuthorLeafCredential::Basic {
                identity: signer.as_str().as_bytes().to_vec(),
            },
            signature_key: key.clone(),
            leaf_node_canonical_bytes: vec![0xA1, leaf_index as u8],
        };
        let view = AgentMlsSignerView {
            group_state: AuthorGroupStateView {
                group_id: "group".to_owned(),
                epoch: 4,
                group_state_ref: authorization.to_string(),
                active_leaves: vec![leaf(1), leaf(2)],
            },
            leaf_authorization_refs: vec![(1, authorization.clone()), (2, authorization.clone())],
        };
        assert!(
            verify_ordinary_agent_mls_binding(
                &view,
                &AgentMlsSignerClaim {
                    group_id: "group",
                    epoch: 4,
                    group_state_ref: authorization.as_str(),
                    signer_id: &signer,
                    signing_key: &key,
                    agent_key_authorize_event_id: &authorization,
                },
            )
            .is_err()
        );
    }
}
