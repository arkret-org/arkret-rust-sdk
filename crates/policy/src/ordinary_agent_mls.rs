//! Ordinary-Realm Native Agent MLS membership/key cross-binding.

use arkret_wire::{Did, EventId};

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
    pub signer_id: &'a Did,
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

    #[test]
    fn duplicate_agent_leaf_is_rejected() {
        let signer = Did::new("did:webvh:z6mkagent:agent.example").unwrap();
        let authorization = EventId::new("ak:event:01964137-0000-7000-8000-000000000001").unwrap();
        let key = vec![7; 32];
        let leaf = |leaf_index| AuthorLeaf {
            leaf_index,
            credential: AuthorLeafCredential::Basic {
                identity: signer.as_str().as_bytes().to_vec(),
            },
            signature_key: key.clone(),
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
