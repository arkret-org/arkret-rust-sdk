//! Bounded governance results from the authenticated Account Station.

use arkret_canonical::DigestSuite;
use arkret_wire::{
    Base64UrlString, ContentScheme, EventId, Hash, Result, ScopeRef, SealBasis, WireError,
};
use serde::{Deserialize, Serialize};

use crate::{MlsGovernanceBindingPayload, MlsSecurityFrontierLeaf, ProposedMlsGroupGenesisBinding};

/// Exact local MLS intent evaluated by the serving Account Station.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceFrontierRequest {
    pub effective_scope: ScopeRef,
    pub mls_group_id: Base64UrlString,
    pub local_mls_leaves: Vec<MlsSecurityFrontierLeaf>,
    pub seal_basis: SealBasis,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub base_group_state_ref: Option<EventId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub proposed_group_genesis_binding: Option<ProposedMlsGroupGenesisBinding>,
    pub previous_epoch: u64,
    pub next_epoch: u64,
}

impl MlsGovernanceFrontierRequest {
    pub fn validate(&self) -> Result<()> {
        self.seal_basis.validate_protocol_bounds()?;
        crate::mls_governance_proof::validate_group_binding_query(
            &self.effective_scope,
            &self.mls_group_id,
            &self.local_mls_leaves,
            self.base_group_state_ref.as_ref(),
            self.proposed_group_genesis_binding.as_ref(),
            self.previous_epoch,
            self.next_epoch,
        )?;
        if arkret_canonical::canonical_json_bytes(self)?.len()
            > crate::MLS_GOVERNANCE_PROOF_MAX_REQUEST_BYTES
        {
            return Err(WireError::Protocol("MLS governance frontier request exceeds 8 MiB (mls_governance_proof_bounds_exceeded)".to_owned()));
        }
        Ok(())
    }

    pub fn query_digest(&self) -> Result<Hash> {
        self.validate()?;
        let bytes = arkret_canonical::canonical_json_bytes(self)?;
        Hash::new(arkret_canonical::canonical::sha256_digest_from_slices(&[
            b"ak.mls-governance-frontier-query-v1",
            &[0],
            &bytes,
        ]))
        .map_err(Into::into)
    }
}

/// The complete registered epoch cell value used by an authored CAS predicate.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsEpochHead {
    pub transition_ref: EventId,
    pub transition_event_digest: Hash,
    pub mls_transition_digest: Hash,
    pub effective_scope: ScopeRef,
    pub mls_group_id: Base64UrlString,
    pub previous_epoch: u64,
    pub next_epoch: u64,
    pub content_scheme: ContentScheme,
}

impl MlsEpochHead {
    pub fn validate(&self) -> Result<()> {
        if self.transition_ref.event_digest() != self.transition_event_digest
            || !matches!(
                self.content_scheme,
                ContentScheme::MlsRfc9420 | ContentScheme::MlsExporterAeadV1
            )
            || self.effective_scope.canonical_mls_group_id()? != self.mls_group_id.as_str()
            || !((self.previous_epoch == 0 && self.next_epoch == 0)
                || self.previous_epoch.checked_add(1) == Some(self.next_epoch))
        {
            return mismatch("MLS epoch head identity or epoch binding is inconsistent");
        }
        Ok(())
    }
}

/// A result binds the authenticated request, not an independently trusted proof.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceFrontierOutcome {
    pub query_digest: Hash,
    pub seal_basis: SealBasis,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = String)))]
    pub live_digest_suite: DigestSuite,
    pub governance_binding: MlsGovernanceBindingPayload,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub epoch_head: Option<MlsEpochHead>,
}

impl MlsGovernanceFrontierOutcome {
    pub fn validate_for_request(&self, request: &MlsGovernanceFrontierRequest) -> Result<()> {
        request.validate()?;
        self.seal_basis.validate_protocol_bounds()?;
        let binding = &self.governance_binding;
        binding.validate()?;
        if self.query_digest != request.query_digest()?
            || self.seal_basis != request.seal_basis
            || binding.effective_scope() != &request.effective_scope
            || binding.mls_group_id() != request.mls_group_id.as_str()
            || binding.previous_epoch() != request.previous_epoch
            || binding.next_epoch() != request.next_epoch
            || binding.binding_profile() != arkret_wire::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1
            || binding.reducer_profile() != arkret_wire::CORE_REDUCER_PROFILE
        {
            return mismatch("MLS governance result differs from the exact request");
        }
        if let Some(proposal) = &request.proposed_group_genesis_binding {
            if binding.content_scheme() != proposal.content_scheme
                || binding.durability_policy() != proposal.durability_policy
            {
                return mismatch("MLS governance result differs from the proposed Genesis binding");
            }
        }
        if let Some(head) = &self.epoch_head {
            head.validate()?;
            if head.effective_scope != request.effective_scope
                || head.mls_group_id != request.mls_group_id
                || head.content_scheme != binding.content_scheme()
                || request.proposed_group_genesis_binding.is_some()
            {
                return mismatch("MLS epoch head belongs to a different group or Genesis branch");
            }
        }
        if let Some(base) = &request.base_group_state_ref {
            if !self.epoch_head.as_ref().is_some_and(|head| {
                &head.transition_ref == base && head.next_epoch == request.previous_epoch
            }) {
                return mismatch("MLS successor base does not match the accepted epoch head");
            }
        }
        if arkret_canonical::canonical_json_bytes(self)?.len()
            > crate::MLS_GOVERNANCE_PROOF_MAX_BYTES as usize
        {
            return Err(WireError::Protocol("MLS governance frontier result exceeds 1 MiB (mls_governance_proof_bounds_exceeded)".to_owned()));
        }
        Ok(())
    }
}

/// One already known MLS artifact whose acceptance is decided by the Station.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsAcceptedArtifactRequest {
    pub effective_scope: ScopeRef,
    pub mls_group_id: Base64UrlString,
    pub artifact_ref: EventId,
}

impl MlsAcceptedArtifactRequest {
    pub fn validate(&self) -> Result<()> {
        if !matches!(
            self.effective_scope,
            ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
        ) || self.effective_scope.canonical_mls_group_id()? != self.mls_group_id.as_str()
        {
            return mismatch("MLS artifact query has an inconsistent scope or group");
        }
        if arkret_canonical::canonical_json_bytes(self)?.len() > 64 * 1024 {
            return Err(WireError::Protocol(
                "MLS artifact request exceeds 64 KiB (limit_exceeded)".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn query_digest(&self) -> Result<Hash> {
        self.validate()?;
        let bytes = arkret_canonical::canonical_json_bytes(self)?;
        Hash::new(arkret_canonical::canonical::sha256_digest_from_slices(&[
            b"ak.mls-accepted-artifact-query-v1",
            &[0],
            &bytes,
        ]))
        .map_err(Into::into)
    }
}

/// Authenticated acceptance facts, without a client governance checkpoint.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsAcceptedArtifactOutcome {
    pub query_digest: Hash,
    pub seal_basis: SealBasis,
    pub transition_head: MlsEpochHead,
    pub governance_binding: MlsGovernanceBindingPayload,
    pub mls_frontier_leaves: Vec<MlsSecurityFrontierLeaf>,
    pub current_epoch_head: MlsEpochHead,
}

impl MlsAcceptedArtifactOutcome {
    pub fn validate_for_request(&self, request: &MlsAcceptedArtifactRequest) -> Result<()> {
        request.validate()?;
        self.seal_basis.validate_protocol_bounds()?;
        self.transition_head.validate()?;
        self.current_epoch_head.validate()?;
        self.governance_binding.validate()?;
        arkret_wire::mls_transition::validate_mls_frontier_leaves(&self.mls_frontier_leaves)?;
        let head = &self.transition_head;
        let current = &self.current_epoch_head;
        let binding = &self.governance_binding;
        if self.query_digest != request.query_digest()?
            || head.effective_scope != request.effective_scope
            || head.mls_group_id != request.mls_group_id
            || current.effective_scope != request.effective_scope
            || current.mls_group_id != request.mls_group_id
            || head.next_epoch > current.next_epoch
            || (head.next_epoch == current.next_epoch && head != current)
            || head.content_scheme != current.content_scheme
            || binding.effective_scope() != &head.effective_scope
            || binding.mls_group_id() != head.mls_group_id.as_str()
            || binding.previous_epoch() != head.previous_epoch
            || binding.next_epoch() != head.next_epoch
            || binding.content_scheme() != head.content_scheme
            || binding.binding_profile() != arkret_wire::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1
            || binding.reducer_profile() != arkret_wire::CORE_REDUCER_PROFILE
        {
            return mismatch(
                "MLS accepted artifact result differs from the exact query or transition",
            );
        }
        if arkret_canonical::canonical_json_bytes(self)?.len() > 16 * 1024 * 1024 {
            return Err(WireError::Protocol(
                "MLS artifact result exceeds 16 MiB (limit_exceeded)".to_owned(),
            ));
        }
        Ok(())
    }
}

fn mismatch<T>(message: &str) -> Result<T> {
    Err(WireError::Protocol(format!("{message} (state_mismatch)")))
}

#[cfg(test)]
mod tests {
    use arkret_wire::{AccountId, ActorId, DidCoreId, NonEmptyString, RealmId, SealId};

    use super::*;

    fn request() -> MlsGovernanceFrontierRequest {
        let effective_scope = ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI")
                .unwrap(),
        };
        MlsGovernanceFrontierRequest {
            mls_group_id: Base64UrlString::new(effective_scope.canonical_mls_group_id().unwrap())
                .unwrap(),
            effective_scope,
            local_mls_leaves: vec![MlsSecurityFrontierLeaf {
                leaf_index: 0,
                actor_id: ActorId::account(AccountId::new(
                    DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                    DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                )),
                credential_ref: NonEmptyString::new("device-1").unwrap(),
            }],
            seal_basis: SealBasis {
                leaves: vec![SealId::new(
                "ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ).unwrap()],
            },
            base_group_state_ref: None,
            proposed_group_genesis_binding: Some(ProposedMlsGroupGenesisBinding {
                content_scheme: ContentScheme::MlsRfc9420,
                durability_policy: None,
            }),
            previous_epoch: 0,
            next_epoch: 0,
        }
    }

    fn outcome(request: &MlsGovernanceFrontierRequest) -> MlsGovernanceFrontierOutcome {
        MlsGovernanceFrontierOutcome {
            query_digest: request.query_digest().unwrap(),
            seal_basis: request.seal_basis.clone(),
            live_digest_suite: DigestSuite::Sha256,
            governance_binding: MlsGovernanceBindingPayload::realm(
                request.effective_scope.realm_id_opt().unwrap().clone(),
                request.mls_group_id.clone(),
                request.previous_epoch,
                request.next_epoch,
                Hash::new(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
                ContentScheme::MlsRfc9420,
                None,
                arkret_wire::ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
                arkret_wire::CORE_REDUCER_PROFILE,
            )
            .unwrap(),
            epoch_head: None,
        }
    }

    #[test]
    fn self_frontier_optional_members_reject_explicit_null() {
        for name in ["base_group_state_ref", "proposed_group_genesis_binding"] {
            let mut wire = serde_json::to_value(request()).unwrap();
            wire[name] = serde_json::Value::Null;
            assert!(serde_json::from_value::<MlsGovernanceFrontierRequest>(wire).is_err());
        }
        let mut wire = serde_json::to_value(outcome(&request())).unwrap();
        wire["epoch_head"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<MlsGovernanceFrontierOutcome>(wire).is_err());
    }

    #[test]
    fn self_frontier_rejects_peer_proof_fields_even_when_null() {
        let request = request();
        request.validate().unwrap();
        for name in [
            "proof_base_basis",
            "proof_target_basis",
            "byte_limit",
            "frontier_purpose",
        ] {
            for value in [serde_json::Value::Null, serde_json::json!({})] {
                let mut json = serde_json::to_value(&request).unwrap();
                json[name] = value;
                assert!(serde_json::from_value::<MlsGovernanceFrontierRequest>(json).is_err());
            }
        }
    }

    #[test]
    fn self_frontier_request_uses_eight_mib_not_the_response_ceiling() {
        let mut request = request();
        let actor = request.local_mls_leaves[0].actor_id.clone();
        let leaves = |count| {
            (0..count)
                .map(|index| MlsSecurityFrontierLeaf {
                    leaf_index: index,
                    actor_id: actor.clone(),
                    credential_ref: NonEmptyString::new(format!("{index:08}{}", "x".repeat(2040)))
                        .unwrap(),
                })
                .collect()
        };
        request.local_mls_leaves = leaves(600);
        let size = arkret_canonical::canonical_json_bytes(&request)
            .unwrap()
            .len();
        assert!(size > crate::MLS_GOVERNANCE_PROOF_MAX_BYTES as usize);
        assert!(size < crate::MLS_GOVERNANCE_PROOF_MAX_REQUEST_BYTES);
        request.validate().unwrap();
        request.local_mls_leaves = leaves(5000);
        assert!(
            request
                .validate()
                .unwrap_err()
                .to_string()
                .contains("8 MiB")
        );
    }

    #[test]
    fn self_frontier_result_binds_station_leaf_intent_basis_and_genesis() {
        let request = request();
        let result = outcome(&request);
        result.validate_for_request(&request).unwrap();
        let mut other = request.clone();
        other.local_mls_leaves[0].actor_id = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        assert_ne!(
            request.query_digest().unwrap(),
            other.query_digest().unwrap()
        );
        assert!(result.validate_for_request(&other).is_err());
        let mut changed = result.clone();
        changed.seal_basis.leaves[0] = SealId::new(
            "ak:seal:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )
        .unwrap();
        assert!(changed.validate_for_request(&request).is_err());
        let mut proposal = request.clone();
        proposal.proposed_group_genesis_binding = Some(ProposedMlsGroupGenesisBinding {
            content_scheme: ContentScheme::MlsExporterAeadV1,
            durability_policy: Some(arkret_wire::DurabilityPolicy::None),
        });
        let mut rebound = result;
        rebound.query_digest = proposal.query_digest().unwrap();
        assert!(rebound.validate_for_request(&proposal).is_err());
    }

    #[test]
    fn self_frontier_successor_requires_exact_accepted_epoch_head() {
        let mut request = request();
        request.proposed_group_genesis_binding = None;
        request.previous_epoch = 2;
        request.next_epoch = 3;
        let event_digest =
            Hash::new("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
                .unwrap();
        let transition_ref = EventId::from_event_digest(&event_digest).unwrap();
        request.base_group_state_ref = Some(transition_ref.clone());
        let mut result = outcome(&request);
        assert!(result.validate_for_request(&request).is_err());
        result.epoch_head = Some(MlsEpochHead {
            transition_ref,
            transition_event_digest: event_digest.clone(),
            mls_transition_digest: event_digest,
            effective_scope: request.effective_scope.clone(),
            mls_group_id: request.mls_group_id.clone(),
            previous_epoch: 1,
            next_epoch: 2,
            content_scheme: ContentScheme::MlsRfc9420,
        });
        result.validate_for_request(&request).unwrap();
        result.epoch_head.as_mut().unwrap().next_epoch = 1;
        assert!(result.validate_for_request(&request).is_err());
    }
    #[test]
    fn accepted_artifact_result_binds_query_group_epoch_and_exact_leaf_input() {
        let intent = request();
        let binding = outcome(&intent).governance_binding;
        let event = EventId::new("ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml").unwrap();
        let query = MlsAcceptedArtifactRequest {
            effective_scope: intent.effective_scope.clone(),
            mls_group_id: intent.mls_group_id.clone(),
            artifact_ref: event.clone(),
        };
        let head = MlsEpochHead {
            transition_ref: event.clone(),
            transition_event_digest: event.event_digest(),
            mls_transition_digest: event.event_digest(),
            effective_scope: intent.effective_scope,
            mls_group_id: intent.mls_group_id,
            previous_epoch: 0,
            next_epoch: 0,
            content_scheme: ContentScheme::MlsRfc9420,
        };
        let accepted = MlsAcceptedArtifactOutcome {
            query_digest: query.query_digest().unwrap(),
            seal_basis: intent.seal_basis,
            transition_head: head.clone(),
            governance_binding: binding,
            mls_frontier_leaves: intent.local_mls_leaves,
            current_epoch_head: head,
        };
        accepted.validate_for_request(&query).unwrap();
        let mut other_query = query.clone();
        other_query.artifact_ref =
            EventId::new("ak:event:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap();
        assert!(accepted.validate_for_request(&other_query).is_err());
        let mut changed = accepted.clone();
        changed.current_epoch_head.transition_ref = other_query.artifact_ref.clone();
        changed.current_epoch_head.transition_event_digest =
            other_query.artifact_ref.event_digest();
        assert!(changed.validate_for_request(&query).is_err());
        let mut changed = accepted.clone();
        changed.mls_frontier_leaves.clear();
        assert!(changed.validate_for_request(&query).is_err());
        let mut old = serde_json::to_value(&accepted).unwrap();
        old["target_checkpoint"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<MlsAcceptedArtifactOutcome>(old).is_err());
        let mut old = serde_json::to_value(&query).unwrap();
        old["proof_base_basis"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<MlsAcceptedArtifactRequest>(old).is_err());
    }
}
