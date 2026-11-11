//! A fresh endpoint's durable candidate, isolated from installed member state.

use arkret_models_collaboration::mls_group_state_material::{
    MlsGroupStateMaterialRequestBody, MlsGroupStateMaterialResponseBody,
};
use arkret_models_crypto::ContentRecoveryBinding;
use openmls::prelude::RatchetTreeIn;
use zeroize::Zeroize;

use super::*;

/// No application encryption or installed-member access is exposed before
/// exact authority acceptance. Persist `export_private_state` in the caller's
/// encrypted journal before submitting the frozen Event. Native replacement
/// authorization, inventory fencing and the all-scope barrier belong to callers.
pub struct PreparedMlsRecoveryExternalCommit {
    candidate: ArkretMlsGroup,
    current: MlsGroupValue,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenRecoveryCandidate {
    actor_id: ActorId,
    endpoint: MlsEndpointIdentity,
    identity_private_state: Vec<u8>,
    current: MlsGroupValue,
    evidence: InstalledMlsRecovery,
}

impl Drop for FrozenRecoveryCandidate {
    fn drop(&mut self) {
        self.identity_private_state.zeroize();
    }
}

impl PreparedMlsRecoveryExternalCommit {
    /// `accepted_base` and `current` must already have independently verified
    /// native authority. Material must name that exact accepted Event, never
    /// an unauthenticated GroupInfo selected from a replacement's own payload.
    pub fn prepare(
        identity: ArkretMlsIdentity,
        accepted_base: &CommittedEventFullView,
        material: &MlsGroupStateMaterialResponseBody,
        current: &MlsGroupValue,
        recovery: &ContentRecoveryBinding,
        binding: &MlsGovernanceBindingPayload,
    ) -> Result<Self> {
        accepted_base.validate_shape()?;
        let value =
            serde_json::Value::Object(accepted_base.event.payload.clone().into_iter().collect());
        let (info_ref, tree_ref, base_binding) = match accepted_base.event.kind {
            EventKind::MlsGenesis => {
                let payload: arkret_models_collaboration::events_payloads::MlsGenesisPayload =
                    serde_json::from_value(value)?;
                payload.validate()?;
                (
                    payload.group_info_ref,
                    payload.ratchet_tree_ref,
                    payload.governance_binding,
                )
            }
            EventKind::MlsCommit => {
                let payload: MlsCommitPayload = serde_json::from_value(value)?;
                payload.validate()?;
                (
                    payload.group_info_ref().clone(),
                    payload.ratchet_tree_ref().clone(),
                    payload.governance_binding().clone(),
                )
            }
            _ => {
                return Err(Error::Protocol(
                    "recovery base must be an accepted MLS state Event".into(),
                ));
            }
        };
        if accepted_base.event.event_id != current.current_mls_commit_event_ref
            || accepted_base.event.scope_ref != current.effective_scope
            || current.effective_scope.realm_id_opt() != Some(&accepted_base.event.realm_id)
            || base_binding.effective_scope() != &current.effective_scope
            || base_binding.next_epoch() != current.epoch
            || material.ratchet_tree_ref != current.public_tree_ref
            || current.cipher_suite.as_str() != ARKRET_MLS_CIPHERSUITE_CANONICAL_ID
        {
            return Err(Error::Protocol(
                "recovery material differs from independently accepted base".into(),
            ));
        }
        let request = MlsGroupStateMaterialRequestBody {
            realm_id: accepted_base.event.realm_id.clone(),
            effective_scope: current.effective_scope.clone(),
            mls_group_id: current.effective_scope.canonical_mls_group_id()?,
            epoch: current.epoch,
            group_state_event_id: accepted_base.event.event_id.clone(),
            caller_actor_id: None,
            target_commit_event_ref: None,
            target_epoch: None,
            group_info_ref: info_ref,
            ratchet_tree_ref: tree_ref,
            max_response_bytes: None,
        };
        let bytes = material.validate_for_request(&request)?;
        validate_replacement_identity(&identity, recovery)?;
        verify_current(current, binding)?;
        let provider = &identity.provider;
        let raw_group_id = GroupId::from_slice(&decode(request.mls_group_id.as_str())?);
        if MlsGroup::load(provider.storage(), &raw_group_id)
            .map_err(mls_error)?
            .is_some()
        {
            return Err(Error::Protocol(
                "external recovery requires a fresh local group holder".into(),
            ));
        }
        let MlsMessageBodyIn::GroupInfo(info) =
            MlsMessageIn::tls_deserialize_exact(&bytes.group_info_bytes)
                .map_err(mls_error)?
                .extract()
        else {
            return Err(Error::Protocol(
                "recovery material must contain GroupInfo".into(),
            ));
        };
        let tree =
            RatchetTreeIn::tls_deserialize_exact(&bytes.ratchet_tree_bytes).map_err(mls_error)?;
        let (mut group, bundle) = MlsGroup::external_commit_builder()
            .with_config(
                MlsGroupJoinConfig::builder()
                    .wire_format_policy(handshake_policy(&current.effective_scope)?)
                    .build(),
            )
            .with_aad(binding.to_deterministic_cbor()?)
            .with_ratchet_tree(tree)
            .build_group(provider, info, identity.credential.clone())
            .map_err(mls_error)?
            .leaf_node_parameters(
                LeafNodeParameters::builder()
                    .with_capabilities(arkret_openmls_capabilities())
                    .with_extensions(keypackage_capabilities_leaf_extensions()?)
                    .build(),
            )
            .load_psks(provider.storage())
            .map_err(mls_error)?
            .build(provider.rand(), provider.crypto(), &identity.signer, |_| {
                true
            })
            .map_err(mls_error)?
            .finalize(provider)
            .map_err(mls_error)?;
        if group.pending_commit().is_some() {
            group.merge_pending_commit(provider).map_err(mls_error)?;
        }
        let wire = bundle
            .into_commit()
            .tls_serialize_detached()
            .map_err(mls_error)?;
        let evidence = InstalledMlsRecovery {
            base_group_info: bytes.group_info_bytes,
            base_ratchet_tree: bytes.ratchet_tree_bytes,
            commit: MlsCommitEnvelope {
                group_id: request.mls_group_id.clone(),
                epoch: binding.next_epoch(),
                commit: encode(&wire),
                commit_digest: Hash::new(canonical::sha256_digest(&wire))?,
                ratchet_tree: None,
            },
            recovery: recovery.clone(),
            binding: binding.clone(),
        };
        let candidate = ArkretMlsGroup {
            identity,
            group,
            scope: current.effective_scope.clone(),
            group_id: request.mls_group_id,
            installed_recovery: Some(evidence.clone()),
            content_roots: BTreeMap::new(),
            leaf_bindings: BTreeMap::new(),
            signal_nonce_counter: Default::default(),
            own_pending_commit_digest: None,
        };
        evidence.verify_group(&candidate)?;
        Ok(Self {
            candidate,
            current: current.clone(),
        })
    }

    pub fn commit(&self) -> &MlsCommitEnvelope {
        &self.evidence().commit
    }

    /// Publish these exact post-transition bytes through the existing private
    /// material upload lane; their refs belong in the original signed Event.
    pub fn public_group_state_bytes(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        self.candidate.public_group_state_bytes()
    }

    /// Contains private keys. Only the encrypted local recovery journal may
    /// retain this; account backup exports content roots through a separate API.
    pub fn export_private_state(&self) -> Result<Zeroizing<Vec<u8>>> {
        let frozen = FrozenRecoveryCandidate {
            actor_id: self.candidate.identity.actor_id.clone(),
            endpoint: self.candidate.identity.endpoint.clone(),
            identity_private_state: self.candidate.identity.export_private_state()?,
            current: self.current.clone(),
            evidence: self.evidence().clone(),
        };
        Ok(Zeroizing::new(serde_json::to_vec(&frozen)?))
    }

    /// Restore the exact persisted candidate; never rebuild a timed-out
    /// submission with fresh randomness or import the lost endpoint's state.
    pub fn restore_private_state(
        bytes: &[u8],
        expected_actor: &ActorId,
        expected_endpoint: &MlsEndpointIdentity,
        expected_recovery: &ContentRecoveryBinding,
        expected_current: &MlsGroupValue,
    ) -> Result<Self> {
        let frozen: FrozenRecoveryCandidate = serde_json::from_slice(bytes)?;
        if &frozen.actor_id != expected_actor
            || &frozen.endpoint != expected_endpoint
            || &frozen.evidence.recovery != expected_recovery
            || &frozen.current != expected_current
        {
            return Err(Error::Protocol(
                "frozen external recovery belongs to another episode or base".into(),
            ));
        }
        let identity = ArkretMlsIdentity::restore_from_private_state(
            expected_actor.clone(),
            expected_endpoint.clone(),
            &frozen.identity_private_state,
        )?;
        validate_replacement_identity(&identity, expected_recovery)?;
        verify_current(expected_current, &frozen.evidence.binding)?;
        let raw_group_id = GroupId::from_slice(&decode(frozen.evidence.commit.group_id.as_str())?);
        let group = MlsGroup::load(identity.provider.storage(), &raw_group_id)
            .map_err(mls_error)?
            .ok_or_else(|| {
                Error::Protocol("frozen external recovery has no private group".into())
            })?;
        let candidate = ArkretMlsGroup {
            identity,
            group,
            scope: frozen.current.effective_scope.clone(),
            group_id: frozen.evidence.commit.group_id.clone(),
            installed_recovery: Some(frozen.evidence.clone()),
            content_roots: BTreeMap::new(),
            leaf_bindings: BTreeMap::new(),
            signal_nonce_counter: Default::default(),
            own_pending_commit_digest: None,
        };
        if candidate.has_pending_commit()
            || !candidate.is_active()
            || candidate.group.configuration().wire_format_policy()
                != handshake_policy(candidate.scope())?
        {
            return Err(Error::Protocol(
                "frozen external recovery has an invalid candidate state".into(),
            ));
        }
        frozen.evidence.verify_group(&candidate)?;
        Ok(Self {
            candidate,
            current: expected_current.clone(),
        })
    }

    /// The caller independently verifies the original Event and RealmCommit,
    /// native recovery source and installed roster bindings first. Returning a
    /// group permits security cleanup only while the global barrier is pending.
    pub fn install_accepted(
        mut self,
        item: &CommittedEventFullView,
        bindings: Vec<MlsVerifiedLeafBinding>,
    ) -> Result<ArkretMlsGroup> {
        item.validate_shape()?;
        if item.event.kind != EventKind::MlsCommit
            || item.event.scope_ref != self.current.effective_scope
            || item.event.actual_signer() != &self.evidence().recovery.replacement.actor_id
        {
            return Err(Error::Protocol(
                "accepted external recovery has another producer or scope".into(),
            ));
        }
        let payload: MlsCommitPayload = serde_json::from_value(serde_json::Value::Object(
            item.event.payload.clone().into_iter().collect(),
        ))?;
        payload.validate()?;
        if payload.commit_envelope()? != self.evidence().commit
            || payload.recovery_binding() != Some(&self.evidence().recovery)
            || payload.governance_binding() != &self.evidence().binding
        {
            return Err(Error::Protocol(
                "accepted external recovery differs from frozen candidate".into(),
            ));
        }
        let (info, tree) = self.public_group_state_bytes()?;
        for (reference, bytes) in [
            (payload.group_info_ref(), info),
            (payload.ratchet_tree_ref(), tree),
        ] {
            let digest =
                arkret_models_collaboration::mls_group_state_material::material_digest_from_ref(
                    reference,
                )?;
            canonical::verify_digest(&bytes, digest.as_str())?;
        }
        self.evidence().verify_group(&self.candidate)?;
        self.candidate.install_verified_leaf_bindings(bindings)?;
        Ok(self.candidate)
    }

    fn evidence(&self) -> &InstalledMlsRecovery {
        self.candidate
            .installed_recovery
            .as_ref()
            .expect("prepared recovery always carries exact evidence")
    }
}

fn verify_current(current: &MlsGroupValue, binding: &MlsGovernanceBindingPayload) -> Result<()> {
    let state = MlsGovernanceBindingPublicState::new(
        current.effective_scope.clone(),
        Some(current.current_mls_commit_event_ref.clone()),
        current.epoch,
        current.current_key_access_revision,
    );
    crate::verify_governance_binding_against_public_state_and_payload(binding, &state, binding)
        .map_err(|error| Error::Protocol(error.code().into()))?;
    Ok(())
}

fn validate_replacement_identity(
    identity: &ArkretMlsIdentity,
    recovery: &ContentRecoveryBinding,
) -> Result<()> {
    recovery.validate()?;
    identity.profile.validate_endpoint(&identity.endpoint)?;
    let endpoint_matches = match (&identity.endpoint, &recovery.replacement.endpoint) {
        (
            MlsEndpointIdentity::HumanDevice { device_id, .. },
            MlsWelcomeRecipientEndpoint::Device { device_id: target },
        ) => device_id == target,
        (
            MlsEndpointIdentity::AgentRuntime {
                verification_method,
                agent_key_authorize_event_id,
                ..
            },
            MlsWelcomeRecipientEndpoint::AgentRuntime {
                verification_method: target,
            },
        ) => {
            verification_method == target
                && agent_key_authorize_event_id == &recovery.authorization_event_ref
        }
        _ => false,
    };
    if identity.actor_id != recovery.replacement.actor_id
        || !endpoint_matches
        || encode(identity.signer.public()) != recovery.replacement.signature_key_base64url
    {
        return Err(Error::Protocol(
            "replacement differs from fresh native MLS identity".into(),
        ));
    }
    Ok(())
}
