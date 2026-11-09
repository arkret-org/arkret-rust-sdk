//! Public historical epoch verification. No member-held private MLS provider
//! is restored, and no current membership or native read authority is minted.

use std::collections::BTreeMap;

use arkret_event_draft::EventContentEnvelopesExt as _;
use arkret_mls::{MlsPublicGroupTracker, MlsVerifiedLeafBinding};
use arkret_models_collaboration::events_payloads::MlsGenesisPayload;
use arkret_models_collaboration::mls_group_state_material::{
    MlsGroupStateMaterialResponseBody, MlsMemberGroupStateMaterialReadRequestBody,
};
use arkret_models_collaboration::mls_roster_authority::{
    MlsMemberRosterAuthorityReadRequestBody, MlsRosterAuthorityReadRequestBody, MlsRosterRecord,
    MlsSelfRosterAuthorityReadResponseBody,
};
use arkret_models_crypto::{
    ContentEndpoint, ContentRootContext, EncryptedEnvelope, EventContentMaterial, MlsCommitPayload,
    MlsGovernanceBindingPayload,
};
use arkret_wire::{CommittedEventFullView, Event, EventId, EventKind};

use super::roster_bindings::{match_occupied_leaf_authorities, verified_roster_authorities};
use super::verify_mls_member_roster_authority_pages;

#[cfg(all(test, feature = "mls-test-utils"))]
#[path = "historical_tests.rs"]
mod tests;

/// The host obtains the complete transcript and originals through its live,
/// authenticated own Station. These borrowed inputs are not a wire carrier or
/// portable proof; native authorization remains at that source boundary.
pub struct MlsHistoricalContentRosterMaterials<'a> {
    pub request: &'a MlsMemberRosterAuthorityReadRequestBody,
    pub pages: &'a [MlsSelfRosterAuthorityReadResponseBody],
    pub genesis_original: &'a CommittedEventFullView,
    pub genesis_material: &'a MlsGroupStateMaterialResponseBody,
    pub target_original: &'a CommittedEventFullView,
    pub target_material: &'a MlsGroupStateMaterialResponseBody,
    pub recovery_material: &'a BTreeMap<EventId, MlsGroupStateMaterialResponseBody>,
    pub root_context: &'a ContentRootContext,
}

/// An exact public epoch's verified leaf attribution, separate from active
/// membership and from original Event producer signatures. The latter use
/// their independently resolved native keys, which can differ from leaf keys.
#[derive(Debug)]
pub struct VerifiedMlsHistoricalContentRoster {
    root_context: ContentRootContext,
    bindings: Vec<MlsVerifiedLeafBinding>,
}

impl VerifiedMlsHistoricalContentRoster {
    pub fn root_context(&self) -> &ContentRootContext {
        &self.root_context
    }

    pub fn content_endpoint(&self, original: &Event) -> Result<ContentEndpoint, String> {
        arkret_mls::content_endpoint_from_verified_roster(
            &self.root_context.effective_scope,
            &self.bindings,
            original,
        )
        .map_err(|error| error.to_string())
    }

    /// The host first consumes this exact original and verifies its native
    /// producer key through the authenticated source. Leaf attribution alone
    /// is not an Event signature verifier or a history-disclosure grant.
    pub fn content_material_for_verified_original(
        &self,
        original: &Event,
        envelope: &EncryptedEnvelope,
    ) -> Result<EventContentMaterial, String> {
        let suite = original.realm_id.digest_suite_code().digest_suite();
        original
            .verify_event_id_matches_content_with_digest_suite(suite)
            .map_err(|error| error.to_string())?;
        original
            .verify_producer_proof_self_consistency(suite)
            .map_err(|error| error.to_string())?;
        if !original
            .event_content_envelopes()
            .map_err(|error| error.to_string())?
            .iter()
            .any(|slot| &slot.envelope == envelope)
        {
            return Err("historical original does not contain this content slot".into());
        }
        EventContentMaterial::from_original(
            original,
            envelope,
            self.root_context.clone(),
            self.content_endpoint(original)?,
        )
        .map_err(|error| error.to_string())
    }
}

pub fn verify_mls_self_historical_content_roster(
    input: MlsHistoricalContentRosterMaterials<'_>,
) -> Result<VerifiedMlsHistoricalContentRoster, String> {
    let peer = verify_mls_member_roster_authority_pages(input.pages, input.request)
        .map_err(|error| error.to_string())?;
    let context = input.root_context;
    context.validate().map_err(|error| error.to_string())?;
    if input.request.cursor.is_some()
        || context.effective_scope != peer.effective_scope
        || context.genesis_event_ref != peer.genesis_event_ref
        || context.group_state_ref != peer.target_commit_event_ref
        || context.epoch != peer.target_epoch
        || context
            .effective_scope
            .canonical_mls_group_id()
            .map_err(|error| error.to_string())?
            != peer.mls_group_id
    {
        return Err("historical roster differs from the exact original root context".into());
    }
    let (genesis_request, _) =
        material_request_for_original(input.genesis_original, &peer, &peer.genesis_event_ref, 0)?;
    input
        .genesis_material
        .validate_for_request(&genesis_request.as_peer_request())
        .map_err(|error| error.to_string())?;
    let genesis: MlsGenesisPayload = serde_json::from_value(
        serde_json::to_value(&input.genesis_original.event.payload)
            .map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    let first = input.pages[0].roster.records.first();
    let Some(MlsRosterRecord::Genesis {
        actor_id,
        leaf_signature_key_base64url,
        endpoint,
        authorization_event_ref,
        ..
    }) = first
    else {
        return Err("historical roster omits its original Genesis authority".into());
    };
    if input.genesis_original.event.actual_signer() != actor_id
        || genesis.cipher_suite.as_str() != context.cipher_suite
        || genesis.creator_leaf_authority.leaf_signature_key_base64url
            != *leaf_signature_key_base64url
        || genesis.creator_leaf_authority.endpoint != *endpoint
        || genesis.creator_leaf_authority.authorization_event_ref != *authorization_event_ref
    {
        return Err("historical Genesis record differs from its accepted original".into());
    }
    let (target_request, target_binding) = material_request_for_original(
        input.target_original,
        &peer,
        &peer.target_commit_event_ref,
        peer.target_epoch,
    )?;
    let bytes = input
        .target_material
        .validate_for_request(&target_request.as_peer_request())
        .map_err(|error| error.to_string())?;
    let public = MlsPublicGroupTracker::from_external(
        &bytes.group_info_bytes,
        &bytes.ratchet_tree_bytes,
        peer.mls_group_id.as_str(),
        peer.target_epoch,
    )
    .map_err(|error| error.to_string())?;
    if public
        .ciphersuite_canonical_id()
        .map_err(|error| error.to_string())?
        != context.cipher_suite
        || public
            .governance_binding()
            .map_err(|error| error.to_string())?
            != target_binding
    {
        return Err("historical public GroupContext differs from its accepted binding".into());
    }
    let pages = input
        .pages
        .iter()
        .map(|page| page.roster.clone())
        .collect::<Vec<_>>();
    let authorities = verified_roster_authorities(
        &pages,
        &peer,
        input.genesis_material,
        input.recovery_material,
    )?;
    let occupied = public.leaves().map_err(|error| error.to_string())?;
    let bindings = match_occupied_leaf_authorities(&occupied, &authorities)?;
    Ok(VerifiedMlsHistoricalContentRoster {
        root_context: context.clone(),
        bindings,
    })
}

fn material_request_for_original(
    original: &CommittedEventFullView,
    roster: &MlsRosterAuthorityReadRequestBody,
    expected_event: &EventId,
    expected_epoch: u64,
) -> Result<
    (
        MlsMemberGroupStateMaterialReadRequestBody,
        MlsGovernanceBindingPayload,
    ),
    String,
> {
    original
        .validate_shape()
        .map_err(|error| error.to_string())?;
    original
        .commit
        .validate_content_address()
        .map_err(|error| error.to_string())?;
    original
        .event
        .verify_event_id_matches_content_with_digest_suite(
            original.event.realm_id.digest_suite_code().digest_suite(),
        )
        .map_err(|error| error.to_string())?;
    if original.event.event_id != *expected_event
        || original.event.scope_ref != roster.effective_scope
        || original.event.realm_id != roster.realm_id
    {
        return Err("historical group original differs from the exact accepted cut".into());
    }
    let payload =
        serde_json::to_value(&original.event.payload).map_err(|error| error.to_string())?;
    let (binding, info, tree) = match original.event.kind {
        EventKind::MlsGenesis if expected_epoch == 0 => {
            let payload: MlsGenesisPayload =
                serde_json::from_value(payload).map_err(|error| error.to_string())?;
            payload.validate().map_err(|error| error.to_string())?;
            (
                payload.governance_binding,
                payload.group_info_ref,
                payload.ratchet_tree_ref,
            )
        }
        EventKind::MlsCommit if expected_epoch > 0 => {
            let payload: MlsCommitPayload =
                serde_json::from_value(payload).map_err(|error| error.to_string())?;
            payload.validate().map_err(|error| error.to_string())?;
            (
                payload.governance_binding().clone(),
                payload.group_info_ref().clone(),
                payload.ratchet_tree_ref().clone(),
            )
        }
        _ => return Err("historical material original is not its accepted MLS epoch".into()),
    };
    if binding.effective_scope() != &roster.effective_scope
        || binding.mls_group_id().map_err(|error| error.to_string())? != roster.mls_group_id
        || binding.next_epoch() != expected_epoch
    {
        return Err("historical group payload differs from the original epoch selectors".into());
    }
    Ok((
        MlsMemberGroupStateMaterialReadRequestBody {
            realm_id: roster.realm_id.clone(),
            effective_scope: roster.effective_scope.clone(),
            mls_group_id: roster.mls_group_id.clone(),
            epoch: expected_epoch,
            group_state_event_id: expected_event.clone(),
            caller_actor_id: roster.caller_actor_id.clone(),
            target_commit_event_ref: roster.target_commit_event_ref.clone(),
            target_epoch: roster.target_epoch,
            group_info_ref: info,
            ratchet_tree_ref: tree,
            max_response_bytes: None,
        },
        binding,
    ))
}
