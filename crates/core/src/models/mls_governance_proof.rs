//! Complete-materialization proof for full-profile MLS governance bindings.
//!
//! A selective Merkle proof only shows that disclosed leaves exist; it cannot
//! prove that a server omitted no policy or capability leaf. The v1 proof
//! therefore materializes the complete covered digest set and every non-bottom
//! control cell committed by the accepted Seal.

use std::collections::{BTreeMap, BTreeSet};

use arkret_state::{CellState, compute_state_root, control_event_set_root};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::*;
use crate::{CellId, CellRef, MoveId, NotarySig, Seal};

pub const MLS_GOVERNANCE_PROOF_BUNDLE_VERSION: u8 = 1;
pub const MLS_GOVERNANCE_COMPLETE_MATERIALIZATION_PROFILE: &str = "complete_control_state_v1";

const POLICY_COMPONENTS_CELL: &str = "ak.component.realm.policy_components.v1";
const PLAINTEXT_VISIBLE_SERVICES_CELL: &str = "ak.component.realm.plaintext_visible_services.v1";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceProofBundle {
    pub bundle_version: u8,
    pub materialization_profile: String,
    pub realm_id: RealmId,
    pub effective_scope: EffectiveScope,
    pub reducer_profile: String,
    pub governance_binding: MlsGovernanceBindingPayload,
    pub trust_anchor_seal_id: SealId,
    pub accepted_seal_id: SealId,
    pub seal_path: Vec<Seal>,
    pub covered_event_digests: Vec<Hash>,
    pub control_state: Vec<MlsGovernanceControlStateLeaf>,
    pub frontier_events: Vec<Event>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceControlStateLeaf {
    pub cell: CellRef,
    pub state: MlsGovernanceControlStateValue,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceControlStateValue {
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMlsGovernanceProof {
    pub accepted_seal_id: SealId,
    pub membership_frontier: Vec<EventId>,
    pub policy_root: Hash,
    pub capability_root: Hash,
    pub discussion_metadata_digest: Hash,
}

/// Verify a complete-materialization proof bundle.
///
/// The callbacks own cryptographic signature verification and authorization
/// resolution. This function always validates the signed object digests,
/// topology, complete Merkle materializations, scope, and governance roots
/// before invoking a successful result.
pub fn verify_mls_governance_proof_bundle<VerifySeal, VerifyEvent>(
    bundle: &MlsGovernanceProofBundle,
    expected_binding: &MlsGovernanceBindingPayload,
    trusted_anchor: &SealId,
    verify_seal_signature: VerifySeal,
    verify_event_signature: VerifyEvent,
) -> Result<VerifiedMlsGovernanceProof>
where
    VerifySeal: Fn(&Seal) -> Result<()>,
    VerifyEvent: Fn(&Event) -> Result<()>,
{
    verify_bundle_header(bundle, expected_binding, trusted_anchor)?;
    let accepted_seal = verify_seal_path(bundle, verify_seal_signature)?;
    let covered = verify_covered_event_materialization(bundle, accepted_seal)?;
    let control_state = verify_control_state_materialization(bundle, accepted_seal)?;
    verify_frontier_events(bundle, expected_binding, &covered, verify_event_signature)?;

    let policy_root = derive_mls_policy_root(&control_state)?;
    if &policy_root != expected_binding.policy_root() {
        return stale("policy_root does not match the complete control state");
    }
    let capability_root = derive_mls_capability_root(&control_state)?;
    if expected_binding.capability_root() != Some(&capability_root) {
        return stale("capability_root does not match the complete control state");
    }
    let discussion_metadata_digest = derive_mls_discussion_metadata_digest(&bundle.control_state)?;
    if expected_binding.discussion_metadata_digest() != Some(&discussion_metadata_digest) {
        return stale("discussion_metadata_digest does not match the complete control state");
    }

    Ok(VerifiedMlsGovernanceProof {
        accepted_seal_id: bundle.accepted_seal_id.clone(),
        membership_frontier: expected_binding.membership_frontier().to_vec(),
        policy_root,
        capability_root,
        discussion_metadata_digest,
    })
}

fn verify_bundle_header(
    bundle: &MlsGovernanceProofBundle,
    expected: &MlsGovernanceBindingPayload,
    trusted_anchor: &SealId,
) -> Result<()> {
    if bundle.bundle_version != MLS_GOVERNANCE_PROOF_BUNDLE_VERSION {
        return schema("unsupported MLS governance proof bundle_version");
    }
    if bundle.materialization_profile != MLS_GOVERNANCE_COMPLETE_MATERIALIZATION_PROFILE {
        return schema("unsupported MLS governance proof materialization_profile");
    }
    if &bundle.trust_anchor_seal_id != trusted_anchor {
        return state_mismatch("bundle trust anchor does not match the locally trusted anchor");
    }
    if &bundle.governance_binding != expected {
        return state_mismatch("bundle governance_binding differs from the MLS transcript binding");
    }
    if &bundle.realm_id != expected.realm_id()
        || &bundle.effective_scope != expected.effective_scope()
        || bundle.reducer_profile != expected.reducer_profile()
    {
        return state_mismatch("bundle Realm, scope, or reducer profile mismatch");
    }
    Ok(())
}

fn verify_seal_path<VerifySeal>(
    bundle: &MlsGovernanceProofBundle,
    verify_seal_signature: VerifySeal,
) -> Result<&Seal>
where
    VerifySeal: Fn(&Seal) -> Result<()>,
{
    if bundle.seal_path.is_empty() {
        return schema("seal_path must not be empty");
    }
    if bundle.seal_path.last().map(|seal| &seal.id) != Some(&bundle.accepted_seal_id) {
        return state_mismatch("accepted_seal_id must identify the final seal_path entry");
    }

    let mut prior = BTreeSet::new();
    let mut path = BTreeMap::new();
    for seal in &bundle.seal_path {
        if seal.realm_id != bundle.realm_id {
            return state_mismatch("seal_path contains a cross-Realm Seal");
        }
        seal.validate_id()?;
        seal.validate_structural()?;
        verify_seal_payload_digest(seal)?;
        verify_seal_signature(seal)?;
        if path.insert(seal.id.clone(), seal).is_some() {
            return schema("seal_path contains duplicate Seal ids");
        }
        if seal.id != bundle.trust_anchor_seal_id {
            if seal.predecessor_refs.is_empty() {
                return state_mismatch("untrusted seal_path entry has no predecessor");
            }
            for predecessor in &seal.predecessor_refs {
                if predecessor != &bundle.trust_anchor_seal_id && !prior.contains(predecessor) {
                    return state_mismatch(
                        "seal_path is not topologically complete from the trusted anchor",
                    );
                }
            }
        }
        prior.insert(seal.id.clone());
    }

    let mut reachable = BTreeSet::new();
    let mut pending = vec![bundle.accepted_seal_id.clone()];
    while let Some(id) = pending.pop() {
        if !reachable.insert(id.clone()) || id == bundle.trust_anchor_seal_id {
            continue;
        }
        if let Some(seal) = path.get(&id) {
            pending.extend(seal.predecessor_refs.iter().cloned());
        }
    }
    if reachable.len() != path.len() {
        return schema("seal_path contains entries outside the accepted Seal ancestry");
    }

    bundle
        .seal_path
        .last()
        .ok_or_else(|| Error::Protocol("seal_path unexpectedly empty".to_owned()))
}

fn verify_seal_payload_digest(seal: &Seal) -> Result<()> {
    let expected = Hash::new(canonical::sha256_digest(seal.canonical_bytes_for_id()?))?;
    match &seal.notary_signature {
        NotarySig::Single(signature) => {
            if signature.payload_digest != expected {
                return state_mismatch("Seal signature payload_digest mismatch");
            }
        }
        NotarySig::Multi(multi) => {
            if multi
                .signatures
                .iter()
                .any(|signature| signature.payload_digest != expected)
            {
                return state_mismatch("Seal multi-signature payload_digest mismatch");
            }
        }
        NotarySig::Threshold(_) => {}
    }
    Ok(())
}

fn verify_covered_event_materialization(
    bundle: &MlsGovernanceProofBundle,
    accepted_seal: &Seal,
) -> Result<BTreeSet<MoveId>> {
    ensure_canonical_order(
        "covered_event_digests",
        bundle
            .covered_event_digests
            .iter()
            .map(|digest| digest.as_str()),
    )?;
    let covered = bundle
        .covered_event_digests
        .iter()
        .map(|digest| MoveId::new(digest.as_str().to_owned()).map_err(Error::from))
        .collect::<Result<BTreeSet<_>>>()?;
    let recomputed = control_event_set_root(&covered)
        .map_err(|error| Error::Protocol(format!("control_event_set_root: {error}")))?;
    if recomputed != accepted_seal.control_event_set_root {
        return state_mismatch("covered_event_digests do not reconstruct control_event_set_root");
    }
    if !accepted_seal.covered_event_digests.is_empty()
        && accepted_seal
            .covered_event_digests
            .iter()
            .ne(covered.iter())
    {
        return state_mismatch(
            "bundle covered_event_digests differ from the compaction Seal manifest",
        );
    }
    Ok(covered)
}

fn verify_control_state_materialization(
    bundle: &MlsGovernanceProofBundle,
    accepted_seal: &Seal,
) -> Result<BTreeMap<CellRef, CellState>> {
    ensure_canonical_order(
        "control_state",
        bundle.control_state.iter().map(|leaf| leaf.cell.as_str()),
    )?;
    let control_state = bundle
        .control_state
        .iter()
        .map(|leaf| {
            (
                leaf.cell.clone(),
                CellState::Value(leaf.state.value.clone()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if control_state.len() != bundle.control_state.len() {
        return schema("control_state contains duplicate cell ids");
    }
    let recomputed = compute_state_root(&control_state)?;
    if recomputed != accepted_seal.state_root {
        return state_mismatch("control_state does not reconstruct the accepted Seal state_root");
    }
    Ok(control_state)
}

fn verify_frontier_events<VerifyEvent>(
    bundle: &MlsGovernanceProofBundle,
    expected: &MlsGovernanceBindingPayload,
    covered: &BTreeSet<MoveId>,
    verify_event_signature: VerifyEvent,
) -> Result<()>
where
    VerifyEvent: Fn(&Event) -> Result<()>,
{
    ensure_canonical_order(
        "membership_frontier",
        expected.membership_frontier().iter().map(EventId::as_str),
    )?;
    ensure_canonical_order(
        "frontier_events",
        bundle
            .frontier_events
            .iter()
            .map(|event| event.event_id.as_str()),
    )?;
    let expected_ids = expected
        .membership_frontier()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let actual_ids = bundle
        .frontier_events
        .iter()
        .map(|event| event.event_id.clone())
        .collect::<BTreeSet<_>>();
    if expected_ids != actual_ids || actual_ids.len() != bundle.frontier_events.len() {
        return state_mismatch(
            "frontier_events do not exactly match governance_binding.membership_frontier",
        );
    }

    for event in &bundle.frontier_events {
        if event.realm_id != bundle.realm_id
            || event.effective_scope.as_ref() != Some(&bundle.effective_scope)
        {
            return state_mismatch("frontier Event Realm or effective_scope mismatch");
        }
        if event.seal_ref.is_some() || event.effects.is_empty() {
            return schema("frontier Event is not a Control Move");
        }
        if !event.effects.iter().any(|effect| {
            CellId::from_ref(&effect.cell)
                .map(|cell| is_membership_frontier_component(cell.component()))
                .unwrap_or(false)
        }) {
            return schema("frontier Event does not affect a membership/device/lifecycle cell");
        }
        event.validate_proof_bindings()?;
        verify_event_signature(event)?;
        let digest = MoveId::new(event.event_digest()?).map_err(Error::from)?;
        if !covered.contains(&digest) {
            return state_mismatch("frontier Event digest is absent from the accepted covered set");
        }
    }
    Ok(())
}

fn is_membership_frontier_component(component: &str) -> bool {
    matches!(
        component,
        "ak.component.member.state.v1"
            | "ak.component.circle.member.v1"
            | "ak.component.account.status.v1"
            | "ak.component.device.authorization.v1"
            | "ak.component.device.list_update.v1"
            | "ak.component.realm.tombstone.v1"
            | "ak.component.realm.destroy.v1"
    )
}

pub fn derive_mls_policy_root(control_state: &BTreeMap<CellRef, CellState>) -> Result<Hash> {
    filtered_control_state_root(control_state, |cell| {
        let component = cell.component();
        (component.starts_with("ak.component.realm.")
            && (component.contains("policy")
                || matches!(
                    component,
                    "ak.component.realm.join_rule.v1"
                        | "ak.component.realm.history_visibility.v1"
                        | "ak.component.realm.media_service.v1"
                        | "ak.component.realm.policy_components.v1"
                        | "ak.component.realm.plaintext_visible_services.v1"
                )))
            || (component.starts_with("ak.component.circle.")
                && ["policy", "history", "encryption", "lifecycle"]
                    .iter()
                    .any(|marker| component.contains(marker)))
    })
}

pub fn derive_mls_capability_root(control_state: &BTreeMap<CellRef, CellState>) -> Result<Hash> {
    filtered_control_state_root(control_state, |cell| {
        cell.component().starts_with("ak.component.capability.")
    })
}

fn filtered_control_state_root(
    control_state: &BTreeMap<CellRef, CellState>,
    include: impl Fn(&CellId) -> bool,
) -> Result<Hash> {
    let mut filtered = BTreeMap::new();
    for (cell_ref, state) in control_state {
        let cell = CellId::from_ref(cell_ref)?;
        if include(&cell) {
            filtered.insert(cell_ref.clone(), state.clone());
        }
    }
    compute_state_root(&filtered)
}

pub fn derive_mls_discussion_metadata_digest(
    control_state: &[MlsGovernanceControlStateLeaf],
) -> Result<Hash> {
    let mut media_service_decrypts = false;
    let mut plaintext_visible_services = Vec::new();
    for leaf in control_state {
        let cell = CellId::from_ref(&leaf.cell)?;
        match cell.component() {
            POLICY_COMPONENTS_CELL => {
                media_service_decrypts = leaf
                    .state
                    .value
                    .get("media_service_decrypts")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
            }
            PLAINTEXT_VISIBLE_SERVICES_CELL => {
                if let Some(services) = leaf.state.value.get("services").and_then(Value::as_array) {
                    for service in services {
                        let exposes_media = service
                            .get("data_classes")
                            .and_then(Value::as_array)
                            .is_some_and(|classes| {
                                classes.iter().any(|class| class == "media_plaintext")
                            });
                        if !exposes_media {
                            continue;
                        }
                        let service_id = service
                            .get("service_id")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                Error::Protocol(
                                    "media_plaintext service is missing service_id".to_owned(),
                                )
                            })?;
                        plaintext_visible_services.push(MediaPlaintextService {
                            service_id: Did::new(service_id.to_owned())?,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    derive_media_decrypt_metadata_digest(&MediaDecryptPolicyValue {
        media_service_decrypts,
        plaintext_visible_services,
    })
}

fn ensure_canonical_order<'a>(
    field: &str,
    values: impl IntoIterator<Item = &'a str>,
) -> Result<()> {
    let values = values.into_iter().collect::<Vec<_>>();
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return schema(&format!(
            "{field} must be canonical sorted and duplicate-free"
        ));
    }
    Ok(())
}

fn schema<T>(message: &str) -> Result<T> {
    Err(Error::Protocol(format!(
        "{message} ({ERROR_CODE_SCHEMA_VIOLATION})"
    )))
}

fn state_mismatch<T>(message: &str) -> Result<T> {
    Err(Error::Protocol(format!(
        "{message} ({ERROR_CODE_STATE_MISMATCH})"
    )))
}

fn stale<T>(message: &str) -> Result<T> {
    Err(Error::Protocol(format!(
        "{message} ({REASON_MLS_GOVERNANCE_BINDING_STALE})"
    )))
}
