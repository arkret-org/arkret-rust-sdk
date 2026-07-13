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
use crate::{
    CellId, CellRef, ERROR_CODE_SCHEMA_VIOLATION, ERROR_CODE_STATE_MISMATCH, MoveId, NotarySig,
    REASON_MLS_GOVERNANCE_BINDING_STALE, Seal, base64url_decode,
};

pub const MLS_GOVERNANCE_PROOF_BUNDLE_VERSION: u8 = 1;
pub const MLS_GOVERNANCE_COMPLETE_MATERIALIZATION_PROFILE: &str = "complete_control_state_v1";

const POLICY_COMPONENTS_CELL: &str = "ak.component.realm.policy_components.v1";
const PLAINTEXT_VISIBLE_SERVICES_CELL: &str = "ak.component.realm.plaintext_visible_services.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MlsGovernanceProofRequest {
    pub realm_id: RealmId,
    pub effective_scope: EffectiveScope,
    pub mls_group_id: String,
    pub previous_epoch: u64,
    pub next_epoch: u64,
    pub binding_profile: String,
    pub reducer_profile: String,
}

impl MlsGovernanceProofRequest {
    pub fn validate(&self) -> Result<()> {
        if self.effective_scope.realm_id() != &self.realm_id {
            return schema("proof request Realm and effective_scope mismatch");
        }
        let is_genesis = self.previous_epoch == 0 && self.next_epoch == 0;
        let is_commit = self.previous_epoch.checked_add(1) == Some(self.next_epoch);
        if !is_genesis && !is_commit {
            return schema(
                "proof request epochs must be 0 -> 0 for genesis or next_epoch = previous_epoch + 1 for a commit",
            );
        }
        if self.binding_profile != MLS_GOVERNANCE_BINDING_FULL_PROFILE {
            return schema("proof request requires the full governance binding profile");
        }
        if self.reducer_profile.trim().is_empty() {
            return schema("proof request reducer_profile must not be empty");
        }
        if base64url_decode(&self.mls_group_id).is_err() {
            return schema("proof request mls_group_id must be base64url");
        }
        Ok(())
    }
}

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
    if path.keys().filter(|id| reachable.contains(*id)).count() != path.len() {
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
                .map(|cell| is_mls_membership_frontier_component(cell.component()))
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

pub fn is_mls_membership_frontier_component(component: &str) -> bool {
    matches!(
        component,
        "ak.component.member.state.v1"
            | "ak.component.realm.create.v1"
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
    Ok(compute_state_root(&filtered)?)
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

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use arkret_state::{CellState, compute_state_root, control_event_set_root};
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;
    use crate::{
        Effect, EventRequirements, Hlc, LatticeOp, LatticeOpType, MoveSignature, Proof, SealKind,
    };

    struct Fixture {
        bundle: MlsGovernanceProofBundle,
        binding: MlsGovernanceBindingPayload,
    }

    fn realm() -> RealmId {
        RealmId::new("ak:realm:0196419b-0000-7000-8000-00000000014a").unwrap()
    }

    fn event_id() -> EventId {
        EventId::new("ak:event:0196419b-0000-7000-8000-000000000002").unwrap()
    }

    fn hash(byte: u8) -> Hash {
        Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap()
    }

    fn cell(component: &str, subject: &str) -> CellRef {
        CellRef::new(format!("ak:cell:{component}:{subject}")).unwrap()
    }

    fn control_state() -> Vec<MlsGovernanceControlStateLeaf> {
        let mut leaves = vec![
            MlsGovernanceControlStateLeaf {
                cell: cell("ak.component.member.state.v1", "did.web.alice.example"),
                state: MlsGovernanceControlStateValue {
                    value: json!({"state": "joined"}),
                },
            },
            MlsGovernanceControlStateLeaf {
                cell: cell("ak.component.realm.policy_components.v1", realm().as_str()),
                state: MlsGovernanceControlStateValue {
                    value: json!({"media_service_decrypts": true}),
                },
            },
            MlsGovernanceControlStateLeaf {
                cell: cell(
                    "ak.component.realm.plaintext_visible_services.v1",
                    realm().as_str(),
                ),
                state: MlsGovernanceControlStateValue {
                    value: json!({
                        "services": [{
                            "service_id": "did:webvh:z6mkfixture:media.example",
                            "data_classes": ["media_plaintext"],
                            "visibility": "realm",
                            "purposes": ["video transcoding"]
                        }]
                    }),
                },
            },
            MlsGovernanceControlStateLeaf {
                cell: cell("ak.component.capability.grant.v1", "ak.grant.fixture"),
                state: MlsGovernanceControlStateValue {
                    value: json!({"active": true}),
                },
            },
        ];
        leaves.sort_by(|left, right| left.cell.as_str().cmp(right.cell.as_str()));
        leaves
    }

    fn state_map(leaves: &[MlsGovernanceControlStateLeaf]) -> BTreeMap<CellRef, CellState> {
        leaves
            .iter()
            .map(|leaf| {
                (
                    leaf.cell.clone(),
                    CellState::Value(leaf.state.value.clone()),
                )
            })
            .collect()
    }

    fn frontier_event(scope: EffectiveScope) -> Event {
        let mut event = Event {
            event_id: event_id(),
            kind: "ak.member.state".into(),
            realm_id: realm(),
            actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            actor_seq: 1,
            created_at: Utc.with_ymd_and_hms(2026, 7, 14, 0, 0, 0).unwrap(),
            hlc: Hlc::new("01980b44cc00-0000-aabbccdd").unwrap(),
            prev_refs: Vec::new(),
            effective_scope: Some(scope),
            refs: Vec::new(),
            preconditions: Vec::new(),
            effects: vec![Effect {
                cell: cell("ak.component.member.state.v1", "did.web.alice.example"),
                op: LatticeOp {
                    op_type: LatticeOpType::Set,
                    tag: None,
                    value: Some(json!({"state": "joined"})),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            }],
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            requirements: EventRequirements::default(),
            redacts: None,
            payload: json!({}),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
        };
        let digest = Hash::new(event.event_digest().unwrap()).unwrap();
        event.proofs.push(Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:alice.example#device-key".to_owned(),
            event_digest: digest,
            created_at: event.created_at,
            domain: None,
            audience: None,
            jws: "AAAA.BBBB.CCCC".to_owned(),
        });
        event
    }

    fn seal(
        state_root: Hash,
        covered_event_digests: Vec<MoveId>,
        control_event_set_root: Hash,
    ) -> Seal {
        let mut seal = Seal {
            id: SealId::new(format!("ak:seal:{}", hash(0).as_str())).unwrap(),
            realm_id: realm(),
            predecessor_refs: Vec::new(),
            delta: Vec::new(),
            control_event_set_root,
            state_root,
            completeness_root: hash(0xcc),
            notary_seq: 1,
            data_view_root: None,
            data_event_set_root: None,
            availability_root: None,
            coverage_scope: None,
            covered_event_digests,
            previous_state_root: None,
            previous_digest_algorithm: None,
            notary_signature: NotarySig::Single(MoveSignature {
                alg: "EdDSA".to_owned(),
                verification_method: "did:webvh:z6mkfixture:notary.example#key-1".to_owned(),
                payload_digest: hash(0),
                created_at: Utc.with_ymd_and_hms(2026, 7, 14, 0, 0, 0).unwrap(),
                jws: "AAAA.BBBB.CCCC".to_owned(),
            }),
            sealed_at: Utc.with_ymd_and_hms(2026, 7, 14, 0, 0, 1).unwrap(),
            hlc: Hlc::new("01980b44cc01-0000-aabbccdd").unwrap(),
            kind: SealKind::Compaction,
        };
        let payload_digest = Hash::new(canonical::sha256_digest(
            seal.canonical_bytes_for_id().unwrap(),
        ))
        .unwrap();
        if let NotarySig::Single(signature) = &mut seal.notary_signature {
            signature.payload_digest = payload_digest;
        }
        seal.id = seal.derive_id().unwrap();
        seal
    }

    fn fixture() -> Fixture {
        let effective_scope = EffectiveScope::Realm { realm_id: realm() };
        let frontier_event = frontier_event(effective_scope.clone());
        let frontier_digest = MoveId::new(frontier_event.event_digest().unwrap()).unwrap();
        let covered_event_digests = vec![frontier_digest.clone()];
        let covered = BTreeSet::from([frontier_digest]);
        let control_state = control_state();
        let states = state_map(&control_state);
        let policy_root = derive_mls_policy_root(&states).unwrap();
        let capability_root = derive_mls_capability_root(&states).unwrap();
        let discussion_metadata_digest =
            derive_mls_discussion_metadata_digest(&control_state).unwrap();
        let binding = MlsGovernanceBindingPayload::realm(
            realm(),
            "YXJrcmV0LW1scy1maXh0dXJl",
            0,
            1,
            vec![event_id()],
            policy_root,
            capability_root,
            discussion_metadata_digest,
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "ak.reducer.v1",
        )
        .unwrap();
        let seal = seal(
            compute_state_root(&states).unwrap(),
            covered_event_digests.clone(),
            control_event_set_root(&covered).unwrap(),
        );
        let seal_id = seal.id.clone();
        Fixture {
            bundle: MlsGovernanceProofBundle {
                bundle_version: MLS_GOVERNANCE_PROOF_BUNDLE_VERSION,
                materialization_profile: MLS_GOVERNANCE_COMPLETE_MATERIALIZATION_PROFILE.to_owned(),
                realm_id: realm(),
                effective_scope,
                reducer_profile: "ak.reducer.v1".to_owned(),
                governance_binding: binding.clone(),
                trust_anchor_seal_id: seal_id.clone(),
                accepted_seal_id: seal_id,
                seal_path: vec![seal],
                covered_event_digests: covered_event_digests
                    .into_iter()
                    .map(|digest| Hash::new(digest.as_str().to_owned()).unwrap())
                    .collect(),
                control_state,
                frontier_events: vec![frontier_event],
            },
            binding,
        }
    }

    fn verify(fixture: &Fixture) -> Result<VerifiedMlsGovernanceProof> {
        verify_mls_governance_proof_bundle(
            &fixture.bundle,
            &fixture.binding,
            &fixture.bundle.trust_anchor_seal_id,
            |_| Ok(()),
            |_| Ok(()),
        )
    }

    #[test]
    fn complete_bundle_verifies() {
        let fixture = fixture();
        let verified = verify(&fixture).unwrap();
        assert_eq!(verified.accepted_seal_id, fixture.bundle.accepted_seal_id);
        assert_eq!(verified.membership_frontier, vec![event_id()]);
    }

    #[test]
    fn proof_request_rejects_epoch_skip() {
        let request = MlsGovernanceProofRequest {
            realm_id: realm(),
            effective_scope: EffectiveScope::Realm { realm_id: realm() },
            mls_group_id: "YXJrcmV0LW1scy1maXh0dXJl".to_owned(),
            previous_epoch: 3,
            next_epoch: 5,
            binding_profile: MLS_GOVERNANCE_BINDING_FULL_PROFILE.to_owned(),
            reducer_profile: "ak.reducer.v1".to_owned(),
        };
        let error = request.validate().unwrap_err();
        assert!(error.to_string().contains(ERROR_CODE_SCHEMA_VIOLATION));
    }

    #[test]
    fn proof_request_accepts_genesis_epoch() {
        let request = MlsGovernanceProofRequest {
            realm_id: realm(),
            effective_scope: EffectiveScope::Realm { realm_id: realm() },
            mls_group_id: "YXJrcmV0LW1scy1maXh0dXJl".to_owned(),
            previous_epoch: 0,
            next_epoch: 0,
            binding_profile: MLS_GOVERNANCE_BINDING_FULL_PROFILE.to_owned(),
            reducer_profile: "ak.reducer.v1".to_owned(),
        };
        request.validate().unwrap();
    }

    #[test]
    fn omitted_control_leaf_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.control_state.remove(0);
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ERROR_CODE_STATE_MISMATCH));
    }

    #[test]
    fn incomplete_covered_manifest_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.covered_event_digests.clear();
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ERROR_CODE_STATE_MISMATCH));
    }

    #[test]
    fn missing_frontier_event_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.frontier_events.clear();
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ERROR_CODE_STATE_MISMATCH));
    }

    #[test]
    fn cross_scope_frontier_event_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.frontier_events[0].effective_scope = None;
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ERROR_CODE_STATE_MISMATCH));
    }

    #[test]
    fn discussion_metadata_tampering_is_rejected() {
        let mut fixture = fixture();
        let bad_binding = MlsGovernanceBindingPayload::realm(
            realm(),
            "YXJrcmV0LW1scy1maXh0dXJl",
            0,
            1,
            vec![event_id()],
            fixture.binding.policy_root().clone(),
            fixture.binding.capability_root().unwrap().clone(),
            hash(0xee),
            MLS_GOVERNANCE_BINDING_FULL_PROFILE,
            "ak.reducer.v1",
        )
        .unwrap();
        fixture.bundle.governance_binding = bad_binding.clone();
        fixture.binding = bad_binding;
        let error = verify(&fixture).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(REASON_MLS_GOVERNANCE_BINDING_STALE)
        );
    }
}
