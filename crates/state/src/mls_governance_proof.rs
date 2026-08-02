//! Verification for complete-materialization MLS governance proofs.
//!
//! The proof request / bundle / chunk data shapes and the chunk build /
//! assemble commitment machinery live in
//! `arkret_models_crypto::mls_governance_proof` (re-exported here). This
//! module owns the verification and control-state root derivation that need
//! `arkret-state` (Seal state roots, `CellState`).
//!
//! `verify_mls_governance_proof_bundle` is generic over the caller's error
//! type `E` (with `E: From<WireError>`): the injected signature and projection
//! callbacks and the returned `Result` share `E`, so callers can use
//! `WireError` directly or a boundary error that implements `From<WireError>`.

use std::collections::{BTreeMap, BTreeSet};

pub use arkret_models_crypto::mls_governance_proof::*;
use arkret_models_crypto::mls_payloads::MlsGovernanceBindingPayload;
use arkret_wire::cell::CellId;
use arkret_wire::event_envelope::{Event, ScopeRef};
use arkret_wire::{CellRef, Error, Hash, NotarySig, Result, Seal, SealId, canonical};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::{CellState, compute_state_root, control_event_set_root};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMlsGovernanceProof {
    pub accepted_seal_id: SealId,
    pub security_frontier_digest: Hash,
}

#[derive(Serialize)]
struct SecurityFrontierCellEntry {
    cell_family: String,
    cell_subject: Value,
    projected_value_digest: Hash,
}

#[derive(Serialize)]
struct SecurityFrontierDigestInput<'a> {
    profile_id: &'static str,
    effective_scope: &'a ScopeRef,
    cell_entries: &'a [SecurityFrontierCellEntry],
    mls_leaf_set_digest: &'a Hash,
}

/// Rebuild the single MLS key-access frontier from accepted control state and
/// the verifier-owned current/pending leaf set.
pub fn derive_mls_security_frontier(
    control_state: &BTreeMap<CellRef, CellState>,
    effective_scope: &ScopeRef,
    leaves: &[MlsSecurityFrontierLeaf],
) -> Result<Hash> {
    validate_effective_scope(effective_scope)?;
    let (canonical_leaves, leaf_principals, leaf_credentials) = canonical_leaf_set(leaves)?;
    let mls_leaf_set_digest = canonical_hash(&canonical_leaves)?;
    let mut cell_entries = Vec::new();
    for (cell, state) in control_state {
        let CellState::Value(value) = state else {
            return stale("security frontier control state contains Bottom");
        };
        let cell_id = CellId::from_ref(cell)?;
        let family = cell_id.component();
        let registered =
            crate::generated::mls_security_frontier::MLS_SECURITY_FRONTIER_CELL_FAMILIES
                .binary_search_by(|candidate| candidate.as_bytes().cmp(family.as_bytes()))
                .is_ok();
        if !registered {
            continue;
        }
        let projected = project_frontier_value(
            family,
            value,
            effective_scope,
            &leaf_principals,
            &leaf_credentials,
            &cell_id,
        )?;
        let Some(projected) = projected else {
            continue;
        };
        cell_entries.push(SecurityFrontierCellEntry {
            cell_family: family.to_owned(),
            cell_subject: decoded_cell_subject(&cell_id)?,
            projected_value_digest: canonical_hash(&projected)?,
        });
    }
    cell_entries.sort_by(|left, right| {
        left.cell_family
            .as_bytes()
            .cmp(right.cell_family.as_bytes())
            .then_with(|| {
                canonical::canonical_json_bytes(&left.cell_subject)
                    .expect("serializing a JSON value cannot fail")
                    .cmp(
                        &canonical::canonical_json_bytes(&right.cell_subject)
                            .expect("serializing a JSON value cannot fail"),
                    )
            })
            .then_with(|| {
                left.projected_value_digest
                    .as_str()
                    .cmp(right.projected_value_digest.as_str())
            })
    });
    if cell_entries.windows(2).any(|pair| {
        pair[0].cell_family == pair[1].cell_family
            && pair[0].cell_subject == pair[1].cell_subject
            && pair[0].projected_value_digest == pair[1].projected_value_digest
    }) {
        return schema("security frontier contains duplicate projected cell entries");
    }
    canonical_hash(&SecurityFrontierDigestInput {
        profile_id: crate::generated::mls_security_frontier::MLS_SECURITY_FRONTIER_PROFILE_ID,
        effective_scope,
        cell_entries: &cell_entries,
        mls_leaf_set_digest: &mls_leaf_set_digest,
    })
}

fn canonical_leaf_set(
    leaves: &[MlsSecurityFrontierLeaf],
) -> Result<(Vec<Value>, BTreeSet<String>, BTreeSet<String>)> {
    let mut encoded = leaves
        .iter()
        .map(|leaf| {
            let value = serde_json::to_value(leaf).map_err(|error| {
                Error::Protocol(format!("serialize MLS security frontier leaf: {error}"))
            })?;
            let bytes = canonical::canonical_json_bytes(&value)?;
            Ok((
                bytes,
                value,
                leaf.principal_id.to_string(),
                leaf.credential_ref.to_string(),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    encoded.sort_by(|left, right| left.0.cmp(&right.0));
    if encoded.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return schema("MLS security frontier leaf set contains duplicates");
    }
    let mut indexes = BTreeSet::new();
    let mut principals = BTreeSet::new();
    let mut credentials = BTreeSet::new();
    for leaf in leaves {
        if !indexes.insert(leaf.leaf_index) {
            return schema("MLS security frontier leaf_index values must be unique");
        }
        principals.insert(leaf.principal_id.to_string());
        if !credentials.insert(leaf.credential_ref.to_string()) {
            return schema("MLS security frontier credential_ref values must be unique");
        }
    }
    Ok((
        encoded.into_iter().map(|(_, value, ..)| value).collect(),
        principals,
        credentials,
    ))
}

fn project_frontier_value(
    family: &str,
    value: &Value,
    scope: &ScopeRef,
    leaf_principals: &BTreeSet<String>,
    leaf_credentials: &BTreeSet<String>,
    cell_id: &CellId,
) -> Result<Option<Value>> {
    let subject = decoded_cell_subject(cell_id)?;
    match family {
        arkret_wire::CellFamilyId::MEMBER_STATE_V1 => {
            if !matches!(scope, ScopeRef::Realm { .. }) {
                return Ok(None);
            }
            Ok(project_membership(value))
        }
        arkret_wire::CellFamilyId::CIRCLE_MEMBER_V1 => {
            if !matches!(scope, ScopeRef::Circle { .. }) {
                return Ok(None);
            }
            Ok(project_membership(value))
        }
        arkret_wire::CellFamilyId::ACCOUNT_STATUS_V1 => {
            let principal = subject_single_string(&subject)?;
            if !leaf_principals.contains(principal) {
                return Ok(None);
            }
            let status = scalar_or_field(value, &["status", "state"])?;
            Ok(Some(json!({"principal_id": principal, "status": status})))
        }
        arkret_wire::CellFamilyId::AGENT_STATUS_V1 => {
            let principal = subject_single_string(&subject)?;
            if !leaf_principals.contains(principal) {
                return Ok(None);
            }
            let status = scalar_or_field(value, &["status", "state"])?;
            Ok(Some(json!({"agent_id": principal, "status": status})))
        }
        arkret_wire::CellFamilyId::DEVICE_AUTHORIZATION_V1
        | arkret_wire::CellFamilyId::AGENT_KEY_V1 => {
            if leaf_credentials
                .iter()
                .any(|credential| value_contains_string(value, credential))
                || leaf_credentials
                    .iter()
                    .any(|credential| subject_contains_string(&subject, credential))
            {
                Ok(Some(value.clone()))
            } else {
                Ok(None)
            }
        }
        arkret_wire::CellFamilyId::DEVICE_REANCHOR_V1 => {
            if leaf_principals
                .iter()
                .any(|principal| value_contains_string(value, principal))
                || leaf_principals
                    .iter()
                    .any(|principal| subject_contains_string(&subject, principal))
            {
                Ok(Some(value.clone()))
            } else {
                Ok(None)
            }
        }
        arkret_wire::CellFamilyId::REALM_POLICY_BUNDLE_V1 => Ok(Some(project_fields(
            value,
            &[
                "content_scheme",
                "content_encryption_floor",
                "metadata_encryption_floor",
                "media_service_decrypts",
            ],
        )?)),
        arkret_wire::CellFamilyId::REALM_HISTORY_VISIBILITY_V1
        | arkret_wire::CellFamilyId::REALM_HISTORY_SHARING_POLICY_V1 => Ok(Some(value.clone())),
        arkret_wire::CellFamilyId::REALM_PLAINTEXT_VISIBLE_SERVICES_V1 => {
            Ok(Some(project_plaintext_visible_services(value)?))
        }
        arkret_wire::CellFamilyId::CIRCLE_CREATE_V1 => {
            if !matches!(scope, ScopeRef::Circle { .. }) {
                return Ok(None);
            }
            Ok(Some(project_fields(
                value,
                &["encryption_profile", "history_visibility"],
            )?))
        }
        arkret_wire::CellFamilyId::CIRCLE_METADATA_V1 => {
            if !matches!(scope, ScopeRef::Circle { .. }) {
                return Ok(None);
            }
            Ok(Some(project_fields(value, &["history_visibility"])?))
        }
        _ => Err(Error::Protocol(format!(
            "registered MLS security frontier family has no SDK projector: {family} (profile_unsupported)"
        ))),
    }
}

fn validate_effective_scope(scope: &ScopeRef) -> Result<()> {
    match scope {
        ScopeRef::Realm { .. } | ScopeRef::Circle { .. } => Ok(()),
        _ => schema("MLS security frontier effective scope is unsupported"),
    }
}

fn project_membership(value: &Value) -> Option<Value> {
    let membership = value
        .as_str()
        .or_else(|| value.get("membership").and_then(Value::as_str))
        .or_else(|| value.get("state").and_then(Value::as_str))?;
    matches!(membership, "join" | "leave" | "ban").then(|| Value::String(membership.to_owned()))
}

fn scalar_or_field(value: &Value, fields: &[&str]) -> Result<Value> {
    if value.is_string() || value.is_boolean() || value.is_number() || value.is_null() {
        return Ok(value.clone());
    }
    fields
        .iter()
        .find_map(|field| value.get(*field).cloned())
        .ok_or_else(|| {
            Error::Protocol(
                "security frontier state omits its projected status field (schema_violation)"
                    .to_owned(),
            )
        })
}

fn project_fields(value: &Value, fields: &[&str]) -> Result<Value> {
    let object = value.as_object().ok_or_else(|| {
        Error::Protocol(
            "security frontier projected state must be an object (schema_violation)".to_owned(),
        )
    })?;
    let mut projected = Map::new();
    for field in fields {
        if let Some(value) = object.get(*field) {
            projected.insert((*field).to_owned(), value.clone());
        }
    }
    Ok(Value::Object(projected))
}

fn project_plaintext_visible_services(value: &Value) -> Result<Value> {
    let services = value
        .as_array()
        .or_else(|| value.get("services").and_then(Value::as_array))
        .ok_or_else(|| {
            Error::Protocol(
                "plaintext-visible services state must be an array (schema_violation)".to_owned(),
            )
        })?;
    services
        .iter()
        .map(|service| project_fields(service, &["service_id", "principal_id", "data_classes"]))
        .collect::<Result<Vec<_>>>()
        .map(Value::Array)
}

fn decoded_cell_subject(cell_id: &CellId) -> Result<Value> {
    let parts = arkret_canonical::canonical::decode_state_subject_parts(cell_id.subject())?;
    if parts.len() == 1 {
        Ok(Value::String(parts[0].clone()))
    } else {
        Ok(Value::Array(parts.into_iter().map(Value::String).collect()))
    }
}

fn subject_single_string(subject: &Value) -> Result<&str> {
    subject.as_str().ok_or_else(|| {
        Error::Protocol(
            "security frontier cell subject must contain one principal id (schema_violation)"
                .to_owned(),
        )
    })
}

fn subject_contains_string(subject: &Value, expected: &str) -> bool {
    subject.as_str() == Some(expected)
        || subject
            .as_array()
            .is_some_and(|parts| parts.iter().any(|part| part.as_str() == Some(expected)))
}

fn value_contains_string(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(value) => value == expected,
        Value::Array(values) => values
            .iter()
            .any(|value| value_contains_string(value, expected)),
        Value::Object(values) => values
            .values()
            .any(|value| value_contains_string(value, expected)),
        _ => false,
    }
}

fn canonical_hash<T: Serialize>(value: &T) -> Result<Hash> {
    Ok(Hash::new(arkret_canonical::canonical::canonical_sha256(
        value,
    )?)?)
}

/// Verify a complete-materialization proof bundle.
///
/// The callbacks own cryptographic signature verification and authorization
/// resolution. This function always validates the signed object digests,
/// topology, complete Merkle materializations, scope, and governance roots
/// before invoking a successful result.
///
/// The error type `E` is chosen by the caller through the injected callbacks:
/// both callbacks return `Result<(), E>` and the function returns
/// `Result<_, E>`. `E: From<WireError>` lets the internal fail-closed checks
/// raise `WireError` and surface it as the caller's `E`.
pub fn verify_mls_governance_proof_bundle<E, VerifySeal, VerifyEvent, ProjectCells>(
    bundle: &MaterializedMlsGovernanceProofBundle,
    expected_binding: &MlsGovernanceBindingPayload,
    trusted_anchor: &SealId,
    verify_seal_signature: VerifySeal,
    verify_event_signature: VerifyEvent,
    project_cells: ProjectCells,
    leaves: &[MlsSecurityFrontierLeaf],
) -> std::result::Result<VerifiedMlsGovernanceProof, E>
where
    E: From<Error>,
    VerifySeal: Fn(&Seal) -> std::result::Result<(), E>,
    VerifyEvent: Fn(&Event) -> std::result::Result<(), E>,
    ProjectCells: Fn(&Event) -> std::result::Result<Vec<CellRef>, E>,
{
    let request = MlsGovernanceProofRequestBodyBody {
        realm_id: expected_binding.realm_id().clone(),
        effective_scope: expected_binding.effective_scope().clone(),
        mls_group_id: expected_binding.mls_group_id().to_owned(),
        previous_epoch: expected_binding.previous_epoch(),
        next_epoch: expected_binding.next_epoch(),
        binding_profile: expected_binding.binding_profile().to_owned(),
        reducer_profile: expected_binding.reducer_profile().to_owned(),
        trusted_anchor_seal_id: trusted_anchor.clone(),
        chunk_index: 0,
        expected_bundle_digest: None,
    };
    let verified = verify_mls_governance_proof_materialization(
        bundle,
        &request,
        trusted_anchor,
        verify_seal_signature,
        verify_event_signature,
        project_cells,
        leaves,
    )?;
    if &verified.security_frontier_digest != expected_binding.security_frontier_digest() {
        return stale("security_frontier_digest does not match the accepted key-access state");
    }
    Ok(verified)
}

/// Verify one complete proof materialization and derive its unique security
/// frontier without accepting a producer-supplied binding copy.
///
/// Commit producers use this before constructing the transcript binding;
/// receivers additionally compare the returned digest through
/// [`verify_mls_governance_proof_bundle`].
pub fn verify_mls_governance_proof_materialization<E, VerifySeal, VerifyEvent, ProjectCells>(
    bundle: &MaterializedMlsGovernanceProofBundle,
    request: &MlsGovernanceProofRequestBodyBody,
    trusted_anchor: &SealId,
    verify_seal_signature: VerifySeal,
    verify_event_signature: VerifyEvent,
    project_cells: ProjectCells,
    leaves: &[MlsSecurityFrontierLeaf],
) -> std::result::Result<VerifiedMlsGovernanceProof, E>
where
    E: From<Error>,
    VerifySeal: Fn(&Seal) -> std::result::Result<(), E>,
    VerifyEvent: Fn(&Event) -> std::result::Result<(), E>,
    ProjectCells: Fn(&Event) -> std::result::Result<Vec<CellRef>, E>,
{
    verify_bundle_header_for_request(bundle, request, trusted_anchor)?;
    let accepted_seal = verify_seal_path(bundle, verify_seal_signature)?;
    let covered = verify_covered_event_materialization(bundle, accepted_seal)?;
    let control_state = verify_control_state_materialization(bundle, accepted_seal)?;
    verify_frontier_events(bundle, &covered, verify_event_signature, project_cells)?;

    let security_frontier_digest =
        derive_mls_security_frontier(&control_state, &bundle.effective_scope, leaves)
            .map_err(E::from)?;
    Ok(VerifiedMlsGovernanceProof {
        accepted_seal_id: bundle.accepted_seal_id.clone(),
        security_frontier_digest,
    })
}

fn verify_bundle_header_for_request(
    bundle: &MaterializedMlsGovernanceProofBundle,
    request: &MlsGovernanceProofRequestBodyBody,
    trusted_anchor: &SealId,
) -> Result<()> {
    if bundle.bundle_version != MLS_GOVERNANCE_PROOF_BUNDLE_VERSION {
        return schema("unsupported MLS governance proof bundle_version");
    }
    if bundle.materialization_profile != MLS_GOVERNANCE_COMPLETE_MATERIALIZATION_PROFILE {
        return schema("unsupported MLS governance proof materialization_profile");
    }
    if &bundle.trusted_anchor_seal_id != trusted_anchor {
        return state_mismatch("bundle trust anchor does not match the locally trusted anchor");
    }
    request.validate()?;
    if &request.trusted_anchor_seal_id != trusted_anchor {
        return state_mismatch("proof request trust anchor differs from the local anchor");
    }
    let expected_request_digest = request.proof_request_digest()?;
    if bundle.proof_request_digest != expected_request_digest {
        return state_mismatch(
            "bundle proof_request_digest does not match the MLS transcript binding identity",
        );
    }
    if bundle.realm_id != request.realm_id
        || bundle.effective_scope != request.effective_scope
        || bundle.reducer_profile != request.reducer_profile
    {
        return state_mismatch("bundle Realm, scope, or reducer profile mismatch");
    }
    Ok(())
}

fn verify_seal_path<E, VerifySeal>(
    bundle: &MaterializedMlsGovernanceProofBundle,
    verify_seal_signature: VerifySeal,
) -> std::result::Result<&Seal, E>
where
    E: From<Error>,
    VerifySeal: Fn(&Seal) -> std::result::Result<(), E>,
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
        if seal.id != bundle.trusted_anchor_seal_id {
            if seal.predecessor_refs.is_empty() {
                return state_mismatch("untrusted seal_path entry has no predecessor");
            }
            for predecessor in &seal.predecessor_refs {
                if predecessor != &bundle.trusted_anchor_seal_id && !prior.contains(predecessor) {
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
        if !reachable.insert(id.clone()) || id == bundle.trusted_anchor_seal_id {
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
        .ok_or_else(|| E::from(Error::Protocol("seal_path unexpectedly empty".to_owned())))
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
    bundle: &MaterializedMlsGovernanceProofBundle,
    accepted_seal: &Seal,
) -> Result<BTreeSet<Hash>> {
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
        .map(|digest| Hash::new(digest.as_str().to_owned()).map_err(Error::from))
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
    bundle: &MaterializedMlsGovernanceProofBundle,
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

fn verify_frontier_events<E, VerifyEvent, ProjectCells>(
    bundle: &MaterializedMlsGovernanceProofBundle,
    covered: &BTreeSet<Hash>,
    verify_event_signature: VerifyEvent,
    project_cells: ProjectCells,
) -> std::result::Result<(), E>
where
    E: From<Error>,
    VerifyEvent: Fn(&Event) -> std::result::Result<(), E>,
    ProjectCells: Fn(&Event) -> std::result::Result<Vec<CellRef>, E>,
{
    ensure_canonical_order(
        "frontier_events",
        bundle
            .frontier_events
            .iter()
            .map(|event| event.event_id.as_str()),
    )?;
    if bundle.frontier_events.is_empty() {
        return schema("frontier_events must not be empty");
    }
    let actual_ids = bundle
        .frontier_events
        .iter()
        .map(|event| event.event_id.clone())
        .collect::<BTreeSet<_>>();
    if actual_ids.len() != bundle.frontier_events.len() {
        return schema("frontier_events contains duplicate Event ids");
    }

    for event in &bundle.frontier_events {
        if event.realm_id != bundle.realm_id || event.scope_ref != bundle.effective_scope {
            return state_mismatch("frontier Event Realm or scope mismatch");
        }
        // `encryption-and-audit.md` §2.5.1.1 step 6 is the closed per-Event
        // list: recompute the producer digest, verify proofs, confirm digest
        // inclusion, control-plane family, Realm and scope. A `seal_basis`
        // presence test is not among them, and requiring one excluded every
        // §5 anchor unit — `ak.realm.create` carries no CBA basis field at
        // all, and it is the only membership-frontier Event a freshly
        // bootstrapped Realm has, so no such Realm could produce a verifiable
        // bundle. What the step does require is that the Event is
        // control-plane, which a `seal_ref` disproves and which the projected
        // cell family below confirms.
        if event.seal_ref.is_some() {
            return schema("frontier Event is a DataEvent, not a Control Move");
        }
        // The affected cells are receiver-projected from the registered
        // reducer contract; the Event itself never names them. The projector
        // is injected because the registry lives one layer above this crate.
        let projected = project_cells(event)?;
        if !projected.iter().any(|cell| {
            CellId::from_ref(cell)
                .map(|cell| is_mls_membership_frontier_component(cell.component()))
                .unwrap_or(false)
        }) {
            return schema("frontier Event does not affect a membership/device/lifecycle cell");
        }
        event.validate_proof_bindings()?;
        verify_event_signature(event)?;
        let digest = Hash::new(event.event_digest()?).map_err(Error::from)?;
        if !covered.contains(&digest) {
            return state_mismatch("frontier Event digest is absent from the accepted covered set");
        }
    }
    Ok(())
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

fn schema<T, E>(message: &str) -> std::result::Result<T, E>
where
    E: From<Error>,
{
    Err(Error::Protocol(format!("{message} (schema_violation)")).into())
}

fn state_mismatch<T, E>(message: &str) -> std::result::Result<T, E>
where
    E: From<Error>,
{
    Err(Error::Protocol(format!("{message} (state_mismatch)")).into())
}

fn stale<T, E>(message: &str) -> std::result::Result<T, E>
where
    E: From<Error>,
{
    Err(Error::Protocol(format!("{message} (mls_governance_binding_stale)")).into())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use arkret_models_crypto::mls_payloads::MlsGovernanceBindingPayload;
    use arkret_wire::error_codes::{ErrorCode, ReasonCode};
    use arkret_wire::event_envelope::{Event, ScopeRef};
    use arkret_wire::{
        CellRef, Did, DidUrl, Error, EventId, EventRequirements, Hash, Hlc, NonEmptyString,
        NotarySig, PayloadSignature, ProfileId, Proof, RealmId, Seal, SealBasis, SealId, SealKind,
        canonical,
    };
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;
    use crate::{CellState, compute_state_root, control_event_set_root};

    struct Fixture {
        bundle: MaterializedMlsGovernanceProofBundle,
        binding: MlsGovernanceBindingPayload,
        security_frontier_digest: Hash,
        leaves: Vec<MlsSecurityFrontierLeaf>,
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
                cell: cell(
                    arkret_wire::CellFamilyId::MEMBER_STATE_V1,
                    "did:webvh:z6mkfixture:alice.example",
                ),
                state: MlsGovernanceControlStateValue {
                    value: json!("join"),
                },
            },
            MlsGovernanceControlStateLeaf {
                cell: cell(
                    arkret_wire::CellFamilyId::REALM_POLICY_BUNDLE_V1,
                    realm().as_str(),
                ),
                state: MlsGovernanceControlStateValue {
                    value: json!({"media_service_decrypts": true}),
                },
            },
            MlsGovernanceControlStateLeaf {
                cell: cell(
                    arkret_wire::CellFamilyId::REALM_PLAINTEXT_VISIBLE_SERVICES_V1,
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
                cell: cell(
                    arkret_wire::CellFamilyId::CAPABILITY_GRANT_V1,
                    "ak.grant.fixture",
                ),
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

    /// A membership Control Move: it carries `seal_basis` and no `seal_ref`,
    /// and names no cell — the cells come back from the injected projector.
    fn frontier_event(scope: ScopeRef) -> Event {
        let mut event = Event {
            event_id: event_id(),
            kind: "ak.member.state".into(),
            realm_id: realm(),
            scope_ref: scope,
            actor_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            actor_seq: 1,
            created_at: Utc.with_ymd_and_hms(2026, 7, 14, 0, 0, 0).unwrap(),
            hlc: Some(Hlc::new("01980b44cc00-0000-aabbccdd").unwrap()),
            prev_refs: Vec::new(),
            refs: Vec::new(),
            preconditions: Vec::new(),
            seal_ref: None,
            auth_context: None,
            seal_basis: Some(SealBasis {
                leaves: vec![SealId::new(format!("ak:seal:{}", hash(0xa1).as_str())).unwrap()],
                control_event_set_root: hash(0xa2),
                state_root: hash(0xa3),
            }),
            requirements: EventRequirements::default(),
            redacts: None,
            payload: BTreeMap::from([("state".to_owned(), json!("joined"))]),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            unsigned: BTreeMap::new(),
            causal_refs: Vec::new(),
            proofs: Vec::new(),
        };
        let digest = Hash::new(event.event_digest().unwrap()).unwrap();
        event.proofs.push(Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#device-key")
                .unwrap(),
            event_digest: digest,
            created_at: event.created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "AAAA.BBBB.CCCC".to_owned(),
        });
        event
    }

    fn seal(
        state_root: Hash,
        covered_event_digests: Vec<Hash>,
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
            notary_signature: NotarySig::Single(PayloadSignature {
                extra: Default::default(),
                alg: "EdDSA".to_owned(),
                verification_method: DidUrl::new("did:webvh:z6mkfixture:notary.example#key-1")
                    .unwrap(),
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
        let effective_scope = ScopeRef::Realm { realm_id: realm() };
        fixture_with_frontier(frontier_event(effective_scope.clone()), effective_scope)
    }

    /// Every digest in the bundle is derived from the frontier Event, so a
    /// variant Event has to rebuild the whole fixture — mutating one in place
    /// would trip digest inclusion before reaching the check under test.
    fn fixture_with_frontier(frontier_event: Event, effective_scope: ScopeRef) -> Fixture {
        let frontier_digest = Hash::new(frontier_event.event_digest().unwrap()).unwrap();
        let covered_event_digests = vec![frontier_digest.clone()];
        let covered = BTreeSet::from([frontier_digest]);
        let control_state = control_state();
        let states = state_map(&control_state);
        let leaves = vec![MlsSecurityFrontierLeaf {
            leaf_index: 0,
            principal_id: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
            credential_ref: NonEmptyString::new("did:webvh:z6mkfixture:alice.example#device-key")
                .unwrap(),
        }];
        let security_frontier_digest =
            derive_mls_security_frontier(&states, &effective_scope, &leaves).unwrap();
        let binding = MlsGovernanceBindingPayload::realm(
            realm(),
            "YXJrcmV0LW1scy1maXh0dXJl",
            0,
            1,
            security_frontier_digest.clone(),
            ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            "ak.reducer.v1",
        )
        .unwrap();
        let seal = seal(
            compute_state_root(&states).unwrap(),
            covered_event_digests.clone(),
            control_event_set_root(&covered).unwrap(),
        );
        let seal_id = seal.id.clone();
        let proof_request_digest = MlsGovernanceProofRequestBodyBody {
            realm_id: realm(),
            effective_scope: effective_scope.clone(),
            mls_group_id: binding.mls_group_id().to_owned(),
            previous_epoch: binding.previous_epoch(),
            next_epoch: binding.next_epoch(),
            binding_profile: binding.binding_profile().to_owned(),
            reducer_profile: binding.reducer_profile().to_owned(),
            trusted_anchor_seal_id: seal_id.clone(),
            chunk_index: 0,
            expected_bundle_digest: None,
        }
        .proof_request_digest()
        .unwrap();
        Fixture {
            bundle: MaterializedMlsGovernanceProofBundle {
                bundle_version: MLS_GOVERNANCE_PROOF_BUNDLE_VERSION,
                proof_request_digest,
                bundle_digest: hash(0),
                materialization_profile: MLS_GOVERNANCE_COMPLETE_MATERIALIZATION_PROFILE.to_owned(),
                realm_id: realm(),
                effective_scope,
                reducer_profile: "ak.reducer.v1".to_owned(),
                trusted_anchor_seal_id: seal_id.clone(),
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
            security_frontier_digest,
            leaves,
        }
    }

    /// Stand-in for `arkret_schema::project_registered_cell_writes`: the
    /// Event never names its cells, so the verifier depends entirely on what
    /// the caller's projector returns.
    fn project_member_cell(_: &Event) -> Result<Vec<CellRef>> {
        Ok(vec![cell(
            arkret_wire::CellFamilyId::MEMBER_STATE_V1,
            "did.web.alice.example",
        )])
    }

    fn verify(fixture: &Fixture) -> Result<VerifiedMlsGovernanceProof> {
        verify_mls_governance_proof_bundle(
            &fixture.bundle,
            &fixture.binding,
            &fixture.bundle.trusted_anchor_seal_id,
            |_| Ok(()),
            |_| Ok(()),
            project_member_cell,
            &fixture.leaves,
        )
    }

    fn proof_request(fixture: &Fixture) -> MlsGovernanceProofRequestBodyBody {
        MlsGovernanceProofRequestBodyBody {
            realm_id: fixture.bundle.realm_id.clone(),
            effective_scope: fixture.bundle.effective_scope.clone(),
            mls_group_id: "YXJrcmV0LW1scy1maXh0dXJl".to_owned(),
            previous_epoch: 0,
            next_epoch: 1,
            binding_profile: ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1.to_owned(),
            reducer_profile: fixture.bundle.reducer_profile.clone(),
            trusted_anchor_seal_id: fixture.bundle.trusted_anchor_seal_id.clone(),
            chunk_index: 0,
            expected_bundle_digest: None,
        }
    }

    #[test]
    fn complete_bundle_verifies() {
        let fixture = fixture();
        let verified = verify(&fixture).unwrap();
        assert_eq!(verified.accepted_seal_id, fixture.bundle.accepted_seal_id);
        assert_eq!(
            verified.security_frontier_digest,
            fixture.security_frontier_digest
        );
    }

    #[test]
    fn chunked_bundle_round_trips_before_verification() {
        let fixture = fixture();
        let request = proof_request(&fixture);
        let chunks = build_mls_governance_proof_chunks(&request, &fixture.bundle).unwrap();
        assert!(chunks.len() >= 2);
        let assembled = assemble_mls_governance_proof_chunks(&request, &chunks).unwrap();
        assert_eq!(assembled.seal_path, fixture.bundle.seal_path);
        assert_eq!(assembled.control_state, fixture.bundle.control_state);
        verify_mls_governance_proof_bundle::<Error, _, _, _>(
            &assembled,
            &fixture.binding,
            &request.trusted_anchor_seal_id,
            |_| Ok(()),
            |_| Ok(()),
            project_member_cell,
            &fixture.leaves,
        )
        .unwrap();
    }

    #[test]
    fn incomplete_duplicate_and_out_of_order_chunks_fail_closed() {
        let fixture = fixture();
        let request = proof_request(&fixture);
        let chunks = build_mls_governance_proof_chunks(&request, &fixture.bundle).unwrap();

        let mut missing = chunks.clone();
        missing.pop();
        assert!(
            assemble_mls_governance_proof_chunks(&request, &missing)
                .unwrap_err()
                .to_string()
                .contains("mls_governance_proof_incomplete")
        );

        let mut duplicate = chunks.clone();
        duplicate[1] = duplicate[0].clone();
        assert!(assemble_mls_governance_proof_chunks(&request, &duplicate).is_err());

        let mut out_of_order = chunks;
        out_of_order.swap(0, 1);
        assert!(
            assemble_mls_governance_proof_chunks(&request, &out_of_order)
                .unwrap_err()
                .to_string()
                .contains("chunk_index order")
        );
    }

    #[test]
    fn tampered_and_mixed_chunks_fail_closed() {
        let fixture = fixture();
        let request = proof_request(&fixture);
        let chunks = build_mls_governance_proof_chunks(&request, &fixture.bundle).unwrap();

        let mut tampered = chunks.clone();
        tampered[0].chunk = match tampered[0].chunk.clone() {
            MlsGovernanceProofChunk::SealPath {
                chunk_index,
                start_index,
                mut items,
                chunk_digest,
                chunk_proof,
            } => {
                items[0].notary_seq += 1;
                MlsGovernanceProofChunk::SealPath {
                    chunk_index,
                    start_index,
                    items,
                    chunk_digest,
                    chunk_proof,
                }
            }
            _ => panic!("first chunk must be seal_path"),
        };
        assert!(
            assemble_mls_governance_proof_chunks(&request, &tampered)
                .unwrap_err()
                .to_string()
                .contains("chunk_digest mismatch")
        );

        let mut mixed = chunks;
        mixed[1].accepted_seal_id =
            SealId::new(format!("ak:seal:{}", hash(0xfe).as_str())).unwrap();
        assert!(
            assemble_mls_governance_proof_chunks(&request, &mixed)
                .unwrap_err()
                .to_string()
                .contains("mix different bundles")
        );
    }

    #[test]
    fn rejected_seal_signature_is_propagated() {
        let fixture = fixture();
        let error = verify_mls_governance_proof_bundle(
            &fixture.bundle,
            &fixture.binding,
            &fixture.bundle.trusted_anchor_seal_id,
            |_| {
                Err(Error::Protocol(
                    "fixture Seal signature rejected".to_owned(),
                ))
            },
            |_| Ok(()),
            project_member_cell,
            &fixture.leaves,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("fixture Seal signature rejected")
        );
    }

    #[test]
    fn rejected_frontier_event_signature_is_propagated() {
        let fixture = fixture();
        let error = verify_mls_governance_proof_bundle(
            &fixture.bundle,
            &fixture.binding,
            &fixture.bundle.trusted_anchor_seal_id,
            |_| Ok(()),
            |_| {
                Err(Error::Protocol(
                    "fixture frontier Event signature rejected".to_owned(),
                ))
            },
            project_member_cell,
            &fixture.leaves,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("fixture frontier Event signature rejected")
        );
    }

    #[test]
    fn seal_signature_payload_digest_tampering_is_rejected() {
        let mut fixture = fixture();
        let NotarySig::Single(signature) = &mut fixture.bundle.seal_path[0].notary_signature else {
            panic!("fixture must use a single notary signature");
        };
        signature.payload_digest = hash(0xef);
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn proof_request_rejects_epoch_skip() {
        let request = MlsGovernanceProofRequestBodyBody {
            realm_id: realm(),
            effective_scope: ScopeRef::Realm { realm_id: realm() },
            mls_group_id: "YXJrcmV0LW1scy1maXh0dXJl".to_owned(),
            previous_epoch: 3,
            next_epoch: 5,
            binding_profile: ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1.to_owned(),
            reducer_profile: "ak.reducer.v1".to_owned(),
            trusted_anchor_seal_id: SealId::new(format!("ak:seal:{}", hash(0).as_str())).unwrap(),
            chunk_index: 0,
            expected_bundle_digest: None,
        };
        let error = request.validate().unwrap_err();
        assert!(error.to_string().contains(ErrorCode::SCHEMA_VIOLATION));
    }

    #[test]
    fn proof_request_accepts_genesis_epoch() {
        let request = MlsGovernanceProofRequestBodyBody {
            realm_id: realm(),
            effective_scope: ScopeRef::Realm { realm_id: realm() },
            mls_group_id: "YXJrcmV0LW1scy1maXh0dXJl".to_owned(),
            previous_epoch: 0,
            next_epoch: 0,
            binding_profile: ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1.to_owned(),
            reducer_profile: "ak.reducer.v1".to_owned(),
            trusted_anchor_seal_id: SealId::new(format!("ak:seal:{}", hash(0).as_str())).unwrap(),
            chunk_index: 0,
            expected_bundle_digest: None,
        };
        request.validate().unwrap();
    }

    #[test]
    fn bundle_epoch_tampering_is_rejected() {
        let mut fixture = fixture();
        fixture.binding = MlsGovernanceBindingPayload::realm(
            realm(),
            "YXJrcmV0LW1scy1maXh0dXJl",
            1,
            2,
            fixture.security_frontier_digest.clone(),
            ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            "ak.reducer.v1",
        )
        .unwrap();
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn bundle_scope_tampering_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.effective_scope = ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:0196419b-0000-7000-8000-00000000014b").unwrap(),
        };
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn bundle_reducer_profile_tampering_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.reducer_profile = "ak.reducer.tampered.v1".to_owned();
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn omitted_control_leaf_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.control_state.remove(0);
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn incomplete_covered_manifest_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.covered_event_digests.clear();
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn missing_frontier_event_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.frontier_events.clear();
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ErrorCode::SCHEMA_VIOLATION));
    }

    #[test]
    fn cross_scope_frontier_event_is_rejected() {
        let mut fixture = fixture();
        fixture.bundle.frontier_events[0].scope_ref = ScopeRef::Circle {
            realm_id: realm(),
            circle_id: arkret_wire::CircleId::new("ak:circle:0196419b-0000-7000-8000-0000000000c1")
                .unwrap(),
        };
        let error = verify(&fixture).unwrap_err();
        assert!(error.to_string().contains(ErrorCode::STATE_MISMATCH));
    }

    #[test]
    fn a_seal_basis_free_anchor_unit_is_a_valid_frontier_event() {
        // `event-auth-state-resolution.md` §5 requires ak.realm.create to carry
        // no CBA basis field at all, and it is the only membership-frontier
        // Event a freshly bootstrapped Realm has. Requiring a seal_basis here
        // meant no such Realm could ever produce a verifiable bundle.
        // §2.5.1.1 step 6 does not list a basis presence test.
        let effective_scope = ScopeRef::Realm { realm_id: realm() };
        let mut anchor_unit = frontier_event(effective_scope.clone());
        anchor_unit.seal_basis = None;
        // seal_basis is inside the producer digest, so the pinned proof digest
        // has to follow — otherwise the proof check fires first and this would
        // pass for the wrong reason.
        anchor_unit.proofs[0].event_digest =
            Hash::new(anchor_unit.event_digest().unwrap()).unwrap();
        let fixture = fixture_with_frontier(anchor_unit, effective_scope);

        verify(&fixture).expect("an anchor unit must be an admissible frontier Event");
    }

    #[test]
    fn a_data_event_is_still_not_a_valid_frontier_event() {
        // The half of the old check that step 6 does require: the frontier is
        // control-plane. A seal_ref disproves that regardless of basis.
        let effective_scope = ScopeRef::Realm { realm_id: realm() };
        let mut data_event = frontier_event(effective_scope.clone());
        data_event.seal_basis = None;
        data_event.seal_ref =
            Some(SealId::new(format!("ak:seal:{}", hash(0xb1).as_str())).unwrap());
        data_event.proofs[0].event_digest = Hash::new(data_event.event_digest().unwrap()).unwrap();
        let fixture = fixture_with_frontier(data_event, effective_scope);

        let error = verify(&fixture).unwrap_err();
        assert!(
            error.to_string().contains(ErrorCode::SCHEMA_VIOLATION),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn frontier_event_touching_no_membership_cell_is_rejected() {
        // The Event carries no cell list, so "does this Move affect membership"
        // is decided purely by the injected projector's answer.
        let fixture = fixture();
        let error = verify_mls_governance_proof_bundle::<Error, _, _, _>(
            &fixture.bundle,
            &fixture.binding,
            &fixture.bundle.trusted_anchor_seal_id,
            |_| Ok(()),
            |_| Ok(()),
            |_| Ok(vec![cell("ak.component.realm.title.v1", realm().as_str())]),
            &fixture.leaves,
        )
        .unwrap_err();
        assert!(error.to_string().contains(ErrorCode::SCHEMA_VIOLATION));
    }

    #[test]
    fn security_frontier_digest_tampering_is_rejected() {
        let mut fixture = fixture();
        let bad_binding = MlsGovernanceBindingPayload::realm(
            realm(),
            "YXJrcmV0LW1scy1maXh0dXJl",
            0,
            1,
            hash(0xee),
            ProfileId::MLS_GOVERNANCE_BINDING_FULL_V1,
            "ak.reducer.v1",
        )
        .unwrap();
        fixture.binding = bad_binding;
        let error = verify(&fixture).unwrap_err();
        assert!(
            error
                .to_string()
                .contains(ReasonCode::MLS_GOVERNANCE_BINDING_STALE)
        );
    }
}
