use std::collections::{BTreeMap, BTreeSet};

use arkret_core::{
    CellRef, Did, Discoverability, Effect, EncryptionFloor, EncryptionProfile, Event, EventId,
    EventRef, EventRequirements, EventsSubmitRequestBody, Hash, HistoryVisibility, Hlc, JoinRule,
    LatticeOp, LatticeOpType, MoveId, MoveSignature, MoveSigner, NotaryProfile, NotarySig, Realm,
    RealmCreatePayload, RealmId, Seal, SealId, SealKind, SecurityClass, TypedTrustDomainId,
};
use arkret_state::{CellRegistry, CellState, SealedOp, compute_state_root, control_event_set_root};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{Error, Result};

pub const PRINCIPAL_CONTROL_REALM_PROFILE: &str = "ak.profile.principal_control_realm.v1";
pub const DID_INCEPTION_REF_ROLE: &str = "did_inception";
const PRINCIPAL_CONTROL_PURPOSE: &str = "principal_control";
pub const PRINCIPAL_CONTROL_CREATE_CELL: &str =
    "ak:cell:ak.component.realm.create.v1:principal_control";
pub const MANAGED_AGENT_PRINCIPAL_CONTROL_CREATE_CELL: &str =
    "ak:cell:ak.component.realm.create.v1:managed_agent_principal_control";

/// Construct the canonical producer effect for a controller-delegated managed
/// Agent Principal Control Realm genesis.
pub fn managed_agent_principal_control_create_effect(
    realm_id: &RealmId,
    actor_seq: u64,
) -> Result<Effect> {
    Ok(Effect {
        cell: CellRef::new(MANAGED_AGENT_PRINCIPAL_CONTROL_CREATE_CELL)?,
        op: LatticeOp {
            op_type: LatticeOpType::Append,
            tag: None,
            value: Some(Value::String(realm_id.to_string())),
            from: None,
            to: None,
            reason: None,
            issuer_seq: Some(actor_seq),
        },
    })
}

/// Public inputs required to construct the unsigned, root-anchored first
/// Event of a self-principal PCR bootstrap unit.
#[derive(Clone, Debug)]
pub struct SelfPrincipalPcrCreateInput {
    pub principal_id: Did,
    pub realm_id: RealmId,
    pub trust_domain: TypedTrustDomainId,
    pub did_inception_ref: EventRef,
    pub event_id: EventId,
    pub created_at: DateTime<Utc>,
    pub hlc: Hlc,
}

/// Construct the only unsigned `ak.realm.create` shape that an identity root
/// may sign. Signing material remains entirely with the caller.
pub fn build_self_principal_pcr_create(input: SelfPrincipalPcrCreateInput) -> Result<Event> {
    let expected_realm_id =
        RealmId::new(arkret_core::principal_control_realm_id(&input.principal_id))?;
    if input.realm_id != expected_realm_id {
        return Err(Error::Protocol(
            "self principal PCR realm_id does not match principal_id".to_owned(),
        ));
    }
    if input.did_inception_ref.role != DID_INCEPTION_REF_ROLE
        || !input.did_inception_ref.critical
        || input.did_inception_ref.proof.is_some()
    {
        return Err(Error::Protocol(
            "self principal PCR requires one direct critical did_inception ref".to_owned(),
        ));
    }

    let mut realm = Realm::new(
        input.realm_id.clone(),
        "Principal Control Realm",
        input.principal_id.clone(),
        input.trust_domain,
        NotaryProfile::SingleDid,
        arkret_core::notary::NotaryValue::single_did(input.principal_id.clone()),
    );
    realm.security_class = Some(SecurityClass::HighAssurance);
    realm.schema_refs = vec![
        arkret_core::REALM_SCHEMA_ID.to_owned(),
        PRINCIPAL_CONTROL_REALM_PROFILE.to_owned(),
    ];
    realm.default_discoverability = Discoverability::Secret;
    realm.default_join_rule = JoinRule::Closed;
    realm.history_visibility = HistoryVisibility::Restricted;
    realm.encryption_profile = EncryptionProfile::MlsRfc9420;
    realm.content_encryption_floor = Some(EncryptionFloor::E2eeRequired);
    realm.metadata_encryption_floor = Some(EncryptionFloor::E2eeRequired);
    realm.fields.insert(
        "purpose".to_owned(),
        Value::String(PRINCIPAL_CONTROL_PURPOSE.to_owned()),
    );
    realm.created_at = input.created_at;

    let payload = payload_map(&RealmCreatePayload {
        object: realm,
        initial_relations: None,
    })?;
    let effect = Effect {
        cell: CellRef::new(PRINCIPAL_CONTROL_CREATE_CELL)?,
        op: LatticeOp {
            op_type: LatticeOpType::Append,
            tag: None,
            value: Some(Value::String(input.realm_id.to_string())),
            from: None,
            to: None,
            reason: None,
            issuer_seq: None,
        },
    };
    let event = Event {
        event_id: input.event_id,
        kind: arkret_core::events::EventKind::REALM_CREATE.into(),
        realm_id: input.realm_id,
        actor_id: input.principal_id,
        actor_seq: 0,
        created_at: input.created_at,
        hlc: input.hlc,
        prev_refs: Vec::new(),
        effective_scope: None,
        refs: vec![input.did_inception_ref],
        preconditions: Vec::new(),
        effects: vec![effect],
        seal_ref: None,
        auth_context: None,
        seal_basis: None,
        requirements: EventRequirements::default(),
        redacts: None,
        payload,
        executed_by: None,
        authorization_ref: None,
        applet_id: None,
        external_ref: None,
        actor_kind: None,
        unsigned: BTreeMap::new(),
        proofs: Vec::new(),
    };
    validate_self_principal_pcr_create(&event, false)?;
    Ok(event)
}

/// Validate and package the closed two-slot self-principal bootstrap batch.
/// The receiver still verifies both cryptographic proofs and entry-0 history.
pub fn self_principal_bootstrap_submit_request(
    create: Event,
    authorize: Event,
) -> Result<EventsSubmitRequestBody> {
    validate_self_principal_bootstrap_unit(&create, &authorize)?;
    Ok(EventsSubmitRequestBody {
        event: None,
        events: vec![create, authorize],
    })
}

/// Build and sign the first principal-control Seal after the closed bootstrap
/// unit has been accepted. The Seal is rooted (no predecessors), covers both
/// bootstrap Event digests, and reproduces the receiver's derived Realm
/// create/member/notary cell state before the authorized device signs it.
pub fn build_self_principal_bootstrap_seal<S: MoveSigner + ?Sized>(
    create: &Event,
    authorize: &Event,
    hlc: Hlc,
    signer: &S,
) -> Result<Seal> {
    validate_self_principal_bootstrap_unit(create, authorize)?;
    if signer.signer_did() != &create.actor_id {
        return Err(Error::Protocol(
            "bootstrap Seal signer DID must equal the principal DID".to_owned(),
        ));
    }

    let create_digest = MoveId::new(create.event_digest()?)?;
    let authorize_digest = MoveId::new(authorize.event_digest()?)?;
    let covered = [create_digest, authorize_digest]
        .into_iter()
        .collect::<BTreeSet<_>>();
    if covered.len() != 2 {
        return Err(Error::Protocol(
            "bootstrap Event digests must be distinct".to_owned(),
        ));
    }
    let delta = covered.iter().cloned().collect::<Vec<_>>();
    let state_root = self_principal_bootstrap_state_root(create, &delta[0], &delta[1])?;
    let control_root = control_event_set_root(&covered)
        .map_err(|error| Error::Protocol(format!("bootstrap Seal coverage root: {error}")))?;
    let sealed_at = Utc::now();
    let zero_hash = Hash::new(format!("sha256:{}", "00".repeat(32)))?;
    let mut seal = Seal {
        id: SealId::new(format!("ak:seal:sha256:{}", "00".repeat(32)))?,
        realm_id: create.realm_id.clone(),
        predecessor_refs: Vec::new(),
        delta: delta.clone(),
        control_event_set_root: control_root.clone(),
        state_root,
        completeness_root: control_root,
        notary_seq: 0,
        data_view_root: None,
        data_event_set_root: None,
        availability_root: None,
        coverage_scope: None,
        covered_event_digests: delta,
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: signer.verification_method_id().to_owned(),
            payload_digest: zero_hash,
            created_at: sealed_at,
            jws: String::new(),
        }),
        sealed_at,
        hlc,
        kind: SealKind::Normal,
    };
    let canonical_bytes = seal.canonical_bytes_for_id()?;
    seal.id = Seal::id_from_canonical_bytes(&canonical_bytes)?;
    seal.notary_signature = NotarySig::Single(signer.sign_payload(&canonical_bytes)?);
    seal.validate_structural()?;
    seal.validate_id()?;
    Ok(seal)
}

/// Complete reducer material needed to construct or validate a
/// controller-signed managed Agent PCR Event Seal.
#[derive(Clone, Debug)]
pub struct ManagedAgentPcrControlMaterial {
    pub realm_id: RealmId,
    pub agent_id: Did,
    pub controller_id: Did,
    pub authorization_ref: String,
    pub covered_event_digests: Vec<MoveId>,
    pub state_root: Hash,
    pub joined: BTreeMap<CellRef, CellState>,
    pub event_ops: Vec<(CellRef, SealedOp)>,
}

/// Materialize the canonical control state of a managed Agent PCR.
///
/// The delegated create Event has one producer marker effect, while the
/// Realm create/member/notary writes are reducer-derived. Later managed PCR
/// Events contribute their literal producer effects. Keeping this expansion
/// in the SDK gives the controller-side Seal builder and receiver admission
/// one byte-identical state-root implementation.
pub fn materialize_managed_agent_pcr_control(
    events: &[Event],
) -> Result<ManagedAgentPcrControlMaterial> {
    let managed_cell = CellRef::new(MANAGED_AGENT_PRINCIPAL_CONTROL_CREATE_CELL)?;
    let creates = events
        .iter()
        .filter(|event| {
            event.kind == arkret_core::events::EventKind::REALM_CREATE
                && event
                    .effects
                    .iter()
                    .any(|effect| effect.cell == managed_cell)
        })
        .collect::<Vec<_>>();
    if creates.len() != 1 {
        return Err(Error::Protocol(
            "managed Agent PCR material requires exactly one canonical create Event".to_owned(),
        ));
    }
    let create = creates[0];
    let controller_id = create.executed_by.clone().ok_or_else(|| {
        Error::Protocol("managed Agent PCR create Event omits executed_by".to_owned())
    })?;
    let authorization_ref = create.authorization_ref.clone().ok_or_else(|| {
        Error::Protocol("managed Agent PCR create Event omits authorization_ref".to_owned())
    })?;
    let object = create
        .payload
        .get("object")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            Error::Protocol("managed Agent PCR create payload omits object".to_owned())
        })?;
    if object.get("created_by").and_then(Value::as_str) != Some(create.actor_id.as_str())
        || object
            .get("fields")
            .and_then(Value::as_object)
            .and_then(|fields| fields.get("purpose"))
            .and_then(Value::as_str)
            != Some(PRINCIPAL_CONTROL_PURPOSE)
    {
        return Err(Error::Protocol(
            "managed Agent PCR create actor, created_by, or purpose is inconsistent".to_owned(),
        ));
    }
    let notary = object
        .get("notary")
        .cloned()
        .ok_or_else(|| Error::Protocol("managed Agent PCR create omits notary".to_owned()))?;
    let notary_value: arkret_core::NotaryValue = serde_json::from_value(notary.clone())?;
    notary_value.validate()?;
    if !notary_value.includes_signer_as_primary(&create.actor_id) {
        return Err(Error::Protocol(
            "managed Agent PCR notary must be the Agent DID".to_owned(),
        ));
    }

    // A managed PCR is itself a control-only Realm. Effectless protocol
    // anchors such as `ak.mls.genesis` still belong to the notarized history:
    // they change the coverage root even though they do not change a lattice
    // cell. Omitting them would leave the MLS genesis outside its own
    // governance anchor.
    let included = events.iter().collect::<Vec<_>>();
    if included.iter().any(|event| {
        event.realm_id != create.realm_id
            || event.actor_id != create.actor_id
            || event.executed_by.as_ref() != Some(&controller_id)
            || event.authorization_ref.as_deref() != Some(authorization_ref.as_str())
    }) {
        return Err(Error::Protocol(
            "managed Agent PCR Event authority or Realm differs from its genesis".to_owned(),
        ));
    }

    let mut covered = BTreeSet::new();
    let mut ops_by_cell = BTreeMap::<CellRef, Vec<SealedOp>>::new();
    let mut event_ops = Vec::new();
    for event in included {
        let move_id = MoveId::new(event.event_digest()?)?;
        if !covered.insert(move_id.clone()) {
            return Err(Error::Protocol(
                "managed Agent PCR Event material contains duplicate digests".to_owned(),
            ));
        }
        let ops = if std::ptr::eq(event, create) {
            managed_agent_pcr_create_ops(create, &move_id, object, notary.clone())?
        } else {
            event
                .effects
                .iter()
                .map(|effect| {
                    (
                        effect.cell.clone(),
                        SealedOp::new(move_id.clone(), effect.op.clone()),
                    )
                })
                .collect()
        };
        for (cell, op) in ops {
            ops_by_cell
                .entry(cell.clone())
                .or_default()
                .push(op.clone());
            event_ops.push((cell, op));
        }
    }

    let registry = crate::lattice_registry::build_sdk_cell_registry();
    let mut joined = BTreeMap::new();
    for (cell, mut ops) in ops_by_cell {
        ops.sort_by(|left, right| right.move_id.as_str().cmp(left.move_id.as_str()));
        let binding = registry.resolve(&create.realm_id, &cell).map_err(|error| {
            Error::Protocol(format!("managed Agent PCR cell registry: {error}"))
        })?;
        let state = binding.lattice.join(&cell, &ops);
        if matches!(state, CellState::Bottom(_)) {
            return Err(Error::Protocol(format!(
                "managed Agent PCR cell {cell} resolved to Bottom"
            )));
        }
        joined.insert(cell, state);
    }
    let state_root = compute_state_root(&joined)
        .map_err(|error| Error::Protocol(format!("managed Agent PCR state root: {error}")))?;
    Ok(ManagedAgentPcrControlMaterial {
        realm_id: create.realm_id.clone(),
        agent_id: create.actor_id.clone(),
        controller_id,
        authorization_ref,
        covered_event_digests: covered.into_iter().collect(),
        state_root,
        joined,
        event_ops,
    })
}

/// Build and sign a managed Agent PCR Seal with the controller device named
/// by the accepted Agent DID delegation.
pub fn build_managed_agent_pcr_event_seal<S: MoveSigner + ?Sized>(
    events: &[Event],
    predecessor: Option<&Seal>,
    hlc: Hlc,
    signer: &S,
) -> Result<Seal> {
    let material = materialize_managed_agent_pcr_control(events)?;
    if signer.signer_did() != &material.controller_id {
        return Err(Error::Protocol(
            "managed Agent PCR Seal signer must be the delegated controller".to_owned(),
        ));
    }
    let target = material
        .covered_event_digests
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let (predecessor_refs, current, notary_seq) = match predecessor {
        Some(seal) => {
            if seal.realm_id != material.realm_id || seal.covered_event_digests.is_empty() {
                return Err(Error::Protocol(
                    "managed Agent PCR predecessor has incompatible Realm or coverage".to_owned(),
                ));
            }
            let current = seal
                .covered_event_digests
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            if !current.is_subset(&target) {
                return Err(Error::Protocol(
                    "managed Agent PCR predecessor coverage is not a subset of the target"
                        .to_owned(),
                ));
            }
            (
                vec![seal.id.clone()],
                current,
                seal.notary_seq.checked_add(1).ok_or_else(|| {
                    Error::Protocol("managed Agent PCR notary sequence overflow".to_owned())
                })?,
            )
        }
        None => (Vec::new(), BTreeSet::new(), 0),
    };
    let delta = target.difference(&current).cloned().collect::<Vec<_>>();
    if delta.is_empty() {
        return Err(Error::Protocol(
            "managed Agent PCR Seal has no new Event delta".to_owned(),
        ));
    }
    let control_root = control_event_set_root(&target)
        .map_err(|error| Error::Protocol(format!("managed Agent PCR control root: {error}")))?;
    let sealed_at = Utc::now();
    let zero_hash = Hash::new(format!("sha256:{}", "00".repeat(32)))?;
    let mut seal = Seal {
        id: SealId::new(format!("ak:seal:sha256:{}", "00".repeat(32)))?,
        realm_id: material.realm_id,
        predecessor_refs,
        delta,
        control_event_set_root: control_root.clone(),
        state_root: material.state_root,
        completeness_root: control_root,
        notary_seq,
        data_view_root: None,
        data_event_set_root: None,
        availability_root: None,
        coverage_scope: None,
        covered_event_digests: material.covered_event_digests,
        previous_state_root: None,
        previous_digest_algorithm: None,
        notary_signature: NotarySig::Single(MoveSignature {
            alg: "EdDSA".to_owned(),
            verification_method: signer.verification_method_id().to_owned(),
            payload_digest: zero_hash,
            created_at: sealed_at,
            jws: String::new(),
        }),
        sealed_at,
        hlc,
        kind: SealKind::Compaction,
    };
    let canonical_bytes = seal.canonical_bytes_for_id()?;
    seal.id = Seal::id_from_canonical_bytes(&canonical_bytes)?;
    seal.notary_signature = NotarySig::Single(signer.sign_payload(&canonical_bytes)?);
    seal.validate_structural()?;
    seal.validate_id()?;
    Ok(seal)
}

fn managed_agent_pcr_create_ops(
    create: &Event,
    move_id: &MoveId,
    object: &serde_json::Map<String, Value>,
    notary: Value,
) -> Result<Vec<(CellRef, SealedOp)>> {
    let mut entry = Value::Object(object.clone());
    entry
        .as_object_mut()
        .expect("Realm create object remains an object")
        .insert(
            "entry_id".to_owned(),
            Value::String(create.event_id.to_string()),
        );
    let create_cell = CellRef::new(format!(
        "ak:cell:ak.component.realm.create.v1:{}",
        create.realm_id
    ))?;
    let member_cell = CellRef::new(format!(
        "ak:cell:ak.component.member.state.v1:{}",
        create.actor_id
    ))?;
    let notary_cell = CellRef::new(format!(
        "ak:cell:ak.component.notary.v1:{}",
        create.realm_id
    ))?;
    Ok(vec![
        (
            create_cell,
            SealedOp::new(
                move_id.clone(),
                LatticeOp {
                    op_type: LatticeOpType::Append,
                    tag: None,
                    value: Some(entry),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: Some(create.actor_seq),
                },
            ),
        ),
        (
            member_cell,
            SealedOp::new(
                move_id.clone(),
                LatticeOp {
                    op_type: LatticeOpType::Transition,
                    tag: None,
                    value: None,
                    from: Some(serde_json::json!("leave")),
                    to: Some(serde_json::json!("join")),
                    reason: Some("realm_genesis".to_owned()),
                    issuer_seq: None,
                },
            ),
        ),
        (
            notary_cell,
            SealedOp::new(
                move_id.clone(),
                LatticeOp {
                    op_type: LatticeOpType::Set,
                    tag: None,
                    value: Some(notary),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            ),
        ),
    ])
}

fn self_principal_bootstrap_state_root(
    create: &Event,
    first_digest: &MoveId,
    second_digest: &MoveId,
) -> Result<Hash> {
    let create_digest = MoveId::new(create.event_digest()?)?;
    let authorize_digest = if first_digest == &create_digest {
        second_digest.clone()
    } else {
        first_digest.clone()
    };
    if create_digest == authorize_digest {
        return Err(Error::Protocol(
            "bootstrap Event digests must be distinct".to_owned(),
        ));
    }
    let object = create
        .payload
        .get("object")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::Protocol("bootstrap Realm object is missing".to_owned()))?;
    let created_by = object
        .get("created_by")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Protocol("bootstrap Realm created_by is missing".to_owned()))?;
    if created_by != create.actor_id.as_str() {
        return Err(Error::Protocol(
            "bootstrap Realm created_by differs from actor_id".to_owned(),
        ));
    }
    let notary = object
        .get("notary")
        .cloned()
        .ok_or_else(|| Error::Protocol("bootstrap Realm notary is missing".to_owned()))?;
    let mut entry = Value::Object(object.clone());
    entry
        .as_object_mut()
        .expect("Realm object remains an object")
        .insert(
            "entry_id".to_owned(),
            Value::String(create.event_id.to_string()),
        );

    let create_cell = CellRef::new(format!(
        "ak:cell:ak.component.realm.create.v1:{}",
        create.realm_id
    ))?;
    let member_cell = CellRef::new(format!(
        "ak:cell:ak.component.member.state.v1:{}",
        create.actor_id
    ))?;
    let notary_cell = CellRef::new(format!(
        "ak:cell:ak.component.notary.v1:{}",
        create.realm_id
    ))?;
    let mut ops_by_cell = BTreeMap::<CellRef, Vec<SealedOp>>::new();
    ops_by_cell.insert(
        create_cell,
        vec![SealedOp::new(
            create_digest.clone(),
            LatticeOp {
                op_type: LatticeOpType::Append,
                tag: None,
                value: Some(entry),
                from: None,
                to: None,
                reason: None,
                issuer_seq: Some(create.actor_seq),
            },
        )],
    );
    ops_by_cell.insert(
        member_cell,
        vec![SealedOp::new(
            create_digest.clone(),
            LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(serde_json::json!("leave")),
                to: Some(serde_json::json!("join")),
                reason: Some("realm_genesis".to_owned()),
                issuer_seq: None,
            },
        )],
    );
    ops_by_cell.insert(
        notary_cell,
        vec![SealedOp::new(
            create_digest,
            LatticeOp {
                op_type: LatticeOpType::Set,
                tag: None,
                value: Some(notary),
                from: None,
                to: None,
                reason: None,
                issuer_seq: None,
            },
        )],
    );

    let registry = crate::lattice_registry::build_sdk_cell_registry();
    let mut joined = BTreeMap::new();
    for (cell, mut ops) in ops_by_cell {
        ops.sort_by(|left, right| right.move_id.as_str().cmp(left.move_id.as_str()));
        let binding = registry
            .resolve(&create.realm_id, &cell)
            .map_err(|error| Error::Protocol(format!("bootstrap cell registry: {error}")))?;
        let state = binding.lattice.join(&cell, &ops);
        if matches!(state, CellState::Bottom(_)) {
            return Err(Error::Protocol(format!(
                "bootstrap cell {cell} resolved to Bottom"
            )));
        }
        joined.insert(cell, state);
    }
    compute_state_root(&joined)
        .map_err(|error| Error::Protocol(format!("bootstrap state root: {error}")))
}

pub fn validate_self_principal_bootstrap_unit(create: &Event, authorize: &Event) -> Result<()> {
    validate_self_principal_pcr_create(create, true)?;
    if authorize.kind != arkret_core::events::EventKind::DEVICE_AUTHORIZE
        || authorize.realm_id != create.realm_id
        || authorize.actor_id != create.actor_id
        || authorize.actor_seq != 1
        || authorize.prev_refs != vec![create.event_id.clone()]
        || authorize.event_id == create.event_id
        || authorize.seal_ref.is_some()
        || authorize.auth_context.is_some()
        || authorize.seal_basis.is_some()
        || !authorize.preconditions.is_empty()
        || !authorize.effects.is_empty()
        || authorize.executed_by.is_none()
        || authorize.authorization_ref.is_none()
        || authorize.applet_id.is_some()
        || authorize.external_ref.is_some()
        || authorize.actor_kind.is_some()
        || !authorize.unsigned.is_empty()
        || authorize.refs.iter().any(|reference| {
            matches!(
                reference.role.as_str(),
                "did_inception" | "did_recovery_anchor" | "bootstrap_binding"
            )
        })
    {
        return Err(Error::Protocol(
            "second self principal bootstrap slot is not the closed device authorize shape"
                .to_owned(),
        ));
    }
    validate_event_proof_digests(authorize)?;
    let payload: arkret_core::DeviceAuthorizePayload =
        authorize.typed_payload(arkret_core::events::EventKind::DEVICE_AUTHORIZE)?;
    if payload.principal_id != create.actor_id
        || payload.cross_signing_binding.is_some()
        || payload.enrollment_authority_binding.is_none()
        || payload.recovery_session_id.is_some()
    {
        return Err(Error::Protocol(
            "bootstrap device authorize must use only enrollment authority binding".to_owned(),
        ));
    }
    payload.validate_service_attested_provenance(
        authorize.executed_by.as_ref(),
        authorize.authorization_ref.as_deref(),
        authorize.created_at,
    )?;
    let binding = payload
        .enrollment_authority_binding
        .as_ref()
        .expect("checked above");
    let authorized_by_matches = matches!(
        &payload.authorized_by,
        arkret_core::DeviceOrPrincipalRef::Did(did) if did == &binding.authority_did
    );
    if !authorized_by_matches
        || authorize.proofs.len() != 1
        || proof_controller(&authorize.proofs[0].verification_method)
            != Some(binding.authority_did.as_str())
    {
        return Err(Error::Protocol(
            "bootstrap authorize proof does not belong to its enrollment authority".to_owned(),
        ));
    }
    Ok(())
}

fn validate_self_principal_pcr_create(event: &Event, require_proof: bool) -> Result<()> {
    let expected_realm_id = RealmId::new(arkret_core::principal_control_realm_id(&event.actor_id))?;
    if event.kind != arkret_core::events::EventKind::REALM_CREATE
        || event.realm_id != expected_realm_id
        || event.actor_seq != 0
        || !event.prev_refs.is_empty()
        || event.refs.len() != 1
        || event.refs[0].role != DID_INCEPTION_REF_ROLE
        || !event.refs[0].critical
        || event.refs[0].proof.is_some()
        || !event.preconditions.is_empty()
        || event.effects.len() != 1
        || event.seal_ref.is_some()
        || event.auth_context.is_some()
        || event.seal_basis.is_some()
        || event.redacts.is_some()
        || event.executed_by.is_some()
        || event.authorization_ref.is_some()
        || event.applet_id.is_some()
        || event.external_ref.is_some()
        || event.actor_kind.is_some()
        || !event.unsigned.is_empty()
    {
        return Err(Error::Protocol(
            "identity root may sign only the closed self principal PCR genesis shape".to_owned(),
        ));
    }
    if require_proof {
        validate_event_proof_digests(event)?;
        if event.proofs.len() != 1 || !event.proofs[0].verification_method.starts_with("did:key:") {
            return Err(Error::Protocol(
                "self principal PCR genesis requires exactly one identity-root proof".to_owned(),
            ));
        }
    } else if !event.proofs.is_empty() {
        return Err(Error::Protocol(
            "unsigned self principal PCR builder output must not contain proofs".to_owned(),
        ));
    }

    validate_principal_control_realm_payload(event)?;
    let effect = &event.effects[0];
    if effect.cell.as_str() != PRINCIPAL_CONTROL_CREATE_CELL
        || effect.op.op_type != LatticeOpType::Append
        || effect.op.value.as_ref() != Some(&Value::String(event.realm_id.to_string()))
        || effect.op.tag.is_some()
        || effect.op.from.is_some()
        || effect.op.to.is_some()
        || effect.op.reason.is_some()
        || effect.op.issuer_seq.is_some()
    {
        return Err(Error::Protocol(
            "self principal PCR genesis has an invalid create effect".to_owned(),
        ));
    }
    Ok(())
}

fn validate_principal_control_realm_payload(event: &Event) -> Result<()> {
    let payload: RealmCreatePayload = event.payload_as()?;
    let realm = payload.object;
    let profile_count = realm
        .schema_refs
        .iter()
        .filter(|profile| profile.as_str() == PRINCIPAL_CONTROL_REALM_PROFILE)
        .count();
    let exact_purpose = realm.fields.len() == 1
        && realm.fields.get("purpose").and_then(Value::as_str) == Some(PRINCIPAL_CONTROL_PURPOSE);
    let notary_matches = matches!(
        &realm.notary,
        arkret_core::notary::NotaryValue::SingleDid { did, .. } if did == &event.actor_id
    );
    if realm.id != event.realm_id
        || realm.schema != arkret_core::REALM_SCHEMA_ID
        || realm.created_by != event.actor_id
        || realm.created_at != event.created_at
        || realm.security_class != Some(SecurityClass::HighAssurance)
        || profile_count != 1
        || realm.default_discoverability != Discoverability::Secret
        || realm.default_join_rule != JoinRule::Closed
        || realm.history_visibility != HistoryVisibility::Restricted
        || realm.encryption_profile != EncryptionProfile::MlsRfc9420
        || realm.content_encryption_floor != Some(EncryptionFloor::E2eeRequired)
        || realm.metadata_encryption_floor != Some(EncryptionFloor::E2eeRequired)
        || realm.notary_profile != NotaryProfile::SingleDid
        || !notary_matches
        || !exact_purpose
        || payload
            .initial_relations
            .is_some_and(|items| !items.is_empty())
    {
        return Err(Error::Protocol(
            "self principal PCR create payload violates create-locked profile".to_owned(),
        ));
    }
    realm.validate_kind_invariants()
}

fn validate_event_proof_digests(event: &Event) -> Result<()> {
    if event.proofs.is_empty() {
        return Err(Error::Protocol(
            "bootstrap event proof is missing".to_owned(),
        ));
    }
    let digest = event.event_digest()?;
    if event.proofs.iter().any(|proof| {
        proof.kind != arkret_core::proof_kind::DETACHED_JWS
            || proof.event_digest.as_str() != digest
            || proof.jws.is_empty()
    }) {
        return Err(Error::Protocol(
            "bootstrap event carries an invalid proof envelope".to_owned(),
        ));
    }
    Ok(())
}

fn proof_controller(verification_method: &str) -> Option<&str> {
    verification_method.split_once('#').map(|(did, _)| did)
}

fn payload_map<T: serde::Serialize>(payload: &T) -> Result<BTreeMap<String, Value>> {
    let Value::Object(map) = serde_json::to_value(payload)? else {
        return Err(Error::Protocol(
            "event payload must serialize to an object".to_owned(),
        ));
    };
    Ok(map.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureSigner {
        did: Did,
        verification_method: String,
    }

    impl MoveSigner for FixtureSigner {
        fn sign_move(
            &self,
            _unsigned: &arkret_core::UnsignedMove,
        ) -> std::result::Result<arkret_core::Move, arkret_core::WireError> {
            unreachable!("bootstrap Seal test does not sign Moves")
        }

        fn signer_did(&self) -> &Did {
            &self.did
        }

        fn verification_method_id(&self) -> &str {
            &self.verification_method
        }

        fn sign_payload(
            &self,
            canonical_bytes: &[u8],
        ) -> std::result::Result<MoveSignature, arkret_core::WireError> {
            Ok(MoveSignature {
                alg: "EdDSA".to_owned(),
                verification_method: self.verification_method.clone(),
                payload_digest: Hash::new(arkret_core::canonical::sha256_digest(canonical_bytes))?,
                created_at: Utc::now(),
                jws: "fixture.detached-signature".to_owned(),
            })
        }
    }

    fn attach_fixture_proof(event: &mut Event, verification_method: &str) {
        let digest = Hash::new(event.event_digest().unwrap()).unwrap();
        event.proofs = vec![arkret_core::Proof {
            kind: arkret_core::proof_kind::DETACHED_JWS.to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: verification_method.to_owned(),
            event_digest: digest,
            created_at: event.created_at,
            domain: None,
            audience: None,
            jws: "fixture.signature".to_owned(),
        }];
    }

    fn bootstrap_unit() -> (Event, Event) {
        let mut create = build_self_principal_pcr_create(input()).unwrap();
        attach_fixture_proof(
            &mut create,
            "did:key:z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ#z6MkvMW3tjuvW6PqYiX8dLRNwZWyGhxe3biRDjA4ZPiBaFaJ",
        );

        let authority =
            Did::new("did:key:z6MkgZb469vbyZCg3L7kx1PbQuUD4NToPpcy1utdLxUUfpsh").unwrap();
        let authorization_ref =
            arkret_core::NonEmptyString::new(format!("{}#enrollment-authority", create.actor_id))
                .unwrap();
        let payload = arkret_core::DeviceAuthorizePayload {
            principal_id: create.actor_id.clone(),
            device_id: arkret_core::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001")
                .unwrap(),
            device_public_key: arkret_core::NonEmptyString::new("z6MkDeviceKey").unwrap(),
            hpke_key: arkret_core::NonEmptyString::new("z6LSDeviceHpkeKey").unwrap(),
            algorithms: vec![
                arkret_core::NonEmptyString::new("ak.hpke_x25519_aead_chacha20poly1305.v1")
                    .unwrap(),
            ],
            device_key_algorithm: Some(arkret_core::NonEmptyString::new("EdDSA").unwrap()),
            authorized_by: arkret_core::DeviceOrPrincipalRef::Did(authority.clone()),
            scopes: None,
            not_before: create.created_at,
            expires_at: None,
            device_signature: None,
            proof: None,
            cross_signing_binding: None,
            enrollment_authority_binding: Some(arkret_core::DeviceEnrollmentAuthorityBinding {
                kind: arkret_core::DeviceEnrollmentAuthorityBindingKind::ServiceAttested,
                authority_did: authority.clone(),
                authorization_ref: authorization_ref.clone(),
            }),
            recovery_session_id: None,
        };
        let mut authorize = Event::new(
            arkret_core::events::EventKind::DEVICE_AUTHORIZE,
            create.realm_id.clone(),
            create.actor_id.clone(),
            1,
            Hlc::new("01970e589d21-0005-a13f9c2e").unwrap(),
            serde_json::to_value(payload).unwrap(),
        )
        .unwrap();
        authorize.event_id = EventId::new("ak:event:01904100-0000-7000-8000-000000000002").unwrap();
        authorize.created_at = create.created_at;
        authorize.prev_refs = vec![create.event_id.clone()];
        authorize.executed_by = Some(authority.clone());
        authorize.authorization_ref = Some(authorization_ref.to_string());
        attach_fixture_proof(
            &mut authorize,
            &format!("{authority}#z6MkgZb469vbyZCg3L7kx1PbQuUD4NToPpcy1utdLxUUfpsh"),
        );
        (create, authorize)
    }

    fn input() -> SelfPrincipalPcrCreateInput {
        let principal_id = Did::new("did:webvh:z6mkfixture:users.example:alice").unwrap();
        SelfPrincipalPcrCreateInput {
            realm_id: RealmId::new(arkret_core::principal_control_realm_id(&principal_id)).unwrap(),
            principal_id,
            trust_domain: TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap(),
            did_inception_ref: EventRef::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                DID_INCEPTION_REF_ROLE,
            ),
            event_id: EventId::new("ak:event:01904100-0000-7000-8000-000000000001").unwrap(),
            created_at: "2026-07-15T00:00:00Z".parse().unwrap(),
            hlc: Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
        }
    }

    #[test]
    fn builder_emits_only_the_closed_unsigned_root_shape() {
        let event = build_self_principal_pcr_create(input()).unwrap();

        assert_eq!(event.kind, arkret_core::events::EventKind::REALM_CREATE);
        assert_eq!(event.actor_seq, 0);
        assert!(event.prev_refs.is_empty());
        assert!(event.proofs.is_empty());
        assert_eq!(event.refs.len(), 1);
        assert_eq!(event.refs[0].role, DID_INCEPTION_REF_ROLE);
        validate_self_principal_pcr_create(&event, false).unwrap();
    }

    #[test]
    fn builder_rejects_a_non_self_realm_and_indirect_inception_ref() {
        let mut wrong_realm = input();
        wrong_realm.realm_id =
            RealmId::new("ak:realm:01904100-0000-7000-8000-000000000002").unwrap();
        assert!(build_self_principal_pcr_create(wrong_realm).is_err());

        let mut indirect = input();
        indirect.did_inception_ref.proof = Some(arkret_core::SemanticRefProof {
            kind: arkret_core::SemanticRefProofKind::Rfc6962Merkle,
            leaf_digest: Hash::new(
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )
            .unwrap(),
            audit_path: Vec::new(),
            leaf_index: 0,
            tree_size: 1,
        });
        assert!(build_self_principal_pcr_create(indirect).is_err());
    }

    #[test]
    fn bootstrap_authorize_must_continue_the_genesis_actor_chain_exactly() {
        let (create, authorize) = bootstrap_unit();
        validate_self_principal_bootstrap_unit(&create, &authorize).unwrap();
        let request =
            self_principal_bootstrap_submit_request(create.clone(), authorize.clone()).unwrap();
        assert!(request.event.is_none());
        assert_eq!(request.events.len(), 2);

        let mut missing = authorize.clone();
        missing.prev_refs.clear();
        assert!(validate_self_principal_bootstrap_unit(&create, &missing).is_err());

        let mut unrelated = authorize;
        unrelated.prev_refs = vec![
            create.event_id.clone(),
            EventId::new("ak:event:01904100-0000-7000-8000-000000000099").unwrap(),
        ];
        assert!(validate_self_principal_bootstrap_unit(&create, &unrelated).is_err());
    }

    #[test]
    fn first_bootstrap_seal_covers_both_events_and_is_signed_by_device_one() {
        let (create, authorize) = bootstrap_unit();
        let device_id = "ak:device:01904100-0000-7000-8000-000000000001";
        let signer = FixtureSigner {
            did: create.actor_id.clone(),
            verification_method: format!("{}#{device_id}", create.actor_id),
        };
        let seal = build_self_principal_bootstrap_seal(
            &create,
            &authorize,
            Hlc::new("01970e589d21-0006-a13f9c2e").unwrap(),
            &signer,
        )
        .unwrap();

        assert!(seal.predecessor_refs.is_empty());
        assert_eq!(seal.notary_seq, 0);
        assert_eq!(seal.delta.len(), 2);
        assert_eq!(seal.covered_event_digests, seal.delta);
        assert_eq!(seal.control_event_set_root, seal.completeness_root);
        assert_eq!(seal.derive_id().unwrap(), seal.id);
        let NotarySig::Single(signature) = seal.notary_signature else {
            panic!("bootstrap Seal must use one device signature")
        };
        assert_eq!(signature.verification_method, signer.verification_method);
    }

    #[test]
    fn managed_agent_seal_covers_effectless_mls_genesis_with_controller_signature() {
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-0000000000a1").unwrap();
        let agent = Did::new("did:web:agent.example").unwrap();
        let controller = Did::new("did:web:controller.example").unwrap();
        let authorization_ref = format!("{agent}#managed-controller");
        let mut create = Event::new(
            arkret_core::events::EventKind::REALM_CREATE,
            realm_id.clone(),
            agent.clone(),
            1,
            Hlc::new("01970e589d21-0007-a13f9c2e").unwrap(),
            serde_json::json!({
                "object": {
                    "id": realm_id,
                    "created_by": agent,
                    "fields": {"purpose": "principal_control"},
                    "notary": {"type": "single_did", "did": agent},
                }
            }),
        )
        .unwrap();
        create.event_id = EventId::new("ak:event:01904100-0000-7000-8000-0000000000a1").unwrap();
        create.executed_by = Some(controller.clone());
        create.authorization_ref = Some(authorization_ref.clone());
        create.effects = vec![
            managed_agent_principal_control_create_effect(&create.realm_id, create.actor_seq)
                .unwrap(),
        ];

        let mut genesis = Event::new(
            arkret_core::events::EventKind::MLS_GENESIS,
            create.realm_id.clone(),
            create.actor_id.clone(),
            2,
            Hlc::new("01970e589d21-0008-a13f9c2e").unwrap(),
            serde_json::json!({}),
        )
        .unwrap();
        genesis.event_id = EventId::new("ak:event:01904100-0000-7000-8000-0000000000a2").unwrap();
        genesis.executed_by = Some(controller.clone());
        genesis.authorization_ref = Some(authorization_ref);
        assert!(genesis.effects.is_empty());

        let signer = FixtureSigner {
            did: controller.clone(),
            verification_method: format!(
                "{controller}#ak:device:01904100-0000-7000-8000-0000000000a1"
            ),
        };
        let first = build_managed_agent_pcr_event_seal(
            &[create.clone()],
            None,
            Hlc::new("01970e589d21-0009-a13f9c2e").unwrap(),
            &signer,
        )
        .unwrap();
        let successor = build_managed_agent_pcr_event_seal(
            &[create, genesis.clone()],
            Some(&first),
            Hlc::new("01970e589d21-000a-a13f9c2e").unwrap(),
            &signer,
        )
        .unwrap();

        assert_eq!(successor.predecessor_refs, vec![first.id.clone()]);
        assert_eq!(successor.notary_seq, 1);
        assert_eq!(successor.delta.len(), 1);
        assert_eq!(successor.delta[0].as_str(), genesis.event_digest().unwrap());
        assert_eq!(successor.covered_event_digests.len(), 2);
        assert_eq!(successor.state_root, first.state_root);
        assert_ne!(
            successor.control_event_set_root,
            first.control_event_set_root
        );
        let NotarySig::Single(signature) = successor.notary_signature else {
            panic!("managed Agent PCR Seal must use one controller signature")
        };
        assert_eq!(signature.verification_method, signer.verification_method);
    }
}
