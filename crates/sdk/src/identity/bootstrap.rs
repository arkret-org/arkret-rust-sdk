use std::collections::BTreeMap;

use arkret_core::events::kinds;
use arkret_core::{
    CellRef, Did, Discoverability, Effect, EncryptionFloor, EncryptionProfile, Event, EventId,
    EventRef, EventRequirements, EventsSubmitRequestBody, HistoryVisibility, Hlc, JoinRule,
    LatticeOp, LatticeOpType, NotaryProfile, Realm, RealmCreatePayload, RealmId, SecurityClass,
    TypedTrustDomainId,
};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::{Error, Result};

pub const PRINCIPAL_CONTROL_REALM_PROFILE: &str = "ak.profile.principal_control_realm.v1";
pub const DID_INCEPTION_REF_ROLE: &str = "did_inception";
const PRINCIPAL_CONTROL_PURPOSE: &str = "principal_control";
const PRINCIPAL_CONTROL_CREATE_CELL: &str =
    "ak:cell:ak.component.realm.create.v1:principal_control";

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
        kind: kinds::REALM_CREATE.into(),
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

pub fn validate_self_principal_bootstrap_unit(create: &Event, authorize: &Event) -> Result<()> {
    validate_self_principal_pcr_create(create, true)?;
    if authorize.kind != kinds::DEVICE_AUTHORIZE
        || authorize.realm_id != create.realm_id
        || authorize.actor_id != create.actor_id
        || authorize.actor_seq != 1
        || !authorize.prev_refs.is_empty()
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
        authorize.typed_payload(kinds::DEVICE_AUTHORIZE)?;
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
    if event.kind != kinds::REALM_CREATE
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

        assert_eq!(event.kind, kinds::REALM_CREATE);
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
            leaf_digest: arkret_core::Hash::new(
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )
            .unwrap(),
            audit_path: Vec::new(),
            leaf_index: 0,
            tree_size: 1,
        });
        assert!(build_self_principal_pcr_create(indirect).is_err());
    }
}
