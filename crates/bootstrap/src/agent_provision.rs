//! Controller-owned managed-agent provisioning Event drafts.

use arkret_models_collaboration::governance::accountability::{
    AccountabilityGrantPayload, AccountabilityScope, AccountabilityScopeKind,
};
use arkret_models_identity::claim_presentation::AgentSelectorClaim;
use arkret_models_identity::handle::{HandleBindingState, HandleVisibility};
use arkret_wire::{
    Did, Error, Event, EventKind, Hash, Hlc, PayloadProof, PayloadSigner, ProfileRef, RealmId,
    Result, SchemaId, ScopeRef, proof_kind,
};
use chrono::{DateTime, Utc};

/// Envelope stamps supplied before the submit pipeline signs each Event envelope.
#[derive(Clone, Debug)]
pub struct AgentProvisionEventDraftOptions {
    pub created_at: DateTime<Utc>,
    pub accountability_actor_seq: u64,
    pub accountability_hlc: Hlc,
    pub selector_actor_seq: u64,
    pub selector_hlc: Hlc,
}

/// Controller-owned Event drafts before ordinary publication evidence is
/// attached. This is deliberately distinct from
/// `agent_operations::AgentProvisionEvents`, whose two fields are complete
/// `EventInitialSubmission` values on the provision commit wire.
#[derive(Clone, Debug)]
pub struct AgentProvisionEventDrafts {
    pub accountability_grant: Event,
    pub selector_claim: Event,
}

/// Build the closed controller-owned managed-agent provisioning Event pair.
pub fn build_agent_provision_event_drafts<S: PayloadSigner + ?Sized>(
    controller_id: &Did,
    controller_realm_id: &RealmId,
    agent_id: &Did,
    agent_slug: &str,
    options: AgentProvisionEventDraftOptions,
    signer: &S,
) -> Result<AgentProvisionEventDrafts> {
    if signer.signer_did() != controller_id {
        return Err(Error::Protocol(format!(
            "provision signer {} does not match controller {controller_id}",
            signer.signer_did()
        )));
    }
    let created_at = arkret_canonical::normalize_timestamp_canonical(options.created_at);
    let verification_method = signer.verification_method_id().to_owned();
    let placeholder_digest = Hash::new(format!("sha256:{}", "0".repeat(64)))?;
    let mut accountability_payload = AccountabilityGrantPayload::new(
        controller_id.clone(),
        agent_id.clone(),
        AccountabilityScope::Single(AccountabilityScopeKind::AgentOperator),
        created_at,
        None,
        PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: verification_method.clone(),
            payload_digest: placeholder_digest,
            created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "pending".to_owned(),
        },
    );
    accountability_payload.proof.payload_digest = accountability_payload.payload_digest()?;
    let proof_bytes = accountability_payload.canonical_proof_binding_bytes()?;
    let signature = signer.sign_payload(&proof_bytes)?;
    if signature.verification_method != verification_method {
        return Err(Error::Protocol(
            "provision signer changed verification_method while signing".to_owned(),
        ));
    }
    let expected_signature_digest =
        Hash::new(arkret_canonical::canonical::sha256_digest(&proof_bytes))?;
    if signature.payload_digest != expected_signature_digest {
        return Err(Error::Protocol(
            "provision signer returned the wrong proof transcript digest".to_owned(),
        ));
    }
    accountability_payload.proof.alg = signature.alg;
    accountability_payload.proof.jws = signature.jws;

    let accountability_value = serde_json::to_value(&accountability_payload)?;
    // Provisioning happens inside the controller's own Realm scope; neither
    // slot is Circle-scoped, and `scope_ref` is now what fixes the envelope
    // `realm_id`, so the two can no longer be stamped independently.
    let controller_scope = ScopeRef::Realm {
        realm_id: controller_realm_id.clone(),
    };
    let mut accountability_grant = Event::new_at(
        EventKind::IDENTITY_ACCOUNTABILITY_GRANT,
        controller_scope.clone(),
        controller_id.clone(),
        options.accountability_actor_seq,
        options.accountability_hlc,
        accountability_value,
        created_at,
    )?;
    accountability_grant.requirements.schema_profile_refs =
        vec![ProfileRef::new(SchemaId::ACCOUNTABILITY_GRANT_V1).unwrap()];

    let mut selector_payload = AgentSelectorClaim {
        schema: SchemaId::AGENT_SELECTOR_CLAIM_V1.to_owned(),
        controller_subject: controller_id.clone(),
        agent_slug: agent_slug.to_owned(),
        subject: agent_id.clone(),
        issuer: controller_id.clone(),
        issuer_service_id: None,
        binding_state: HandleBindingState::Pending,
        visibility: HandleVisibility::Private,
        audience: None,
        claim_scope: Default::default(),
        expires_at: None,
        created_at,
        verified_at: None,
        source_refs: vec![accountability_grant.event_id.to_string()],
        proofs: vec![PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: verification_method.clone(),
            payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64)))?,
            created_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "pending".to_owned(),
        }],
    };
    selector_payload.proofs[0].payload_digest = selector_payload.payload_digest()?;
    let selector_binding =
        selector_payload.canonical_proof_binding_bytes(&selector_payload.proofs[0])?;
    let selector_signature = signer.sign_payload(&selector_binding)?;
    if selector_signature.verification_method != verification_method
        || selector_signature.payload_digest
            != Hash::new(arkret_canonical::canonical::sha256_digest(
                &selector_binding,
            ))?
    {
        return Err(Error::Protocol(
            "provision signer returned an invalid selector proof signature".to_owned(),
        ));
    }
    selector_payload.proofs[0].alg = selector_signature.alg;
    selector_payload.proofs[0].jws = selector_signature.jws;
    selector_payload.validate()?;
    let selector_value = serde_json::to_value(&selector_payload)?;
    let mut selector_claim = Event::new_at(
        "ak.agent.selector_claim",
        controller_scope,
        controller_id.clone(),
        options.selector_actor_seq,
        options.selector_hlc,
        selector_value,
        created_at,
    )?;
    selector_claim.requirements.schema_profile_refs =
        vec![ProfileRef::new(SchemaId::AGENT_SELECTOR_CLAIM_V1).unwrap()];

    Ok(AgentProvisionEventDrafts {
        accountability_grant,
        selector_claim,
    })
}
