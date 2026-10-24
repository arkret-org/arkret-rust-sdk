//! Authenticated Contact current operations, original grants and exact closures.
//!
//! This module authenticates original Contact carriers, exact bilateral round
//! origins and bounded source-certified current at an actual observation. Source
//! confirmation and holder signatures are separate evidence. Consumers still
//! retain fixed first identity and ordinary-history closures before
//! publication; this adapter does not grant runtime or session capabilities.

use arkret_canonical::DigestSuite;
use arkret_identity::{AuthorityDidHistoryResolver, DidVerificationRelationship};
use arkret_models_collaboration::contact_operations::{
    ContactCurrentMaterial, ContactCurrentProof, ContactInitialIdentity, ContactOperationEvidence,
    ContactPeer, ContactProducerSigner, ContactRoundBasis, ContactRoundEvidenceBundle,
    ContactScope, PeerContactSubmitRequestBody, RequestAcceptanceReceipt,
};
use arkret_models_collaboration::events_payloads::contact::ContactRequestedPayload;
use arkret_models_identity::{DidDocument, DidMethodUri};
use arkret_wire::{DidCoreId, Event, EventId, EventKind, Hash, ProtocolSignature};
use chrono::{DateTime, Utc};

#[derive(Debug, thiserror::Error)]
pub enum ContactAuthorizationError {
    #[error("Contact historical material is unavailable: {0}")]
    MissingMaterial(String),
    #[error("invalid Contact directional evidence: {0}")]
    InvalidEvidence(String),
    #[error("Contact evidence is not current at the requested observation")]
    NotCurrent,
}

type Result<T> = std::result::Result<T, ContactAuthorizationError>;
fn invalid(error: impl ToString) -> ContactAuthorizationError {
    ContactAuthorizationError::InvalidEvidence(error.to_string())
}

/// An exact open interval, or its authenticated closing transition. Fields are
/// immutable and instances are produced only from verified source evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedContactScopeInterval {
    scope: ContactScope,
    authorization_event_id: EventId,
    generation_event_id: EventId,
    closed_by: Option<EventId>,
}
impl VerifiedContactScopeInterval {
    pub fn scope(&self) -> ContactScope {
        self.scope
    }
    pub fn authorization_event_id(&self) -> &EventId {
        &self.authorization_event_id
    }
    pub fn generation_event_id(&self) -> &EventId {
        &self.generation_event_id
    }
    pub fn closed_by(&self) -> Option<&EventId> {
        self.closed_by.as_ref()
    }
}

/// Non-serializable verified evidence for an independent receiving Station or
/// auditor, not a prerequisite imposed on an ordinary client. Durable restore
/// must retain authenticated evidence and observation provenance; this API does
/// not deserialize a cached allow flag or authenticate a claimed old observation.
#[derive(Clone, Debug)]
pub struct VerifiedContactDirection {
    issuer: ContactPeer,
    peer: ContactPeer,
    round: Hash,
    head: EventId,
    current_from: DateTime<Utc>,
    cache_expires_at: DateTime<Utc>,
    intervals: Vec<VerifiedContactScopeInterval>,
}
impl VerifiedContactDirection {
    pub fn issuer(&self) -> &ContactPeer {
        &self.issuer
    }
    pub fn peer(&self) -> &ContactPeer {
        &self.peer
    }
    pub fn contact_round_id(&self) -> &Hash {
        &self.round
    }
    pub fn head_event_id(&self) -> &EventId {
        &self.head
    }
    pub fn intervals(&self) -> &[VerifiedContactScopeInterval] {
        &self.intervals
    }
    /// Scope still open in the authenticated source history. This has no TTL
    /// check: freshness is not revocation. Later verified narrowing/terminal
    /// evidence and ordinary-history cuts must independently fence publication.
    pub fn open_interval(&self, scope: ContactScope) -> Option<&VerifiedContactScopeInterval> {
        self.intervals
            .iter()
            .find(|interval| interval.scope == scope && interval.closed_by.is_none())
    }
    /// Required by current Contact mutations and Direct Conversation founding.
    pub fn require_current_at(&self, at: DateTime<Utc>) -> Result<()> {
        if at < self.current_from || at >= self.cache_expires_at {
            return Err(ContactAuthorizationError::NotCurrent);
        }
        Ok(())
    }
}

/// Exact original carrier with independent producer and source authentication.
/// This is evidence of a confirmed Contact command, not a current grant or a
/// complete round. Only authenticated current material derives scope intervals.
#[derive(Clone, Debug)]
pub struct VerifiedContactEvent {
    carrier: PeerContactSubmitRequestBody,
    holder: ContactPeer,
    peer: ContactPeer,
    event_id: EventId,
    kind: EventKind,
    observed_at: DateTime<Utc>,
    fence: Option<VerifiedContactTerminalFence>,
}
impl VerifiedContactEvent {
    pub fn carrier(&self) -> &PeerContactSubmitRequestBody {
        &self.carrier
    }
    pub fn holder(&self) -> &ContactPeer {
        &self.holder
    }
    pub fn peer(&self) -> &ContactPeer {
        &self.peer
    }
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }
    pub fn kind(&self) -> EventKind {
        self.kind.clone()
    }
    pub fn observed_at(&self) -> DateTime<Utc> {
        self.observed_at
    }
    pub fn terminal_fence(&self) -> Option<VerifiedContactTerminalFence> {
        self.fence.clone()
    }
}

/// A source-confirmed, holder-signed whole-round tombstone. It can fence an
/// opposite direction without inventing a new local lineage version.
#[derive(Clone, Debug)]
pub struct VerifiedContactTerminalFence {
    round: Hash,
    holder: ContactPeer,
    peer: ContactPeer,
    event_id: EventId,
}
impl VerifiedContactTerminalFence {
    pub fn holder(&self) -> &ContactPeer {
        &self.holder
    }
    pub fn peer(&self) -> &ContactPeer {
        &self.peer
    }
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }
    pub fn contact_round_id(&self) -> &Hash {
        &self.round
    }
}

fn payload<T: serde::de::DeserializeOwned>(event: &Event) -> Result<T> {
    serde_json::from_value(serde_json::to_value(&event.payload).map_err(invalid)?).map_err(invalid)
}

/// Public Agent identity authenticated from its complete native DID history.
/// This proves the exact Contact actor/controller/PCR binding at the Event's
/// historical identity point; command authorization still belongs to admission.
#[derive(Clone, Debug)]
pub struct VerifiedContactAgentIdentity {
    did: arkret_wire::Did,
    event_id: EventId,
}
impl VerifiedContactAgentIdentity {
    pub fn did(&self) -> &arkret_wire::Did {
        &self.did
    }
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }
}

pub fn verify_contact_agent_identity(
    event: &Event,
    holder: &ContactPeer,
    did: &arkret_wire::Did,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<VerifiedContactAgentIdentity> {
    if !matches!(holder, ContactPeer::Agent { .. }) {
        return Err(invalid("Contact Agent identity requires an Agent holder"));
    }
    verify_agent_holder_binding(event, holder, Some(did), resolver)?;
    Ok(VerifiedContactAgentIdentity {
        did: did.clone(),
        event_id: event.event_id.clone(),
    })
}

fn verify_agent_holder_binding(
    event: &Event,
    holder: &ContactPeer,
    agent_did: Option<&arkret_wire::Did>,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<()> {
    let ContactPeer::Agent {
        actor_id: actor,
        controller_account_id: controller,
    } = holder
    else {
        return Ok(());
    };
    if actor.as_account_id().is_none()
        || actor != &event.actor_id
        || actor.fixed_route_service_id() != Some(&controller.station_id)
        || event
            .executed_by
            .as_ref()
            .is_some_and(|executor| executor != &arkret_wire::ActorId::account(controller.clone()))
    {
        return Err(invalid(
            "Agent holder, source Station and controller do not form the exact accepted account pair",
        ));
    }
    let candidate = agent_did.cloned().or_else(|| {
        event
            .producer_proof
            .as_ref()
            .map(|p| p.verification_method.as_str())
            .into_iter()
            .chain(event.authorization_ref.as_ref().map(|r| r.as_str()))
            .filter_map(|reference| reference.split_once('#'))
            .filter_map(|(did, _)| arkret_wire::Did::new(did).ok())
            .find(|did| {
                arkret_wire::project_did_to_core_id(did).ok().as_ref()
                    == Some(actor.signing_principal_id())
            })
    });
    let did = candidate.ok_or_else(|| {
        ContactAuthorizationError::MissingMaterial(
            "source-authenticated public Agent DID locator is absent".into(),
        )
    })?;
    if arkret_wire::project_did_to_core_id(&did).map_err(invalid)? != *actor.signing_principal_id()
    {
        return Err(invalid(
            "public Agent DID does not bind the expected full account principal",
        ));
    }
    let history = resolver
        .resolve_complete_history(&did)
        .map_err(|e| ContactAuthorizationError::MissingMaterial(e.to_string()))?;
    if history.did != did
        || history.method != DidMethodUri::Webvh
        || history.native_history == Some(false)
        || history.entries.is_empty()
        || history.has_more
        || history.next_cursor.is_some()
    {
        return Err(ContactAuthorizationError::MissingMaterial(
            "complete Agent DID delegation history is absent".into(),
        ));
    }
    let verified =
        arkret_identity::verify_did_webvh_v1_chain(&did, &history.entries).map_err(invalid)?;
    arkret_identity::contact_producer_identity::validate_agent_contact_identity_at(
        event, holder, &did, &verified,
    )
    .map_err(invalid)
}

fn verify_holder(
    event: &Event,
    holder: &ContactPeer,
    signer: &ContactProducerSigner,
    suite: DigestSuite,
) -> Result<()> {
    signer.validate_for_event(event, holder).map_err(invalid)?;
    if event.actor_id != holder.contact_actor_id() || event.actor_id.as_account_id().is_none() {
        return Err(invalid(
            "Event actor differs from the expected complete Contact holder account",
        ));
    }
    event
        .validate_for_contact_history_structural()
        .map_err(invalid)?;
    arkret_schema::validate_event_wire_schema(event).map_err(invalid)?;
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(invalid)?;
    let Some(proof) = event.producer_proof.as_ref() else {
        return Err(invalid("Contact requires producer_proof"));
    };
    proof.validate_production().map_err(invalid)?;
    // Ordinary Contact Events do not inherit a native atomic unit's shared
    // authoring checkpoint. The source descriptor binds the exact method/key;
    // the original proof independently binds its own signing timestamp.
    if &proof.verification_method != signer.verification_method() {
        return Err(invalid(
            "producer method differs from the source-authenticated exact Event",
        ));
    }
    let producer = event.executed_by.as_ref().unwrap_or(&event.actor_id);
    match holder {
        ContactPeer::Human { .. } if event.executed_by.is_some() => {
            return Err(invalid(
                "human Contact Event cannot have a delegated executor",
            ));
        }
        ContactPeer::Agent {
            controller_account_id,
            ..
        } if event.executed_by.is_some()
            && producer != &arkret_wire::ActorId::account(controller_account_id.clone()) =>
        {
            return Err(invalid(
                "Agent executor is not its exact controller account",
            ));
        }
        _ => {}
    }
    let did = arkret_identity::verification_method_did(signer.verification_method().as_str())
        .map_err(invalid)?;
    if arkret_wire::project_did_to_core_id(&did).map_err(invalid)?
        != *producer.signing_principal_id()
    {
        return Err(invalid(
            "source-projected method does not belong to the actual Event producer",
        ));
    }
    let key = arkret_signatures::proof::PublicKeyMaterial::Ed25519Raw {
        bytes: signer.public_key_bytes().map_err(invalid)?.to_vec(),
    };
    let bytes = arkret_canonical::canonical_json_bytes(&event.digest_payload().map_err(invalid)?)
        .map_err(invalid)?;
    arkret_signatures::proof::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &key,
        suite,
    )
    .map_err(invalid)
}

fn verify_request_receipt(
    receipt: &RequestAcceptanceReceipt,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<()> {
    receipt.validate_shape().map_err(invalid)?;
    if receipt.core.issuer_id != *receipt.core.holder.delivery_station_id() {
        return Err(invalid(
            "request receipt source differs from the holder authority",
        ));
    }
    verify_source_signature_at(
        receipt.core.holder.delivery_station_id(),
        &receipt.signature,
        &arkret_signatures::contact_receipt::contact_request_acceptance_receipt_signing_bytes(
            receipt,
        )
        .map_err(invalid)?,
        receipt.core.accepted_at,
        resolver,
    )
}

fn verify_current_identity(
    proof: &ContactCurrentProof,
    holder: &ContactPeer,
    peer: &ContactPeer,
    round: Option<&Hash>,
    observed_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<()> {
    proof.validate_shape().map_err(invalid)?;
    if proof.holder != *holder
        || proof.peer != *peer
        || proof.contact_round_id.as_ref() != round
        || proof.issued_at > observed_at
    {
        return Err(invalid(
            "current proof does not bind the exact direction and observation",
        ));
    }
    verify_source_signature_at(
        holder.delivery_station_id(),
        &proof.signature,
        &proof.canonical_signing_bytes().map_err(invalid)?,
        proof.issued_at,
        resolver,
    )
}

/// Authenticate original holder intent and its exact source confirmation.
/// This returns no current authorization and does not re-admit cached facts.
pub fn authenticate_contact_event_carrier(
    carrier: &PeerContactSubmitRequestBody,
    expected_holder: &ContactPeer,
    suite: DigestSuite,
    observed_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<VerifiedContactEvent> {
    let operation = contact_carrier_operation(carrier)?;
    if operation.holder() != expected_holder {
        return Err(invalid(
            "carrier holder differs from expected exact participant",
        ));
    }
    verify_original_operation(&operation, suite, observed_at, resolver)?;
    if let PeerContactSubmitRequestBody::Request {
        introduction_evidence,
        ..
    } = carrier
    {
        let request: ContactRequestedPayload = payload(operation.event())?;
        let digest = Hash::new(
            arkret_canonical::domain_prefixed_canonical_sha256(
                "ak.contact.introduction-evidence.v1",
                introduction_evidence,
            )
            .map_err(invalid)?,
        )
        .map_err(invalid)?;
        if digest != request.introduction_evidence_digest {
            return Err(invalid("introduction evidence differs from signed digest"));
        }
    }
    let (address, current) = match carrier {
        PeerContactSubmitRequestBody::Request {
            contact_address,
            current_proof,
            ..
        }
        | PeerContactSubmitRequestBody::Response {
            contact_address,
            current_proof,
            ..
        } => (contact_address, current_proof.as_ref()),
        PeerContactSubmitRequestBody::Reject {
            contact_address, ..
        } => (contact_address, None),
        PeerContactSubmitRequestBody::ScopeUpdate {
            contact_address,
            current_proof,
            ..
        }
        | PeerContactSubmitRequestBody::Tombstone {
            contact_address,
            current_proof,
            ..
        } => (contact_address, Some(current_proof)),
        _ => return Err(invalid("not an original Contact carrier")),
    };
    address.validate_shape().map_err(invalid)?;
    if &address.recipient != operation.peer() {
        return Err(invalid("carrier address differs from exact signed peer"));
    }
    if let Some(proof) = current {
        verify_current_identity(
            proof,
            operation.holder(),
            operation.peer(),
            proof.contact_round_id.as_ref(),
            observed_at,
            resolver,
        )?;
        if proof.trust_domain_id != *operation.trust_domain_id()
            || proof.version < operation.version()
            || (proof.version == operation.version()
                && proof.head_event_ref != operation.event().event_id)
        {
            return Err(invalid(
                "carrier current predates or changes exact original operation",
            ));
        }
    }
    let fence = match &operation {
        ContactOperationEvidence::Tombstone {
            signed_event,
            lineage,
        } => Some(VerifiedContactTerminalFence {
            round: lineage
                .contact_round_id
                .clone()
                .ok_or_else(|| invalid("tombstone round missing"))?,
            holder: operation.holder().clone(),
            peer: operation.peer().clone(),
            event_id: signed_event.event_id.clone(),
        }),
        _ => None,
    };
    Ok(VerifiedContactEvent {
        carrier: carrier.clone(),
        holder: operation.holder().clone(),
        peer: operation.peer().clone(),
        event_id: operation.event().event_id.clone(),
        kind: operation.event().kind.clone(),
        observed_at,
        fence,
    })
}

fn contact_carrier_operation(
    carrier: &PeerContactSubmitRequestBody,
) -> Result<ContactOperationEvidence> {
    Ok(match carrier {
        PeerContactSubmitRequestBody::Request {
            signed_event,
            request_receipt,
            ..
        } => ContactOperationEvidence::Request {
            signed_event: signed_event.clone(),
            request_receipt: request_receipt.clone(),
        },
        PeerContactSubmitRequestBody::Response {
            signed_event,
            response_receipt,
            ..
        } => ContactOperationEvidence::Response {
            signed_event: signed_event.clone(),
            response_receipt: response_receipt.clone(),
        },
        PeerContactSubmitRequestBody::Reject {
            signed_event,
            reject_receipt,
            ..
        } => ContactOperationEvidence::Reject {
            signed_event: signed_event.clone(),
            reject_receipt: reject_receipt.clone(),
        },
        PeerContactSubmitRequestBody::ScopeUpdate {
            signed_event,
            lineage,
            ..
        } => ContactOperationEvidence::ScopeUpdate {
            signed_event: signed_event.clone(),
            lineage: lineage.clone(),
        },
        PeerContactSubmitRequestBody::Tombstone {
            signed_event,
            lineage,
            ..
        } => ContactOperationEvidence::Tombstone {
            signed_event: signed_event.clone(),
            lineage: lineage.clone(),
        },
        _ => return Err(invalid("control request contains no holder operation")),
    })
}
/// Authenticate an original operation without re-admitting its introduction.
/// Original source admission and holder signatures remain independent checks.
fn verify_original_operation(
    operation: &ContactOperationEvidence,
    suite: DigestSuite,
    observed_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<()> {
    operation.validate_shape().map_err(invalid)?;
    if operation.accepted_at() > observed_at
        || operation.source_signature().created_at > observed_at
    {
        return Err(invalid("original operation confirmation is in the future"));
    }
    verify_source_signature_at(
        operation.holder().delivery_station_id(),
        operation.source_signature(),
        &operation.source_signing_bytes().map_err(invalid)?,
        operation.source_authority_at(),
        resolver,
    )?;
    verify_holder(
        operation.event(),
        operation.holder(),
        operation.producer_signer(),
        suite,
    )?;
    verify_agent_holder_binding(
        operation.event(),
        operation.holder(),
        operation.producer_signer().delegated_actor_did(),
        resolver,
    )?;
    match operation {
        ContactOperationEvidence::Response {
            response_receipt, ..
        } => verify_request_receipt(&response_receipt.request_receipt, resolver)?,
        ContactOperationEvidence::Reject { reject_receipt, .. } => {
            verify_request_receipt(&reject_receipt.request_receipt, resolver)?
        }
        _ => {}
    }
    Ok(())
}
fn verify_basis_originals(
    basis: &ContactRoundBasis,
    events: &[Event],
    suite: DigestSuite,
    observed_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<()> {
    basis.validate_shape().map_err(invalid)?;
    for receipt in &basis.request_receipts {
        let event = events
            .iter()
            .find(|e| e.event_id == receipt.core.request_event_ref)
            .ok_or_else(|| {
                ContactAuthorizationError::MissingMaterial("original round request missing".into())
            })?;
        verify_original_operation(
            &ContactOperationEvidence::Request {
                signed_event: event.clone(),
                request_receipt: receipt.clone(),
            },
            suite,
            observed_at,
            resolver,
        )?;
    }
    if let Some(receipt) = &basis.normal_response_receipt {
        let event = events
            .iter()
            .find(|e| e.event_id == receipt.response_event_ref)
            .ok_or_else(|| {
                ContactAuthorizationError::MissingMaterial("original round accept missing".into())
            })?;
        verify_original_operation(
            &ContactOperationEvidence::Response {
                signed_event: event.clone(),
                response_receipt: receipt.clone(),
            },
            suite,
            observed_at,
            resolver,
        )?;
    }
    if let Some(attestations) = &basis.glare_concurrency_attestations {
        for attestation in attestations {
            if attestation.observed_at > observed_at
                || attestation.signature.created_at > observed_at
            {
                return Err(invalid("glare observation is in the future"));
            }
            verify_source_signature_at(
                &attestation.issuer_id,
                &attestation.signature,
                &attestation.canonical_signing_bytes().map_err(invalid)?,
                attestation.observed_at,
                resolver,
            )?;
        }
    }
    Ok(())
}
pub fn verify_contact_initial_identity(
    initial: &ContactInitialIdentity,
    suite: DigestSuite,
    observed_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<()> {
    initial.validate_shape().map_err(invalid)?;
    verify_basis_originals(
        &initial.round,
        &initial.events,
        suite,
        observed_at,
        resolver,
    )
}
fn verify_round_closure(
    closure: &arkret_models_collaboration::contact_operations::ContactRoundClosure,
    holder: &ContactPeer,
    peer: &ContactPeer,
    domain: &arkret_wire::TrustDomainId,
    observed_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<VerifiedContactTerminalFence> {
    let op = closure.operation.operation();
    verify_original_operation(
        &op,
        op.event()
            .event_id
            .event_digest()
            .digest_suite()
            .map_err(invalid)?,
        observed_at,
        resolver,
    )?;
    if closure.operation.lineage.contact_round_id.as_ref() != Some(&closure.contact_round_id)
        || op.trust_domain_id() != domain
        || !((op.holder() == holder && op.peer() == peer)
            || (op.holder() == peer && op.peer() == holder))
    {
        return Err(invalid(
            "closure does not bind the exact round and direction",
        ));
    }
    Ok(VerifiedContactTerminalFence {
        round: closure.contact_round_id.clone(),
        holder: op.holder().clone(),
        peer: op.peer().clone(),
        event_id: op.event().event_id.clone(),
    })
}

/// Verified bounded response. Consumers retain the original signed control
/// result and install the material atomically with their immutable local root,
/// head conflict checks and known exact-round fences.
#[derive(Clone, Debug)]
pub struct VerifiedContactCurrentMaterial {
    material: ContactCurrentMaterial,
    direction: Option<VerifiedContactDirection>,
    closure: Option<VerifiedContactTerminalFence>,
}
impl VerifiedContactCurrentMaterial {
    pub fn material(&self) -> &ContactCurrentMaterial {
        &self.material
    }
    pub fn direction(&self) -> Option<&VerifiedContactDirection> {
        self.direction.as_ref()
    }
    pub fn closure(&self) -> Option<&VerifiedContactTerminalFence> {
        self.closure.as_ref()
    }
}
#[allow(clippy::too_many_arguments)]
fn verify_current_material_inner(
    material: &ContactCurrentMaterial,
    expected_holder: &ContactPeer,
    expected_peer: &ContactPeer,
    expected_domain: &arkret_wire::TrustDomainId,
    suite: DigestSuite,
    observed_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
    certified_intervals: bool,
) -> Result<VerifiedContactCurrentMaterial> {
    material.validate_shape().map_err(invalid)?;
    if !certified_intervals && !material.historical_intervals.is_empty() {
        return Err(ContactAuthorizationError::MissingMaterial(
            "historical interval boundaries require the exact signed control result".into(),
        ));
    }
    let proof = &material.current_proof;
    if &proof.trust_domain_id != expected_domain {
        return Err(invalid("current domain mismatch"));
    }
    verify_current_identity(
        proof,
        expected_holder,
        expected_peer,
        proof.contact_round_id.as_ref(),
        observed_at,
        resolver,
    )?;
    if observed_at >= proof.cache_expires_at {
        return Err(ContactAuthorizationError::NotCurrent);
    }
    verify_original_operation(&material.head_operation, suite, observed_at, resolver)?;
    for grant in &material.scope_grants {
        verify_original_operation(grant, suite, observed_at, resolver)?;
    }
    if let Some(initial) = &material.initial_identity {
        verify_contact_initial_identity(initial, suite, observed_at, resolver)?;
    }
    if let Some(basis) = &material.round_evidence {
        verify_basis_originals(
            basis,
            material
                .round_events
                .as_deref()
                .ok_or_else(|| invalid("current round originals missing"))?,
            suite,
            observed_at,
            resolver,
        )?;
    }
    let original_closure = material
        .head_operation
        .round_closure()
        .or_else(|| proof.closed_round.as_deref().cloned());
    let closure = original_closure
        .as_ref()
        .map(|close| {
            verify_round_closure(
                close,
                expected_holder,
                expected_peer,
                expected_domain,
                observed_at,
                resolver,
            )
        })
        .transpose()?;
    let mut intervals = Vec::new();
    for instance in &proof.scope_instances {
        let grant = material
            .scope_grants
            .iter()
            .find(|op| op.event().event_id == instance.grant_event_ref)
            .ok_or_else(|| {
                ContactAuthorizationError::MissingMaterial("current grant missing".into())
            })?;
        let closed_by = closure
            .as_ref()
            .filter(|c| Some(&c.round) == proof.contact_round_id.as_ref())
            .map(|c| c.event_id.clone());
        intervals.push(VerifiedContactScopeInterval {
            scope: instance.contact_scope,
            authorization_event_id: grant.event().event_id.clone(),
            generation_event_id: grant.event().event_id.clone(),
            closed_by,
        });
    }
    for interval in &material.historical_intervals {
        verify_original_operation(&interval.grant, suite, observed_at, resolver)?;
        verify_basis_originals(
            &interval.round,
            &interval.round_events,
            suite,
            observed_at,
            resolver,
        )?;
        if let Some(close) = &interval.closed_by {
            verify_original_operation(close, suite, observed_at, resolver)?;
        }
    }
    let direction = proof
        .contact_round_id
        .as_ref()
        .map(|round| VerifiedContactDirection {
            issuer: expected_holder.clone(),
            peer: expected_peer.clone(),
            round: round.clone(),
            head: proof.head_event_ref.clone(),
            current_from: proof.issued_at,
            cache_expires_at: proof.cache_expires_at,
            intervals,
        });
    Ok(VerifiedContactCurrentMaterial {
        material: material.clone(),
        direction,
        closure,
    })
}

fn verify_source_signature_at(
    expected_source: &DidCoreId,
    signature: &ProtocolSignature,
    bytes: &[u8],
    effective_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<()> {
    let did = arkret_identity::verification_method_did(signature.verification_method.as_str())
        .map_err(invalid)?;
    if arkret_wire::project_did_to_core_id(&did).map_err(invalid)? != *expected_source {
        return Err(invalid("signature controller is not the issuer's Station"));
    }
    let history = resolver
        .resolve_complete_history(&did)
        .map_err(|error| ContactAuthorizationError::MissingMaterial(error.to_string()))?;
    if history.did != did {
        return Err(invalid(
            "source history does not bind the exact historical DID",
        ));
    }
    if history.method != DidMethodUri::Webvh || did.method() != "webvh" {
        return Err(ContactAuthorizationError::MissingMaterial(
            "authenticated historical verifier for this DID method is unavailable".to_owned(),
        ));
    }
    if history.native_history == Some(false)
        || history.entries.is_empty()
        || history.has_more
        || history.next_cursor.is_some()
    {
        return Err(ContactAuthorizationError::MissingMaterial(
            "source method history is incomplete".to_owned(),
        ));
    }
    let point =
        arkret_signatures::webvh::validate_webvh_history_at(&did, &history.entries, effective_at)
            .map_err(invalid)?;
    let document: DidDocument = serde_json::from_value(point.document).map_err(invalid)?;
    arkret_identity::validate_verification_method_relationship(
        &document,
        &signature.verification_method,
        &did,
        DidVerificationRelationship::AssertionMethod,
    )
    .map_err(invalid)?;
    let key = arkret_identity::resolve_verification_method_key_from_document(
        &document,
        signature.verification_method.as_str(),
    )
    .map_err(invalid)?;
    arkret_signatures::Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(&signature.jws, bytes, &key.public_key)
        .map_err(|_| invalid("source signature is invalid"))?;
    Ok(())
}

#[cfg(test)]
mod tests;

/// Full current founding evidence, separate from ordinary message publication.
pub fn verify_contact_founding_bundle(
    bundle: &ContactRoundEvidenceBundle,
    domain: &arkret_wire::TrustDomainId,
    suite: DigestSuite,
    observed_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<[VerifiedContactDirection; 2]> {
    bundle.validate_shape().map_err(invalid)?;
    let mut directions = Vec::new();
    for proof in &bundle.current_proofs {
        let head = bundle
            .current_operations
            .iter()
            .find(|op| op.holder() == &proof.holder)
            .ok_or_else(|| invalid("founding original head missing"))?;
        let material = ContactCurrentMaterial {
            initial_identity: Some(bundle.initial_identity.clone()),
            round_evidence: Some(bundle.basis()),
            round_events: Some(bundle.round_events.clone()),
            head_operation: head.clone(),
            scope_grants: bundle
                .scope_grants
                .iter()
                .filter(|op| op.holder() == &proof.holder)
                .cloned()
                .collect(),
            historical_intervals: vec![],
            current_proof: proof.clone(),
        };
        let verified = verify_contact_current_material(
            &material,
            &proof.holder,
            &proof.peer,
            domain,
            suite,
            observed_at,
            resolver,
        )?;
        let direction = verified
            .direction
            .ok_or_else(|| invalid("founding Contact round not established"))?;
        direction.require_current_at(observed_at)?;
        if direction
            .open_interval(ContactScope::DirectMessage)
            .is_none()
        {
            return Err(invalid(
                "founding requires both exact direct_message instances",
            ));
        }
        directions.push(direction);
    }
    directions
        .try_into()
        .map_err(|_| invalid("founding requires exactly two directions"))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_contact_current_material(
    material: &ContactCurrentMaterial,
    holder: &ContactPeer,
    peer: &ContactPeer,
    domain: &arkret_wire::TrustDomainId,
    suite: DigestSuite,
    observed_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<VerifiedContactCurrentMaterial> {
    verify_current_material_inner(
        material,
        holder,
        peer,
        domain,
        suite,
        observed_at,
        resolver,
        false,
    )
}
/// Authenticate exact response ownership and its complete historical boundaries.
pub fn verify_contact_current_refresh_response(
    request: &PeerContactSubmitRequestBody,
    outcome: &arkret_models_collaboration::contact_operations::PeerContactSubmitResponseBody,
    suite: DigestSuite,
    observed_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<VerifiedContactCurrentMaterial> {
    use arkret_models_collaboration::contact_operations::{
        PeerContactAdmissionAttemptOutcome, PeerContactControlKind,
        PeerContactControlSubmitResponseBody, PeerContactSubmitResponseBody,
        peer_contact_control_result_digest,
    };
    let PeerContactSubmitRequestBody::CurrentRefresh {
        requester,
        trust_domain_id,
        initial_contact_round_id,
        known_version,
        grant_event_refs,
        contact_address,
        ..
    } = request
    else {
        return Err(invalid("not current_refresh"));
    };
    let PeerContactSubmitResponseBody::Control(
        PeerContactControlSubmitResponseBody::CurrentRefresh {
            status,
            control_receipt,
            material,
        },
    ) = outcome
    else {
        return Err(ContactAuthorizationError::NotCurrent);
    };
    if arkret_canonical::canonical_json_bytes(request)
        .map_err(invalid)?
        .len()
        > 2 * 1024 * 1024
        || arkret_canonical::canonical_json_bytes(outcome)
            .map_err(invalid)?
            .len()
            > 2 * 1024 * 1024
        || grant_event_refs.len() > 5
        || *known_version > 9_007_199_254_740_991
    {
        return Err(invalid("current recovery exceeds contract budget"));
    }
    let request_digest = Hash::new(arkret_canonical::canonical_sha256(request).map_err(invalid)?)
        .map_err(invalid)?;
    let proof = &material.current_proof;
    let expected_digest = peer_contact_control_result_digest(
        &request_digest,
        PeerContactControlKind::CurrentRefresh,
        None,
        None,
        Some(material),
    )
    .map_err(invalid)?;
    if !matches!(
        status,
        PeerContactAdmissionAttemptOutcome::Accepted
            | PeerContactAdmissionAttemptOutcome::Duplicate
    ) || control_receipt.outcome != *status
        || control_receipt.request_kind != PeerContactControlKind::CurrentRefresh
        || control_receipt.request_digest != request_digest
        || control_receipt.control_material_digest.as_ref() != Some(&expected_digest)
        || control_receipt.issuer_id != *contact_address.recipient.delivery_station_id()
        || control_receipt.recipient_id != control_receipt.issuer_id
        || control_receipt.received_at > observed_at
        || proof.version < *known_version
        || initial_contact_round_id
            .as_ref()
            .is_some_and(|root| Some(root) != proof.initial_contact_round_id.as_ref())
        || material
            .historical_intervals
            .iter()
            .any(|i| !grant_event_refs.contains(&i.grant.event().event_id))
        || grant_event_refs.iter().any(|grant| {
            !material
                .historical_intervals
                .iter()
                .any(|i| &i.grant.event().event_id == grant)
        })
    {
        return Err(invalid(
            "current control response differs from exact request/result/direction",
        ));
    }
    verify_source_signature_at(
        &control_receipt.issuer_id,
        &control_receipt.signature,
        &control_receipt.canonical_signing_bytes().map_err(invalid)?,
        control_receipt.received_at,
        resolver,
    )?;
    verify_current_material_inner(
        material,
        &contact_address.recipient,
        requester,
        trust_domain_id,
        suite,
        observed_at,
        resolver,
        true,
    )
}

pub fn verify_contact_round_closure(
    closure: &arkret_models_collaboration::contact_operations::ContactRoundClosure,
    holder: &ContactPeer,
    peer: &ContactPeer,
    domain: &arkret_wire::TrustDomainId,
    observed_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<VerifiedContactTerminalFence> {
    verify_round_closure(closure, holder, peer, domain, observed_at, resolver)
}
