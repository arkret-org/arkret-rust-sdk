//! Authenticated Contact directional history and continuous scope intervals.
//!
//! This module authenticates original Contact carriers, exact bilateral round
//! origins and complete directional history at an actual observation. Source
//! confirmation and holder signatures are separate evidence. Consumers still
//! evaluate predecessor-round continuity and ordinary-history closures before
//! publication; this adapter does not grant runtime or session capabilities.

use std::collections::BTreeSet;

use arkret_canonical::DigestSuite;
use arkret_identity::{AuthorityDidHistoryResolver, DidVerificationRelationship};
use arkret_models_collaboration::contact_operations::{
    ContactCurrentProof, ContactPeer, ContactProducerSigner, ContactRound,
    ContactRoundEvidenceBundle, ContactScope, ContactScopeUpdatePayload,
    PeerContactSubmitRequestBody, RequestAcceptanceReceipt,
};
use arkret_models_collaboration::events_payloads::contact::{
    ContactAcceptedPayload, ContactRejectedPayload, ContactRequestedPayload,
    ContactTombstonedPayload,
};
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

const CONTACT_ROUND_DOMAIN: &[u8] = b"ak.contact.round.v1\n";

fn compute_contact_round_id(round: &ContactRound) -> Result<Hash> {
    round.validate_canonical_order().map_err(invalid)?;
    let canonical = arkret_canonical::canonical_json_bytes(round).map_err(invalid)?;
    let mut transcript = Vec::with_capacity(CONTACT_ROUND_DOMAIN.len() + canonical.len());
    transcript.extend_from_slice(CONTACT_ROUND_DOMAIN);
    transcript.extend_from_slice(&canonical);
    Hash::new(arkret_canonical::sha256_digest(transcript)).map_err(invalid)
}

/// An exact open interval, or its authenticated closing transition. Fields are
/// immutable and instances are produced only from verified source evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContactScopeInterval {
    scope: ContactScope,
    authorization_event_id: EventId,
    generation_event_id: EventId,
    closed_by: Option<EventId>,
}
impl ContactScopeInterval {
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
    fresh_until: DateTime<Utc>,
    intervals: Vec<ContactScopeInterval>,
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
    pub fn intervals(&self) -> &[ContactScopeInterval] {
        &self.intervals
    }
    /// Scope still open in the authenticated source history. This has no TTL
    /// check: freshness is not revocation. Later verified narrowing/terminal
    /// evidence and ordinary-history cuts must independently fence publication.
    pub fn open_interval(&self, scope: ContactScope) -> Option<&ContactScopeInterval> {
        self.intervals
            .iter()
            .find(|interval| interval.scope == scope && interval.closed_by.is_none())
    }
    /// Required by current Contact mutations and Direct Conversation founding.
    pub fn require_current_at(&self, at: DateTime<Utc>) -> Result<()> {
        if at < self.current_from || at >= self.fresh_until {
            return Err(ContactAuthorizationError::NotCurrent);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct ContactTransition {
    contact_round_id: Hash,
    issuer: ContactPeer,
    peer: ContactPeer,
    version: u64,
    predecessor_event_ref: Option<EventId>,
    event_ref: EventId,
    granted_to_peer_scopes: Vec<ContactScope>,
    terminal: Option<bool>,
}

/// Exact original carrier with independent producer and source authentication.
/// This is evidence of a confirmed Contact command, not a current grant or a
/// complete round. Only the complete-history verifier derives scope intervals.
#[derive(Clone, Debug)]
pub struct VerifiedContactEvent {
    carrier: PeerContactSubmitRequestBody,
    holder: ContactPeer,
    peer: ContactPeer,
    event_id: EventId,
    kind: EventKind,
    observed_at: DateTime<Utc>,
    transition: Option<ContactTransition>,
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
        self.transition
            .as_ref()
            .filter(|t| t.terminal == Some(true))
            .map(|t| VerifiedContactTerminalFence {
                round: t.contact_round_id.clone(),
                holder: self.holder.clone(),
                peer: self.peer.clone(),
                event_id: self.event_id.clone(),
            })
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
    pub fn event_id(&self) -> &EventId {
        &self.event_id
    }
    pub fn contact_round_id(&self) -> &Hash {
        &self.round
    }
}

/// Authenticated initial transitions for both exact participants. It retains
/// the real request/response origins; no synthetic signed lineage is created.
#[derive(Clone, Debug)]
pub struct VerifiedContactRound {
    round: Hash,
    origins: [ContactTransition; 2],
    origin_checkpoints: Vec<ContactCurrentProof>,
}
impl VerifiedContactRound {
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
        || actor.route_service_id() != &controller.station_id
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
            .proofs
            .first()
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
    let point = arkret_signatures::webvh::validate_webvh_history_at(
        &did,
        &history.entries,
        event.created_at,
    )
    .map_err(invalid)?;
    arkret_signatures::webvh::validate_agent_did_document_profile(
        did.as_str(),
        &point.document,
        &[],
    )
    .map_err(invalid)?;
    // The complete native chain was authenticated above. Later binding changes
    // affect new authorization, not the historical identity of this Event.
    // Exact eligibility at command confirmation is the independently signed
    // source projection's responsibility; created_at is not live authority.
    let historical_end = history
        .entries
        .iter()
        .position(|entry| {
            entry.get("versionId").and_then(serde_json::Value::as_str)
                == Some(point.version_id.as_str())
        })
        .ok_or_else(|| invalid("verified Agent history point is absent from its chain"))?;
    let historical_entries = &history.entries[..=historical_end];
    let inception_delegation = historical_entries[0].pointer("/state/service/1");
    let initial_binding = historical_entries
        .get(1)
        .and_then(|e| e.pointer("/state/service/2/serviceEndpoint"));
    if historical_entries[0].pointer("/state/service/2").is_some() || initial_binding.is_none() {
        return Err(invalid("Agent binding must first appear in entry one"));
    }
    for (index, entry) in historical_entries.iter().enumerate() {
        let document = entry
            .get("state")
            .ok_or_else(|| invalid("Agent history entry has no document"))?;
        arkret_signatures::webvh::validate_agent_did_document_profile(did.as_str(), document, &[])
            .map_err(invalid)?;
        if entry.pointer("/state/service/1") != inception_delegation
            || (index > 0 && entry.pointer("/state/service/2/serviceEndpoint") != initial_binding)
        {
            return Err(invalid(
                "Agent history rewrites its create-locked delegation or PCR tuple",
            ));
        }
    }
    let services = point
        .document
        .get("service")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid("verified Agent document has no services"))?;
    let binding = services
        .get(2)
        .and_then(|s| s.get("serviceEndpoint"))
        .ok_or_else(|| {
            ContactAuthorizationError::MissingMaterial(
                "Agent PCR binding is absent at publication".into(),
            )
        })?;
    if binding.get("realm_id").and_then(serde_json::Value::as_str) != Some(event.realm_id.as_str())
        || binding
            .get("controller_did")
            .and_then(serde_json::Value::as_str)
            != Some(controller.principal_id.as_str())
        || event.scope_ref
            != (arkret_wire::ScopeRef::Realm {
                realm_id: event.realm_id.clone(),
            })
    {
        return Err(invalid(
            "Contact management exceeds the accepted Agent PCR delegation",
        ));
    }
    if event.executed_by.is_some() {
        let reference = event
            .authorization_ref
            .as_ref()
            .ok_or_else(|| invalid("controller Contact Event omits its authorization source"))?;
        if arkret_wire::DidUrl::new(reference.as_str()).is_ok()
            && binding
                .get("authorization_ref")
                .and_then(serde_json::Value::as_str)
                != Some(reference.as_str())
        {
            return Err(invalid(
                "controller DID delegation differs from the locked Agent binding",
            ));
        }
        if arkret_wire::DidUrl::new(reference.as_str()).is_err()
            && arkret_wire::GrantId::new(reference.as_str()).is_err()
            && EventId::new(reference.as_str()).is_err()
        {
            return Err(invalid(
                "controller authorization is not the accepted delegation or a materialized grant",
            ));
        }
    }
    // Source confirmation attests the exact command's internal authorization.
    // Private key/grant/scope histories do not cross this Contact boundary.
    Ok(())
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
    let [proof] = event.proofs.as_slice() else {
        return Err(invalid("Contact requires exactly one producer proof"));
    };
    proof.validate_production().map_err(invalid)?;
    if proof.created_at != event.created_at
        || &proof.verification_method != signer.verification_method()
    {
        return Err(invalid(
            "producer method or time differs from the source-authenticated exact Event",
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

fn verify_checkpoint_identity(
    checkpoint: &ContactCurrentProof,
    holder: &ContactPeer,
    peer: &ContactPeer,
    round: &Hash,
    observed_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<()> {
    if checkpoint.issuer_id != *holder.delivery_station_id()
        || checkpoint.peer != *peer
        || checkpoint.contact_round_id != *round
        || checkpoint.complete_through == 0
        || !checkpoint
            .accepted_commit_event_ids
            .contains(&checkpoint.head_event_ref)
        || checkpoint.signature.created_at > observed_at
        || checkpoint.fresh_until <= checkpoint.signature.created_at
        || checkpoint
            .accepted_commit_event_ids
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != checkpoint.accepted_commit_event_ids.len()
    {
        return Err(invalid(
            "current proof does not bind the exact direction and certified commit checkpoint",
        ));
    }
    verify_source_signature(
        holder.delivery_station_id(),
        &checkpoint.signature,
        &checkpoint.canonical_signing_bytes().map_err(invalid)?,
        resolver,
    )
}

/// Authenticate all five original signed-Event carriers using the producer key
/// covered by their source receipt/lineage. A delegated Agent locator is taken
/// only from that authenticated source projection. Its complete native history
/// and exact principal/controller/Station binding are independently verified.
/// An optional or expired
/// current proof never becomes current authority here. A later head requires
/// its complete exact predecessor chain in verify_contact_direction_history.
pub fn authenticate_contact_event_carrier(
    carrier: &PeerContactSubmitRequestBody,
    expected_holder: &ContactPeer,
    suite: DigestSuite,
    observed_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<VerifiedContactEvent> {
    let (event, kind) = match carrier {
        PeerContactSubmitRequestBody::Request { signed_event, .. } => {
            (signed_event, EventKind::ContactRequested)
        }
        PeerContactSubmitRequestBody::Response { signed_event, .. } => {
            (signed_event, EventKind::ContactAccepted)
        }
        PeerContactSubmitRequestBody::Reject { signed_event, .. } => {
            (signed_event, EventKind::ContactRejected)
        }
        PeerContactSubmitRequestBody::ScopeUpdate { signed_event, .. } => {
            (signed_event, EventKind::ContactScopeUpdate)
        }
        PeerContactSubmitRequestBody::Tombstone { signed_event, .. } => {
            (signed_event, EventKind::ContactTombstone)
        }
        _ => return Err(invalid("this carrier contains no Contact command Event")),
    };
    if event.kind != kind || event.created_at > observed_at {
        return Err(invalid(
            "carrier kind or observation conflicts with its Event",
        ));
    }
    let (peer, transition) = match carrier {
        PeerContactSubmitRequestBody::Request {
            request_receipt,
            current_proof,
            introduction_evidence,
            ..
        } => {
            let p: ContactRequestedPayload = payload(event)?;
            let mut introduction_bytes = b"ak.contact.introduction-evidence.v1\n".to_vec();
            introduction_bytes.extend(
                arkret_canonical::canonical_json_bytes(introduction_evidence).map_err(invalid)?,
            );
            if Hash::new(arkret_canonical::sha256_digest(introduction_bytes)).map_err(invalid)?
                != p.introduction_evidence_digest
            {
                return Err(invalid(
                    "request introduction evidence differs from the signed payload digest",
                ));
            }
            verify_request_receipt(request_receipt, resolver)?;
            if request_receipt.core.holder != *expected_holder
                || request_receipt.core.peer != p.peer
                || request_receipt.core.request_event_ref != event.event_id
                || request_receipt.core.previous_terminal_contact_round_id
                    != p.previous_terminal_contact_round_id
                || request_receipt.core.accepted_at < event.created_at
                || request_receipt.core.accepted_at > observed_at
                || request_receipt.signature.created_at > observed_at
            {
                return Err(invalid(
                    "request receipt does not bind the exact Event and participants",
                ));
            }
            if let Some(proof) = current_proof {
                verify_checkpoint_identity(
                    proof,
                    expected_holder,
                    &p.peer,
                    &proof.contact_round_id,
                    observed_at,
                    resolver,
                )?;
            }
            (p.peer, None)
        }
        PeerContactSubmitRequestBody::Response {
            response_receipt,
            current_proof,
            ..
        } => {
            let p: ContactAcceptedPayload = payload(event)?;
            verify_request_receipt(&response_receipt.request_receipt, resolver)?;
            if response_receipt.response_event_ref != event.event_id
                || response_receipt.issuer_id != *expected_holder.delivery_station_id()
                || response_receipt.contact_round_id != p.contact_round_id
                || p.version != 1
                || response_receipt.request_receipt.core.holder != p.peer
                || response_receipt.request_receipt.core.peer != *expected_holder
                || response_receipt.request_receipt.core.request_event_ref != p.request_event_ref
                || response_receipt
                    .request_receipt
                    .computed_receipt_digest()
                    .map_err(invalid)?
                    != p.request_acceptance_receipt_digest
                || response_receipt
                    .request_receipt
                    .core
                    .previous_terminal_contact_round_id
                    != p.previous_terminal_contact_round_id
                || response_receipt.accepted_at < event.created_at
                || response_receipt.accepted_at > observed_at
                || response_receipt.signature.created_at > observed_at
            {
                return Err(invalid(
                    "response receipt does not bind the exact acceptance and request",
                ));
            }
            verify_source_signature_at(
                expected_holder.delivery_station_id(),
                &response_receipt.signature,
                &response_receipt
                    .canonical_signing_bytes()
                    .map_err(invalid)?,
                response_receipt.accepted_at,
                resolver,
            )?;
            if let Some(proof) = current_proof {
                verify_checkpoint_identity(
                    proof,
                    expected_holder,
                    &p.peer,
                    &p.contact_round_id,
                    observed_at,
                    resolver,
                )?;
            }
            let transition = ContactTransition {
                contact_round_id: p.contact_round_id,
                issuer: expected_holder.clone(),
                peer: p.peer.clone(),
                version: 1,
                predecessor_event_ref: None,
                event_ref: event.event_id.clone(),
                granted_to_peer_scopes: p.granted_to_peer_scopes,
                terminal: None,
            };
            (p.peer, Some(transition))
        }
        PeerContactSubmitRequestBody::Reject { reject_receipt, .. } => {
            let p: ContactRejectedPayload = payload(event)?;
            verify_request_receipt(&reject_receipt.request_receipt, resolver)?;
            if reject_receipt.reject_event_ref != event.event_id
                || reject_receipt.issuer_id != *expected_holder.delivery_station_id()
                || reject_receipt.request_receipt.core.holder != p.peer
                || reject_receipt.request_receipt.core.peer != *expected_holder
                || reject_receipt.request_receipt.core.request_event_ref != p.request_event_ref
                || reject_receipt
                    .request_receipt
                    .computed_receipt_digest()
                    .map_err(invalid)?
                    != p.request_acceptance_receipt_digest
                || reject_receipt.accepted_at < event.created_at
                || reject_receipt.accepted_at > observed_at
                || reject_receipt.signature.created_at > observed_at
            {
                return Err(invalid(
                    "reject receipt does not bind the exact rejection and request",
                ));
            }
            verify_source_signature_at(
                expected_holder.delivery_station_id(),
                &reject_receipt.signature,
                &reject_receipt.canonical_signing_bytes().map_err(invalid)?,
                reject_receipt.accepted_at,
                resolver,
            )?;
            (p.peer, None)
        }
        PeerContactSubmitRequestBody::ScopeUpdate {
            lineage,
            current_proof,
            ..
        }
        | PeerContactSubmitRequestBody::Tombstone {
            lineage,
            current_proof,
            ..
        } => {
            let (peer, round, version, predecessor, scopes, terminal) =
                if kind == EventKind::ContactScopeUpdate {
                    let p: ContactScopeUpdatePayload = payload(event)?;
                    (
                        p.peer,
                        p.contact_round_id,
                        p.version,
                        p.predecessor_event_ref,
                        p.granted_to_peer_scopes,
                        false,
                    )
                } else {
                    let p: ContactTombstonedPayload = payload(event)?;
                    (
                        p.peer,
                        p.contact_round_id,
                        p.version,
                        p.predecessor_event_ref,
                        Vec::new(),
                        true,
                    )
                };
            if version < 2
                || lineage.issuer != *expected_holder
                || lineage.peer != peer
                || lineage.contact_round_id != round
                || lineage.version != version
                || lineage.event_ref != event.event_id
                || lineage.predecessor_event_ref.as_ref() != Some(&predecessor)
                || lineage.granted_to_peer_scopes != scopes
                || (lineage.terminal == Some(true)) != terminal
                || lineage.signature.created_at < event.created_at
                || lineage.signature.created_at > observed_at
            {
                return Err(invalid(
                    "signed lineage differs from its exact producer Event",
                ));
            }
            verify_source_signature(
                expected_holder.delivery_station_id(),
                &lineage.signature,
                &lineage.canonical_signing_bytes().map_err(invalid)?,
                resolver,
            )?;
            verify_checkpoint_identity(
                current_proof,
                expected_holder,
                &peer,
                &round,
                observed_at,
                resolver,
            )?;
            (
                peer.clone(),
                Some(ContactTransition {
                    contact_round_id: round,
                    issuer: expected_holder.clone(),
                    peer,
                    version,
                    predecessor_event_ref: Some(predecessor),
                    event_ref: event.event_id.clone(),
                    granted_to_peer_scopes: scopes,
                    terminal: terminal.then_some(true),
                }),
            )
        }
        _ => unreachable!(),
    };
    let producer_signer = match carrier {
        PeerContactSubmitRequestBody::Request {
            request_receipt, ..
        } => &request_receipt.core.producer_signer,
        PeerContactSubmitRequestBody::Response {
            response_receipt, ..
        } => &response_receipt.producer_signer,
        PeerContactSubmitRequestBody::Reject { reject_receipt, .. } => {
            &reject_receipt.producer_signer
        }
        PeerContactSubmitRequestBody::ScopeUpdate { lineage, .. }
        | PeerContactSubmitRequestBody::Tombstone { lineage, .. } => &lineage.producer_signer,
        _ => unreachable!(),
    };
    verify_holder(event, expected_holder, producer_signer, suite)?;
    verify_agent_holder_binding(
        event,
        expected_holder,
        producer_signer.delegated_actor_did(),
        resolver,
    )?;
    let address = match carrier {
        PeerContactSubmitRequestBody::Request {
            contact_address, ..
        }
        | PeerContactSubmitRequestBody::Response {
            contact_address, ..
        }
        | PeerContactSubmitRequestBody::Reject {
            contact_address, ..
        }
        | PeerContactSubmitRequestBody::ScopeUpdate {
            contact_address, ..
        }
        | PeerContactSubmitRequestBody::Tombstone {
            contact_address, ..
        } => contact_address,
        _ => unreachable!(),
    };
    if address.recipient != peer {
        return Err(invalid("carrier address names a different Contact peer"));
    }
    address.validate_shape().map_err(invalid)?;
    if expected_holder.contact_actor_id() == peer.contact_actor_id() {
        return Err(invalid("Contact participants must be distinct"));
    }
    Ok(VerifiedContactEvent {
        carrier: carrier.clone(),
        holder: expected_holder.clone(),
        peer,
        event_id: event.event_id.clone(),
        kind,
        observed_at,
        transition,
    })
}

fn exact_request<'a>(
    events: &'a [VerifiedContactEvent],
    receipt: &RequestAcceptanceReceipt,
) -> Result<&'a VerifiedContactEvent> {
    let mut matches = events
        .iter()
        .filter(|e| e.event_id == receipt.core.request_event_ref);
    let event = matches.next().ok_or_else(|| {
        ContactAuthorizationError::MissingMaterial(
            "round origin request producer evidence is absent".into(),
        )
    })?;
    if matches.next().is_some() {
        return Err(invalid("duplicate round origin Event"));
    }
    let PeerContactSubmitRequestBody::Request {
        request_receipt, ..
    } = &event.carrier
    else {
        return Err(invalid("round origin is not a request"));
    };
    if request_receipt != receipt {
        return Err(invalid("round references different request receipt bytes"));
    }
    Ok(event)
}
fn request_transition(event: &VerifiedContactEvent, round: &Hash) -> Result<ContactTransition> {
    let PeerContactSubmitRequestBody::Request { signed_event, .. } = &event.carrier else {
        return Err(invalid("initial grant is not a request"));
    };
    let p: ContactRequestedPayload = payload(signed_event)?;
    Ok(ContactTransition {
        contact_round_id: round.clone(),
        issuer: event.holder.clone(),
        peer: event.peer.clone(),
        version: 1,
        predecessor_event_ref: None,
        event_ref: event.event_id.clone(),
        granted_to_peer_scopes: p.granted_to_peer_scopes,
        terminal: None,
    })
}

/// Establish both initial grant origins from exact authenticated Events and
/// source receipts. Glare is a two-request round and never an invented accept.
/// This validates round identity, not predecessor-round continuity or current
/// ordinary publication eligibility.
pub fn verify_contact_round_origins(
    bundle: &ContactRoundEvidenceBundle,
    events: &[VerifiedContactEvent],
    observed_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<VerifiedContactRound> {
    if events.iter().any(|e| e.observed_at > observed_at) {
        return Err(invalid("round evidence predates its producer observation"));
    }
    let round = compute_contact_round_id(&bundle.contact_round)?;
    if round != bundle.contact_round_id {
        return Err(invalid("round id differs from its canonical core"));
    }
    let origins = match &bundle.contact_round {
        ContactRound::Normal {
            request_event_ref,
            request_acceptance_receipt_digest,
            ..
        } => {
            let [receipt] = bundle.request_receipts.as_slice() else {
                return Err(invalid("normal round requires exactly one request"));
            };
            let response = bundle.normal_response_receipt.as_ref().ok_or_else(|| {
                ContactAuthorizationError::MissingMaterial(
                    "normal response receipt is absent".into(),
                )
            })?;
            if bundle.glare_concurrency_attestations.is_some()
                || receipt.core.request_event_ref != *request_event_ref
                || receipt.computed_receipt_digest().map_err(invalid)?
                    != *request_acceptance_receipt_digest
                || response.request_receipt != *receipt
                || response.contact_round_id != round
            {
                return Err(invalid("normal round receipt binding is inconsistent"));
            }
            let request = exact_request(events, receipt)?;
            let mut matches = events
                .iter()
                .filter(|e| e.event_id == response.response_event_ref);
            let accept = matches.next().ok_or_else(|| {
                ContactAuthorizationError::MissingMaterial(
                    "normal accept producer evidence is absent".into(),
                )
            })?;
            if matches.next().is_some() {
                return Err(invalid("duplicate normal accept evidence"));
            }
            let PeerContactSubmitRequestBody::Response {
                response_receipt, ..
            } = &accept.carrier
            else {
                return Err(invalid("normal response is not an accept"));
            };
            if response_receipt != response
                || accept.holder != request.peer
                || accept.peer != request.holder
            {
                return Err(invalid(
                    "normal acceptance does not reverse the exact request direction",
                ));
            }
            [
                request_transition(request, &round)?,
                accept
                    .transition
                    .clone()
                    .ok_or_else(|| invalid("normal acceptance has no initial transition"))?,
            ]
        }
        ContactRound::Glare { requests, .. } => {
            let [first, second] = bundle.request_receipts.as_slice() else {
                return Err(invalid("glare requires exactly two request receipts"));
            };
            let attestations = bundle
                .glare_concurrency_attestations
                .as_ref()
                .ok_or_else(|| {
                    ContactAuthorizationError::MissingMaterial(
                        "glare concurrency attestations are absent".into(),
                    )
                })?;
            if bundle.normal_response_receipt.is_some() {
                return Err(invalid("glare cannot carry a normal response"));
            }
            let expected = requests
                .iter()
                .map(|r| {
                    (
                        r.request_event_ref.clone(),
                        r.request_acceptance_receipt_digest.clone(),
                    )
                })
                .collect::<BTreeSet<_>>();
            let actual = [first, second]
                .into_iter()
                .map(|r| {
                    Ok((
                        r.core.request_event_ref.clone(),
                        r.computed_receipt_digest().map_err(invalid)?,
                    ))
                })
                .collect::<Result<BTreeSet<_>>>()?;
            if expected != actual {
                return Err(invalid(
                    "glare core does not bind both exact signed receipts",
                ));
            }
            let a = exact_request(events, first)?;
            let b = exact_request(events, second)?;
            if a.holder != b.peer || a.peer != b.holder {
                return Err(invalid(
                    "glare requests do not cover the reverse exact pair",
                ));
            }
            let digests = actual
                .iter()
                .map(|(_, digest)| digest.clone())
                .collect::<BTreeSet<_>>();
            let mut subjects = BTreeSet::new();
            for attestation in attestations {
                let origin = [a, b]
                    .into_iter()
                    .find(|e| e.holder.contact_actor_id() == attestation.subject_id)
                    .ok_or_else(|| invalid("glare attestation subject is outside the round"))?;
                if attestation.peer_id != origin.peer.contact_actor_id()
                    || attestation.issuer_id != *origin.holder.delivery_station_id()
                    || !subjects.insert(attestation.subject_id.clone())
                    || attestation.complete_through == 0
                    || attestation
                        .request_receipt_digests
                        .iter()
                        .cloned()
                        .collect::<BTreeSet<_>>()
                        != digests
                    || ![a, b]
                        .into_iter()
                        .all(|e| attestation.observed_commit_event_ids.contains(&e.event_id))
                    || attestation.observed_at > observed_at
                    || attestation.signature.created_at > observed_at
                {
                    return Err(invalid(
                        "glare attestation does not bind both concurrent request origins",
                    ));
                }
                verify_source_signature_at(
                    origin.holder.delivery_station_id(),
                    &attestation.signature,
                    &attestation.canonical_signing_bytes().map_err(invalid)?,
                    attestation.observed_at,
                    resolver,
                )?;
            }
            [
                request_transition(a, &round)?,
                request_transition(b, &round)?,
            ]
        }
    };
    let pair = match &bundle.contact_round {
        ContactRound::Normal {
            sorted_pair_member_ids,
            ..
        }
        | ContactRound::Glare {
            sorted_pair_member_ids,
            ..
        } => sorted_pair_member_ids,
    };
    if origins
        .iter()
        .map(|t| t.issuer.contact_actor_id())
        .collect::<BTreeSet<_>>()
        != pair.iter().cloned().collect()
        || origins.iter().any(|t| t.contact_round_id != round)
        || bundle.request_receipts.iter().any(|r| {
            r.core.previous_terminal_contact_round_id != bundle.previous_terminal_contact_round_id
        })
    {
        return Err(invalid(
            "round origins differ from the canonical pair or predecessor round",
        ));
    }
    if bundle.current_proofs.len() != 2 {
        return Err(ContactAuthorizationError::MissingMaterial(
            "round requires both directional current proofs".into(),
        ));
    }
    let mut directions = BTreeSet::new();
    for proof in &bundle.current_proofs {
        let origin = origins
            .iter()
            .find(|t| t.peer == proof.peer)
            .ok_or_else(|| invalid("round current proof belongs to another pair"))?;
        if !directions.insert(origin.issuer.contact_actor_id()) {
            return Err(invalid("duplicate round current proof direction"));
        }
        verify_checkpoint_identity(
            proof,
            &origin.issuer,
            &origin.peer,
            &round,
            observed_at,
            resolver,
        )?;
    }
    let origin_checkpoints = events
        .iter()
        .filter(|e| origins.iter().any(|o| o.event_ref == e.event_id))
        .filter_map(carrier_checkpoint)
        .cloned()
        .chain(bundle.current_proofs.iter().cloned())
        .collect();
    Ok(VerifiedContactRound {
        round,
        origins,
        origin_checkpoints,
    })
}

fn carrier_checkpoint(event: &VerifiedContactEvent) -> Option<&ContactCurrentProof> {
    match &event.carrier {
        PeerContactSubmitRequestBody::Request { current_proof, .. }
        | PeerContactSubmitRequestBody::Response { current_proof, .. } => current_proof.as_ref(),
        PeerContactSubmitRequestBody::ScopeUpdate { current_proof, .. }
        | PeerContactSubmitRequestBody::Tombstone { current_proof, .. } => Some(current_proof),
        _ => None,
    }
}

/// Derive one complete direction from authenticated round origins and ordered
/// successor carriers. A carrier certified by a later head remains incomplete
/// until that exact successor chain is present, irrespective of numeric versions.
pub fn verify_contact_direction_history(
    round: &VerifiedContactRound,
    issuer: &ContactPeer,
    successors: &[VerifiedContactEvent],
    checkpoint: &ContactCurrentProof,
    observed_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
    terminal: Option<&VerifiedContactTerminalFence>,
) -> Result<VerifiedContactDirection> {
    let origin = round
        .origins
        .iter()
        .find(|t| &t.issuer == issuer)
        .ok_or_else(|| invalid("direction holder is not an authenticated round participant"))?;
    verify_checkpoint_identity(
        checkpoint,
        issuer,
        &origin.peer,
        &round.round,
        observed_at,
        resolver,
    )?;
    let mut transitions = vec![origin.clone()];
    for event in successors {
        let next = event
            .transition
            .as_ref()
            .ok_or_else(|| invalid("successor carrier has no directional transition"))?;
        if next.version < 2 {
            return Err(invalid("initial grant cannot be repeated as a successor"));
        }
        transitions.push(next.clone());
    }
    // The chain verifier below checks every link. This check also fences any
    // later checkpoint bundled with an earlier accepted carrier.
    if successors.iter().any(|e| e.observed_at > observed_at) {
        return Err(invalid("history predates its producer observation"));
    }
    for (proof, covered_version) in round
        .origin_checkpoints
        .iter()
        .filter(|p| p.peer == origin.peer)
        .map(|proof| (proof, 1))
        .chain(successors.iter().filter_map(|event| {
            carrier_checkpoint(event).map(|proof| {
                (
                    proof,
                    event
                        .transition
                        .as_ref()
                        .expect("successor transition checked above")
                        .version,
                )
            })
        }))
    {
        if proof.contact_round_id != round.round
            || proof.peer != origin.peer
            || proof.issuer_id != *issuer.delivery_station_id()
        {
            return Err(invalid("carrier current proof changes direction or round"));
        }
        let local = transitions
            .iter()
            .find(|t| t.event_ref == proof.head_event_ref);
        let remote_terminal =
            terminal.is_some_and(|f| f.event_id == proof.head_event_ref && proof.terminal);
        if local.is_none() && !remote_terminal {
            return Err(ContactAuthorizationError::MissingMaterial(
                "carrier certifies a later head whose exact predecessor chain is absent".into(),
            ));
        }
        if remote_terminal && local.is_none() {
            let local_version = transitions.last().expect("origin is present").version;
            if proof.complete_through > local_version {
                return Err(ContactAuthorizationError::MissingMaterial(
                    "terminal carrier certifies local versions whose predecessor chain is absent"
                        .into(),
                ));
            }
            if proof.complete_through != local_version {
                return Err(invalid(
                    "terminal carrier conflicts with the last complete local version",
                ));
            }
        }
        if proof.complete_through < covered_version {
            return Err(invalid(
                "carrier current proof precedes its own exact command",
            ));
        }
        if let Some(head) = local {
            if head.version != proof.complete_through
                || (head.terminal == Some(true)) != proof.terminal
            {
                return Err(invalid(
                    "carrier proof conflicts with its authenticated exact head",
                ));
            }
        }
    }
    verify_transition_history(
        issuer,
        &origin.peer,
        &round.round,
        &transitions,
        checkpoint,
        observed_at,
        resolver,
        terminal,
    )
}

/// Verify every source signature through complete authenticated method-native
/// DID history, including historical assertionMethod membership. The resolver
/// supplies raw history, never a caller-selected public key or allow result.
/// `observed_at` is the actual first observation, not an invented old timestamp.
/// A complete lineage starts at version one and ends at the signed checkpoint;
/// a latest-head-only projection cannot construct this verified value.
fn verify_transition_history(
    issuer: &ContactPeer,
    peer: &ContactPeer,
    contact_round_id: &Hash,
    lineages: &[ContactTransition],
    checkpoint: &ContactCurrentProof,
    observed_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
    terminal: Option<&VerifiedContactTerminalFence>,
) -> Result<VerifiedContactDirection> {
    if issuer.contact_actor_id() == peer.contact_actor_id() {
        return Err(invalid(
            "Contact direction requires two distinct participants",
        ));
    }
    if checkpoint.contact_round_id != *contact_round_id
        || checkpoint.peer != *peer
        || checkpoint.issuer_id != *issuer.delivery_station_id()
    {
        return Err(invalid(
            "checkpoint does not bind the expected issuer, peer and round",
        ));
    }
    verify_source_signature(
        issuer.delivery_station_id(),
        &checkpoint.signature,
        &checkpoint.canonical_signing_bytes().map_err(invalid)?,
        resolver,
    )?;
    if checkpoint.fresh_until <= checkpoint.signature.created_at {
        return Err(invalid("checkpoint freshness interval is empty"));
    }
    if observed_at < checkpoint.signature.created_at || observed_at >= checkpoint.fresh_until {
        return Err(ContactAuthorizationError::NotCurrent);
    }
    let Some(first) = lineages.first() else {
        return Err(ContactAuthorizationError::MissingMaterial(
            "directional lineage is absent".to_owned(),
        ));
    };
    let Some(last) = lineages.last() else {
        unreachable!()
    };
    if first.version == 0 || (first.version == 1 && first.predecessor_event_ref.is_some()) {
        return Err(invalid(
            "initial lineage has an invalid version or predecessor",
        ));
    }
    if first.version != 1 || last.version < checkpoint.complete_through {
        return Err(ContactAuthorizationError::MissingMaterial(
            "directional history does not span its initial grant through the certified head"
                .to_owned(),
        ));
    }
    if last.version != checkpoint.complete_through
        || !checkpoint
            .accepted_commit_event_ids
            .contains(&checkpoint.head_event_ref)
        || (last.event_ref != checkpoint.head_event_ref && terminal.is_none())
    {
        return Err(invalid(
            "directional history conflicts with its certified head",
        ));
    }
    let mut intervals = Vec::<ContactScopeInterval>::new();
    let mut seen = BTreeSet::new();
    for (index, lineage) in lineages.iter().enumerate() {
        if lineage.issuer != *issuer
            || lineage.peer != *peer
            || lineage.contact_round_id != *contact_round_id
        {
            return Err(invalid("lineage changes issuer, peer or round"));
        }
        if !seen.insert(lineage.event_ref.clone()) {
            return Err(invalid("lineage repeats an Event identity"));
        }
        if index > 0 {
            let previous = &lineages[index - 1];
            if lineage.version
                != previous
                    .version
                    .checked_add(1)
                    .ok_or_else(|| invalid("lineage version overflow"))?
            {
                return Err(ContactAuthorizationError::MissingMaterial(
                    "directional history skips a version".to_owned(),
                ));
            }
            if lineage.predecessor_event_ref.as_ref() != Some(&previous.event_ref) {
                return Err(invalid(
                    "lineage predecessor conflicts with the preceding exact Event",
                ));
            }
            if previous.terminal == Some(true) {
                return Err(invalid("terminal Contact lineage cannot be reopened"));
            }
        }
        let scopes = lineage
            .granted_to_peer_scopes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if scopes.len() != lineage.granted_to_peer_scopes.len() {
            return Err(invalid("scope set contains duplicates"));
        }
        for interval in &mut intervals {
            if interval.closed_by.is_none()
                && (lineage.terminal == Some(true) || !scopes.contains(&interval.scope))
            {
                interval.closed_by = Some(lineage.event_ref.clone());
            }
        }
        if lineage.terminal != Some(true) {
            for scope in scopes {
                if !intervals
                    .iter()
                    .any(|interval| interval.scope == scope && interval.closed_by.is_none())
                {
                    intervals.push(ContactScopeInterval {
                        scope,
                        authorization_event_id: first.event_ref.clone(),
                        generation_event_id: lineage.event_ref.clone(),
                        closed_by: None,
                    });
                }
            }
        }
    }
    if let Some(fence) = terminal {
        if fence.round != *contact_round_id
            || !((fence.holder == *issuer && fence.peer == *peer)
                || (fence.holder == *peer && fence.peer == *issuer))
            || !checkpoint.terminal
            || checkpoint.head_event_ref != fence.event_id
        {
            return Err(invalid(
                "terminal acknowledgement does not bind the verified round fence",
            ));
        }
        for interval in &mut intervals {
            if interval.closed_by.is_none() {
                interval.closed_by = Some(fence.event_id.clone());
            }
        }
    }
    if terminal.is_none() && checkpoint.terminal != (last.terminal == Some(true)) {
        return Err(invalid(
            "checkpoint terminal state disagrees with its exact head",
        ));
    }
    Ok(VerifiedContactDirection {
        issuer: issuer.clone(),
        peer: peer.clone(),
        round: contact_round_id.clone(),
        head: checkpoint.head_event_ref.clone(),
        current_from: checkpoint.signature.created_at,
        fresh_until: checkpoint.fresh_until,
        intervals,
    })
}

fn verify_source_signature(
    expected_source: &DidCoreId,
    signature: &ProtocolSignature,
    bytes: &[u8],
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<()> {
    verify_source_signature_at(
        expected_source,
        signature,
        bytes,
        signature.created_at,
        resolver,
    )
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
    if !arkret_signatures::proof::verify_detached_ed25519_signature(
        &key.public_key,
        bytes,
        signature.jws.as_str(),
    ) {
        return Err(invalid("source signature is invalid"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
