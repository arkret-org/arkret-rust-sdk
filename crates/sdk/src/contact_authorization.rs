//! Authenticated Contact directional history and continuous scope intervals.
//!
//! This module verifies one source's complete signed lineage at an actual
//! observation. It does not infer a bilateral round from a resolver summary,
//! locate the issuer's PCR, or decide an ordinary Event's full authorization.
//! Consumers must bind both directions to an authenticated round and evaluate
//! the applicable ordinary-history closures before publication.

use std::collections::BTreeSet;

use arkret_identity::{AuthorityDidHistoryResolver, DidVerificationRelationship};
use arkret_models_collaboration::contact_operations::{ContactCurrentProof, ContactLineage, ContactPeer, ContactScope};
use arkret_models_identity::{DidDocument, DidMethodUri};
use arkret_wire::{Did, DidCoreId, EventId, Hash, ProtocolSignature};
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
pub struct ContactScopeInterval {
    scope: ContactScope,
    authorization_event_id: EventId,
    generation_event_id: EventId,
    closed_by: Option<EventId>,
}
impl ContactScopeInterval {
    pub fn scope(&self) -> ContactScope { self.scope }
    pub fn authorization_event_id(&self) -> &EventId { &self.authorization_event_id }
    pub fn generation_event_id(&self) -> &EventId { &self.generation_event_id }
    pub fn closed_by(&self) -> Option<&EventId> { self.closed_by.as_ref() }
}

/// Non-serializable verified evidence. Persist original signed material and
/// authenticate it again on restore; do not deserialize a bare allow flag.
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
    pub fn issuer(&self) -> &ContactPeer { &self.issuer }
    pub fn peer(&self) -> &ContactPeer { &self.peer }
    pub fn contact_round_id(&self) -> &Hash { &self.round }
    pub fn head_event_id(&self) -> &EventId { &self.head }
    pub fn intervals(&self) -> &[ContactScopeInterval] { &self.intervals }
    /// Scope still open in the authenticated source history. This has no TTL
    /// check: freshness is not revocation. Later verified narrowing/terminal
    /// evidence and ordinary-history cuts must independently fence publication.
    pub fn open_interval(&self, scope: ContactScope) -> Option<&ContactScopeInterval> {
        self.intervals.iter().find(|interval| interval.scope == scope && interval.closed_by.is_none())
    }
    /// Required by current Contact mutations and Direct Conversation founding.
    pub fn require_current_at(&self, at: DateTime<Utc>) -> Result<()> {
        if at < self.current_from || at >= self.fresh_until { return Err(ContactAuthorizationError::NotCurrent); }
        Ok(())
    }
}

/// Verify every source signature through complete authenticated method-native
/// DID history, including historical assertionMethod membership. The resolver
/// supplies raw history, never a caller-selected public key or allow result.
/// `observed_at` is the actual first observation, not an invented old timestamp.
/// A complete lineage starts at version one and ends at the signed checkpoint;
/// a latest-head-only projection cannot construct this verified value.
pub fn verify_contact_direction_history(
    issuer: &ContactPeer,
    peer: &ContactPeer,
    contact_round_id: &Hash,
    lineages: &[ContactLineage],
    checkpoint: &ContactCurrentProof,
    observed_at: DateTime<Utc>,
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<VerifiedContactDirection> {
    if issuer.contact_actor_id() == peer.contact_actor_id() {
        return Err(invalid("Contact direction requires two distinct participants"));
    }
    if checkpoint.contact_round_id != *contact_round_id || checkpoint.peer != *peer
        || checkpoint.issuer_id != *issuer.delivery_station_id() {
        return Err(invalid("checkpoint does not bind the expected issuer, peer and round"));
    }
    verify_source_signature(issuer.delivery_station_id(), &checkpoint.signature,
        &checkpoint.canonical_signing_bytes().map_err(invalid)?, resolver)?;
    if observed_at < checkpoint.signature.created_at || observed_at >= checkpoint.fresh_until {
        return Err(ContactAuthorizationError::NotCurrent);
    }
    let Some(first) = lineages.first() else { return Err(ContactAuthorizationError::MissingMaterial("directional lineage is absent".to_owned())); };
    let Some(last) = lineages.last() else { unreachable!() };
    if first.version != 1 || first.predecessor_event_ref.is_some()
        || last.version != checkpoint.complete_through || last.event_ref != checkpoint.head_event_ref
        || !checkpoint.accepted_frontier.contains(&last.event_ref) {
        return Err(ContactAuthorizationError::MissingMaterial("directional history does not span its initial grant through the certified head".to_owned()));
    }
    let mut intervals = Vec::<ContactScopeInterval>::new();
    let mut seen = BTreeSet::new();
    for (index, lineage) in lineages.iter().enumerate() {
        if lineage.issuer != *issuer || lineage.peer != *peer || lineage.contact_round_id != *contact_round_id {
            return Err(invalid("lineage changes issuer, peer or round"));
        }
        verify_source_signature(issuer.delivery_station_id(), &lineage.signature,
            &lineage.canonical_signing_bytes().map_err(invalid)?, resolver)?;
        if !seen.insert(lineage.event_ref.clone()) { return Err(invalid("lineage repeats an Event identity")); }
        if index > 0 {
            let previous = &lineages[index - 1];
            if lineage.version != previous.version.checked_add(1).ok_or_else(|| invalid("lineage version overflow"))? {
                return Err(ContactAuthorizationError::MissingMaterial("directional history skips a version".to_owned()));
            }
            if lineage.predecessor_event_ref.as_ref() != Some(&previous.event_ref) {
                return Err(invalid("lineage predecessor conflicts with the preceding exact Event"));
            }
            if previous.terminal == Some(true) { return Err(invalid("terminal Contact lineage cannot be reopened")); }
        }
        let scopes = lineage.granted_to_peer_scopes.iter().copied().collect::<BTreeSet<_>>();
        if scopes.len() != lineage.granted_to_peer_scopes.len() { return Err(invalid("scope set contains duplicates")); }
        for interval in &mut intervals {
            if interval.closed_by.is_none() && (lineage.terminal == Some(true) || !scopes.contains(&interval.scope)) {
                interval.closed_by = Some(lineage.event_ref.clone());
            }
        }
        if lineage.terminal != Some(true) {
            for scope in scopes {
                if !intervals.iter().any(|interval| interval.scope == scope && interval.closed_by.is_none()) {
                    intervals.push(ContactScopeInterval { scope,
                        authorization_event_id: first.event_ref.clone(),
                        generation_event_id: lineage.event_ref.clone(), closed_by: None });
                }
            }
        }
    }
    if checkpoint.terminal != (last.terminal == Some(true)) {
        return Err(invalid("checkpoint terminal state disagrees with its exact head"));
    }
    Ok(VerifiedContactDirection { issuer: issuer.clone(), peer: peer.clone(), round: contact_round_id.clone(),
        head: last.event_ref.clone(), current_from: checkpoint.signature.created_at,
        fresh_until: checkpoint.fresh_until, intervals })
}

fn verify_source_signature(
    expected_source: &DidCoreId,
    signature: &ProtocolSignature,
    bytes: &[u8],
    resolver: &dyn AuthorityDidHistoryResolver,
) -> Result<()> {
    let did = arkret_identity::verification_method_did(signature.verification_method.as_str()).map_err(invalid)?;
    if arkret_wire::project_did_to_core_id(&did).map_err(invalid)? != *expected_source {
        return Err(invalid("signature controller is not the issuer's Station"));
    }
    let history = resolver.resolve_complete_history(&did)
        .map_err(|error| ContactAuthorizationError::MissingMaterial(error.to_string()))?;
    if history.did != did || history.method != DidMethodUri::Webvh || did.method() != "webvh" {
        return Err(invalid("source history does not bind the exact supported historical DID"));
    }
    if history.native_history == Some(false) || history.has_more || history.next_cursor.is_some() {
        return Err(ContactAuthorizationError::MissingMaterial("source method history is incomplete".to_owned()));
    }
    let point = arkret_signatures::webvh::validate_webvh_history_at(&did, &history.entries, signature.created_at).map_err(invalid)?;
    let document: DidDocument = serde_json::from_value(point.document).map_err(invalid)?;
    arkret_identity::validate_verification_method_relationship(&document, &signature.verification_method,
        &did, DidVerificationRelationship::AssertionMethod).map_err(invalid)?;
    let key = arkret_identity::resolve_verification_method_key_from_document(&document,
        signature.verification_method.as_str()).map_err(invalid)?;
    if !arkret_signatures::proof::verify_detached_ed25519_signature(&key.public_key, bytes, signature.jws.as_str()) {
        return Err(invalid("source signature is invalid"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
