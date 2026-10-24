//! Structural invariants shared by source writers and authenticated consumers.
//! These checks never substitute for holder or historical source verification.
use std::collections::BTreeSet;

use arkret_wire::{EventKind, TrustDomainId, WireError};

use super::*;

fn invalid(message: &str) -> WireError {
    WireError::Protocol(message.to_owned())
}
pub fn validate_contact_operation_version(
    version: u64,
    predecessor: Option<&EventId>,
) -> arkret_wire::Result<()> {
    if version == 0 || version > 9_007_199_254_740_991 || (version == 1) == predecessor.is_some() {
        return Err(invalid(
            "invalid Contact lifetime operation version/predecessor",
        ));
    }
    Ok(())
}
impl ContactRoundBasis {
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        self.contact_round.validate_canonical_order()?;
        if self.contact_round.compute_id()? != self.contact_round_id {
            return Err(invalid("Contact round digest differs from its core"));
        }
        let pair = contact_round_participants(&self.contact_round);
        let mut holders = BTreeSet::new();
        for receipt in &self.request_receipts {
            receipt.validate_shape()?;
            if !pair.contains(&receipt.core.holder.contact_actor_id())
                || !pair.contains(&receipt.core.peer.contact_actor_id())
                || !holders.insert(receipt.core.holder.contact_actor_id())
            {
                return Err(invalid(
                    "Contact round request directions differ from exact pair",
                ));
            }
        }
        match &self.contact_round {
            ContactRound::Normal {
                request_event_ref,
                request_acceptance_receipt_digest,
                ..
            } => {
                let [request] = self.request_receipts.as_slice() else {
                    return Err(invalid("normal round requires one request"));
                };
                let response = self
                    .normal_response_receipt
                    .as_ref()
                    .ok_or_else(|| invalid("normal response confirmation missing"))?;
                if self.glare_concurrency_attestations.is_some()
                    || &request.core.request_event_ref != request_event_ref
                    || &request.computed_receipt_digest()? != request_acceptance_receipt_digest
                    || response.request_receipt != *request
                    || response.contact_round_id != self.contact_round_id
                    || response.trust_domain_id != request.core.trust_domain_id
                    || response.issuer_id != *request.core.peer.delivery_station_id()
                {
                    return Err(invalid("normal Contact source confirmations disagree"));
                }
                validate_contact_operation_version(
                    response.version,
                    response.predecessor_event_ref.as_ref(),
                )?;
            }
            ContactRound::Glare { requests, .. } => {
                if self.normal_response_receipt.is_some() || self.request_receipts.len() != 2 {
                    return Err(invalid(
                        "glare requires two requests and no normal response",
                    ));
                }
                let attestations = self
                    .glare_concurrency_attestations
                    .as_ref()
                    .ok_or_else(|| invalid("glare needs both durable choices"))?;
                let mut subjects = BTreeSet::new();
                for request in requests {
                    let receipt = self
                        .request_receipts
                        .iter()
                        .find(|r| r.core.request_event_ref == request.request_event_ref)
                        .ok_or_else(|| invalid("glare request confirmation missing"))?;
                    if receipt.computed_receipt_digest()?
                        != request.request_acceptance_receipt_digest
                    {
                        return Err(invalid("glare receipt digest mismatch"));
                    }
                }
                let digests = [
                    requests[0].request_acceptance_receipt_digest.clone(),
                    requests[1].request_acceptance_receipt_digest.clone(),
                ];
                for attestation in attestations {
                    attestation.validate_slot_commitment()?;
                    let receipt = self
                        .request_receipts
                        .iter()
                        .find(|r| r.core.holder.contact_actor_id() == attestation.subject_id)
                        .ok_or_else(|| invalid("glare subject mismatch"))?;
                    if !subjects.insert(attestation.subject_id.clone())
                        || attestation.peer_id != receipt.core.peer.contact_actor_id()
                        || attestation.issuer_id != receipt.core.issuer_id
                        || attestation.trust_domain_id != receipt.core.trust_domain_id
                        || attestation.initial_contact_round_id
                            != receipt.core.initial_contact_round_id
                        || attestation.contact_round_id != self.contact_round_id
                        || attestation.request_event_ref != receipt.core.request_event_ref
                        || attestation.version != receipt.core.version
                        || attestation.request_receipt_digests != digests
                    {
                        return Err(invalid(
                            "glare choice does not bind the canonical exact requests",
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}
impl ContactInitialIdentity {
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        self.round.validate_shape()?;
        if self.events.is_empty()
            || self.events.len() > 3
            || self.round.request_receipts.iter().any(|r| {
                r.core.trust_domain_id != self.trust_domain_id
                    || r.core.initial_contact_round_id.is_some()
            })
        {
            return Err(invalid("fixed first identity is not a first establishment"));
        }
        validate_round_events(&self.round, &self.events)?;
        Ok(())
    }
}
fn validate_round_events(basis: &ContactRoundBasis, events: &[Event]) -> arkret_wire::Result<()> {
    let mut expected: BTreeSet<EventId> = basis
        .request_receipts
        .iter()
        .map(|r| r.core.request_event_ref.clone())
        .collect();
    if let Some(response) = &basis.normal_response_receipt {
        expected.insert(response.response_event_ref.clone());
    }
    let actual: BTreeSet<EventId> = events.iter().map(|event| event.event_id.clone()).collect();
    if actual != expected || actual.len() != events.len() {
        return Err(invalid(
            "round must preserve exactly its original signed Events",
        ));
    }
    Ok(())
}
impl ContactRoundEvidenceBundle {
    pub fn basis(&self) -> ContactRoundBasis {
        ContactRoundBasis {
            contact_round_id: self.contact_round_id.clone(),
            contact_round: self.contact_round.clone(),
            request_receipts: self.request_receipts.clone(),
            normal_response_receipt: self.normal_response_receipt.clone(),
            glare_concurrency_attestations: self.glare_concurrency_attestations.clone(),
        }
    }
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        let basis = self.basis();
        basis.validate_shape()?;
        self.initial_identity.validate_shape()?;
        validate_round_events(&basis, &self.round_events)?;
        if contact_round_participants(&basis.contact_round)
            != contact_round_participants(&self.initial_identity.round.contact_round)
            || self.scope_grants.len() > 10
            || self.current_proofs.len() != 2
        {
            return Err(invalid("Contact current bundle pair or bounds mismatch"));
        }
        validate_contact_evidence_directions(self)?;
        for proof in &self.current_proofs {
            proof.validate_shape()?;
            if proof.trust_domain_id != self.initial_identity.trust_domain_id
                || proof.initial_contact_round_id.as_ref()
                    != Some(&self.initial_identity.round.contact_round_id)
                || proof.contact_round_id.as_ref() != Some(&self.contact_round_id)
            {
                return Err(invalid("current bundle fixed identity/round mismatch"));
            }
            let head = self
                .current_operations
                .iter()
                .find(|op| op.event().event_id == proof.head_event_ref)
                .ok_or_else(|| invalid("current head original operation missing"))?;
            validate_head(proof, head)?;
            validate_scope_grants(proof, &self.scope_grants)?;
            validate_current_intent(proof, head, Some(&basis), &self.scope_grants)?;
        }
        Ok(())
    }
}
impl ContactOperationEvidence {
    pub fn event(&self) -> &Event {
        match self {
            Self::Request { signed_event, .. }
            | Self::Response { signed_event, .. }
            | Self::Reject { signed_event, .. }
            | Self::ScopeUpdate { signed_event, .. }
            | Self::Tombstone { signed_event, .. } => signed_event,
        }
    }
    pub fn holder(&self) -> &ContactPeer {
        match self {
            Self::Request {
                request_receipt, ..
            } => &request_receipt.core.holder,
            Self::Response {
                response_receipt, ..
            } => &response_receipt.request_receipt.core.peer,
            Self::Reject { reject_receipt, .. } => &reject_receipt.request_receipt.core.peer,
            Self::ScopeUpdate { lineage, .. } | Self::Tombstone { lineage, .. } => &lineage.issuer,
        }
    }
    pub fn peer(&self) -> &ContactPeer {
        match self {
            Self::Request {
                request_receipt, ..
            } => &request_receipt.core.peer,
            Self::Response {
                response_receipt, ..
            } => &response_receipt.request_receipt.core.holder,
            Self::Reject { reject_receipt, .. } => &reject_receipt.request_receipt.core.holder,
            Self::ScopeUpdate { lineage, .. } | Self::Tombstone { lineage, .. } => &lineage.peer,
        }
    }
    pub fn trust_domain_id(&self) -> &TrustDomainId {
        match self {
            Self::Request {
                request_receipt, ..
            } => &request_receipt.core.trust_domain_id,
            Self::Response {
                response_receipt, ..
            } => &response_receipt.trust_domain_id,
            Self::Reject { reject_receipt, .. } => &reject_receipt.trust_domain_id,
            Self::ScopeUpdate { lineage, .. } | Self::Tombstone { lineage, .. } => {
                &lineage.trust_domain_id
            }
        }
    }
    pub fn initial_contact_round_id(&self) -> Option<&Hash> {
        match self {
            Self::Request {
                request_receipt, ..
            } => request_receipt.core.initial_contact_round_id.as_ref(),
            Self::Response {
                response_receipt, ..
            } => response_receipt.initial_contact_round_id.as_ref(),
            Self::Reject { reject_receipt, .. } => reject_receipt.initial_contact_round_id.as_ref(),
            Self::ScopeUpdate { lineage, .. } | Self::Tombstone { lineage, .. } => {
                lineage.initial_contact_round_id.as_ref()
            }
        }
    }
    pub fn version(&self) -> u64 {
        match self {
            Self::Request {
                request_receipt, ..
            } => request_receipt.core.version,
            Self::Response {
                response_receipt, ..
            } => response_receipt.version,
            Self::Reject { reject_receipt, .. } => reject_receipt.version,
            Self::ScopeUpdate { lineage, .. } | Self::Tombstone { lineage, .. } => lineage.version,
        }
    }
    pub fn predecessor_event_ref(&self) -> Option<&EventId> {
        match self {
            Self::Request {
                request_receipt, ..
            } => request_receipt.core.predecessor_event_ref.as_ref(),
            Self::Response {
                response_receipt, ..
            } => response_receipt.predecessor_event_ref.as_ref(),
            Self::Reject { reject_receipt, .. } => reject_receipt.predecessor_event_ref.as_ref(),
            Self::ScopeUpdate { lineage, .. } | Self::Tombstone { lineage, .. } => {
                lineage.predecessor_event_ref.as_ref()
            }
        }
    }
    pub fn producer_signer(&self) -> &ContactProducerSigner {
        match self {
            Self::Request {
                request_receipt, ..
            } => &request_receipt.core.producer_signer,
            Self::Response {
                response_receipt, ..
            } => &response_receipt.producer_signer,
            Self::Reject { reject_receipt, .. } => &reject_receipt.producer_signer,
            Self::ScopeUpdate { lineage, .. } | Self::Tombstone { lineage, .. } => {
                &lineage.producer_signer
            }
        }
    }
    pub fn source_signature(&self) -> &ProtocolSignature {
        match self {
            Self::Request {
                request_receipt, ..
            } => &request_receipt.signature,
            Self::Response {
                response_receipt, ..
            } => &response_receipt.signature,
            Self::Reject { reject_receipt, .. } => &reject_receipt.signature,
            Self::ScopeUpdate { lineage, .. } | Self::Tombstone { lineage, .. } => {
                &lineage.signature
            }
        }
    }
    pub fn accepted_at(&self) -> DateTime<Utc> {
        match self {
            Self::Request {
                request_receipt, ..
            } => request_receipt.core.accepted_at,
            Self::Response {
                response_receipt, ..
            } => response_receipt.accepted_at,
            Self::Reject { reject_receipt, .. } => reject_receipt.accepted_at,
            Self::ScopeUpdate { lineage, .. } | Self::Tombstone { lineage, .. } => {
                lineage.accepted_at
            }
        }
    }
    /// Receipts retain the business acceptance key; lineage uses its actual
    /// issuance authority. These cuts can differ after source key rotation.
    pub fn round_closure(&self) -> Option<ContactRoundClosure> {
        match self {
            Self::Tombstone {
                signed_event,
                lineage,
            } => lineage
                .contact_round_id
                .clone()
                .map(|contact_round_id| ContactRoundClosure {
                    contact_round_id,
                    operation: ContactTombstoneEvidence {
                        kind: ContactTombstoneEvidenceKind::Tombstone,
                        signed_event: signed_event.clone(),
                        lineage: lineage.clone(),
                    },
                }),
            _ => None,
        }
    }
    pub fn source_authority_at(&self) -> DateTime<Utc> {
        match self {
            Self::ScopeUpdate { .. } | Self::Tombstone { .. } => self.source_signature().created_at,
            _ => self.accepted_at(),
        }
    }
    pub fn source_signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        match self {
            Self::Request {
                request_receipt, ..
            } => request_receipt.canonical_signing_bytes(),
            Self::Response {
                response_receipt, ..
            } => response_receipt.canonical_signing_bytes(),
            Self::Reject { reject_receipt, .. } => reject_receipt.canonical_signing_bytes(),
            Self::ScopeUpdate { lineage, .. } | Self::Tombstone { lineage, .. } => {
                lineage.canonical_signing_bytes()
            }
        }
    }
    pub fn granted_scopes(&self) -> arkret_wire::Result<Vec<ContactScope>> {
        let value = serde_json::to_value(&self.event().payload)?;
        match self {
            Self::Reject { .. } | Self::Tombstone { .. } => Ok(Vec::new()),
            _ => serde_json::from_value(
                value
                    .get("granted_to_peer_scopes")
                    .cloned()
                    .ok_or_else(|| invalid("Contact grant scopes absent"))?,
            )
            .map_err(Into::into),
        }
    }
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        let expected = match self {
            Self::Request { .. } => EventKind::ContactRequested,
            Self::Response { .. } => EventKind::ContactAccepted,
            Self::Reject { .. } => EventKind::ContactRejected,
            Self::ScopeUpdate { .. } => EventKind::ContactScopeUpdate,
            Self::Tombstone { .. } => EventKind::ContactTombstone,
        };
        if self.event().kind != expected
            || self.event().actor_id != self.holder().contact_actor_id()
            || self.holder() == self.peer()
            || self.accepted_at() < self.event().created_at
        {
            return Err(invalid(
                "Contact original operation branch/holder/confirmation mismatch",
            ));
        }
        validate_contact_operation_version(self.version(), self.predecessor_event_ref())?;
        self.producer_signer()
            .validate_for_event(self.event(), self.holder())?;
        let value = serde_json::to_value(&self.event().payload)?;
        match self {
            Self::Request { .. } => {
                let _: crate::events_payloads::contact::ContactRequestedPayload =
                    serde_json::from_value(value.clone())?;
            }
            Self::ScopeUpdate { .. } => {
                let _: ContactScopeUpdatePayload = serde_json::from_value(value.clone())?;
            }
            Self::Tombstone { .. } => {
                let _: crate::events_payloads::contact::ContactTombstonedPayload =
                    serde_json::from_value(value.clone())?;
            }
            _ => {}
        }
        let scopes = self.granted_scopes()?;
        if scopes.len() > 5 || scopes.iter().collect::<BTreeSet<_>>().len() != scopes.len() {
            return Err(invalid("Contact scopes exceed the closed unique scope set"));
        }

        for (key, expected) in [
            (
                "trust_domain_id",
                serde_json::to_value(self.trust_domain_id())?,
            ),
            ("peer", serde_json::to_value(self.peer())?),
            ("version", serde_json::to_value(self.version())?),
        ] {
            if value.get(key) != Some(&expected) {
                return Err(invalid("Contact payload/source cursor mismatch"));
            }
        }
        if value.get("initial_contact_round_id").cloned()
            != self
                .initial_contact_round_id()
                .map(serde_json::to_value)
                .transpose()?
            || value.get("predecessor_event_ref").cloned()
                != self
                    .predecessor_event_ref()
                    .map(serde_json::to_value)
                    .transpose()?
        {
            return Err(invalid(
                "Contact payload/source predecessor or fixed identity mismatch",
            ));
        }
        match self {
            Self::Request {
                signed_event,
                request_receipt,
            } => {
                request_receipt.validate_shape()?;
                let checkpoint = Hash::new(arkret_canonical::domain_prefixed_canonical_sha256(
                    arkret_wire::DomainSeparationId::CONTACT_REQUEST_SOURCE_CHECKPOINT_V1,
                    &serde_json::json!({"event_ref":signed_event.event_id,"event_digest":signed_event.event_id.event_digest()}),
                )?)?;
                if request_receipt.core.source_checkpoint != checkpoint {
                    return Err(invalid(
                        "source request checkpoint differs from exact original Event commitment",
                    ));
                }

                if request_receipt.core.request_event_ref != signed_event.event_id
                    || request_receipt.core.issuer_id != *self.holder().delivery_station_id()
                {
                    return Err(invalid("request confirmation mismatch"));
                }
            }
            Self::Response {
                signed_event,
                response_receipt,
            } => {
                let p: crate::events_payloads::contact::ContactAcceptedPayload =
                    serde_json::from_value(value)?;
                response_receipt.request_receipt.validate_shape()?;
                if response_receipt.trust_domain_id
                    != response_receipt.request_receipt.core.trust_domain_id
                    || response_receipt.initial_contact_round_id
                        != response_receipt
                            .request_receipt
                            .core
                            .initial_contact_round_id
                {
                    return Err(invalid(
                        "nested request changes domain or fixed first identity",
                    ));
                }
                if ContactRound::normal_from_request_receipt(&response_receipt.request_receipt)?
                    .compute_id()?
                    != response_receipt.contact_round_id
                {
                    return Err(invalid(
                        "normal response round does not bind its original request",
                    ));
                }
                if response_receipt.response_event_ref != signed_event.event_id
                    || response_receipt.contact_round_id != p.contact_round_id
                    || response_receipt.issuer_id != *self.holder().delivery_station_id()
                    || p.request_event_ref
                        != response_receipt.request_receipt.core.request_event_ref
                    || p.request_acceptance_receipt_digest
                        != response_receipt.request_receipt.computed_receipt_digest()?
                {
                    return Err(invalid("response confirmation mismatch"));
                }
            }
            Self::Reject {
                signed_event,
                reject_receipt,
            } => {
                let p: crate::events_payloads::contact::ContactRejectedPayload =
                    serde_json::from_value(value)?;
                reject_receipt.request_receipt.validate_shape()?;
                if reject_receipt.trust_domain_id
                    != reject_receipt.request_receipt.core.trust_domain_id
                    || reject_receipt.initial_contact_round_id
                        != reject_receipt.request_receipt.core.initial_contact_round_id
                {
                    return Err(invalid(
                        "nested request changes domain or fixed first identity",
                    ));
                }
                if reject_receipt.reject_event_ref != signed_event.event_id
                    || reject_receipt.issuer_id != *self.holder().delivery_station_id()
                    || p.request_event_ref != reject_receipt.request_receipt.core.request_event_ref
                    || p.request_acceptance_receipt_digest
                        != reject_receipt.request_receipt.computed_receipt_digest()?
                {
                    return Err(invalid("reject confirmation mismatch"));
                }
            }
            Self::ScopeUpdate {
                signed_event,
                lineage,
            }
            | Self::Tombstone {
                signed_event,
                lineage,
            } => {
                if lineage.event_ref != signed_event.event_id
                    || value.get("contact_round_id").cloned()
                        != lineage
                            .contact_round_id
                            .as_ref()
                            .map(serde_json::to_value)
                            .transpose()?
                    || self.granted_scopes()? != lineage.granted_to_peer_scopes
                {
                    return Err(invalid("successor confirmation mismatch"));
                }
            }
        }
        Ok(())
    }
}
impl ContactCurrentProof {
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        if self.holder == self.peer
            || self.issuer_id != *self.holder.delivery_station_id()
            || self.version == 0
            || self.version > 9_007_199_254_740_991
            || self.issued_at != self.signature.created_at
            || self.cache_expires_at <= self.issued_at
            || self.scope_instances.len() > 5
            || self
                .scope_instances
                .iter()
                .map(|i| i.contact_scope)
                .collect::<BTreeSet<_>>()
                .len()
                != self.scope_instances.len()
        {
            return Err(invalid(
                "invalid Contact current direction/bounds/freshness",
            ));
        }
        if let Some(closure) = &self.closed_round {
            closure.operation.validate_shape()?;
            let op = closure.operation.operation();
            if op.trust_domain_id() != &self.trust_domain_id
                || op.initial_contact_round_id() != self.initial_contact_round_id.as_ref()
                || !((op.holder() == &self.holder && op.peer() == &self.peer)
                    || (op.holder() == &self.peer && op.peer() == &self.holder))
            {
                return Err(invalid(
                    "current closure changes exact pair, domain or fixed identity",
                ));
            }
        }
        Ok(())
    }
}
impl ContactTombstoneEvidence {
    pub fn operation(&self) -> ContactOperationEvidence {
        ContactOperationEvidence::Tombstone {
            signed_event: self.signed_event.clone(),
            lineage: self.lineage.clone(),
        }
    }
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        self.operation().validate_shape()
    }
}
fn validate_head(
    proof: &ContactCurrentProof,
    head: &ContactOperationEvidence,
) -> arkret_wire::Result<()> {
    head.validate_shape()?;
    if proof.holder != *head.holder()
        || proof.peer != *head.peer()
        || proof.trust_domain_id != *head.trust_domain_id()
        || proof.version != head.version()
        || proof.head_event_ref != head.event().event_id
        || head
            .initial_contact_round_id()
            .is_some_and(|root| Some(root) != proof.initial_contact_round_id.as_ref())
    {
        return Err(invalid(
            "current proof differs from its exact original head",
        ));
    }
    Ok(())
}
fn validate_operation_round(
    operation: &ContactOperationEvidence,
    basis: &ContactRoundBasis,
) -> arkret_wire::Result<()> {
    let pair = contact_round_participants(&basis.contact_round);
    let participants = [
        operation.holder().contact_actor_id(),
        operation.peer().contact_actor_id(),
    ];
    if operation.trust_domain_id() != &basis.request_receipts[0].core.trust_domain_id
        || !participants.iter().all(|actor| pair.contains(actor))
    {
        return Err(invalid(
            "current original differs from established pair/domain",
        ));
    }
    let belongs = match operation {
        ContactOperationEvidence::Request {
            request_receipt, ..
        } => basis.request_receipts.contains(request_receipt),
        ContactOperationEvidence::Response {
            response_receipt, ..
        } => basis.normal_response_receipt.as_ref() == Some(response_receipt),
        ContactOperationEvidence::Reject { .. } => false,
        ContactOperationEvidence::ScopeUpdate { lineage, .. }
        | ContactOperationEvidence::Tombstone { lineage, .. } => {
            let root = basis.request_receipts[0]
                .core
                .initial_contact_round_id
                .as_ref()
                .unwrap_or(&basis.contact_round_id);
            let start_version = basis
                .request_receipts
                .iter()
                .find(|r| r.core.holder == *operation.holder())
                .map(|r| r.core.version)
                .or_else(|| {
                    basis
                        .normal_response_receipt
                        .as_ref()
                        .filter(|r| r.request_receipt.core.peer == *operation.holder())
                        .map(|r| r.version)
                });
            lineage.contact_round_id.as_ref() == Some(&basis.contact_round_id)
                && lineage.initial_contact_round_id.as_ref() == Some(root)
                && start_version.is_some_and(|v| operation.version() > v)
        }
    };
    if !belongs {
        return Err(invalid(
            "current original is not an operation in its claimed round",
        ));
    }
    Ok(())
}
fn validate_current_intent(
    proof: &ContactCurrentProof,
    head: &ContactOperationEvidence,
    basis: Option<&ContactRoundBasis>,
    grants: &[ContactOperationEvidence],
) -> arkret_wire::Result<()> {
    if let Some(basis) = basis {
        validate_operation_round(head, basis)?;
        for grant in grants.iter().filter(|g| g.holder() == &proof.holder) {
            validate_operation_round(grant, basis)?;
        }
    }
    let closed = head.round_closure().is_some()
        || proof
            .closed_round
            .as_ref()
            .is_some_and(|c| Some(&c.contact_round_id) == proof.contact_round_id.as_ref());
    let expected: BTreeSet<_> = if basis.is_some() && !closed {
        head.granted_scopes()?.into_iter().collect()
    } else {
        BTreeSet::new()
    };
    let actual: BTreeSet<_> = proof
        .scope_instances
        .iter()
        .map(|i| i.contact_scope)
        .collect();
    if actual != expected {
        return Err(invalid(
            "current scopes contradict the original holder head or closure",
        ));
    }
    Ok(())
}
fn validate_scope_grants(
    proof: &ContactCurrentProof,
    grants: &[ContactOperationEvidence],
) -> arkret_wire::Result<()> {
    for instance in &proof.scope_instances {
        let grant = grants
            .iter()
            .find(|op| op.event().event_id == instance.grant_event_ref)
            .ok_or_else(|| invalid("exact current scope grant missing"))?;
        grant.validate_shape()?;
        if grant.holder() != &proof.holder
            || grant.peer() != &proof.peer
            || grant.trust_domain_id() != &proof.trust_domain_id
            || grant.version() > proof.version
            || !grant.granted_scopes()?.contains(&instance.contact_scope)
        {
            return Err(invalid(
                "scope instance is not an original grant in this direction",
            ));
        }
    }
    Ok(())
}
impl ContactCurrentMaterial {
    pub fn validate_shape(&self) -> arkret_wire::Result<()> {
        self.current_proof.validate_shape()?;
        validate_head(&self.current_proof, &self.head_operation)?;
        if self.scope_grants.len() > 5 || self.historical_intervals.len() > 5 {
            return Err(invalid("Contact current material exceeds object bounds"));
        }
        validate_scope_grants(&self.current_proof, &self.scope_grants)?;
        validate_current_intent(
            &self.current_proof,
            &self.head_operation,
            self.round_evidence.as_ref(),
            &self.scope_grants,
        )?;
        if let Some(initial) = &self.initial_identity {
            initial.validate_shape()?;
            if initial.trust_domain_id != self.current_proof.trust_domain_id
                || Some(&initial.round.contact_round_id)
                    != self.current_proof.initial_contact_round_id.as_ref()
            {
                return Err(invalid("current material fixed identity mismatch"));
            }
        } else if self.current_proof.initial_contact_round_id.is_some() {
            return Err(invalid("fixed first identity missing"));
        }
        if let Some(round) = &self.round_evidence {
            round.validate_shape()?;
            let initial = self
                .initial_identity
                .as_ref()
                .ok_or_else(|| invalid("established current lacks fixed initial originals"))?;
            if contact_round_participants(&round.contact_round)
                != contact_round_participants(&initial.round.contact_round)
                || round.request_receipts[0]
                    .core
                    .initial_contact_round_id
                    .as_ref()
                    .unwrap_or(&round.contact_round_id)
                    != &initial.round.contact_round_id
            {
                return Err(invalid("current round changes fixed first pair or root"));
            }
            validate_round_events(
                round,
                self.round_events
                    .as_deref()
                    .ok_or_else(|| invalid("current round originals missing"))?,
            )?;
            if Some(&round.contact_round_id) != self.current_proof.contact_round_id.as_ref() {
                return Err(invalid("current round basis mismatch"));
            }
        }
        if !self.current_proof.scope_instances.is_empty()
            && (self.round_evidence.is_none() || self.initial_identity.is_none())
        {
            return Err(invalid(
                "live scope lacks fixed identity or established round",
            ));
        }
        for interval in &self.historical_intervals {
            interval.grant.validate_shape()?;
            interval.round.validate_shape()?;
            validate_round_events(&interval.round, &interval.round_events)?;
            if interval.grant.holder() != &self.current_proof.holder
                || interval.grant.peer() != &self.current_proof.peer
                || interval.grant.trust_domain_id() != &self.current_proof.trust_domain_id
                || !interval
                    .grant
                    .granted_scopes()?
                    .contains(&interval.contact_scope)
            {
                return Err(invalid("historical scope origin mismatch"));
            }
            if let Some(close) = &interval.closed_by {
                close.validate_shape()?;
                let same = close.holder() == interval.grant.holder()
                    && close.peer() == interval.grant.peer();
                let opposite = close.holder() == interval.grant.peer()
                    && close.peer() == interval.grant.holder();
                let close_round = serde_json::to_value(&close.event().payload)?
                    .get("contact_round_id")
                    .cloned();
                if close.trust_domain_id() != interval.grant.trust_domain_id()
                    || close_round != Some(serde_json::to_value(&interval.round.contact_round_id)?)
                    || (!same
                        && !(opposite
                            && matches!(close, ContactOperationEvidence::Tombstone { .. })))
                    || (same
                        && (close.version() <= interval.grant.version()
                            || close.version() > self.current_proof.version))
                    || !matches!(
                        close,
                        ContactOperationEvidence::ScopeUpdate { .. }
                            | ContactOperationEvidence::Tombstone { .. }
                    )
                    || (matches!(close, ContactOperationEvidence::ScopeUpdate { .. })
                        && close.granted_scopes()?.contains(&interval.contact_scope))
                {
                    return Err(invalid(
                        "historical interval has no actual closing operation in its exact round",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Private durable projection. It is not a public wire result or Event reducer.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ContactPrivateState {
    pub local_glare_attestations: Vec<GlareConcurrencyAttestation>,
    pub observed_closure: Option<Box<ContactRoundClosure>>,
    pub initial_root_floor: Option<Hash>,
    pub observed_scope_update: Option<Box<ContactOperationEvidence>>,
    pub initial_identity: Option<ContactInitialIdentity>,
    pub round_basis: Option<ContactRoundBasis>,
    pub round_events: Vec<Event>,
    pub directions: Vec<ContactDirectionCurrent>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContactDirectionCurrent {
    pub head_operation: ContactOperationEvidence,
    pub scope_instances: Vec<ContactScopeInstance>,
    pub scope_grants: Vec<ContactOperationEvidence>,
    pub closed_round: Option<ContactRoundClosure>,
    pub current_proof: Option<ContactCurrentProof>,
}
impl ContactPrivateState {
    pub fn direction(&self, holder: &ContactPeer) -> Option<&ContactDirectionCurrent> {
        self.directions
            .iter()
            .find(|d| d.head_operation.holder() == holder)
    }
    pub fn direction_actor(&self, holder: &ActorId) -> Option<&ContactDirectionCurrent> {
        self.directions
            .iter()
            .find(|d| d.head_operation.holder().contact_actor_id() == *holder)
    }
    pub fn next_operation(
        &self,
        holder: &ContactPeer,
    ) -> arkret_wire::Result<(u64, Option<EventId>)> {
        if self.initial_root_floor.is_some() && self.initial_identity.is_none() {
            return Err(invalid(
                "fixed first identity must be recovered before authoring",
            ));
        }
        self.direction(holder).map_or(Ok((1, None)), |current| {
            Ok((
                current
                    .head_operation
                    .version()
                    .checked_add(1)
                    .filter(|v| *v <= 9_007_199_254_740_991)
                    .ok_or_else(|| invalid("Contact operation version exhausted"))?,
                Some(current.head_operation.event().event_id.clone()),
            ))
        })
    }
    /// Record authenticated restrictive facts without advancing a directional
    /// head. The caller atomically persists the observation cursor and indexes
    /// removed exact grant instances before replacing this bounded original.
    pub fn observe_authenticated_operation(
        &mut self,
        operation: &ContactOperationEvidence,
    ) -> arkret_wire::Result<()> {
        operation.validate_shape()?;
        if self.directions.iter().any(|d| {
            operation.trust_domain_id() != d.head_operation.trust_domain_id()
                || !((operation.holder() == d.head_operation.holder()
                    && operation.peer() == d.head_operation.peer())
                    || (operation.holder() == d.head_operation.peer()
                        && operation.peer() == d.head_operation.holder()))
        }) {
            return Err(invalid(
                "observed operation changes full pair or trust domain",
            ));
        }
        let root = operation
            .initial_contact_round_id()
            .cloned()
            .or_else(|| match operation {
                ContactOperationEvidence::Response {
                    response_receipt, ..
                } => Some(response_receipt.contact_round_id.clone()),
                _ => None,
            });
        if let Some(root) = root {
            if self
                .initial_root_floor
                .as_ref()
                .is_some_and(|known| known != &root)
                || self
                    .initial_identity
                    .as_ref()
                    .is_some_and(|known| known.round.contact_round_id != root)
            {
                return Err(invalid(
                    "observed operation changes immutable first identity",
                ));
            }
            self.initial_root_floor = Some(root);
        }
        if let Some(closure) = operation.round_closure() {
            self.close_round(closure)?;
        }
        if matches!(operation, ContactOperationEvidence::ScopeUpdate { .. }) {
            let round = operation.event().payload.get("contact_round_id");
            if self.round_basis.as_ref().is_some_and(|basis| {
                serde_json::to_value(&basis.contact_round_id).ok().as_ref() == round
            }) {
                let scopes = operation.granted_scopes()?;
                if let Some(direction) = self
                    .directions
                    .iter_mut()
                    .find(|d| d.head_operation.holder() == operation.holder())
                {
                    let removed: Vec<_> = direction
                        .scope_grants
                        .iter()
                        .filter(|grant| grant.version() < operation.version())
                        .map(|grant| grant.event().event_id.clone())
                        .collect();
                    direction.scope_instances.retain(|i| {
                        scopes.contains(&i.contact_scope) || !removed.contains(&i.grant_event_ref)
                    });
                    direction.scope_grants.retain(|g| {
                        direction
                            .scope_instances
                            .iter()
                            .any(|i| i.grant_event_ref == g.event().event_id)
                    });
                    direction.current_proof = None;
                }
                self.observed_scope_update = Some(Box::new(operation.clone()));
            }
        }
        Ok(())
    }
    /// Source-side exact next operation. Remote version gaps require a complete
    /// authenticated current response instead of inferring scope continuity.
    pub fn apply_confirmed(
        &mut self,
        operation: ContactOperationEvidence,
    ) -> arkret_wire::Result<()> {
        operation.validate_shape()?;
        let holder = operation.holder().clone();
        let current = self
            .directions
            .iter()
            .position(|d| d.head_operation.holder() == &holder);
        if let Some(index) = current {
            let prior = &self.directions[index].head_operation;
            if operation.version() == prior.version() {
                if arkret_canonical::canonical_json_bytes(prior)?
                    != arkret_canonical::canonical_json_bytes(&operation)?
                {
                    return Err(invalid(
                        "same Contact version names different immutable operation bytes",
                    ));
                }
                return Ok(());
            }
            if operation.version() < prior.version() {
                return Ok(());
            }
            if operation.version() != prior.version() + 1
                || operation.predecessor_event_ref() != Some(&prior.event().event_id)
            {
                return Err(invalid(
                    "Contact operation gap requires authenticated current recovery",
                ));
            }
        } else if operation.version() != 1 {
            return Err(invalid(
                "missing Contact direction requires authenticated current recovery",
            ));
        }
        let mut direction = current
            .map(|i| self.directions.remove(i))
            .unwrap_or_else(|| ContactDirectionCurrent {
                head_operation: operation.clone(),
                scope_instances: vec![],
                scope_grants: vec![],
                closed_round: None,
                current_proof: None,
            });
        let scopes = operation.granted_scopes()?;
        let established = self.round_basis.as_ref().is_some_and(|r| {
            self.round_events
                .iter()
                .any(|event| event.event_id == operation.event().event_id)
                || serde_json::to_value(&operation.event().payload)
                    .ok()
                    .and_then(|v| v.get("contact_round_id").cloned())
                    == serde_json::to_value(&r.contact_round_id).ok()
        });
        if established
            && !matches!(
                operation,
                ContactOperationEvidence::Request { .. } | ContactOperationEvidence::Reject { .. }
            )
        {
            direction
                .scope_instances
                .retain(|i| scopes.contains(&i.contact_scope));
            for scope in &scopes {
                if !direction
                    .scope_instances
                    .iter()
                    .any(|i| i.contact_scope == *scope)
                {
                    direction.scope_instances.push(ContactScopeInstance {
                        contact_scope: *scope,
                        grant_event_ref: operation.event().event_id.clone(),
                    });
                }
            }
            direction.scope_instances.sort_by_key(|i| i.contact_scope);
            if direction
                .scope_instances
                .iter()
                .any(|i| i.grant_event_ref == operation.event().event_id)
            {
                direction.scope_grants.push(operation.clone());
            }
            direction.scope_grants.retain(|g| {
                direction
                    .scope_instances
                    .iter()
                    .any(|i| i.grant_event_ref == g.event().event_id)
            });
        } else {
            direction.scope_instances.clear();
            direction.scope_grants.clear();
        }
        direction.head_operation = operation;
        direction.current_proof = None;
        self.directions.push(direction);
        self.directions
            .sort_by_key(|d| d.head_operation.holder().contact_actor_id());
        if self.directions.len() > 2 {
            return Err(invalid(
                "Contact private state contains more than two directions",
            ));
        }
        Ok(())
    }
    pub fn establish(
        &mut self,
        basis: ContactRoundBasis,
        events: Vec<Event>,
    ) -> arkret_wire::Result<()> {
        basis.validate_shape()?;
        validate_round_events(&basis, &events)?;
        if self
            .observed_closure
            .as_ref()
            .is_some_and(|c| c.contact_round_id == basis.contact_round_id)
            || self.directions.iter().any(|d| {
                d.closed_round
                    .as_ref()
                    .is_some_and(|c| c.contact_round_id == basis.contact_round_id)
            })
        {
            return Err(invalid(
                "establishment cannot revive an independently closed exact round",
            ));
        }
        let root = basis.request_receipts[0]
            .core
            .initial_contact_round_id
            .as_ref()
            .unwrap_or(&basis.contact_round_id);
        if self
            .initial_root_floor
            .as_ref()
            .is_some_and(|known| known != root)
        {
            return Err(invalid(
                "establishment changes observed fixed first identity",
            ));
        }
        self.initial_root_floor = Some(root.clone());
        let initial = ContactInitialIdentity {
            trust_domain_id: basis.request_receipts[0].core.trust_domain_id.clone(),
            round: basis.clone(),
            events: events.clone(),
        };
        if let Some(prior) = &self.initial_identity {
            if basis.contact_round_id == prior.round.contact_round_id {
                if prior.round != basis || prior.events != events {
                    return Err(invalid("first establishment originals changed"));
                }
            } else if prior.trust_domain_id != initial.trust_domain_id
                || contact_round_participants(&prior.round.contact_round)
                    != contact_round_participants(&basis.contact_round)
                || basis.request_receipts.iter().any(|r| {
                    r.core.initial_contact_round_id.as_ref() != Some(&prior.round.contact_round_id)
                })
            {
                return Err(invalid(
                    "Contact establishment changes the immutable first identity",
                ));
            }
        } else {
            initial.validate_shape()?;
            self.initial_identity = Some(initial);
        }
        self.round_basis = Some(basis);
        self.round_events = events;
        for direction in &mut self.directions {
            if !self
                .round_events
                .iter()
                .any(|e| e.event_id == direction.head_operation.event().event_id)
            {
                continue;
            }
            let scopes = direction.head_operation.granted_scopes()?;
            direction.scope_instances = scopes
                .into_iter()
                .map(|scope| ContactScopeInstance {
                    contact_scope: scope,
                    grant_event_ref: direction.head_operation.event().event_id.clone(),
                })
                .collect();
            direction.scope_instances.sort_by_key(|i| i.contact_scope);
            direction.scope_grants = if direction.scope_instances.is_empty() {
                vec![]
            } else {
                vec![direction.head_operation.clone()]
            };
        }
        Ok(())
    }
    /// The caller independently authenticates the original closure and persists
    /// its exact round in the durable closure index before dropping old heads.
    pub fn close_round(&mut self, closure: ContactRoundClosure) -> arkret_wire::Result<()> {
        closure.operation.validate_shape()?;
        if closure.operation.lineage.contact_round_id.as_ref() != Some(&closure.contact_round_id) {
            return Err(invalid("closure round differs from original tombstone"));
        }
        let close = closure.operation.operation();
        if self.directions.iter().any(|d| {
            close.trust_domain_id() != d.head_operation.trust_domain_id()
                || !((close.holder() == d.head_operation.holder()
                    && close.peer() == d.head_operation.peer())
                    || (close.holder() == d.head_operation.peer()
                        && close.peer() == d.head_operation.holder()))
        }) {
            return Err(invalid("closure changes full pair or trust domain"));
        }
        if self.initial_identity.as_ref().is_some_and(|initial| {
            close.initial_contact_round_id() != Some(&initial.round.contact_round_id)
        }) {
            return Err(invalid("closure changes fixed first identity"));
        }
        if self
            .initial_root_floor
            .as_ref()
            .is_some_and(|known| close.initial_contact_round_id() != Some(known))
        {
            return Err(invalid("closure changes observed first identity"));
        }
        if let Some(root) = close.initial_contact_round_id() {
            self.initial_root_floor = Some(root.clone());
        }
        self.observed_closure = Some(Box::new(closure.clone()));
        for direction in &mut self.directions {
            let preserve_active = direction.closed_round.as_ref().is_some_and(|known| {
                self.round_basis.as_ref().is_some_and(|r| {
                    known.contact_round_id == r.contact_round_id
                        && closure.contact_round_id != r.contact_round_id
                })
            });
            if !preserve_active {
                direction.closed_round = Some(closure.clone());
            }
            if self
                .round_basis
                .as_ref()
                .is_some_and(|r| r.contact_round_id == closure.contact_round_id)
            {
                direction.scope_instances.clear();
                direction.scope_grants.clear();
                direction.current_proof = None;
            }
        }
        Ok(())
    }
    pub fn install_authenticated_current(
        &mut self,
        material: ContactCurrentMaterial,
    ) -> arkret_wire::Result<()> {
        material.validate_shape()?;
        if let Some(root) = &self.initial_root_floor
            && material
                .initial_identity
                .as_ref()
                .map(|i| &i.round.contact_round_id)
                != Some(root)
        {
            return Err(invalid("current recovery changes observed first identity"));
        }
        if let Some(close) = &self.observed_scope_update
            && close.holder() == material.head_operation.holder()
            && close.event().payload.get("contact_round_id")
                == material
                    .head_operation
                    .event()
                    .payload
                    .get("contact_round_id")
        {
            let retained = close.granted_scopes()?;
            if material.current_proof.scope_instances.iter().any(|i| {
                !retained.contains(&i.contact_scope)
                    && material.scope_grants.iter().any(|g| {
                        g.event().event_id == i.grant_event_ref && g.version() < close.version()
                    })
            }) {
                return Err(invalid(
                    "current recovery revives an observed removed grant instance",
                ));
            }
        }
        if let Some(root) = self
            .observed_closure
            .as_ref()
            .and_then(|c| c.operation.lineage.initial_contact_round_id.as_ref())
            && material
                .initial_identity
                .as_ref()
                .map(|i| &i.round.contact_round_id)
                != Some(root)
        {
            return Err(invalid(
                "recovery conflicts with authenticated closed-round first identity",
            ));
        }
        if let Some(initial) = &self.initial_identity
            && material.initial_identity.as_ref() != Some(initial)
        {
            return Err(invalid("current recovery changes immutable first identity"));
        }
        if let Some(closure) = &material.current_proof.closed_round {
            self.close_round((**closure).clone())?;
        }
        let head_closure = material.head_operation.round_closure();
        if let Some(closure) = &head_closure {
            self.close_round(closure.clone())?;
        }
        let holder = material.head_operation.holder();
        if let Some(prior) = self.direction(holder) {
            if prior.head_operation.version() > material.head_operation.version() {
                return Ok(());
            }
            if prior.head_operation.version() == material.head_operation.version()
                && arkret_canonical::canonical_json_bytes(&prior.head_operation)?
                    != arkret_canonical::canonical_json_bytes(&material.head_operation)?
            {
                return Err(invalid(
                    "same Contact version carries conflicting operation bytes",
                ));
            }
            if let Some(closure) = &prior.closed_round
                && material.current_proof.contact_round_id.as_ref()
                    == Some(&closure.contact_round_id)
                && !material.current_proof.scope_instances.is_empty()
            {
                return Err(invalid("current response revives a known closed round"));
            }
            if prior.head_operation.version() == material.head_operation.version() {
                if prior
                    .current_proof
                    .as_ref()
                    .is_some_and(|p| p.issued_at > material.current_proof.issued_at)
                {
                    return Ok(());
                }
                if self.round_basis.is_some() && material.round_evidence.is_none() {
                    return Ok(());
                }
                if let (Some(old), Some(new)) = (&self.round_basis, &material.round_evidence)
                    && old.contact_round_id != new.contact_round_id
                {
                    return Err(invalid(
                        "same original operation establishes conflicting rounds",
                    ));
                }
            }
        }
        if self.initial_identity.is_none() {
            self.initial_identity = material.initial_identity.clone();
        }
        if let Some(initial) = &self.initial_identity {
            self.initial_root_floor = Some(initial.round.contact_round_id.clone());
        }
        let resets_round = material.round_evidence.is_none()
            && matches!(
                material.head_operation,
                ContactOperationEvidence::Request { .. } | ContactOperationEvidence::Reject { .. }
            );
        let reset_owner = holder.clone();
        self.directions
            .retain(|d| d.head_operation.holder() != holder);
        self.directions.push(ContactDirectionCurrent {
            head_operation: material.head_operation,
            scope_instances: material.current_proof.scope_instances.clone(),
            scope_grants: material.scope_grants,
            closed_round: head_closure
                .or_else(|| material.current_proof.closed_round.as_deref().cloned()),
            current_proof: Some(material.current_proof),
        });
        if let Some(basis) = material.round_evidence {
            let closed = self
                .observed_closure
                .as_ref()
                .is_some_and(|c| c.contact_round_id == basis.contact_round_id)
                || self.directions.iter().any(|d| {
                    d.closed_round
                        .as_ref()
                        .is_some_and(|c| c.contact_round_id == basis.contact_round_id)
                });
            if !closed
                || self
                    .round_basis
                    .as_ref()
                    .is_some_and(|known| known.contact_round_id == basis.contact_round_id)
            {
                self.round_basis = Some(basis);
                self.round_events = material.round_events.unwrap_or_default();
            }
        }
        if resets_round {
            self.round_basis = None;
            self.round_events.clear();
            for direction in &mut self.directions {
                if direction.head_operation.holder() != &reset_owner {
                    direction.scope_instances.clear();
                    direction.scope_grants.clear();
                    direction.current_proof = None;
                }
            }
        }
        Ok(())
    }
    pub fn evidence_bundle(&self) -> arkret_wire::Result<ContactRoundEvidenceBundle> {
        let basis = self
            .round_basis
            .as_ref()
            .ok_or_else(|| invalid("Contact round not established"))?;
        let initial = self
            .initial_identity
            .as_ref()
            .ok_or_else(|| invalid("Contact fixed first identity missing"))?;
        let [a, b] = self.directions.as_slice() else {
            return Err(invalid("Contact needs both original direction heads"));
        };
        let proofs = self
            .directions
            .iter()
            .map(|d| {
                d.current_proof
                    .clone()
                    .ok_or_else(|| invalid("Contact current proof missing"))
            })
            .collect::<arkret_wire::Result<Vec<_>>>()?;
        let mut grants = Vec::new();
        for grant in a.scope_grants.iter().chain(&b.scope_grants) {
            if !grants
                .iter()
                .any(|g: &ContactOperationEvidence| g.event().event_id == grant.event().event_id)
            {
                grants.push(grant.clone());
            }
        }
        let bundle = ContactRoundEvidenceBundle {
            contact_round_id: basis.contact_round_id.clone(),
            contact_round: basis.contact_round.clone(),
            request_receipts: basis.request_receipts.clone(),
            normal_response_receipt: basis.normal_response_receipt.clone(),
            glare_concurrency_attestations: basis.glare_concurrency_attestations.clone(),
            current_proofs: proofs,
            initial_identity: initial.clone(),
            scope_grants: grants,
            round_events: self.round_events.clone(),
            current_operations: [a.head_operation.clone(), b.head_operation.clone()],
        };
        bundle.validate_shape()?;
        Ok(bundle)
    }
}

/// Exact non-recursive control result commitment from the Contact contract.
pub fn peer_contact_control_result_digest(
    request_digest: &Hash,
    operation_kind: PeerContactControlKind,
    attestation: Option<&GlareConcurrencyAttestation>,
    current_proof: Option<&ContactCurrentProof>,
    material: Option<&ContactCurrentMaterial>,
) -> arkret_wire::Result<Hash> {
    #[derive(Serialize)]
    struct ResultTranscript<'a> {
        request_digest: &'a Hash,
        operation_kind: PeerContactControlKind,
        #[serde(skip_serializing_if = "Option::is_none")]
        glare_concurrency_attestation: Option<&'a GlareConcurrencyAttestation>,
        #[serde(skip_serializing_if = "Option::is_none")]
        current_proof: Option<&'a ContactCurrentProof>,
        #[serde(skip_serializing_if = "Option::is_none")]
        material: Option<&'a ContactCurrentMaterial>,
    }
    if (operation_kind == PeerContactControlKind::CurrentRefresh
        && (material.is_none() || attestation.is_some() || current_proof.is_some()))
        || (operation_kind == PeerContactControlKind::GlareFinalize
            && (attestation.is_none() || material.is_some()))
    {
        return Err(invalid(
            "control result branch contains inconsistent members",
        ));
    }
    Hash::new(arkret_canonical::domain_prefixed_canonical_sha256(
        "ak.peer-contact.control-result.v1",
        &ResultTranscript {
            request_digest,
            operation_kind,
            glare_concurrency_attestation: attestation,
            current_proof,
            material,
        },
    )?)
    .map_err(Into::into)
}
impl PeerContactControlReceipt {
    pub fn canonical_signing_bytes(&self) -> arkret_canonical::Result<Vec<u8>> {
        canonical_signing_bytes_without_signature(self)
    }
}

#[derive(Serialize)]
struct GlareSlotObservation<'a> {
    trust_domain_id: &'a TrustDomainId,
    subject_id: &'a ActorId,
    peer_id: &'a ActorId,
    contact_round_id: &'a Hash,
    request_event_ref: &'a EventId,
    version: u64,
    request_receipt_digests: &'a [Hash; 2],
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    observed_at: DateTime<Utc>,
    slot_state: &'static str,
}
#[derive(Serialize)]
struct UnsignedGlareConcurrencyAttestation {
    trust_domain_id: TrustDomainId,
    #[serde(skip_serializing_if = "Option::is_none")]
    initial_contact_round_id: Option<Hash>,
    contact_round_id: Hash,
    version: u64,
    request_event_ref: EventId,
    subject_id: ActorId,
    issuer_id: DidCoreId,
    peer_id: ActorId,
    request_receipt_digests: [Hash; 2],
    unconsumed_slot_checkpoint: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    observed_at: DateTime<Utc>,
}
impl GlareConcurrencyAttestation {
    pub fn slot_commitment(&self) -> arkret_wire::Result<Hash> {
        glare_slot_commitment(
            &self.trust_domain_id,
            &self.subject_id,
            &self.peer_id,
            &self.contact_round_id,
            &self.request_event_ref,
            self.version,
            &self.request_receipt_digests,
            self.observed_at,
        )
    }
    pub fn validate_slot_commitment(&self) -> arkret_wire::Result<()> {
        if self.version == 0
            || self.request_receipt_digests[0] == self.request_receipt_digests[1]
            || self.slot_commitment()? != self.unconsumed_slot_checkpoint
        {
            return Err(invalid(
                "glare source choice has an invalid bounded slot commitment",
            ));
        }
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn sign_with(
        trust_domain_id: TrustDomainId,
        initial_contact_round_id: Option<Hash>,
        contact_round_id: Hash,
        version: u64,
        request_event_ref: EventId,
        subject_id: ActorId,
        issuer_id: DidCoreId,
        peer_id: ActorId,
        request_receipt_digests: [Hash; 2],
        observed_at: DateTime<Utc>,
        sign: impl FnOnce(&[u8]) -> arkret_wire::Result<ProtocolSignature>,
    ) -> arkret_wire::Result<Self> {
        let unconsumed_slot_checkpoint = glare_slot_commitment(
            &trust_domain_id,
            &subject_id,
            &peer_id,
            &contact_round_id,
            &request_event_ref,
            version,
            &request_receipt_digests,
            observed_at,
        )?;
        let unsigned = UnsignedGlareConcurrencyAttestation {
            trust_domain_id,
            initial_contact_round_id,
            contact_round_id,
            version,
            request_event_ref,
            subject_id,
            issuer_id,
            peer_id,
            request_receipt_digests,
            unconsumed_slot_checkpoint,
            observed_at,
        };
        let signature = sign(&arkret_canonical::canonical_json_bytes(&unsigned)?)?;
        let result = Self {
            trust_domain_id: unsigned.trust_domain_id,
            initial_contact_round_id: unsigned.initial_contact_round_id,
            contact_round_id: unsigned.contact_round_id,
            version: unsigned.version,
            request_event_ref: unsigned.request_event_ref,
            subject_id: unsigned.subject_id,
            issuer_id: unsigned.issuer_id,
            peer_id: unsigned.peer_id,
            request_receipt_digests: unsigned.request_receipt_digests,
            unconsumed_slot_checkpoint: unsigned.unconsumed_slot_checkpoint,
            observed_at: unsigned.observed_at,
            signature,
        };
        result.validate_slot_commitment()?;
        Ok(result)
    }
}
#[allow(clippy::too_many_arguments)]
fn glare_slot_commitment(
    trust_domain_id: &TrustDomainId,
    subject_id: &ActorId,
    peer_id: &ActorId,
    contact_round_id: &Hash,
    request_event_ref: &EventId,
    version: u64,
    request_receipt_digests: &[Hash; 2],
    observed_at: DateTime<Utc>,
) -> arkret_wire::Result<Hash> {
    Hash::new(arkret_canonical::domain_prefixed_canonical_sha256(
        arkret_wire::DomainSeparationId::CONTACT_GLARE_UNCONSUMED_SLOT_V1,
        &GlareSlotObservation {
            trust_domain_id,
            subject_id,
            peer_id,
            contact_round_id,
            request_event_ref,
            version,
            request_receipt_digests,
            observed_at,
            slot_state: "glare_selected",
        },
    )?)
    .map_err(Into::into)
}
