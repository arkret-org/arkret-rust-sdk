//! One-shot producer Event proof construction.

use arkret_canonical::{base64url_encode, canonical};
use arkret_wire::{Audience, AuthoredEvent, ProducerEventProof, proof_kind};
use chrono::{DateTime, Utc};

use crate::{Error, EventSigner, Result};

/// Optional producer-proof binding members.
#[derive(Clone, Debug, Default)]
pub struct SignEventOptions {
    pub domain: Option<String>,
    pub audience: Option<Audience>,
    pub created_at: Option<DateTime<Utc>>,
}

impl SignEventOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    pub fn with_audience(mut self, audience: Audience) -> Self {
        self.audience = Some(audience);
        self
    }

    pub fn with_created_at(mut self, created_at: DateTime<Utc>) -> Self {
        self.created_at = Some(created_at);
        self
    }
}

/// Sign the canonical producer-proof binding for an already finalized Event.
///
/// Event proofs authenticate producer bytes only. Realm acceptance and order
/// are authenticated separately by the governance Station's `RealmCommit`.
pub fn sign_event<S: EventSigner + ?Sized>(
    event: &mut AuthoredEvent,
    signer: &S,
    options: SignEventOptions,
) -> Result<()> {
    if signer.algorithm() != "Ed25519" {
        return Err(Error::Protocol(
            "Arkret v1 producer Event proofs require Ed25519".to_owned(),
        ));
    }
    event.verify_identity()?;
    let verification_method = arkret_wire::DidUrl::new(signer.verification_method().to_owned())
        .map_err(|error| Error::Protocol(error.to_owned()))?;
    if let Some(existing) = event.proofs.iter().find(|proof| {
        proof.kind == proof_kind::DETACHED_JWS && proof.verification_method != verification_method
    }) {
        return Err(Error::Protocol(format!(
            "Event already carries a producer proof for {}",
            existing.verification_method
        )));
    }

    let event_digest = arkret_wire::Hash::new(canonical::digest(
        event.digest_suite(),
        canonical::canonical_json_bytes(&event.digest_payload()?)?,
    ))?;
    let mut proof = ProducerEventProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method,
        event_digest,
        created_at: canonical::normalize_timestamp_canonical(
            options.created_at.unwrap_or_else(Utc::now),
        ),
        domain: options.domain,
        audience: options.audience,
        proof_purpose: None,
        jws: String::new(),
    };
    let binding = proof.canonical_binding_bytes(&event.actor_id)?;
    let signature = signer
        .sign(&binding)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    let header = base64url_encode(br#"{"alg":"Ed25519"}"#);
    proof.jws = format!("{header}..{}", base64url_encode(signature));
    event.attach_proof(proof);
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_wire::{ActorId, DidCoreId, Event, EventId, RealmId, ScopeRef};
    use chrono::TimeZone;
    use ed25519_dalek::SigningKey;
    use serde_json::json;

    use super::*;
    use crate::Ed25519DetachedJwsSigner;

    #[test]
    fn signs_current_minimal_event_shape() {
        let event_id = EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [7; 32]);
        let realm_id = RealmId::from_event_id(&event_id);
        let event = Event {
            event_id,
            kind: "ak.message.create".into(),
            realm_id: realm_id.clone(),
            scope_ref: ScopeRef::Realm { realm_id },
            actor_id: ActorId::service(DidCoreId::new("ak:did_core:web:alice.example").unwrap()),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            created_at: Utc.with_ymd_and_hms(2026, 9, 16, 0, 0, 0).unwrap(),
            refs: Vec::new(),
            payload: BTreeMap::from([("body".to_owned(), json!("hello"))]),
            proofs: Vec::new(),
        };
        let mut authored =
            AuthoredEvent::finalize_with_digest_suite(event, arkret_canonical::DigestSuite::Sha256)
                .unwrap();
        let signer = Ed25519DetachedJwsSigner::new(
            SigningKey::from_bytes(&[9; 32]),
            "did:web:alice.example#key-1",
        );
        sign_event(&mut authored, &signer, SignEventOptions::new()).unwrap();
        assert_eq!(authored.proofs.len(), 1);
        authored
            .validate_proof_bindings_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
    }
}
