//! High-level `sign_event` helper for Arkret Event Envelopes.
//!
//! S-1 (savfox SDK gap, 2026-05-27) — external Applet implementations
//! (savfox, gateway-server channels, etc.) were rolling their own
//! canonical-JSON + detached-JWS pipelines per Envelope. This module is
//! the single one-shot entry point: compute the canonical event bytes
//! (with `proofs` / `unsigned` removed), sign them with the supplied
//! [`arkret_wire::PayloadSigner`], and append a [`ProducerEventProof`] to
//! `event.proofs`.
//!
//! Per spec `encoding.md` §6 / `event-and-patch.md` §3 the detached JWS
//! MUST sign the canonical **proof binding object**, NOT the raw canonical
//! event bytes:
//!
//! ```text
//! { event_digest, actor_id, verification_method,
//!   signer_resolution_evidence_ref?, signer_resolution_evidence_digest?,
//!   created_at, domain?, audience? }
//! ```
//!
//! where `event_digest = sha256(canonical event bytes with proofs/unsigned
//! removed)` and `actor_id` is the Event envelope's `actor_id` field. This
//! is what cryptographically covers `created_at`, `domain`, `audience` and
//! `verification_method` — plaintext-only comparison of those fields would
//! leave them tamperable. `executed_by` / `authorization_ref` are covered
//! transitively via `event_digest` (they are top-level Envelope fields).
//!
//! The companion verification path is
//! [`crate::proof::verify_ed25519_detached_jws_proof`]
//! (`crates/signatures/src/proof.rs`), which rebuilds the same binding
//! object via [`arkret_wire::ProducerEventProof::canonical_binding_bytes`].

use arkret_canonical::canonical;
use arkret_wire::{
    Audience, AuthoredEvent, DidUrl, Hash, PayloadSigner, ProducerEventProof, SignerEvidenceRef,
    proof_kind,
};
use chrono::{DateTime, Utc};

use crate::{Error, Result};

/// Options threaded into [`sign_event`].
///
/// `domain`, `audience`, and the direct-regime signer-resolution evidence
/// pair are optional binding additions threaded into the produced [`ProducerEventProof`].
/// They default to `None`. `created_at`
/// defaults to `Utc::now()` when omitted so callers don't have to
/// stamp the wall clock themselves.
#[derive(Clone, Debug, Default)]
pub struct SignEventOptions {
    pub domain: Option<String>,
    pub audience: Option<Audience>,
    pub created_at: Option<DateTime<Utc>>,
    pub signer_resolution_evidence_ref: Option<SignerEvidenceRef>,
    pub signer_resolution_evidence_digest: Option<Hash>,
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

/// Sign an [`AuthoredEvent`] in place: compute its canonical digest,
/// produce a detached JWS with `signer`, and attach a [`ProducerEventProof`].
///
/// The signing transcript covers canonical event bytes (with
/// `proofs` / `unsigned` removed). Because `executed_by` and
/// `authorization_ref` are top-level fields of the Envelope they are
/// already in the canonical event bytes when set. `domain` and
/// `audience` are folded into the [`ProducerEventProof`] envelope and verified by
/// [`ProducerEventProof::validate_binding`].
///
/// The produced `ProducerEventProof::payload_digest` equals
/// [`arkret_wire::Event::event_digest`].
///
/// The input is an [`AuthoredEvent`], not a bare `Event`, because signing comes
/// *after* the authoring boundary rather than being part of it: a caller that
/// still has producer fields to write does not yet have anything to sign. This
/// function re-proves that boundary and fails closed on a mismatch instead of
/// quietly re-deriving `event_id`. The old silent refresh hid exactly that
/// caller error, and let anything that had already read the pre-refresh id
/// persist an identity no Event would ever carry.
///
/// The digest suite comes from the `AuthoredEvent`, so the proof can never be
/// bound under a suite other than the one that produced the identity.
///
/// Refuses to attach if the event already carries a [`ProducerEventProof`] from a
/// different `verification_method` — clear the proofs to re-sign with another
/// key. Calling `sign_event` again with the **same** signer is idempotent
/// (replaces the existing proof).
pub fn sign_event<S: PayloadSigner + ?Sized>(
    event: &mut AuthoredEvent,
    signer: &S,
    verification_method: &DidUrl,
    options: SignEventOptions,
) -> Result<()> {
    let digest_suite = event.digest_suite();
    event.verify_identity()?;

    // Refuse to mix proofs from different signers — caller mistake.
    if let Some(existing) = event
        .proofs
        .iter()
        .filter_map(|proof| proof.as_producer())
        .find(|proof| {
            &proof.verification_method != verification_method
                && proof.kind == proof_kind::DETACHED_JWS
        })
    {
        return Err(Error::Protocol(format!(
            "sign_event refuses to append: event already carries a detached-jws proof for a \
             different verification_method '{}'",
            existing.verification_method
        )));
    }

    let canonical_bytes = canonical::canonical_json_bytes(&event.digest_payload()?)?;
    let payload_digest = Hash::new(canonical::digest(digest_suite, &canonical_bytes))?;

    let created_at =
        canonical::normalize_timestamp_canonical(options.created_at.unwrap_or_else(Utc::now));

    // Per `encoding.md` §6 / `event-and-patch.md` §3 the detached JWS MUST
    // sign the canonical **proof binding object** — NOT the raw canonical
    // event bytes — so that `created_at`, `domain`, `audience` and
    // `verification_method` are cryptographically covered, not merely
    // compared as plaintext. `actor_id` in the binding object is the
    // Event envelope's `actor_id` field (spec §6 L201). The binding object
    // does not include `alg`/`jws`, so it can be built before signing.
    let mut proof = ProducerEventProof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        verification_method: verification_method.clone(),
        event_digest: payload_digest.clone(),
        signer_resolution_evidence_ref: options.signer_resolution_evidence_ref,
        signer_resolution_evidence_digest: options.signer_resolution_evidence_digest,
        created_at,
        domain: options.domain,
        audience: options.audience,
        proof_purpose: None,
        jws: String::new(),
    };
    proof.validate_signer_resolution_evidence_pair()?;
    let binding_bytes = proof.canonical_binding_bytes(&event.actor_id)?;
    let signature = signer.sign_payload(&binding_bytes)?;
    proof.jws = signature.jws;

    // Idempotent: replace any existing proof from the same verification
    // method (e.g. a re-sign with a refreshed `created_at`).
    event.attach_proof(proof.into());

    debug_assert_eq!(
        canonical::digest(digest_suite, canonical_bytes),
        payload_digest.as_str()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_wire::{
        Audience, AuthoredEvent, Did, DidCoreId, Event, EventId, EventRequirements, Hash, Hlc,
        PayloadSignature, PayloadSigner, RealmId, Result as WireResult, canonical,
    };
    use chrono::{DateTime, TimeZone, Utc};
    use serde_json::json;

    use super::*;

    const SUITE: arkret_canonical::DigestSuite = arkret_canonical::DigestSuite::Sha256;

    fn realm() -> RealmId {
        RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x65; 32],
        ))
    }

    fn alice() -> Did {
        Did::new("did:web:alice.example").unwrap()
    }

    fn vm_alice() -> DidUrl {
        DidUrl::new("did:web:alice.example#key-1").unwrap()
    }

    fn bob() -> Did {
        Did::new("did:web:bob.example").unwrap()
    }

    fn make_event() -> Event {
        Event {
            event_id: EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [0xa0; 32]),
            kind: "ak.message.create".into(),
            realm_id: realm(),
            scope_ref: arkret_wire::ScopeRef::Realm { realm_id: realm() },
            actor_id: arkret_wire::project_did_to_core_id(&alice()).unwrap(),
            station_id: arkret_wire::project_did_to_core_id(&alice()).unwrap(),
            actor_seq: 1,
            created_at: Utc.with_ymd_and_hms(2026, 4, 26, 0, 0, 0).unwrap(),
            hlc: Some(Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()),
            prev_refs: Vec::new(),
            refs: Vec::new(),
            preconditions: Vec::new(),
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            requirements: EventRequirements::default(),
            payload: BTreeMap::from([("body".to_owned(), json!("hello"))]),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            unsigned: BTreeMap::new(),
            causal_refs: Vec::new(),
            proofs: Vec::new(),
        }
    }

    /// `make_event` finished: the identity derived once from that content.
    fn authored() -> AuthoredEvent {
        AuthoredEvent::finalize_with_digest_suite(make_event(), SUITE).unwrap()
    }

    /// Minimal in-test signer that mimics a detached JWS over arbitrary
    /// canonical bytes. Mirrors the production
    /// `Ed25519DetachedJwsSigner` shape, but lives in-crate so the
    /// `sign_event` tests don't pull the `signer` feature in.
    struct StubPayloadSigner {
        did: Did,
        kid: DidUrl,
    }

    impl StubPayloadSigner {
        fn new(did: Did, kid: DidUrl) -> Self {
            Self { did, kid }
        }
    }

    impl PayloadSigner for StubPayloadSigner {
        fn signer_did(&self) -> &Did {
            &self.did
        }

        fn verification_method_id(&self) -> &DidUrl {
            &self.kid
        }

        fn sign_payload(&self, canonical_bytes: &[u8]) -> WireResult<PayloadSignature> {
            let payload_digest = Hash::new(canonical::sha256_digest(canonical_bytes))?;
            // Deterministic "signature" — sufficient for transcript
            // coverage tests; no Ed25519 dep required. Only the digest hex
            // goes into the signature segment: the wire form is a detached
            // compact JWS and `sha256:` is not a base64url character.
            let stub_jws = format!(
                "eyJhbGciOiJFZDI1NTE5In0..{}",
                payload_digest
                    .as_str()
                    .rsplit(':')
                    .next()
                    .unwrap_or_default()
            );
            Ok(PayloadSignature {
                verification_method: self.kid.clone(),
                payload_digest,
                created_at: Utc::now(),
                jws: stub_jws,
            })
        }

        fn sign_notary_payload_with_digest_suite(
            &self,
            canonical_bytes: &[u8],
            digest_suite: arkret_canonical::DigestSuite,
        ) -> WireResult<PayloadSignature> {
            let mut signature = self.sign_payload(canonical_bytes)?;
            signature.payload_digest = Hash::new(canonical::digest(digest_suite, canonical_bytes))?;
            Ok(signature)
        }
    }

    #[test]
    fn sign_event_attaches_one_proof_matching_digest() {
        let mut event = authored();
        let signer = StubPayloadSigner::new(alice(), vm_alice());
        sign_event(&mut event, &signer, &vm_alice(), SignEventOptions::new()).unwrap();
        assert_eq!(event.proofs.len(), 1);
        let digest = event
            .event_digest_with_digest_suite(arkret_canonical::DigestSuite::Sha256)
            .unwrap();
        let proof = event.proofs[0].as_producer().unwrap();
        assert_eq!(proof.event_digest.as_str(), digest);
        assert_eq!(proof.verification_method, vm_alice());
        assert_eq!(proof.kind, proof_kind::DETACHED_JWS);
        assert!(!proof.jws.is_empty());
        // validate_proof_bindings (production) round-trips.
        event
            .validate_proof_bindings_with_digest_suite(SUITE)
            .unwrap();
    }

    /// Authoring must be finished BEFORE signing, and signing must not move
    /// the identity. The old behavior re-derived `event_id` inside
    /// `sign_event`, which silently repaired a caller that was still writing
    /// producer fields — and orphaned every id already read off that draft.
    #[test]
    fn sign_event_does_not_move_the_authored_identity() {
        let mut event = make_event();
        event.actor_seq = 42;
        event.prev_refs = vec![EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x42; 32],
        )];
        event.hlc = Some(Hlc::new("01970e589d21-0042-a13f9c2e").unwrap());
        let mut event = AuthoredEvent::finalize_with_digest_suite(event, SUITE).unwrap();
        let authored_event_id = event.event_id().clone();

        let signer = StubPayloadSigner::new(alice(), vm_alice());
        sign_event(&mut event, &signer, &vm_alice(), SignEventOptions::new()).unwrap();

        assert_eq!(event.event_id(), &authored_event_id);
        event.verify_identity().unwrap();
        event
            .validate_proof_bindings_with_digest_suite(SUITE)
            .unwrap();
    }

    #[test]
    fn sign_event_uses_the_realm_suite_the_event_was_authored_under() {
        let mut event = AuthoredEvent::finalize_with_digest_suite(
            make_event(),
            arkret_canonical::DigestSuite::Blake3,
        )
        .unwrap();
        let signer = StubPayloadSigner::new(alice(), vm_alice());
        sign_event(&mut event, &signer, &vm_alice(), SignEventOptions::new()).unwrap();
        assert!(
            event.proofs[0]
                .as_producer()
                .unwrap()
                .event_digest
                .as_str()
                .starts_with("blake3:")
        );
    }

    #[test]
    fn sign_event_with_executed_by_signs_over_executed_by() {
        let mut without = authored();
        let mut with = make_event();
        with.executed_by = Some(DidCoreId::new("ak:did_core:web:applet.example").unwrap());
        let mut with = AuthoredEvent::finalize_with_digest_suite(with, SUITE).unwrap();

        let signer = StubPayloadSigner::new(alice(), vm_alice());
        sign_event(&mut without, &signer, &vm_alice(), SignEventOptions::new()).unwrap();
        sign_event(&mut with, &signer, &vm_alice(), SignEventOptions::new()).unwrap();

        // The signing transcript MUST cover executed_by → the digests
        // and therefore the produced JWS must differ.
        assert_ne!(
            without.proofs[0].as_producer().unwrap().event_digest,
            with.proofs[0].as_producer().unwrap().event_digest,
            "executed_by must enter the signing transcript"
        );
        assert_ne!(
            without.proofs[0].as_producer().unwrap().jws,
            with.proofs[0].as_producer().unwrap().jws
        );
    }

    #[test]
    fn sign_event_with_authorization_ref_signs_over_it() {
        let mut without = authored();
        let mut with = make_event();
        with.authorization_ref = Some(
            arkret_wire::AuthorizationRef::new(
                "ak:grant:AUiSHUfqumU5_UtRrOIga2jjSmucw5MpSQdam3TtzPQu",
            )
            .unwrap(),
        );
        let mut with = AuthoredEvent::finalize_with_digest_suite(with, SUITE).unwrap();

        let signer = StubPayloadSigner::new(alice(), vm_alice());
        sign_event(&mut without, &signer, &vm_alice(), SignEventOptions::new()).unwrap();
        sign_event(&mut with, &signer, &vm_alice(), SignEventOptions::new()).unwrap();

        assert_ne!(
            without.proofs[0].as_producer().unwrap().event_digest,
            with.proofs[0].as_producer().unwrap().event_digest,
            "authorization_ref must enter the signing transcript"
        );
    }

    #[test]
    fn sign_event_with_options_binds_domain_and_audience() {
        let mut event = authored();
        let signer = StubPayloadSigner::new(alice(), vm_alice());
        let opts = SignEventOptions::new()
            .with_domain("api.example")
            .with_audience(Audience::Single("did:web:svc.example".to_owned()));
        sign_event(&mut event, &signer, &vm_alice(), opts).unwrap();
        let proof = event.proofs[0].as_producer().unwrap();
        assert_eq!(proof.domain.as_deref(), Some("api.example"));
        match &proof.audience {
            Some(Audience::Single(value)) => assert_eq!(value, "did:web:svc.example"),
            other => panic!("expected single audience, got {other:?}"),
        }
    }

    #[test]
    fn sign_event_normalizes_proof_timestamp_to_canonical_milliseconds() {
        let mut event = authored();
        let signer = StubPayloadSigner::new(alice(), vm_alice());
        let subsecond = DateTime::parse_from_rfc3339("2026-05-26T12:00:00.987654Z")
            .unwrap()
            .with_timezone(&Utc);

        sign_event(
            &mut event,
            &signer,
            &vm_alice(),
            SignEventOptions::new().with_created_at(subsecond),
        )
        .unwrap();

        let proof = serde_json::to_value(&event.proofs[0]).unwrap();
        assert_eq!(proof["created_at"], json!("2026-05-26T12:00:00.987Z"));
        event
            .validate_proof_bindings_with_digest_suite(SUITE)
            .unwrap();
    }

    #[test]
    fn sign_event_idempotent_against_redundant_call() {
        let mut event = authored();
        let signer = StubPayloadSigner::new(alice(), vm_alice());
        let pinned_at = Utc.with_ymd_and_hms(2026, 5, 26, 12, 0, 0).unwrap();
        sign_event(
            &mut event,
            &signer,
            &vm_alice(),
            SignEventOptions::new().with_created_at(pinned_at),
        )
        .unwrap();
        assert_eq!(event.proofs.len(), 1);
        // Re-sign with the same signer + pinned timestamp: the existing
        // proof is replaced, not appended.
        sign_event(
            &mut event,
            &signer,
            &vm_alice(),
            SignEventOptions::new().with_created_at(pinned_at),
        )
        .unwrap();
        assert_eq!(event.proofs.len(), 1, "re-sign must replace, not append");
        event
            .validate_proof_bindings_with_digest_suite(SUITE)
            .unwrap();
    }

    #[test]
    fn sign_event_rejects_when_proofs_already_populated_with_other_signer() {
        let mut event = authored();
        let alice_signer = StubPayloadSigner::new(alice(), vm_alice());
        sign_event(
            &mut event,
            &alice_signer,
            &vm_alice(),
            SignEventOptions::new(),
        )
        .unwrap();

        let bob_kid = DidUrl::new("did:web:bob.example#key-1").unwrap();
        let bob_signer = StubPayloadSigner::new(bob(), bob_kid.clone());
        let err = sign_event(&mut event, &bob_signer, &bob_kid, SignEventOptions::new())
            .expect_err("re-signing under a different VM must be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("different verification_method") || msg.contains("verification_method"),
            "got: {msg}"
        );
    }

    /// SDK-TEST-06: tampering with a signed event (payload or proof fields)
    /// MUST fail the event-signature binding check — the happy-path tests
    /// above never exercised the reject arm of `validate_proof_bindings`.
    #[test]
    fn tampered_event_fails_proof_binding_validation() {
        let mut authored = authored();
        let signer = StubPayloadSigner::new(alice(), vm_alice());
        sign_event(&mut authored, &signer, &vm_alice(), SignEventOptions::new()).unwrap();
        authored
            .validate_proof_bindings_with_digest_suite(SUITE)
            .unwrap();
        let event = authored.into_event();

        // Payload tamper: the recomputed canonical event digest changes, so
        // the signed proof binding no longer matches.
        let mut payload_tampered = event.clone();
        payload_tampered.payload = BTreeMap::from([("body".to_owned(), json!("tampered"))]);
        let err = payload_tampered
            .validate_proof_bindings_with_digest_suite(SUITE)
            .expect_err("payload tamper must fail binding validation");
        assert!(format!("{err}").contains("event_digest"), "got: {err}");

        // Proof tamper: swapping event_digest for another well-formed hash
        // must be rejected against the recomputed digest.
        let mut digest_tampered = event.clone();
        digest_tampered.proofs[0]
            .as_producer_mut()
            .unwrap()
            .event_digest =
            Hash::new("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap();
        assert!(
            digest_tampered
                .validate_proof_bindings_with_digest_suite(SUITE)
                .is_err(),
            "proof event_digest tamper must fail binding validation"
        );

        // Top-level field tamper (actor_seq is inside the signed canonical
        // bytes): the digest moves, binding validation must fail.
        let mut field_tampered = event;
        field_tampered.actor_seq += 1;
        assert!(
            field_tampered
                .validate_proof_bindings_with_digest_suite(SUITE)
                .is_err(),
            "actor_seq tamper must fail binding validation"
        );
    }
}
