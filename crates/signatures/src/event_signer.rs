//! High-level `sign_event` helper for Cokret Event Envelopes.
//!
//! S-1 (savfox SDK gap, 2026-05-27) — external Applet implementations
//! (savfox, gateway-server channels, etc.) were rolling their own
//! canonical-JSON + detached-JWS pipelines per Envelope. This module is
//! the single one-shot entry point: compute the canonical event bytes
//! (with `proofs` / `unsigned` removed), sign them with the supplied
//! [`cokret_core::MoveSigner`], and append a [`Proof`] to
//! `event.proofs`.
//!
//! Per spec `encoding.md` §6 / `event-and-patch.md` §3 the detached JWS
//! MUST sign the canonical **proof binding object**, NOT the raw canonical
//! event bytes:
//!
//! ```text
//! { event_digest, actor_id, verification_method, created_at, domain?, audience? }
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
//! [`cokret_signatures::verify_eddsa_detached_jws_proof`]
//! (`crates/signatures/src/proof.rs`), which rebuilds the same binding
//! object via [`cokret_core::Proof::canonical_binding_bytes`].

use chrono::{DateTime, Utc};
use cokret_core::{Audience, Error, Event, Hash, MoveSigner, Proof, Result, canonical, proof_kind};

/// Options threaded into [`sign_event`].
///
/// `domain` / `audience` are optional binding additions threaded into
/// the produced [`Proof`]; both default to `None`. `created_at`
/// defaults to `Utc::now()` when omitted so callers don't have to
/// stamp the wall clock themselves.
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

/// Sign an Event Envelope in-place: compute its canonical digest,
/// produce a detached JWS with `signer`, and append a [`Proof`] to
/// `event.proofs`.
///
/// The signing transcript covers canonical event bytes (with
/// `proofs` / `unsigned` removed). Because `executed_by` and
/// `authorization_ref` are top-level fields of the Envelope they are
/// already in the canonical event bytes when set. `domain` and
/// `audience` are folded into the [`Proof`] envelope and verified by
/// [`Proof::validate_binding`].
///
/// The produced [`Proof::payload_digest`] equals
/// [`cokret_core::Event::event_digest`].
///
/// Refuses to append if `event.proofs` already contains a [`Proof`]
/// produced by a different `verification_method` — pass a fresh
/// envelope (or pop existing proofs) to re-sign. Calling `sign_event`
/// again with the **same** signer is idempotent (replaces the existing
/// proof).
pub fn sign_event<S: MoveSigner + ?Sized>(
    event: &mut Event,
    signer: &S,
    verification_method: &str,
    options: SignEventOptions,
) -> Result<()> {
    // Refuse to mix proofs from different signers — caller mistake.
    if let Some(existing) = event.proofs.iter().find(|proof| {
        proof.verification_method != verification_method && proof.kind == proof_kind::DETACHED_JWS
    }) {
        return Err(Error::Protocol(format!(
            "sign_event refuses to append: event already carries a detached-jws proof for a \
             different verification_method '{}'",
            existing.verification_method
        )));
    }

    let canonical_bytes = canonical::canonical_json_bytes(&event.digest_payload()?)?;
    let payload_digest = Hash::new(canonical::sha256_digest(&canonical_bytes))?;

    let created_at = options.created_at.unwrap_or_else(Utc::now);

    // Per `encoding.md` §6 / `event-and-patch.md` §3 the detached JWS MUST
    // sign the canonical **proof binding object** — NOT the raw canonical
    // event bytes — so that `created_at`, `domain`, `audience` and
    // `verification_method` are cryptographically covered, not merely
    // compared as plaintext. `actor_id` in the binding object is the
    // Event envelope's `actor_id` field (spec §6 L201). The binding object
    // does not include `alg`/`jws`, so it can be built before signing.
    let mut proof = Proof {
        kind: proof_kind::DETACHED_JWS.to_owned(),
        alg: "EdDSA".to_owned(),
        verification_method: verification_method.to_owned(),
        event_digest: payload_digest.clone(),
        created_at,
        domain: options.domain,
        audience: options.audience,
        jws: String::new(),
    };
    let binding_bytes = proof.canonical_binding_bytes(&event.actor_id)?;
    let signature = signer.sign_payload(&binding_bytes)?;
    proof.alg = signature.alg;
    proof.jws = signature.jws;

    // Idempotent: replace any existing proof from the same verification
    // method (e.g. a re-sign with a refreshed `created_at`).
    if let Some(slot) = event
        .proofs
        .iter_mut()
        .find(|proof| proof.verification_method == verification_method)
    {
        *slot = proof;
    } else {
        event.proofs.push(proof);
    }

    debug_assert_eq!(event.event_digest()?, payload_digest.as_str());
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::{TimeZone, Utc};
    use cokret_core::move_event::Move;
    use cokret_core::{
        Audience, Did, Event, EventId, EventRequirements, Hash, Hlc, MoveSignature, MoveSigner,
        RealmId, Result, UnsignedMove, canonical,
    };
    use serde_json::json;

    use super::*;

    fn realm() -> RealmId {
        RealmId::new("ck:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap()
    }

    fn alice() -> Did {
        Did::new("did:web:alice.example").unwrap()
    }

    fn vm_alice() -> &'static str {
        "did:web:alice.example#key-1"
    }

    fn bob() -> Did {
        Did::new("did:web:bob.example").unwrap()
    }

    fn make_event() -> Event {
        Event {
            event_id: EventId::new("ck:event:01904100-0000-7000-8000-a0086f45c575").unwrap(),
            kind: "ck.message.create".into(),
            realm_id: realm(),
            actor_id: alice(),
            actor_seq: 1,
            created_at: Utc.with_ymd_and_hms(2026, 4, 26, 0, 0, 0).unwrap(),
            hlc: Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            prev_refs: Vec::new(),
            effective_scope: None,
            refs: Vec::new(),
            preconditions: Vec::new(),
            effects: Vec::new(),
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            requirements: EventRequirements::default(),
            redacts: None,
            payload: json!({ "body": "hello" }),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
        }
    }

    /// Minimal in-test signer that mimics a detached JWS over arbitrary
    /// canonical bytes. Mirrors the production
    /// `Ed25519DetachedJwsSigner` shape, but lives in-crate so the
    /// `sign_event` tests don't pull the `signer` feature in.
    struct StubMoveSigner {
        did: Did,
        kid: String,
    }

    impl StubMoveSigner {
        fn new(did: Did, kid: impl Into<String>) -> Self {
            Self {
                did,
                kid: kid.into(),
            }
        }
    }

    impl MoveSigner for StubMoveSigner {
        fn sign_move(&self, _unsigned: &UnsignedMove) -> Result<Move> {
            unreachable!("sign_event helper only calls sign_payload");
        }

        fn signer_did(&self) -> &Did {
            &self.did
        }

        fn verification_method_id(&self) -> &str {
            &self.kid
        }

        fn sign_payload(&self, canonical_bytes: &[u8]) -> Result<MoveSignature> {
            let payload_digest = Hash::new(canonical::sha256_digest(canonical_bytes))?;
            // Deterministic "signature" — sufficient for transcript
            // coverage tests; no Ed25519 dep required.
            let stub_jws = format!("stub..{}", payload_digest.as_str());
            Ok(MoveSignature {
                alg: "EdDSA".to_owned(),
                verification_method: self.kid.clone(),
                payload_digest,
                created_at: Utc::now(),
                jws: stub_jws,
            })
        }
    }

    #[test]
    fn sign_event_attaches_one_proof_matching_digest() {
        let mut event = make_event();
        let signer = StubMoveSigner::new(alice(), vm_alice());
        sign_event(&mut event, &signer, vm_alice(), SignEventOptions::new()).unwrap();
        assert_eq!(event.proofs.len(), 1);
        let digest = event.event_digest().unwrap();
        assert_eq!(event.proofs[0].event_digest.as_str(), digest);
        assert_eq!(event.proofs[0].verification_method, vm_alice());
        assert_eq!(event.proofs[0].kind, proof_kind::DETACHED_JWS);
        assert_eq!(event.proofs[0].alg, "EdDSA");
        // validate_proof_bindings (production) round-trips.
        event.validate_proof_bindings().unwrap();
    }

    #[test]
    fn sign_event_with_executed_by_signs_over_executed_by() {
        let mut without = make_event();
        let mut with = make_event();
        with.executed_by = Some(Did::new("did:web:applet.example").unwrap());

        let signer = StubMoveSigner::new(alice(), vm_alice());
        sign_event(&mut without, &signer, vm_alice(), SignEventOptions::new()).unwrap();
        sign_event(&mut with, &signer, vm_alice(), SignEventOptions::new()).unwrap();

        // The signing transcript MUST cover executed_by → the digests
        // and therefore the produced JWS must differ.
        assert_ne!(
            without.proofs[0].event_digest, with.proofs[0].event_digest,
            "executed_by must enter the signing transcript"
        );
        assert_ne!(without.proofs[0].jws, with.proofs[0].jws);
    }

    #[test]
    fn sign_event_with_authorization_ref_signs_over_it() {
        let mut without = make_event();
        let mut with = make_event();
        with.authorization_ref = Some("ck:grant:01904100-0000-7000-8000-aaaaaaaaaaaa".to_owned());

        let signer = StubMoveSigner::new(alice(), vm_alice());
        sign_event(&mut without, &signer, vm_alice(), SignEventOptions::new()).unwrap();
        sign_event(&mut with, &signer, vm_alice(), SignEventOptions::new()).unwrap();

        assert_ne!(
            without.proofs[0].event_digest, with.proofs[0].event_digest,
            "authorization_ref must enter the signing transcript"
        );
    }

    #[test]
    fn sign_event_with_options_binds_domain_and_audience() {
        let mut event = make_event();
        let signer = StubMoveSigner::new(alice(), vm_alice());
        let opts = SignEventOptions::new()
            .with_domain("api.example")
            .with_audience(Audience::Single("did:web:svc.example".to_owned()));
        sign_event(&mut event, &signer, vm_alice(), opts).unwrap();
        assert_eq!(event.proofs[0].domain.as_deref(), Some("api.example"));
        match &event.proofs[0].audience {
            Some(Audience::Single(value)) => assert_eq!(value, "did:web:svc.example"),
            other => panic!("expected single audience, got {other:?}"),
        }
    }

    #[test]
    fn sign_event_idempotent_against_redundant_call() {
        let mut event = make_event();
        let signer = StubMoveSigner::new(alice(), vm_alice());
        let pinned_at = Utc.with_ymd_and_hms(2026, 5, 26, 12, 0, 0).unwrap();
        sign_event(
            &mut event,
            &signer,
            vm_alice(),
            SignEventOptions::new().with_created_at(pinned_at),
        )
        .unwrap();
        assert_eq!(event.proofs.len(), 1);
        // Re-sign with the same signer + pinned timestamp: the existing
        // proof is replaced, not appended.
        sign_event(
            &mut event,
            &signer,
            vm_alice(),
            SignEventOptions::new().with_created_at(pinned_at),
        )
        .unwrap();
        assert_eq!(event.proofs.len(), 1, "re-sign must replace, not append");
        event.validate_proof_bindings().unwrap();
    }

    #[test]
    fn sign_event_rejects_when_proofs_already_populated_with_other_signer() {
        let mut event = make_event();
        let alice_signer = StubMoveSigner::new(alice(), vm_alice());
        sign_event(
            &mut event,
            &alice_signer,
            vm_alice(),
            SignEventOptions::new(),
        )
        .unwrap();

        let bob_kid = "did:web:bob.example#key-1";
        let bob_signer = StubMoveSigner::new(bob(), bob_kid);
        let err = sign_event(&mut event, &bob_signer, bob_kid, SignEventOptions::new())
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
        let mut event = make_event();
        let signer = StubMoveSigner::new(alice(), vm_alice());
        sign_event(&mut event, &signer, vm_alice(), SignEventOptions::new()).unwrap();
        event.validate_proof_bindings().unwrap();

        // Payload tamper: the recomputed canonical event digest changes, so
        // the signed proof binding no longer matches.
        let mut payload_tampered = event.clone();
        payload_tampered.payload = json!({ "body": "tampered" });
        let err = payload_tampered
            .validate_proof_bindings()
            .expect_err("payload tamper must fail binding validation");
        assert!(format!("{err}").contains("event_digest"), "got: {err}");

        // Proof tamper: swapping event_digest for another well-formed hash
        // must be rejected against the recomputed digest.
        let mut digest_tampered = event.clone();
        digest_tampered.proofs[0].event_digest =
            Hash::new("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                .unwrap();
        assert!(
            digest_tampered.validate_proof_bindings().is_err(),
            "proof event_digest tamper must fail binding validation"
        );

        // Top-level field tamper (actor_seq is inside the signed canonical
        // bytes): the digest moves, binding validation must fail.
        let mut field_tampered = event;
        field_tampered.actor_seq += 1;
        assert!(
            field_tampered.validate_proof_bindings().is_err(),
            "actor_seq tamper must fail binding validation"
        );
    }
}
