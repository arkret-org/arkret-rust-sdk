//! The canonical signed Event, built once.
//!
//! Fixture construction shares the SDK's `raw Event -> finalize -> proof`
//! pipeline. Complete-Event entry points preserve fields supplied by the host;
//! the builder provides fixed defaults for isolated tests and explicit inputs
//! for live fixtures. Real and placeholder proofs carry distinct fidelity.

use arkret_canonical::DigestSuite;
use arkret_signatures::{Ed25519PayloadSigner, EventSigner, SignEventOptions, sign_event};
use arkret_wire::{ActorId, AuthoredEvent, Event, Result, ScopeRef};
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::proof::{ProofFidelity, StructuralOnlyPayloadSigner};

/// The default authoring instant for a fixture that does not inject a clock.
///
/// A static instant is correct for anything that never reaches a live service.
/// It is wrong for anything that does: it lands before the Realm bootstrap the
/// service already accepted. Live callers should inject their own clock.
pub const FIXTURE_CREATED_AT: &str = "2026-01-01T00:00:00Z";

/// An injected authoring clock.
pub type FixtureClock = Box<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// A signed Event together with what its proof actually establishes.
///
/// There is deliberately no unconditional accessor that yields the bare
/// `Event`: unwrapping states which fidelity the call site is relying on, so a
/// later swap of the signer turns into a panic instead of a silent change of
/// what the test proves.
#[derive(Debug)]
pub struct SignedEventFixture {
    event: Event,
    fidelity: ProofFidelity,
}

impl SignedEventFixture {
    /// What this Event's proof establishes.
    #[must_use]
    pub const fn fidelity(&self) -> ProofFidelity {
        self.fidelity
    }

    /// Borrow the Event without asserting a fidelity.
    #[must_use]
    pub const fn event(&self) -> &Event {
        &self.event
    }

    /// Take the Event, asserting that its proof really verifies.
    ///
    /// # Panics
    ///
    /// Panics if the Event was signed by a placeholder signer.
    #[must_use]
    pub fn expect_verifiable(self) -> Event {
        assert_eq!(
            self.fidelity,
            ProofFidelity::Verifiable,
            "this call site relies on a proof that verifies, but the fixture carries a \
             structural-only placeholder"
        );
        self.event
    }

    /// Take the Event, asserting that its proof is a placeholder.
    ///
    /// # Panics
    ///
    /// Panics if the Event carries a real signature, which would mean the case
    /// is no longer exercising the envelope-shape path it claims to.
    #[must_use]
    pub fn expect_structural_only(self) -> Event {
        assert_eq!(
            self.fidelity,
            ProofFidelity::StructuralOnly,
            "this call site is a shape-only case, but the fixture carries a real signature"
        );
        self.event
    }
}

/// Builder for one canonically signed Event.
pub struct SignedEventFixtureBuilder {
    kind: String,
    scope_ref: ScopeRef,
    actor_id: ActorId,
    payload: Value,
    clock: FixtureClock,
    digest_suite: DigestSuite,
}

impl SignedEventFixtureBuilder {
    /// An Event of `kind` in `scope_ref`, authored by `actor_id`.
    #[must_use]
    pub fn new(
        kind: impl Into<String>,
        scope_ref: ScopeRef,
        actor_id: ActorId,
        payload: Value,
    ) -> Self {
        Self {
            kind: kind.into(),
            scope_ref,
            actor_id,
            payload,
            clock: Box::new(fixed_fixture_instant),
            digest_suite: DigestSuite::Sha256,
        }
    }

    /// Inject the authoring clock.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> DateTime<Utc> + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    /// Pin the authoring instant.
    #[must_use]
    pub fn with_created_at(self, created_at: DateTime<Utc>) -> Self {
        self.with_clock(move || created_at)
    }

    /// Select the digest suite that produces the Event identity and binds the
    /// proof.
    #[must_use]
    pub fn with_digest_suite(mut self, digest_suite: DigestSuite) -> Self {
        self.digest_suite = digest_suite;
        self
    }

    /// Build the unsigned Event.
    ///
    /// # Errors
    ///
    /// Returns the wire error if the envelope is not a valid Event.
    pub fn build_unsigned(self) -> Result<Event> {
        let created_at = (self.clock)();
        arkret_wire::test_support::raw_event_for_actor_at(
            self.kind,
            self.scope_ref,
            self.actor_id,
            self.payload,
            created_at,
        )
    }

    /// Sign with a real Ed25519 key.
    ///
    /// # Errors
    ///
    /// Returns the wire error if the envelope does not finalize or the proof
    /// cannot be attached.
    pub fn sign_verifiable(self, signer: &Ed25519PayloadSigner) -> Result<SignedEventFixture> {
        let digest_suite = self.digest_suite;
        sign_verifiable_event(self.build_unsigned()?, signer, digest_suite)
    }

    /// Sign with a placeholder that carries no key material.
    ///
    /// # Errors
    ///
    /// Returns the wire error if the envelope does not finalize or the proof
    /// cannot be attached.
    pub fn sign_structural_only(
        self,
        signer: &StructuralOnlyPayloadSigner,
    ) -> Result<SignedEventFixture> {
        let digest_suite = self.digest_suite;
        sign_structural_only_event(self.build_unsigned()?, signer, digest_suite)
    }
}

/// Attach a real Ed25519 proof to a complete Event.
///
/// Preserves caller-supplied fields and uses the Event's creation time for the
/// proof. Finalizes the content-derived identity after all fields are set.
///
/// # Errors
///
/// Returns an error if the Event cannot finalize or its proof cannot be attached.
pub fn sign_verifiable_event(
    event: Event,
    signer: &Ed25519PayloadSigner,
    digest_suite: DigestSuite,
) -> Result<SignedEventFixture> {
    let created_at = event.created_at;
    let event = attach_proof(event, signer, created_at, digest_suite)?;
    Ok(SignedEventFixture {
        event,
        fidelity: ProofFidelity::Verifiable,
    })
}

/// Attach a structural-only placeholder proof to a complete Event.
///
/// Preserves caller-supplied fields and uses the Event's creation time for the
/// proof. Finalizes the content-derived identity after all fields are set.
///
/// # Errors
///
/// Returns an error if the Event cannot finalize or its proof cannot be attached.
pub fn sign_structural_only_event(
    event: Event,
    signer: &StructuralOnlyPayloadSigner,
    digest_suite: DigestSuite,
) -> Result<SignedEventFixture> {
    let created_at = event.created_at;
    let event = attach_proof(event, signer, created_at, digest_suite)?;
    Ok(SignedEventFixture {
        event,
        fidelity: ProofFidelity::StructuralOnly,
    })
}

fn attach_proof<S: EventSigner + ?Sized>(
    event: Event,
    signer: &S,
    created_at: DateTime<Utc>,
    digest_suite: DigestSuite,
) -> Result<Event> {
    let mut authored = AuthoredEvent::finalize_with_digest_suite(event, digest_suite)?;
    sign_event(
        &mut authored,
        signer,
        SignEventOptions::new().with_created_at(created_at),
    )
    .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
    Ok(authored.into_event())
}

fn fixed_fixture_instant() -> DateTime<Utc> {
    FIXTURE_CREATED_AT
        .parse::<DateTime<Utc>>()
        .expect("the default fixture instant is a valid timestamp")
}
