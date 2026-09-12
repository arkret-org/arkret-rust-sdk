//! Protocol test material shared by every Arkret implementation.
//!
//! This crate exists because the same canonical signed Event, the same
//! standard subject vocabulary and the same pinned HLC template had been
//! re-derived independently in seven repositories, with two properties that
//! silently produce false green:
//!
//! * a structurally valid but cryptographically meaningless proof and a real Ed25519 proof have the
//!   **same wire shape**, so swapping one for the other changes what a test proves without changing
//!   whether it passes;
//! * the deterministic key, timestamp and HLC choices differ per repository with no mapping between
//!   them, so unifying a constructor without unifying its inputs silently rewrites every
//!   content-bound identifier.
//!
//! Both are addressed here rather than by convention. [`ProofFidelity`] makes
//! the first distinction a type the compiler and the test author can see, and
//! the builder takes its key material, clock and HLC as explicit inputs rather
//! than baking in one repository's choice.
//!
//! # Not a production surface
//!
//! `arkret-test-kit` is `publish = false`, is excluded from the workspace
//! `default-members`, and MUST only ever be reachable from a
//! `[dev-dependencies]` entry, a crate-level test-support feature, or an
//! explicitly audited test harness dependency.
//! `tools/test_kit_production_gate.py` enforces that across the workspace: it
//! derives signing keys from public strings, so a production build that can
//! reach it can mint any fixture actor's signature.

pub mod hlc;
pub mod keys;
pub mod negative;
pub mod proof;
pub mod signed_event;
pub mod subjects;

pub use arkret_event_draft::test_support::raw_projected_operation;
pub use arkret_wire::test_support::{
    RawProjectionFixtureParts, raw_event, raw_event_at, raw_event_for_actor_at,
    split_raw_projection_fixture_payload,
};
pub use hlc::{PINNED_HLC_NODE, PINNED_HLC_PHYSICAL, monotonic_floor_clock, pinned_hlc, wall_hlc};
pub use keys::{
    development_signing_key, development_signing_key_seed, development_verifying_key,
    seeded_signer, seeded_signer_for_seed,
};
pub use negative::{WireNegativeBody, wire_negative_from_sdk};
pub use proof::{ProofFidelity, StructuralOnlyPayloadSigner};
pub use signed_event::{
    FixtureClock, SignedEventFixture, SignedEventFixtureBuilder, sign_structural_only_event,
    sign_verifiable_event,
};
