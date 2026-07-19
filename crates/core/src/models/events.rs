//! Event Envelope wire models, re-exported from `arkret_wire::event_envelope`.
//!
//! The payload-agnostic envelope container (struct, limits, canonical
//! digest computation, proof-binding checks, and the structural submit
//! gate) lives in `arkret-wire`. Kind-specific strongly-typed payload
//! accessors and the schema-registry submit gate are layered on top in
//! [`super::event_accessors`].

pub use arkret_wire::event_envelope::*;
