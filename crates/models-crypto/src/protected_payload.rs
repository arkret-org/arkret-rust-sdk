//! Orthogonal payload-protection types for durable Event payloads.
//!
//! These wrappers describe how a typed payload is carried. They do not create
//! a second Event envelope: a plain and an MLS-protected payload still travel
//! inside the same outer `Event` and retain the same CBA plane.

use std::marker::PhantomData;

use arkret_wire::{Error, Result};

use crate::EncryptedEnvelope;

/// A payload value carried in plaintext by a profile that permits plaintext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlainPayload<T>(T);

impl<T> PlainPayload<T> {
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(&self) -> &T {
        &self.0
    }

    #[must_use]
    pub fn into_value(self) -> T {
        self.0
    }
}

/// Associates a typed plaintext payload with its one canonical MLS envelope
/// content type. This prevents a ciphertext for one schema from being routed
/// and decoded as another payload type.
pub trait MlsPayloadType {
    const MLS_CONTENT_TYPE: &'static str;
}

/// An MLS encrypted envelope whose decrypted bytes are declared to contain
/// `T`. Construction validates both the envelope and the type-specific
/// `content_type`; the marker is not a wire field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsEncryptedPayload<T> {
    envelope: EncryptedEnvelope,
    marker: PhantomData<fn() -> T>,
}

impl<T: MlsPayloadType> MlsEncryptedPayload<T> {
    pub fn new(envelope: EncryptedEnvelope) -> Result<Self> {
        envelope.validate()?;
        if envelope.content_type != T::MLS_CONTENT_TYPE {
            return Err(Error::Protocol(format!(
                "MLS encrypted payload content_type must be {} for the selected payload type",
                T::MLS_CONTENT_TYPE
            )));
        }
        Ok(Self {
            envelope,
            marker: PhantomData,
        })
    }

    #[must_use]
    pub const fn envelope(&self) -> &EncryptedEnvelope {
        &self.envelope
    }

    #[must_use]
    pub fn into_envelope(self) -> EncryptedEnvelope {
        self.envelope
    }
}

impl<T: MlsPayloadType> TryFrom<EncryptedEnvelope> for MlsEncryptedPayload<T> {
    type Error = Error;

    fn try_from(envelope: EncryptedEnvelope) -> Result<Self> {
        Self::new(envelope)
    }
}

/// Closed protection choice for one typed payload. This axis is independent
/// from the outer Event's Data / Control / non-reducer submission plane.
#[derive(Clone, Debug, PartialEq, Eq)]
// A one-shot HTTP body/aggregate: it is built once per request, moved a
// handful of times, then dropped. Boxing the large variant would trade a
// free stack move for a heap allocation on every request and break the
// constructor/pattern shape in every downstream repository, so the size
// skew is accepted deliberately.
#[allow(clippy::large_enum_variant)]
pub enum ProtectedPayload<T> {
    Plain(PlainPayload<T>),
    Mls(MlsEncryptedPayload<T>),
}

impl<T> From<PlainPayload<T>> for ProtectedPayload<T> {
    fn from(payload: PlainPayload<T>) -> Self {
        Self::Plain(payload)
    }
}

impl<T> From<MlsEncryptedPayload<T>> for ProtectedPayload<T> {
    fn from(payload: MlsEncryptedPayload<T>) -> Self {
        Self::Mls(payload)
    }
}
