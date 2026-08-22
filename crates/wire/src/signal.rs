//! Signal Extension envelope (`zh/sync/signal.md`).
//!
//! A Signal is a peer of Event and Device Message, not a subtype: an Event is a
//! durable signed fact that enters the reducer and federates, while a Signal is
//! a momentary encrypted announcement with no durable effect.
//!
//! There is exactly one encrypted envelope and one live rail. There is no
//! plaintext branch: an implementation that cannot verify encrypted signals for
//! a scope MUST withdraw the scope capability rather than fall back.
//!
//! The only product classification a service sees is [`SignalClass`].
//! The exact payload type, the Strand / Message / Call / receipt target and
//! the sender sequence live inside `encrypted_payload` and are never
//! reconstructible from the outer header.
//!
//! Device verification, secret distribution and history recovery do NOT
//! belong here — they use `DeviceMessageEnvelope` and its reliable queue.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::error_codes::ErrorCode;
use crate::event_envelope::ScopeRef;
use crate::generated::ProofContextId;
use crate::primitives::Audience;
use crate::{
    DeviceId, DidCoreId, DidFullId, DidUrl, ExporterLabelId, Hash, RealmId, SealId, canonical,
    project_full_id_to_core_id,
};

/// Construction identifier of the v1 Signal payload.
///
/// It deliberately names the construction, not the algorithm: the algorithm
/// lives in [`SignalEncryptedPayload::aead_profile`] and must equal whatever
/// ciphersuite the scope's MLS group actually negotiated, so activating a
/// further ciphersuite reaches Signal with no wire change
/// (`zh/sync/signal.md` §1).
pub const SIGNAL_AEAD_SCHEME: &str = "ak.signal_exporter_aead.v1";

/// AEAD purpose of this domain, a nonce-derivation and AAD input.
///
/// It is what keeps a Signal nonce from colliding with a content-encryption
/// nonce under the same key and epoch (`encoding.md` §10.1).
pub const SIGNAL_AEAD_PURPOSE: &str = "ak.signal.v1";

/// MLS-Exporter label the Signal content key is derived under.
///
/// Taken from the generated exporter-label registry rather than spelled out
/// here: the label is a wire-breaking domain separator, so it must have
/// exactly one source.
pub const SIGNAL_EXPORTER_LABEL: &str = ExporterLabelId::SIGNAL_V1;

/// Canonical envelope size bound.
pub const MAX_SIGNAL_ENVELOPE_BYTES: usize = 64 * 1024;

/// Maximum number of envelopes in one single-hop peer relay request.
pub const MAX_SIGNAL_RELAY_ITEMS: usize = 128;

/// Canonical JSON bound for one peer relay request.
pub const MAX_SIGNAL_RELAY_CANONICAL_BODY_BYTES: usize = 1024 * 1024;

/// Maximum reconnect hint accepted on a Signal drain frame.
pub const MAX_SIGNAL_STREAM_RECONNECT_AFTER_MS: u64 = 300_000;

/// Maximum Unicode scalar count for a Signal stream control-frame reason.
pub const MAX_SIGNAL_STREAM_REASON_CHARS: usize = 128;

/// AEAD plaintext bound before encryption.
pub const MAX_SIGNAL_PLAINTEXT_BYTES: usize = 48 * 1024;

/// Unpadded base64url ceiling for `ciphertext`, including the AEAD tag
/// (16 bytes for every active v1 ciphersuite).
pub const MAX_SIGNAL_CIPHERTEXT_CHARS: usize = 65_558;

/// Hard TTL ceiling across every class.
pub const MAX_SIGNAL_TTL: Duration = Duration::seconds(120);

/// Server-visible product classification of a Signal.
///
/// `#[non_exhaustive]`: downstream `match` expressions MUST carry a fail-closed
/// `_` arm, because a spec revision may register a further class and silently
/// defaulting an unknown one could widen what the service is willing to relay.
/// Inside this crate the match in [`SignalClass::max_ttl`] stays exhaustive on
/// purpose: a new class must not be able to inherit another class's TTL by
/// falling through a catch-all. Deserialization stays closed-set.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SignalClass {
    /// Wake-up, VoIP push, live session establishment.
    Setup,
    /// Additionally gated on the corresponding moderation action.
    Moderation,
    /// Ordinary presence / typing / receipt / candidate / session signals.
    Session,
}

impl SignalClass {
    /// Protocol maximum `expires_at - sent_at` for this class.
    pub fn max_ttl(self) -> Duration {
        match self {
            Self::Setup => Duration::seconds(120),
            Self::Moderation => Duration::seconds(60),
            Self::Session => Duration::seconds(30),
        }
    }
}

/// AEAD ciphertext plus the metadata a receiver needs to select the key.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalEncryptedPayload {
    pub scheme: String,
    /// MLS group whose exporter produced the content key. It is also what
    /// fixes which ciphersuite `aead_profile` must equal.
    pub key_ref: SignalKeyRef,
    pub purpose: String,
    /// `canonical_id` of an ACTIVE row of the MLS ciphersuite registry, equal
    /// to the ciphersuite the group at `key_ref` actually negotiated. A
    /// reserved suite, an unregistered suite, or a mismatch fails closed. This
    /// crate can only check the shape; the equality needs accepted group state
    /// and belongs to the caller.
    pub aead_profile: String,
    pub epoch: u64,
    pub nonce: String,
    pub ciphertext: String,
    /// Digest of the immutable outer header bound into the AEAD AAD.
    pub aad_digest: Hash,
}

/// MLS group state the Signal content key was exported from.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalKeyRef {
    pub algorithm: String,
    pub group_state_ref: String,
}

/// The Signal domain's **pre-encryption immutable header** (`encoding.md`
/// §10.2). Its canonical bytes are the AEAD AAD, and its digest is what
/// travels as [`SignalEncryptedPayload::aad_digest`].
///
/// Every member is fixed before the AEAD seal runs, which is the whole point
/// of §10.2: nothing that depends on the AEAD output (ciphertext digest, the
/// `aad_digest` itself, `envelope_digest`, the proof) may enter the AAD, so a
/// sender can build the AAD without having encrypted anything yet. The one
/// member a sender only learns *while* sealing is the nonce, so it is passed
/// separately to [`Self::aad_bytes`] rather than stored here — that also lets
/// the sealing layer own nonce derivation without owning the header shape.
///
/// Borrowed rather than owned so both directions use the same type: a sender
/// assembles one from the values it is about to sign, and a receiver gets one
/// from [`SignalEnvelope::aead_binding`] with no allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignalAeadBinding<'a> {
    pub realm_id: &'a RealmId,
    pub scope_ref: &'a ScopeRef,
    pub sender_actor_id: &'a DidCoreId,
    pub sender_device_id: &'a DeviceId,
    pub seal_ref: &'a SealId,
    pub signal_class: SignalClass,
    pub sent_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Construction id; [`Self::validate`] pins it to [`SIGNAL_AEAD_SCHEME`].
    pub scheme: &'a str,
    pub key_ref: &'a SignalKeyRef,
    /// AEAD purpose; [`Self::validate`] pins it to [`SIGNAL_AEAD_PURPOSE`].
    pub purpose: &'a str,
    /// `canonical_id` of the ciphersuite the group at `key_ref` negotiated.
    pub aead_profile: &'a str,
    pub epoch: u64,
}

impl SignalAeadBinding<'_> {
    /// Every rule that is decidable from the immutable header alone.
    ///
    /// Shared by the sealing path (which has no envelope yet) and by
    /// [`SignalEnvelope::validate_structural`], so a sender cannot encrypt
    /// under a header an ingress would then reject.
    pub fn validate(&self) -> Result<()> {
        if self.scope_ref.realm_id() != self.realm_id {
            return Err(Error::Protocol(
                "signal scope_ref.realm_id must equal the envelope realm_id".to_owned(),
            ));
        }
        if self.scheme != SIGNAL_AEAD_SCHEME {
            return Err(Error::Protocol(format!(
                "signal payload scheme must be {SIGNAL_AEAD_SCHEME}"
            )));
        }
        if self.purpose != SIGNAL_AEAD_PURPOSE {
            return Err(Error::Protocol(format!(
                "signal payload purpose must be {SIGNAL_AEAD_PURPOSE}"
            )));
        }
        if self.aead_profile.is_empty() {
            return Err(Error::Protocol(
                "signal payload aead_profile must name an active MLS ciphersuite".to_owned(),
            ));
        }
        if self.expires_at <= self.sent_at {
            return Err(Error::Protocol(
                "signal expires_at must be strictly after sent_at".to_owned(),
            ));
        }
        let ttl = self.expires_at - self.sent_at;
        let ceiling = self.signal_class.max_ttl();
        if ttl > ceiling || ttl > MAX_SIGNAL_TTL {
            return Err(Error::ProtocolCode {
                code: ErrorCode::SignalTtlOutOfRange,
                message: format!(
                    "signal TTL {}s exceeds the {:?} class ceiling of {}s",
                    ttl.num_seconds(),
                    self.signal_class,
                    ceiling.num_seconds()
                ),
            });
        }
        Ok(())
    }

    /// Canonical bytes of the immutable header — the AEAD AAD itself.
    ///
    /// `nonce` is the unpadded base64url form exactly as it appears in
    /// [`SignalEncryptedPayload::nonce`]; binding the wire spelling rather
    /// than the raw bytes means a receiver AADs whatever it actually read.
    pub fn aad_bytes(&self, nonce: &str) -> Result<Vec<u8>> {
        let mut object = serde_json::Map::new();
        object.insert(
            "realm_id".to_owned(),
            Value::String(self.realm_id.as_str().to_owned()),
        );
        object.insert(
            "scope_ref".to_owned(),
            serde_json::to_value(self.scope_ref)?,
        );
        object.insert(
            "sender_actor_id".to_owned(),
            Value::String(self.sender_actor_id.as_str().to_owned()),
        );
        object.insert(
            "sender_device_id".to_owned(),
            Value::String(self.sender_device_id.as_str().to_owned()),
        );
        object.insert(
            "seal_ref".to_owned(),
            Value::String(self.seal_ref.as_str().to_owned()),
        );
        object.insert(
            "signal_class".to_owned(),
            serde_json::to_value(self.signal_class)?,
        );
        object.insert(
            "sent_at".to_owned(),
            Value::String(canonical::format_timestamp_canonical(self.sent_at)),
        );
        object.insert(
            "expires_at".to_owned(),
            Value::String(canonical::format_timestamp_canonical(self.expires_at)),
        );
        object.insert("scheme".to_owned(), Value::String(self.scheme.to_owned()));
        // `encoding.md` §10.1 requires every AEAD-bearing envelope to bind at
        // least key_ref, nonce, purpose and aead_profile. They are also the
        // canonical nonce-derivation context, so omitting them would leave a
        // receiver unable to recompute the sender nonce prefix.
        object.insert("key_ref".to_owned(), serde_json::to_value(self.key_ref)?);
        object.insert("purpose".to_owned(), Value::String(self.purpose.to_owned()));
        object.insert(
            "aead_profile".to_owned(),
            Value::String(self.aead_profile.to_owned()),
        );
        object.insert("epoch".to_owned(), Value::Number(self.epoch.into()));
        object.insert("nonce".to_owned(), Value::String(nonce.to_owned()));
        Ok(canonical::canonical_json_bytes(&Value::Object(object))?)
    }

    /// `H(aad_bytes)`. Carried on the wire so a receiver can report a
    /// mismatch before attempting the AEAD open, never as a substitute for
    /// recomputing the AAD (`encoding.md` §10.2).
    pub fn aad_digest(&self, nonce: &str) -> Result<Hash> {
        Ok(Hash::new(canonical::sha256_digest(self.aad_bytes(nonce)?))?)
    }
}

/// Detached device proof over the Signal envelope.
///
/// Distinct from [`crate::primitives::ProducerEventProof`]: the transcript names the
/// sending device explicitly and commits to `envelope_digest`, not to an
/// Event digest.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalProof {
    pub kind: String,
    pub verification_method: DidUrl,
    pub envelope_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
    pub jws: String,
}

/// Encrypted-only broadcast Signal envelope.
///
/// It is never a durable Event: it advances no `actor_seq`, enters no Seal
/// coverage or `state_root`, and produces no reducer state.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalEnvelope {
    pub realm_id: RealmId,
    pub scope_ref: ScopeRef,
    pub sender_actor_id: DidCoreId,
    pub sender_device_id: DeviceId,
    pub seal_ref: SealId,
    pub signal_class: SignalClass,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub sent_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub encrypted_payload: SignalEncryptedPayload,
    pub proof: SignalProof,
}

impl SignalEnvelope {
    /// `H(canonical_json(envelope_without_proof))`.
    ///
    /// Because `proof` is the only removal, the digest commits to the
    /// ciphertext and to `aad_digest` as well as to the header.
    pub fn envelope_digest(&self) -> Result<Hash> {
        let mut json = serde_json::to_value(self)?;
        if let Value::Object(map) = &mut json {
            map.remove("proof");
        }
        Ok(Hash::new(canonical::canonical_sha256(&json)?)?)
    }

    /// Borrow this envelope's immutable header as the AEAD binding.
    ///
    /// The header shape lives in exactly one place ([`SignalAeadBinding`]) so
    /// a sender that has not yet produced a ciphertext and a receiver holding
    /// a finished envelope cannot drift apart in what they authenticate.
    pub fn aead_binding(&self) -> SignalAeadBinding<'_> {
        SignalAeadBinding {
            realm_id: &self.realm_id,
            scope_ref: &self.scope_ref,
            sender_actor_id: &self.sender_actor_id,
            sender_device_id: &self.sender_device_id,
            seal_ref: &self.seal_ref,
            signal_class: self.signal_class,
            sent_at: self.sent_at,
            expires_at: self.expires_at,
            scheme: &self.encrypted_payload.scheme,
            key_ref: &self.encrypted_payload.key_ref,
            purpose: &self.encrypted_payload.purpose,
            aead_profile: &self.encrypted_payload.aead_profile,
            epoch: self.encrypted_payload.epoch,
        }
    }

    /// Recompute the AAD digest from the immutable server-visible header.
    ///
    /// Deliberately excludes `aad_digest` itself, the ciphertext and the
    /// proof: the AEAD tag already binds ciphertext to AAD.
    pub fn expected_aad_digest(&self) -> Result<Hash> {
        self.aead_binding()
            .aad_digest(&self.encrypted_payload.nonce)
    }

    /// Canonical bytes the sending device signs.
    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        let mut object = serde_json::Map::new();
        object.insert(
            "context".to_owned(),
            Value::String(ProofContextId::SIGNAL_PROOF_V1.to_owned()),
        );
        object.insert(
            "envelope_digest".to_owned(),
            Value::String(self.proof.envelope_digest.as_str().to_owned()),
        );
        object.insert(
            "sender_actor_id".to_owned(),
            Value::String(self.sender_actor_id.as_str().to_owned()),
        );
        object.insert(
            "sender_device_id".to_owned(),
            Value::String(self.sender_device_id.as_str().to_owned()),
        );
        object.insert(
            "verification_method".to_owned(),
            Value::String(self.proof.verification_method.as_str().to_owned()),
        );
        object.insert(
            "created_at".to_owned(),
            Value::String(canonical::format_timestamp_canonical(self.proof.created_at)),
        );
        if let Some(domain) = &self.proof.domain {
            object.insert("domain".to_owned(), Value::String(domain.clone()));
        }
        if let Some(audience) = &self.proof.audience {
            object.insert("audience".to_owned(), serde_json::to_value(audience)?);
        }
        Ok(canonical::canonical_json_bytes(&Value::Object(object))?)
    }

    /// Every check the sender, ingress, relay and receiver share, except the
    /// signature verification and the current-directory device authorization
    /// lookup, which need key material and accepted state. The two are separate
    /// state domains: `seal_ref` selects the Realm/scope basis only, never the
    /// device frontier (`signal.md` §1).
    ///
    /// Notably absent by design: any inspection of a product `signal_kind`,
    /// `call_id` or `strand_id`. Those do not exist on the outer envelope, and
    /// an implementation that starts requiring them has reintroduced the
    /// metadata leak this rail removed.
    pub fn validate_structural(&self) -> Result<()> {
        // Everything decidable from the immutable header is delegated so the
        // sealing path (which runs before an envelope exists) enforces the
        // identical set.
        self.aead_binding().validate()?;
        if self.encrypted_payload.ciphertext.len() > MAX_SIGNAL_CIPHERTEXT_CHARS {
            return Err(Error::Protocol(format!(
                "signal ciphertext exceeds {MAX_SIGNAL_CIPHERTEXT_CHARS} characters"
            )));
        }
        // `signal.md` §1 — the bare full DID must project to the sender core id,
        // and the fragment must equal the device id. This is only the
        // completeness condition of the directory lookup key, never a
        // substitute for current device authorization.
        let (proof_controller, proof_fragment) = self
            .proof
            .verification_method
            .as_str()
            .split_once('#')
            .ok_or_else(|| {
                Error::Protocol(
                    "signal proof verification_method requires a DID URL fragment".to_owned(),
                )
            })?;
        let proof_controller = project_full_id_to_core_id(&DidFullId::new(proof_controller)?)?;
        if proof_controller != self.sender_actor_id
            || proof_fragment != self.sender_device_id.as_str()
        {
            return Err(Error::Protocol(
                "signal proof verification_method controller or fragment does not match the sender directory key"
                    .to_owned(),
            ));
        }
        if self.proof.created_at != self.sent_at {
            return Err(Error::Protocol(
                "signal proof created_at must equal sent_at".to_owned(),
            ));
        }
        if self.proof.envelope_digest != self.envelope_digest()? {
            return Err(Error::Protocol(
                "signal proof envelope_digest does not match the envelope".to_owned(),
            ));
        }
        if self.encrypted_payload.aad_digest != self.expected_aad_digest()? {
            return Err(Error::Protocol(
                "signal aad_digest does not match the immutable outer header".to_owned(),
            ));
        }
        let canonical_len = canonical::canonical_json_bytes(self)?.len();
        if canonical_len > MAX_SIGNAL_ENVELOPE_BYTES {
            return Err(Error::Protocol(format!(
                "signal envelope exceeds {MAX_SIGNAL_ENVELOPE_BYTES} canonical bytes"
            )));
        }
        Ok(())
    }
}

/// Closed frame union for `ak.self.signal.stream.subscribe`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
// Tagged wire union; boxing a variant changes the public constructor shape
// without changing the JSON.
#[allow(clippy::large_enum_variant)]
pub enum SignalStreamFrame {
    Signal {
        envelope: SignalEnvelope,
    },
    Heartbeat,
    Drain {
        #[serde(skip_serializing_if = "Option::is_none")]
        reconnect_after_ms: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Unauthorized {
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

impl SignalStreamFrame {
    pub fn signal(envelope: SignalEnvelope) -> Self {
        Self::Signal { envelope }
    }

    pub const HEARTBEAT: Self = Self::Heartbeat;

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Signal { envelope } => envelope.validate_structural(),
            Self::Heartbeat => Ok(()),
            Self::Drain {
                reconnect_after_ms,
                reason,
            } => {
                if reconnect_after_ms
                    .is_some_and(|value| value > MAX_SIGNAL_STREAM_RECONNECT_AFTER_MS)
                {
                    return Err(Error::Protocol(format!(
                        "Signal drain reconnect_after_ms exceeds \
                         {MAX_SIGNAL_STREAM_RECONNECT_AFTER_MS}"
                    )));
                }
                validate_signal_stream_reason(reason.as_deref())
            }
            Self::Unauthorized { reason } => validate_signal_stream_reason(reason.as_deref()),
        }
    }
}

fn validate_signal_stream_reason(reason: Option<&str>) -> Result<()> {
    if reason.is_some_and(|value| value.chars().count() > MAX_SIGNAL_STREAM_REASON_CHARS) {
        return Err(Error::Protocol(format!(
            "Signal stream reason exceeds {MAX_SIGNAL_STREAM_REASON_CHARS} characters"
        )));
    }
    Ok(())
}

/// Closed request body for `ak.peer.signal.command.relay`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalRelayRequest {
    pub realm_id: RealmId,
    pub signals: Vec<SignalEnvelope>,
}

impl SignalRelayRequest {
    /// Validate request-level invariants before any local fanout.
    pub fn validate(&self) -> Result<()> {
        if self.signals.is_empty() || self.signals.len() > MAX_SIGNAL_RELAY_ITEMS {
            return Err(Error::Protocol(format!(
                "signal relay requires 1..={MAX_SIGNAL_RELAY_ITEMS} signals"
            )));
        }
        for signal in &self.signals {
            if signal.realm_id != self.realm_id || signal.scope_ref.realm_id() != &self.realm_id {
                return Err(Error::Protocol(
                    "signal relay request and every envelope must use one realm_id".to_owned(),
                ));
            }
            signal.validate_structural()?;
        }
        let canonical_len = canonical::canonical_json_bytes(self)?.len();
        if canonical_len > MAX_SIGNAL_RELAY_CANONICAL_BODY_BYTES {
            return Err(Error::Protocol(format!(
                "signal relay request exceeds {MAX_SIGNAL_RELAY_CANONICAL_BODY_BYTES} canonical bytes"
            )));
        }
        Ok(())
    }
}

/// Opaque success body for `ak.peer.signal.command.relay`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalRelayOutcome {
    pub accepted: bool,
}

impl SignalRelayOutcome {
    pub const ACCEPTED: Self = Self { accepted: true };

    pub fn validate(self) -> Result<()> {
        if !self.accepted {
            return Err(Error::Protocol(
                "signal relay outcome accepted must be true".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::primitives::proof_kind;

    fn realm() -> RealmId {
        RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").unwrap()
    }

    fn sent_at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0).unwrap()
    }

    fn actor() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap()
    }

    fn actor_full() -> DidFullId {
        DidFullId::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn device() -> DeviceId {
        DeviceId::new("ak:device:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap()
    }

    fn envelope(signal_class: SignalClass, ttl_seconds: i64) -> SignalEnvelope {
        let mut envelope = SignalEnvelope {
            realm_id: realm(),
            scope_ref: ScopeRef::Realm { realm_id: realm() },
            sender_actor_id: actor(),
            sender_device_id: device(),
            seal_ref: SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            signal_class,
            sent_at: sent_at(),
            expires_at: sent_at() + Duration::seconds(ttl_seconds),
            encrypted_payload: SignalEncryptedPayload {
                scheme: SIGNAL_AEAD_SCHEME.to_owned(),
                key_ref: SignalKeyRef {
                    algorithm: "MLS-EXPORTER-AEAD".to_owned(),
                    group_state_ref: "ak:event:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM"
                        .to_owned(),
                },
                purpose: SIGNAL_AEAD_PURPOSE.to_owned(),
                aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
                epoch: 7,
                nonce: "AAAAAAAAAAAAAAAA".to_owned(),
                ciphertext: "Q2lwaGVydGV4dFBsYWNlaG9sZGVy".to_owned(),
                aad_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            },
            proof: SignalProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new(format!("{}#{}", actor_full(), device())).unwrap(),
                envelope_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: sent_at(),
                domain: None,
                audience: None,
                jws: "a..b".to_owned(),
            },
        };
        envelope.encrypted_payload.aad_digest = envelope.expected_aad_digest().unwrap();
        envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
        envelope
    }

    #[test]
    fn relay_request_is_closed_bounded_and_single_realm() {
        let signal = envelope(SignalClass::Session, 30);
        let request = SignalRelayRequest {
            realm_id: realm(),
            signals: vec![signal.clone()],
        };
        request.validate().unwrap();
        assert_eq!(
            serde_json::to_value(SignalRelayOutcome::ACCEPTED).unwrap(),
            serde_json::json!({"accepted": true})
        );
        SignalRelayOutcome::ACCEPTED.validate().unwrap();

        let empty = SignalRelayRequest {
            realm_id: realm(),
            signals: Vec::new(),
        };
        assert!(empty.validate().is_err());

        let too_many = SignalRelayRequest {
            realm_id: realm(),
            signals: vec![signal.clone(); MAX_SIGNAL_RELAY_ITEMS + 1],
        };
        assert!(too_many.validate().is_err());

        let other_realm =
            RealmId::new("ak:realm:ARkI10daMTZLo_cMC-hjorA_xQhU-5dVl4H0BWDB_xTA").unwrap();
        let cross_realm = SignalRelayRequest {
            realm_id: other_realm,
            signals: vec![signal],
        };
        assert!(cross_realm.validate().is_err());
    }

    #[test]
    fn per_class_ttl_ceilings_are_enforced() {
        envelope(SignalClass::Session, 30)
            .validate_structural()
            .expect("30s session signal is at the ceiling");
        for (class, over) in [
            (SignalClass::Session, 31),
            (SignalClass::Moderation, 61),
            (SignalClass::Setup, 121),
        ] {
            let err = envelope(class, over).validate_structural().unwrap_err();
            assert_eq!(err.error_code(), Some(ErrorCode::SignalTtlOutOfRange));
        }
    }

    #[test]
    fn verification_method_must_equal_the_directory_lookup_key() {
        // `signal.md` §3 conformance case 3: a fragment that merely looks like
        // a device id, and a method controlled by another DID, both name a
        // different directory row than the envelope claims.
        for method in [
            format!("{}#device-key", actor_full()),
            format!("did:webvh:z6mkother:mallory.example#{}", device()),
            format!(
                "{}#ak:device:01904100-0000-7000-8000-bbbbbbbbbbbc",
                actor_full()
            ),
        ] {
            let mut mutated = envelope(SignalClass::Session, 30);
            // `envelope_digest` removes `proof`, so it stays valid here and the
            // verification-method rule is the only check under test.
            mutated.proof.verification_method = DidUrl::new(method).unwrap();

            let err = mutated.validate_structural().unwrap_err();
            assert!(err.to_string().contains("verification_method"), "{err}");
        }
    }

    #[test]
    fn mutating_any_header_member_breaks_the_envelope_digest() {
        let baseline = envelope(SignalClass::Session, 30);
        baseline.validate_structural().unwrap();

        let mut retimed = baseline;
        retimed.expires_at = sent_at() + Duration::seconds(20);
        let err = retimed.validate_structural().unwrap_err();
        assert!(err.to_string().contains("envelope_digest"), "{err}");
    }

    #[test]
    fn aad_digest_covers_every_immutable_header_member() {
        // Re-derive the proof digest after each mutation so the envelope digest
        // check passes and the AAD binding is the one actually under test.
        // Without this the first check would mask the second.
        let mutations: [fn(&mut SignalEnvelope); 5] = [
            |envelope: &mut SignalEnvelope| {
                envelope.expires_at = sent_at() + Duration::seconds(20);
            },
            |envelope: &mut SignalEnvelope| envelope.signal_class = SignalClass::Setup,
            |envelope: &mut SignalEnvelope| envelope.encrypted_payload.epoch += 1,
            |envelope: &mut SignalEnvelope| {
                envelope.encrypted_payload.aead_profile =
                    "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519".to_owned();
            },
            |envelope: &mut SignalEnvelope| {
                envelope.encrypted_payload.nonce = "BBBBBBBBBBBBBBBB".to_owned();
            },
        ];
        for mutate in mutations {
            let mut mutated = envelope(SignalClass::Session, 30);
            mutate(&mut mutated);
            mutated.proof.envelope_digest = mutated.envelope_digest().unwrap();

            let err = mutated.validate_structural().unwrap_err();
            assert!(err.to_string().contains("aad_digest"), "{err}");
        }
    }

    #[test]
    fn envelope_digest_commits_to_the_ciphertext() {
        let baseline = envelope(SignalClass::Session, 30);
        let mut tampered = baseline.clone();
        tampered.encrypted_payload.ciphertext = "T3RoZXJDaXBoZXJ0ZXh0".to_owned();
        assert_ne!(
            baseline.envelope_digest().unwrap(),
            tampered.envelope_digest().unwrap()
        );
    }

    #[test]
    fn envelope_rejects_a_plaintext_product_selector_on_the_outer_header() {
        let mut value = serde_json::to_value(envelope(SignalClass::Session, 30)).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("signal_kind".to_owned(), Value::String("typing".to_owned()));
        serde_json::from_value::<SignalEnvelope>(value)
            .expect_err("outer plaintext product selectors must not deserialize");
    }

    #[test]
    fn proof_binding_uses_the_signal_context_and_names_the_device() {
        let envelope = envelope(SignalClass::Setup, 120);
        let bytes = String::from_utf8(envelope.proof_binding_bytes().unwrap()).unwrap();
        assert!(bytes.contains("ak.signal-proof-v1"));
        assert!(bytes.contains("sender_device_id"));
    }

    #[test]
    fn stream_frames_are_closed_and_bounded() {
        let signal = SignalStreamFrame::signal(envelope(SignalClass::Session, 30));
        signal.validate().unwrap();
        assert_eq!(
            serde_json::to_value(signal).unwrap()["kind"],
            serde_json::json!("signal")
        );
        assert_eq!(
            serde_json::to_value(SignalStreamFrame::HEARTBEAT).unwrap(),
            serde_json::json!({"kind": "heartbeat"})
        );
        assert!(
            SignalStreamFrame::Drain {
                reconnect_after_ms: Some(MAX_SIGNAL_STREAM_RECONNECT_AFTER_MS + 1),
                reason: None,
            }
            .validate()
            .is_err()
        );
        assert!(
            SignalStreamFrame::Unauthorized {
                reason: Some("x".repeat(MAX_SIGNAL_STREAM_REASON_CHARS + 1)),
            }
            .validate()
            .is_err()
        );
    }
}
