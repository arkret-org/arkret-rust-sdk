//! Signal Extension envelope (`zh/sync/signal.md`).
//!
//! A Signal is a peer of Event, not a subtype: an Event is a
//! durable signed fact committed by the governance Station, while a Signal is
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
//! Device verification and MLS Welcome delivery do not belong here.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Result, WireError};
use crate::error_codes::ErrorCode;
use crate::event_envelope::ScopeRef;
use crate::generated::ProofContextId;
use crate::primitives::Audience;
use crate::{
    AccountId, ActorId, Base64UrlString, DeviceId, Did, DidUrl, EventId, ExporterLabelId, Hash,
    RealmCommitId, RealmId, canonical, project_did_to_core_id,
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
pub const MAX_SIGNAL_PLAINTEXT_BYTES: usize = 46 * 1024;

/// Unpadded base64url ceiling for `ciphertext`, including the AEAD tag
/// (16 bytes for every active v1 ciphersuite).
pub const MAX_SIGNAL_CIPHERTEXT_CHARS: usize = 62_827;

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
}

/// MLS group state the Signal content key was exported from.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalKeyRef {
    pub group_state_ref: String,
}

/// The Signal domain's **pre-encryption immutable header** (`encoding.md`
/// §10.2). Its canonical bytes are the AEAD AAD. Receivers reconstruct the
/// bytes from the envelope; no redundant AAD digest travels on the wire.
///
/// Every member is fixed before AEAD encryption runs, which is the whole point
/// of §10.2: nothing that depends on the AEAD output (ciphertext digest,
/// `envelope_digest`, the proof) may enter the AAD, so a
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
    pub sender_actor_id: &'a ActorId,
    pub sender_device_id: Option<&'a DeviceId>,
    /// Exact head of this scope's independent commit stream used for current
    /// sender authorization.
    pub authority_commit_id: &'a RealmCommitId,
    /// Independent parent Realm cut, present exactly for Circle scope.
    pub parent_realm_authority_commit_id: Option<&'a RealmCommitId>,
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
        self.sender_actor_id.validate()?;
        if self.scope_ref.realm_id_opt() != Some(self.realm_id) {
            return Err(WireError::Protocol(
                "signal scope_ref.realm_id must equal the envelope realm_id".to_owned(),
            ));
        }
        match self.scope_ref {
            ScopeRef::Circle { .. } if self.parent_realm_authority_commit_id.is_some() => {}
            ScopeRef::Realm { .. } | ScopeRef::Sidecar { .. }
                if self.parent_realm_authority_commit_id.is_none() => {}
            _ => {
                return Err(WireError::Protocol(
                    "Signal parent Realm cut must be present exactly for Circle scope".to_owned(),
                ));
            }
        }
        if self.scheme != SIGNAL_AEAD_SCHEME {
            return Err(WireError::Protocol(format!(
                "signal payload scheme must be {SIGNAL_AEAD_SCHEME}"
            )));
        }
        if self.purpose != SIGNAL_AEAD_PURPOSE {
            return Err(WireError::Protocol(format!(
                "signal payload purpose must be {SIGNAL_AEAD_PURPOSE}"
            )));
        }
        if self.aead_profile.is_empty() {
            return Err(WireError::Protocol(
                "signal payload aead_profile must name an active MLS ciphersuite".to_owned(),
            ));
        }
        if self.expires_at <= self.sent_at {
            return Err(WireError::Protocol(
                "signal expires_at must be strictly after sent_at".to_owned(),
            ));
        }
        let ttl = self.expires_at - self.sent_at;
        let ceiling = self.signal_class.max_ttl();
        if ttl > ceiling || ttl > MAX_SIGNAL_TTL {
            return Err(WireError::ProtocolCode {
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
            serde_json::to_value(self.sender_actor_id)?,
        );
        if let Some(sender_device_id) = self.sender_device_id {
            object.insert(
                "sender_device_id".to_owned(),
                Value::String(sender_device_id.as_str().to_owned()),
            );
        }
        object.insert(
            "authority_commit_id".to_owned(),
            Value::String(self.authority_commit_id.as_str().to_owned()),
        );
        if let Some(parent) = self.parent_realm_authority_commit_id {
            object.insert(
                "parent_realm_authority_commit_id".to_owned(),
                Value::String(parent.as_str().to_owned()),
            );
        }
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
}

/// Detached sender proof over the Signal envelope.
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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_proof_value"
    )]
    pub domain: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_proof_value"
    )]
    pub audience: Option<Audience>,
    pub jws: String,
}

/// Encrypted-only broadcast Signal envelope.
///
/// It is never a durable Event and never enters an authority commit stream.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalEnvelope {
    pub realm_id: RealmId,
    pub scope_ref: ScopeRef,
    pub sender_actor_id: ActorId,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_proof_value"
    )]
    pub sender_device_id: Option<DeviceId>,
    pub authority_commit_id: RealmCommitId,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_present_proof_value"
    )]
    pub parent_realm_authority_commit_id: Option<RealmCommitId>,
    pub signal_class: SignalClass,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub sent_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub encrypted_payload: SignalEncryptedPayload,
    pub proof: SignalProof,
}

/// Closed sender branch selected by the presence of `sender_device_id`.
///
/// This is only a structural discriminator. `Agent` becomes trusted only
/// after the caller validates accepted Agent classification and current
/// runtime authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalSenderEndpoint<'a> {
    AccountDevice(&'a DeviceId),
    Agent,
}

fn deserialize_present_proof_value<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}

impl SignalEnvelope {
    pub fn sender_endpoint(&self) -> SignalSenderEndpoint<'_> {
        match self.sender_device_id.as_ref() {
            Some(device_id) => SignalSenderEndpoint::AccountDevice(device_id),
            None => SignalSenderEndpoint::Agent,
        }
    }

    /// `H(canonical_json(envelope_without_proof))`.
    ///
    /// Because `proof` is the only removal, the digest commits to the
    /// ciphertext and the complete server-visible header.
    pub fn envelope_digest(&self) -> Result<Hash> {
        let json = canonical::unsigned_value(self, &["proof"])?;
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
            sender_device_id: self.sender_device_id.as_ref(),
            authority_commit_id: &self.authority_commit_id,
            parent_realm_authority_commit_id: self.parent_realm_authority_commit_id.as_ref(),
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
            serde_json::to_value(&self.sender_actor_id)?,
        );
        if let Some(sender_device_id) = &self.sender_device_id {
            object.insert(
                "sender_device_id".to_owned(),
                Value::String(sender_device_id.as_str().to_owned()),
            );
        }
        object.insert(
            "verification_method".to_owned(),
            Value::String(self.proof.verification_method.as_str().to_owned()),
        );
        object.insert(
            "created_at".to_owned(),
            Value::String(canonical::format_timestamp_canonical(self.sent_at)),
        );
        if let Some(domain) = &self.proof.domain {
            object.insert("domain".to_owned(), Value::String(domain.clone()));
        }
        if let Some(audience) = &self.proof.audience {
            object.insert("audience".to_owned(), serde_json::to_value(audience)?);
        }
        Ok(canonical::canonical_json_bytes(&Value::Object(object))?)
    }

    /// Closed schema shape, independent of an individual item's admission.
    /// Typed deserialization already rejects absent and unknown fields. A bad
    /// transcript digest, TTL or sender binding is deliberately not a batch
    /// shape error; the destination discards that item without an oracle.
    pub fn validate_wire_shape(&self) -> Result<()> {
        fn b64_chars(value: &str) -> bool {
            value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        }
        let invalid = || {
            WireError::Protocol("signal envelope does not match its closed wire schema".to_owned())
        };
        self.sender_actor_id.validate()?;
        let payload = &self.encrypted_payload;
        if payload.ciphertext.len() > MAX_SIGNAL_CIPHERTEXT_CHARS {
            return Err(WireError::Protocol(format!(
                "signal ciphertext exceeds {MAX_SIGNAL_CIPHERTEXT_CHARS} characters"
            )));
        }
        if payload.scheme != SIGNAL_AEAD_SCHEME
            || payload.purpose != SIGNAL_AEAD_PURPOSE
            || (EventId::new(&payload.key_ref.group_state_ref).is_err()
                && Hash::new(&payload.key_ref.group_state_ref).is_err())
            || payload.nonce.len() != 16
            || !b64_chars(&payload.nonce)
            || payload.ciphertext.len() < 22
            || !b64_chars(&payload.ciphertext)
            || self.proof.kind != crate::proof_kind::DETACHED_JWS
        {
            return Err(invalid());
        }
        let Some((controller, fragment)) = self.proof.verification_method.as_str().split_once('#')
        else {
            return Err(invalid());
        };
        if controller.contains('?')
            || controller.chars().any(char::is_whitespace)
            || fragment.is_empty()
            || !fragment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        {
            return Err(invalid());
        }
        if !crate::is_compact_detached_jws(&self.proof.jws) {
            return Err(invalid());
        }
        if canonical::canonical_json_bytes(self)?.len() > MAX_SIGNAL_ENVELOPE_BYTES {
            return Err(WireError::ProtocolCode {
                code: ErrorCode::PayloadTooLarge,
                message: format!(
                    "signal envelope exceeds {MAX_SIGNAL_ENVELOPE_BYTES} canonical bytes"
                ),
            });
        }
        Ok(())
    }

    /// Every check the sender, ingress, relay and receiver share, except the
    /// signature verification and the current-directory device authorization
    /// lookup, which need key material and accepted state. The two are separate
    /// state domains: `authority_commit_id` selects the Realm/scope basis only, never the
    /// device checkpoint (`signal.md` §1).
    ///
    /// Notably absent by design: any inspection of a product `signal_kind`,
    /// `call_id` or `strand_id`. Those do not exist on the outer envelope, and
    /// an implementation that starts requiring them has reintroduced the
    /// metadata leak this rail removed.
    pub fn validate_structural(&self) -> Result<()> {
        self.validate_wire_shape()?;
        // Everything decidable from the immutable header is delegated so the
        // sealing path (which runs before an envelope exists) enforces the
        // identical set.
        self.aead_binding().validate()?;
        // `signal.md` §1 — the DID must project to the sender core id.
        // Ordinary senders additionally bind the fragment to the device id;
        // Agent senders bind the complete method through current authority.
        let (proof_controller, proof_fragment) = self
            .proof
            .verification_method
            .as_str()
            .split_once('#')
            .ok_or_else(|| {
                WireError::Protocol(
                    "signal proof verification_method requires a DID URL fragment".to_owned(),
                )
            })?;
        let proof_controller = project_did_to_core_id(&Did::new(proof_controller)?)?;
        if &proof_controller != self.sender_actor_id.signing_principal_id()
            || self
                .sender_device_id
                .as_ref()
                .is_some_and(|device_id| proof_fragment != device_id.as_str())
        {
            return Err(WireError::Protocol(
                "signal proof verification_method does not match the sender endpoint".to_owned(),
            ));
        }
        if self.proof.envelope_digest != self.envelope_digest()? {
            return Err(WireError::Protocol(
                "signal proof envelope_digest does not match the envelope".to_owned(),
            ));
        }
        Ok(())
    }
}

/// A signing key returned by the authenticated recipient's own Station.
/// The key bytes may be cached; a current authorization result may not.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct StationSigningKey {
    pub actor: ActorId,
    pub verification_method: DidUrl,
    pub public_key_b64u: Base64UrlString,
    pub authorization_ref: EventId,
}
impl StationSigningKey {
    pub fn validate(&self) -> Result<()> {
        self.actor.validate()?;
        let did = self
            .verification_method
            .as_str()
            .split_once('#')
            .map(|(did, _)| did)
            .ok_or_else(|| {
                station_key_error(
                    ErrorCode::SchemaViolation,
                    "signing method requires a fragment",
                )
            })?;
        let did = Did::new(did.to_owned())?;
        if project_did_to_core_id(&did)? != *self.actor.signing_principal_id() {
            return Err(station_key_error(
                ErrorCode::SchemaViolation,
                "signing method principal mismatch",
            ));
        }
        let value = self.public_key_b64u.as_str();
        if !matches!(self.actor, ActorId::Account { .. })
            || value.len() != 43
            || !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || !b"AEIMQUYcgkosw048".contains(&value.as_bytes()[42])
        {
            return Err(station_key_error(
                ErrorCode::SchemaViolation,
                "invalid Station signing key",
            ));
        }
        Ok(())
    }
}
fn station_key_error(code: ErrorCode, message: &str) -> WireError {
    WireError::ProtocolCode {
        code,
        message: message.to_owned(),
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalDeliveryAuthority {
    pub recipient_account_id: AccountId,
    pub key: StationSigningKey,
}

impl SignalDeliveryAuthority {
    pub fn validate_for_envelope(&self, envelope: &SignalEnvelope) -> Result<()> {
        self.recipient_account_id.validate()?;
        self.key.validate()?;
        if self.key.actor != envelope.sender_actor_id
            || self.key.verification_method != envelope.proof.verification_method
        {
            return Err(station_key_error(
                ErrorCode::SchemaViolation,
                "Signal delivery authority does not bind the exact sender",
            ));
        }
        Ok(())
    }
}

/// Closed frame union for `ak.self.signal.stream.subscribe.v1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
// Tagged wire union; boxing a variant changes the public constructor shape
// without changing the JSON.
#[allow(clippy::large_enum_variant)]
pub enum SignalStreamFrame {
    Signal {
        envelope: SignalEnvelope,
        delivery_authority: SignalDeliveryAuthority,
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
    pub fn signal(envelope: SignalEnvelope, delivery_authority: SignalDeliveryAuthority) -> Self {
        Self::Signal {
            envelope,
            delivery_authority,
        }
    }

    pub const HEARTBEAT: Self = Self::Heartbeat;

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Signal {
                envelope,
                delivery_authority,
            } => {
                envelope.validate_structural()?;
                delivery_authority.validate_for_envelope(envelope)
            }
            Self::Heartbeat => Ok(()),
            Self::Drain {
                reconnect_after_ms,
                reason,
            } => {
                if reconnect_after_ms
                    .is_some_and(|value| value > MAX_SIGNAL_STREAM_RECONNECT_AFTER_MS)
                {
                    return Err(WireError::Protocol(format!(
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
        return Err(WireError::Protocol(format!(
            "Signal stream reason exceeds {MAX_SIGNAL_STREAM_REASON_CHARS} characters"
        )));
    }
    Ok(())
}

/// Closed request body for `ak.peer.signal.command.relay.v1`.
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
            return Err(WireError::Protocol(format!(
                "signal relay requires 1..={MAX_SIGNAL_RELAY_ITEMS} signals"
            )));
        }
        for signal in &self.signals {
            if signal.realm_id != self.realm_id
                || signal.scope_ref.realm_id_opt() != Some(&self.realm_id)
            {
                return Err(WireError::Protocol(
                    "signal relay request and every envelope must use one realm_id".to_owned(),
                ));
            }
            signal.validate_wire_shape()?;
        }
        let canonical_len = canonical::canonical_json_bytes(self)?.len();
        if canonical_len > MAX_SIGNAL_RELAY_CANONICAL_BODY_BYTES {
            return Err(WireError::ProtocolCode {
                code: ErrorCode::PayloadTooLarge,
                message: format!(
                    "signal relay request exceeds {MAX_SIGNAL_RELAY_CANONICAL_BODY_BYTES} canonical bytes"
                ),
            });
        }
        Ok(())
    }
}

/// Opaque success body for `ak.peer.signal.command.relay.v1`.
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
            return Err(WireError::Protocol(
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

    fn actor() -> ActorId {
        ActorId::account(AccountId::new(
            crate::DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            crate::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ))
    }

    fn actor_did() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn device() -> DeviceId {
        DeviceId::new("ak:device:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap()
    }

    fn envelope(signal_class: SignalClass, ttl_seconds: i64) -> SignalEnvelope {
        let mut envelope = SignalEnvelope {
            realm_id: realm(),
            scope_ref: ScopeRef::Realm { realm_id: realm() },
            sender_actor_id: actor(),
            sender_device_id: Some(device()),
            authority_commit_id: RealmCommitId::from_digest([0xaa; 32]),
            parent_realm_authority_commit_id: None,
            signal_class,
            sent_at: sent_at(),
            expires_at: sent_at() + Duration::seconds(ttl_seconds),
            encrypted_payload: SignalEncryptedPayload {
                scheme: SIGNAL_AEAD_SCHEME.to_owned(),
                key_ref: SignalKeyRef {
                    group_state_ref: "ak:event:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM"
                        .to_owned(),
                },
                purpose: SIGNAL_AEAD_PURPOSE.to_owned(),
                aead_profile: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519".to_owned(),
                epoch: 7,
                nonce: "AAAAAAAAAAAAAAAA".to_owned(),
                ciphertext: "Q2lwaGVydGV4dFBsYWNlaG9sZGVy".to_owned(),
            },
            proof: SignalProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new(format!("{}#{}", actor_did(), device())).unwrap(),
                envelope_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                domain: None,
                audience: None,
                jws: "a..b".to_owned(),
            },
        };
        envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
        envelope
    }

    #[test]
    fn parent_realm_cut_is_circle_only_and_binds_aad_and_proof() {
        let mut signal = envelope(SignalClass::Session, 30);
        let parent = RealmCommitId::from_digest([0x41; 32]);
        let mut null = serde_json::to_value(&signal).unwrap();
        null["parent_realm_authority_commit_id"] = Value::Null;
        assert!(serde_json::from_value::<SignalEnvelope>(null).is_err());
        signal.parent_realm_authority_commit_id = Some(parent.clone());
        assert!(signal.aead_binding().validate().is_err());
        signal.scope_ref = ScopeRef::Circle {
            realm_id: signal.realm_id.clone(),
            circle_id: crate::CircleId::from_event_id(&EventId::from_digest(
                arkret_canonical::DigestSuite::Sha256,
                [0x42; 32],
            )),
        };
        signal.aead_binding().validate().unwrap();
        let aad = signal
            .aead_binding()
            .aad_bytes(&signal.encrypted_payload.nonce)
            .unwrap();
        let digest = signal.envelope_digest().unwrap();
        signal.parent_realm_authority_commit_id = Some(RealmCommitId::from_digest([0x43; 32]));
        assert_ne!(
            aad,
            signal
                .aead_binding()
                .aad_bytes(&signal.encrypted_payload.nonce)
                .unwrap()
        );
        assert_ne!(digest, signal.envelope_digest().unwrap());
        signal.parent_realm_authority_commit_id = None;
        assert!(signal.aead_binding().validate().is_err());
    }

    #[test]
    fn signal_proof_uses_outer_timestamp_and_rejects_a_duplicate_wire_timestamp() {
        let original = envelope(SignalClass::Session, 30);
        let mut wire = serde_json::to_value(&original).unwrap();
        assert!(wire["proof"].get("created_at").is_none());
        let binding: Value =
            serde_json::from_slice(&original.proof_binding_bytes().unwrap()).unwrap();
        assert_eq!(binding["created_at"], wire["sent_at"]);
        wire["proof"]["created_at"] = wire["sent_at"].clone();
        assert!(serde_json::from_value::<SignalEnvelope>(wire).is_err());
        let mut changed = original;
        changed.sent_at += Duration::seconds(1);
        assert_ne!(
            changed.proof_binding_bytes().unwrap(),
            canonical::canonical_json_bytes(&binding).unwrap()
        );
    }

    #[test]
    fn signal_sender_is_a_closed_actor_bound_into_aad_and_proof() {
        let original = envelope(SignalClass::Session, 30);
        let value = serde_json::to_value(&original).unwrap();
        assert!(value["sender_actor_id"].is_object());
        let aad: Value = serde_json::from_slice(
            &original
                .aead_binding()
                .aad_bytes(&original.encrypted_payload.nonce)
                .unwrap(),
        )
        .unwrap();
        let proof: Value =
            serde_json::from_slice(&original.proof_binding_bytes().unwrap()).unwrap();
        assert_eq!(aad["sender_actor_id"], value["sender_actor_id"]);
        assert_eq!(proof["sender_actor_id"], value["sender_actor_id"]);
        let mut moved = original.clone();
        let mut account = moved.sender_actor_id.as_account_id().unwrap().clone();
        account.station_id =
            crate::DidCoreId::new("ak:did_core:web:other-station.example").unwrap();
        moved.sender_actor_id = ActorId::account(account);
        assert_ne!(
            moved
                .aead_binding()
                .aad_bytes(&moved.encrypted_payload.nonce)
                .unwrap(),
            original
                .aead_binding()
                .aad_bytes(&original.encrypted_payload.nonce)
                .unwrap()
        );
        assert_ne!(
            moved.proof_binding_bytes().unwrap(),
            original.proof_binding_bytes().unwrap()
        );
    }

    #[test]
    fn agent_sender_omits_device_and_null_is_not_an_alias() {
        let mut agent = envelope(SignalClass::Session, 30);
        agent.sender_device_id = None;
        agent.proof.verification_method =
            DidUrl::new("did:webvh:z6mkfixture:alice.example#runtime-key").unwrap();
        agent.proof.envelope_digest = agent.envelope_digest().unwrap();
        agent.validate_structural().unwrap();
        assert_eq!(agent.sender_endpoint(), SignalSenderEndpoint::Agent);

        let mut encoded = serde_json::to_value(agent).unwrap();
        assert!(encoded.get("sender_device_id").is_none());
        encoded["sender_device_id"] = Value::Null;
        assert!(serde_json::from_value::<SignalEnvelope>(encoded).is_err());
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
    fn proof_optional_fields_reject_explicit_null_without_normalizing_signed_bytes() {
        for field in ["domain", "audience"] {
            let mut value = serde_json::to_value(envelope(SignalClass::Session, 30)).unwrap();
            value["proof"][field] = Value::Null;
            assert!(serde_json::from_value::<SignalEnvelope>(value).is_err());
        }
    }

    #[test]
    fn relay_shape_does_not_promote_one_item_rejection_into_a_batch_oracle() {
        let mut bad = envelope(SignalClass::Session, 31);
        bad.proof.envelope_digest = Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap();
        let mut request = SignalRelayRequest {
            realm_id: realm(),
            signals: vec![bad],
        };
        request.validate().unwrap();
        assert!(request.signals[0].validate_structural().is_err());
        request.signals[0].proof.kind = "unknown".to_owned();
        assert!(request.validate().is_err());
        request.signals[0].proof.kind = proof_kind::DETACHED_JWS.to_owned();
        request.signals[0].encrypted_payload.nonce = "not base64".to_owned();
        assert!(request.validate().is_err());
        let mut value = serde_json::to_value(envelope(SignalClass::Session, 30)).unwrap();
        value.as_object_mut().unwrap().remove("proof");
        assert!(serde_json::from_value::<SignalEnvelope>(value).is_err());
    }

    #[test]
    fn relay_canonical_body_limit_has_a_machine_readable_size_code() {
        let mut signal = envelope(SignalClass::Session, 30);
        signal.encrypted_payload.ciphertext = "A".repeat(16_000);
        let request = SignalRelayRequest {
            realm_id: realm(),
            signals: vec![signal; 128],
        };
        assert_eq!(
            request.validate().unwrap_err().error_code(),
            Some(ErrorCode::PayloadTooLarge)
        );
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
            format!("{}#device-key", actor_did()),
            format!("did:webvh:z6mkother:mallory.example#{}", device()),
            format!(
                "{}#ak:device:01904100-0000-7000-8000-bbbbbbbbbbbc",
                actor_did()
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
    fn aad_bytes_cover_every_immutable_header_member() {
        let baseline = envelope(SignalClass::Session, 30);
        let baseline_aad = baseline
            .aead_binding()
            .aad_bytes(&baseline.encrypted_payload.nonce)
            .unwrap();
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
            let mutated_aad = mutated
                .aead_binding()
                .aad_bytes(&mutated.encrypted_payload.nonce)
                .unwrap();
            assert_ne!(mutated_aad, baseline_aad);
        }
    }

    #[test]
    fn wire_omits_redundant_aad_digest_and_key_algorithm() {
        let original = envelope(SignalClass::Session, 30);
        let wire = serde_json::to_value(&original).unwrap();
        assert!(wire["encrypted_payload"].get("aad_digest").is_none());
        assert!(
            wire["encrypted_payload"]["key_ref"]
                .get("algorithm")
                .is_none()
        );

        let mut with_aad_digest = wire.clone();
        with_aad_digest["encrypted_payload"]["aad_digest"] =
            Value::String(format!("sha256:{}", "0".repeat(64)));
        assert!(serde_json::from_value::<SignalEnvelope>(with_aad_digest).is_err());

        let mut with_algorithm = wire;
        with_algorithm["encrypted_payload"]["key_ref"]["algorithm"] =
            Value::String("MLS-EXPORTER-AEAD".to_owned());
        assert!(serde_json::from_value::<SignalEnvelope>(with_algorithm).is_err());
    }

    #[test]
    fn ciphertext_bound_reserves_envelope_overhead_for_46_kib_plaintext() {
        assert_eq!(MAX_SIGNAL_PLAINTEXT_BYTES, 46 * 1024);
        let encoded = crate::base64url::base64url_encode(vec![0; MAX_SIGNAL_PLAINTEXT_BYTES + 16]);
        assert_eq!(encoded.len(), MAX_SIGNAL_CIPHERTEXT_CHARS);
        let mut signal = envelope(SignalClass::Session, 30);
        signal.encrypted_payload.ciphertext = encoded;
        signal.proof.envelope_digest = signal.envelope_digest().unwrap();
        signal.validate_structural().unwrap();
        signal.encrypted_payload.ciphertext.push('A');
        signal.proof.envelope_digest = signal.envelope_digest().unwrap();
        assert!(
            signal
                .validate_structural()
                .unwrap_err()
                .to_string()
                .contains("signal ciphertext exceeds")
        );
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
        assert!(bytes.contains(ProofContextId::SIGNAL_PROOF_V1));
        assert!(bytes.contains("sender_device_id"));
    }

    #[test]
    fn stream_frames_are_closed_and_bounded() {
        let envelope = envelope(SignalClass::Session, 30);
        let authority = SignalDeliveryAuthority {
            recipient_account_id: envelope.sender_actor_id.as_account_id().unwrap().clone(),
            key: StationSigningKey {
                actor: envelope.sender_actor_id.clone(),
                verification_method: envelope.proof.verification_method.clone(),
                public_key_b64u: Base64UrlString::new("A".repeat(43)).unwrap(),
                authorization_ref: EventId::from_digest(canonical::DigestSuite::Sha256, [0x42; 32]),
            },
        };
        let signal = SignalStreamFrame::signal(envelope, authority);
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
