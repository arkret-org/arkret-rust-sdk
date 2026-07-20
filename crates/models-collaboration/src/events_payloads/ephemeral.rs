//! Broadcast ephemeral envelope wire model.
//!
//! The typed `ak.call.signal` payload helpers and the per-key sequence
//! monotonicity bookkeeping migrated here from `arkret-core`; a shim there
//! re-exports them to preserve the `arkret_core::` path.

use std::collections::BTreeMap;

use arkret_wire::primitives::{Proof, proof_kind};
use arkret_wire::{
    CALL_SIGNAL_TYPES, CallId, DeviceId, Did, Error, ErrorCode, RealmId, Result, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Absolute hard ceiling on `expires_at - sent_at` for an ephemeral signal,
/// in milliseconds. Per `schemas/ephemeral-envelope.schema.json`:
/// "Signals with expires_at > sent_at + 5 minutes MUST be dropped by
/// receivers (`invalid_param`)." Five minutes = 300_000 ms.
pub const EPHEMERAL_ABSOLUTE_HARD_CEILING_MS: u32 = 300_000;

/// Broadcast ephemeral envelope (`ak.schema.ephemeral_envelope.v1`).
///
/// Wire shape for the four broadcast ephemeral signal kinds — `ak.presence`,
/// `ak.typing`, `ak.receipt.read`, `ak.call.signal`. Carried on dedicated
/// ephemeral channels (sync subscribe live stream, presence/typing fanout,
/// call signaling channel) and dropped at TTL. Point-to-point to-device
/// signals (`ak.key.verification.*`) use the device message schema instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct EphemeralEnvelope {
    /// Ephemeral signal kind. MUST be one of the four broadcast forms.
    pub kind: String,
    pub realm_id: RealmId,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub sent_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Kind-specific signal payload. Schema per kind is defined by the
    /// producing module; MUST NOT carry mutable governance state.
    pub payload: BTreeMap<String, Value>,
    /// Detached signature over canonical envelope bytes (excluding `proof`
    /// itself). Per `ephemeral-envelope.schema.json` this is REQUIRED for
    /// every broadcast ephemeral kind (`ak.presence`, `ak.typing`,
    /// `ak.receipt.read`, `ak.call.signal`).
    pub proof: Proof,
}

impl EphemeralEnvelope {
    pub const SCHEMA: &'static str = "ak.schema.ephemeral_envelope.v1";

    /// Construct with validation. Rejects:
    /// - non-ephemeral `kind`
    /// - `expires_at - sent_at > EPHEMERAL_ABSOLUTE_HARD_CEILING_MS` (5 min)
    /// - `expires_at <= sent_at`
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: impl Into<String>,
        realm_id: RealmId,
        actor_id: Did,
        device_id: DeviceId,
        sent_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        payload: BTreeMap<String, Value>,
        proof: Proof,
    ) -> Result<Self> {
        let envelope = Self {
            kind: kind.into(),
            realm_id,
            actor_id,
            device_id,
            sent_at,
            expires_at,
            payload,
            proof,
        };
        envelope.validate()?;
        Ok(envelope)
    }

    /// Validate protocol-level envelope invariants that do not require a
    /// device-directory key. Cryptographic verification remains the
    /// receiver's responsibility.
    pub fn validate(&self) -> Result<()> {
        if !matches!(
            self.kind.as_str(),
            "ak.call.signal" | "ak.presence" | "ak.typing" | "ak.receipt.read"
        ) {
            return Err(Error::Protocol(format!(
                "ephemeral envelope kind {:?} not in {{ak.call.signal, ak.presence, ak.typing, ak.receipt.read}}",
                self.kind
            )));
        }
        if self.expires_at <= self.sent_at {
            return Err(Error::Protocol(
                "ephemeral envelope expires_at must be strictly after sent_at".to_owned(),
            ));
        }
        let window_ms = self
            .expires_at
            .signed_duration_since(self.sent_at)
            .num_milliseconds();
        if window_ms < 0 || (window_ms as u64) > EPHEMERAL_ABSOLUTE_HARD_CEILING_MS as u64 {
            return Err(Error::Protocol(format!(
                "ephemeral envelope window {window_ms}ms exceeds absolute hard ceiling \
                 {EPHEMERAL_ABSOLUTE_HARD_CEILING_MS}ms (invalid_param)"
            )));
        }
        self.proof.validate_production()?;
        if self.proof.kind != proof_kind::DETACHED_JWS {
            return Err(Error::Protocol(
                "ephemeral proof kind must be detached_jws".to_owned(),
            ));
        }
        let expected_verification_method = format!("{}#{}", self.actor_id, self.device_id);
        if self.proof.verification_method != expected_verification_method {
            return Err(Error::Protocol(format!(
                "ephemeral proof verification_method must be {expected_verification_method}"
            )));
        }
        Ok(())
    }

    /// Canonical JCS bytes used to compute `proof.event_digest`.
    /// The proof itself is excluded exactly as required by the wire schema.
    pub fn canonical_bytes_without_proof(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        let object = value.as_object_mut().ok_or_else(|| {
            Error::Protocol("ephemeral envelope must serialize as an object".to_owned())
        })?;
        object.remove("proof");
        Ok(canonical::canonical_json_bytes(&value)?)
    }
}

/// Typed `ak.call.signal` envelope payload.
///
/// The wire requires the three fields `call_id` + `signal_type` + `seq` and
/// validates `signal_type` against [`CALL_SIGNAL_TYPES`] (14
/// values). `seq` is monotonic per `(realm, call, actor, device)` —
/// see [`validate_signal_seq`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct CallSignalPayload {
    pub call_id: CallId,
    pub signal_type: String,
    pub seq: u64,
    /// Per-signal_type extra fields nested under `data` so the
    /// envelope shape stays predictable (sdp, ice, mute_state, etc.).
    /// The SDK does not parse this — the client renderer does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<BTreeMap<String, Value>>,
}

impl CallSignalPayload {
    /// Returns `true` when `signal_type` is in the canonical 14-value enum.
    pub fn signal_type_is_canonical(&self) -> bool {
        CALL_SIGNAL_TYPES.contains(&self.signal_type.as_str())
    }

    /// Reject envelopes whose `signal_type` is not in the canonical set.
    pub fn validate_signal_type(&self) -> Result<()> {
        if !self.signal_type_is_canonical() {
            return Err(Error::Protocol(format!(
                "ak.call.signal payload.signal_type {:?} not in canonical 14-value enum \
                 ({})",
                self.signal_type,
                ErrorCode::SCHEMA_VIOLATION
            )));
        }
        Ok(())
    }
}

/// Composite key for the `ak.call.signal` `seq` monotonicity
/// guard. Receivers maintain one `seq` per `(realm, call, actor,
/// device)` tuple; rollback rejects the signal and the receiver SHOULD
/// emit `hangup` for that call.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallSignalSeqKey {
    pub realm_id: RealmId,
    pub call_id: CallId,
    pub actor_id: Did,
    pub device_id: DeviceId,
}

impl CallSignalSeqKey {
    pub fn new(realm_id: RealmId, call_id: CallId, actor_id: Did, device_id: DeviceId) -> Self {
        Self {
            realm_id,
            call_id,
            actor_id,
            device_id,
        }
    }
}

/// Verify `next` is strictly greater than `prev` for the same
/// `key`. `prev = None` accepts any `next` (first observation).
///
/// Returns `Err(ErrorCode::SCHEMA_VIOLATION)` on rollback / repeat —
/// receivers MUST drop the signal and emit `hangup`.
pub fn validate_signal_seq(prev: Option<u64>, next: u64) -> Result<()> {
    match prev {
        None => Ok(()),
        Some(prev) if next > prev => Ok(()),
        Some(prev) => Err(Error::Protocol(format!(
            "ak.call.signal seq rollback prev={prev} next={next} ({})",
            ErrorCode::SCHEMA_VIOLATION
        ))),
    }
}

/// In-memory bookkeeping for `seq` monotonicity per key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallSignalState {
    seqs: BTreeMap<String, u64>,
}

impl CallSignalState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reduce a `seq` observation for `key`. Returns `Ok` when monotonic;
    /// `Err` (rollback) otherwise. On `Ok`, the per-key seq advances.
    pub fn observe(&mut self, key: &CallSignalSeqKey, next: u64) -> Result<()> {
        let composite = format!(
            "{}|{}|{}|{}",
            key.realm_id.as_str(),
            key.call_id.as_str(),
            key.actor_id.as_str(),
            key.device_id.as_str()
        );
        let prev = self.seqs.get(&composite).copied();
        validate_signal_seq(prev, next)?;
        self.seqs.insert(composite, next);
        Ok(())
    }
}

/// Verify that an `ak.call.signal` [`EphemeralEnvelope`] carries a device
/// binding and a payload with a canonical `signal_type`.
pub fn validate_call_signal_envelope(env: &EphemeralEnvelope) -> Result<CallSignalPayload> {
    if env.kind != "ak.call.signal" {
        return Err(Error::Protocol(format!(
            "envelope kind {:?} is not ak.call.signal",
            env.kind
        )));
    }
    let payload: CallSignalPayload = serde_json::from_value(Value::Object(
        env.payload.clone().into_iter().collect(),
    ))
    .map_err(|e| {
        Error::Protocol(format!(
            "ak.call.signal payload must carry {{call_id, signal_type, seq}}: {e} ({})",
            ErrorCode::SCHEMA_VIOLATION
        ))
    })?;
    payload.validate_signal_type()?;
    Ok(payload)
}
