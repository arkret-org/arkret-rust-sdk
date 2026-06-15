//! Ephemeral signal wire models and realtime call helpers.
//!
//! These are protocol-level types grouped by runtime surface rather than by the review batch that
//! introduced them.

use super::*;
use crate::ERROR_CODE_INVALID_PARAM;

/// Absolute hard ceiling on `expires_at - sent_at` for an ephemeral signal,
/// in milliseconds. Per `schemas/ephemeral-envelope.schema.json`:
/// "Signals with expires_at > sent_at + 5 minutes MUST be dropped by
/// receivers (`invalid_param`)." Five minutes = 300_000 ms. Round R2/R3.
pub const EPHEMERAL_ABSOLUTE_HARD_CEILING_MS: u32 = 300_000;

/// Broadcast ephemeral envelope (`ck.schema.ephemeral_envelope.v1`).
///
/// Wire shape for the four broadcast ephemeral signal kinds — `ck.presence`,
/// `ck.typing`, `ck.receipt.read`, `ck.call.signal`. Carried on dedicated
/// ephemeral channels (sync subscribe live stream, presence/typing fanout,
/// call signaling channel) and dropped at TTL. Point-to-point to-device
/// signals (`ck.key.verification.*`) use the device message schema instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct EphemeralEnvelope {
    /// Ephemeral signal kind. MUST be one of the four broadcast forms.
    pub kind: String,
    pub realm_id: RealmId,
    pub actor_id: Did,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    pub sent_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Kind-specific signal payload. Schema per kind is defined by the
    /// producing module; MUST NOT carry mutable governance state.
    pub payload: Value,
    /// Optional detached signature over canonical envelope bytes
    /// (excluding `proof` itself). REQUIRED for `ck.call.signal` in E2EE
    /// Realms; RECOMMENDED for `ck.receipt.read`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<Value>,
}

impl EphemeralEnvelope {
    pub const SCHEMA: &'static str = "ck.schema.ephemeral_envelope.v1";

    /// Construct with validation. Rejects:
    /// - non-ephemeral `kind`
    /// - `expires_at - sent_at > EPHEMERAL_ABSOLUTE_HARD_CEILING_MS` (5 min)
    /// - `expires_at <= sent_at`
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: impl Into<String>,
        realm_id: RealmId,
        actor_id: Did,
        device_id: Option<DeviceId>,
        sent_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        payload: Value,
        proof: Option<Value>,
    ) -> Result<Self> {
        let kind = kind.into();
        if !matches!(
            kind.as_str(),
            "ck.call.signal" | "ck.presence" | "ck.typing" | "ck.receipt.read"
        ) {
            return Err(Error::Protocol(format!(
                "ephemeral envelope kind {kind:?} not in {{ck.call.signal, ck.presence, ck.typing, ck.receipt.read}}"
            )));
        }
        if expires_at <= sent_at {
            return Err(Error::Protocol(
                "ephemeral envelope expires_at must be strictly after sent_at".to_owned(),
            ));
        }
        let window_ms = expires_at.signed_duration_since(sent_at).num_milliseconds();
        if window_ms < 0 || (window_ms as u64) > EPHEMERAL_ABSOLUTE_HARD_CEILING_MS as u64 {
            return Err(Error::Protocol(format!(
                "ephemeral envelope window {window_ms}ms exceeds absolute hard ceiling \
                 {EPHEMERAL_ABSOLUTE_HARD_CEILING_MS}ms ({ERROR_CODE_INVALID_PARAM})"
            )));
        }
        Ok(Self {
            kind,
            realm_id,
            actor_id,
            device_id,
            sent_at,
            expires_at,
            payload,
            proof,
        })
    }
}

// ── EphemeralEnvelope v2 / ck.call.signal ───────────────────────────────

/// Round 4 (commit 58c5926) — typed `ck.call.signal` envelope payload.
///
/// The pre-round-4 envelope carried an open `Value` payload; the round-4
/// wire requires the three fields `call_id` + `signal_type` + `seq` and
/// validates `signal_type` against [`crate::CALL_SIGNAL_TYPES`] (14
/// values). `seq` is monotonic per `(realm, call, actor, device)` —
/// see [`validate_signal_seq`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct CallSignalPayload {
    pub call_id: CallId,
    pub signal_type: String,
    pub seq: u64,
    /// Per-signal_type extra fields nested under `data` so the
    /// envelope shape stays predictable (sdp, ice, mute_state, etc.).
    /// The SDK does not parse this — the client renderer does.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub data: Value,
}

impl CallSignalPayload {
    /// Returns `true` when `signal_type` is in the round-4 canonical
    /// 14-value enum.
    pub fn signal_type_is_canonical(&self) -> bool {
        CALL_SIGNAL_TYPES.contains(&self.signal_type.as_str())
    }

    /// Reject envelopes whose `signal_type` is not in the canonical set.
    pub fn validate_signal_type(&self) -> Result<()> {
        if !self.signal_type_is_canonical() {
            return Err(Error::Protocol(format!(
                "ck.call.signal payload.signal_type {:?} not in canonical 14-value enum \
                 ({})",
                self.signal_type,
                crate::ERROR_CODE_SCHEMA_VIOLATION
            )));
        }
        Ok(())
    }
}

/// Round 4 — composite key for the `ck.call.signal` `seq` monotonicity
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

/// Round 4 — verify `next` is strictly greater than `prev` for the same
/// `key`. `prev = None` accepts any `next` (first observation).
///
/// Returns `Err(ERROR_CODE_SCHEMA_VIOLATION)` on rollback / repeat —
/// receivers MUST drop the signal and emit `hangup`.
pub fn validate_signal_seq(prev: Option<u64>, next: u64) -> Result<()> {
    match prev {
        None => Ok(()),
        Some(prev) if next > prev => Ok(()),
        Some(prev) => Err(Error::Protocol(format!(
            "ck.call.signal seq rollback prev={prev} next={next} ({})",
            crate::ERROR_CODE_SCHEMA_VIOLATION
        ))),
    }
}

/// Round 4 — in-memory bookkeeping for `seq` monotonicity per key.
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

// ── EphemeralEnvelope v2 helpers (ck.call.signal required fields) ────

/// Round 4 — verify a `ck.call.signal` [`EphemeralEnvelope`] satisfies
/// the v2 wire requirements: `device_id` + `proof` are REQUIRED, and
/// the payload deserialises into a [`CallSignalPayload`] with a
/// canonical `signal_type`.
pub fn validate_call_signal_envelope(env: &EphemeralEnvelope) -> Result<CallSignalPayload> {
    if env.kind != "ck.call.signal" {
        return Err(Error::Protocol(format!(
            "envelope kind {:?} is not ck.call.signal",
            env.kind
        )));
    }
    if env.device_id.is_none() {
        return Err(Error::Protocol(format!(
            "ck.call.signal envelope MUST carry device_id ({})",
            crate::ERROR_CODE_SCHEMA_VIOLATION
        )));
    }
    if env.proof.is_none() {
        return Err(Error::Protocol(format!(
            "ck.call.signal envelope MUST carry proof ({})",
            crate::ERROR_CODE_SCHEMA_VIOLATION
        )));
    }
    let payload: CallSignalPayload = serde_json::from_value(env.payload.clone()).map_err(|e| {
        Error::Protocol(format!(
            "ck.call.signal payload must carry {{call_id, signal_type, seq}}: {e} ({})",
            crate::ERROR_CODE_SCHEMA_VIOLATION
        ))
    })?;
    payload.validate_signal_type()?;
    Ok(payload)
}
