//! Ephemeral signal wire models and realtime call helpers.
//!
//! These are protocol-level types grouped by runtime surface rather than by the review batch that
//! introduced them. The broadcast [`EphemeralEnvelope`] wire shape migrated
//! to `arkret-models-collaboration` (re-exported below); the typed call
//! signal payload helpers and per-key sequence bookkeeping stay here.

pub use arkret_models_collaboration::events_payloads::ephemeral::{
    EPHEMERAL_ABSOLUTE_HARD_CEILING_MS, EphemeralEnvelope,
};

use super::*;

/// Typed `ak.call.signal` envelope payload.
///
/// The wire requires the three fields `call_id` + `signal_type` + `seq` and
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
                crate::ErrorCode::SCHEMA_VIOLATION
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
/// Returns `Err(crate::ErrorCode::SCHEMA_VIOLATION)` on rollback / repeat —
/// receivers MUST drop the signal and emit `hangup`.
pub fn validate_signal_seq(prev: Option<u64>, next: u64) -> Result<()> {
    match prev {
        None => Ok(()),
        Some(prev) if next > prev => Ok(()),
        Some(prev) => Err(Error::Protocol(format!(
            "ak.call.signal seq rollback prev={prev} next={next} ({})",
            crate::ErrorCode::SCHEMA_VIOLATION
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
            crate::ErrorCode::SCHEMA_VIOLATION
        ))
    })?;
    payload.validate_signal_type()?;
    Ok(payload)
}
