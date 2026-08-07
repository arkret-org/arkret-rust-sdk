//! Closed plaintext carried by encrypted `ak.call.signal` envelopes.

use std::collections::BTreeMap;

use arkret_wire::{CallId, Error, Result, canonical};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallSignalPlaintextKind {
    #[serde(rename = "ak.call.signal")]
    CallSignal,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallSignalKind {
    Invite,
    Answer,
    Candidate,
    Reject,
    Hangup,
    Renegotiate,
    MuteState,
    MediaState,
    Speaking,
    FocusJoin,
    FocusLeave,
    Moderation,
    Error,
    Ack,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallSignalPlaintext {
    pub kind: CallSignalPlaintextKind,
    /// Signal-rail dedupe component, third member of the
    /// `(sender_device_id, scope_ref, payload_sequence)` triple
    /// (`sync/signal.md` §1.1).
    ///
    /// It coexists with [`Self::seq`] and neither may be omitted: `seq` is the
    /// per-call anti-rollback sequence monotonic over
    /// `(realm_id, call_id, actor_id, device_id)`, while this one is monotonic
    /// per sender device and signed scope across every Signal the device sends.
    /// Substituting one for the other degrades the receiver dedupe triple.
    pub payload_sequence: u64,
    pub call_id: CallId,
    pub signal_kind: CallSignalKind,
    pub seq: u64,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub data: BTreeMap<String, Value>,
}

impl CallSignalPlaintext {
    pub fn new(
        payload_sequence: u64,
        call_id: CallId,
        signal_kind: CallSignalKind,
        seq: u64,
        data: BTreeMap<String, Value>,
    ) -> Self {
        Self {
            kind: CallSignalPlaintextKind::CallSignal,
            payload_sequence,
            call_id,
            signal_kind,
            seq,
            data,
        }
    }

    pub fn from_plaintext(bytes: &[u8]) -> Result<Self> {
        Ok(canonical::from_canonical_json_slice(bytes)?)
    }

    pub fn canonical_plaintext(&self) -> Result<Vec<u8>> {
        canonical::canonical_json_bytes(self)
            .map_err(|error| Error::Protocol(format!("call signal plaintext: {error}")))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn call_id() -> CallId {
        CallId::new("ak:call:01904100-0000-8000-8000-000000000001").unwrap()
    }

    #[test]
    fn call_signal_plaintext_is_closed_and_requires_data() {
        let valid = json!({
            "kind": "ak.call.signal",
            "payload_sequence": 11,
            "call_id": call_id(),
            "signal_kind": "candidate",
            "seq": 3,
            "data": {"candidate": "opaque"}
        });
        let decoded: CallSignalPlaintext = serde_json::from_value(valid.clone()).unwrap();
        assert_eq!(decoded.seq, 3);
        // The two sequences are independent axes; carrying one is not carrying
        // the other.
        assert_eq!(decoded.payload_sequence, 11);

        let mut missing_data = valid.clone();
        missing_data.as_object_mut().unwrap().remove("data");
        assert!(serde_json::from_value::<CallSignalPlaintext>(missing_data).is_err());

        for required in ["payload_sequence", "seq"] {
            let mut missing = valid.clone();
            missing.as_object_mut().unwrap().remove(required);
            assert!(
                serde_json::from_value::<CallSignalPlaintext>(missing).is_err(),
                "{required} must not be omissible"
            );
        }

        let mut extra = valid;
        extra["actor_id"] = json!("did:webvh:z6mkfixture:alice.example");
        assert!(serde_json::from_value::<CallSignalPlaintext>(extra).is_err());
    }
}
