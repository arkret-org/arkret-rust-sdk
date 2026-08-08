use std::collections::BTreeMap;
use std::fmt;
use std::result::Result as StdResult;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Closed issuer-ledger state returned for an exact replay whose recorded
/// grant has expired. This is not a hint to transparently issue again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionGrantReplayExpiredProblem {
    grant_id: crate::SessionGrantId,
    state: &'static str,
}

impl SessionGrantReplayExpiredProblem {
    pub fn new(grant_id: crate::SessionGrantId) -> Self {
        Self {
            grant_id,
            state: "expired",
        }
    }

    pub fn grant_id(&self) -> &crate::SessionGrantId {
        &self.grant_id
    }

    pub const fn state(&self) -> &'static str {
        self.state
    }
}

impl<'de> Deserialize<'de> for SessionGrantReplayExpiredProblem {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireDetails {
            grant_id: crate::SessionGrantId,
            state: String,
        }

        let wire = WireDetails::deserialize(deserializer)?;
        if wire.state != "expired" {
            return Err(serde::de::Error::custom("state must be expired"));
        }
        Ok(Self::new(wire.grant_id))
    }
}

/// Durable terminal states returned for an exact replay. The client must not
/// convert either state into an automatic re-issuance attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantReplayTerminalState {
    Revoked,
    Superseded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantReplayTerminalProblem {
    grant_id: crate::SessionGrantId,
    state: SessionGrantReplayTerminalState,
}

impl SessionGrantReplayTerminalProblem {
    pub fn new(grant_id: crate::SessionGrantId, state: SessionGrantReplayTerminalState) -> Self {
        Self { grant_id, state }
    }

    pub fn grant_id(&self) -> &crate::SessionGrantId {
        &self.grant_id
    }

    pub const fn state(&self) -> SessionGrantReplayTerminalState {
        self.state
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SessionGrantReplayProblemError {
    #[error("invalid session-grant replay error details: {0}")]
    InvalidDetails(#[from] serde_json::Error),
}

/// Closed details carried by a `claim_required` error when an agent action
/// needs out-of-band controller approval.
///
/// The fields are private so callers cannot construct a value with a different
/// reason code or an empty approval request id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AgentHumanApprovalProblem {
    reason_code: &'static str,
    approval_request_id: crate::OpaqueLocalId,
}

impl AgentHumanApprovalProblem {
    pub fn new(
        approval_request_id: impl Into<String>,
    ) -> StdResult<Self, AgentHumanApprovalProblemError> {
        let approval_request_id = crate::OpaqueLocalId::new(approval_request_id)
            .map_err(AgentHumanApprovalProblemError::InvalidApprovalRequestId)?;
        Ok(Self {
            reason_code: crate::ReasonCode::HUMAN_APPROVAL_REQUIRED,
            approval_request_id,
        })
    }

    pub const fn reason_code(&self) -> &'static str {
        self.reason_code
    }

    pub fn approval_request_id(&self) -> &str {
        self.approval_request_id.as_str()
    }

    fn into_wire_details(self) -> BTreeMap<String, Value> {
        BTreeMap::from([
            (
                "reason_code".to_owned(),
                Value::String(self.reason_code.to_owned()),
            ),
            (
                "approval_request_id".to_owned(),
                Value::String(self.approval_request_id.into_string()),
            ),
        ])
    }
}

impl<'de> Deserialize<'de> for AgentHumanApprovalProblem {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireDetails {
            reason_code: String,
            approval_request_id: String,
        }

        let wire = WireDetails::deserialize(deserializer)?;
        if wire.reason_code != crate::ReasonCode::HUMAN_APPROVAL_REQUIRED {
            return Err(serde::de::Error::custom(format!(
                "reason_code must be {}",
                crate::ReasonCode::HUMAN_APPROVAL_REQUIRED
            )));
        }
        Self::new(wire.approval_request_id).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AgentHumanApprovalProblemError {
    #[error("invalid approval_request_id: {0}")]
    InvalidApprovalRequestId(&'static str),
    #[error("invalid agent human-approval error details: {0}")]
    InvalidDetails(#[from] serde_json::Error),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, Value>,
}

impl ErrorDetail {
    /// Typed registry view of the wire `code` string. `None` when the code is
    /// not (or not yet) in the SDK's error-code registry, so callers can
    /// `match` on [`crate::error_codes::ErrorCode`] instead of comparing strings.
    pub fn error_code(&self) -> Option<crate::error_codes::ErrorCode> {
        crate::error_codes::ErrorCode::from_wire(&self.code)
    }

    /// Construct the only typed `claim_required` detail shape currently
    /// defined by the protocol.
    pub fn claim_required_human_approval(
        message: impl Into<String>,
        details: AgentHumanApprovalProblem,
    ) -> Self {
        Self {
            code: crate::error_codes::ErrorCode::CLAIM_REQUIRED.to_owned(),
            message: message.into(),
            retry_after_ms: None,
            details: details.into_wire_details(),
        }
    }

    /// Parse human-approval details only when the enclosing error code is
    /// `claim_required`. Other codes return `Ok(None)` without interpreting
    /// their open details map.
    pub fn agent_human_approval_details(
        &self,
    ) -> StdResult<Option<AgentHumanApprovalProblem>, AgentHumanApprovalProblemError> {
        if self.code != crate::error_codes::ErrorCode::CLAIM_REQUIRED {
            return Ok(None);
        }
        let value = Value::Object(self.details.clone().into_iter().collect());
        serde_json::from_value(value)
            .map(Some)
            .map_err(AgentHumanApprovalProblemError::from)
    }

    /// Decode the closed expired-record details only for the matching
    /// registry code. An indeterminate replay deliberately has no typed
    /// terminal details.
    pub fn session_grant_replay_expired_details(
        &self,
    ) -> StdResult<Option<SessionGrantReplayExpiredProblem>, SessionGrantReplayProblemError> {
        if self.code != crate::error_codes::ErrorCode::SESSION_GRANT_REPLAY_EXPIRED {
            return Ok(None);
        }
        serde_json::from_value(Value::Object(self.details.clone().into_iter().collect()))
            .map(Some)
            .map_err(SessionGrantReplayProblemError::from)
    }

    /// Decode the closed revoked/superseded record details only for the
    /// matching registry code.
    pub fn session_grant_replay_terminal_details(
        &self,
    ) -> StdResult<Option<SessionGrantReplayTerminalProblem>, SessionGrantReplayProblemError> {
        if self.code != crate::error_codes::ErrorCode::SESSION_GRANT_REPLAY_TERMINAL {
            return Ok(None);
        }
        serde_json::from_value(Value::Object(self.details.clone().into_iter().collect()))
            .map(Some)
            .map_err(SessionGrantReplayProblemError::from)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ErrorEnvelope {
    pub ok: bool,
    pub error: ErrorDetail,
    pub request_id: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Problem {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub problem_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl ErrorEnvelope {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: ErrorDetail {
                code: code.into(),
                message: message.into(),
                retry_after_ms: None,
                details: BTreeMap::new(),
            },
            request_id: "unknown".to_owned(),
        }
    }

    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.request_id = request_id.into();
        self
    }

    pub fn claim_required_human_approval(
        message: impl Into<String>,
        details: AgentHumanApprovalProblem,
    ) -> Self {
        Self {
            ok: false,
            error: ErrorDetail::claim_required_human_approval(message, details),
            request_id: "unknown".to_owned(),
        }
    }

    pub fn with_retry_after_ms(mut self, retry_after_ms: Option<u64>) -> Self {
        self.error.retry_after_ms = retry_after_ms;
        self
    }

    pub fn with_detail(mut self, key: impl Into<String>, value: Value) -> Self {
        self.error.details.insert(key.into(), value);
        self
    }

    pub fn code(&self) -> &str {
        &self.error.code
    }

    pub fn message(&self) -> &str {
        &self.error.message
    }

    pub fn retry_after_ms(&self) -> Option<u64> {
        self.error.retry_after_ms
    }

    pub fn details(&self) -> &BTreeMap<String, Value> {
        &self.error.details
    }

    pub fn agent_human_approval_details(
        &self,
    ) -> StdResult<Option<AgentHumanApprovalProblem>, AgentHumanApprovalProblemError> {
        self.error.agent_human_approval_details()
    }

    pub fn session_grant_replay_expired_details(
        &self,
    ) -> StdResult<Option<SessionGrantReplayExpiredProblem>, SessionGrantReplayProblemError> {
        self.error.session_grant_replay_expired_details()
    }

    pub fn session_grant_replay_terminal_details(
        &self,
    ) -> StdResult<Option<SessionGrantReplayTerminalProblem>, SessionGrantReplayProblemError> {
        self.error.session_grant_replay_terminal_details()
    }
}

impl fmt::Display for ErrorEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.error.code, self.error.message)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn human_approval_details_are_closed_and_round_trip_through_envelope() {
        let details = AgentHumanApprovalProblem::new("approval-opaque-01").unwrap();
        let envelope = ErrorEnvelope::claim_required_human_approval(
            "controller approval required",
            details.clone(),
        );

        assert_eq!(
            envelope.code(),
            crate::error_codes::ErrorCode::CLAIM_REQUIRED
        );
        assert_eq!(
            envelope.agent_human_approval_details().unwrap(),
            Some(details)
        );
        assert_eq!(
            serde_json::to_value(&envelope).unwrap()["error"]["details"],
            json!({
                "reason_code": "human_approval_required",
                "approval_request_id": "approval-opaque-01",
            })
        );
        assert_eq!(envelope.message(), "controller approval required");
    }

    #[test]
    fn human_approval_details_reject_invalid_shapes() {
        for invalid in [
            json!({"approval_request_id": "approval-opaque-01"}),
            json!({"reason_code": "human_approval_required"}),
            json!({
                "reason_code": "different_reason",
                "approval_request_id": "approval-opaque-01",
            }),
            json!({
                "reason_code": "human_approval_required",
                "approval_request_id": "",
            }),
            json!({
                "reason_code": "human_approval_required",
                "approval_request_id": "contains a space",
            }),
            json!({
                "reason_code": "human_approval_required",
                "approval_request_id": "a".repeat(129),
            }),
            json!({
                "reason_code": "human_approval_required",
                "approval_request_id": "approval-opaque-01",
                "captcha": "not-allowed",
            }),
        ] {
            assert!(serde_json::from_value::<AgentHumanApprovalProblem>(invalid).is_err());
        }
    }

    #[test]
    fn typed_accessor_ignores_non_claim_required_details() {
        let envelope = ErrorEnvelope::new("failed_precondition", "different error")
            .with_detail("reason_code", json!("human_approval_required"))
            .with_detail("approval_request_id", json!("approval-opaque-01"));

        assert_eq!(envelope.agent_human_approval_details().unwrap(), None);
    }

    #[test]
    fn error_envelope_serializes_to_spec_canonical_shape() {
        let envelope = ErrorEnvelope::new("capability_denied", "session grant is revoked")
            .with_request_id("ak:request:test")
            .with_retry_after_ms(None);

        assert_eq!(
            serde_json::to_value(envelope).unwrap(),
            json!({
                "ok": false,
                "error": {
                    "code": "capability_denied",
                    "message": "session grant is revoked"
                },
                "request_id": "ak:request:test"
            })
        );
    }

    #[test]
    fn unknown_error_code_is_preserved() {
        let details = ErrorDetail {
            code: "vendor_remote_error".to_owned(),
            message: "remote failure".to_owned(),
            retry_after_ms: None,
            details: Default::default(),
        };

        assert_eq!(details.error_code(), None);
        assert_eq!(details.code, "vendor_remote_error");
    }

    fn grant_id() -> crate::SessionGrantId {
        crate::SessionGrantId::new("ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW")
            .unwrap()
    }

    #[test]
    fn session_grant_replay_details_are_code_gated_and_closed() {
        let expired = ErrorEnvelope::new(
            crate::error_codes::ErrorCode::SESSION_GRANT_REPLAY_EXPIRED,
            "recorded grant expired",
        )
        .with_detail("grant_id", json!(grant_id()))
        .with_detail("state", json!("expired"));
        let details = expired
            .session_grant_replay_expired_details()
            .unwrap()
            .unwrap();
        assert_eq!(details.grant_id(), &grant_id());
        assert_eq!(details.state(), "expired");
        assert_eq!(
            expired.session_grant_replay_terminal_details().unwrap(),
            None
        );

        let terminal = ErrorEnvelope::new(
            crate::error_codes::ErrorCode::SESSION_GRANT_REPLAY_TERMINAL,
            "recorded grant is terminal",
        )
        .with_detail("grant_id", json!(grant_id()))
        .with_detail("state", json!("superseded"));
        assert_eq!(
            terminal
                .session_grant_replay_terminal_details()
                .unwrap()
                .unwrap()
                .state(),
            SessionGrantReplayTerminalState::Superseded
        );

        for invalid in [
            json!({"grant_id": grant_id(), "state": "revoked", "extra": true}),
            json!({"grant_id": grant_id(), "state": "active"}),
            json!({"state": "expired"}),
        ] {
            assert!(serde_json::from_value::<SessionGrantReplayExpiredProblem>(invalid).is_err());
        }
    }

    #[test]
    fn replay_indeterminate_never_fabricates_terminal_details() {
        let envelope = ErrorEnvelope::new(
            crate::error_codes::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
            "replay record no longer decidable",
        )
        .with_detail("grant_id", json!(grant_id()))
        .with_detail("state", json!("revoked"));

        assert_eq!(
            envelope.session_grant_replay_expired_details().unwrap(),
            None
        );
        assert_eq!(
            envelope.session_grant_replay_terminal_details().unwrap(),
            None
        );
    }
}
