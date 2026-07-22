use std::collections::BTreeMap;
use std::fmt;
use std::result::Result as StdResult;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Closed details carried by a `claim_required` error when an agent action
/// needs out-of-band controller approval.
///
/// The fields are private so callers cannot construct a value with a different
/// reason code or an empty approval request id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct AgentHumanApprovalErrorDetails {
    reason_code: &'static str,
    approval_request_id: String,
}

impl AgentHumanApprovalErrorDetails {
    pub fn new(
        approval_request_id: impl Into<String>,
    ) -> StdResult<Self, AgentHumanApprovalErrorDetailsError> {
        let approval_request_id = approval_request_id.into();
        if approval_request_id.trim().is_empty() {
            return Err(AgentHumanApprovalErrorDetailsError::EmptyApprovalRequestId);
        }
        if approval_request_id.len() > 128 {
            return Err(AgentHumanApprovalErrorDetailsError::ApprovalRequestIdTooLong);
        }
        if !approval_request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
        {
            return Err(AgentHumanApprovalErrorDetailsError::InvalidApprovalRequestId);
        }
        Ok(Self {
            reason_code: crate::ReasonCode::HUMAN_APPROVAL_REQUIRED,
            approval_request_id,
        })
    }

    pub const fn reason_code(&self) -> &'static str {
        self.reason_code
    }

    pub fn approval_request_id(&self) -> &str {
        &self.approval_request_id
    }

    fn into_wire_details(self) -> BTreeMap<String, Value> {
        BTreeMap::from([
            (
                "reason_code".to_owned(),
                Value::String(self.reason_code.to_owned()),
            ),
            (
                "approval_request_id".to_owned(),
                Value::String(self.approval_request_id),
            ),
        ])
    }
}

impl<'de> Deserialize<'de> for AgentHumanApprovalErrorDetails {
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
pub enum AgentHumanApprovalErrorDetailsError {
    #[error("approval_request_id must be non-empty")]
    EmptyApprovalRequestId,
    #[error("approval_request_id must be at most 128 ASCII characters")]
    ApprovalRequestIdTooLong,
    #[error("approval_request_id contains a character outside [A-Za-z0-9._:-]")]
    InvalidApprovalRequestId,
    #[error("invalid agent human-approval error details: {0}")]
    InvalidDetails(#[from] serde_json::Error),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
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
        details: AgentHumanApprovalErrorDetails,
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
    ) -> StdResult<Option<AgentHumanApprovalErrorDetails>, AgentHumanApprovalErrorDetailsError>
    {
        if self.code != crate::error_codes::ErrorCode::CLAIM_REQUIRED {
            return Ok(None);
        }
        let value = Value::Object(self.details.clone().into_iter().collect());
        serde_json::from_value(value)
            .map(Some)
            .map_err(AgentHumanApprovalErrorDetailsError::from)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ErrorEnvelope {
    pub ok: bool,
    pub error: ErrorDetail,
    pub request_id: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
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
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
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
        details: AgentHumanApprovalErrorDetails,
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
    ) -> StdResult<Option<AgentHumanApprovalErrorDetails>, AgentHumanApprovalErrorDetailsError>
    {
        self.error.agent_human_approval_details()
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
        let details = AgentHumanApprovalErrorDetails::new("approval-opaque-01").unwrap();
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
            assert!(serde_json::from_value::<AgentHumanApprovalErrorDetails>(invalid).is_err());
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
}
