//! Framework-independent protocol rejection data.

use std::collections::BTreeMap;

use arkret_wire::error_codes::{ErrorCode, ErrorStatusContext};
use arkret_wire::problem_details::ErrorEnvelope;
use serde_json::Value;

/// Typed rejection shared by server implementations and framework adapters.
#[derive(Clone, Debug, PartialEq)]
pub struct ProtocolRejection {
    code: ErrorCode,
    message: Box<str>,
    status_context: Option<ErrorStatusContext>,
    retry_after_ms: Option<u64>,
    details: BTreeMap<String, Value>,
}

impl ProtocolRejection {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into().into_boxed_str(),
            status_context: None,
            retry_after_ms: None,
            details: BTreeMap::new(),
        }
    }

    pub fn with_status_context(mut self, context: ErrorStatusContext) -> Self {
        self.status_context = Some(context);
        self
    }

    pub fn with_retry_after_ms(mut self, retry_after_ms: u64) -> Self {
        self.retry_after_ms = Some(retry_after_ms);
        self
    }

    pub fn with_detail(mut self, key: impl Into<String>, value: impl serde::Serialize) -> Self {
        if let Ok(value) = serde_json::to_value(value) {
            self.details.insert(key.into(), value);
        }
        self
    }

    pub const fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub const fn status_context(&self) -> Option<ErrorStatusContext> {
        self.status_context
    }

    pub fn http_status(&self) -> u16 {
        self.status_context.map_or_else(
            || self.code.http_status(),
            |context| self.code.http_status_in(context),
        )
    }

    pub fn details(&self) -> &BTreeMap<String, Value> {
        &self.details
    }

    pub const fn retry_after_ms(&self) -> Option<u64> {
        self.retry_after_ms
    }

    pub fn into_envelope(self, request_id: impl Into<String>) -> ErrorEnvelope {
        let mut envelope = ErrorEnvelope::new(self.code.as_str(), self.message)
            .with_request_id(request_id)
            .with_retry_after_ms(self.retry_after_ms);
        for (key, value) in self.details {
            envelope = envelope.with_detail(key, value);
        }
        envelope
    }
}

impl std::fmt::Display for ProtocolRejection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProtocolRejection {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_is_derived_from_registry_and_context() {
        let protected = ProtocolRejection::new(ErrorCode::AccountDeactivated, "inactive")
            .with_status_context(ErrorStatusContext::ProtectedResource);
        let issuance = ProtocolRejection::new(ErrorCode::AccountDeactivated, "inactive")
            .with_status_context(ErrorStatusContext::SessionIssuanceOrRefresh);
        assert_eq!(protected.http_status(), 401);
        assert_eq!(issuance.http_status(), 403);
    }

    #[test]
    fn envelope_preserves_typed_code_and_details() {
        let envelope = ProtocolRejection::new(ErrorCode::ParamInvalid, "bad selector")
            .with_detail("reason_code", "selector_invalid")
            .with_retry_after_ms(250)
            .into_envelope("ak:request:test");
        assert_eq!(envelope.code(), "param_invalid");
        assert_eq!(envelope.request_id, "ak:request:test");
        assert_eq!(envelope.retry_after_ms(), Some(250));
        assert_eq!(
            envelope.details().get("reason_code"),
            Some(&Value::String("selector_invalid".to_owned()))
        );
    }
}
