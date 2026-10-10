use std::collections::BTreeMap;
use std::fmt;
use std::result::Result as StdResult;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Account stale-prefix continuation, not a newly installable checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AccountRevisionStaleProblem {
    continuation_cursor: String,
}

impl AccountRevisionStaleProblem {
    pub fn new(continuation_cursor: impl Into<String>) -> crate::Result<Self> {
        let continuation_cursor = continuation_cursor.into();
        let suffix = continuation_cursor
            .strip_prefix("ak:cursor:")
            .ok_or_else(|| {
                crate::WireError::Protocol("Account continuation is not a cursor token".into())
            })?;
        if suffix.is_empty()
            || suffix.len() > 2028
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(crate::WireError::Protocol(
                "Account continuation has invalid token shape".into(),
            ));
        }
        Ok(Self {
            continuation_cursor,
        })
    }

    pub fn continuation_cursor(&self) -> &str {
        &self.continuation_cursor
    }

    pub fn validate_after(&self, after: &str) -> crate::Result<()> {
        if self.continuation_cursor != after {
            return Err(crate::WireError::Protocol(
                "Account continuation differs from request after".into(),
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for AccountRevisionStaleProblem {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireDetails {
            continuation_cursor: String,
        }
        let wire = WireDetails::deserialize(deserializer)?;
        Self::new(wire.continuation_cursor).map_err(serde::de::Error::custom)
    }
}

/// Closed issuer-ledger state returned for an exact replay whose recorded
/// grant has expired. This is not a hint to transparently issue again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionGrantReplayExpiredProblem {
    session_grant_id: crate::SessionGrantId,
    state: &'static str,
}

impl SessionGrantReplayExpiredProblem {
    pub fn new(session_grant_id: crate::SessionGrantId) -> Self {
        Self {
            session_grant_id,
            state: "expired",
        }
    }

    pub fn session_grant_id(&self) -> &crate::SessionGrantId {
        &self.session_grant_id
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
            session_grant_id: crate::SessionGrantId,
            state: String,
        }

        let wire = WireDetails::deserialize(deserializer)?;
        if wire.state != "expired" {
            return Err(serde::de::Error::custom("state must be expired"));
        }
        Ok(Self::new(wire.session_grant_id))
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
    session_grant_id: crate::SessionGrantId,
    state: SessionGrantReplayTerminalState,
}

impl SessionGrantReplayTerminalProblem {
    pub fn new(
        session_grant_id: crate::SessionGrantId,
        state: SessionGrantReplayTerminalState,
    ) -> Self {
        Self {
            session_grant_id,
            state,
        }
    }

    pub fn session_grant_id(&self) -> &crate::SessionGrantId {
        &self.session_grant_id
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

/// Closed details carried by the `failed_precondition` that rejects an
/// `ak.invite.create` whose invitee already holds the Realm live-target slot
/// (`zh/models/governance-objects.md` section 5.3).
///
/// Both identifiers name the same 33-octet token under two prefixes. The pair
/// is derived here, never accepted from two independent inputs, so a producer
/// cannot emit an `invite_id` and a `create_event_id` that disagree and a
/// client cannot be handed an `expected_revision` value it has to re-spell
/// itself. The slot stores the `ak:event:` spelling verbatim:
/// [`Self::create_event_id`] is the value a release Event must assert, and
/// `invite_id` is only the object name to show a human or look a lifecycle up
/// by.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InviteLiveTargetOccupiedProblem {
    reason_code: &'static str,
    invite_id: crate::InviteId,
    create_event_id: crate::EventId,
}

impl InviteLiveTargetOccupiedProblem {
    /// Build the closed details from the slot value itself.
    ///
    /// The slot stores the occupying `ak.invite.create` Event id, so that is
    /// the only input: `invite_id` is its retype and cannot be passed in.
    pub fn new(create_event_id: crate::EventId) -> Self {
        Self {
            reason_code: crate::ReasonCode::INVITE_LIVE_TARGET_OCCUPIED,
            invite_id: crate::InviteId::from_event_id(&create_event_id),
            create_event_id,
        }
    }

    pub const fn reason_code(&self) -> &'static str {
        self.reason_code
    }

    pub fn invite_id(&self) -> &crate::InviteId {
        &self.invite_id
    }

    /// The current slot value, and therefore the exact `expected_revision`
    /// value a release Event must carry. Always the `ak:event:` spelling.
    pub fn create_event_id(&self) -> &crate::EventId {
        &self.create_event_id
    }

    fn into_wire_details(self) -> BTreeMap<String, Value> {
        BTreeMap::from([
            (
                "reason_code".to_owned(),
                Value::String(self.reason_code.to_owned()),
            ),
            (
                "invite_id".to_owned(),
                Value::String(self.invite_id.into_string()),
            ),
            (
                "create_event_id".to_owned(),
                Value::String(self.create_event_id.into_string()),
            ),
        ])
    }
}

impl<'de> Deserialize<'de> for InviteLiveTargetOccupiedProblem {
    fn deserialize<D>(deserializer: D) -> StdResult<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireDetails {
            reason_code: String,
            invite_id: crate::InviteId,
            create_event_id: crate::EventId,
        }

        let wire = WireDetails::deserialize(deserializer)?;
        if wire.reason_code != crate::ReasonCode::INVITE_LIVE_TARGET_OCCUPIED {
            return Err(serde::de::Error::custom(format!(
                "reason_code must be {}",
                crate::ReasonCode::INVITE_LIVE_TARGET_OCCUPIED
            )));
        }
        let details = Self::new(wire.create_event_id);
        // The two members are one token under two prefixes. A pair that does
        // not retype into itself is a producer that spelled one of them by
        // hand, which is the exact failure that leaks the slot forever.
        if details.invite_id != wire.invite_id {
            return Err(serde::de::Error::custom(
                "invite_id must be the retype of create_event_id",
            ));
        }
        Ok(details)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InviteLiveTargetOccupiedProblemError {
    #[error("invalid invite live-target occupied error details: {0}")]
    InvalidDetails(#[from] serde_json::Error),
}

/// Canonical RFC 9457 Problem Details wire object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(default, flatten)]
    pub extensions: BTreeMap<String, Value>,
}

#[cfg(feature = "openapi")]
impl salvo_oapi::ToSchema for Problem {
    fn to_schema(
        _components: &mut salvo_oapi::Components,
    ) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {
        use salvo_oapi::schema::{BasicType, Object};

        let string = || Object::new().schema_type(BasicType::String);
        Object::new()
            .property("type", string())
            .property("title", string())
            .property("status", Object::new().schema_type(BasicType::Integer))
            .property("detail", string())
            .property("instance", string())
            .required("type")
            .required("title")
            .required("status")
            .required("detail")
            .additional_properties(Object::new())
            .into()
    }
}

#[cfg(feature = "openapi")]
impl salvo_oapi::ComposeSchema for Problem {
    fn compose(
        components: &mut salvo_oapi::Components,
        _generics: Vec<salvo_oapi::RefOr<salvo_oapi::schema::Schema>>,
    ) -> salvo_oapi::RefOr<salvo_oapi::schema::Schema> {
        <Self as salvo_oapi::ToSchema>::to_schema(components)
    }
}

const PROBLEM_TYPE_BASE: &str = "https://arkret.org/problems/";

fn problem_title(code: &str) -> String {
    let mut title = code.replace('_', " ");
    if let Some(first) = title.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    title
}

impl Problem {
    pub fn new(code: impl Into<String>, status: u16, detail: impl Into<String>) -> Self {
        let code = code.into();
        let registered = crate::error_codes::ErrorCode::from_wire(&code);
        let problem_type = registered.map_or_else(
            || {
                if code.starts_with("https://") || code.starts_with("http://") {
                    code.clone()
                } else {
                    format!("{PROBLEM_TYPE_BASE}{code}")
                }
            },
            |entry| entry.type_uri().to_owned(),
        );
        Self {
            problem_type,
            title: registered
                .map_or_else(|| problem_title(&code), |entry| entry.title().to_owned()),
            status,
            detail: detail.into(),
            instance: None,
            extensions: BTreeMap::new(),
        }
    }

    pub fn code(&self) -> &str {
        self.problem_type
            .strip_prefix(PROBLEM_TYPE_BASE)
            .unwrap_or(&self.problem_type)
    }

    /// Typed registry view of the wire code, so callers can `match` on
    /// [`crate::error_codes::ErrorCode`] instead of comparing strings.
    /// `None` when the code is not (or not yet) in the registry.
    #[must_use]
    pub fn error_code(&self) -> Option<crate::error_codes::ErrorCode> {
        crate::error_codes::ErrorCode::from_wire(self.code())
    }

    /// Override the HTTP status the registry chose for this code.
    ///
    /// A transport that already decided the response status uses this so the
    /// rendered body and the response line cannot disagree.
    #[must_use]
    pub const fn with_status(mut self, status: u16) -> Self {
        self.status = status;
        self
    }

    pub fn with_instance(mut self, instance: impl Into<String>) -> Self {
        self.instance = Some(instance.into());
        self
    }

    pub fn with_extension(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extensions.insert(key.into(), value);
        self
    }

    /// Build a Problem from a registered error code, taking the HTTP status
    /// from the registry.
    ///
    /// This is the constructor most call sites want: they know the code and
    /// the message, and the status is a property of the code. [`Self::new`]
    /// stays for the caller that must override the registry's status.
    ///
    /// An unregistered code has no registry status; 500 is the same fallback
    /// the compatibility envelope used before it was removed.
    pub fn from_code(code: impl Into<String>, detail: impl Into<String>) -> Self {
        let code = code.into();
        let status = crate::error_codes::ErrorCode::from_wire(&code)
            .map_or(500, crate::error_codes::ErrorCode::http_status);
        Self::new(code, status, detail)
    }

    /// The `claim_required` problem carrying the closed human-approval object.
    pub fn claim_required_human_approval(
        detail: impl Into<String>,
        details: AgentHumanApprovalProblem,
    ) -> Self {
        Self::from_code(crate::error_codes::ErrorCode::CLAIM_REQUIRED, detail)
            .with_extensions(details.into_wire_details())
    }

    /// The closed `failed_precondition` problem returned when an
    /// `ak.invite.create` hits an occupied Realm live-target slot.
    ///
    /// The rejection is atomic: the Event is not accepted, enters no canonical
    /// history and derives no projection or notification.
    pub fn invite_live_target_occupied(
        detail: impl Into<String>,
        details: InviteLiveTargetOccupiedProblem,
    ) -> Self {
        Self::from_code(crate::error_codes::ErrorCode::FAILED_PRECONDITION, detail)
            .with_extensions(details.into_wire_details())
    }

    fn with_extensions(mut self, extensions: BTreeMap<String, Value>) -> Self {
        self.extensions.extend(extensions);
        self
    }

    /// Producer helper for the registered Account operation branch only.
    pub fn account_revision_stale(
        detail: impl Into<String>,
        details: AccountRevisionStaleProblem,
    ) -> Self {
        Self::from_code(crate::error_codes::ErrorCode::REVISION_STALE, detail).with_extension(
            "continuation_cursor",
            Value::String(details.continuation_cursor),
        )
    }

    /// Only an Account continuation consumer may interpret this extension.
    /// Unknown RFC 9457 members remain tolerated; missing or malformed recovery
    /// material is not a command to reset or to install a new checkpoint.
    pub fn account_revision_stale_details(
        &self,
    ) -> crate::Result<Option<AccountRevisionStaleProblem>> {
        if self.error_code() != Some(crate::error_codes::ErrorCode::RevisionStale) {
            return Ok(None);
        }
        if self.status != 409 {
            return Err(crate::WireError::Protocol(
                "Account revision_stale requires status 409".into(),
            ));
        }
        let cursor = self
            .extensions
            .get("continuation_cursor")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                crate::WireError::Protocol("Account revision_stale lacks its continuation".into())
            })?;
        AccountRevisionStaleProblem::new(cursor).map(Some)
    }

    /// Set (or clear) the retry hint carried as the `retry_after_ms` extension.
    pub fn with_retry_after_ms(mut self, retry_after_ms: Option<u64>) -> Self {
        match retry_after_ms {
            Some(value) => {
                self.extensions
                    .insert("retry_after_ms".to_owned(), Value::Number(value.into()));
            }
            None => {
                self.extensions.remove("retry_after_ms");
            }
        }
        self
    }

    /// The retry hint, when the peer sent one as a non-negative integer.
    #[must_use]
    pub fn retry_after_ms(&self) -> Option<u64> {
        self.extensions
            .get("retry_after_ms")
            .and_then(Value::as_u64)
    }

    /// Decode the occupied-slot details only when the enclosing code is
    /// `failed_precondition` and the details carry the matching reason code.
    ///
    /// Any other `failed_precondition` returns `Ok(None)`: the top-level code
    /// is shared by many sub-reasons, so the reason code inside the closed
    /// object is what selects this shape.
    pub fn invite_live_target_occupied_details(
        &self,
    ) -> StdResult<Option<InviteLiveTargetOccupiedProblem>, InviteLiveTargetOccupiedProblemError>
    {
        if self.code() != crate::error_codes::ErrorCode::FAILED_PRECONDITION {
            return Ok(None);
        }
        if self.extensions.get("reason_code").and_then(Value::as_str)
            != Some(crate::ReasonCode::INVITE_LIVE_TARGET_OCCUPIED)
        {
            return Ok(None);
        }
        self.decode_extensions()
            .map(Some)
            .map_err(InviteLiveTargetOccupiedProblemError::from)
    }

    /// Parse human-approval details only when the enclosing error code is
    /// `claim_required`. Other codes return `Ok(None)` without interpreting
    /// their open extensions.
    pub fn agent_human_approval_details(
        &self,
    ) -> StdResult<Option<AgentHumanApprovalProblem>, AgentHumanApprovalProblemError> {
        if self.code() != crate::error_codes::ErrorCode::CLAIM_REQUIRED {
            return Ok(None);
        }
        self.decode_extensions()
            .map(Some)
            .map_err(AgentHumanApprovalProblemError::from)
    }

    /// Decode the closed expired-record details only for the matching registry
    /// code. An indeterminate replay deliberately has no typed terminal
    /// details.
    pub fn session_grant_replay_expired_details(
        &self,
    ) -> StdResult<Option<SessionGrantReplayExpiredProblem>, SessionGrantReplayProblemError> {
        if self.code() != crate::error_codes::ErrorCode::SESSION_GRANT_REPLAY_EXPIRED {
            return Ok(None);
        }
        self.decode_extensions()
            .map(Some)
            .map_err(SessionGrantReplayProblemError::from)
    }

    /// Decode the closed revoked/superseded record details only for the
    /// matching registry code.
    pub fn session_grant_replay_terminal_details(
        &self,
    ) -> StdResult<Option<SessionGrantReplayTerminalProblem>, SessionGrantReplayProblemError> {
        if self.code() != crate::error_codes::ErrorCode::SESSION_GRANT_REPLAY_TERMINAL {
            return Ok(None);
        }
        self.decode_extensions()
            .map(Some)
            .map_err(SessionGrantReplayProblemError::from)
    }

    /// The extensions map as the closed object a typed decoder expects.
    ///
    /// `retry_after_ms` is a transport hint rather than part of any closed
    /// details object, so it is dropped before decoding: leaving it in would
    /// make every `deny_unknown_fields` details type fail on a problem that
    /// merely carried a retry hint alongside them.
    fn decode_extensions<T: serde::de::DeserializeOwned>(&self) -> serde_json::Result<T> {
        let mut extensions = self.extensions.clone();
        extensions.remove("retry_after_ms");
        serde_json::from_value(Value::Object(extensions.into_iter().collect()))
    }
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code(), self.detail)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn human_approval_details_are_closed_and_round_trip_through_the_problem() {
        let details = AgentHumanApprovalProblem::new("approval-opaque-01").unwrap();
        let envelope =
            Problem::claim_required_human_approval("controller approval required", details.clone());

        assert_eq!(
            envelope.code(),
            crate::error_codes::ErrorCode::CLAIM_REQUIRED
        );
        assert_eq!(
            envelope.agent_human_approval_details().unwrap(),
            Some(details)
        );
        assert_eq!(
            serde_json::to_value(&envelope).unwrap(),
            json!({
                "type": "https://arkret.org/problems/claim_required",
                "title": "Claim required",
                "status": 403,
                "detail": "controller approval required",
                "reason_code": "human_approval_required",
                "approval_request_id": "approval-opaque-01",
            })
        );
        assert_eq!(envelope.detail, "controller approval required");
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
        let envelope = Problem::from_code("failed_precondition", "different error")
            .with_extension("reason_code", json!("human_approval_required"))
            .with_extension("approval_request_id", json!("approval-opaque-01"));

        assert_eq!(envelope.agent_human_approval_details().unwrap(), None);
    }

    #[test]
    fn a_problem_built_from_a_registered_code_takes_the_registry_status() {
        let envelope = Problem::from_code("capability_denied", "session grant is revoked")
            .with_instance("ak:request:test")
            .with_retry_after_ms(None);

        assert_eq!(
            serde_json::to_value(envelope).unwrap(),
            json!({
                "type": "https://arkret.org/problems/capability_denied",
                "title": "Capability denied",
                "status": 403,
                "detail": "session grant is revoked",
                "instance": "ak:request:test"
            })
        );
    }

    #[test]
    fn account_stale_continuation_is_typed_exact_and_not_a_new_cut() {
        let after = "ak:cursor:account-backfill";
        let problem = Problem::account_revision_stale(
            "recoverable lag",
            AccountRevisionStaleProblem::new(after).unwrap(),
        )
        .with_extension("future_hint", json!(true));
        let details = problem.account_revision_stale_details().unwrap().unwrap();
        details.validate_after(after).unwrap();
        assert!(details.validate_after("ak:cursor:another-cut").is_err());
        assert_eq!(details.continuation_cursor(), after);
        let mut wrong_status = problem.clone();
        wrong_status.status = 400;
        assert!(wrong_status.account_revision_stale_details().is_err());
        let wrong_code = Problem::from_code("cas_conflict", "not recovery")
            .with_extension("continuation_cursor", json!(after));
        assert!(
            wrong_code
                .account_revision_stale_details()
                .unwrap()
                .is_none()
        );
        assert!(
            Problem::from_code("revision_stale", "missing recovery")
                .account_revision_stale_details()
                .is_err()
        );
        for token in [
            "",
            "ak:cursor:",
            "ak:cursor:with space",
            "ak:cursor:with+plus",
        ] {
            assert!(AccountRevisionStaleProblem::new(token).is_err());
        }
        assert!(
            AccountRevisionStaleProblem::new(format!("ak:cursor:{}", "a".repeat(2029))).is_err()
        );
    }

    #[test]
    fn a_problem_decodes_the_rfc_9457_wire() {
        let decoded = serde_json::from_value::<Problem>(json!({
            "type": "https://arkret.org/problems/not_found",
            "title": "Not found",
            "status": 404,
            "detail": "not found",
            "instance": "ak:request:test",
            "reason_code": "hidden"
        }))
        .unwrap();
        assert_eq!(decoded.code(), "not_found");
        assert_eq!(decoded.instance.as_deref(), Some("ak:request:test"));
        assert_eq!(decoded.extensions["reason_code"], "hidden");
    }

    #[test]
    fn unknown_error_code_is_preserved() {
        let problem = Problem::from_code("vendor_remote_error", "remote failure");

        // Not in the registry: no typed view, and the fallback status.
        assert_eq!(problem.error_code(), None);
        assert_eq!(problem.code(), "vendor_remote_error");
        assert_eq!(problem.status, 500);
    }

    fn session_grant_id() -> crate::SessionGrantId {
        crate::SessionGrantId::new("ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW")
            .unwrap()
    }

    #[test]
    fn session_grant_replay_details_are_code_gated_and_closed() {
        let expired = Problem::from_code(
            crate::error_codes::ErrorCode::SESSION_GRANT_REPLAY_EXPIRED,
            "recorded grant expired",
        )
        .with_extension("session_grant_id", json!(session_grant_id()))
        .with_extension("state", json!("expired"));
        let details = expired
            .session_grant_replay_expired_details()
            .unwrap()
            .unwrap();
        assert_eq!(details.session_grant_id(), &session_grant_id());
        assert_eq!(details.state(), "expired");
        assert_eq!(
            expired.session_grant_replay_terminal_details().unwrap(),
            None
        );

        let terminal = Problem::from_code(
            crate::error_codes::ErrorCode::SESSION_GRANT_REPLAY_TERMINAL,
            "recorded grant is terminal",
        )
        .with_extension("session_grant_id", json!(session_grant_id()))
        .with_extension("state", json!("superseded"));
        assert_eq!(
            terminal
                .session_grant_replay_terminal_details()
                .unwrap()
                .unwrap()
                .state(),
            SessionGrantReplayTerminalState::Superseded
        );

        for invalid in [
            json!({"session_grant_id": session_grant_id(), "state": "revoked", "extra": true}),
            json!({"session_grant_id": session_grant_id(), "state": "active"}),
            json!({"state": "expired"}),
        ] {
            assert!(serde_json::from_value::<SessionGrantReplayExpiredProblem>(invalid).is_err());
        }
    }

    #[test]
    fn replay_indeterminate_never_fabricates_terminal_details() {
        let envelope = Problem::from_code(
            crate::error_codes::ErrorCode::SESSION_GRANT_REPLAY_INDETERMINATE,
            "replay record no longer decidable",
        )
        .with_extension("session_grant_id", json!(session_grant_id()))
        .with_extension("state", json!("revoked"));

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
