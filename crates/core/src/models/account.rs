use super::*;

fn is_default_registration_verification_policy(
    value: &AccountRegistrationVerificationPolicy,
) -> bool {
    !value.required && value.code_digest.is_none()
}

fn is_default_registration_invitation_policy(value: &AccountRegistrationInvitationPolicy) -> bool {
    !value.required && value.token_digests.is_empty()
}

fn registration_policy_enabled_default() -> bool {
    true
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountRegistrationVerificationPolicy {
    #[serde(default, skip_serializing_if = "is_false")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_digest: Option<Hash>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountRegistrationInvitationPolicy {
    #[serde(default, skip_serializing_if = "is_false")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub token_digests: Vec<Hash>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountRegistrationRateLimitPolicy {
    pub max_attempts: u32,
    pub window_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountRegistrationPolicy {
    #[serde(default = "registration_policy_enabled_default")]
    pub enabled: bool,
    #[serde(
        default,
        skip_serializing_if = "is_default_registration_verification_policy"
    )]
    pub verification_code: AccountRegistrationVerificationPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub organization_allowlist: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "is_default_registration_invitation_policy"
    )]
    pub invitation: AccountRegistrationInvitationPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<AccountRegistrationRateLimitPolicy>,
}

impl Default for AccountRegistrationPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            verification_code: AccountRegistrationVerificationPolicy::default(),
            organization_allowlist: Vec::new(),
            invitation: AccountRegistrationInvitationPolicy::default(),
            rate_limit: None,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountRegistrationPolicyEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invitation_token: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AccountRegistrationAuditOutcome {
    Accepted,
    RegistrationClosed,
    VerificationCodeRequired,
    VerificationCodeInvalid,
    OrganizationNotAllowed,
    InvitationRequired,
    InvitationInvalid,
    RateLimited,
    DuplicateConflict,
}

impl AccountRegistrationAuditOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::RegistrationClosed => "registration_closed",
            Self::VerificationCodeRequired => "verification_code_required",
            Self::VerificationCodeInvalid => "verification_code_invalid",
            Self::OrganizationNotAllowed => "organization_not_allowed",
            Self::InvitationRequired => "invitation_required",
            Self::InvitationInvalid => "invitation_invalid",
            Self::RateLimited => "rate_limited",
            Self::DuplicateConflict => "duplicate_conflict",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountRegistrationEvidenceSummary {
    #[serde(default, skip_serializing_if = "is_false")]
    pub verification_code_present: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub invitation_token_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountRegistrationAudit {
    pub outcome: AccountRegistrationAuditOutcome,
    pub policy_digest: Hash,
    pub evidence: AccountRegistrationEvidenceSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountDataReplaceRequestBody {
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub content: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountDataEntry {
    pub data_type: String,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    pub content: Value,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountDataList {
    #[serde(default)]
    pub entries: Vec<AccountDataEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountDataDeleteOutcome {
    pub ok: bool,
    pub data_type: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ConsentState {
    Active,
    Pending,
    Revoked,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ConsentCellView {
    pub ok: bool,
    pub cell_id: String,
    pub holder_did: Did,
    pub peer_did: Did,
    pub consent_scope: ConsentScope,
    pub state: ConsentState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub active_grant_dots: Vec<String>,
    #[serde(default)]
    pub grant_dots: Vec<String>,
    #[serde(default)]
    pub revoked_dots: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ConsentCellList {
    pub ok: bool,
    #[serde(default)]
    pub cells: Vec<ConsentCellView>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ConsentUpdateRequestBody {
    pub peer_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consent_scope: Option<ConsentScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ConsentRequestRequestBody {
    pub holder_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_did: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consent_scope: Option<ConsentScope>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountDeviceSummary {
    pub device_id: DeviceId,
    pub status: String,
    /// device-lifecycle.md §6 trust dimension: `unverified` / `cross_signed`
    /// / `needs_reverification` / `verified`. Distinct from `status`, which is
    /// the lifecycle rollup (`active` / `revoked` / `unknown`). Clients render
    /// the §6 trust pill and gate device-to-device pairing fan-out on it.
    pub verification_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountLifecycleProof {
    pub proof_kind: String,
    pub challenge: String,
    pub request_canonical_digest: Hash,
    pub audience: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<String>,
    pub signature: String,
}

pub const ACCOUNT_LIFECYCLE_PROOF_SCHEMA: &str = "ak.schema.account_lifecycle_proof.v1";
pub const SESSION_REVOKE_LIFECYCLE_PROOF_KIND: &str =
    "ak.account.lifecycle_proof.session_revoke.v1";
pub const SESSION_REVOKE_OPERATION_ID: &str = "ak.gate.account.command.revoke_session";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionGrantAppletSelector {
    pub applet_id: String,
    pub effective_scope: Value,
    pub registration_epoch: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_grant_refs: Vec<String>,
}

impl AccountLifecycleProof {
    pub fn session_revoke_request_digest(
        actor_id: &Did,
        service_id: &Did,
        session_device_id: &DeviceId,
        target_grant_id: Option<&GrantId>,
        target_device_id: Option<&DeviceId>,
        all_sessions: bool,
        applet_selector: Option<&SessionGrantAppletSelector>,
    ) -> Result<Hash> {
        let request = json!({
            "schema": "ak.schema.session_revoke.request.v1",
            "operation": SESSION_REVOKE_OPERATION_ID,
            "actor_id": actor_id,
            "service_id": service_id,
            "session_device_id": session_device_id,
            "target_grant_id": target_grant_id,
            "target_device_id": target_device_id,
            "all_sessions": all_sessions,
            "applet_selector": applet_selector,
        });
        Ok(Hash::new(canonical::canonical_sha256(&request)?)?)
    }

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        let signing_input = json!({
            "schema": ACCOUNT_LIFECYCLE_PROOF_SCHEMA,
            "proof_kind": &self.proof_kind,
            "challenge": &self.challenge,
            "request_canonical_digest": &self.request_canonical_digest,
            "audience": &self.audience,
            "issued_at": &self.issued_at,
            "expires_at": &self.expires_at,
            "verification_method": &self.verification_method,
        });
        Ok(canonical::canonical_json_bytes(&signing_input)?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountView {
    pub principal_id: Did,
    pub state: AccountStatus,
    #[serde(default)]
    pub devices: Vec<AccountDeviceSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_handle_claim: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_handle_claim_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handle_claim_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ActorProfile>,
    /// True when the authenticated principal is a deployment server
    /// administrator (the server's configured admin principal set). Operator-only
    /// product surfaces (e.g. organization creation) gate their UI on this.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub is_server_admin: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountRegisterRequestBody {
    pub principal_id: Did,
    /// Optional canonical registration handle (`<localpart>:<domain>`) the
    /// Account Authority asserts. When present and the localpart is available,
    /// the Principal Server issues the first signed handle claim and returns it
    /// as `AccountRegisterOutcome.primary_handle_claim` (identity-handles.md
    /// §3.7.1; never an unsigned bare handle).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<AccountLifecycleProof>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_evidence: Option<AccountRegistrationPolicyEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountRegisterOutcome {
    pub principal_id: Did,
    pub state: AccountStatus,
    #[serde(default)]
    pub devices: Vec<AccountDeviceSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_handle_claim: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_handle_claim_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handle_claim_digests: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ActorProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_audit: Option<AccountRegistrationAudit>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AccountUpdateProfileRequestBody {
    pub patch: ProfilePatch,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountUpdateProfileOutcome {
    pub profile: ActorProfile,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct SessionRevokeRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_grant_id: Option<GrantId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all_sessions: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applet_id: Option<AppletId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_scope: Option<EffectiveScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registration_epoch: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_grant_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<AccountLifecycleProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionRevokeOutcome {
    pub revoked_count: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revoked_grant_ids: Vec<GrantId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CursorRevokeScope {
    ThisCursor,
    SameDevice,
    SameSession,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountCursorRevokeRequestBody {
    pub cursor: String,
    pub reason_code: String,
    #[serde(default = "default_cursor_revoke_scope")]
    pub revoke_scope: CursorRevokeScope,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountCursorRevokeOutcome {
    pub revoked: bool,
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_scope_effective: Option<CursorRevokeScope>,
}

fn default_cursor_revoke_scope() -> CursorRevokeScope {
    CursorRevokeScope::ThisCursor
}
