use super::*;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountView {
    pub principal_id: Did,
    pub state: String,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountRegisterOutcome {
    pub principal_id: Did,
    pub state: String,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountUpdateProfileRequestBody {
    pub patch: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AccountUpdateProfileOutcome {
    pub profile: ActorProfile,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SessionRevokeRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_grant_id: Option<GrantId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub all_sessions: Option<bool>,
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
