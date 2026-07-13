use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentKeyPairRequestBody {
    pub pairing_request_id: String,
    pub agent_id: Did,
    pub verification_method: String,
    pub public_key: Value,
    pub proof_of_possession: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<AgentKeyAuthorizePayloadRuntimeAttestation>,
    pub authorize_event: Event,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentKeyPairOutcome {
    pub ok: bool,
    pub authorized_event_ref: EventId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalRequestBody {
    pub pairing_code: String,
    pub pairing_request_id: String,
    pub agent_id: Did,
    pub verification_method: String,
    pub public_key: Value,
    pub proof_of_possession: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<AgentKeyAuthorizePayloadRuntimeAttestation>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalOutcome {
    pub ok: bool,
    pub approval_request_id: String,
    pub status: AgentStatus,
}

/// Runtime-side poll for the controller decision on a previously submitted
/// runtime key request. The `pairing_request_id` + `pairing_code` +
/// `agent_id` triple is the query credential; a record miss and a
/// mismatch are indistinguishable (both not_found). Mirrors
/// `agent-operations.schema.json#/$defs/agent_runtime_approval_status_request_body`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalStatusRequestBody {
    pub pairing_request_id: String,
    pub pairing_code: String,
    pub agent_id: Did,
}

/// Controller-decision status for an agent runtime key pairing request.
/// Once approved, `authorized_event_ref` plus the authorized key binding
/// fields are present; the runtime MUST compare
/// `authorized_public_key_digest` against its own key and treat a mismatch
/// as paired-by-another-runtime. Mirrors
/// `agent-operations.schema.json#/$defs/agent_runtime_approval_status_outcome`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalStatusOutcome {
    pub ok: bool,
    pub status: AgentStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_verification_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_public_key_digest: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentProvisionRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_scope: Option<AgentKeyScope>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub accountability: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_ttl_ms: Option<u64>,
}

// NOTE: `AgentKeyScope` is the spec object `{actions, resources, constraints?}`
// defined in `models/artifacts/event_payload/agent.rs`
// (`event-payload.schema.json#/$defs/agent_key_scope`, `$ref`'d by
// `agent-operations.schema.json#/$defs/agent_provision_request_body.requested_scope`).
// The former SDK-local `account/realm/applet/limited` enum was off-spec and
// has been removed.

/// Re-open pairing on any non-terminal agent. The service issues a fresh
/// one-time pairing handle and every previously issued handle becomes
/// permanently unresolvable. `pending_runtime_key` / `pairing_expired`
/// re-open bootstrap pairing; `active` / `paused` perform runtime
/// replacement re-pairing (existing keys stay valid until the new pairing
/// completes, then are atomically superseded by the single accepted
/// authorization Event).
/// `deactivated` rejects. Mirrors
/// `agent-operations.schema.json#/$defs/agent_renew_pairing_request_body`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentRenewPairingRequestBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pairing_ttl_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentPcrRecoveryStatus {
    Pending,
    Ready,
    Stale,
}

/// Recovery coverage for a managed Agent Principal Control Realm. The tagged
/// representation preserves the schema invariant that only ready/stale states
/// carry an accepted backup reference.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentPcrRecoveryState {
    Pending,
    Ready {
        backup_id: BackupId,
        series_id: BackupSeriesId,
        series_seq: u64,
        managed_frontier_ref: ManagedFrontierRef,
    },
    Stale {
        backup_id: BackupId,
        series_id: BackupSeriesId,
        series_seq: u64,
        managed_frontier_ref: ManagedFrontierRef,
    },
}

impl AgentPcrRecoveryState {
    pub const fn status(&self) -> AgentPcrRecoveryStatus {
        match self {
            Self::Pending => AgentPcrRecoveryStatus::Pending,
            Self::Ready { .. } => AgentPcrRecoveryStatus::Ready,
            Self::Stale { .. } => AgentPcrRecoveryStatus::Stale,
        }
    }

    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }
}

/// Provisioning is the raw allocation stage, so its recovery projection is
/// constrained to pending and carries no backup reference.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentProvisionPcrRecovery {
    pub status: AgentProvisionPcrRecoveryStatus,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentProvisionPcrRecoveryStatus {
    #[default]
    Pending,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentPairingMode {
    Bootstrap,
    Replacement,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentProvisionOutcome {
    pub agent_id: Did,
    pub principal_control_realm_id: RealmId,
    pub controller_authorization_ref: String,
    pub pcr_recovery: AgentProvisionPcrRecovery,
    pub pairing_request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentRenewPairingOutcome {
    pub agent_id: Did,
    pub principal_control_realm_id: RealmId,
    pub controller_authorization_ref: String,
    pub pcr_recovery: AgentPcrRecoveryState,
    pub pairing_mode: AgentPairingMode,
    pub pairing_request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    pub expires_at: DateTime<Utc>,
}

/// One-time bootstrap material handed to a personal agent runtime after
/// provisioning. Mirrors `agent-operations.schema.json#/$defs/agent_pairing_bootstrap`
/// and AKP-0008 §4.4: a short-lived, revocable pairing input only. It is not a
/// session grant, capability grant or long-term secret, and it deliberately
/// carries no scope payload (the authoritative ceiling lives in
/// `ak.agent.key.authorize` and the effective-permission intersection).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentPairingBootstrap {
    pub arkret_base_url: String,
    pub service_id: Did,
    pub agent_id: Did,
    pub pairing_request_id: String,
    pub pairing_code: String,
    pub pairing_expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentPairingResolveRequestBody {
    pub pairing_token: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    PendingRuntimeKey,
    Active,
    PairingExpired,
    Paused,
    Deactivated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentProjection {
    pub agent_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub slug: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    pub status: AgentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentLifecycleState {
    #[default]
    Active,
    Paused,
    Deactivated,
}

impl AgentLifecycleState {
    pub fn as_wire_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Deactivated => "deactivated",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentLifecycleOutcome {
    pub ok: bool,
    pub status: AgentLifecycleState,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentList {
    #[serde(default)]
    pub agents: Vec<AgentProjection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    pub has_more: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentView {
    pub agent: AgentProjection,
    pub status: AgentStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<GrantSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_state: Option<KeyState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentPauseRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentResumeRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sidecar_exposure_ack: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentDeactivateRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentGrantAttachRequestBody {
    pub grant: CapabilityGrant,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentGrantAttachOutcome {
    pub ok: bool,
    pub grant_id: GrantId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentGrantDetachOutcome {
    pub ok: bool,
    pub revoked_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarContextRef {
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub track_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<MessageId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relation_id: Option<RelationId>,
}

impl AgentSidecarContextRef {
    pub fn strand(realm_id: RealmId, strand_id: StrandId) -> Self {
        Self {
            realm_id,
            strand_id: Some(strand_id),
            track_name: None,
            message_id: None,
            relation_id: None,
        }
    }

    pub fn relation(realm_id: RealmId, relation_id: RelationId) -> Self {
        Self {
            realm_id,
            strand_id: None,
            track_name: None,
            message_id: None,
            relation_id: Some(relation_id),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentSidecarThreadEnsureRequestBody {
    pub controller_id: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addressed_agent_ids: Vec<Did>,
    pub context_ref: AgentSidecarContextRef,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentSidecarThreadEnsureOutcome {
    pub ok: bool,
    pub private_circle_id: CircleId,
    pub private_strand_id: StrandId,
    pub private_relation_id: RelationId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_member_reconciliations: Vec<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime_approval_request(runtime_attestation: Value) -> Value {
        serde_json::json!({
            "pairing_code": "12345678",
            "pairing_request_id": "agent_pairing_request:01964137-0000-7000-8000-000000000001",
            "agent_id": "did:webvh:z6mkfixture:agent.example",
            "verification_method": "did:webvh:z6mkfixture:agent.example#runtime-key-1",
            "public_key": {},
            "proof_of_possession": {},
            "runtime_attestation": runtime_attestation
        })
    }

    #[test]
    fn runtime_attestation_is_closed_to_the_v1_self_asserted_shape() {
        let accepted: AgentRuntimeApprovalRequestBody =
            serde_json::from_value(runtime_approval_request(serde_json::json!({
                "kind": "self_asserted",
                "software": "arkret-agent"
            })))
            .expect("registered self_asserted attestation accepts");
        assert!(accepted.runtime_attestation.is_some());

        assert!(
            serde_json::from_value::<AgentRuntimeApprovalRequestBody>(runtime_approval_request(
                serde_json::json!({ "kind": "tee" })
            ))
            .is_err(),
            "unknown attestation kinds must fail closed"
        );
        assert!(
            serde_json::from_value::<AgentRuntimeApprovalRequestBody>(runtime_approval_request(
                serde_json::json!({ "kind": "self_asserted", "unregistered": true })
            ))
            .is_err(),
            "unregistered attestation fields must fail closed"
        );
    }

    #[test]
    fn sidecar_thread_ensure_request_uses_context_ref_shape() {
        let request = AgentSidecarThreadEnsureRequestBody {
            controller_id: Did::new("did:webvh:z6mkfixture:example.com:users:alice").unwrap(),
            addressed_agent_ids: vec![Did::new("did:webvh:z6mkfixture:agent.example").unwrap()],
            context_ref: AgentSidecarContextRef::strand(
                RealmId::new("ak:realm:01964137-0000-7000-8000-000000000030").unwrap(),
                StrandId::new("ak:strand:01964137-0000-7000-8000-000000000031").unwrap(),
            ),
        };
        let value = serde_json::to_value(request).unwrap();
        assert!(value.get("realm_id").is_none());
        assert!(value.get("agent_id").is_none());
        assert_eq!(
            value["controller_id"],
            "did:webvh:z6mkfixture:example.com:users:alice"
        );
        assert_eq!(
            value["addressed_agent_ids"][0],
            "did:webvh:z6mkfixture:agent.example"
        );
        assert_eq!(
            value["context_ref"]["realm_id"],
            "ak:realm:01964137-0000-7000-8000-000000000030"
        );
        assert_eq!(
            value["context_ref"]["strand_id"],
            "ak:strand:01964137-0000-7000-8000-000000000031"
        );
    }
}
