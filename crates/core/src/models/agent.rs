use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentKeyPairRequestBody {
    pub pairing_request_id: String,
    pub agent_principal_id: Did,
    pub verification_method: String,
    pub public_key: Value,
    pub proof_of_possession: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<Value>,
    pub authorize_event: Value,
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
    pub agent_principal_id: Did,
    pub verification_method: String,
    pub public_key: Value,
    pub proof_of_possession: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentRuntimeApprovalOutcome {
    pub ok: bool,
    pub approval_request_id: String,
    pub status: AgentStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentProvisionRequestBody {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_slug: Option<String>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentProvisionOutcome {
    pub agent_principal_id: Did,
    pub pairing_request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    pub expires_at: DateTime<Utc>,
}

/// One-time bootstrap material handed to a personal agent runtime after
/// provisioning. Mirrors `agent-operations.schema.json#/$defs/agent_pairing_bootstrap`
/// and CKP-0008 §4.4: a short-lived, revocable pairing input only. It is not a
/// session grant, capability grant or long-term secret, and it deliberately
/// carries no scope payload (the authoritative ceiling lives in
/// `ck.agent.key.authorize` and the effective-permission intersection).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AgentPairingBootstrap {
    pub cokret_base_url: String,
    pub service_did: Did,
    pub agent_principal_id: Did,
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
    pub agent_principal_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_slug: Option<String>,
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

/// Request body for `POST /_cokret/self/agents/discover`
/// (`ck.agent.protocol.discover`). The caller names the target agent
/// runtime DID; soland reflects the registered `ck.agent.endpoint`
/// projection back as the supported protocol catalogue.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentProtocolDiscoverRequestBody {
    pub agent_id: Did,
}

/// Outcome for `ck.agent.protocol.discover`. `supported_protocols` is a
/// subset of the §11 adapter registry ids (`a2a` / `acp` / `mcp_bridge`
/// / `http_custom`). `agent_card_url` / `metadata_url` mirror the
/// `ck.agent.endpoint` declaration (§5.1) when present.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentProtocolDiscoverOutcome {
    pub agent_id: Did,
    #[serde(default)]
    pub supported_protocols: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_card_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
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
    pub agent: Value,
    pub status: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub key_state: Value,
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
pub struct AgentRotateKeyRequestBody {
    pub replacement_key: Value,
    pub proof_of_possession: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentRotateKeyOutcome {
    pub ok: bool,
    pub authorized_event_ref: EventId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentGrantAttachRequestBody {
    pub grant: Value,
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
    pub controller_principal_id: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub addressed_agent_principal_ids: Vec<Did>,
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

    #[test]
    fn sidecar_thread_ensure_request_uses_context_ref_shape() {
        let request = AgentSidecarThreadEnsureRequestBody {
            controller_principal_id: Did::new("did:webvh:z6mkfixture:example.com:users:alice")
                .unwrap(),
            addressed_agent_principal_ids: vec![
                Did::new("did:webvh:z6mkfixture:agent.example").unwrap(),
            ],
            context_ref: AgentSidecarContextRef::strand(
                RealmId::new("ck:realm:01964137-0000-7000-8000-000000000030").unwrap(),
                StrandId::new("ck:strand:01964137-0000-7000-8000-000000000031").unwrap(),
            ),
        };
        let value = serde_json::to_value(request).unwrap();
        assert!(value.get("realm_id").is_none());
        assert!(value.get("agent_principal_id").is_none());
        assert_eq!(
            value["controller_principal_id"],
            "did:webvh:z6mkfixture:example.com:users:alice"
        );
        assert_eq!(
            value["addressed_agent_principal_ids"][0],
            "did:webvh:z6mkfixture:agent.example"
        );
        assert_eq!(
            value["context_ref"]["realm_id"],
            "ck:realm:01964137-0000-7000-8000-000000000030"
        );
        assert_eq!(
            value["context_ref"]["strand_id"],
            "ck:strand:01964137-0000-7000-8000-000000000031"
        );
    }
}
