use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentKeyPairRequestBody {
    pub agent_principal_id: Did,
    pub verification_method: String,
    pub public_key: Value,
    pub proof_of_possession: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_attestation: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorize_event: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentKeyPairOutcome {
    pub ok: bool,
    pub authorized_event_ref: EventId,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum AgentKeyScope {
    Account,
    Realm,
    Applet,
    Limited,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentProvisionOutcome {
    pub agent_principal_id: Did,
    pub pairing_request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pairing_code: Option<String>,
    pub expires_at: DateTime<Utc>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct AgentList {
    #[serde(default)]
    pub agents: Vec<Value>,
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
            controller_principal_id: Did::new("did:web:example.com:users:alice").unwrap(),
            addressed_agent_principal_ids: vec![Did::new("did:web:agent.example").unwrap()],
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
            "did:web:example.com:users:alice"
        );
        assert_eq!(
            value["addressed_agent_principal_ids"][0],
            "did:web:agent.example"
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
