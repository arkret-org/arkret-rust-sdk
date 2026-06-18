//! Agent runtime and protocol interop helpers.

#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(test)]
use crate::Error;
use crate::{
    AgentDeactivateRequestBody, AgentGrantAttachRequestBody, AgentKeyPairRequestBody,
    AgentPauseRequestBody, AgentProvisionRequestBody, AgentResumeRequestBody,
    AgentRotateKeyRequestBody, AgentSidecarThreadEnsureRequestBody, CapabilityGrant, Did, GrantId,
    OP_ACCOUNT_AGENT_KEY_PAIR, OP_AGENT_DEACTIVATE, OP_AGENT_GET, OP_AGENT_GRANT_ATTACH,
    OP_AGENT_GRANT_DETACH, OP_AGENT_LIST, OP_AGENT_PAUSE, OP_AGENT_PROVISION, OP_AGENT_RESUME,
    OP_AGENT_ROTATE_KEY, OP_AGENT_SIDECAR_THREAD_ENSURE, Result,
};

/// Agent principal profile.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentPrincipal {
    pub agent_id: Did,
    pub controller: Did,
    pub display_name: String,
    #[serde(default)]
    pub capabilities: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
    pub created_at: DateTime<Utc>,
}

impl AgentPrincipal {
    /// Create a principal controlled by a DID.
    pub fn new(agent_id: Did, controller: Did, display_name: impl Into<String>) -> Self {
        Self {
            agent_id,
            controller,
            display_name: display_name.into(),
            capabilities: BTreeSet::new(),
            metadata: Value::Null,
            created_at: Utc::now(),
        }
    }
}

/// HTTP method used by a Cokret personal-agent operation plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentHttpMethod {
    Get,
    Post,
    Put,
    Delete,
}

impl AgentHttpMethod {
    /// Return the wire method token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

/// A transport-neutral plan for one standard `/_cokret/...` personal-agent
/// HTTP operation.
#[derive(Clone, Debug, PartialEq)]
pub struct AgentRequestPlan<B> {
    pub operation_id: &'static str,
    pub method: AgentHttpMethod,
    pub path: String,
    pub body: Option<B>,
}

impl<B> AgentRequestPlan<B> {
    fn with_body(
        operation_id: &'static str,
        method: AgentHttpMethod,
        path: impl Into<String>,
        body: B,
    ) -> Self {
        Self {
            operation_id,
            method,
            path: path.into(),
            body: Some(body),
        }
    }

    fn without_body(
        operation_id: &'static str,
        method: AgentHttpMethod,
        path: impl Into<String>,
    ) -> Self {
        Self {
            operation_id,
            method,
            path: path.into(),
            body: None,
        }
    }
}

impl<B: Serialize> AgentRequestPlan<B> {
    /// Serialize the typed body for generic HTTP clients.
    pub fn body_value(&self) -> Result<Option<Value>> {
        self.body
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(Into::into)
    }
}

pub const AGENT_KEY_PAIR_PATH: &str = "/_cokret/gate/account/agent-key-pair";
pub const AGENTS_PATH: &str = "/_cokret/self/agents";
pub const AGENT_SIDECAR_THREAD_ENSURE_PATH: &str = "/_cokret/self/agent-sidecar-threads:ensure";

/// Percent-encode one path component for the personal-agent HTTP surface.
pub fn agent_path_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(&mut encoded, "%{byte:02X}");
        }
    }
    encoded
}

/// Builder for `ck.self.agent.command.provision` request bodies.
#[derive(Clone, Debug, Default)]
pub struct AgentProvisionRequestBuilder {
    display_name: Option<String>,
    agent_slug: Option<String>,
    requested_scope: Option<crate::AgentKeyScope>,
    accountability: Value,
    pairing_ttl_ms: Option<u64>,
}

impl AgentProvisionRequestBuilder {
    pub fn new() -> Self {
        Self {
            display_name: None,
            agent_slug: None,
            requested_scope: None,
            accountability: Value::Null,
            pairing_ttl_ms: None,
        }
    }

    pub fn display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    pub fn agent_slug(mut self, agent_slug: impl Into<String>) -> Self {
        self.agent_slug = Some(agent_slug.into());
        self
    }

    pub fn requested_scope(mut self, requested_scope: crate::AgentKeyScope) -> Self {
        self.requested_scope = Some(requested_scope);
        self
    }

    pub fn accountability(mut self, accountability: Value) -> Self {
        self.accountability = accountability;
        self
    }

    pub fn pairing_ttl_ms(mut self, pairing_ttl_ms: u64) -> Self {
        self.pairing_ttl_ms = Some(pairing_ttl_ms);
        self
    }

    pub fn build(self) -> AgentProvisionRequestBody {
        AgentProvisionRequestBody {
            display_name: self.display_name,
            agent_slug: self.agent_slug,
            requested_scope: self.requested_scope,
            accountability: self.accountability,
            pairing_ttl_ms: self.pairing_ttl_ms,
        }
    }
}

pub fn capability_grant_attach_body(
    grant: &CapabilityGrant,
) -> Result<AgentGrantAttachRequestBody> {
    Ok(AgentGrantAttachRequestBody {
        grant: serde_json::to_value(grant)?,
    })
}

pub fn plan_agent_key_pair(
    body: AgentKeyPairRequestBody,
) -> AgentRequestPlan<AgentKeyPairRequestBody> {
    AgentRequestPlan::with_body(
        OP_ACCOUNT_AGENT_KEY_PAIR,
        AgentHttpMethod::Post,
        AGENT_KEY_PAIR_PATH,
        body,
    )
}

pub fn plan_agent_provision(
    body: AgentProvisionRequestBody,
) -> AgentRequestPlan<AgentProvisionRequestBody> {
    AgentRequestPlan::with_body(OP_AGENT_PROVISION, AgentHttpMethod::Post, AGENTS_PATH, body)
}

pub fn plan_agent_list() -> AgentRequestPlan<()> {
    AgentRequestPlan::without_body(OP_AGENT_LIST, AgentHttpMethod::Get, AGENTS_PATH)
}

pub fn plan_agent_get(agent_principal_id: &str) -> AgentRequestPlan<()> {
    AgentRequestPlan::without_body(
        OP_AGENT_GET,
        AgentHttpMethod::Get,
        format!(
            "{}/{}",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)
        ),
    )
}

pub fn plan_agent_pause(
    agent_principal_id: &str,
    body: AgentPauseRequestBody,
) -> AgentRequestPlan<AgentPauseRequestBody> {
    AgentRequestPlan::with_body(
        OP_AGENT_PAUSE,
        AgentHttpMethod::Post,
        format!(
            "{}/{}/pause",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)
        ),
        body,
    )
}

pub fn plan_agent_resume(
    agent_principal_id: &str,
    body: AgentResumeRequestBody,
) -> AgentRequestPlan<AgentResumeRequestBody> {
    AgentRequestPlan::with_body(
        OP_AGENT_RESUME,
        AgentHttpMethod::Post,
        format!(
            "{}/{}/resume",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)
        ),
        body,
    )
}

pub fn plan_agent_deactivate(
    agent_principal_id: &str,
    body: AgentDeactivateRequestBody,
) -> AgentRequestPlan<AgentDeactivateRequestBody> {
    AgentRequestPlan::with_body(
        OP_AGENT_DEACTIVATE,
        AgentHttpMethod::Post,
        format!(
            "{}/{}/deactivate",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)
        ),
        body,
    )
}

pub fn plan_agent_rotate_key(
    agent_principal_id: &str,
    body: AgentRotateKeyRequestBody,
) -> AgentRequestPlan<AgentRotateKeyRequestBody> {
    AgentRequestPlan::with_body(
        OP_AGENT_ROTATE_KEY,
        AgentHttpMethod::Post,
        format!(
            "{}/{}/rotate-key",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)
        ),
        body,
    )
}

pub fn plan_agent_grant_attach(
    agent_principal_id: &str,
    body: AgentGrantAttachRequestBody,
) -> AgentRequestPlan<AgentGrantAttachRequestBody> {
    AgentRequestPlan::with_body(
        OP_AGENT_GRANT_ATTACH,
        AgentHttpMethod::Post,
        format!(
            "{}/{}/grants",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)
        ),
        body,
    )
}

pub fn plan_agent_grant_detach(
    agent_principal_id: &str,
    grant_id: &GrantId,
) -> AgentRequestPlan<()> {
    AgentRequestPlan::without_body(
        OP_AGENT_GRANT_DETACH,
        AgentHttpMethod::Delete,
        format!(
            "{}/{}/grants/{}",
            AGENTS_PATH,
            agent_path_component(agent_principal_id),
            agent_path_component(grant_id.as_str())
        ),
    )
}

pub fn plan_agent_sidecar_thread_ensure(
    body: AgentSidecarThreadEnsureRequestBody,
) -> AgentRequestPlan<AgentSidecarThreadEnsureRequestBody> {
    AgentRequestPlan::with_body(
        OP_AGENT_SIDECAR_THREAD_ENSURE,
        AgentHttpMethod::Post,
        AGENT_SIDECAR_THREAD_ENSURE_PATH,
        body,
    )
}

/// Delegated actor relationship for an agent.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DelegatedActor {
    pub delegated_actor_id: Did,
    pub agent_id: Did,
    pub principal_id: Did,
    #[serde(default)]
    pub scopes: BTreeSet<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl DelegatedActor {
    /// Check whether the delegation is active.
    pub fn is_active(&self, at: DateTime<Utc>) -> bool {
        self.expires_at
            .map(|expires_at| expires_at > at)
            .unwrap_or(true)
    }
}

/// Agent run lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRunState {
    Queued,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
    Killed,
}

/// Agent run record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentRun {
    pub run_id: String,
    pub agent_id: Did,
    pub principal_id: Did,
    pub state: AgentRunState,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub input: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub output: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

/// In-memory agent run lifecycle manager.
#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub(crate) struct AgentRunManager {
    runs: BTreeMap<String, AgentRun>,
}

#[cfg(test)]
impl AgentRunManager {
    /// Create an empty run manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a run.
    pub fn start_run(&mut self, agent_id: Did, principal_id: Did, input: Value) -> AgentRun {
        let now = Utc::now();
        let run = AgentRun {
            run_id: format!("run_{}", uuid::Uuid::now_v7()),
            agent_id,
            principal_id,
            state: AgentRunState::Running,
            input,
            output: Value::Null,
            error: None,
            started_at: now,
            updated_at: now,
            completed_at: None,
        };
        self.runs.insert(run.run_id.clone(), run.clone());
        run
    }

    /// Transition a run to a new state.
    pub fn transition(
        &mut self,
        run_id: &str,
        state: AgentRunState,
        output: Option<Value>,
        error: Option<String>,
    ) -> Result<AgentRun> {
        let run = self
            .runs
            .get_mut(run_id)
            .ok_or_else(|| Error::Protocol("agent run not found".to_owned()))?;
        run.state = state;
        if let Some(output) = output {
            run.output = output;
        }
        run.error = error;
        run.updated_at = Utc::now();
        if matches!(
            state,
            AgentRunState::Completed
                | AgentRunState::Failed
                | AgentRunState::Cancelled
                | AgentRunState::Killed
        ) {
            run.completed_at = Some(run.updated_at);
        }
        Ok(run.clone())
    }

    /// Activate the kill switch for a run.
    pub fn kill_run(&mut self, run_id: &str, reason: impl Into<String>) -> Result<AgentRun> {
        self.transition(run_id, AgentRunState::Killed, None, Some(reason.into()))
    }
}

/// Tool audit action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentToolAuditAction {
    Requested,
    Allowed,
    Denied,
    Completed,
    Failed,
}

/// Agent tool audit entry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentToolAuditEntry {
    pub entry_id: String,
    pub run_id: String,
    pub agent_id: Did,
    pub tool_name: String,
    pub action: AgentToolAuditAction,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub input: Value,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub output: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// In-memory tool audit log.
#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub(crate) struct AgentToolAuditLog {
    entries: Vec<AgentToolAuditEntry>,
}

#[cfg(test)]
impl AgentToolAuditLog {
    /// Create an empty audit log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an audit entry.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        run_id: impl Into<String>,
        agent_id: Did,
        tool_name: impl Into<String>,
        action: AgentToolAuditAction,
        input: Value,
        output: Value,
        error: Option<String>,
    ) -> AgentToolAuditEntry {
        let entry = AgentToolAuditEntry {
            entry_id: format!("tool_audit_{}", uuid::Uuid::now_v7()),
            run_id: run_id.into(),
            agent_id,
            tool_name: tool_name.into(),
            action,
            input,
            output,
            error,
            created_at: Utc::now(),
        };
        self.entries.push(entry.clone());
        entry
    }

    /// List entries for a run.
    pub fn entries_for_run(&self, run_id: &str) -> Vec<&AgentToolAuditEntry> {
        self.entries
            .iter()
            .filter(|entry| entry.run_id == run_id)
            .collect()
    }
}

/// Agent protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentProtocol {
    A2a,
    Acp,
    Mcp,
}

/// Agent protocol message.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentProtocolMessage {
    pub protocol: AgentProtocol,
    pub message_id: String,
    pub sender: Did,
    pub recipient: Did,
    pub payload: Value,
}

/// External agent registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalAgent {
    pub agent_id: Did,
    pub endpoint: String,
    pub supported_protocols: Vec<AgentProtocol>,
}

/// Metadata for one agent protocol bridge endpoint.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentProtocolEndpoint {
    pub endpoint: String,
    #[serde(default)]
    pub capabilities: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

/// A2A/ACP/MCP bridge metadata for an agent.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentBridgeMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub a2a: Option<AgentProtocolEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acp: Option<AgentProtocolEndpoint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp: Option<AgentProtocolEndpoint>,
}

/// Protocol bridge and registry.
#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub(crate) struct AgentProtocolBridge {
    external_agents: BTreeMap<Did, ExternalAgent>,
    bridge_metadata: BTreeMap<Did, AgentBridgeMetadata>,
}

#[cfg(test)]
impl AgentProtocolBridge {
    /// Create an empty bridge.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an external agent.
    pub fn register_external_agent(&mut self, agent: ExternalAgent) {
        self.external_agents.insert(agent.agent_id.clone(), agent);
    }

    /// Get external agent info.
    pub fn external_agent(&self, agent_id: &Did) -> Option<&ExternalAgent> {
        self.external_agents.get(agent_id)
    }

    /// Set bridge metadata for an external agent.
    pub fn set_bridge_metadata(&mut self, agent_id: Did, metadata: AgentBridgeMetadata) {
        self.bridge_metadata.insert(agent_id, metadata);
    }

    /// Get bridge metadata for an external agent.
    pub fn bridge_metadata(&self, agent_id: &Did) -> Option<&AgentBridgeMetadata> {
        self.bridge_metadata.get(agent_id)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    #[test]
    fn personal_agent_request_plans_use_standard_paths() {
        let provision = AgentProvisionRequestBuilder::new()
            .display_name("summary agent")
            .agent_slug("summary")
            .requested_scope(crate::AgentKeyScope::Limited)
            .build();
        let plan = plan_agent_provision(provision);
        assert_eq!(plan.operation_id, OP_AGENT_PROVISION);
        assert_eq!(plan.method.as_str(), "POST");
        assert_eq!(plan.path, "/_cokret/self/agents");
        let body = plan.body_value().unwrap().unwrap();
        assert_eq!(body["display_name"], "summary agent");
        assert_eq!(body["agent_slug"], "summary");
        assert_eq!(body["requested_scope"], "limited");

        let get = plan_agent_get("did:web:agent.example");
        assert_eq!(get.operation_id, OP_AGENT_GET);
        assert_eq!(get.method.as_str(), "GET");
        assert_eq!(get.path, "/_cokret/self/agents/did%3Aweb%3Aagent.example");

        let grant_id =
            GrantId::new("ck:grant:01964137-0000-7000-8000-000000000010".to_owned()).unwrap();
        let detach = plan_agent_grant_detach("did:web:agent.example", &grant_id);
        assert_eq!(detach.operation_id, OP_AGENT_GRANT_DETACH);
        assert_eq!(detach.method.as_str(), "DELETE");
        assert_eq!(
            detach.path,
            "/_cokret/self/agents/did%3Aweb%3Aagent.example/grants/ck%3Agrant%3A01964137-0000-7000-8000-000000000010"
        );
    }

    #[test]
    fn agent_protocol_registers_external_agents() {
        let agent_id = did("external");
        let mut bridge = AgentProtocolBridge::new();
        bridge.register_external_agent(ExternalAgent {
            agent_id: agent_id.clone(),
            endpoint: "https://agent.example/a2a".to_owned(),
            supported_protocols: vec![AgentProtocol::A2a],
        });

        assert!(bridge.external_agent(&agent_id).is_some());
    }

    #[test]
    fn agent_runs_support_lifecycle_kill_switch_and_tool_audit() {
        let agent = did("agent");
        let principal = did("principal");
        let mut runs = AgentRunManager::new();
        let run = runs.start_run(agent.clone(), principal, json!({"task": "answer"}));
        assert_eq!(run.state, AgentRunState::Running);

        let killed = runs.kill_run(&run.run_id, "operator stop").unwrap();
        assert_eq!(killed.state, AgentRunState::Killed);
        assert!(killed.completed_at.is_some());

        let mut audit = AgentToolAuditLog::new();
        audit.record(
            run.run_id.clone(),
            agent,
            "search",
            AgentToolAuditAction::Denied,
            json!({"q": "secret"}),
            Value::Null,
            Some("policy".to_owned()),
        );
        assert_eq!(audit.entries_for_run(&run.run_id).len(), 1);
    }

    #[test]
    fn agent_protocol_bridge_stores_a2a_acp_mcp_metadata() {
        let agent_id = did("external");
        let mut bridge = AgentProtocolBridge::new();
        bridge.set_bridge_metadata(
            agent_id.clone(),
            AgentBridgeMetadata {
                a2a: Some(AgentProtocolEndpoint {
                    endpoint: "https://agent.example/a2a".to_owned(),
                    capabilities: BTreeSet::from(["tasks".to_owned()]),
                    metadata: Value::Null,
                }),
                acp: Some(AgentProtocolEndpoint {
                    endpoint: "https://agent.example/acp".to_owned(),
                    capabilities: BTreeSet::new(),
                    metadata: json!({"version": "1"}),
                }),
                mcp: Some(AgentProtocolEndpoint {
                    endpoint: "https://agent.example/mcp".to_owned(),
                    capabilities: BTreeSet::from(["tools".to_owned()]),
                    metadata: Value::Null,
                }),
            },
        );

        let metadata = bridge.bridge_metadata(&agent_id).unwrap();
        assert!(metadata.a2a.is_some());
        assert!(metadata.acp.is_some());
        assert!(metadata.mcp.is_some());
    }
}
