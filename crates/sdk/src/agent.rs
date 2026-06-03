//! Agent runtime and protocol interop helpers.

#[cfg(test)]
use std::collections::BTreeMap;
use std::collections::BTreeSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Did;
#[cfg(test)]
use crate::{Error, Result};

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
        self.expires_at.map(|expires_at| expires_at > at).unwrap_or(true)
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
        self.entries.iter().filter(|entry| entry.run_id == run_id).collect()
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
