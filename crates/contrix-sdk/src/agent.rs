//! Agent memory and protocol interop helpers.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ulid::Ulid;

use crate::{Did, Error, Result, model::{Operation, OperationId, SpaceId}};

/// Agent memory lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMemoryState {
    Draft,
    InReview,
    Promoted,
    Rejected,
    Archived,
    Expired,
}

/// Agent memory layer — the four-layer memory model from the spec.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryLayer {
    /// Temporary working memory for current task context.
    Working,
    /// Episodic memory — what happened (events, interactions).
    Episodic,
    /// Semantic memory — what is known (facts, knowledge).
    Semantic,
    /// Task memory — what needs to happen (goals, plans).
    Task,
}

/// Agent memory record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentMemory {
    pub memory_id: String,
    pub agent_id: Did,
    pub content: Value,
    pub importance: u8,
    pub state: AgentMemoryState,
    /// Memory layer classification.
    #[serde(default = "default_memory_layer")]
    pub memory_layer: MemoryLayer,
    /// Memory kind — semantic category (e.g. "fact", "preference", "skill").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_kind: Option<String>,
    /// Subject reference — DID or entity this memory is about.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_ref: Option<String>,
    /// Source references — events, documents, or entities that produced this memory.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_refs: Vec<String>,
    /// Confidence score (0-100).
    #[serde(default = "default_confidence")]
    pub confidence: u8,
    /// Memory this supersedes (for memory updates/corrections).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
    /// When this memory becomes valid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
    /// When this memory expires.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

fn default_memory_layer() -> MemoryLayer {
    MemoryLayer::Working
}

fn default_confidence() -> u8 {
    100
}

/// Review decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMemoryReview {
    pub memory_id: String,
    pub reviewer: Did,
    pub approved: bool,
    pub comment: Option<String>,
    pub reviewed_at: DateTime<Utc>,
}

/// Agent memory store.
#[derive(Clone, Debug, Default)]
pub struct AgentMemoryStore {
    memories: BTreeMap<String, AgentMemory>,
    reviews: BTreeMap<String, Vec<AgentMemoryReview>>,
}

impl AgentMemoryStore {
    /// Create an empty memory store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a draft memory.
    pub fn add_memory(&mut self, agent_id: Did, content: Value, importance: u8) -> AgentMemory {
        let now = Utc::now();
        let memory = AgentMemory {
            memory_id: format!("mem_{}", Ulid::new()),
            agent_id,
            content,
            importance,
            state: AgentMemoryState::Draft,
            memory_layer: MemoryLayer::Working,
            memory_kind: None,
            subject_ref: None,
            source_refs: Vec::new(),
            confidence: 100,
            supersedes: None,
            valid_from: None,
            valid_until: None,
            created_at: now,
            updated_at: now,
        };
        self.memories.insert(memory.memory_id.clone(), memory.clone());
        memory
    }

    /// Submit a memory for review.
    pub fn submit_for_review(&mut self, memory_id: &str) -> Result<()> {
        let memory = self.memory_mut(memory_id)?;
        memory.state = AgentMemoryState::InReview;
        memory.updated_at = Utc::now();
        Ok(())
    }

    /// Record a review and promote/reject memory.
    pub fn review_memory(
        &mut self,
        memory_id: &str,
        reviewer: Did,
        approved: bool,
        comment: Option<String>,
    ) -> Result<AgentMemoryReview> {
        let review = AgentMemoryReview {
            memory_id: memory_id.to_owned(),
            reviewer,
            approved,
            comment,
            reviewed_at: Utc::now(),
        };
        let memory = self.memory_mut(memory_id)?;
        memory.state =
            if approved { AgentMemoryState::Promoted } else { AgentMemoryState::Rejected };
        memory.updated_at = Utc::now();
        self.reviews.entry(memory_id.to_owned()).or_default().push(review.clone());
        Ok(review)
    }

    /// Promote a memory without review.
    pub fn promote_memory(&mut self, memory_id: &str) -> Result<()> {
        let memory = self.memory_mut(memory_id)?;
        memory.state = AgentMemoryState::Promoted;
        memory.updated_at = Utc::now();
        Ok(())
    }

    /// Archive a memory that should no longer be active.
    pub fn archive_memory(&mut self, memory_id: &str) -> Result<()> {
        let memory = self.memory_mut(memory_id)?;
        memory.state = AgentMemoryState::Archived;
        memory.updated_at = Utc::now();
        Ok(())
    }

    /// Mark a memory as expired.
    pub fn expire_memory(&mut self, memory_id: &str) -> Result<()> {
        let memory = self.memory_mut(memory_id)?;
        memory.state = AgentMemoryState::Expired;
        memory.updated_at = Utc::now();
        Ok(())
    }

    /// Get promoted memories for an agent.
    pub fn promoted_memories(&self, agent_id: &Did) -> Vec<&AgentMemory> {
        self.memories
            .values()
            .filter(|memory| {
                memory.agent_id == *agent_id && memory.state == AgentMemoryState::Promoted
            })
            .collect()
    }

    /// Get active promoted memories valid at a point in time.
    pub fn active_memories(&self, agent_id: &Did, at: DateTime<Utc>) -> Vec<&AgentMemory> {
        self.promoted_memories(agent_id)
            .into_iter()
            .filter(|memory| memory.valid_from.map(|valid_from| valid_from <= at).unwrap_or(true))
            .filter(|memory| memory.valid_until.map(|valid_until| valid_until > at).unwrap_or(true))
            .collect()
    }

    /// Get memories by memory layer.
    pub fn memories_by_layer(&self, agent_id: &Did, layer: MemoryLayer) -> Vec<&AgentMemory> {
        self.memories
            .values()
            .filter(|memory| memory.agent_id == *agent_id && memory.memory_layer == layer)
            .collect()
    }

    fn memory_mut(&mut self, memory_id: &str) -> Result<&mut AgentMemory> {
        self.memories
            .get_mut(memory_id)
            .ok_or_else(|| Error::Protocol("agent memory not found".to_owned()))
    }

    /// Build an `agent.memory.create` operation for a new memory.
    pub fn create_memory_operation(
        &self,
        space_id: SpaceId,
        agent_id: &Did,
        content: &Value,
        importance: u8,
    ) -> Result<Operation> {
        let operation_id = OperationId::new(format!("cx:operation:{}", Ulid::new()))?;
        let payload = serde_json::json!({
            "agent_id": agent_id.as_str(),
            "content": content,
            "importance": importance,
        });
        Ok(Operation::create(operation_id, space_id, "agent.memory.create", payload))
    }

    /// Build an `agent.memory.promote` operation.
    pub fn promote_memory_operation(
        &self,
        space_id: SpaceId,
        memory_id: &str,
    ) -> Result<Operation> {
        let memory = self.memories.get(memory_id).ok_or_else(|| Error::Protocol("memory not found".to_owned()))?;
        let operation_id = OperationId::new(format!("cx:operation:{}", Ulid::new()))?;
        let payload = serde_json::json!({
            "memory_id": memory.memory_id,
            "agent_id": memory.agent_id.as_str(),
        });
        Ok(Operation::create(operation_id, space_id, "agent.memory.promote", payload))
    }
}

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
#[derive(Clone, Debug, Default)]
pub struct AgentRunManager {
    runs: BTreeMap<String, AgentRun>,
}

impl AgentRunManager {
    /// Create an empty run manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a run.
    pub fn start_run(&mut self, agent_id: Did, principal_id: Did, input: Value) -> AgentRun {
        let now = Utc::now();
        let run = AgentRun {
            run_id: format!("run_{}", Ulid::new()),
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

    /// Get a run.
    pub fn run(&self, run_id: &str) -> Option<&AgentRun> {
        self.runs.get(run_id)
    }

    /// Build an `agent.run.create` operation for a new run.
    pub fn create_run_operation(
        &self,
        space_id: SpaceId,
        agent_id: &Did,
        principal_id: &Did,
        input: &Value,
    ) -> Result<Operation> {
        let run_id = &self.runs.iter().next().map(|(k, _)| k.clone()).unwrap_or_default();
        let operation_id = OperationId::new(format!("cx:operation:{}", Ulid::new()))?;
        let payload = serde_json::json!({
            "agent_id": agent_id.as_str(),
            "principal_id": principal_id.as_str(),
            "input": input,
        });
        Ok(Operation::create(operation_id, space_id, "agent.run.create", payload))
    }

    /// Build an `agent.run.complete` operation for a finished run.
    pub fn complete_run_operation(
        &self,
        space_id: SpaceId,
        run_id: &str,
        output: &Value,
    ) -> Result<Operation> {
        let run = self.runs.get(run_id).ok_or_else(|| Error::Protocol("run not found".to_owned()))?;
        let operation_id = OperationId::new(format!("cx:operation:{}", Ulid::new()))?;
        let payload = serde_json::json!({
            "run_id": run.run_id,
            "agent_id": run.agent_id.as_str(),
            "output": output,
        });
        Ok(Operation::create(operation_id, space_id, "agent.run.complete", payload))
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
#[derive(Clone, Debug, Default)]
pub struct AgentToolAuditLog {
    entries: Vec<AgentToolAuditEntry>,
}

impl AgentToolAuditLog {
    /// Create an empty audit log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an audit entry.
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
            entry_id: format!("tool_audit_{}", Ulid::new()),
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
    Legacy,
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
#[derive(Clone, Debug, Default)]
pub struct AgentProtocolBridge {
    external_agents: BTreeMap<Did, ExternalAgent>,
    bridge_metadata: BTreeMap<Did, AgentBridgeMetadata>,
}

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

    /// Build an A2A message.
    pub fn a2a_message(sender: Did, recipient: Did, payload: Value) -> AgentProtocolMessage {
        AgentProtocolMessage {
            protocol: AgentProtocol::A2a,
            message_id: format!("a2a_{}", Ulid::new()),
            sender,
            recipient,
            payload,
        }
    }

    /// Convert a legacy message payload into A2A shape.
    pub fn bridge_legacy_to_a2a(message: AgentProtocolMessage) -> AgentProtocolMessage {
        AgentProtocolMessage {
            protocol: AgentProtocol::A2a,
            message_id: format!("a2a_{}", Ulid::new()),
            sender: message.sender,
            recipient: message.recipient,
            payload: serde_json::json!({
                "legacy_message_id": message.message_id,
                "legacy_payload": message.payload
            }),
        }
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
    fn agent_memory_stores_reviews_and_promotes() {
        let agent = did("agent");
        let mut store = AgentMemoryStore::new();
        let memory = store.add_memory(agent.clone(), json!({"fact": "Contrix"}), 9);

        store.submit_for_review(&memory.memory_id).unwrap();
        store
            .review_memory(&memory.memory_id, did("reviewer"), true, Some("ok".to_owned()))
            .unwrap();

        assert_eq!(store.promoted_memories(&agent).len(), 1);
    }

    #[test]
    fn agent_protocol_bridges_legacy_to_a2a() {
        let legacy = AgentProtocolMessage {
            protocol: AgentProtocol::Legacy,
            message_id: "legacy1".to_owned(),
            sender: did("agent-a"),
            recipient: did("agent-b"),
            payload: json!({"text": "hello"}),
        };
        let bridged = AgentProtocolBridge::bridge_legacy_to_a2a(legacy);

        assert_eq!(bridged.protocol, AgentProtocol::A2a);
        assert_eq!(bridged.payload["legacy_message_id"], "legacy1");
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
    fn agent_memory_lifecycle_filters_layers_and_validity() {
        let agent = did("agent");
        let mut store = AgentMemoryStore::new();
        let memory = store.add_memory(agent.clone(), json!({"fact": "Contrix"}), 9);
        store.promote_memory(&memory.memory_id).unwrap();

        assert_eq!(store.active_memories(&agent, Utc::now()).len(), 1);
        assert_eq!(store.memories_by_layer(&agent, MemoryLayer::Working).len(), 1);

        store.archive_memory(&memory.memory_id).unwrap();
        assert_eq!(store.promoted_memories(&agent).len(), 0);

        let memory = store.add_memory(agent.clone(), json!({"old": true}), 1);
        store.expire_memory(&memory.memory_id).unwrap();
        assert_eq!(store.memories_by_layer(&agent, MemoryLayer::Working).len(), 2);
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
