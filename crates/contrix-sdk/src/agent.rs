//! Agent memory and protocol interop helpers.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ulid::Ulid;

use crate::{Did, Error, Result};

/// Agent memory lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentMemoryState {
    Draft,
    InReview,
    Promoted,
    Rejected,
}

/// Agent memory record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentMemory {
    pub memory_id: String,
    pub agent_id: Did,
    pub content: Value,
    pub importance: u8,
    pub state: AgentMemoryState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
        let memory = AgentMemory {
            memory_id: format!("mem_{}", Ulid::new()),
            agent_id,
            content,
            importance,
            state: AgentMemoryState::Draft,
            created_at: Utc::now(),
            updated_at: Utc::now(),
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

    /// Get promoted memories for an agent.
    pub fn promoted_memories(&self, agent_id: &Did) -> Vec<&AgentMemory> {
        self.memories
            .values()
            .filter(|memory| {
                memory.agent_id == *agent_id && memory.state == AgentMemoryState::Promoted
            })
            .collect()
    }

    fn memory_mut(&mut self, memory_id: &str) -> Result<&mut AgentMemory> {
        self.memories
            .get_mut(memory_id)
            .ok_or_else(|| Error::Protocol("agent memory not found".to_owned()))
    }
}

/// Agent protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentProtocol {
    A2a,
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

/// Protocol bridge and registry.
#[derive(Clone, Debug, Default)]
pub struct AgentProtocolBridge {
    external_agents: BTreeMap<Did, ExternalAgent>,
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
}
