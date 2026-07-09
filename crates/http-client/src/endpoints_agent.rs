//! Personal-agent endpoint methods on [`Client`].

use arkret_core::{
    AgentDeactivateRequestBody, AgentGrantAttachOutcome, AgentGrantAttachRequestBody,
    AgentGrantDetachOutcome, AgentKeyPairOutcome, AgentKeyPairRequestBody, AgentLifecycleOutcome,
    AgentList, AgentParticipationOutcome, AgentParticipationReplaceRequestBody,
    AgentPauseRequestBody, AgentProvisionOutcome, AgentProvisionRequestBody,
    AgentResumeRequestBody, AgentRotateKeyOutcome, AgentRotateKeyRequestBody,
    AgentRuntimeApprovalOutcome, AgentRuntimeApprovalRequestBody, AgentSidecarThreadEnsureOutcome,
    AgentSidecarThreadEnsureRequestBody, AgentView, Error, GrantId, Result,
};
use serde_json::Value;

use crate::Client;

const AGENT_KEY_PAIR_PATH: &str = "/_cokret/gate/account/agent-key-pair";
const AGENT_PAIRING_RUNTIME_KEY_REQUESTS_PATH: &str =
    "/_cokret/open/agent-pairing/runtime-key-requests";
const AGENTS_PATH: &str = "/_cokret/self/agents";
const AGENT_SIDECAR_THREAD_ENSURE_PATH: &str = "/_cokret/self/agent-sidecar-threads:ensure";

impl Client {
    /// `POST /_cokret/gate/account/agent-key-pair`
    /// (`ck.gate.account.command.pair_agent_key`).
    pub async fn agent_key_pair(
        &self,
        request: &AgentKeyPairRequestBody,
    ) -> Result<AgentKeyPairOutcome> {
        self.post(AGENT_KEY_PAIR_PATH, request).await
    }

    /// `POST /_cokret/open/agent-pairing/runtime-key-requests`
    /// (`ck.open.agent_pairing.command.submit_runtime_key_request`).
    pub async fn agent_runtime_approval_request(
        &self,
        request: &AgentRuntimeApprovalRequestBody,
    ) -> Result<AgentRuntimeApprovalOutcome> {
        self.post(AGENT_PAIRING_RUNTIME_KEY_REQUESTS_PATH, request)
            .await
    }

    /// `POST /_cokret/self/agents` (`ck.self.agent.command.provision`).
    pub async fn agent_provision(
        &self,
        request: &AgentProvisionRequestBody,
    ) -> Result<AgentProvisionOutcome> {
        self.post(AGENTS_PATH, request).await
    }

    /// `GET /_cokret/self/agents` (`ck.self.agent.query.list`).
    pub async fn agent_list(&self) -> Result<AgentList> {
        let value: Value = self.get(AGENTS_PATH).await?;
        decode_agent_list_response(value)
    }

    /// `GET /_cokret/self/agents/{agent_principal_id}`
    /// (`ck.self.agent.resource.get`).
    pub async fn agent_get(&self, agent_principal_id: &str) -> Result<AgentView> {
        let path = format!(
            "{}/{}",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)?
        );
        self.get(&path).await
    }

    /// `POST /_cokret/self/agents/{agent_principal_id}/pause`
    /// (`ck.self.agent.command.pause`).
    pub async fn agent_pause(
        &self,
        agent_principal_id: &str,
        request: &AgentPauseRequestBody,
    ) -> Result<AgentLifecycleOutcome> {
        let path = format!(
            "{}/{}/pause",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)?
        );
        self.post(&path, request).await
    }

    /// `POST /_cokret/self/agents/{agent_principal_id}/resume`
    /// (`ck.self.agent.command.resume`).
    pub async fn agent_resume(
        &self,
        agent_principal_id: &str,
        request: &AgentResumeRequestBody,
    ) -> Result<AgentLifecycleOutcome> {
        let path = format!(
            "{}/{}/resume",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)?
        );
        self.post(&path, request).await
    }

    /// `POST /_cokret/self/agents/{agent_principal_id}/deactivate`
    /// (`ck.self.agent.command.deactivate`).
    pub async fn agent_deactivate(
        &self,
        agent_principal_id: &str,
        request: &AgentDeactivateRequestBody,
    ) -> Result<AgentLifecycleOutcome> {
        let path = format!(
            "{}/{}/deactivate",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)?
        );
        self.post(&path, request).await
    }

    /// `POST /_cokret/self/agents/{agent_principal_id}/rotate-key`
    /// (`ck.self.agent.command.rotate_key`).
    pub async fn agent_rotate_key(
        &self,
        agent_principal_id: &str,
        request: &AgentRotateKeyRequestBody,
    ) -> Result<AgentRotateKeyOutcome> {
        let path = format!(
            "{}/{}/rotate-key",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)?
        );
        self.post(&path, request).await
    }

    /// `POST /_cokret/self/agents/{agent_principal_id}/grants`
    /// (`ck.self.agent.grant.command.attach`).
    pub async fn agent_grant_attach(
        &self,
        agent_principal_id: &str,
        request: &AgentGrantAttachRequestBody,
    ) -> Result<AgentGrantAttachOutcome> {
        let path = format!(
            "{}/{}/grants",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)?
        );
        self.post(&path, request).await
    }

    /// `DELETE /_cokret/self/agents/{agent_principal_id}/grants/{grant_id}`
    /// (`ck.self.agent.grant.resource.delete`). The `_detach` method name is
    /// retained for API compatibility; the registered operation id is `.delete`.
    pub async fn agent_grant_detach(
        &self,
        agent_principal_id: &str,
        grant_id: &GrantId,
    ) -> Result<AgentGrantDetachOutcome> {
        let path = format!(
            "{}/{}/grants/{}",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)?,
            agent_path_component(grant_id.as_str())?
        );
        self.delete(&path).await
    }

    /// `GET /_cokret/self/agents/{agent_principal_id}/participation`
    /// (`ck.self.agent.participation.resource.get`).
    pub async fn agent_participation_get(
        &self,
        agent_principal_id: &str,
    ) -> Result<AgentParticipationOutcome> {
        let path = format!(
            "{}/{}/participation",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)?
        );
        self.get(&path).await
    }

    /// `PUT /_cokret/self/agents/{agent_principal_id}/participation`
    /// (`ck.self.agent.participation.resource.replace`).
    pub async fn agent_participation_replace(
        &self,
        agent_principal_id: &str,
        request: &AgentParticipationReplaceRequestBody,
    ) -> Result<AgentParticipationOutcome> {
        let path = format!(
            "{}/{}/participation",
            AGENTS_PATH,
            agent_path_component(agent_principal_id)?
        );
        self.put(&path, request).await
    }

    /// `POST /_cokret/self/agent-sidecar-threads:ensure`
    /// (`ck.self.agent.sidecar_thread.command.ensure`).
    pub async fn agent_sidecar_thread_ensure(
        &self,
        request: &AgentSidecarThreadEnsureRequestBody,
    ) -> Result<AgentSidecarThreadEnsureOutcome> {
        self.post(AGENT_SIDECAR_THREAD_ENSURE_PATH, request).await
    }
}

fn decode_agent_list_response(mut value: Value) -> Result<AgentList> {
    if let Some(object) = value.as_object_mut() {
        if !object.contains_key("agents")
            && let Some(items) = object.get("items").cloned()
        {
            object.insert("agents".to_owned(), items);
        }
        object
            .entry("has_more".to_owned())
            .or_insert(Value::Bool(false));
    }
    serde_json::from_value(value).map_err(|error| Error::Protocol(error.to_string()))
}

fn agent_path_component(value: &str) -> Result<String> {
    if value.trim().is_empty() || value == "." || value == ".." {
        return Err(Error::Protocol(
            "agent path component must not be empty or relative".to_owned(),
        ));
    }
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(&mut encoded, "%{byte:02X}");
        }
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_path_component_percent_encodes_did_and_grant_id() {
        assert_eq!(
            agent_path_component("did:web:agent.example/user").unwrap(),
            "did%3Aweb%3Aagent.example%2Fuser"
        );
        assert_eq!(
            agent_path_component("ak:grant:01964137-0000-7000-8000-000000000a01").unwrap(),
            "ck%3Agrant%3A01964137-0000-7000-8000-000000000a01"
        );
    }

    #[test]
    fn agent_path_component_rejects_empty_and_relative_segments() {
        assert!(agent_path_component("").is_err());
        assert!(agent_path_component(".").is_err());
        assert!(agent_path_component("..").is_err());
    }

    #[test]
    fn agent_list_accepts_legacy_items_field() {
        let list = decode_agent_list_response(serde_json::json!({
            "items": [{
                "agent_principal_id": "did:web:agents.example:summary",
                "display_name": "Summary",
                "agent_slug": "summary",
                "status": "active"
            }]
        }))
        .unwrap();

        assert_eq!(list.agents.len(), 1);
        assert_eq!(list.agents[0]["agent_slug"], "summary");
        assert!(!list.has_more);
    }
}
