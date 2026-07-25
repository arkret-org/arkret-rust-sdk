//! Personal-agent endpoint methods on [`Client`].

use std::ops::Deref;
use std::time::Duration;

use arkret_models_collaboration::agent_operations::{
    AgentDeactivateRequestBody, AgentGrantAttachOutcome, AgentGrantAttachRequestBody,
    AgentGrantDetachOutcome, AgentKeyPairOutcome, AgentKeyPairRequestBody, AgentLifecycleOutcome,
    AgentList, AgentPauseRequestBody, AgentProvisionOutcome, AgentProvisionRequestBody,
    AgentRenewPairingOutcome, AgentRenewPairingRequestBody, AgentResumeRequestBody,
    AgentRuntimeApprovalOutcome, AgentRuntimeApprovalRequestBody,
    AgentRuntimeApprovalStatusOutcome, AgentRuntimeApprovalStatusRequestBody,
    AgentSidecarEnsureOutcome, AgentSidecarEnsureRequestBody, AgentSidecarList, AgentSidecarView,
    AgentView,
};
use arkret_models_collaboration::agent_signer_evidence::{
    AgentSignerEvidenceQueryOutcome, AgentSignerEvidenceQueryRequest,
};
use arkret_models_collaboration::governance::agent_participation::{
    AgentParticipationOutcome, AgentParticipationReplaceRequestBody,
};
use arkret_wire::{GrantId, RealmId, SidecarId};
use reqwest::Method;

use crate::{Client, Error, Result, retry_after_ms};

const AGENT_KEY_PAIR_PATH: &str = "/_arkret/gate/account/agent-key-pair";
const AGENT_PAIRING_RUNTIME_KEY_REQUESTS_PATH: &str =
    "/_arkret/open/agent-pairing/runtime-key-requests";
const AGENT_PAIRING_RUNTIME_KEY_REQUEST_STATUS_PATH: &str =
    "/_arkret/open/agent-pairing/runtime-key-requests/status";
const AGENTS_PATH: &str = "/_arkret/self/agents";
const AGENT_SIGNER_EVIDENCE_QUERY_PATH: &str = "/_arkret/self/agent-signer-evidence/query";
const AGENT_SIDECARS_PATH: &str = "/_arkret/self/agent-sidecars";
const AGENT_SIDECAR_ENSURE_PATH: &str = "/_arkret/self/agent-sidecars:ensure";

#[derive(Clone, Debug)]
pub struct AgentRuntimeApprovalStatusResponse {
    pub outcome: AgentRuntimeApprovalStatusOutcome,
    pub retry_after: Option<Duration>,
}

impl Deref for AgentRuntimeApprovalStatusResponse {
    type Target = AgentRuntimeApprovalStatusOutcome;

    fn deref(&self) -> &Self::Target {
        &self.outcome
    }
}

impl Client {
    /// `POST /_arkret/self/agent-signer-evidence/query`
    /// (`ak.self.agent_signer_evidence.query`).
    pub async fn agent_signer_evidence_query(
        &self,
        request: &AgentSignerEvidenceQueryRequest,
    ) -> Result<AgentSignerEvidenceQueryOutcome> {
        self.post(AGENT_SIGNER_EVIDENCE_QUERY_PATH, request).await
    }

    /// `POST /_arkret/gate/account/agent-key-pair`
    /// (`ak.gate.account.command.pair_agent_key`).
    pub async fn agent_key_pair(
        &self,
        request: &AgentKeyPairRequestBody,
    ) -> Result<AgentKeyPairOutcome> {
        let builder = self
            .request(Method::POST, AGENT_KEY_PAIR_PATH)?
            .header("Idempotency-Key", request.authorize_event.event_id.as_str());
        let builder = self.canonical_json_body(builder, request)?;
        self.send_json(builder).await
    }

    /// `POST /_arkret/open/agent-pairing/runtime-key-requests`
    /// (`ak.open.agent_pairing.command.submit_runtime_key_request`).
    pub async fn agent_runtime_approval_request(
        &self,
        request: &AgentRuntimeApprovalRequestBody,
    ) -> Result<AgentRuntimeApprovalOutcome> {
        self.post(AGENT_PAIRING_RUNTIME_KEY_REQUESTS_PATH, request)
            .await
    }

    /// `POST /_arkret/open/agent-pairing/runtime-key-requests/status`
    /// (`ak.open.agent_pairing.query.runtime_key_request_status`).
    pub async fn agent_runtime_approval_status(
        &self,
        request: &AgentRuntimeApprovalStatusRequestBody,
    ) -> Result<AgentRuntimeApprovalStatusResponse> {
        let builder = self.canonical_json_body(
            self.request(Method::POST, AGENT_PAIRING_RUNTIME_KEY_REQUEST_STATUS_PATH)?,
            request,
        )?;
        let (outcome, headers) = self.send_json_with_headers(builder).await?;
        Ok(AgentRuntimeApprovalStatusResponse {
            outcome,
            retry_after: retry_after_ms(&headers).map(Duration::from_millis),
        })
    }

    /// `POST /_arkret/self/agents` (`ak.self.agent.command.provision`).
    pub async fn agent_provision(
        &self,
        request: &AgentProvisionRequestBody,
    ) -> Result<AgentProvisionOutcome> {
        self.post(AGENTS_PATH, request).await
    }

    /// `POST /_arkret/self/agents/{agent_id}/renew-pairing`
    /// (`ak.self.agent.command.renew_pairing`).
    pub async fn agent_renew_pairing(
        &self,
        agent_id: &str,
        request: &AgentRenewPairingRequestBody,
    ) -> Result<AgentRenewPairingOutcome> {
        let path = format!(
            "{}/{}/renew-pairing",
            AGENTS_PATH,
            agent_path_component(agent_id)?
        );
        self.post(&path, request).await
    }

    /// `GET /_arkret/self/agents` (`ak.self.agent.query.list`).
    pub async fn agent_list(&self) -> Result<AgentList> {
        self.get(AGENTS_PATH).await
    }

    /// `GET /_arkret/self/agents/{agent_id}`
    /// (`ak.self.agent.resource.get`).
    pub async fn agent_get(&self, agent_id: &str) -> Result<AgentView> {
        let path = format!("{}/{}", AGENTS_PATH, agent_path_component(agent_id)?);
        self.get(&path).await
    }

    /// `POST /_arkret/self/agents/{agent_id}/pause`
    /// (`ak.self.agent.command.pause`).
    pub async fn agent_pause(
        &self,
        agent_id: &str,
        request: &AgentPauseRequestBody,
    ) -> Result<AgentLifecycleOutcome> {
        let path = format!("{}/{}/pause", AGENTS_PATH, agent_path_component(agent_id)?);
        self.post(&path, request).await
    }

    /// `POST /_arkret/self/agents/{agent_id}/resume`
    /// (`ak.self.agent.command.resume`).
    pub async fn agent_resume(
        &self,
        agent_id: &str,
        request: &AgentResumeRequestBody,
    ) -> Result<AgentLifecycleOutcome> {
        let path = format!("{}/{}/resume", AGENTS_PATH, agent_path_component(agent_id)?);
        self.post(&path, request).await
    }

    /// `POST /_arkret/self/agents/{agent_id}/deactivate`
    /// (`ak.self.agent.command.deactivate`).
    pub async fn agent_deactivate(
        &self,
        agent_id: &str,
        request: &AgentDeactivateRequestBody,
    ) -> Result<AgentLifecycleOutcome> {
        let path = format!(
            "{}/{}/deactivate",
            AGENTS_PATH,
            agent_path_component(agent_id)?
        );
        self.post(&path, request).await
    }

    /// `POST /_arkret/self/agents/{agent_id}/grants`
    /// (`ak.self.agent.grant.command.attach`).
    pub async fn agent_grant_attach(
        &self,
        agent_id: &str,
        request: &AgentGrantAttachRequestBody,
    ) -> Result<AgentGrantAttachOutcome> {
        let path = format!("{}/{}/grants", AGENTS_PATH, agent_path_component(agent_id)?);
        self.post(&path, request).await
    }

    /// `DELETE /_arkret/self/agents/{agent_id}/grants/{grant_id}`
    /// (`ak.self.agent.grant.resource.delete`). The `_detach` method name is
    /// retained for API compatibility; the registered operation id is `.delete`.
    pub async fn agent_grant_detach(
        &self,
        agent_id: &str,
        grant_id: &GrantId,
    ) -> Result<AgentGrantDetachOutcome> {
        let path = format!(
            "{}/{}/grants/{}",
            AGENTS_PATH,
            agent_path_component(agent_id)?,
            agent_path_component(grant_id.as_str())?
        );
        self.delete(&path).await
    }

    /// `GET /_arkret/self/agents/{agent_id}/participation`
    /// (`ak.self.agent.participation.resource.get`).
    pub async fn agent_participation_get(
        &self,
        agent_id: &str,
    ) -> Result<AgentParticipationOutcome> {
        let path = format!(
            "{}/{}/participation",
            AGENTS_PATH,
            agent_path_component(agent_id)?
        );
        self.get(&path).await
    }

    /// `PUT /_arkret/self/agents/{agent_id}/participation`
    /// (`ak.self.agent.participation.resource.replace`).
    pub async fn agent_participation_replace(
        &self,
        agent_id: &str,
        request: &AgentParticipationReplaceRequestBody,
    ) -> Result<AgentParticipationOutcome> {
        let path = format!(
            "{}/{}/participation",
            AGENTS_PATH,
            agent_path_component(agent_id)?
        );
        self.put(&path, request).await
    }

    /// `POST /_arkret/self/agent-sidecars:ensure`
    /// (`ak.self.agent.sidecar.command.ensure`).
    pub async fn agent_sidecar_ensure(
        &self,
        request: &AgentSidecarEnsureRequestBody,
    ) -> Result<AgentSidecarEnsureOutcome> {
        self.post(AGENT_SIDECAR_ENSURE_PATH, request).await
    }

    /// `GET /_arkret/self/agent-sidecars/{sidecar_id}`
    /// (`ak.self.agent.sidecar.resource.get`).
    pub async fn agent_sidecar_get(&self, sidecar_id: &SidecarId) -> Result<AgentSidecarView> {
        self.get(&format!("{AGENT_SIDECARS_PATH}/{sidecar_id}"))
            .await
    }

    /// `GET /_arkret/self/agent-sidecars`
    /// (`ak.self.agent.sidecar.query.list`).
    pub async fn agent_sidecar_list(
        &self,
        realm_id: Option<&RealmId>,
        cursor: Option<&str>,
    ) -> Result<AgentSidecarList> {
        let mut builder = self.request(Method::GET, AGENT_SIDECARS_PATH)?;
        if let Some(realm_id) = realm_id {
            builder = builder.query(&[("realm_id", realm_id.as_str())]);
        }
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        self.send_json(builder).await
    }
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
            "ak%3Agrant%3A01964137-0000-7000-8000-000000000a01"
        );
    }

    #[test]
    fn agent_path_component_rejects_empty_and_relative_segments() {
        assert!(agent_path_component("").is_err());
        assert!(agent_path_component(".").is_err());
        assert!(agent_path_component("..").is_err());
    }

    #[test]
    fn agent_list_requires_agents_and_has_more() {
        let error = serde_json::from_value::<AgentList>(serde_json::json!({
            "items": [{
                "agent_id": "did:web:agents.example:summary",
                "display_name": "Summary",
                "slug": "summary",
                "status": "active"
            }],
            "has_more": false
        }))
        .unwrap_err();

        assert!(error.to_string().contains("agents"));

        let error = serde_json::from_value::<AgentList>(serde_json::json!({
            "agents": []
        }))
        .unwrap_err();

        assert!(error.to_string().contains("has_more"));
    }
}
