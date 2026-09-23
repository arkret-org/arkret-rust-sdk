//! Agent endpoint methods on [`Client`].

use arkret_models_collaboration::agent_operations::{
    AgentDeactivateRequestBody, AgentKeyPairOutcome, AgentKeyPairRequestBody,
    AgentLifecycleOutcome, AgentList, AgentPauseRequestBody, AgentProvisionOutcome,
    AgentProvisionRequestBody, AgentRenewPairingOutcome, AgentRenewPairingRequestBody,
    AgentResumeRequestBody, AgentSidecarList, AgentSidecarView, AgentView,
};
use arkret_models_collaboration::governance::agent_participation::{
    AgentParticipationOutcome, ParticipationReplaceRequestBody,
};
use arkret_models_collaboration::sidecar_operations::{
    SidecarEnsureOutcome, SidecarEnsureRequestBody,
};
use arkret_models_identity::signer_key_operations::{
    SignerKeysQueryOutcome, SignerKeysQueryRequestBody,
};
use arkret_wire::{RealmId, SidecarId};
use reqwest::Method;

use crate::{Client, Error, Result};

const AGENT_KEY_PAIR_PATH: &str = "/_arkret/gate/account/agent-key-pair";
const AGENTS_PATH: &str = "/_arkret/self/agents";
const SIGNER_KEYS_QUERY_PATH: &str = "/_arkret/self/signer-keys/query";
const AGENT_SIDECARS_PATH: &str = "/_arkret/self/agent-sidecars";
const AGENT_SIDECAR_ENSURE_PATH: &str = "/_arkret/self/agent-sidecars:ensure";

impl Client {
    /// `POST /_arkret/self/signer-keys/query`
    /// (`ak.self.signer_keys.read.resolve.v1`).
    ///
    /// One surface for both questions the recipient Station can answer: which
    /// key is currently admitted for a sender, and which key signed one exact
    /// locally accepted historical Event. Device and Agent senders share it, so
    /// a caller no longer has to know which of two operations to reach for.
    /// Selectors carry the independent `verification_mode` and `sender_kind`
    /// discriminators; a resolved historical result additionally requires its
    /// canonical `accepted_at` authorization-effective time.
    ///
    /// The result is not portable evidence and not a reusable current grant: a
    /// `unavailable` answer means only that this Station cannot answer that
    /// selector right now.
    pub async fn signer_keys_query(
        &self,
        request: &SignerKeysQueryRequestBody,
    ) -> Result<SignerKeysQueryOutcome> {
        request.validate()?;
        let builder = self.request(Method::POST, SIGNER_KEYS_QUERY_PATH)?;
        let builder = self.canonical_json_body(builder, request)?;
        let outcome: SignerKeysQueryOutcome = self
            .send_json_limited(
                builder,
                arkret_models_identity::SELF_SIGNER_OUTCOME_MAX_BYTES,
            )
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// `POST /_arkret/gate/account/agent-key-pair`
    /// (`ak.gate.account.command.pair_agent_key.v1`).
    pub async fn agent_key_pair(
        &self,
        request: &AgentKeyPairRequestBody,
    ) -> Result<AgentKeyPairOutcome> {
        let builder = self.request(Method::POST, AGENT_KEY_PAIR_PATH)?.header(
            "Idempotency-Key",
            request.authorize_event.event.event_id.as_str(),
        );
        let builder = self.canonical_json_body(builder, request)?;
        self.send_json(builder).await
    }

    /// `POST /_arkret/self/agents` (`ak.self.agent.command.provision.v1`).
    pub async fn agent_provision(
        &self,
        request: &AgentProvisionRequestBody,
    ) -> Result<AgentProvisionOutcome> {
        self.post(AGENTS_PATH, request).await
    }

    /// `POST /_arkret/self/agents/{agent_id}/renew-pairing`
    /// (`ak.self.agent.command.renew_pairing.v1`).
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

    /// `GET /_arkret/self/agents` (`ak.self.agent.read.list.v1`).
    pub async fn agent_list(&self) -> Result<AgentList> {
        self.get(AGENTS_PATH).await
    }

    /// `GET /_arkret/self/agents/{agent_id}`
    /// (`ak.self.agent.resource.get.v1`).
    pub async fn agent_get(&self, agent_id: &str) -> Result<AgentView> {
        let path = format!("{}/{}", AGENTS_PATH, agent_path_component(agent_id)?);
        self.get(&path).await
    }

    /// `POST /_arkret/self/agents/{agent_id}/pause`
    /// (`ak.self.agent.command.pause.v1`).
    pub async fn agent_pause(
        &self,
        agent_id: &str,
        request: &AgentPauseRequestBody,
    ) -> Result<AgentLifecycleOutcome> {
        let path = format!("{}/{}/pause", AGENTS_PATH, agent_path_component(agent_id)?);
        self.post(&path, request).await
    }

    /// `POST /_arkret/self/agents/{agent_id}/resume`
    /// (`ak.self.agent.command.resume.v1`).
    pub async fn agent_resume(
        &self,
        agent_id: &str,
        request: &AgentResumeRequestBody,
    ) -> Result<AgentLifecycleOutcome> {
        let path = format!("{}/{}/resume", AGENTS_PATH, agent_path_component(agent_id)?);
        self.post(&path, request).await
    }

    /// `POST /_arkret/self/agents/{agent_id}/deactivate`
    /// (`ak.self.agent.command.deactivate.v1`).
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

    /// `GET /_arkret/self/agents/{agent_id}/participation`
    /// (`ak.self.agent.participation.resource.get.v1`).
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
    /// (`ak.self.agent.participation.resource.replace.v1`).
    pub async fn agent_participation_replace(
        &self,
        agent_id: &str,
        request: &ParticipationReplaceRequestBody,
    ) -> Result<AgentParticipationOutcome> {
        let path = format!(
            "{}/{}/participation",
            AGENTS_PATH,
            agent_path_component(agent_id)?
        );
        self.put(&path, request).await
    }

    /// `POST /_arkret/self/agent-sidecars:ensure`
    /// (`ak.self.agent.sidecar.command.ensure.v1`).
    pub async fn agent_sidecar_ensure(
        &self,
        request: &SidecarEnsureRequestBody,
    ) -> Result<SidecarEnsureOutcome> {
        self.post(AGENT_SIDECAR_ENSURE_PATH, request).await
    }

    /// `GET /_arkret/self/agent-sidecars/{sidecar_id}`
    /// (`ak.self.agent.sidecar.resource.get.v1`).
    pub async fn agent_sidecar_get(&self, sidecar_id: &SidecarId) -> Result<AgentSidecarView> {
        self.get(&format!("{AGENT_SIDECARS_PATH}/{sidecar_id}"))
            .await
    }

    /// `GET /_arkret/self/agent-sidecars`
    /// (`ak.self.agent.sidecar.read.list.v1`).
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
    use serde_json::json;

    use super::*;

    #[test]
    fn agent_path_component_percent_encodes_did_and_grant_id() {
        assert_eq!(
            agent_path_component("did:web:agent.example/user").unwrap(),
            "did%3Aweb%3Aagent.example%2Fuser"
        );
        assert_eq!(
            agent_path_component("ak:grant:ARF6inGTAigpVRHdDKO3YiWYHn3tJycH9CnluHfVxh20").unwrap(),
            "ak%3Agrant%3AARF6inGTAigpVRHdDKO3YiWYHn3tJycH9CnluHfVxh20"
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
                "agent_id": "ak:did_core:web:agents.example:summary",
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

    #[test]
    fn formal_historical_signer_key_response_decodes_for_the_client() {
        let outcome: SignerKeysQueryOutcome = serde_json::from_value(json!({
            "request_id": "ak:request:01904100-0000-7000-8000-000000000001",
            "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5",
            "recipient_account_id": {
                "principal_id": "ak:did_core:web:recipient.example",
                "station_id": "ak:did_core:web:station.example"
            },
            "results": [{
                "selector": {
                    "verification_mode": "historical_event",
                    "sender_kind": "agent",
                    "actor": {
                        "kind": "account",
                        "account_id": {
                            "principal_id": "ak:did_core:web:agent.example",
                            "station_id": "ak:did_core:web:station.example"
                        }
                    },
                    "verification_method": "did:web:agent.example#runtime-1",
                    "committed_event_ref": {
                        "event_id": "ak:event:ARTzU1T6HTPffn8VGBicK6XWx4KIC4PXvv0NX-EMSj4G",
                        "commit_id": "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
                        "stream_ref": {
                            "kind": "realm",
                            "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5"
                        },
                        "stream_position": 12
                    }
                },
                "status": "resolved",
                "key": {
                    "public_key_b64u": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "authorization_ref": {
                        "event_id": "ak:event:Aao964Xuq1Q7PmnLt9I97ih00Qs2N6qMkBgKgYCvUFFe",
                        "commit_id": "ak:realm_commit:AdA0TA9zF1BPiudM7qe4WqKZLjMn0r7--gKAHqstAWDZ",
                        "stream_ref": {
                            "kind": "realm",
                            "realm_id": "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5"
                        },
                        "stream_position": 7
                    },
                    "revision": {
                        "commit_id": "ak:realm_commit:AQPhm6Di_JMyu-JM932ww_EvyQU0dIIEO2ykFmYb9nD5",
                        "stream_position": 15
                    },
                    "governance_generation": 4
                },
                "accepted_at": "2026-09-20T00:00:00.000Z"
            }]
        }))
        .expect("the formal Station response must decode before endpoint validation");

        assert_eq!(outcome.results.len(), 1);
        assert!(outcome.results[0].selector().is_historical());
        assert!(outcome.results[0].accepted_at().is_some());

        let request = SignerKeysQueryRequestBody {
            request_id: outcome.request_id.clone(),
            realm_id: outcome.realm_id.clone(),
            recipient_account_id: outcome.recipient_account_id.clone(),
            queries: vec![outcome.results[0].selector().clone()],
        };
        outcome
            .validate_for_request(&request)
            .expect("the HTTP client must accept the schema-valid response for its exact request");
    }
}
