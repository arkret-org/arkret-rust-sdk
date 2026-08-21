//! Typed private history-key recovery endpoints.

use arkret_models_collaboration::history_key::{
    HistoryKeyRequest, HistoryKeyRequestCreateOutcome, HistoryKeyRequestListOutcome,
    HistoryKeyRequestListQuery, HistoryKeyRequestReplica, HistoryKeyRequestReplicaOutcome,
    HistoryKeyResponseAckOutcome, HistoryKeyResponseAckRequest, HistoryKeyResponseListOutcome,
    HistoryKeyResponseListQuery, HistoryKeyResponseSendOutcome, HistoryKeyResponseSendRequest,
    HistoryKeySourceRelay, HistoryMailboxId, OrganizationRecoveryArchiveListOutcome,
    OrganizationRecoveryArchiveListQuery, OrganizationRecoveryArchiveReplica,
    OrganizationRecoveryArchiveReplicaOutcome,
};
use reqwest::Method;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};

use crate::{Client, Error, Result, reject_path_segment};

const PATH_SELF_HISTORY_KEY_REQUESTS: &str = "/_arkret/self/history-key-requests";
const PATH_SELF_HISTORY_KEY_REQUESTS_READ: &str = "/_arkret/self/history-key-requests/read";
const PATH_SELF_HISTORY_KEY_RESPONSES: &str = "/_arkret/self/history-key-responses";
const PATH_SELF_ORGANIZATION_RECOVERY_ARCHIVES_READ: &str =
    "/_arkret/self/organization-recovery-archives/read";
const PATH_PEER_HISTORY_KEY_REQUESTS_REPLICATE: &str =
    "/_arkret/peer/history-key-requests/replicate";
const PATH_PEER_HISTORY_KEY_RESPONSES_RELAY: &str = "/_arkret/peer/history-key-responses/relay";
const PATH_PEER_ORGANIZATION_RECOVERY_ARCHIVES_REPLICATE: &str =
    "/_arkret/peer/organization-recovery-archives/replicate";

fn mailbox_authorization(capability_b64u: &str) -> Result<HeaderValue> {
    if capability_b64u.len() != 43
        || !capability_b64u
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(Error::Protocol(
            "history mailbox capability must encode exactly 32 bytes as base64url".to_owned(),
        ));
    }
    HeaderValue::from_str(&format!("Arkret-Mailbox {capability_b64u}"))
        .map_err(|error| Error::Protocol(format!("invalid mailbox capability header: {error}")))
}

impl Client {
    pub async fn history_key_request_create(
        &self,
        request: &HistoryKeyRequest,
    ) -> Result<HistoryKeyRequestCreateOutcome> {
        request.validate()?;
        let outcome: HistoryKeyRequestCreateOutcome = self
            .post_protocol_replay_safe(PATH_SELF_HISTORY_KEY_REQUESTS, request)
            .await?;
        outcome.validate()?;
        if outcome.request != *request {
            return Err(Error::Protocol(
                "history request create outcome changed the accepted request".to_owned(),
            ));
        }
        Ok(outcome)
    }

    pub async fn history_key_request_list(
        &self,
        query: &HistoryKeyRequestListQuery,
    ) -> Result<HistoryKeyRequestListOutcome> {
        query.validate()?;
        let outcome: HistoryKeyRequestListOutcome = self
            .post(PATH_SELF_HISTORY_KEY_REQUESTS_READ, query)
            .await?;
        outcome.validate()?;
        Ok(outcome)
    }

    pub async fn history_key_response_send(
        &self,
        request: &HistoryKeyResponseSendRequest,
    ) -> Result<HistoryKeyResponseSendOutcome> {
        request.validate()?;
        let outcome: HistoryKeyResponseSendOutcome = self
            .post_protocol_replay_safe(PATH_SELF_HISTORY_KEY_RESPONSES, request)
            .await?;
        outcome.validate()?;
        if outcome.response_id != request.response_id {
            return Err(Error::Protocol(
                "history response receipt changed response_id".to_owned(),
            ));
        }
        Ok(outcome)
    }

    pub async fn history_key_response_list(
        &self,
        reply_mailbox_id: &HistoryMailboxId,
        capability_b64u: &str,
        query: &HistoryKeyResponseListQuery,
    ) -> Result<HistoryKeyResponseListOutcome> {
        query.validate()?;
        reject_path_segment(reply_mailbox_id.as_str())?;
        let path = format!(
            "/_arkret/self/history-key-responses/{}/read",
            reply_mailbox_id.as_str()
        );
        let builder = self
            .public_request(Method::POST, &path)?
            .header(AUTHORIZATION, mailbox_authorization(capability_b64u)?);
        let builder = self.canonical_json_body(builder, query)?;
        let outcome: HistoryKeyResponseListOutcome = self.send_json(builder).await?;
        outcome.validate()?;
        Ok(outcome)
    }

    pub async fn history_key_response_ack(
        &self,
        reply_mailbox_id: &HistoryMailboxId,
        capability_b64u: &str,
        request: &HistoryKeyResponseAckRequest,
    ) -> Result<HistoryKeyResponseAckOutcome> {
        request.validate()?;
        reject_path_segment(reply_mailbox_id.as_str())?;
        let path = format!(
            "/_arkret/self/history-key-responses/{}/ack",
            reply_mailbox_id.as_str()
        );
        let builder = self
            .public_request(Method::POST, &path)?
            .header(AUTHORIZATION, mailbox_authorization(capability_b64u)?)
            .header(CONTENT_TYPE, "application/json");
        let builder = self.canonical_json_body(builder, request)?;
        let outcome: HistoryKeyResponseAckOutcome = self.send_json(builder).await?;
        outcome.validate()?;
        if outcome.acked_through_cursor != request.high_water_cursor {
            return Err(Error::Protocol(
                "history response ack outcome changed the high-water cursor".to_owned(),
            ));
        }
        Ok(outcome)
    }

    pub async fn organization_recovery_archive_list(
        &self,
        query: &OrganizationRecoveryArchiveListQuery,
    ) -> Result<OrganizationRecoveryArchiveListOutcome> {
        query.validate()?;
        let outcome: OrganizationRecoveryArchiveListOutcome = self
            .post(PATH_SELF_ORGANIZATION_RECOVERY_ARCHIVES_READ, query)
            .await?;
        outcome.validate()?;
        Ok(outcome)
    }

    pub async fn peer_history_key_request_replicate(
        &self,
        request: &HistoryKeyRequestReplica,
    ) -> Result<HistoryKeyRequestReplicaOutcome> {
        request.validate()?;
        let outcome: HistoryKeyRequestReplicaOutcome = self
            .post_protocol_replay_safe(PATH_PEER_HISTORY_KEY_REQUESTS_REPLICATE, request)
            .await?;
        outcome.validate()?;
        if outcome.destination_service_id != request.destination_service_id {
            return Err(Error::Protocol(
                "history request replica receipt changed destination_service_id".to_owned(),
            ));
        }
        Ok(outcome)
    }

    pub async fn peer_history_key_response_relay(
        &self,
        request: &HistoryKeySourceRelay,
    ) -> Result<HistoryKeyResponseSendOutcome> {
        request.validate()?;
        let outcome: HistoryKeyResponseSendOutcome = self
            .post_protocol_replay_safe(PATH_PEER_HISTORY_KEY_RESPONSES_RELAY, request)
            .await?;
        outcome.validate()?;
        if outcome.response_id != request.response.response_id {
            return Err(Error::Protocol(
                "history response relay receipt changed response_id".to_owned(),
            ));
        }
        Ok(outcome)
    }

    pub async fn peer_organization_recovery_archive_replicate(
        &self,
        request: &OrganizationRecoveryArchiveReplica,
    ) -> Result<OrganizationRecoveryArchiveReplicaOutcome> {
        request.validate()?;
        let outcome: OrganizationRecoveryArchiveReplicaOutcome = self
            .post_protocol_replay_safe(PATH_PEER_ORGANIZATION_RECOVERY_ARCHIVES_REPLICATE, request)
            .await?;
        outcome.validate()?;
        if outcome.holder_service_id != request.holder_service_id {
            return Err(Error::Protocol(
                "archive replica receipt changed holder_service_id".to_owned(),
            ));
        }
        Ok(outcome)
    }
}
