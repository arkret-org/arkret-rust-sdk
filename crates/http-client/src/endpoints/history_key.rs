//! Typed private history-key recovery endpoints.

use arkret_models_collaboration::history_key::{
    HistoryKeyRequest, HistoryKeyRequestCreateOutcome, HistoryKeyRequestListOutcome,
    HistoryKeyRequestListQuery, HistoryKeyResponseAckOutcome, HistoryKeyResponseAckRequest,
    HistoryKeyResponseListOutcome, HistoryKeyResponseListQuery, HistoryKeyResponseSendReceipt,
    HistoryKeyResponseSendRequest, HistoryKeySourceRelay, OrganizationRecoveryArchiveListOutcome,
    OrganizationRecoveryArchiveListQuery,
};
use reqwest::Method;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};

use crate::{Client, Error, Result};

const PATH_SELF_HISTORY_KEY_REQUESTS: &str = "/_arkret/self/history-key-requests";
const PATH_SELF_HISTORY_KEY_REQUESTS_READ: &str = "/_arkret/self/history-key-requests/read";
const PATH_SELF_HISTORY_KEY_RESPONSES: &str = "/_arkret/self/history-key-responses";
const PATH_SELF_HISTORY_KEY_RESPONSES_READ: &str = "/_arkret/self/history-key-responses/read";
const PATH_SELF_HISTORY_KEY_RESPONSES_ACK: &str = "/_arkret/self/history-key-responses/ack";
const PATH_SELF_ORGANIZATION_RECOVERY_ARCHIVES_READ: &str =
    "/_arkret/self/organization-recovery-archives/read";
const PATH_PEER_HISTORY_KEY_RESPONSES_RELAY: &str = "/_arkret/peer/history-key-responses/relay";

fn history_response_authorization(capability_b64u: &str) -> Result<HeaderValue> {
    let decoded = arkret_canonical::base64url::base64url_decode(capability_b64u)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    if decoded.len() != 32
        || arkret_canonical::base64url::base64url_encode(&decoded) != capability_b64u
    {
        return Err(Error::Protocol(
            "history response capability must canonically encode exactly 32 bytes as base64url"
                .to_owned(),
        ));
    }
    HeaderValue::from_str(&format!("Arkret-History-Capability {capability_b64u}")).map_err(
        |error| {
            Error::Protocol(format!(
                "invalid history response capability header: {error}"
            ))
        },
    )
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
    ) -> Result<HistoryKeyResponseSendReceipt> {
        request.validate()?;
        let outcome: HistoryKeyResponseSendReceipt = self
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
        capability_b64u: &str,
        query: &HistoryKeyResponseListQuery,
    ) -> Result<HistoryKeyResponseListOutcome> {
        query.validate()?;
        let builder = self
            .public_request(Method::POST, PATH_SELF_HISTORY_KEY_RESPONSES_READ)?
            .header(
                AUTHORIZATION,
                history_response_authorization(capability_b64u)?,
            );
        let builder = self.canonical_json_body(builder, query)?;
        let outcome: HistoryKeyResponseListOutcome = self.send_json(builder).await?;
        outcome.validate()?;
        Ok(outcome)
    }

    pub async fn history_key_response_ack(
        &self,
        capability_b64u: &str,
        request: &HistoryKeyResponseAckRequest,
    ) -> Result<HistoryKeyResponseAckOutcome> {
        request.validate()?;
        let builder = self
            .public_request(Method::POST, PATH_SELF_HISTORY_KEY_RESPONSES_ACK)?
            .header(
                AUTHORIZATION,
                history_response_authorization(capability_b64u)?,
            )
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

    pub async fn peer_history_key_response_relay(
        &self,
        request: &HistoryKeySourceRelay,
    ) -> Result<HistoryKeyResponseSendReceipt> {
        request.validate()?;
        let outcome: HistoryKeyResponseSendReceipt = self
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
}
