//! Session-grant, account-subscribe, contacts, and direct-conversation
//! endpoint methods on [`Client`].

use arkret_models_collaboration::account_lifecycle::{
    AccountRegisterOutcome, AccountRegisterRequestBody, AccountUpdateProfileRequestBody,
    AccountView,
};
use arkret_models_collaboration::contact_operations::{
    ContactAcceptRequestBody, ContactOperationOutcome, ContactOperationRequestBody,
    ContactTombstoneRequestBody,
};
use arkret_models_collaboration::direct_conversation_ops::{
    DirectConversationResolveOutcome, DirectConversationResolveRequestBody,
};
use arkret_models_collaboration::http_bodies::{
    AccountDevicePairOutcome, AccountDevicePairRequestBody, ContactList, DevicePairingBootstrap,
    DevicePairingCodeClaimOutcome, DevicePairingCodeClaimRequestBody, DevicePairingFinalizeOutcome,
    DevicePairingFinalizeRequestBody, DevicePairingResolveRequestBody, DevicePairingStageOutcome,
    DevicePairingStageRequestBody, DevicePairingStatusOutcome, DevicePairingStatusRequestBody,
};
#[cfg(all(test, not(target_arch = "wasm32")))]
use arkret_models_collaboration::session_grant_bodies::{
    AgentSessionGrantProof, AgentSessionGrantProofKind, AgentSessionGrantRequest,
    SessionGrantAgentScopeRequest, SessionGrantDpopBindingProof,
};
use arkret_models_collaboration::session_grant_bodies::{
    SessionGrantOutcome, SessionGrantRefreshRequestBody, SessionGrantRequestBody,
};
use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeBatch, AccountSubscribeFrame, AccountSubscribeFrameKind,
    AccountSubscribeSnapshotResult,
};
use arkret_models_collaboration::sync_frames::client_sync::SyncRequestBody;
use arkret_models_collaboration::sync_frames::stream_trace::StreamTraceValidator;
use arkret_models_discovery::ServiceDescribe;
use arkret_models_identity::{
    AccountCursorRevokeOutcome, AccountCursorRevokeRequestBody, AccountHandoffOutcome,
    AccountHandoffRequestBody, AccountLogoutOutcome, AccountLogoutRequestBody,
    AccountOnboardingState, AccountUpdateProfileOutcome, IdentityAbandonmentOutcome,
    IdentityAbandonmentRequestBody, IdentityBindingChallengeOutcome,
    IdentityBindingChallengeRequestBody,
};
use arkret_wire::{
    PATH_SELF_CONTACTS, PATH_SELF_CONTACTS_REQUEST, PATH_SELF_CONTACTS_RESPOND,
    PATH_SELF_CONTACTS_TOMBSTONE, PATH_SELF_DIRECT_CONVERSATIONS_RESOLVE,
};
use reqwest::header::CONTENT_TYPE;
use reqwest::{Method, RequestBuilder, Response};

use crate::client_internals::trim_ascii;
use crate::{AccountSubscribeFolder, Client, ClientRequestOptions, Error, Result};

#[cfg(not(target_arch = "wasm32"))]
type BoxAccountSubscribeFrameStream =
    std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<AccountSubscribeFrame>> + Send>>;

#[cfg(target_arch = "wasm32")]
type BoxAccountSubscribeFrameStream =
    std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<AccountSubscribeFrame>>>>;

/// Validated account-subscribe frame stream bound to its request context.
pub struct AccountSubscribeFrameStream {
    inner: BoxAccountSubscribeFrameStream,
    trace: StreamTraceValidator,
    failed: bool,
    round_budget: arkret_models_collaboration::sync_frames::demand_sync::AccountSyncRoundBudget,
}

impl AccountSubscribeFrameStream {
    pub async fn next_frame(&mut self) -> Result<Option<AccountSubscribeFrame>> {
        use futures_util::StreamExt;

        if self.failed {
            return Err(Error::Protocol(
                "account subscribe stream was already rejected".to_owned(),
            ));
        }
        let frame = match self.inner.next().await {
            Some(Ok(frame)) => frame,
            Some(Err(error)) => {
                self.failed = true;
                return Err(error);
            }
            None => {
                self.trace.finish()?;
                return Ok(None);
            }
        };
        self.failed = true;
        self.round_budget
            .observe(arkret_canonical::canonical_json_bytes(&frame)?.len())?;
        self.trace.push(&frame)?;
        self.failed = false;
        Ok(Some(frame))
    }

    pub fn reconnect_cursor(&self) -> Option<&str> {
        self.trace.reconnect_cursor()
    }

    pub const fn is_terminal(&self) -> bool {
        self.trace.is_terminal()
    }
}

impl Client {
    /// `POST /_arkret/gate/account/authentication-handoffs`
    /// (`ak.gate.account.exchange.create_handoff.v1`): exchange an OIDC
    /// authorization code for a short-lived DPoP-bound account handoff.
    pub async fn auth_create_account_handoff(
        &self,
        req: &AccountHandoffRequestBody,
    ) -> Result<AccountHandoffOutcome> {
        let outcome: AccountHandoffOutcome = self
            .post("/_arkret/gate/account/authentication-handoffs", req)
            .await?;
        outcome.validate()?;
        Ok(outcome)
    }

    /// Read the current server-authored onboarding projection using the live
    /// DPoP-bound account handoff. Clients call this before reconciling local
    /// onboarding artifacts after reload, callback, or an uncertain result.
    pub async fn auth_account_onboarding_state(&self) -> Result<AccountOnboardingState> {
        let snapshot: AccountOnboardingState = self.get("/_arkret/gate/account/onboarding").await?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// `POST /_arkret/gate/account/identity-binding-challenges`
    /// (`ak.gate.account.command.issue_identity_binding_challenge.v1`). The
    /// client must use `Authorization: DPoP <account_handoff_grant>` and a
    /// matching per-request DPoP proof.
    pub async fn auth_issue_identity_binding_challenge(
        &self,
        req: &IdentityBindingChallengeRequestBody,
    ) -> Result<IdentityBindingChallengeOutcome> {
        self.post("/_arkret/gate/account/identity-binding-challenges", req)
            .await
    }

    /// `POST /_arkret/gate/account/session-grants`
    /// (`ak.gate.account.command.issue_session_grant.v1`): exchange a body-borne
    /// passkey / OIDC / device / DID proof for a session grant. This is
    /// the only session-grant issuance path registered in the spec HTTP
    /// binding (`x-arkret-auth.proof_in_body: true`); challenge
    /// acquisition is deployment-local per `identity-did.md` §5.1.
    pub async fn auth_issue_session_grant(
        &self,
        req: &SessionGrantRequestBody,
    ) -> Result<SessionGrantOutcome> {
        self.post_protocol_replay_safe("/_arkret/gate/account/session-grants", req)
            .await
    }

    /// `POST /_arkret/gate/account/session-grants/refresh`
    /// (`ak.gate.account.command.refresh_session_grant.v1`): rotate a
    /// DPoP-bound session grant without changing the grant audience.
    pub async fn auth_refresh_session_grant(
        &self,
        req: &SessionGrantRefreshRequestBody,
    ) -> Result<SessionGrantOutcome> {
        self.post_protocol_replay_safe("/_arkret/gate/account/session-grants/refresh", req)
            .await
    }

    /// `POST /_arkret/gate/account/logout`
    /// (`ak.gate.account.command.logout.v1`): terminate the current
    /// DPoP-bound account session at the Account Authority.
    pub async fn auth_account_logout(&self) -> Result<AccountLogoutOutcome> {
        self.post(
            "/_arkret/gate/account/logout",
            &AccountLogoutRequestBody::default(),
        )
        .await
    }

    pub async fn account_viewer(&self) -> Result<AccountView> {
        self.get("/_arkret/self/account/viewer").await
    }

    pub async fn account_register(
        &self,
        request: &AccountRegisterRequestBody,
    ) -> Result<AccountRegisterOutcome> {
        request.validate()?;
        let outcome: AccountRegisterOutcome =
            self.post("/_arkret/gate/account/register", request).await?;
        outcome.validate_against_request(request)?;
        Ok(outcome)
    }

    /// Explicitly abandon a provisional identity using fresh account authentication.
    /// Exact request-id replay returns the recorded terminal.
    pub async fn auth_abandon_identity_creation(
        &self,
        request: &IdentityAbandonmentRequestBody,
    ) -> Result<IdentityAbandonmentOutcome> {
        request.validate()?;
        self.post("/_arkret/gate/account/identity-abandonments", request)
            .await
    }

    pub async fn account_update_profile(
        &self,
        request: &AccountUpdateProfileRequestBody,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<AccountUpdateProfileOutcome> {
        request.validate(digest_suite)?;
        self.post("/_arkret/self/account/profile", request).await
    }

    pub async fn account_device_pair(
        &self,
        request: &AccountDevicePairRequestBody,
    ) -> Result<AccountDevicePairOutcome> {
        self.post("/_arkret/gate/account/device-pair", request)
            .await
    }

    /// `POST /_arkret/open/device-pairing/requests`
    /// (`ak.open.device_pairing.command.stage.v1`). Unauthenticated: the
    /// not-yet-authorized device stages its device key and gets back a short
    /// `device_pairing_request_id` + `pairing_code` to encode into its QR.
    pub async fn device_pairing_stage(
        &self,
        request: &DevicePairingStageRequestBody,
    ) -> Result<DevicePairingStageOutcome> {
        self.post("/_arkret/open/device-pairing/requests", request)
            .await
    }

    /// `POST /_arkret/gate/account/device-pairing/finalizations`
    /// (`ak.gate.account.command.finalize_device_pairing.v1`). Authenticated
    /// with `Authorization: DPoP <account_handoff_grant>` and a matching DPoP
    /// proof: the staged candidate attaches its signed target proof and the
    /// record moves one way from `staged` to `ready_for_claim`. This is the
    /// only server-facing carrier of the target proof; the anonymous stage and
    /// resolve surfaces MUST NOT receive it.
    pub async fn auth_finalize_device_pairing(
        &self,
        request: &DevicePairingFinalizeRequestBody,
    ) -> Result<DevicePairingFinalizeOutcome> {
        self.post(
            "/_arkret/gate/account/device-pairing/finalizations",
            request,
        )
        .await
    }

    /// `POST /_arkret/gate/account/device-pairing/code-claims`
    /// (`ak.gate.account.read.claim_device_pairing_code.v1`). Authenticated,
    /// body-only: an accepted device of the account exchanges the eight-
    /// character code for the same bootstrap and byte-equivalent target proof
    /// the short-link resolve returns. Claiming authorizes nothing.
    pub async fn device_pairing_claim_code(
        &self,
        request: &DevicePairingCodeClaimRequestBody,
    ) -> Result<DevicePairingCodeClaimOutcome> {
        self.post("/_arkret/gate/account/device-pairing/code-claims", request)
            .await
    }

    /// `POST /_arkret/open/device-pairing/resolve`
    /// (`ak.open.device_pairing.read.resolve.v1`). Unauthenticated, body-only: an
    /// already-authorized device exchanges a scanned/pasted pairing token for the
    /// staged `DevicePairingBootstrap`, then drives `account_device_pair`.
    pub async fn device_pairing_resolve(
        &self,
        request: &DevicePairingResolveRequestBody,
    ) -> Result<DevicePairingBootstrap> {
        self.post("/_arkret/open/device-pairing/resolve", request)
            .await
    }

    /// `POST /_arkret/open/device-pairing/requests/status`
    /// (`ak.open.device_pairing.read.status.v1`). Unauthenticated, body-only: the
    /// new device polls whether a sibling has authorized its staged request.
    pub async fn device_pairing_status(
        &self,
        request: &DevicePairingStatusRequestBody,
    ) -> Result<DevicePairingStatusOutcome> {
        let outcome: DevicePairingStatusOutcome = self
            .post("/_arkret/open/device-pairing/requests/status", request)
            .await?;
        // The conditional members are the §5.4.1 pre-assembly entry point, so a
        // shape the schema rejects must not reach the caller as a usable state.
        outcome.validate()?;
        Ok(outcome)
    }

    fn account_subscribe_request(
        &self,
        request: &SyncRequestBody,
        accept: &str,
    ) -> Result<RequestBuilder> {
        request.validate()?;
        let mut builder = self
            .request_unbounded(Method::GET, "/_arkret/self/account/subscribe")?
            .header("accept", accept);
        if let Some(after) = request.after.as_deref() {
            builder = builder.query(&[("after", after)]);
        }
        if let Some(catchup) = request.catchup {
            builder = builder.query(&[("catchup", catchup)]);
        }
        if let Some(replace) = request.replace_filter {
            builder = builder.query(&[("replace_filter", replace)]);
        }
        if let Some(page) = &request.realm_list {
            let encoded = String::from_utf8(arkret_canonical::canonical_json_bytes(page)?)
                .map_err(|error| Error::Protocol(error.to_string()))?;
            builder = builder.query(&[("realm_list", encoded)]);
        }
        if let Some(filter) = &request.filter {
            let encoded = String::from_utf8(arkret_canonical::canonical_json_bytes(filter)?)
                .map_err(|error| Error::Protocol(error.to_string()))?;
            builder = builder.query(&[("filter", encoded)]);
        }
        Ok(builder)
    }

    async fn account_subscribe(
        &self,
        request: &SyncRequestBody,
        options: &ClientRequestOptions,
    ) -> Result<Response> {
        // Long-lived NDJSON stream — exempt from the per-request default
        // total timeout (see `DEFAULT_REQUEST_TIMEOUT`).
        let builder = self.account_subscribe_request(request, "application/x-ndjson")?;
        self.send_response(self.apply_request_options(builder, options)?)
            .await
    }

    /// Subscribe and return one validated account delta snapshot.
    ///
    /// `/_arkret/self/account/subscribe` is a long-lived NDJSON stream:
    /// the server keeps pushing frames and does not close the response
    /// on its own, so reading the whole body up front would never
    /// return (and would buffer the stream without bound). The body is
    /// therefore read incrementally. With `catchup=true`, all baseline
    /// deltas are folded until a valid `catchup_complete`; without catch-up,
    /// the first validated delta completes this one-shot call.
    ///
    /// Benign keepalive and frontier frames are validated while waiting.
    /// Control interrupts (`dropped` / `resync_required` /
    /// `unauthorized`) surface as [`Error::AccountStreamInterrupt`] so
    /// the caller can reconcile per client-sync.md §2.2 — they are never
    /// silently consumed.
    pub async fn account_subscribe_batch(
        &self,
        request: &SyncRequestBody,
    ) -> Result<AccountSubscribeBatch> {
        self.account_subscribe_batch_with_options(request, &ClientRequestOptions::default())
            .await
    }

    pub async fn account_subscribe_batch_with_options(
        &self,
        request: &SyncRequestBody,
        options: &ClientRequestOptions,
    ) -> Result<AccountSubscribeBatch> {
        use futures_util::StreamExt;

        fn decode_subscribe_line(line: &[u8]) -> Result<Option<AccountSubscribeFrame>> {
            let trimmed = trim_ascii(line);
            if trimmed.is_empty() {
                return Ok(None);
            }
            let frame: AccountSubscribeFrame = serde_json::from_slice(trimmed)
                .map_err(|error| Error::Protocol(error.to_string()))?;
            Ok(Some(frame))
        }

        fn push_frame(
            folder: &mut AccountSubscribeFolder,
            frame: AccountSubscribeFrame,
            catchup: bool,
        ) -> Result<bool> {
            let is_delta = frame.kind == AccountSubscribeFrameKind::Delta;
            let interrupt = frame.interrupt()?;
            let stopped = folder.push(frame)?;
            if let Some(interrupt) = interrupt {
                return Err(Error::AccountStreamInterrupt(interrupt));
            }
            Ok(stopped || (!catchup && is_delta))
        }

        fn finish_folder(folder: AccountSubscribeFolder) -> Result<AccountSubscribeBatch> {
            match folder.finish()? {
                AccountSubscribeSnapshotResult::Batch(batch) => Ok(batch),
                AccountSubscribeSnapshotResult::ReconnectAfter { .. } => Err(Error::Protocol(
                    "account subscribe terminated before a delta snapshot".to_owned(),
                )),
            }
        }

        let builder = self.account_subscribe_request(request, "application/x-ndjson")?;
        let response = self
            .send_response(self.apply_request_options(builder, options)?)
            .await?;
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !content_type.contains("application/x-ndjson") {
            return Err(Error::Protocol(
                "account subscribe requires application/x-ndjson".to_owned(),
            ));
        }

        let catchup = request.catchup.unwrap_or(false);
        let mut folder = AccountSubscribeFolder::for_request(request);
        if crate::subscribe_body::streaming_bodies_available() {
            let lines = crate::subscribe_body::ndjson_lines(response.bytes_stream());
            let mut lines = std::pin::pin!(lines);
            while let Some(line) = lines.next().await {
                if let Some(frame) = decode_subscribe_line(line?.as_bytes())?
                    && push_frame(&mut folder, frame, catchup)?
                {
                    return finish_folder(folder);
                }
            }
        } else {
            for line in crate::subscribe_body::bounded_response_lines(response).await? {
                if let Some(frame) = decode_subscribe_line(line.as_bytes())?
                    && push_frame(&mut folder, frame, catchup)?
                {
                    return finish_folder(folder);
                }
            }
        }
        finish_folder(folder)
    }

    /// S-6 (savfox SDK gap): NDJSON-streamed account subscribe. Yields
    /// one [`AccountSubscribeFrame`] per line; transient per-line
    /// decode errors surface as `Err` items but the stream continues
    /// until the underlying HTTP body ends.
    pub async fn account_subscribe_frames(
        &self,
        request: &SyncRequestBody,
    ) -> Result<AccountSubscribeFrameStream> {
        self.account_subscribe_frames_with_options(request, &ClientRequestOptions::default())
            .await
    }

    pub async fn account_subscribe_frames_with_options(
        &self,
        request: &SyncRequestBody,
        options: &ClientRequestOptions,
    ) -> Result<AccountSubscribeFrameStream> {
        use futures_util::StreamExt;

        let response = self.account_subscribe(request, options).await?;
        let inner: BoxAccountSubscribeFrameStream =
            if crate::subscribe_body::streaming_bodies_available() {
                Box::pin(
                    crate::subscribe_body::ndjson_lines(response.bytes_stream()).filter_map(
                        |line| async move {
                            match line.and_then(|line| {
                                AccountSubscribeFrame::from_ndjson_line(&line).map_err(Error::from)
                            }) {
                                Ok(Some(frame)) => Some(Ok(frame)),
                                Ok(None) => None,
                                Err(error) => Some(Err(error)),
                            }
                        },
                    ),
                )
            } else {
                let lines = crate::subscribe_body::bounded_response_lines(response).await?;
                Box::pin(
                    futures_util::stream::iter(lines).filter_map(|line| async move {
                        match AccountSubscribeFrame::from_ndjson_line(&line) {
                            Ok(Some(frame)) => Some(Ok(frame)),
                            Ok(None) => None,
                            Err(error) => Some(Err(Error::from(error))),
                        }
                    }),
                )
            };
        Ok(AccountSubscribeFrameStream {
            inner,
            trace: StreamTraceValidator::new(
                request.catchup.unwrap_or(false),
                request.after.clone(),
            ),
            failed: false,
            round_budget: Default::default(),
        })
    }

    pub async fn account_describe(&self) -> Result<ServiceDescribe> {
        self.get("/_arkret/self/account/describe").await
    }

    pub async fn account_cursor_revoke(
        &self,
        request: &AccountCursorRevokeRequestBody,
    ) -> Result<AccountCursorRevokeOutcome> {
        self.post("/_arkret/self/account/cursor/revoke", request)
            .await
    }

    pub async fn contacts_request(
        &self,
        request: &ContactOperationRequestBody,
    ) -> Result<ContactOperationOutcome> {
        self.post(PATH_SELF_CONTACTS_REQUEST, request).await
    }

    pub async fn contacts_respond(
        &self,
        request: &ContactAcceptRequestBody,
    ) -> Result<ContactOperationOutcome> {
        self.post(PATH_SELF_CONTACTS_RESPOND, request).await
    }

    pub async fn contacts_list(&self) -> Result<ContactList> {
        self.get(PATH_SELF_CONTACTS).await
    }

    pub async fn contacts_export_continuity(&self) -> Result<ContactList> {
        self.get(&format!("{PATH_SELF_CONTACTS}?include_continuity=true"))
            .await
    }

    pub async fn contacts_tombstone(
        &self,
        request: &ContactTombstoneRequestBody,
    ) -> Result<ContactOperationOutcome> {
        self.post(PATH_SELF_CONTACTS_TOMBSTONE, request).await
    }

    /// Query-only resolver for the pair's single stable Direct Conversation.
    ///
    /// This never creates. A Direct Conversation Realm is created only by the founder derived from
    /// the pair's root Contact round, through the `direct_conversation_genesis` admission variant
    /// of `ak.realm.create`. `AwaitingFounder` never becomes create authority no matter how
    /// long the caller waits: base v1 has no timeout fallback or takeover.
    pub async fn direct_conversation_resolve(
        &self,
        request: &DirectConversationResolveRequestBody,
    ) -> Result<DirectConversationResolveOutcome> {
        self.post(PATH_SELF_DIRECT_CONVERSATIONS_RESOLVE, request)
            .await
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::sync_frames::client_sync::SyncFilter;
    use url::Url;

    use super::*;
    fn client() -> Client {
        Client::new(Url::parse("https://alice.example/").unwrap()).unwrap()
    }

    fn empty_request() -> SyncRequestBody {
        SyncRequestBody {
            after: None,
            catchup: None,
            filter: None,

            realm_list: None,
            replace_filter: None,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn split_request(raw: &[u8]) -> (String, String, Vec<u8>) {
        let idx = raw
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        let head = std::str::from_utf8(&raw[..idx]).unwrap();
        let body = raw[idx + 4..].to_vec();
        let mut lines = head.splitn(2, "\r\n");
        let request_line = lines.next().unwrap_or("").to_owned();
        let headers = lines.next().unwrap_or("").to_owned();
        (request_line, headers, body)
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn read_http_request(socket: &mut tokio::net::TcpStream) -> Vec<u8> {
        use tokio::io::AsyncReadExt;

        let mut raw = Vec::new();
        let mut buffer = [0u8; 2048];
        loop {
            let count = socket.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            raw.extend_from_slice(&buffer[..count]);
            let Some(header_end) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let headers = std::str::from_utf8(&raw[..header_end]).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    line.split_once(':').and_then(|(name, value)| {
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                })
                .unwrap_or(0);
            if raw.len() >= header_end + 4 + content_length {
                break;
            }
        }
        raw
    }

    /// Built from the wire structs rather than a JSON literal: the literal this
    /// replaced still carried a retired `nonce` member and no `issued_at`, and
    /// nothing failed until the body was actually deserialized at run time.
    #[cfg(not(target_arch = "wasm32"))]
    fn session_grant_request() -> SessionGrantRequestBody {
        SessionGrantRequestBody::Agent(AgentSessionGrantRequest {
            principal_id: arkret_wire::DidCoreId::new("ak:did_core:web:agent.example").unwrap(),
            device_id: arkret_wire::DeviceId::new("ak:device:01964137-0000-7000-8000-000000000041")
                .unwrap(),
            requested_scope: vec!["ak.message.create".to_owned()],
            agent_key_authorization_ref: "ak:event:Ae6YFfDokA1FLUx_l-MhAbSvTvoys2ZpRPmqFwrWjd9g"
                .to_owned(),
            agent_scope_request: SessionGrantAgentScopeRequest {
                realm_ids: Vec::new(),
                strand_ids: Vec::new(),
                track_names: Vec::new(),
            },
            requested_scope_disclosure: None,
            dpop_binding_proof: SessionGrantDpopBindingProof {
                proof_jwt: "holder.proof.jwt".to_owned(),
            },
            applet_authority: None,
            proof: AgentSessionGrantProof {
                proof_kind: AgentSessionGrantProofKind::AgentKeyProof,
                challenge: arkret_wire::base64url::base64url_encode([0u8; 16]),
                request_canonical_digest: arkret_wire::Hash::new(format!(
                    "sha256:{}",
                    "00".repeat(32)
                ))
                .unwrap(),
                audience_id: arkret_wire::DidCoreId::new("ak:did_core:web:service.example")
                    .unwrap(),
                issued_at: "2026-08-08T12:00:00.000Z".parse().unwrap(),
                expires_at: "2026-08-08T12:04:00.000Z".parse().unwrap(),
                verification_method: arkret_wire::DidUrl::new(
                    "did:web:agent.example#runtime-key-1",
                )
                .unwrap(),
                signature: "detached.jws".to_owned(),
            },
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn session_grant_outcome_json() -> String {
        serde_json::json!({
            "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:service.example"
            },
            "session_grant": "signed.jwt",
            "expires_at": "2026-08-08T12:04:00.000Z",
            "session_grant_id": "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW",
            "session_public_key": r#"{"crv":"Ed25519","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
            "audience_id": "ak:did_core:web:service.example",
            "granted_scope": []
        })
        .to_string()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn session_grant_refresh_request() -> SessionGrantRefreshRequestBody {
        serde_json::from_value(serde_json::json!({
            "grant_jwt": "predecessor.jwt",
            "device_id": "ak:device:01964137-0000-7000-8000-000000000041",
            "agent_session_refresh_proof": {
                "context": "ak.agent_session_refresh_proof.v1",
                "request_canonical_digest": format!("sha256:{}", "11".repeat(32)),
                "audience_id": "ak:did_core:web:service.example",
                "issued_at": "2026-08-08T11:59:00.000Z",
                "expires_at": "2026-08-08T12:04:00.000Z",
                "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "verification_method": "did:web:agent.example#runtime-key-1"
            }
        }))
        .unwrap()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn session_grant_refresh_outcome_json() -> String {
        serde_json::json!({
            "session_grant_id": "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW",
            "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": "ak:did_core:web:service.example"
            },
            "session_grant": "successor.jwt",
            "session_public_key": r#"{"crv":"Ed25519","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
            "expires_at": "2026-08-08T12:04:00.000Z",
            "audience_id": "ak:did_core:web:service.example",
            "granted_scope": [],
            "previous_session_grant_id": "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW"
        })
        .to_string()
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[derive(Clone, Copy)]
    enum ReplayTrigger {
        Timeout,
        ServiceUnavailable,
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn start_exact_replay_server(
        trigger: ReplayTrigger,
        success_body: String,
    ) -> (
        std::net::SocketAddr,
        tokio::task::JoinHandle<(Vec<u8>, Vec<u8>)>,
    ) {
        use std::time::Duration as StdDuration;

        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let first_raw = read_http_request(&mut first).await;
            match trigger {
                ReplayTrigger::Timeout => {
                    tokio::time::sleep(StdDuration::from_millis(80)).await;
                }
                ReplayTrigger::ServiceUnavailable => {
                    let body = serde_json::json!({
                        "type": "https://arkret.org/problems/frontier_unavailable",
                        "title": "Frontier unavailable",
                        "status": 503,
                        "detail": "retry",
                        "instance": "attempt-1"
                    })
                    .to_string();
                    let response = format!(
                        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/problem+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    first.write_all(response.as_bytes()).await.unwrap();
                }
            }
            drop(first);

            let (mut second, _) = listener.accept().await.unwrap();
            let second_raw = read_http_request(&mut second).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                success_body.len(),
                success_body
            );
            second.write_all(response.as_bytes()).await.unwrap();
            (first_raw, second_raw)
        });
        (addr, server)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn exact_replay_client(addr: std::net::SocketAddr, timeout_ms: u64) -> Client {
        use std::time::Duration as StdDuration;

        Client::builder(Url::parse(&format!("http://{addr}/")).unwrap())
            .allow_insecure_localhost()
            .timeout(StdDuration::from_millis(timeout_ms))
            .retry(
                crate::RetryConfig {
                    base_delay: StdDuration::from_millis(1),
                    ..crate::RetryConfig::standard(1)
                }
                .with_jitter(false),
            )
            .build()
            .unwrap()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn assert_exact_replay_capture(first: &[u8], second: &[u8], expected_path: &str) {
        let (first_line, first_headers, first_body) = split_request(first);
        let (second_line, second_headers, second_body) = split_request(second);
        assert!(first_line.starts_with(&format!("POST {expected_path} ")));
        assert!(second_line.starts_with(&format!("POST {expected_path} ")));
        assert_eq!(first_body, second_body);
        assert!(
            !first_headers
                .to_ascii_lowercase()
                .contains("idempotency-key:")
        );
        assert!(
            !second_headers
                .to_ascii_lowercase()
                .contains("idempotency-key:")
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn session_grant_retry_after_commit_timeout_reuses_exact_body_without_idempotency_key() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration as StdDuration;

        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let first_raw = read_http_request(&mut first).await;
            // Keep the committed first request open without a response. The
            // client timeout deterministically opens the retry; accepting it
            // directly avoids making the second attempt race an arbitrary
            // wall-clock sleep under a loaded test runner.
            let (mut second, _) = listener.accept().await.unwrap();
            let second_raw = read_http_request(&mut second).await;
            let body = session_grant_outcome_json();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            second.write_all(response.as_bytes()).await.unwrap();
            drop(first);
            (first_raw, second_raw)
        });

        let proof_calls = Arc::new(AtomicUsize::new(0));
        let proof_calls_for_auth = Arc::clone(&proof_calls);
        let client = Client::builder(Url::parse(&format!("http://{addr}/")).unwrap())
            .allow_insecure_localhost()
            .auth(crate::Auth::Dpop(crate::DpopAuth::proof_only(move |_| {
                Ok(format!(
                    "outer-proof-{}",
                    proof_calls_for_auth.fetch_add(1, Ordering::SeqCst)
                ))
            })))
            .timeout(StdDuration::from_millis(40))
            .retry(
                crate::RetryConfig {
                    base_delay: StdDuration::from_millis(1),
                    ..crate::RetryConfig::standard(1)
                }
                .with_jitter(false),
            )
            .build()
            .unwrap();

        client
            .auth_issue_session_grant(&session_grant_request())
            .await
            .unwrap();
        let (first, second) = server.await.unwrap();
        let (_, first_headers, first_body) = split_request(&first);
        let (_, second_headers, second_body) = split_request(&second);
        assert_eq!(first_body, second_body);
        assert!(
            !first_headers
                .to_ascii_lowercase()
                .contains("idempotency-key:")
        );
        assert!(
            !second_headers
                .to_ascii_lowercase()
                .contains("idempotency-key:")
        );
        let dpop = |headers: &str| {
            headers
                .lines()
                .find_map(|line| {
                    line.split_once(':')
                        .filter(|(name, _)| name.eq_ignore_ascii_case("dpop"))
                        .map(|(_, value)| value.trim().to_owned())
                })
                .unwrap()
        };
        assert_ne!(dpop(&first_headers), dpop(&second_headers));
        assert_eq!(proof_calls.load(Ordering::SeqCst), 3);
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn session_grant_refresh_timeout_reuses_exact_body_without_idempotency_key() {
        let (addr, server) =
            start_exact_replay_server(ReplayTrigger::Timeout, session_grant_refresh_outcome_json())
                .await;
        exact_replay_client(addr, 40)
            .auth_refresh_session_grant(&session_grant_refresh_request())
            .await
            .unwrap();
        let (first, second) = server.await.unwrap();
        assert_exact_replay_capture(
            &first,
            &second,
            "/_arkret/gate/account/session-grants/refresh",
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn session_grant_issue_and_refresh_replay_exact_body_after_5xx() {
        let (addr, server) = start_exact_replay_server(
            ReplayTrigger::ServiceUnavailable,
            session_grant_outcome_json(),
        )
        .await;
        exact_replay_client(addr, 1_000)
            .auth_issue_session_grant(&session_grant_request())
            .await
            .unwrap();
        let (first, second) = server.await.unwrap();
        assert_exact_replay_capture(&first, &second, "/_arkret/gate/account/session-grants");

        let (addr, server) = start_exact_replay_server(
            ReplayTrigger::ServiceUnavailable,
            session_grant_refresh_outcome_json(),
        )
        .await;
        exact_replay_client(addr, 1_000)
            .auth_refresh_session_grant(&session_grant_refresh_request())
            .await
            .unwrap();
        let (first, second) = server.await.unwrap();
        assert_exact_replay_capture(
            &first,
            &second,
            "/_arkret/gate/account/session-grants/refresh",
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn terminal_session_grant_replay_is_not_automatically_reissued() {
        use std::time::Duration as StdDuration;

        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = read_http_request(&mut socket).await;
            let body = serde_json::json!({
                "type": "https://arkret.org/problems/session_grant_replay_terminal",
                "title": "Session grant replay terminal",
                "status": 409,
                "detail": "recorded grant is superseded",
                "instance": "request-1",
                "session_grant_id": "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW",
                "state": "superseded"
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 409 Conflict\r\nContent-Type: application/problem+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            drop(socket);

            tokio::time::timeout(StdDuration::from_millis(80), listener.accept())
                .await
                .is_ok()
        });

        let client = Client::builder(Url::parse(&format!("http://{addr}/")).unwrap())
            .allow_insecure_localhost()
            .retry(
                crate::RetryConfig {
                    base_delay: StdDuration::from_millis(1),
                    ..crate::RetryConfig::standard(1)
                }
                .with_jitter(false),
            )
            .build()
            .unwrap();
        let error = client
            .auth_issue_session_grant(&session_grant_request())
            .await
            .unwrap_err();
        match error {
            Error::Api { error, .. } => assert!(
                error
                    .session_grant_replay_terminal_details()
                    .unwrap()
                    .is_some()
            ),
            other => panic!("unexpected error: {other}"),
        }
        assert!(
            !server.await.unwrap(),
            "terminal outcome must not be retried"
        );
    }

    #[test]
    fn account_subscribe_query_preserves_canonical_empty_filter_and_false() {
        let request = SyncRequestBody {
            after: Some("ak:cursor:resume".to_owned()),
            filter: Some(
                serde_json::from_value(
                    serde_json::json!({"realm_ids":[],"lazy_load_members":false}),
                )
                .unwrap(),
            ),
            realm_list: Some(Default::default()),
            replace_filter: Some(true),
            ..empty_request()
        };
        let built = client()
            .account_subscribe_request(&request, "application/x-ndjson")
            .unwrap()
            .build()
            .unwrap();
        let query = built
            .url()
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            query.get("filter").unwrap(),
            "{\"lazy_load_members\":false,\"realm_ids\":[]}"
        );
        assert_eq!(query.get("realm_list").unwrap(), "{}");
        assert_eq!(query.get("replace_filter").unwrap(), "true");
        assert!(!query.keys().any(|name| name.starts_with("filter.")));
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn auth_account_logout_posts_canonical_path_with_dpop() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        use crate::{Auth, DpopAuth};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let capture = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = socket.read(&mut buf).await.unwrap();
            let raw = buf[..n].to_vec();
            let body = r#"{"ok":true,"revoked":true}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.shutdown().await.ok();
            raw
        });

        let expected_htu = format!("http://{addr}/_arkret/gate/account/logout");
        let client = Client::builder(Url::parse(&format!("http://{addr}/")).unwrap())
            .allow_insecure_localhost()
            .auth(Auth::Dpop(DpopAuth::with_dpop_token(
                "grant.jwt",
                move |request| {
                    assert_eq!(request.method, "POST");
                    assert_eq!(request.htu, expected_htu);
                    assert_eq!(request.access_token.as_deref(), Some("grant.jwt"));
                    Ok("proof.jwt".to_owned())
                },
            )))
            .build()
            .unwrap();

        let outcome = client.auth_account_logout().await.unwrap();
        assert!(outcome.revoked);

        let raw = capture.await.unwrap();
        let (request_line, headers, body) = split_request(&raw);
        assert!(
            request_line.starts_with("POST /_arkret/gate/account/logout "),
            "unexpected request line: {request_line}"
        );
        assert!(
            headers
                .lines()
                .any(|line| line.eq_ignore_ascii_case("authorization: DPoP grant.jwt")),
            "missing Authorization header: {headers}"
        );
        assert!(
            headers
                .lines()
                .any(|line| line.eq_ignore_ascii_case("dpop: proof.jwt")),
            "missing DPoP header: {headers}"
        );
        assert_eq!(body, b"{}");
    }

    #[test]
    fn account_subscribe_request_rejects_unregistered_subscriptions() {
        for value in [
            serde_json::json!({"subscriptions": {}}),
            serde_json::json!({"subscriptions": null}),
        ] {
            assert!(serde_json::from_value::<SyncRequestBody>(value).is_err());
        }
    }

    #[test]
    fn account_subscribe_request_options_attach_wait_for_header() {
        let options = ClientRequestOptions::new().wait_for("ak:cursor:01904100");
        let built = client()
            .account_subscribe_request(&empty_request(), "application/x-ndjson")
            .and_then(|request| client().apply_request_options(request, &options))
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(
            built
                .headers()
                .get(crate::HEADER_WAIT_FOR)
                .and_then(|value| value.to_str().ok()),
            Some("ak:cursor:01904100")
        );
    }

    #[test]
    fn account_subscribe_filter_extensions_are_closed_at_parse() {
        assert!(
            serde_json::from_value::<SyncFilter>(serde_json::json!({"custom":{"nested":true}}))
                .is_err()
        );
        assert!(serde_json::from_value::<SyncFilter>(serde_json::json!({"realms":[]})).is_err());
    }
}
