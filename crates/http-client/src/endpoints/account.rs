//! Session-grant, account-subscribe, contacts, and direct-conversation
//! endpoint methods on [`Client`].

use arkret_models_collaboration::account_lifecycle::{
    AccountRegisterOutcome, AccountRegisterRequestBody, AccountUpdateProfileRequestBody,
    AccountView, SessionRevokeOutcome, SessionRevokeRequestBody,
};
use arkret_models_collaboration::contact_operations::{
    ContactAcceptRequestBody, ContactOperationOutcome, ContactOperationRequestBody,
    ContactTombstoneRequestBody,
};
use arkret_models_collaboration::direct_conversation_ops::{
    DirectConversationResolveOutcome, DirectConversationResolveRequestBody,
    PrincipalServiceBindingCommitOutcome, PrincipalServiceBindingCommitRequestBody,
    PrincipalServiceBindingPrepareOutcome, PrincipalServiceBindingPrepareRequestBody,
};
use arkret_models_collaboration::direct_conversation_repair::{
    DirectConversationRepairDispatchRequest, DirectConversationRepairEnqueueOutcome,
};
use arkret_models_collaboration::http_bodies::{
    AccountDevicePairOutcome, AccountDevicePairRequestBody, ContactList, DevicePairingBootstrap,
    DevicePairingResolveRequestBody, DevicePairingStageOutcome, DevicePairingStageRequestBody,
    DevicePairingStatusOutcome, DevicePairingStatusRequestBody,
};
use arkret_models_collaboration::session_grant_bodies::{
    SessionGrantIntrospectOutcome, SessionGrantIntrospectRequestBody, SessionGrantOutcome,
    SessionGrantRefreshOutcome, SessionGrantRefreshRequestBody, SessionGrantRequestBody,
    UnsignedSessionGrantRequestBody, UnsignedSessionGrantRequestProof,
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
    AccountUpdateProfileOutcome, IdentityAbandonmentChallengeOutcome,
    IdentityAbandonmentChallengeRequestBody, IdentityAbandonmentOutcome,
    IdentityAbandonmentRequestBody, IdentityBindingChallengeOutcome,
    IdentityBindingChallengeRequestBody, SessionGrantProofKind,
};
use arkret_wire::{
    DeviceId, DidCoreId, NonEmptyString, PATH_SELF_CONTACTS, PATH_SELF_CONTACTS_REQUEST,
    PATH_SELF_CONTACTS_RESPOND, PATH_SELF_CONTACTS_TOMBSTONE,
    PATH_SELF_DIRECT_CONVERSATIONS_REPAIR_DISPATCH, PATH_SELF_DIRECT_CONVERSATIONS_RESOLVE,
    PATH_SELF_PRINCIPAL_SERVICE_BINDINGS_COMMIT, PATH_SELF_PRINCIPAL_SERVICE_BINDINGS_PREPARE,
    PayloadSigner,
};
use chrono::{Duration, Utc};
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

const DID_PROOF_FRESHNESS_WINDOW_SECS: i64 = 300;

/// Build and submit the canonical `ak.did.proof` session-grant request.
///
/// Challenge acquisition is deployment-local. The request binds the
/// principal, device, audience, challenge, timestamps and canonical request
/// digest before signing, then submits the only registered session-grant
/// issuance operation.
pub async fn login_did_proof<S>(
    client: &Client,
    principal_id: DidCoreId,
    device_id: DeviceId,
    signer: &S,
    challenge: &str,
    audience: DidCoreId,
) -> Result<SessionGrantOutcome>
where
    S: PayloadSigner + ?Sized,
{
    if challenge.len() < 16 {
        return Err(Error::Protocol(
            "session grant challenge must be at least 16 characters".to_owned(),
        ));
    }

    let expires_at = Utc::now() + Duration::seconds(DID_PROOF_FRESHNESS_WINDOW_SECS);
    let request = UnsignedSessionGrantRequestBody::new(
        principal_id,
        Some(device_id),
        Vec::new(),
        None,
        None,
        None,
        None,
        None,
        UnsignedSessionGrantRequestProof {
            proof_kind: SessionGrantProofKind::DidBoundSignature,
            challenge: challenge.to_owned(),
            audience,
            expires_at: Some(expires_at),
            verification_method: None,
            issuer: None,
            client_id: None,
            redirect_uri: None,
            state: None,
            nonce: None,
            authorization_code: None,
            code_verifier: None,
        },
    )?;

    // Prepare the complete intent once, derive the body-bound request identity,
    // then finalize its detached proof exactly once. Transport retry below
    // reuses the resulting canonical body bytes verbatim.
    let signing_bytes = request.canonical_signing_bytes()?;
    let signature = NonEmptyString::new(signer.sign_payload(&signing_bytes)?.jws)
        .map_err(|reason| Error::Protocol(reason.to_owned()))?;
    let request = request.attach_signature(signature)?;

    client.auth_issue_session_grant(&request).await
}

/// Validated account-subscribe frame stream bound to its request context.
pub struct AccountSubscribeFrameStream {
    inner: BoxAccountSubscribeFrameStream,
    trace: StreamTraceValidator,
    failed: bool,
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
        self.trace.push(&frame)?;
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
    /// (`ak.gate.account.exchange.create_handoff`): exchange an OIDC
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

    /// `POST /_arkret/gate/account/identity-binding-challenges`
    /// (`ak.gate.account.command.issue_identity_binding_challenge`). The
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
    /// (`ak.gate.account.command.issue_session_grant`): exchange a body-borne
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
    /// (`ak.gate.account.command.refresh_session_grant`): rotate a
    /// DPoP-bound session grant without changing the grant audience.
    pub async fn auth_refresh_session_grant(
        &self,
        req: &SessionGrantRefreshRequestBody,
    ) -> Result<SessionGrantRefreshOutcome> {
        self.post_protocol_replay_safe("/_arkret/gate/account/session-grants/refresh", req)
            .await
    }

    /// Durable exact-replay session-grant revocation. Retries reuse the same
    /// canonical request body and proof; no `Idempotency-Key` header is added.
    pub async fn auth_revoke_session_grant(
        &self,
        req: &SessionRevokeRequestBody,
    ) -> Result<SessionRevokeOutcome> {
        self.post_protocol_replay_safe("/_arkret/gate/account/session-grants/revoke", req)
            .await
    }

    /// Read-only issuer-ledger introspection. Exactly one of grant id or JWT is
    /// encoded by `SessionGrantIntrospectRequestBody`.
    pub async fn auth_introspect_session_grant(
        &self,
        req: &SessionGrantIntrospectRequestBody,
    ) -> Result<SessionGrantIntrospectOutcome> {
        self.post("/_arkret/gate/account/session-grants/introspect", req)
            .await
    }

    /// `POST /_arkret/gate/account/logout`
    /// (`ak.gate.account.command.logout`): terminate the current
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

    /// Issue the durable, single-use challenge that makes giving up a
    /// never-accepted provisional identity explicit. Authentication is the
    /// current account handoff grant, not a principal-bound session grant.
    pub async fn auth_issue_identity_abandonment_challenge(
        &self,
        request: &IdentityAbandonmentChallengeRequestBody,
    ) -> Result<IdentityAbandonmentChallengeOutcome> {
        request.validate()?;
        let outcome: IdentityAbandonmentChallengeOutcome = self
            .post(
                "/_arkret/gate/account/identity-abandonment-challenges",
                request,
            )
            .await?;
        outcome.validate()?;
        Ok(outcome)
    }

    /// Consume a previously issued abandonment challenge with a fresh account
    /// handoff grant. Exact request-id replay returns the recorded terminal.
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
    ) -> Result<AccountUpdateProfileOutcome> {
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
    /// (`ak.open.device_pairing.command.stage`). Unauthenticated: the
    /// not-yet-authorized device stages its device key and gets back a short
    /// `device_pairing_request_id` + `pairing_code` to encode into its QR.
    pub async fn device_pairing_stage(
        &self,
        request: &DevicePairingStageRequestBody,
    ) -> Result<DevicePairingStageOutcome> {
        self.post("/_arkret/open/device-pairing/requests", request)
            .await
    }

    /// `POST /_arkret/open/device-pairing/resolve`
    /// (`ak.open.device_pairing.read.resolve`). Unauthenticated, body-only: an
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
    /// (`ak.open.device_pairing.read.status`). Unauthenticated, body-only: the
    /// new device polls whether a sibling has authorized its staged request.
    pub async fn device_pairing_status(
        &self,
        request: &DevicePairingStatusRequestBody,
    ) -> Result<DevicePairingStatusOutcome> {
        self.post("/_arkret/open/device-pairing/requests/status", request)
            .await
    }

    fn account_subscribe_request(
        &self,
        request: &SyncRequestBody,
        accept: &str,
    ) -> Result<RequestBuilder> {
        // `ak.self.account.stream.subscribe` has no request body; its query
        // surface is `after` / `catchup` / `filter.*` (client-sync.md §2
        // request-parameter table). `subscriptions` and `wait_for` are not
        // part of this transport — fail loudly instead of silently dropping
        // fields the caller expects the server to honor.
        if request.subscriptions.is_some() {
            return Err(Error::Protocol(
                "account subscribe does not support `subscriptions`; use per-Realm \
                 events subscriptions instead"
                    .to_owned(),
            ));
        }
        let mut builder = self
            .request_unbounded(Method::GET, "/_arkret/self/account/subscribe")?
            .header("accept", accept);
        if let Some(after) = request.after.as_deref() {
            builder = builder.query(&[("after", after)]);
        }
        if let Some(catchup) = request.catchup {
            builder = builder.query(&[("catchup", catchup)]);
        }
        if let Some(filter) = &request.filter {
            // deepObject encoding with the dotted parameter names from the
            // client-sync.md §2 table (`filter.realms`, `filter.timeline_limit`, …).
            if !filter.extra.is_empty() {
                return Err(Error::Protocol(
                    "account subscribe filter extensions are not representable as query \
                     parameters"
                        .to_owned(),
                ));
            }
            for realm_id in &filter.realms {
                builder = builder.query(&[("filter.realms", realm_id.as_str())]);
            }
            if let Some(timeline_limit) = filter.timeline_limit {
                builder = builder.query(&[("filter.timeline_limit", timeline_limit)]);
            }
            if filter.lazy_load_members {
                builder = builder.query(&[("filter.lazy_load_members", true)]);
            }
            if filter.include_redundant_members {
                builder = builder.query(&[("filter.include_redundant_members", true)]);
            }
            for event_type in &filter.event_types {
                builder = builder.query(&[("filter.event_types", event_type.as_str())]);
            }
            for event_type in &filter.not_event_types {
                builder = builder.query(&[("filter.not_event_types", event_type.as_str())]);
            }
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
                let mut frames = Vec::new();
                for line in crate::subscribe_body::bounded_response_lines(response).await? {
                    if let Some(frame) = AccountSubscribeFrame::from_ndjson_line(&line)? {
                        frames.push(Ok(frame));
                    }
                }
                Box::pin(futures_util::stream::iter(frames))
            };
        Ok(AccountSubscribeFrameStream {
            inner,
            trace: StreamTraceValidator::new(
                request.catchup.unwrap_or(false),
                request.after.clone(),
            ),
            failed: false,
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

    pub async fn contacts_tombstone(
        &self,
        request: &ContactTombstoneRequestBody,
    ) -> Result<ContactOperationOutcome> {
        self.post(PATH_SELF_CONTACTS_TOMBSTONE, request).await
    }

    /// Query-only resolver for the pair's single stable Direct Conversation.
    ///
    /// This never creates. A Direct Conversation Realm is created only by the founder derived from
    /// the pair's root Contact basis, through the `direct_conversation_genesis` admission variant
    /// of `ak.realm.create`. `AwaitingFounder` never becomes create authority no matter how
    /// long the caller waits: base v1 has no timeout fallback or takeover.
    pub async fn direct_conversation_resolve(
        &self,
        request: &DirectConversationResolveRequestBody,
    ) -> Result<DirectConversationResolveOutcome> {
        self.post(PATH_SELF_DIRECT_CONVERSATIONS_RESOLVE, request)
            .await
    }

    /// Persist one exact requester-authorized repair relay outbox and wait for
    /// the destination's atomic closed-target durable-enqueue outcome.
    pub async fn direct_conversation_repair_dispatch(
        &self,
        request: &DirectConversationRepairDispatchRequest,
    ) -> Result<DirectConversationRepairEnqueueOutcome> {
        request.validate_shape()?;
        let outcome: DirectConversationRepairEnqueueOutcome = self
            .post_protocol_replay_safe(PATH_SELF_DIRECT_CONVERSATIONS_REPAIR_DISPATCH, request)
            .await?;
        outcome.validate_shape()?;
        if outcome.request_id != request.request_id {
            return Err(Error::Protocol(
                "repair dispatch outcome request_id mismatch".to_owned(),
            ));
        }
        Ok(outcome)
    }

    /// Ask the current Principal Server to freeze a DID-authority-backed
    /// service-binding core and a single-use challenge.
    pub async fn principal_service_binding_prepare(
        &self,
        request: &PrincipalServiceBindingPrepareRequestBody,
    ) -> Result<PrincipalServiceBindingPrepareOutcome> {
        self.post(PATH_SELF_PRINCIPAL_SERVICE_BINDINGS_PREPARE, request)
            .await
    }

    /// Commit the exact frozen binding after the principal signs its closed
    /// authorization transcript.
    pub async fn principal_service_binding_commit(
        &self,
        request: &PrincipalServiceBindingCommitRequestBody,
    ) -> Result<PrincipalServiceBindingCommitOutcome> {
        self.post(PATH_SELF_PRINCIPAL_SERVICE_BINDINGS_COMMIT, request)
            .await
    }
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::sync_frames::client_sync::{SubscriptionConfig, SyncFilter};
    use arkret_wire::RealmId;
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
            subscriptions: None,
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

    #[cfg(not(target_arch = "wasm32"))]
    fn session_grant_request() -> SessionGrantRequestBody {
        serde_json::from_value(serde_json::json!({
            "principal_id": "ak:did_core:web:alice.example",
            "device_id": "ak:device:01964137-0000-7000-8000-000000000041",
            "proof": {
                "proof_kind": "did_bound_signature",
                "challenge": "0123456789abcdef",
                "request_canonical_digest": format!("sha256:{}", "00".repeat(32)),
                "audience": "ak:did_core:web:service.example",
                "expires_at": "2026-08-08T12:04:00.000Z",
                "signature": "detached.jws"
            }
        }))
        .unwrap()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn session_grant_outcome_json() -> String {
        serde_json::json!({
            "principal_id": "ak:did_core:web:alice.example",
            "session_grant": "signed.jwt",
            "expires_at": "2026-08-08T12:04:00.000Z",
            "grant_id": "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW",
            "session_public_key": r#"{"crv":"Ed25519","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
            "audience": "ak:did_core:web:service.example"
        })
        .to_string()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn session_grant_refresh_request() -> SessionGrantRefreshRequestBody {
        serde_json::from_value(serde_json::json!({
            "grant_jwt": "predecessor.jwt",
            "device_id": "ak:device:01964137-0000-7000-8000-000000000041",
            "proof": {
                "proof_kind": "did_bound_signature",
                "challenge": "0123456789abcdef",
                "request_canonical_digest": format!("sha256:{}", "11".repeat(32)),
                "audience": "ak:did_core:web:service.example",
                "issued_at": "2026-08-08T11:59:00.000Z",
                "expires_at": "2026-08-08T12:04:00.000Z",
                "signature": "refresh.detached.jws"
            }
        }))
        .unwrap()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn session_grant_refresh_outcome_json() -> String {
        serde_json::json!({
            "grant_id": "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW",
            "grant_jwt": "successor.jwt",
            "session_public_key": r#"{"crv":"Ed25519","kty":"OKP","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
            "expires_at": "2026-08-08T12:04:00.000Z",
            "audience": "ak:did_core:web:service.example",
            "scopes": [],
            "dpop_jkt": "holder-thumbprint",
            "previous_grant_id": "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW"
        })
        .to_string()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn session_revoke_request() -> SessionRevokeRequestBody {
        serde_json::from_value(serde_json::json!({
            "target_grant_id": "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW"
        }))
        .unwrap()
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn session_revoke_outcome_json() -> String {
        serde_json::json!({
            "revoked_count": 1,
            "revoked_grant_ids": [
                "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW"
            ]
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
                        "ok": false,
                        "error": {"code": "frontier_unavailable", "message": "retry"},
                        "request_id": "attempt-1"
                    })
                    .to_string();
                    let response = format!(
                        "HTTP/1.1 503 Service Unavailable\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
                crate::RetryConfig::standard(1)
                    .with_base_delay(StdDuration::from_millis(1))
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
            // Model a durable commit followed by a lost/late response.
            tokio::time::sleep(StdDuration::from_millis(80)).await;
            drop(first);

            let (mut second, _) = listener.accept().await.unwrap();
            let second_raw = read_http_request(&mut second).await;
            let body = session_grant_outcome_json();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            second.write_all(response.as_bytes()).await.unwrap();
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
                crate::RetryConfig::standard(1)
                    .with_base_delay(StdDuration::from_millis(1))
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
    async fn session_grant_revoke_timeout_reuses_exact_body_without_idempotency_key() {
        let (addr, server) =
            start_exact_replay_server(ReplayTrigger::Timeout, session_revoke_outcome_json()).await;
        exact_replay_client(addr, 40)
            .auth_revoke_session_grant(&session_revoke_request())
            .await
            .unwrap();
        let (first, second) = server.await.unwrap();
        assert_exact_replay_capture(
            &first,
            &second,
            "/_arkret/gate/account/session-grants/revoke",
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[tokio::test]
    async fn all_session_grant_mutations_replay_exact_body_after_5xx() {
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

        let (addr, server) = start_exact_replay_server(
            ReplayTrigger::ServiceUnavailable,
            session_revoke_outcome_json(),
        )
        .await;
        exact_replay_client(addr, 1_000)
            .auth_revoke_session_grant(&session_revoke_request())
            .await
            .unwrap();
        let (first, second) = server.await.unwrap();
        assert_exact_replay_capture(
            &first,
            &second,
            "/_arkret/gate/account/session-grants/revoke",
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
                "ok": false,
                "error": {
                    "code": "session_grant_replay_terminal",
                    "message": "recorded grant is superseded",
                    "details": {
                        "grant_id": "ak:session_grant:Af0GheZX08ev4L1fQoFdngIpe5c_9Lk7SQqfN4jztzDW",
                        "state": "superseded"
                    }
                },
                "request_id": "request-1"
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 409 Conflict\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
                crate::RetryConfig::standard(1)
                    .with_base_delay(StdDuration::from_millis(1))
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
    fn account_subscribe_request_serializes_filter_deep_object() {
        let filter = SyncFilter {
            realms: vec![
                RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap(),
            ],
            timeline_limit: Some(20),
            lazy_load_members: true,
            include_redundant_members: false,
            event_types: vec!["ak.message.create".to_owned()],
            not_event_types: vec!["ak.reaction.add".to_owned()],
            extra: Default::default(),
        };
        let request = SyncRequestBody {
            after: Some("cur1".to_owned()),
            catchup: Some(true),
            filter: Some(filter),
            ..empty_request()
        };

        let built = client()
            .account_subscribe_request(&request, "application/x-ndjson")
            .unwrap()
            .build()
            .unwrap();
        let query = built.url().query().unwrap().to_owned();

        assert!(query.contains("after=cur1"), "query: {query}");
        assert!(query.contains("catchup=true"), "query: {query}");
        assert!(
            query.contains(
                "filter.realms=ak%3Arealm%3AAdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19"
            ),
            "query: {query}"
        );
        assert!(query.contains("filter.timeline_limit=20"), "query: {query}");
        assert!(
            query.contains("filter.lazy_load_members=true"),
            "query: {query}"
        );
        // Default-false booleans are omitted rather than sent as `false`.
        assert!(
            !query.contains("include_redundant_members"),
            "query: {query}"
        );
        assert!(
            query.contains("filter.event_types=ak.message.create"),
            "query: {query}"
        );
        assert!(
            query.contains("filter.not_event_types=ak.reaction.add"),
            "query: {query}"
        );
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
            .auth(Auth::Dpop(DpopAuth::with_access_token(
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
        assert!(outcome.ok);
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
                .any(|line| line.eq_ignore_ascii_case("authorization: Bearer grant.jwt")),
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
    fn account_subscribe_request_rejects_transport_unsupported_fields() {
        let with_subscriptions = SyncRequestBody {
            subscriptions: Some(SubscriptionConfig {
                subscriptions: Vec::new(),
                batch_item_count: None,
                timeline_filter: None,
            }),
            ..empty_request()
        };
        let error = client()
            .account_subscribe_request(&with_subscriptions, "application/x-ndjson")
            .unwrap_err();
        assert!(matches!(error, Error::Protocol(message) if message.contains("subscriptions")));
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
    fn account_subscribe_request_rejects_unrepresentable_filter_extension() {
        let mut filter = SyncFilter {
            realms: Vec::new(),
            timeline_limit: None,
            lazy_load_members: false,
            include_redundant_members: false,
            event_types: Vec::new(),
            not_event_types: Vec::new(),
            extra: Default::default(),
        };
        filter
            .extra
            .insert("custom".to_owned(), serde_json::json!({"nested": true}));
        let request = SyncRequestBody {
            filter: Some(filter),
            ..empty_request()
        };
        let error = client()
            .account_subscribe_request(&request, "application/x-ndjson")
            .unwrap_err();
        assert!(matches!(error, Error::Protocol(message) if message.contains("filter extensions")));
    }
}
