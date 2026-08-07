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
    DevicePairingResolveRequestBody, DevicePairingStageOutcome, DevicePairingStageRequestBody,
    DevicePairingStatusOutcome, DevicePairingStatusRequestBody,
};
use arkret_models_collaboration::session_grant_bodies::{
    SessionGrantOutcome, SessionGrantRefreshOutcome, SessionGrantRefreshRequestBody,
    SessionGrantRequestBody, SessionGrantRequestProof,
};
use arkret_models_collaboration::sync_frames::account_subscribe::{
    AccountSubscribeBatch, AccountSubscribeFrame, AccountSubscribeFrameKind,
    AccountSubscribeSnapshotResult,
};
use arkret_models_collaboration::sync_frames::client_sync::SyncRequestBody;
use arkret_models_collaboration::sync_frames::stream_trace::StreamTraceValidator;
use arkret_models_discovery::ServiceDescribe;
use arkret_models_identity::{
    AccountCursorRevokeOutcome, AccountCursorRevokeRequestBody, AccountDeviceEnrollOutcome,
    AccountDeviceEnrollRequestBody, AccountHandoffOutcome, AccountHandoffRequestBody,
    AccountLogoutOutcome, AccountLogoutRequestBody, AccountUpdateProfileOutcome,
    IdentityBindingChallengeOutcome, IdentityBindingChallengeRequestBody, SessionGrantProofKind,
};
use arkret_wire::{
    DeviceId, Did, Hash, PATH_SELF_CONTACTS, PATH_SELF_CONTACTS_REQUEST,
    PATH_SELF_CONTACTS_RESPOND, PATH_SELF_CONTACTS_TOMBSTONE,
    PATH_SELF_DIRECT_CONVERSATIONS_RESOLVE, PayloadSigner,
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
    principal_id: Did,
    device_id: DeviceId,
    signer: &S,
    challenge: &str,
    audience: Did,
) -> Result<SessionGrantOutcome>
where
    S: PayloadSigner + ?Sized,
{
    if challenge.len() < 16 {
        return Err(Error::Protocol(
            "session grant challenge must be at least 16 characters".to_owned(),
        ));
    }

    let issued_at = Utc::now();
    let expires_at = issued_at + Duration::seconds(DID_PROOF_FRESHNESS_WINDOW_SECS);
    let request_binding = serde_json::json!({
        "principal_id": principal_id.as_str(),
        "device_id": device_id.as_str(),
    });
    let request_canonical_digest = Hash::new(arkret_canonical::canonical::sha256_digest(
        &arkret_canonical::canonical::canonical_json_bytes(&request_binding)?,
    ))?;
    let signing_payload = serde_json::json!({
        "kind": "ak.did.proof",
        "purpose": "ak.session.grant",
        "did": principal_id.as_str(),
        "device_id": device_id.as_str(),
        "audience": audience.as_str(),
        "challenge": challenge,
        "request_canonical_digest": request_canonical_digest.as_str(),
        "issued_at": arkret_canonical::canonical::format_timestamp_canonical(issued_at),
        "expires_at": arkret_canonical::canonical::format_timestamp_canonical(expires_at),
    });
    let payload_bytes = arkret_canonical::canonical::canonical_json_bytes(&signing_payload)?;
    let move_sig = signer.sign_payload(&payload_bytes)?;

    client
        .auth_issue_session_grant(&SessionGrantRequestBody {
            principal_id,
            device_id: Some(device_id),
            requested_scope: Vec::new(),
            agent_key_authorization_ref: None,
            agent_scope_request: None,
            dpop_binding_proof: None,
            applet_authority: None,
            proof: SessionGrantRequestProof {
                proof_kind: SessionGrantProofKind::DidBoundSignature,
                challenge: challenge.to_owned(),
                request_canonical_digest,
                audience,
                expires_at: Some(expires_at),
                signature: move_sig.jws,
                verification_method: None,
                issuer: None,
                client_id: None,
                redirect_uri: None,
                state: None,
                nonce: None,
                authorization_code: None,
                code_verifier: None,
            },
        })
        .await
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
        self.post("/_arkret/gate/account/session-grants", req).await
    }

    /// `POST /_arkret/gate/account/session-grants/refresh`
    /// (`ak.gate.account.command.refresh_session_grant`): rotate a
    /// DPoP-bound session grant without changing the grant audience.
    pub async fn auth_refresh_session_grant(
        &self,
        req: &SessionGrantRefreshRequestBody,
    ) -> Result<SessionGrantRefreshOutcome> {
        self.post("/_arkret/gate/account/session-grants/refresh", req)
            .await
    }

    /// `POST /_arkret/gate/account/device-enroll`
    /// (`ak.gate.account.command.enroll_device`): ask the Account Authority
    /// to mint a signed `service_attested` `ak.device.authorize` event for the
    /// current DPoP-bound session device.
    pub async fn auth_device_enroll(
        &self,
        req: &AccountDeviceEnrollRequestBody,
    ) -> Result<AccountDeviceEnrollOutcome> {
        self.post("/_arkret/gate/account/device-enroll", req).await
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
        self.post("/_arkret/gate/account/register", request).await
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
