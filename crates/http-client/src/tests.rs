//! Integration-style unit tests for the crate root, kept in a sibling
//! module per repository convention (`#[cfg(test)] mod tests;`).

use arkret_wire::{AccountId, ActorId, SchemaId};
use reqwest::Method;
use reqwest::header::{HeaderValue, USER_AGENT};

use super::*;
use crate::Error;

#[test]
fn auth_debug_redacts_all_credentials() {
    for (auth, secret) in [
        (Auth::Bearer("bearer-secret".to_owned()), "bearer-secret"),
        (
            Auth::DeviceProof("device-secret".to_owned()),
            "device-secret",
        ),
        (
            Auth::ServiceSignature("service-secret".to_owned()),
            "service-secret",
        ),
    ] {
        let debug = format!("{auth:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(secret));
    }
}

#[test]
fn builds_relative_api_url() {
    let client = Client::new(Url::parse("https://alice.example/arkret/").unwrap()).unwrap();
    let request = client
        .request(Method::GET, "/_arkret/describe")
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(
        request.url().as_str(),
        "https://alice.example/arkret/_arkret/describe"
    );
    assert_eq!(
        request.headers()[HEADER_OPERATION],
        "ak.server.read.describe.v1"
    );
}

#[test]
fn rejects_remote_http_by_default() {
    let error = Client::new(Url::parse("http://alice.example/arkret/").unwrap()).unwrap_err();
    assert!(matches!(error, Error::InsecureUrl(_)));
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn allows_insecure_localhost_when_explicit() {
    let client = Client::builder(Url::parse("http://127.0.0.1:8080/").unwrap())
        .allow_insecure_localhost()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    assert_eq!(client.base_url().scheme(), "http");
}

#[test]
fn rejects_absolute_request_paths() {
    let client = Client::new(Url::parse("https://alice.example/arkret/").unwrap()).unwrap();
    let error = client
        .request(Method::GET, "https://evil.example/api")
        .unwrap_err();
    assert!(matches!(error, Error::Protocol(_)));
}

#[test]
fn rejects_header_unsafe_auth_material() {
    let error = Client::builder(Url::parse("https://alice.example/arkret/").unwrap())
        .auth(Auth::Bearer("token\r\nX-Evil: true".to_owned()))
        .build()
        .unwrap_err();
    assert!(matches!(error, Error::Protocol(_)));
}

#[test]
fn dpop_auth_adds_dpop_token_and_per_request_proof() {
    let client = Client::builder(Url::parse("https://alice.example/arkret/").unwrap())
        .auth(Auth::Dpop(DpopAuth::with_dpop_token("grant.jwt", |req| {
            assert_eq!(req.method, "POST");
            assert_eq!(req.htu, "https://alice.example/arkret/_arkret/self/events");
            assert_eq!(req.access_token.as_deref(), Some("grant.jwt"));
            Ok("proof.jwt".to_owned())
        })))
        .build()
        .unwrap();
    let request = client
        .request(Method::POST, "/_arkret/self/events?cursor=ignored")
        .unwrap()
        .build()
        .unwrap();

    assert_eq!(request.headers()["authorization"], "DPoP grant.jwt");
    assert_eq!(request.headers()["dpop"], "proof.jwt");
}

#[test]
fn account_handoff_auth_uses_the_same_dpop_authorization_scheme() {
    let client = Client::builder(Url::parse("https://alice.example/arkret/").unwrap())
        .auth(Auth::Dpop(DpopAuth::with_dpop_token(
            "handoff-secret",
            |req| {
                assert_eq!(req.method, "POST");
                assert_eq!(
                    req.htu,
                    "https://alice.example/arkret/_arkret/gate/account/register"
                );
                assert_eq!(req.access_token.as_deref(), Some("handoff-secret"));
                Ok("handoff-proof.jwt".to_owned())
            },
        )))
        .build()
        .unwrap();
    let request = client
        .request(Method::POST, "/_arkret/gate/account/register")
        .unwrap()
        .build()
        .unwrap();

    assert_eq!(request.headers()["authorization"], "DPoP handoff-secret");
    assert_eq!(request.headers()["dpop"], "handoff-proof.jwt");
}

#[test]
fn dpop_auth_supports_proof_only_kickoff() {
    let client = Client::builder(Url::parse("https://alice.example/arkret/").unwrap())
        .auth(Auth::Dpop(DpopAuth::proof_only(|req| {
            assert_eq!(req.method, "POST");
            assert_eq!(req.access_token, None);
            Ok("kickoff.proof.jwt".to_owned())
        })))
        .build()
        .unwrap();
    let request = client
        .request(Method::POST, "/_arkret/gate/account/session-grants")
        .unwrap()
        .build()
        .unwrap();

    assert!(!request.headers().contains_key("authorization"));
    assert_eq!(request.headers()["dpop"], "kickoff.proof.jwt");
}

#[test]
fn rejects_encoded_path_separator_segments() {
    let error = reject_path_segment("txn_%2Fescape").unwrap_err();
    assert!(matches!(error, Error::Protocol(_)));
}

#[test]
fn request_options_add_standard_headers() {
    let client = Client::builder(Url::parse("https://alice.example/arkret/").unwrap())
        .user_agent("arkret-sdk-test/1")
        .build()
        .unwrap();
    let options = ClientRequestOptions::new()
        .request_id("req-1")
        .idempotency_key("idem-1")
        .wait_for("ak:cursor:01");
    let request = client
        .apply_request_options(
            client
                .request(Method::POST, "/_arkret/self/events")
                .unwrap(),
            &options,
        )
        .unwrap()
        .build()
        .unwrap();

    assert_eq!(request.headers()[USER_AGENT], "arkret-sdk-test/1");
    assert_eq!(request.headers()[HEADER_REQUEST_ID], "req-1");
    assert_eq!(request.headers()[HEADER_IDEMPOTENCY_KEY], "idem-1");
    assert_eq!(request.headers()[HEADER_WAIT_FOR], "ak:cursor:01");
    assert_eq!(
        request.headers()[HEADER_OPERATION],
        "ak.self.events.command.submit.v1"
    );
}

#[test]
fn request_options_reject_header_injection() {
    let client = Client::new(Url::parse("https://alice.example/arkret/").unwrap()).unwrap();
    let options = ClientRequestOptions::new().request_id("req\r\nX-Evil: true");

    let error = client
        .apply_request_options(
            client.request(Method::GET, "/_arkret/describe").unwrap(),
            &options,
        )
        .unwrap_err();
    assert!(matches!(error, Error::Protocol(_)));
}

#[test]
fn rejects_query_auth_on_base_path_and_built_request() {
    assert!(
        Client::new(Url::parse("https://alice.example/arkret/?access_token=secret").unwrap())
            .is_err()
    );

    let client = Client::new(Url::parse("https://alice.example/arkret/").unwrap()).unwrap();
    let builder = client
        .request(Method::GET, "/_arkret/self/account/describe")
        .unwrap()
        .query(&[("access_token", "secret")]);

    let error = validate_request_builder(&builder).unwrap_err();
    assert!(matches!(error, Error::Protocol(_)));
}

#[test]
fn retry_after_seconds_are_reported_as_millis() {
    let mut headers = HeaderMap::new();
    headers.insert(RETRY_AFTER, HeaderValue::from_static("3"));

    assert_eq!(retry_after_ms(&headers), Some(3000));
}

#[test]
fn standard_retry_config_covers_transient_statuses() {
    let retry = RetryConfig::standard(2);

    assert!(retry.should_retry_status(StatusCode::TOO_MANY_REQUESTS));
    assert!(retry.should_retry_status(StatusCode::SERVICE_UNAVAILABLE));
    assert!(!retry.should_retry_status(StatusCode::BAD_REQUEST));
}

#[test]
fn retry_config_uses_bounded_exponential_backoff() {
    let retry = RetryConfig::standard(4).with_jitter(false);

    assert_eq!(retry.retry_delay(1), Duration::from_millis(1000));
    assert_eq!(retry.retry_delay(2), Duration::from_millis(2000));
    assert_eq!(retry.retry_delay(3), Duration::from_millis(4000));
}

#[test]
fn retry_config_defaults_match_spec_backoff_policy() {
    // api-conventions.md §9: base ≥ 1000 ms, factor 2, cap ≥ 60 000 ms,
    // jitter on, at most 5 retries.
    let retry = RetryConfig::standard(10);

    assert_eq!(retry.max_retries, 5);
    assert_eq!(retry.base_delay, Duration::from_millis(1000));
    assert_eq!(retry.max_delay, Duration::from_secs(60));
    assert!(retry.jitter);
}

#[test]
fn retry_delay_jitter_stays_within_twenty_percent() {
    let retry = RetryConfig::standard(3);
    for attempt in 1..=3 {
        let base = Duration::from_millis(1000 * (1 << (attempt - 1)));
        let delay = retry.retry_delay(attempt);
        assert!(delay >= base, "attempt {attempt}: {delay:?} < {base:?}");
        assert!(
            delay <= base.mul_f64(1.2),
            "attempt {attempt}: {delay:?} > {:?}",
            base.mul_f64(1.2)
        );
    }
}

#[test]
fn retry_after_overrides_max_delay_cap() {
    // api-conventions.md §9: a server Retry-After is authoritative and
    // MUST NOT be truncated by the client's own max_delay.
    let mut headers = HeaderMap::new();
    headers.insert(RETRY_AFTER, HeaderValue::from_static("3"));
    let retry = RetryConfig::standard(2).with_jitter(false);

    assert_eq!(
        retry.retry_delay_from_headers(&headers, 1),
        Duration::from_secs(3)
    );
}

#[test]
fn retry_after_is_combined_with_local_backoff_as_a_lower_bound() {
    let retry = RetryConfig::standard(5).with_jitter(false);
    for (attempt, hint, expected) in [
        (1, "0", Duration::from_secs(1)),
        (4, "1", Duration::from_secs(8)),
        (4, "30", Duration::from_secs(30)),
    ] {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static(hint));
        assert_eq!(retry.retry_delay_from_headers(&headers, attempt), expected);
    }
}

#[test]
fn retry_after_http_date_form_is_parsed_as_relative_delay() {
    // Future IMF-fixdate → positive delay near the actual delta.
    let target = chrono::Utc::now() + chrono::Duration::seconds(30);
    let mut headers = HeaderMap::new();
    headers.insert(
        RETRY_AFTER,
        HeaderValue::from_str(&target.to_rfc2822().replace("+0000", "GMT")).unwrap(),
    );
    let ms = retry_after_ms(&headers).expect("HTTP-date Retry-After must parse");
    assert!((20_000..=31_000).contains(&ms), "unexpected delay: {ms}");

    // Past HTTP-date → clamped to zero, not an error / fallback.
    let past = chrono::Utc::now() - chrono::Duration::seconds(30);
    let mut headers = HeaderMap::new();
    headers.insert(
        RETRY_AFTER,
        HeaderValue::from_str(&past.to_rfc2822().replace("+0000", "GMT")).unwrap(),
    );
    assert_eq!(retry_after_ms(&headers), Some(0));

    // Garbage still falls back to None (exponential backoff path).
    let mut headers = HeaderMap::new();
    headers.insert(RETRY_AFTER, HeaderValue::from_static("not-a-date"));
    assert_eq!(retry_after_ms(&headers), None);
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn transport_options_apply_without_panic() {
    let client = Client::builder(Url::parse("https://alice.example/arkret/").unwrap())
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(5))
        .pool_idle_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(8)
        .tcp_nodelay(true)
        .tcp_keepalive(Duration::from_secs(45))
        .http2_keep_alive_interval(Duration::from_secs(30))
        .http2_keep_alive_timeout(Duration::from_secs(10))
        .http2_keep_alive_while_idle(true)
        .gzip(false)
        .redirect(RedirectPolicy::None)
        .no_proxy()
        .build()
        .unwrap();

    assert_eq!(client.base_url().as_str(), "https://alice.example/arkret/");
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn proxy_can_be_added_via_builder() {
    let proxy = reqwest::Proxy::http("http://proxy.example:3128").unwrap();
    let client = Client::builder(Url::parse("https://alice.example/arkret/").unwrap())
        .proxy(proxy)
        .build()
        .unwrap();
    assert_eq!(client.base_url().as_str(), "https://alice.example/arkret/");
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn transport_options_conflict_with_pre_built_http_client() {
    let http = reqwest::Client::new();
    let error = Client::builder(Url::parse("https://alice.example/arkret/").unwrap())
        .http_client(http)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_err();
    assert!(matches!(error, Error::Protocol(message) if message.contains("transport options")));
}

#[test]
fn pre_built_http_client_alone_is_accepted() {
    let http = reqwest::Client::new();
    let client = Client::builder(Url::parse("https://alice.example/arkret/").unwrap())
        .http_client(http)
        .build()
        .unwrap();
    assert_eq!(client.base_url().as_str(), "https://alice.example/arkret/");
}

#[cfg(not(target_arch = "wasm32"))]
mod events_submit_tests {
    use std::collections::BTreeMap;

    use arkret_models_collaboration::contact_operations::ContactPeer;
    use arkret_models_collaboration::direct_conversation_ops::{
        DirectConversationResolveOutcome, DirectConversationResolveRequestBody,
    };
    use arkret_models_collaboration::http_bodies::{
        MimiReportAbuseRequestBody, MimiReporterAuthority,
    };
    use arkret_models_collaboration::objects::blob::BlobUploadMetadata;
    use arkret_models_collaboration::sync_frames::client_sync::SyncRequestBody;
    use arkret_models_crypto::{
        MlsGovernanceBindingProfile, MlsGovernanceFrontierPurpose, MlsGovernanceProofProfile,
        MlsGovernanceProofRequestBody, MlsSecurityFrontierLeaf,
    };
    use arkret_wire::{
        AuthoritySetAuthorizationRule, AuthoritySetIssuer, AuthoritySetIssuerRole,
        AuthoritySetPolicy, AuthoritySetPolicyKind, AuthoritySetPolicySource, AuthoritySetRef,
        AuthoritySetSourceKind, AuthorizationLease, AuthorizationLeaseId, Base64UrlString, BlobRef,
        DeviceId, Did, DidCoreId, DidUrl, Event, EventId, EventInitialSubmission,
        EventRequirements, Hash, Hlc, LeaseBasisRef, NonEmptyString, PayloadProof, RealmId,
        RiskTier, ScopeRef, SealBasis, SealId, ServiceKind, project_did_to_core_id, proof_kind,
    };
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// Build an `Event` suitable for wire-shape tests. The fixture is not
    /// signed and would fail `validate_for_submit`, but the SDK methods
    /// under test do not invoke that validation — they just serialise the
    /// envelope into the request body. The fixture is deliberately
    /// stripped down so the serialised body is easy to assert against.
    fn fixture_event(content_body: &str) -> Event {
        let realm_id =
            RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").unwrap();
        Event {
            event_id: EventId::new("ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6")
                .unwrap(),
            kind: "ak.message.create".into(),
            realm_id: realm_id.clone(),
            scope_ref: ScopeRef::Realm { realm_id },
            actor_id: ActorId::account(AccountId::new(
                project_did_to_core_id(&Did::new("did:webvh:z6mkfixture:alice.example").unwrap())
                    .unwrap(),
                project_did_to_core_id(
                    &Did::new("did:webvh:z6mkfixture:principal.example").unwrap(),
                )
                .unwrap(),
            )),
            actor_seq: 1,
            created_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
            hlc: Some(Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()),
            prev_refs: Vec::new(),
            refs: Vec::new(),
            preconditions: Vec::new(),
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            requirements: EventRequirements::default(),
            payload: BTreeMap::from([("body".to_owned(), json!(content_body))]),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            unsigned: BTreeMap::new(),
            causal_refs: Vec::new(),
            proofs: Vec::new(),
        }
    }

    /// Wrap a fixture Event in the publication evidence the v1 submit rail
    /// requires. An Event never travels alone here: the lease is what
    /// bounds the revocation window, and only the caller can mint it.
    ///
    /// The lease must bind to the Event it authorizes — same `actor_id`,
    /// same signed `scope_ref` — and its `expires_at - issued_at` must
    /// stay inside the [`RiskTier::Low`] ceiling of 24h. Each proof covers
    /// the lease digest (computed with `proofs` removed, so a proof commits
    /// to every other member) and carries `created_at == issued_at`. The
    /// JWS is a placeholder: these tests assert wire shape, and the SDK
    /// methods under test do not verify signatures.
    fn fixture_submission(content_body: &str) -> EventInitialSubmission {
        let event = fixture_event(content_body);
        let issued_at: chrono::DateTime<chrono::Utc> = "2026-04-26T00:00:00.000Z".parse().unwrap();
        let authority_set_policy = AuthoritySetPolicy {
            schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
            authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
            policy_kind: AuthoritySetPolicyKind::RealmAdmission,
            scope_ref: event.scope_ref.clone(),
            source: AuthoritySetPolicySource {
                source_kind: AuthoritySetSourceKind::RealmControl,
                source_ref: event.event_id.as_str().to_owned(),
                source_digest: Hash::new(format!("sha256:{}", "e".repeat(64))).unwrap(),
                generation_ref: "1".to_owned(),
            },
            authorization_rules: vec![AuthoritySetAuthorizationRule {
                rule_id: "realm_admission".to_owned(),
                issuer_role: AuthoritySetIssuerRole::RealmAdmission,
                allowed_actions: vec![event.kind.as_str().to_owned()],
                issuers: vec![AuthoritySetIssuer {
                    verification_method: DidUrl::new(
                        "did:webvh:z6mkfixture:authority.example#key-1",
                    )
                    .unwrap(),
                }],
                threshold: 1,
            }],
        };
        let mut authorization_lease = AuthorizationLease {
            authorization_lease_id: AuthorizationLeaseId::new(
                "ak:authorization_lease:01904100-0000-7000-8000-aaaaaaaaaaaa",
            )
            .unwrap(),
            basis_ref: LeaseBasisRef::Seal(
                SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            ),
            actor_id: ActorId::service(DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap()),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-000000000002").unwrap(),
            scope_ref: event.scope_ref.clone(),
            action: event.kind.as_str().to_owned(),
            authorization_rule_id: "realm_admission".to_owned(),
            risk_tier: RiskTier::Low,
            issued_at,
            expires_at: issued_at + chrono::Duration::hours(1),
            authority_set_ref: AuthoritySetRef {
                authority_set_id: authority_set_policy.authority_set_id.clone(),
                authority_set_digest: authority_set_policy.digest().unwrap(),
            },
            authority_set_policy,
            proofs: Vec::new(),
        };
        let lease_digest = authorization_lease.lease_digest().unwrap();
        authorization_lease.proofs = vec![PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:authority.example#key-1")
                .unwrap(),
            payload_digest: lease_digest,
            created_at: issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        }];

        EventInitialSubmission {
            event,
            authorization_lease: Some(authorization_lease),
            // Optional receiver-relative dependency evidence; the fixture
            // Event cites no seal_ref / seal_basis, so it needs none.
            cbs_proof_bundles: Vec::new(),
            control_proposal_ack: None,
            membership_compensation_evidence: None,
        }
    }

    /// Spin up a single-shot HTTP listener on `127.0.0.1` and return both
    /// a [`Client`] pointing at it and a oneshot receiver that yields the
    /// raw request bytes once the listener has served `body_response`.
    ///
    /// The listener accepts exactly one connection, reads until the body
    /// is consumed (assuming a `Content-Length` header is present, which
    /// `reqwest::RequestBuilder::json` guarantees), and replies with the
    /// supplied `body_response` JSON under HTTP/1.1 200 OK. The chosen
    /// port is allocated by the OS so tests can run in parallel.
    async fn spawn_capture_server(
        body_response: &'static str,
    ) -> (Client, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        spawn_capture_server_with(body_response, |builder| builder).await
    }

    async fn spawn_capture_server_with<F>(
        body_response: &'static str,
        configure: F,
    ) -> (Client, tokio::sync::oneshot::Receiver<Vec<u8>>)
    where
        F: FnOnce(ClientBuilder) -> ClientBuilder,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            let mut headers_end = None;
            let mut content_length: Option<usize> = None;
            loop {
                let n = socket.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if headers_end.is_none()
                    && let Some(idx) = buf.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    headers_end = Some(idx + 4);
                    let header_str = std::str::from_utf8(&buf[..idx]).unwrap_or("");
                    for line in header_str.split("\r\n") {
                        if let Some(value) = line
                            .strip_prefix("Content-Length: ")
                            .or_else(|| line.strip_prefix("content-length: "))
                        {
                            content_length = value.trim().parse().ok();
                        }
                    }
                }
                if let (Some(hdr_end), Some(len)) = (headers_end, content_length)
                    && buf.len() >= hdr_end + len
                {
                    break;
                }
                if headers_end.is_some() && content_length.is_none() {
                    break;
                }
            }

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body_response.len(),
                body_response
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            socket.shutdown().await.ok();
            let _ = tx.send(buf);
        });

        let base = Url::parse(&format!("http://{addr}/")).unwrap();
        let client = configure(Client::builder(base).allow_insecure_localhost())
            .build()
            .unwrap();
        (client, rx)
    }

    /// Split a raw HTTP/1.1 request capture into (request-line, headers, body).
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

    #[tokio::test]
    async fn effective_grants_transmits_the_complete_actor_branch() {
        let principal = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let station = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        for subject in [
            ActorId::account(AccountId::new(principal.clone(), station.clone())),
            ActorId::service(station),
        ] {
            let (client, capture) =
                spawn_capture_server(r#"{"grants":[],"evaluated_at":"2026-08-31T00:00:00.000Z"}"#)
                    .await;
            let realm =
                RealmId::new("ak:realm:ASZ8VNF9qzH4Hcjd-1qOOKONYlZmfQOIRvMYdkQ0XXBH").unwrap();
            client
                .authz_effective_grants(&realm, &subject, None)
                .await
                .unwrap();
            let raw = capture.await.unwrap();
            let (line, ..) = split_request(&raw);
            let url = Url::parse(&format!(
                "https://fixture.example{}",
                line.split_whitespace().nth(1).unwrap()
            ))
            .unwrap();
            let query = url.query_pairs().collect::<BTreeMap<_, _>>();
            assert_eq!(query.get("subject_actor_id").unwrap(), &subject.to_string());
            assert_eq!(query.get("realm_id").unwrap(), realm.as_str());
            assert_eq!(query.len(), 2);
        }
    }

    #[tokio::test]
    async fn authz_invites_transmits_the_complete_account_pair() {
        for station in [
            "ak:did_core:web:first.example",
            "ak:did_core:web:second.example",
        ] {
            let (client, capture) =
                spawn_capture_server(r#"{"invites":[],"has_more":false}"#).await;
            let subject = AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                DidCoreId::new(station).unwrap(),
            );
            client.authz_invites(&subject, None, None).await.unwrap();
            let raw = capture.await.unwrap();
            let (line, ..) = split_request(&raw);
            let url = Url::parse(&format!(
                "https://fixture.example{}",
                line.split_whitespace().nth(1).unwrap()
            ))
            .unwrap();
            let query = url.query_pairs().collect::<BTreeMap<_, _>>();
            assert_eq!(query.get("subject").unwrap(), subject.principal_id.as_str());
            assert_eq!(query.get("subject_station_id").unwrap(), station);
            assert_eq!(query.len(), 2);
        }
    }

    #[tokio::test]
    async fn events_submit_single_posts_initial_submission() {
        let canned = r#"{"status":"accepted","pending_delivery_count":0,"accepted":["ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6"]}"#;
        let (client, capture) = spawn_capture_server(canned).await;

        let submission = fixture_submission("hello");
        let response = client.events_submit(&submission).await.unwrap();

        assert!(matches!(
            response.status,
            arkret_models_collaboration::http_bodies::EventsSubmitStatus::Accepted
        ));
        assert_eq!(response.accepted.len(), 1);

        let raw = capture.await.unwrap();
        let (request_line, _headers, body) = split_request(&raw);
        assert!(
            request_line.starts_with("POST /_arkret/self/events "),
            "unexpected request line: {request_line}",
        );
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        // The wire body is the single `EventInitialSubmission` arm: the
        // Event under `event`, its lease beside it, and no `events[]`
        // batch wrapper.
        assert!(
            parsed.get("events").is_none(),
            "single submission POST must not wrap in events[]: {parsed}"
        );
        assert_eq!(parsed["event"]["kind"], "ak.message.create");
        assert_eq!(parsed["event"]["payload"]["body"], "hello");
        assert_eq!(
            parsed["event"]["actor_id"],
            json!({
                "kind": "account",
                "account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkfixture",
                    "station_id": "ak:did_core:webvh:z6mkfixture"
                }
            })
        );
        // The lease is publication evidence, not an Event field: it sits
        // next to the envelope and never inside it.
        assert!(parsed["event"].get("authorization_lease").is_none());
        assert_eq!(
            parsed["authorization_lease"]["actor_id"],
            json!({
                "kind": "service",
                "service_id": "ak:did_core:webvh:z6mkfixture"
            })
        );
        assert_eq!(
            parsed["authorization_lease"]["scope_ref"],
            parsed["event"]["scope_ref"]
        );
    }

    #[tokio::test]
    async fn mls_governance_proof_uses_canonical_query_body() {
        let (client, capture) = spawn_capture_server("{}").await;
        let realm_id =
            RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").unwrap();
        let effective_scope = ScopeRef::Realm {
            realm_id: realm_id.clone(),
        };
        let group_id = effective_scope.canonical_mls_group_id().unwrap();
        let basis = SealBasis {
                leaves: vec![SealId::new(
                    "ak:seal:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap()],
            };
        let request = MlsGovernanceProofRequestBody {
            profile: MlsGovernanceProofProfile::GroupSecurityFrontier,
            effective_scope,
            mls_group_id: Base64UrlString::new(group_id.clone()).unwrap(),
            local_mls_leaves: vec![MlsSecurityFrontierLeaf {
                leaf_index: 0,
                actor_id: ActorId::account(AccountId::new(
                    DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
                    DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                )),
                credential_ref: NonEmptyString::new("did:webvh:z6mkfixture#device-1").unwrap(),
            }],
            proof_base_basis: basis.clone(),
            proof_target_basis: basis,
            byte_limit: 1_048_576,
            frontier_purpose: MlsGovernanceFrontierPurpose::GroupBinding,
            base_group_state_ref: Some(
                EventId::new("ak:event:AbnHJt4q4qY18zqvLiy3Emmqy7weTAuApx42RmRgPr2h").unwrap(),
            ),
            proposed_group_genesis_binding: None,
            previous_epoch: 0,
            next_epoch: 1,
            binding_profile: MlsGovernanceBindingProfile::AkSecurityFrontierV1,
        };

        client.mls_governance_proof(&request).await.unwrap_err();

        let raw = capture.await.unwrap();
        let (request_line, _headers, body) = split_request(&raw);
        assert!(
            request_line.starts_with("POST /_arkret/self/seals/mls-governance-proof "),
            "unexpected request line: {request_line}",
        );
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["profile"], "group_security_frontier");
        assert_eq!(parsed["effective_scope"]["kind"], "realm");
        assert_eq!(parsed["mls_group_id"], group_id);
        assert_eq!(parsed["previous_epoch"], 0);
        assert_eq!(parsed["next_epoch"], 1);
        assert_eq!(parsed["binding_profile"], "ak.security_frontier.v1");
    }

    #[tokio::test]
    async fn blob_upload_bytes_posts_multipart_form() {
        let canned = r#"{"blob_ref":"ak:blob:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size_bytes":5,"media_type":"text/plain","upload_receipt":null}"#;
        let (client, capture) = spawn_capture_server(canned).await;
        let metadata = BlobUploadMetadata {
            realm_id: None,
            content_digest: Some(
                Hash::new(
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                )
                .unwrap(),
            ),
            size_bytes: 5,
            media_type: Some("text/plain".to_owned()),
            filename: Some("note.txt".to_owned()),
            purpose: Some("message_attachment".to_owned()),
        };

        let response = client
            .blob_upload_bytes(&metadata, b"hello".to_vec())
            .await
            .unwrap();

        assert_eq!(response.size_bytes, 5);
        let raw = capture.await.unwrap();
        let (request_line, headers, body) = split_request(&raw);
        assert!(request_line.starts_with("POST /_arkret/self/blob/upload "));
        assert!(headers.lines().any(|line| {
            line.to_ascii_lowercase()
                .starts_with("content-type: multipart/form-data; boundary=")
        }));
        let body = String::from_utf8(body).unwrap();
        assert!(body.contains("name=\"content\""));
        assert!(body.contains("hello"));
        assert!(body.contains("name=\"size_bytes\""));
        assert!(body.contains("5"));
        assert!(body.contains("name=\"media_type\""));
        assert!(body.contains("text/plain"));
        assert!(body.contains("name=\"filename\""));
        assert!(body.contains("note.txt"));
        assert!(body.contains("name=\"purpose\""));
        assert!(body.contains("message_attachment"));
    }

    #[tokio::test]
    async fn blob_download_bytes_gets_purpose_range_and_wait_for() {
        let (client, capture) = spawn_capture_server("hello").await;
        let blob_ref = BlobRef::new(
            "ak:blob:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
        )
        .unwrap();
        let options = BlobDownloadOptions::new()
            .purpose("message_attachment")
            .range("bytes=1-3")
            .max_bytes(16);
        let request_options = ClientRequestOptions::new().wait_for("ak:cursor:test");

        let bytes = client
            .blob_download_bytes_with_options(&blob_ref, &options, &request_options)
            .await
            .unwrap();

        assert_eq!(bytes, b"hello");
        let raw = capture.await.unwrap();
        let (request_line, headers, _body) = split_request(&raw);
        assert!(request_line.starts_with("GET /_arkret/self/blob/get?"));
        assert!(
                request_line.contains(
                    "blob_ref=ak%3Ablob%3Asha256%3Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
                "unexpected request line: {request_line}",
            );
        assert!(request_line.contains("purpose=message_attachment"));
        assert!(
            headers
                .lines()
                .any(|line| { line.to_ascii_lowercase().starts_with("range: bytes=1-3") })
        );
        assert!(headers.lines().any(|line| {
            line.to_ascii_lowercase()
                .starts_with("x-arkret-wait-for: ak:cursor:test")
        }));
    }

    #[tokio::test]
    async fn blob_download_bytes_enforces_configured_cap() {
        let (client, _capture) = spawn_capture_server("hello").await;
        let blob_ref = BlobRef::new(
            "ak:blob:sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_owned(),
        )
        .unwrap();
        let options = BlobDownloadOptions::new().max_bytes(4);

        let error = client
            .blob_download_bytes(&blob_ref, &options)
            .await
            .unwrap_err();

        assert!(matches!(error, Error::Protocol(message) if message.contains("4-byte limit")));
    }

    #[tokio::test]
    async fn http_message_signer_signs_self_requests_before_send() {
        let canned = r#"{"status":"accepted","pending_delivery_count":0,"accepted":["ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6"]}"#;
        let signer = HttpMessageSigner::new("grant-key", SigningKey::from_bytes(&[7u8; 32]));
        let (client, capture) =
            spawn_capture_server_with(canned, |builder| builder.http_message_signer(signer)).await;

        let submission = fixture_submission("signed");
        client.events_submit(&submission).await.unwrap();

        let raw = capture.await.unwrap();
        let (_request_line, headers, body) = split_request(&raw);
        assert!(
            headers
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("signature-input:"))
        );
        let signature_input = headers
            .lines()
            .find(|line| line.to_ascii_lowercase().starts_with("signature-input:"))
            .expect("signature-input header");
        assert!(signature_input.contains("\"arkret-operation\""));
        assert!(
            headers
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("signature:"))
        );
        assert!(
            headers
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("content-digest:"))
        );
        arkret_canonical::canonical::validate_canonical_bytes(&body)
            .expect("signed HTTP body must be canonical JSON");
        let content_digest = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-digest")
                    .then_some(value.trim())
            })
            .expect("content-digest header");
        let content_digest =
            arkret_signatures::http_signature::ContentDigest::parse(content_digest).unwrap();
        arkret_signatures::http_signature::verify_content_digest(&content_digest, &body)
            .expect("content digest must cover exact canonical body bytes");
    }

    #[tokio::test]
    async fn http_message_signer_does_not_sign_public_describe() {
        let canned = r#"{"name":"test","version":"v1"}"#;
        let signer = HttpMessageSigner::new("grant-key", SigningKey::from_bytes(&[8u8; 32]));
        let (client, capture) =
            spawn_capture_server_with(canned, |builder| builder.http_message_signer(signer)).await;

        let _: Value = client.get("/_arkret/describe").await.unwrap();

        let raw = capture.await.unwrap();
        let (_request_line, headers, _body) = split_request(&raw);
        assert!(
            !headers
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("signature-input:"))
        );
        assert!(
            !headers
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("signature:"))
        );
    }

    #[tokio::test]
    async fn dpop_auth_does_not_authenticate_public_describe() {
        let canned = r#"{
                "protocol_version":"1.0",
                "service_kind":"station",
                "service_id":"ak:did_core:web:server.local",
                "service_resolution":{
                    "did":"did:web:server.local",
                    "method_history_head":"sha256:fixture",
                    "version_id":"fixture-v1"
                },
                "trust_domain":"ak:trust_domain:server.local",
                "supported_profiles":[],
                "supported_operation_bundles":["ak.operation_bundle.station.describe.v1"],
                "transport_bindings":[{"kind":"http_json","base_url":"https://server.local","extension_profile_required":null}],
                "supported_features":[],
                "auth_metadata":{"methods":[]},
                "limits":{},
                "plaintext_visibility":{"data_classes":[],"max_visibility":"none"},
                "claimed_profiles":[],
                "verified_profiles":[],
                "interop_surfaces":[],
                "development_mode":false,
                "rate_limit_policy":{}
            }"#;
        let (client, capture) = spawn_capture_server_with(canned, |builder| {
            builder.auth(Auth::Dpop(DpopAuth::with_dpop_token(
                "session-grant",
                |_| Ok("proof.jwt".to_owned()),
            )))
        })
        .await;

        client.describe().await.unwrap();

        let raw = capture.await.unwrap();
        let (_request_line, headers, _body) = split_request(&raw);
        assert!(
            !headers
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("authorization:"))
        );
        assert!(
            !headers
                .lines()
                .any(|line| line.to_ascii_lowercase().starts_with("dpop:"))
        );
    }

    #[tokio::test]
    async fn role_scoped_describe_sends_selector_and_rejects_mismatched_response() {
        let canned = r#"{
                "protocol_version":"1.0",
                "service_kind":"station",
                "service_id":"ak:did_core:web:server.local",
                "service_resolution":{
                    "did":"did:web:server.local",
                    "method_history_head":"sha256:fixture",
                    "version_id":"fixture-v1"
                },
                "trust_domain":"ak:trust_domain:server.local",
                "supported_profiles":[],
                "supported_operation_bundles":["ak.operation_bundle.station.describe.v1"],
                "transport_bindings":[{"kind":"http_json","base_url":"https://server.local","extension_profile_required":null}],
                "supported_features":[],
                "auth_metadata":{"methods":[]},
                "limits":{},
                "plaintext_visibility":{"data_classes":[],"max_visibility":"none"},
                "claimed_profiles":[],
                "verified_profiles":[],
                "interop_surfaces":[],
                "development_mode":false,
                "rate_limit_policy":{}
            }"#;
        let (client, capture) = spawn_capture_server(canned).await;
        let description = client
            .describe_for_role(ServiceKind::Station)
            .await
            .unwrap();
        assert_eq!(description.service_kind, ServiceKind::Station);

        let raw = capture.await.unwrap();
        let (request_line, _headers, _body) = split_request(&raw);
        assert!(
            request_line.starts_with("GET /_arkret/describe?service_kind=station HTTP/1.1"),
            "unexpected request line: {request_line}",
        );

        let mismatched = Box::leak(
            canned
                .replace(
                    "\"service_kind\":\"station\"",
                    "\"service_kind\":\"notary\"",
                )
                .into_boxed_str(),
        );
        let (client, _capture) = spawn_capture_server(mismatched).await;
        assert!(
            client
                .describe_for_role(ServiceKind::Station)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn events_submit_batch_posts_events_array() {
        let canned = r#"{"status":"accepted","pending_delivery_count":0,"accepted":["ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6"]}"#;
        let (client, capture) = spawn_capture_server(canned).await;

        let submissions = vec![fixture_submission("first"), fixture_submission("second")];
        let response = client.events_submit_batch(&submissions).await.unwrap();
        assert!(matches!(
            response.status,
            arkret_models_collaboration::http_bodies::EventsSubmitStatus::Accepted
        ));

        let raw = capture.await.unwrap();
        let (request_line, _headers, body) = split_request(&raw);
        assert!(request_line.starts_with("POST /_arkret/self/events "));
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        let events_value = parsed
            .get("events")
            .expect("batch body must carry events[]");
        let arr = events_value.as_array().expect("events must be an array");
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["event"]["payload"]["body"], "first");
        assert_eq!(arr[1]["event"]["payload"]["body"], "second");
        // Every element is a full submission: each Event carries its own
        // lease rather than sharing one for the batch.
        assert!(arr[0].get("authorization_lease").is_some());
        assert!(arr[1].get("authorization_lease").is_some());
        // Idempotency is a header concern; the batch body has no such field.
        assert!(
            parsed.get("idempotency_key").is_none(),
            "batch body must not carry idempotency_key: {parsed}"
        );
    }

    #[tokio::test]
    async fn events_read_queries_canonical_events_collection_with_json_content() {
        let canned = r#"{"events":[],"has_more":false}"#;
        let (client, capture) = spawn_capture_server(canned).await;

        let response = client
            .events_read_outcome(
                "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI",
                Some("ak:cursor:older"),
                Some("ak:cursor:newer"),
                Some("descending"),
                Some(20),
            )
            .await
            .unwrap();
        assert!(response.events.is_empty());

        let raw = capture.await.unwrap();
        let (request_line, headers, body) = split_request(&raw);
        assert!(
            request_line.starts_with("QUERY /_arkret/self/events "),
            "unexpected request line: {request_line}",
        );
        assert!(
            headers
                .lines()
                .any(|line| line.eq_ignore_ascii_case("content-type: application/json"))
        );
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed["realm_ids"],
            json!(["ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"])
        );
        assert_eq!(parsed["before"], "ak:cursor:older");
        assert_eq!(parsed["after"], "ak:cursor:newer");
        assert_eq!(parsed["order"], "descending");
        assert_eq!(parsed["limit"], 20);
    }

    #[tokio::test]
    async fn events_resolve_uses_canonical_query_body() {
        let event_id =
            EventId::new("ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6").unwrap();
        let canned =
            r#"{"events":[],"missing":["ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6"]}"#;
        let (client, capture) = spawn_capture_server(canned).await;
        let request = arkret_models_collaboration::http_bodies::EventsResolveRequestBody {
            event_ids: vec![event_id.clone()],
            event_digests: Vec::new(),
            include_payload: Some(true),
            history_traversal_access: None,
            max_response_bytes: None,
        };

        let response = client.events_resolve(&request).await.unwrap();
        assert_eq!(response.missing, vec![event_id.to_string()]);

        let raw = capture.await.unwrap();
        let (request_line, _headers, body) = split_request(&raw);
        assert!(request_line.starts_with("QUERY /_arkret/self/events/resolve "));
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["event_ids"], serde_json::json!([event_id.as_str()]));
        assert_eq!(parsed["include_payload"], true);
        assert!(parsed.get("event_digests").is_none());
        assert!(parsed.get("history_traversal_access").is_none());
    }

    #[tokio::test]
    async fn list_key_backups_includes_series_id_query() {
        let (client, capture) = spawn_capture_server(r#"{"backups":[],"has_more":false}"#).await;
        let query = arkret_models_crypto::KeyBackupsListQuery {
            series_id: Some(
                arkret_wire::BackupSeriesId::new(
                    "ak:backup_series:01964137-0000-7000-8000-000000000777",
                )
                .unwrap(),
            ),
            backup_kind: Some(arkret_models_crypto::BackupKind::SecretStorage),
            cursor: None,
            limit: Some(25),
        };

        let response = client.list_key_backups(&query).await.unwrap();
        assert!(response.backups.is_empty());
        assert!(!response.has_more);

        let raw = capture.await.unwrap();
        let (request_line, _headers, _body) = split_request(&raw);
        assert!(
            request_line.starts_with("GET /_arkret/self/keys/backups?"),
            "unexpected request line: {request_line}",
        );
        assert!(
            request_line
                .contains("series_id=ak%3Abackup_series%3A01964137-0000-7000-8000-000000000777")
        );
        assert!(request_line.contains("backup_kind=secret_storage"));
        assert!(request_line.contains("limit=25"));
    }

    #[tokio::test]
    async fn contacts_list_gets_spec_path() {
        let (client, capture) = spawn_capture_server(r#"{"contacts":[],"has_more":false}"#).await;

        let response = client.contacts_list().await.unwrap();
        assert!(response.contacts.is_empty());
        assert!(!response.has_more);

        let raw = capture.await.unwrap();
        let (request_line, _headers, _body) = split_request(&raw);
        assert!(
            request_line.starts_with("GET /_arkret/self/contacts "),
            "unexpected request line: {request_line}",
        );
    }

    #[tokio::test]
    async fn direct_conversation_resolve_posts_spec_path_and_current_shape() {
        let canned = r#"{
                "state":"found",
                "coordinates": {
                    "pair_key":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "realm_id":"ak:realm:AbcWFuKINjkcm1y06x9Wj7OmWCtemxIBLdYilRrGdY-J",
                    "main_strand_id":"ak:strand:AecaKJ8FXN30ZcALRwEuYjmb1ezqL2TQ3YA4OoGfdpx9",
                    "binding_event_ref":"ak:event:AfOnmtYgQpP17IGXP_64dE-weM-8C_AfXXXfYpJ3ubJG"
                },
                "group_state_ref":"ak:event:AfR_M7E56E86OkxTne77vQ9fmdFkzpnxO_TBqB4ymjKV",
                "send_blockers": []
            }"#;
        let (client, capture) = spawn_capture_server(canned).await;
        let request = DirectConversationResolveRequestBody {
            peer: ContactPeer::Human {
                account_id: AccountId::new(
                    DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
                    DidCoreId::new("ak:did_core:webvh:z6mkfixturestation").unwrap(),
                ),
            },
        };

        let response = client.direct_conversation_resolve(&request).await.unwrap();
        let DirectConversationResolveOutcome::Found {
            coordinates,
            group_state_ref,
            ..
        } = response
        else {
            panic!("expected found direct conversation");
        };
        assert_eq!(
            coordinates
                .binding_event_ref
                .as_ref()
                .expect("found carries a binding ref")
                .as_str(),
            "ak:event:AfOnmtYgQpP17IGXP_64dE-weM-8C_AfXXXfYpJ3ubJG"
        );
        assert_eq!(
            group_state_ref.as_str(),
            "ak:event:AfR_M7E56E86OkxTne77vQ9fmdFkzpnxO_TBqB4ymjKV"
        );

        let raw = capture.await.unwrap();
        let (request_line, _headers, body) = split_request(&raw);
        assert!(
            request_line.starts_with("POST /_arkret/self/direct-conversations/resolve "),
            "unexpected request line: {request_line}",
        );
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert!(
            parsed.get("create").is_none(),
            "resolve is query-only and MUST NOT carry a create phase: {parsed}"
        );
        assert!(
            parsed.get("peer").is_some(),
            "resolve body carries peer: {parsed}"
        );
    }

    #[tokio::test]
    async fn mimi_provider_directory_gets_canonical_path_with_filters() {
        let (client, capture) = spawn_capture_server(
                r#"{
                    "schema":"ak.schema.mimi_interop.v1",
                    "service_id":"ak:did_core:web:mimi.example.test",
                    "service_kind":"mimi_provider",
                    "supported_profiles":["ak.profile.mimi_interop.v1"],
                    "mimi":{
                        "protocol_draft":"draft-ietf-mimi-protocol-04",
                        "content_draft":"draft-ietf-mimi-content-04",
                        "room_policy_draft":"draft-ietf-mimi-room-policy-03",
                        "identifier_draft":"draft-kohbrok-mimi-identifiers-01",
                        "base_url":"https://mimi.example.test",
                        "provider_id":"mimi://provider-a.example",
                        "endpoints":[{"endpoint_id":"mimi_v1","relative_path":"/messages"}],
                        "features":["mimi_v1"],
                        "mls_cipher_suites":["MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"],
                        "content_profiles":["application/mimi-content"],
                        "room_policy_components":["membership"]
                    },
                    "proof":{
                        "kind":"detached_jws",
                        "verification_method":"did:web:mimi.example.test#notary-key",
                        "payload_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000",
                        "created_at":"2026-08-01T00:00:00.000Z",
                        "jws":"eyJhbGciOiJFZDI1NTE5In0..c2ln"
                    }
                }"#,
            )
            .await;
        let features = vec!["blind_wakeup".to_owned(), "mimi_v1".to_owned()];

        let response = client
            .mimi_provider_directory(Some("provider-a"), &features)
            .await
            .unwrap();
        assert_eq!(response.service_kind, "mimi_provider");
        assert_eq!(
            response.mimi.provider_id.as_str(),
            "mimi://provider-a.example"
        );
        assert_eq!(response.mimi.features, ["mimi_v1"]);

        let raw = capture.await.unwrap();
        let (request_line, _headers, _body) = split_request(&raw);
        assert!(
            request_line.starts_with("GET /_arkret/open/mimi/provider-directory?"),
            "unexpected request line: {request_line}",
        );
        assert!(request_line.contains("provider_id=provider-a"));
        assert!(request_line.contains("features=blind_wakeup"));
        assert!(request_line.contains("features=mimi_v1"));
    }

    #[tokio::test]
    async fn mimi_report_abuse_posts_canonical_path() {
        let (client, capture) = spawn_capture_server(
                r#"{"report_id":"ak:report:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6","status":"queued","routed_to_ids":[]}"#,
            )
            .await;
        let request = MimiReportAbuseRequestBody {
            reporter_authority: MimiReporterAuthority {
                actor_id: ActorId::account(AccountId::new(
                    DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
                    DidCoreId::new("ak:did_core:web:station.example").unwrap(),
                )),
                membership_event_id: EventId::new(
                    "ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6",
                )
                .unwrap(),
                room_binding_event_id: EventId::new(
                    "ak:event:Adoyyx1AqvJH02hYxuUtpzuC-zpV8GxwFQ8XInZLbu3s",
                )
                .unwrap(),
                expires_at: "2026-09-01T01:00:00Z".parse().unwrap(),
                proof: PayloadProof {
                    kind: proof_kind::DETACHED_JWS.to_owned(),
                    verification_method: DidUrl::new(
                        "did:webvh:z6mkfixture:alice.example#device-1",
                    )
                    .unwrap(),
                    payload_digest: Hash::new(arkret_canonical::sha256_digest(b"mimi-report"))
                        .unwrap(),
                    created_at: "2026-09-01T00:00:00Z".parse().unwrap(),
                    domain: None,
                    audience: None,
                    proof_purpose: None,
                    jws: "a..b".to_owned(),
                },
            },
            report_event: fixture_submission("mimi moderation report"),
            cbs_proof_bundles: Vec::new(),
        };

        let response = client.mimi_report_abuse(&request).await.unwrap();
        assert_eq!(
            response.status,
            arkret_models_collaboration::http_bodies::MimiReportAbuseStatus::Queued
        );

        let raw = capture.await.unwrap();
        let (request_line, _headers, body) = split_request(&raw);
        assert!(
            request_line.starts_with("POST /_arkret/open/mimi/report-abuse "),
            "unexpected request line: {request_line}",
        );
        let parsed: Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed.get("abuse_reason_code").is_none());
        assert!(parsed.get("reporter_id").is_none());
        assert_eq!(parsed.as_object().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn events_submit_returns_partial_status() {
        let canned = r#"{
                "status": "partial",
                "pending_delivery_count": 0,
                "accepted": ["ak:event:AZL87nwhLc8pnnvIhrfEQSfNkZvdPzaV3rFGVoJCQWW6"],
                "rejections": [
                    {"id": "ak:event:Adoyyx1AqvJH02hYxuUtpzuC-zpV8GxwFQ8XInZLbu3s", "reason_code": "schema_violation"}
                ]
            }"#;
        let (client, _capture) = spawn_capture_server(canned).await;

        let response = client
            .events_submit_batch(&[fixture_submission("a"), fixture_submission("b")])
            .await
            .unwrap();

        assert!(
            matches!(
                response.status,
                arkret_models_collaboration::http_bodies::EventsSubmitStatus::Partial
            ),
            "expected Partial status, got {:?}",
            response.status
        );
        assert_eq!(response.accepted.len(), 1);
        assert_eq!(response.rejections.len(), 1);
        assert_eq!(
            response.rejections[0].reason_code.as_str(),
            "schema_violation"
        );
    }

    /// S-6 (savfox SDK gap): the streaming API yields one
    /// [`AccountSubscribeFrame`] per NDJSON line, including across
    /// chunk boundaries. Backed by a minimal stub server that
    /// dribbles the body out in slices.
    async fn spawn_chunked_ndjson_server(body_parts: Vec<&'static str>) -> Client {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            // Read & discard request headers.
            let mut buf = [0u8; 4096];
            let mut acc = Vec::new();
            loop {
                let n = socket.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
                if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }

            let body: String = body_parts.iter().copied().collect();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            for part in body_parts {
                socket.write_all(part.as_bytes()).await.unwrap();
                // Yield so the client side observes >1 chunk.
                tokio::task::yield_now().await;
            }
            socket.shutdown().await.ok();
        });

        let base = Url::parse(&format!("http://{addr}/")).unwrap();
        Client::builder(base)
            .allow_insecure_localhost()
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn account_subscribe_frames_yields_one_frame_per_line() {
        use arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrame;

        // Four frames split across chunks; the frontier frame
        // straddles a chunk boundary mid-line so the codec must
        // buffer to assemble it.
        let parts = vec![
            r#"{"kind":"heartbeat"}"#,
            "\n{\"cursor\":\"ak:cursor:adv-1\"",
            ",\"kind\":\"frontier\"}\n",
            "{\"cursor\":\"ak:cursor:delta-1\",\"kind\":\"delta\",\"partial\":false}\n",
            "{\"cursor\":\"ak:cursor:live-0\",\"kind\":\"catchup_complete\"}\n",
        ];
        let client = spawn_chunked_ndjson_server(parts).await;
        let mut stream = client
            .account_subscribe_frames(&SyncRequestBody {
                after: None,
                catchup: Some(true),
                filter: None,
                subscriptions: None,
            })
            .await
            .expect("stream init");

        let mut got = Vec::new();
        while let Some(frame) = stream.next_frame().await.expect("frame decode") {
            got.push(frame);
        }
        assert_eq!(got.len(), 4, "expected 4 frames, got {got:?}");
        assert_eq!(
            got[0].kind,
            AccountSubscribeFrame::from_ndjson_line(r#"{"kind":"heartbeat"}"#)
                .unwrap()
                .unwrap()
                .kind
        );
        assert!(got[1].cursor.is_some());
        assert_eq!(got[2].kind, arkret_models_collaboration::sync_frames::account_subscribe::AccountSubscribeFrameKind::Delta);
        assert!(got[3].is_catchup_complete());
        assert_eq!(stream.reconnect_cursor(), Some("ak:cursor:live-0"));
    }

    #[tokio::test]
    async fn account_subscribe_batch_waits_for_valid_catchup_completion() {
        let parts = vec![
            "{\"cursor\":\"ak:cursor:delta-1\",\"kind\":\"delta\",\"partial\":true}\n",
            "{\"cursor\":\"ak:cursor:delta-2\",\"kind\":\"delta\",\"partial\":false}\n",
            "{\"cursor\":\"ak:cursor:complete-2\",\"kind\":\"catchup_complete\"}\n",
        ];
        let client = spawn_chunked_ndjson_server(parts).await;
        let outcome = client
            .account_subscribe_batch(&SyncRequestBody {
                after: None,
                catchup: Some(true),
                filter: None,
                subscriptions: None,
            })
            .await
            .unwrap();

        assert_eq!(outcome.cursor, "ak:cursor:complete-2");
        assert_eq!(outcome.frames.len(), 2);
        assert_eq!(outcome.frames[1].partial, Some(false));
    }

    #[tokio::test]
    async fn account_subscribe_batch_returns_while_live_body_stays_open() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = socket.read(&mut buffer).await.unwrap();
                if count == 0 {
                    return;
                }
                request.extend_from_slice(&buffer[..count]);
            }
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ndjson\r\n\
                          Transfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
                )
                .await
                .unwrap();
            for frame in [
                "{\"cursor\":\"ak:cursor:delta-live\",\"kind\":\"delta\",\"partial\":false}\n",
                "{\"cursor\":\"ak:cursor:catchup-live\",\"kind\":\"catchup_complete\"}\n",
            ] {
                socket
                    .write_all(format!("{:X}\r\n{}\r\n", frame.len(), frame).as_bytes())
                    .await
                    .unwrap();
            }
            let _ = release_rx.await;
            let _ = socket.write_all(b"0\r\n\r\n").await;
        });

        let client = Client::builder(Url::parse(&format!("http://{addr}/")).unwrap())
            .allow_insecure_localhost()
            .build()
            .unwrap();
        let outcome = tokio::time::timeout(
            Duration::from_secs(2),
            client.account_subscribe_batch(&SyncRequestBody {
                after: None,
                catchup: Some(true),
                filter: None,
                subscriptions: None,
            }),
        )
        .await
        .expect("account batch must not wait for the live response body to close")
        .unwrap();
        release_tx.send(()).ok();

        assert_eq!(outcome.cursor, "ak:cursor:catchup-live");
        assert_eq!(outcome.frames.len(), 1);
    }

    #[tokio::test]
    async fn account_subscribe_batch_surfaces_dropped_interrupt() {
        use arkret_models_collaboration::sync_frames::account_subscribe::AccountStreamInterrupt;

        // Benign keepalive first, then a `dropped` control frame: the
        // dropped frame must surface as a structured interrupt instead
        // of being skipped while waiting for a delta.
        let parts = vec![
            "{\"kind\":\"heartbeat\"}\n",
            "{\"kind\":\"dropped\",\"cursor\":\"ak:cursor:drop-9\",\"reconnect_after_ms\":10000}\n",
        ];
        let client = spawn_chunked_ndjson_server(parts).await;
        let error = client
            .account_subscribe_batch(&SyncRequestBody {
                after: None,
                catchup: Some(true),
                filter: None,
                subscriptions: None,
            })
            .await
            .unwrap_err();

        match error {
            Error::AccountStreamInterrupt(AccountStreamInterrupt::Dropped {
                cursor,
                reconnect_after_ms,
            }) => {
                assert_eq!(cursor, "ak:cursor:drop-9");
                assert_eq!(reconnect_after_ms, Some(10_000));
            }
            other => panic!("expected dropped interrupt, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn account_subscribe_batch_surfaces_unauthorized_interrupt() {
        use arkret_models_collaboration::sync_frames::account_subscribe::AccountStreamInterrupt;

        let parts = vec!["{\"kind\":\"unauthorized\"}\n"];
        let client = spawn_chunked_ndjson_server(parts).await;
        let error = client
            .account_subscribe_batch(&SyncRequestBody {
                after: None,
                catchup: Some(true),
                filter: None,
                subscriptions: None,
            })
            .await
            .unwrap_err();

        assert!(matches!(
            error,
            Error::AccountStreamInterrupt(AccountStreamInterrupt::Unauthorized)
        ));
    }
}
