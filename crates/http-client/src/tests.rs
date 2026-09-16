//! Integration-style unit tests for the crate root, kept in a sibling
//! module per repository convention (`#[cfg(test)] mod tests;`).

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
