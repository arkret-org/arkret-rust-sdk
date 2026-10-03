//! Method-native service discovery, independent of the caller's Station.

use std::future::Future;
use std::time::Duration;

use arkret_egress_policy::OutboundPolicy;
use arkret_identity::{DidResolver as _, DidWebResolver, DidWebvhResolver};
use arkret_models_identity::AuthenticatedServiceResolution;
use arkret_wire::{Did, ServiceKind};
use chrono::Utc;
use reqwest::header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_TYPE};
use url::Url;

use crate::{Client, Error, Result, SERVICE_RESOLUTION_FETCH_MAX_BYTES};

fn protocol(error: impl std::fmt::Display) -> Error {
    Error::Protocol(error.to_string())
}

fn method_fetch_policy() -> OutboundPolicy {
    if cfg!(debug_assertions) {
        OutboundPolicy::local_development()
    } else {
        OutboundPolicy::public_https()
    }
}

impl Client {
    /// Resolve a complete service DID through its registered method adapter.
    ///
    /// The own-Station open resolution endpoint publishes only that Station.
    /// Remote discovery instead verifies the DID's native history and current
    /// endpoint. No Account grant, DPoP signer, cookies or service credentials
    /// are inherited. The result is a route candidate, not Realm authority.
    pub async fn resolve_service_from_did(
        &self,
        did: &Did,
        service_kind: ServiceKind,
    ) -> Result<AuthenticatedServiceResolution> {
        resolve_method_with_fetch(did, service_kind, |url| async move {
            fetch_method_bytes(&url).await
        })
        .await
    }
}

async fn resolve_method_with_fetch<F, Fut>(
    did: &Did,
    service_kind: ServiceKind,
    mut fetch: F,
) -> Result<AuthenticatedServiceResolution>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<Option<(String, Vec<u8>)>>>,
{
    if !service_kind.valid_in("service_describe") {
        return Err(protocol("service role is not valid for route discovery"));
    }
    let service_id = arkret_wire::project_did_to_core_id(did).map_err(protocol)?;
    let mut current_did = did.clone();
    for _ in 0..4 {
        let (current, log_entries, witness_records) = match current_did.method() {
            "web" => {
                let url = DidWebResolver::document_url(&current_did).map_err(protocol)?;
                let (content_type, body) = required_method_bytes(fetch(url.clone()).await?)?;
                let document = DidWebResolver::new()
                    .insert_from_https_response(
                        &current_did,
                        arkret_identity::DidWebDocumentOutcome {
                            url,
                            content_type,
                            body,
                        },
                    )
                    .map_err(protocol)?;
                (
                    arkret_identity::ResolvedDid::proofless(document),
                    Vec::new(),
                    Vec::new(),
                )
            }
            "webvh" => {
                let log_url = DidWebvhResolver::log_url(&current_did).map_err(protocol)?;
                let (log_type, log_body) = required_method_bytes(fetch(log_url.clone()).await?)?;
                let discovered =
                    arkret_identity::discover_webvh_current_did(&service_id, &log_body)
                        .map_err(protocol)?;
                if discovered != current_did {
                    current_did = discovered;
                    continue;
                }
                let doc_url = DidWebvhResolver::document_url(&current_did).map_err(protocol)?;
                let (doc_type, doc_body) = required_method_bytes(fetch(doc_url.clone()).await?)?;
                let mut resolver = DidWebvhResolver::new();
                resolver
                    .insert_from_https_response(
                        &current_did,
                        arkret_identity::DidWebvhDocumentOutcome {
                            url: doc_url,
                            content_type: doc_type,
                            body: doc_body,
                        },
                    )
                    .map_err(protocol)?;
                let log = arkret_identity::verify_did_webvh_v1_chain_bytes(&current_did, &log_body)
                    .map_err(protocol)?;
                resolver
                    .ingest_log(
                        &current_did,
                        arkret_identity::DidWebvhLogOutcome {
                            url: log_url,
                            content_type: log_type,
                            body: log_body,
                        },
                    )
                    .map_err(protocol)?;
                let witness_url = DidWebvhResolver::witness_url(&current_did).map_err(protocol)?;
                let mut witnesses = Vec::new();
                if let Some((_, bytes)) = fetch(witness_url).await? {
                    resolver
                        .ingest_witness_records(&current_did, &bytes)
                        .map_err(protocol)?;
                    witnesses = serde_json::from_slice(&bytes).map_err(protocol)?;
                }
                (
                    resolver.resolve_did(&current_did).map_err(protocol)?,
                    log.raw_entries,
                    witnesses,
                )
            }
            _ => return Err(protocol("service DID method has no route adapter")),
        };
        let now = chrono::DateTime::from_timestamp_millis(Utc::now().timestamp_millis())
            .ok_or_else(|| protocol("service resolution timestamp is invalid"))?;
        let resolution = match current_did.method() {
            "webvh" => arkret_identity::build_authenticated_webvh_service_resolution(
                service_id.clone(),
                service_kind.as_str().to_owned(),
                current.document.clone(),
                log_entries,
                witness_records,
                now,
            ),
            "web" => arkret_identity::build_authenticated_did_web_service_resolution(
                service_id.clone(),
                service_kind.as_str().to_owned(),
                current.document.clone(),
                now,
            ),
            _ => unreachable!(),
        }
        .map_err(protocol)?;
        arkret_identity::verify_current_service_resolution(
            &resolution,
            &service_id,
            service_kind.as_str(),
            &current,
            now,
        )
        .map_err(protocol)?;
        return Ok(resolution);
    }
    Err(protocol(
        "service DID portability discovery exceeded four hops",
    ))
}

fn required_method_bytes(bytes: Option<(String, Vec<u8>)>) -> Result<(String, Vec<u8>)> {
    bytes.ok_or_else(|| protocol("service DID method material is missing"))
}

fn method_status_error(status: reqwest::StatusCode) -> Error {
    let detail = format!("service DID fetch returned {status}");
    if status.is_server_error() || status.as_u16() == 429 {
        Error::Http(detail)
    } else {
        protocol(detail)
    }
}

async fn fetch_method_bytes(url: &str) -> Result<Option<(String, Vec<u8>)>> {
    let parsed = Url::parse(url)?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(protocol("service DID fetch requires credential-free HTTPS"));
    }
    method_fetch_policy()
        .validate_url(&parsed)
        .map_err(protocol)?;
    #[cfg(not(target_arch = "wasm32"))]
    let http = {
        let guard = arkret_egress_reqwest::EgressGuard::new(method_fetch_policy());
        let target = tokio::time::timeout(
            Duration::from_secs(2),
            guard.lock_url_async(&parsed, "service DID material"),
        )
        .await
        .map_err(|_| Error::Http("service DID DNS lookup timed out".to_owned()))?
        .map_err(|error| match error.kind() {
            arkret_egress_reqwest::EgressErrorKind::Dns { .. } => Error::Http(error.to_string()),
            _ => protocol(error),
        })?;
        let builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .gzip(false);
        let builder = crate::tls_roots::apply_explicit_tls_roots(builder)?;
        target
            .apply_to_client_builder(builder)
            .build()
            .map_err(crate::client_internals::transport_error)?
    };
    #[cfg(target_arch = "wasm32")]
    let http = reqwest::Client::new();
    let request = http
        .get(parsed.clone())
        .header(ACCEPT_ENCODING, "identity")
        .timeout(Duration::from_secs(2));
    #[cfg(target_arch = "wasm32")]
    let request = request.fetch_credentials_omit();
    let response = request
        .send()
        .await
        .map_err(crate::client_internals::transport_error)?;
    if response.url() != &parsed {
        return Err(protocol("service DID fetch changed its target"));
    }
    if response.status().as_u16() == 404 {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err(method_status_error(response.status()));
    }
    if response
        .headers()
        .get(CONTENT_ENCODING)
        .is_some_and(|value| value.as_bytes() != b"identity")
        || response
            .content_length()
            .is_some_and(|size| size > SERVICE_RESOLUTION_FETCH_MAX_BYTES as u64)
    {
        return Err(protocol(
            "service DID material exceeds its identity-encoded byte bound",
        ));
    }
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body =
        crate::client_internals::read_body_limited(response, SERVICE_RESOLUTION_FETCH_MAX_BYTES)
            .await?;
    Ok(Some((content_type, body)))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use arkret_models_identity::service_identity::{CanonicalServiceUrl, ServiceRegistrationKey};
    use arkret_signatures::webvh::{
        ServiceRegistrationInceptionInput, prepare_service_registration_inception,
    };
    use rand_core::SeedableRng as _;

    use super::*;

    type Materials = BTreeMap<String, (String, Vec<u8>)>;

    fn fixture() -> (Did, Materials) {
        let provider = Url::parse("https://identity.example/").unwrap();
        let registration = ServiceRegistrationKey::new(
            ServiceKind::Station,
            CanonicalServiceUrl::new("https://station.example/").unwrap(),
        )
        .unwrap();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1725);
        let prepared = prepare_service_registration_inception(
            &mut rng,
            &ServiceRegistrationInceptionInput {
                provider_endpoint: &provider,
                registration_key: &registration,
                also_known_as: &[],
                version_time: Utc::now() - chrono::Duration::minutes(1),
                did_key_fragment: None,
            },
        )
        .unwrap();
        let did = Did::new(prepared.did.clone()).unwrap();
        let materials = BTreeMap::from([
            (
                DidWebvhResolver::document_url(&did).unwrap(),
                (
                    "application/did+json".to_owned(),
                    serde_json::to_vec(&prepared.log_entry["state"]).unwrap(),
                ),
            ),
            (
                DidWebvhResolver::log_url(&did).unwrap(),
                (
                    "application/jsonl".to_owned(),
                    serde_json::to_vec(&prepared.log_entry).unwrap(),
                ),
            ),
        ]);
        (did, materials)
    }

    #[tokio::test]
    async fn remote_station_route_comes_from_signed_method_not_its_hosting_origin() {
        let (did, materials) = fixture();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let requests = seen.clone();
        let resolution = resolve_method_with_fetch(&did, ServiceKind::Station, move |url| {
            requests.lock().unwrap().push(url.clone());
            std::future::ready(Ok(materials.get(&url).cloned()))
        })
        .await
        .unwrap();
        assert_eq!(
            resolution.service_id,
            arkret_wire::project_did_to_core_id(&did).unwrap()
        );
        assert_eq!(
            resolution.projection().unwrap().base_url,
            "https://station.example/"
        );
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 3);
        assert!(
            seen.iter()
                .all(|url| Url::parse(url).unwrap().host_str() == Some("identity.example"))
        );
        assert_eq!(seen[0], DidWebvhResolver::log_url(&did).unwrap());
        assert_eq!(seen[1], DidWebvhResolver::document_url(&did).unwrap());
        assert_eq!(seen[2], DidWebvhResolver::witness_url(&did).unwrap());
    }

    #[tokio::test]
    async fn mismatched_role_or_tampered_document_and_history_fail_closed() {
        let (did, materials) = fixture();
        let wrong_role = materials.clone();
        assert!(
            resolve_method_with_fetch(&did, ServiceKind::DirectoryService, move |url| {
                std::future::ready(Ok(wrong_role.get(&url).cloned()))
            })
            .await
            .is_err()
        );
        for url in [
            DidWebvhResolver::document_url(&did).unwrap(),
            DidWebvhResolver::log_url(&did).unwrap(),
        ] {
            let mut tampered = materials.clone();
            let bytes = &mut tampered.get_mut(&url).unwrap().1;
            let mut value: serde_json::Value = serde_json::from_slice(bytes).unwrap();
            if value.get("state").is_some() {
                value["state"]["service"][0]["serviceEndpoint"] =
                    serde_json::json!("https://forged.example/");
            } else {
                value["service"][0]["serviceEndpoint"] =
                    serde_json::json!("https://forged.example/");
            }
            *bytes = serde_json::to_vec(&value).unwrap();
            assert!(
                resolve_method_with_fetch(&did, ServiceKind::Station, move |url| {
                    std::future::ready(Ok(tampered.get(&url).cloned()))
                })
                .await
                .is_err()
            );
        }
    }

    #[tokio::test]
    async fn method_fetch_refuses_plaintext_credentials_and_metadata_before_network() {
        for url in [
            "http://127.0.0.1/did.json",
            "https://user:secret@identity.example/did.json",
            "https://169.254.169.254/did.json",
            "https://10.0.0.1/did.json",
        ] {
            assert!(fetch_method_bytes(url).await.is_err());
        }
    }

    #[test]
    fn method_outages_remain_retryable_but_redirects_and_refusals_fail_closed() {
        for status in [503, 429] {
            assert!(matches!(
                method_status_error(reqwest::StatusCode::from_u16(status).unwrap()),
                Error::Http(_)
            ));
        }
        for status in [302, 403] {
            assert!(matches!(
                method_status_error(reqwest::StatusCode::from_u16(status).unwrap()),
                Error::Protocol(_)
            ));
        }
    }
}
