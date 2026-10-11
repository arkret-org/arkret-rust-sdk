//! Credential-free Station bootstrap from an explicitly selected origin.

use arkret_models_discovery::{ServiceDescribe, StationConnectionBinding, validate_connection_url};
use url::Url;

use crate::{Error, Result};

/// Fetch before reusing any credentials. No DID resolver is involved.
pub async fn fetch_station_description(
    base: &Url,
    allow_insecure_loopback: bool,
) -> Result<ServiceDescribe> {
    validate_connection_url(base, allow_insecure_loopback)?;
    let mut endpoint = base.join("_arkret/describe")?;
    endpoint
        .query_pairs_mut()
        .append_pair("service_kind", "station");
    let bytes = fetch(&endpoint).await?;
    let description: ServiceDescribe = serde_json::from_slice(&bytes)?;
    StationConnectionBinding::from_description(base, &description, allow_insecure_loopback)?;
    Ok(description)
}

/// Credential-free discovery with independently configured deployment roots.
/// This keeps hostname verification and all bootstrap transport limits.
#[cfg(all(not(target_arch = "wasm32"), feature = "tls-rustls"))]
pub async fn fetch_station_description_with_roots(
    base: &Url,
    allow_insecure_loopback: bool,
    roots: &[reqwest::Certificate],
) -> Result<ServiceDescribe> {
    validate_connection_url(base, allow_insecure_loopback)?;
    let mut endpoint = base.join("_arkret/describe")?;
    endpoint
        .query_pairs_mut()
        .append_pair("service_kind", "station");
    let client = native_client(roots)?;
    let bytes = fetch_with_client(&client, &endpoint).await?;
    let description: ServiceDescribe = serde_json::from_slice(&bytes)?;
    StationConnectionBinding::from_description(base, &description, allow_insecure_loopback)?;
    Ok(description)
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch(endpoint: &Url) -> Result<Vec<u8>> {
    let client = crate::tls_roots::apply_explicit_tls_roots(native_builder())?
        .build()
        .map_err(crate::client_internals::transport_error)?;
    fetch_with_client(&client, endpoint).await
}

#[cfg(not(target_arch = "wasm32"))]
fn native_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(crate::SERVICE_RESOLUTION_FETCH_TIMEOUT)
        .gzip(false)
}

#[cfg(all(not(target_arch = "wasm32"), feature = "tls-rustls"))]
fn native_client(roots: &[reqwest::Certificate]) -> Result<reqwest::Client> {
    let builder = native_builder();
    let builder = if roots.is_empty() {
        crate::tls_roots::apply_explicit_tls_roots(builder)?
    } else {
        builder
            .tls_backend_rustls()
            .tls_certs_only(roots.iter().cloned())
    };
    builder
        .build()
        .map_err(crate::client_internals::transport_error)
}

#[cfg(not(target_arch = "wasm32"))]
async fn fetch_with_client(client: &reqwest::Client, endpoint: &Url) -> Result<Vec<u8>> {
    use crate::{SERVICE_DESCRIBE_FETCH_MAX_BYTES, SERVICE_RESOLUTION_FETCH_TIMEOUT};
    tokio::time::timeout(SERVICE_RESOLUTION_FETCH_TIMEOUT, async {
        let response = client
            .get(endpoint.clone())
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .header(
                crate::HEADER_OPERATION,
                arkret_wire::ServiceOperationId::SERVER_READ_DESCRIBE_V1,
            )
            .send()
            .await
            .map_err(crate::client_internals::transport_error)?;
        if !response.status().is_success()
            || response.url() != endpoint
            || response
                .headers()
                .contains_key(reqwest::header::CONTENT_ENCODING)
        {
            return Err(Error::Protocol(
                "Station describe rejected status, redirect or content encoding".into(),
            ));
        }
        crate::client_internals::read_body_limited(response, SERVICE_DESCRIBE_FETCH_MAX_BYTES).await
    })
    .await
    .map_err(|_| Error::Protocol("Station describe exceeded 5 seconds".into()))?
}

#[cfg(target_arch = "wasm32")]
async fn fetch(endpoint: &Url) -> Result<Vec<u8>> {
    station_description_bytes(endpoint.as_str())
        .await
        .map_err(|error| Error::Protocol(format!("Station describe: {error:?}")))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
export async function station_description_bytes(url) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    try {
        const response = await fetch(url, {
            method: 'GET', redirect: 'error', credentials: 'omit', cache: 'no-store',
            signal: controller.signal,
            headers: {'Arkret-Operation': 'ak.server.read.describe.v1'}
        });
        if (!response.ok || response.redirected || response.url !== url ||
            response.headers.has('Content-Encoding')) {
            throw new Error('Rejected Station status, redirect or content encoding');
        }
        if (Number(response.headers.get('Content-Length') || 0) > 1048576 || !response.body) {
            throw new Error('Invalid Station describe response size');
        }
        const reader = response.body.getReader();
        const chunks = [];
        let length = 0;
        for (;;) {
            const {done, value} = await reader.read();
            if (done) break;
            length += value.length;
            if (length > 1048576) {
                controller.abort();
                throw new Error('Station describe exceeds 1 MiB');
            }
            chunks.push(value);
        }
        const bytes = new Uint8Array(length);
        let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
        return bytes;
    } finally { clearTimeout(timeout); }
}
"#)]
extern "C" {
    #[wasm_bindgen(catch)]
    async fn station_description_bytes(
        url: &str,
    ) -> std::result::Result<Vec<u8>, wasm_bindgen::JsValue>;
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    async fn server(
        response: impl FnOnce(&Url) -> Vec<u8>,
    ) -> (Url, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let bytes = response(&base);
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = vec![0; 8192];
            let length = stream.read(&mut request).await.unwrap();
            let _ = stream.write_all(&bytes).await;
            String::from_utf8_lossy(&request[..length]).into_owned()
        });
        (base, task)
    }

    #[tokio::test]
    async fn station_bootstrap_fetches_only_public_describe_without_credentials_or_history() {
        let (base, task) = server(|base| {
            let mut describe = ServiceDescribe::development(
                arkret_wire::Did::new("did:webvh:z6mkfixture:station.example").unwrap(),
                arkret_wire::TrustDomainId::new("ak:trust_domain:station.example").unwrap(),
                arkret_wire::ServiceKind::Station,
                vec!["ak.operation_bundle.station.describe.v1".into()],
                vec![arkret_models_discovery::TransportBinding::HttpJson {
                    base_url: base.to_string(), extension_profile_required: (),
                }],
            );
            describe.auth_metadata.account_authority = Some(arkret_models_discovery::AccountAuthority {
                origin: arkret_wire::WebOrigin::new("https://auth.example").unwrap(),
                gate_account_base_url: "https://auth.example/_arkret/gate/account".into(),
                extra: Default::default(),
            });
            let body = serde_json::to_vec(&describe).unwrap();
            let mut bytes = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
            bytes.extend(body);
            bytes
        }).await;
        fetch_station_description(&base, true).await.unwrap();
        let request = task.await.unwrap().to_ascii_lowercase();
        assert!(request.starts_with("get /_arkret/describe?service_kind=station "));
        assert!(
            !request.contains("authorization:")
                && !request.contains("cookie:")
                && !request.contains("dpop:")
        );
    }

    #[tokio::test]
    async fn station_bootstrap_rejects_redirect_encoding_and_oversize() {
        for response in [
            "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/stolen\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n",
        ] {
            let (base, task) = server(|_| response.as_bytes().to_vec()).await;
            assert!(fetch_station_description(&base, true).await.is_err());
            task.await.unwrap();
        }
    }
}
