//! Native HTTP routing and credential isolation for public Directory reads.
#![cfg(not(target_arch = "wasm32"))]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use arkret_http_client::{Auth, Client, DpopAuth, HttpMessageSigner, RetryConfig};
use arkret_models_discovery::{
    DirectoryRealmSearchOutcome, DirectoryResolveRealmRequestBody, DirectoryResourceKind,
    DirectorySearchRealmsRequestBody, PublicRealmDirectoryEntry, PublicRealmMetadata,
    ServiceDescribe, TransportBinding,
};
use arkret_wire::{Did, DidCoreId, EventId, RealmId, ServiceKind, TrustDomainId};
use ed25519_dalek::SigningKey;

fn description(kind: ServiceKind) -> ServiceDescribe {
    let bundle = match kind {
        ServiceKind::DirectoryService => "ak.operation_bundle.directory_service.describe.v1",
        ServiceKind::Station => "ak.operation_bundle.station.describe.v1",
        _ => unreachable!("test fixture only covers Directory and Station"),
    };
    let mut description = ServiceDescribe::development(
        Did::new("did:web:directory.example").unwrap(),
        TrustDomainId::new("ak:trust_domain:directory.example").unwrap(),
        kind,
        vec![bundle.to_owned()],
        vec![TransportBinding::HttpJson {
            base_url: "https://directory.example".to_owned(),
            extension_profile_required: (),
        }],
    );
    if kind == ServiceKind::DirectoryService {
        description.resource_kinds = vec![DirectoryResourceKind::Realm];
    }
    description.validate().unwrap();
    description
}

fn serve(response: impl serde::Serialize) -> (url::Url, JoinHandle<String>) {
    let body = serde_json::to_vec(&response).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let request = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(stream) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("Directory request did not arrive: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0; 4096];
        while !request.windows(4).any(|part| part == b"\r\n\r\n") {
            let count = stream.read(&mut chunk).unwrap();
            assert!(count > 0, "Describe request ended before its headers");
            request.extend_from_slice(&chunk[..count]);
            assert!(request.len() < 64 * 1024, "unexpected oversized request");
        }
        let header_end = request
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap()
            + 4;
        let headers = std::str::from_utf8(&request[..header_end]).unwrap();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        assert!(
            content_length < 64 * 1024,
            "unexpected oversized request body"
        );
        while request.len() < header_end + content_length {
            let count = stream.read(&mut chunk).unwrap();
            assert!(count > 0, "Directory request ended before its body");
            request.extend_from_slice(&chunk[..count]);
        }
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(&body).unwrap();
        String::from_utf8(request).unwrap()
    });
    (base, request)
}

fn client(base: url::Url, credential: &str) -> Client {
    let auth = if credential == "dpop" {
        Auth::Dpop(DpopAuth::with_dpop_token("account-secret", |_| {
            panic!("public Directory read must not request DPoP")
        }))
    } else {
        Auth::Bearer("account-secret".to_owned())
    };
    let client = Client::builder(base)
        .allow_insecure_localhost()
        .auth(auth)
        .retry(RetryConfig::disabled())
        .build()
        .unwrap();
    if credential == "service" {
        client.with_service_http_signer(
            DidCoreId::new("ak:did_core:web:source.example").unwrap(),
            DidCoreId::new("ak:did_core:web:destination.example").unwrap(),
            HttpMessageSigner::new(
                "did:web:source.example#key",
                SigningKey::from_bytes(&[9; 32]),
            ),
        )
    } else {
        client
    }
}

fn assert_public_directory_request(request: &str) {
    let request = request.to_ascii_lowercase();
    assert_eq!(
        request.lines().next(),
        Some("get /_arkret/find/directory/describe http/1.1")
    );
    assert!(
        request
            .lines()
            .any(|line| { line == "arkret-operation: ak.find.directory.read.describe.v1" })
    );
    assert_no_credentials(&request);
}

fn assert_no_credentials(request: &str) {
    let headers = request
        .split_once("\r\n\r\n")
        .unwrap()
        .0
        .to_ascii_lowercase();
    for header in [
        "authorization:",
        "dpop:",
        "signature:",
        "signature-input:",
        "source-service-id:",
        "destination-service-id:",
    ] {
        assert!(
            !headers.lines().any(|line| line.starts_with(header)),
            "public Directory read leaked {header}: {headers}"
        );
    }
}

#[tokio::test]
async fn directory_describe_uses_registered_public_operation_for_both_entrypoints() {
    for dedicated in [false, true] {
        for credential in ["bearer", "dpop", "service"] {
            let expected = description(ServiceKind::DirectoryService);
            let (base, captured) = serve(expected.clone());
            let client = client(base, credential);
            let result = if dedicated {
                client.directory_describe().await
            } else {
                client
                    .describe_for_role(ServiceKind::DirectoryService)
                    .await
            };
            let request = captured.join().unwrap();
            assert_public_directory_request(&request);
            let actual = result.unwrap();
            assert_eq!(
                serde_json::to_value(actual).unwrap(),
                serde_json::to_value(expected).unwrap()
            );
        }
    }
}

#[tokio::test]
async fn directory_queries_use_public_operations_without_changing_typed_bodies() {
    let realm_id = RealmId::from_event_id(&EventId::from_digest(
        arkret_canonical::DigestSuite::Sha256,
        [7; 32],
    ));
    let entry = PublicRealmDirectoryEntry {
        realm_id: realm_id.clone(),
        public_metadata: PublicRealmMetadata {
            display_name: "Public Room".to_owned(),
            summary: Some("Public metadata only".to_owned()),
            public_locator: Some("https://station.example/rooms/public".to_owned()),
            avatar_blob_ref: None,
        },
        indexed_at: chrono::DateTime::from_timestamp(1_800_000_000, 0).unwrap(),
        expires_at: chrono::DateTime::from_timestamp(1_800_003_600, 0).unwrap(),
    };
    entry.validate().unwrap();
    for search in [false, true] {
        for credential in ["bearer", "dpop", "service"] {
            let (path, operation, expected_body, expected_response, actual_response, captured) =
                if search {
                    let selector = DirectorySearchRealmsRequestBody {
                        query: Some("Mixed Case & Room".to_owned()),
                        limit: Some(5),
                        cursor: Some("Page-A+/=".to_owned()),
                    };
                    selector.validate().unwrap();
                    let response = DirectoryRealmSearchOutcome {
                        realms: vec![entry.clone()],
                        has_more: false,
                        next_cursor: None,
                    };
                    response.validate().unwrap();
                    let (base, captured) = serve(&response);
                    let result = client(base, credential)
                        .directory_search_realms(&selector)
                        .await;
                    (
                        "/_arkret/find/directory/search-realms",
                        "ak.find.directory.read.search_realms.v1",
                        arkret_canonical::canonical::canonical_json_bytes(&selector).unwrap(),
                        serde_json::to_value(response).unwrap(),
                        result.map(|value| serde_json::to_value(value).unwrap()),
                        captured,
                    )
                } else {
                    let selector = DirectoryResolveRealmRequestBody {
                        realm_id: realm_id.clone(),
                    };
                    let (base, captured) = serve(&entry);
                    let result = client(base, credential)
                        .directory_resolve_realm(&selector)
                        .await;
                    (
                        "/_arkret/find/directory/resolve-realm",
                        "ak.find.directory.read.resolve_realm.v1",
                        arkret_canonical::canonical::canonical_json_bytes(&selector).unwrap(),
                        serde_json::to_value(&entry).unwrap(),
                        result.map(|value| serde_json::to_value(value).unwrap()),
                        captured,
                    )
                };
            let request = captured.join().unwrap();
            assert_no_credentials(&request);
            let (headers, body) = request.split_once("\r\n\r\n").unwrap();
            let headers = headers.to_ascii_lowercase();
            assert_eq!(
                headers.lines().next(),
                Some(format!("post {path} http/1.1").as_str())
            );
            assert!(
                headers
                    .lines()
                    .any(|line| line == format!("arkret-operation: {operation}"))
            );
            assert!(
                headers
                    .lines()
                    .any(|line| line == "content-type: application/json")
            );
            assert_eq!(body.as_bytes(), expected_body);
            assert_eq!(actual_response.unwrap(), expected_response);
        }
    }
}

#[tokio::test]
async fn directory_describe_rejects_valid_description_of_another_role() {
    for dedicated in [false, true] {
        let (base, captured) = serve(description(ServiceKind::Station));
        let client = client(base, "bearer");
        let result = if dedicated {
            client.directory_describe().await
        } else {
            client
                .describe_for_role(ServiceKind::DirectoryService)
                .await
        };
        assert_public_directory_request(&captured.join().unwrap());
        assert!(
            result.is_err(),
            "Directory endpoint accepted a Station role"
        );
    }
}

#[tokio::test]
async fn directory_describe_rejects_invalid_directory_overlay() {
    for dedicated in [false, true] {
        let mut malformed = description(ServiceKind::DirectoryService);
        malformed.resource_kinds.clear();
        assert!(malformed.validate().is_err());
        let (base, captured) = serve(malformed);
        let client = client(base, "bearer");
        let result = if dedicated {
            client.directory_describe().await
        } else {
            client
                .describe_for_role(ServiceKind::DirectoryService)
                .await
        };
        assert_public_directory_request(&captured.join().unwrap());
        assert!(
            result.is_err(),
            "Directory endpoint accepted invalid overlay"
        );
    }
}

#[tokio::test]
async fn shared_station_describe_preserves_registered_role_query() {
    let (base, captured) = serve(description(ServiceKind::Station));
    let result = client(base, "bearer")
        .describe_for_role(ServiceKind::Station)
        .await;
    let request = captured.join().unwrap().to_ascii_lowercase();
    assert_eq!(
        request.lines().next(),
        Some("get /_arkret/describe?service_kind=station http/1.1")
    );
    assert!(
        request
            .lines()
            .any(|line| { line == "arkret-operation: ak.server.read.describe.v1" })
    );
    assert!(!request.contains("authorization:"));
    assert_eq!(result.unwrap().service_kind, ServiceKind::Station);
}
