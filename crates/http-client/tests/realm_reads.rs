//! Real transport and request/response binding for registered Realm reads.
#![cfg(not(target_arch = "wasm32"))]
use std::io::{Read, Write};

use arkret_http_client::{Auth, Client, DpopAuth};
use arkret_models_collaboration::governance::realm_governance::{
    RealmLinkDirection, RealmLinkKind,
};
use arkret_wire::RealmId;
use serde_json::{Value, json};
const REALM: &str = "ak:realm:ATYL-87CDhaLQem29G2JQCXbZ_8zuu7khej2MbrsGLK6";
const OTHER: &str = "ak:realm:AS1N4QnbZ6JgVObAF-yTx1GWoK2XnO_vUaZ2qe0WCyQV";
fn server(
    path: String,
    operation: &'static str,
    body: Value,
) -> (Client, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        let mut bytes = Vec::new();
        while !bytes.windows(4).any(|v| v == b"\r\n\r\n") {
            let mut chunk = [0; 4096];
            let count = socket.read(&mut chunk).unwrap();
            assert!(count > 0);
            bytes.extend_from_slice(&chunk[..count]);
        }
        let original = String::from_utf8_lossy(&bytes);
        assert!(
            original.starts_with(&format!("GET {path} HTTP/1.1")),
            "{original}"
        );
        let head = original.to_ascii_lowercase();
        assert!(head.contains(&format!("arkret-operation: {operation}")));
        assert!(head.contains("authorization: dpop session-token"));
        assert!(head.contains("dpop: request-proof"));
        let body = body.to_string();
        write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    });
    let client = Client::builder(url::Url::parse(&format!("http://{address}")).unwrap())
        .allow_insecure_localhost()
        .auth(Auth::Dpop(DpopAuth::with_dpop_token(
            "session-token",
            |_| Ok("request-proof".into()),
        )))
        .build()
        .unwrap();
    (client, handle)
}
#[tokio::test]
async fn lifecycle_requires_closed_shape_unique_members_and_exact_realm() {
    let realm = RealmId::new(REALM).unwrap();
    let valid = json!({"realm_id":REALM,"owner_id":"ak:did_core:web:owner.example","member_ids":[],"deleted":false});
    let mut foreign = valid.clone();
    foreign["realm_id"] = json!(OTHER);
    let mut invalid = valid.clone();
    invalid["terminal_state"] = json!("invented");
    let mut missing = valid.clone();
    missing.as_object_mut().unwrap().remove("member_ids");
    let member = json!({"kind":"account","account_id":{"principal_id":"ak:did_core:web:owner.example","station_id":"ak:did_core:web:station.example"}});
    let mut duplicated = valid.clone();
    duplicated["member_ids"] = json!([member.clone(), member]);
    let mut null_terminal = valid.clone();
    null_terminal["terminal_state"] = Value::Null;
    let mut null_successor = valid.clone();
    null_successor["successor_realm_id"] = Value::Null;
    for (body, expected) in [
        (valid, true),
        (foreign, false),
        (invalid, false),
        (missing, false),
        (duplicated, false),
        (null_terminal, false),
        (null_successor, false),
    ] {
        let (client, handle) = server(
            format!("/_arkret/self/realms/{REALM}"),
            "ak.self.realm.resource.get.v1",
            body,
        );
        let result = client.realm_get(&realm).await;
        handle.join().unwrap();
        assert_eq!(result.is_ok(), expected, "{result:?}");
    }
}
#[tokio::test]
async fn export_binds_realm_and_preserves_withheld_rows() {
    let realm = RealmId::new(REALM).unwrap();
    for (id, expected) in [(REALM, true), (OTHER, false)] {
        let body = json!({"schema":"ak.export.realm.v1","realm_id":id,"generated_at":"2026-10-20T00:00:00.000Z","operations":[],"events":[{"event_disclosure":{"status":"withheld"}}]});
        let (client, handle) = server(
            format!("/_arkret/self/realms/{REALM}/export"),
            "ak.self.realm.read.export.v1",
            body,
        );
        let result = client.realm_export(&realm).await;
        handle.join().unwrap();
        assert_eq!(result.is_ok(), expected, "{result:?}");
    }
}
#[tokio::test]
async fn links_canonicalize_filters_and_bind_direction_endpoints_and_uniqueness() {
    let realm = RealmId::new(REALM).unwrap();
    let link = json!({"realm_id":REALM,"target_realm_id":OTHER,"link_kind":"governed_by","status":"active","created_at":"2026-10-20T00:00:00.000Z","updated_at":"2026-10-20T00:00:00.000Z"});
    let mut inbound = link.clone();
    inbound["realm_id"] = json!(OTHER);
    inbound["target_realm_id"] = json!(REALM);
    let mut wrong_kind = link.clone();
    wrong_kind["link_kind"] = json!("mirror_of");
    let mut null_label = link.clone();
    null_label["label"] = Value::Null;
    let mut null_commitment = link.clone();
    null_commitment["commitment"] = Value::Null;
    let mut long_label = link.clone();
    long_label["label"] = json!("x".repeat(257));
    let mut multiline = link.clone();
    multiline["label"] = json!("first\nsecond");
    for (direction, links, expected) in [
        ("outbound", vec![link.clone()], true),
        ("both", vec![], false),
        ("outbound", vec![inbound], false),
        ("outbound", vec![link.clone(), link], false),
        ("outbound", vec![wrong_kind], false),
        ("outbound", vec![null_label], false),
        ("outbound", vec![null_commitment], false),
        ("outbound", vec![long_label], false),
        ("outbound", vec![multiline], false),
    ] {
        let (client, handle) = server(
            format!(
                "/_arkret/self/realms/{REALM}/links?direction=outbound&link_kind_allow=governed_by"
            ),
            "ak.self.realm_link.read.list.v1",
            json!({"realm_id":REALM,"direction":direction,"links":links}),
        );
        let result = client
            .realm_links_list(
                &realm,
                RealmLinkDirection::Outbound,
                Some(&[
                    RealmLinkKind::parse("governed_by").unwrap(),
                    RealmLinkKind::parse("governed_by").unwrap(),
                ]),
            )
            .await;
        handle.join().unwrap();
        assert_eq!(result.is_ok(), expected, "{result:?}");
    }
}
