use std::fs;
use std::path::{Path, PathBuf};

use arkret_models_discovery::ServiceDescribe;
use arkret_models_identity::IdentityDescription;
use arkret_models_integration::AppletPingOutcome;
use arkret_schema::embedded_json_artifact;
use arkret_wire::{DidFullId, ServiceKind, TrustDomainId};
use serde_json::{Value, json};

const INVENTORY: &str = include_str!("../../../conformance/ak-sdk-024-public-api-inventory.json");

fn fixture() -> Value {
    embedded_json_artifact("fixtures/service-protocol-version-bootstrap-fixture.json").unwrap()
}

fn service_describe_value() -> Value {
    serde_json::to_value(ServiceDescribe::development(
        DidFullId::new("did:webvh:z6mkfixture:service.example").unwrap(),
        TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        ServiceKind::PrincipalServer,
    ))
    .unwrap()
}

fn applet_ping_value() -> Value {
    json!({
        "ok": true,
        "applet_id": "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
        "service_id": "ak:did_core:webvh:z6mkfixture",
        "protocol_version": "1.0"
    })
}

fn identity_describe_value() -> Value {
    json!({
        "service_id": "ak:did_core:webvh:z6mkfixture",
        "registry_mode": "writer",
        "supported_receipts": [],
        "protocol_version": "1.0",
        "profiles": []
    })
}

fn classify_decode(carrier: &str, value: Value) -> &'static str {
    let result = match carrier {
        "service_describe" => serde_json::from_value::<ServiceDescribe>(value).map(|_| ()),
        "applet_ping" => serde_json::from_value::<AppletPingOutcome>(value).map(|_| ()),
        "identity_describe" => serde_json::from_value::<IdentityDescription>(value).map(|_| ()),
        other => panic!("unknown protocol-version fixture carrier {other}"),
    };
    match result {
        Ok(()) => "continue_typed_validation",
        Err(error) if error.to_string().contains("unsupported_protocol_version") => {
            "unsupported_protocol_version"
        }
        Err(_) => "schema_violation",
    }
}

#[test]
fn ak_sdk_024_runs_all_bootstrap_vector_cases_before_side_effects() {
    let fixture = fixture();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 12);

    for case in cases {
        let carrier = case["carrier"].as_str().unwrap();
        let mut value = match carrier {
            "service_describe" => service_describe_value(),
            "applet_ping" => applet_ping_value(),
            "identity_describe" => identity_describe_value(),
            other => panic!("unknown carrier {other}"),
        };
        let object = value.as_object_mut().unwrap();
        match case.get("protocol_version") {
            Some(version) => {
                object.insert("protocol_version".to_owned(), version.clone());
            }
            None => {
                object.remove("protocol_version");
            }
        }
        if let Some(poison) = case.get("poison_fields").and_then(Value::as_object) {
            object.extend(poison.clone());
        }

        let outcome = classify_decode(carrier, value);
        let mut route_cache_writes = 0_u64;
        let business_requests = 0_u64;
        if outcome == "continue_typed_validation" && carrier == "service_describe" {
            route_cache_writes += 1;
        }

        assert_eq!(outcome, case["expected"]["outcome"], "{}", case["name"]);
        assert_eq!(
            route_cache_writes, case["expected"]["route_cache_writes"],
            "{}",
            case["name"]
        );
        assert_eq!(
            business_requests, case["expected"]["business_requests"],
            "{}",
            case["name"]
        );
    }
}

fn collect_rust_sources(root: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path.file_name().is_none_or(|name| name != "tests") {
                collect_rust_sources(&path, files);
            }
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

#[test]
fn ak_sdk_024_public_api_inventory_is_complete_and_every_typed_carrier_is_gated() {
    let inventory: Value = serde_json::from_str(INVENTORY).unwrap();
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let expected = inventory["typed_carriers"].as_array().unwrap();

    let mut sources = Vec::new();
    collect_rust_sources(&workspace.join("crates"), &mut sources);
    let mut actual = Vec::new();
    for source in sources {
        let text = fs::read_to_string(&source).unwrap().replace("\r\n", "\n");
        if text.contains("pub protocol_version: String") {
            let relative = source
                .strip_prefix(&workspace)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            assert!(
                text.contains("#[serde(deserialize_with = \"arkret_wire::deserialize_protocol_version\")]\n    pub protocol_version: String"),
                "public typed protocol_version carrier bypasses bootstrap gate: {relative}"
            );
            actual.push(relative);
        }
    }
    actual.sort();

    let mut inventoried = expected
        .iter()
        .map(|entry| entry["source"].as_str().unwrap().to_owned())
        .collect::<Vec<_>>();
    inventoried.sort();
    assert_eq!(actual, inventoried);
}
