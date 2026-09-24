//! The holder-private `ak.account.invite_delivery` value stays
//! member-for-member isomorphic to `invite-delivery.schema.json`, including
//! each entry's untrusted `authority_locator_hints`.

use std::path::PathBuf;
use std::{fmt, fs};

use arkret_models_collaboration::governance::invite_addressing::{
    InviteDelivery, InviteDeliveryEntry,
};
use arkret_schema::ProtocolSchemaRegistry;
use arkret_schema_conformance::schema_registry_from_spec_artifacts;
use serde::Deserialize;
use serde::de::{Deserializer, IgnoredAny, MapAccess, Visitor};
use serde_json::{Value, json};

const SCHEMA_FILE: &str = "invite-delivery.schema.json";

fn artifacts_dir() -> PathBuf {
    arkret_schema_conformance::default_spec_artifacts_dir()
        .expect("the arkret-spec artifacts checkout must be reachable")
}

fn schema_text() -> String {
    let path = artifacts_dir().join("schemas").join(SCHEMA_FILE);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()))
}

fn schema_accepts(value: &Value) -> bool {
    let mut registry: ProtocolSchemaRegistry = schema_registry_from_spec_artifacts(artifacts_dir())
        .expect("the spec artifacts must produce a schema registry");
    let schema: Value = serde_json::from_str(&schema_text()).expect("schema must be valid JSON");
    registry
        .register_reference_document(schema.clone())
        .expect("schema document declares an absolute $id");
    registry.register("test:invite-delivery", schema);
    registry
        .validate_value("test:invite-delivery", value)
        .is_ok()
}

/// Object member names in document order; `serde_json::Value` would sort them.
struct OrderedKeys(Vec<String>);

impl<'de> Deserialize<'de> for OrderedKeys {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KeysVisitor;
        impl<'de> Visitor<'de> for KeysVisitor {
            type Value = OrderedKeys;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<OrderedKeys, A::Error> {
                let mut keys = Vec::new();
                while let Some(key) = map.next_key::<String>()? {
                    map.next_value::<IgnoredAny>()?;
                    keys.push(key);
                }
                Ok(OrderedKeys(keys))
            }
        }
        deserializer.deserialize_map(KeysVisitor)
    }
}

#[derive(Deserialize)]
struct PublishedObject {
    properties: OrderedKeys,
    required: Vec<String>,
}

#[derive(Deserialize)]
struct PublishedDefs {
    delivery_entry: PublishedObject,
}

#[derive(Deserialize)]
struct PublishedSchema {
    #[serde(flatten)]
    top_level: PublishedObject,
    #[serde(rename = "$defs")]
    defs: PublishedDefs,
}

fn published() -> PublishedSchema {
    serde_json::from_str(&schema_text()).expect("schema must parse")
}

fn hint(service_id: &str, source: &str) -> Value {
    json!({"service_kind": "station", "service_id": service_id, "source": source})
}

fn entry() -> Value {
    json!({
        "invite_id": "ak:invite:ASo6zC5lXw3GKOieKXlXJYfKoQKng4sYXtvdUAaE9WRB",
        "realm_id": "ak:realm:ATh7OWLLpUdTVYsKdp6rkClScUpjYJlF1Y3byjeyHS8J",
        "inviter_account_id": {
            "principal_id": "ak:did_core:web:alice.example",
            "station_id": "ak:did_core:web:station-a.example"
        },
        "invite_token": "opaque-private-locator-token",
        "authority_locator_hints": [
            hint("ak:did_core:web:a.example", "invite"),
            {
                "service_kind": "station",
                "service_id": "ak:did_core:web:b.example",
                "endpoint_url": "https://b.example/_arkret",
                "source": "invite"
            }
        ],
        "received_at": "2026-09-20T00:00:00.000Z",
        "expires_at": "2026-09-21T00:00:00.000Z"
    })
}

fn delivery_with(entry: Value) -> Value {
    json!({
        "schema": "ak.schema.invite_delivery.v1",
        "updated_at": "2026-09-20T00:00:00.000Z",
        "delivery_entries": [entry]
    })
}

fn sdk_accepts(value: &Value) -> bool {
    serde_json::from_value::<InviteDelivery>(value.clone())
        .is_ok_and(|delivery| delivery.validate().is_ok())
}

#[test]
fn delivery_value_matches_the_published_schema_member_for_member() {
    let value = delivery_with(entry());
    assert!(
        schema_accepts(&value),
        "schema rejected the canonical value"
    );

    let delivery: InviteDelivery =
        serde_json::from_value(value.clone()).expect("SDK accepts the canonical value");
    delivery.validate().expect("canonical value validates");
    assert_eq!(serde_json::to_value(&delivery).unwrap(), value);

    let published = published();
    let top: OrderedKeys =
        serde_json::from_str(&serde_json::to_string(&delivery).unwrap()).unwrap();
    assert_eq!(top.0, published.top_level.properties.0);
    let entry: OrderedKeys =
        serde_json::from_str(&serde_json::to_string(&delivery.delivery_entries[0]).unwrap())
            .unwrap();
    assert_eq!(
        entry.0, published.defs.delivery_entry.properties.0,
        "SDK entry member order must be the schema properties order"
    );
}

#[test]
fn every_required_entry_member_is_required_by_schema_and_sdk() {
    let required = published().defs.delivery_entry.required;
    assert!(
        required
            .iter()
            .any(|member| member == "authority_locator_hints")
    );
    for member in required {
        let mut value = entry();
        value.as_object_mut().unwrap().remove(&member);
        assert!(
            !schema_accepts(&delivery_with(value.clone())),
            "schema accepted entry without {member}"
        );
        assert!(
            serde_json::from_value::<InviteDeliveryEntry>(value).is_err(),
            "SDK accepted entry without {member}"
        );
    }
}

#[test]
fn entry_authority_locator_hints_follow_the_closed_array_contract() {
    let with_hints = |hints: Value| {
        let mut value = entry();
        value["authority_locator_hints"] = hints;
        delivery_with(value)
    };

    let empty = with_hints(json!([]));
    assert!(!schema_accepts(&empty));
    assert!(!sdk_accepts(&empty));

    let nine = with_hints(Value::Array(
        (0..9)
            .map(|index| hint(&format!("ak:did_core:web:s{index}.example"), "invite"))
            .collect(),
    ));
    assert!(!schema_accepts(&nine));
    assert!(!sdk_accepts(&nine));

    let a = hint("ak:did_core:web:a.example", "invite");
    let b = hint("ak:did_core:web:b.example", "directory");

    let exact_duplicate = with_hints(json!([a, a]));
    assert!(!schema_accepts(&exact_duplicate));
    assert!(!sdk_accepts(&exact_duplicate));

    let conflicting = with_hints(json!([a, hint("ak:did_core:web:a.example", "cache")]));
    assert!(!sdk_accepts(&conflicting));

    let reversed = with_hints(json!([b, a]));
    assert!(!sdk_accepts(&reversed));

    let mut retired = a.clone();
    retired["expires_at"] = json!("2026-09-21T00:00:00.000Z");
    let retired = with_hints(json!([retired]));
    assert!(!schema_accepts(&retired));
    assert!(serde_json::from_value::<InviteDelivery>(retired).is_err());

    let sorted = with_hints(json!([a, b]));
    assert!(schema_accepts(&sorted));
    assert!(sdk_accepts(&sorted));
}
