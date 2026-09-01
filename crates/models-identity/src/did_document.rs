//! DID Document data shape and did:web helpers.
//!
//! Identity behavior crates (`arkret-identity`, `arkret-auth`) operate directly
//! on this owner-defined model. The `arkret::identity::*` surface remains
//! available to application consumers.
//!
//! Behavior that needs signature verification, DID resolution, or state
//! reduction lives in the behavior crates; this module holds
//! the DID Document serde shape, its type-local helpers, and the pure did:web
//! document-URL derivation only.

use std::collections::BTreeMap;

use arkret_wire::{Did, DidCoreId, Result, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const DID_WEB_MAX_DOCUMENT_BYTES: usize = 64 * 1024;
pub const DID_WEBVH_V1_METHOD: &str = "did:webvh:1.0";

pub fn validate_did_webvh_v1_method(parameters: &Value) -> Result<()> {
    if parameters.get("method").and_then(Value::as_str) != Some(DID_WEBVH_V1_METHOD) {
        return Err(WireError::Protocol(
            "unsupported_did_method: expected did:webvh:1.0".to_owned(),
        ));
    }
    Ok(())
}

pub fn did_web_document_url(did: &Did) -> Result<String> {
    if did.method() != "web" {
        return Err(WireError::Protocol("DID method is not did:web".to_owned()));
    }
    let method_id = did
        .as_str()
        .strip_prefix("did:web:")
        .ok_or_else(|| WireError::Protocol("invalid did:web identifier".to_owned()))?;
    let mut parts = method_id.split(':');
    let encoded_authority = parts
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| WireError::Protocol("did:web authority is empty".to_owned()))?;
    let authority = encoded_authority.replace("%3A", ":").replace("%3a", ":");
    let path: Vec<&str> = parts.collect();
    if path.iter().any(|segment| {
        segment.is_empty()
            || segment.contains('/')
            || segment.contains("..")
            || segment.contains('?')
            || segment.contains('#')
    }) {
        return Err(WireError::Protocol(
            "did:web contains an invalid path segment".to_owned(),
        ));
    }
    let raw = if path.is_empty() {
        format!("https://{authority}/.well-known/did.json")
    } else {
        format!("https://{authority}/{}/did.json", path.join("/"))
    };
    let parsed =
        url::Url::parse(&raw).map_err(|_| WireError::Protocol("invalid did:web URL".to_owned()))?;
    let host = parsed
        .host_str()
        .filter(|host| host.contains('.'))
        .ok_or_else(|| WireError::Protocol("invalid did:web host".to_owned()))?;
    if !host.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
    }) {
        return Err(WireError::Protocol("invalid did:web host".to_owned()));
    }
    Ok(parsed.to_string())
}

/// Issuer proof attached to a handle-claim challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandleAttestation {
    pub issuer_id: DidCoreId,
    pub proof: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

/// Shared identity wire helper for DID resolution producers/consumers.
///
/// This is intentionally a product/shared contract, not the normative DID
/// data model for the SDK. The protocol response envelope
/// (`IdentityResolveOutcome`) while this type provides the
/// serde shape and convenience helpers used by identity resolvers.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct DidDocument {
    pub id: Did,
    pub verification_methods: BTreeMap<String, String>,
    pub also_known_as: Vec<String>,
    pub updated_at: Option<DateTime<Utc>>,
    /// Exact DID Document properties received on the wire. This preserves
    /// standard relationships, services, contexts, controller declarations,
    /// and extension properties that the convenience indexes above do not
    /// interpret.
    pub raw_properties: BTreeMap<String, Value>,
}

const W3C_DOCUMENT_MEMBERS: &[&str] = &[
    "@context",
    "id",
    "controller",
    "alsoKnownAs",
    "verificationMethod",
    "authentication",
    "assertionMethod",
    "keyAgreement",
    "capabilityInvocation",
    "capabilityDelegation",
    "service",
    "metadata",
    // `updated` is resolution/convenience metadata, not part of the normalized
    // DID Document projection registered by Arkret v1.
    "updated",
];

const NORMALIZED_DOCUMENT_MEMBERS: &[&str] = &[
    "did",
    "contexts",
    "controller_dids",
    "also_known_as",
    "verification_methods",
    "authentication",
    "assertion_methods",
    "key_agreements",
    "capability_invocations",
    "capability_delegations",
    "services",
    "metadata",
    "extensions",
];

fn protocol_error(detail: impl Into<String>) -> WireError {
    WireError::Protocol(format!(
        "normalized DID document projection failed: {}",
        detail.into()
    ))
}

fn sorted_unique_strings(field: &str, value: Option<&Value>) -> Result<Vec<Value>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = match value {
        Value::String(value) => vec![value.clone()],
        Value::Array(values) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| protocol_error(format!("{field} contains a non-string value")))
            })
            .collect::<Result<Vec<_>>>()?,
        _ => return Err(protocol_error(format!("{field} must be a string or array"))),
    };
    let mut sorted = values;
    sorted.sort();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(protocol_error(format!(
            "{field} contains a duplicate value"
        )));
    }
    Ok(sorted.into_iter().map(Value::String).collect())
}

fn normalized_extensions(source: &serde_json::Map<String, Value>, known: &[&str]) -> Vec<Value> {
    source
        .iter()
        .filter(|(name, _)| !known.contains(&name.as_str()))
        .map(|(name, value)| {
            serde_json::json!({
                "name": name,
                "value": value,
            })
        })
        .collect()
}

fn normalize_extension_rows(field: &str, value: Option<&Value>) -> Result<Vec<Value>> {
    let Some(Value::Array(rows)) = value else {
        return if value.is_none() {
            Ok(Vec::new())
        } else {
            Err(protocol_error(format!("{field} must be an array")))
        };
    };
    let mut normalized = Vec::with_capacity(rows.len());
    for row in rows {
        let object = row
            .as_object()
            .ok_or_else(|| protocol_error(format!("{field} contains a non-object row")))?;
        if object.len() != 2 || !object.contains_key("name") || !object.contains_key("value") {
            return Err(protocol_error(format!(
                "{field} rows must contain exactly name and value"
            )));
        }
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| protocol_error(format!("{field} contains an invalid name")))?;
        normalized.push(serde_json::json!({
            "name": name,
            "value": object.get("value").expect("checked above"),
        }));
    }
    normalized.sort_by(|left, right| {
        left["name"]
            .as_str()
            .expect("normalized extension name")
            .cmp(right["name"].as_str().expect("normalized extension name"))
    });
    if normalized
        .windows(2)
        .any(|pair| pair[0]["name"] == pair[1]["name"])
    {
        return Err(protocol_error(format!(
            "{field} contains a duplicate extension name"
        )));
    }
    Ok(normalized)
}

fn normalize_w3c_verification_method(value: &Value) -> Result<Value> {
    let method = value
        .as_object()
        .ok_or_else(|| protocol_error("verificationMethod contains a non-object entry"))?;
    let verification_method = method
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| protocol_error("verificationMethod entry omits id"))?;
    let controller_did = method
        .get("controller")
        .and_then(Value::as_str)
        .ok_or_else(|| protocol_error("verificationMethod entry omits controller"))?;
    let verification_method_suite = method
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| protocol_error("verificationMethod entry omits type"))?;
    let public_key_material = method
        .iter()
        .filter(|(name, _)| name.starts_with("publicKey"))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<serde_json::Map<_, _>>();
    if public_key_material.is_empty() {
        return Err(protocol_error(
            "verificationMethod entry omits registered public-key material",
        ));
    }
    let extensions = method
        .iter()
        .filter(|(name, _)| {
            !["id", "controller", "type"].contains(&name.as_str()) && !name.starts_with("publicKey")
        })
        .map(|(name, value)| serde_json::json!({ "name": name, "value": value }))
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "verification_method": verification_method,
        "controller_did": controller_did,
        "verification_method_suite": verification_method_suite,
        "public_key_material": public_key_material,
        "extensions": extensions,
    }))
}

fn normalize_projection_verification_method(value: &Value) -> Result<Value> {
    let method = value
        .as_object()
        .ok_or_else(|| protocol_error("verification_methods contains a non-object entry"))?;
    let verification_method = method
        .get("verification_method")
        .and_then(Value::as_str)
        .ok_or_else(|| protocol_error("verification_methods entry omits verification_method"))?;
    let controller_did = method
        .get("controller_did")
        .and_then(Value::as_str)
        .ok_or_else(|| protocol_error("verification_methods entry omits controller_did"))?;
    let verification_method_suite = method
        .get("verification_method_suite")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            protocol_error("verification_methods entry omits verification_method_suite")
        })?;
    let public_key_material = method
        .get("public_key_material")
        .and_then(Value::as_object)
        .filter(|material| !material.is_empty())
        .ok_or_else(|| protocol_error("verification_methods entry omits public_key_material"))?;
    if method.keys().any(|name| {
        ![
            "verification_method",
            "controller_did",
            "verification_method_suite",
            "public_key_material",
            "extensions",
        ]
        .contains(&name.as_str())
    }) {
        return Err(protocol_error(
            "verification_methods entry contains an unknown member",
        ));
    }
    Ok(serde_json::json!({
        "verification_method": verification_method,
        "controller_did": controller_did,
        "verification_method_suite": verification_method_suite,
        "public_key_material": public_key_material,
        "extensions": normalize_extension_rows(
            "verification_methods.extensions",
            method.get("extensions"),
        )?,
    }))
}

fn insert_verification_method(methods: &mut BTreeMap<String, Value>, method: Value) -> Result<()> {
    let id = method["verification_method"]
        .as_str()
        .expect("normalized verification method id")
        .to_owned();
    if methods.insert(id.clone(), method).is_some() {
        return Err(protocol_error(format!(
            "duplicate verification method {id}"
        )));
    }
    Ok(())
}

fn normalize_relationship(
    field: &str,
    value: Option<&Value>,
    methods: &mut BTreeMap<String, Value>,
) -> Result<Vec<Value>> {
    let Some(Value::Array(entries)) = value else {
        return if value.is_none() {
            Ok(Vec::new())
        } else {
            Err(protocol_error(format!("{field} must be an array")))
        };
    };
    let mut ids = Vec::with_capacity(entries.len());
    for entry in entries {
        let id = if let Some(id) = entry.as_str() {
            id.to_owned()
        } else {
            let method = normalize_w3c_verification_method(entry)?;
            let id = method["verification_method"]
                .as_str()
                .expect("normalized verification method id")
                .to_owned();
            insert_verification_method(methods, method)?;
            id
        };
        ids.push(id);
    }
    ids.sort();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(protocol_error(format!(
            "{field} contains a duplicate entry"
        )));
    }
    for id in &ids {
        if !methods.contains_key(id) {
            return Err(protocol_error(format!(
                "{field} references unknown verification method {id}"
            )));
        }
    }
    Ok(ids
        .into_iter()
        .map(
            |verification_method| serde_json::json!({ "verification_method": verification_method }),
        )
        .collect())
}

fn normalize_projection_relationship(
    field: &str,
    value: Option<&Value>,
    methods: &BTreeMap<String, Value>,
) -> Result<Vec<Value>> {
    let Some(Value::Array(entries)) = value else {
        return if value.is_none() {
            Ok(Vec::new())
        } else {
            Err(protocol_error(format!("{field} must be an array")))
        };
    };
    let mut ids = entries
        .iter()
        .map(|entry| {
            let object = entry
                .as_object()
                .filter(|object| object.len() == 1)
                .ok_or_else(|| protocol_error(format!("{field} contains an invalid entry")))?;
            object
                .get("verification_method")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| protocol_error(format!("{field} entry omits verification_method")))
        })
        .collect::<Result<Vec<_>>>()?;
    ids.sort();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(protocol_error(format!(
            "{field} contains a duplicate entry"
        )));
    }
    for id in &ids {
        if !methods.contains_key(id) {
            return Err(protocol_error(format!(
                "{field} references unknown verification method {id}"
            )));
        }
    }
    Ok(ids
        .into_iter()
        .map(
            |verification_method| serde_json::json!({ "verification_method": verification_method }),
        )
        .collect())
}

fn normalize_w3c_services(value: Option<&Value>) -> Result<Vec<Value>> {
    let Some(Value::Array(services)) = value else {
        return if value.is_none() {
            Ok(Vec::new())
        } else {
            Err(protocol_error("service must be an array"))
        };
    };
    let mut normalized = Vec::with_capacity(services.len());
    for service in services {
        let object = service
            .as_object()
            .ok_or_else(|| protocol_error("service contains a non-object entry"))?;
        let uri = object
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| protocol_error("service entry omits id"))?;
        let protocol_names = sorted_unique_strings("service.type", object.get("type"))?;
        if protocol_names.is_empty() {
            return Err(protocol_error("service entry has no type"));
        }
        let endpoint = object
            .get("serviceEndpoint")
            .ok_or_else(|| protocol_error("service entry omits serviceEndpoint"))?;
        normalized.push(serde_json::json!({
            "uri": uri,
            "protocol_names": protocol_names,
            "endpoint": endpoint,
            "extensions": normalized_extensions(
                object,
                &["id", "type", "serviceEndpoint"],
            ),
        }));
    }
    normalized.sort_by(|left, right| {
        left["uri"]
            .as_str()
            .expect("normalized service uri")
            .cmp(right["uri"].as_str().expect("normalized service uri"))
    });
    if normalized
        .windows(2)
        .any(|pair| pair[0]["uri"] == pair[1]["uri"])
    {
        return Err(protocol_error("service contains a duplicate id"));
    }
    Ok(normalized)
}

fn normalize_projection_services(value: Option<&Value>) -> Result<Vec<Value>> {
    let Some(Value::Array(services)) = value else {
        return if value.is_none() {
            Ok(Vec::new())
        } else {
            Err(protocol_error("services must be an array"))
        };
    };
    let mut normalized = Vec::with_capacity(services.len());
    for service in services {
        let object = service
            .as_object()
            .ok_or_else(|| protocol_error("services contains a non-object entry"))?;
        if object.keys().any(|name| {
            !["uri", "protocol_names", "endpoint", "extensions"].contains(&name.as_str())
        }) {
            return Err(protocol_error("services entry contains an unknown member"));
        }
        let uri = object
            .get("uri")
            .and_then(Value::as_str)
            .ok_or_else(|| protocol_error("services entry omits uri"))?;
        let protocol_names =
            sorted_unique_strings("services.protocol_names", object.get("protocol_names"))?;
        if protocol_names.is_empty() {
            return Err(protocol_error("services entry has no protocol_names"));
        }
        let endpoint = object
            .get("endpoint")
            .ok_or_else(|| protocol_error("services entry omits endpoint"))?;
        normalized.push(serde_json::json!({
            "uri": uri,
            "protocol_names": protocol_names,
            "endpoint": endpoint,
            "extensions": normalize_extension_rows("services.extensions", object.get("extensions"))?,
        }));
    }
    normalized.sort_by(|left, right| {
        left["uri"]
            .as_str()
            .expect("normalized service uri")
            .cmp(right["uri"].as_str().expect("normalized service uri"))
    });
    if normalized
        .windows(2)
        .any(|pair| pair[0]["uri"] == pair[1]["uri"])
    {
        return Err(protocol_error("services contains a duplicate uri"));
    }
    Ok(normalized)
}

fn normalized_metadata(value: Option<&Value>) -> Result<Value> {
    let Some(value) = value else {
        return Ok(serde_json::json!({}));
    };
    let object = value
        .as_object()
        .ok_or_else(|| protocol_error("metadata must be an object"))?;
    if object.keys().any(|name| name != "primary_handle") {
        return Err(protocol_error("metadata contains an unknown member"));
    }
    if let Some(primary_handle) = object.get("primary_handle")
        && primary_handle.as_str().is_none()
    {
        return Err(protocol_error("metadata.primary_handle must be a string"));
    }
    Ok(Value::Object(object.clone()))
}

fn convenience_verification_methods(document: &DidDocument) -> Result<BTreeMap<String, Value>> {
    let mut methods = BTreeMap::new();
    for (key_id, public_key) in &document.verification_methods {
        let verification_method = if key_id.starts_with("did:") && key_id.contains('#') {
            key_id.clone()
        } else {
            format!("{}#{}", document.id, key_id.trim_start_matches('#'))
        };
        insert_verification_method(
            &mut methods,
            serde_json::json!({
                "verification_method": verification_method,
                "controller_did": document.id,
                "verification_method_suite": "Multikey",
                "public_key_material": { "publicKeyMultibase": public_key },
                "extensions": [],
            }),
        )?;
    }
    Ok(methods)
}

fn normalize_w3c_document(document: &DidDocument) -> Result<Value> {
    let properties = document
        .raw_properties
        .clone()
        .into_iter()
        .collect::<serde_json::Map<_, _>>();
    if properties.contains_key("did")
        || properties.contains_key("contexts")
        || properties.contains_key("verification_methods")
    {
        return Err(protocol_error(
            "raw W3C document mixes normalized projection member names",
        ));
    }
    if properties
        .get("id")
        .and_then(Value::as_str)
        .is_some_and(|id| id != document.id.as_str())
    {
        return Err(protocol_error("id differs from the verified DID"));
    }

    let contexts = match properties.get("@context") {
        None => Vec::new(),
        Some(Value::Array(contexts)) => contexts.clone(),
        Some(Value::String(context)) => vec![Value::String(context.clone())],
        Some(_) => return Err(protocol_error("@context must be a string or array")),
    };
    if contexts
        .iter()
        .any(|context| !context.is_string() && !context.is_object())
    {
        return Err(protocol_error("@context contains an invalid value"));
    }
    let controller_dids = sorted_unique_strings("controller", properties.get("controller"))?;
    let also_known_as = if properties.contains_key("alsoKnownAs") {
        let raw_aliases = properties
            .get("alsoKnownAs")
            .and_then(Value::as_array)
            .and_then(|aliases| {
                aliases
                    .iter()
                    .map(Value::as_str)
                    .collect::<Option<Vec<_>>>()
            })
            .ok_or_else(|| protocol_error("alsoKnownAs must be a string array"))?;
        if raw_aliases
            != document
                .also_known_as
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
        {
            return Err(protocol_error(
                "alsoKnownAs differs from the verified convenience index",
            ));
        }
        sorted_unique_strings("alsoKnownAs", properties.get("alsoKnownAs"))?
    } else {
        let mut aliases = document.also_known_as.clone();
        aliases.sort();
        if aliases.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(protocol_error("alsoKnownAs contains a duplicate value"));
        }
        aliases.into_iter().map(Value::String).collect()
    };

    let mut methods = if let Some(raw_methods) = properties.get("verificationMethod") {
        let raw_index = verification_method_index(raw_methods).map_err(protocol_error)?;
        if raw_index != document.verification_methods {
            return Err(protocol_error(
                "verificationMethod differs from the verified convenience index",
            ));
        }
        match raw_methods {
            Value::Array(raw_methods) => {
                let mut methods = BTreeMap::new();
                for method in raw_methods {
                    let method = normalize_w3c_verification_method(method)?;
                    insert_verification_method(&mut methods, method)?;
                }
                methods
            }
            Value::Object(_) => convenience_verification_methods(document)?,
            _ => return Err(protocol_error("verificationMethod must be an array")),
        }
    } else {
        convenience_verification_methods(document)?
    };

    let authentication = normalize_relationship(
        "authentication",
        properties.get("authentication"),
        &mut methods,
    )?;
    let assertion_methods = normalize_relationship(
        "assertionMethod",
        properties.get("assertionMethod"),
        &mut methods,
    )?;
    let key_agreements =
        normalize_relationship("keyAgreement", properties.get("keyAgreement"), &mut methods)?;
    let capability_invocations = normalize_relationship(
        "capabilityInvocation",
        properties.get("capabilityInvocation"),
        &mut methods,
    )?;
    let capability_delegations = normalize_relationship(
        "capabilityDelegation",
        properties.get("capabilityDelegation"),
        &mut methods,
    )?;

    Ok(serde_json::json!({
        "did": document.id,
        "contexts": contexts,
        "controller_dids": controller_dids,
        "also_known_as": also_known_as,
        "verification_methods": methods.into_values().collect::<Vec<_>>(),
        "authentication": authentication,
        "assertion_methods": assertion_methods,
        "key_agreements": key_agreements,
        "capability_invocations": capability_invocations,
        "capability_delegations": capability_delegations,
        "services": normalize_w3c_services(properties.get("service"))?,
        "metadata": normalized_metadata(properties.get("metadata"))?,
        "extensions": normalized_extensions(&properties, W3C_DOCUMENT_MEMBERS),
    }))
}

fn normalize_projection_document(document: &DidDocument) -> Result<Value> {
    let properties = document
        .raw_properties
        .clone()
        .into_iter()
        .collect::<serde_json::Map<_, _>>();
    if properties.contains_key("id")
        || properties.contains_key("@context")
        || properties.contains_key("verificationMethod")
    {
        return Err(protocol_error(
            "normalized projection mixes raw W3C member names",
        ));
    }
    if properties
        .get("did")
        .and_then(Value::as_str)
        .is_none_or(|did| did != document.id.as_str())
    {
        return Err(protocol_error("did differs from the verified DID"));
    }
    if properties
        .keys()
        .any(|name| !NORMALIZED_DOCUMENT_MEMBERS.contains(&name.as_str()))
    {
        return Err(protocol_error(
            "normalized projection contains an unknown top-level member",
        ));
    }

    let contexts = properties
        .get("contexts")
        .and_then(Value::as_array)
        .ok_or_else(|| protocol_error("contexts must be an array"))?
        .clone();
    if contexts
        .iter()
        .any(|context| !context.is_string() && !context.is_object())
    {
        return Err(protocol_error("contexts contains an invalid value"));
    }
    let controller_dids =
        sorted_unique_strings("controller_dids", properties.get("controller_dids"))?;
    let also_known_as = sorted_unique_strings("also_known_as", properties.get("also_known_as"))?;

    let raw_methods = properties
        .get("verification_methods")
        .and_then(Value::as_array)
        .ok_or_else(|| protocol_error("verification_methods must be an array"))?;
    let mut methods = BTreeMap::new();
    for method in raw_methods {
        let method = normalize_projection_verification_method(method)?;
        insert_verification_method(&mut methods, method)?;
    }
    let method_values = methods.values().cloned().collect::<Vec<_>>();
    let raw_index = normalized_verification_method_index(&Value::Array(method_values.clone()))
        .map_err(protocol_error)?;
    if raw_index != document.verification_methods {
        return Err(protocol_error(
            "verification_methods differs from the verified convenience index",
        ));
    }
    let raw_aliases = properties
        .get("also_known_as")
        .and_then(Value::as_array)
        .and_then(|aliases| {
            aliases
                .iter()
                .map(Value::as_str)
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| protocol_error("also_known_as must be a string array"))?;
    if raw_aliases
        != document
            .also_known_as
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    {
        return Err(protocol_error(
            "also_known_as differs from the verified convenience index",
        ));
    }

    Ok(serde_json::json!({
        "did": document.id,
        "contexts": contexts,
        "controller_dids": controller_dids,
        "also_known_as": also_known_as,
        "verification_methods": method_values,
        "authentication": normalize_projection_relationship(
            "authentication",
            properties.get("authentication"),
            &methods,
        )?,
        "assertion_methods": normalize_projection_relationship(
            "assertion_methods",
            properties.get("assertion_methods"),
            &methods,
        )?,
        "key_agreements": normalize_projection_relationship(
            "key_agreements",
            properties.get("key_agreements"),
            &methods,
        )?,
        "capability_invocations": normalize_projection_relationship(
            "capability_invocations",
            properties.get("capability_invocations"),
            &methods,
        )?,
        "capability_delegations": normalize_projection_relationship(
            "capability_delegations",
            properties.get("capability_delegations"),
            &methods,
        )?,
        "services": normalize_projection_services(properties.get("services"))?,
        "metadata": normalized_metadata(properties.get("metadata"))?,
        "extensions": normalize_extension_rows("extensions", properties.get("extensions"))?,
    }))
}

/// Construct the sole Arkret v1 normalized DID Document projection used by
/// `document_digest`. Resolver/convenience metadata such as `updated` is
/// deliberately outside this preimage; unknown DID Document extensions remain
/// losslessly bound through sorted extension rows.
pub fn normalized_did_document(document: &DidDocument) -> Result<Value> {
    document.validate()?;
    if document.raw_properties.contains_key("did") {
        normalize_projection_document(document)
    } else {
        normalize_w3c_document(document)
    }
}

/// Compute the only Arkret v1 `document_digest`: SHA-256 over RFC 8785 JCS of
/// [`normalized_did_document`]. Raw resolver bytes, when retained as internal
/// evidence, use the separately named `raw_document_digest` contract.
pub fn normalized_did_document_digest(document: &DidDocument) -> Result<arkret_wire::Hash> {
    Ok(arkret_wire::Hash::new(arkret_canonical::canonical_sha256(
        &normalized_did_document(document)?,
    )?)?)
}

fn verification_method_index(
    value: &Value,
) -> std::result::Result<BTreeMap<String, String>, String> {
    match value {
        Value::Object(methods) => Ok(methods
            .iter()
            .map(|(key_id, key_value)| {
                let public_key = key_value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| key_value.to_string());
                (key_id.clone(), public_key)
            })
            .collect()),
        Value::Array(methods) => {
            let mut out = BTreeMap::new();
            for method in methods {
                if let Value::Object(object) = method {
                    let Some(key_id) = object
                        .get("id")
                        .and_then(|value| value.as_str())
                        .map(ToOwned::to_owned)
                    else {
                        continue;
                    };
                    let public_key = object
                        .get("publicKeyMultibase")
                        .or_else(|| object.get("publicKeyJwk"))
                        .map(|value| {
                            value
                                .as_str()
                                .map(ToOwned::to_owned)
                                .unwrap_or_else(|| value.to_string())
                        })
                        .unwrap_or_default();
                    out.insert(key_id, public_key);
                }
            }
            Ok(out)
        }
        Value::Null => Ok(BTreeMap::new()),
        other => Err(format!(
            "verificationMethod must be an object or array, got {other}"
        )),
    }
}

fn normalized_verification_method_index(
    value: &Value,
) -> std::result::Result<BTreeMap<String, String>, String> {
    let Value::Array(methods) = value else {
        return Err("verification_methods must be an array".to_owned());
    };
    let mut out = BTreeMap::new();
    for method in methods {
        let Value::Object(object) = method else {
            continue;
        };
        let Some(key_id) = object
            .get("verification_method")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
        else {
            continue;
        };
        let public_key = object
            .get("public_key_material")
            .and_then(Value::as_object)
            .and_then(|material| {
                material
                    .get("publicKeyMultibase")
                    .or_else(|| material.get("publicKeyJwk"))
                    .or_else(|| material.values().next())
            })
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| value.to_string())
            })
            .unwrap_or_default();
        out.insert(key_id, public_key);
    }
    Ok(out)
}

impl Serialize for DidDocument {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut properties = self.raw_properties.clone();
        if properties.contains_key("did") && !properties.contains_key("id") {
            properties.insert("did".to_owned(), Value::String(self.id.to_string()));
            return properties.serialize(serializer);
        }
        properties.insert("id".to_owned(), Value::String(self.id.to_string()));

        let keep_raw_verification_methods = properties
            .get("verificationMethod")
            .and_then(|value| verification_method_index(value).ok())
            .is_some_and(|index| index == self.verification_methods);
        if !keep_raw_verification_methods {
            if self.verification_methods.is_empty() {
                properties.remove("verificationMethod");
            } else {
                properties.insert(
                    "verificationMethod".to_owned(),
                    serde_json::to_value(&self.verification_methods)
                        .map_err(serde::ser::Error::custom)?,
                );
            }
        }

        let keep_raw_aliases = properties
            .get("alsoKnownAs")
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items.iter().map(Value::as_str).collect::<Option<Vec<_>>>()
                    == Some(self.also_known_as.iter().map(String::as_str).collect())
            });
        if !keep_raw_aliases {
            if self.also_known_as.is_empty() {
                properties.remove("alsoKnownAs");
            } else {
                properties.insert(
                    "alsoKnownAs".to_owned(),
                    serde_json::to_value(&self.also_known_as).map_err(serde::ser::Error::custom)?,
                );
            }
        }

        let keep_raw_updated = properties
            .get("updated")
            .cloned()
            .and_then(|value| serde_json::from_value::<DateTime<Utc>>(value).ok())
            .as_ref()
            == self.updated_at.as_ref();
        match (self.updated_at.as_ref(), keep_raw_updated) {
            (Some(_), true) => {}
            (Some(updated_at), false) => {
                properties.insert(
                    "updated".to_owned(),
                    serde_json::to_value(updated_at).map_err(serde::ser::Error::custom)?,
                );
            }
            (None, _) => {
                properties.remove("updated");
            }
        }
        properties.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DidDocument {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw_properties = BTreeMap::<String, Value>::deserialize(deserializer)?;
        let id = raw_properties
            .get("id")
            .or_else(|| raw_properties.get("did"))
            .cloned()
            .ok_or_else(|| serde::de::Error::custom("missing field `id` or `did`"))
            .and_then(|value| serde_json::from_value(value).map_err(serde::de::Error::custom))?;
        let verification_methods = raw_properties
            .get("verificationMethod")
            .map(verification_method_index)
            .or_else(|| {
                raw_properties
                    .get("verification_methods")
                    .map(normalized_verification_method_index)
            })
            .transpose()
            .map_err(serde::de::Error::custom)?
            .unwrap_or_default();
        let also_known_as = raw_properties
            .get("alsoKnownAs")
            .or_else(|| raw_properties.get("also_known_as"))
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(serde::de::Error::custom)?
            .unwrap_or_default();
        let updated_at = raw_properties
            .get("updated")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(serde::de::Error::custom)?;
        Ok(Self {
            id,
            verification_methods,
            also_known_as,
            updated_at,
            raw_properties,
        })
    }
}

impl DidDocument {
    pub fn new(id: Did, key_id: impl Into<String>, public_key: impl Into<String>) -> Self {
        Self {
            id,
            verification_methods: BTreeMap::from([(key_id.into(), public_key.into())]),
            also_known_as: Vec::new(),
            updated_at: Some(Utc::now()),
            raw_properties: BTreeMap::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self
            .raw_properties
            .get("id")
            .or_else(|| self.raw_properties.get("did"))
            .and_then(Value::as_str)
            .is_some_and(|raw_id| raw_id != self.id.as_str())
        {
            return Err(WireError::Protocol("did document id mismatch".to_owned()));
        }
        Ok(())
    }

    pub fn method(&self) -> &str {
        self.id.method()
    }

    pub fn handles(&self) -> Vec<&str> {
        self.also_known_as
            .iter()
            .filter(|entry| !entry.starts_with("http://") && !entry.starts_with("https://"))
            .map(String::as_str)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    #[test]
    fn did_webvh_v1_method_marker_is_closed() {
        validate_did_webvh_v1_method(&serde_json::json!({
            "method": DID_WEBVH_V1_METHOD
        }))
        .unwrap();
        assert!(
            validate_did_webvh_v1_method(&serde_json::json!({
                "method": "did:webvh:2.0"
            }))
            .is_err()
        );
    }

    #[test]
    fn did_document_preserves_relationships_and_allows_empty_verification_methods() {
        let value = serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:webvh:z6mkfixture:alice.example",
            "capabilityDelegation": [
                "did:webvh:z6mkfixture:alice.example#invalid-device-authority"
            ],
            "service": [{
                "id": "did:webvh:z6mkfixture:alice.example#station",
                "type": "ArkretStation",
                "serviceEndpoint": "https://principal.example"
            }],
            "x-vendor": {"preserve": true}
        });
        let document: DidDocument = serde_json::from_value(value.clone()).unwrap();
        assert!(document.verification_methods.is_empty());
        document.validate().unwrap();
        assert_eq!(serde_json::to_value(document).unwrap(), value);
    }

    #[test]
    fn did_document_preserves_canonical_normalized_projection() {
        let value = serde_json::json!({
            "did": "did:webvh:z6mkfixture:alice.example",
            "contexts": ["https://www.w3.org/ns/did/v1"],
            "controller_dids": [],
            "also_known_as": ["acct:alice@example.test"],
            "verification_methods": [{
                "verification_method": "did:webvh:z6mkfixture:alice.example#key-1",
                "controller_did": "did:webvh:z6mkfixture:alice.example",
                "verification_method_suite": "Multikey",
                "public_key_material": {"publicKeyMultibase": "z6Mkfixture"},
                "extensions": []
            }],
            "authentication": [],
            "assertion_methods": [{
                "verification_method": "did:webvh:z6mkfixture:alice.example#key-1"
            }],
            "key_agreements": [],
            "capability_invocations": [],
            "capability_delegations": [],
            "services": [],
            "metadata": {},
            "extensions": []
        });
        let document: DidDocument = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(document.id.as_str(), "did:webvh:z6mkfixture:alice.example");
        assert_eq!(
            document
                .verification_methods
                .get("did:webvh:z6mkfixture:alice.example#key-1"),
            Some(&"z6Mkfixture".to_owned())
        );
        assert_eq!(document.also_known_as, vec!["acct:alice@example.test"]);
        document.validate().unwrap();
        assert_eq!(serde_json::to_value(document).unwrap(), value);
    }

    #[test]
    fn normalized_document_digest_matches_registered_kat_and_ignores_convenience_metadata() {
        let value = serde_json::json!({
            "did": "did:web:alice.example",
            "contexts": ["https://www.w3.org/ns/did/v1"],
            "controller_dids": [],
            "also_known_as": ["acct:alice@example.com"],
            "verification_methods": [{
                "verification_method": "did:web:alice.example#key-1",
                "controller_did": "did:web:alice.example",
                "verification_method_suite": "Multikey",
                "public_key_material": {
                    "publicKeyMultibase": "z6MkfixtureAlicePublicKey1111111111111111111"
                },
                "extensions": []
            }],
            "authentication": [{
                "verification_method": "did:web:alice.example#key-1"
            }],
            "assertion_methods": [{
                "verification_method": "did:web:alice.example#key-1"
            }],
            "key_agreements": [],
            "capability_invocations": [],
            "capability_delegations": [],
            "services": [{
                "uri": "did:web:alice.example#station",
                "protocol_names": ["ArkretService"],
                "endpoint": "https://ps.alice.example/",
                "extensions": [{"name": "serviceKind", "value": "station"}]
            }],
            "metadata": {"primary_handle": "alice:example.com"},
            "extensions": []
        });
        let mut document: DidDocument = serde_json::from_value(value).unwrap();
        let digest = normalized_did_document_digest(&document).unwrap();
        assert_eq!(
            digest.as_ref(),
            "sha256:10b3e107d51b7428103becb9345faf5c250f89832aac173657b16fb3dc0328ee"
        );

        document.updated_at = Some(
            DateTime::parse_from_rfc3339("2030-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        assert_eq!(normalized_did_document_digest(&document).unwrap(), digest);
    }

    #[test]
    fn raw_w3c_document_projects_to_the_same_registered_preimage() {
        let document: DidDocument = serde_json::from_value(serde_json::json!({
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:web:alice.example",
            "alsoKnownAs": ["acct:alice@example.com"],
            "verificationMethod": [{
                "id": "did:web:alice.example#key-1",
                "controller": "did:web:alice.example",
                "type": "Multikey",
                "publicKeyMultibase": "z6MkfixtureAlicePublicKey1111111111111111111"
            }],
            "authentication": ["did:web:alice.example#key-1"],
            "assertionMethod": ["did:web:alice.example#key-1"],
            "service": [{
                "id": "did:web:alice.example#station",
                "type": "ArkretService",
                "serviceEndpoint": "https://ps.alice.example/",
                "serviceKind": "station"
            }],
            "metadata": {"primary_handle": "alice:example.com"},
            "updated": "2026-08-01T00:00:00Z"
        }))
        .unwrap();
        assert_eq!(
            normalized_did_document_digest(&document).unwrap().as_ref(),
            "sha256:10b3e107d51b7428103becb9345faf5c250f89832aac173657b16fb3dc0328ee"
        );
    }

    #[test]
    fn did_document_helpers_cover_sdk_usage() {
        let mut document = DidDocument::new(did("alice"), "key-1", "pub");
        document.also_known_as = vec![
            "@alice:example".to_owned(),
            "https://example.test/users/alice".to_owned(),
        ];

        assert_eq!(document.method(), "webvh");
        assert_eq!(
            document.verification_methods.get("key-1"),
            Some(&"pub".to_owned())
        );
        assert_eq!(document.handles(), vec!["@alice:example"]);
    }

    #[test]
    fn did_web_url_supports_encoded_ports_and_paths() {
        let did = Did::new("did:web:example.test%3A8443:users:alice").unwrap();
        assert_eq!(
            did_web_document_url(&did).unwrap(),
            "https://example.test:8443/users/alice/did.json"
        );
    }
}
