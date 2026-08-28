use std::sync::{Arc, OnceLock};

#[cfg(test)]
use arkret_wire::{EventKind, SchemaId};

use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPayloadSchemaRule {
    pub event_kind: String,
    pub payload_schema_id: String,
    pub required_fields: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EventPayloadValidatorCatalog {
    pub rules: BTreeMap<String, EventPayloadSchemaRule>,
    #[serde(default, skip)]
    registry: Arc<ProtocolSchemaRegistry>,
}

impl EventPayloadValidatorCatalog {
    pub fn has_payload_validator(&self, event_kind: &str) -> bool {
        self.rules.contains_key(event_kind)
    }

    pub fn validate_payload(&self, event_kind: &str, payload: &Value) -> Result<()> {
        let warnings = self.validate_payload_with_warnings(event_kind, payload)?;
        for warning in warnings {
            tracing::warn!(
                event_kind = %event_kind,
                warning = %warning,
                "event payload validation warning"
            );
        }
        Ok(())
    }

    pub fn validate_payload_with_warnings(
        &self,
        event_kind: &str,
        payload: &Value,
    ) -> Result<Vec<String>> {
        let Some(rule) = self.rules.get(event_kind) else {
            return Err(SchemaError::Protocol(format!(
                "event kind '{event_kind}' has no payload validator"
            )));
        };
        validate_required_payload_fields(event_kind, payload, &rule.required_fields)?;
        let mut warnings = Vec::new();
        warnings.extend(
            self.registry
                .validate_value_with_warnings(&rule.payload_schema_id, payload)
                .map_err(|error| {
                    SchemaError::Protocol(format!(
                        "event kind '{event_kind}' payload violates {}: {error}",
                        rule.payload_schema_id
                    ))
                })?,
        );
        Ok(warnings)
    }

    pub fn missing_payload_validators_for<'a>(
        &self,
        event_kinds: impl IntoIterator<Item = &'a str>,
    ) -> Vec<String> {
        event_kinds
            .into_iter()
            .filter(|event_kind| !self.has_payload_validator(event_kind))
            .map(str::to_owned)
            .collect()
    }
}

fn validate_required_payload_fields(
    event_kind: &str,
    payload: &Value,
    required_fields: &[String],
) -> Result<()> {
    let object = payload.as_object().ok_or_else(|| {
        SchemaError::Protocol(format!(
            "event kind '{event_kind}' payload must be a JSON object"
        ))
    })?;
    for field in required_fields {
        if !object.contains_key(field) {
            return Err(SchemaError::Protocol(format!(
                "event kind '{event_kind}' payload requires field '{field}'"
            )));
        }
    }
    Ok(())
}

static DEFAULT_EVENT_PAYLOAD_VALIDATOR_CATALOG: OnceLock<
    std::result::Result<EventPayloadValidatorCatalog, String>,
> = OnceLock::new();

pub fn event_payload_validator_catalog() -> Result<EventPayloadValidatorCatalog> {
    match DEFAULT_EVENT_PAYLOAD_VALIDATOR_CATALOG.get_or_init(|| {
        build_default_event_payload_validator_catalog().map_err(|err| err.to_string())
    }) {
        Ok(catalog) => Ok(catalog.clone()),
        Err(error) => Err(SchemaError::Protocol(error.clone())),
    }
}

fn build_default_event_payload_validator_catalog() -> Result<EventPayloadValidatorCatalog> {
    if let Some(artifacts_dir) = default_spec_artifacts_dir() {
        event_payload_validator_catalog_from_spec_artifacts(artifacts_dir)
    } else {
        event_payload_validator_catalog_from_embedded_spec_artifacts()
    }
}

pub fn event_payload_validator_catalog_from_spec_artifacts(
    artifacts_dir: impl AsRef<Path>,
) -> Result<EventPayloadValidatorCatalog> {
    let artifacts_dir = artifacts_dir.as_ref();
    let bundle = SpecArtifactBundle::load(artifacts_dir)?;
    let registry = schema_registry_from_spec_artifacts(artifacts_dir)?;
    event_payload_validator_catalog_from_bundle(&bundle, registry)
}

pub fn event_payload_validator_catalog_from_embedded_spec_artifacts()
-> Result<EventPayloadValidatorCatalog> {
    let bundle = SpecArtifactBundle::load_embedded()?;
    let registry = schema_registry_from_embedded_spec_artifacts()?;
    event_payload_validator_catalog_from_bundle(&bundle, registry)
}

fn event_payload_validator_catalog_from_bundle(
    bundle: &SpecArtifactBundle,
    registry: ProtocolSchemaRegistry,
) -> Result<EventPayloadValidatorCatalog> {
    let entries = bundle
        .event_kind_registry
        .get("event_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            SchemaError::Protocol("event kind registry missing event_kinds".to_owned())
        })?;

    let mut rules = BTreeMap::new();
    for entry in entries {
        if entry.get("status").and_then(Value::as_str) != Some("active") {
            continue;
        }
        let Some(event_kind) = entry.get("event_kind").and_then(Value::as_str) else {
            continue;
        };
        if !events::is_standard_event_kind(event_kind) {
            continue;
        }
        let payload_schema_id =
            payload_schema_ref_for_event_entry(entry, &bundle.schema_registry).ok_or_else(|| {
                SchemaError::Protocol(format!(
                    "active standard event kind '{event_kind}' is missing a resolvable payload_schema_ref"
                ))
            })?;
        let required_fields = required_fields_for_schema_ref(&registry, &payload_schema_id)
            .ok_or_else(|| {
                SchemaError::Protocol(format!(
                    "event kind '{event_kind}' payload_schema_ref '{payload_schema_id}' does not resolve"
                ))
            })?;
        rules.insert(
            event_kind.to_owned(),
            EventPayloadSchemaRule {
                event_kind: event_kind.to_owned(),
                payload_schema_id,
                required_fields,
            },
        );
    }
    Ok(EventPayloadValidatorCatalog {
        rules,
        registry: Arc::new(registry),
    })
}

pub(super) fn payload_schema_ref_for_event_entry(
    entry: &Value,
    schema_registry: &Value,
) -> Option<String> {
    if let Some(schema_ref) = entry.get("payload_schema_ref").and_then(Value::as_str) {
        let (file, fragment) = schema_ref
            .split_once('#')
            .map_or((schema_ref, None), |(file, fragment)| {
                (file, Some(fragment))
            });
        let schema_id = schema_registry
            .get("schemas")
            .and_then(Value::as_array)?
            .iter()
            .find(|schema| schema.get("file").and_then(Value::as_str) == Some(file))?
            .get("schema_id")
            .and_then(Value::as_str)?;
        return Some(match fragment {
            Some(fragment) => format!("{schema_id}#{fragment}"),
            None => schema_id.to_owned(),
        });
    }
    None
}

fn required_fields_for_schema_ref(
    registry: &ProtocolSchemaRegistry,
    schema_ref: &str,
) -> Option<Vec<String>> {
    let schema = registry.schema(schema_ref)?;
    Some(
        schema
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier};

    use serde_json::json;

    use super::*;

    #[test]
    fn concurrent_catalog_clones_compile_each_payload_validator_once() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        let payload = Arc::new(json!({
            "policy_revision": 1,
            "federation_policy": "restricted",
            "content_encryption_floor": "allow_plaintext",
            "metadata_encryption_floor": "allow_plaintext"
        }));
        let worker_count = 8;
        let barrier = Arc::new(Barrier::new(worker_count));
        let workers = (0..worker_count)
            .map(|_| {
                let catalog = catalog.clone();
                let payload = Arc::clone(&payload);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    catalog
                        .validate_payload("ak.realm.policy_bundle", payload.as_ref())
                        .unwrap();
                })
            })
            .collect::<Vec<_>>();

        for worker in workers {
            worker.join().unwrap();
        }

        let stats = catalog.registry.validator_stats();
        assert_eq!(stats.compiled_validators, 1);
        assert_eq!(stats.cache_misses, 1);
        assert_eq!(stats.cache_hits, (worker_count - 1) as u64);
    }

    #[test]
    fn rsvp_payload_allows_nullable_occurrence_but_not_null_event_ref() {
        let catalog = event_payload_validator_catalog().unwrap();
        let entry = json!({
            "schedule_basis_refs": [
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ],
            "response": {"status": "accepted"}
        });
        // occurrence=null is the whole series.
        catalog
            .validate_payload(
                "ak.rsvp.set",
                &json!({
                    "event_ref": "ak:strand:AQVC6IqFkbYCve-UUUa0ciJb36fBVkZWvlnEwgTs3Q15",
                    "occurrence": null,
                    "entry": entry
                }),
            )
            .unwrap();
        assert!(
            catalog
                .validate_payload(
                    "ak.rsvp.set",
                    &json!({
                        "event_ref": null,
                        "occurrence": null,
                        "entry": entry
                    }),
                )
                .is_err()
        );
        // The pre-closure flat shape carried status at the payload root; the
        // response now lives inside the complete entry.
        assert!(
            catalog
                .validate_payload(
                    "ak.rsvp.set",
                    &json!({
                        "event_ref": "ak:strand:AQVC6IqFkbYCve-UUUa0ciJb36fBVkZWvlnEwgTs3Q15",
                        "occurrence": null,
                        "status": "accepted"
                    }),
                )
                .is_err()
        );
        // Exactly one response branch.
        assert!(
            catalog
                .validate_payload(
                    "ak.rsvp.set",
                    &json!({
                        "event_ref": "ak:strand:AQVC6IqFkbYCve-UUUa0ciJb36fBVkZWvlnEwgTs3Q15",
                        "occurrence": null,
                        "entry": {"schedule_basis_refs": [
                            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        ]}
                    }),
                )
                .is_err()
        );
    }

    #[test]
    fn catalog_validates_known_payload_fields() {
        let catalog = event_payload_validator_catalog().unwrap();
        catalog
            .validate_payload(
                "ak.strand.move",
                &json!({
                    "board_space_id": "ak:space:ATqrupSFYozzL7O90hPaSlvHmLnxxSRiRUZA4RgeuZpD",
                    "strand_id": "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9",
                    "target_space_id": "ak:space:AUl4PuPYccbXn1G6ELp6eIIBxEMjcgAj8cXBfX9KLb1G",
                    "rank": "U"
                }),
            )
            .unwrap();
        assert!(matches!(
            catalog.validate_payload(
                "ak.strand.move",
                &json!({
                    "strand_id": "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9",
                    "target_space_id": "ak:space:AUl4PuPYccbXn1G6ELp6eIIBxEMjcgAj8cXBfX9KLb1G",
                    "rank": "U"
                })
            ),
            Err(SchemaError::Protocol(_))
        ));
    }

    #[test]
    fn artifact_catalog_enforces_deep_schema_rules() {
        let Some(artifacts_dir) = default_spec_artifacts_dir() else {
            return;
        };
        let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();
        catalog
            .validate_payload(
                EventKind::StrandMove.as_str(),
                &json!({
                    "board_space_id": "ak:space:ATqrupSFYozzL7O90hPaSlvHmLnxxSRiRUZA4RgeuZpD",
                    "strand_id": "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9",
                    "target_space_id": "ak:space:AUl4PuPYccbXn1G6ELp6eIIBxEMjcgAj8cXBfX9KLb1G",
                    "rank": "U"
                }),
            )
            .unwrap();
        assert!(
            catalog
                .validate_payload(
                    EventKind::StrandMove.as_str(),
                    &json!({
                        "board_space_id": "not-a-space-id",
                        "strand_id": "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9",
                        "target_space_id": "ak:space:AUl4PuPYccbXn1G6ELp6eIIBxEMjcgAj8cXBfX9KLb1G",
                        "rank": "U"
                    }),
                )
                .is_err()
        );
        assert!(
            catalog
                .validate_payload(
                    EventKind::StrandMove.as_str(),
                    &json!({
                        "board_space_id": "ak:space:ATqrupSFYozzL7O90hPaSlvHmLnxxSRiRUZA4RgeuZpD",
                        "strand_id": "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9",
                        "target_space_id": "ak:space:AUl4PuPYccbXn1G6ELp6eIIBxEMjcgAj8cXBfX9KLb1G",
                        "rank": "U",
                        "unexpected": true
                    }),
                )
                .is_err(),
            "closed strand-move payload accepted an unexpected field"
        );
    }

    /// Every active standard event kind must resolve through its explicit
    /// registry `payload_schema_ref`; there is no naming fallback or exception.
    #[test]
    fn catalog_covers_every_active_standard_kind() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        let bundle = SpecArtifactBundle::load_embedded().unwrap();
        let entries = bundle
            .event_kind_registry
            .get("event_kinds")
            .and_then(Value::as_array)
            .unwrap();

        let mut missing = BTreeSet::new();
        for entry in entries {
            if entry.get("status").and_then(Value::as_str) != Some("active") {
                continue;
            }
            let Some(event_kind) = entry.get("event_kind").and_then(Value::as_str) else {
                continue;
            };
            if !events::is_standard_event_kind(event_kind) {
                continue;
            }
            if !catalog.has_payload_validator(event_kind) {
                missing.insert(event_kind.to_owned());
            }
        }

        assert_eq!(
            missing,
            BTreeSet::new(),
            "active standard kinds without an explicit payload validator"
        );
    }

    /// Active standard kinds whose explicit registry ref selects the loose
    /// `generic_standard_payload` shape.
    ///
    /// Every entry is a deliberate "no dedicated event-payload def" decision. A
    /// *new* active standard kind that silently inherits this loose shape must be
    /// added here with a rationale, which is exactly what
    /// [`every_active_standard_kind_avoids_undocumented_generic_payloads`]
    /// forces — so the hand-maintained match table cannot quietly drift a new
    /// kind onto an under-specified payload surface.
    const KINDS_USING_GENERIC_STANDARD_PAYLOAD: &[EventKind] = &[];

    /// Beyond [`catalog_covers_every_active_standard_kind`]
    /// (which fails closed when a kind resolves to *no* validator), this test
    /// pins *which* kinds are allowed to resolve to a **catch-all** payload shape
    /// (`generic_standard_payload`) rather than a dedicated
    /// `event-payload.schema.json#/$defs/*_payload` def.
    ///
    /// It asserts, over the full embedded spec event-kind registry, that the set
    /// of active standard kinds landing on each catch-all shape is *exactly* the
    /// documented list — catching drift in both directions:
    /// - a newly registered kind that silently inherits a catch-all via a broad family arm (appears
    ///   in the computed set, absent from the list) → red;
    /// - a kind that gained a dedicated def in the spec but is still listed as catch-all here
    ///   (absent from the computed set, still listed) → red, prompting removal from the list.
    ///
    /// Any kind resolving to a dedicated `*_payload` def is, by construction, in
    /// neither set and needs no maintenance here. This turns hand-table drift
    /// toward under-validation into a CI-catchable failure.
    #[test]
    fn every_active_standard_kind_avoids_undocumented_generic_payloads() {
        const GENERIC_DEF: &str = "generic_standard_payload";

        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        let bundle = SpecArtifactBundle::load_embedded().unwrap();
        let entries = bundle
            .event_kind_registry
            .get("event_kinds")
            .and_then(Value::as_array)
            .unwrap();

        let mut generic = BTreeSet::new();
        for entry in entries {
            if entry.get("status").and_then(Value::as_str) != Some("active") {
                continue;
            }
            let Some(event_kind) = entry.get("event_kind").and_then(Value::as_str) else {
                continue;
            };
            if !events::is_standard_event_kind(event_kind) {
                continue;
            }
            let Some(rule) = catalog.rules.get(event_kind) else {
                // No validator at all is the concern of
                // `catalog_covers_every_active_standard_kind`, not this test.
                continue;
            };
            let def = rule
                .payload_schema_id
                .rsplit("#/$defs/")
                .next()
                .unwrap_or(rule.payload_schema_id.as_str());
            if def == GENERIC_DEF {
                generic.insert(event_kind.to_owned());
            }
        }

        let expected_generic: BTreeSet<String> = KINDS_USING_GENERIC_STANDARD_PAYLOAD
            .iter()
            .map(|kind| kind.as_str().to_owned())
            .collect();
        assert_eq!(
            generic, expected_generic,
            "active standard kinds resolving to the loose `generic_standard_payload` shape \
             drifted from the documented KINDS_USING_GENERIC_STANDARD_PAYLOAD set; either wire \
             the new kind to a dedicated `*_payload` def in the registry or register \
             it here with a rationale"
        );
    }

    #[test]
    fn applet_registration_resolves_to_strong_payload_not_generic() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        // The strong def wins over the generic fallback.
        assert_eq!(
            catalog.rules["ak.applet.registration"].payload_schema_id,
            format!(
                "{schemaid_event_payload_v1}#/$defs/applet_registration_payload",
                schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
            )
        );
        // Discovery state uses the dedicated closed state payload shared by
        // resource-discovery kinds.
        assert_eq!(
            catalog.rules["ak.applet.discovery"].payload_schema_id,
            format!(
                "{schemaid_event_payload_v1}#/$defs/resource_discovery_state_payload",
                schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
            )
        );
    }

    #[test]
    fn catalog_reports_registered_payload_validators() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();

        assert!(catalog.has_payload_validator(EventKind::RealmHistoryAccess.as_str()));
        assert!(!catalog.has_payload_validator("ak.unknown.test"));
    }

    #[test]
    fn selector_claim_resolves_to_its_registered_schema() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        let rule = &catalog.rules[EventKind::AgentSelectorClaim.as_str()];

        assert_eq!(rule.payload_schema_id, SchemaId::AGENT_SELECTOR_CLAIM_V1);
        assert!(
            rule.required_fields
                .contains(&"controller_subject_id".to_owned())
        );
        assert!(rule.required_fields.contains(&"proofs".to_owned()));
        assert!(
            catalog
                .validate_payload(
                    EventKind::AgentSelectorClaim.as_str(),
                    &json!({"schema": SchemaId::AGENT_SELECTOR_CLAIM_V1})
                )
                .is_err(),
            "partial selector claims must fail the dedicated schema validator"
        );
    }

    #[test]
    fn payload_schema_resolution_requires_the_canonical_ref_carrier() {
        let schema_registry = json!({
            "schemas": [{
                "file": "schemas/event-payload.schema.json",
                "schema_id": SchemaId::EVENT_PAYLOAD_V1
            }]
        });
        assert_eq!(
            payload_schema_ref_for_event_entry(
                &json!({
                    "event_kind": EventKind::MessageCreate.as_str(),
                    "payload_schema_ref": "schemas/event-payload.schema.json#/$defs/message_create_payload"
                }),
                &schema_registry,
            ),
            Some(format!(
                "{}#/$defs/message_create_payload",
                SchemaId::EVENT_PAYLOAD_V1
            ))
        );
        assert_eq!(
            payload_schema_ref_for_event_entry(
                &json!({
                    "event_kind": EventKind::MessageCreate.as_str(),
                    "payload_schema": SchemaId::EVENT_PAYLOAD_V1
                }),
                &schema_registry,
            ),
            None,
            "the removed payload_schema carrier must not regain precedence"
        );
        assert_eq!(
            payload_schema_ref_for_event_entry(
                &json!({"event_kind": EventKind::MessageCreate.as_str()}),
                &schema_registry,
            ),
            None,
            "missing refs must not fall back to a guessed def name"
        );
    }

    #[test]
    fn strong_catalog_accepts_read_receipt_policy_payload() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        assert_eq!(
            catalog.rules["ak.realm.read_receipt_policy"].payload_schema_id,
            format!(
                "{schemaid_event_payload_v1}#/$defs/read_receipt_policy_payload",
                schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
            )
        );
        catalog
            .validate_payload(
                "ak.realm.read_receipt_policy",
                &json!({
                    "disclosure": "required"
                }),
            )
            .unwrap();
    }

    #[cfg(feature = "embedded-artifacts")]
    #[test]
    fn realm_join_rule_and_discovery_each_close_their_own_whole_value() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        assert_eq!(
            catalog.rules["ak.realm.join_rule"].payload_schema_id,
            format!(
                "{schemaid_event_payload_v1}#/$defs/realm_join_rule_payload",
                schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
            )
        );
        assert_eq!(
            catalog.rules["ak.realm.discovery"].payload_schema_id,
            format!(
                "{schemaid_event_payload_v1}#/$defs/realm_discovery_payload",
                schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
            )
        );

        for value in [
            "public",
            "invite",
            "knock",
            "restricted",
            "knock_restricted",
            "closed",
        ] {
            catalog
                .validate_payload("ak.realm.join_rule", &json!({"value": value}))
                .unwrap();
        }
        for discoverability in [
            "public",
            "listed",
            "restricted",
            "unlisted",
            "invite_only",
            "secret",
        ] {
            catalog
                .validate_payload(
                    "ak.realm.discovery",
                    &json!({"value": {"discoverability": discoverability}}),
                )
                .unwrap();
        }

        // The point of the dedicated defs: the wire shape itself now closes the
        // value space, so enum closure no longer depends on the typed model
        // downstream of the catalog.
        for (kind, payload, why) in [
            (
                "ak.realm.join_rule",
                json!({"value": "open"}),
                "join_rule value outside the closed enum",
            ),
            (
                "ak.realm.discovery",
                json!({"value": 1}),
                "discovery value that is not the closed object",
            ),
            (
                "ak.realm.discovery",
                json!({"value": "listed"}),
                "discovery bare string instead of {discoverability}",
            ),
            (
                "ak.realm.discovery",
                json!({"value": {"discoverability": "listed"}, "unexpected": true}),
                "unknown sibling member",
            ),
            ("ak.realm.join_rule", json!({}), "missing value"),
        ] {
            assert!(
                catalog.validate_payload(kind, &payload).is_err(),
                "{kind} unexpectedly accepted {payload} ({why})"
            );
        }
    }

    fn registration_anchored_device_authorize_payload() -> Value {
        json!({
            "principal_id": "ak:did_core:webvh:z6mkfixture",
            "device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
            "device_public_key": "did:key:z6Mki3devicepublickey",
            "hpke_key": "z6LSdevicehpke",
            "algorithms": ["ed25519", "x25519-hpke"],
            "device_key_algorithm": "Ed25519",
            "authorized_by": "ak:did_core:webvh:z6mkfixture",
            "not_before": "2026-06-30T00:00:00.000Z",
            "authorization_binding_kind": "registration_anchor",
            "device_signature": "c2lnbmF0dXJl"
        })
    }

    #[test]
    fn strong_catalog_accepts_device_authorize_payload() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        assert_eq!(
            catalog.rules["ak.device.authorize"].payload_schema_id,
            format!(
                "{schemaid_event_payload_v1}#/$defs/device_authorize_payload",
                schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
            )
        );
        catalog
            .validate_payload(
                "ak.device.authorize",
                &registration_anchored_device_authorize_payload(),
            )
            .unwrap();
    }

    fn realm_organization_active_payload() -> Value {
        json!({
            "statement_id": "org-stmt-1",
            "realm_id": "ak:realm:AVFSR4O2uTcP6zGsyewp0OdaGeDZBXQAUZ9VIEKLSXYo",
            "organization_id": "ak:did_core:webvh:example.test",
            "relationship": "owner",
            "status": "active",
            "control_scopes": ["official_badge", "realm_admin"],
            "issued_at": "2026-06-25T00:00:00.000Z",
            "authorization": {
                "issuer": "ak:did_core:webvh:example.test",
                "issuer_role": "organization_principal_id",
                "verification_method": "did:webvh:example.test:orgs:org1#k1",
                "signed_at": "2026-06-25T00:00:00.000Z",
                "proof": "c2ln"
            }
        })
    }

    /// SDK-ORG-03: the strong catalog MUST resolve `ak.realm.organization` to
    /// the `realm_organization_payload` def and derive the 8 top-level required fields.
    #[test]
    fn strong_catalog_validates_realm_organization_relationship_statement() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();
        assert_eq!(
            catalog.rules["ak.realm.organization"].payload_schema_id,
            format!(
                "{schemaid_event_payload_v1}#/$defs/realm_organization_payload",
                schemaid_event_payload_v1 = SchemaId::EVENT_PAYLOAD_V1
            )
        );
        let required: BTreeSet<&str> = catalog.rules["ak.realm.organization"]
            .required_fields
            .iter()
            .map(String::as_str)
            .collect();
        for field in [
            "statement_id",
            "realm_id",
            "organization_id",
            "relationship",
            "status",
            "control_scopes",
            "issued_at",
            "authorization",
        ] {
            assert!(required.contains(field), "missing required field {field}");
        }

        // Active positive case.
        catalog
            .validate_payload(
                "ak.realm.organization",
                &realm_organization_active_payload(),
            )
            .unwrap();

        // Revoked positive case (carries revokes_statement_id).
        let mut revoked = realm_organization_active_payload();
        revoked["status"] = json!("revoked");
        revoked["revokes_statement_id"] = json!("org-stmt-0");
        catalog
            .validate_payload("ak.realm.organization", &revoked)
            .unwrap();
    }

    /// SDK-ORG-03 negative cases: each MUST be rejected by the strong schema.
    #[test]
    fn strong_catalog_rejects_invalid_realm_organization_statements() {
        let catalog = event_payload_validator_catalog_from_embedded_spec_artifacts().unwrap();

        // revoked status without revokes_statement_id.
        let mut revoked_missing = realm_organization_active_payload();
        revoked_missing["status"] = json!("revoked");
        assert!(
            catalog
                .validate_payload("ak.realm.organization", &revoked_missing)
                .is_err(),
            "revoked without revokes_statement_id must fail"
        );

        // governance_service issuer without delegation_ref.
        let mut gov_missing = realm_organization_active_payload();
        gov_missing["authorization"]["issuer_role"] = json!("governance_service");
        assert!(
            catalog
                .validate_payload("ak.realm.organization", &gov_missing)
                .is_err(),
            "governance_service without delegation_ref must fail"
        );

        // account_authority issuer without delegation_ref.
        let mut acct_missing = realm_organization_active_payload();
        acct_missing["authorization"]["issuer_role"] = json!("account_authority");
        assert!(
            catalog
                .validate_payload("ak.realm.organization", &acct_missing)
                .is_err(),
            "account_authority without delegation_ref must fail"
        );

        // missing proof.
        let mut no_proof = realm_organization_active_payload();
        no_proof["authorization"]
            .as_object_mut()
            .unwrap()
            .remove("proof");
        assert!(
            catalog
                .validate_payload("ak.realm.organization", &no_proof)
                .is_err(),
            "missing authorization.proof must fail"
        );

        // bad relationship.
        let mut bad_rel = realm_organization_active_payload();
        bad_rel["relationship"] = json!("admin");
        assert!(
            catalog
                .validate_payload("ak.realm.organization", &bad_rel)
                .is_err(),
            "invalid relationship must fail"
        );

        // bad control_scopes item.
        let mut bad_scope = realm_organization_active_payload();
        bad_scope["control_scopes"] = json!(["not_a_scope"]);
        assert!(
            catalog
                .validate_payload("ak.realm.organization", &bad_scope)
                .is_err(),
            "invalid control_scopes item must fail"
        );
    }
}
