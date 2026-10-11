//! Read-only metadata evidence for the MLS send gate.
//!
//! This is an SDK projection, not a serialized protocol object. Plaintext key
//! presence must be captured before serde defaults erase empty or null members.

use std::collections::BTreeMap;

use arkret_models_crypto::EncryptedEnvelope;
use arkret_wire::patch::{Patch, PatchOp, PatchOpKind};
use arkret_wire::{Event, EventKind, Result, WireError, event_spec};
use serde_json::Value;

use crate::{EventIntent, EventPayloadExt, EventSpec};

/// User metadata carriers observed at the immutable Event/intent boundary.
#[derive(Clone, Debug, PartialEq)]
pub struct EventMetadataSendGate {
    pub encrypted_metadata: Vec<EncryptedEnvelope>,
    /// Presence of a plaintext metadata key, including empty and null values.
    pub user_metadata_present: bool,
}

/// Project the four standard Space/Strand metadata kinds for an MLS gate.
pub trait EventMetadataSendGateExt {
    /// `None` denotes another Event kind. Empty envelopes and a false
    /// presence bit denote a structural update with no user metadata.
    fn event_metadata_send_gate(&self) -> Result<Option<EventMetadataSendGate>>;
}

impl EventMetadataSendGateExt for Event {
    fn event_metadata_send_gate(&self) -> Result<Option<EventMetadataSendGate>> {
        project(MetadataSource::Event(self))
    }
}

impl EventMetadataSendGateExt for EventIntent {
    fn event_metadata_send_gate(&self) -> Result<Option<EventMetadataSendGate>> {
        project(MetadataSource::Intent(self))
    }
}

enum MetadataSource<'a> {
    Event(&'a Event),
    Intent(&'a EventIntent),
}

impl MetadataSource<'_> {
    fn kind(&self) -> &EventKind {
        match self {
            Self::Event(event) => &event.kind,
            Self::Intent(intent) => intent.kind(),
        }
    }

    fn raw_payload(&self) -> &BTreeMap<String, Value> {
        match self {
            Self::Event(event) => &event.payload,
            Self::Intent(intent) => intent.payload(),
        }
    }

    fn typed_payload<K: EventSpec>(&self) -> Result<K::Payload> {
        match self {
            Self::Event(event) => event.typed_payload::<K>(),
            Self::Intent(intent) => {
                let payload = intent
                    .typed_payload::<K>()
                    .map_err(|error| WireError::Protocol(error.to_string()))?;
                K::validate_payload(&payload)?;
                Ok(payload)
            }
        }
    }
}

fn project(source: MetadataSource<'_>) -> Result<Option<EventMetadataSendGate>> {
    let object = || -> Result<&serde_json::Map<String, Value>> {
        source
            .raw_payload()
            .get("object")
            .and_then(Value::as_object)
            .ok_or_else(|| WireError::Protocol("invalid metadata create object".into()))
    };
    let create =
        |keys: &[&str], encrypted: Option<EncryptedEnvelope>| -> Result<EventMetadataSendGate> {
            let object = object()?;
            if object.contains_key("encrypted_metadata") && encrypted.is_none() {
                return Err(WireError::Protocol(
                    "encrypted metadata must be an envelope, not null".into(),
                ));
            }
            let encrypted_metadata = encrypted.into_iter().collect::<Vec<_>>();
            for envelope in &encrypted_metadata {
                envelope.validate()?;
            }
            Ok(EventMetadataSendGate {
                encrypted_metadata,
                user_metadata_present: keys.iter().any(|key| object.contains_key(*key)),
            })
        };
    Ok(Some(match source.kind() {
        EventKind::SpaceCreate => {
            let payload = source.typed_payload::<event_spec::SpaceCreate>()?;
            create(
                &["title", "summary", "labels", "avatar_blob_ref"],
                payload.object.encrypted_metadata,
            )?
        }
        EventKind::StrandCreate => {
            let payload = source.typed_payload::<event_spec::StrandCreate>()?;
            create(&["metadata"], payload.object.encrypted_metadata)?
        }
        EventKind::SpaceUpdate => {
            let payload = source.typed_payload::<event_spec::SpaceUpdate>()?;
            payload.validate()?;
            match payload.patch {
                Some(patch) => project_patch(&patch)?,
                None => EventMetadataSendGate {
                    encrypted_metadata: Vec::new(),
                    user_metadata_present: false,
                },
            }
        }
        EventKind::StrandUpdate => {
            let payload = source.typed_payload::<event_spec::StrandUpdate>()?;
            payload.validate()?;
            project_patch(&payload.patch)?
        }
        _ => return Ok(None),
    }))
}

fn project_patch(patch: &Patch) -> Result<EventMetadataSendGate> {
    let mut projected = EventMetadataSendGate {
        encrypted_metadata: Vec::new(),
        user_metadata_present: false,
    };
    for (path, operation) in patch.iter() {
        let root = path.split('.').next().unwrap_or_default();
        if root == "encrypted_metadata" {
            let PatchOp::Explicit {
                op: PatchOpKind::Set,
                value: Some(value),
            } = operation
            else {
                return Err(WireError::Protocol(
                    "encrypted metadata requires whole-envelope set".into(),
                ));
            };
            if path != "encrypted_metadata" {
                return Err(WireError::Protocol(
                    "encrypted metadata requires whole-envelope set".into(),
                ));
            }
            let envelope: EncryptedEnvelope = serde_json::from_value(value.clone())
                .map_err(|error| WireError::Protocol(error.to_string()))?;
            envelope.validate()?;
            projected.encrypted_metadata.push(envelope);
        } else if matches!(
            root,
            "title" | "summary" | "labels" | "avatar_blob_ref" | "metadata"
        ) {
            projected.user_metadata_present = true;
        }
    }
    Ok(projected)
}

#[cfg(test)]
mod tests {
    use arkret_models_crypto::EncryptedEnvelopeEncryptionContext;
    use arkret_wire::{ActorId, DidCoreId, EventId, RealmId, ScopeRef};
    use serde_json::json;

    use super::*;

    const REALM: &str = "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19";
    const SPACE: &str = "ak:space:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9";
    const STRAND: &str = "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9";

    fn sources(kind: EventKind, payload: Value) -> (Event, EventIntent) {
        let scope = ScopeRef::Realm {
            realm_id: RealmId::new(REALM).unwrap(),
        };
        let principal = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let station = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let created_at = "2026-10-09T00:00:00.000Z".parse().unwrap();
        let event = arkret_wire::test_support::raw_event_at(
            kind.as_str(),
            scope.clone(),
            principal.clone(),
            station.clone(),
            payload.clone(),
            created_at,
        )
        .unwrap();
        let intent = EventIntent::new(
            kind,
            scope,
            ActorId::account(arkret_wire::AccountId::new(principal, station)),
            created_at,
            payload.as_object().unwrap().clone().into_iter().collect(),
        );
        (event, intent)
    }

    fn envelope() -> EncryptedEnvelope {
        EncryptedEnvelope {
            version: "1.0".into(),
            content_type: "application/json".into(),
            encryption_context: EncryptedEnvelopeEncryptionContext::standard(
                7,
                EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [2; 32]),
            ),
            ciphertext: "AA".into(),
        }
    }

    fn assert_projection(kind: EventKind, payload: Value, expected: Option<EventMetadataSendGate>) {
        let (event, intent) = sources(kind, payload);
        assert_eq!(event.event_metadata_send_gate().unwrap(), expected);
        assert_eq!(intent.event_metadata_send_gate().unwrap(), expected);
    }

    fn assert_rejected(kind: EventKind, payload: Value) {
        let (event, intent) = sources(kind, payload);
        assert!(event.event_metadata_send_gate().is_err());
        assert!(intent.event_metadata_send_gate().is_err());
    }

    fn create(kind: &EventKind) -> Value {
        let actor = ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        match kind {
            EventKind::SpaceCreate => {
                let mut object = arkret_models_collaboration::objects::space::Space::create_object(
                    RealmId::new(REALM).unwrap(),
                    "list",
                    "title",
                    actor,
                );
                object.title = None;
                json!({"object": object})
            }
            EventKind::StrandCreate => {
                let mut object = arkret_models_collaboration::objects::strand::Strand::new_create(
                    RealmId::new(REALM).unwrap(),
                    "title",
                    actor,
                );
                object.metadata = None;
                json!({"object": object})
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn create_projection_preserves_empty_and_null_plaintext_keys() {
        for (key, value) in [
            ("title", json!(null)),
            ("summary", json!(null)),
            ("labels", json!([])),
            ("avatar_blob_ref", json!(null)),
        ] {
            let mut payload = create(&EventKind::SpaceCreate);
            payload["object"]["encrypted_metadata"] = json!(envelope());
            payload["object"][key] = value;
            assert_projection(
                EventKind::SpaceCreate,
                payload,
                Some(EventMetadataSendGate {
                    encrypted_metadata: vec![envelope()],
                    user_metadata_present: true,
                }),
            );
        }
        let mut payload = create(&EventKind::StrandCreate);
        payload["object"]["metadata"] = Value::Null;
        payload["object"]["encrypted_metadata"] = json!(envelope());
        assert_projection(
            EventKind::StrandCreate,
            payload,
            Some(EventMetadataSendGate {
                encrypted_metadata: vec![envelope()],
                user_metadata_present: true,
            }),
        );
    }

    #[test]
    fn create_projection_keeps_typed_envelopes_and_rejects_null_envelopes() {
        for kind in [EventKind::SpaceCreate, EventKind::StrandCreate] {
            let mut payload = create(&kind);
            assert_projection(
                kind.clone(),
                payload.clone(),
                Some(EventMetadataSendGate {
                    encrypted_metadata: vec![],
                    user_metadata_present: false,
                }),
            );
            payload["object"]["encrypted_metadata"] = json!(envelope());
            assert_projection(
                kind.clone(),
                payload.clone(),
                Some(EventMetadataSendGate {
                    encrypted_metadata: vec![envelope()],
                    user_metadata_present: false,
                }),
            );
            for malformed in [
                Value::Null,
                json!({}),
                json!({"version": "1.0", "content_type": "application/json", "ciphertext": "AA", "encryption_context": {"epoch": 7, "group_state_ref": "invalid"}}),
            ] {
                payload["object"]["encrypted_metadata"] = malformed;
                assert_rejected(kind.clone(), payload.clone());
            }
        }
        assert_projection(EventKind::MemberState, json!({}), None);
        assert_rejected(
            EventKind::SpaceCreate,
            json!({"patch": {"title": "wrong kind"}}),
        );
    }

    #[test]
    fn update_projection_distinguishes_user_metadata_from_structure() {
        for kind in [EventKind::SpaceUpdate, EventKind::StrandUpdate] {
            let (target, id) = if kind == EventKind::SpaceUpdate {
                ("space_id", SPACE)
            } else {
                ("target_ref", STRAND)
            };
            let structural = if kind == EventKind::SpaceUpdate {
                json!({"rank": "U"})
            } else {
                json!({"schema_refs": []})
            };
            let plain_path = if kind == EventKind::SpaceUpdate {
                "summary"
            } else {
                "metadata.summary"
            };
            let mut clear = json!({});
            clear[plain_path] = json!({"$op": "unset"});
            let mut mixed = json!({"encrypted_metadata": {"$op": "set", "value": envelope()}});
            mixed[plain_path] = json!("plaintext");
            for (patch, user_metadata_present, encrypted_metadata) in [
                (structural, false, vec![]),
                (clear, true, vec![]),
                (
                    json!({"encrypted_metadata": {"$op": "set", "value": envelope()}}),
                    false,
                    vec![envelope()],
                ),
                (mixed, true, vec![envelope()]),
            ] {
                let mut payload = json!({"patch": patch});
                payload[target] = json!(id);
                assert_projection(
                    kind.clone(),
                    payload,
                    Some(EventMetadataSendGate {
                        encrypted_metadata,
                        user_metadata_present,
                    }),
                );
            }
        }
    }

    #[test]
    fn update_projection_rejects_partial_nonset_and_malformed_patches() {
        for kind in [EventKind::SpaceUpdate, EventKind::StrandUpdate] {
            let (target, id) = if kind == EventKind::SpaceUpdate {
                ("space_id", SPACE)
            } else {
                ("target_ref", STRAND)
            };
            for patch in [
                json!(null),
                json!([]),
                json!({}),
                json!({"encrypted_metadata": envelope()}),
                json!({"encrypted_metadata": {"$op": "unset"}}),
                json!({"encrypted_metadata.ciphertext": {"$op": "set", "value": "AA"}}),
                json!({"encrypted_metadata": {"$op": "set", "value": null}}),
            ] {
                let mut payload = json!({"patch": patch});
                payload[target] = json!(id);
                assert_rejected(kind.clone(), payload);
            }
        }
    }
}
