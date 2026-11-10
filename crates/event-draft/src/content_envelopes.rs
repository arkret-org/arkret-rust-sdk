//! Registered encrypted application carriers at their original JSON pointers.
//!
//! This projection never searches arbitrary plaintext, extension maps or opaque
//! account-data ciphertext for envelope-shaped objects. The Event is typed and
//! validated first; only the registered carrier slots are then inspected.

use arkret_models_collaboration::objects::productivity::CalendarEventLocation;
use arkret_models_crypto::EncryptedEnvelope;
use arkret_wire::patch::{Patch, PatchOp, PatchOpKind, parse_object_path};
use arkret_wire::{Event, EventKind, Result, WireError};
use serde_json::Value;

/// SDK-local projection; `content_path` addresses the original signed Event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventContentEnvelope {
    pub content_path: String,
    pub envelope: EncryptedEnvelope,
}

pub trait EventContentEnvelopesExt {
    fn event_content_envelopes(&self) -> Result<Vec<EventContentEnvelope>>;
    fn event_content_protections_digest(&self) -> Result<arkret_wire::Hash>;
    fn validate_content_backup_source_binding(
        &self,
        source: &arkret_models_crypto::ContentBackupSourceAttestation,
        actual_producer: &arkret_models_crypto::ContentEndpoint,
        destination: &arkret_wire::DidCoreId,
    ) -> Result<()>;
}

impl EventContentEnvelopesExt for Event {
    fn event_content_protections_digest(&self) -> Result<arkret_wire::Hash> {
        let mut slots = self.event_content_envelopes()?;
        if slots.is_empty() {
            return Err(invalid(
                "backup source requires registered encrypted content",
            ));
        }
        slots.sort_by(|a, b| a.content_path.as_bytes().cmp(b.content_path.as_bytes()));
        let rows: Result<Vec<_>> = slots.into_iter().map(|slot| {
            let context = serde_json::to_value(slot.envelope.encryption_context)?;
            Ok(serde_json::json!({"content_path":slot.content_path,"protection":context["protection"]}))
        }).collect();
        Ok(arkret_wire::Hash::new(arkret_canonical::canonical_sha256(
            &rows?,
        )?)?)
    }

    fn validate_content_backup_source_binding(
        &self,
        source: &arkret_models_crypto::ContentBackupSourceAttestation,
        actual_producer: &arkret_models_crypto::ContentEndpoint,
        destination: &arkret_wire::DidCoreId,
    ) -> Result<()> {
        source.validate_original_binding(
            self,
            actual_producer,
            destination,
            &self.event_content_protections_digest()?,
        )
    }

    fn event_content_envelopes(&self) -> Result<Vec<EventContentEnvelope>> {
        if !matches!(
            self.kind,
            EventKind::MessageCreate
                | EventKind::MessageRevise
                | EventKind::ReactionAdd
                | EventKind::ReactionRemove
                | EventKind::AgentSidecarExchangeControl
                | EventKind::PinAdd
                | EventKind::RsvpSet
                | EventKind::MemberIdentityUpdate
                | EventKind::SpaceCreate
                | EventKind::MorphCreate
                | EventKind::StrandCreate
                | EventKind::SpaceUpdate
                | EventKind::MorphUpdate
                | EventKind::StrandUpdate
                | EventKind::StrandTracksUpdate
                | EventKind::ProfileCreate
                | EventKind::ProfileUpdate
        ) {
            return Ok(Vec::new());
        }
        let payload = serde_json::to_value(&self.payload)?;
        crate::validate_event_payload(&self.kind, &payload)?;
        project(&self.kind, &payload)
    }
}

fn invalid(detail: impl Into<String>) -> WireError {
    WireError::Protocol(detail.into())
}

/// Decode only a registered ContentBlock plaintext slot before encryption.
/// Metadata and arbitrary extension-shaped objects are not dependency sources.
pub fn content_block_plaintext(
    kind: &EventKind,
    content_path: &str,
    plaintext: &[u8],
) -> Result<Option<arkret_models_collaboration::events_payloads::ContentBlock>> {
    let whole = match kind {
        EventKind::MessageCreate | EventKind::MessageRevise => {
            content_path == "/payload/encrypted_content"
        }
        EventKind::MorphCreate | EventKind::StrandCreate => {
            content_path == "/payload/object/encrypted_content"
        }
        _ => false,
    };
    let track = *kind == EventKind::StrandCreate
        && content_path
            .strip_prefix("/payload/object/tracks/")
            .and_then(|value| value.strip_suffix("/encrypted_content"))
            .is_some_and(|name| !name.is_empty() && unescape_segment(name).is_some());
    let patch = if matches!(
        kind,
        EventKind::MorphUpdate | EventKind::StrandUpdate | EventKind::StrandTracksUpdate
    ) {
        if let Some(raw) = content_path.strip_prefix("/payload/patch/") {
            let raw = raw.strip_suffix("/value").unwrap_or(raw);
            if let Some(decoded) = unescape_segment(raw) {
                let fields = parse_object_path(&decoded)?;
                fields == ["encrypted_content"]
                    || (*kind == EventKind::StrandUpdate
                        && fields == ["tracks", "synthesis", "encrypted_content"])
            } else {
                false
            }
        } else {
            false
        }
    } else {
        false
    };
    if whole || track || patch {
        Ok(Some(serde_json::from_slice(plaintext)?))
    } else {
        Ok(None)
    }
}

/// Complete cross-Station byte binding before native acceptance. The caller
/// independently qualifies every actual producer and verifies each source's
/// Service history/signature and retained storage. Local root checks are not
/// replaced by this cross-Station operation.
pub fn validate_cross_station_content_backup_sources(
    events: &[&Event],
    sources: Option<&[arkret_models_collaboration::content_history::ContentBackupSource]>,
    actual_producers: &[arkret_models_crypto::ContentEndpoint],
    destination: &arkret_wire::DidCoreId,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    if events.is_empty() || events.len() != actual_producers.len() || events.len() > 2 {
        return Err(invalid(
            "backup sources require exact original producer coordinates",
        ));
    }
    let mut required = Vec::new();
    for (event, producer) in events.iter().zip(actual_producers) {
        if !event.event_content_envelopes()?.is_empty() {
            let account = producer.actor_id.as_account_id().ok_or_else(|| {
                invalid("cross-Station backup source requires an Account producer")
            })?;
            if &account.station_id == destination {
                return Err(invalid(
                    "same-Station content requires native local root dependency checks",
                ));
            }
            required.push((*event, producer));
        }
    }
    match (required.is_empty(), sources) {
        (true, None) => return Ok(()),
        (false, Some(sources)) if sources.len() == required.len() => {
            for (source, (event, producer)) in sources.iter().zip(required) {
                source.attestation.validate_at(now)?;
                source.validate_submission_binding(
                    event,
                    producer,
                    destination,
                    &event.event_content_protections_digest()?,
                )?;
            }
            return Ok(());
        }
        _ => {}
    }
    Err(invalid(
        "missing, extra, duplicate or unordered original backup sources",
    ))
}

fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

fn unescape_segment(raw: &str) -> Option<String> {
    let mut decoded = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        decoded.push(match ch {
            '/' => return None,
            '~' => match chars.next()? {
                '0' => '~',
                '1' => '/',
                _ => return None,
            },
            ch => ch,
        });
    }
    Some(decoded)
}

fn envelope(value: &Value, path: String, out: &mut Vec<EventContentEnvelope>) -> Result<()> {
    let envelope: EncryptedEnvelope = serde_json::from_value(value.clone())?;
    envelope.validate()?;
    out.push(EventContentEnvelope {
        content_path: path,
        envelope,
    });
    Ok(())
}

fn optional(
    value: &Value,
    key: &str,
    path: &str,
    out: &mut Vec<EventContentEnvelope>,
) -> Result<()> {
    if let Some(value) = value.get(key) {
        envelope(value, format!("{path}/{}", escape(key)), out)?;
    }
    Ok(())
}

fn calendar_location(
    value: &Value,
    path: String,
    out: &mut Vec<EventContentEnvelope>,
) -> Result<()> {
    let location: CalendarEventLocation = serde_json::from_value(value.clone())?;
    if let CalendarEventLocation::Encrypted(value) = location {
        envelope(&serde_json::to_value(value)?, path, out)?;
    }
    Ok(())
}

fn strand_metadata(value: &Value, path: &str, out: &mut Vec<EventContentEnvelope>) -> Result<()> {
    if let Some(location) = value.pointer("/fields/calendar/location") {
        calendar_location(location, format!("{path}/fields/calendar/location"), out)?;
    }
    Ok(())
}

fn project(kind: &EventKind, payload: &Value) -> Result<Vec<EventContentEnvelope>> {
    let mut out = Vec::new();
    match kind {
        EventKind::MessageCreate | EventKind::MessageRevise => {
            optional(payload, "encrypted_content", "/payload", &mut out)?;
            optional(payload, "encrypted_metadata", "/payload", &mut out)?;
        }
        EventKind::ReactionAdd
        | EventKind::ReactionRemove
        | EventKind::AgentSidecarExchangeControl => {
            optional(payload, "encrypted_payload", "/payload", &mut out)?;
        }
        EventKind::PinAdd => optional(payload, "note", "/payload", &mut out)?,
        EventKind::RsvpSet => optional(
            &payload["entry"],
            "encrypted_response",
            "/payload/entry",
            &mut out,
        )?,
        EventKind::MemberIdentityUpdate => optional(
            &payload["identity_payload"],
            "encrypted_payload",
            "/payload/identity_payload",
            &mut out,
        )?,
        EventKind::ProfileCreate => optional(
            &payload["object"],
            "encrypted_private_fields",
            "/payload/object",
            &mut out,
        )?,
        EventKind::SpaceCreate | EventKind::MorphCreate | EventKind::StrandCreate => {
            let object = &payload["object"];
            optional(object, "encrypted_metadata", "/payload/object", &mut out)?;
            if *kind != EventKind::SpaceCreate {
                optional(object, "encrypted_content", "/payload/object", &mut out)?;
            }
            if *kind == EventKind::StrandCreate {
                if let Some(tracks) = object.get("tracks").and_then(Value::as_object) {
                    for (name, track) in tracks {
                        optional(
                            track,
                            "encrypted_content",
                            &format!("/payload/object/tracks/{}", escape(name)),
                            &mut out,
                        )?;
                    }
                }
                strand_metadata(&object["metadata"], "/payload/object/metadata", &mut out)?;
            }
        }
        EventKind::SpaceUpdate
        | EventKind::MorphUpdate
        | EventKind::StrandUpdate
        | EventKind::StrandTracksUpdate
        | EventKind::ProfileUpdate => {
            if let Some(patch) = payload.get("patch") {
                project_patch(kind, patch, &mut out)?;
            }
        }
        _ => {}
    }
    Ok(out)
}

fn project_patch(kind: &EventKind, raw: &Value, out: &mut Vec<EventContentEnvelope>) -> Result<()> {
    let patch: Patch = serde_json::from_value(raw.clone())?;
    patch.validate()?;
    for (path, operation) in patch.iter() {
        let segments = parse_object_path(path)?;
        let fields = segments.iter().map(String::as_str).collect::<Vec<_>>();
        let slot = match fields.as_slice() {
            ["encrypted_private_fields"] => *kind == EventKind::ProfileUpdate,
            _ if *kind == EventKind::ProfileUpdate => false,
            ["encrypted_metadata"] => true,
            ["encrypted_content"] => *kind != EventKind::SpaceUpdate,
            ["tracks", "synthesis", "encrypted_content"] => *kind == EventKind::StrandUpdate,
            _ => false,
        };
        // Patching inside an envelope is never a new complete content intent.
        let partial = (*kind == EventKind::ProfileUpdate
            && matches!(fields.as_slice(), ["encrypted_private_fields", _, ..]))
            || matches!(
                fields.as_slice(),
                ["encrypted_content" | "encrypted_metadata", _, ..]
                    | ["tracks", "synthesis", "encrypted_content", _, ..]
            );
        if partial {
            return Err(invalid(
                "encrypted carrier requires a whole-envelope replacement",
            ));
        }
        let base = format!(
            "/payload/patch/{}{}",
            escape(path),
            if matches!(operation, PatchOp::Explicit { .. }) {
                "/value"
            } else {
                ""
            }
        );
        if slot {
            if operation.op() != PatchOpKind::Set {
                return Err(invalid("encrypted carrier requires a whole-envelope set"));
            }
            envelope(
                operation
                    .value()
                    .ok_or_else(|| invalid("encrypted carrier has no value"))?,
                base,
                out,
            )?;
        } else if *kind == EventKind::StrandUpdate && operation.op() == PatchOpKind::Set {
            let value = operation
                .value()
                .ok_or_else(|| invalid("patch has no set value"))?;
            match fields.as_slice() {
                ["metadata"] => strand_metadata(value, &base, out)?,
                ["metadata", "fields"] => {
                    if let Some(location) = value.pointer("/calendar/location") {
                        calendar_location(location, format!("{base}/calendar/location"), out)?;
                    }
                }
                ["metadata", "fields", "calendar"] => {
                    if let Some(location) = value.get("location") {
                        calendar_location(location, format!("{base}/location"), out)?;
                    }
                }
                ["metadata", "fields", "calendar", "location"] => {
                    calendar_location(value, base, out)?
                }
                _ => {}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn encrypted() -> Value {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../../arkret-spec/spec/v1/artifacts/fixtures/content-history-fixture.json"
        ))
        .unwrap();
        fixture["kat"]["envelope"].clone()
    }

    #[test]
    fn registered_slots_include_non_message_carriers_and_original_paths() {
        for (kind, payload, path) in [
            (
                EventKind::ProfileCreate,
                json!({"object":{"encrypted_private_fields":encrypted()}}),
                "/payload/object/encrypted_private_fields",
            ),
            (
                EventKind::PinAdd,
                json!({"note": encrypted()}),
                "/payload/note",
            ),
            (
                EventKind::RsvpSet,
                json!({"entry":{"encrypted_response": encrypted()}}),
                "/payload/entry/encrypted_response",
            ),
            (
                EventKind::MemberIdentityUpdate,
                json!({"identity_payload":{"encrypted_payload": encrypted()}}),
                "/payload/identity_payload/encrypted_payload",
            ),
            (
                EventKind::AgentSidecarExchangeControl,
                json!({"encrypted_payload":encrypted()}),
                "/payload/encrypted_payload",
            ),
            (
                EventKind::MorphCreate,
                json!({"object":{"encrypted_content":encrypted()}}),
                "/payload/object/encrypted_content",
            ),
        ] {
            let result = project(&kind, &payload).unwrap();
            assert_eq!(result.len(), 1);
            assert_eq!(result[0].content_path, path);
        }
    }

    #[test]
    fn private_profile_projects_only_its_registered_whole_slot() {
        for value in [encrypted(), json!({"$op":"set","value":encrypted()})] {
            let payload = json!({"patch":{"encrypted_private_fields": value}});
            let entries = project(&EventKind::ProfileUpdate, &payload).unwrap();
            assert_eq!(entries.len(), 1);
            let entry = &entries[0];
            assert_eq!(
                payload
                    .pointer(entry.content_path.strip_prefix("/payload").unwrap())
                    .unwrap(),
                &serde_json::to_value(&entry.envelope).unwrap()
            );
        }
        for patch in [
            json!({"encrypted_private_fields.ciphertext":"AA"}),
            json!({"encrypted_private_fields":{"$op":"unset"}}),
            json!({"encrypted_private_fields":null}),
        ] {
            assert!(project(&EventKind::ProfileUpdate, &json!({"patch":patch})).is_err());
        }
        let opaque = json!({"patch":{"profile_fields.private":encrypted()}});
        assert!(
            project(&EventKind::ProfileUpdate, &opaque)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn plaintext_and_opaque_maps_are_never_recursively_treated_as_envelopes() {
        for kind in [
            EventKind::MessageCreate,
            EventKind::AccountDataSet,
            EventKind::StrandUpdate,
        ] {
            let payload = json!({"content": encrypted(), "encrypted_payload": encrypted(), "x_test": {"encrypted_content": encrypted()}});
            assert!(project(&kind, &payload).unwrap().is_empty());
        }
    }

    #[test]
    fn whole_envelope_patch_paths_point_into_signed_ops() {
        let payload = json!({"patch": {
            "encrypted_content": {"$op":"set", "value":encrypted()},
            "tracks.synthesis.encrypted_content": encrypted()
        }});
        let result = project(&EventKind::StrandUpdate, &payload).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(
            result[0].content_path,
            "/payload/patch/encrypted_content/value"
        );
        assert_eq!(
            result[1].content_path,
            "/payload/patch/tracks.synthesis.encrypted_content"
        );
        for item in result {
            assert_eq!(
                payload
                    .pointer(item.content_path.strip_prefix("/payload").unwrap())
                    .unwrap(),
                &serde_json::to_value(item.envelope).unwrap()
            );
        }
    }

    #[test]
    fn partial_quoted_null_and_non_set_envelopes_fail_closed() {
        for patch in [
            json!({"encrypted_content.ciphertext":"AA"}),
            json!({"`encrypted_content`.ciphertext":"AA"}),
            json!({"encrypted_content":null}),
            json!({"encrypted_content":{"$op":"add","value":encrypted()}}),
            json!({"encrypted_content":{"$op":"unset"}}),
        ] {
            assert!(project(&EventKind::StrandUpdate, &json!({"patch":patch})).is_err());
        }
        assert!(project(&EventKind::PinAdd, &json!({"note":null})).is_err());
    }

    #[test]
    fn track_and_calendar_nested_carriers_have_exact_escaped_pointers() {
        let payload = json!({"object":{
            "tracks":{"synthesis":{"encrypted_content": encrypted()}},
            "metadata":{"fields":{"calendar":{"location": encrypted()}}}
        }});
        let result = project(&EventKind::StrandCreate, &payload).unwrap();
        assert_eq!(result.len(), 2);
        for item in result {
            assert_eq!(
                payload
                    .pointer(item.content_path.strip_prefix("/payload").unwrap())
                    .unwrap(),
                &serde_json::to_value(item.envelope).unwrap()
            );
        }
        let payload = json!({"patch":{"`metadata`.fields.calendar.location":{"$op":"set","value":encrypted()}}});
        let item = project(&EventKind::StrandUpdate, &payload)
            .unwrap()
            .remove(0);
        assert_eq!(
            item.content_path,
            "/payload/patch/`metadata`.fields.calendar.location/value"
        );
    }
    #[test]
    fn plaintext_dependency_source_is_a_registered_content_block_slot() {
        let body = br#"{"kind":"ak.content.text","body":"original"}"#;
        for (kind, path) in [
            (EventKind::MessageCreate, "/payload/encrypted_content"),
            (EventKind::MessageRevise, "/payload/encrypted_content"),
            (EventKind::StrandCreate, "/payload/object/encrypted_content"),
            (
                EventKind::StrandCreate,
                "/payload/object/tracks/synthesis/encrypted_content",
            ),
            (
                EventKind::StrandCreate,
                "/payload/object/tracks/a~1b~0c/encrypted_content",
            ),
            (
                EventKind::StrandUpdate,
                "/payload/patch/encrypted_content/value",
            ),
            (
                EventKind::StrandUpdate,
                "/payload/patch/tracks.synthesis.encrypted_content/value",
            ),
        ] {
            assert_eq!(
                content_block_plaintext(&kind, path, body)
                    .unwrap()
                    .unwrap()
                    .body,
                "original"
            );
            assert!(content_block_plaintext(&kind, path, b"not-json").is_err());
        }
        for (kind, path) in [
            (EventKind::MessageCreate, "/payload/encrypted_metadata"),
            (
                EventKind::SpaceUpdate,
                "/payload/patch/encrypted_content/value",
            ),
            (
                EventKind::StrandUpdate,
                "/payload/patch/encrypted_metadata/value",
            ),
            (
                EventKind::StrandUpdate,
                "/payload/patch/encrypted_content/ciphertext/value",
            ),
            (
                EventKind::MessageCreate,
                "/payload/x_extension/encrypted_content",
            ),
            (
                EventKind::StrandCreate,
                "/payload/object/tracks/a~2b/encrypted_content",
            ),
            (
                EventKind::StrandCreate,
                "/payload/object/tracks/a~/encrypted_content",
            ),
            (
                EventKind::StrandUpdate,
                "/payload/patch/encrypted~2_content/value",
            ),
        ] {
            assert!(
                content_block_plaintext(&kind, path, body)
                    .unwrap()
                    .is_none()
            );
        }
    }
}
