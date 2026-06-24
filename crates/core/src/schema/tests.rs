use super::*;

fn local_spec_artifacts_dir() -> Option<PathBuf> {
    if let Some(dir) = default_spec_artifacts_dir() {
        return Some(dir);
    }
    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("cokret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts");
    candidate.is_dir().then_some(candidate)
}

fn collect_json_artifact_paths(root: &Path, dir: &Path, out: &mut BTreeSet<String>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|error| panic!("failed to read entry in {}: {error}", dir.display()))
            .path();
        if path.is_dir() {
            collect_json_artifact_paths(root, &path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            let rel = path
                .strip_prefix(root)
                .unwrap_or_else(|error| {
                    panic!(
                        "failed to strip {} from {}: {error}",
                        root.display(),
                        path.display()
                    )
                })
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel);
        }
    }
}

#[test]
fn embedded_spec_artifacts_match_live_spec_when_available() {
    let Some(artifacts_dir) = local_spec_artifacts_dir() else {
        return;
    };
    let embedded: BTreeSet<String> = embedded_spec_artifact_paths()
        .expect("embedded artifacts must load")
        .into_iter()
        .collect();
    let mut live = BTreeSet::new();
    collect_json_artifact_paths(&artifacts_dir, &artifacts_dir, &mut live);

    assert_eq!(embedded, live, "embedded spec artifact path set drifted");
    for path in live {
        let live_path = artifacts_dir.join(&path);
        let live_text = fs::read_to_string(&live_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", live_path.display()));
        let live_value: Value = serde_json::from_str(&live_text)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", live_path.display()));
        let embedded_value = read_embedded_json_artifact(&path)
            .unwrap_or_else(|error| panic!("embedded artifact {path} failed to load: {error}"));
        assert_eq!(embedded_value, live_value, "artifact {path} drifted");
    }
}

fn fixture_artifact(name: &str) -> Value {
    if let Some(artifacts_dir) = default_spec_artifacts_dir() {
        let path = artifacts_dir.join("fixtures").join(name);
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
    } else {
        read_embedded_json_artifact(&format!("fixtures/{name}")).unwrap()
    }
}

fn assert_warns_additional_field(warnings: &[String], field: &str) {
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("additional field") && warning.contains(field)),
        "expected warning for additional field {field:?}, got {warnings:?}"
    );
}

#[test]
fn schema_catalog_reports_all_registered_schemas() {
    let catalog = schema_catalog();
    catalog.validate().unwrap();
    assert!(
        catalog
            .entries
            .iter()
            .any(|entry| entry.schema_id == EVENT_SCHEMA)
    );
}

#[test]
fn schema_vectors_include_negative_security_extension_case() {
    validate_schema_vectors(&built_in_schema_vectors()).unwrap();
}

#[test]
fn federation_fixture_expected_digest_matches_sdk_canonicalizer() {
    let fixture = fixture_artifact("federation-fixture.json");
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .expect("federation fixture missing cases");
    let case = cases
        .iter()
        .find(|case| {
            case.get("name").and_then(Value::as_str)
                == Some("reducer_profile_digest_federation_minimal")
        })
        .expect("federation fixture missing reducer_profile_digest_federation_minimal");
    let canonical_input = case
        .get("canonical_input")
        .expect("federation reducer profile fixture missing canonical_input");
    let expected_digest = case
        .get("expected_digest")
        .and_then(Value::as_str)
        .expect("federation reducer profile fixture missing expected_digest");

    assert_eq!(
        crate::canonical::canonical_sha256(canonical_input).unwrap(),
        expected_digest
    );
}

#[test]
fn event_payload_catalog_validates_known_payload_fields() {
    let catalog = event_payload_validator_catalog();
    // `ck.strand.move` payload requires Space container ids:
    // `board_space_id` (ck:space prefix) + `target_space_id`.
    catalog
        .validate_payload(
            "ck.strand.move",
            &json!({
                "board_space_id": "ck:space:01904100-0000-7000-8000-111111111111",
                "strand_id": "ck:strand:01904100-0000-7000-8000-6c663fa0205f",
                "target_space_id": "ck:space:01904100-0000-7000-8000-222222222222",
                "rank": "U"
            }),
        )
        .unwrap();
    assert!(matches!(
        catalog.validate_payload(
            "ck.strand.move",
            &json!({
                "strand_id": "ck:strand:01904100-0000-7000-8000-6c663fa0205f",
                "target_space_id": "ck:space:01904100-0000-7000-8000-222222222222",
                "rank": "U"
            })
        ),
        Err(Error::Protocol(_))
    ));
}

#[test]
fn relation_create_payload_strong_type_passes_spec_validator() {
    let catalog = event_payload_validator_catalog();
    let payload = crate::models::RelationCreatePayload::new(
        "ck.relation.parent_of",
        "ck:strand:01904100-0000-7000-8000-111111111111",
        "ck:strand:01904100-0000-7000-8000-222222222222",
    )
    .with_rank("U");
    catalog
        .validate_payload("ck.relation.create", &payload.to_value().unwrap())
        .unwrap();

    // Unknown additive keys are reported but do not fail schema validation.
    let mut leaky = payload.to_value().unwrap();
    leaky["fields"] = json!({"role": "x"});
    let warnings = catalog
        .validate_payload_with_warnings("ck.relation.create", &leaky)
        .unwrap();
    assert_warns_additional_field(&warnings, "fields");
}

#[test]
fn membership_payload_strong_type_passes_spec_validator() {
    use crate::models::{DeliveryStatus, MembershipPayload, MembershipPayloadState};
    let catalog = event_payload_validator_catalog();

    // invite transition (non-join): only `membership` is structurally required.
    let invite = MembershipPayload::transition(
        MembershipPayloadState::Invite,
        crate::models::Did::new("did:web:bob.example").unwrap(),
        "space_create",
    );
    catalog
        .validate_payload("ck.member.state", &invite.to_value().unwrap())
        .unwrap();

    // join transition (unroutable): realm_id + actor_id + delivery_status
    // required, but delivery_binding only when routable.
    let join = MembershipPayload::join(
        crate::models::RealmId::new("ck:realm:01904100-0000-7000-8000-111111111111").unwrap(),
        crate::models::Did::new("did:web:bob.example").unwrap(),
        DeliveryStatus::Unroutable,
        "invite_accept",
    )
    .with_invite_ref("ck:event:01904100-0000-7000-8000-222222222222");
    catalog
        .validate_payload("ck.member.state", &join.to_value().unwrap())
        .unwrap();

    // join missing delivery_status is rejected by to_value (conditional req).
    let mut bad = join.clone();
    bad.delivery_status = None;
    assert!(matches!(bad.to_value(), Err(Error::Protocol(_))));

    // Unknown additive keys are reported but do not fail schema validation.
    let mut leaky = invite.to_value().unwrap();
    leaky["handle"] = json!("bob:example.com");
    let warnings = catalog
        .validate_payload_with_warnings("ck.member.state", &leaky)
        .unwrap();
    assert_warns_additional_field(&warnings, "handle");
}

#[test]
fn invite_payload_strong_types_pass_spec_validator() {
    use crate::models::{
        Did, Hash, InviteCreatePayload, InviteDeliveryTarget, InviteId, InviteRefPayload,
    };
    let catalog = event_payload_validator_catalog();

    // Directed-create (anyOf branch: invitee + invite_delivery_target +
    // introduction_evidence_digest + expires_at), with an `x_role` extension.
    let create = InviteCreatePayload::new(
        InviteId::new("ck:invite:01904100-0000-7000-8000-111111111111").unwrap(),
        Did::new("did:web:bob.example").unwrap(),
        InviteDeliveryTarget::principal_server(Did::new("did:web:ps.example").unwrap()),
        Hash::new("sha256:".to_owned() + &"a".repeat(64)).unwrap(),
        chrono::Utc::now() + chrono::Duration::days(7),
    )
    .with_extension("role", json!("member"));
    let create_value = create.to_value().unwrap();
    assert_eq!(create_value["x_role"], "member");
    catalog
        .validate_payload("ck.invite.create", &create_value)
        .unwrap();
    InviteCreatePayload::from_wire_value(&create_value).unwrap();
    let mut leaky_create = create_value.clone();
    leaky_create["hlc"] = json!("2026-06-14T10:00:00Z/node/1");
    assert!(InviteCreatePayload::from_wire_value(&leaky_create).is_err());

    // invite_id ref form (accept / cancel / revoke).
    let cancel = InviteRefPayload::new(
        InviteId::new("ck:invite:01904100-0000-7000-8000-222222222222").unwrap(),
    )
    .with_reason("withdrawn");
    let cancel_value = cancel.to_value().unwrap();
    catalog
        .validate_payload("ck.invite.cancel", &cancel_value)
        .unwrap();
    catalog
        .validate_payload("ck.invite.revoke", &cancel_value)
        .unwrap();
}

#[test]
fn realm_lifecycle_payloads_strong_types_pass_spec_validator() {
    use crate::models::{
        RealmArchivePayload, RealmDestroyPayload, RealmFreezePayload, RealmId,
        RealmTombstonePayload,
    };
    let catalog = event_payload_validator_catalog();

    // ck.realm.archive: reversible boolean register; `archived:false` un-archives.
    let archive = RealmArchivePayload::new(true).with_reason("retiring inactive realm");
    catalog
        .validate_payload("ck.realm.archive", &archive.to_value().unwrap())
        .unwrap();
    catalog
        .validate_payload(
            "ck.realm.archive",
            &RealmArchivePayload::new(false).to_value().unwrap(),
        )
        .unwrap();

    // ck.realm.freeze: reversible boolean register; `frozen:false` unfreezes.
    let freeze = RealmFreezePayload::new(true).with_reason("incident response hold");
    catalog
        .validate_payload("ck.realm.freeze", &freeze.to_value().unwrap())
        .unwrap();
    catalog
        .validate_payload(
            "ck.realm.freeze",
            &RealmFreezePayload::new(false).to_value().unwrap(),
        )
        .unwrap();

    // ck.realm.tombstone: reason + successor_realm_id both required by spec.
    let tombstone = RealmTombstonePayload::new(
        RealmId::new("ck:realm:01904100-0000-7000-8000-333333333333").unwrap(),
        "migrated to successor",
    );
    catalog
        .validate_payload("ck.realm.tombstone", &tombstone.to_value().unwrap())
        .unwrap();

    // ck.realm.destroy: reason required; verification_stub_required omitted so
    // the reducer applies its default (true).
    let destroy = RealmDestroyPayload::new("permanent retirement");
    catalog
        .validate_payload("ck.realm.destroy", &destroy.to_value().unwrap())
        .unwrap();

    // Unknown additive keys are reported but do not fail schema validation.
    let mut leaky = archive.to_value().unwrap();
    leaky["successor_realm_id"] = json!("ck:realm:01904100-0000-7000-8000-444444444444");
    let warnings = catalog
        .validate_payload_with_warnings("ck.realm.archive", &leaky)
        .unwrap();
    assert_warns_additional_field(&warnings, "successor_realm_id");
}

#[test]
fn strand_lifecycle_payloads_strong_types_pass_spec_validator() {
    use crate::models::{
        Did, ObjectLifecyclePayload, SpaceId, StrandId, StrandMovePayload,
        StrandReorderExpectedPosition, StrandReorderPayload, StrandWatchExpectedValue,
        StrandWatchLevel, StrandWatchSetPayload,
    };
    let catalog = event_payload_validator_catalog();
    let board = || SpaceId::new("ck:space:01904100-0000-7000-8000-111111111111").unwrap();
    let target = || SpaceId::new("ck:space:01904100-0000-7000-8000-222222222222").unwrap();
    let strand = || StrandId::new("ck:strand:01904100-0000-7000-8000-6c663fa0205f").unwrap();
    let actor = || Did::new("did:web:alice.example").unwrap();

    // ck.strand.move — board/target Space ids + rank; from_space_id +
    // expected_position optional. Destination is single-sourced by
    // target_space_id (a stray `list_space_id` is reported as additive).
    let mv = StrandMovePayload::new(board(), strand(), target(), "U")
        .with_from_space_id(board())
        .with_expected_position(crate::models::StrandMoveExpectedPosition {
            space_id: Some(board()),
            rank: Some("T".to_owned()),
            relation_id: None,
        });
    catalog
        .validate_payload("ck.strand.move", &mv.to_value().unwrap())
        .unwrap();

    // ck.strand.reorder — single List Space (`space_id`); no destination field.
    let reorder = StrandReorderPayload::new(board(), strand(), target(), "V")
        .with_expected_position(StrandReorderExpectedPosition {
            rank: Some("U".to_owned()),
            relation_id: None,
        });
    catalog
        .validate_payload("ck.strand.reorder", &reorder.to_value().unwrap())
        .unwrap();

    // ck.strand.watch.set — concrete level + clear (level:null) + CAS guard.
    let set = StrandWatchSetPayload::set(strand(), actor(), StrandWatchLevel::All, Some(true));
    catalog
        .validate_payload("ck.strand.watch.set", &set.to_value().unwrap())
        .unwrap();
    let cleared = StrandWatchSetPayload::clear(strand(), actor());
    let cleared_value = cleared.to_value().unwrap();
    assert!(cleared_value["level"].is_null());
    // allOf: level_public MUST be omitted when level is null.
    assert!(cleared_value.get("level_public").is_none());
    catalog
        .validate_payload("ck.strand.watch.set", &cleared_value)
        .unwrap();
    let guarded =
        StrandWatchSetPayload::set(strand(), actor(), StrandWatchLevel::Participating, None)
            .with_expected_value(Some(StrandWatchExpectedValue {
                level: StrandWatchLevel::Muted,
                level_public: None,
            }));
    catalog
        .validate_payload("ck.strand.watch.set", &guarded.to_value().unwrap())
        .unwrap();
    // expected_value may also assert "no prior cell" via null.
    let guarded_null = StrandWatchSetPayload::set(strand(), actor(), StrandWatchLevel::All, None)
        .with_expected_value(None);
    let guarded_null_value = guarded_null.to_value().unwrap();
    assert!(guarded_null_value["expected_value"].is_null());
    catalog
        .validate_payload("ck.strand.watch.set", &guarded_null_value)
        .unwrap();

    // ck.strand.archive / ck.strand.restore — object_lifecycle_payload, single
    // truth source `target_ref`.
    let archive = ObjectLifecyclePayload::new("ck:strand:01904100-0000-7000-8000-6c663fa0205f")
        .with_target_state("archived")
        .with_reason("season closed");
    catalog
        .validate_payload("ck.strand.archive", &archive.to_value().unwrap())
        .unwrap();
    catalog
        .validate_payload(
            "ck.strand.restore",
            &ObjectLifecyclePayload::new("ck:strand:01904100-0000-7000-8000-6c663fa0205f")
                .to_value()
                .unwrap(),
        )
        .unwrap();

    // Unknown additive keys are reported but do not fail schema validation.
    let mut leaky = mv.to_value().unwrap();
    leaky["list_space_id"] = json!("ck:space:01904100-0000-7000-8000-222222222222");
    let warnings = catalog
        .validate_payload_with_warnings("ck.strand.move", &leaky)
        .unwrap();
    assert_warns_additional_field(&warnings, "list_space_id");
}

#[test]
fn realm_state_payloads_strong_types_match_named_spec_defs() {
    // Validate the strong types directly against the named `$defs/*_payload`
    // schema_ref so this test stays pinned to the exact artifact shape.
    use crate::models::{
        Did, HistoryKeyShareDefault, HistoryKeySource, HistorySharingPolicyPayload,
        HistorySharingPolicyPayloadValue, HistorySharingPolicyPayloadValueAudit, HistoryVisibility,
        HistoryVisibilityPayload, PlaintextDataClassKind, PlaintextServiceVisibility,
        PlaintextVisibleService, PlaintextVisibleServicesPayload,
    };
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let registry = schema_registry_from_spec_artifacts(&artifacts_dir).unwrap();
    let catalog = event_payload_validator_catalog_from_spec_artifacts(&artifacts_dir).unwrap();
    let history_ref = format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/history_visibility_payload");
    let history_policy_ref =
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/history_sharing_policy_payload");
    let services_ref = format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/plaintext_visible_services_payload");

    // history_visibility: non-restricted value carries just `{value}`.
    let shared = HistoryVisibilityPayload::new(HistoryVisibility::Shared);
    registry
        .validate_value(&history_ref, &shared.to_value().unwrap())
        .unwrap();
    catalog
        .validate_payload(
            crate::events::REALM_HISTORY_VISIBILITY,
            &shared.to_value().unwrap(),
        )
        .unwrap();
    // restricted requires restricted_policy_digest (schema allOf); to_value
    // refuses to emit a non-conformant restricted payload.
    assert!(
        HistoryVisibilityPayload::new(HistoryVisibility::Restricted)
            .to_value()
            .is_err()
    );
    let restricted = HistoryVisibilityPayload::restricted("sha256:".to_owned() + &"a".repeat(64));
    registry
        .validate_value(&history_ref, &restricted.to_value().unwrap())
        .unwrap();
    // Unknown additive keys are reported but do not fail schema validation.
    let mut leaky = shared.to_value().unwrap();
    leaky["unexpected"] = json!(true);
    let warnings = registry
        .validate_value_with_warnings(&history_ref, &leaky)
        .unwrap();
    assert_warns_additional_field(&warnings, "unexpected");

    let history_policy = HistorySharingPolicyPayload {
        value: HistorySharingPolicyPayloadValue {
            version: 1,
            default_key_share: HistoryKeyShareDefault::EventTimeVisibility,
            pre_join_history: None,
            post_removal_recovery: None,
            allowed_key_sources: vec![HistoryKeySource::VerifiedMemberDevice],
            allowed_receiver_states: None,
            audit: HistorySharingPolicyPayloadValueAudit {
                share_audit_event_required: false,
                access_audit_required: false,
            },
            restricted_rules: None,
        },
        reason: None,
    };
    let history_policy_value = serde_json::to_value(&history_policy).unwrap();
    registry
        .validate_value(&history_policy_ref, &history_policy_value)
        .unwrap();
    catalog
        .validate_payload(
            crate::events::REALM_HISTORY_SHARING_POLICY,
            &history_policy_value,
        )
        .unwrap();

    // plaintext_visible_services: required item fields strongly typed.
    let services = PlaintextVisibleServicesPayload::new(vec![PlaintextVisibleService::new(
        Did::new("did:web:index.example").unwrap(),
        "principal_server",
        vec![
            PlaintextDataClassKind::MessageContent,
            PlaintextDataClassKind::FullTextIndex,
            PlaintextDataClassKind::NotificationSummary,
            PlaintextDataClassKind::InboxPreview,
        ],
        vec!["message_index".to_owned(), "notification_fanout".to_owned()],
        PlaintextServiceVisibility::PrivatePlaintext,
    )]);
    registry
        .validate_value(&services_ref, &services.to_value().unwrap())
        .unwrap();
    // Top-level additive keys are warnings, not schema violations.
    let mut leaky_services = services.to_value().unwrap();
    leaky_services["unexpected"] = json!(true);
    let warnings = registry
        .validate_value_with_warnings(&services_ref, &leaky_services)
        .unwrap();
    assert_warns_additional_field(&warnings, "unexpected");
}

#[test]
fn artifact_payload_catalog_enforces_deep_schema_rules() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();
    // `ck.strand.move` requires current Space container ids:
    // `board_space_id` and `target_space_id`.
    catalog
        .validate_payload(
            crate::events::STRAND_MOVE,
            &json!({
                "board_space_id": "ck:space:01904100-0000-7000-8000-111111111111",
                "strand_id": "ck:strand:01904100-0000-7000-8000-6c663fa0205f",
                "target_space_id": "ck:space:01904100-0000-7000-8000-222222222222",
                "rank": "U"
            }),
        )
        .unwrap();
    assert!(
        catalog
            .validate_payload(
                crate::events::STRAND_MOVE,
                &json!({
                    "board_space_id": "not-a-space-id",
                    "strand_id": "ck:strand:01904100-0000-7000-8000-6c663fa0205f",
                    "target_space_id": "ck:space:01904100-0000-7000-8000-222222222222",
                    "rank": "U"
                }),
            )
            .is_err()
    );
    let warnings = catalog
        .validate_payload_with_warnings(
            crate::events::STRAND_MOVE,
            &json!({
                "board_space_id": "ck:space:01904100-0000-7000-8000-111111111111",
                "strand_id": "ck:strand:01904100-0000-7000-8000-6c663fa0205f",
                "target_space_id": "ck:space:01904100-0000-7000-8000-222222222222",
                "rank": "U",
                "unexpected": true
            }),
        )
        .unwrap();
    assert_warns_additional_field(&warnings, "unexpected");
}

#[test]
fn artifact_payload_catalog_prefers_registered_specialized_defs_over_name_matches() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();

    assert_eq!(
        catalog.rules["ck.space.archive"].payload_schema_id,
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/space_state_transition_payload")
    );
    assert_eq!(
        catalog.rules["ck.space.restore"].payload_schema_id,
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/space_state_transition_payload")
    );
    assert_eq!(
        catalog.rules["ck.space.tombstone"].payload_schema_id,
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/space_object_tombstone_payload")
    );

    catalog
        .validate_payload(
            "ck.space.archive",
            &json!({
                "space_id": "ck:space:01904100-0000-7000-8000-111111111111",
                "reason": "done"
            }),
        )
        .unwrap();
    assert!(
        catalog
            .validate_payload("ck.space.archive", &json!({ "archived": true }))
            .is_err()
    );
}

#[test]
fn artifact_payload_catalog_maps_patch_event_family_to_canonical_payloads() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();
    let patch_kinds = [
        (
            "ck.realm.update",
            "object_patch_payload",
            json!({
                "target_ref": "ck:realm:0196419b-0000-7000-8000-000000000001",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
        ),
        (
            "ck.strand.update",
            "strand_patch_payload",
            json!({
                "target_ref": "ck:strand:0196419b-0000-7000-8000-000000000001",
                "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
            }),
        ),
        (
            "ck.morph.update",
            "morph_update_payload",
            json!({
                "target_ref": "ck:morph:0196419b-0000-7000-8000-000000000001",
                "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
            }),
        ),
        (
            "ck.space.update",
            "space_patch_payload",
            json!({
                "space_id": "ck:space:0196419b-0000-7000-8000-000000000001",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
        ),
        (
            "ck.profile.update",
            "object_patch_payload",
            json!({
                "target_ref": "ck:actor_profile:0196419b-0000-7000-8000-000000000001",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
        ),
    ];
    for (event_kind, payload_def, payload) in patch_kinds {
        assert_eq!(
            catalog.rules[event_kind].payload_schema_id,
            format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/{payload_def}"),
            "{event_kind} must use the canonical patch payload schema"
        );
        catalog
            .validate_payload(event_kind, &payload)
            .unwrap_or_else(|err| panic!("{event_kind} should accept {payload_def}: {err}"));
    }
    // ck.profile.realm_override carries a Realm-scoped override and needs
    // target_realm_id in addition to target_ref+patch, so the spec gives it a
    // dedicated profile_realm_override_payload def rather than folding it into
    // the generic object_patch_payload.
    assert_eq!(
        catalog.rules["ck.profile.realm_override"].payload_schema_id,
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/profile_realm_override_payload"),
        "ck.profile.realm_override must use the dedicated profile_realm_override_payload schema"
    );
    catalog
        .validate_payload(
            "ck.profile.realm_override",
            &json!({
                "target_ref": "ck:actor_profile:0196419b-0000-7000-8000-000000000001",
                "target_realm_id": "ck:realm:0196419b-0000-7000-8000-000000000002",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
        )
        .unwrap_or_else(|err| {
            panic!("ck.profile.realm_override should accept profile_realm_override_payload: {err}")
        });
    assert_eq!(
        catalog.rules["ck.strand.tracks.update"].payload_schema_id,
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/generic_standard_payload"),
        "ck.strand.tracks.update has dedicated track-table semantics and must not be folded into object_patch_payload"
    );
    catalog
        .validate_payload(
            "ck.strand.tracks.update",
            &json!({
                "strand_id": "ck:strand:0196419b-0000-7000-8000-000000000001",
                "tracks": {
                    "main": { "title": "Main", "rank": "a0" }
                }
            }),
        )
        .unwrap_or_else(|err| {
            panic!("ck.strand.tracks.update should accept track payloads: {err}")
        });
    assert!(
        catalog
            .validate_payload(
                "ck.strand.tracks.update",
                &json!({
                    "type": "ck.strand.tracks.update",
                    "strand_id": "ck:strand:0196419b-0000-7000-8000-000000000001"
                }),
            )
            .is_err(),
        "ck.strand.tracks.update must still reject the retired type discriminator"
    );
    assert!(
        catalog
            .validate_payload(
                "ck.strand.update",
                &json!({
                    "target_ref": "ck:morph:0196419b-0000-7000-8000-000000000001",
                    "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
                }),
            )
            .is_err(),
        "ck.strand.update target_ref must be a Strand id"
    );
}

#[test]
fn morph_update_payload_rejects_create_locked_morph_type() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();

    catalog
        .validate_payload(
            "ck.morph.update",
            &json!({
                "target_ref": "ck:morph:0196419b-0000-7000-8000-000000000001",
                "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
            }),
        )
        .unwrap();
    assert!(
        catalog
            .validate_payload(
                "ck.morph.update",
                &json!({
                    "target_ref": "ck:morph:0196419b-0000-7000-8000-000000000001",
                    "patch": { "morph_type": { "$op": "set", "value": "task" } }
                }),
            )
            .is_err(),
        "ck.morph.update must reject create-locked morph_type changes"
    );
    assert!(
        catalog
            .validate_payload(
                "ck.morph.update",
                &json!({
                    "target_ref": "ck:strand:0196419b-0000-7000-8000-000000000001",
                    "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
                }),
            )
            .is_err(),
        "ck.morph.update target_ref must be a Morph id"
    );
}

#[test]
fn artifact_payload_catalog_enforces_invite_create_payload_shape() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();
    let payload = json!({
        "invite_id": "ck:invite:01904100-0000-7000-8000-000000000001",
        "invitee": "did:web:bob.example",
        "invite_delivery_target": {
            "recipient_service_did": "did:web:server.example",
            "recipient_service_type": "principal_server"
        },
        "introduction_evidence_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "expires_at": "2026-06-14T10:00:00Z",
        "x_role": "member"
    });

    assert_eq!(
        catalog.rules[crate::events::INVITE_CREATE].payload_schema_id,
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/invite_payload")
    );
    assert!(
        catalog.rules[crate::events::INVITE_CREATE]
            .required_fields
            .iter()
            .any(|field| field == "invite_id"),
        "ck.invite.create must require invite_id"
    );
    catalog
        .validate_payload(crate::events::INVITE_CREATE, &payload)
        .unwrap_or_else(|err| panic!("ck.invite.create should accept directed invite: {err}"));

    let mut missing_invite_id = payload.clone();
    missing_invite_id
        .as_object_mut()
        .unwrap()
        .remove("invite_id");
    assert!(
        catalog
            .validate_payload(crate::events::INVITE_CREATE, &missing_invite_id)
            .is_err(),
        "ck.invite.create must reject directed invite payloads without invite_id"
    );

    let mut missing_expires_at = payload;
    missing_expires_at
        .as_object_mut()
        .unwrap()
        .remove("expires_at");
    assert!(
        catalog
            .validate_payload(crate::events::INVITE_CREATE, &missing_expires_at)
            .is_err(),
        "ck.invite.create must reject directed invite payloads without expires_at"
    );
}

#[test]
fn artifact_payload_catalog_enforces_external_schema_refs_and_enums() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();
    let key = json!({
        "kid": "did:web:alice.example#psk-1",
        "alg": "EdDSA",
        "public_key": "z6MkiExample",
        "key_format": "multibase"
    });
    let subordinate_key = json!({
        "kid": "did:web:alice.example#ssk-1",
        "alg": "EdDSA",
        "public_key": "z6MkiExampleSub",
        "key_format": "multibase",
        "binding": {
            "verification_method": "did:web:alice.example#psk-1",
            "alg": "EdDSA",
            "signature": "sig"
        }
    });
    catalog
        .validate_payload(
            crate::events::CROSS_SIGNING_PUBLISH,
            &json!({
                "principal_id": "did:web:alice.example",
                "trust_domain": "ck:trust_domain:example.net",
                "principal_signing_key": key,
                "self_signing_key": subordinate_key,
                "user_signing_key": subordinate_key,
                "expected_previous_generation": 0,
                "generation": 1,
                "issued_at": "2026-05-02T00:00:00Z"
            }),
        )
        .unwrap();
    assert!(
        catalog
            .validate_payload(
                crate::events::CROSS_SIGNING_PUBLISH,
                &json!({
                    "principal_id": "did:web:alice.example",
                    "principal_signing_key": key,
                    "self_signing_key": subordinate_key,
                    "user_signing_key": subordinate_key,
                    "generation": 0,
                    "issued_at": "2026-05-02T00:00:00Z"
                }),
            )
            .is_err()
    );
}

#[test]
fn schema_registry_enforces_json_schema_composition_and_value_rules() {
    let mut registry = ProtocolSchemaRegistry::new();
    registry.register(
        "ck.schema.deep_test.v1",
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "ck.schema.deep_test.v1",
            "type": "object",
            "required": ["kind", "items", "target"],
            "properties": {
                "kind": {"const": "demo"},
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string", "pattern": "^[a-z]+$"}
                },
                "target": {
                    "oneOf": [
                        {"type": "string", "enum": ["user", "space"]},
                        {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}
                    ]
                }
            },
            "allOf": [{"properties": {"kind": {"type": "string"}}}],
            "patternProperties": {
                "^x_[a-z][a-z0-9_]{0,63}$": {"type": "string"}
            },
            "additionalProperties": false
        }),
    );
    registry
        .validate_value(
            "ck.schema.deep_test.v1",
            &json!({"kind": "demo", "items": ["alpha"], "target": "user", "x_role": "member"}),
        )
        .unwrap();
    assert!(
        registry
            .validate_value(
                "ck.schema.deep_test.v1",
                &json!({"kind": "demo", "items": [], "target": "user"}),
            )
            .is_err()
    );
    assert!(
        registry
            .validate_value(
                "ck.schema.deep_test.v1",
                &json!({"kind": "demo", "items": ["alpha"], "target": "other"}),
            )
            .is_err()
    );
    assert!(
        registry
            .validate_value(
                "ck.schema.deep_test.v1",
                &json!({"kind": "other", "items": ["alpha"], "target": "user"}),
            )
            .is_err()
    );
    let warnings = registry
        .validate_value_with_warnings(
            "ck.schema.deep_test.v1",
            &json!({"kind": "demo", "items": ["alpha"], "target": "user", "extra": true}),
        )
        .unwrap();
    assert_warns_additional_field(&warnings, "extra");
    assert!(
        registry
            .validate_value(
                "ck.schema.deep_test.v1",
                &json!({"kind": "demo", "items": ["alpha"], "target": "user", "x_role": false}),
            )
            .is_err()
    );
}

#[test]
fn component_descriptor_resolves_canonical_and_alias_kinds() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let bundle = SpecArtifactBundle::load(artifacts_dir).unwrap();

    // Canonical kind owns its slot — no alias_of.
    let canonical = bundle
        .component("ck.capability.grant")
        .unwrap()
        .expect("ck.capability.grant should be registered");
    assert_eq!(canonical.criticality, Criticality::Required);
    assert!(canonical.component_type.starts_with("ck.component."));
    assert!(canonical.component_version >= 1);
    assert!(canonical.component_slot_alias_of.is_none());

    // Alias kind shares the canonical kind's slot.
    let alias = bundle
        .component("ck.capability.revoke")
        .unwrap()
        .expect("ck.capability.revoke should be registered");
    assert_eq!(
        alias.component_slot_alias_of.as_deref(),
        Some("ck.capability.grant"),
        "ck.capability.revoke should slot-alias ck.capability.grant"
    );
    assert_eq!(alias.component_type, canonical.component_type);
    assert_eq!(alias.component_version, canonical.component_version);

    // Unknown kind is a clean None, not an error.
    assert!(bundle.component("ck.bogus.kind").unwrap().is_none());
}

#[test]
fn evolution_plan_rejects_breaking_release_candidate() {
    let mut breaking_changes = BTreeSet::new();
    breaking_changes.insert(SchemaBreakingChange::NewRequiredField);
    let plan = SchemaEvolutionPlan {
        from_version: "0.1.0".to_owned(),
        to_version: "0.2.0".to_owned(),
        affected_schemas: vec![EVENT_SCHEMA.to_owned()],
        breaking_changes,
    };
    assert!(matches!(
        plan.validate_release_candidate(),
        Err(Error::Protocol(_))
    ));
}
