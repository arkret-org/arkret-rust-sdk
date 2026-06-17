use chrono::Utc;
use serde_json::json;

use super::super::*;

#[test]
fn rank_helpers_generate_between_and_rebalance_assignments() {
    let first = rank_between(None, None).unwrap();
    let second = rank_between(Some(&first), None).unwrap();
    assert!(first < second);
    assert!(rank_exhausted(Some("r:0000000000000001"), Some("r:0000000000000002")).unwrap());

    let assignments = container_rebalance_assignments(&[
        "ck:morph:01904100-0000-7000-8000-8b4aa2ca29ef".to_owned(),
        "ck:morph:01904100-0000-7000-8000-d5864c129df4".to_owned(),
        "ck:morph:01904100-0000-7000-8000-6057e4215f24".to_owned(),
    ])
    .unwrap();
    assert_eq!(assignments.len(), 3);
    assert!(assignments[0].rank < assignments[1].rank);
    assert!(assignments[1].rank < assignments[2].rank);
}

#[test]
fn strand_constructor_sets_protocol_shape() {
    let mut subject = Strand::new(
        StrandId::new("ck:strand:01904100-0000-7000-8000-6c663fa0205f").unwrap(),
        RealmId::new("ck:realm:01904100-0000-7000-8000-fd3637e8361f").unwrap(),
        "Payment refactor",
        Did::new("did:web:alice.example").unwrap(),
    );

    assert_eq!(subject.schema, STRAND_SCHEMA);
    assert!(
        serde_json::to_value(&subject)
            .unwrap()
            .get("type")
            .is_none()
    );
    assert!(subject.tracks.contains_key("synthesis"));
    assert_eq!(subject.state, Some(ObjectState::Active));
    subject.validate_title().unwrap();

    subject = subject.with_metadata_title(" ");
    assert!(subject.validate_title().is_err());
}

/// T21 — typed Strand::discussion shorthand for chat-style strands.
#[test]
fn strand_discussion_constructor_sets_room_shape() {
    let strand = Strand::discussion(
        StrandId::new("ck:strand:01904100-0000-7000-8000-58754cf88c25").unwrap(),
        RealmId::new("ck:realm:01904100-0000-7000-8000-2007b59d0dc4").unwrap(),
        "Launch board discussion",
        Did::new("did:web:alice.example").unwrap(),
    );
    assert!(strand.is_conversational());
    assert_eq!(strand.tracks.len(), 2, "synthesis + discussion expected");

    let synthesis = strand
        .tracks
        .get("synthesis")
        .expect("synthesis track present");
    assert!(synthesis.is_primary != Some(true));

    let discussion = strand
        .tracks
        .get("discussion")
        .expect("discussion track present");
    assert_eq!(discussion.is_primary, Some(true));
    assert_eq!(discussion.profile.as_deref(), Some("discussion"));
}

#[test]
fn read_scope_strand_track_uses_explicit_track_field() {
    let scope = ReadScope::strand(
        "ck:strand:01904100-0000-7000-8000-58754cf88c25",
        Some("discussion"),
    );
    scope.validate().unwrap();

    let value = serde_json::to_value(&scope).unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "kind": "strand",
            "ref": "ck:strand:01904100-0000-7000-8000-58754cf88c25",
            "track_name": "discussion"
        })
    );
}

#[test]
fn read_scope_rejects_removed_track_kind_variants() {
    let old = serde_json::json!("strand_discussion");
    assert!(serde_json::from_value::<ReadScope>(old).is_err());
}

/// T21 — synthesis-only Strands are not conversational.
#[test]
fn synthesis_strand_is_not_conversational() {
    let strand = Strand::new(
        StrandId::new("ck:strand:01904100-0000-7000-8000-58754cf88c25").unwrap(),
        RealmId::new("ck:realm:01904100-0000-7000-8000-2007b59d0dc4").unwrap(),
        "Launch board synthesis",
        Did::new("did:web:alice.example").unwrap(),
    );
    assert!(!strand.is_conversational());
}

/// T21 — StrandTrackConfig typed constructors honour the standard
/// profile from spec §6.1; track names live in the parent map keys.
#[test]
fn strand_track_typed_constructors() {
    let synth = StrandTrackConfig::synthesis();
    assert!(synth.profile.is_none());
    assert!(synth.is_primary.is_none());
    validate_strand_track_name(STRAND_TRACK_NAME_SYNTHESIS).unwrap();

    let disc = StrandTrackConfig::discussion();
    assert_eq!(disc.profile.as_deref(), Some("discussion"));
    assert!(disc.is_primary.is_none());
    validate_strand_track_name(STRAND_TRACK_NAME_DISCUSSION).unwrap();

    let primary = StrandTrackConfig::discussion_primary();
    assert_eq!(primary.is_primary, Some(true));

    let custom = StrandTrackConfig::new().with_profile("review").primary();
    assert_eq!(custom.profile.as_deref(), Some("review"));
    assert_eq!(custom.is_primary, Some(true));
    validate_strand_track_name("review").unwrap();
}

/// Realm seal fields default to None (notary cell is the source
/// of truth) and the builders set them to expected values.
#[test]
fn realm_anchor_fields_default_none_and_builders_apply() {
    use crate::notary::NotaryValue;

    let mut realm = Realm::new(
        RealmId::new("ck:realm:0196419b-0000-7000-8000-000000000001").unwrap(),
        "Seal Test",
        Did::new("did:web:alice.example").unwrap(),
        TypedTrustDomainId::new("ck:trust_domain:example.net").unwrap(),
    );
    assert!(realm.notary_profile.is_none());
    assert!(realm.notary.is_none());
    assert!(realm.revocation_freshness_window_ms.is_none());
    assert!(realm.cell_lattices.is_empty());
    assert!(realm.co_write_policy.is_none());

    realm = realm
        .with_notary_profile(NotaryProfile::Threshold)
        .with_notary(NotaryValue::Threshold {
            k: 2,
            n: 3,
            members: vec![
                Did::new("did:web:a.example").unwrap(),
                Did::new("did:web:b.example").unwrap(),
                Did::new("did:web:c.example").unwrap(),
            ],
        })
        .with_revocation_freshness_window(60_000)
        .with_cell_lattice(
            "ck.component.strand.track.v1",
            "or_set",
            Some("reject".to_owned()),
        )
        .with_co_write_policy(CoWritePolicy::CausalOnly);

    assert_eq!(realm.notary_profile, Some(NotaryProfile::Threshold));
    assert!(matches!(
        realm.notary,
        Some(NotaryValue::Threshold { k: 2, n: 3, .. })
    ));
    assert_eq!(realm.revocation_freshness_window_ms, Some(60_000));
    assert_eq!(realm.cell_lattices.len(), 1);
    assert_eq!(
        realm.cell_lattices[0].cell_family,
        "ck.component.strand.track.v1"
    );
    assert_eq!(realm.cell_lattices[0].lattice, "or_set");
    assert_eq!(realm.cell_lattices[0].bottom.as_deref(), Some("reject"));
    assert_eq!(realm.co_write_policy, Some(CoWritePolicy::CausalOnly));

    // Round-trip through serde to confirm wire shape.
    let json = serde_json::to_value(&realm).unwrap();
    assert_eq!(json["notary_profile"], "threshold");
    assert_eq!(json["revocation_freshness_window_ms"], 60_000);
    assert_eq!(json["co_write_policy"], "causal_only");
    assert_eq!(
        json["cell_lattices"][0]["cell_family"],
        "ck.component.strand.track.v1"
    );

    let restored: Realm = serde_json::from_value(json).unwrap();
    assert_eq!(restored.notary_profile, realm.notary_profile);
    assert_eq!(
        restored.revocation_freshness_window_ms,
        realm.revocation_freshness_window_ms
    );
    assert_eq!(restored.co_write_policy, realm.co_write_policy);
}

/// `Realm::new` omits seal fields from the wire when they're
/// `None` (skip_serializing_if), so sparse fixtures stay clean.
#[test]
fn realm_anchor_fields_omitted_when_none() {
    let realm = Realm::new(
        RealmId::new("ck:realm:0196419b-0000-7000-8000-000000000002").unwrap(),
        "No Seal Hint",
        Did::new("did:web:alice.example").unwrap(),
        TypedTrustDomainId::new("ck:trust_domain:example.net").unwrap(),
    );
    let json = serde_json::to_value(&realm).unwrap();
    let obj = json.as_object().unwrap();
    assert!(!obj.contains_key("notary_profile"));
    assert!(!obj.contains_key("notary"));
    assert!(!obj.contains_key("revocation_freshness_window_ms"));
    assert!(!obj.contains_key("cell_lattices"));
    assert!(!obj.contains_key("co_write_policy"));
}

/// T20 — CollectionProjectionOutcome round-trips through serde with
/// the exact wire shape from `models/views.md` §6.3, including the
/// nested groups -> items -> position / discussion structure.
#[test]
fn collection_projection_response_serde_round_trip() {
    let payload = serde_json::json!({
        "kind": "collection",
        "renderer": "board",
        "view_id": "ck:view:019641be-0000-7000-8000-000000000000",
        "frontier": ["ck:event:01904100-0000-7000-8000-69b393b5179f"],
        "groups": [
            {
                "group_id": "ck:space:01c3b617-7000-7000-8000-000000000000",
                "title": "Review",
                "rank": "mV",
                "items": [
                    {
                        "object": {
                            "id": "ck:strand:01d2b330-0000-7000-8000-000000000000",
                            "type": "strand",
                            "title": "Legal review"
                        },
                        "position": {
                            "relation_id": "ck:relation:01b03200-0000-7000-8000-000000000000",
                            "rank": "mV"
                        },
                        "discussion": {
                            "enabled": true,
                            "visibility": "locked",
                            "lazy_link": true
                        }
                    }
                ]
            }
        ]
    });
    let resp: CollectionProjectionOutcome =
        serde_json::from_value(payload.clone()).expect("deserialize");
    assert!(matches!(resp.kind, ViewKind::Collection));
    assert!(matches!(resp.renderer, ViewRenderer::Board));
    assert_eq!(
        resp.view_id.as_str(),
        "ck:view:019641be-0000-7000-8000-000000000000"
    );
    assert_eq!(resp.frontier.len(), 1);
    assert_eq!(resp.groups.len(), 1);
    let group = &resp.groups[0];
    assert_eq!(
        group.group_id,
        "ck:space:01c3b617-7000-7000-8000-000000000000"
    );
    assert_eq!(group.title, "Review");
    assert_eq!(group.rank.as_deref(), Some("mV"));
    assert_eq!(group.items.len(), 1);
    let item = &group.items[0];
    assert_eq!(
        item.object.get("id").and_then(|v| v.as_str()),
        Some("ck:strand:01d2b330-0000-7000-8000-000000000000")
    );
    let position = item.position.as_ref().expect("position");
    assert_eq!(
        position.relation_id,
        "ck:relation:01b03200-0000-7000-8000-000000000000"
    );
    assert_eq!(position.rank, "mV");
    let discussion = item.discussion.as_ref().expect("discussion");
    assert!(discussion.enabled);
    assert_eq!(discussion.visibility, "locked");
    assert!(discussion.lazy_link);

    // Re-serialize: the resulting JSON must be structurally
    // equivalent (same set of fields with same values).
    let reserialized = serde_json::to_value(&resp).expect("serialize");
    assert_eq!(reserialized, payload);
}

/// T20 — `hidden_count` is omitted from the wire when absent (None)
/// so policy-tight responses don't accidentally leak a 0 count.
#[test]
fn collection_projection_group_omits_hidden_count_when_none() {
    let group = CollectionProjectionGroup {
        group_id: "ck:space:01904100-0000-7000-8000-b83c6d2ca363".to_owned(),
        title: "List".to_owned(),
        rank: Some("a0".to_owned()),
        items: Vec::new(),
        hidden_count: None,
    };
    let json = serde_json::to_value(&group).unwrap();
    assert!(
        json.get("hidden_count").is_none(),
        "hidden_count must be omitted when None to avoid leaking aggregate counts"
    );
}

/// T20 — discussion.lazy_link defaults to false when omitted on the
/// wire (e.g. for fully readable rooms) so caller's branch logic
/// stays simple.
#[test]
fn collection_projection_discussion_lazy_link_defaults_false() {
    let payload = serde_json::json!({
        "enabled": true,
        "visibility": "readable"
    });
    let d: CollectionProjectionDiscussion = serde_json::from_value(payload).unwrap();
    assert!(d.enabled);
    assert_eq!(d.visibility, "readable");
    assert!(!d.lazy_link);
}

// Field-order guard for common-fields.md §3.2, adapted from origin 71c0e0d.
// `top_level_keys` extracts top-level keys by string position because this
// workspace does not enable serde_json preserve_order; `Value` would reorder
// keys. `assert_field_order` checks the machine-verifiable wire-key order.

fn top_level_keys(json: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let bytes = json.as_bytes();
    let mut depth: i32 = 0;
    let mut i = 0;
    let mut in_string = false;
    let mut current = String::new();
    let mut expecting_key = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if in_string {
            if c == '\\' {
                if expecting_key {
                    current.push(c);
                    if i + 1 < bytes.len() {
                        current.push(bytes[i + 1] as char);
                    }
                }
                i += 2;
                continue;
            }
            if c == '"' {
                in_string = false;
                i += 1;
                continue;
            }
            if expecting_key {
                current.push(c);
            }
            i += 1;
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                expecting_key = depth == 1;
                if expecting_key {
                    current.clear();
                }
            }
            ':' if depth == 1 && !current.is_empty() => {
                keys.push(std::mem::take(&mut current));
            }
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            _ => {}
        }
        i += 1;
    }
    keys
}

fn assert_field_order(object: &str, keys: &[String]) {
    let pos = |name: &str| keys.iter().position(|k| k == name);
    if let (Some(id), Some(schema)) = (pos("id"), pos("schema")) {
        assert!(
            id < schema,
            "{object}: `id` MUST precede `schema` (§3.2 identity cluster)"
        );
    }
    if let (Some(cb), Some(ca)) = (pos("created_by"), pos("created_at")) {
        assert!(
            cb < ca,
            "{object}: `created_by` MUST precede `created_at` (§3.2)"
        );
    }
    if let (Some(ub), Some(ua)) = (pos("updated_by"), pos("updated_at")) {
        assert!(
            ub < ua,
            "{object}: `updated_by` MUST precede `updated_at` (§3.2)"
        );
    }
    if let (Some(ca), Some(ua)) = (pos("created_at"), pos("updated_at")) {
        assert!(
            ca < ua,
            "{object}: `created_at` MUST precede `updated_at` (§3.2)"
        );
    }
    if let (Some(s), Some(sca)) = (pos("state"), pos("state_changed_at")) {
        assert_eq!(
            sca,
            s + 1,
            "{object}: `state_changed_at` MUST immediately follow `state` (§3.2)"
        );
    }
    if let (Some(st), Some(stca)) = (pos("stage"), pos("stage_changed_at")) {
        assert_eq!(
            stca,
            st + 1,
            "{object}: `stage_changed_at` MUST immediately follow `stage` (§3.2)"
        );
    }
    let audit_start = pos("created_by").or_else(|| pos("created_at"));
    if let Some(audit) = audit_start {
        for container in ["metadata", "fields"] {
            if let Some(c) = pos(container) {
                assert!(
                    c < audit,
                    "{object}: `{container}` MUST be in the content/config cluster, before the audit cluster (§3.2)"
                );
            }
        }
    }
}

#[test]
fn morph_schema_refs_are_required_non_empty_and_unique() {
    let morph = Morph::new(
        MorphId::new("ck:morph:01904100-0000-7000-8000-0000000000b0").unwrap(),
        RealmId::new("ck:realm:01904100-0000-7000-8000-0000000000b1").unwrap(),
        "ck.demo.morph",
        Did::new("did:web:alice.example").unwrap(),
    );
    let value = serde_json::to_value(&morph).unwrap();
    assert_eq!(value["schema_refs"], json!([MORPH_SCHEMA]));

    let mut missing = value.clone();
    missing.as_object_mut().unwrap().remove("schema_refs");
    assert!(serde_json::from_value::<Morph>(missing).is_err());

    let mut empty = value.clone();
    empty["schema_refs"] = json!([]);
    assert!(serde_json::from_value::<Morph>(empty).is_err());

    let mut duplicate = value;
    duplicate["schema_refs"] = json!([MORPH_SCHEMA, MORPH_SCHEMA]);
    assert!(serde_json::from_value::<Morph>(duplicate).is_err());
}

#[test]
fn morph_labels_are_sdk_local_not_wire() {
    let mut morph = Morph::new(
        MorphId::new("ck:morph:01904100-0000-7000-8000-0000000000c0").unwrap(),
        RealmId::new("ck:realm:01904100-0000-7000-8000-0000000000c1").unwrap(),
        "ck.demo.morph",
        Did::new("did:web:alice.example").unwrap(),
    );
    morph.labels.push("urgent".to_owned());

    let value = serde_json::to_value(&morph).unwrap();
    assert!(
        value.get("labels").is_none(),
        "Morph.labels is SDK-local until morph.schema.json defines a wire field"
    );

    let mut inbound = value;
    inbound["labels"] = json!(["wire-label"]);
    let parsed: Morph = serde_json::from_value(inbound).unwrap();
    assert!(parsed.labels.is_empty());
    assert_eq!(parsed.extra.get("labels"), Some(&json!(["wire-label"])));
}

#[test]
fn materialized_objects_serialize_field_clusters_per_common_fields_3_2() {
    let created_by = Did::new("did:web:alice.example").unwrap();
    let updated_by = Did::new("did:web:bob.example").unwrap();
    let now = Utc::now();

    // Strand — id, schema, …, state, state_changed_at, stage, stage_changed_at, audit.
    let mut strand = Strand::new(
        StrandId::new("ck:strand:01904100-0000-7000-8000-0000000000f0").unwrap(),
        RealmId::new("ck:realm:01904100-0000-7000-8000-0000000000f1").unwrap(),
        "Order guard strand",
        created_by.clone(),
    );
    strand.state_changed_at = Some(now);
    strand.stage_changed_at = Some(now);
    strand.updated_by = Some(updated_by.clone());
    strand.updated_at = Some(now);
    assert_field_order(
        "Strand",
        &top_level_keys(&serde_json::to_string(&strand).unwrap()),
    );

    // Morph — scope/container cluster `scope_circle_id` precedes lifecycle `state`.
    let mut morph = Morph::new(
        MorphId::new("ck:morph:01904100-0000-7000-8000-0000000000a0").unwrap(),
        RealmId::new("ck:realm:01904100-0000-7000-8000-0000000000a1").unwrap(),
        "ck.demo.morph",
        created_by.clone(),
    )
    .with_metadata_title("Demo morph");
    morph.state_changed_at = Some(now);
    let morph_keys = top_level_keys(&serde_json::to_string(&morph).unwrap());
    assert_field_order("Morph", &morph_keys);
    if let (Some(scope), Some(state)) = (
        morph_keys.iter().position(|k| k == "scope_circle_id"),
        morph_keys.iter().position(|k| k == "state"),
    ) {
        assert!(
            scope < state,
            "Morph: `scope_circle_id` MUST precede `state` (§3.2 scope/container cluster)"
        );
    }
}
