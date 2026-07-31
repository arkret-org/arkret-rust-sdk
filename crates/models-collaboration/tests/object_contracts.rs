use arkret_canonical as canonical;
use arkret_identifiers::{Did, MorphId, PolicyId, RealmId, StrandId, TypedTrustDomainId};
use arkret_models_collaboration::objects::profiles::{
    Morph, STRAND_TRACK_NAME_DISCUSSION, STRAND_TRACK_NAME_SYNTHESIS, StrandTrackConfig,
    validate_strand_track_name,
};
use arkret_models_collaboration::objects::realm::{
    CellLatticeDeclaration, NotaryProfile, Realm, SyncEndpoint,
};
use arkret_models_collaboration::objects::strand::Strand;
use arkret_wire::{FederationPolicy, Hash, MORPH_SCHEMA, ObjectStage, ObjectState, STRAND_SCHEMA};
use chrono::Utc;
use serde_json::json;

fn single_did_notary(did: &str) -> arkret_wire::NotaryValue {
    arkret_wire::NotaryValue::single_did(Did::new(did).unwrap())
}

#[test]
fn strand_constructor_sets_protocol_shape() {
    let mut subject = Strand::new(
        StrandId::new("ak:strand:01904100-0000-7000-8000-6c663fa0205f").unwrap(),
        RealmId::new("ak:realm:01904100-0000-7000-8000-fd3637e8361f").unwrap(),
        "Payment refactor",
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
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
    assert_eq!(subject.stage, Some(ObjectStage::Draft));
    subject.validate_title().unwrap();

    subject = subject.with_metadata_title(" ");
    assert!(subject.validate_title().is_err());
}

/// Optional Strand stage accepts sparse wire objects.
#[test]
fn strand_stage_is_optional_on_wire() {
    let strand = Strand::new(
        StrandId::new("ak:strand:01904100-0000-7000-8000-6c663fa0206f").unwrap(),
        RealmId::new("ak:realm:01904100-0000-7000-8000-fd3637e8362f").unwrap(),
        "Payment refactor",
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
    );
    let mut value = serde_json::to_value(&strand).unwrap();
    assert_eq!(value.get("stage"), Some(&json!("draft")));
    value.as_object_mut().unwrap().remove("stage");

    let parsed: Strand = serde_json::from_value(value).unwrap();
    assert_eq!(parsed.stage, None);
    assert!(
        serde_json::to_value(&parsed)
            .unwrap()
            .get("stage")
            .is_none()
    );
}

/// T21 - typed Strand::discussion shorthand for chat-style strands.
#[test]
fn strand_discussion_constructor_sets_room_shape() {
    let strand = Strand::discussion(
        StrandId::new("ak:strand:01904100-0000-7000-8000-58754cf88c25").unwrap(),
        RealmId::new("ak:realm:01904100-0000-7000-8000-2007b59d0dc4").unwrap(),
        "Launch board discussion",
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
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

/// T21 — synthesis-only Strands are not conversational.
#[test]
fn synthesis_strand_is_not_conversational() {
    let strand = Strand::new(
        StrandId::new("ak:strand:01904100-0000-7000-8000-58754cf88c25").unwrap(),
        RealmId::new("ak:realm:01904100-0000-7000-8000-2007b59d0dc4").unwrap(),
        "Launch board synthesis",
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
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

/// Realm seal fields are explicit genesis values and the builders set them to
/// expected overrides.
#[test]
fn realm_anchor_fields_are_required_and_builders_apply() {
    use arkret_wire::NotaryValue;

    let mut realm = Realm::new(
        RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000001").unwrap(),
        "Seal Test",
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        NotaryProfile::SingleDid,
        single_did_notary("did:webvh:z6mkfixture:alice.example"),
        Hash::new(format!("sha256:{}", "9a".repeat(32))).unwrap(),
    );
    assert!(realm.preview_policy_id.is_none());
    assert!(realm.sync_endpoints.is_empty());
    assert_eq!(realm.notary_profile, NotaryProfile::SingleDid);
    assert_eq!(realm.digest_algorithm, canonical::DigestSuite::Sha256);
    assert!(matches!(
        &realm.notary,
        NotaryValue::SingleDid { did, .. } if did.as_str() == "did:webvh:z6mkfixture:alice.example"
    ));
    assert!(realm.revocation_freshness_window_ms.is_none());
    assert_eq!(realm.max_authority_lifetime_ms, 86_400_000);
    assert!(realm.bottom_escalation_after_ms.is_none());
    assert!(realm.cell_lattices.is_empty());
    assert!(realm.cowrite_policy.is_empty());
    assert!(realm.updated_by.is_none());

    realm = realm
        .with_notary_profile(NotaryProfile::Threshold)
        .with_notary(NotaryValue::Threshold {
            threshold: 2,
            members: vec![
                Did::new("did:webvh:z6mkfixture:a.example").unwrap(),
                Did::new("did:webvh:z6mkfixture:b.example").unwrap(),
                Did::new("did:webvh:z6mkfixture:c.example").unwrap(),
            ],
            forensic_attribution: arkret_wire::ForensicAttribution::QuorumIntersection,
        })
        .with_revocation_freshness_window(60_000)
        .with_cell_lattice(
            "ak.component.strand.track.v1",
            "or_set",
            Some("reject".to_owned()),
        )
        .with_cowrite_group([
            "ak.component.strand.track.v1",
            "ak.component.realm.join_rule.v1",
        ]);
    realm.preview_policy_id =
        Some(PolicyId::new("ak:policy:0196419b-0000-7000-8000-000000000003").unwrap());
    realm.sync_endpoints.push(SyncEndpoint {
        did: Did::new("did:webvh:z6mkfixture:sync.example").unwrap(),
        endpoint: "https://sync.example/_arkret".to_owned(),
        role: "primary".to_owned(),
        service_kind: "principal_server".to_owned(),
        plaintext_visible: false,
        visibility_scope: Some("members".to_owned()),
        policy_id: realm.preview_policy_id.clone(),
        expires_at: None,
    });
    realm.digest_algorithm = canonical::DigestSuite::Blake3;
    realm.max_authority_lifetime_ms = 3_600_000;
    realm.bottom_escalation_after_ms = Some(120_000);
    realm.updated_by = Some(Did::new("did:webvh:z6mkfixture:bob.example").unwrap());

    assert_eq!(
        realm.preview_policy_id.as_ref().map(PolicyId::as_str),
        Some("ak:policy:0196419b-0000-7000-8000-000000000003")
    );
    assert_eq!(realm.sync_endpoints.len(), 1);
    assert_eq!(realm.notary_profile, NotaryProfile::Threshold);
    assert_eq!(realm.digest_algorithm, canonical::DigestSuite::Blake3);
    assert!(matches!(
        &realm.notary,
        NotaryValue::Threshold { threshold: 2, .. }
    ));
    assert_eq!(realm.revocation_freshness_window_ms, Some(60_000));
    assert_eq!(realm.max_authority_lifetime_ms, 3_600_000);
    assert_eq!(realm.bottom_escalation_after_ms, Some(120_000));
    assert_eq!(realm.cell_lattices.len(), 1);
    assert_eq!(
        realm.cell_lattices[0].cell_family,
        "ak.component.strand.track.v1"
    );
    assert_eq!(realm.cell_lattices[0].lattice, "or_set");
    assert_eq!(realm.cell_lattices[0].bottom.as_deref(), Some("reject"));
    assert_eq!(
        realm.cowrite_policy,
        vec![vec![
            "ak.component.strand.track.v1".to_owned(),
            "ak.component.realm.join_rule.v1".to_owned(),
        ]]
    );

    // Round-trip through serde to confirm wire shape.
    let json = serde_json::to_value(&realm).unwrap();
    assert_eq!(
        json["preview_policy_id"],
        "ak:policy:0196419b-0000-7000-8000-000000000003"
    );
    assert_eq!(
        json["sync_endpoints"][0]["did"],
        "did:webvh:z6mkfixture:sync.example"
    );
    assert_eq!(json["notary_profile"], "threshold");
    assert_eq!(json["digest_algorithm"], "blake3");
    assert_eq!(json["revocation_freshness_window_ms"], 60_000);
    assert_eq!(json["max_authority_lifetime_ms"], 3_600_000);
    assert_eq!(json["bottom_escalation_after_ms"], 120_000);
    // `realm.schema.json` cowrite_policy is `array<array<component>>` — a
    // whitelist of cell families writable by the same Control Move, not an
    // ordering enum. Ordering is unconditional (event-auth-state-resolution.md
    // §6.3.1) and carries no Realm field.
    assert_eq!(
        json["cowrite_policy"],
        json!([[
            "ak.component.strand.track.v1",
            "ak.component.realm.join_rule.v1"
        ]])
    );
    assert_eq!(json["updated_by"], "did:webvh:z6mkfixture:bob.example");
    assert_eq!(
        json["cell_lattices"][0]["cell_family"],
        "ak.component.strand.track.v1"
    );

    let restored: Realm = serde_json::from_value(json).unwrap();
    assert_eq!(
        restored.preview_policy_id.as_ref().map(PolicyId::as_str),
        realm.preview_policy_id.as_ref().map(PolicyId::as_str)
    );
    assert_eq!(restored.sync_endpoints.len(), 1);
    assert_eq!(restored.notary_profile, realm.notary_profile);
    assert_eq!(restored.digest_algorithm, realm.digest_algorithm);
    assert_eq!(
        restored.revocation_freshness_window_ms,
        realm.revocation_freshness_window_ms
    );
    assert_eq!(
        restored.max_authority_lifetime_ms,
        realm.max_authority_lifetime_ms
    );
    assert_eq!(
        restored.bottom_escalation_after_ms,
        realm.bottom_escalation_after_ms
    );
    assert_eq!(restored.cowrite_policy, realm.cowrite_policy);
    assert_eq!(
        restored.updated_by.as_ref().map(Did::as_str),
        realm.updated_by.as_ref().map(Did::as_str)
    );
}

/// `Realm::new` keeps the required genesis seal fields on the wire while
/// still omitting optional seal health hints.
#[test]
fn realm_anchor_fields_include_required_notary() {
    let realm = Realm::new(
        RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000002").unwrap(),
        "No Seal Hint",
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        NotaryProfile::SingleDid,
        single_did_notary("did:webvh:z6mkfixture:alice.example"),
        Hash::new(format!("sha256:{}", "9a".repeat(32))).unwrap(),
    );
    let json = serde_json::to_value(&realm).unwrap();
    let obj = json.as_object().unwrap();
    assert!(!obj.contains_key("preview_policy_id"));
    assert!(!obj.contains_key("sync_endpoints"));
    assert_eq!(obj.get("notary_profile"), Some(&json!("single_did")));
    assert_eq!(json["notary"]["kind"], "single_did");
    assert_eq!(json["notary"]["did"], "did:webvh:z6mkfixture:alice.example");
    assert!(!obj.contains_key("revocation_freshness_window_ms"));
    assert_eq!(obj.get("digest_algorithm"), Some(&json!("sha256")));
    assert_eq!(
        obj.get("max_authority_lifetime_ms"),
        Some(&json!(86_400_000))
    );
    assert!(!obj.contains_key("bottom_escalation_after_ms"));
    assert!(!obj.contains_key("cell_lattices"));
    assert!(!obj.contains_key("cowrite_policy"));
    assert!(!obj.contains_key("updated_by"));
}

#[test]
fn realm_notary_profile_must_match_notary_kind() {
    let realm = Realm::new(
        RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000005").unwrap(),
        "Mismatched Notary",
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        NotaryProfile::Threshold,
        single_did_notary("did:webvh:z6mkfixture:notary.example"),
        Hash::new(format!("sha256:{}", "9a".repeat(32))).unwrap(),
    );

    let err = realm.validate_kind_invariants().unwrap_err();
    assert!(format!("{err}").contains("notary_profile must match notary.kind"));
}

#[test]
fn realm_digest_algorithm_defaults_and_rejects_unknown_values() {
    let realm = Realm::new(
        RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000004").unwrap(),
        "Digest Defaults",
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        NotaryProfile::SingleDid,
        single_did_notary("did:webvh:z6mkfixture:alice.example"),
        Hash::new(format!("sha256:{}", "9a".repeat(32))).unwrap(),
    );
    let mut json = serde_json::to_value(&realm).unwrap();
    let obj = json.as_object_mut().unwrap();
    obj.remove("digest_algorithm");
    obj.remove("max_authority_lifetime_ms");

    let parsed: Realm = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(parsed.digest_algorithm, canonical::DigestSuite::Sha256);
    assert_eq!(parsed.max_authority_lifetime_ms, 86_400_000);

    json["digest_algorithm"] = json!("md5");
    assert!(serde_json::from_value::<Realm>(json).is_err());
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
        MorphId::new("ak:morph:01904100-0000-7000-8000-0000000000b0").unwrap(),
        RealmId::new("ak:realm:01904100-0000-7000-8000-0000000000b1").unwrap(),
        "ak.demo.morph",
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
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
fn materialized_objects_serialize_field_clusters_per_common_fields_3_2() {
    let created_by = Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
    let updated_by = Did::new("did:webvh:z6mkfixture:bob.example").unwrap();
    let now = Utc::now();

    // Strand — id, schema, …, state, state_changed_at, stage, stage_changed_at, audit.
    let mut strand = Strand::new(
        StrandId::new("ak:strand:01904100-0000-7000-8000-0000000000f0").unwrap(),
        RealmId::new("ak:realm:01904100-0000-7000-8000-0000000000f1").unwrap(),
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

    let mut realm = Realm::new(
        RealmId::new("ak:realm:01904100-0000-7000-8000-0000000000f2").unwrap(),
        "Order guard realm",
        created_by.clone(),
        TypedTrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        NotaryProfile::SingleDid,
        single_did_notary("did:webvh:z6mkfixture:notary.example"),
        Hash::new(format!("sha256:{}", "9a".repeat(32))).unwrap(),
    );
    realm.policy_id =
        Some(PolicyId::new("ak:policy:01904100-0000-7000-8000-0000000000f3").unwrap());
    realm.preview_policy_id =
        Some(PolicyId::new("ak:policy:01904100-0000-7000-8000-0000000000f4").unwrap());
    realm.federation_policy = Some(FederationPolicy::Restricted);
    realm.sync_endpoints.push(SyncEndpoint {
        did: Did::new("did:webvh:z6mkfixture:sync.example").unwrap(),
        endpoint: "https://sync.example/_arkret".to_owned(),
        role: "primary".to_owned(),
        service_kind: "principal_server".to_owned(),
        plaintext_visible: false,
        visibility_scope: None,
        policy_id: None,
        expires_at: None,
    });
    realm.digest_algorithm = canonical::DigestSuite::Blake3;
    realm.revocation_freshness_window_ms = Some(30_000);
    realm.max_authority_lifetime_ms = 3_600_000;
    realm.bottom_escalation_after_ms = Some(120_000);
    realm.cell_lattices.push(CellLatticeDeclaration {
        cell_family: "ak.component.strand.track.v1".to_owned(),
        lattice: "or_set".to_owned(),
        bottom: Some("reject".to_owned()),
    });
    realm.updated_by = Some(updated_by);
    realm.updated_at = Some(now);
    let realm_keys = top_level_keys(&serde_json::to_string(&realm).unwrap());
    assert_field_order("Realm", &realm_keys);
    let realm_pos = |name: &str| realm_keys.iter().position(|k| k == name).unwrap();
    assert!(realm_pos("policy_id") < realm_pos("preview_policy_id"));
    assert!(realm_pos("preview_policy_id") < realm_pos("default_discoverability"));
    assert!(realm_pos("federation_policy") < realm_pos("sync_endpoints"));
    assert!(realm_pos("sync_endpoints") < realm_pos("notary_profile"));
    assert!(realm_pos("notary_profile") < realm_pos("digest_algorithm"));
    assert!(realm_pos("digest_algorithm") < realm_pos("notary"));
    assert!(realm_pos("revocation_freshness_window_ms") < realm_pos("max_authority_lifetime_ms"));
    assert!(realm_pos("max_authority_lifetime_ms") < realm_pos("bottom_escalation_after_ms"));
    assert!(realm_pos("bottom_escalation_after_ms") < realm_pos("cell_lattices"));

    // Morph — scope/container cluster `scope_circle_id` precedes lifecycle `state`.
    let mut morph = Morph::new(
        MorphId::new("ak:morph:01904100-0000-7000-8000-0000000000a0").unwrap(),
        RealmId::new("ak:realm:01904100-0000-7000-8000-0000000000a1").unwrap(),
        "ak.demo.morph",
        created_by,
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
