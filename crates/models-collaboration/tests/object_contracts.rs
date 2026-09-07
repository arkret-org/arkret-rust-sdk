use arkret_canonical as canonical;
use arkret_identifiers::{MorphId, PolicyId, RealmId, StrandId, TrustDomainId};
use arkret_models_collaboration::events_payloads::ContentBlock;
use arkret_models_collaboration::objects::profiles::{
    Morph, STRAND_TRACK_NAME_DISCUSSION, STRAND_TRACK_NAME_SYNTHESIS, StrandTrack,
    validate_strand_track_name,
};
use arkret_models_collaboration::objects::realm::{CellLatticeDeclaration, Realm};
use arkret_models_collaboration::objects::strand::Strand;
use arkret_wire::{
    ActorId, Did, DidCoreId, DidUrl, FederationPolicy, Hash, NotaryJoseAlgorithm, NotaryKeyKind,
    NotarySignerDescriptor, ObjectStage, ObjectState, SchemaId, project_did_to_core_id,
};
use chrono::Utc;
use serde_json::json;

fn signer(did: &str) -> NotarySignerDescriptor {
    NotarySignerDescriptor {
        actor_id: actor(did),
        verification_method: DidUrl::new(format!("{did}#key-1")).unwrap(),
        key_kind: NotaryKeyKind::Ed25519Raw32,
        jose_algorithm: NotaryJoseAlgorithm::Ed25519,
        frozen_public_key_b64u: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
        frozen_public_key_digest: Hash::new(
            "sha256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925",
        )
        .unwrap(),
    }
}

fn single_signer_notary(did: &str) -> arkret_wire::NotaryValue {
    arkret_wire::NotaryValue::single_signer(signer(did))
}

fn actor(value: &str) -> ActorId {
    let core = if value.starts_with("ak:did_core:") {
        DidCoreId::new(value).unwrap()
    } else {
        project_did_to_core_id(&Did::new(value).unwrap()).unwrap()
    };
    ActorId::service(core)
}

#[test]
fn strand_constructor_sets_protocol_shape() {
    let mut subject = Strand::new(
        StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9").unwrap(),
        RealmId::new("ak:realm:AX-N4k3nJ3KKtkbL-adKMKRyKUlTWlwhxQVvjmvEBEVB").unwrap(),
        "Payment refactor",
        actor("did:webvh:z6mkfixture:alice.example"),
    );

    assert_eq!(subject.schema, SchemaId::STRAND_V1);
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

#[test]
fn strand_description_and_synthesis_use_distinct_wire_slots() {
    let mut strand = Strand::new(
        StrandId::new("ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9").unwrap(),
        RealmId::new("ak:realm:AX-N4k3nJ3KKtkbL-adKMKRyKUlTWlwhxQVvjmvEBEVB").unwrap(),
        "Payment refactor",
        actor("did:webvh:z6mkfixture:alice.example"),
    );
    strand.content = Some(ContentBlock::text("Description body"));
    strand
        .tracks
        .get_mut(STRAND_TRACK_NAME_SYNTHESIS)
        .unwrap()
        .content = Some(ContentBlock::text("Synthesis body"));

    let value = serde_json::to_value(&strand).unwrap();
    assert_eq!(value["content"]["body"], "Description body");
    assert_eq!(
        value["tracks"]["synthesis"]["content"]["body"],
        "Synthesis body"
    );
    assert!(value.get("synthesis_content").is_none());
    assert!(value.get("body").is_none());

    let parsed: Strand = serde_json::from_value(value).unwrap();
    assert_eq!(parsed.content.unwrap().body, "Description body");
    assert_eq!(
        parsed.tracks[STRAND_TRACK_NAME_SYNTHESIS]
            .content
            .as_ref()
            .unwrap()
            .body,
        "Synthesis body"
    );
}

/// Optional Strand stage accepts sparse wire objects.
#[test]
fn strand_stage_is_optional_on_wire() {
    let strand = Strand::new(
        StrandId::new("ak:strand:AcKSRJZPkByig1GflJEt_bZDB7P97ojqBwYH1b1ueEW4").unwrap(),
        RealmId::new("ak:realm:AZ6K8FZoZ5exQI95ZRAfS7jlgIdfNkV6QLYAofxG2SGm").unwrap(),
        "Payment refactor",
        actor("did:webvh:z6mkfixture:alice.example"),
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
        StrandId::new("ak:strand:AT_TSQZlyY7Fu85J33nzo3fSau9RjJOeu21RspghP1gC").unwrap(),
        RealmId::new("ak:realm:Ae45Cr1AeIit-Zrz1lJhczoDtaA38mI5e6z8nYtMnMW7").unwrap(),
        "Launch board discussion",
        actor("did:webvh:z6mkfixture:alice.example"),
    );
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

/// T21 — StrandTrack typed constructors honour the standard
/// profile from spec §6.1; track names live in the parent map keys.
#[test]
fn strand_track_typed_constructors() {
    let synth = StrandTrack::synthesis();
    assert!(synth.profile.is_none());
    assert!(synth.is_primary.is_none());
    validate_strand_track_name(STRAND_TRACK_NAME_SYNTHESIS).unwrap();

    let disc = StrandTrack::discussion();
    assert_eq!(disc.profile.as_deref(), Some("discussion"));
    assert!(disc.is_primary.is_none());
    validate_strand_track_name(STRAND_TRACK_NAME_DISCUSSION).unwrap();

    let primary = StrandTrack::discussion_primary();
    assert_eq!(primary.is_primary, Some(true));

    let custom = StrandTrack::new().with_profile("review").primary();
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
        RealmId::new("ak:realm:Aepgr15HbtERKfqPAh9SrfWBdihSvX_c94JvujvBS2f-").unwrap(),
        "Seal Test",
        actor("did:webvh:z6mkfixture:alice.example"),
        TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        arkret_wire::CORE_REDUCER_PROFILE,
        single_signer_notary("did:webvh:z6mkfixture:alice.example"),
    );
    assert!(realm.preview_policy_id.is_none());
    assert_eq!(realm.digest_algorithm, canonical::DigestSuite::Sha256);
    assert!(matches!(
        &realm.notary,
        NotaryValue::SingleSigner { signer, .. }
            if signer.actor_id.signing_principal_id().as_str()
                == "ak:did_core:webvh:z6mkfixture"
    ));
    assert!(realm.revocation_freshness_window_ms.is_none());
    assert_eq!(realm.max_authority_lifetime_ms, 86_400_000);
    assert!(realm.bottom_escalation_after_ms.is_none());
    assert!(realm.cell_lattices.is_empty());
    assert!(realm.updated_by.is_none());

    realm.notary = NotaryValue::Threshold {
        threshold: 2,
        signers: vec![
            signer("did:webvh:z6mkfixturea:a.example"),
            signer("did:webvh:z6mkfixtureb:b.example"),
            signer("did:webvh:z6mkfixturec:c.example"),
        ],
        forensic_attribution: arkret_wire::ForensicAttribution::QuorumIntersection,
    };
    realm.revocation_freshness_window_ms = Some(60_000);
    realm.cell_lattices.push(CellLatticeDeclaration {
        cell_family: arkret_wire::CellFamilyId::STRAND_OBJECT_V1.to_owned(),
        lattice: "cas_register".to_owned(),
        bottom: Some("reject".to_owned()),
    });
    realm.preview_policy_id =
        Some(PolicyId::new("ak:policy:0196419b-0000-7000-8000-000000000003").unwrap());
    realm.digest_algorithm = canonical::DigestSuite::Blake3;
    realm.max_authority_lifetime_ms = 3_600_000;
    realm.bottom_escalation_after_ms = Some(120_000);
    realm.updated_by = Some(actor("did:webvh:z6mkfixture:bob.example"));

    assert_eq!(
        realm.preview_policy_id.as_ref().map(PolicyId::as_str),
        Some("ak:policy:0196419b-0000-7000-8000-000000000003")
    );
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
        arkret_wire::CellFamilyId::STRAND_OBJECT_V1
    );
    assert_eq!(realm.cell_lattices[0].lattice, "cas_register");
    assert_eq!(realm.cell_lattices[0].bottom.as_deref(), Some("reject"));

    // Round-trip through serde to confirm wire shape.
    let json = serde_json::to_value(&realm).unwrap();
    assert_eq!(
        json["preview_policy_id"],
        "ak:policy:0196419b-0000-7000-8000-000000000003"
    );
    assert_eq!(json["digest_algorithm"], "blake3");
    assert_eq!(json["revocation_freshness_window_ms"], 60_000);
    assert_eq!(json["max_authority_lifetime_ms"], 3_600_000);
    assert_eq!(json["bottom_escalation_after_ms"], 120_000);
    assert_eq!(
        json["updated_by"],
        json!({"kind":"service","service_id":"ak:did_core:webvh:z6mkfixture"})
    );
    assert_eq!(
        json["cell_lattices"][0]["cell_family"],
        arkret_wire::CellFamilyId::STRAND_OBJECT_V1
    );

    let restored: Realm = serde_json::from_value(json).unwrap();
    assert_eq!(
        restored.preview_policy_id.as_ref().map(PolicyId::as_str),
        realm.preview_policy_id.as_ref().map(PolicyId::as_str)
    );
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
    assert_eq!(restored.updated_by, realm.updated_by);
}

/// `Realm::new` keeps the required genesis seal fields on the wire while
/// still omitting optional seal health hints.
#[test]
fn realm_anchor_fields_include_required_notary() {
    let realm = Realm::new(
        RealmId::new("ak:realm:AQM8rE4gp8l4axkSbbb9_dkqwWE8ZPYHwFsC24o2mrIL").unwrap(),
        "No Seal Hint",
        actor("did:webvh:z6mkfixture:alice.example"),
        TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        arkret_wire::CORE_REDUCER_PROFILE,
        single_signer_notary("did:webvh:z6mkfixture:alice.example"),
    );
    let json = serde_json::to_value(&realm).unwrap();
    let obj = json.as_object().unwrap();
    assert!(!obj.contains_key("preview_policy_id"));
    assert!(!obj.contains_key("sync_endpoints"));
    assert_eq!(json["notary"]["kind"], "single_signer");
    assert_eq!(
        json["notary"]["signer"]["actor_id"],
        json!({"kind":"service","service_id":"ak:did_core:webvh:z6mkfixture"})
    );
    assert!(!obj.contains_key("revocation_freshness_window_ms"));
    assert_eq!(obj.get("digest_algorithm"), Some(&json!("sha256")));
    assert_eq!(
        obj.get("max_authority_lifetime_ms"),
        Some(&json!(86_400_000))
    );
    assert!(!obj.contains_key("bottom_escalation_after_ms"));
    assert!(!obj.contains_key("cell_lattices"));
    assert!(!obj.contains_key("updated_by"));
}

#[test]
fn realm_notary_descriptor_must_be_valid() {
    let realm = Realm::new(
        RealmId::new("ak:realm:AdIeygO8cj8jUpcxH6i4a15i1zh2wq8eNKz5RgGEItdA").unwrap(),
        "Mismatched Notary",
        actor("did:webvh:z6mkfixture:alice.example"),
        TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        arkret_wire::CORE_REDUCER_PROFILE,
        arkret_wire::NotaryValue::single_signer(NotarySignerDescriptor {
            frozen_public_key_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
            ..signer("did:webvh:z6mkfixture:notary.example")
        }),
    );

    let err = realm.validate_kind_invariants().unwrap_err();
    assert!(format!("{err}").contains("frozen_public_key_digest"));
}

#[test]
fn realm_digest_algorithm_defaults_and_rejects_unknown_values() {
    let realm = Realm::new(
        RealmId::new("ak:realm:ASc_XP_IqOBAY6GgbPMLFCeZmi0uBNaWvHazHgmn-B8K").unwrap(),
        "Digest Defaults",
        actor("did:webvh:z6mkfixture:alice.example"),
        TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        arkret_wire::CORE_REDUCER_PROFILE,
        single_signer_notary("did:webvh:z6mkfixture:alice.example"),
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
        MorphId::new("ak:morph:AdF-OpLT-7la09L28Pgl41aEHXK3MEZNnwMNhc02Uz19").unwrap(),
        RealmId::new("ak:realm:AZaaHAEvC1DejakImwHCcJHb0F1pgE-Jd-3_9BGirbuW").unwrap(),
        "ak.demo.morph",
        actor("did:webvh:z6mkfixture:alice.example"),
    );
    let value = serde_json::to_value(&morph).unwrap();
    assert_eq!(value["schema_refs"], json!([SchemaId::MORPH_V1]));

    let mut missing = value.clone();
    missing.as_object_mut().unwrap().remove("schema_refs");
    assert!(serde_json::from_value::<Morph>(missing).is_err());

    let mut empty = value.clone();
    empty["schema_refs"] = json!([]);
    assert!(serde_json::from_value::<Morph>(empty).is_err());

    let mut duplicate = value;
    duplicate["schema_refs"] = json!([SchemaId::MORPH_V1, SchemaId::MORPH_V1]);
    assert!(serde_json::from_value::<Morph>(duplicate).is_err());
}

#[test]
fn materialized_objects_serialize_field_clusters_per_common_fields_3_2() {
    let created_by = actor("did:webvh:z6mkfixture:alice.example");
    let updated_by = actor("did:webvh:z6mkfixture:bob.example");
    let now = Utc::now();

    // Strand — id, schema, …, state, state_changed_at, stage, stage_changed_at, audit.
    let mut strand = Strand::new(
        StrandId::new("ak:strand:AfIJFv2OZq7YFmfcgrysn4iCCeZnltKXmDNUzrSqwI4W").unwrap(),
        RealmId::new("ak:realm:AUAf2-oZl31wupPqnQLO-zloaqgMoX5xk2tpVSbi8zjD").unwrap(),
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
        RealmId::new("ak:realm:ATz4yMg8D3eSMJ7kiPNr0BF70hg3o_DBZklFZd5GZSuJ").unwrap(),
        "Order guard realm",
        created_by.clone(),
        TrustDomainId::new("ak:trust_domain:example.net").unwrap(),
        arkret_wire::CORE_REDUCER_PROFILE,
        single_signer_notary("did:webvh:z6mkfixture:notary.example"),
    );
    realm.policy_id =
        Some(PolicyId::new("ak:policy:01904100-0000-7000-8000-0000000000f3").unwrap());
    realm.preview_policy_id =
        Some(PolicyId::new("ak:policy:01904100-0000-7000-8000-0000000000f4").unwrap());
    realm.federation_policy = Some(FederationPolicy::Restricted);
    realm.digest_algorithm = canonical::DigestSuite::Blake3;
    realm.revocation_freshness_window_ms = Some(30_000);
    realm.max_authority_lifetime_ms = 3_600_000;
    realm.bottom_escalation_after_ms = Some(120_000);
    realm.cell_lattices.push(CellLatticeDeclaration {
        cell_family: arkret_wire::CellFamilyId::STRAND_OBJECT_V1.to_owned(),
        lattice: "cas_register".to_owned(),
        bottom: Some("reject".to_owned()),
    });
    realm.updated_by = Some(updated_by);
    realm.updated_at = Some(now);
    let realm_keys = top_level_keys(&serde_json::to_string(&realm).unwrap());
    assert_field_order("Realm", &realm_keys);
    let realm_pos = |name: &str| realm_keys.iter().position(|k| k == name).unwrap();
    assert!(realm_pos("policy_id") < realm_pos("preview_policy_id"));
    assert!(realm_pos("preview_policy_id") < realm_pos("default_discoverability"));
    assert!(realm_pos("federation_policy") < realm_pos("digest_algorithm"));
    assert!(realm_pos("digest_algorithm") < realm_pos("notary"));
    assert!(realm_pos("revocation_freshness_window_ms") < realm_pos("max_authority_lifetime_ms"));
    assert!(realm_pos("max_authority_lifetime_ms") < realm_pos("bottom_escalation_after_ms"));
    assert!(realm_pos("bottom_escalation_after_ms") < realm_pos("cell_lattices"));

    // Morph — scope/container cluster `scope_circle_id` precedes lifecycle `state`.
    let mut morph = Morph::new(
        MorphId::new("ak:morph:AXHnkT-tdDqCMpsoD_x6N087pBWlUx40WhTdBqPJatRN").unwrap(),
        RealmId::new("ak:realm:AYqEzQ3jW02EHkMjxFQTlyeowxPQXJE4fI6JGOnzi23t").unwrap(),
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
