use super::*;
use crate::{DeviceId, Event, EventRequirements, Hlc, OperationType, base::SessionMeta};

fn sessioned_base() -> Arc<BaseClient> {
    let base_client = Arc::new(BaseClient::new());
    let meta = SessionMeta::new(
        Did::new("did:web:alice.example.com").unwrap(),
        DeviceId::new("cx:device:01904100-0000-7000-8000-000000000005").unwrap(),
    );
    base_client.set_session_meta(meta).unwrap();
    base_client
}

fn event(kind: &str, seq: u64, space_id: &SpaceId, content: Value) -> Event {
    Event {
        event_id: EventId::new(format!("cx:event:01904100-0000-7000-8000-{seq:012x}")).unwrap(),
        kind: kind.to_owned(),
        realm_id: RealmId::new(space_id.as_str().replacen("cx:space:", "cx:realm:", 1)).unwrap(),
        actor_id: Did::new("did:web:alice.example.com").unwrap(),
        actor_seq: seq,
        created_at: Utc::now(),
        hlc: Hlc::new(format!("01970e589d21-{seq:04x}-a13f9c2e")).unwrap(),
        prev_refs: vec![],
        effective_scope: None,
        refs: vec![],
        preconditions: vec![],
        effects: vec![],
        anchor_ref: None,
        requirements: EventRequirements::default(),
        redacts: None,
        content,
        executed_by: None,
        authorization_ref: None,
        actor_kind: None,
        applet_id: None,
        external_ref: None,
        unsigned: BTreeMap::new(),
        proofs: vec![],
    }
}

fn morph_create_payload(morph_id: &MorphId, morph_type: &str, title: &str) -> Value {
    json!({
        "object": {
            "id": morph_id.as_str(),
            "schema": crate::MORPH_SCHEMA,
            "space_id": "cx:space:01904100-0000-7000-8000-9b64700c6ee8",
            "morph_type": morph_type,
            "title": title,
            "created_by": "did:web:alice.example.com",
            "created_at": "2026-05-02T00:00:00.000Z"
        }
    })
}

#[test]
fn space_checks_membership() {
    let base_client = Arc::new(BaseClient::new());
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();

    base_client.update_space_state(&space_id, SpaceStateType::Joined).unwrap();

    let space = Space::new(space_id, base_client);
    assert!(space.is_joined());
    assert!(!space.is_invited());
    assert!(!space.is_left());
}

#[test]
fn space_creates_morph_operation() {
    let base_client = sessioned_base();
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let space = Space::new(space_id.clone(), base_client);

    let op = space
        .create_morph_operation("task", Some("Test task".to_owned()), None, None, BTreeMap::new())
        .unwrap();

    assert_eq!(op.operation_type, OperationType::Create);
    assert_eq!(op.realm_id.as_str(), space_id.as_str().replacen("cx:space:", "cx:realm:", 1));
    assert_eq!(op.object_type, OP_MORPH_CREATE);
    assert_eq!(op.payload["object"]["morph_type"], "task");
    assert!(op.payload["object"]["id"].as_str().unwrap().starts_with("cx:morph:"));
}

#[test]
fn space_creates_relation_operation() {
    let base_client = sessioned_base();
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let space = Space::new(space_id.clone(), base_client);

    let input = RelationOperationInput::new(
        RelationKind::DependsOn,
        "cx:morph:01904100-0000-7000-8000-d48c478ecd0b",
        "cx:morph:01904100-0000-7000-8000-e75dc3f6ab2e",
    );
    let op = space.create_relation_operation(input).unwrap();

    assert_eq!(op.operation_type, OperationType::Create);
    assert_eq!(op.realm_id.as_str(), space_id.as_str().replacen("cx:space:", "cx:realm:", 1));
    assert_eq!(op.payload["relation"]["relation_kind"], "depends_on");
    assert!(op.payload["relation"]["id"].as_str().unwrap().starts_with("cx:relation:"));
}

#[test]
fn space_creates_flow_operations_and_reads_default_view_relations() {
    let base_client = sessioned_base();
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let space = Space::new(space_id.clone(), base_client.clone());

    let create = space
        .create_flow_operation(
            "Payment refactor",
            Some("Unify payment flows".to_owned()),
            BTreeMap::new(),
        )
        .unwrap();
    let flow_id = FlowId::new(create.payload["object"]["id"].as_str().unwrap()).unwrap();
    assert_eq!(create.operation_type, OperationType::Create);
    assert_eq!(create.object_type, crate::OP_FLOW_CREATE);
    assert!(create.payload["object"]["tracks"]["synthesis"].is_object());

    base_client
        .process_events(
            &space_id,
            vec![
                event(
                    crate::OP_FLOW_CREATE,
                    1,
                    &space_id,
                    json!({
                        "object": {
                            "id": flow_id.as_str(),
                            "schema": crate::FLOW_SCHEMA,
                            "space_id": space_id.as_str(),
                            "title": "Payment refactor",
                            "tracks": {"synthesis": {}},
                            "created_by": "did:web:alice.example.com",
                            "created_at": "2026-05-02T00:00:00.000Z"
                        }
                    }),
                ),
                event(
                    OP_RELATION_CREATE,
                    2,
                    &space_id,
                    json!({
                        "relation": {
                            "id": "cx:relation:01904100-0000-7000-8000-4da53c8b9e89",
                            "schema": crate::RELATION_SCHEMA,
                            "space_id": space_id.as_str(),
                            "relation_kind": "has_default_view",
                            "from_ref": flow_id.as_str(),
                            "to_ref": "cx:view:01904100-0000-7000-8000-08ca7b733afd",
                            "created_by": "did:web:alice.example.com",
                            "created_at": "2026-05-02T00:00:00.000Z",
                            "fields": {"primary": true}
                        }
                    }),
                ),
            ],
        )
        .unwrap();

    let refreshed = Space::new(space_id, base_client);
    assert_eq!(refreshed.flows().len(), 1);
    assert_eq!(refreshed.flow_default_views(&flow_id).len(), 1);
}

#[test]
fn space_queries_searches_and_aggregates_morphs() {
    let base_client = sessioned_base();
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let task_id = MorphId::new("cx:morph:01904100-0000-7000-8000-d48c478ecd0b").unwrap();
    let doc_id = MorphId::new("cx:morph:01904100-0000-7000-8000-e75dc3f6ab2e").unwrap();
    base_client
        .process_events(
            &space_id,
            vec![
                event(
                    OP_MORPH_CREATE,
                    1,
                    &space_id,
                    json!({
                        "object": {
                            "id": task_id.as_str(),
                            "schema": crate::MORPH_SCHEMA,
                            "space_id": space_id.as_str(),
                            "morph_type": "task",
                            "title": "Alpha task",
                            "content": {"kind": "cx.content.text", "body": "implement local search"},
                            "fields": {"status": "todo", "priority": 2},
                            "created_by": "did:web:alice.example.com",
                            "created_at": "2026-05-02T00:00:00.000Z"
                        }
                    }),
                ),
                event(
                    OP_MORPH_CREATE,
                    2,
                    &space_id,
                    json!({
                        "object": {
                            "id": doc_id.as_str(),
                            "schema": crate::MORPH_SCHEMA,
                            "space_id": space_id.as_str(),
                            "morph_type": "document",
                            "title": "Spec",
                            "fields": {"status": "done", "priority": 1},
                            "created_by": "did:web:alice.example.com",
                            "created_at": "2026-05-02T00:00:00.000Z"
                        }
                    }),
                ),
            ],
        )
        .unwrap();
    let space = Space::new(space_id, base_client);

    let results = space.query_morphs(MorphQuery {
        morph_types: vec!["task".to_owned()],
        filters: vec![Filter::Predicate(FieldFilter {
            field: "fields.status".to_owned(),
            op: FilterOp::Eq,
            value: Some(json!("todo")),
        })],
        order_by: vec![SortSpec {
            field: "fields.priority".to_owned(),
            direction: SortDirection::Desc,
            nulls: None,
        }],
        limit: Some(10),
    });
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].id, task_id.as_str());

    assert_eq!(space.search_morphs("LOCAL SEARCH").len(), 1);

    let aggregation = space.aggregate_morphs(&["fields.status"]);
    assert_eq!(aggregation.total, 2);
    assert_eq!(aggregation.by_type["task"], 1);
    assert_eq!(aggregation.by_field["fields.status"]["todo"], 1);
}

#[test]
fn space_traverses_relation_ref_graph_paths_and_cycles() {
    let base_client = sessioned_base();
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let a = "cx:morph:01904100-0000-7000-8000-093d58d9d0c4";
    let b = "cx:morph:01904100-0000-7000-8000-af13d24f756d";
    let c = "cx:morph:01904100-0000-7000-8000-28bb259aec1d";
    base_client
        .process_events(
            &space_id,
            vec![
                event(
                    OP_MORPH_CREATE,
                    1,
                    &space_id,
                    morph_create_payload(&MorphId::new(a).unwrap(), "task", "A"),
                ),
                event(
                    OP_MORPH_CREATE,
                    2,
                    &space_id,
                    morph_create_payload(&MorphId::new(b).unwrap(), "task", "B"),
                ),
                event(
                    OP_MORPH_CREATE,
                    3,
                    &space_id,
                    morph_create_payload(&MorphId::new(c).unwrap(), "task", "C"),
                ),
                event(
                    OP_RELATION_CREATE,
                    4,
                    &space_id,
                    json!({"relation": {"id": "cx:relation:01904100-0000-7000-8000-7b3bf7d6e46b", "schema": crate::RELATION_SCHEMA, "space_id": space_id.as_str(), "relation_kind": "depends_on", "from_ref": a, "to_ref": b, "created_by": "did:web:alice.example.com", "created_at": "2026-05-02T00:00:00.000Z"}}),
                ),
                event(
                    OP_RELATION_CREATE,
                    5,
                    &space_id,
                    json!({"relation": {"id": "cx:relation:01904100-0000-7000-8000-8b48e0461d8c", "schema": crate::RELATION_SCHEMA, "space_id": space_id.as_str(), "relation_kind": "depends_on", "from_ref": b, "to_ref": c, "created_by": "did:web:alice.example.com", "created_at": "2026-05-02T00:00:00.000Z"}}),
                ),
                event(
                    OP_RELATION_CREATE,
                    6,
                    &space_id,
                    json!({"relation": {"id": "cx:relation:01904100-0000-7000-8000-f891fd92960d", "schema": crate::RELATION_SCHEMA, "space_id": space_id.as_str(), "relation_kind": "depends_on", "from_ref": c, "to_ref": a, "created_by": "did:web:alice.example.com", "created_at": "2026-05-02T00:00:00.000Z"}}),
                ),
            ],
        )
        .unwrap();
    let space = Space::new(space_id, base_client);

    assert_eq!(
        space.traverse_relation_refs(
            a,
            Some(RelationKind::DependsOn),
            GraphTraversal::BreadthFirst,
            Some(2)
        ),
        vec![b.to_owned(), c.to_owned()]
    );
    assert_eq!(
        space.shortest_relation_ref_path(a, c, Some(RelationKind::DependsOn)).unwrap(),
        vec![a.to_owned(), b.to_owned(), c.to_owned()]
    );
    assert!(space.relation_ref_graph_has_cycle(Some(RelationKind::DependsOn)));
}

#[test]
fn space_tracks_morph_versions_compares_and_rolls_back() {
    let base_client = sessioned_base();
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let morph_id = MorphId::new("cx:morph:01904100-0000-7000-8000-69c57da8d707").unwrap();
    base_client
        .process_events(
            &space_id,
            vec![
                event(
                    OP_MORPH_CREATE,
                    1,
                    &space_id,
                    json!({
                        "object": {
                            "id": morph_id.as_str(),
                            "schema": crate::MORPH_SCHEMA,
                            "space_id": space_id.as_str(),
                            "morph_type": "task",
                            "title": "Initial",
                            "fields": {"status": "todo"},
                            "created_by": "did:web:alice.example.com",
                            "created_at": "2026-05-02T00:00:00.000Z"
                        }
                    }),
                ),
                event(
                    OP_MORPH_UPDATE,
                    2,
                    &space_id,
                    json!({
                        "morph_id": morph_id.as_str(),
                        "patch": {"title": "Updated", "fields": {"status": "done", "owner": "alice"}}
                    }),
                ),
            ],
        )
        .unwrap();
    let space = Space::new(space_id, base_client);

    let versions = space.morph_versions(&morph_id);
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].version, 0);
    assert_eq!(versions[1].version, 1);

    let diff = space.compare_morph_versions(&morph_id, 0, 1).unwrap();
    assert!(diff.title_changed);
    assert_eq!(diff.added_fields, vec!["owner".to_owned()]);
    assert_eq!(diff.changed_fields, vec!["status".to_owned()]);

    let rollback = space.rollback_morph_operation(morph_id, 0).unwrap();
    assert_eq!(rollback.payload["patch"]["title"], "Initial");
    assert_eq!(rollback.payload["rollback_to_version"], 0);
}

#[test]
fn space_creates_batch_morph_operations() {
    let base_client = sessioned_base();
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let space = Space::new(space_id, base_client);

    let creates = space
        .batch_create_morph_operations(vec![
            BatchCreateMorph {
                morph_type: "task".to_owned(),
                title: Some("A".to_owned()),
                summary: None,
                content: None,
                fields: BTreeMap::new(),
            },
            BatchCreateMorph {
                morph_type: "document".to_owned(),
                title: Some("B".to_owned()),
                summary: None,
                content: None,
                fields: BTreeMap::new(),
            },
        ])
        .unwrap();
    assert_eq!(creates.len(), 2);

    let updates = space
        .batch_update_morph_operations(vec![BatchUpdateMorph {
            morph_id: MorphId::new("cx:morph:01904100-0000-7000-8000-604e58949e32").unwrap(),
            title: Some("Updated".to_owned()),
            summary: None,
            content: None,
            fields: None,
        }])
        .unwrap();
    assert_eq!(updates.len(), 1);

    let archives = space
        .batch_archive_morph_operations(vec![
            MorphId::new("cx:morph:01904100-0000-7000-8000-604e58949e32").unwrap(),
        ])
        .unwrap();
    assert_eq!(archives.len(), 1);
}

#[test]
fn space_provides_message_membership_and_media_convenience_helpers() {
    let base_client = sessioned_base();
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let space = Space::new(space_id.clone(), base_client.clone());
    let bob = Did::new("did:web:bob.example.com").unwrap();

    let text = space.send_text("hello").unwrap();
    assert_eq!(text.object_type, "cx.message.create");
    assert_eq!(text.payload["content"]["body"], "hello");

    let message_id = MessageId::new(text.payload["message_id"].as_str().unwrap()).unwrap();
    let edit = space.edit_message(message_id.clone(), json!({"body": "updated"})).unwrap();
    assert_eq!(edit.object_type, "cx.message.revise");
    assert_eq!(edit.object_id, Some(message_id.as_str().to_owned()));

    let redact = space.redact_message(message_id, Some("cleanup".to_owned())).unwrap();
    assert_eq!(redact.operation_type, OperationType::Redact);

    let join = space.join_space().unwrap();
    assert_eq!(join.object_type, "cx.member.state");
    assert_eq!(base_client.get_space(&space_id).unwrap().state, SpaceStateType::Joined);

    let leave = space.leave_space().unwrap();
    assert_eq!(leave.object_type, "cx.member.state");
    assert_eq!(base_client.get_space(&space_id).unwrap().state, SpaceStateType::Left);

    #[allow(deprecated)]
    let invite_op = space.invite(bob.clone(), Some("member".to_owned())).unwrap();
    assert_eq!(invite_op.object_type, "cx.invite.create");
    assert_eq!(
        space.ban(bob.clone(), Some("spam".to_owned())).unwrap().object_type,
        "cx.member.state"
    );
    assert_eq!(space.unban(bob).unwrap().object_type, "cx.member.state");

    let media = space.upload_media(b"bytes", "text/plain", Some("note.txt".to_owned())).unwrap();
    assert_eq!(space.download_media(&media.blob_ref).unwrap(), b"bytes");

    space
        .upload_encrypted_attachment("att1", "secret.txt", "text/plain", b"secret", b"key")
        .unwrap();
    assert_eq!(space.download_decrypted_attachment("att1", b"key").unwrap(), b"secret");
}

#[test]
fn member_add_with_candidate_emits_routable_join_with_typed_binding() {
    use crate::model::{
        CandidateIntent, DeliveryBindingHint, DeliveryMode, Handle, HandleHintBindingSource,
        MemberDeliveryBindingCandidate, RecipientServiceType,
    };

    let base_client = sessioned_base();
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-000000000300").unwrap();
    let space = Space::new(space_id.clone(), base_client);

    let subject = Did::new("did:web:bob.example".to_owned()).unwrap();
    let principal = Did::new("did:web:principal.acme.example".to_owned()).unwrap();
    let mut modes = std::collections::BTreeSet::new();
    modes.insert(DeliveryMode::Events);
    modes.insert(DeliveryMode::Sync);
    let candidate = MemberDeliveryBindingCandidate {
        subject_id: subject.clone(),
        handle: Handle::parse("bob:acme.example").unwrap(),
        handle_aliases: vec![],
        member_delivery_binding: DeliveryBindingHint {
            recipient_service_did: principal.clone(),
            recipient_service_type: RecipientServiceType::PrincipalServer,
            binding_source: HandleHintBindingSource::OrganizationPolicy,
            delivery_modes: modes,
            service_acceptance_ref: Some(
                "cx:event:01890000-0000-7000-8000-0000000000a1".to_owned(),
            ),
            policy_ref: Some("cx:event:01890000-0000-7000-8000-0000000000a2".to_owned()),
        },
        issuer_service_did: principal,
        audience: space_id.as_str().to_owned(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
        issued_at: Some(Utc::now()),
        source_refs: vec!["cx:event:01890000-0000-7000-8000-0000000000a3".to_owned()],
        proofs: vec![serde_json::json!({
            "kind": "detached_jws",
            "alg": "EdDSA",
            "verification_method": "did:web:principal.acme.example#key-1",
            "payload_digest": "sha256:00000000000000000000000000000000000000000000000000000000000000aa",
            "created_at": "2026-05-19T00:00:00Z",
            "audience": space_id.as_str(),
            "jws": "aaa.bbb.ccc"
        })],
        claim_digest: None,
        intent: CandidateIntent::MemberAdd,
    };

    let op = space.member_add_with_candidate(&candidate).unwrap();
    assert_eq!(op.object_type, "cx.member.state");
    let payload = &op.payload;
    assert_eq!(payload["actor_id"], serde_json::json!(subject));
    assert_eq!(payload["membership"], "join");
    assert_eq!(payload["delivery_status"], "routable");
    assert_eq!(payload["handle"], "bob:acme.example");
    assert!(payload["delivery_binding"].is_object());
    assert!(payload["delivery_binding_candidate"].is_object());
}

#[test]
fn member_add_with_candidate_rejects_audience_mismatch() {
    use crate::model::{
        CandidateIntent, DeliveryBindingHint, DeliveryMode, Handle, HandleHintBindingSource,
        MemberDeliveryBindingCandidate, RecipientServiceType,
    };

    let base_client = sessioned_base();
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-000000000301").unwrap();
    let space = Space::new(space_id, base_client);

    let principal = Did::new("did:web:principal.acme.example".to_owned()).unwrap();
    let mut modes = std::collections::BTreeSet::new();
    modes.insert(DeliveryMode::Events);
    let candidate = MemberDeliveryBindingCandidate {
        subject_id: Did::new("did:web:bob.example".to_owned()).unwrap(),
        handle: Handle::parse("bob:acme.example").unwrap(),
        handle_aliases: vec![],
        member_delivery_binding: DeliveryBindingHint {
            recipient_service_did: principal.clone(),
            recipient_service_type: RecipientServiceType::PrincipalServer,
            binding_source: HandleHintBindingSource::OrganizationPolicy,
            delivery_modes: modes,
            service_acceptance_ref: Some(
                "cx:event:01890000-0000-7000-8000-0000000000a1".to_owned(),
            ),
            policy_ref: Some("cx:event:01890000-0000-7000-8000-0000000000a2".to_owned()),
        },
        issuer_service_did: principal,
        // Wrong audience — Space id does not match.
        audience: "cx:space:DEADBEEF-0000-7000-8000-00000000ffff".to_owned(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
        issued_at: Some(Utc::now()),
        source_refs: vec!["cx:event:01890000-0000-7000-8000-0000000000a3".to_owned()],
        proofs: vec![serde_json::json!({"kind":"detached_jws","jws":"a.b.c"})],
        claim_digest: None,
        intent: CandidateIntent::MemberAdd,
    };

    let err = space.member_add_with_candidate(&candidate).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("audience"), "expected audience mismatch error, got: {msg}");
}
