use super::*;
use crate::{
    DeviceId, Event, Hlc, OperationType,
    base::SessionMeta,
    model::{OP_ENTITY_CREATE, OP_ENTITY_UPDATE, OP_RELATION_CREATE},
};

fn sessioned_base() -> Arc<BaseClient> {
    let base_client = Arc::new(BaseClient::new());
    let meta = SessionMeta::new(
        Did::new("did:web:alice.example.com").unwrap(),
        DeviceId::new("dev_123").unwrap(),
    );
    base_client.set_session_meta(meta).unwrap();
    base_client
}

fn event(kind: &str, seq: u64, space_id: &SpaceId, content: Value) -> Event {
    Event {
        event_id: EventId::new(format!("cx:event:01904100-0000-7000-8000-{seq:012x}")).unwrap(),
        kind: kind.to_owned(),
        space_id: space_id.clone(),
        space_version: "1".to_owned(),
        actor_id: Did::new("did:web:alice.example.com").unwrap(),
        actor_seq: seq,
        created_at: Utc::now(),
        hlc: Hlc::new(format!("01970e589d21-{seq:08x}-a13f9c2e")).unwrap(),
        prev_refs: vec![],
        auth_refs: vec![],
        schema_profile_refs: vec![],
        reducer_profile_ref: None,
        required_features: vec![],
        critical_extensions: vec![],
        redacts: None,
        content,
        unsigned: BTreeMap::new(),
        proofs: vec![],
    }
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
fn space_creates_entity_operation() {
    let base_client = Arc::new(BaseClient::new());
    let meta = SessionMeta::new(
        Did::new("did:web:alice.example.com").unwrap(),
        DeviceId::new("dev_123").unwrap(),
    );
    base_client.set_session_meta(meta).unwrap();

    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let space = Space::new(space_id.clone(), base_client);

    let op = space
        .create_entity_operation(
            EntityType::Task,
            Some("Test task".to_owned()),
            None,
            BTreeMap::new(),
        )
        .unwrap();

    assert_eq!(op.operation_type, OperationType::Create);
    assert_eq!(op.space_id, space_id);
    assert!(op.payload["id"].is_string());
}

#[test]
fn space_creates_relation_operation() {
    let base_client = Arc::new(BaseClient::new());
    let meta = SessionMeta::new(
        Did::new("did:web:alice.example.com").unwrap(),
        DeviceId::new("dev_123").unwrap(),
    );
    base_client.set_session_meta(meta).unwrap();

    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let space = Space::new(space_id.clone(), base_client);

    let mut input = RelationOperationInput::new(RelationKind::DependsOn);
    input.from_entity_id =
        Some(EntityId::new("cx:entity:01904100-0000-7000-8000-d48c478ecd0b").unwrap());
    input.to_entity_id =
        Some(EntityId::new("cx:entity:01904100-0000-7000-8000-e75dc3f6ab2e").unwrap());
    let op = space.create_relation_operation(input).unwrap();

    assert_eq!(op.operation_type, OperationType::Create);
    assert_eq!(op.space_id, space_id);
    assert!(op.payload["id"].is_string());
}

#[test]
fn space_creates_flow_operations_and_reads_surfaces() {
    let base_client = sessioned_base();
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let space = Space::new(space_id.clone(), base_client.clone());

    let create = space
        .create_flow_operation(
            "Payment refactor",
            FlowKind::Initiative,
            Some("Unify payment flows".to_owned()),
            None,
            BTreeMap::new(),
        )
        .unwrap();
    let flow_id = FlowId::new(create.payload["flow_id"].as_str().unwrap()).unwrap();
    assert_eq!(create.operation_type, OperationType::Create);
    assert_eq!(create.object_type, "flow");
    assert_eq!(create.payload["flow_kind"], "initiative");

    let link = space
        .link_flow_surface_operation(
            flow_id.clone(),
            "cx:flow:01904100-0000-7000-8000-08ca7b733afd",
            Some("status_card".to_owned()),
            true,
        )
        .unwrap();
    assert_eq!(link.operation_type, OperationType::Link);
    assert_eq!(link.object_id.as_deref(), Some(flow_id.as_str()));
    assert_eq!(link.payload["surface_role"], "status_card");

    base_client
        .process_events(
            &space_id,
            vec![
                event(
                    "cx.flow.create",
                    1,
                    &space_id,
                    json!({
                        "flow_id": flow_id.as_str(),
                        "title": "Payment refactor",
                        "flow_kind": "initiative"
                    }),
                ),
                event(
                    "cx.flow.link_surface",
                    2,
                    &space_id,
                    json!({
                        "flow_id": flow_id.as_str(),
                        "surface_ref": "cx:flow:01904100-0000-7000-8000-08ca7b733afd",
                        "surface_role": "status_card",
                        "primary": true,
                        "relation_id": "cx:relation:01904100-0000-7000-8000-4da53c8b9e89"
                    }),
                ),
            ],
        )
        .unwrap();

    let refreshed = Space::new(space_id, base_client);
    assert_eq!(refreshed.find_flows_by_kind(FlowKind::Initiative).len(), 1);
    assert_eq!(refreshed.flow_surfaces(&flow_id).len(), 1);
}

#[test]
fn space_queries_searches_and_aggregates_entities() {
    let base_client = sessioned_base();
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let task_id = EntityId::new("cx:entity:01904100-0000-7000-8000-d48c478ecd0b").unwrap();
    let doc_id = EntityId::new("cx:entity:01904100-0000-7000-8000-e75dc3f6ab2e").unwrap();
    base_client
        .process_events(
            &space_id,
            vec![
                event(
                    OP_ENTITY_CREATE,
                    1,
                    &space_id,
                    json!({
                        "id": task_id.as_str(),
                        "entity_type": "task",
                        "title": "Alpha task",
                        "content": {"body": "implement local search"},
                        "fields": {"status": "todo", "priority": 2}
                    }),
                ),
                event(
                    OP_ENTITY_CREATE,
                    2,
                    &space_id,
                    json!({
                        "id": doc_id.as_str(),
                        "entity_type": "document",
                        "title": "Spec",
                        "fields": {"status": "done", "priority": 1}
                    }),
                ),
            ],
        )
        .unwrap();
    let space = Space::new(space_id, base_client);

    let results = space.query_entities(EntityQuery {
        entity_types: vec![EntityType::Task],
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
    assert_eq!(results[0].id, task_id);

    assert_eq!(space.search_entities("LOCAL SEARCH").len(), 1);

    let aggregation = space.aggregate_entities(&["fields.status"]);
    assert_eq!(aggregation.total, 2);
    assert_eq!(aggregation.by_type["task"], 1);
    assert_eq!(aggregation.by_field["fields.status"]["todo"], 1);
}

#[test]
fn space_traverses_relation_graph_paths_and_cycles() {
    let base_client = sessioned_base();
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let a = EntityId::new("cx:entity:01904100-0000-7000-8000-093d58d9d0c4").unwrap();
    let b = EntityId::new("cx:entity:01904100-0000-7000-8000-af13d24f756d").unwrap();
    let c = EntityId::new("cx:entity:01904100-0000-7000-8000-28bb259aec1d").unwrap();
    base_client
        .process_events(
            &space_id,
            vec![
                event(
                    OP_ENTITY_CREATE,
                    1,
                    &space_id,
                    json!({"id": a.as_str(), "entity_type": "task"}),
                ),
                event(
                    OP_ENTITY_CREATE,
                    2,
                    &space_id,
                    json!({"id": b.as_str(), "entity_type": "task"}),
                ),
                event(
                    OP_ENTITY_CREATE,
                    3,
                    &space_id,
                    json!({"id": c.as_str(), "entity_type": "task"}),
                ),
                event(
                    OP_RELATION_CREATE,
                    4,
                    &space_id,
                    json!({
                        "id": "cx:relation:01904100-0000-7000-8000-7b3bf7d6e46b",
                        "relation_kind": "depends_on",
                        "from_entity_id": a.as_str(),
                        "to_entity_id": b.as_str()
                    }),
                ),
                event(
                    OP_RELATION_CREATE,
                    5,
                    &space_id,
                    json!({
                        "id": "cx:relation:01904100-0000-7000-8000-8b48e0461d8c",
                        "relation_kind": "depends_on",
                        "from_entity_id": b.as_str(),
                        "to_entity_id": c.as_str()
                    }),
                ),
                event(
                    OP_RELATION_CREATE,
                    6,
                    &space_id,
                    json!({
                        "id": "cx:relation:01904100-0000-7000-8000-f891fd92960d",
                        "relation_kind": "depends_on",
                        "from_entity_id": c.as_str(),
                        "to_entity_id": a.as_str()
                    }),
                ),
            ],
        )
        .unwrap();
    let space = Space::new(space_id, base_client);

    assert_eq!(
        space.traverse_relations(
            &a,
            Some(RelationKind::DependsOn),
            GraphTraversal::BreadthFirst,
            Some(2),
        ),
        vec![b.clone(), c.clone()]
    );
    assert_eq!(
        space.shortest_relation_path(&a, &c, Some(RelationKind::DependsOn)).unwrap(),
        vec![a.clone(), b, c]
    );
    assert!(space.relation_graph_has_cycle(Some(RelationKind::DependsOn)));
}

#[test]
fn space_tracks_entity_versions_compares_and_rolls_back() {
    let base_client = sessioned_base();
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let entity_id = EntityId::new("cx:entity:01904100-0000-7000-8000-69c57da8d707").unwrap();
    base_client
        .process_events(
            &space_id,
            vec![
                event(
                    OP_ENTITY_CREATE,
                    1,
                    &space_id,
                    json!({
                        "id": entity_id.as_str(),
                        "entity_type": "task",
                        "title": "Initial",
                        "fields": {"status": "todo"}
                    }),
                ),
                event(
                    OP_ENTITY_UPDATE,
                    2,
                    &space_id,
                    json!({
                        "id": entity_id.as_str(),
                        "title": "Updated",
                        "fields": {"status": "done", "owner": "alice"}
                    }),
                ),
            ],
        )
        .unwrap();
    let space = Space::new(space_id, base_client);

    let versions = space.entity_versions(&entity_id);
    assert_eq!(versions.len(), 2);
    assert_eq!(versions[0].version, 0);
    assert_eq!(versions[1].version, 1);

    let diff = space.compare_entity_versions(&entity_id, 0, 1).unwrap();
    assert!(diff.title_changed);
    assert_eq!(diff.added_fields, vec!["owner".to_owned()]);
    assert_eq!(diff.changed_fields, vec!["status".to_owned()]);

    let rollback = space.rollback_entity_operation(entity_id, 0).unwrap();
    assert_eq!(rollback.payload["title"], "Initial");
    assert_eq!(rollback.payload["rollback_to_version"], 0);
}

#[test]
fn space_creates_batch_entity_operations() {
    let base_client = sessioned_base();
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let space = Space::new(space_id, base_client);

    let creates = space
        .batch_create_entity_operations(vec![
            BatchCreateEntity {
                entity_type: EntityType::Task,
                title: Some("A".to_owned()),
                content: None,
                fields: BTreeMap::new(),
            },
            BatchCreateEntity {
                entity_type: EntityType::Document,
                title: Some("B".to_owned()),
                content: None,
                fields: BTreeMap::new(),
            },
        ])
        .unwrap();
    assert_eq!(creates.len(), 2);

    let updates = space
        .batch_update_entity_operations(vec![BatchUpdateEntity {
            entity_id: EntityId::new("cx:entity:01904100-0000-7000-8000-604e58949e32").unwrap(),
            title: Some("Updated".to_owned()),
            content: None,
            fields: None,
        }])
        .unwrap();
    assert_eq!(updates.len(), 1);

    let deletes = space
        .batch_delete_entity_operations(vec![
            EntityId::new("cx:entity:01904100-0000-7000-8000-604e58949e32").unwrap(),
        ])
        .unwrap();
    assert_eq!(deletes.len(), 1);
}

#[test]
fn space_provides_message_membership_and_media_convenience_helpers() {
    let base_client = sessioned_base();
    let space_id = SpaceId::new("cx:space:01904100-0000-7000-8000-9b64700c6ee8").unwrap();
    let space = Space::new(space_id.clone(), base_client.clone());
    let bob = Did::new("did:web:bob.example.com").unwrap();

    let text = space.send_text("hello").unwrap();
    assert_eq!(text.object_type, "entity.create");
    assert_eq!(text.payload["entity_type"], "message");
    assert_eq!(text.payload["content"]["body"], "hello");

    let message_id = EntityId::new(text.payload["id"].as_str().unwrap()).unwrap();
    let edit = space.edit_message(message_id.clone(), json!({"body": "updated"})).unwrap();
    assert_eq!(edit.object_type, "message.edit");
    assert_eq!(edit.object_id, Some(message_id.as_str().to_owned()));

    let redact = space.redact_message(message_id, Some("cleanup".to_owned())).unwrap();
    assert_eq!(redact.operation_type, OperationType::Redact);

    let join = space.join_space().unwrap();
    assert_eq!(join.object_type, "join");
    assert_eq!(base_client.get_space(&space_id).unwrap().state, SpaceStateType::Joined);

    let leave = space.leave_space().unwrap();
    assert_eq!(leave.object_type, "leave");
    assert_eq!(base_client.get_space(&space_id).unwrap().state, SpaceStateType::Left);

    assert_eq!(
        space.invite(bob.clone(), Some("member".to_owned())).unwrap().object_type,
        "invite"
    );
    assert_eq!(space.ban(bob.clone(), Some("spam".to_owned())).unwrap().object_type, "ban");
    assert_eq!(space.unban(bob).unwrap().object_type, "unban");

    let media =
        space.upload_media(b"bytes", "text/plain", Some("note.txt".to_owned())).unwrap();
    assert_eq!(space.download_media(&media.blob_ref).unwrap(), b"bytes");

    space
        .upload_encrypted_attachment("att1", "secret.txt", "text/plain", b"secret", b"key")
        .unwrap();
    assert_eq!(space.download_decrypted_attachment("att1", b"key").unwrap(), b"secret");
}
