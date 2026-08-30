use std::collections::BTreeMap;

use arkret_identifiers::{RealmId, RelationId, ViewId};
use arkret_models_collaboration::events_payloads::private_view_account_data_key;
use arkret_models_collaboration::objects::queries::{
    CollectionConfig, CollectionGrouping, CollectionItemRender, FieldFilter, Filter, View,
    ViewQuery, ViewState,
};
use arkret_models_collaboration::objects::relation::Relation;
use arkret_wire::{
    ActorId, DidCoreId, Facet, Facets, FilterOp, RelationKind, SchemaId, ViewKind, ViewRenderer,
    ViewVisibility,
};
use chrono::Utc;
use serde_json::json;

fn actor(value: &str) -> ActorId {
    let core = value
        .strip_prefix("did:webvh:")
        .and_then(|rest| rest.split(':').next())
        .expect("test helper expects did:webvh");
    ActorId::service(DidCoreId::new(format!("ak:did_core:webvh:{core}")).unwrap())
}

#[test]
fn relation_requires_exact_wire_endpoints() {
    let relation = Relation {
        schema: SchemaId::RELATION_V1.to_owned(),
        id: Some(
            RelationId::new("ak:relation:AbihRHGq5MW5AMbxaGJlHnvF9zxJ0Hli4rDPiSQtjjLp").unwrap(),
        ),
        realm_id: RealmId::new("ak:realm:AX-N4k3nJ3KKtkbL-adKMKRyKUlTWlwhxQVvjmvEBEVB").unwrap(),
        scope_circle_id: None,
        effective_scope: None,
        relation_kind: RelationKind::Mentions,
        from_ref: "ak:morph:AdDdo41xqpK3J2_u26PQlGHCNJzU-Sym3p-LwW-bZmbb".into(),
        to_ref: actor("did:webvh:z6mkfixture:alice.example").into(),
        rank: None,
        fields: BTreeMap::new(),
        state: None,
        state_changed_at: None,
        created_by: actor("did:webvh:z6mkfixture:alice.example"),
        created_at: Utc::now(),
        updated_by: None,
        updated_at: None,
    };
    relation.validate_endpoints().unwrap();
}

#[test]
fn query_request_uses_protocol_filters_array() {
    let request = ViewQuery {
        realm_ids: vec![
            RealmId::new("ak:realm:AX-N4k3nJ3KKtkbL-adKMKRyKUlTWlwhxQVvjmvEBEVB").unwrap(),
        ],
        object_kinds: vec!["morph".to_owned()],
        morph_kinds: vec!["task".to_owned()],
        facets: vec![Facet::Stateful, Facet::Rankable],
        seal_ref: None,
        filters: vec![Filter::Predicate(FieldFilter {
            field: "fields.status".to_owned(),
            op: FilterOp::Eq,
            value: Some(json!("todo")),
        })],
        relation: None,
        context: None,
        order_by: vec![],
        projection: vec![],
        cursor: None,
        limit: Some(50),
        consistency: None,
    };

    let value = serde_json::to_value(request).unwrap();
    assert!(value.get("realm_ids").unwrap().is_array());
    assert!(value.get("filters").unwrap().is_array());
    assert_eq!(value["facets"], json!(["stateful", "rankable"]));
    assert!(value.get("renderer").is_none());
    assert!(value.get("sync_token").is_none());
}

#[test]
fn facets_accept_name_lists_and_config_maps() {
    let names: Facets =
        serde_json::from_value(json!(["stateful", "rankable", "renderable"])).unwrap();
    assert!(names.contains(&Facet::Stateful));

    let configs: Facets = serde_json::from_value(json!({
        "rankable": {"rank_field": "fields.rank"},
        "renderable": {"renderers": ["card"]}
    }))
    .unwrap();
    assert!(configs.contains(&Facet::Rankable));
    assert_eq!(
        serde_json::to_value(configs).unwrap()["renderable"]["renderers"][0],
        "card"
    );
}

fn collection_view() -> View {
    View {
        schema: SchemaId::VIEW_V1.to_owned(),
        id: ViewId::new("ak:view:AaiFHUI8GObKlPqeNvnl4E37L9moM-J0DjA4_UN9FvhR").unwrap(),
        realm_id: RealmId::new("ak:realm:AX-N4k3nJ3KKtkbL-adKMKRyKUlTWlwhxQVvjmvEBEVB").unwrap(),
        kind: ViewKind::Collection,
        visibility: None,
        state: ViewState::Active,
        state_changed_at: None,
        renderer: Some(ViewRenderer::Board),
        title: Some("Board".to_owned()),
        query: ViewQuery {
            realm_ids: vec![
                RealmId::new("ak:realm:AX-N4k3nJ3KKtkbL-adKMKRyKUlTWlwhxQVvjmvEBEVB").unwrap(),
            ],
            object_kinds: Vec::new(),
            morph_kinds: Vec::new(),
            facets: Vec::new(),
            seal_ref: None,
            filters: Vec::new(),
            relation: None,
            context: None,
            order_by: Vec::new(),
            projection: Vec::new(),
            cursor: None,
            limit: None,
            consistency: None,
        },
        visible_fields: Vec::new(),
        layout: None,
        collection: Some(CollectionConfig::default()),
        timeline: None,
        graph: None,
        document: None,
        dashboard: None,
        sort: Vec::new(),
        created_by: ActorId::service(DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap()),
        created_at: Utc::now(),
        updated_by: None,
        updated_at: None,
    }
}

#[test]
fn view_validate_enforces_kind_config_exclusivity_and_renderer_whitelist() {
    let mut view = collection_view();
    view.validate().unwrap();

    // A config belonging to another kind is rejected even though serde
    // accepts the field.
    view.timeline = Some(BTreeMap::new());
    assert!(view.validate().is_err());
    view.timeline = None;

    // The matching config is mandatory, not optional.
    view.collection = None;
    assert!(view.validate().is_err());
    view.collection = Some(CollectionConfig::default());

    view.renderer = Some(ViewRenderer::Thread);
    assert!(view.validate().is_err());
    view.renderer = Some(ViewRenderer::Custom);
    view.validate().unwrap();

    view.schema = "ak.schema.view.unregistered.v1".to_owned();
    assert!(view.validate().is_err());
}

#[test]
fn private_account_data_view_binds_visibility_state_and_key() {
    let mut view = collection_view();
    let key = private_view_account_data_key(&view.id);

    // A shared-visibility definition must never be stored under the
    // private account-data key.
    assert!(view.validate_private_account_data(&key).is_err());
    view.visibility = Some(ViewVisibility::Shared);
    assert!(view.validate_private_account_data(&key).is_err());

    view.visibility = Some(ViewVisibility::Private);
    view.validate_private_account_data(&key).unwrap();

    // Another View's key would let a client silently re-home a definition.
    let foreign_key = private_view_account_data_key(
        &ViewId::new("ak:view:ATmtapZXfxsLwiLRxOBYnVvhLCkfPsu9iZzgt9b60vhK").unwrap(),
    );
    assert!(view.validate_private_account_data(&foreign_key).is_err());

    // `tombstoned` is the shared terminal; a private View is removed by
    // physically deleting its account-data key.
    view.state = ViewState::Tombstoned;
    view.state_changed_at = Some(Utc::now());
    assert!(view.validate_private_account_data(&key).is_err());
}

#[test]
fn view_supports_renderer_and_facet_config_facades() {
    let request = ViewQuery {
        realm_ids: vec![
            RealmId::new("ak:realm:AX-N4k3nJ3KKtkbL-adKMKRyKUlTWlwhxQVvjmvEBEVB").unwrap(),
        ],
        object_kinds: Vec::new(),
        morph_kinds: Vec::new(),
        facets: vec![Facet::Stateful, Facet::Rankable],
        seal_ref: None,
        filters: Vec::new(),
        relation: None,
        context: None,
        order_by: Vec::new(),
        projection: Vec::new(),
        cursor: None,
        limit: None,
        consistency: None,
    };
    let mut view = View {
        schema: SchemaId::VIEW_V1.to_owned(),
        id: ViewId::new("ak:view:AaiFHUI8GObKlPqeNvnl4E37L9moM-J0DjA4_UN9FvhR").unwrap(),
        realm_id: RealmId::new("ak:realm:AX-N4k3nJ3KKtkbL-adKMKRyKUlTWlwhxQVvjmvEBEVB").unwrap(),
        kind: ViewKind::Collection,
        visibility: None,
        state: ViewState::Active,
        state_changed_at: None,
        renderer: Some(ViewRenderer::Board),
        title: Some("Board".to_owned()),
        query: request,
        visible_fields: Vec::new(),
        layout: None,
        collection: Some(CollectionConfig {
            item_facets: vec![Facet::Stateful, Facet::Rankable],
            item_render: Some(CollectionItemRender::Card),
            ..Default::default()
        }),
        timeline: None,
        graph: None,
        document: None,
        dashboard: None,
        sort: Vec::new(),
        created_by: ActorId::service(DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap()),
        created_at: Utc::now(),
        updated_by: None,
        updated_at: None,
    };

    view.validate_lifecycle().unwrap();
    let value = serde_json::to_value(&view).unwrap();
    assert_eq!(value["renderer"], "board");
    assert_eq!(
        value["collection"]["item_facets"],
        json!(["stateful", "rankable"])
    );
    view.state = ViewState::Tombstoned;
    assert!(view.validate_lifecycle().is_err());
    view.state_changed_at = Some(Utc::now());
    view.validate_lifecycle().unwrap();

    for removed in [
        json!({"item_order_by": [], "grouping": null, "page_size": 50}),
        json!({"item_order_by": [], "grouping": null, "selection_policy": "multiple"}),
    ] {
        assert!(serde_json::from_value::<CollectionConfig>(removed).is_err());
    }
    assert!(
        serde_json::from_value::<CollectionGrouping>(json!({
            "mode": "none",
            "wip_limit_enforcement": "warn"
        }))
        .is_err()
    );
}
