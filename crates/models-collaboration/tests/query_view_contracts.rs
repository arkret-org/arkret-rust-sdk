use std::collections::BTreeMap;

use arkret_identifiers::{Did, RealmId, RelationId, ViewId};
use arkret_models_collaboration::objects::queries::{
    CollectionConfig, CollectionGrouping, CollectionItemRender, FieldFilter, Filter, View,
    ViewQuery, ViewState,
};
use arkret_models_collaboration::objects::relation::Relation;
use arkret_wire::{
    Facet, Facets, FilterOp, RELATION_SCHEMA, RelationKind, VIEW_SCHEMA, ViewKind, ViewRenderer,
};
use chrono::Utc;
use serde_json::json;

#[test]
fn relation_requires_exact_wire_endpoints() {
    let relation = Relation {
        schema: RELATION_SCHEMA.to_owned(),
        id: RelationId::new("ak:relation:01904100-0000-7000-8000-7b3bf7d6e46b").unwrap(),
        realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-fd3637e8361f").unwrap(),
        scope_circle_id: None,
        effective_scope: None,
        relation_kind: RelationKind::Mentions,
        from_ref: "ak:morph:01904100-0000-7000-8000-c12dc98b2948".to_owned(),
        to_ref: "did:webvh:z6mkfixture:alice.example".to_owned(),
        rank: None,
        fields: BTreeMap::new(),
        state: None,
        state_changed_at: None,
        created_by: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
        created_at: Utc::now(),
        updated_by: None,
        updated_at: None,
    };
    relation.validate_endpoints().unwrap();
}

#[test]
fn query_request_uses_protocol_filters_array() {
    let request = ViewQuery {
        realm_ids: vec![RealmId::new("ak:realm:01904100-0000-7000-8000-fd3637e8361f").unwrap()],
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
    assert_eq!(names.facet_names().len(), 3);

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

#[test]
fn view_supports_renderer_and_facet_config_facades() {
    let request = ViewQuery {
        realm_ids: vec![RealmId::new("ak:realm:01904100-0000-7000-8000-fd3637e8361f").unwrap()],
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
        schema: VIEW_SCHEMA.to_owned(),
        id: ViewId::new("ak:view:01904100-0000-7000-8000-848727f328fe").unwrap(),
        realm_id: RealmId::new("ak:realm:01904100-0000-7000-8000-fd3637e8361f").unwrap(),
        kind: ViewKind::Collection,
        visibility: None,
        state: None,
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
        created_by: Did::new("did:webvh:z6mkfixture:alice.example").unwrap(),
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
    view.state = Some(ViewState::Tombstoned);
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
