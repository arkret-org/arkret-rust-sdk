//! Relation wire-model facade.
//!
//! The Relation object, cardinality enforcement, and direct-write
//! guards live in `arkret-models-collaboration`. The embedded-registry
//! consistency test stays here because it reads the relation-kind
//! registry through `arkret_core::schema`.

pub use arkret_models_collaboration::objects::relation::*;

#[cfg(test)]
mod tests {
    use arkret_wire::{
        RelationTruthSourceClass, STANDARD_RELATION_KIND_METADATA, standard_relation_kind_metadata,
    };

    #[test]
    fn standard_relation_kind_metadata_matches_embedded_registry() {
        let registry =
            crate::schema::embedded_json_artifact("registry/relation-kind-registry.json")
                .expect("embedded relation registry");
        let relation_kinds = registry["relation_kinds"]
            .as_array()
            .expect("relation_kinds array");
        let mut registry_ids: Vec<&str> = relation_kinds
            .iter()
            .map(|row| row["canonical_id"].as_str().expect("canonical_id"))
            .collect();
        let mut sdk_ids: Vec<&str> = STANDARD_RELATION_KIND_METADATA
            .iter()
            .map(|metadata| metadata.canonical_id)
            .collect();
        registry_ids.sort_unstable();
        sdk_ids.sort_unstable();
        assert_eq!(sdk_ids, registry_ids);

        for row in relation_kinds {
            let id = row["canonical_id"].as_str().expect("canonical_id");
            let metadata = standard_relation_kind_metadata(id).expect("SDK metadata row");
            assert_eq!(
                metadata.default_cardinality,
                row["default_cardinality"]
                    .as_str()
                    .expect("default_cardinality")
            );
            assert_eq!(
                metadata.truth_source_class,
                match row["truth_source_class"]
                    .as_str()
                    .expect("truth_source_class")
                {
                    "canonical" => RelationTruthSourceClass::Canonical,
                    "derived_projection" => RelationTruthSourceClass::DerivedProjection,
                    "shape_dependent" => RelationTruthSourceClass::ShapeDependent,
                    other => panic!("unexpected truth_source_class: {other}"),
                }
            );
            assert_eq!(
                metadata.weak_semantic,
                row["weak_semantic"].as_bool().expect("weak_semantic")
            );
        }
    }
}
