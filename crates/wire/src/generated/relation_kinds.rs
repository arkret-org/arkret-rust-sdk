//! @generated; do not edit by hand.
//! Generator: tools/spec-codegen
//! Input: registry/relation-kind-registry.json; version=2026-09-20.1;
//! sha256=ba36a1db56ead87c79104d41b82e95c3ba98677252d76e6e23ca31490b28bb2d Entries: standard=15

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RelationKind {
    AssignedTo,
    AttachedTo,
    BelongsTo,
    Blocks,
    ConfidentialDiscussionOf,
    Contains,
    DependsOn,
    DerivedFrom,
    HasDefaultView,
    Mentions,
    PromotedFromDiscussion,
    References,
    RepliesTo,
    SummarizedFrom,
    Watches,
    Custom(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelationTruthSourceClass {
    Canonical,
    DerivedProjection,
    ShapeDependent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelationKindDescriptor {
    pub canonical_id: &'static str,
    pub default_cardinality: &'static str,
    pub primary_conflict_domain: &'static str,
    /// Primary conflict domain of the directly writable shape, if any.
    pub direct_write_primary_conflict_domain: Option<&'static str>,
    pub truth_source_class: RelationTruthSourceClass,
    pub weak_semantic: bool,
}

impl RelationKind {
    pub const STANDARD: &'static [Self] = &[
        Self::AssignedTo,
        Self::AttachedTo,
        Self::BelongsTo,
        Self::Blocks,
        Self::ConfidentialDiscussionOf,
        Self::Contains,
        Self::DependsOn,
        Self::DerivedFrom,
        Self::HasDefaultView,
        Self::Mentions,
        Self::PromotedFromDiscussion,
        Self::References,
        Self::RepliesTo,
        Self::SummarizedFrom,
        Self::Watches,
    ];

    pub fn as_str(&self) -> &str {
        match self {
            Self::AssignedTo => "assigned_to",
            Self::AttachedTo => "attached_to",
            Self::BelongsTo => "belongs_to",
            Self::Blocks => "blocks",
            Self::ConfidentialDiscussionOf => "confidential_discussion_of",
            Self::Contains => "contains",
            Self::DependsOn => "depends_on",
            Self::DerivedFrom => "derived_from",
            Self::HasDefaultView => "has_default_view",
            Self::Mentions => "mentions",
            Self::PromotedFromDiscussion => "promoted_from_discussion",
            Self::References => "references",
            Self::RepliesTo => "replies_to",
            Self::SummarizedFrom => "summarized_from",
            Self::Watches => "watches",
            Self::Custom(value) => value,
        }
    }

    pub fn from_wire(value: &str) -> Self {
        match value {
            "assigned_to" => Self::AssignedTo,
            "attached_to" => Self::AttachedTo,
            "belongs_to" => Self::BelongsTo,
            "blocks" => Self::Blocks,
            "confidential_discussion_of" => Self::ConfidentialDiscussionOf,
            "contains" => Self::Contains,
            "depends_on" => Self::DependsOn,
            "derived_from" => Self::DerivedFrom,
            "has_default_view" => Self::HasDefaultView,
            "mentions" => Self::Mentions,
            "promoted_from_discussion" => Self::PromotedFromDiscussion,
            "references" => Self::References,
            "replies_to" => Self::RepliesTo,
            "summarized_from" => Self::SummarizedFrom,
            "watches" => Self::Watches,
            _ => Self::Custom(value.to_owned()),
        }
    }

    pub fn descriptor(&self) -> Option<&'static RelationKindDescriptor> {
        RELATION_KIND_DESCRIPTORS
            .iter()
            .find(|row| row.canonical_id == self.as_str())
    }

    pub fn is_standard(&self) -> bool {
        self.descriptor().is_some()
    }

    pub fn is_structural(&self) -> bool {
        self.descriptor().is_some_and(|row| !row.weak_semantic)
    }
}

impl Serialize for RelationKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RelationKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::from_wire(&String::deserialize(deserializer)?))
    }
}

pub const RELATION_KIND_DESCRIPTORS: &[RelationKindDescriptor] = &[
    RelationKindDescriptor {
        canonical_id: "assigned_to",
        default_cardinality: "many_to_many",
        primary_conflict_domain: "tuple",
        direct_write_primary_conflict_domain: Some("tuple"),
        truth_source_class: RelationTruthSourceClass::Canonical,
        weak_semantic: true,
    },
    RelationKindDescriptor {
        canonical_id: "attached_to",
        default_cardinality: "many_to_many",
        primary_conflict_domain: "tuple",
        direct_write_primary_conflict_domain: Some("tuple"),
        truth_source_class: RelationTruthSourceClass::Canonical,
        weak_semantic: true,
    },
    RelationKindDescriptor {
        canonical_id: "belongs_to",
        default_cardinality: "many_to_one",
        primary_conflict_domain: "from",
        direct_write_primary_conflict_domain: Some("from"),
        truth_source_class: RelationTruthSourceClass::Canonical,
        weak_semantic: false,
    },
    RelationKindDescriptor {
        canonical_id: "blocks",
        default_cardinality: "many_to_many",
        primary_conflict_domain: "tuple",
        direct_write_primary_conflict_domain: Some("tuple"),
        truth_source_class: RelationTruthSourceClass::Canonical,
        weak_semantic: true,
    },
    RelationKindDescriptor {
        canonical_id: "confidential_discussion_of",
        default_cardinality: "many_to_one",
        primary_conflict_domain: "from",
        direct_write_primary_conflict_domain: Some("from"),
        truth_source_class: RelationTruthSourceClass::Canonical,
        weak_semantic: true,
    },
    RelationKindDescriptor {
        canonical_id: "contains",
        default_cardinality: "shape_dependent",
        primary_conflict_domain: "shape_dependent",
        direct_write_primary_conflict_domain: Some("tuple"),
        truth_source_class: RelationTruthSourceClass::ShapeDependent,
        weak_semantic: false,
    },
    RelationKindDescriptor {
        canonical_id: "depends_on",
        default_cardinality: "many_to_many",
        primary_conflict_domain: "tuple",
        direct_write_primary_conflict_domain: Some("tuple"),
        truth_source_class: RelationTruthSourceClass::Canonical,
        weak_semantic: true,
    },
    RelationKindDescriptor {
        canonical_id: "derived_from",
        default_cardinality: "many_to_many",
        primary_conflict_domain: "tuple",
        direct_write_primary_conflict_domain: Some("tuple"),
        truth_source_class: RelationTruthSourceClass::Canonical,
        weak_semantic: true,
    },
    RelationKindDescriptor {
        canonical_id: "has_default_view",
        default_cardinality: "many_to_one",
        primary_conflict_domain: "from",
        direct_write_primary_conflict_domain: Some("from"),
        truth_source_class: RelationTruthSourceClass::Canonical,
        weak_semantic: true,
    },
    RelationKindDescriptor {
        canonical_id: "mentions",
        default_cardinality: "many_to_many",
        primary_conflict_domain: "tuple",
        direct_write_primary_conflict_domain: Some("tuple"),
        truth_source_class: RelationTruthSourceClass::Canonical,
        weak_semantic: true,
    },
    RelationKindDescriptor {
        canonical_id: "promoted_from_discussion",
        default_cardinality: "many_to_many",
        primary_conflict_domain: "tuple",
        direct_write_primary_conflict_domain: Some("tuple"),
        truth_source_class: RelationTruthSourceClass::Canonical,
        weak_semantic: true,
    },
    RelationKindDescriptor {
        canonical_id: "references",
        default_cardinality: "many_to_many",
        primary_conflict_domain: "tuple",
        direct_write_primary_conflict_domain: Some("tuple"),
        truth_source_class: RelationTruthSourceClass::Canonical,
        weak_semantic: true,
    },
    RelationKindDescriptor {
        canonical_id: "replies_to",
        default_cardinality: "many_to_one",
        primary_conflict_domain: "from",
        direct_write_primary_conflict_domain: Some("from"),
        truth_source_class: RelationTruthSourceClass::Canonical,
        weak_semantic: true,
    },
    RelationKindDescriptor {
        canonical_id: "summarized_from",
        default_cardinality: "many_to_many",
        primary_conflict_domain: "tuple",
        direct_write_primary_conflict_domain: Some("tuple"),
        truth_source_class: RelationTruthSourceClass::Canonical,
        weak_semantic: true,
    },
    RelationKindDescriptor {
        canonical_id: "watches",
        default_cardinality: "one_active_edge_per_pair",
        primary_conflict_domain: "truth_source",
        direct_write_primary_conflict_domain: Some("truth_source"),
        truth_source_class: RelationTruthSourceClass::DerivedProjection,
        weak_semantic: false,
    },
];
