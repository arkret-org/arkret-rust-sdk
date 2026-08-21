//! @generated; do not edit by hand.
//! Generator: tools/generate-registry-types.py
//! Input: registry/reducer-managed-path-registry.json; version=2026-08-21.1;
//! sha256=b460206038e7e948563890302f8ee1f0e006b71cf5011ccce8bee9f1372e44fe
//! Entries: universal_paths=9, object_kinds=7, any_object_paths=16

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReducerManagedPathDescriptor {
    pub path: &'static str,
    pub basis: &'static str,
    pub reason_code: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReducerManagedObjectPathDescriptor {
    pub path: &'static str,
    pub basis: &'static str,
    pub reason_code: &'static str,
    pub schema_enforced: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReducerManagedObjectDescriptor {
    pub object_kind: &'static str,
    pub forbidden_paths: &'static [ReducerManagedObjectPathDescriptor],
    pub universal_exemptions: &'static [&'static str],
}

/// General minimum set of `event-and-patch.md` section 4.2.5: the patch
/// paths every patch-bearing object kind forbids unless it declares an
/// explicit exemption.
pub const REDUCER_MANAGED_UNIVERSAL_PATHS: &[ReducerManagedPathDescriptor] = &[
    ReducerManagedPathDescriptor {
        path: "created_at",
        basis: "reducer_derived",
        reason_code: "patch_path_reducer_managed",
    },
    ReducerManagedPathDescriptor {
        path: "created_by",
        basis: "reducer_derived",
        reason_code: "patch_path_reducer_managed",
    },
    ReducerManagedPathDescriptor {
        path: "id",
        basis: "create_locked",
        reason_code: "patch_path_reducer_managed",
    },
    ReducerManagedPathDescriptor {
        path: "realm_id",
        basis: "create_locked",
        reason_code: "patch_path_reducer_managed",
    },
    ReducerManagedPathDescriptor {
        path: "schema",
        basis: "create_locked",
        reason_code: "patch_path_reducer_managed",
    },
    ReducerManagedPathDescriptor {
        path: "state",
        basis: "dedicated_event_owned",
        reason_code: "patch_path_reducer_managed",
    },
    ReducerManagedPathDescriptor {
        path: "state_changed_at",
        basis: "reducer_derived",
        reason_code: "patch_path_reducer_managed",
    },
    ReducerManagedPathDescriptor {
        path: "updated_at",
        basis: "reducer_derived",
        reason_code: "patch_path_reducer_managed",
    },
    ReducerManagedPathDescriptor {
        path: "updated_by",
        basis: "reducer_derived",
        reason_code: "patch_path_reducer_managed",
    },
];

/// Per-object-kind additions and exemptions. An object kind absent from
/// this table has no patch surface registered in the spec.
pub const REDUCER_MANAGED_OBJECTS: &[ReducerManagedObjectDescriptor] = &[
    ReducerManagedObjectDescriptor {
        object_kind: "actor_profile",
        forbidden_paths: &[ReducerManagedObjectPathDescriptor {
            path: "resolution",
            basis: "cell_projection",
            reason_code: "patch_path_reducer_managed",
            schema_enforced: true,
        }],
        universal_exemptions: &[],
    },
    ReducerManagedObjectDescriptor {
        object_kind: "circle",
        forbidden_paths: &[
            ReducerManagedObjectPathDescriptor {
                path: "encryption_profile",
                basis: "create_locked",
                reason_code: "patch_path_reducer_managed",
                schema_enforced: false,
            },
            ReducerManagedObjectPathDescriptor {
                path: "mls_group_id",
                basis: "reducer_derived",
                reason_code: "patch_path_reducer_managed",
                schema_enforced: false,
            },
        ],
        universal_exemptions: &[],
    },
    ReducerManagedObjectDescriptor {
        object_kind: "morph",
        forbidden_paths: &[
            ReducerManagedObjectPathDescriptor {
                path: "morph_kind",
                basis: "create_locked",
                reason_code: "patch_path_reducer_managed",
                schema_enforced: true,
            },
            ReducerManagedObjectPathDescriptor {
                path: "stage",
                basis: "dedicated_event_owned",
                reason_code: "patch_path_reducer_managed",
                schema_enforced: true,
            },
            ReducerManagedObjectPathDescriptor {
                path: "stage_changed_at",
                basis: "reducer_derived",
                reason_code: "patch_path_reducer_managed",
                schema_enforced: true,
            },
        ],
        universal_exemptions: &[],
    },
    ReducerManagedObjectDescriptor {
        object_kind: "relation",
        forbidden_paths: &[ReducerManagedObjectPathDescriptor {
            path: "effective_scope",
            basis: "reducer_derived",
            reason_code: "effective_scope_reducer_managed",
            schema_enforced: true,
        }],
        universal_exemptions: &[],
    },
    ReducerManagedObjectDescriptor {
        object_kind: "space",
        forbidden_paths: &[],
        universal_exemptions: &[],
    },
    ReducerManagedObjectDescriptor {
        object_kind: "strand",
        forbidden_paths: &[
            ReducerManagedObjectPathDescriptor {
                path: "stage",
                basis: "dedicated_event_owned",
                reason_code: "patch_path_reducer_managed",
                schema_enforced: false,
            },
            ReducerManagedObjectPathDescriptor {
                path: "stage_changed_at",
                basis: "reducer_derived",
                reason_code: "patch_path_reducer_managed",
                schema_enforced: false,
            },
        ],
        universal_exemptions: &[],
    },
    ReducerManagedObjectDescriptor {
        object_kind: "view",
        forbidden_paths: &[],
        universal_exemptions: &["state"],
    },
];

/// Conservative object-agnostic superset: every path forbidden on at
/// least one object kind, with no exemption applied. Only for callers
/// that cannot name the object kind; a caller that can name it MUST use
/// the per-object table instead, because applying this superset to a
/// View rejects the `state` patch that `views.md` section 3.1 requires.
pub const REDUCER_MANAGED_ANY_OBJECT_PATCH_PATHS: &[&str] = &[
    "created_at",
    "created_by",
    "effective_scope",
    "encryption_profile",
    "id",
    "mls_group_id",
    "morph_kind",
    "realm_id",
    "resolution",
    "schema",
    "stage",
    "stage_changed_at",
    "state",
    "state_changed_at",
    "updated_at",
    "updated_by",
];
