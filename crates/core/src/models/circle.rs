//! Circle child-scope policy enforcement retained by `arkret-core`.
//!
//! The Circle wire types and reducer-pure Circle validators migrated to
//! `arkret-models-collaboration` (re-exported below). The
//! `Space.child_scope_policy` enforcement helpers stay here because they
//! consume [`ChildScopePolicy`] from the (not yet migrated) `space`
//! collaboration-object module.

pub use arkret_models_collaboration::governance::circle::*;

use super::*;

/// Reducer-pure predicate for `Space.child_scope_policy` enforcement
/// (AKP-0007 §3.4.2).
///
/// * `AllowAny` — accepts any scope.
/// * `RequireE2ee` — child MUST live in an MLS-backed scope: a Circle scope, or the Realm-default
///   scope when `realm_encryption_profile = MlsRfc9420`.
/// * `RequireSameScope` — child's `scope_circle_id` MUST equal the parent Space's `scope_circle_id`
///   (both `None` counts as "same").
/// * `RequireScopeCircleId` — child's `scope_circle_id` MUST equal the named Circle.
pub fn enforce_child_scope_policy(
    policy: &ChildScopePolicy,
    child_scope: Option<&CircleId>,
    parent_space_scope: Option<&CircleId>,
    realm_encryption_profile: &EncryptionProfile,
) -> std::result::Result<(), CircleScopeError> {
    enforce_child_scope_policy_with_circle_profile(
        policy,
        child_scope,
        parent_space_scope,
        realm_encryption_profile,
        None,
    )
}

/// Variant of [`enforce_child_scope_policy`] for reducers that have already
/// resolved the child Circle and can distinguish plaintext delivery-only
/// Circles from MLS-backed Circles.
pub fn enforce_child_scope_policy_with_circle_profile(
    policy: &ChildScopePolicy,
    child_scope: Option<&CircleId>,
    parent_space_scope: Option<&CircleId>,
    realm_encryption_profile: &EncryptionProfile,
    child_circle_encryption_profile: Option<&EncryptionProfile>,
) -> std::result::Result<(), CircleScopeError> {
    match policy {
        ChildScopePolicy::AllowAny {} => Ok(()),
        ChildScopePolicy::RequireE2ee {} => match child_scope {
            Some(_)
                if matches!(
                    child_circle_encryption_profile,
                    Some(EncryptionProfile::MlsRfc9420)
                ) =>
            {
                Ok(())
            }
            Some(_) => Err(CircleScopeError::ChildScopePolicyViolated {
                policy_kind: "require_e2ee",
                detail: "Circle-scoped child requires circle.encryption_profile = mls_rfc9420",
            }),
            None => match realm_encryption_profile {
                EncryptionProfile::MlsRfc9420 => Ok(()),
                _ => Err(CircleScopeError::ChildScopePolicyViolated {
                    policy_kind: "require_e2ee",
                    detail: "Realm-default child requires realm.encryption_profile = mls_rfc9420",
                }),
            },
        },
        ChildScopePolicy::RequireSameScope {} => {
            let child_s = child_scope.map(|c| c.as_str());
            let parent_s = parent_space_scope.map(|c| c.as_str());
            if child_s == parent_s {
                Ok(())
            } else {
                Err(CircleScopeError::ChildScopePolicyViolated {
                    policy_kind: "require_same_scope",
                    detail: "child scope_circle_id differs from parent Space scope_circle_id",
                })
            }
        }
        ChildScopePolicy::RequireScopeCircleId {
            scope_circle_id, ..
        } => match child_scope {
            Some(child) if child.as_str() == scope_circle_id.as_str() => Ok(()),
            _ => Err(CircleScopeError::ChildScopePolicyViolated {
                policy_kind: "require_scope_circle_id",
                detail: "child scope_circle_id does not match the policy's required circle",
            }),
        },
    }
}

#[cfg(test)]
mod child_scope_tests {
    use super::*;

    fn circle_a() -> CircleId {
        CircleId::new("ak:circle:0196419b-0000-7000-8000-000000000a01".to_owned()).unwrap()
    }
    fn circle_b() -> CircleId {
        CircleId::new("ak:circle:0196419b-0000-7000-8000-000000000a02".to_owned()).unwrap()
    }

    // ── enforce_child_scope_policy ─────────────────────────────────────────

    #[test]
    fn child_scope_allow_any_accepts_everything() {
        let policy = ChildScopePolicy::AllowAny {};
        enforce_child_scope_policy(&policy, None, None, &EncryptionProfile::None).unwrap();
        enforce_child_scope_policy(&policy, Some(&circle_a()), None, &EncryptionProfile::None)
            .unwrap();
    }

    #[test]
    fn child_scope_require_e2ee_needs_circle_or_mls_realm() {
        let policy = ChildScopePolicy::RequireE2ee {};
        // Circle-scoped child requires the reducer to resolve the Circle's
        // encryption profile; plaintext delivery-only Circles do not satisfy
        // require_e2ee.
        enforce_child_scope_policy_with_circle_profile(
            &policy,
            Some(&circle_a()),
            None,
            &EncryptionProfile::None,
            Some(&EncryptionProfile::MlsRfc9420),
        )
        .unwrap();
        assert!(matches!(
            enforce_child_scope_policy_with_circle_profile(
                &policy,
                Some(&circle_a()),
                None,
                &EncryptionProfile::None,
                Some(&EncryptionProfile::None),
            ),
            Err(CircleScopeError::ChildScopePolicyViolated {
                policy_kind: "require_e2ee",
                ..
            })
        ));
        // Realm-default child + MLS realm → accept.
        enforce_child_scope_policy(&policy, None, None, &EncryptionProfile::MlsRfc9420).unwrap();
        // Realm-default child + non-MLS realm → reject.
        assert!(matches!(
            enforce_child_scope_policy(&policy, None, None, &EncryptionProfile::None),
            Err(CircleScopeError::ChildScopePolicyViolated {
                policy_kind: "require_e2ee",
                ..
            })
        ));
    }

    #[test]
    fn child_scope_require_same_scope_matches_parent() {
        let policy = ChildScopePolicy::RequireSameScope {};
        let a = circle_a();
        enforce_child_scope_policy(&policy, Some(&a), Some(&a), &EncryptionProfile::None).unwrap();
        enforce_child_scope_policy(&policy, None, None, &EncryptionProfile::None).unwrap();
        // Mismatch.
        let b = circle_b();
        assert!(matches!(
            enforce_child_scope_policy(&policy, Some(&b), Some(&a), &EncryptionProfile::None),
            Err(CircleScopeError::ChildScopePolicyViolated {
                policy_kind: "require_same_scope",
                ..
            })
        ));
        // Asymmetric None/Some.
        assert!(matches!(
            enforce_child_scope_policy(&policy, None, Some(&a), &EncryptionProfile::None),
            Err(CircleScopeError::ChildScopePolicyViolated { .. })
        ));
    }

    #[test]
    fn child_scope_require_circle_id_matches_named() {
        let a = circle_a();
        let policy = ChildScopePolicy::RequireScopeCircleId {
            scope_circle_id: a.clone(),
        };
        enforce_child_scope_policy(&policy, Some(&a), None, &EncryptionProfile::None).unwrap();
        // Wrong circle.
        let b = circle_b();
        assert!(matches!(
            enforce_child_scope_policy(&policy, Some(&b), None, &EncryptionProfile::None),
            Err(CircleScopeError::ChildScopePolicyViolated {
                policy_kind: "require_scope_circle_id",
                ..
            })
        ));
        // No scope at all.
        assert!(matches!(
            enforce_child_scope_policy(&policy, None, None, &EncryptionProfile::None),
            Err(CircleScopeError::ChildScopePolicyViolated { .. })
        ));
    }
}
