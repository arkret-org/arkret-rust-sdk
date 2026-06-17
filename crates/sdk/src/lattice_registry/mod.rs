//! Cell-family lattice registry + spec-normative cell-family bindings.
//!
//! Per-cell-family [`LatticeKind`] runtime (one impl per `cell_family`
//! declared in the spec event-kind-registry) plus a [`LatticeRegistry`]
//! that pre-registers every spec-normative family via
//! [`default_lattice_registry`].
//!
//! Naming note: this module's [`LatticeKind`] is the *trait* declaring
//! which lattice algebra owns a given `cell_family`; the SDK's
//! [`crate::lattice::LatticeKind`] is the *enum* listing the six
//! normative algebras themselves. Impls below dispatch a `cell_family`
//! → `crate::lattice::LatticeKind` enum mapping plus a typed
//! subject-derivation function.
//!
//! Coverage (mirrors soland `reducer::lattice_kinds`):
//! - **OrSet** (causal add/remove): consent.grant, capability.grant / delegate / derived,
//!   session.grant, device.authorized, device.list_update, agent.key, covered_seals (MLS).
//! - **CasRegister** (last-writer-wins, conflict→Bottom): realm.policy, realm.read_receipt_policy,
//!   realm.history_visibility, realm.join_rule, realm.discovery, realm.organization, realm.upgrade,
//!   strand.position, strand.stage, morph.stage, space.parent, device.push_route, notary (Move/Seal
//!   authority cell), mls_epoch.
//! - **Fsm** (legal transitions only): member.state, agent.status.
//! - **OrderedLog** (per-issuer monotonic append): account.status, policy.rule,
//!   cross_signing.reset, contact.fact_log, direct_conversation.binding.
//! - **MvRegister** (concurrent multi-value): profile.create, view.create / update / reconcile,
//!   mimi.room_binding.

mod factory;
mod impls;
mod registry;
mod types;

pub use factory::*;
pub use impls::*;
pub use registry::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::lattice::LatticeKind as SdkLatticeKind;

    #[test]
    fn default_registry_covers_at_least_all_spec_normative_cell_families() {
        let registry = default_lattice_registry();
        // Spec event-kind-registry has 40+ unique `cell_family` strings;
        // this registry should cover them all.
        assert!(
            registry.len() >= 40,
            "expected ≥40 cell families registered, got {}",
            registry.len()
        );
    }

    #[test]
    fn default_registry_kind_count_matches_expected_total() {
        // The registry covers the 60 cell families declared by
        // event-kind-registry plus the three reducer-local seal/MLS
        // families (`notary`, `mls.epoch`, `covered_seals`).
        let registry = default_lattice_registry();
        assert_eq!(registry.len(), 63);
    }

    #[test]
    fn consent_grant_has_or_set_lattice_and_consent_id_subject() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ck.component.consent.grant.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrSet);
        assert_eq!(kind.bottom_policy(), BottomPolicy::Reject);
        let payload = json!({"consent_id": "cnt:01HXYZ"});
        let subject = kind.subject_for_effect(&payload).unwrap();
        assert_eq!(subject.as_deref(), Some("cnt:01HXYZ"));
    }

    #[test]
    fn member_state_uses_fsm_lattice_with_actor_subject() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ck.component.member.state.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::Fsm);
        let payload = json!({"actor_id": "did:example:alice"});
        let subject = kind.subject_for_effect(&payload).unwrap();
        assert_eq!(subject.as_deref(), Some("did:example:alice"));
    }

    #[test]
    fn realm_policy_is_singleton_cas_register() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ck.component.realm.policy.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::CasRegister);
        let subject = kind.subject_for_effect(&json!({})).unwrap();
        assert!(subject.is_none());
    }

    #[test]
    fn notary_cell_is_singleton_cas_register_and_required() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ck.component.notary.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::CasRegister);
        assert_eq!(kind.bottom_policy(), BottomPolicy::Reject);
        let comp = kind.component();
        assert_eq!(comp.criticality, Criticality::Required);
        assert_eq!(comp.component_type, "ck.component.notary.v1");
    }

    #[test]
    fn covered_seals_is_singleton_or_set() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ck.component.covered_seals.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrSet);
        let subject = kind.subject_for_effect(&json!({})).unwrap();
        assert!(subject.is_none());
    }

    #[test]
    fn mv_register_families_have_expose_bottom() {
        let registry = default_lattice_registry();
        for family in [
            "ck.component.profile.create.v1",
            "ck.component.view.create.v1",
            "ck.component.view.update.v1",
            "ck.component.view.reconcile.v1",
            "ck.component.mimi.room_binding.v1",
        ] {
            let kind = registry
                .lookup(family)
                .unwrap_or_else(|| panic!("missing impl for {family}"));
            assert_eq!(kind.lattice(), SdkLatticeKind::MvRegister);
            assert_eq!(
                kind.bottom_policy(),
                BottomPolicy::Expose,
                "{family} should expose multi-value via UX, not reject"
            );
        }
    }

    #[test]
    fn ordered_log_families_have_per_issuer_subject_or_singleton() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ck.component.realm.create.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrderedLog);
        let kind = registry.lookup("ck.component.account.status.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrderedLog);
        let payload = json!({"account_id": "act:01HXYZ"});
        let subject = kind.subject_for_effect(&payload).unwrap();
        assert_eq!(subject.as_deref(), Some("act:01HXYZ"));
    }

    #[test]
    fn missing_subject_field_surfaces_typed_error() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ck.component.strand.position.v1").unwrap();
        let err = kind
            .subject_for_effect(&json!({"unrelated": "x"}))
            .unwrap_err();
        match err {
            LatticeKindError::MissingSubjectField { cell_family, field } => {
                assert_eq!(cell_family, "ck.component.strand.position.v1");
                assert_eq!(field, "strand_id");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn event_kind_index_resolves_consent_grant_and_revoke() {
        let registry = default_lattice_registry();
        let grant = registry
            .lookup_for_event_kind("ck.consent.grant")
            .expect("ck.consent.grant should map to consent.grant.v1 cell");
        assert_eq!(grant.cell_family(), "ck.component.consent.grant.v1");
        let revoke = registry
            .lookup_for_event_kind("ck.consent.revoke")
            .expect("ck.consent.revoke shares the consent.grant.v1 cell (or-set rm)");
        assert_eq!(revoke.cell_family(), "ck.component.consent.grant.v1");
    }

    #[test]
    fn lattice_kind_error_display_is_stable() {
        let err = LatticeKindError::MissingSubjectField {
            cell_family: "ck.component.strand.position.v1",
            field: "strand_id",
        };
        let msg = format!("{err}");
        assert!(msg.contains("ck.component.strand.position.v1"));
        assert!(msg.contains("strand_id"));
    }
}
