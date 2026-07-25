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
//! - **Fsm** (legal transitions only): member.state, agent.status, call.state, realm.link.
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
    use arkret_state::lattice::LatticeKind as SdkLatticeKind;
    use arkret_state::{BottomMode, CellRegistry, CellState, SealedOp};
    use arkret_wire::{CellRef, LatticeOp, LatticeOpType, MoveId, RealmId, composite_subject};
    use serde_json::json;

    use super::*;

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
        // The registry covers the 66 cell families declared by
        // event-kind-registry (including `strand.object`, the
        // `ak.strand.create` cell write) plus the three reducer-local
        // seal/MLS families (`notary`, `mls.epoch`, `covered_seals`).
        let registry = default_lattice_registry();
        assert_eq!(registry.len(), 69);
    }

    #[test]
    fn consent_grant_has_or_set_lattice_and_consent_id_subject() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ak.component.consent.grant.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrSet);
        assert_eq!(kind.bottom_policy(), BottomPolicy::Reject);
        let payload = json!({"consent_id": "cnt:01HXYZ"});
        let subject = kind.subject_for_effect(&payload).unwrap();
        assert_eq!(subject.as_deref(), Some("cnt:01HXYZ"));
    }

    #[test]
    fn member_state_uses_fsm_lattice_with_actor_subject() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ak.component.member.state.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::Fsm);
        let payload = json!({"actor_id": "did:example:alice"});
        let subject = kind.subject_for_effect(&payload).unwrap();
        assert_eq!(subject.as_deref(), Some("did:example:alice"));
    }

    #[test]
    fn realm_link_uses_tuple_subject_fsm_and_rejects_bottom() {
        let registry = default_lattice_registry();
        let kind = registry
            .lookup("ak.component.realm.link.v1")
            .expect("Realm Link cell must be registered");
        assert_eq!(kind.lattice(), SdkLatticeKind::Fsm);
        assert_eq!(kind.bottom_policy(), BottomPolicy::Reject);
        let subject = kind
            .subject_for_effect(&json!({
                "target_realm_id": "ak:realm:01904100-0000-7000-8000-000000000022",
                "link_kind": "governed_by",
            }))
            .unwrap()
            .unwrap();
        assert_eq!(
            subject,
            composite_subject(&[
                "ak:realm:01904100-0000-7000-8000-000000000022",
                "governed_by",
            ])
            .unwrap()
        );
        assert_eq!(kind.event_kinds(), &["ak.realm.link"]);

        let sdk_registry = build_sdk_cell_registry();
        let realm_id =
            RealmId::new("ak:realm:01904100-0000-7000-8000-000000000011".to_owned()).unwrap();
        let cell = CellRef::new(format!("ak:cell:ak.component.realm.link.v1:{subject}")).unwrap();
        let binding = sdk_registry.resolve(&realm_id, &cell).unwrap();
        assert_eq!(binding.lattice.kind(), SdkLatticeKind::Fsm);
        assert_eq!(binding.bottom_mode, BottomMode::Reject);
    }

    #[test]
    fn realm_member_fsm_uses_leave_as_the_normative_initial_state() {
        let registry = build_sdk_cell_registry();
        let realm_id = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000011").unwrap();
        let cell =
            CellRef::new("ak:cell:ak.component.member.state.v1:did:web:bob.example".to_owned())
                .unwrap();
        let binding = registry.resolve(&realm_id, &cell).unwrap();
        let invite = SealedOp::new(
            MoveId::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
            LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!("leave")),
                to: Some(json!("invite")),
                reason: None,
                issuer_seq: None,
            },
        );

        assert_eq!(
            binding.lattice.join(&cell, &[invite]),
            CellState::Value(json!("invite"))
        );
    }

    #[test]
    fn call_state_and_summary_use_call_id_subjects() {
        let registry = default_lattice_registry();
        let state = registry.lookup("ak.component.call.state.v1").unwrap();
        assert_eq!(state.lattice(), SdkLatticeKind::Fsm);
        assert_eq!(
            state
                .subject_for_effect(&json!({"call_id": "ak:call:01"}))
                .unwrap()
                .as_deref(),
            Some("ak:call:01")
        );
        let summary = registry.lookup("ak.component.call.summary.v1").unwrap();
        assert_eq!(summary.lattice(), SdkLatticeKind::CasRegister);
        assert_eq!(
            summary
                .subject_for_effect(&json!({"call_id": "ak:call:01"}))
                .unwrap()
                .as_deref(),
            Some("ak:call:01")
        );
    }

    #[test]
    fn realm_policy_is_singleton_cas_register() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ak.component.realm.policy.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::CasRegister);
        let subject = kind.subject_for_effect(&json!({})).unwrap();
        assert!(subject.is_none());
    }

    #[test]
    fn notary_cell_is_singleton_cas_register_and_required() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ak.component.notary.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::CasRegister);
        assert_eq!(kind.bottom_policy(), BottomPolicy::Reject);
        let comp = kind.component();
        assert_eq!(comp.criticality, Criticality::Required);
        assert_eq!(comp.component_type, "ak.component.notary.v1");
    }

    #[test]
    fn covered_seals_is_singleton_or_set() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ak.component.covered_seals.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrSet);
        let subject = kind.subject_for_effect(&json!({})).unwrap();
        assert!(subject.is_none());
    }

    #[test]
    fn mv_register_families_have_expose_bottom() {
        let registry = default_lattice_registry();
        for family in [
            "ak.component.profile.create.v1",
            "ak.component.view.create.v1",
            "ak.component.view.update.v1",
            "ak.component.view.reconcile.v1",
            "ak.component.mimi.room_binding.v1",
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
        let kind = registry.lookup("ak.component.realm.create.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrderedLog);
        let kind = registry.lookup("ak.component.account.status.v1").unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrderedLog);
        let payload = json!({"account_id": "act:01HXYZ"});
        let subject = kind.subject_for_effect(&payload).unwrap();
        assert_eq!(subject.as_deref(), Some("act:01HXYZ"));
    }

    #[test]
    fn missing_subject_field_surfaces_typed_error() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ak.component.strand.position.v1").unwrap();
        let err = kind
            .subject_for_effect(&json!({"unrelated": "x"}))
            .unwrap_err();
        match err {
            LatticeKindError::MissingSubjectField { cell_family, field } => {
                assert_eq!(cell_family, "ak.component.strand.position.v1");
                assert_eq!(field, "strand_id");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn agent_key_subject_uses_canonical_composite_encoding() {
        let registry = default_lattice_registry();
        let kind = registry.lookup("ak.component.agent.key.v1").unwrap();
        let agent_id = "did:webvh:z6mkfixture:agent.example";
        let key_id = "did:webvh:z6mkfixture:agent.example#runtime-1";
        let expected = composite_subject(&[agent_id, key_id]).unwrap();
        assert_eq!(
            kind.subject_for_effect(&json!({
                "agent_id": agent_id,
                "key_id": key_id,
            }))
            .unwrap()
            .as_deref(),
            Some(expected.as_str())
        );
    }

    #[test]
    fn event_kind_index_resolves_consent_grant_and_revoke() {
        let registry = default_lattice_registry();
        let grant = registry
            .lookup_for_event_kind("ak.consent.grant")
            .expect("ak.consent.grant should map to consent.grant.v1 cell");
        assert_eq!(grant.cell_family(), "ak.component.consent.grant.v1");
        let revoke = registry
            .lookup_for_event_kind("ak.consent.revoke")
            .expect("ak.consent.revoke shares the consent.grant.v1 cell (or-set rm)");
        assert_eq!(revoke.cell_family(), "ak.component.consent.grant.v1");
    }

    #[test]
    fn lattice_kind_error_display_is_stable() {
        let err = LatticeKindError::MissingSubjectField {
            cell_family: "ak.component.strand.position.v1",
            field: "strand_id",
        };
        let msg = format!("{err}");
        assert!(msg.contains("ak.component.strand.position.v1"));
        assert!(msg.contains("strand_id"));
    }
}
