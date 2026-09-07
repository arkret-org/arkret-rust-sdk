//! Cell-family lattice registry + spec-normative cell-family bindings.
//!
//! [`build_sdk_cell_registry`] installs the complete executable
//! family/lattice/bottom mapping generated from the spec event-kind registry.
//! [`default_lattice_registry`] provides typed subject-derivation and
//! event-kind dispatch implementations for callers that need those helpers.
//!
//! Naming note: this module's [`LatticeKind`] is the *trait* declaring
//! which lattice algebra owns a given `cell_family`; the SDK's
//! `arkret_state::lattice::LatticeKind` is the *enum* listing the six
//! normative algebras themselves. Impls below dispatch a `cell_family`
//! → `crate::lattice::LatticeKind` enum mapping plus a typed
//! subject-derivation function.
mod contract_registry;
mod factory;
mod generated;
mod impls;
mod registry;
mod types;

pub use contract_registry::*;
pub use factory::*;
pub use impls::*;
pub use registry::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_state::lattice::LatticeKind as SdkLatticeKind;
    use arkret_state::{BottomMode, CellRegistry, CellState, SealedOp};
    use arkret_wire::{CellRef, Hash, LatticeOp, LatticeOpType, RealmId, composite_subject};
    use serde_json::json;

    use super::*;

    fn account_actor(station: &str) -> serde_json::Value {
        json!({
            "kind": "account",
            "account_id": {
                "principal_id": "ak:did_core:web:alice.example",
                "station_id": station
            }
        })
    }

    fn actor_component(actor: &serde_json::Value) -> String {
        String::from_utf8(arkret_wire::canonical::canonical_json_bytes(actor).unwrap()).unwrap()
    }

    #[test]
    fn sdk_cell_registry_bindings_match_configured_spec_exactly() {
        let artifact =
            arkret_schema_conformance::spec_json_artifact("registry/event-kind-registry.json")
                .unwrap();
        let mut expected = BTreeMap::new();
        for event in artifact["event_kinds"].as_array().unwrap() {
            if event["status"] != "active" {
                continue;
            }
            let mut writes = event["cell_writes"].as_array().cloned().unwrap_or_default();
            if event.get("cell_family").is_some() {
                writes.push(event.clone());
            }
            for write in writes {
                if write.get("cell_family").is_none() {
                    continue;
                }
                let family = write["cell_family"].as_str().unwrap().to_owned();
                let binding = (
                    write["lattice"].as_str().unwrap().to_owned(),
                    write["bottom"].as_str().unwrap().to_owned(),
                );
                assert_eq!(
                    expected
                        .insert(family.clone(), binding.clone())
                        .unwrap_or(binding.clone()),
                    binding,
                    "conflicting spec binding for {family}"
                );
            }
        }

        let actual: BTreeMap<_, _> = lattice_bindings_for_sdk_registry()
            .into_iter()
            .map(|(family, lattice, bottom)| {
                (
                    family.to_owned(),
                    (
                        match lattice {
                            SdkLatticeKind::OrSet => "or_set",
                            SdkLatticeKind::CasRegister => "cas_register",
                            SdkLatticeKind::Fsm => "fsm",
                            SdkLatticeKind::OrderedLog => "ordered_log",
                            SdkLatticeKind::MvRegister => "mv_register",
                            SdkLatticeKind::Counter => "counter",
                        }
                        .to_owned(),
                        match bottom {
                            BottomMode::Reject => "reject",
                            BottomMode::Expose => "expose",
                            BottomMode::Inert => "inert",
                        }
                        .to_owned(),
                    ),
                )
            })
            .collect();
        assert_eq!(actual, expected);

        let registry = build_sdk_cell_registry();
        let realm_id =
            RealmId::new("ak:realm:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934".to_owned())
                .unwrap();
        for family in actual.keys() {
            let cell = CellRef::new(format!("ak:cell:{family}:coverage")).unwrap();
            registry
                .resolve(&realm_id, &cell)
                .unwrap_or_else(|error| panic!("{family} missing from SDK registry: {error}"));
        }
    }

    #[test]
    fn spec_bound_or_sets_are_inert_and_cannot_materialize_bottom() {
        let typed = default_lattice_registry();
        let runtime = build_sdk_cell_registry();
        let realm_id =
            RealmId::new("ak:realm:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934".to_owned())
                .unwrap();
        let families = [
            arkret_wire::CellFamilyId::CAPABILITY_DERIVED_V1,
            arkret_wire::CellFamilyId::CAPABILITY_GRANT_V1,
            arkret_wire::CellFamilyId::CONSENT_GRANT_V1,
            arkret_wire::CellFamilyId::DEVICE_AUTHORIZATION_V1,
            arkret_wire::CellFamilyId::DEVICE_LIST_UPDATE_V1,
        ];

        let sealed = |byte: usize, op_type: LatticeOpType| {
            SealedOp::new(
                Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap(),
                LatticeOp {
                    op_type,
                    tag: Some("dot".to_owned()),
                    value: matches!(op_type, LatticeOpType::Add).then(|| json!({"active": true})),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            )
        };

        for (index, family) in families.into_iter().enumerate() {
            let adapter = typed.lookup(family).unwrap();
            assert_eq!(adapter.lattice(), SdkLatticeKind::OrSet);
            assert_eq!(adapter.bottom_policy(), BottomPolicy::Inert);

            let cell = CellRef::new(format!("ak:cell:{family}:coverage")).unwrap();
            let binding = runtime.resolve(&realm_id, &cell).unwrap();
            assert_eq!(binding.lattice.kind(), SdkLatticeKind::OrSet);
            assert_eq!(binding.bottom_mode, BottomMode::Inert);

            let grant = sealed(index * 2 + 1, LatticeOpType::Add);
            let revoke = sealed(index * 2 + 2, LatticeOpType::Remove);

            // A lone grant materializes the element and never a Bottom, so
            // `inert` cannot be reached through the normal write path.
            assert_eq!(
                binding.lattice.join(&cell, std::slice::from_ref(&grant)),
                CellState::Value(json!([{"tag": "dot", "value": {"active": true}}])),
                "{family} grant must resolve to a value"
            );

            // A causally later revoke wipes the grant instead of joining to
            // Bottom. `inert` therefore never leaves a revoked authority
            // standing, which is the way this bottom policy could widen
            // permissions.
            assert_eq!(
                binding
                    .lattice
                    .join(&cell, &[grant.clone(), revoke.clone()]),
                CellState::Value(json!([])),
                "{family} revoke must withdraw the grant"
            );

            // The mirrored order is a re-grant, not a conflict: still a value,
            // still no Bottom to fall back on.
            assert_eq!(
                binding.lattice.join(&cell, &[revoke, grant]),
                CellState::Value(json!([{"tag": "dot", "value": {"active": true}}])),
                "{family} re-grant after revoke must resolve to a value"
            );
        }

        let principal_id = "ak:did_core:webvh:z6mkfixture";
        let device_id = "ak:device:01904100-0000-7000-8000-000000000044";
        let expected_device_subject = composite_subject(&[principal_id, device_id]).unwrap();
        assert_eq!(
            typed
                .lookup(arkret_wire::CellFamilyId::DEVICE_AUTHORIZATION_V1)
                .unwrap()
                .subject_for_effect(&json!({
                    "principal_id": principal_id,
                    "device_id": device_id,
                }))
                .unwrap()
                .as_deref(),
            Some(expected_device_subject.as_str())
        );
        assert_eq!(
            typed
                .lookup(arkret_wire::CellFamilyId::DEVICE_LIST_UPDATE_V1)
                .unwrap()
                .subject_for_effect(&json!({"principal_id": principal_id}))
                .unwrap()
                .as_deref(),
            Some(principal_id)
        );
        assert_eq!(
            typed
                .lookups_for_event_kind("ak.capability.relinquish")
                .map(|kind| kind.cell_family())
                .collect::<Vec<_>>(),
            vec![arkret_wire::CellFamilyId::CAPABILITY_GRANT_V1]
        );
        let grant_adapter = typed
            .lookup(arkret_wire::CellFamilyId::CAPABILITY_GRANT_V1)
            .unwrap();
        let event_id = arkret_wire::EventId::new(
            "ak:event:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934".to_owned(),
        )
        .unwrap();
        let grant_id = arkret_wire::GrantId::from_event_id(&event_id);
        assert_eq!(
            grant_adapter
                .subject_for_event("ak.capability.grant", &event_id, &json!({}))
                .unwrap()
                .as_deref(),
            Some(grant_id.as_str())
        );
        assert_eq!(
            grant_adapter
                .subject_for_event(
                    "ak.capability.relinquish",
                    &event_id,
                    &json!({"grant_id": grant_id.as_str()}),
                )
                .unwrap()
                .as_deref(),
            Some(grant_id.as_str())
        );
    }

    #[test]
    fn object_creation_and_updates_share_the_registered_subject() {
        let registry = default_lattice_registry();
        let event_id = arkret_wire::EventId::from_event_digest(
            &Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
        )
        .unwrap();
        for (family, create, updates, field, subject) in [
            (
                arkret_wire::CellFamilyId::STRAND_OBJECT_V1,
                arkret_wire::event_kind_str::STRAND_CREATE,
                vec![
                    arkret_wire::event_kind_str::STRAND_UPDATE,
                    arkret_wire::event_kind_str::STRAND_TRACKS_UPDATE,
                ],
                "target_ref",
                arkret_wire::StrandId::from_event_id(&event_id).to_string(),
            ),
            (
                arkret_wire::CellFamilyId::VIEW_V1,
                arkret_wire::event_kind_str::VIEW_CREATE,
                vec![
                    arkret_wire::event_kind_str::VIEW_UPDATE,
                    arkret_wire::event_kind_str::VIEW_RECONCILE,
                ],
                "view_id",
                arkret_wire::ViewId::from_event_id(&event_id).to_string(),
            ),
        ] {
            let adapter = registry.lookup(family).unwrap();
            assert_eq!(
                adapter
                    .subject_for_event(create, &event_id, &json!({}))
                    .unwrap(),
                Some(subject.clone())
            );
            for update in updates {
                assert_eq!(
                    adapter
                        .subject_for_event(update, &event_id, &json!({field: subject}))
                        .unwrap(),
                    Some(subject.clone())
                );
                assert!(
                    adapter
                        .subject_for_event(update, &event_id, &json!({}))
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn strand_object_exposes_distinct_concurrent_heads_and_deduplicates_replay() {
        let strand_id = "ak:strand:0196419b-0000-7000-8000-000000000901";
        let typed = default_lattice_registry();
        let adapter = typed
            .lookup(arkret_wire::CellFamilyId::STRAND_OBJECT_V1)
            .unwrap();
        assert_eq!(adapter.lattice(), SdkLatticeKind::MvRegister);
        assert_eq!(adapter.bottom_policy(), BottomPolicy::Expose);
        assert_eq!(
            adapter
                .subject_for_effect(&json!({"target_ref": strand_id}))
                .unwrap()
                .as_deref(),
            Some(strand_id)
        );

        let realm_id =
            RealmId::new("ak:realm:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934".to_owned())
                .unwrap();
        let cell = CellRef::new(format!(
            "ak:cell:{}:{strand_id}",
            arkret_wire::CellFamilyId::STRAND_OBJECT_V1
        ))
        .unwrap();
        let runtime = build_sdk_cell_registry();
        let binding = runtime.resolve(&realm_id, &cell).unwrap();
        assert_eq!(binding.lattice.kind(), SdkLatticeKind::MvRegister);
        assert_eq!(binding.bottom_mode, BottomMode::Expose);

        let set = |byte: u8, value: serde_json::Value| {
            SealedOp::new(
                Hash::new(format!("sha256:{}", format!("{byte:02x}").repeat(32))).unwrap(),
                LatticeOp {
                    op_type: LatticeOpType::Set,
                    tag: None,
                    value: Some(value),
                    from: None,
                    to: None,
                    reason: None,
                    issuer_seq: None,
                },
            )
        };
        let track_a = json!({"tracks": {"main": {"enabled": true}}});
        let track_b = json!({"tracks": {"main": {"enabled": false}}});

        assert_eq!(
            binding
                .lattice
                .join(&cell, &[set(1, track_a.clone()), set(2, track_a.clone())]),
            CellState::Value(track_a.clone())
        );
        match binding
            .lattice
            .join(&cell, &[set(3, track_a.clone()), set(4, track_b.clone())])
        {
            CellState::Bottom(bottom) => {
                assert_eq!(bottom.head_ids, vec![track_a, track_b]);
                assert_eq!(bottom.move_ids.len(), 2);
            }
            CellState::Value(value) => panic!("distinct concurrent heads resolved to {value}"),
        }
    }

    #[test]
    fn canonical_fsm_contracts_resolve_all_templates_with_exact_closure() {
        let contracts = canonical_fsm_contracts().unwrap();
        // 18 registered FSM cell families; the moderation-appeal FSM is not one
        // of them — v1 has no protocol-native appeal workflow.
        assert_eq!(contracts.len(), 18);
        let by_family: BTreeMap<_, _> = contracts
            .iter()
            .map(|contract| (contract.cell_family.as_str(), contract))
            .collect();
        let realm_member = by_family[arkret_wire::CellFamilyId::MEMBER_STATE_V1];
        assert!(
            !realm_member
                .allowed_transitions
                .contains(&("join".to_owned(), "join".to_owned()))
        );
        assert!(
            realm_member
                .allowed_transitions
                .contains(&("leave".to_owned(), "join".to_owned()))
        );
        let circle_member = by_family[arkret_wire::CellFamilyId::CIRCLE_MEMBER_V1];
        assert!(
            !circle_member
                .allowed_transitions
                .contains(&("join".to_owned(), "join".to_owned()))
        );
        let keypackage = by_family[arkret_wire::CellFamilyId::MLS_KEYPACKAGE_V1];
        assert!(keypackage.states.contains(&"retired".to_owned()));
        assert!(!keypackage.states.contains(&"expired".to_owned()));
        assert!(
            keypackage
                .allowed_transitions
                .contains(&("published".to_owned(), "retired".to_owned()))
        );
        for family in [
            arkret_wire::CellFamilyId::REALM_HISTORY_ACCESS_V1,
            arkret_wire::CellFamilyId::CIRCLE_HISTORY_ACCESS_V1,
        ] {
            let history_access = by_family[family];
            assert!(history_access.runtime_transitions.iter().any(|(from, to)| {
                from.is_null() && to == &serde_json::Value::String("since_join".to_owned())
            }));
            assert!(history_access.runtime_transitions.iter().any(|(from, to)| {
                from.is_null()
                    && to
                        == &serde_json::Value::String("all_history_for_current_members".to_owned())
            }));
        }
    }

    fn private_candidate(
        value: serde_json::Value,
        revision: Option<u64>,
        expected_revision: Option<u64>,
        causal_order: Option<u64>,
        hlc: Option<&str>,
        device_id: Option<&str>,
    ) -> ActorPrivateCandidate {
        ActorPrivateCandidate {
            value,
            revision,
            expected_revision,
            causal_order,
            hlc: hlc.map(ToOwned::to_owned),
            device_id: device_id.map(ToOwned::to_owned),
        }
    }

    #[test]
    fn actor_private_registry_is_exact_and_isolated_from_shared_cells() {
        let private = build_actor_private_registry().unwrap();
        assert_eq!(private.event_writes().len(), 8);
        assert_eq!(private.families().len(), 5);
        let push_route_family = private.family("ak.private.device.push_route.v1").unwrap();
        assert_eq!(
            push_route_family.merge,
            ActorPrivateMergeKind::ServerRevisionCas
        );
        assert_eq!(
            push_route_family.tombstone,
            Some(ActorPrivateTombstoneMode::VersionedTombstone)
        );
        assert!(!push_route_family.bottom_reject);
        assert!(
            private
                .family("ak.component.device.push_route.v1")
                .is_none()
        );

        assert!(
            CellRef::new("ak:cell:ak.private.device.push_route.v1:fixture".to_owned()).is_err()
        );

        let payload = json!({
            "account_id": {
                "principal_id": "ak:did_core:webvh:z6mkfixture",
                "station_id": "ak:did_core:webvh:z6mkfixtureservice"
            },
            "device_id": "ak:device:01904100-0000-7000-8000-000000000001",
            "push_route": "fcm"
        });
        assert_eq!(
            private
                .derive_subject(
                    "ak.device.push_route",
                    &json!({
                        "kind": "account",
                        "account_id": {
                            "principal_id": "ak:did_core:webvh:z6mkfixture",
                            "station_id": "ak:did_core:webvh:z6mkfixtureservice"
                        }
                    }),
                    &payload
                )
                .unwrap(),
            composite_subject(&[
                r#"{"principal_id":"ak:did_core:webvh:z6mkfixture","station_id":"ak:did_core:webvh:z6mkfixtureservice"}"#,
                "ak:device:01904100-0000-7000-8000-000000000001",
                "fcm",
            ])
            .unwrap()
        );
        assert!(
            private
                .validate_private_event_shape(&json!({
                    "kind": "ak.device.push_route",
                    "payload": payload,
                    "seal_basis": {}
                }))
                .is_err()
        );
    }

    #[test]
    fn actor_private_merge_contracts_cover_account_data_push_route_and_cursor() {
        let private = build_actor_private_registry().unwrap();
        let account = private_candidate(json!({"content": "a"}), Some(7), None, None, None, None);
        let next = private_candidate(json!({"content": "b"}), Some(8), Some(7), None, None, None);
        assert!(matches!(
            private
                .apply("ak.private.account_data.v1", Some(&account), next.clone())
                .unwrap(),
            ActorPrivateMergeOutcome::Accepted(candidate) if candidate == next
        ));
        let stale = private_candidate(
            json!({"content": "stale"}),
            Some(8),
            Some(7),
            None,
            None,
            None,
        );
        assert_eq!(
            private
                .apply("ak.private.account_data.v1", Some(&next), stale)
                .unwrap(),
            ActorPrivateMergeOutcome::Conflict
        );

        let invalid_create =
            private_candidate(json!({"target": "invalid"}), None, None, None, None, None);
        assert_eq!(
            private
                .apply("ak.private.device.push_route.v1", None, invalid_create)
                .unwrap(),
            ActorPrivateMergeOutcome::Conflict
        );
        let route_a = private_candidate(json!({"target": "a"}), Some(1), Some(0), None, None, None);
        assert!(matches!(
            private
                .apply("ak.private.device.push_route.v1", None, route_a.clone())
                .unwrap(),
            ActorPrivateMergeOutcome::Accepted(candidate) if candidate == route_a
        ));
        let route_b = private_candidate(json!({"target": "b"}), Some(2), Some(1), None, None, None);
        assert!(matches!(
            private
                .apply("ak.private.device.push_route.v1", Some(&route_a), route_b.clone())
                .unwrap(),
            ActorPrivateMergeOutcome::Accepted(candidate) if candidate == route_b
        ));
        let sibling = private_candidate(
            json!({"target": "sibling"}),
            Some(2),
            Some(1),
            None,
            None,
            None,
        );
        assert_eq!(
            private
                .apply("ak.private.device.push_route.v1", Some(&route_b), sibling)
                .unwrap(),
            ActorPrivateMergeOutcome::Conflict
        );

        let cursor_a = private_candidate(
            json!({"event_id": "a"}),
            None,
            None,
            Some(5),
            Some("01970e589d21-0001-a13f9c2e"),
            Some("device-a"),
        );
        let cursor_b = private_candidate(
            json!({"event_id": "b"}),
            None,
            None,
            Some(5),
            Some("01970e589d21-0002-a13f9c2e"),
            Some("device-b"),
        );
        assert!(matches!(
            private
                .apply(
                    "ak.private.read_cursor.v1",
                    Some(&cursor_a),
                    cursor_b.clone()
                )
                .unwrap(),
            ActorPrivateMergeOutcome::Accepted(candidate) if candidate == cursor_b
        ));

        let proposed = private_candidate(json!("proposed"), Some(1), Some(0), None, None, None);
        assert!(matches!(
            private
                .apply("ak.private.agent.draft.v1", None, proposed.clone())
                .unwrap(),
            ActorPrivateMergeOutcome::Accepted(_)
        ));
        let approved = private_candidate(json!("approved"), Some(2), Some(1), None, None, None);
        assert!(matches!(
            private
                .apply("ak.private.agent.draft.v1", Some(&proposed), approved)
                .unwrap(),
            ActorPrivateMergeOutcome::Accepted(_)
        ));
        let skipped = private_candidate(json!("published"), Some(2), Some(1), None, None, None);
        assert_eq!(
            private
                .apply("ak.private.agent.draft.v1", Some(&proposed), skipped)
                .unwrap(),
            ActorPrivateMergeOutcome::Conflict
        );
    }

    #[test]
    fn applet_registration_uses_spec_cas_register_binding() {
        let registry = default_lattice_registry();
        let kind = registry
            .lookup(arkret_wire::CellFamilyId::APPLET_REGISTRATION_V1)
            .expect("Applet registration family must be registered");
        assert_eq!(kind.lattice(), SdkLatticeKind::CasRegister);
        assert_eq!(kind.bottom_policy(), BottomPolicy::Reject);
        assert_eq!(
            kind.subject_for_effect(&json!({"applet_id": "ak:applet:fixture"}))
                .unwrap()
                .as_deref(),
            Some("ak:applet:fixture")
        );
    }

    #[test]
    fn consent_grant_has_or_set_lattice_and_consent_id_subject() {
        let registry = default_lattice_registry();
        let kind = registry
            .lookup(arkret_wire::CellFamilyId::CONSENT_GRANT_V1)
            .unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrSet);
        assert_eq!(kind.bottom_policy(), BottomPolicy::Inert);
        let payload = json!({"consent_id": "cnt:01HXYZ"});
        let subject = kind.subject_for_effect(&payload).unwrap();
        assert_eq!(subject.as_deref(), Some("cnt:01HXYZ"));
    }

    #[test]
    fn moderation_state_has_or_set_lattice_and_target_ref_subject() {
        let registry = default_lattice_registry();
        let kind = registry
            .lookup(arkret_wire::CellFamilyId::MODERATION_STATE_V1)
            .expect("moderation state must be registered");
        assert_eq!(kind.lattice(), SdkLatticeKind::OrSet);
        assert_eq!(kind.bottom_policy(), BottomPolicy::Expose);
        assert_eq!(
            kind.subject_for_effect(&json!({"target_ref": "ak:event:target"}))
                .unwrap()
                .as_deref(),
            Some("ak:event:target")
        );
    }

    #[test]
    fn member_state_uses_fsm_lattice_with_actor_subject() {
        assert_eq!(
            MemberState::CELL_FAMILY,
            arkret_wire::CellFamilyId::MEMBER_STATE_V1
        );
        let registry = default_lattice_registry();
        let kind = registry
            .lookup(arkret_wire::CellFamilyId::MEMBER_STATE_V1)
            .unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::Fsm);
        let actor = account_actor("ak:did_core:web:station.example");
        let payload = json!({"member_id": actor});
        let subject = kind.subject_for_effect(&payload).unwrap();
        assert_eq!(
            subject,
            Some(composite_subject(&[actor_component(&actor)]).unwrap())
        );
    }

    #[test]
    fn actor_subject_adapters_separate_stations_and_reject_bare_principals() {
        use arkret_wire::CellFamilyId;
        let registry = default_lattice_registry();
        let first = account_actor("ak:did_core:web:first.example");
        let second = account_actor("ak:did_core:web:second.example");
        let call_id = "ak:call:fixture";
        let device_id = "ak:device:fixture";
        let circle_id = "ak:circle:fixture";
        let realm_id = "ak:realm:fixture";
        for family in [
            CellFamilyId::MEMBER_STATE_V1,
            CellFamilyId::CIRCLE_MEMBER_V1,
            CellFamilyId::MEMBER_IDENTITY_V1,
            CellFamilyId::KEY_BACKUP_ACTIVE_SERIES_V1,
            CellFamilyId::CALL_MUTE_OVERRIDE_V1,
        ] {
            let kind = registry.lookup(family).unwrap();
            let payload = |actor: &serde_json::Value| match family {
                CellFamilyId::MEMBER_STATE_V1 => json!({"member_id": actor}),
                CellFamilyId::CIRCLE_MEMBER_V1 => {
                    json!({"circle_id": circle_id, "member_id": actor})
                }
                CellFamilyId::MEMBER_IDENTITY_V1 => {
                    json!({"realm_id": realm_id, "member_id": actor, "segment": "profile"})
                }
                CellFamilyId::KEY_BACKUP_ACTIVE_SERIES_V1 => {
                    json!({"actor_id": actor, "backup_kind": "mls_history"})
                }
                CellFamilyId::CALL_MUTE_OVERRIDE_V1 => {
                    json!({"call_id": call_id, "mute_override": {"actor_id": actor, "device_id": device_id}})
                }
                _ => unreachable!(),
            };
            let actor = actor_component(&first);
            let components = match family {
                CellFamilyId::MEMBER_STATE_V1 => vec![actor.as_str()],
                CellFamilyId::CIRCLE_MEMBER_V1 => vec![circle_id, &actor],
                CellFamilyId::MEMBER_IDENTITY_V1 => vec![realm_id, &actor, "profile"],
                CellFamilyId::KEY_BACKUP_ACTIVE_SERIES_V1 => vec![&actor, "mls_history"],
                CellFamilyId::CALL_MUTE_OVERRIDE_V1 => vec![call_id, &actor, device_id],
                _ => unreachable!(),
            };
            let first_subject = kind.subject_for_effect(&payload(&first)).unwrap();
            assert_eq!(
                first_subject,
                Some(composite_subject(&components).unwrap()),
                "{family}"
            );
            assert_ne!(
                first_subject,
                kind.subject_for_effect(&payload(&second)).unwrap(),
                "{family}"
            );
            assert!(
                kind.subject_for_effect(&payload(&json!("ak:did_core:web:alice.example")))
                    .is_err(),
                "{family}"
            );
        }
    }

    #[test]
    fn realm_link_uses_tuple_subject_fsm_and_rejects_bottom() {
        let registry = default_lattice_registry();
        let kind = registry
            .lookup(arkret_wire::CellFamilyId::REALM_LINK_V1)
            .expect("Realm Link cell must be registered");
        assert_eq!(kind.lattice(), SdkLatticeKind::Fsm);
        assert_eq!(kind.bottom_policy(), BottomPolicy::Reject);
        let subject = kind
            .subject_for_effect(&json!({
                "target_realm_id": "ak:realm:Ab0jbIKlPZ-M3WbarZlCPLYtkCWggYwWZeRDlW-ShdQ9",
                "link_kind": "governed_by",
            }))
            .unwrap()
            .unwrap();
        assert_eq!(
            subject,
            composite_subject(&[
                "ak:realm:Ab0jbIKlPZ-M3WbarZlCPLYtkCWggYwWZeRDlW-ShdQ9",
                "governed_by",
            ])
            .unwrap()
        );

        let sdk_registry = build_sdk_cell_registry();
        let realm_id =
            RealmId::new("ak:realm:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934".to_owned())
                .unwrap();
        let cell = CellRef::new(format!("ak:cell:ak.component.realm.link.v1:{subject}")).unwrap();
        let binding = sdk_registry.resolve(&realm_id, &cell).unwrap();
        assert_eq!(binding.lattice.kind(), SdkLatticeKind::Fsm);
        assert_eq!(binding.bottom_mode, BottomMode::Reject);
    }

    #[test]
    fn realm_member_fsm_uses_leave_as_the_normative_initial_state() {
        let registry = build_sdk_cell_registry();
        let realm_id =
            RealmId::new("ak:realm:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934").unwrap();
        let cell =
            CellRef::new("ak:cell:ak.component.member.state.v1:did:web:bob.example".to_owned())
                .unwrap();
        let binding = registry.resolve(&realm_id, &cell).unwrap();
        let join = SealedOp::new(
            Hash::new(format!("sha256:{}", "11".repeat(32))).unwrap(),
            LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!("leave")),
                to: Some(json!("join")),
                reason: None,
                issuer_seq: None,
            },
        );

        assert_eq!(
            binding.lattice.join(&cell, &[join]),
            CellState::Value(json!("join"))
        );
    }

    #[test]
    fn invite_lifecycle_fsm_uses_null_to_pending_then_accepted() {
        let registry = default_lattice_registry();
        let kind = registry
            .lookup(arkret_wire::CellFamilyId::INVITE_LIFECYCLE_V1)
            .expect("invite lifecycle must be registered");
        assert_eq!(kind.lattice(), SdkLatticeKind::Fsm);
        assert_eq!(
            kind.subject_for_effect(&json!({
                "invite": {"id": "ak:invite:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu"}
            }))
            .unwrap()
            .as_deref(),
            Some("ak:invite:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu")
        );

        let sdk_registry = build_sdk_cell_registry();
        let realm_id =
            RealmId::new("ak:realm:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934").unwrap();
        let cell = CellRef::new(
            "ak:cell:ak.component.invite.lifecycle.v1:ak:invite:AUg3kgXpMvW4kMuGtTepFkRVooX03jTSKInIfDj4dDvu"
                .to_owned(),
        )
        .unwrap();
        let binding = sdk_registry.resolve(&realm_id, &cell).unwrap();
        let pending = SealedOp::new(
            Hash::new(format!("sha256:{}", "12".repeat(32))).unwrap(),
            LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!(null)),
                to: Some(json!("pending")),
                reason: None,
                issuer_seq: None,
            },
        );
        // The accept supersedes the pending write its own basis observed
        // (§9.3.1.7 item 4). Without that edge the two are concurrent writes
        // with different `to` and the cell reads `⊥` — which is the right answer
        // for two writers who never saw each other, and the reason a chain has
        // to say it is a chain.
        let accepted = SealedOp::superseding(
            Hash::new(format!("sha256:{}", "13".repeat(32))).unwrap(),
            LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!("pending")),
                to: Some(json!("accepted")),
                reason: None,
                issuer_seq: None,
            },
            vec![pending.move_id.clone()],
        );
        assert_eq!(
            binding.lattice.join(&cell, &[pending, accepted]),
            CellState::Value(json!("accepted"))
        );
    }

    #[test]
    fn fsm_initial_states_are_explicit_null_transitions() {
        let registry = build_sdk_cell_registry();
        let realm_id =
            RealmId::new("ak:realm:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934".to_owned())
                .unwrap();
        for (family, initial) in [
            // The lifecycle FSM lives on the state cell; `audit.binding.v1`
            // is the immutable config cas_register beside it.
            (arkret_wire::CellFamilyId::AUDIT_BINDING_STATE_V1, "active"),
            (arkret_wire::CellFamilyId::AUDIT_SESSION_V1, "request"),
            (arkret_wire::CellFamilyId::REALM_LINK_V1, "active"),
        ] {
            let cell = CellRef::new(format!("ak:cell:{family}:initial")).unwrap();
            let binding = registry.resolve(&realm_id, &cell).unwrap();
            let op = LatticeOp {
                op_type: LatticeOpType::Transition,
                tag: None,
                value: None,
                from: Some(json!(null)),
                to: Some(json!(initial)),
                reason: None,
                issuer_seq: None,
            };
            binding.lattice.validate_op(&op).unwrap_or_else(|error| {
                panic!("{family} rejects initial state {initial}: {error}")
            });
        }
    }

    #[test]
    fn agent_status_starts_uninitialized_and_accepts_provision_then_pause() {
        let registry = build_sdk_cell_registry();
        let realm_id =
            RealmId::new("ak:realm:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934".to_owned())
                .unwrap();
        let cell = CellRef::new("ak:cell:ak.component.agent.status.v1:agent".to_owned()).unwrap();
        let binding = registry.resolve(&realm_id, &cell).unwrap();
        // Spec zh/models/realm-and-space.md section 2.5 step 7: the reducer
        // initial state is the registered internal `uninitialized`, which the
        // Agent genesis branch transitions to `active`. It is not a
        // public lifecycle value, so nothing may treat it as active.
        assert_eq!(
            binding.lattice.initial_state(),
            Some(json!("uninitialized"))
        );

        let provision = LatticeOp {
            op_type: LatticeOpType::Transition,
            tag: None,
            value: None,
            from: Some(json!("uninitialized")),
            to: Some(json!("active")),
            reason: None,
            issuer_seq: None,
        };
        binding.lattice.validate_op(&provision).unwrap();

        let op = LatticeOp {
            op_type: LatticeOpType::Transition,
            tag: None,
            value: None,
            from: Some(json!("active")),
            to: Some(json!("paused")),
            reason: None,
            issuer_seq: None,
        };
        binding.lattice.validate_op(&op).unwrap();
    }

    #[test]
    fn membership_self_transition_is_rejected_for_realm_and_circle() {
        let registry = build_sdk_cell_registry();
        let realm_id =
            RealmId::new("ak:realm:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934".to_owned())
                .unwrap();
        let circle_cell =
            CellRef::new("ak:cell:ak.component.circle.member.v1:membership".to_owned()).unwrap();
        let op = LatticeOp {
            op_type: LatticeOpType::Transition,
            tag: None,
            value: None,
            from: Some(json!("join")),
            to: Some(json!("join")),
            reason: None,
            issuer_seq: None,
        };
        let circle = registry.resolve(&realm_id, &circle_cell).unwrap();
        assert!(circle.lattice.validate_op(&op).is_err());

        let realm_cell =
            CellRef::new("ak:cell:ak.component.member.state.v1:membership".to_owned()).unwrap();
        let realm = registry.resolve(&realm_id, &realm_cell).unwrap();
        assert!(realm.lattice.validate_op(&op).is_err());
    }

    #[test]
    fn last_resort_keypackage_preservation_does_not_invent_a_self_transition() {
        let registry = build_sdk_cell_registry();
        let realm_id =
            RealmId::new("ak:realm:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934".to_owned())
                .unwrap();
        let cell =
            CellRef::new("ak:cell:ak.component.mls.keypackage.v1:last-resort".to_owned()).unwrap();
        let binding = registry.resolve(&realm_id, &cell).unwrap();
        let op = LatticeOp {
            op_type: LatticeOpType::Transition,
            tag: None,
            value: None,
            from: Some(json!("published")),
            to: Some(json!("published")),
            reason: None,
            issuer_seq: None,
        };
        assert!(binding.lattice.validate_op(&op).is_err());
    }

    #[test]
    fn agent_provision_control_families_are_registered() {
        let registry = default_lattice_registry();
        let accountability = registry
            .lookup(arkret_wire::CellFamilyId::IDENTITY_ACCOUNTABILITY_V1)
            .expect("identity accountability must be registered");
        assert_eq!(accountability.lattice(), SdkLatticeKind::CasRegister);
        assert_eq!(accountability.bottom_policy(), BottomPolicy::Reject);

        let selector = registry
            .lookup(arkret_wire::CellFamilyId::AGENT_SELECTOR_CLAIM_V1)
            .expect("agent selector claim must be registered");
        assert_eq!(selector.lattice(), SdkLatticeKind::MvRegister);
        assert_eq!(selector.bottom_policy(), BottomPolicy::Expose);
        let subject = selector
            .subject_for_effect(&json!({
                "controller_subject_id": "did:web:alice.example",
                "agent_slug": "research"
            }))
            .unwrap()
            .unwrap();
        assert_eq!(
            subject,
            composite_subject(&["did:web:alice.example", "research"]).unwrap()
        );

        let sdk_registry = build_sdk_cell_registry();
        let realm_id =
            RealmId::new("ak:realm:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934").unwrap();
        for family in [
            arkret_wire::CellFamilyId::IDENTITY_ACCOUNTABILITY_V1,
            arkret_wire::CellFamilyId::AGENT_SELECTOR_CLAIM_V1,
        ] {
            let cell = CellRef::new(format!("ak:cell:{family}:fixture")).unwrap();
            sdk_registry
                .resolve(&realm_id, &cell)
                .unwrap_or_else(|error| panic!("{family} missing from SDK registry: {error}"));
        }
    }

    #[test]
    fn call_state_and_summary_use_call_id_subjects() {
        let registry = default_lattice_registry();
        let state = registry
            .lookup(arkret_wire::CellFamilyId::CALL_STATE_V1)
            .unwrap();
        assert_eq!(state.lattice(), SdkLatticeKind::Fsm);
        assert_eq!(
            state
                .subject_for_effect(&json!({"call_id": "ak:call:01"}))
                .unwrap()
                .as_deref(),
            Some("ak:call:01")
        );
        let summary = registry
            .lookup(arkret_wire::CellFamilyId::CALL_SUMMARY_V1)
            .unwrap();
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
    fn orthogonal_call_cells_have_canonical_lattices_subjects_and_bottom_modes() {
        let registry = default_lattice_registry();
        let call_id = "ak:call:AU2FuZ5Cmuwsb0J0xuJwH47SCEL34D7oJWb4JivTH934";
        let recording_id = "ak:recording:01904100-0000-7000-8000-000000000022";
        let expected_capture_subject = composite_subject(&[call_id, recording_id]).unwrap();

        for family in [
            arkret_wire::CellFamilyId::CALL_FOCUS_V1,
            arkret_wire::CellFamilyId::CALL_MODERATION_V1,
            arkret_wire::CellFamilyId::CALL_ROSTER_V1,
        ] {
            let kind = registry.lookup(family).unwrap();
            assert_eq!(
                kind.subject_for_effect(&json!({"call_id": call_id}))
                    .unwrap()
                    .as_deref(),
                Some(call_id)
            );
        }
        assert_eq!(
            registry
                .lookup(arkret_wire::CellFamilyId::CALL_FOCUS_V1)
                .unwrap()
                .lattice(),
            SdkLatticeKind::CasRegister
        );
        for family in [
            arkret_wire::CellFamilyId::CALL_MODERATION_V1,
            arkret_wire::CellFamilyId::CALL_ROSTER_V1,
        ] {
            let kind = registry.lookup(family).unwrap();
            assert_eq!(kind.lattice(), SdkLatticeKind::OrSet);
            assert_eq!(kind.bottom_policy(), BottomPolicy::Inert);
        }

        let recording = registry
            .lookup(arkret_wire::CellFamilyId::CALL_RECORDING_V1)
            .unwrap();
        assert_eq!(recording.lattice(), SdkLatticeKind::Fsm);
        assert_eq!(
            recording
                .subject_for_effect(&json!({
                    "call_id": call_id,
                    "recording_id": recording_id,
                }))
                .unwrap()
                .as_deref(),
            Some(expected_capture_subject.as_str())
        );
        assert_eq!(
            recording
                .subject_for_effect(&json!({
                    "call_id": call_id,
                    "recording_transition": {"recording_id": recording_id},
                }))
                .unwrap()
                .as_deref(),
            Some(expected_capture_subject.as_str())
        );

        let transcript = registry
            .lookup(arkret_wire::CellFamilyId::CALL_TRANSCRIPT_V1)
            .unwrap();
        assert_eq!(transcript.lattice(), SdkLatticeKind::Fsm);
        assert_eq!(
            transcript
                .subject_for_effect(&json!({
                    "call_id": call_id,
                    "transcript_transition": {"recording_id": recording_id},
                }))
                .unwrap()
                .as_deref(),
            Some(expected_capture_subject.as_str())
        );

        for family in [
            arkret_wire::CellFamilyId::CALL_RECORDING_RESULT_V1,
            arkret_wire::CellFamilyId::CALL_TRANSCRIPT_RESULT_V1,
        ] {
            assert_eq!(
                registry.lookup(family).unwrap().lattice(),
                SdkLatticeKind::CasRegister
            );
        }
        let mute = registry
            .lookup(arkret_wire::CellFamilyId::CALL_MUTE_OVERRIDE_V1)
            .unwrap();
        assert_eq!(mute.lattice(), SdkLatticeKind::CasRegister);
        let mute_actor = account_actor("ak:did_core:web:station.example");
        let expected_mute_subject = composite_subject(&[
            call_id,
            &actor_component(&mute_actor),
            "ak:device:01904100-0000-7000-8000-000000000044",
        ])
        .unwrap();
        assert_eq!(
            mute.subject_for_effect(&json!({
                "call_id": call_id,
                "mute_override": {
                    "actor_id": mute_actor,
                    "device_id": "ak:device:01904100-0000-7000-8000-000000000044"
                }
            }))
            .unwrap()
            .as_deref(),
            Some(expected_mute_subject.as_str())
        );

        let sdk_registry = build_sdk_cell_registry();
        let realm_id =
            RealmId::new("ak:realm:ARO6sshXyY_8aIrsd0F5-zoAcfxTRnG5n7zA6tFwGX2l").unwrap();
        for family in [
            arkret_wire::CellFamilyId::CALL_MODERATION_V1,
            arkret_wire::CellFamilyId::CALL_ROSTER_V1,
        ] {
            let cell = CellRef::new(format!("ak:cell:{family}:{call_id}")).unwrap();
            assert_eq!(
                sdk_registry.resolve(&realm_id, &cell).unwrap().bottom_mode,
                BottomMode::Inert
            );
        }
    }

    #[test]
    fn inert_ordered_create_cells_are_registered_as_inert() {
        let registry = default_lattice_registry();
        for family in [
            arkret_wire::CellFamilyId::CIRCLE_CREATE_V1,
            arkret_wire::CellFamilyId::SIDECAR_CREATE_V1,
            arkret_wire::CellFamilyId::REALM_CREATE_V1,
        ] {
            let kind = registry.lookup(family).unwrap();
            assert_eq!(kind.lattice(), SdkLatticeKind::OrderedLog);
            assert_eq!(kind.bottom_policy(), BottomPolicy::Inert);
        }
    }

    #[test]
    fn realm_policy_is_singleton_cas_register() {
        let registry = default_lattice_registry();
        let kind = registry
            .lookup(arkret_wire::CellFamilyId::REALM_POLICY_V1)
            .unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::CasRegister);
        let subject = kind.subject_for_effect(&json!({})).unwrap();
        assert!(subject.is_none());
    }

    #[test]
    fn policy_definition_is_per_policy_cas_register() {
        let registry = default_lattice_registry();
        let kind = registry
            .lookup(arkret_wire::CellFamilyId::POLICY_DEFINITION_V1)
            .unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::CasRegister);
        assert_eq!(kind.bottom_policy(), BottomPolicy::Reject);
        assert_eq!(
            kind.subject_for_effect(&json!({
                "policy_id": "ak:policy:01904100-0000-7000-8000-000000000001"
            }))
            .unwrap()
            .as_deref(),
            Some("ak:policy:01904100-0000-7000-8000-000000000001")
        );
    }

    #[test]
    fn notary_cell_is_singleton_cas_register_and_required() {
        let registry = default_lattice_registry();
        let kind = registry
            .lookup(arkret_wire::CellFamilyId::NOTARY_V1)
            .unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::CasRegister);
        assert_eq!(kind.bottom_policy(), BottomPolicy::Reject);
        let comp = kind.component();
        assert_eq!(comp.criticality, Criticality::Required);
        assert_eq!(comp.component_type, arkret_wire::CellFamilyId::NOTARY_V1);
    }

    #[test]
    fn mv_register_families_have_expose_bottom() {
        let registry = default_lattice_registry();
        for family in [
            arkret_wire::CellFamilyId::PROFILE_CREATE_V1,
            arkret_wire::CellFamilyId::VIEW_V1,
            arkret_wire::CellFamilyId::MIMI_ROOM_BINDING_V1,
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
    fn ordered_log_realm_create_is_registered() {
        let registry = default_lattice_registry();
        let kind = registry
            .lookup(arkret_wire::CellFamilyId::REALM_CREATE_V1)
            .unwrap();
        assert_eq!(kind.lattice(), SdkLatticeKind::OrderedLog);
    }

    #[test]
    fn missing_subject_field_surfaces_typed_error() {
        let registry = default_lattice_registry();
        let kind = registry
            .lookup(arkret_wire::CellFamilyId::STRAND_POSITION_V1)
            .unwrap();
        let err = kind
            .subject_for_effect(&json!({"unrelated": "x"}))
            .unwrap_err();
        match err {
            LatticeKindError::MissingSubjectField { cell_family, field } => {
                assert_eq!(cell_family, arkret_wire::CellFamilyId::STRAND_POSITION_V1);
                assert_eq!(field, "strand_id");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn agent_key_subject_uses_canonical_composite_encoding() {
        let registry = default_lattice_registry();
        let kind = registry
            .lookup(arkret_wire::CellFamilyId::AGENT_KEY_V1)
            .unwrap();
        let agent_id = "ak:did_core:webvh:z6mkfixture";
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
            .lookups_for_event_kind("ak.consent.grant")
            .map(|kind| kind.cell_family())
            .collect::<Vec<_>>();
        assert_eq!(grant, vec![arkret_wire::CellFamilyId::CONSENT_GRANT_V1]);
        let revoke = registry
            .lookups_for_event_kind("ak.consent.revoke")
            .map(|kind| kind.cell_family())
            .collect::<Vec<_>>();
        assert_eq!(revoke, vec![arkret_wire::CellFamilyId::CONSENT_GRANT_V1]);
    }

    #[test]
    fn event_kind_index_preserves_multi_cell_writes() {
        let registry = default_lattice_registry();
        let families = registry
            .lookups_for_event_kind(arkret_wire::event_kind_str::AUDIT_APPLET_BINDING_CREATE)
            .map(|kind| kind.cell_family())
            .collect::<Vec<_>>();
        assert_eq!(
            families,
            vec![
                arkret_wire::CellFamilyId::AUDIT_BINDING_V1,
                arkret_wire::CellFamilyId::AUDIT_BINDING_STATE_V1,
            ]
        );
    }

    #[test]
    fn lattice_kind_error_display_is_stable() {
        let err = LatticeKindError::MissingSubjectField {
            cell_family: arkret_wire::CellFamilyId::STRAND_POSITION_V1,
            field: "strand_id",
        };
        let msg = format!("{err}");
        assert!(msg.contains(arkret_wire::CellFamilyId::STRAND_POSITION_V1));
        assert!(msg.contains("strand_id"));
    }
}
