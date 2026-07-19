//! Applet wire objects: registration, package, install aggregate
//! operations, namespace claims/matching, bridge-error events and
//! portal / bridge-mapping helpers (spec `applet-schema.md` +
//! `applet-integration.md`).

mod bridge_error;
mod portal;

pub use arkret_core::applet::*;
pub use bridge_error::*;
pub use portal::*;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use arkret_core::{
        AppletInstallAppletId, AppletInstallPlan, E2eeEffect, EffectiveScope, WidgetEffect,
    };
    use chrono::{DateTime, Duration, Utc};
    use serde_json::{Value, json};

    use super::*;
    use crate::models::AppletTransactionOutcome;
    use crate::{ActorKind, ActorProfileId, AppletId, Did, Hlc, PayloadProof, Proof, RealmId};

    fn did(name: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{name}.example")).unwrap()
    }

    fn ghost_test_realm() -> RealmId {
        RealmId::new("ak:realm:01904100-0000-7000-8000-9b64700c6ee8").unwrap()
    }

    fn profile_id() -> ActorProfileId {
        ActorProfileId::new("ak:actor_profile:01904100-0000-7000-8000-aaaaaaaaaaaa").unwrap()
    }

    fn applet_id() -> AppletId {
        AppletId::new("ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap()
    }

    fn ghost_test_hlc() -> Hlc {
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()
    }

    fn production_proof(issuer: &Did, now: DateTime<Utc>) -> PayloadProof {
        PayloadProof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: format!("{issuer}#key-1"),
            payload_digest: crate::Hash::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            created_at: now,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "eyJhbGciOiJFZERTQSJ9..c2ln".to_owned(),
        }
    }

    #[test]
    fn ghost_actor_profile_request_emits_schema_legal_shape() {
        let owner = did("owner");
        let request = GhostActorProfileRequest::new(
            profile_id(),
            did("ghost"),
            "Alice on Slack",
            applet_id(),
        )
        .with_realm_id(ghost_test_realm())
        .with_accountable_principal_ids(vec![owner.clone()])
        .with_external_ref(BTreeMap::from([
            ("protocol".to_owned(), json!("slack")),
            ("user_id".to_owned(), json!("U123")),
        ]));

        let profile = request.to_actor_profile().unwrap();
        assert_eq!(profile.actor_kind, ActorKind::Integration);
        assert_eq!(profile.accountable_principal_ids, vec![owner]);
        assert_eq!(
            profile.profile_fields["managed_by_applet"],
            "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb"
        );
        assert_eq!(profile.profile_fields["external_ref"]["user_id"], "U123");

        let wire = serde_json::to_value(&profile).unwrap();
        assert!(wire.get("accountability").is_none());
        assert!(wire.get("managed_by_applet").is_none());
        assert_eq!(
            wire["profile_fields"]["managed_by_applet"],
            profile.profile_fields["managed_by_applet"]
        );
    }

    #[test]
    fn ghost_actor_profile_event_carries_delegated_authorization_fields() {
        let request = GhostActorProfileRequest::new(
            profile_id(),
            did("ghost"),
            "Alice on Slack",
            applet_id(),
        )
        .with_accountable_principal_ids(vec![did("owner")]);
        let authorization = AppletDelegatedEventAuthorization::new(
            did("bridge"),
            "ak:grant:01904100-0000-7000-8000-cccccccccccc",
            applet_id(),
        );

        let event = request
            .profile_create_event(
                ghost_test_realm(),
                1,
                ghost_test_hlc(),
                Some(&authorization),
            )
            .unwrap();
        assert_eq!(event.kind, "ak.profile.create");
        assert_eq!(event.executed_by.as_ref().unwrap(), &did("bridge"));
        assert_eq!(
            event.authorization_ref.as_deref(),
            Some("ak:grant:01904100-0000-7000-8000-cccccccccccc")
        );
        assert_eq!(
            event.payload["object"]["profile_fields"]["managed_by_applet"],
            "ak:applet:01904100-0000-7000-8000-bbbbbbbbbbbb"
        );
    }

    #[test]
    fn accountability_grant_validates_profile_binding_and_builds_event() {
        let now = Utc::now();
        let owner = did("owner");
        let subject = did("ghost");
        let profile = GhostActorProfileRequest::new(
            profile_id(),
            subject.clone(),
            "Alice on Slack",
            applet_id(),
        )
        .with_accountable_principal_ids(vec![owner.clone()])
        .to_actor_profile()
        .unwrap();
        let grant = AccountabilityGrantPayload::new(
            owner.clone(),
            subject,
            AccountabilityScope::Single(AccountabilityScopeKind::ContractedService),
            now - Duration::minutes(1),
            Some(now + Duration::minutes(10)),
            production_proof(&owner, now),
        );

        grant.validate_for_profile(&profile, now).unwrap();
        let event = grant
            .to_event(ghost_test_realm(), 2, ghost_test_hlc(), None)
            .unwrap();
        assert_eq!(
            event.kind,
            arkret_core::events::EventKind::IDENTITY_ACCOUNTABILITY_GRANT
        );
        assert_eq!(event.actor_id, owner);
        assert_eq!(event.payload["grant_status"], "active");
        assert_eq!(event.payload["accountability_scope"], "contracted_service");
    }

    #[test]
    fn applet_portal_manages_space_bridge_and_ghost_actor() {
        let mut manager = AppletPortalManager::new();
        let portal = manager.create_portal(ghost_test_realm());
        manager.install_applet(&portal.portal_id, "todo").unwrap();
        manager.enable_bridge(&portal.portal_id).unwrap();
        manager
            .set_ghost_actor(&portal.portal_id, did("ghost"))
            .unwrap();

        let portal = manager.portal(&portal.portal_id).unwrap();
        assert_eq!(portal.mode, PortalMode::Bridge);
        assert!(portal.applets.contains("todo"));
        assert!(portal.ghost_actor.is_some());
    }

    #[test]
    fn applet_wire_namespaces_detect_exclusive_conflicts() {
        let a = AppletWireNamespaces {
            actors: vec![AppletNamespaceEntry::exclusive(
                "did:webvh:z6mkfixture:slack-bridge.example:ghost:*",
            )],
            ..Default::default()
        };
        // Exclusive vs overlapping concrete claim in the same domain conflicts.
        let b = AppletWireNamespaces {
            actors: vec![AppletNamespaceEntry::exclusive(
                "did:webvh:z6mkfixture:slack-bridge.example:ghost:u1",
            )],
            ..Default::default()
        };
        let conflicts = a.conflicts_with(&b);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].domain, Actors);

        // Two non-exclusive claims may coexist.
        let c = AppletWireNamespaces {
            actors: vec![AppletNamespaceEntry::shared(
                "did:webvh:z6mkfixture:slack-bridge.example:ghost:*",
            )],
            ..Default::default()
        };
        let d = AppletWireNamespaces {
            actors: vec![AppletNamespaceEntry::shared(
                "did:webvh:z6mkfixture:slack-bridge.example:ghost:u1",
            )],
            ..Default::default()
        };
        assert!(c.conflicts_with(&d).is_empty());

        // Claims in different domain buckets never conflict.
        let realm_only = AppletWireNamespaces {
            realms: vec![AppletNamespaceEntry::exclusive("slack:team:*")],
            ..Default::default()
        };
        assert!(a.conflicts_with(&realm_only).is_empty());
    }

    #[test]
    fn applet_service_transactions_are_idempotent() {
        // Deduplication is owned by the shared `IdempotencyWindow` (the same
        // implementation `arkret-server` wires into the router) keyed by the
        // spec 5-tuple identity — no test-local reimplementation.
        use std::time::Duration as StdDuration;

        use crate::{
            IdempotencyClaim, IdempotencyDirection, IdempotencyIdentity, IdempotencyWindow,
        };

        let intent = AppletServiceIntent::new(did("svc"), did("ghost"));
        let transaction = intent.transaction("k1", Vec::new());
        let response = AppletTransactionOutcome {
            ok: true,
            rejected: Vec::new(),
            retry_after_ms: None,
        };
        let window: IdempotencyWindow<AppletTransactionOutcome> =
            IdempotencyWindow::new(StdDuration::from_secs(5 * 60));
        let identity = IdempotencyIdentity::applet_transaction(
            IdempotencyDirection::NodeToApplet,
            transaction.request.source_service_id.to_string(),
            "did:webvh:QmDst:applet.example",
            transaction.idempotency_key.clone(),
        );
        let digest =
            crate::Hash::new(crate::canonical::canonical_sha256(&transaction.request).unwrap())
                .unwrap();

        assert!(matches!(
            window.claim(&identity, &digest, "anchor-a"),
            IdempotencyClaim::Fresh
        ));
        assert!(window.complete(&identity, response.clone()));
        match window.claim(&identity, &digest, "anchor-a") {
            IdempotencyClaim::Duplicate { outcome, .. } => assert_eq!(outcome, response),
            other => panic!("expected Duplicate, got {other:?}"),
        }

        let mut changed = transaction.clone();
        changed.request.source_service_id = did("svc-other");
        let changed_digest =
            crate::Hash::new(crate::canonical::canonical_sha256(&changed.request).unwrap())
                .unwrap();
        assert!(matches!(
            window.claim(&identity, &changed_digest, "anchor-a"),
            IdempotencyClaim::DuplicateConflict { .. }
        ));
    }

    use AppletNamespaceDomain::{Actors, Realms};

    #[test]
    fn namespace_pattern_single_star_matches_one_segment() {
        assert!(namespace_pattern_matches(
            Actors,
            "did:webvh:z6mkfixture:slack-bridge.example:ghost:*",
            "did:webvh:z6mkfixture:slack-bridge.example:ghost:u123"
        ));
    }

    #[test]
    fn namespace_pattern_single_star_rejects_different_host() {
        assert!(!namespace_pattern_matches(
            Actors,
            "did:webvh:z6mkfixture:slack-bridge.example:ghost:*",
            "did:webvh:z6mkfixture:other.example:ghost:u123"
        ));
    }

    #[test]
    fn namespace_pattern_single_star_rejects_missing_prefix() {
        assert!(!namespace_pattern_matches(
            Actors,
            "did:webvh:z6mkfixture:slack-bridge.example:ghost:*",
            "did:webvh:z6mkfixture:slack-bridge.example:bot"
        ));
    }

    #[test]
    fn namespace_pattern_actor_ignores_fragment() {
        // `#fragment` does not participate in actor-domain matching.
        assert!(namespace_pattern_matches(
            Actors,
            "did:webvh:z6mkfixture:slack-bridge.example:ghost:*",
            "did:webvh:z6mkfixture:slack-bridge.example:ghost:u123#key-1"
        ));
    }

    #[test]
    fn namespace_pattern_multiple_single_stars_match_segments() {
        assert!(namespace_pattern_matches(
            Realms,
            "slack:team:*:channel:*",
            "slack:team:T123:channel:C456"
        ));
    }

    #[test]
    fn namespace_pattern_single_star_does_not_cross_separator() {
        assert!(!namespace_pattern_matches(
            Realms,
            "slack:team:*:channel:*",
            "slack:team:T123:channel:C456:thread:1"
        ));
    }

    #[test]
    fn namespace_pattern_double_star_crosses_slash_only() {
        // `**` matches one or more `/`-separated segments...
        assert!(namespace_pattern_matches(
            Realms,
            "slack.acme.example/**",
            "slack.acme.example/team/a/b"
        ));
        // ...but never crosses `:`.
        assert!(!namespace_pattern_matches(
            Realms,
            "slack:team:**",
            "slack:team:T123:channel:C456"
        ));
        // ...and never matches an empty segment.
        assert!(!namespace_pattern_matches(
            Realms,
            "slack.acme.example/**",
            "slack.acme.example/"
        ));
    }

    #[test]
    fn namespace_pattern_escaped_star_matches_literal() {
        assert!(namespace_pattern_matches(
            Realms,
            "literal\\*pattern",
            "literal*pattern"
        ));
    }

    #[test]
    fn namespace_pattern_escaped_star_rejects_non_star() {
        assert!(!namespace_pattern_matches(
            Realms,
            "literal\\*pattern",
            "literalXpattern"
        ));
    }

    #[test]
    fn namespace_pattern_empty_pattern_rejects_non_empty_candidate() {
        assert!(!namespace_pattern_matches(
            Actors,
            "",
            "did:webvh:z6mkfixture:anything.example"
        ));
    }

    // ─── S-4 (savfox SDK gap) tests ──────────────────────────────────

    fn sample_epoch() -> crate::Hash {
        crate::Hash::new(format!("sha256:{}", "bb".repeat(32))).unwrap()
    }

    fn sample_epoch_evidence(service_id: &Did) -> AppletRegistrationEpochEvidence {
        let document = crate::identity::DidDocument::new(
            service_id.clone(),
            format!("{service_id}#key-1"),
            "z6MkrJVnaZkeF7EsnJQ9xQY4bqG9tbeFqTzL7uTVs11FwUjT",
        );
        AppletRegistrationEpochEvidence::from_did_document(
            &document,
            AppletDidMethodVersionEvidence::versioned(
                "did:webvh",
                Some("QmSdkAppletTestVersion1".to_owned()),
                None,
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn sample_wire_registration() -> WireAppletRegistration {
        WireAppletRegistration::new(
            "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
            did("slackbridge"),
            did("alice"),
            "https://applet.example/cx",
            did("bot"),
            vec!["ak.applet.v1".to_owned()],
            AppletWireNamespaces {
                actors: vec![AppletNamespaceEntry::exclusive(
                    "did:webvh:z6mkfixture:slackbridge.example#ghost-*",
                )],
                realms: vec![],
                handles: vec![],
            },
            sample_epoch(),
        )
    }

    #[test]
    fn wire_registration_round_trips_through_json() {
        let reg = sample_wire_registration();
        let value = serde_json::to_value(&reg).unwrap();
        assert!(value.get("kind").is_none());
        assert_eq!(value["applet_id"], reg.applet_id);
        assert_eq!(value["service_id"], reg.service_id.as_str());
        assert_eq!(value["controller_id"], reg.controller_id.as_str());
        assert_eq!(value["base_url"], reg.base_url);
        assert_eq!(value["bot_actor_id"], reg.bot_actor_id.as_str());
        let back: WireAppletRegistration = serde_json::from_value(value).unwrap();
        assert_eq!(back.applet_id, reg.applet_id);
        assert_eq!(back.namespaces.actors, reg.namespaces.actors);
    }

    #[test]
    fn wire_registration_payload_digest_is_stable_and_excludes_proof() {
        let reg = sample_wire_registration();
        let digest_before = reg.payload_digest().unwrap();

        let mut with_proof = reg;
        with_proof.proof = Some(Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:alice.example#key-1".to_owned(),
            event_digest: digest_before.clone(),
            created_at: Utc::now(),
            domain: None,
            audience: None,
            jws: "header..sig".to_owned(),
        });
        let digest_after = with_proof.payload_digest().unwrap();
        assert_eq!(
            digest_before, digest_after,
            "payload_digest MUST exclude `proof` so re-signing is idempotent"
        );
    }

    // ─── S-11 (savfox SDK gap) tests ─────────────────────────────────

    fn realm() -> RealmId {
        RealmId::new("ak:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap()
    }

    fn hlc() -> Hlc {
        Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()
    }

    #[test]
    fn applet_bridge_error_builder_emits_canonical_kind_and_payload() {
        let event = AppletBridgeErrorBuilder::new(
            realm(),
            "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
            did("bot"),
            "ak:event:01904100-0000-7000-8000-deadbeefdead",
            AppletBridgeErrorClass::ExternalNetwork,
            "external_rate_limited",
            true,
            AppletBridgeErrorVisibility::RealmAdmins,
        )
        .with_message("external network rejected the message")
        .with_external_ref(serde_json::json!({"slack_response_code": 429}))
        .with_retry_after_ms(1000)
        .build(1, hlc())
        .unwrap();
        assert_eq!(event.kind, "ak.applet.bridge_error");
        assert_eq!(event.payload["realm_id"], realm().as_str());
        assert_eq!(
            event.payload["failed_transaction_ref"],
            "ak:event:01904100-0000-7000-8000-deadbeefdead"
        );
        assert_eq!(event.payload["error_class"], "external_network");
        assert_eq!(event.payload["error_code"], "external_rate_limited");
        assert_eq!(event.payload["retriable"], true);
        assert_eq!(event.payload["visibility_scope"], "realm_admins");
        assert_eq!(
            event.payload["message"],
            "external network rejected the message"
        );
        assert_eq!(event.payload["retry_after_ms"], 1000);
        assert_eq!(
            event.payload["applet_id"],
            "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa"
        );
        assert_eq!(event.payload["external_ref"]["slack_response_code"], 429);
    }

    #[test]
    fn wire_registration_serializes_registration_epoch() {
        let reg = sample_wire_registration();
        let value = serde_json::to_value(&reg).unwrap();
        assert_eq!(value["registration_epoch"], reg.registration_epoch.as_str());
        // namespace entries are object-form `{ exclusive, pattern }`.
        assert_eq!(value["namespaces"]["actors"][0]["exclusive"], true);
        assert_eq!(
            value["namespaces"]["actors"][0]["pattern"],
            "did:webvh:z6mkfixture:slackbridge.example#ghost-*"
        );
    }

    #[test]
    fn applet_package_derives_registration_and_round_trips() {
        let mut package = AppletPackage::new(
            "applet_pkg_todo",
            "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
            did("slackbridge"),
            did("alice"),
            "https://applet.example/cx",
            did("bot"),
            vec!["slack".to_owned()],
            AppletWireNamespaces {
                actors: vec![AppletNamespaceEntry::exclusive(
                    "did:webvh:z6mkfixture:slackbridge.example:ghost:*",
                )],
                realms: vec![],
                handles: vec![],
            },
        );
        package.requested_scopes = vec!["ak.message.create".to_owned()];
        package.endpoint_policy.endpoints.push(AppletEndpointEntry {
            method: AppletEndpointMethod::Post,
            path: "/_arkret/edge/applet/transactions".to_owned(),
            auth: Some(AppletEndpointAuth::WebhookSignature),
            description: None,
            extra: Default::default(),
        });
        package.webhook_auth = WebhookAuth::http_message_signature(
            format!("{}#key-1", package.service_id),
            vec![WebhookSignatureAlg::EdDsa],
        );
        package
            .seal_registration_epoch(sample_epoch_evidence(&package.service_id))
            .unwrap();

        // Unsealed / unsigned package fails validation and derivation.
        assert!(package.validate().is_err());
        package.seal().unwrap();
        package.proof = Some(Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:webvh:z6mkfixture:alice.example#key-1".to_owned(),
            event_digest: package.package_digest.clone().unwrap(),
            created_at: Utc::now(),
            domain: None,
            audience: None,
            jws: "header..sig".to_owned(),
        });
        package.validate().unwrap();

        let mut stale_epoch = package.clone();
        stale_epoch.base_url = "https://other.example/cx".to_owned();
        assert!(stale_epoch.validate().is_err());

        let reg = package.to_registration().unwrap();
        assert_eq!(reg.applet_id, package.applet_id);
        assert_eq!(reg.registration_epoch, package.registration_epoch);
        assert_eq!(reg.requested_scopes, package.requested_scopes);
        assert_eq!(reg.namespaces, package.namespaces);
        assert!(reg.manifest.is_some());
        assert!(
            reg.manifest
                .as_ref()
                .unwrap()
                .get("registration_epoch_evidence")
                .is_some()
        );

        // Package digest excludes itself and proof.
        let recomputed = package.compute_package_digest().unwrap();
        assert_eq!(recomputed, package.package_digest.clone().unwrap());

        let mut wire = serde_json::to_value(&package).unwrap();
        assert!(wire.get("registration_epoch_evidence").is_none());
        wire.as_object_mut().unwrap().insert(
            "registration_epoch_evidence".to_owned(),
            serde_json::to_value(package.registration_epoch_evidence.as_ref().unwrap()).unwrap(),
        );
        let back: AppletPackage = serde_json::from_value(wire).unwrap();
        assert_eq!(
            back.registration_epoch_evidence,
            package.registration_epoch_evidence
        );
        let back_wire = serde_json::to_value(back).unwrap();
        assert!(back_wire.get("registration_epoch_evidence").is_none());
    }

    #[test]
    fn applet_package_rejects_non_extension_flattened_fields() {
        let mut package = AppletPackage::new(
            "applet_pkg_todo",
            "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
            did("slackbridge"),
            did("alice"),
            "https://applet.example/cx",
            did("bot"),
            vec!["slack".to_owned()],
            AppletWireNamespaces::default(),
        );
        package.requested_scopes = vec!["ak.message.create".to_owned()];
        package.endpoint_policy.endpoints.push(AppletEndpointEntry {
            method: AppletEndpointMethod::Post,
            path: "/_arkret/edge/applet/transactions".to_owned(),
            auth: Some(AppletEndpointAuth::WebhookSignature),
            description: None,
            extra: Default::default(),
        });
        package.webhook_auth = WebhookAuth::http_message_signature(
            format!("{}#key-1", package.service_id),
            vec![WebhookSignatureAlg::EdDsa],
        );
        assert!(
            package
                .endpoint_policy
                .extra
                .insert("unexpected".to_owned(), Value::Bool(true))
                .is_err()
        );
    }

    #[test]
    fn applet_package_missing_base_profile_is_rejected() {
        let mut package = AppletPackage::new(
            "applet_pkg_todo",
            "ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa",
            did("slackbridge"),
            did("alice"),
            "https://applet.example/cx",
            did("bot"),
            vec!["slack".to_owned()],
            AppletWireNamespaces::default(),
        );
        package.claimed_profiles = vec!["ak.profile.applet_bridge.v1".to_owned()];
        package.requested_scopes = vec!["ak.message.create".to_owned()];
        package.endpoint_policy.endpoints.push(AppletEndpointEntry {
            method: AppletEndpointMethod::Post,
            path: "/_arkret/edge/applet/transactions".to_owned(),
            auth: Some(AppletEndpointAuth::WebhookSignature),
            description: None,
            extra: Default::default(),
        });
        package.webhook_auth = WebhookAuth::http_message_signature(
            format!("{}#key-1", package.service_id),
            vec![WebhookSignatureAlg::EdDsa],
        );
        package
            .seal_registration_epoch(sample_epoch_evidence(&package.service_id))
            .unwrap();
        package.seal().unwrap();
        assert!(package.validate().is_err());
    }

    #[test]
    fn install_plan_digest_excludes_itself_and_effective_scope_round_trips() {
        let mut plan = AppletInstallPlan {
            schema: "ak.schema.applet_install_plan.v1".to_owned(),
            plan_id: "plan_1".to_owned(),
            applet_id: AppletInstallAppletId::AppletId(
                AppletId::new("ak:applet:01904100-0000-7000-8000-aaaaaaaaaaaa").unwrap(),
            ),
            package_digest: sample_epoch(),
            registration_epoch: sample_epoch(),
            effective_scope: EffectiveScope::Realm { realm_id: realm() },
            requested_scopes: vec!["ak.message.create".to_owned()],
            approved_scopes: vec![],
            denied_scopes: vec![],
            events_to_submit: vec![],
            capability_constraints: vec![],
            namespace_conflicts: vec![],
            e2ee_effect: E2eeEffect {
                requires_mls_join: false,
                plaintext_access: "none".to_owned(),
                authorization_refs: None,
            },
            widget_effect: WidgetEffect {
                allow_widget: false,
                policy_event_ref: None,
            },
            warnings: vec![],
            plan_digest: sample_epoch(),
        };
        let before = plan.compute_plan_digest().unwrap();
        plan.seal().unwrap();
        assert_eq!(plan.plan_digest, before);

        let value = serde_json::to_value(&plan).unwrap();
        assert_eq!(value["effective_scope"]["kind"], "realm");
        let back: AppletInstallPlan = serde_json::from_value(value).unwrap();
        assert_eq!(back.effective_scope.realm_id(), &realm());
    }

    #[test]
    fn sign_registration_attaches_proof_with_matching_digest() {
        use std::collections::BTreeMap;

        use arkret_core::move_event::Move;
        use arkret_core::{
            Did as CoreDid, Hash as CoreHash, MoveSignature, MoveSigner, UnsignedMove, canonical,
        };
        use arkret_wire::Result as WireResult;

        struct StubSigner {
            did: CoreDid,
            kid: String,
        }

        impl MoveSigner for StubSigner {
            fn sign_move(&self, _: &UnsignedMove) -> WireResult<Move> {
                unreachable!()
            }
            fn signer_did(&self) -> &CoreDid {
                &self.did
            }
            fn verification_method_id(&self) -> &str {
                &self.kid
            }
            fn sign_payload(&self, canonical_bytes: &[u8]) -> WireResult<MoveSignature> {
                let payload_digest = CoreHash::new(canonical::sha256_digest(canonical_bytes))?;
                Ok(MoveSignature {
                    alg: "EdDSA".to_owned(),
                    verification_method: self.kid.clone(),
                    payload_digest: payload_digest.clone(),
                    created_at: Utc::now(),
                    jws: format!("stub..{}", payload_digest.as_str()),
                })
            }
        }

        let signer = StubSigner {
            did: did("alice"),
            kid: "did:webvh:z6mkfixture:alice.example#key-1".to_owned(),
        };
        let mut reg = sample_wire_registration();
        sign_registration(
            &mut reg,
            &signer,
            "did:webvh:z6mkfixture:alice.example#key-1",
        )
        .unwrap();

        let proof = reg.proof.as_ref().expect("proof must be attached");
        assert_eq!(proof.alg, "EdDSA");
        assert_eq!(
            proof.verification_method,
            "did:webvh:z6mkfixture:alice.example#key-1"
        );
        assert_eq!(proof.event_digest, reg.payload_digest().unwrap());

        // Silence any unused warnings on the BTreeMap import — kept for symmetry.
        let _ = BTreeMap::<String, ()>::new();
        let _ = json!({});
    }
}
