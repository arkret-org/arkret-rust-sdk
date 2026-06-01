//! Wire-model invariants preserved while domain modules stay split.

mod session_and_identity {
    use super::super::*;
    use chrono::{Duration, Utc};
    fn realm() -> RealmId {
        RealmId::new("cx:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn did() -> Did {
        Did::new("did:web:alice.example").unwrap()
    }

    #[test]
    fn ephemeral_envelope_rejects_window_over_ceiling() {
        let now = Utc::now();
        let bad = EphemeralEnvelope::new(
            "cx.presence",
            realm(),
            did(),
            None,
            now,
            now + Duration::milliseconds(EPHEMERAL_ABSOLUTE_HARD_CEILING_MS as i64 + 1),
            serde_json::json!({"status":"online"}),
            None,
        );
        assert!(bad.is_err());
    }

    #[test]
    fn ephemeral_envelope_accepts_window_at_ceiling() {
        let now = Utc::now();
        let ok = EphemeralEnvelope::new(
            "cx.presence",
            realm(),
            did(),
            None,
            now,
            now + Duration::milliseconds(EPHEMERAL_ABSOLUTE_HARD_CEILING_MS as i64),
            serde_json::json!({"status":"online"}),
            None,
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn ephemeral_envelope_rejects_non_ephemeral_kind() {
        let now = Utc::now();
        assert!(
            EphemeralEnvelope::new(
                "cx.message.create",
                realm(),
                did(),
                None,
                now,
                now + Duration::seconds(30),
                serde_json::json!({}),
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn moderation_appeal_decision_modify_requires_ref() {
        let p = ModerationAppealPayload::Decision(AppealDecisionPayload {
            appeal_id: TypedAppealId::new("cx:appeal:01904100-0000-7000-8000-000000000001")
                .unwrap(),
            reviewer: did(),
            verdict: AppealVerdict::Modify,
            reason_text_ref: "blob:reason".to_owned(),
            modify_decision_ref: None,
            decided_at: Utc::now(),
        });
        assert!(p.validate_minimal().is_err());
    }

    #[test]
    fn moderation_appeal_decision_uphold_rejects_modify_ref() {
        let p = ModerationAppealPayload::Decision(AppealDecisionPayload {
            appeal_id: TypedAppealId::new("cx:appeal:01904100-0000-7000-8000-000000000001")
                .unwrap(),
            reviewer: did(),
            verdict: AppealVerdict::Uphold,
            reason_text_ref: "blob:reason".to_owned(),
            modify_decision_ref: Some(
                EventId::new("cx:event:01904100-0000-7000-8000-000000000002").unwrap(),
            ),
            decided_at: Utc::now(),
        });
        assert!(p.validate_minimal().is_err());
    }

    #[test]
    fn policy_frontier_digest_is_deterministic() {
        let h1 = compute_policy_frontier_digest(
            &serde_json::json!({"mode": "strict"}),
            &serde_json::json!("members_only"),
            &serde_json::json!({"profile": "default"}),
            &serde_json::json!(false),
        )
        .unwrap();
        let h2 = compute_policy_frontier_digest(
            &serde_json::json!({"mode": "strict"}),
            &serde_json::json!("members_only"),
            &serde_json::json!({"profile": "default"}),
            &serde_json::json!(false),
        )
        .unwrap();
        assert_eq!(h1, h2);
        let h3 = compute_policy_frontier_digest(
            &serde_json::json!({"mode": "strict"}),
            &serde_json::json!("members_only"),
            &serde_json::json!({"profile": "default"}),
            &serde_json::json!(true),
        )
        .unwrap();
        assert_ne!(h1, h3);
    }

    #[test]
    fn trust_domain_id_validates_scope() {
        assert!(TypedTrustDomainId::new("cx:trust_domain:example.net").is_ok());
        assert!(TypedTrustDomainId::new("cx:trust_domain:Example").is_err());
        assert!(TypedTrustDomainId::new("cx:trust_domain:").is_err());
        let too_long = format!("cx:trust_domain:{}", "a".repeat(129));
        assert!(TypedTrustDomainId::new(too_long).is_err());
    }
}

mod protocol_wire {
    use super::super::*;
    use chrono::Utc;
    fn realm() -> RealmId {
        RealmId::new("cx:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }
    fn td() -> TypedTrustDomainId {
        TypedTrustDomainId::new("cx:trust_domain:example.net").unwrap()
    }
    fn td2() -> TypedTrustDomainId {
        TypedTrustDomainId::new("cx:trust_domain:other.example").unwrap()
    }

    #[test]
    fn audit_policy_version_digest_is_deterministic_and_domain_separates() {
        let disclosure = serde_json::json!({"mode": "strict"});
        let assurance = serde_json::json!("attested_hardware");
        let h1 =
            compute_audit_policy_version_digest(&realm(), &td(), &disclosure, &assurance).unwrap();
        let h2 =
            compute_audit_policy_version_digest(&realm(), &td(), &disclosure, &assurance).unwrap();
        assert_eq!(h1, h2);
        // Different trust domain MUST produce a different digest.
        let h3 =
            compute_audit_policy_version_digest(&realm(), &td2(), &disclosure, &assurance).unwrap();
        assert_ne!(h1, h3);
    }

    #[test]
    fn third_party_invite_rejects_mode_mismatch() {
        let mut invite = ThirdPartyInvite {
            oob_code_kind: ThirdPartyInviteOobKind::OfflineToken,
            token_commitment: None,
            token_salt_id: None,
            token_entropy_bits: Some(64),
            lookup_table_ref: None,
            pepper_id: None,
            max_claims: 3,
            verification_service_did: Did::new("did:web:auth.example").unwrap(),
            verification_public_key: "z6MkVK".to_owned(),
        };
        // Missing token_commitment + token_salt_id → reject.
        assert!(invite.validate_minimal().is_err());

        invite.token_commitment = Some(Hash::new("sha256:".to_owned() + &"0".repeat(64)).unwrap());
        invite.token_salt_id = Some("salt-1".to_owned());
        // entropy_bits = 64 still < 128 → reject.
        assert!(invite.validate_minimal().is_err());

        invite.token_entropy_bits = Some(128);
        assert!(invite.validate_minimal().is_ok());

        // Lookup mode requires lookup_table_ref + pepper_id, not offline_token fields.
        let lookup_bad = ThirdPartyInvite {
            oob_code_kind: ThirdPartyInviteOobKind::Lookup,
            token_commitment: invite.token_commitment.clone(),
            ..invite
        };
        assert!(lookup_bad.validate_minimal().is_err());
    }

    #[test]
    fn validate_signal_seq_enforces_monotonicity() {
        assert!(validate_signal_seq(None, 0).is_ok());
        assert!(validate_signal_seq(Some(0), 1).is_ok());
        assert!(validate_signal_seq(Some(5), 6).is_ok());
        assert!(validate_signal_seq(Some(5), 5).is_err());
        assert!(validate_signal_seq(Some(5), 4).is_err());
    }

    #[test]
    fn call_signal_state_tracks_per_key_seq() {
        let mut state = CallSignalState::new();
        let key = CallSignalSeqKey::new(
            realm(),
            CallId::new("cx:call:01904100-0000-7000-8000-000000000002").unwrap(),
            Did::new("did:web:alice.example").unwrap(),
            DeviceId::new("cx:device:01904100-0000-7000-8000-000000000003").unwrap(),
        );
        assert!(state.observe(&key, 1).is_ok());
        assert!(state.observe(&key, 2).is_ok());
        assert!(state.observe(&key, 2).is_err()); // repeat = rollback
        assert!(state.observe(&key, 5).is_ok());
    }

    #[test]
    fn audit_policy_access_payload_validates_late_recovery_pairing() {
        let payload = AuditPolicyAccessPayload {
            realm_id: realm(),
            actor: Did::new("did:web:alice.example").unwrap(),
            access_kind: AccessKind::E2EELateRecovery,
            late_recovery_original_event_id: None,
            observed_at: Utc::now(),
        };
        assert!(payload.validate_minimal().is_err());
    }

    #[test]
    fn consent_revoke_requires_observed_dots() {
        let payload = ConsentRevokePayload {
            consent_id: "cid".to_owned(),
            peer: Did::new("did:web:bob.example").unwrap(),
            scope: "invite".to_owned(),
            observed_dots: Vec::new(),
            revoked_at: None,
            reason: None,
        };
        assert!(payload.validate_minimal().is_err());
    }

    #[test]
    fn snapshot_bootstrap_signature_binds_header_and_chunk_root() {
        let mut bootstrap = SnapshotBootstrap {
            signature: SnapshotBootstrapSignature {
                alg: "EdDSA".to_owned(),
                verification_method: "did:web:snapshot.example#k1".to_owned(),
                payload_digest: Hash::new(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                created_at: Utc::now(),
                jws: "AAAA.BBBB.CCCC".to_owned(),
            },
            state_digest: Hash::new(
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            )
            .unwrap(),
            snapshot_frontier: vec![
                EventId::new("cx:event:01904100-0000-7000-8000-000000000001").unwrap(),
            ],
            chunks: vec![SnapshotBootstrapChunk {
                chunk_id: "0".to_owned(),
                digest: Hash::new(
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222",
                )
                .unwrap(),
                size_bytes: 1024,
                fetch_ref: "cx:blob:sha256:3333333333333333333333333333333333333333333333333333333333333333"
                    .to_owned(),
            }],
        };
        bootstrap.signature.payload_digest = bootstrap.signing_payload_digest().unwrap();
        bootstrap.validate_signature_binding().unwrap();

        bootstrap.chunks[0].digest =
            Hash::new("sha256:4444444444444444444444444444444444444444444444444444444444444444")
                .unwrap();
        assert!(bootstrap.validate_signature_binding().is_err());
    }

    #[test]
    fn flow_cell_subject_helpers_return_flow_id() {
        let flow = FlowId::new("cx:flow:01904100-0000-7000-8000-000000000004").unwrap();
        assert_eq!(flow_update_cell_subject(&flow), flow.as_str());
        assert_eq!(flow_tracks_patch_cell_subject(&flow), flow.as_str());
    }
}
