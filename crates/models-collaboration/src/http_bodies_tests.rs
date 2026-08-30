use super::*;

mod mimi_consent_tests {
    use arkret_wire::{
        Audience, Did, DidCoreId, DidUrl, EventKind, EventRequirements, ScopeRef,
        project_did_to_core_id, proof_kind,
    };
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    #[test]
    fn mimi_outcome_statuses_reject_unknown_literals() {
        assert_eq!(
            serde_json::from_str::<MimiRequestConsentStatus>(r#""requested""#).unwrap(),
            MimiRequestConsentStatus::Requested
        );
        assert_eq!(
            serde_json::from_str::<MimiReportAbuseStatus>(r#""queued""#).unwrap(),
            MimiReportAbuseStatus::Queued
        );
        assert!(serde_json::from_str::<MimiRequestConsentStatus>(r#""accepted""#).is_err());
        assert!(serde_json::from_str::<MimiReportAbuseStatus>(r#""accepted""#).is_err());
    }

    fn request() -> MimiUpdateConsentRequestBody {
        let created_at = Utc
            .with_ymd_and_hms(2026, 7, 19, 6, 30, 0)
            .single()
            .unwrap();
        let mut request = MimiUpdateConsentRequestBody {
            consent_id: ConsentId::new(
                "ak:consent:01964137-0000-7000-8000-000000000777".to_owned(),
            )
            .unwrap(),
            decision: MimiConsentDecision::Accept,
            actor_id: ActorId::account(AccountId::new(
                DidCoreId::new("ak:did_core:webvh:z6mkfixture".to_owned()).unwrap(),
                DidCoreId::new("ak:did_core:webvh:z6mkfixturestation".to_owned()).unwrap(),
            )),
            consent_event: EventInitialSubmission {
                event: Event {
                    event_id: EventId::new(
                        "ak:event:Aaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_owned(),
                    )
                    .unwrap(),
                    kind: EventKind::ConsentGrant,
                    realm_id: RealmId::new(
                        "ak:realm:Aaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_owned(),
                    )
                    .unwrap(),
                    scope_ref: ScopeRef::Realm {
                        realm_id: RealmId::new(
                            "ak:realm:Aaqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_owned(),
                        )
                        .unwrap(),
                    },
                    actor_id: ActorId::account(AccountId::new(
                        project_did_to_core_id(
                            &Did::new("did:webvh:z6mkfixture:example.com:users:alice".to_owned())
                                .unwrap(),
                        )
                        .unwrap(),
                        DidCoreId::new("ak:did_core:webvh:z6mkfixturestation").unwrap(),
                    )),
                    executed_by: None,
                    authorization_ref: None,
                    applet_id: None,
                    external_ref: None,
                    actor_kind: None,
                    actor_seq: 1,
                    created_at,
                    hlc: None,
                    prev_refs: Vec::new(),
                    refs: Vec::new(),
                    causal_refs: Vec::new(),
                    preconditions: Vec::new(),
                    seal_ref: None,
                    auth_context: None,
                    seal_basis: None,
                    payload: [
                        (
                            "consent_id".to_owned(),
                            json!("ak:consent:01964137-0000-7000-8000-000000000777"),
                        ),
                        (
                            "peer".to_owned(),
                            json!("did:webvh:z6mkfixture:example.com:users:bob"),
                        ),
                        ("consent_scope".to_owned(), json!("direct_message")),
                    ]
                    .into_iter()
                    .collect(),
                    unsigned: Default::default(),
                    proofs: Vec::new(),
                    requirements: EventRequirements::default(),
                },
                authorization_lease: None,
                cba_proof_bundles: Vec::new(),
                control_proposal_ack: None,
                membership_compensation_evidence: None,
            },
            signature: PayloadProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new(
                    "did:webvh:z6mkfixture:example.com:users:alice#device-1",
                )
                .unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at,
                domain: Some("ak:trust_domain:example.com".to_owned()),
                audience: Some(Audience::Single(
                    "did:webvh:z6mkservice:example.com".to_owned(),
                )),
                proof_purpose: None,
                jws: "e30..c2ln".to_owned(),
            },
            reason: Some(AuditReasonText::new("accepted after review").unwrap()),
            expires_at: None,
        };
        request.signature.payload_digest = request.payload_digest().unwrap();
        request
    }

    #[test]
    fn mimi_consent_signature_binds_unsigned_payload() {
        let request = request();
        let binding: Value =
            canonical::from_canonical_json_slice(&request.signature_binding_bytes().unwrap())
                .unwrap();

        assert_eq!(
            binding,
            json!({
                "audience": "did:webvh:z6mkservice:example.com",
                "consent_id": "ak:consent:01964137-0000-7000-8000-000000000777",
                "context": "ak.mimi_update_consent_request_proof.v1",
                "created_at": "2026-07-19T06:30:00.000Z",
                "decision": "accept",
                "domain": "ak:trust_domain:example.com",
                "issuer": {"kind": "account", "account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkfixture",
                    "station_id": "ak:did_core:webvh:z6mkfixturestation"
                }},
                "operation_id": "ak.open.mimi.command.update_consent.v1",
                "payload_digest": request.payload_digest().unwrap(),
                "verification_method": "did:webvh:z6mkfixture:example.com:users:alice#device-1"
            })
        );
    }

    #[test]
    fn mimi_operation_contexts_are_per_object_family() {
        let request = request();
        let mut identifier_query = MimiIdentifierQueryRequestBody {
            identifiers: Vec::new(),
            requester_id: None,
            privacy_profile: None,
            proofs: Vec::new(),
        };
        let mut proof = request.signature;
        proof.payload_digest = identifier_query.payload_digest().unwrap();
        identifier_query.proofs = vec![proof.clone()];

        let binding: Value = canonical::from_canonical_json_slice(
            &identifier_query.proof_binding_bytes(&proof).unwrap(),
        )
        .unwrap();

        assert_eq!(
            binding["context"],
            json!("ak.mimi_identifier_query_request_proof.v1")
        );
        assert!(binding.get("issuer").is_none());
    }

    #[test]
    fn mimi_consent_signature_rejects_event_proof_shape() {
        let mut value = serde_json::to_value(request()).unwrap();
        let signature = value["signature"].as_object_mut().unwrap();
        let digest = signature.remove("payload_digest").unwrap();
        signature.insert("event_digest".to_owned(), digest);

        let error = serde_json::from_value::<MimiUpdateConsentRequestBody>(value)
            .expect_err("Event proof fields must fail closed");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn mimi_consent_signature_detects_payload_tampering() {
        let mut request = request();
        request.decision = MimiConsentDecision::Revoke;

        assert!(request.signature_binding_bytes().is_err());
    }

    #[test]
    fn mimi_consent_event_must_match_decision_actor_and_consent_id() {
        let request = request();
        request.validate_consent_event().unwrap();

        let mut wrong_decision = request.clone();
        wrong_decision.decision = MimiConsentDecision::Revoke;
        assert!(wrong_decision.validate_consent_event().is_err());

        let mut wrong_actor = request.clone();
        wrong_actor.actor_id = ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturemallory").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixturestation").unwrap(),
        ));
        assert!(wrong_actor.validate_consent_event().is_err());

        let mut wrong_consent = request;
        wrong_consent.consent_event.event.payload.insert(
            "consent_id".to_owned(),
            json!("ak:consent:01964137-0000-7000-8000-000000000778"),
        );
        assert!(wrong_consent.validate_consent_event().is_err());
    }
}

mod federation_dependency_tests {
    use super::*;

    fn event_id(suffix: &str) -> EventId {
        EventId::from_event_digest(
            &Hash::new(arkret_canonical::sha256_digest(suffix.as_bytes())).unwrap(),
        )
        .unwrap()
    }

    fn realm_id() -> RealmId {
        RealmId::new("ak:realm:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5".to_owned()).unwrap()
    }

    #[test]
    fn peer_resolve_requires_sorted_non_empty_selectors() {
        let valid = PeerEventsResolveRequestBody {
            realm_id: realm_id(),
            event_ids: vec![event_id("1"), event_id("2")],
            event_digests: Vec::new(),
            include_payload: None,
            max_response_bytes: Some(4096),
            history_traversal_access: None,
        };
        assert!(valid.validate().is_ok());

        let mut empty = valid.clone();
        empty.event_ids.clear();
        assert!(empty.validate().is_err());

        let mut unsorted = valid;
        unsorted.event_ids.reverse();
        assert!(unsorted.validate().is_err());
    }
}

mod device_pairing_tests {
    use arkret_wire::{
        DidCoreId, DidUrl, EventKind, EventRequirements, ProducerEventProof, ScopeRef, SealBasis,
        proof_kind,
    };

    use super::*;
    use crate::events_payloads::{DeviceOrPrincipalRef, UnsignedDeviceAuthorizePayload};

    #[test]
    fn device_pairing_identifiers_enforce_the_wire_profiles() {
        assert!(
            DevicePairingRequestId::new(
                "device_pairing_request:01964137-0000-7000-8000-0000000000c1".to_owned()
            )
            .is_ok()
        );
        assert!(
            DevicePairingRequestId::new("device_pairing_request:not-a-uuid".to_owned()).is_err()
        );
        assert!(DevicePairingCode::new("7H2K9M4Q".to_owned()).is_ok());
        assert!(DevicePairingCode::new("00000000".to_owned()).is_err());
        assert!(DevicePairingCode::new("TOO-SHORT".to_owned()).is_err());
    }

    fn pair_request_fixture() -> (DevicePairingTargetAttestation, AccountDevicePairRequestBody) {
        let created_at = DateTime::parse_from_rfc3339("2026-08-08T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let principal_id = DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap();
        let principal_did = "did:webvh:z6mkfixturealice:alice.example";
        let authorizing_device =
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001").unwrap();
        let target_device =
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000009").unwrap();
        let did_key =
            DidKey::new("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuVkhY7g94pVQyG98x").unwrap();
        let public_key_bytes = arkret_canonical::decode_ed25519_multibase(
            did_key.as_str().strip_prefix("did:key:").unwrap(),
        )
        .unwrap();
        let hpke_key = NonEmptyString::new("hpke-public-key-fixture").unwrap();
        let algorithms = vec![NonEmptyString::new("Ed25519").unwrap()];
        let transcript_digest = Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let device_signature =
            SignatureMaterial::NonEmptyString(NonEmptyString::new("AA").unwrap());
        let attestation = UnsignedDevicePairingTargetAttestation::new(
            target_device.clone(),
            did_key.clone(),
            hpke_key.clone(),
            algorithms.clone(),
            transcript_digest.clone(),
        )
        .unwrap()
        .attach_signature(device_signature);
        let authorize_payload = UnsignedDeviceAuthorizePayload::new(
            principal_id.clone(),
            target_device.clone(),
            NonEmptyString::new(did_key.as_str()).unwrap(),
            hpke_key,
            algorithms,
            Some(NonEmptyString::new("Ed25519").unwrap()),
            DeviceOrPrincipalRef::DeviceId(authorizing_device.clone()),
            None,
            created_at,
            None,
            DeviceAuthorizationBindingKind::AcceptedDevice,
            None,
        )
        .unwrap()
        .attach_signature(Base64UrlString::new("AA").unwrap())
        .unwrap();
        let realm_id =
            RealmId::new("ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5").unwrap();
        let event = Event {
            event_id: EventId::new("ak:event:AWi7O9JH8Ib3wHJrt01Tl7Gf67pixYPhAmufRLOXFoBA")
                .unwrap(),
            kind: EventKind::DeviceAuthorize,
            realm_id: realm_id.clone(),
            scope_ref: ScopeRef::Realm { realm_id },
            actor_id: ActorId::account(AccountId::new(principal_id.clone(), principal_id)),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            actor_seq: 2,
            created_at,
            hlc: None,
            prev_refs: Vec::new(),
            refs: Vec::new(),
            causal_refs: Vec::new(),
            preconditions: Vec::new(),
            seal_ref: None,
            auth_context: None,
            seal_basis: Some(SealBasis {
                leaves: vec![SealId::new(format!("ak:seal:sha256:{}", "b".repeat(64))).unwrap()],
            }),
            payload: serde_json::to_value(authorize_payload)
                .unwrap()
                .as_object()
                .unwrap()
                .clone()
                .into_iter()
                .collect(),
            unsigned: BTreeMap::new(),
            proofs: vec![
                ProducerEventProof {
                    kind: proof_kind::DETACHED_JWS.to_owned(),
                    verification_method: DidUrl::new(format!(
                        "{}#{}",
                        principal_did, authorizing_device
                    ))
                    .unwrap(),
                    event_digest: Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap(),
                    signer_resolution_evidence_ref: None,
                    signer_resolution_evidence_digest: None,
                    created_at,
                    domain: None,
                    audience: None,
                    proof_purpose: None,
                    jws: "a..b".to_owned(),
                }
                .into(),
            ],
            requirements: EventRequirements::default(),
        };
        let request = AccountDevicePairRequestBody {
            pairing_code: DevicePairingCode::new("7H2K9M4Q".to_owned()).unwrap(),
            new_device_pubkey: PublicKey {
                kty: NonEmptyString::new("OKP").unwrap(),
                kid: NonEmptyString::new(target_device.as_str()).unwrap(),
                algorithm: NonEmptyString::new("Ed25519").unwrap(),
                key: Base64UrlString::new(arkret_canonical::base64url_encode(public_key_bytes))
                    .unwrap(),
                key_digest: None,
            },
            challenge_proof: DevicePairingChallengeProof {
                transcript: DevicePairingChallengeTranscriptKind::ServerMediated,
                kid: target_device,
                signature_algorithm: NonEmptyString::new("Ed25519").unwrap(),
                transcript_digest,
                signature: Base64UrlString::new("AA").unwrap(),
            },
            authorize_event: EventInitialSubmission {
                event,
                authorization_lease: None,
                cba_proof_bundles: Vec::new(),
                control_proposal_ack: None,
                membership_compensation_evidence: None,
            },
            display_name: None,
            device_metadata: None,
            device_pairing_request_id: None,
            challenge_transcript: None,
        };
        (attestation, request)
    }

    #[test]
    fn target_attestation_preassembly_binds_exact_pair_request_and_event() {
        let (attestation, request) = pair_request_fixture();
        attestation
            .validate_against_pair_request(&request, arkret_canonical::DigestSuite::Sha256)
            .unwrap();

        let mut changed_request = request.clone();
        changed_request.authorize_event.event.payload.insert(
            "hpke_key".to_owned(),
            serde_json::json!("different-hpke-key"),
        );
        assert!(
            attestation
                .validate_against_pair_request(
                    &changed_request,
                    arkret_canonical::DigestSuite::Sha256,
                )
                .is_err()
        );

        let mut changed_attestation = attestation;
        changed_attestation.pairing_challenge_transcript_digest =
            Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap();
        assert!(
            changed_attestation
                .validate_against_pair_request(&request, arkret_canonical::DigestSuite::Sha256,)
                .is_err()
        );
    }
}

mod contact_projection_tests {
    use serde_json::json;

    use super::*;

    const REQUEST_EVENT_REF: &str = "ak:event:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD";

    fn accepted_row_fixture() -> Value {
        json!({
            "peer": {
                "kind": "human",
                "account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkfixturepeer",
                    "station_id": "ak:did_core:webvh:z6mkfixturestation"
                }
            },
            "state": "accepted",
            "next_prepare_input": {
                "contact_round_id": format!("sha256:{}", "c".repeat(64)),
                "version": 2,
                "predecessor_event_ref": REQUEST_EVENT_REF
            },
            "granted_to_peer_scopes": ["direct_message"],
            "granted_by_peer_scopes": ["direct_message"],
            "bidirectional_scopes": ["direct_message"]
        })
    }

    fn pending_incoming_row_fixture() -> Value {
        json!({
            "peer": {
                "kind": "human",
                "account_id": {
                    "principal_id": "ak:did_core:webvh:z6mkfixture",
                    "station_id": "ak:did_core:webvh:z6mkfixturestation"
                }
            },
            "state": "pending_incoming",
            "request_event_ref": REQUEST_EVENT_REF,
            "request_receipt": {
                "core": {
                    "holder": {
                        "kind": "human",
                        "account_id": {
                            "principal_id": "ak:did_core:webvh:z6mkfixtureholder",
                            "station_id": "ak:did_core:webvh:z6mkfixturestation"
                        }
                    },
                    "peer": {
                        "kind": "human",
                        "account_id": {
                            "principal_id": "ak:did_core:webvh:z6mkfixturepeer",
                            "station_id": "ak:did_core:webvh:z6mkfixturestation"
                        }
                    },
                    "slot_version": 1,
                    "request_event_ref": REQUEST_EVENT_REF,
                    "source_checkpoint": format!("sha256:{}", "b".repeat(64)),
                    "accepted_at": "2026-08-08T00:00:00.000Z",
                    "issuer_id": "ak:did_core:web:ps.example"
                },
                "receipt_digest": "sha256:641452044a0d87132a2233b0765b061e065eefebb2ec14987451cd48df407a71",
                "signature": {
                    "verification_method": "did:web:ps.example#key-1",
                    "created_at": "2026-08-08T00:00:00.000Z",
                    "jws": "AA"
                }
            },
            "granted_to_peer_scopes": [],
            "granted_by_peer_scopes": [],
            "bidirectional_scopes": []
        })
    }

    #[test]
    fn accepted_contact_row_carries_exact_next_prepare_cursor() {
        let row: ContactListRow = serde_json::from_value(accepted_row_fixture()).unwrap();
        let next = row.next_prepare_input.unwrap();
        assert_eq!(next.version, 2);
        assert_eq!(next.predecessor_event_ref.as_str(), REQUEST_EVENT_REF);

        let mut missing = accepted_row_fixture();
        missing
            .as_object_mut()
            .unwrap()
            .remove("next_prepare_input");
        assert!(serde_json::from_value::<ContactListRow>(missing).is_err());

        let mut stale_version = accepted_row_fixture();
        stale_version["next_prepare_input"]["version"] = json!(1);
        assert!(serde_json::from_value::<ContactListRow>(stale_version).is_err());
    }

    #[test]
    fn pending_incoming_row_requires_matching_source_receipt() {
        let row: ContactListRow = serde_json::from_value(pending_incoming_row_fixture()).unwrap();
        assert_eq!(
            row.request_receipt
                .as_ref()
                .unwrap()
                .core
                .request_event_ref
                .as_str(),
            REQUEST_EVENT_REF
        );

        let mut missing = pending_incoming_row_fixture();
        missing.as_object_mut().unwrap().remove("request_receipt");
        assert!(serde_json::from_value::<ContactListRow>(missing).is_err());

        let mut mismatched = pending_incoming_row_fixture();
        mismatched["request_event_ref"] =
            json!("ak:event:AWi7O9JH8Ib3wHJrt01Tl7Gf67pixYPhAmufRLOXFoBA");
        assert!(serde_json::from_value::<ContactListRow>(mismatched).is_err());
    }
}

mod event_delivery_status_tests {
    use serde_json::json;

    use super::*;

    const EVENT_ID: &str = "ak:event:AQJmSg1s9QyzppFeJL40dN92YVHZeLdBBt3UWHa9XNOD";

    fn request() -> EventDeliveryStatusRequestBody {
        EventDeliveryStatusRequestBody {
            event_id: EventId::new(EVENT_ID.to_owned()).unwrap(),
        }
    }

    fn target(target_id: &str, status: EventDeliveryTargetState) -> EventDeliveryTargetStatus {
        EventDeliveryTargetStatus {
            target_id: target_id.to_owned(),
            status,
            service_id: None,
        }
    }

    #[test]
    fn delivery_status_derives_pending_aggregate_from_sorted_targets() {
        let outcome = EventDeliveryStatusOutcome {
            event_id: request().event_id,
            targets: vec![
                target(
                    "00000000-0000-7000-8000-000000000001",
                    EventDeliveryTargetState::PendingRoute,
                ),
                target(
                    "00000000-0000-7000-8000-000000000002",
                    EventDeliveryTargetState::Delivered,
                ),
            ],
        };
        outcome.validate_for_request(&request()).unwrap();
        assert_eq!(outcome.pending_delivery_count(), 1);
        assert_eq!(outcome.delivery_state(), EventDeliveryStateView::Pending);

        let mut out_of_order = outcome;
        out_of_order.targets.reverse();
        assert!(out_of_order.validate().is_err());
    }

    #[test]
    fn submit_delivery_aggregate_is_derived_and_old_wire_field_is_rejected() {
        let missing = json!({
            "status": "accepted",
            "accepted": [EVENT_ID]
        });
        assert!(serde_json::from_value::<EventsSubmitOutcome>(missing).is_err());

        let valid = json!({
            "status": "accepted",
            "accepted": [EVENT_ID],
            "pending_delivery_count": 1
        });
        let outcome: EventsSubmitOutcome = serde_json::from_value(valid).unwrap();
        outcome.validate_delivery_invariants().unwrap();
        assert_eq!(outcome.delivery_state(), EventDeliveryStateView::Pending);

        let old = json!({
            "status": "accepted",
            "accepted": [EVENT_ID],
            "delivery_state": "complete",
            "pending_delivery_count": 1
        });
        assert!(serde_json::from_value::<EventsSubmitOutcome>(old).is_err());
    }
}

mod events_submit_status_tests {
    use super::*;

    /// `as_str` is a second spelling of the serde projection, so pin both
    /// representations to the same diagnostic token.
    #[test]
    fn as_str_matches_the_serde_wire_token() {
        for status in [
            EventsSubmitStatus::Accepted,
            EventsSubmitStatus::Duplicate,
            EventsSubmitStatus::Partial,
            EventsSubmitStatus::HistoricalOnly,
        ] {
            assert_eq!(
                serde_json::to_value(status).unwrap(),
                Value::String(status.as_str().to_owned()),
            );
            assert_eq!(status.to_string(), status.as_str());
        }
    }
}
