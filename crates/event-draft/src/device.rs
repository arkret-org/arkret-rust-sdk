use arkret_identifiers::{Did, Hlc};
use arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload;
use arkret_models_identity::CrossSigningPublish;
use arkret_wire::{Event, ScopeRef};
use chrono::{DateTime, Utc};

use crate::Result;

/// Author a canonical `ak.cross_signing.publish` control Event.
///
/// The reducer target and lattice operation are derived by the receiver from
/// the registered contract, so the draft carries only the signed envelope and
/// payload.
pub fn build_cross_signing_publish_event_at(
    scope_ref: ScopeRef,
    actor_id: Did,
    actor_seq: u64,
    hlc: Hlc,
    payload: CrossSigningPublish,
    created_at: DateTime<Utc>,
) -> Result<Event> {
    let payload_value = serde_json::to_value(&payload)?;
    let event = Event::new_at(
        arkret_wire::EventKind::CROSS_SIGNING_PUBLISH,
        scope_ref,
        actor_id,
        actor_seq,
        hlc,
        payload_value,
        created_at,
    )?;
    Ok(event)
}

/// Author a canonical `ak.device.authorize` control Event.
pub fn build_device_authorize_event_at(
    scope_ref: ScopeRef,
    actor_id: Did,
    actor_seq: u64,
    hlc: Hlc,
    payload: DeviceAuthorizePayload,
    created_at: DateTime<Utc>,
) -> Result<Event> {
    let payload_value = serde_json::to_value(&payload)?;
    let event = Event::new_at(
        arkret_wire::EventKind::DEVICE_AUTHORIZE,
        scope_ref,
        actor_id,
        actor_seq,
        hlc,
        payload_value,
        created_at,
    )?;
    Ok(event)
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::{DeviceId, RealmId, TypedTrustDomainId};
    use arkret_models_collaboration::events_payloads::SignatureMaterial;
    use arkret_models_collaboration::events_payloads::device_identity::{
        DeviceCrossSigningBinding, DeviceOrPrincipalRef,
    };
    use arkret_models_identity::{
        KeyFormat, PublishedKey, SubordinateSignedKey, SubordinateSignedKeyBinding,
    };
    use arkret_schema::{or_set_dot, project_registered_cell_writes};
    use arkret_wire::cell::composite_subject;
    use arkret_wire::{
        Base64UrlString, CellRef, DidUrl, LatticeOp, LatticeOpType, NonEmptyString,
        ProjectedCellWrite, ProjectedOp,
    };
    use serde_json::{Value, json};

    use super::*;

    fn did(value: &str) -> Did {
        Did::new(value.to_owned()).unwrap()
    }

    fn scope() -> ScopeRef {
        ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                .unwrap(),
        }
    }

    /// Every cell write the registry derives for `event`; a v1 producer writes
    /// no reducer instruction of its own.
    fn project(event: &Event) -> Vec<ProjectedCellWrite> {
        project_registered_cell_writes(event, arkret_canonical::DigestSuite::Sha256)
            .expect("the registered contract must be evaluable")
    }

    fn payload_object(event: &Event) -> Value {
        Value::Object(event.payload.clone().into_iter().collect())
    }

    fn published_key(kid: &str) -> PublishedKey {
        PublishedKey {
            kid: DidUrl::new(kid.to_owned()).unwrap(),
            algorithm: NonEmptyString::new("Ed25519").unwrap(),
            public_key: NonEmptyString::new("z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
                .unwrap(),
            key_format: KeyFormat::Multibase,
        }
    }

    fn subordinate(kid: &str, controller: &DidUrl) -> SubordinateSignedKey {
        let key = published_key(kid);
        SubordinateSignedKey {
            kid: key.kid,
            algorithm: key.algorithm,
            public_key: key.public_key,
            key_format: key.key_format,
            binding: SubordinateSignedKeyBinding {
                verification_method: controller.clone(),
                signature_algorithm: NonEmptyString::new("Ed25519").unwrap(),
                signature: NonEmptyString::new("signature").unwrap(),
            },
        }
    }

    #[test]
    fn device_control_events_project_registered_writes_and_keep_millis_time() {
        let principal = did("did:web:alice.example");
        // `cross-signing-publish.schema.json` calls this a "PSK kid", but the
        // official fixture instance is a full DID URL
        // (`did:webvh:z6mkfixture:alice.example#psk`) and
        // `identity/device-lifecycle.md` requires it to resolve to a
        // `verificationMethod` of the DID head — so it is a DID URL, never a
        // bare DID.
        let psk = DidUrl::new(format!("{principal}#psk")).unwrap();
        let psk_kid = psk.as_str().to_owned();
        let created_at = DateTime::parse_from_rfc3339("2026-07-18T01:02:03.987654Z")
            .unwrap()
            .with_timezone(&Utc);
        let publish = CrossSigningPublish {
            principal_id: principal.clone(),
            trust_domain: TypedTrustDomainId::new("ak:trust_domain:example").unwrap(),
            principal_signing_key: published_key(&psk_kid),
            self_signing_key: subordinate("did:web:alice.example#ssk", &psk),
            user_signing_key: subordinate("did:web:alice.example#usk", &psk),
            expected_previous_generation: 0,
            generation: std::num::NonZeroU64::new(1).unwrap(),
            issued_at: created_at,
        };
        let publish_event = build_cross_signing_publish_event_at(
            scope(),
            principal.clone(),
            7,
            Hlc::new("019b00000000-0001-a13f9c2e").unwrap(),
            publish,
            created_at,
        )
        .unwrap();
        // `cas_register` + `set(payload)`: the registry derives the whole signed
        // payload as the register value, and the tuple subject is
        // `(principal_id, expected_previous_generation)`.
        let mut publish_op = LatticeOp::empty();
        publish_op.op_type = LatticeOpType::Set;
        publish_op.value = Some(payload_object(&publish_event));
        let publish_subject = composite_subject(&[json!(principal.as_str()), json!(0)]).unwrap();
        assert_eq!(
            project(&publish_event),
            vec![ProjectedCellWrite {
                cell: CellRef::new(format!(
                    "ak:cell:ak.component.cross_signing.publish.v1:{publish_subject}"
                ))
                .unwrap(),
                op: ProjectedOp::Direct(publish_op),
            }]
        );
        assert_eq!(publish_event.created_at.timestamp_subsec_millis(), 987);

        let device_id =
            DeviceId::new("ak:device:01904100-0000-7000-8000-000000000001".to_owned()).unwrap();
        let authorize = DeviceAuthorizePayload {
            principal_id: principal.clone(),
            device_id: device_id.clone(),
            device_public_key: NonEmptyString::new(
                "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
            )
            .unwrap(),
            hpke_key: NonEmptyString::new("z6LSdevice").unwrap(),
            algorithms: vec![NonEmptyString::new("ak.mls.v1").unwrap()],
            device_key_algorithm: Some(NonEmptyString::new("Ed25519").unwrap()),
            authorized_by: DeviceOrPrincipalRef::Did(principal.clone()),
            scopes: None,
            not_before: created_at,
            expires_at: None,
            device_signature: Some(SignatureMaterial::NonEmptyString(
                NonEmptyString::new("signature").unwrap(),
            )),
            proof: None,
            cross_signing_binding: Some(DeviceCrossSigningBinding {
                verification_method: DidUrl::new("did:web:alice.example#ssk").unwrap(),
                signature_algorithm: NonEmptyString::new("Ed25519").unwrap(),
                ssk_generation: std::num::NonZeroU64::new(1).unwrap(),
                signature: Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
            }),
            enrollment_authority_binding: None,
            recovery_session_id: None,
        };
        let authorize_event = build_device_authorize_event_at(
            scope(),
            principal.clone(),
            8,
            Hlc::new("019b00000000-0002-a13f9c2e").unwrap(),
            authorize,
            created_at,
        )
        .unwrap();
        let mut authorize_op = LatticeOp::empty();
        authorize_op.op_type = LatticeOpType::Add;
        // The or_set tag is the write's canonical dot, not the device id:
        // `event-and-patch.md` §2.4.2 fixes it to
        // `"ak:event:" + event_id + ":" + write_index`, and this contract's
        // single write sits at index 0.
        authorize_op.tag = Some(or_set_dot(authorize_event.event_id.as_str(), 0));
        authorize_op.value = Some(payload_object(&authorize_event));
        let authorize_subject =
            composite_subject(&[principal.as_str(), device_id.as_str()]).unwrap();
        assert_eq!(
            project(&authorize_event),
            vec![ProjectedCellWrite {
                cell: CellRef::new(format!(
                    "ak:cell:ak.component.device.authorization.v1:{authorize_subject}"
                ))
                .unwrap(),
                op: ProjectedOp::Direct(authorize_op),
            }]
        );
    }
}
