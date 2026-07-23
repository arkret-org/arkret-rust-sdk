use arkret_identifiers::{CellRef, Did, Hlc, RealmId};
use arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizePayload;
use arkret_models_identity::CrossSigningPublish;
use arkret_wire::{Effect, Event, LatticeOp, LatticeOpType, composite_subject};
use chrono::{DateTime, Utc};

use crate::Result;

const CROSS_SIGNING_PUBLISH_CELL_FAMILY: &str = "ak.component.cross_signing.publish.v1";
const DEVICE_AUTHORIZATION_CELL_FAMILY: &str = "ak.component.device.authorization.v1";

/// Author a canonical `ak.cross_signing.publish` control Event, including the
/// spec-owned CAS-register effect. Consumers only provide live coordinates;
/// Event defaults, wire time and cell subject construction remain in the
/// event-draft owner.
pub fn build_cross_signing_publish_event_at(
    realm_id: RealmId,
    actor_id: Did,
    actor_seq: u64,
    hlc: Hlc,
    payload: CrossSigningPublish,
    created_at: DateTime<Utc>,
) -> Result<Event> {
    let expected_previous_generation = payload.expected_previous_generation.to_string();
    let subject = composite_subject(&[
        payload.principal_id.as_str(),
        expected_previous_generation.as_str(),
    ])?;
    let payload_value = serde_json::to_value(&payload)?;
    let mut event = Event::new_at(
        arkret_wire::events::EventKind::CROSS_SIGNING_PUBLISH,
        realm_id,
        actor_id,
        actor_seq,
        hlc,
        payload_value.clone(),
        created_at,
    )?;
    event.effects = vec![Effect {
        cell: CellRef::new(format!(
            "ak:cell:{CROSS_SIGNING_PUBLISH_CELL_FAMILY}:{subject}"
        ))?,
        op: LatticeOp {
            op_type: LatticeOpType::Set,
            tag: None,
            value: Some(payload_value),
            from: None,
            to: None,
            reason: None,
            issuer_seq: Some(actor_seq),
        },
    }];
    Ok(event)
}

/// Author a canonical `ak.device.authorize` control Event, including the
/// spec-owned principal/device composite OR-set effect.
pub fn build_device_authorize_event_at(
    realm_id: RealmId,
    actor_id: Did,
    actor_seq: u64,
    hlc: Hlc,
    payload: DeviceAuthorizePayload,
    created_at: DateTime<Utc>,
) -> Result<Event> {
    let subject = composite_subject(&[payload.principal_id.as_str(), payload.device_id.as_str()])?;
    let tag = payload.device_id.to_string();
    let payload_value = serde_json::to_value(&payload)?;
    let mut event = Event::new_at(
        arkret_wire::events::EventKind::DEVICE_AUTHORIZE,
        realm_id,
        actor_id,
        actor_seq,
        hlc,
        payload_value.clone(),
        created_at,
    )?;
    event.effects = vec![Effect {
        cell: CellRef::new(format!(
            "ak:cell:{DEVICE_AUTHORIZATION_CELL_FAMILY}:{subject}"
        ))?,
        op: LatticeOp {
            op_type: LatticeOpType::Add,
            tag: Some(tag),
            value: Some(payload_value),
            from: None,
            to: None,
            reason: None,
            issuer_seq: Some(actor_seq),
        },
    }];
    Ok(event)
}

#[cfg(test)]
mod tests {
    use arkret_identifiers::{DeviceId, TypedTrustDomainId};
    use arkret_models_collaboration::events_payloads::device_identity::{
        DeviceCrossSigningBinding, DeviceOrPrincipalRef,
    };
    use arkret_models_collaboration::events_payloads::preview_realm_reaction::SignatureMaterial;
    use arkret_models_identity::{
        KeyFormat, PublishedKey, SubordinateSignedKey, SubordinateSignedKeyBinding,
    };
    use arkret_wire::{Base64UrlString, DidUrl, NonEmptyString};

    use super::*;

    fn did(value: &str) -> Did {
        Did::new(value.to_owned()).unwrap()
    }

    fn published_key(kid: &str) -> PublishedKey {
        PublishedKey {
            kid: NonEmptyString::new(kid).unwrap(),
            alg: NonEmptyString::new("EdDSA").unwrap(),
            public_key: NonEmptyString::new("z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
                .unwrap(),
            key_format: KeyFormat::Multibase,
        }
    }

    fn subordinate(kid: &str, controller: &str) -> SubordinateSignedKey {
        let key = published_key(kid);
        SubordinateSignedKey {
            kid: key.kid,
            alg: key.alg,
            public_key: key.public_key,
            key_format: key.key_format,
            binding: SubordinateSignedKeyBinding {
                verification_method: NonEmptyString::new(controller).unwrap(),
                alg: NonEmptyString::new("EdDSA").unwrap(),
                signature: NonEmptyString::new("signature").unwrap(),
            },
        }
    }

    #[test]
    fn device_control_event_authoring_owns_effects_and_millis_time() {
        let principal = did("did:web:alice.example");
        let realm = RealmId::new("ak:realm:01904100-0000-7000-8000-000000000001").unwrap();
        let created_at = DateTime::parse_from_rfc3339("2026-07-18T01:02:03.987654Z")
            .unwrap()
            .with_timezone(&Utc);
        let publish = CrossSigningPublish {
            principal_id: principal.clone(),
            trust_domain: TypedTrustDomainId::new("ak:trust_domain:example").unwrap(),
            principal_signing_key: published_key(principal.as_str()),
            self_signing_key: subordinate("did:web:alice.example#ssk", principal.as_str()),
            user_signing_key: subordinate("did:web:alice.example#usk", principal.as_str()),
            expected_previous_generation: 0,
            generation: std::num::NonZeroU64::new(1).unwrap(),
            issued_at: created_at,
        };
        let publish_event = build_cross_signing_publish_event_at(
            realm.clone(),
            principal.clone(),
            7,
            Hlc::new("019b00000000-0001-a13f9c2e").unwrap(),
            publish,
            created_at,
        )
        .unwrap();
        assert_eq!(publish_event.effects.len(), 1);
        assert_eq!(publish_event.effects[0].op.op_type, LatticeOpType::Set);
        assert!(
            publish_event.effects[0]
                .cell
                .as_str()
                .starts_with("ak:cell:ak.component.cross_signing.publish.v1:")
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
            device_key_algorithm: Some(NonEmptyString::new("EdDSA").unwrap()),
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
                alg: NonEmptyString::new("EdDSA").unwrap(),
                ssk_generation: std::num::NonZeroU64::new(1).unwrap(),
                signature: Base64UrlString::new("c2lnbmF0dXJl").unwrap(),
            }),
            enrollment_authority_binding: None,
            recovery_session_id: None,
        };
        let authorize_event = build_device_authorize_event_at(
            realm,
            principal,
            8,
            Hlc::new("019b00000000-0002-a13f9c2e").unwrap(),
            authorize,
            created_at,
        )
        .unwrap();
        assert_eq!(authorize_event.effects.len(), 1);
        assert_eq!(authorize_event.effects[0].op.op_type, LatticeOpType::Add);
        assert_eq!(
            authorize_event.effects[0].op.tag.as_deref(),
            Some(device_id.as_str())
        );
        assert!(
            authorize_event.effects[0]
                .cell
                .as_str()
                .starts_with("ak:cell:ak.component.device.authorization.v1:")
        );
    }
}
