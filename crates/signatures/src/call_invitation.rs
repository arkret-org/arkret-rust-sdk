//! Producer and holder-authority proofs for transient call admission.

use arkret_models_collaboration::call_invitation::{
    CallInvitationAdmissionOutcome, CallInvitationAdmissionRequestBody, CallInvitationEnvelope,
};
use arkret_wire::{DidUrl, SignalEnvelope};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;

use crate::{
    Ed25519DetachedJwsVerifier, Error, PublicKeyMaterial, Result, sign_ed25519_detached_jws,
};

pub fn sign_call_invitation(
    invitation: &mut CallInvitationEnvelope,
    key: &SigningKey,
) -> Result<()> {
    invitation.proof.jws = sign_ed25519_detached_jws(key, &invitation.signature_input()?)?;
    Ok(())
}
pub fn sign_consent_current_read(
    outcome: &mut arkret_models_collaboration::consent_operations::ConsentCurrentReadOutcome,
    key: &SigningKey,
) -> Result<()> {
    outcome.proof.jws = sign_ed25519_detached_jws(key, &outcome.signature_input()?)?;
    Ok(())
}
pub fn verify_consent_current_read(
    outcome: &arkret_models_collaboration::consent_operations::ConsentCurrentReadOutcome,
    request: &arkret_models_collaboration::consent_operations::ConsentCurrentReadRequestBody,
    authority_method: &DidUrl,
    key: &PublicKeyMaterial,
    generation: u64,
    now: DateTime<Utc>,
) -> Result<()> {
    if outcome.proof.verification_method != authority_method.as_str() {
        return Err(Error::Protocol(
            "Consent read names another authority signer".into(),
        ));
    }
    outcome.validate_for_request(request, generation, now)?;
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(&outcome.proof.jws, &outcome.signature_input()?, key)
        .map(|_| ())
        .map_err(|error| Error::Protocol(error.to_string()))
}

/// The key must come from current verified producer authorization; a valid
/// signature does not establish that authorization or the accepted Call.
pub fn verify_call_invitation(
    invitation: &CallInvitationEnvelope,
    envelope: &SignalEnvelope,
    key: &PublicKeyMaterial,
    now: DateTime<Utc>,
) -> Result<()> {
    invitation.validate_for_envelope(envelope)?;
    if invitation.expires_at <= now || envelope.expires_at <= now {
        return Err(Error::Protocol("call invitation expired".into()));
    }
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(&invitation.proof.jws, &invitation.signature_input()?, key)
        .map(|_| ())
        .map_err(|error| Error::Protocol(error.to_string()))
}

pub fn sign_call_invitation_admission(
    outcome: &mut CallInvitationAdmissionOutcome,
    key: &SigningKey,
) -> Result<()> {
    outcome.proof.jws = sign_ed25519_detached_jws(key, &outcome.signature_input()?)?;
    Ok(())
}

pub fn sign_call_voluntary_join(
    request: &mut arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody,
    key: &SigningKey,
) -> Result<()> {
    let bytes = request.voluntary_join_signing_bytes()?;
    let arkret_models_collaboration::call_invitation::CallMediaJoinContext::Voluntary(context) =
        &mut request.join_context
    else {
        return Err(Error::Protocol(
            "token request has no voluntary intent".into(),
        ));
    };
    context.proof.jws = sign_ed25519_detached_jws(key, &bytes)?;
    Ok(())
}

pub fn verify_call_voluntary_join(
    request: &arkret_models_collaboration::objects::media::CallMediaTokenExchangeRequestBody,
    method: &DidUrl,
    key: &PublicKeyMaterial,
    now: DateTime<Utc>,
) -> Result<()> {
    request.validate_join_context_at(now)?;
    let arkret_models_collaboration::call_invitation::CallMediaJoinContext::Voluntary(context) =
        &request.join_context
    else {
        return Err(Error::Protocol(
            "token request has no voluntary intent".into(),
        ));
    };
    if context.proof.verification_method.as_str() != method.as_str() {
        return Err(Error::Protocol(
            "voluntary join names another authenticated device signer".into(),
        ));
    }
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(
            &context.proof.jws,
            &request.voluntary_join_signing_bytes()?,
            key,
        )
        .map_err(|error| Error::Protocol(error.to_string()))?;
    Ok(())
}

/// Bind an authorized consumer's outstanding request to its independently
/// anchored current holder authority. Neither key nor generation is sourced
/// from the untrusted outcome itself.
pub fn verify_call_invitation_admission(
    outcome: &CallInvitationAdmissionOutcome,
    request: &CallInvitationAdmissionRequestBody,
    method: &DidUrl,
    key: &PublicKeyMaterial,
    generation: u64,
    now: DateTime<Utc>,
) -> Result<bool> {
    if outcome.proof.verification_method.as_str() != method.as_str() {
        return Err(Error::Protocol(
            "call admission names another authority key".into(),
        ));
    }
    outcome.validate_for_request(request, generation, now)?;
    Ed25519DetachedJwsVerifier::new()
        .verify_detached_jws(&outcome.proof.jws, &outcome.signature_input()?, key)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    Ok(outcome.admitted)
}

#[cfg(test)]
mod tests {
    use arkret_models_collaboration::call_invitation::*;
    use arkret_models_collaboration::consent_operations::ConsentCurrentRow;
    use arkret_wire::{AccountId, ActorId};
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 14, 8, 0, 0).unwrap()
    }
    fn account(name: &str) -> AccountId {
        AccountId::new(
            format!("ak:did_core:web:{name}.example").parse().unwrap(),
            "ak:did_core:web:station.example".parse().unwrap(),
        )
    }
    fn envelope(key: &SigningKey) -> SignalEnvelope {
        let mut envelope: SignalEnvelope = serde_json::from_value(json!({
            "realm_id":"ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI",
            "scope_ref":{"kind":"realm","realm_id":"ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"},
            "sender_actor_id":ActorId::account(account("alice")),
            "sender_device_id":"ak:device:01904100-0000-7000-8000-bbbbbbbbbbbb",
            "authority_commit_id":arkret_wire::RealmCommitId::from_digest([42;32]),
            "signal_class":"setup", "sent_at":"2026-10-14T08:00:00.000Z", "expires_at":"2026-10-14T08:01:00.000Z",
            "encrypted_payload":{"scheme":arkret_wire::SIGNAL_AEAD_SCHEME,"key_ref":{"group_state_ref":"ak:event:AdIAmf-J5rIPxEomGXwJblJdhNg-TllVN8uRTI85EUIM"},"purpose":arkret_wire::SIGNAL_AEAD_PURPOSE,"aead_profile":"MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519","epoch":7,"nonce":"AAAAAAAAAAAAAAAA","ciphertext":"Q2lwaGVydGV4dFBsYWNlaG9sZGVy"},
            "proof":{"kind":"detached_jws","verification_method":"did:web:alice.example#ak:device:01904100-0000-7000-8000-bbbbbbbbbbbb","envelope_digest":format!("sha256:{}","0".repeat(64)),"jws":"AA..AA"}
        })).unwrap();
        envelope.proof.envelope_digest = envelope.envelope_digest().unwrap();
        envelope.proof.jws =
            sign_ed25519_detached_jws(key, &envelope.proof_binding_bytes().unwrap()).unwrap();
        envelope.validate_structural().unwrap();
        envelope
    }
    fn invitation(key: &SigningKey, envelope: &SignalEnvelope) -> CallInvitationEnvelope {
        let mut value = CallInvitationEnvelope {
            inviter_actor_id: envelope.sender_actor_id.clone(),
            holder_account_id: account("bob"),
            scope_ref: envelope.scope_ref.clone(),
            call_id: "ak:call:ARzVic5s2NUShp82C8GPo-shbkm7isUWyvILLThc3aNL"
                .parse()
                .unwrap(),
            media: CallInvitationMedia {
                audio: true,
                video: false,
                screen: false,
            },
            envelope_digest: call_invitation_envelope_digest(envelope).unwrap(),
            expires_at: envelope.expires_at,
            proof: CallInvitationProof {
                verification_method: envelope.proof.verification_method.to_string(),
                jws: String::new(),
            },
        };
        sign_call_invitation(&mut value, key).unwrap();
        value
    }

    #[test]
    fn call_invitation_producer_and_authority_proofs_bind_every_direction_and_cut() {
        let signer = SigningKey::from_bytes(&[29; 32]);
        let key = PublicKeyMaterial::Ed25519Raw {
            bytes: signer.verifying_key().to_bytes().to_vec(),
        };
        let envelope = envelope(&signer);
        let invitation = invitation(&signer, &envelope);
        verify_call_invitation(&invitation, &envelope, &key, now()).unwrap();
        for mutate in [0, 1, 2, 3, 4] {
            let mut changed = invitation.clone();
            match mutate {
                0 => changed.holder_account_id = account("charlie"),
                1 => changed.inviter_actor_id = ActorId::account(account("charlie")),
                2 => changed.media.video = true,
                3 => {
                    changed.call_id = "ak:call:AVxshP1cCAeTx94DZvt3ODhEjNR9Da4hbdzLBzwPU-T1"
                        .parse()
                        .unwrap()
                }
                _ => changed.expires_at += chrono::Duration::seconds(1),
            }
            assert!(verify_call_invitation(&changed, &envelope, &key, now()).is_err());
        }
        let mut changed = envelope.clone();
        changed.encrypted_payload.ciphertext = "QW5vdGhlcg".into();
        assert!(verify_call_invitation(&invitation, &changed, &key, now()).is_err());
        let request = CallInvitationAdmissionRequestBody {
            invitation: invitation.clone(),
            envelope,
            admission_phase: CallInvitationAdmissionPhase::MediaToken,
            audience_actor_id: ActorId::service("ak:did_core:web:media.example".parse().unwrap()),
            subject_actor_id: ActorId::account(invitation.holder_account_id.clone()),
            subject_device_id: "ak:device:01904100-0000-7000-8000-cccccccccccc"
                .parse()
                .unwrap(),
            nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
            focus_id: Some("fra-1".into()),
            desired_media: Some(invitation.media.clone()),
        };
        let method = DidUrl::new("did:web:station.example#key-1").unwrap();
        let mut outcome = CallInvitationAdmissionOutcome {
            request_digest: canonical_request_digest(&request).unwrap(),
            admitted: true,
            authority_generation: 4,
            evaluated_at: now(),
            expires_at: now() + chrono::Duration::seconds(30),
            proof: CallInvitationAdmissionProof {
                verification_method: method.to_string(),
                jws: String::new(),
            },
        };
        sign_call_invitation_admission(&mut outcome, &signer).unwrap();
        assert!(
            verify_call_invitation_admission(&outcome, &request, &method, &key, 4, now()).unwrap()
        );
        let mut exchanged = request.clone();
        exchanged.audience_actor_id =
            ActorId::service("ak:did_core:web:other.example".parse().unwrap());
        assert!(
            verify_call_invitation_admission(&outcome, &exchanged, &method, &key, 4, now())
                .is_err()
        );
        assert!(
            verify_call_invitation_admission(&outcome, &request, &method, &key, 5, now()).is_err()
        );
        assert!(
            verify_call_invitation_admission(
                &outcome,
                &request,
                &method,
                &key,
                4,
                now() + chrono::Duration::seconds(30)
            )
            .is_err()
        );
        let mut wrong = outcome.clone();
        wrong.proof.jws =
            sign_ed25519_detached_jws(&signer, &invitation.signature_input().unwrap()).unwrap();
        assert!(
            verify_call_invitation_admission(&wrong, &request, &method, &key, 4, now()).is_err()
        );
    }

    #[test]
    fn call_consent_full_values_bind_the_exact_peer_and_one_scope() {
        let peer = ActorId::account(account("alice"));
        let media = CallInvitationMedia {
            audio: true,
            video: false,
            screen: false,
        };
        let row: ConsentCurrentRow = serde_json::from_value(json!({
            "selector":{"kind":"consent","peer_id":peer},
            "source_stream_ref":{"kind":"realm","realm_id":"ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI"},
            "revision":{"commit_id":arkret_wire::RealmCommitId::from_digest([3;32]),"stream_position":1},
            "value":{"permissions":[{"consent_scope":"voice_call"}]}
        })).unwrap();
        assert!(consent_value_permits_call(&row, &peer, &media, now()));
        let mut future = row.clone();
        future.value.permissions[0].not_before = Some(now() + chrono::Duration::seconds(1));
        let mut expired = row.clone();
        expired.value.permissions[0].expires_at = Some(now());
        let mut constrained = row.clone();
        constrained.value.permissions[0].constraints =
            Some(vec![[("unknown".into(), json!(true))].into()]);
        let mut closed = row.clone();
        closed.value.permissions.clear();
        for value in [&future, &expired, &constrained, &closed] {
            assert!(!consent_value_permits_call(value, &peer, &media, now()));
        }
        let mut other_station = account("alice");
        other_station.station_id = "ak:did_core:web:other.example".parse().unwrap();
        assert!(!consent_value_permits_call(
            &row,
            &ActorId::account(other_station),
            &media,
            now()
        ));
        assert!(!consent_value_permits_call(
            &row,
            &peer,
            &CallInvitationMedia {
                audio: true,
                video: true,
                screen: false
            },
            now()
        ));
    }
}
