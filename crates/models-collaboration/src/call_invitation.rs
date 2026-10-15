//! Exact encrypted call invitation relation and current admission semantics.

use arkret_wire::{ActorId, ConsentScope, Hash, Result, SignalEnvelope, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::call_signal::{CallMediaSelection, CallSignalData, CallSignalPlaintext};
use crate::consent_operations::{ConsentState, ConsentValue};
use crate::events_payloads::consent::ConsentPeer;

include!("generated/call_invitation_contracts.rs");

pub const CALL_INVITATION_SIGNING_LABEL: &str = "ak.call.invitation.v1";
pub const CALL_INVITATION_ADMISSION_SIGNING_LABEL: &str = "ak.call.invitation.admission.v1";
pub const CALL_VOLUNTARY_JOIN_SIGNING_LABEL: &str = "ak.call.voluntary_join.v1";

fn invalid(message: &str) -> WireError {
    WireError::Protocol(message.to_owned())
}

fn signed_bytes<T: serde::Serialize>(value: &T, label: &str) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(value)?;
    value
        .as_object_mut()
        .ok_or_else(|| invalid("call signed object must be an object"))?
        .remove("proof")
        .ok_or_else(|| invalid("call signed object must carry proof"))?;
    let mut bytes = label.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(arkret_canonical::canonical_json_bytes(&value)?);
    Ok(bytes)
}

pub fn call_invitation_envelope_digest(envelope: &SignalEnvelope) -> Result<Hash> {
    Ok(Hash::new(arkret_wire::canonical::canonical_sha256(
        &serde_json::to_value(envelope)?,
    )?)?)
}

impl CallInvitationMedia {
    pub fn from_selection(media: &CallMediaSelection) -> Self {
        Self {
            audio: media.audio,
            video: media.video,
            screen: media.screen.unwrap_or(false),
        }
    }

    pub fn consent_scope(&self) -> Result<ConsentScope> {
        if self.video || self.screen {
            Ok(ConsentScope::VideoCall)
        } else if self.audio {
            Ok(ConsentScope::VoiceCall)
        } else {
            Err(invalid("call invitation requires non-empty media"))
        }
    }

    pub fn permits(&self, desired: &Self) -> bool {
        desired.consent_scope().is_ok()
            && (!desired.audio || self.audio)
            && (!desired.video || self.video)
            && (!desired.screen || self.screen)
    }
}

impl CallInvitationEnvelope {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        signed_bytes(self, CALL_INVITATION_SIGNING_LABEL)
    }

    /// Structural/exact binding only. The consumer must separately verify the
    /// producer signature, accepted Call and current signing authorization.
    pub fn validate_for_envelope(
        &self,
        envelope: &SignalEnvelope,
        now: DateTime<Utc>,
    ) -> Result<()> {
        self.holder_account_id.validate()?;
        self.media.consent_scope()?;
        if self.inviter_actor_id != envelope.sender_actor_id
            || self.scope_ref != envelope.scope_ref
            || self.envelope_digest != call_invitation_envelope_digest(envelope)?
            || self.proof.verification_method != envelope.proof.verification_method
            || self.expires_at > envelope.expires_at
            || self.expires_at <= now
            || envelope.expires_at <= now
        {
            return Err(invalid(
                "call invitation differs from its exact producer envelope",
            ));
        }
        Ok(())
    }

    pub fn validate_plaintext(&self, plaintext: &CallSignalPlaintext) -> Result<()> {
        let CallSignalData::Invite(invite) = &plaintext.signal else {
            return Err(invalid("call invitation plaintext is not an invite"));
        };
        if self.call_id != plaintext.call_id
            || self.media != CallInvitationMedia::from_selection(&invite.media)
        {
            return Err(invalid(
                "call invitation plaintext differs from its signed relation",
            ));
        }
        Ok(())
    }
}

impl CallInvitationAdmissionRequestBody {
    pub fn digest(&self) -> Result<Hash> {
        Ok(Hash::new(arkret_wire::canonical::canonical_sha256(
            &serde_json::to_value(self)?,
        )?)?)
    }

    pub fn validate(&self, now: DateTime<Utc>) -> Result<()> {
        self.invitation.validate_for_envelope(&self.envelope, now)?;
        if self.subject_actor_id != ActorId::account(self.invitation.holder_account_id.clone())
            || !(22..=64).contains(&self.nonce.len())
            || !self
                .nonce
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(invalid("call admission subject or nonce differs"));
        }
        match self.admission_phase {
            CallInvitationAdmissionStage::ProductDelivery => {
                if self.focus_id.is_some() || self.desired_media.is_some() {
                    return Err(invalid("product admission cannot carry media token fields"));
                }
            }
            CallInvitationAdmissionStage::MediaToken => {
                if self.focus_id.as_ref().is_none_or(|focus| {
                    focus.is_empty() || focus.len() > 64 || focus.starts_with("ak:")
                }) || self
                    .desired_media
                    .as_ref()
                    .is_none_or(|media| !self.invitation.media.permits(media))
                {
                    return Err(invalid("media admission exceeds the signed invitation"));
                }
            }
        }
        Ok(())
    }
}

impl CallInvitationAdmissionOutcome {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        signed_bytes(self, CALL_INVITATION_ADMISSION_SIGNING_LABEL)
    }

    /// Validate against a fresh outstanding request. This never verifies the
    /// authority key or substitutes for current authority/generation checks.
    pub fn validate_for_request(
        &self,
        request: &CallInvitationAdmissionRequestBody,
        generation: u64,
        now: DateTime<Utc>,
    ) -> Result<()> {
        request.validate(now)?;
        if self.request_digest != request.digest()?
            || self.authority_generation != generation
            || self.evaluated_at > now
            || self.expires_at <= now
            || self.expires_at <= self.evaluated_at
            || self.expires_at > self.evaluated_at + chrono::Duration::seconds(30)
            || self.expires_at > request.invitation.expires_at
        {
            return Err(invalid(
                "call admission outcome is stale or bound to another request",
            ));
        }
        Ok(())
    }
}

/// Evaluate one full typed value only. Authority freshness and monotonic
/// installation of its accepted revision are obligations of the caller.
pub fn consent_value_permits_call(
    value: &ConsentValue,
    inviter: &ActorId,
    media: &CallInvitationMedia,
    now: DateTime<Utc>,
) -> bool {
    let Ok(scope) = media.consent_scope() else {
        return false;
    };
    let ConsentPeer::Actor { actor_id } = &value.peer;
    actor_id == inviter
        && value.status == ConsentState::Active
        && (value.consent_scope == scope || value.consent_scope == ConsentScope::Any)
        && value.not_before.is_none_or(|start| start <= now)
        && value.expires_at.is_none_or(|end| now < end)
        && value
            .constraints
            .as_ref()
            .is_none_or(|constraints| constraints.is_empty())
}

impl CallMediaSubjectBinding {
    pub fn public_binding_digest(
        binding: &crate::objects::media::CallMediaParticipantBinding,
    ) -> arkret_wire::Result<arkret_wire::Hash> {
        Ok(arkret_wire::Hash::new(
            arkret_wire::canonical::canonical_sha256(binding)?,
        )?)
    }

    pub fn signed_digest(&self) -> arkret_wire::Result<arkret_wire::Hash> {
        Ok(arkret_wire::Hash::new(arkret_canonical::canonical_sha256(
            self,
        )?)?)
    }

    pub fn unsigned_for_token(
        request: &crate::objects::media::CallMediaTokenExchangeRequestBody,
        roster_identity: CallMediaRosterIdentity,
        participant_id: String,
        binding: &crate::objects::media::CallMediaParticipantBinding,
        nonce: String,
    ) -> arkret_wire::Result<Self> {
        Ok(Self {
            realm_id: request.realm_id.clone(),
            call_id: request.call_id.clone(),
            subject_actor_id: request.actor_id.clone(),
            subject_device_id: request.device_id.clone(),
            roster_identity,
            focus_id: request.focus_id.clone(),
            participant_id,
            media: request.invitation_media(),
            expires_at: binding.expires_at,
            nonce,
            issuer_kid: binding.issuer_kid.clone(),
            sig: String::new(),
        })
    }

    pub fn signing_bytes(&self) -> arkret_wire::Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .ok_or_else(|| {
                arkret_wire::WireError::Protocol("subject binding is not an object".into())
            })?
            .remove("sig");
        let mut bytes = b"ak.media.subject_binding.v1\0".to_vec();
        bytes.extend(arkret_canonical::canonical_json_bytes(&value)?);
        Ok(bytes)
    }

    pub fn validate_outcome(
        &self,
        request: &crate::objects::media::CallMediaTokenExchangeRequestBody,
        outcome: &crate::objects::media::CallMediaTokenExchangeOutcome,
    ) -> arkret_wire::Result<()> {
        if self.subject_actor_id != request.actor_id
            || self.subject_device_id != request.device_id
            || self.realm_id != request.realm_id
            || self.call_id != request.call_id
            || self.focus_id != request.focus_id
            || self.participant_id != outcome.participant_id
            || self.roster_identity != outcome.roster_identity
            || self.issuer_kid != outcome.participant_binding.issuer_kid
            || self.expires_at != outcome.participant_binding.expires_at
            || self.signed_digest()? != outcome.participant_binding.subject_binding_digest
            || self.nonce.len() < 22
            || self.nonce.len() > 64
            || arkret_canonical::base64url_decode(&self.nonce).map_or(true, |bytes| {
                bytes.len() < 16 || arkret_canonical::base64url_encode(&bytes) != self.nonce
            })
            || self.media != request.invitation_media()
            || self.roster_identity.actor_id == *request.actor_id.signing_principal_id()
            || self.roster_identity.device_id == request.device_id
        {
            return Err(arkret_wire::WireError::Protocol(
                "private subject binding differs from the exact token and anonymous roster tuple"
                    .into(),
            ));
        }
        if let CallJoinContext::Refresh(previous) = &request.join_context {
            if previous.subject_binding.roster_identity != self.roster_identity
                || previous.participant_id != self.participant_id
            {
                return Err(arkret_wire::WireError::Protocol(
                    "refresh changed the established alias".into(),
                ));
            }
        }
        Ok(())
    }
}
