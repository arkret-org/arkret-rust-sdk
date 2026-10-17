//! Exact encrypted call invitation and holder-private Consent admission.

#[path = "generated/call_invitation_contracts.rs"]
mod contracts;
pub use contracts::*;

impl CallInvitationMedia {
    pub fn consent_scope(&self) -> arkret_wire::ConsentScope {
        if self.video || self.screen {
            arkret_wire::ConsentScope::VideoCall
        } else {
            arkret_wire::ConsentScope::VoiceCall
        }
    }

    pub fn is_subset_of(&self, other: &Self) -> bool {
        (!self.audio || other.audio)
            && (!self.video || other.video)
            && (!self.screen || other.screen)
    }

    pub fn is_nonempty(&self) -> bool {
        self.audio || self.video || self.screen
    }
}

fn invalid(message: &str) -> arkret_wire::WireError {
    arkret_wire::WireError::Protocol(message.to_owned())
}

pub fn canonical_request_digest<T: serde::Serialize>(value: &T) -> arkret_wire::Result<String> {
    let bytes = arkret_canonical::canonical_json_bytes(value)
        .map_err(|error| invalid(&error.to_string()))?;
    Ok(arkret_canonical::sha256_digest(bytes))
}

pub fn domain_signing_input<T: serde::Serialize>(
    domain: &str,
    value: &T,
    omitted: &str,
) -> arkret_wire::Result<Vec<u8>> {
    let mut value = serde_json::to_value(value).map_err(|error| invalid(&error.to_string()))?;
    value
        .as_object_mut()
        .ok_or_else(|| invalid("signed carrier must be an object"))?
        .remove(omitted);
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(
        arkret_canonical::canonical_json_bytes(&value)
            .map_err(|error| invalid(&error.to_string()))?,
    );
    Ok(bytes)
}

impl CallInvitationEnvelope {
    pub fn validate_for_envelope(
        &self,
        envelope: &arkret_wire::SignalEnvelope,
    ) -> arkret_wire::Result<()> {
        if self.inviter_actor_id != envelope.sender_actor_id
            || self.scope_ref != envelope.scope_ref
            || self.scope_ref.realm_id() != &envelope.realm_id
            || self.envelope_digest != canonical_request_digest(envelope)?
            || self.proof.verification_method != envelope.proof.verification_method.as_str()
            || self.expires_at > envelope.expires_at
            || !self.media.is_nonempty()
        {
            return Err(invalid(
                "call invitation does not bind its exact producer envelope",
            ));
        }
        Ok(())
    }

    pub fn signature_input(&self) -> arkret_wire::Result<Vec<u8>> {
        domain_signing_input("ak.call.invitation.v1", self, "proof")
    }
}

impl CallInvitationAdmissionRequestBody {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.invitation.validate_for_envelope(&self.envelope)?;
        if self.subject_actor_id.as_account_id() != Some(&self.invitation.holder_account_id)
            || !valid_nonce(&self.nonce)
        {
            return Err(invalid("call admission subject or nonce is invalid"));
        }
        match self.admission_phase {
            CallInvitationAdmissionPhase::ProductDelivery
                if self.focus_id.is_none() && self.desired_media.is_none() => {}
            CallInvitationAdmissionPhase::MediaToken
                if self.focus_id.as_ref().is_some_and(|f| !f.is_empty())
                    && self.desired_media.as_ref().is_some_and(|m| {
                        m.is_nonempty() && m.is_subset_of(&self.invitation.media)
                    }) => {}
            _ => return Err(invalid("call admission phase fields or media differ")),
        }
        Ok(())
    }
}

pub fn valid_nonce(nonce: &str) -> bool {
    (22..=64).contains(&nonce.len())
        && nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        && arkret_canonical::base64url_decode(nonce).is_ok_and(|bytes| bytes.len() >= 16)
}

pub fn voluntary_join_signing_input_from_value(
    value: &serde_json::Value,
) -> arkret_wire::Result<Vec<u8>> {
    let mut unsigned = value.clone();
    unsigned
        .get_mut("join_context")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| invalid("voluntary join context is absent"))?
        .remove("proof");
    let mut bytes = b"ak.call.voluntary_join.v1\0".to_vec();
    bytes.extend(
        arkret_canonical::canonical_json_bytes(&unsigned).map_err(|e| invalid(&e.to_string()))?,
    );
    Ok(bytes)
}

impl CallInvitationAdmissionOutcome {
    pub fn signature_input(&self) -> arkret_wire::Result<Vec<u8>> {
        domain_signing_input("ak.call.invitation.admission.v1", self, "proof")
    }

    pub fn validate_for_request(
        &self,
        request: &CallInvitationAdmissionRequestBody,
        generation: u64,
        now: chrono::DateTime<chrono::Utc>,
    ) -> arkret_wire::Result<()> {
        request.validate()?;
        if self.request_digest != canonical_request_digest(request)?
            || self.authority_generation != generation
            || self.evaluated_at > now
            || self.expires_at <= now
            || self.expires_at > self.evaluated_at + chrono::Duration::seconds(30)
            || self.expires_at > request.invitation.expires_at
        {
            return Err(invalid(
                "call admission outcome is stale or does not bind this request",
            ));
        }
        Ok(())
    }
}

impl CallInvitationDeliveryView {
    pub fn validate_for_envelope(
        &self,
        envelope: &arkret_wire::SignalEnvelope,
        holder: &arkret_wire::AccountId,
    ) -> arkret_wire::Result<()> {
        self.invitation.validate_for_envelope(envelope)?;
        self.request.validate()?;
        if &self.invitation.holder_account_id != holder
            || self.request.invitation != self.invitation
            || &self.request.envelope != envelope
            || self.request.admission_phase != CallInvitationAdmissionPhase::ProductDelivery
            || !self.outcome.admitted
            || self.outcome.request_digest != canonical_request_digest(&self.request)?
        {
            return Err(invalid(
                "call delivery is not the exact admitted holder request",
            ));
        }
        Ok(())
    }
}

impl ConsentCurrentReadOutcome {
    pub fn signature_input(&self) -> arkret_wire::Result<Vec<u8>> {
        domain_signing_input("ak.consent.current_read.v1", self, "proof")
    }

    pub fn validate_for_request(
        &self,
        request: &ConsentCurrentReadRequestBody,
        generation: u64,
        now: chrono::DateTime<chrono::Utc>,
    ) -> arkret_wire::Result<()> {
        if !valid_nonce(&request.nonce)
            || self.request_digest != canonical_request_digest(request)?
            || self.governance_generation != generation
            || self.evaluated_at > now
            || self.expires_at <= now
            || self.expires_at > self.evaluated_at + chrono::Duration::seconds(30)
            || self.effective_stream_head.stream_ref
                != (arkret_wire::CommitStreamRef::Realm {
                    realm_id: self.realm_id.clone(),
                })
        {
            return Err(invalid(
                "Consent current read is stale or bound to a different request",
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        for row in &self.consents {
            if row.selector.consent_id != row.value.consent_id
                || !ids.insert(row.selector.consent_id.clone())
                || row.source_stream_ref != self.effective_stream_head.stream_ref
                || row.revision.stream_position > self.effective_stream_head.stream_position
                || row.value.peer != request.peer
                || (row.value.consent_scope != request.consent_scope
                    && row.value.consent_scope != arkret_wire::ConsentScope::Any)
            {
                return Err(invalid(
                    "Consent read contains an unrelated or incomplete current row",
                ));
            }
        }
        Ok(())
    }

    pub fn permits(
        &self,
        request: &ConsentCurrentReadRequestBody,
        now: chrono::DateTime<chrono::Utc>,
    ) -> bool {
        self.validate_for_request(request, self.governance_generation, now)
            .is_ok()
            && self.consents.iter().any(|r| {
                r.value.status == crate::consent_operations::ConsentState::Active
                    && r.value.not_before.is_none_or(|start| start <= now)
                    && r.value.expires_at.is_none_or(|end| now < end)
                    && r.value.constraints.as_ref().is_none_or(Vec::is_empty)
            })
    }
}

impl CallInvitationMedia {
    pub fn from_selection(media: &crate::call_signal::CallMediaSelection) -> Self {
        Self {
            audio: media.audio,
            video: media.video,
            screen: media.screen.unwrap_or(false),
        }
    }
    pub fn permits(&self, desired: &Self) -> bool {
        desired.is_nonempty() && desired.is_subset_of(self)
    }
}
impl CallInvitationEnvelope {
    pub fn validate_plaintext(
        &self,
        plaintext: &crate::call_signal::CallSignalPlaintext,
    ) -> arkret_wire::Result<()> {
        let crate::call_signal::CallSignalData::Invite(invite) = &plaintext.signal else {
            return Err(invalid("call invitation plaintext is not Invite"));
        };
        if self.call_id != plaintext.call_id
            || self.media != CallInvitationMedia::from_selection(&invite.media)
        {
            return Err(invalid(
                "call invitation plaintext differs from signed relation",
            ));
        }
        Ok(())
    }
}
pub fn call_invitation_envelope_digest(
    envelope: &arkret_wire::SignalEnvelope,
) -> arkret_wire::Result<String> {
    canonical_request_digest(envelope)
}
pub fn consent_value_permits_call(
    value: &crate::consent_operations::ConsentValue,
    inviter: &arkret_wire::ActorId,
    media: &CallInvitationMedia,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let crate::events_payloads::consent::ConsentPeer::Actor { actor_id } = &value.peer;
    media.is_nonempty()
        && actor_id == inviter
        && value.status == crate::consent_operations::ConsentState::Active
        && (value.consent_scope == media.consent_scope()
            || value.consent_scope == arkret_wire::ConsentScope::Any)
        && value.not_before.is_none_or(|start| start <= now)
        && value.expires_at.is_none_or(|end| now < end)
        && value.constraints.as_ref().is_none_or(Vec::is_empty)
}

impl ConsentCurrentReadRequestBody {
    pub fn validate(&self) -> arkret_wire::Result<()> {
        self.holder_account_id.validate()?;
        if self.audience_actor_id
            != arkret_wire::ActorId::service(self.holder_account_id.station_id.clone())
            || !valid_nonce(&self.nonce)
        {
            return Err(invalid(
                "Consent read does not bind its exact holder hosting Station and fresh nonce",
            ));
        }
        Ok(())
    }
    pub fn digest(&self) -> arkret_wire::Result<String> {
        canonical_request_digest(self)
    }
}
impl CallInvitationAdmissionRequestBody {
    pub fn digest(&self) -> arkret_wire::Result<String> {
        canonical_request_digest(self)
    }
}
