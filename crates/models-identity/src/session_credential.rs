use arkret_wire::{
    DeviceId, Did, Error, Event, EventId, EventKind, PolicyId, RecoveryModelGenerationRef,
    RecoverySessionId, Result, SessionGrantId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const RECOVERY_RESTRICTED_SESSION_GRANT_SCOPES: [&str; 9] = [
    "ak.root.identity.recovery_policy.resource.get",
    "ak.root.identity.recovery_session.command.create",
    "ak.root.identity.recovery_session.resource.get",
    "ak.root.identity.recovery_session.command.submit_proof",
    "ak.self.security_transaction.command.create",
    "ak.self.security_transaction.resource.get",
    "ak.self.security_transaction.command.continue",
    "ak.self.recovery_authority_ticket.command.issue",
    "ak.self.keys.backups.command.unlock",
];

/// Proof kind presented with an `ak.session.grant` request.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantProofKind {
    DidBoundSignature,
    PairedDeviceProof,
    PasskeyAssertion,
    OidcCodeExchange,
    PreRegistrationHandoff,
    AgentKeyProof,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantCredentialClass {
    Standard,
    RecoveryRestricted,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantRecoveryBinding {
    pub recovery_session_id: RecoverySessionId,
    pub policy_id: PolicyId,
    pub policy_version: u64,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantDeviceBinding {
    pub device_id: DeviceId,
    pub authorization_event_id: EventId,
    pub model_generation_ref: RecoveryModelGenerationRef,
}

/// Signed credential claims carried by an `ak.session.grant` JWT.
///
/// This credential is distinct from the durable `ak.session.grant` control
/// event payload. The latter additionally binds the principal control Realm,
/// issuer and session public key in the event body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedSessionGrantClaims {
    pub kind: String,
    #[serde(rename = "jti")]
    pub grant_id: SessionGrantId,
    pub issuer: Did,
    pub subject: Did,
    pub session_public_key: String,
    pub audience: String,
    pub scopes: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub session_id: String,
    pub cnf: SessionGrantCnf,
    pub credential_class: SessionGrantCredentialClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_binding: Option<SessionGrantRecoveryBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_binding: Option<SessionGrantDeviceBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_kind: Option<SessionGrantProofKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_details: Option<Value>,
}

/// Immutable payload of the durable `ak.session.grant` genesis Event.
///
/// The payload deliberately has no grant id. The only valid SessionGrantId is
/// obtained by retyping the accepted EventId.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantGenesisPayload {
    pub issuer: Did,
    pub subject: Did,
    pub session_public_key: String,
    pub audience: String,
    pub scopes: Vec<String>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub not_before: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub session_id: String,
    pub cnf: SessionGrantCnf,
    pub credential_class: SessionGrantCredentialClass,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_binding: Option<SessionGrantRecoveryBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_binding: Option<SessionGrantDeviceBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_kind: Option<SessionGrantProofKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_details: Option<Value>,
}

/// Marker proving that the exact genesis Event was named in a durable submit
/// outcome. JWT authoring APIs consume this marker instead of a producer-chosen
/// id, preventing pre-acceptance or UUIDv7 fallback issuance.
#[derive(Clone, Debug, PartialEq)]
pub struct AcceptedSessionGrantGenesis {
    event_id: EventId,
    payload: SessionGrantGenesisPayload,
}

impl AcceptedSessionGrantGenesis {
    pub fn from_submit_outcome(event: &Event, accepted_event_ids: &[EventId]) -> Result<Self> {
        if event.kind.as_str() != EventKind::SESSION_GRANT {
            return Err(Error::Protocol(
                "accepted session grant marker requires ak.session.grant".to_owned(),
            ));
        }
        if !accepted_event_ids.iter().any(|id| id == &event.event_id) {
            return Err(Error::Protocol(
                "session grant event is not present in accepted[]".to_owned(),
            ));
        }
        let payload: SessionGrantGenesisPayload =
            serde_json::from_value(serde_json::to_value(&event.payload).map_err(|error| {
                Error::Protocol(format!("invalid session grant genesis: {error}"))
            })?)
            .map_err(|error| Error::Protocol(format!("invalid session grant genesis: {error}")))?;
        payload.validate()?;
        if event.actor_id != payload.issuer {
            return Err(Error::Protocol(
                "session grant event actor_id must equal payload issuer".to_owned(),
            ));
        }
        Ok(Self {
            event_id: event.event_id.clone(),
            payload,
        })
    }

    #[must_use]
    pub fn session_grant_id(&self) -> SessionGrantId {
        SessionGrantId::from_event_id(&self.event_id)
    }

    #[must_use]
    pub fn into_signed_claims(self) -> SignedSessionGrantClaims {
        SignedSessionGrantClaims {
            kind: EventKind::SESSION_GRANT.to_owned(),
            grant_id: SessionGrantId::from_event_id(&self.event_id),
            issuer: self.payload.issuer,
            subject: self.payload.subject,
            session_public_key: self.payload.session_public_key,
            audience: self.payload.audience,
            scopes: self.payload.scopes,
            not_before: self.payload.not_before,
            expires_at: self.payload.expires_at,
            session_id: self.payload.session_id,
            cnf: self.payload.cnf,
            credential_class: self.payload.credential_class,
            recovery_binding: self.payload.recovery_binding,
            device_binding: self.payload.device_binding,
            proof_kind: self.payload.proof_kind,
            scope_details: self.payload.scope_details,
        }
    }
}

impl SessionGrantGenesisPayload {
    pub fn validate(&self) -> Result<()> {
        SignedSessionGrantClaims {
            kind: EventKind::SESSION_GRANT.to_owned(),
            grant_id: SessionGrantId::new(
                "ak:session_grant:ASyOHakrqmsRPkLKvhTD20V-YWCl-X7zYrlca5tdQLaR",
            )?,
            issuer: self.issuer.clone(),
            subject: self.subject.clone(),
            session_public_key: self.session_public_key.clone(),
            audience: self.audience.clone(),
            scopes: self.scopes.clone(),
            not_before: self.not_before,
            expires_at: self.expires_at,
            session_id: self.session_id.clone(),
            cnf: self.cnf.clone(),
            credential_class: self.credential_class,
            recovery_binding: self.recovery_binding.clone(),
            device_binding: self.device_binding.clone(),
            proof_kind: self.proof_kind,
            scope_details: self.scope_details.clone(),
        }
        .validate()?;
        if self.session_public_key.trim().is_empty() {
            return Err(Error::Protocol(
                "session grant session_public_key must not be empty".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantTerminalState {
    Revoked,
    Superseded,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantStatePayload {
    pub session_grant_id: SessionGrantId,
    pub from: SessionGrantActiveState,
    pub to: SessionGrantTerminalState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub successor_session_grant_id: Option<SessionGrantId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionGrantActiveState {
    Active,
}

impl SessionGrantStatePayload {
    pub fn validate(&self) -> Result<()> {
        if matches!(self.to, SessionGrantTerminalState::Superseded)
            != self.successor_session_grant_id.is_some()
        {
            return Err(Error::Protocol(
                "successor_session_grant_id is required exactly for superseded".to_owned(),
            ));
        }
        if self
            .reason_code
            .as_ref()
            .is_some_and(|reason| reason.trim().is_empty())
        {
            return Err(Error::Protocol(
                "session grant reason_code must not be empty".to_owned(),
            ));
        }
        Ok(())
    }
}

/// RFC 7800 confirmation claim binding a grant to a DPoP holder key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantCnf {
    pub jkt: String,
}

impl SignedSessionGrantClaims {
    pub fn validate(&self) -> Result<()> {
        if self.kind != EventKind::SESSION_GRANT {
            return Err(Error::Protocol(format!(
                "session grant kind must be {eventkind_session_grant}",
                eventkind_session_grant = EventKind::SESSION_GRANT
            )));
        }
        if self.audience.trim().is_empty() {
            return Err(Error::Protocol(
                "session grant audience must not be empty".to_owned(),
            ));
        }
        if self.session_public_key.trim().is_empty() {
            return Err(Error::Protocol(
                "session grant session_public_key must not be empty".to_owned(),
            ));
        }
        if self.scopes.is_empty() || self.scopes.iter().any(|scope| scope.trim().is_empty()) {
            return Err(Error::Protocol(
                "session grant scopes must contain only non-empty values".to_owned(),
            ));
        }
        if self.session_id.trim().is_empty() {
            return Err(Error::Protocol(
                "session grant session_id must not be empty".to_owned(),
            ));
        }
        if self.expires_at <= self.not_before {
            return Err(Error::Protocol(
                "session grant expires_at must be after not_before".to_owned(),
            ));
        }
        if self.cnf.jkt.len() != 43
            || !self
                .cnf
                .jkt
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(Error::Protocol(
                "session grant cnf.jkt must be a base64url SHA-256 JWK thumbprint".to_owned(),
            ));
        }
        match (
            self.credential_class,
            &self.recovery_binding,
            &self.device_binding,
        ) {
            (SessionGrantCredentialClass::RecoveryRestricted, Some(binding), None)
                if binding.policy_version > 0
                    && self.scopes.iter().all(|scope| {
                        RECOVERY_RESTRICTED_SESSION_GRANT_SCOPES.contains(&scope.as_str())
                    }) => {}
            (SessionGrantCredentialClass::Standard, None, _) => {}
            _ => {
                return Err(Error::Protocol(
                    "session grant credential class and typed bindings disagree".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> SignedSessionGrantClaims {
        SignedSessionGrantClaims {
            kind: EventKind::SESSION_GRANT.to_owned(),
            grant_id: SessionGrantId::new(
                "ak:session_grant:AUGAImJ4SNwk8MhBY2VUl3BpTzz9ZXxWvytGG9qTt_KR",
            )
            .unwrap(),
            issuer: Did::new("did:web:issuer.example").unwrap(),
            subject: Did::new("did:web:alice.example").unwrap(),
            session_public_key: "{\"kty\":\"OKP\"}".to_owned(),
            audience: "https://app.example.com".to_owned(),
            scopes: vec!["ak.self.events.command.submit".to_owned()],
            not_before: "2026-07-18T00:00:00.000Z".parse().unwrap(),
            expires_at: "2026-07-18T00:15:00.000Z".parse().unwrap(),
            session_id: "session-1".to_owned(),
            cnf: SessionGrantCnf {
                jkt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            },
            credential_class: SessionGrantCredentialClass::Standard,
            recovery_binding: None,
            device_binding: None,
            proof_kind: Some(SessionGrantProofKind::DidBoundSignature),
            scope_details: None,
        }
    }

    #[test]
    fn validates_normative_shape() {
        claims().validate().unwrap();
        let value = serde_json::to_value(claims()).unwrap();
        assert_eq!(
            value["jti"],
            "ak:session_grant:AUGAImJ4SNwk8MhBY2VUl3BpTzz9ZXxWvytGG9qTt_KR"
        );
        assert!(value.get("grant_id").is_none());
    }

    #[test]
    fn rejects_unknown_claims() {
        let mut value = serde_json::to_value(claims()).unwrap();
        value["unexpected"] = Value::String("nope".to_owned());
        assert!(serde_json::from_value::<SignedSessionGrantClaims>(value).is_err());
    }

    #[test]
    fn rejects_wrong_type_and_invalid_window() {
        let mut value = claims();
        value.kind = "session".to_owned();
        assert!(value.validate().is_err());

        let mut value = claims();
        value.expires_at = value.not_before;
        assert!(value.validate().is_err());
    }
}
