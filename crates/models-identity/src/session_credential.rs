use arkret_wire::{
    DeviceId, Did, Error, EventId, GrantId, PolicyId, RecoveryModelGenerationRef,
    RecoverySessionId, Result,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SIGNED_SESSION_GRANT_KIND: &str = "ak.session.grant";
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
    pub grant_id: GrantId,
    pub subject: Did,
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

/// RFC 7800 confirmation claim binding a grant to a DPoP holder key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionGrantCnf {
    pub jkt: String,
}

impl SignedSessionGrantClaims {
    pub fn validate(&self) -> Result<()> {
        if self.kind != SIGNED_SESSION_GRANT_KIND {
            return Err(Error::Protocol(format!(
                "session grant kind must be {SIGNED_SESSION_GRANT_KIND}"
            )));
        }
        if self.audience.trim().is_empty() {
            return Err(Error::Protocol(
                "session grant audience must not be empty".to_owned(),
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
            kind: SIGNED_SESSION_GRANT_KIND.to_owned(),
            grant_id: GrantId::new("ak:grant:01964198-0000-7000-8000-000000000000").unwrap(),
            subject: Did::new("did:web:alice.example").unwrap(),
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
    }

    #[test]
    fn rejects_unknown_claims() {
        let mut value = serde_json::to_value(claims()).unwrap();
        value["issuer"] = Value::String("did:web:issuer.example".to_owned());
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
