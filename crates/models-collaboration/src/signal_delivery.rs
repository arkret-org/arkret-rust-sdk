//! One authenticated transient delivery, including scoped product authority.
use arkret_wire::*;
use serde::{Deserialize, Serialize};

use crate::events_payloads::agent::AgentKeyScope;
use crate::governance::grant_constraint::CapabilityGrant;
use crate::governance::operation_wire::Policy;

/// Counterpart: `signal-stream-frame.schema.json#/$defs/product_authority`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalProductAuthority {
    pub authority_commit_id: RealmCommitId,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub parent_realm_authority_commit_id: Option<RealmCommitId>,
    pub current_realm_head: CommitStreamHead,
    pub current_scope_head: CommitStreamHead,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub sent_at: chrono::DateTime<chrono::Utc>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub grants: Vec<CapabilityGrant>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub current_grants: Vec<CapabilityGrant>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub historical_product_policies: Vec<Policy>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub current_product_policies: Vec<Policy>,
    pub owner_actions: Vec<String>,
    pub profile_actions: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub agent: Option<SignalAgentProductAuthority>,
}

/// Counterpart: `signal-stream-frame.schema.json#/$defs/agent_product_authority`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalAgentProductAuthority {
    pub controller_account_id: AccountId,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub controller_grants: Vec<CapabilityGrant>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub current_controller_grants: Vec<CapabilityGrant>,
    pub historical_controller_owner_actions: Vec<String>,
    pub current_controller_owner_actions: Vec<String>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub historical_management_policies: Vec<Policy>,
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = Vec<serde_json::Value>)))]
    pub current_management_policies: Vec<Policy>,
    pub key_scope: AgentKeyScope,
}

impl PartialEq for SignalProductAuthority {
    fn eq(&self, other: &Self) -> bool {
        matches!((serde_json::to_value(self), serde_json::to_value(other)), (Ok(left), Ok(right)) if left == right)
    }
}

impl SignalProductAuthority {
    pub const MAX_CANONICAL_BYTES: usize = 32 * 1024;
    pub fn validate_for_envelope(&self, envelope: &SignalEnvelope) -> Result<()> {
        let realm_stream = CommitStreamRef::Realm {
            realm_id: envelope.realm_id.clone(),
        };
        let scope_stream = CommitStreamRef::from_scope(&envelope.scope_ref, None)?;
        if self.sent_at != envelope.sent_at
            || self.authority_commit_id != envelope.authority_commit_id
            || self.parent_realm_authority_commit_id != envelope.parent_realm_authority_commit_id
            || self.current_realm_head.stream_ref != realm_stream
            || self.current_scope_head.stream_ref != scope_stream
            || (self.agent.is_some() != envelope.sender_device_id.is_none())
            || arkret_canonical::canonical_json_bytes(self)?.len() > Self::MAX_CANONICAL_BYTES
        {
            return Err(WireError::Protocol(
                "Signal product authority differs from its delivery".into(),
            ));
        }
        for (actions, allowed) in [
            (
                &self.owner_actions,
                &[CapabilityActionId::MESSAGE_CREATE][..],
            ),
            (
                &self.profile_actions,
                &[
                    CapabilityActionId::MESSAGE_CREATE,
                    CapabilityActionId::TYPING_BROADCAST,
                ][..],
            ),
        ] {
            if actions.len() > allowed.len()
                || actions
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    != actions.len()
                || actions.iter().any(|a| !allowed.contains(&a.as_str()))
            {
                return Err(WireError::Protocol(
                    "Signal product authority names an unrelated action".into(),
                ));
            }
        }
        fn validate_grants(
            grants: &[CapabilityGrant],
            realm: &RealmId,
            actor: &ActorId,
        ) -> Result<()> {
            let mut seen = std::collections::BTreeSet::new();
            if grants.len() > 64 || grants.iter().any(|grant|
                grant.status != crate::governance::grant_constraint::CapabilityGrantStatus::Active
                || grant.realm_id.as_ref() != Some(realm)
                || !matches!(&grant.subject, crate::governance::grant_constraint::CapabilitySubject::Actor(subject) if subject == actor)
                || !seen.insert(grant.id.clone())) {
                return Err(WireError::Protocol("Signal product grants differ from the verified actor".into()));
            }
            Ok(())
        }
        validate_grants(&self.grants, &envelope.realm_id, &envelope.sender_actor_id)?;
        validate_grants(
            &self.current_grants,
            &envelope.realm_id,
            &envelope.sender_actor_id,
        )?;
        for policies in [
            &self.historical_product_policies,
            &self.current_product_policies,
        ] {
            if policies.len() > 64
                || policies.iter().any(|policy| {
                    policy.realm_id.as_ref() != Some(&envelope.realm_id)
                        || !matches!(
                            policy.policy_kind,
                            PolicyKind::Access | PolicyKind::Moderation
                        )
                        || policy.validate().is_err()
                })
            {
                return Err(WireError::Protocol(
                    "Signal product policies differ from their scope".into(),
                ));
            }
        }
        if scope_stream == realm_stream && self.current_realm_head != self.current_scope_head {
            return Err(WireError::Protocol(
                "Signal product Realm heads differ".into(),
            ));
        }
        if let Some(agent) = &self.agent {
            let controller = ActorId::account(agent.controller_account_id.clone());
            if controller == envelope.sender_actor_id
                || agent.historical_controller_owner_actions.len() > 1
                || agent.current_controller_owner_actions.len() > 1
                || agent.key_scope.actions.is_empty()
                || agent.key_scope.resources.is_empty()
                || agent
                    .historical_controller_owner_actions
                    .iter()
                    .chain(&agent.current_controller_owner_actions)
                    .any(|a| !matches!(a.as_str(), CapabilityActionId::MESSAGE_CREATE))
            {
                return Err(WireError::Protocol(
                    "Signal Agent controller authority differs".into(),
                ));
            }
            validate_grants(&agent.controller_grants, &envelope.realm_id, &controller)?;
            validate_grants(
                &agent.current_controller_grants,
                &envelope.realm_id,
                &controller,
            )?;
            for policies in [
                &agent.historical_management_policies,
                &agent.current_management_policies,
            ] {
                if policies.len() > 64
                    || policies.iter().any(|p| {
                        p.realm_id.as_ref() != Some(&envelope.realm_id)
                            || p.policy_kind != PolicyKind::Agent
                    })
                {
                    return Err(WireError::Protocol(
                        "Signal Agent management material differs".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

fn station_key_error(code: ErrorCode, message: &str) -> WireError {
    WireError::ProtocolCode {
        code,
        message: message.into(),
    }
}

/// Counterpart: `signal-stream-frame.schema.json#/$defs/delivery_authority`.
/// Product Signal projection; invitation delivery views require a separate
/// supported representation and are rejected by this closed decoder.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalDeliveryAuthority {
    pub recipient_account_id: AccountId,
    pub key: StationSigningKey,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub product_authority: Option<Box<SignalProductAuthority>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub call_invitation: Option<Box<crate::call_invitation::CallInvitationDeliveryView>>,
}

impl SignalDeliveryAuthority {
    pub fn validate_for_envelope(&self, envelope: &SignalEnvelope) -> Result<()> {
        self.recipient_account_id.validate()?;
        self.key.validate()?;
        if self.key.actor != envelope.sender_actor_id
            || self.key.verification_method != envelope.proof.verification_method
        {
            return Err(station_key_error(
                ErrorCode::SchemaViolation,
                "Signal delivery authority does not bind the exact sender",
            ));
        }
        if let Some(delivery) = &self.call_invitation {
            delivery.validate_for_envelope(envelope, &self.recipient_account_id)?;
        }
        if let Some(authority) = &self.product_authority {
            authority.validate_for_envelope(envelope)?;
        }
        Ok(())
    }
}

/// Counterpart: `signal-stream-frame.schema.json`.
/// Closed frame union for `ak.self.signal.stream.subscribe.v1`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
// Tagged wire union; boxing a variant changes the public constructor shape
// without changing the JSON.
#[allow(clippy::large_enum_variant)]
pub enum SignalStreamFrame {
    Signal {
        envelope: SignalEnvelope,
        delivery_authority: SignalDeliveryAuthority,
    },
    Heartbeat,
    Drain {
        #[serde(skip_serializing_if = "Option::is_none")]
        reconnect_after_ms: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    Unauthorized {
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

impl SignalStreamFrame {
    pub fn signal(envelope: SignalEnvelope, delivery_authority: SignalDeliveryAuthority) -> Self {
        Self::Signal {
            envelope,
            delivery_authority,
        }
    }

    pub const HEARTBEAT: Self = Self::Heartbeat;

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Signal {
                envelope,
                delivery_authority,
            } => {
                envelope.validate_structural()?;
                delivery_authority.validate_for_envelope(envelope)
            }
            Self::Heartbeat => Ok(()),
            Self::Drain {
                reconnect_after_ms,
                reason,
            } => {
                if reconnect_after_ms
                    .is_some_and(|value| value > MAX_SIGNAL_STREAM_RECONNECT_AFTER_MS)
                {
                    return Err(WireError::Protocol(format!(
                        "Signal drain reconnect_after_ms exceeds \
                         {MAX_SIGNAL_STREAM_RECONNECT_AFTER_MS}"
                    )));
                }
                validate_signal_stream_reason(reason.as_deref())
            }
            Self::Unauthorized { reason } => validate_signal_stream_reason(reason.as_deref()),
        }
    }
}

fn validate_signal_stream_reason(reason: Option<&str>) -> Result<()> {
    if reason.is_some_and(|value| value.chars().count() > MAX_SIGNAL_STREAM_REASON_CHARS) {
        return Err(WireError::Protocol(format!(
            "Signal stream reason exceeds {MAX_SIGNAL_STREAM_REASON_CHARS} characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Duration, TimeZone, Utc};

    use super::*;
    fn realm() -> RealmId {
        RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI").unwrap()
    }

    fn sent_at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 28, 12, 0, 0).unwrap()
    }

    fn actor() -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ))
    }

    fn actor_did() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn device() -> DeviceId {
        DeviceId::new("ak:device:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap()
    }

    fn envelope(signal_class: SignalClass, ttl_seconds: i64) -> SignalEnvelope {
        test_support::structural_signal_envelope_at(
            ScopeRef::Realm { realm_id: realm() },
            actor(),
            device(),
            DidUrl::new(format!("{}#{}", actor_did(), device())).unwrap(),
            RealmCommitId::from_digest([0xaa; 32]),
            signal_class,
            sent_at(),
            sent_at() + Duration::seconds(ttl_seconds),
        )
    }

    #[test]
    fn product_material_is_bound_closed_and_bounded() {
        let envelope = envelope(SignalClass::Session, 30);
        let head = CommitStreamHead {
            stream_ref: CommitStreamRef::Realm { realm_id: realm() },
            commit_id: envelope.authority_commit_id.clone(),
            stream_position: 7,
        };
        let product = SignalProductAuthority {
            authority_commit_id: envelope.authority_commit_id.clone(),
            parent_realm_authority_commit_id: None,
            current_realm_head: head.clone(),
            current_scope_head: head,
            sent_at: envelope.sent_at,
            grants: vec![],
            current_grants: vec![],
            historical_product_policies: vec![],
            current_product_policies: vec![],
            owner_actions: vec![],
            profile_actions: vec![],
            agent: None,
        };
        product.validate_for_envelope(&envelope).unwrap();
        for field in ["historical_product_policies", "current_product_policies"] {
            let mut missing = serde_json::to_value(&product).unwrap();
            missing.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<SignalProductAuthority>(missing).is_err());
        }
        let mut typing_profile = product.clone();
        typing_profile.profile_actions = vec![
            CapabilityActionId::MESSAGE_CREATE.into(),
            CapabilityActionId::TYPING_BROADCAST.into(),
        ];
        typing_profile.validate_for_envelope(&envelope).unwrap();
        typing_profile.owner_actions = vec![CapabilityActionId::TYPING_BROADCAST.into()];
        assert!(typing_profile.validate_for_envelope(&envelope).is_err());
        let mut wrong_role = product.clone();
        wrong_role.owner_actions = vec![CapabilityActionId::MESSAGE_STREAM_SEND.into()];
        assert!(wrong_role.validate_for_envelope(&envelope).is_err());
        let mut wrong = product.clone();
        wrong.authority_commit_id = RealmCommitId::from_digest([0xbb; 32]);
        assert!(wrong.validate_for_envelope(&envelope).is_err());
        let mut wrong = product.clone();
        wrong.sent_at += Duration::milliseconds(1);
        assert!(wrong.validate_for_envelope(&envelope).is_err());
        let mut wrong = product.clone();
        wrong.current_scope_head.commit_id = RealmCommitId::from_digest([0xbb; 32]);
        assert!(wrong.validate_for_envelope(&envelope).is_err());
        for field in ["parent_realm_authority_commit_id", "agent"] {
            let mut value = serde_json::to_value(&product).unwrap();
            value[field] = serde_json::Value::Null;
            assert!(serde_json::from_value::<SignalProductAuthority>(value).is_err());
        }
        let mut value = serde_json::to_value(&product).unwrap();
        value["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SignalProductAuthority>(value).is_err());
        let mut oversized = product;
        oversized.owner_actions = vec!["x".repeat(SignalProductAuthority::MAX_CANONICAL_BYTES)];
        assert!(oversized.validate_for_envelope(&envelope).is_err());
    }

    #[test]
    fn stream_frames_are_closed_and_bounded() {
        let envelope = envelope(SignalClass::Session, 30);
        let authority = SignalDeliveryAuthority {
            call_invitation: None,
            product_authority: None,
            recipient_account_id: envelope.sender_actor_id.as_account_id().unwrap().clone(),
            key: StationSigningKey {
                actor: envelope.sender_actor_id.clone(),
                verification_method: envelope.proof.verification_method.clone(),
                public_key_base64url: Base64UrlString::new("A".repeat(43)).unwrap(),
                authorization_ref: EventId::from_digest(canonical::DigestSuite::Sha256, [0x42; 32]),
            },
        };
        let mut unsupported = serde_json::to_value(&authority).unwrap();
        unsupported["unregistered_invitation"] = serde_json::json!({});
        let error = serde_json::from_value::<SignalDeliveryAuthority>(unsupported).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unknown field `unregistered_invitation`")
        );
        let mut malformed = serde_json::to_value(&authority).unwrap();
        malformed["call_invitation"] = serde_json::json!({});
        assert!(serde_json::from_value::<SignalDeliveryAuthority>(malformed).is_err());
        let signal = SignalStreamFrame::signal(envelope, authority);
        signal.validate().unwrap();
        assert_eq!(
            serde_json::to_value(signal).unwrap()["kind"],
            serde_json::json!("signal")
        );
        assert_eq!(
            serde_json::to_value(SignalStreamFrame::HEARTBEAT).unwrap(),
            serde_json::json!({"kind": "heartbeat"})
        );
        assert!(
            SignalStreamFrame::Drain {
                reconnect_after_ms: Some(MAX_SIGNAL_STREAM_RECONNECT_AFTER_MS + 1),
                reason: None,
            }
            .validate()
            .is_err()
        );
        assert!(
            SignalStreamFrame::Unauthorized {
                reason: Some("x".repeat(MAX_SIGNAL_STREAM_REASON_CHARS + 1)),
            }
            .validate()
            .is_err()
        );
    }
}
