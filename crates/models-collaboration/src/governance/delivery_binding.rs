use std::collections::BTreeSet;

use arkret_wire::{DeviceId, Did, Error, EventId, Hash, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Per-Realm binding of a member to a concrete delivery target service.
///
/// Authoritative source for Realm-scoped event / sync / to-device / push /
/// key-package delivery. Senders MUST NOT consult the actor's DID Document
/// service entry as an alternative resolution path when this binding is
/// present. Pairwise / unlinkability use-cases are orthogonal - see
/// `identity-did.md` and the pairwise DID guidance.
///
/// Spec source: `event-payload.schema.json#/$defs/member_delivery_binding`
/// (commit 0a5ab85, 2026-05-19).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MemberDeliveryBinding {
    pub recipient_service_id: Did,
    #[serde(default = "default_recipient_service_type")]
    pub recipient_service_type: RecipientServiceType,
    #[serde(default = "default_binding_scope")]
    pub binding_scope: BindingScope,
    pub binding_source: BindingSource,
    pub delivery_modes: BTreeSet<DeliveryMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_digest: Option<Hash>,
    pub resolved_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_acceptance_ref: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder_proof_ref: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_event_ref: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

fn default_recipient_service_type() -> RecipientServiceType {
    RecipientServiceType::PrincipalServer
}

fn default_binding_scope() -> BindingScope {
    BindingScope::Realm
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RecipientServiceType {
    PrincipalServer,
}

/// The binding is scoped to the Realm security boundary. The wire value is
/// the canonical token `"realm"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum BindingScope {
    Realm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum BindingSource {
    Explicit,
    DidDocumentDefault,
    Invite,
    JoinPolicy,
    OrganizationPolicy,
    RealmPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    Events,
    Sync,
    ToDevice,
    Push,
    KeyPackages,
}

impl MemberDeliveryBinding {
    /// Validate the schema-level conditional required fields enforced by
    /// `event-payload.schema.json` (`binding_source`-driven `allOf`).
    pub fn validate(&self) -> Result<()> {
        if self.delivery_modes.is_empty() {
            return Err(Error::Protocol(
                "member_delivery_binding.delivery_modes MUST NOT be empty".to_owned(),
            ));
        }
        match self.binding_source {
            BindingSource::DidDocumentDefault => {
                if self.did_document_digest.is_none() {
                    return Err(Error::Protocol(
                        "binding_source=did_document_default requires did_document_digest"
                            .to_owned(),
                    ));
                }
            }
            BindingSource::Explicit | BindingSource::Invite => {
                if self.service_acceptance_ref.is_none() {
                    return Err(Error::Protocol(format!(
                        "binding_source={:?} requires service_acceptance_ref",
                        self.binding_source
                    )));
                }
            }
            BindingSource::OrganizationPolicy => {
                if self.service_acceptance_ref.is_none() || self.policy_event_ref.is_none() {
                    return Err(Error::Protocol(
                        "binding_source=organization_policy requires service_acceptance_ref + \
                         policy_event_ref"
                            .to_owned(),
                    ));
                }
            }
            BindingSource::JoinPolicy | BindingSource::RealmPolicy => {
                if self.policy_event_ref.is_none() {
                    return Err(Error::Protocol(format!(
                        "binding_source={:?} requires policy_event_ref",
                        self.binding_source
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Membership delivery routability flag carried on `ak.member.state{join}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Routable,
    Unroutable,
}

/// Composite cell-subject key for `ak.device.push_route` events.
///
/// Scope: `(recipient_service_id, principal_id, device_id, push_route)`.
/// `push_target_id` MUST be derived against this scope; push registration
/// MUST be scoped to the current Principal Server's service DID.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct PushRouteScope {
    pub recipient_service_id: Did,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub push_route: String,
}

/// Per-device push route binding payload (`ak.device.push_route`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct DevicePushRoutePayload {
    pub recipient_service_id: Did,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub push_route: String,
    pub push_target_id: String,
    pub push_gateway_did: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

impl DevicePushRoutePayload {
    pub fn scope(&self) -> PushRouteScope {
        PushRouteScope {
            recipient_service_id: self.recipient_service_id.clone(),
            principal_id: self.principal_id.clone(),
            device_id: self.device_id.clone(),
            push_route: self.push_route.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_did(label: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{label}.example")).unwrap()
    }

    fn fake_event_id() -> EventId {
        EventId::new("ak:event:01890000-0000-7000-8000-000000000001").unwrap()
    }

    #[test]
    fn binding_requires_modes() {
        let mut b = MemberDeliveryBinding {
            recipient_service_id: fake_did("rs"),
            recipient_service_type: RecipientServiceType::PrincipalServer,
            binding_scope: BindingScope::Realm,
            binding_source: BindingSource::Explicit,
            delivery_modes: BTreeSet::new(),
            service_endpoint: None,
            did_document_digest: None,
            resolved_at: Utc::now(),
            service_acceptance_ref: Some(fake_event_id()),
            holder_proof_ref: None,
            policy_event_ref: None,
            expires_at: None,
        };
        assert!(b.validate().is_err());
        b.delivery_modes.insert(DeliveryMode::Events);
        assert!(b.validate().is_ok());
    }

    #[test]
    fn binding_source_explicit_requires_acceptance_ref() {
        let b = MemberDeliveryBinding {
            recipient_service_id: fake_did("rs"),
            recipient_service_type: RecipientServiceType::PrincipalServer,
            binding_scope: BindingScope::Realm,
            binding_source: BindingSource::Explicit,
            delivery_modes: [DeliveryMode::Events].into_iter().collect(),
            service_endpoint: None,
            did_document_digest: None,
            resolved_at: Utc::now(),
            service_acceptance_ref: None,
            holder_proof_ref: None,
            policy_event_ref: None,
            expires_at: None,
        };
        assert!(b.validate().is_err());
    }

    /// The only legal `binding_scope` wire value is "realm". The enum has a
    /// single variant `Realm` (serialised as "realm"), so any other token
    /// fails the serde tag match.
    #[test]
    fn binding_scope_only_accepts_realm() {
        // Positive: "realm" deserialises.
        let ok: BindingScope = serde_json::from_value::<BindingScope>(serde_json::json!("realm"))
            .expect("realm MUST deserialise");
        assert_eq!(ok, BindingScope::Realm);

        // Negative: "space" is not a legal Realm binding scope.
        let err: std::result::Result<BindingScope, _> =
            serde_json::from_value(serde_json::json!("space"));
        assert!(
            err.is_err(),
            "BindingScope value 'space' MUST be rejected, got {err:?}"
        );

        // Defensive: arbitrary tokens MUST also be rejected.
        for bad in &["Realm", "REALM", "tenant", "container", ""] {
            let err: std::result::Result<BindingScope, _> =
                serde_json::from_value(serde_json::json!(*bad));
            assert!(
                err.is_err(),
                "BindingScope MUST reject `{bad}`, got {err:?}"
            );
        }
    }

    /// The full member-delivery-binding payload MUST reject "space"
    /// binding_scope at the envelope level too.
    #[test]
    fn member_delivery_binding_rejects_space_binding_scope() {
        let payload = serde_json::json!({
            "recipient_service_id": "did:webvh:z6mkfixture:rs.example",
            "recipient_service_type": "principal_server",
            "binding_scope": "space",
            "binding_source": "explicit",
            "delivery_modes": ["events"],
            "resolved_at": "2026-05-20T00:00:00Z",
            "service_acceptance_ref": {
                "id": "ak:event:01890000-0000-7000-8000-000000000001",
                "tag": "authorized_by"
            }
        });
        let parsed: std::result::Result<MemberDeliveryBinding, _> = serde_json::from_value(payload);
        assert!(
            parsed.is_err(),
            "binding_scope=space MUST be rejected at MemberDeliveryBinding deserialisation"
        );
    }

    #[test]
    fn binding_source_did_document_default_requires_hash() {
        let b = MemberDeliveryBinding {
            recipient_service_id: fake_did("rs"),
            recipient_service_type: RecipientServiceType::PrincipalServer,
            binding_scope: BindingScope::Realm,
            binding_source: BindingSource::DidDocumentDefault,
            delivery_modes: [DeliveryMode::Events].into_iter().collect(),
            service_endpoint: None,
            did_document_digest: None,
            resolved_at: Utc::now(),
            service_acceptance_ref: None,
            holder_proof_ref: None,
            policy_event_ref: None,
            expires_at: None,
        };
        assert!(b.validate().is_err());
    }
}
