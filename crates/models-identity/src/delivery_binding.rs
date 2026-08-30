use std::collections::BTreeSet;

use arkret_wire::{DeviceId, DidCoreId, EventId, Hash, PushTargetId, Result, WireError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::ServiceResolutionCarrier;

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
#[serde(deny_unknown_fields)]
pub struct MemberDeliveryBinding {
    pub recipient_id: DidCoreId,
    #[serde(default = "default_recipient_kind")]
    pub recipient_kind: RecipientServiceKind,
    #[serde(default = "default_binding_scope")]
    pub binding_scope: BindingScope,
    pub binding_source: BindingSource,
    pub delivery_modes: BTreeSet<DeliveryMode>,
    pub service_resolution: ServiceResolutionCarrier,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_digest: Option<Hash>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub resolved_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_acceptance_ref: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder_proof_ref: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_event_ref: Option<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

fn default_recipient_kind() -> RecipientServiceKind {
    RecipientServiceKind::PrincipalServer
}

fn default_binding_scope() -> BindingScope {
    BindingScope::Realm
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecipientServiceKind {
    PrincipalServer,
}

/// The binding is scoped to the Realm security boundary. The wire value is
/// the canonical token `"realm"`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingScope {
    Realm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BindingSource {
    Explicit,
    DidDocumentDefault,
    JoinPolicy,
    OrganizationPolicy,
    RealmPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    Events,
    Sync,
    ToDevice,
    Push,
    /// Wire value is the unsegmented `keypackages`, matching
    /// `member-delivery-binding-candidate.schema.json` and
    /// `governance/member-delivery-binding.md` §7.
    #[serde(rename = "keypackages")]
    KeyPackages,
}

impl MemberDeliveryBinding {
    /// Validate the schema-level conditional required fields enforced by
    /// `event-payload.schema.json` (`binding_source`-driven `allOf`).
    pub fn validate(&self) -> Result<()> {
        self.service_resolution.validate_shape(&self.recipient_id)?;
        if self.delivery_modes.is_empty() {
            return Err(WireError::Protocol(
                "member_delivery_binding.delivery_modes MUST NOT be empty".to_owned(),
            ));
        }
        match self.binding_source {
            BindingSource::DidDocumentDefault => {
                if self.document_digest.is_none() {
                    return Err(WireError::Protocol(
                        "binding_source=did_document_default requires document_digest".to_owned(),
                    ));
                }
            }
            BindingSource::Explicit => {
                if self.service_acceptance_ref.is_none() {
                    return Err(WireError::Protocol(format!(
                        "binding_source={:?} requires service_acceptance_ref",
                        self.binding_source
                    )));
                }
            }
            BindingSource::OrganizationPolicy => {
                if self.service_acceptance_ref.is_none() || self.policy_event_ref.is_none() {
                    return Err(WireError::Protocol(
                        "binding_source=organization_policy requires service_acceptance_ref + \
                         policy_event_ref"
                            .to_owned(),
                    ));
                }
            }
            BindingSource::JoinPolicy | BindingSource::RealmPolicy => {
                if self.policy_event_ref.is_none() {
                    return Err(WireError::Protocol(format!(
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
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Routable,
    Unroutable,
}

/// Composite cell-subject key for `ak.device.push_route` events.
///
/// Scope: `(recipient_id, principal_id, device_id, push_route)`.
/// `push_target_id` MUST be derived against this scope; push registration
/// MUST be scoped to the current Principal Server's service DID.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PushRouteScope {
    pub recipient_id: DidCoreId,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub push_route: String,
}

/// Closed active/revoked payload union for `ak.device.push_route`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DevicePushRoutePayload {
    Active(DevicePushRouteActivePayload),
    Revoked(DevicePushRouteRevokedPayload),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePushRouteActivePayload {
    pub recipient_id: DidCoreId,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub push_route: String,
    pub expected_revision: u64,
    pub push_target_id: PushTargetId,
    pub push_gateway_id: DidCoreId,
    pub encryption_key: String,
    pub capabilities: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DevicePushRouteRevokedPayload {
    pub recipient_id: DidCoreId,
    pub principal_id: DidCoreId,
    pub device_id: DeviceId,
    pub push_route: String,
    pub expected_revision: u64,
    pub revoked: PushRouteRevokedMarker,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PushRouteRevokedMarker;

impl Serialize for PushRouteRevokedMarker {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for PushRouteRevokedMarker {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if bool::deserialize(deserializer)? {
            Ok(Self)
        } else {
            Err(de::Error::custom("revoked must be true"))
        }
    }
}

impl DevicePushRoutePayload {
    pub fn scope(&self) -> PushRouteScope {
        let (recipient_id, principal_id, device_id, push_route) = match self {
            Self::Active(value) => (
                &value.recipient_id,
                &value.principal_id,
                &value.device_id,
                &value.push_route,
            ),
            Self::Revoked(value) => (
                &value.recipient_id,
                &value.principal_id,
                &value.device_id,
                &value.push_route,
            ),
        };
        PushRouteScope {
            recipient_id: recipient_id.clone(),
            principal_id: principal_id.clone(),
            device_id: device_id.clone(),
            push_route: push_route.clone(),
        }
    }

    pub const fn expected_revision(&self) -> u64 {
        match self {
            Self::Active(value) => value.expected_revision,
            Self::Revoked(value) => value.expected_revision,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_service(label: &str) -> DidCoreId {
        DidCoreId::new(format!("ak:did_core:webvh:z6mkfixture{label}")).unwrap()
    }

    fn fake_event_id() -> EventId {
        EventId::new("ak:event:ATYeQ_3uy7u8Z1cbK6nfFvEpFMXMcbNvQJsXqt-4f03A").unwrap()
    }

    fn fake_resolution(label: &str) -> ServiceResolutionCarrier {
        let service_id = fake_service(label);
        ServiceResolutionCarrier::CurrentRecordUrl {
            current_record_url: format!(
                "https://service.example{}",
                crate::canonical_service_current_record_path(&service_id)
            ),
            pinned_record_digest: None,
        }
    }

    #[test]
    fn binding_requires_modes() {
        let mut b = MemberDeliveryBinding {
            recipient_id: fake_service("rs"),
            recipient_kind: RecipientServiceKind::PrincipalServer,
            binding_scope: BindingScope::Realm,
            binding_source: BindingSource::Explicit,
            delivery_modes: BTreeSet::new(),
            service_resolution: fake_resolution("rs"),
            document_digest: None,
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
            recipient_id: fake_service("rs"),
            recipient_kind: RecipientServiceKind::PrincipalServer,
            binding_scope: BindingScope::Realm,
            binding_source: BindingSource::Explicit,
            delivery_modes: [DeliveryMode::Events].into_iter().collect(),
            service_resolution: fake_resolution("rs"),
            document_digest: None,
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
            "recipient_id": "ak:did_core:webvh:z6mkfixturers",
            "recipient_kind": "principal_server",
            "binding_scope": "space",
            "binding_source": "explicit",
            "delivery_modes": ["events"],
            "resolved_at": "2026-05-20T00:00:00.000Z",
            "service_acceptance_ref": {
                "id": "ak:event:ATYeQ_3uy7u8Z1cbK6nfFvEpFMXMcbNvQJsXqt-4f03A",
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
            recipient_id: fake_service("rs"),
            recipient_kind: RecipientServiceKind::PrincipalServer,
            binding_scope: BindingScope::Realm,
            binding_source: BindingSource::DidDocumentDefault,
            delivery_modes: [DeliveryMode::Events].into_iter().collect(),
            service_resolution: fake_resolution("rs"),
            document_digest: None,
            resolved_at: Utc::now(),
            service_acceptance_ref: None,
            holder_proof_ref: None,
            policy_event_ref: None,
            expires_at: None,
        };
        assert!(b.validate().is_err());
    }
}
