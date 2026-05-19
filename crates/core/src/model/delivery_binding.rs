use super::*;

/// Per-Space binding of a member to a concrete delivery target service.
///
/// Authoritative source for Space-scoped event / sync / to-device / push /
/// key-package delivery. Senders MUST NOT consult the actor's DID Document
/// service entry as an alternative resolution path when this binding is
/// present. Pairwise / unlinkability use-cases are orthogonal — see
/// `identity-did.md` and the pairwise DID guidance.
///
/// Spec source: `event-payload.schema.json#/$defs/member_delivery_binding`
/// (commit 0a5ab85, 2026-05-19).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct MemberDeliveryBinding {
    pub recipient_service_did: Did,
    #[serde(default = "default_recipient_service_type")]
    pub recipient_service_type: RecipientServiceType,
    #[serde(default = "default_binding_scope")]
    pub binding_scope: BindingScope,
    pub binding_source: BindingSource,
    pub delivery_modes: BTreeSet<DeliveryMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_hash: Option<Hash>,
    pub resolved_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_acceptance_ref: Option<EventRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder_proof_ref: Option<EventRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<EventRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

fn default_recipient_service_type() -> RecipientServiceType {
    RecipientServiceType::PrincipalServer
}

fn default_binding_scope() -> BindingScope {
    BindingScope::Space
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RecipientServiceType {
    PrincipalServer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum BindingScope {
    Space,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum BindingSource {
    Explicit,
    DidDocumentDefault,
    Invite,
    JoinPolicy,
    OrganizationPolicy,
    SpacePolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
                if self.did_document_hash.is_none() {
                    return Err(Error::Protocol(
                        "binding_source=did_document_default requires did_document_hash"
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
                if self.service_acceptance_ref.is_none() || self.policy_ref.is_none() {
                    return Err(Error::Protocol(
                        "binding_source=organization_policy requires service_acceptance_ref + \
                         policy_ref"
                            .to_owned(),
                    ));
                }
            }
            BindingSource::JoinPolicy | BindingSource::SpacePolicy => {
                if self.policy_ref.is_none() {
                    return Err(Error::Protocol(format!(
                        "binding_source={:?} requires policy_ref",
                        self.binding_source
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Membership delivery routability flag carried on `cx.member.state{join}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DeliveryStatus {
    Routable,
    Unroutable,
}

/// Composite cell-subject key for `cx.device.push_route` events.
///
/// Scope: `(recipient_service_did, principal_id, device_id, push_route)`.
/// `push_target_id` MUST be derived against this scope; push registration
/// MUST be scoped to the current Principal Server's service DID.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct PushRouteScope {
    pub recipient_service_did: Did,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub push_route: String,
}

/// Per-device push route binding payload (`cx.device.push_route`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct DevicePushRoutePayload {
    pub recipient_service_did: Did,
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
            recipient_service_did: self.recipient_service_did.clone(),
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
        Did::new(format!("did:web:{label}.example")).unwrap()
    }

    fn fake_event_ref() -> EventRef {
        EventRef::new(
            "cx:event:01890000-0000-7000-8000-000000000001".to_owned(),
            "authorized_by".to_owned(),
        )
    }

    #[test]
    fn binding_requires_modes() {
        let mut b = MemberDeliveryBinding {
            recipient_service_did: fake_did("rs"),
            recipient_service_type: RecipientServiceType::PrincipalServer,
            binding_scope: BindingScope::Space,
            binding_source: BindingSource::Explicit,
            delivery_modes: BTreeSet::new(),
            service_endpoint: None,
            did_document_hash: None,
            resolved_at: Utc::now(),
            service_acceptance_ref: Some(fake_event_ref()),
            holder_proof_ref: None,
            policy_ref: None,
            expires_at: None,
        };
        assert!(b.validate().is_err());
        b.delivery_modes.insert(DeliveryMode::Events);
        assert!(b.validate().is_ok());
    }

    #[test]
    fn binding_source_explicit_requires_acceptance_ref() {
        let b = MemberDeliveryBinding {
            recipient_service_did: fake_did("rs"),
            recipient_service_type: RecipientServiceType::PrincipalServer,
            binding_scope: BindingScope::Space,
            binding_source: BindingSource::Explicit,
            delivery_modes: [DeliveryMode::Events].into_iter().collect(),
            service_endpoint: None,
            did_document_hash: None,
            resolved_at: Utc::now(),
            service_acceptance_ref: None,
            holder_proof_ref: None,
            policy_ref: None,
            expires_at: None,
        };
        assert!(b.validate().is_err());
    }

    #[test]
    fn binding_source_did_document_default_requires_hash() {
        let b = MemberDeliveryBinding {
            recipient_service_did: fake_did("rs"),
            recipient_service_type: RecipientServiceType::PrincipalServer,
            binding_scope: BindingScope::Space,
            binding_source: BindingSource::DidDocumentDefault,
            delivery_modes: [DeliveryMode::Events].into_iter().collect(),
            service_endpoint: None,
            did_document_hash: None,
            resolved_at: Utc::now(),
            service_acceptance_ref: None,
            holder_proof_ref: None,
            policy_ref: None,
            expires_at: None,
        };
        assert!(b.validate().is_err());
    }
}
