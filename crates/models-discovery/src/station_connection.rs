//! Local Station connection trust, not a wire credential or DID-history proof.

use arkret_wire::{DidCoreId, ServiceKind, TrustDomainId, WireError};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{AuthMetadata, ServiceDescribe, TransportBinding};

/// Durable identity and authentication binding selected by a client/operator.
/// Dynamic features, method history and signing-key rotations are not pins.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StationConnectionBinding {
    pub service_id: DidCoreId,
    pub base_url: String,
    pub trust_domain: TrustDomainId,
    pub auth_metadata: AuthMetadata,
}

impl StationConnectionBinding {
    /// Validate origin-scoped bootstrap without a network resolver or history replay.
    pub fn from_description(
        selected_base: &Url,
        description: &ServiceDescribe,
        allow_insecure_loopback: bool,
    ) -> Result<Self, WireError> {
        validate_connection_url(selected_base, allow_insecure_loopback)?;
        description.validate()?;
        if description.service_kind != ServiceKind::Station {
            return Err(invalid("selected service is not a Station"));
        }
        let base = selected_base.as_str();
        if !base.ends_with('/') {
            return Err(invalid("selected Station base must have a trailing slash"));
        }
        let bases: Vec<_> = description
            .transport_bindings
            .iter()
            .filter_map(|binding| match binding {
                TransportBinding::HttpJson { base_url, .. } => Some(base_url.as_str()),
                _ => None,
            })
            .collect();
        if bases != [base] {
            return Err(invalid(
                "Station describe does not confirm the selected base",
            ));
        }
        let mut auth_metadata = description.auth_metadata.clone();
        let authority = auth_metadata
            .account_authority
            .as_mut()
            .ok_or_else(|| invalid("Station account authority is missing"))?;
        let gate = Url::parse(&authority.gate_account_base_url)
            .map_err(|_| invalid("Station account authority base is invalid"))?;
        validate_connection_url(&gate, allow_insecure_loopback)?;
        if gate.origin().ascii_serialization() != authority.origin.as_str() {
            return Err(invalid(
                "Station account authority origin differs from its base",
            ));
        }
        authority.extra = Default::default();
        auth_metadata.extra = Default::default();
        // Method/scopes order and inert extensions do not change authority.
        let mut methods = Vec::with_capacity(auth_metadata.methods.len());
        for mut method in auth_metadata.methods {
            method.extra = Default::default();
            method.grant_exchange.extra = Default::default();
            method.scopes.sort();
            method.scopes.dedup();
            for uri in [
                &method.issuer_uri,
                &method.provider_uri,
                &method.openid_configuration_url,
            ]
            .into_iter()
            .flatten()
            {
                let mut url = Url::parse(uri)
                    .map_err(|_| invalid("Station authentication method URL is invalid"))?;
                // Method endpoints can contain query parameters; the complete
                // advertised value remains pinned above.
                url.set_query(None);
                validate_connection_url(&url, allow_insecure_loopback)?;
            }
            let key = serde_json::to_string(&method)
                .map_err(|_| invalid("Station authentication method cannot be encoded"))?;
            methods.push((key, method));
        }
        methods.sort_by(|left, right| left.0.cmp(&right.0));
        methods.dedup_by(|left, right| left.0 == right.0);
        auth_metadata.methods = methods.into_iter().map(|(_, method)| method).collect();
        auth_metadata.did_binding_methods.sort();
        auth_metadata.did_binding_methods.dedup();
        Ok(Self {
            service_id: description.service_id.clone(),
            base_url: base.to_owned(),
            trust_domain: description.trust_domain.clone(),
            auth_metadata,
        })
    }

    /// A known/preconfigured binding is never overwritten by a self-report.
    pub fn require_same(&self, candidate: &Self) -> Result<(), WireError> {
        if self != candidate {
            return Err(invalid(
                "Station identity or authentication changed; explicit re-enrollment is required",
            ));
        }
        Ok(())
    }
}

/// Validate an explicitly selected URL; this does not infer service identity.
pub fn validate_connection_url(url: &Url, allow_insecure_loopback: bool) -> Result<(), WireError> {
    let loopback = match url.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.scheme() != "https"
            && !(allow_insecure_loopback && loopback && url.scheme() == "http"))
    {
        return Err(invalid(
            "Station connection requires HTTPS without URL credentials/query/fragment",
        ));
    }
    Ok(())
}

fn invalid(message: &str) -> WireError {
    WireError::Protocol(message.to_owned())
}
