//! Directory consumption has distinct independent-provider and own-Station roles.
use std::collections::BTreeMap;

pub use arkret_egress_policy::OutboundPolicy;
use arkret_models_collaboration::objects::interop::ProviderDirectory;
use arkret_models_discovery::StationConnectionBinding;
use arkret_models_identity::DidDocument;
use arkret_wire::{Did, DidCoreId, MimiUri};
use chrono::{DateTime, Utc};
use url::Url;

use crate::{Error, Result};

fn protocol(error: impl std::fmt::Display) -> Error {
    Error::Protocol(error.to_string())
}

#[derive(Clone, Debug)]
struct DirectoryReadBinding {
    service_id: DidCoreId,
    base_url: Url,
    max_age: chrono::Duration,
    egress: OutboundPolicy,
}
impl DirectoryReadBinding {
    fn new(
        service_id: DidCoreId,
        base_url: Url,
        max_age: chrono::Duration,
        egress: OutboundPolicy,
    ) -> Result<Self> {
        if max_age <= chrono::Duration::zero()
            || base_url.scheme() != "https"
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            return Err(protocol(
                "directory needs HTTPS and a positive explicit freshness policy",
            ));
        }
        Ok(Self {
            service_id,
            base_url,
            max_age,
            egress,
        })
    }
    fn check_request_origin(&self, base: &Url) -> Result<()> {
        if base.origin() != self.base_url.origin() {
            return Err(protocol(
                "directory transport origin differs from accepted service",
            ));
        }
        self.egress.validate_url(base).map_err(protocol)?;
        Ok(())
    }
    fn validate(
        &self,
        directory: &ProviderDirectory,
        provider: Option<&MimiUri>,
        features: &[String],
        now: DateTime<Utc>,
    ) -> Result<Vec<u8>> {
        directory.validate().map_err(protocol)?;
        if directory.service_id != self.service_id
            || directory.mimi.base_url != self.base_url.as_str()
            || provider.is_some_and(|expected| expected != &directory.mimi.provider_id)
            || features
                .iter()
                .any(|feature| !directory.mimi.features.contains(feature))
        {
            return Err(protocol(
                "directory does not bind the requested service, provider, base or capabilities",
            ));
        }
        let (controller, fragment) = directory
            .proof
            .0
            .verification_method
            .as_str()
            .split_once('#')
            .ok_or_else(|| protocol("directory proof needs a service assertion method"))?;
        if fragment.is_empty() || fragment.contains(['/', '?', '#']) {
            return Err(protocol("directory proof method fragment is invalid"));
        }
        arkret_signatures::service_resolution::verify_full_to_core_binding(
            &Did::new(controller).map_err(protocol)?,
            &self.service_id,
        )
        .map_err(protocol)?;
        let age = now.signed_duration_since(directory.proof.0.created_at);
        if age < chrono::Duration::zero() || age > self.max_age {
            return Err(protocol(
                "directory proof is outside the explicit freshness window",
            ));
        }
        directory.proof_binding_bytes().map_err(protocol)
    }
    fn contents(&self, mut directory: ProviderDirectory) -> Result<DirectoryContents> {
        self.egress.validate_url(&self.base_url).map_err(protocol)?;
        let mut endpoints = BTreeMap::new();
        for row in &directory.mimi.endpoints {
            let effective = self.base_url.join(&row.relative_path)?;
            if effective.origin() != self.base_url.origin() {
                return Err(protocol("directory endpoint changed origin"));
            }
            self.egress.validate_url(&effective).map_err(protocol)?;
            if directory.mimi.features.contains(&row.endpoint_id) {
                endpoints.insert(row.endpoint_id.clone(), effective);
            }
        }
        directory.extra.clear();
        directory.mimi.extra.clear();
        Ok(DirectoryContents {
            directory,
            endpoints,
        })
    }
}

/// Local trust input, never a wire proof. Independent providers supply the
/// CURRENT document accepted through the registered DID method and delegation.
/// Server-side hosts also enforce DNS/redirect policy on their Client transport;
/// URL admission here is not DNS pinning.
#[derive(Clone, Debug)]
pub struct MimiDirectoryAuthority {
    binding: DirectoryReadBinding,
    document: DidDocument,
}
impl MimiDirectoryAuthority {
    pub fn new(
        service_id: DidCoreId,
        document: DidDocument,
        base_url: Url,
        max_age: chrono::Duration,
    ) -> Result<Self> {
        document.validate().map_err(protocol)?;
        arkret_signatures::service_resolution::verify_full_to_core_binding(
            &document.id,
            &service_id,
        )
        .map_err(protocol)?;
        Ok(Self {
            binding: DirectoryReadBinding::new(
                service_id,
                base_url,
                max_age,
                OutboundPolicy::public_https(),
            )?,
            document,
        })
    }
    /// Explicit deployment policy; response metadata can never relax egress.
    pub fn with_egress_policy(mut self, policy: OutboundPolicy) -> Self {
        self.binding.egress = policy;
        self
    }
    pub(crate) fn check_request_origin(&self, base: &Url) -> Result<()> {
        self.binding.check_request_origin(base)
    }
    pub fn verify(
        &self,
        directory: ProviderDirectory,
        provider: Option<&MimiUri>,
        features: &[String],
        now: DateTime<Utc>,
    ) -> Result<VerifiedProviderDirectory> {
        let bytes = self.binding.validate(&directory, provider, features, now)?;
        arkret_signatures::service_resolution::verify_service_payload_proof(
            &self.binding.service_id,
            &self.document,
            &directory.proof.0,
            &bytes,
        )
        .map_err(protocol)?;
        Ok(VerifiedProviderDirectory {
            contents: self.binding.contents(directory)?,
        })
    }
}

#[derive(Clone, Debug)]
struct DirectoryContents {
    directory: ProviderDirectory,
    endpoints: BTreeMap<String, Url>,
}

/// Independent JWS verification result. Not deserializable or publicly
/// constructible. Senders still enforce current authority, DNS/redirects, TLS,
/// HTTP source signatures and Realm delegation before using any endpoint.
#[derive(Clone, Debug)]
pub struct VerifiedProviderDirectory {
    contents: DirectoryContents,
}
impl VerifiedProviderDirectory {
    pub fn directory(&self) -> &ProviderDirectory {
        &self.contents.directory
    }
    pub fn endpoint(&self, feature: &str) -> Option<&Url> {
        self.contents.endpoints.get(feature)
    }
}

/// An ordinary client's directory result from its accepted own Station.
/// This is deliberately not an independently verified provider proof. The
/// Station verifies original authority; the client checks exact request binding,
/// shape and digest without fetching DID or governance history (MIMI section 3).
#[derive(Clone, Debug)]
pub struct OwnStationProviderDirectory {
    contents: DirectoryContents,
    station: StationConnectionBinding,
}
impl OwnStationProviderDirectory {
    pub fn directory(&self) -> &ProviderDirectory {
        &self.contents.directory
    }
    pub fn endpoint(&self, feature: &str) -> Option<&Url> {
        self.contents.endpoints.get(feature)
    }
    pub fn station_binding(&self) -> &StationConnectionBinding {
        &self.station
    }
}

pub(crate) struct OwnStationDirectoryRead {
    binding: DirectoryReadBinding,
    station: StationConnectionBinding,
}
impl OwnStationDirectoryRead {
    pub(crate) fn new(
        station: &StationConnectionBinding,
        transport: &Url,
        max_age: chrono::Duration,
        egress: OutboundPolicy,
    ) -> Result<Self> {
        if station.base_url != transport.as_str() {
            return Err(protocol("directory own Station transport binding mismatch"));
        }
        let binding = DirectoryReadBinding::new(
            station.service_id.clone(),
            transport.join("_arkret/open/mimi")?,
            max_age,
            egress,
        )?;
        binding.check_request_origin(transport)?;
        Ok(Self {
            binding,
            station: station.clone(),
        })
    }
    pub(crate) fn accept(
        self,
        directory: ProviderDirectory,
        provider: Option<&MimiUri>,
        features: &[String],
        now: DateTime<Utc>,
    ) -> Result<OwnStationProviderDirectory> {
        self.binding.validate(&directory, provider, features, now)?;
        Ok(OwnStationProviderDirectory {
            contents: self.binding.contents(directory)?,
            station: self.station,
        })
    }
}
