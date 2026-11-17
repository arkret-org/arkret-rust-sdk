//! Restricted native scope source wire carriers and byte-only invariants.
//! Native current, genuine joined candidates, original leaf provenance and
//! held permanent fences remain obligations of the owning G/H transactions.

use arkret_wire::{
    AccountId, ActorId, Base64UrlString, DidCoreId, EventId, Hash, RealmCommitAuthorityRef,
    RealmId, ScopeRef, SidecarId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{ContentEndpoint, KeyOperationSignature, KeyPackagesClaimQueryRequestBody};

mod basis;
pub use basis::*;

fn invalid(detail: impl core::fmt::Display) -> arkret_wire::WireError {
    arkret_wire::WireError::Protocol(format!("native scope source {detail}"))
}

fn sha256_ref(value: &Hash) -> arkret_wire::Result<()> {
    let Some(hex) = value.as_str().strip_prefix("sha256:") else {
        return Err(invalid("requires its registered SHA256 digest"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    {
        return Err(invalid("digest is not canonical lowercase SHA256"));
    }
    Ok(())
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsNativeScopeMemberJoin {
    pub agent_actor_id: ActorId,
    pub join_event_ref: EventId,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsNativeScopeMembershipBasis {
    pub sidecar_id: SidecarId,
    pub controller_account_id: AccountId,
    pub sidecar_create_event_ref: EventId,
    pub controller_join_event_ref: EventId,
    pub candidate_joins: Vec<MlsNativeScopeMemberJoin>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MlsNativeScopeSourcePurpose {
    MlsAdmission,
    SidecarView,
    GroupStateMaterial,
    RosterAuthority,
    WelcomeBootstrap,
    PayloadDelivery,
}

/// Reuses the old closed claim-id shape without inheriting that operation's
/// ACL. An authorization reference is resolved from H's real accepted source.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum MlsNativeScopeEndpointSource {
    Authorization { authorization_event_ref: EventId },
    Claim(KeyPackagesClaimQueryRequestBody),
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsNativeScopeSourceRequestBody {
    pub source_id: DidCoreId,
    pub destination_id: DidCoreId,
    pub query_nonce_base64url: Base64UrlString,
    pub realm_id: RealmId,
    pub effective_scope: ScopeRef,
    pub governance_authority_ref: RealmCommitAuthorityRef,
    pub purpose: MlsNativeScopeSourcePurpose,
    pub original_request_digest: Hash,
    pub g_basis_digest: Hash,
    pub endpoint_sources: Vec<MlsNativeScopeEndpointSource>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub genesis_event_ref: Option<EventId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub sidecar_membership_basis: Option<MlsNativeScopeMembershipBasis>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum MlsNativeScopeEndpointQualification {
    Qualified {
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
        )]
        endpoint: Option<Box<ContentEndpoint>>,
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
        )]
        keypackage_ref: Option<Hash>,
    },
    Ineligible,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsNativeScopeQualification {
    pub endpoint_qualifications: Vec<MlsNativeScopeEndpointQualification>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub desired_qualifications: Option<Vec<bool>>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsNativeScopeSourceResponseBody {
    pub qualification: MlsNativeScopeQualification,
    pub signature: KeyOperationSignature,
}

impl MlsNativeScopeSourceRequestBody {
    /// Shape/canonical projection only. A valid EventId is not an access grant.
    pub fn validate(&self) -> arkret_wire::Result<()> {
        if self.effective_scope.realm_id_opt() != Some(&self.realm_id)
            || !matches!(
                self.effective_scope,
                ScopeRef::Realm { .. } | ScopeRef::Circle { .. } | ScopeRef::Sidecar { .. }
            )
        {
            return Err(invalid("effective scope differs from the native Realm"));
        }
        self.effective_scope.canonical_mls_group_id()?;
        sha256_ref(&self.original_request_digest)?;
        sha256_ref(&self.g_basis_digest)?;
        let nonce = arkret_canonical::base64url_decode(self.query_nonce_base64url.as_str())
            .map_err(invalid)?;
        if nonce.len() != 32
            || arkret_canonical::base64url_encode(&nonce) != self.query_nonce_base64url.as_str()
        {
            return Err(invalid("challenge is not canonical 32-byte base64url"));
        }
        let mut sources = std::collections::BTreeSet::new();
        for source in &self.endpoint_sources {
            if !sources.insert(arkret_canonical::canonical_json_bytes(source)?) {
                return Err(invalid("endpoint selectors are not unique"));
            }
        }
        match (&self.effective_scope, &self.sidecar_membership_basis) {
            (ScopeRef::Sidecar { sidecar_id, .. }, Some(basis)) => {
                if sidecar_id != &basis.sidecar_id
                    || basis.sidecar_id != SidecarId::from_event_id(&basis.sidecar_create_event_ref)
                    || basis.controller_account_id.station_id != self.destination_id
                {
                    return Err(invalid("Sidecar basis or fixed owning H differs"));
                }
                let mut previous: Option<Vec<u8>> = None;
                for candidate in &basis.candidate_joins {
                    candidate.agent_actor_id.validate()?;
                    let account = candidate
                        .agent_actor_id
                        .as_account_id()
                        .ok_or_else(|| invalid("candidate is not a complete Account Actor"))?;
                    if account.station_id != self.destination_id {
                        return Err(invalid("candidate is not fixed at owning H"));
                    }
                    let bytes = arkret_canonical::canonical_json_bytes(&candidate.agent_actor_id)?;
                    if previous.as_ref().is_some_and(|old| old >= &bytes) {
                        return Err(invalid("candidate Actors are not JCS sorted and unique"));
                    }
                    previous = Some(bytes);
                }
            }
            (ScopeRef::Sidecar { .. }, None) | (_, Some(_)) => {
                return Err(invalid("complete Sidecar basis is missing or misplaced"));
            }
            (_, None) => {
                if self.purpose != MlsNativeScopeSourcePurpose::MlsAdmission {
                    return Err(invalid("registered non-admission use requires Sidecar"));
                }
            }
        }
        Ok(())
    }
}

impl MlsNativeScopeQualification {
    /// Validate association before signing or after parsing. This does not
    /// establish native current or a complete G-selected source collection.
    pub fn validate_for_request(
        &self,
        request: &MlsNativeScopeSourceRequestBody,
    ) -> arkret_wire::Result<()> {
        request.validate()?;
        if self.issued_at >= self.expires_at
            || self.endpoint_qualifications.len() != request.endpoint_sources.len()
        {
            return Err(invalid("source window or endpoint association differs"));
        }
        for (source, qualification) in request
            .endpoint_sources
            .iter()
            .zip(&self.endpoint_qualifications)
        {
            match (source, qualification) {
                (_, MlsNativeScopeEndpointQualification::Ineligible) => {}
                (
                    MlsNativeScopeEndpointSource::Authorization { .. },
                    MlsNativeScopeEndpointQualification::Qualified {
                        endpoint: None,
                        keypackage_ref: None,
                    },
                ) => {}
                (
                    MlsNativeScopeEndpointSource::Claim(_),
                    MlsNativeScopeEndpointQualification::Qualified {
                        endpoint: Some(endpoint),
                        keypackage_ref: Some(package),
                    },
                ) => {
                    endpoint.validate()?;
                    let account = endpoint.actor_id.as_account_id().ok_or_else(|| {
                        invalid("selected native endpoint is not an Account Actor")
                    })?;
                    if account.station_id != request.destination_id {
                        return Err(invalid("selected endpoint is not fixed at owning H"));
                    }
                    sha256_ref(package)?;
                }
                _ => {
                    return Err(invalid(
                        "qualification copies an endpoint or loses its selected package",
                    ));
                }
            }
        }
        match (
            &request.sidecar_membership_basis,
            &self.desired_qualifications,
        ) {
            (Some(basis), Some(values)) if basis.candidate_joins.len() == values.len() => {}
            (None, None) => {}
            _ => {
                return Err(invalid(
                    "desired qualifications do not cover the exact raw candidate basis",
                ));
            }
        }
        Ok(())
    }

    /// Pure projection into the unchanged five-member participant digest.
    /// Verify the source signature and native G/H cuts before using this data.
    pub fn desired_agent_ids_for(
        &self,
        request: &MlsNativeScopeSourceRequestBody,
    ) -> arkret_wire::Result<Option<Vec<DidCoreId>>> {
        self.validate_for_request(request)?;
        let (Some(basis), Some(values)) = (
            &request.sidecar_membership_basis,
            &self.desired_qualifications,
        ) else {
            return Ok(None);
        };
        let mut ids = basis
            .candidate_joins
            .iter()
            .zip(values)
            .filter_map(|(candidate, desired)| {
                desired.then(|| candidate.agent_actor_id.signing_principal_id().clone())
            })
            .collect::<Vec<_>>();
        ids.sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
        ids.dedup();
        Ok(Some(ids))
    }
}

/// The sole unsigned signing projection. No dummy signature or copied common
/// request fields are needed to prepare an H source.
pub fn mls_native_scope_source_signing_bytes(
    request: &MlsNativeScopeSourceRequestBody,
    qualification: &MlsNativeScopeQualification,
) -> arkret_wire::Result<Vec<u8>> {
    qualification.validate_for_request(request)?;
    let value = serde_json::json!({ "request": request, "qualification": qualification });
    let mut bytes = b"ak.mls.native_scope_source.v1\n".to_vec();
    bytes.extend(arkret_canonical::canonical_json_bytes(&value)?);
    Ok(bytes)
}

impl MlsNativeScopeSourceResponseBody {
    pub fn validate_for_request(
        &self,
        request: &MlsNativeScopeSourceRequestBody,
    ) -> arkret_wire::Result<()> {
        self.qualification.validate_for_request(request)?;
        let signature = arkret_canonical::base64url_decode(self.signature.signature.as_str())
            .map_err(invalid)?;
        arkret_wire::DidUrl::new(self.signature.kid.as_str()).map_err(invalid)?;
        if signature.len() != 64
            || arkret_canonical::base64url_encode(&signature) != self.signature.signature.as_str()
            || self
                .signature
                .signature_algorithm
                .as_ref()
                .is_some_and(|value| value.as_str() != "Ed25519")
        {
            return Err(invalid("Service Ed25519 signature shape differs"));
        }
        Ok(())
    }

    pub fn signing_bytes(
        &self,
        request: &MlsNativeScopeSourceRequestBody,
    ) -> arkret_wire::Result<Vec<u8>> {
        mls_native_scope_source_signing_bytes(request, &self.qualification)
    }
}

#[cfg(test)]
#[path = "mls_native_scope_source/tests.rs"]
mod tests;
