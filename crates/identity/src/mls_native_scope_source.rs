//! Pure method-native H signature and exact-query association checks.
//! G/H role, original lineage, complete census/candidate selection and held
//! membership/fence cuts are native owner obligations, never verified here.

use arkret_models_crypto::{MlsNativeScopeSourceRequestBody, MlsNativeScopeSourceResponseBody};
use arkret_models_identity::AuthenticatedServiceResolution;
use arkret_wire::DidUrl;
use chrono::{DateTime, Utc};

use crate::{IdentityError, Result, VerifiedRealmAuthority};

fn invalid(detail: impl core::fmt::Display) -> IdentityError {
    arkret_wire::WireError::ProtocolCode {
        code: arkret_wire::ErrorCode::SignatureInvalid,
        message: format!("native scope source {detail}"),
    }
    .into()
}

/// The receiving H may use its independently verified fresh current bundle
/// here. A local native G record remains with its own locked transaction;
/// neither a request body nor this cryptographic helper creates that role.
pub fn verify_mls_native_scope_source_request_authority(
    request: &MlsNativeScopeSourceRequestBody,
    authority: &VerifiedRealmAuthority,
    now: DateTime<Utc>,
) -> Result<()> {
    request.validate().map_err(invalid)?;
    if authority.realm_id() != &request.realm_id
        || authority.current_service_id() != &request.source_id
        || !authority.binds_current_authority(
            authority.current_generation(),
            &request.governance_authority_ref,
        )
        || authority
            .current_assertion_expires_at()
            .is_none_or(|end| now >= end)
    {
        return Err(invalid(
            "requester is not that verified current authority tenure",
        ));
    }
    Ok(())
}

/// `expected_query` must come from G's original operation and its actual final
/// held basis. A caller-supplied expected body is not a native qualification.
/// `peer_deadline` is the real signed request's earliest expiry/freshness bound.
/// Verify every required pair and the complete source collection before effects.
pub fn verify_mls_native_scope_source_pair(
    request: &MlsNativeScopeSourceRequestBody,
    response: &MlsNativeScopeSourceResponseBody,
    expected_query: &MlsNativeScopeSourceRequestBody,
    owning_h: &AuthenticatedServiceResolution,
    now: DateTime<Utc>,
    peer_deadline: DateTime<Utc>,
) -> Result<()> {
    response.validate_for_request(request).map_err(invalid)?;
    if request != expected_query {
        return Err(invalid("original request or held G basis changed"));
    }
    let qualification = &response.qualification;
    if qualification.issued_at > now
        || now >= qualification.expires_at
        || qualification.expires_at > peer_deadline
    {
        return Err(invalid("native source or original peer window closed"));
    }
    let method = DidUrl::new(response.signature.kid.as_str()).map_err(invalid)?;
    crate::content_scope_cleanup::verify_signature(
        owning_h,
        &request.destination_id,
        qualification.issued_at,
        &method,
        &response.signature,
        &response.signing_bytes(request).map_err(invalid)?,
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "mls_native_scope_source/tests.rs"]
mod tests;
