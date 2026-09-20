//! Server-describe, identity, and directory endpoint methods on [`Client`].

use arkret_models_discovery::{
    DirectoryRealmResolutionOutcome, DirectoryRealmSearchOutcome, DirectoryResolveRealmRequestBody,
    DirectorySearchRealmsRequestBody, ServiceDescribe, ServiceRequirements,
};
use arkret_models_identity::actor_profile_operations::{
    ActorProfileResolveOutcome, ActorProfileResolveRequest,
};
use arkret_models_identity::service_identity::{
    SERVICE_REGISTRATION_ENSURE_PATH, SERVICE_REGISTRATION_GET_PATH,
    ServiceRegistrationEnsureRequestBody, ServiceRegistrationKey, ServiceRegistrationOutcome,
};
use arkret_models_identity::{
    AuthenticatedServiceResolution, DidOperationSubmitOutcome, DidOperationSubmitRequestBody,
    IdentityDocumentView, IdentityLogListOutcome, IdentityReceiptListOutcome,
    IdentityResolveOutcome, IdentityResolveRequestBody, PrincipalResolutionAuditEvidence,
    PrincipalResolutionAuditRequest, PublicPrincipalResolution,
};
use arkret_wire::{DidCoreId, ServiceKind};
use reqwest::Method;

use crate::{Client, Error, Result};

impl Client {
    /// Read this authenticated Account's current principal projection and unique PCR.
    pub async fn current_principal(
        &self,
        request: &arkret_models_identity::CurrentPrincipalRequestBody,
    ) -> Result<arkret_models_identity::CurrentPrincipalOutcome> {
        request.validate()?;
        let outcome: arkret_models_identity::CurrentPrincipalOutcome = self
            .post("/_arkret/self/account/current-principal", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Read the own-Station verified route and signing keys of the media
    /// service anchored by one joined Realm
    /// (`sync/server-trusted-results.md` §5.9).
    ///
    /// `accepted_service_id` is the `service_id` the caller already installed
    /// from the Realm's accepted `ak.realm.media_service` cell. A route that
    /// does not match it is rejected here rather than adopted.
    pub async fn media_service_binding(
        &self,
        request: &arkret_models_identity::MediaServiceBindingRequestBody,
        accepted_service_id: &DidCoreId,
    ) -> Result<arkret_models_identity::MediaServiceBindingOutcome> {
        request.validate()?;
        let outcome: arkret_models_identity::MediaServiceBindingOutcome = self
            .post("/_arkret/self/media-service-bindings/query", request)
            .await?;
        outcome.validate_for_request(request, accepted_service_id)?;
        Ok(outcome)
    }

    /// Read the authenticated account's exact Principal Control Realm lineage.
    ///
    /// The authority pair is an explicit selector: the server must not choose
    /// an implicit current PCR when more than one lineage exists.
    pub async fn principal_resolution_audit(
        &self,
        request: &PrincipalResolutionAuditRequest,
    ) -> Result<PrincipalResolutionAuditEvidence> {
        request.validate()?;
        let evidence: PrincipalResolutionAuditEvidence = self
            .post("/_arkret/self/identity/resolution-audit/query", request)
            .await?;
        evidence.validate_history_continuation()?;
        Ok(evidence)
    }

    /// Resolve co-member global Actor Profiles through the only outward
    /// carrier for PCR-resident profile state.
    ///
    /// `realm_id` is the authorization basis: the caller and every returned
    /// actor must be current effective joined members of it, and it must not be
    /// a Principal Control Realm. Every requested actor comes back exactly once
    /// across `profiles` and `failures`, and every per-actor failure is the
    /// single `profile_unavailable` value, so the response cannot be used to
    /// probe membership or account existence.
    ///
    /// Only that batch-wide invariant is enforced here. Whether an individual
    /// row's Event, projection and actor agree is a per-row fact, so it is left
    /// to the consumer through
    /// [`validate_resolved_actor_profile`](arkret_models_collaboration::actor_profile_resolution::validate_resolved_actor_profile):
    /// a caller degrades that one actor to unavailable rather than losing the
    /// rows that were fine, which is what the single-valued per-actor failure
    /// vocabulary is for. The returned profile projection is already bound to
    /// an accepted authority commit reference.
    pub async fn actor_profile_resolve(
        &self,
        request: &ActorProfileResolveRequest,
    ) -> Result<ActorProfileResolveOutcome> {
        request.validate()?;
        let outcome: ActorProfileResolveOutcome = self
            .post("/_arkret/self/actor-profiles/query", request)
            .await?;
        outcome.validate_covers(&request.actor_ids)?;
        Ok(outcome)
    }

    /// Fetch the current public principal resolution projection without
    /// persisting a remote binding.
    ///
    /// This surface carries no PCR material and therefore has no history
    /// selector. Sensitive callers must still verify the projection attestation
    /// and run the method adapter themselves.
    pub async fn open_principal_resolution(
        &self,
        principal_id: &DidCoreId,
        station_id: &DidCoreId,
    ) -> Result<PublicPrincipalResolution> {
        let encoded = url::form_urlencoded::byte_serialize(principal_id.as_str().as_bytes())
            .collect::<String>();
        let path = format!("/_arkret/open/principals/{encoded}/resolution");
        let builder = self
            .public_request(Method::GET, &path)?
            .query(&[("station_id", station_id.as_str())]);
        let resolution: PublicPrincipalResolution = self.send_json(builder).await?;
        resolution
            .validate_attestation_binding()
            .map_err(|error| Error::Protocol(error.to_string()))?;
        Ok(resolution)
    }

    /// Fetch the current authenticated resolution closure for one stable service id.
    ///
    /// Unlike `ServiceDescribe`, this response retains the signed route record,
    /// method-native history evidence, and normalized DID document together.
    /// The returned shape is not trusted until
    /// [`Client::open_service_signer_evidence`] verifies it.
    pub async fn open_service_resolution(
        &self,
        service_id: &DidCoreId,
    ) -> Result<AuthenticatedServiceResolution> {
        let encoded = url::form_urlencoded::byte_serialize(service_id.as_str().as_bytes())
            .collect::<String>();
        let path = format!("/_arkret/open/services/{encoded}/resolution");
        let builder = self.public_request(Method::GET, &path)?;
        self.send_json_limited(builder, 1024 * 1024).await
    }

    pub async fn describe(&self) -> Result<ServiceDescribe> {
        let builder = self.public_request(Method::GET, "/_arkret/describe")?;
        let description: ServiceDescribe = self.send_json(builder).await?;
        description.validate()?;
        Ok(description)
    }

    /// Fetches the description for exactly one co-located service role.
    pub async fn describe_for_role(&self, service_kind: ServiceKind) -> Result<ServiceDescribe> {
        if !service_kind.valid_in("service_describe") {
            return Err(Error::Protocol(format!(
                "service_kind {} is not valid for service describe",
                service_kind.as_str()
            )));
        }
        let builder = self
            .public_request(Method::GET, "/_arkret/describe")?
            .query(&[("service_kind", service_kind.as_str())]);
        let description: ServiceDescribe = self.send_json(builder).await?;
        description.validate()?;
        ServiceRequirements::new()
            .service_kind(service_kind)
            .verify(&description)?;
        Ok(description)
    }

    pub async fn identity_describe(&self) -> Result<ServiceDescribe> {
        let description: ServiceDescribe = self.get("/_arkret/root/identity/describe").await?;
        description.validate()?;
        ServiceRequirements::new()
            .service_kind(ServiceKind::IdentityRegistry)
            .verify(&description)?;
        Ok(description)
    }

    pub async fn identity_resolve(
        &self,
        request: &IdentityResolveRequestBody,
    ) -> Result<IdentityResolveOutcome> {
        self.post("/_arkret/root/identity/resolve", request).await
    }

    pub async fn identity_document(
        &self,
        did: &str,
        version: Option<&str>,
    ) -> Result<IdentityDocumentView> {
        let mut builder = self
            .request(Method::GET, "/_arkret/root/identity/document")?
            .query(&[("did", did)]);
        if let Some(version) = version {
            builder = builder.query(&[("version", version)]);
        }
        self.send_json(builder).await
    }

    pub async fn identity_log(
        &self,
        did: &str,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<IdentityLogListOutcome> {
        let mut builder = self
            .request(Method::GET, "/_arkret/root/identity/log")?
            .query(&[("did", did)]);
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn identity_submit_did_operation(
        &self,
        request: &DidOperationSubmitRequestBody,
    ) -> Result<DidOperationSubmitOutcome> {
        request.validate()?;
        let outcome: DidOperationSubmitOutcome = self
            .post("/_arkret/root/identity/submit-did-operation", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Idempotently return or create the service identity bound to the signed
    /// registration request. The returned receipt and DID-document binding are
    /// validated before the outcome reaches the caller.
    pub async fn service_registration_ensure(
        &self,
        request: &ServiceRegistrationEnsureRequestBody,
    ) -> Result<ServiceRegistrationOutcome> {
        request.validate()?;
        let outcome: ServiceRegistrationOutcome =
            self.post(SERVICE_REGISTRATION_ENSURE_PATH, request).await?;
        outcome.validate_ensure_response(request)?;
        Ok(outcome)
    }

    /// Read an existing service registration without creating identity state.
    /// The returned registration key, DID document, and receipt are validated.
    pub async fn service_registration_get(
        &self,
        key: &ServiceRegistrationKey,
    ) -> Result<ServiceRegistrationOutcome> {
        let builder = self
            .request(Method::GET, SERVICE_REGISTRATION_GET_PATH)?
            .query(&[
                ("service_kind", key.service_kind().as_str()),
                ("public_base_url", key.public_base_url().as_str()),
            ]);
        let outcome: ServiceRegistrationOutcome = self.send_json(builder).await?;
        outcome.validate_for(key)?;
        if outcome.created {
            return Err(Error::Protocol(
                "service-registration GET response must set created=false".to_owned(),
            ));
        }
        Ok(outcome)
    }

    pub async fn identity_receipts(
        &self,
        did: &str,
        head: &str,
    ) -> Result<IdentityReceiptListOutcome> {
        let builder = self
            .request(Method::GET, "/_arkret/root/identity/receipts")?
            .query(&[("did", did), ("head", head)]);
        let outcome: IdentityReceiptListOutcome = self.send_json(builder).await?;
        for receipt in &outcome.receipts {
            receipt.validate_proof_binding()?;
        }
        Ok(outcome)
    }

    pub async fn directory_describe(&self) -> Result<ServiceDescribe> {
        self.get("/_arkret/find/directory/describe").await
    }

    pub async fn directory_search_realms(
        &self,
        request: &DirectorySearchRealmsRequestBody,
    ) -> Result<DirectoryRealmSearchOutcome> {
        self.post("/_arkret/find/directory/search-realms", request)
            .await
    }

    pub async fn directory_resolve_realm(
        &self,
        request: &DirectoryResolveRealmRequestBody,
    ) -> Result<DirectoryRealmResolutionOutcome> {
        self.post("/_arkret/find/directory/resolve-realm", request)
            .await
    }
}
