//! Server-describe, identity, and directory endpoint methods on [`Client`].

use arkret_models_discovery::{
    DirectoryActorSearchOutcome, DirectoryAgentSelectorResolutionOutcome,
    DirectoryHandleResolutionOutcome, DirectoryListHandlesForSubjectRequestBody,
    DirectoryOrganizationResolutionOutcome, DirectoryOrganizationSearchOutcome,
    DirectoryPrivateContactDiscoveryOutcome, DirectoryPrivateContactDiscoveryRequestBody,
    DirectoryRealmResolutionOutcome, DirectoryRealmSearchOutcome,
    DirectoryResolveAgentSelectorRequestBody, DirectoryResolveHandleRequestBody,
    DirectoryResolveOrganizationRequestBody, DirectoryResolveRealmRequestBody,
    DirectoryResolveTargetRequestBody, DirectorySearchActorsRequestBody,
    DirectorySearchOrganizationsRequestBody, DirectorySearchRealmsRequestBody,
    DirectorySearchUsersRequestBody, DirectorySubjectHandleList, DirectoryTargetResolutionOutcome,
    DirectoryUserSearchOutcome, ServiceDescribe, ServiceEndpointBinding, ServiceIdAllowlist,
    ServiceRequirements,
};
use arkret_models_identity::service_identity::{
    SERVICE_REGISTRATION_ENSURE_PATH, SERVICE_REGISTRATION_GET_PATH,
    ServiceRegistrationEnsureRequestBody, ServiceRegistrationKey, ServiceRegistrationOutcome,
};
use arkret_models_identity::{
    DidOperationSubmitOutcome, DidOperationSubmitRequestBody, IdentityDescription,
    IdentityDocumentView, IdentityLogListOutcome, IdentityReceiptListOutcome,
    IdentityResolveOutcome, IdentityResolveRequestBody,
};
use arkret_wire::ServiceType;
use reqwest::Method;

use crate::{Client, Error, Result};

impl Client {
    pub async fn describe(&self) -> Result<ServiceDescribe> {
        let builder = self.public_request(Method::GET, "/_arkret/describe")?;
        self.send_json(builder).await
    }

    /// Fetches the description for exactly one co-located service role.
    pub async fn describe_for_role(&self, service_type: ServiceType) -> Result<ServiceDescribe> {
        if !service_type.valid_in("service_describe") {
            return Err(Error::Protocol(format!(
                "service_type {} is not valid for service describe",
                service_type.as_str()
            )));
        }
        let builder = self
            .public_request(Method::GET, "/_arkret/describe")?
            .query(&[("service_type", service_type.as_str())]);
        let description: ServiceDescribe = self.send_json(builder).await?;
        ServiceRequirements::new()
            .service_type(service_type)
            .verify(&description)?;
        Ok(description)
    }

    pub async fn describe_and_verify(
        &self,
        requirements: &ServiceRequirements,
    ) -> Result<ServiceDescribe> {
        let description = self.describe().await?;
        requirements.verify(&description)?;
        Ok(description)
    }

    pub async fn describe_role_and_verify(
        &self,
        service_type: ServiceType,
        requirements: &ServiceRequirements,
    ) -> Result<ServiceDescribe> {
        let description = self.describe_for_role(service_type).await?;
        requirements.verify(&description)?;
        Ok(description)
    }

    /// Fetches one role-scoped description and verifies its service DID and
    /// advertised operations against the expected DID service binding.
    pub async fn describe_role_and_verify_binding(
        &self,
        service_type: ServiceType,
        requirements: &ServiceRequirements,
        binding: &ServiceEndpointBinding,
    ) -> Result<ServiceDescribe> {
        if binding.service_type != service_type {
            return Err(Error::Protocol(format!(
                "service binding role {} does not match requested role {}",
                binding.service_type, service_type
            )));
        }
        let description = self
            .describe_role_and_verify(service_type, requirements)
            .await?;
        ServiceIdAllowlist::new()
            .allow(binding.clone())
            .verify_description(&description)?;
        Ok(description)
    }

    pub async fn identity_describe(&self) -> Result<IdentityDescription> {
        self.get("/_arkret/root/identity/describe").await
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
        self.post("/_arkret/root/identity/submit-did-operation", request)
            .await
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
                ("service_type", key.service_type().as_str()),
                ("public_base", key.public_base().as_str()),
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
        self.send_json(builder).await
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

    /// R3.3 (AKP-0011, arkret-spec @ cced4b8) — `ak.find.directory.query.resolve_target`.
    /// Resolve a client-agnostic shareable object address (Realm / Strand /
    /// Message) to a preview. The `address` and any `token` should be derived
    /// from [`arkret_wire::parse_address`]; invite and preview tokens
    /// MUST be bound to the resolved object server-side via
    /// [`arkret_wire::verify_token_target`].
    pub async fn directory_resolve_target(
        &self,
        request: &DirectoryResolveTargetRequestBody,
    ) -> Result<DirectoryTargetResolutionOutcome> {
        self.post("/_arkret/find/directory/resolve-target", request)
            .await
    }

    pub async fn directory_search_organizations(
        &self,
        request: &DirectorySearchOrganizationsRequestBody,
    ) -> Result<DirectoryOrganizationSearchOutcome> {
        self.post("/_arkret/find/directory/search-organizations", request)
            .await
    }

    pub async fn directory_resolve_organization(
        &self,
        request: &DirectoryResolveOrganizationRequestBody,
    ) -> Result<DirectoryOrganizationResolutionOutcome> {
        self.post("/_arkret/find/directory/resolve-organization", request)
            .await
    }

    pub async fn directory_search_actors(
        &self,
        request: &DirectorySearchActorsRequestBody,
    ) -> Result<DirectoryActorSearchOutcome> {
        self.post("/_arkret/find/directory/search-actors", request)
            .await
    }

    pub async fn directory_search_users(
        &self,
        q: &str,
        realm_id: Option<&str>,
        limit: Option<u32>,
    ) -> Result<DirectoryUserSearchOutcome> {
        let request = DirectorySearchUsersRequestBody {
            query: q.to_owned(),
            realm_id: realm_id.map(str::parse).transpose()?,
            cursor: None,
            limit,
            intent: None,
        };
        self.post("/_arkret/find/directory/search-users", &request)
            .await
    }

    pub async fn directory_resolve_handle(
        &self,
        request: &DirectoryResolveHandleRequestBody,
    ) -> Result<DirectoryHandleResolutionOutcome> {
        self.post("/_arkret/find/directory/resolve-handle", request)
            .await
    }

    /// Resolve a controller-scoped native personal agent selector exactly.
    pub async fn directory_resolve_agent_selector(
        &self,
        request: &DirectoryResolveAgentSelectorRequestBody,
    ) -> Result<DirectoryAgentSelectorResolutionOutcome> {
        let body: DirectoryAgentSelectorResolutionOutcome = self
            .post("/_arkret/find/directory/resolve-agent-selector", request)
            .await?;
        body.validate()?;
        Ok(body)
    }

    /// R3.2 (arkret-spec @ b56cab1) — `ak.find.directory.query.list_handles_for_subject`.
    /// Known holder/principal DID → current visible handle claims. The
    /// response invariant `claims[].subject == subject` is enforced via
    /// [`DirectorySubjectHandleList::validate`] before returning.
    pub async fn directory_list_handles_for_subject(
        &self,
        request: &DirectoryListHandlesForSubjectRequestBody,
    ) -> Result<DirectorySubjectHandleList> {
        let body: DirectorySubjectHandleList = self
            .post("/_arkret/find/directory/list-handles-for-subject", request)
            .await?;
        body.validate()?;
        Ok(body)
    }

    pub async fn directory_private_contact_discovery(
        &self,
        request: &DirectoryPrivateContactDiscoveryRequestBody,
    ) -> Result<DirectoryPrivateContactDiscoveryOutcome> {
        self.post("/_arkret/find/directory/private-contact-discovery", request)
            .await
    }
}
