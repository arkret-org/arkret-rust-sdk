//! Server-describe, identity, and directory endpoint methods on [`Client`].

use cokret_core::{
    DidOperationSubmitOutcome, DidOperationSubmitRequestBody, DirectoryActorSearchOutcome,
    DirectoryAgentSelectorResolutionOutcome, DirectoryDescription,
    DirectoryHandleResolutionOutcome, DirectoryListHandlesForSubjectRequestBody,
    DirectoryOrganizationResolutionOutcome, DirectoryOrganizationSearchOutcome,
    DirectoryPrivateContactDiscoveryOutcome, DirectoryPrivateContactDiscoveryRequestBody,
    DirectoryRealmResolutionOutcome, DirectoryRealmSearchOutcome,
    DirectoryResolveAgentSelectorRequestBody, DirectoryResolveHandleRequestBody,
    DirectoryResolveOrganizationRequestBody, DirectoryResolveRealmRequestBody,
    DirectoryResolveTargetRequestBody, DirectorySearchActorsRequestBody,
    DirectorySearchOrganizationsRequestBody, DirectorySearchRealmsRequestBody,
    DirectorySearchUsersRequestBody, DirectorySubjectHandleList, DirectoryTargetResolutionOutcome,
    DirectoryUserSearchOutcome, IdentityDescription, IdentityDocumentView, IdentityLogListOutcome,
    IdentityReceiptListOutcome, IdentityResolveOutcome, IdentityResolveRequestBody, Result,
    ServerDescription, ServiceRequirements,
};
use reqwest::Method;

use crate::Client;

impl Client {
    pub async fn describe(&self) -> Result<ServerDescription> {
        self.get("/_cokret/describe").await
    }

    pub async fn describe_and_verify(
        &self,
        requirements: &ServiceRequirements,
    ) -> Result<ServerDescription> {
        let description = self.describe().await?;
        requirements.verify(&description)?;
        Ok(description)
    }

    pub async fn identity_describe(&self) -> Result<IdentityDescription> {
        self.get("/_cokret/root/identity/describe").await
    }

    pub async fn identity_resolve(
        &self,
        request: &IdentityResolveRequestBody,
    ) -> Result<IdentityResolveOutcome> {
        self.post("/_cokret/root/identity/resolve", request).await
    }

    pub async fn identity_document(
        &self,
        did: &str,
        version: Option<&str>,
    ) -> Result<IdentityDocumentView> {
        let mut builder = self
            .request(Method::GET, "/_cokret/root/identity/document")?
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
            .request(Method::GET, "/_cokret/root/identity/log")?
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
        self.post("/_cokret/root/identity/submit-did-operation", request)
            .await
    }

    pub async fn identity_receipts(
        &self,
        did: &str,
        head: &str,
    ) -> Result<IdentityReceiptListOutcome> {
        let builder = self
            .request(Method::GET, "/_cokret/root/identity/receipts")?
            .query(&[("did", did), ("head", head)]);
        self.send_json(builder).await
    }

    pub async fn directory_describe(&self) -> Result<DirectoryDescription> {
        self.get("/_cokret/find/directory/describe").await
    }

    pub async fn directory_search_realms(
        &self,
        request: &DirectorySearchRealmsRequestBody,
    ) -> Result<DirectoryRealmSearchOutcome> {
        self.post("/_cokret/find/directory/search-realms", request)
            .await
    }

    pub async fn directory_resolve_realm(
        &self,
        request: &DirectoryResolveRealmRequestBody,
    ) -> Result<DirectoryRealmResolutionOutcome> {
        self.post("/_cokret/find/directory/resolve-realm", request)
            .await
    }

    /// R3.3 (CKP-0011, cokret-spec @ cced4b8) — `ck.find.directory.query.resolve_target`.
    /// Resolve a client-agnostic shareable object address (Realm / Strand /
    /// Message) to a preview. The `address` and any `token` should be derived
    /// from [`cokret_core::models::parse_address`]; invite and preview tokens
    /// MUST be bound to the resolved object server-side via
    /// [`cokret_core::models::verify_token_target`].
    pub async fn directory_resolve_target(
        &self,
        request: &DirectoryResolveTargetRequestBody,
    ) -> Result<DirectoryTargetResolutionOutcome> {
        self.post("/_cokret/find/directory/resolve-target", request)
            .await
    }

    pub async fn directory_search_organizations(
        &self,
        request: &DirectorySearchOrganizationsRequestBody,
    ) -> Result<DirectoryOrganizationSearchOutcome> {
        self.post("/_cokret/find/directory/search-organizations", request)
            .await
    }

    pub async fn directory_resolve_organization(
        &self,
        request: &DirectoryResolveOrganizationRequestBody,
    ) -> Result<DirectoryOrganizationResolutionOutcome> {
        self.post("/_cokret/find/directory/resolve-organization", request)
            .await
    }

    pub async fn directory_search_actors(
        &self,
        request: &DirectorySearchActorsRequestBody,
    ) -> Result<DirectoryActorSearchOutcome> {
        self.post("/_cokret/find/directory/search-actors", request)
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
        self.post("/_cokret/find/directory/search-users", &request)
            .await
    }

    pub async fn directory_resolve_handle(
        &self,
        request: &DirectoryResolveHandleRequestBody,
    ) -> Result<DirectoryHandleResolutionOutcome> {
        self.post("/_cokret/find/directory/resolve-handle", request)
            .await
    }

    /// Resolve a controller-scoped native personal agent selector exactly.
    pub async fn directory_resolve_agent_selector(
        &self,
        request: &DirectoryResolveAgentSelectorRequestBody,
    ) -> Result<DirectoryAgentSelectorResolutionOutcome> {
        let body: DirectoryAgentSelectorResolutionOutcome = self
            .post("/_cokret/find/directory/resolve-agent-selector", request)
            .await?;
        body.validate()?;
        Ok(body)
    }

    /// R3.2 (cokret-spec @ b56cab1) — `ck.find.directory.query.list_handles_for_subject`.
    /// Known holder/principal DID → current visible handle claims. The
    /// response invariant `claims[].subject == subject` is enforced via
    /// [`DirectorySubjectHandleList::validate`] before returning.
    pub async fn directory_list_handles_for_subject(
        &self,
        request: &DirectoryListHandlesForSubjectRequestBody,
    ) -> Result<DirectorySubjectHandleList> {
        let body: DirectorySubjectHandleList = self
            .post("/_cokret/find/directory/list-handles-for-subject", request)
            .await?;
        body.validate()?;
        Ok(body)
    }

    pub async fn directory_private_contact_discovery(
        &self,
        request: &DirectoryPrivateContactDiscoveryRequestBody,
    ) -> Result<DirectoryPrivateContactDiscoveryOutcome> {
        self.post("/_cokret/find/directory/private-contact-discovery", request)
            .await
    }
}
