use reqwest::{Method, RequestBuilder};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use url::Url;

use crate::{
    AuthzCheckRequest, AuthzCheckResponse, BlobMetadata, BlobRef, Commit,
    DeviceMessagesReceiveResponse, DeviceMessagesSendRequest, DeviceMessagesSendResponse, Error,
    ErrorEnvelope, KeysClaimRequest, KeysClaimResponse, KeysQueryRequest, KeysQueryResponse,
    KeysUploadRequest, KeysUploadResponse, QueryRequest, QueryResponse, Result, ServerDescription,
    ServiceRequirements, SubmitCommitResponse, SyncRequest, SyncResponse,
};

#[derive(Clone, Debug)]
pub enum Auth {
    Bearer(String),
    DeviceProof(String),
    ServiceSignature(String),
}

#[derive(Clone, Debug)]
pub struct Client {
    base_url: Url,
    http: reqwest::Client,
    auth: Option<Auth>,
}

#[derive(Clone, Debug)]
pub struct ClientBuilder {
    base_url: Url,
    http: Option<reqwest::Client>,
    auth: Option<Auth>,
    allow_insecure_localhost: bool,
}

impl ClientBuilder {
    pub fn new(base_url: Url) -> Self {
        Self { base_url, http: None, auth: None, allow_insecure_localhost: false }
    }

    pub fn http_client(mut self, http: reqwest::Client) -> Self {
        self.http = Some(http);
        self
    }

    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = Some(auth);
        self
    }

    pub fn allow_insecure_localhost(mut self) -> Self {
        self.allow_insecure_localhost = true;
        self
    }

    pub fn build(self) -> Result<Client> {
        validate_base_url(&self.base_url, self.allow_insecure_localhost)?;
        Ok(Client { base_url: self.base_url, http: self.http.unwrap_or_default(), auth: self.auth })
    }
}

impl Client {
    pub fn builder(base_url: Url) -> ClientBuilder {
        ClientBuilder::new(base_url)
    }

    pub fn new(base_url: Url) -> Result<Self> {
        Self::builder(base_url).build()
    }

    pub fn base_url(&self) -> &Url {
        &self.base_url
    }

    pub async fn describe(&self) -> Result<ServerDescription> {
        self.get("/api/v1/server/describe").await
    }

    pub async fn describe_and_verify(
        &self,
        requirements: &ServiceRequirements,
    ) -> Result<ServerDescription> {
        let description = self.describe().await?;
        requirements.verify(&description)?;
        Ok(description)
    }

    pub async fn submit_commit(&self, commit: &Commit) -> Result<SubmitCommitResponse> {
        self.post("/api/v1/repo/submit-commit", commit).await
    }

    pub async fn identity_describe(&self) -> Result<Value> {
        self.get("/api/v1/identity/describe").await
    }

    pub async fn identity_resolve<T: Serialize, R: DeserializeOwned>(
        &self,
        request: &T,
    ) -> Result<R> {
        self.post("/api/v1/identity/resolve", request).await
    }

    pub async fn identity_document<R: DeserializeOwned>(
        &self,
        did: &str,
        version: Option<&str>,
    ) -> Result<R> {
        let mut builder =
            self.request(Method::GET, "/api/v1/identity/document")?.query(&[("did", did)]);
        if let Some(version) = version {
            builder = builder.query(&[("version", version)]);
        }
        self.send_json(builder).await
    }

    pub async fn identity_log<R: DeserializeOwned>(
        &self,
        did: &str,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<R> {
        let mut builder = self.request(Method::GET, "/api/v1/identity/log")?.query(&[("did", did)]);
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn identity_submit_did_operation<T: Serialize, R: DeserializeOwned>(
        &self,
        request: &T,
    ) -> Result<R> {
        self.post("/api/v1/identity/submit-did-operation", request).await
    }

    pub async fn identity_receipts<R: DeserializeOwned>(&self, did: &str, head: &str) -> Result<R> {
        let builder = self
            .request(Method::GET, "/api/v1/identity/receipts")?
            .query(&[("did", did), ("head", head)]);
        self.send_json(builder).await
    }

    pub async fn repo_describe<R: DeserializeOwned>(&self, repo_id: Option<&str>) -> Result<R> {
        let mut builder = self.request(Method::GET, "/api/v1/repo/describe")?;
        if let Some(repo_id) = repo_id {
            builder = builder.query(&[("repo_id", repo_id)]);
        }
        self.send_json(builder).await
    }

    pub async fn repo_commits<R: DeserializeOwned>(
        &self,
        repo_id: &str,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<R> {
        let mut builder =
            self.request(Method::GET, "/api/v1/repo/commits")?.query(&[("repo_id", repo_id)]);
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn repo_commit<R: DeserializeOwned>(
        &self,
        commit_id: &str,
        repo_id: Option<&str>,
    ) -> Result<R> {
        let mut builder =
            self.request(Method::GET, "/api/v1/repo/commit")?.query(&[("commit_id", commit_id)]);
        if let Some(repo_id) = repo_id {
            builder = builder.query(&[("repo_id", repo_id)]);
        }
        self.send_json(builder).await
    }

    pub async fn repo_operations<T: Serialize, R: DeserializeOwned>(
        &self,
        request: &T,
    ) -> Result<R> {
        self.post("/api/v1/repo/operations", request).await
    }

    pub async fn repo_sync<T: Serialize, R: DeserializeOwned>(&self, request: &T) -> Result<R> {
        self.post("/api/v1/repo/sync", request).await
    }

    pub async fn sync(&self, request: &SyncRequest) -> Result<SyncResponse> {
        self.post("/api/v1/sync", request).await
    }

    pub async fn sync_describe(&self) -> Result<Value> {
        self.get("/api/v1/sync/describe").await
    }

    pub async fn sync_subscribe<R: DeserializeOwned>(
        &self,
        space_id: &str,
        cursor: Option<&str>,
    ) -> Result<R> {
        let mut builder =
            self.request(Method::GET, "/api/v1/sync/subscribe")?.query(&[("space_id", space_id)]);
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        self.send_json(builder).await
    }

    pub async fn sync_backfill<R: DeserializeOwned>(
        &self,
        space_id: &str,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<R> {
        let mut builder =
            self.request(Method::GET, "/api/v1/sync/backfill")?.query(&[("space_id", space_id)]);
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn sync_snapshot_head<R: DeserializeOwned>(&self, space_id: &str) -> Result<R> {
        let builder = self
            .request(Method::GET, "/api/v1/sync/snapshot-head")?
            .query(&[("space_id", space_id)]);
        self.send_json(builder).await
    }

    pub async fn index_query<T: DeserializeOwned>(
        &self,
        request: &QueryRequest,
    ) -> Result<QueryResponse<T>> {
        let mut builder = self.request(Method::POST, "/api/v1/index/query")?;
        if let Some(consistency) = &request.consistency {
            builder = builder.header("X-Contrix-Wait-For", &consistency.wait_for);
        }
        self.send_json(builder.json(request)).await
    }

    pub async fn authz_check(&self, request: &AuthzCheckRequest) -> Result<AuthzCheckResponse> {
        self.post("/api/v1/authz/check", request).await
    }

    pub async fn authz_effective_grants<R: DeserializeOwned>(
        &self,
        space_id: &str,
        subject: &str,
        at: Option<&str>,
    ) -> Result<R> {
        let mut builder = self
            .request(Method::GET, "/api/v1/authz/effective-grants")?
            .query(&[("space_id", space_id), ("subject", subject)]);
        if let Some(at) = at {
            builder = builder.query(&[("at", at)]);
        }
        self.send_json(builder).await
    }

    pub async fn authz_invites<R: DeserializeOwned>(
        &self,
        subject: &str,
        space_id: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<R> {
        let mut builder =
            self.request(Method::GET, "/api/v1/authz/invites")?.query(&[("subject", subject)]);
        if let Some(space_id) = space_id {
            builder = builder.query(&[("space_id", space_id)]);
        }
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        self.send_json(builder).await
    }

    pub async fn blob_metadata(&self, blob_ref: &BlobRef) -> Result<BlobMetadata> {
        let builder = self
            .request(Method::GET, "/api/v1/blob/get")?
            .query(&[("blob_ref", blob_ref.as_str())]);
        self.send_json(builder).await
    }

    pub async fn blob_head(&self, blob_ref: &BlobRef) -> Result<reqwest::header::HeaderMap> {
        let builder = self
            .request(Method::HEAD, "/api/v1/blob/get")?
            .query(&[("blob_ref", blob_ref.as_str())]);
        self.send_empty(builder).await
    }

    pub async fn blob_upload<T: Serialize, R: DeserializeOwned>(&self, body: &T) -> Result<R> {
        self.post("/api/v1/blob/upload", body).await
    }

    pub async fn keys_upload(&self, request: &KeysUploadRequest) -> Result<KeysUploadResponse> {
        self.post("/api/v1/keys/upload", request).await
    }

    pub async fn keys_query(&self, request: &KeysQueryRequest) -> Result<KeysQueryResponse> {
        self.post("/api/v1/keys/query", request).await
    }

    pub async fn keys_claim(&self, request: &KeysClaimRequest) -> Result<KeysClaimResponse> {
        self.post("/api/v1/keys/claim", request).await
    }

    pub async fn send_device_messages(
        &self,
        txn_id: &str,
        request: &DeviceMessagesSendRequest,
    ) -> Result<DeviceMessagesSendResponse> {
        reject_path_segment(txn_id)?;
        let path = format!("/api/v1/device_messages/{txn_id}");
        self.put(&path, request).await
    }

    pub async fn receive_device_messages(
        &self,
        from: Option<&str>,
        limit: Option<u32>,
    ) -> Result<DeviceMessagesReceiveResponse> {
        let mut builder = self.request(Method::GET, "/api/v1/device_messages")?;
        if let Some(from) = from {
            builder = builder.query(&[("from", from)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn federation_transaction<T: Serialize, R: DeserializeOwned>(
        &self,
        txn_id: &str,
        request: &T,
    ) -> Result<R> {
        reject_path_segment(txn_id)?;
        let path = format!("/api/v1/federation/transactions/{txn_id}");
        self.put(&path, request).await
    }

    pub async fn federation_push_operations<T: Serialize, R: DeserializeOwned>(
        &self,
        request: &T,
    ) -> Result<R> {
        self.post("/api/v1/federation/push-operations", request).await
    }

    pub async fn federation_pull_operations<R: DeserializeOwned>(
        &self,
        space_id: &str,
        after_cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<R> {
        let mut builder = self
            .request(Method::GET, "/api/v1/federation/pull-operations")?
            .query(&[("space_id", space_id)]);
        if let Some(after_cursor) = after_cursor {
            builder = builder.query(&[("after_cursor", after_cursor)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn federation_space_members<R: DeserializeOwned>(
        &self,
        space_id: &str,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<R> {
        let mut builder = self
            .request(Method::GET, "/api/v1/federation/space-members")?
            .query(&[("space_id", space_id)]);
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn federation_verify_actor<T: Serialize, R: DeserializeOwned>(
        &self,
        request: &T,
    ) -> Result<R> {
        self.post("/api/v1/federation/verify-actor", request).await
    }

    pub async fn index_describe(&self) -> Result<Value> {
        self.get("/api/v1/index/describe").await
    }

    pub async fn index_entity<R: DeserializeOwned>(
        &self,
        entity_id: &str,
        space_id: Option<&str>,
        at: Option<&str>,
    ) -> Result<R> {
        let mut builder =
            self.request(Method::GET, "/api/v1/index/entity")?.query(&[("entity_id", entity_id)]);
        if let Some(space_id) = space_id {
            builder = builder.query(&[("space_id", space_id)]);
        }
        if let Some(at) = at {
            builder = builder.query(&[("at", at)]);
        }
        self.send_json(builder).await
    }

    pub async fn index_thread<R: DeserializeOwned>(
        &self,
        topic_id: &str,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<R> {
        let mut builder =
            self.request(Method::GET, "/api/v1/index/thread")?.query(&[("topic_id", topic_id)]);
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn index_notifications<R: DeserializeOwned>(
        &self,
        cursor: Option<&str>,
        state: Option<&str>,
        limit: Option<u32>,
    ) -> Result<R> {
        let mut builder = self.request(Method::GET, "/api/v1/index/notifications")?;
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        if let Some(state) = state {
            builder = builder.query(&[("state", state)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn index_inbox<R: DeserializeOwned>(
        &self,
        scope: Option<&str>,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<R> {
        let mut builder = self.request(Method::GET, "/api/v1/index/inbox")?;
        if let Some(scope) = scope {
            builder = builder.query(&[("scope", scope)]);
        }
        if let Some(cursor) = cursor {
            builder = builder.query(&[("cursor", cursor)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn index_search<T: Serialize, R: DeserializeOwned>(&self, request: &T) -> Result<R> {
        self.post("/api/v1/index/search", request).await
    }

    pub async fn index_space_hierarchy<R: DeserializeOwned>(
        &self,
        space_id: &str,
        depth: Option<u32>,
        include_unconfirmed: Option<bool>,
    ) -> Result<R> {
        let mut builder = self
            .request(Method::GET, "/api/v1/index/space-hierarchy")?
            .query(&[("space_id", space_id)]);
        if let Some(depth) = depth {
            builder = builder.query(&[("depth", depth)]);
        }
        if let Some(include_unconfirmed) = include_unconfirmed {
            builder = builder.query(&[("include_unconfirmed", include_unconfirmed)]);
        }
        self.send_json(builder).await
    }

    pub async fn directory_describe(&self) -> Result<Value> {
        self.get("/api/v1/directory/describe").await
    }

    pub async fn directory_search_spaces<T: Serialize, R: DeserializeOwned>(
        &self,
        request: &T,
    ) -> Result<R> {
        self.post("/api/v1/directory/search-spaces", request).await
    }

    pub async fn directory_resolve_space<T: Serialize, R: DeserializeOwned>(
        &self,
        request: &T,
    ) -> Result<R> {
        self.post("/api/v1/directory/resolve-space", request).await
    }

    pub async fn directory_search_organizations<T: Serialize, R: DeserializeOwned>(
        &self,
        request: &T,
    ) -> Result<R> {
        self.post("/api/v1/directory/search-organizations", request).await
    }

    pub async fn directory_resolve_organization<T: Serialize, R: DeserializeOwned>(
        &self,
        request: &T,
    ) -> Result<R> {
        self.post("/api/v1/directory/resolve-organization", request).await
    }

    pub async fn directory_search_actors<T: Serialize, R: DeserializeOwned>(
        &self,
        request: &T,
    ) -> Result<R> {
        self.post("/api/v1/directory/search-actors", request).await
    }

    pub async fn directory_search_users<R: DeserializeOwned>(
        &self,
        q: &str,
        space_id: Option<&str>,
        limit: Option<u32>,
    ) -> Result<R> {
        let mut builder =
            self.request(Method::GET, "/api/v1/directory/search-users")?.query(&[("q", q)]);
        if let Some(space_id) = space_id {
            builder = builder.query(&[("space_id", space_id)]);
        }
        if let Some(limit) = limit {
            builder = builder.query(&[("limit", limit)]);
        }
        self.send_json(builder).await
    }

    pub async fn directory_resolve_handle<T: Serialize, R: DeserializeOwned>(
        &self,
        request: &T,
    ) -> Result<R> {
        self.post("/api/v1/directory/resolve-handle", request).await
    }

    pub async fn push_register_device<T: Serialize, R: DeserializeOwned>(
        &self,
        request: &T,
    ) -> Result<R> {
        self.post("/api/v1/push/register-device", request).await
    }

    pub async fn push_unregister_device<T: Serialize, R: DeserializeOwned>(
        &self,
        request: &T,
    ) -> Result<R> {
        self.post("/api/v1/push/unregister-device", request).await
    }

    pub async fn push_notify<T: Serialize, R: DeserializeOwned>(&self, request: &T) -> Result<R> {
        self.post("/api/v1/push/notify", request).await
    }

    pub async fn policy_check<T: Serialize, R: DeserializeOwned>(&self, request: &T) -> Result<R> {
        self.post("/contrix/v1/check", request).await
    }

    pub async fn media_ice_config<T: Serialize, R: DeserializeOwned>(
        &self,
        request: &T,
    ) -> Result<R> {
        self.post("/contrix/v1/ice-config", request).await
    }

    pub async fn moderation_report<T: Serialize, R: DeserializeOwned>(
        &self,
        request: &T,
    ) -> Result<R> {
        self.post("/api/v1/moderation/report", request).await
    }

    pub async fn applet_ping(&self) -> Result<Value> {
        self.get("/api/v1/applet/ping").await
    }

    pub async fn applet_describe(&self) -> Result<Value> {
        self.get("/api/v1/applet/describe").await
    }

    pub async fn applet_transaction<T: Serialize, R: DeserializeOwned>(
        &self,
        txn_id: &str,
        request: &T,
    ) -> Result<R> {
        reject_path_segment(txn_id)?;
        let path = format!("/api/v1/applet/transactions/{txn_id}");
        self.put(&path, request).await
    }

    pub async fn applet_actor<R: DeserializeOwned>(&self, actor_id: &str) -> Result<R> {
        reject_path_segment(actor_id)?;
        let path = format!("/api/v1/applet/actors/{actor_id}");
        self.get(&path).await
    }

    pub async fn applet_space<R: DeserializeOwned>(&self, space_id_or_alias: &str) -> Result<R> {
        reject_path_segment(space_id_or_alias)?;
        let path = format!("/api/v1/applet/spaces/{space_id_or_alias}");
        self.get(&path).await
    }

    pub async fn applet_protocol<R: DeserializeOwned>(&self, protocol: &str) -> Result<R> {
        reject_path_segment(protocol)?;
        let path = format!("/api/v1/applet/protocols/{protocol}");
        self.get(&path).await
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let builder = self.request(Method::GET, path)?;
        self.send_json(builder).await
    }

    pub async fn post<T: Serialize, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R> {
        let builder = self.request(Method::POST, path)?.json(body);
        self.send_json(builder).await
    }

    pub async fn put<T: Serialize, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R> {
        let builder = self.request(Method::PUT, path)?.json(body);
        self.send_json(builder).await
    }

    fn request(&self, method: Method, path: &str) -> Result<RequestBuilder> {
        reject_absolute_path(path)?;
        let url = self.base_url.join(path.trim_start_matches('/'))?;
        let builder = self.http.request(method, url).header("Accept", "application/json");
        Ok(self.apply_auth(builder))
    }

    fn apply_auth(&self, builder: RequestBuilder) -> RequestBuilder {
        match &self.auth {
            Some(Auth::Bearer(token)) => builder.bearer_auth(token),
            Some(Auth::DeviceProof(proof)) => builder.header("X-Contrix-Device-Proof", proof),
            Some(Auth::ServiceSignature(signature)) => {
                builder.header("Signature", signature).header("X-Contrix-Service-Signature", "1")
            }
            None => builder,
        }
    }

    async fn send_json<T: DeserializeOwned>(&self, builder: RequestBuilder) -> Result<T> {
        let response = builder.send().await?;
        let status = response.status();
        if !status.is_success() {
            let error = response.json::<ErrorEnvelope>().await.unwrap_or_else(|_| ErrorEnvelope {
                errcode: "cx.error.http_status".to_owned(),
                error: format!("HTTP request failed with status {status}"),
                retry_after_ms: None,
                extra: Default::default(),
            });
            return Err(Error::Api { status: status.as_u16(), error });
        }

        Ok(response.json().await?)
    }

    async fn send_empty(&self, builder: RequestBuilder) -> Result<reqwest::header::HeaderMap> {
        let response = builder.send().await?;
        let status = response.status();
        let headers = response.headers().clone();
        if !status.is_success() {
            let error = response.json::<ErrorEnvelope>().await.unwrap_or_else(|_| ErrorEnvelope {
                errcode: "cx.error.http_status".to_owned(),
                error: format!("HTTP request failed with status {status}"),
                retry_after_ms: None,
                extra: Default::default(),
            });
            return Err(Error::Api { status: status.as_u16(), error });
        }

        Ok(headers)
    }
}

fn validate_base_url(url: &Url, allow_insecure_localhost: bool) -> Result<()> {
    if url.scheme() == "https" {
        return Ok(());
    }

    if allow_insecure_localhost && url.scheme() == "http" && is_localhost(url) {
        return Ok(());
    }

    Err(Error::InsecureUrl(url.to_string()))
}

fn is_localhost(url: &Url) -> bool {
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
}

fn reject_absolute_path(path: &str) -> Result<()> {
    if path.starts_with("//") || Url::parse(path).is_ok() {
        return Err(Error::Protocol(
            "request path must be relative to the Contrix service".to_owned(),
        ));
    }
    Ok(())
}

fn reject_path_segment(segment: &str) -> Result<()> {
    if segment.is_empty()
        || segment.contains('/')
        || segment.contains('\\')
        || segment.contains('?')
    {
        return Err(Error::Protocol("path segment contains reserved characters".to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_relative_api_url() {
        let client = Client::new(Url::parse("https://alice.example/contrix/").unwrap()).unwrap();
        let request =
            client.request(Method::GET, "/api/v1/server/describe").unwrap().build().unwrap();
        assert_eq!(request.url().as_str(), "https://alice.example/contrix/api/v1/server/describe");
    }

    #[test]
    fn rejects_remote_http_by_default() {
        let error = Client::new(Url::parse("http://alice.example/contrix/").unwrap()).unwrap_err();
        assert!(matches!(error, Error::InsecureUrl(_)));
    }

    #[test]
    fn allows_insecure_localhost_when_explicit() {
        let client = Client::builder(Url::parse("http://127.0.0.1:8080/").unwrap())
            .allow_insecure_localhost()
            .build()
            .unwrap();
        assert_eq!(client.base_url().scheme(), "http");
    }

    #[test]
    fn rejects_absolute_request_paths() {
        let client = Client::new(Url::parse("https://alice.example/contrix/").unwrap()).unwrap();
        let error = client.request(Method::GET, "https://evil.example/api").unwrap_err();
        assert!(matches!(error, Error::Protocol(_)));
    }
}
