use reqwest::{Method, RequestBuilder};
use serde::{Serialize, de::DeserializeOwned};
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

    pub async fn sync(&self, request: &SyncRequest) -> Result<SyncResponse> {
        self.post("/api/v1/sync", request).await
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

    pub async fn blob_metadata(&self, blob_ref: &BlobRef) -> Result<BlobMetadata> {
        let builder = self
            .request(Method::GET, "/api/v1/blob/get")?
            .query(&[("blob_ref", blob_ref.as_str())]);
        self.send_json(builder).await
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
