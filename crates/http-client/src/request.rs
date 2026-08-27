//! Generic JSON request helpers shared by the typed endpoint modules.

use reqwest::Method;
use reqwest::header::CONTENT_TYPE;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{Client, ClientRequestOptions, Result};

impl Client {
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let builder = self.request(Method::GET, path)?;
        self.send_json(builder).await
    }

    pub async fn get_with_options<T: DeserializeOwned>(
        &self,
        path: &str,
        options: &ClientRequestOptions,
    ) -> Result<T> {
        let builder = self.apply_request_options(self.request(Method::GET, path)?, options)?;
        self.send_json(builder).await
    }

    pub async fn post<T: Serialize, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R> {
        let builder = self.canonical_json_body(self.request(Method::POST, path)?, body)?;
        self.send_json(builder).await
    }

    pub async fn post_with_options<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
        options: &ClientRequestOptions,
    ) -> Result<R> {
        let builder = self.apply_request_options(self.request(Method::POST, path)?, options)?;
        self.send_json(self.canonical_json_body(builder, body)?)
            .await
    }

    /// Serialize a protocol-replay-safe operation exactly once, then reuse
    /// those canonical bytes for every transport attempt. Eligibility is kept
    /// crate-private and is limited to endpoints whose operation contracts
    /// define a durable body-bound request identity.
    pub(crate) async fn post_protocol_replay_safe<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R> {
        let body = arkret_canonical::canonical::canonical_json_bytes(body)?;
        let builder = self
            .request(Method::POST, path)?
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        self.send_json_protocol_replay_safe(builder).await
    }

    pub async fn put<T: Serialize, R: DeserializeOwned>(&self, path: &str, body: &T) -> Result<R> {
        let builder = self.canonical_json_body(self.request(Method::PUT, path)?, body)?;
        self.send_json(builder).await
    }

    pub async fn put_with_options<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
        options: &ClientRequestOptions,
    ) -> Result<R> {
        let builder = self.apply_request_options(self.request(Method::PUT, path)?, options)?;
        self.send_json(self.canonical_json_body(builder, body)?)
            .await
    }

    pub async fn delete<R: DeserializeOwned>(&self, path: &str) -> Result<R> {
        let builder = self.request(Method::DELETE, path)?;
        self.send_json(builder).await
    }

    /// `DELETE` with a canonical JSON body.
    ///
    /// A registered DELETE carries a body when the operation's durable effect is a
    /// signed Event: the signature has nowhere else to go, and a service MUST NOT
    /// produce it. `ak.self.keys.backups.resource.delete.v1` was the first such
    /// endpoint and open-coded this; `ak.self.account_data.resource.delete.v1` is the
    /// second, so it belongs beside the other verbs instead.
    pub async fn delete_with_body<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R> {
        let builder = self.canonical_json_body(self.request(Method::DELETE, path)?, body)?;
        self.send_json(builder).await
    }
}
