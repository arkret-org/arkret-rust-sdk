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

    /// Replay a caller-persisted canonical JSON body without serializing it
    /// again. This is intended for immutable signed-envelope transport retry.
    pub async fn post_canonical_bytes_with_options<R: DeserializeOwned>(
        &self,
        path: &str,
        body: &[u8],
        options: &ClientRequestOptions,
    ) -> Result<R> {
        let builder = self.apply_request_options(self.request(Method::POST, path)?, options)?;
        self.send_json(
            builder
                .header(CONTENT_TYPE, "application/json")
                .body(body.to_vec()),
        )
        .await
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
}
