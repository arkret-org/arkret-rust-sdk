//! Authority-commit submission, replication, discovery, and handoff methods.

use arkret_models_collaboration::authority_commit::{
    AuthorityHandoffRequest, PeerAuthoritySubmitOutcome, PeerAuthoritySubmitRequest,
    PeerStreamScanOutcome, SelfAuthoritySubmitOutcome, SelfAuthoritySubmitRequest,
};
use arkret_wire::{
    AuthorityBundleRequest, RealmAuthorityBundle, RealmAuthorityHandoff, StreamScanOutcome,
    StreamScanRequest,
};
use reqwest::Method;

use crate::{Client, ClientRequestOptions, Error, Result};

impl Client {
    /// Submit a producer-signed Event, or an atomic MLS Commit + Welcome set,
    /// to the current Realm governance Station.
    pub async fn submit_to_realm_authority(
        &self,
        request: &SelfAuthoritySubmitRequest,
        options: &ClientRequestOptions,
    ) -> Result<SelfAuthoritySubmitOutcome> {
        request.validate()?;
        let outcome: SelfAuthoritySubmitOutcome = self
            .post_with_options("/_arkret/self/events", request, options)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Submit one explicitly discriminated peer Event ingress branch.
    pub async fn submit_to_peer_authority(
        &self,
        request: &PeerAuthoritySubmitRequest,
        options: &ClientRequestOptions,
    ) -> Result<PeerAuthoritySubmitOutcome> {
        request.validate()?;
        let outcome: PeerAuthoritySubmitOutcome = self
            .post_with_options("/_arkret/peer/events", request, options)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Read one authorized independent Realm, Circle, or Sidecar stream.
    pub async fn scan_commit_stream(
        &self,
        request: &StreamScanRequest,
    ) -> Result<StreamScanOutcome> {
        request.validate()?;
        let outcome: StreamScanOutcome = self.post("/_arkret/self/streams/scan", request).await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Receive original peer rows and frozen facts. Caller independently authenticates every
    /// original.
    pub async fn scan_peer_commit_stream(
        &self,
        request: &StreamScanRequest,
        options: &ClientRequestOptions,
    ) -> Result<PeerStreamScanOutcome> {
        request.validate()?;
        let outcome: PeerStreamScanOutcome = self
            .post_with_options("/_arkret/peer/streams/scan", request, options)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Resolve the nonce-bound genesis-to-current authority chain.
    pub async fn realm_authority_bundle(
        &self,
        request: &AuthorityBundleRequest,
    ) -> Result<RealmAuthorityBundle> {
        request.validate()?;
        let builder = self.canonical_json_body(
            self.public_request(Method::POST, "/_arkret/open/realm-authority/bundle")?,
            request,
        )?;
        let outcome: RealmAuthorityBundle = self.send_json(builder).await?;
        outcome.validate_for_request(request, chrono::Utc::now())?;
        Ok(outcome)
    }

    /// Install a planned handoff after importing the complete private stream
    /// head manifest and the signed typed snapshot.
    pub async fn install_realm_authority_handoff(
        &self,
        request: &AuthorityHandoffRequest,
        options: &ClientRequestOptions,
    ) -> Result<RealmAuthorityHandoff> {
        request.validate_new_handoff()?;
        let outcome: RealmAuthorityHandoff = self
            .post_with_options("/_arkret/peer/realm-authority/handoff", request, options)
            .await?;
        outcome.validate_shape()?;
        if outcome != request.handoff {
            return Err(Error::Protocol(
                "authority handoff response changed the installed handoff".to_owned(),
            ));
        }
        Ok(outcome)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn routed_open_authority_bundle_never_forwards_account_credentials() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let captured = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0_u8; 4096];
            let count = stream.read(&mut bytes).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\n\r\n{}")
                .await
                .unwrap();
            String::from_utf8_lossy(&bytes[..count]).to_ascii_lowercase()
        });
        let own = Client::builder(url::Url::parse("https://account.example/").unwrap())
            .allow_insecure_localhost()
            .auth(crate::Auth::Dpop(crate::DpopAuth::with_dpop_token(
                "account-grant-must-stay-local",
                |_| panic!("an open authority request must not sign an Account DPoP proof"),
            )))
            .build()
            .unwrap();
        let remote = own
            .with_base_url(url::Url::parse(&format!("http://{address}/")).unwrap())
            .unwrap();
        let request = AuthorityBundleRequest {
            realm_id: arkret_wire::RealmId::new(
                "ak:realm:AfF-hFqRoMbajXkPapH-xaq0xwK-UKt2ph2zTs9JZRAO",
            )
            .unwrap(),
            nonce: arkret_wire::Base64UrlString::new("BBBBBBBBBBBBBBBBBBBBBB").unwrap(),
        };
        assert!(remote.realm_authority_bundle(&request).await.is_err());
        let request = captured.await.unwrap();
        assert!(request.starts_with("post /_arkret/open/realm-authority/bundle "));
        assert!(request.contains("ak.open.realm_authority.read.bundle.v1"));
        assert!(!request.contains("authorization:"));
        assert!(!request.contains("dpop:"));
        assert!(!request.contains("account-grant-must-stay-local"));
    }
}
