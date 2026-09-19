//! Authority-commit submission, replication, discovery, and handoff methods.

use arkret_models_collaboration::authority_commit::{
    PeerAuthoritySubmitOutcome, PeerAuthoritySubmitRequest, SelfAuthoritySubmitOutcome,
    SelfAuthoritySubmitRequest,
};
use arkret_wire::{
    AuthorityBundleRequest, AuthorityHandoffRequest, CommittedEventResolveOutcome,
    CommittedEventResolveRequest, RealmAuthorityBundle, RealmAuthorityHandoff, StreamScanOutcome,
    StreamScanRequest,
};
use reqwest::Method;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::{Client, ClientRequestOptions, Error, Result};

impl Client {
    pub(crate) async fn events_read_query<T, B>(&self, path: &str, body: &B) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let query_method = Method::from_bytes(b"QUERY").expect("QUERY is a registered HTTP method");
        let request = self.canonical_json_body(self.request(query_method, path)?, body)?;
        self.send_json(request).await
    }

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

    /// Resolve exact authority-committed Events by their closed commit refs.
    pub async fn resolve_committed_events(
        &self,
        request: &CommittedEventResolveRequest,
    ) -> Result<CommittedEventResolveOutcome> {
        request.validate()?;
        let outcome: CommittedEventResolveOutcome =
            self.post("/_arkret/peer/streams/resolve", request).await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Resolve the nonce-bound genesis-to-current authority chain.
    pub async fn realm_authority_bundle(
        &self,
        request: &AuthorityBundleRequest,
    ) -> Result<RealmAuthorityBundle> {
        request.validate()?;
        let outcome: RealmAuthorityBundle = self
            .post("/_arkret/open/realm-authority/bundle", request)
            .await?;
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
        request.validate_shape()?;
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
