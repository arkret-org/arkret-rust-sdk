//! First cross-station Realm join endpoints on [`Client`].
//!
//! The four `self` and `peer` faces of `realm-join-intake.schema.json`
//! (`sync/federation.md` sections 5.3 to 5.3.4, `sync/invite-addressing.md`
//! section 7.1). Every outcome is checked against the exact request that
//! produced it before it is returned, because these results reach a caller
//! that is not yet a member and therefore has no accepted state to compare
//! them with.
//!
//! Submission itself is not here: a prepared join is signed by the caller and
//! goes through `ak.self.events.command.submit.v1` like any other Control
//! Move.

use arkret_models_collaboration::governance::realm_join_intake::{
    RealmJoinBootstrapOutcome, RealmJoinBootstrapRequestBody,
    RealmJoinPeerApplicationStatusOutcome, RealmJoinPeerApplicationStatusRequestBody,
    RealmJoinPrepareOutcome, RealmJoinPrepareRequestBody, RealmJoinSelfApplicationStatusOutcome,
    RealmJoinSelfApplicationStatusRequestBody,
};
use arkret_models_discovery::realm_join_preview::{
    RealmJoinPeerPreviewOutcome, RealmJoinPeerPreviewRequestBody, RealmJoinSelfPreviewOutcome,
    RealmJoinSelfPreviewRequestBody,
};

use crate::{Client, Result};

impl Client {
    /// Read a pre-join Realm preview from this account's own Station.
    ///
    /// This is the only preview entry point a client has. The Station reaches
    /// the exact inviter Station for a directed invite and the Directory
    /// discovery input surface otherwise; the client never contacts either.
    pub async fn self_realm_join_preview(
        &self,
        request: &RealmJoinSelfPreviewRequestBody,
    ) -> Result<RealmJoinSelfPreviewOutcome> {
        request.validate()?;
        let outcome: RealmJoinSelfPreviewOutcome = self
            .post("/_arkret/self/realm-joins/preview", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Freeze every input of one join attempt: the verified governance facts,
    /// the exact Event kind, the canonical payload and the preconditions.
    ///
    /// The caller checks target, purpose, request binding and the bytes it is
    /// about to sign, then signs and submits. It never fetches remote
    /// governance evidence, recomputes Seal roots, selects a candidate
    /// endpoint or runs a reducer.
    pub async fn self_realm_join_prepare(
        &self,
        request: &RealmJoinPrepareRequestBody,
    ) -> Result<RealmJoinPrepareOutcome> {
        request.validate()?;
        let outcome: RealmJoinPrepareOutcome = self
            .post_protocol_replay_safe("/_arkret/self/realm-joins/prepare", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Read how far one own join application has progressed, before membership
    /// exists.
    pub async fn self_realm_join_application_status(
        &self,
        request: &RealmJoinSelfApplicationStatusRequestBody,
    ) -> Result<RealmJoinSelfApplicationStatusOutcome> {
        request.validate()?;
        let outcome: RealmJoinSelfApplicationStatusOutcome = self
            .post("/_arkret/self/realm-joins/application-status", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Read the pre-join preview of one directed invite from the exact inviter
    /// Station.
    ///
    /// Service-to-service only: the invitee's own Station calls this, and the
    /// invitee's local bearer or session credential is never forwarded.
    pub async fn peer_realm_join_preview(
        &self,
        request: &RealmJoinPeerPreviewRequestBody,
    ) -> Result<RealmJoinPeerPreviewOutcome> {
        request.validate()?;
        let outcome: RealmJoinPeerPreviewOutcome = self
            .post("/_arkret/peer/realm-joins/preview", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Fetch the bounded material required to author and verify exactly one
    /// join attempt from an existing member Station.
    ///
    /// The returned facts are not trusted as they stand: the caller verifies
    /// them against `dependency_bundles` and its own accepted state before
    /// preparing anything from them.
    pub async fn peer_realm_join_bootstrap(
        &self,
        request: &RealmJoinBootstrapRequestBody,
    ) -> Result<RealmJoinBootstrapOutcome> {
        request.validate()?;
        let outcome: RealmJoinBootstrapOutcome = self
            .post("/_arkret/peer/realm-joins/bootstrap", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Read the restricted outcome of one forwarded join application from the
    /// member Station that accepted it.
    pub async fn peer_realm_join_application_status(
        &self,
        request: &RealmJoinPeerApplicationStatusRequestBody,
    ) -> Result<RealmJoinPeerApplicationStatusOutcome> {
        request.validate()?;
        let outcome: RealmJoinPeerApplicationStatusOutcome = self
            .post("/_arkret/peer/realm-joins/application-status", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }
}
