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
    PeerRealmJoinBootstrapOutcome, PeerRealmJoinBootstrapRequestBody, PeerRealmJoinPreviewOutcome,
    PeerRealmJoinPreviewRequestBody, RealmJoinApplicationStatusOutcome,
    RealmJoinApplicationStatusRequest, SelfRealmJoinPrepareOutcome, SelfRealmJoinPrepareRequestBody,
    SelfRealmJoinPreviewOutcome, SelfRealmJoinPreviewRequestBody,
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
        request: &SelfRealmJoinPreviewRequestBody,
    ) -> Result<SelfRealmJoinPreviewOutcome> {
        request.target.validate()?;
        let outcome: SelfRealmJoinPreviewOutcome = self
            .post("/_arkret/self/realm-joins/preview", request)
            .await?;
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
        request: &SelfRealmJoinPrepareRequestBody,
    ) -> Result<SelfRealmJoinPrepareOutcome> {
        request.target.validate()?;
        let outcome: SelfRealmJoinPrepareOutcome = self
            .post_protocol_replay_safe("/_arkret/self/realm-joins/prepare", request)
            .await?;
        Ok(outcome)
    }

    /// Read how far one own join application has progressed, before membership
    /// exists.
    pub async fn self_realm_join_application_status(
        &self,
        request: &RealmJoinApplicationStatusRequest,
    ) -> Result<RealmJoinApplicationStatusOutcome> {
        let outcome: RealmJoinApplicationStatusOutcome = self
            .post("/_arkret/self/realm-joins/application-status", request)
            .await?;
        outcome.validate()?;
        Ok(outcome)
    }

    /// Read the pre-join preview of one directed invite from the exact inviter
    /// Station.
    ///
    /// Service-to-service only: the invitee's own Station calls this, and the
    /// invitee's local bearer or session credential is never forwarded.
    pub async fn peer_realm_join_preview(
        &self,
        request: &PeerRealmJoinPreviewRequestBody,
    ) -> Result<PeerRealmJoinPreviewOutcome> {
        let outcome: PeerRealmJoinPreviewOutcome = self
            .post("/_arkret/peer/realm-joins/preview", request)
            .await?;
        Ok(outcome)
    }

    /// Fetch the bounded material required to author and verify exactly one
    /// join attempt from an existing member Station.
    ///
    /// The returned facts are not trusted as they stand: the caller verifies
    /// them by complete governance replay and its own accepted state before
    /// preparing anything from them.
    pub async fn peer_realm_join_bootstrap(
        &self,
        request: &PeerRealmJoinBootstrapRequestBody,
    ) -> Result<PeerRealmJoinBootstrapOutcome> {
        let outcome: PeerRealmJoinBootstrapOutcome = self
            .post("/_arkret/peer/realm-joins/bootstrap", request)
            .await?;
        Ok(outcome)
    }

    /// Read the restricted outcome of one forwarded join application from the
    /// member Station that accepted it.
    pub async fn peer_realm_join_application_status(
        &self,
        request: &RealmJoinApplicationStatusRequest,
    ) -> Result<RealmJoinApplicationStatusOutcome> {
        let outcome: RealmJoinApplicationStatusOutcome = self
            .post("/_arkret/peer/realm-joins/application-status", request)
            .await?;
        outcome.validate()?;
        Ok(outcome)
    }
}
