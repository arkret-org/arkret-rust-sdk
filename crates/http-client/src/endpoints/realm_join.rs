//! First cross-station Realm join endpoints on [`Client`].
//!
//! The `self` and `peer` faces of `realm-join-intake.schema.json`
//! (`sync/federation.md` sections 5.3 to 5.3.4, `sync/invite-addressing.md`
//! section 7.1). There is no application-status read: a join Event's outcome
//! comes back synchronously from Event submit and an uncertain result is
//! resolved by an exact retry of the same bytes. Every outcome is checked against the exact request
//! that produced it before it is returned, because these results reach a caller
//! that is not yet a member and therefore has no accepted state to compare
//! them with.
//!
//! Submission itself is not here: a prepared join is signed by the caller and
//! goes through `ak.self.events.command.submit.v1` like any other Control
//! Move.

use arkret_models_collaboration::governance::realm_join_intake::{
    PeerRealmJoinBootstrapOutcome, PeerRealmJoinBootstrapRequestBody, PeerRealmJoinPreviewOutcome,
    PeerRealmJoinPreviewRequestBody, SelfRealmJoinPrepareOutcome, SelfRealmJoinPrepareRequestBody,
    SelfRealmJoinPreviewOutcome, SelfRealmJoinPreviewRequestBody,
};

use crate::{Client, Result};

impl Client {
    /// Read a pre-join Realm preview from this account's own Station.
    ///
    /// This is the only preview entry point a client has. The Station verifies
    /// the Realm's current governance Station with its own nonce from the
    /// target's locator hints and reads the preview from it; the client never
    /// contacts the inviter Station, a Directory or the governance Station.
    pub async fn self_realm_join_preview(
        &self,
        request: &SelfRealmJoinPreviewRequestBody,
    ) -> Result<SelfRealmJoinPreviewOutcome> {
        request.validate()?;
        let outcome: SelfRealmJoinPreviewOutcome = self
            .post("/_arkret/self/realm-joins/preview", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Return the verified, nonce-bound authority bundle and current Realm
    /// stream head for one join attempt. This read neither reserves a commit
    /// position nor authorizes admission of a later producer-signed Event.
    pub async fn self_realm_join_prepare(
        &self,
        request: &SelfRealmJoinPrepareRequestBody,
    ) -> Result<SelfRealmJoinPrepareOutcome> {
        request.validate()?;
        let outcome: SelfRealmJoinPrepareOutcome = self
            .post_protocol_replay_safe("/_arkret/self/realm-joins/prepare", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Read a pre-join preview from the Realm's current governance Station.
    ///
    /// Service-to-service only: the invitee's own Station calls this, and the
    /// invitee's local bearer or session credential is never forwarded.
    pub async fn peer_realm_join_preview(
        &self,
        request: &PeerRealmJoinPreviewRequestBody,
    ) -> Result<PeerRealmJoinPreviewOutcome> {
        request.validate()?;
        let outcome: PeerRealmJoinPreviewOutcome = self
            .post("/_arkret/peer/realm-joins/preview", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Fetch one signed snapshot and the stream heads visible after the
    /// membership Commit. The caller verifies the authority bundle and
    /// snapshot, then scans each permitted stream to its advertised head.
    pub async fn peer_realm_join_bootstrap(
        &self,
        request: &PeerRealmJoinBootstrapRequestBody,
    ) -> Result<PeerRealmJoinBootstrapOutcome> {
        let outcome: PeerRealmJoinBootstrapOutcome = self
            .post("/_arkret/peer/realm-joins/bootstrap", request)
            .await?;
        Ok(outcome)
    }
}
