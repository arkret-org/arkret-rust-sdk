//! Relation conflict repair-material endpoint methods on [`Client`].

use arkret_models_collaboration::objects::relation::{
    RelationConflictBaseline, RelationConflictCandidatesOutcome,
    RelationConflictCandidatesRequestBody, RelationConflictDomain,
    RelationConflictMaterialVerifier,
};
use arkret_wire::{EventId, RealmId};

use crate::{Client, Error, Result};

impl Client {
    /// Read one page of the frozen repair material for a Relation primary
    /// conflict domain.
    ///
    /// A single page proves nothing on its own; use
    /// [`Client::relation_conflict_candidates_all`] unless the caller is
    /// implementing its own resumable walk and will still verify the complete
    /// chain against `baseline.members_digest` before signing anything.
    pub async fn relation_conflict_candidates(
        &self,
        request: &RelationConflictCandidatesRequestBody,
    ) -> Result<RelationConflictCandidatesOutcome> {
        request.validate()?;
        let outcome: RelationConflictCandidatesOutcome = self
            .events_read_query("/_arkret/self/relation-conflicts/candidates", request)
            .await?;
        outcome.validate_for_request(request)?;
        Ok(outcome)
    }

    /// Walk every page of one domain's repair material and return the verified
    /// member set together with the baseline it reproduces.
    ///
    /// The walk restarts nothing and stitches nothing: a dropped, reordered,
    /// duplicated or short page fails closed inside
    /// [`RelationConflictMaterialVerifier`], because a partially verified
    /// member set is exactly what must never reach an `ak.relation.resolve`.
    pub async fn relation_conflict_candidates_all(
        &self,
        realm_id: &RealmId,
        conflict_domain: &RelationConflictDomain,
        suite: arkret_canonical::DigestSuite,
    ) -> Result<(Vec<EventId>, RelationConflictBaseline)> {
        let mut request = RelationConflictCandidatesRequestBody {
            realm_id: realm_id.clone(),
            conflict_domain: conflict_domain.clone(),
            cursor: None,
        };
        let mut verifier = RelationConflictMaterialVerifier::new(
            realm_id.clone(),
            conflict_domain.clone(),
            suite,
        )?;
        let mut carried: Option<RelationConflictBaseline> = None;
        let baseline = loop {
            let outcome = self.relation_conflict_candidates(&request).await?;
            // The group changing mid-walk is the other way material can go
            // stale, and it is invisible to the page chain alone.
            if carried
                .as_ref()
                .is_some_and(|first| first != &outcome.baseline)
            {
                return Err(Error::Protocol(
                    "relation_conflict_material_page_gap: the baseline changed during the walk"
                        .to_owned(),
                ));
            }
            verifier.push_page(&outcome.page)?;
            match outcome.page.next_cursor.clone() {
                Some(cursor) => {
                    request.cursor = Some(cursor);
                    carried = Some(outcome.baseline);
                }
                None => break outcome.baseline,
            }
        };
        let members = verifier.finish(&baseline)?;
        Ok((members, baseline))
    }
}
