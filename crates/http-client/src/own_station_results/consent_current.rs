//! Independent authority anchoring for holder-private Consent current reads.

use arkret_identity::{
    DidVerificationRelationship, VerifiedRealmAuthority,
    resolve_verification_method_key_from_document, validate_verification_method_relationship,
};
use arkret_models_collaboration::consent_operations::{
    ConsentCurrentReadRequestBody, ConsentCurrentReadResponseBody,
};
use arkret_models_identity::{AuthenticatedServiceResolution, DidDocument};
use arkret_wire::{
    AccountId, CommitStreamHead, CommitStreamRef, CommittedEventView, Did, DidCoreId, EventId,
    GenesisGovernance, RealmCommitAuthorityRef, RealmId, ScopeRef, ServiceKind,
};
use chrono::{DateTime, Utc};

use super::{BoundOwnStationResponse, OwnStationSessionSnapshot, OwnStationStateClient, protocol};
use crate::Result;

/// Independent expected authority for one holder PCR. This is not a wire DTO.
/// A Human root is pinned to its accepted session and initial tenure; other
/// authorities can only originate from a verified Realm authority chain.
pub struct ConsentCurrentReadAuthority {
    realm_id: RealmId,
    generation: u64,
    service_id: DidCoreId,
    service_did: Option<Did>,
    human_session: Option<OwnStationSessionSnapshot>,
    authority_expires_at: Option<DateTime<Utc>>,
    minimum_head: CommitStreamHead,
}

impl ConsentCurrentReadAuthority {
    /// Derive Human tenure zero from an original already accepted through the
    /// exact live own-Station session. The PCR is independently registered,
    /// never learned from a Consent response or an arbitrary Genesis carrier.
    pub fn from_human_genesis(
        holder: &AccountId,
        registered_pcr: &RealmId,
        genesis: &BoundOwnStationResponse<EventId, CommittedEventView>,
    ) -> Result<Self> {
        let original = genesis.value()?;
        let CommittedEventView::Full(full) = original else {
            return Err(protocol(
                "Human Consent authority requires the original PCR Genesis",
            ));
        };
        full.validate_shape()?;
        full.commit.validate_content_address()?;
        let event = &full.event;
        event.verify_event_id_matches_content_with_digest_suite(
            arkret_canonical::DigestSuite::Sha256,
        )?;
        if genesis.session().account_id() != holder
            || genesis.request() != &event.event_id
            || &event.realm_id != registered_pcr
            || RealmId::from_event_id(&event.event_id) != *registered_pcr
            || event.scope_ref != ScopeRef::RealmGenesis
            || full.commit.stream_ref
                != (CommitStreamRef::Realm {
                    realm_id: registered_pcr.clone(),
                })
            || full.commit.stream_position != 0
            || full.commit.previous_commit_ref.is_some()
            || full.commit.governance_generation != 0
            || full.commit.authority_ref
                != RealmCommitAuthorityRef::GenesisOrChangeEvent(event.event_id.clone())
            || !matches!(GenesisGovernance::from_genesis(event)?, GenesisGovernance::Human(ref account) if account == holder)
        {
            return Err(protocol(
                "Human Consent authority differs from the accepted holder PCR Genesis",
            ));
        }
        Ok(Self {
            realm_id: registered_pcr.clone(),
            generation: 0,
            service_id: holder.station_id.clone(),
            service_did: None,
            human_session: Some(genesis.session().clone()),
            authority_expires_at: None,
            minimum_head: CommitStreamHead {
                stream_ref: full.commit.stream_ref.clone(),
                stream_position: 0,
                commit_id: full.commit.commit_id.clone(),
            },
        })
    }

    /// The verified chain alone supplies authority and generation. Its known
    /// route record supplies only a locator, which is resolved independently
    /// again before consuming a new Consent assertion.
    pub fn from_verified_realm(
        authority: &VerifiedRealmAuthority,
        current_route_record: &AuthenticatedServiceResolution,
    ) -> Result<Self> {
        Self::from_verified_realm_at(authority, current_route_record, Utc::now())
    }

    fn from_verified_realm_at(
        authority: &VerifiedRealmAuthority,
        current_route_record: &AuthenticatedServiceResolution,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        let expires_at = authority
            .current_assertion_expires_at()
            .filter(|expires_at| *expires_at > now)
            .ok_or_else(|| {
                protocol("Consent authority requires a fresh verified current assertion")
            })?;
        current_route_record.validate_shape(authority.current_service_id(), now)?;
        if current_route_record.service_kind != "station" {
            return Err(protocol("Consent authority route is not a Station"));
        }
        Ok(Self {
            realm_id: authority.realm_id().clone(),
            generation: authority.current_generation(),
            service_id: authority.current_service_id().clone(),
            service_did: Some(current_route_record.normalized_did_document.id.clone()),
            human_session: None,
            authority_expires_at: Some(expires_at),
            minimum_head: authority
                .current_realm_stream_head()
                .ok_or_else(|| {
                    protocol("Consent authority has no independently verified current head")
                })?
                .clone(),
        })
    }

    pub fn realm_id(&self) -> &RealmId {
        &self.realm_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    fn validate_client(
        &self,
        client: &OwnStationStateClient,
        request: &ConsentCurrentReadRequestBody,
        registered_pcr: &RealmId,
    ) -> Result<()> {
        client.check_session()?;
        request.validate()?;
        if self
            .authority_expires_at
            .is_some_and(|deadline| deadline <= Utc::now())
            || &request.holder_account_id != client.session()?.account_id()
            || &self.realm_id != registered_pcr
            || self.human_session.as_ref().is_some_and(|session| {
                session != &client.session
                    || self.service_id != request.holder_account_id.station_id
                    || self.generation != 0
            })
        {
            return Err(protocol(
                "Consent authority differs from the live holder session or registered PCR",
            ));
        }
        Ok(())
    }

    async fn current_document(&self, client: &OwnStationStateClient) -> Result<DidDocument> {
        let locator = if let Some(did) = &self.service_did {
            did.clone()
        } else {
            // The accepted connection pins this service id. This carrier
            // supplies a locator only, never a current key or generation.
            let advertised = client
                .client
                .open_service_resolution(&self.service_id)
                .await?;
            advertised.validate_shape(&self.service_id, Utc::now())?;
            if advertised.service_kind != "station" {
                return Err(protocol("Consent authority locator is not a Station"));
            }
            advertised.normalized_did_document.id
        };
        if arkret_wire::project_did_to_core_id(&locator)? != self.service_id {
            return Err(protocol("Consent authority locator names another service"));
        }
        let current = client
            .client
            .resolve_service_from_did(&locator, ServiceKind::Station)
            .await?;
        current.validate_shape(&self.service_id, Utc::now())?;
        if current.service_kind != "station" {
            return Err(protocol(
                "Consent authority current method state is not a Station",
            ));
        }
        Ok(current.normalized_did_document)
    }

    fn verify_outcome(
        &self,
        request: &ConsentCurrentReadRequestBody,
        outcome: &ConsentCurrentReadResponseBody,
        current_document: &DidDocument,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if self
            .authority_expires_at
            .is_some_and(|deadline| deadline <= now)
            || outcome.realm_id != self.realm_id
            || arkret_wire::project_did_to_core_id(&current_document.id)? != self.service_id
        {
            return Err(protocol(
                "Consent current read differs from independently anchored PCR or service",
            ));
        }
        outcome.validate_for_request(request, self.generation, now)?;
        let head = &outcome.effective_stream_head;
        if head.stream_ref != self.minimum_head.stream_ref
            || head.stream_position < self.minimum_head.stream_position
            || (head.stream_position == self.minimum_head.stream_position
                && head.commit_id != self.minimum_head.commit_id)
        {
            return Err(protocol(
                "Consent current read rolls back or forks its independently verified head",
            ));
        }
        // The untrusted proof may select only a method authorized by the
        // independently resolved current document. It never drives discovery.
        validate_verification_method_relationship(
            current_document,
            &outcome.proof.verification_method,
            &current_document.id,
            DidVerificationRelationship::AssertionMethod,
        )
        .map_err(|error| protocol(&error.to_string()))?;
        let key = resolve_verification_method_key_from_document(
            current_document,
            outcome.proof.verification_method.as_str(),
        )?;
        arkret_signatures::call_invitation::verify_consent_current_read(
            outcome,
            request,
            &outcome.proof.verification_method,
            &key.public_key,
            self.generation,
            now,
        )?;
        Ok(())
    }
}

impl OwnStationStateClient {
    /// Return a session-bound Consent value only after independently checking
    /// its registered PCR, authority tenure, current assertion method and JWS.
    /// Ordinary own-Station synchronization keeps its separate trust contract.
    pub async fn consent_current(
        &self,
        request: &ConsentCurrentReadRequestBody,
        registered_pcr: &RealmId,
        authority: &ConsentCurrentReadAuthority,
    ) -> Result<
        BoundOwnStationResponse<ConsentCurrentReadRequestBody, ConsentCurrentReadResponseBody>,
    > {
        authority.validate_client(self, request, registered_pcr)?;
        let document = authority.current_document(self).await?;
        self.consent_current_with_document(request, registered_pcr, authority, &document)
            .await
    }

    async fn consent_current_with_document(
        &self,
        request: &ConsentCurrentReadRequestBody,
        registered_pcr: &RealmId,
        authority: &ConsentCurrentReadAuthority,
        document: &DidDocument,
    ) -> Result<
        BoundOwnStationResponse<ConsentCurrentReadRequestBody, ConsentCurrentReadResponseBody>,
    > {
        authority.validate_client(self, request, registered_pcr)?;
        let value = self.client.consent_current_read(request).await?;
        authority.verify_outcome(request, &value, document, Utc::now())?;
        authority.validate_client(self, request, registered_pcr)?;
        let valid_until = authority
            .authority_expires_at
            .map_or(value.expires_at, |deadline| deadline.min(value.expires_at));
        let mut response = self.bind(request.clone(), value)?;
        response.valid_until = Some(valid_until);
        response.value()?;
        Ok(response)
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
