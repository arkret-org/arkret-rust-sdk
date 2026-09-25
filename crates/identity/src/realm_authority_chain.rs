//! Cryptographic genesis-to-current verification of the Realm authority chain.
//!
//! [`arkret_wire::RealmAuthorityBundle::validate_shape`] decides only whether
//! the carried coordinates agree with one another. It says so itself:
//! "Cryptographic verification and freshness are caller responsibilities and
//! must fail closed." This module is that caller responsibility, expressed
//! once, here, so no downstream service re-derives the rule and drifts.
//!
//! What a verified bundle establishes:
//!
//! 1. the genesis `RealmCommit` is signed by the generation-0 governance Station and addresses the
//!    exact genesis Event;
//! 2. every authority transition is a **planned, doubly signed handoff** — the outgoing Station
//!    signs under [`DetachedSignatureContext::RealmAuthorityHandoffOld`] and the incoming Station
//!    signs the same unsigned body under
//!    [`DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance`]. The two domains are
//!    deliberately different: one signature can never stand in for the other, and a single Station
//!    cannot manufacture a transition by signing twice in one domain;
//! 3. the generations form one contiguous chain — `0, 1, ... current_generation` — with no skipped
//!    number and no fork, and each hop starts at the Station the previous hop ended on;
//! 4. `current_route_record` is a method-native authenticated service resolution for
//!    `current_service_id`, and the online assertion is signed by a verification method of *that*
//!    document. Losing a Station does not open an election or a takeover path: there is no
//!    admissible input to this verifier that installs a new authority without the outgoing one's
//!    signature.
//!
//! Freshness is an explicit parameter ([`RealmAuthorityFreshness`]). The
//! library never reads the wall clock, so a caller cannot accidentally accept
//! a replayed bundle because the machine it verified on happened to agree.
//!
//! Key material is supplied through [`RealmAuthorityKeyDirectory`]. Resolving a
//! DID is an I/O act with an egress policy attached; it does not belong inside
//! a pure verifier. A verification method the directory does not know is
//! [`RealmAuthorityChainError::MaterialIncomplete`] — never a pass.

use std::collections::BTreeMap;

use arkret_canonical::canonical;
use arkret_models_identity::{AuthenticatedServiceResolution, ResolutionMethodHistoryEvidence};
use arkret_signatures::PublicKeyMaterial;
use arkret_signatures::detached_object::verify_detached_object_signature;
use arkret_wire::{
    Base64UrlString, CommittedEventFullView, DetachedObjectSignature, DetachedSignatureContext,
    Did, DidCoreId, DidUrl, Event, EventId, RealmAuthorityBundle, RealmAuthorityHandoffId,
    RealmCommit, RealmCommitAuthorityRef, RealmId, project_did_to_core_id,
};
use chrono::{DateTime, Utc};

/// Every way the authority chain can fail to establish its claim.
///
/// The variants are separated because the operator responses differ: missing
/// material can be retried once the resolver has the document, a broken chain
/// or an invalid signature never can.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RealmAuthorityChainError {
    /// A verification method, key, or carrier the verifier needs was not
    /// supplied. This is the one retryable variant; it still fails closed.
    #[error("realm authority material is incomplete: {0}")]
    MaterialIncomplete(String),
    /// The genesis-to-current chain does not connect: a missing hop, a fork, a
    /// Station that does not continue its predecessor, or a coordinate that
    /// contradicts the carried records.
    #[error("realm authority chain is broken: {0}")]
    ChainBroken(String),
    /// A detached signature did not verify, carried the wrong domain context,
    /// or did not address the body it claims to seal.
    #[error("realm authority signature is invalid: {0}")]
    SignatureInvalid(String),
    /// A generation number is not the one the chain requires: a skipped
    /// number, a non-consecutive handoff, or a Commit whose generation the
    /// bundle does not cover.
    #[error("realm authority generation does not match: {0}")]
    GenerationMismatch(String),
    /// A signature was made by a Station other than the authority of its own
    /// generation.
    #[error("realm authority signer Station binding does not hold: {0}")]
    StationMismatch(String),
    /// The DID route dimension does not bind: the route record is not an
    /// authenticated resolution of `current_service_id`, or the online
    /// assertion is signed by a method that document does not carry.
    #[error("realm authority route binding does not match: {0}")]
    RouteMismatch(String),
    /// The bundle is outside the freshness window the caller stated. A cached
    /// valid prefix is not evidence that no later handoff exists.
    #[error("realm authority material is not fresh: {0}")]
    NotFresh(String),
}

impl RealmAuthorityChainError {
    /// The single mapping from a chain failure to the registered protocol
    /// error code it surfaces; `None` where the spec registers no code that
    /// covers every failure the variant carries.
    ///
    /// A non-governance receiver rejects an invalid governance `RealmCommit`
    /// signature, and a Commit whose signer the verified genesis/handoff chain
    /// does not name as the governance Station of that generation, as
    /// `signature_invalid` (`sync/federation.md` section 3,
    /// `ak.vector.federation.non_governance_receiver_trusts_governance_commit.v1`);
    /// invite delivery reports every invalid signature or proof binding the
    /// same way (`sync/invite-addressing.md` section 6 step 4). A generation
    /// that the chain does not install, or a signed `governance_generation` /
    /// `authority_ref` that does not bind to the installing record, is that
    /// signer-authority binding failure.
    ///
    /// `MaterialIncomplete`, `ChainBroken`, `RouteMismatch` and `NotFresh` have
    /// no registered code: they mix structural, resolution, freshness and
    /// verifier-local causes, so the calling operation classifies them.
    #[must_use]
    pub const fn error_code(&self) -> Option<arkret_wire::ErrorCode> {
        match self {
            Self::SignatureInvalid(_) | Self::StationMismatch(_) | Self::GenerationMismatch(_) => {
                Some(arkret_wire::ErrorCode::SignatureInvalid)
            }
            Self::MaterialIncomplete(_)
            | Self::ChainBroken(_)
            | Self::RouteMismatch(_)
            | Self::NotFresh(_) => None,
        }
    }
}

/// Fail-closed outcomes when several untrusted locators have each produced a
/// cryptographically verified authority result.
///
/// A locator is intentionally absent from this API. Only
/// [`VerifiedRealmAuthority`] values returned by
/// [`verify_realm_authority_bundle`] can participate in convergence.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RealmAuthorityConvergenceError {
    /// No locator produced a complete, fresh, nonce-bound verified chain.
    #[error("no verified Realm authority chain is available")]
    NoVerifiedAuthority,
    /// Individually valid results disagree on the authority history or the
    /// current Realm-stream cut. Choosing either would create a split brain.
    #[error("verified Realm authority chains conflict")]
    ConflictingVerifiedAuthorities,
}

type ChainResult<T> = Result<T, RealmAuthorityChainError>;

use RealmAuthorityChainError as E;

/// Public key material for the verification methods an authority chain names.
///
/// Implementations resolve however the deployment resolves DIDs; the verifier
/// only ever asks, and treats a `None` as incomplete material.
pub trait RealmAuthorityKeyDirectory {
    fn public_key(&self, verification_method: &DidUrl) -> Option<PublicKeyMaterial>;
}

/// Pre-resolved key material, keyed by the exact verification-method DID URL.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RealmAuthorityKeyMap {
    keys: BTreeMap<String, PublicKeyMaterial>,
}

impl RealmAuthorityKeyMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        verification_method: &DidUrl,
        key: PublicKeyMaterial,
    ) -> Option<PublicKeyMaterial> {
        self.keys
            .insert(verification_method.as_str().to_owned(), key)
    }

    #[must_use]
    pub fn with_key(mut self, verification_method: &DidUrl, key: PublicKeyMaterial) -> Self {
        self.insert(verification_method, key);
        self
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl RealmAuthorityKeyDirectory for RealmAuthorityKeyMap {
    fn public_key(&self, verification_method: &DidUrl) -> Option<PublicKeyMaterial> {
        self.keys.get(verification_method.as_str()).cloned()
    }
}

/// Adapt a closure — typically "ask the deployment's DID resolver" — into a
/// [`RealmAuthorityKeyDirectory`].
///
/// A blanket `impl<F: Fn(..)>` would collide with the concrete
/// [`RealmAuthorityKeyMap`] impl under coherence, so the wrapper is explicit.
pub struct RealmAuthorityKeyLookup<F>(pub F);

impl<F> RealmAuthorityKeyDirectory for RealmAuthorityKeyLookup<F>
where
    F: Fn(&DidUrl) -> Option<PublicKeyMaterial>,
{
    fn public_key(&self, verification_method: &DidUrl) -> Option<PublicKeyMaterial> {
        (self.0)(verification_method)
    }
}

/// The caller's own clock and nonce.
///
/// `expected_nonce` must be the nonce the caller put in its own
/// [`arkret_wire::AuthorityBundleRequest`]. Accepting a bundle whose assertion
/// answers somebody else's nonce is accepting a replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmAuthorityFreshness {
    pub now: DateTime<Utc>,
    pub expected_nonce: Base64UrlString,
}

impl RealmAuthorityFreshness {
    pub fn new(now: DateTime<Utc>, expected_nonce: Base64UrlString) -> Self {
        Self {
            now,
            expected_nonce,
        }
    }
}

/// The authority of one generation, and the records that may legitimately be
/// named as having installed it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct GenerationAuthority {
    service_id: DidCoreId,
    /// Generation 0: the genesis Event. Generation `k > 0`: either the handoff
    /// record or the governance-station change Event it carries — the closed
    /// union `RealmCommitAuthorityRef` admits exactly these two spellings.
    installing_event: EventId,
    installing_handoff: Option<RealmAuthorityHandoffId>,
}

impl GenerationAuthority {
    fn admits(&self, authority_ref: &RealmCommitAuthorityRef) -> bool {
        match authority_ref {
            RealmCommitAuthorityRef::GenesisOrChangeEvent(event_id) => {
                *event_id == self.installing_event
            }
            RealmCommitAuthorityRef::Handoff(handoff_id) => {
                self.installing_handoff.as_ref() == Some(handoff_id)
            }
        }
    }
}

/// A fully verified authority chain, and the only thing that may be used to
/// judge an individual `RealmCommit`.
///
/// It is deliberately not constructible except by
/// [`verify_realm_authority_bundle`]: holding one *is* the proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRealmAuthority {
    realm_id: RealmId,
    current_generation: u64,
    current_service_id: DidCoreId,
    generations: BTreeMap<u64, GenerationAuthority>,
    /// Exact canonical bytes of the verified genesis, handoff history, and
    /// current stream cut. This is an internal equality witness, not a wire
    /// digest or a substitute proof. Keeping the complete bytes makes a
    /// same-id handoff equivocation or a same-generation different cut
    /// visible to convergence instead of collapsing both to coordinates.
    chain_and_cut_identity: Vec<u8>,
}

impl VerifiedRealmAuthority {
    #[must_use]
    pub fn realm_id(&self) -> &RealmId {
        &self.realm_id
    }

    #[must_use]
    pub fn current_generation(&self) -> u64 {
        self.current_generation
    }

    #[must_use]
    pub fn current_service_id(&self) -> &DidCoreId {
        &self.current_service_id
    }

    /// The governance Station that held authority at `generation`, or `None`
    /// when this bundle does not cover that generation at all.
    #[must_use]
    pub fn authority_service_at(&self, generation: u64) -> Option<&DidCoreId> {
        self.generations
            .get(&generation)
            .map(|authority| &authority.service_id)
    }

    /// Verify one `RealmCommit` against the generation that actually held
    /// authority when it was made.
    ///
    /// Structural equality against a `CommittedEventRef` is *not* part of this
    /// and must never substitute for it: matching coordinates prove only that
    /// somebody echoed the coordinates back.
    pub fn verify_commit(
        &self,
        commit: &RealmCommit,
        keys: &dyn RealmAuthorityKeyDirectory,
    ) -> ChainResult<()> {
        commit
            .validate_shape()
            .map_err(|error| E::ChainBroken(error.to_string()))?;
        if commit.realm_id != self.realm_id {
            return Err(E::ChainBroken(format!(
                "commit belongs to Realm {} but the verified authority is for {}",
                commit.realm_id, self.realm_id
            )));
        }
        let authority = self
            .generations
            .get(&commit.governance_generation)
            .ok_or_else(|| {
                E::GenerationMismatch(format!(
                    "commit claims authority generation {} but the bundle only covers 0..={}",
                    commit.governance_generation, self.current_generation
                ))
            })?;
        if !authority.admits(&commit.authority_ref) {
            return Err(E::GenerationMismatch(format!(
                "commit authority_ref does not name the record that installed generation {}",
                commit.governance_generation
            )));
        }
        let signer = signature_service_id(&commit.signature)?;
        if signer != authority.service_id {
            return Err(E::StationMismatch(format!(
                "commit at generation {} is signed by {signer}, not by that generation's \
                 governance Station {}",
                commit.governance_generation, authority.service_id
            )));
        }
        verify_commit_signature(commit, keys)
    }

    /// Verify a resolved `(RealmCommit, Event)` pair: the commit's authority,
    /// and the Event's own content binding.
    pub fn verify_committed_item(
        &self,
        item: &CommittedEventFullView,
        keys: &dyn RealmAuthorityKeyDirectory,
    ) -> ChainResult<()> {
        item.validate_shape()
            .map_err(|error| E::ChainBroken(error.to_string()))?;
        verify_event_content_binding(&item.event)?;
        self.verify_commit(&item.commit, keys)
    }
}

/// Converge authority results obtained through one or more untrusted
/// locators.
///
/// Every input has already passed genesis verification, continuous handoff
/// verification, current-route binding, and the caller-supplied nonce and
/// freshness checks because [`VerifiedRealmAuthority`] has no public
/// constructor. The results are accepted only when their exact verified
/// authority history and current Realm-stream cut agree. Empty input and any
/// disagreement fail closed.
///
/// `RealmJoinCandidate` deliberately cannot be passed here: reachability,
/// source, endpoint metadata, and a locator's own signature never establish
/// authority.
pub fn converge_verified_realm_authorities(
    authorities: &[VerifiedRealmAuthority],
) -> Result<&VerifiedRealmAuthority, RealmAuthorityConvergenceError> {
    let first = authorities
        .first()
        .ok_or(RealmAuthorityConvergenceError::NoVerifiedAuthority)?;
    if authorities.iter().skip(1).any(|candidate| {
        candidate.realm_id != first.realm_id
            || candidate.current_generation != first.current_generation
            || candidate.current_service_id != first.current_service_id
            || candidate.chain_and_cut_identity != first.chain_and_cut_identity
    }) {
        return Err(RealmAuthorityConvergenceError::ConflictingVerifiedAuthorities);
    }
    Ok(first)
}

/// Verify a [`RealmAuthorityBundle`] end to end and return the authority it
/// establishes.
///
/// Order is a security property, and it is: freshness, then every shape check,
/// then every cryptographic check. A signature is never computed over a body
/// whose coordinates have not already been agreed, and no shape agreement is
/// ever reported as acceptance.
pub fn verify_realm_authority_bundle(
    bundle: &RealmAuthorityBundle,
    freshness: &RealmAuthorityFreshness,
    keys: &dyn RealmAuthorityKeyDirectory,
) -> ChainResult<VerifiedRealmAuthority> {
    verify_freshness(bundle, freshness)?;
    let generations = walk_chain_shape(bundle)?;
    // Closed wire-shape backstop. Everything it can refuse has been refused
    // above with a classified error; it is here so a future member added to
    // the wire type cannot slip past this verifier unchecked.
    bundle
        .validate_shape()
        .map_err(|error| E::ChainBroken(error.to_string()))?;
    let resolution = verify_route_record(bundle, freshness.now)?;
    verify_chain_signatures(bundle, keys, &resolution)?;
    // Deliberately excludes the online assertion, route material, nonce, and
    // bundle issue time: two fetches of the same chain and cut may carry
    // different fresh assertion envelopes. Everything that installs
    // authority, plus the current cut whose equivocation must freeze the
    // Realm, remains in the comparison identity.
    let chain_and_cut_identity = canonical::canonical_json_bytes(&(
        &bundle.genesis_event,
        &bundle.genesis_commit,
        &bundle.authority_transitions,
        &bundle.realm_stream_head,
    ))
    .map_err(|error| E::ChainBroken(format!("cannot encode verified authority chain: {error}")))?;
    Ok(VerifiedRealmAuthority {
        realm_id: bundle.realm_id.clone(),
        current_generation: bundle.current_generation,
        current_service_id: bundle.current_service_id.clone(),
        generations,
        chain_and_cut_identity,
    })
}

fn verify_freshness(
    bundle: &RealmAuthorityBundle,
    freshness: &RealmAuthorityFreshness,
) -> ChainResult<()> {
    // The nonce-bound, unexpired current assertion is the only freshness
    // signal (`join-policy.md`, `service-surface.md` section 2.6). The caller
    // adds no bundle age limit and no clock-skew window of its own.
    if bundle.current_assertion.nonce != freshness.expected_nonce {
        return Err(E::NotFresh(
            "current assertion answers a nonce this verifier did not issue".to_owned(),
        ));
    }
    if bundle.current_assertion.expires_at <= freshness.now {
        return Err(E::NotFresh(format!(
            "current assertion expired at {}",
            bundle.current_assertion.expires_at
        )));
    }
    Ok(())
}

/// Walk genesis → transitions → current with classified errors, and build the
/// per-generation authority table the commit verifier consumes.
fn walk_chain_shape(
    bundle: &RealmAuthorityBundle,
) -> ChainResult<BTreeMap<u64, GenerationAuthority>> {
    if bundle.genesis_commit.signature.context != DetachedSignatureContext::RealmCommit {
        return Err(E::SignatureInvalid(
            "genesis commit signature is not in the realm-commit domain".to_owned(),
        ));
    }
    if bundle.genesis_commit.governance_generation != 0 {
        return Err(E::GenerationMismatch(
            "the genesis commit must carry authority generation 0".to_owned(),
        ));
    }
    if bundle.genesis_event.realm_id != bundle.realm_id
        || bundle.genesis_commit.realm_id != bundle.realm_id
    {
        return Err(E::ChainBroken(
            "genesis Event and commit must belong to the bundle's Realm".to_owned(),
        ));
    }
    if bundle.genesis_commit.event_ref != bundle.genesis_event.event_id {
        return Err(E::ChainBroken(
            "genesis commit does not address the carried genesis Event".to_owned(),
        ));
    }
    if bundle.genesis_commit.authority_ref
        != RealmCommitAuthorityRef::GenesisOrChangeEvent(bundle.genesis_event.event_id.clone())
    {
        return Err(E::ChainBroken(
            "genesis commit authority_ref does not name the genesis Event".to_owned(),
        ));
    }

    let genesis_service = signature_service_id(&bundle.genesis_commit.signature)?;
    let mut generations = BTreeMap::new();
    generations.insert(
        0,
        GenerationAuthority {
            service_id: genesis_service.clone(),
            installing_event: bundle.genesis_event.event_id.clone(),
            installing_handoff: None,
        },
    );

    let mut expected_generation = 0_u64;
    let mut expected_service = genesis_service;
    let mut last_handoff: Option<RealmAuthorityHandoffId> = None;

    for transition in &bundle.authority_transitions {
        let handoff = &transition.handoff;
        if handoff.realm_id != bundle.realm_id {
            return Err(E::ChainBroken(
                "authority handoff belongs to another Realm".to_owned(),
            ));
        }
        if handoff.from_generation != expected_generation {
            return Err(E::GenerationMismatch(format!(
                "handoff starts at generation {} where {expected_generation} is required",
                handoff.from_generation
            )));
        }
        if handoff.to_generation != handoff.from_generation.saturating_add(1) {
            return Err(E::GenerationMismatch(format!(
                "handoff jumps from generation {} to {}; generations advance by exactly one",
                handoff.from_generation, handoff.to_generation
            )));
        }
        if handoff.from_service_id != expected_service {
            return Err(E::ChainBroken(format!(
                "handoff hands over from {} but generation {} is held by {expected_service}",
                handoff.from_service_id, handoff.from_generation
            )));
        }
        if handoff.from_service_id == handoff.to_service_id {
            return Err(E::ChainBroken(
                "a handoff must transfer authority to a different Station".to_owned(),
            ));
        }
        // The two signatures live in different domains on purpose. Requiring
        // it here, before any key is fetched, is what makes "one Station signs
        // twice" structurally impossible rather than merely unlikely.
        if handoff.old_authority_signature.context
            != DetachedSignatureContext::RealmAuthorityHandoffOld
            || handoff.new_authority_acceptance_signature.context
                != DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance
        {
            return Err(E::SignatureInvalid(
                "the outgoing and incoming handoff signatures must each use their own domain \
                 context"
                    .to_owned(),
            ));
        }
        if signature_service_id(&handoff.old_authority_signature)? != handoff.from_service_id {
            return Err(E::StationMismatch(
                "outgoing handoff signature does not belong to from_service_id".to_owned(),
            ));
        }
        if signature_service_id(&handoff.new_authority_acceptance_signature)?
            != handoff.to_service_id
        {
            return Err(E::StationMismatch(
                "incoming handoff acceptance signature does not belong to to_service_id".to_owned(),
            ));
        }
        if transition.change_commit.signature.context != DetachedSignatureContext::RealmCommit {
            return Err(E::SignatureInvalid(
                "authority change commit signature is not in the realm-commit domain".to_owned(),
            ));
        }
        if transition.change_commit.governance_generation != handoff.from_generation {
            return Err(E::GenerationMismatch(format!(
                "the change commit is at generation {} but its handoff leaves generation {}",
                transition.change_commit.governance_generation, handoff.from_generation
            )));
        }
        if transition.change_commit.event_ref != transition.change_event.event_id
            || handoff.change_event_ref != transition.change_event.event_id
            || handoff.change_commit_id != transition.change_commit.commit_id
        {
            return Err(E::ChainBroken(
                "authority change Event, its commit, and the handoff do not address one another"
                    .to_owned(),
            ));
        }
        if signature_service_id(&transition.change_commit.signature)? != handoff.from_service_id {
            return Err(E::StationMismatch(
                "the change commit is not signed by the outgoing governance Station".to_owned(),
            ));
        }
        if generations.contains_key(&handoff.to_generation) {
            return Err(E::ChainBroken(format!(
                "generation {} is installed twice; the chain forks",
                handoff.to_generation
            )));
        }
        generations.insert(
            handoff.to_generation,
            GenerationAuthority {
                service_id: handoff.to_service_id.clone(),
                installing_event: transition.change_event.event_id.clone(),
                installing_handoff: Some(handoff.handoff_id.clone()),
            },
        );
        expected_generation = handoff.to_generation;
        expected_service = handoff.to_service_id.clone();
        last_handoff = Some(handoff.handoff_id.clone());
    }

    if expected_generation != bundle.current_generation {
        return Err(E::ChainBroken(format!(
            "the handoff chain reaches generation {expected_generation} but the bundle claims \
             generation {}",
            bundle.current_generation
        )));
    }
    if expected_service != bundle.current_service_id {
        return Err(E::ChainBroken(format!(
            "the handoff chain ends at {expected_service} but the bundle claims {}",
            bundle.current_service_id
        )));
    }
    if bundle.current_assertion.last_handoff_ref != last_handoff {
        return Err(E::ChainBroken(
            "current assertion does not name the last handoff of its own chain".to_owned(),
        ));
    }
    if bundle.current_assertion.signature.context
        != DetachedSignatureContext::RealmAuthorityCurrentAssertion
    {
        return Err(E::SignatureInvalid(
            "current assertion signature is not in the current-assertion domain".to_owned(),
        ));
    }
    if signature_service_id(&bundle.current_assertion.signature)? != bundle.current_service_id {
        return Err(E::StationMismatch(
            "current assertion is not signed by current_service_id".to_owned(),
        ));
    }
    Ok(generations)
}

/// The DID-route dimension: `current_route_record` must be a method-native
/// authenticated resolution of `current_service_id`, and the online assertion
/// must be signed by a verification method that same document carries.
fn verify_route_record(
    bundle: &RealmAuthorityBundle,
    now: DateTime<Utc>,
) -> ChainResult<AuthenticatedServiceResolution> {
    let resolution: AuthenticatedServiceResolution =
        serde_json::from_value(bundle.current_route_record.clone()).map_err(|error| {
            E::MaterialIncomplete(format!(
                "current_route_record is not an authenticated service resolution: {error}"
            ))
        })?;
    resolution
        .validate_shape(&bundle.current_service_id, now)
        .map_err(|error| E::RouteMismatch(error.to_string()))?;
    // WebVH carries its own verifiable history; verify it offline rather than
    // trusting the carrier. did:key is reconstructed from the identifier.
    // Mutable did:web has no history to verify, and `validate_shape` already
    // bound project(did) == current_service_id and the document digest.
    if !matches!(
        resolution.method_history_evidence,
        ResolutionMethodHistoryEvidence::DidWebDocument { .. }
    ) {
        crate::verify_authenticated_service_resolution_history(
            &resolution,
            &bundle.current_service_id,
            now,
        )
        .map_err(|error| E::RouteMismatch(error.to_string()))?;
    }
    // The unique `ArkretService` entry and its canonical https endpoint.
    resolution
        .projection()
        .map_err(|error| E::RouteMismatch(error.to_string()))?;
    let assertion_controller =
        signature_controller_did(&bundle.current_assertion.signature.verification_method)?;
    if assertion_controller != resolution.normalized_did_document.id {
        return Err(E::RouteMismatch(format!(
            "current assertion is signed under {assertion_controller} but the route record \
             resolves {}",
            resolution.normalized_did_document.id
        )));
    }
    Ok(resolution)
}

fn verify_chain_signatures(
    bundle: &RealmAuthorityBundle,
    keys: &dyn RealmAuthorityKeyDirectory,
    resolution: &AuthenticatedServiceResolution,
) -> ChainResult<()> {
    verify_event_content_binding(&bundle.genesis_event)?;
    verify_commit_signature(&bundle.genesis_commit, keys)?;

    for transition in &bundle.authority_transitions {
        verify_event_content_binding(&transition.change_event)?;
        verify_commit_signature(&transition.change_commit, keys)?;
        // Both signatures seal the same unsigned handoff body; only the domain
        // separates them.
        let unsigned = canonical::unsigned_value(
            &transition.handoff,
            &[
                "old_authority_signature",
                "new_authority_acceptance_signature",
            ],
        )
        .map_err(|error| E::ChainBroken(error.to_string()))?;
        verify_detached(
            &transition.handoff.old_authority_signature,
            &unsigned,
            DetachedSignatureContext::RealmAuthorityHandoffOld,
            keys,
        )?;
        verify_detached(
            &transition.handoff.new_authority_acceptance_signature,
            &unsigned,
            DetachedSignatureContext::RealmAuthorityHandoffNewAcceptance,
            keys,
        )?;
    }

    // The current assertion's key comes from the route document itself, not
    // from the caller's directory: the route record is precisely the
    // authenticated statement of what the current Station's keys are, so
    // consulting anything else here would weaken the binding.
    let assertion = &bundle.current_assertion;
    let verifying_key = crate::jws::resolve_ed25519_pubkey_from_document(
        &resolution.normalized_did_document,
        assertion.signature.verification_method.as_str(),
    )
    .map_err(|error| {
        E::RouteMismatch(format!(
            "current assertion verification method is not in the route document: {error}"
        ))
    })?;
    let unsigned = canonical::unsigned_value(assertion, &["signature"])
        .map_err(|error| E::ChainBroken(error.to_string()))?;
    verify_detached_object_signature(
        &assertion.signature,
        &unsigned,
        DetachedSignatureContext::RealmAuthorityCurrentAssertion,
        &PublicKeyMaterial::Ed25519Raw {
            bytes: verifying_key.to_bytes().to_vec(),
        },
    )
    .map_err(|error| E::SignatureInvalid(error.to_string()))
}

fn verify_commit_signature(
    commit: &RealmCommit,
    keys: &dyn RealmAuthorityKeyDirectory,
) -> ChainResult<()> {
    let unsigned = canonical::unsigned_value(commit, &["signature"])
        .map_err(|error| E::ChainBroken(error.to_string()))?;
    verify_detached(
        &commit.signature,
        &unsigned,
        DetachedSignatureContext::RealmCommit,
        keys,
    )
}

fn verify_detached(
    signature: &DetachedObjectSignature,
    unsigned_body: &serde_json::Value,
    expected_context: DetachedSignatureContext,
    keys: &dyn RealmAuthorityKeyDirectory,
) -> ChainResult<()> {
    let key = keys
        .public_key(&signature.verification_method)
        .ok_or_else(|| {
            E::MaterialIncomplete(format!(
                "no public key for verification method {}",
                signature.verification_method
            ))
        })?;
    verify_detached_object_signature(signature, unsigned_body, expected_context, &key)
        .map_err(|error| E::SignatureInvalid(error.to_string()))
}

/// An Event id is a digest of the Event's own canonical content. Re-deriving
/// it is what stops a bundle from pairing a real commit with a substituted
/// body.
fn verify_event_content_binding(event: &Event) -> ChainResult<()> {
    let suite =
        canonical::digest_suite(event.event_id.digest_suite_code().as_str()).map_err(|error| {
            E::ChainBroken(format!(
                "Event id carries an unusable digest suite: {error}"
            ))
        })?;
    event
        .verify_event_id_matches_content_with_digest_suite(suite)
        .map_err(|error| E::ChainBroken(error.to_string()))
}

fn signature_controller_did(verification_method: &DidUrl) -> ChainResult<Did> {
    let (controller, _) = verification_method
        .as_str()
        .split_once('#')
        .ok_or_else(|| {
            E::MaterialIncomplete(format!(
                "verification method {verification_method} has no fragment"
            ))
        })?;
    Did::new(controller.to_owned()).map_err(|error| {
        E::MaterialIncomplete(format!(
            "verification method {verification_method} does not name a DID: {error}"
        ))
    })
}

fn signature_service_id(signature: &DetachedObjectSignature) -> ChainResult<DidCoreId> {
    let did = signature_controller_did(&signature.verification_method)?;
    project_did_to_core_id(&did).map_err(|error| {
        E::MaterialIncomplete(format!(
            "verification method {} does not project to a stable service id: {error}",
            signature.verification_method
        ))
    })
}

#[cfg(test)]
mod tests;
