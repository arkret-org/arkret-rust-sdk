//! Authenticated Account device source intervals in a complete confirmed PCR.
//!
//! These facts authenticate device source coordinates, not ordinary business
//! authorization or the ancestry of closure frontiers. Recovery-first histories
//! without an authenticated predecessor anchor remain unavailable.

use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical::DigestSuite;
use arkret_event_draft::EventPayloadExt;
use arkret_models_collaboration::events_payloads::device_identity::{
    DeviceAuthorizePayload, DeviceReanchorPayload, DeviceRevokePayload,
};
use arkret_state::ordinary_history::HistoryEvidenceError;
use arkret_state::{
    CommandEventResult, OrderedControlBatchAbort, OrderedControlUnit, OrderedControlUnitEvent,
    ResolvedCellState,
};
use arkret_wire::{
    AccountId, ActorId, CellFamilyId, CellRef, CommandOutcome, DeviceId, Event, EventId, EventKind,
    Hash, NotaryValue, RealmId, Seal, SealId,
};
use chrono::{DateTime, Utc};

type Result<T> = std::result::Result<T, HistoryEvidenceError>;
fn invalid(error: impl std::fmt::Display) -> HistoryEvidenceError {
    HistoryEvidenceError::Invalid(error.to_string())
}
fn missing(error: impl std::fmt::Display) -> HistoryEvidenceError {
    HistoryEvidenceError::Unavailable(error.to_string())
}

/// One exact generation opening, including its authenticated closing command.
#[derive(Clone, Debug)]
pub struct DeviceGenerationInterval {
    number: u64,
    authorization_event_id: EventId,
    generation_event_id: EventId,
    closed_by: Option<EventId>,
}
impl DeviceGenerationInterval {
    pub fn number(&self) -> u64 {
        self.number
    }
    pub fn authorization_event_id(&self) -> &EventId {
        &self.authorization_event_id
    }
    pub fn generation_event_id(&self) -> &EventId {
        &self.generation_event_id
    }
    pub fn closed_by(&self) -> Option<&EventId> {
        self.closed_by.as_ref()
    }
}

/// Confirmed authorization bytes, their original generation and exact revocation.
/// A later generation fences this instance independently of an explicit revoke.
#[derive(Clone, Debug)]
pub struct DeviceAuthorizationInterval {
    event: Event,
    payload: DeviceAuthorizePayload,
    generation: u64,
    tag_id: String,
    public_key: [u8; 32],
    generation_event_id: EventId,
    confirmed_seal: SealId,
    sealed_at: DateTime<Utc>,
    revoked_by: Option<EventId>,
}
impl DeviceAuthorizationInterval {
    pub fn event(&self) -> &Event {
        &self.event
    }
    pub fn payload(&self) -> &DeviceAuthorizePayload {
        &self.payload
    }
    pub fn authorization_event_id(&self) -> &EventId {
        &self.event.event_id
    }
    pub fn device_id(&self) -> &DeviceId {
        &self.payload.device_id
    }
    pub fn authorized_generation_ref(&self) -> u64 {
        self.generation
    }
    pub fn generation_event_id(&self) -> &EventId {
        &self.generation_event_id
    }
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
    pub fn confirmed_seal(&self) -> &SealId {
        &self.confirmed_seal
    }
    /// Signed Seal time, deliberately not a local transaction linearization time.
    pub fn sealed_at(&self) -> DateTime<Utc> {
        self.sealed_at
    }
    pub fn revoked_by(&self) -> Option<&EventId> {
        self.revoked_by.as_ref()
    }
}

/// A complete authenticated device projection through one pinned known head.
/// No constructor accepts a caller-authored generation map or authorization flag.
#[derive(Clone, Debug)]
pub struct DeviceAuthorizationHistory {
    account_id: AccountId,
    realm_id: RealmId,
    genesis_event_id: EventId,
    confirmed_head: SealId,
    principal_registration_anchor: arkret_models_identity::PrincipalRegistrationAnchor,
    seals: Vec<Seal>,
    events: Vec<Event>,
    generations: Vec<DeviceGenerationInterval>,
    authorizations: Vec<DeviceAuthorizationInterval>,
}

/// A portable human-Control signer root after its complete referenced PCR
/// prefix has been authenticated. Construction is intentionally coupled to
/// [`DeviceAuthorizationHistory::verify`]; callers cannot install a bare key,
/// a Station projection, or a caller-authored `verified` flag.
#[derive(Clone, Debug)]
pub struct VerifiedAccountDeviceControlEvidence {
    history: DeviceAuthorizationHistory,
    authorization_event_id: EventId,
    verification_method: arkret_wire::DidUrl,
    public_key: [u8; 32],
    not_before: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

impl VerifiedAccountDeviceControlEvidence {
    pub fn history(&self) -> &DeviceAuthorizationHistory {
        &self.history
    }
    pub fn authorization_event_id(&self) -> &EventId {
        &self.authorization_event_id
    }
    pub fn verification_method(&self) -> &arkret_wire::DidUrl {
        &self.verification_method
    }
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
    pub fn authorization_contains(&self, at: DateTime<Utc>) -> bool {
        self.not_before <= at && self.expires_at.is_none_or(|expiry| at < expiry)
    }
}

impl DeviceAuthorizationHistory {
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }
    pub fn realm_id(&self) -> &RealmId {
        &self.realm_id
    }
    pub fn confirmed_head(&self) -> &SealId {
        &self.confirmed_head
    }
    pub fn control_signer_evidence(
        &self,
        authorization_event_id: &EventId,
    ) -> Result<arkret_models_identity::AuthenticatedSignerResolutionEvidence> {
        let authorization = self
            .authorization(authorization_event_id)
            .ok_or_else(|| missing("device authorization is not in the authenticated history"))?;
        let confirmation_index = self
            .seals
            .iter()
            .position(|seal| seal.id == authorization.confirmed_seal)
            .ok_or_else(|| missing("device authorization confirmation Seal is missing"))?;
        let prefix = &self.seals[..=confirmation_index];
        let mut included = BTreeSet::new();
        for seal in prefix {
            for result in &seal.command_results {
                if result.outcome == CommandOutcome::Committed {
                    for digest in &result.unit_event_digests {
                        included.insert(EventId::from_event_digest(digest).map_err(invalid)?);
                    }
                }
            }
        }
        let mut history_event_refs = self
            .events
            .iter()
            .filter(|event| included.contains(&event.event_id))
            .map(|event| event.event_id.clone())
            .collect::<Vec<_>>();
        history_event_refs.sort();
        history_event_refs.dedup();
        if history_event_refs.len() != included.len() {
            return Err(missing(
                "device authorization evidence prefix omits a committed Event",
            ));
        }
        let mut history_seal_refs = prefix
            .iter()
            .map(|seal| seal.id.clone())
            .collect::<Vec<_>>();
        history_seal_refs.sort();
        history_seal_refs.dedup();
        let verification_method = arkret_wire::DidUrl::new(format!(
            "{}#{}",
            self.principal_registration_anchor.did(),
            authorization.device_id()
        ))
        .map_err(invalid)?;
        let evidence =
            arkret_models_identity::AuthenticatedSignerResolutionEvidence::AccountDeviceControl {
                signer_id: self.account_id.principal_id.clone(),
                account_id: self.account_id.clone(),
                device_id: authorization.device_id().clone(),
                verification_method,
                authorization_event_ref: authorization.authorization_event_id().clone(),
                authorized_generation_ref: authorization.authorized_generation_ref(),
                generation_event_ref: authorization.generation_event_id().clone(),
                confirmation_seal_ref: authorization.confirmed_seal().clone(),
                pcr_genesis_event_ref: self.genesis_event_id.clone(),
                principal_registration_anchor: Box::new(self.principal_registration_anchor.clone()),
                history_event_refs,
                history_seal_refs,
            };
        evidence.validate_attester_binding().map_err(invalid)?;
        Ok(evidence)
    }
    pub fn generations(&self) -> &[DeviceGenerationInterval] {
        &self.generations
    }
    pub fn authorizations(&self) -> &[DeviceAuthorizationInterval] {
        &self.authorizations
    }
    pub fn current_generation(&self) -> &DeviceGenerationInterval {
        self.generations
            .last()
            .expect("authenticated genesis opens generation one")
    }
    pub fn authorization(&self, event_id: &EventId) -> Option<&DeviceAuthorizationInterval> {
        self.authorizations
            .iter()
            .find(|authorization| &authorization.event.event_id == event_id)
    }
    /// Generation/revoke status only; caller still checks the signed time window
    /// and any locally known pending-revocation or other live-admission gate.
    pub fn is_currently_active(&self, authorization: &DeviceAuthorizationInterval) -> bool {
        self.authorization(authorization.authorization_event_id())
            .is_some_and(|owned| {
                owned.generation == self.current_generation().number && owned.revoked_by.is_none()
            })
    }

    /// Materialize the canonical portable Control root for one authorization
    /// from this already-verified history. The emitted closure stops at the
    /// authorization's first successful confirmation Seal and contains exactly
    /// the Events committed by that predecessor-complete Seal prefix.
    pub fn account_device_control_evidence(
        &self,
        authorization_event_id: &EventId,
        principal_registration_anchor: &arkret_models_identity::PrincipalRegistrationAnchor,
        seals: &[Seal],
        events: &[Event],
        suite: DigestSuite,
    ) -> Result<arkret_models_identity::AuthenticatedSignerResolutionEvidence> {
        let authorization = self.authorization(authorization_event_id).ok_or_else(|| {
            missing("account device Control authorization is absent from verified history")
        })?;
        let pcr_genesis_event_ref = self
            .generations
            .first()
            .map(|generation| generation.generation_event_id.clone())
            .ok_or_else(|| invalid("verified device history has no genesis generation"))?;

        let mut ordered_seals = seals.iter().collect::<Vec<_>>();
        ordered_seals.sort_by_key(|seal| seal.notary_seq);
        let confirmation_index = ordered_seals
            .iter()
            .position(|seal| &seal.id == authorization.confirmed_seal())
            .ok_or_else(|| missing("authorization confirmation Seal is unavailable"))?;
        let prefix_seals = &ordered_seals[..=confirmation_index];

        let mut events_by_id = BTreeMap::new();
        for event in events {
            if events_by_id.insert(event.event_id.clone(), event).is_some() {
                return Err(invalid(
                    "duplicate Event input cannot materialize a canonical Control root",
                ));
            }
        }
        let mut prefix_events = Vec::new();
        let mut seen_event_refs = BTreeSet::new();
        for seal in prefix_seals {
            for unit in &seal.command_results {
                if unit.outcome != CommandOutcome::Committed {
                    continue;
                }
                for digest in &unit.unit_event_digests {
                    let event_id = EventId::from_event_digest(digest).map_err(invalid)?;
                    if !seen_event_refs.insert(event_id.clone()) {
                        return Err(invalid("confirmed prefix commits an Event more than once"));
                    }
                    prefix_events.push(
                        (*events_by_id.get(&event_id).ok_or_else(|| {
                            missing("confirmed prefix committed Event is unavailable")
                        })?)
                        .clone(),
                    );
                }
            }
        }

        let mut history_event_refs = prefix_events
            .iter()
            .map(|event| event.event_id.clone())
            .collect::<Vec<_>>();
        history_event_refs
            .sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
        let mut history_seal_refs = prefix_seals
            .iter()
            .map(|seal| seal.id.clone())
            .collect::<Vec<_>>();
        history_seal_refs
            .sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
        let verification_method = arkret_wire::DidUrl::new(format!(
            "{}#{}",
            principal_registration_anchor.did(),
            authorization.device_id()
        ))
        .map_err(invalid)?;
        let evidence =
            arkret_models_identity::AuthenticatedSignerResolutionEvidence::AccountDeviceControl {
                signer_id: self.account_id.principal_id.clone(),
                account_id: self.account_id.clone(),
                device_id: authorization.device_id().clone(),
                verification_method,
                authorization_event_ref: authorization.authorization_event_id().clone(),
                authorized_generation_ref: authorization.authorized_generation_ref(),
                generation_event_ref: authorization.generation_event_id().clone(),
                confirmation_seal_ref: authorization.confirmed_seal().clone(),
                pcr_genesis_event_ref,
                principal_registration_anchor: Box::new(principal_registration_anchor.clone()),
                history_event_refs,
                history_seal_refs,
            };

        // Keep construction coupled to verification: no caller can receive a
        // canonical-looking root whose frozen prefix fails replay.
        Self::verify_account_device_control(
            &evidence,
            &prefix_seals
                .iter()
                .map(|seal| (*seal).clone())
                .collect::<Vec<_>>(),
            &prefix_events,
            suite,
        )?;
        Ok(evidence)
    }

    /// Authenticate an `account_device_control` root against every exact Event
    /// and Seal it references, then derive the frozen device key and original
    /// authorization window from the replayed PCR rather than from duplicated
    /// claims in the root.
    pub fn verify_account_device_control(
        evidence: &arkret_models_identity::AuthenticatedSignerResolutionEvidence,
        seals: &[Seal],
        events: &[Event],
        suite: DigestSuite,
    ) -> Result<VerifiedAccountDeviceControlEvidence> {
        evidence.validate_attester_binding().map_err(invalid)?;
        let arkret_models_identity::AuthenticatedSignerResolutionEvidence::AccountDeviceControl {
            account_id,
            device_id,
            verification_method,
            authorization_event_ref,
            authorized_generation_ref,
            generation_event_ref,
            confirmation_seal_ref,
            pcr_genesis_event_ref,
            principal_registration_anchor,
            history_event_refs,
            history_seal_refs,
            ..
        } = evidence
        else {
            return Err(invalid(
                "portable Control history verifier requires account_device_control evidence",
            ));
        };

        let mut supplied_event_refs = events
            .iter()
            .map(|event| event.event_id.clone())
            .collect::<Vec<_>>();
        supplied_event_refs
            .sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
        if supplied_event_refs != *history_event_refs {
            return Err(missing(
                "account device Control Event closure differs from its exact reference list",
            ));
        }
        let mut supplied_seal_refs = seals.iter().map(|seal| seal.id.clone()).collect::<Vec<_>>();
        supplied_seal_refs
            .sort_by(|left, right| left.as_str().as_bytes().cmp(right.as_str().as_bytes()));
        if supplied_seal_refs != *history_seal_refs {
            return Err(missing(
                "account device Control Seal closure differs from its exact reference list",
            ));
        }

        let create = events
            .iter()
            .find(|event| &event.event_id == pcr_genesis_event_ref)
            .ok_or_else(|| missing("account device Control PCR genesis Event is missing"))?;
        let create_payload: crate::RealmCreatePayload = create
            .typed_payload::<arkret_wire::event_spec::RealmCreate>()
            .map_err(invalid)?;
        let mut ordered_seals = seals.iter().cloned().collect::<Vec<_>>();
        ordered_seals.sort_by_key(|seal| seal.notary_seq);
        let history = Self::verify(
            account_id,
            pcr_genesis_event_ref,
            &create_payload.object.notary,
            principal_registration_anchor,
            confirmation_seal_ref,
            &ordered_seals,
            events,
            suite,
        )?;
        let authorization = history
            .authorization(authorization_event_ref)
            .ok_or_else(|| missing("account device Control authorization Event is unavailable"))?;
        let expected_method = arkret_wire::DidUrl::new(format!(
            "{}#{}",
            principal_registration_anchor.did(),
            device_id
        ))
        .map_err(invalid)?;
        if authorization.device_id() != device_id
            || authorization.authorized_generation_ref() != *authorized_generation_ref
            || authorization.generation_event_id() != generation_event_ref
            || authorization.confirmed_seal() != confirmation_seal_ref
            || verification_method != &expected_method
        {
            return Err(invalid(
                "account device Control root differs from its replayed authorization",
            ));
        }
        let public_key = *authorization.public_key();
        let not_before = authorization.payload().not_before;
        let expires_at = authorization.payload().expires_at.flatten();
        Ok(VerifiedAccountDeviceControlEvidence {
            history,
            authorization_event_id: authorization_event_ref.clone(),
            verification_method: verification_method.clone(),
            public_key,
            not_before,
            expires_at,
        })
    }

    /// Authenticate the ordinary PCR chain and derive all device intervals.
    ///
    /// The account, genesis ID and initial configuration are independently trusted
    /// inputs from the registration/recovery trust boundary, never fields copied
    /// out of this candidate history. Every committed member must be supplied
    /// exactly once. Complete registered unit effects and state roots are replayed;
    /// subsequent authority comes from the preceding authenticated notary Cell.
    /// No separate signer-issued conclusion certificate is required. The exact
    /// signed inception operation is verified independently, including its root
    /// controller proof, before it can authenticate the genesis producer.
    /// Ordinary producers must be active in the replayed device prestate.
    /// Recovery producers must prove possession of the exact committed replacement
    /// key; the authenticated source decision owns recovery-session authorization.
    ///
    /// This authenticates confirmed decisions and their exact deterministic effects.
    /// It does not independently re-authorize the authority's business admission or
    /// certify ordinary closure-frontier ancestry. A new ordinary data effect that
    /// needs an unavailable causal base remains unavailable.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        account_id: &AccountId,
        genesis_event_id: &EventId,
        trusted_configuration: &NotaryValue,
        anchor: &arkret_models_identity::PrincipalRegistrationAnchor,
        expected_head: &SealId,
        seals: &[Seal],
        events: &[Event],
        suite: DigestSuite,
    ) -> Result<Self> {
        account_id.validate().map_err(invalid)?;
        // One adapter dispatch owns every human anchor method: nothing here
        // may reach for a webvh-specific verifier or a current resolver.
        let root =
            arkret_identity::validate_principal_registration_anchor(anchor).map_err(invalid)?;
        if root.principal_id != account_id.principal_id {
            return Err(invalid(
                "registration anchor does not authenticate the expected Account principal",
            ));
        }
        let realm_id = RealmId::from_event_id(genesis_event_id);
        let actor = ActorId::account(account_id.clone());
        let Some(first) = seals.first() else {
            return Err(missing("PCR history is empty"));
        };
        if seals.last().map(|seal| &seal.id) != Some(expected_head) {
            return Err(missing("PCR history does not reach the pinned head"));
        }
        let mut by_id = BTreeMap::new();
        for event in events {
            arkret_schema::validate_event_wire_schema(event).map_err(invalid)?;
            event
                .verify_event_id_matches_content_with_digest_suite(suite)
                .map_err(invalid)?;
            if event.realm_id != realm_id || by_id.insert(event.event_id.clone(), event).is_some() {
                return Err(invalid("foreign or duplicate PCR Event"));
            }
        }
        let create = by_id
            .get(genesis_event_id)
            .copied()
            .ok_or_else(|| missing("PCR genesis Event is missing"))?;
        if create.actor_id != actor
            || create.kind != EventKind::RealmCreate
            || first.predecessor_ref.is_some()
            || first.notary_seq != 0
            || first.configuration_ref != *genesis_event_id
            || first.command_results.len() != 1
        {
            return Err(missing(
                "history needs its independently authenticated PCR genesis anchor",
            ));
        }
        let genesis_unit = &first.command_results[0];
        if genesis_unit.outcome != CommandOutcome::Committed
            || genesis_unit.unit_event_digests.len() != 2
            || genesis_unit.unit_event_digests[0] != genesis_event_id.event_digest()
        {
            return Err(invalid(
                "PCR genesis is not the complete committed two-member unit",
            ));
        }
        let authorize_id =
            EventId::from_event_digest(&genesis_unit.unit_event_digests[1]).map_err(invalid)?;
        let founding = by_id
            .get(&authorize_id)
            .copied()
            .ok_or_else(|| missing("founding authorize Event is missing"))?;
        let create_payload: crate::RealmCreatePayload = create
            .typed_payload::<arkret_wire::event_spec::RealmCreate>()
            .map_err(invalid)?;
        if &create_payload.object.notary != trusted_configuration
            || create_payload.object.digest_algorithm != suite
        {
            return Err(invalid(
                "PCR genesis differs from the independently trusted configuration",
            ));
        }
        arkret_bootstrap::validate_self_principal_pcr_genesis_unit(create, founding, &|event| {
            arkret_schema::project_registered_cell_writes(event, suite)
                .map_err(|error| error.to_string())
        })
        .map_err(invalid)?;
        let resolution = create_payload
            .object
            .initial_resolution
            .as_ref()
            .ok_or_else(|| missing("PCR genesis initial resolution is missing"))?;
        if resolution.did != root.did
            || resolution.version_id != root.did_version_id
            || resolution.method_history_head != root.method_history_head.as_str()
            || create.refs[0].id != root.did_version_id
            || root
                .did_version_time
                .is_some_and(|published_at| create.created_at < published_at)
        {
            return Err(invalid(
                "PCR genesis does not bind the authenticated registration anchor",
            ));
        }
        let founding_payload: DeviceAuthorizePayload = founding
            .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
            .map_err(invalid)?;
        let founding_key = founding_payload
            .device_public_key_did
            .as_str()
            .strip_prefix("did:key:")
            .ok_or_else(|| invalid("founding key is not did:key"))?;
        let founding_key =
            arkret_canonical::decode_ed25519_multibase(founding_key).map_err(invalid)?;
        if trusted_configuration.signer.actor_id != actor
            || trusted_configuration.signer.verification_method
                != founding.proofs[0].verification_method
            || trusted_configuration.signer.frozen_public_key_b64u
                != arkret_canonical::base64url_encode(founding_key)
        {
            return Err(invalid(
                "initial notary does not bind the root-committed founding device",
            ));
        }
        let root_key = arkret_canonical::decode_ed25519_multibase(&root.root_public_key_multibase)
            .map_err(invalid)?;
        verify_event_producer(create, &root.root_verification_method, &root_key, suite)?;
        let registry = arkret_lattice_registry::try_build_sdk_state_registry().map_err(invalid)?;
        let mut state = BTreeMap::<CellRef, ResolvedCellState>::new();
        let mut history = Self {
            account_id: account_id.clone(),
            realm_id: realm_id.clone(),
            genesis_event_id: genesis_event_id.clone(),
            confirmed_head: expected_head.clone(),
            principal_registration_anchor: anchor.clone(),
            seals: seals.to_vec(),
            events: events.to_vec(),
            generations: vec![DeviceGenerationInterval {
                number: 1,
                authorization_event_id: genesis_event_id.clone(),
                generation_event_id: genesis_event_id.clone(),
                closed_by: None,
            }],
            authorizations: Vec::new(),
        };
        let mut seen = BTreeSet::new();
        let mut decided = BTreeSet::new();
        let mut previous: Option<&Seal> = None;
        let mut accumulated = BTreeSet::new();
        let mut accepted_bases = BTreeMap::<SealId, &Seal>::new();
        for seal in seals {
            if seal.realm_id != realm_id
                || seal.predecessor_ref.as_ref() != previous.map(|seal| &seal.id)
                || previous
                    .is_some_and(|prev| prev.notary_seq.checked_add(1) != Some(seal.notary_seq))
            {
                return Err(missing(
                    "PCR prefix has a gap or a recovery-first anchor requiring additional authenticated material",
                ));
            }
            seal.validate_structural().map_err(invalid)?;
            if seal.previous_digest_algorithm.is_some() {
                return Err(missing(
                    "PCR digest-suite migration requires its authenticated migration context",
                ));
            }
            seal.validate_id(suite).map_err(invalid)?;
            let (configuration_ref, configuration) = if previous.is_none() {
                (genesis_event_id.clone(), trusted_configuration.clone())
            } else {
                let cell = CellRef::new(arkret_bootstrap::REALM_NOTARY_CELL).map_err(invalid)?;
                let Some(ResolvedCellState::Sequenced(value)) = state.get(&cell) else {
                    return Err(missing(
                        "authenticated predecessor has no unique sequenced notary",
                    ));
                };
                (
                    value.revision_event_id.clone(),
                    serde_json::from_value(value.value.clone()).map_err(invalid)?,
                )
            };
            if seal.configuration_ref != configuration_ref {
                return Err(invalid(
                    "PCR Seal authority differs from the authenticated predecessor configuration",
                ));
            }
            arkret_signatures::verify_seal_signature(seal, &configuration, suite)
                .map_err(invalid)?;
            let mut seal_delta = Vec::new();
            for unit in &seal.command_results {
                for digest in &unit.unit_event_digests {
                    if !decided.insert(digest.clone()) {
                        return Err(invalid(
                            "PCR history re-decides an already terminal unit member",
                        ));
                    }
                }
                if unit.outcome != CommandOutcome::Committed {
                    let reason = unit
                        .reason_code
                        .clone()
                        .ok_or_else(|| invalid("rejected unit omits its reason"))?;
                    let expected = arkret_wire::SealCommandOutcome::rejected(
                        unit.event_digest.clone(),
                        unit.unit_event_digests.clone(),
                        reason,
                        suite,
                    )
                    .map_err(invalid)?;
                    if &expected != unit {
                        return Err(invalid("rejected unit result digest is inconsistent"));
                    }
                    continue;
                }
                let members =
                    unit.unit_event_digests
                        .iter()
                        .map(|digest| {
                            let id = EventId::from_event_digest(digest).map_err(invalid)?;
                            if !seen.insert(id.clone()) {
                                return Err(invalid("committed PCR member appears more than once"));
                            }
                            by_id.get(&id).copied().ok_or_else(|| {
                                missing("complete committed PCR unit member is missing")
                            })
                        })
                        .collect::<Result<Vec<_>>>()?;
                if members.len() == 2
                    && members[0].kind == EventKind::DeviceReanchor
                    && members[1].kind == EventKind::DeviceAuthorize
                {
                    arkret_bootstrap::validate_pcr_native_unit_authoring_checkpoint(
                        members[0], members[1],
                    )
                    .map_err(invalid)?;
                }
                let registered_unit = OrderedControlUnit {
                    events: members
                        .iter()
                        .map(|event| OrderedControlUnitEvent {
                            digest: event.event_id.event_digest(),
                            event: (*event).clone(),
                            digest_suite: suite,
                        })
                        .collect(),
                };
                let mut local_error = None;
                let batch = arkret_state::execute_ordered_control_units(
                    &realm_id,
                    &state,
                    &registry,
                    &[registered_unit],
                    suite,
                    previous.is_none(),
                    |member, staged, _| {
                        let result = (|| -> Result<Vec<arkret_wire::ProjectionEffect>> {
                            let event = &member.event;
                            if event.event_id != *genesis_event_id {
                                verify_device_producer(
                                    &history, event, &members, &root.did, suite,
                                )?;
                            }
                            let projection =
                                crate::project_control_writes_at_state(event, suite, staged)
                                    .map_err(missing)?;
                            let mut effects = Vec::new();
                            for write in &projection.writes {
                                effects.extend(
                                    arkret_state::resolve_projected_write(
                                        write, &realm_id, staged, &registry,
                                    )
                                    .map_err(invalid)?,
                                );
                            }
                            derive_device_transition(
                                &mut history,
                                event,
                                &members,
                                &effects,
                                seal,
                                suite,
                                &accepted_bases,
                            )?;
                            Ok(effects)
                        })();
                        match result {
                            Ok(effects) => Ok(CommandEventResult::Applied(effects)),
                            Err(error) => {
                                local_error = Some(error);
                                Err(OrderedControlBatchAbort::Infrastructure(
                                    "device source derivation failed".into(),
                                ))
                            }
                        }
                    },
                );
                let batch = match batch {
                    Ok(batch) => batch,
                    Err(error) => {
                        return Err(local_error.unwrap_or_else(|| match error {
                            OrderedControlBatchAbort::Pending { detail, .. } => missing(detail),
                            other => invalid(other),
                        }));
                    }
                };
                if batch.command_results.as_slice() != std::slice::from_ref(unit) {
                    return Err(invalid(
                        "complete registered PCR effects do not reproduce the signed unit result",
                    ));
                }
                seal_delta.extend(batch.committed_event_digests);
                state = batch.post_state;
            }
            seal_delta.sort();
            if seal_delta != seal.delta {
                return Err(invalid(
                    "PCR security delta differs from complete committed unit replay",
                ));
            }
            accumulated.extend(seal.delta.iter().cloned());
            if arkret_state::control_event_set_root(&accumulated, suite).map_err(invalid)?
                != seal.control_event_set_root
            {
                return Err(invalid(
                    "PCR accumulated control Event root is inconsistent",
                ));
            }
            if arkret_state::compute_state_root(arkret_state::GovernanceView::new(&state), suite)
                .map_err(invalid)?
                != seal.state_root
            {
                return Err(invalid(
                    "PCR state root differs from complete registered replay",
                ));
            }
            accepted_bases.insert(seal.id.clone(), seal);
            previous = Some(seal);
        }
        if seen.len() != by_id.len() {
            return Err(invalid(
                "device history includes material outside its committed prefix",
            ));
        }
        Ok(history)
    }
}

fn verify_event_producer(
    event: &Event,
    method: &arkret_wire::DidUrl,
    public_key: &[u8; 32],
    suite: DigestSuite,
) -> Result<()> {
    let [proof] = event.proofs.as_slice() else {
        return Err(invalid("PCR Event must have exactly one producer proof"));
    };
    proof.validate_production().map_err(invalid)?;
    if proof.verification_method != *method {
        return Err(invalid("PCR producer method does not match"));
    }
    let bytes = arkret_canonical::canonical_json_bytes(&event.digest_payload().map_err(invalid)?)
        .map_err(invalid)?;
    arkret_signatures::proof::verify_ed25519_detached_jws_proof_with_digest_suite(
        proof,
        &bytes,
        &event.actor_id,
        &arkret_signatures::proof::PublicKeyMaterial::Ed25519Raw {
            bytes: public_key.to_vec(),
        },
        suite,
    )
    .map_err(invalid)
}

fn verify_device_producer(
    history: &DeviceAuthorizationHistory,
    event: &Event,
    members: &[&Event],
    principal_did: &arkret_wire::Did,
    suite: DigestSuite,
) -> Result<()> {
    if event.actor_id != ActorId::account(history.account_id.clone()) || event.executed_by.is_some()
    {
        return Err(missing(
            "PCR producer needs an authenticated delegated identity outside the device history",
        ));
    }
    let [proof] = event.proofs.as_slice() else {
        return Err(invalid("PCR Event must have exactly one producer proof"));
    };
    let proof_did = arkret_identity::verification_method_did(proof.verification_method.as_str())
        .map_err(invalid)?;
    if arkret_wire::project_did_to_core_id(&proof_did).map_err(invalid)?
        != history.account_id.principal_id
    {
        return Err(invalid(
            "PCR device method belongs to a different principal",
        ));
    }
    let anchor_authorize = if members.len() == 2
        && matches!(
            members[0].kind,
            EventKind::RealmCreate | EventKind::DeviceReanchor
        )
        && members[1].kind == EventKind::DeviceAuthorize
    {
        Some(members[1])
    } else {
        None
    };
    if let Some(authorize) = anchor_authorize {
        let payload: DeviceAuthorizePayload = authorize
            .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
            .map_err(invalid)?;
        arkret_signatures::verify_device_authorize_possession(&payload, &history.account_id)
            .map_err(invalid)?;
        let key = payload
            .device_public_key_did
            .as_str()
            .strip_prefix("did:key:")
            .ok_or_else(|| invalid("replacement key is not did:key"))?;
        let key = arkret_canonical::decode_ed25519_multibase(key).map_err(invalid)?;
        let controller = if members[0].kind == EventKind::RealmCreate {
            principal_did
        } else {
            &proof_did
        };
        let method = arkret_wire::DidUrl::new(format!("{controller}#{}", payload.device_id))
            .map_err(invalid)?;
        return verify_event_producer(event, &method, &key, suite);
    }
    let fragment = proof
        .verification_method
        .as_str()
        .split_once('#')
        .map(|(_, fragment)| fragment)
        .ok_or_else(|| invalid("device proof method has no exact device identifier"))?;
    let device_id = DeviceId::new(fragment).map_err(invalid)?;
    let candidates = history
        .authorizations
        .iter()
        .filter(|source| {
            source.device_id() == &device_id
                && history.is_currently_active(source)
                && source.payload.not_before <= event.created_at
                && source
                    .payload
                    .expires_at
                    .flatten()
                    .is_none_or(|end| event.created_at < end)
        })
        .collect::<Vec<_>>();
    let Some(source) = candidates.first() else {
        return Err(invalid(
            "PCR producer is not an active authorized device in the execution prestate",
        ));
    };
    if candidates
        .iter()
        .any(|other| other.public_key != source.public_key)
    {
        return Err(invalid(
            "device identifier has conflicting active signing keys",
        ));
    }
    if event.kind == EventKind::DeviceAuthorize {
        let payload: DeviceAuthorizePayload = event
            .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
            .map_err(invalid)?;
        if !matches!(&payload.authorized_by, arkret_models_collaboration::events_payloads::device_identity::DeviceOrPrincipalRef::DeviceId(authorizer) if authorizer == &device_id)
        {
            return Err(invalid(
                "accepted-device authorizer differs from its actual producer",
            ));
        }
    }
    verify_event_producer(event, &proof.verification_method, &source.public_key, suite)
}

fn derive_device_transition(
    history: &mut DeviceAuthorizationHistory,
    event: &Event,
    members: &[&Event],
    effects: &[arkret_wire::ProjectionEffect],
    seal: &Seal,
    suite: DigestSuite,
    accepted_bases: &BTreeMap<SealId, &Seal>,
) -> Result<()> {
    let actor = ActorId::account(history.account_id.clone());
    if matches!(
        event.kind,
        EventKind::DeviceAuthorize | EventKind::DeviceRevoke | EventKind::DeviceReanchor
    ) && event.actor_id != actor
    {
        return Err(invalid(
            "device command changes a different complete Account",
        ));
    }
    match event.kind {
        EventKind::DeviceReanchor => {
            let payload: DeviceReanchorPayload = event
                .typed_payload::<arkret_wire::event_spec::DeviceReanchor>()
                .map_err(invalid)?;
            if payload.pre_fence_seal_frontier.is_none() {
                return Err(missing(
                    "recovery-first reanchor requires an independently authenticated recovery anchor",
                ));
            }
            let basis = payload
                .pre_fence_seal_frontier
                .as_ref()
                .expect("non-null recovery basis checked");
            let mut latest: Option<&Seal> = None;
            for leaf in &basis.leaves {
                let accepted = accepted_bases.get(leaf).copied().ok_or_else(|| {
                    missing("reanchor basis is not in the authenticated preceding PCR history")
                })?;
                if latest.is_none_or(|previous| previous.notary_seq < accepted.notary_seq) {
                    latest = Some(accepted);
                }
            }
            let latest = latest.ok_or_else(|| invalid("reanchor basis is empty"))?;
            if basis.control_event_set_root != latest.control_event_set_root
                || basis.state_root != latest.state_root
            {
                return Err(invalid(
                    "reanchor frontier roots differ from their authenticated history view",
                ));
            }
            if payload.account_id != history.account_id
                || payload.previous_device_generation != history.current_generation().number
            {
                return Err(invalid(
                    "reanchor does not extend the authenticated Account generation",
                ));
            }
            if members.len() != 2
                || members[0].event_id != event.event_id
                || members[1].kind != EventKind::DeviceAuthorize
            {
                return Err(invalid(
                    "reanchor and replacement authorize must be one exact ordered two-member unit",
                ));
            }
            let replacement = members[1];
            let replacement_payload: DeviceAuthorizePayload = replacement
                .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
                .map_err(invalid)?;
            let replacement_digest = Hash::new(arkret_canonical::digest(
                suite,
                &arkret_canonical::canonical_json_bytes(&replacement.payload).map_err(invalid)?,
            ))
            .map_err(invalid)?;
            if replacement_digest != payload.replacement_authorize_payload_digest
                || replacement_payload.recovery_session_id.as_ref() != Some(&payload.recovery_session_id)
                || replacement_payload.authorization_binding_kind != arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizationBindingKind::PcrRecovery {
                return Err(invalid("replacement authorize differs from the reanchor commitment"));
            }
            let authorization_event_id = history.generations[0].authorization_event_id.clone();
            history.generations.last_mut().unwrap().closed_by = Some(event.event_id.clone());
            history.generations.push(DeviceGenerationInterval {
                number: payload.new_device_generation,
                authorization_event_id,
                generation_event_id: event.event_id.clone(),
                closed_by: None,
            });
        }
        EventKind::DeviceAuthorize => {
            let payload: DeviceAuthorizePayload = event
                .typed_payload::<arkret_wire::event_spec::DeviceAuthorize>()
                .map_err(invalid)?;
            use arkret_models_collaboration::events_payloads::device_identity::DeviceAuthorizationBindingKind;
            let is_genesis =
                history.authorizations.is_empty() && history.current_generation().number == 1;
            let is_replacement = members.len() == 2
                && members[0].kind == EventKind::DeviceReanchor
                && members[1].event_id == event.event_id;
            let expected_binding = if is_genesis {
                DeviceAuthorizationBindingKind::RegistrationAnchor
            } else if is_replacement {
                DeviceAuthorizationBindingKind::PcrRecovery
            } else {
                DeviceAuthorizationBindingKind::AcceptedDevice
            };
            if payload.authorization_binding_kind != expected_binding {
                return Err(invalid(
                    "device authorize uses a binding outside its exact unit context",
                ));
            }
            if is_replacement && event.prev_refs != vec![members[0].event_id.clone()] {
                return Err(invalid(
                    "replacement authorize does not bind its exact reanchor predecessor",
                ));
            }
            arkret_signatures::verify_device_authorize_possession(&payload, &history.account_id)
                .map_err(invalid)?;
            let mut tags = effects
                .iter()
                .filter(|effect| is_family(&effect.cell_id, CellFamilyId::DEVICE_AUTHORIZATION_V1))
                .filter_map(|effect| effect.op.tag.clone());
            let tag_id = tags
                .next()
                .ok_or_else(|| invalid("authorize has no registered authorization tag"))?;
            if tags.next().is_some() {
                return Err(invalid("authorize has multiple authorization tags"));
            }
            let key = payload
                .device_public_key_did
                .as_str()
                .strip_prefix("did:key:")
                .ok_or_else(|| invalid("device key is not did:key"))?;
            let public_key = arkret_canonical::decode_ed25519_multibase(key).map_err(invalid)?;
            history.authorizations.push(DeviceAuthorizationInterval {
                event: event.clone(),
                payload,
                generation: history.current_generation().number,
                tag_id,
                public_key,
                generation_event_id: history.current_generation().generation_event_id.clone(),
                confirmed_seal: seal.id.clone(),
                sealed_at: seal.sealed_at,
                revoked_by: None,
            });
        }
        EventKind::DeviceRevoke => {
            let payload: DeviceRevokePayload = event
                .typed_payload::<arkret_wire::event_spec::DeviceRevoke>()
                .map_err(invalid)?;
            for effect in effects
                .iter()
                .filter(|effect| is_family(&effect.cell_id, CellFamilyId::DEVICE_AUTHORIZATION_V1))
            {
                let tag = effect
                    .op
                    .tag
                    .as_deref()
                    .ok_or_else(|| invalid("device revoke resolved without an observed tag"))?;
                let source = history
                    .authorizations
                    .iter_mut()
                    .find(|source| source.tag_id == tag)
                    .ok_or_else(|| {
                        invalid("device revoke observes an unknown authorization instance")
                    })?;
                if source.payload.device_id != payload.device_id || source.revoked_by.is_some() {
                    return Err(invalid(
                        "device revoke targets a different or already closed authorization",
                    ));
                }
                source.revoked_by = Some(event.event_id.clone());
            }
        }
        _ if effects.iter().any(|effect| {
            is_family(&effect.cell_id, CellFamilyId::DEVICE_AUTHORIZATION_V1)
                || is_family(&effect.cell_id, CellFamilyId::DEVICE_REANCHOR_V1)
        }) =>
        {
            return Err(missing(
                "registered device family has an unsupported modifying command",
            ));
        }
        _ => {}
    }
    Ok(())
}
fn is_family(cell: &CellRef, family: &str) -> bool {
    arkret_wire::cell::CellId::parse(cell.as_str()).is_ok_and(|id| id.component() == family)
}

#[cfg(test)]
mod tests;
