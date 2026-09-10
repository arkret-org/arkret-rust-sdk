//! Kind-erased semantic Event intent: everything a producer decides, and
//! nothing that authoring derives.
//!
//! [`TypedEventDraft`] is the typed front door, but a durable submit queue and a
//! UI command bus have to hold drafts of many kinds in one collection, which
//! means erasing `K`. Before this type existed the only way to erase the kind
//! was to author immediately — with a placeholder `actor_seq` and HLC — and then
//! keep writing producer fields onto the resulting [`Event`]. That handed every
//! caller an `event_id` that looked final while the envelope was still being
//! assembled.
//!
//! [`EventIntent`] is that erased draft. It carries the producer's decisions and
//! deliberately exposes no `event_id`, no derived object id and no conversion
//! into [`Event`]. The single exit is [`EventIntent::author`], which takes the
//! actor-chain position and HLC that were missing and returns an
//! [`AuthoredEvent`] whose identity was derived exactly once from the finished
//! content.
//!
//! [`TypedEventDraft`]: crate::TypedEventDraft

use std::collections::BTreeMap;

use arkret_canonical::DigestSuite;
use arkret_wire::{
    ActorId, AppletId, AuthContext, AuthoredEvent, AuthorizationRef, EventId, EventKind, EventRef,
    EventRequirements, Hash, Hlc, Precondition, ProfileRef, RealmId, ScopeRef, SealBasis, SealId,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Result;

/// A complete producer intent with the authoring position still open.
///
/// `PartialEq` is the durable queue's semantic-drift guard: two attempts at the
/// same user operation must compare equal here even though each one authors
/// with a fresh actor frontier, HLC and CBS basis.
///
/// An intent has no identity to read, so nothing can be derived from one:
///
/// ```compile_fail
/// # use arkret_event_draft::EventIntent;
/// fn premature_identity(intent: &EventIntent) {
///     let _ = intent.event_id();
/// }
/// ```
///
/// and it cannot be smuggled into an [`Event`] to get at that identity either:
///
/// ```compile_fail
/// # use arkret_event_draft::EventIntent;
/// # use arkret_wire::Event;
/// fn premature_envelope(intent: EventIntent) -> Event {
///     intent.into()
/// }
/// ```
///
/// A persistent object id is `retype(event_id)`, so an intent cannot name a
/// Space, Strand or Message either — the only input those constructors accept is
/// an `EventId` that does not exist yet:
///
/// ```compile_fail
/// # use arkret_event_draft::EventIntent;
/// # use arkret_wire::SpaceId;
/// fn premature_space_id(intent: &EventIntent) -> SpaceId {
///     SpaceId::from_event_id(intent.event_id())
/// }
/// ```
///
/// [`Event`]: arkret_wire::Event
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventIntent {
    kind: EventKind,
    scope_ref: ScopeRef,
    actor_id: ActorId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    created_at: DateTime<Utc>,
    payload: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    prev_refs: Vec<EventId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    refs: Vec<EventRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    causal_refs: Vec<Hash>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    preconditions: Vec<Precondition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seal_ref: Option<SealId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auth_context: Option<AuthContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seal_basis: Option<SealBasis>,
    #[serde(default, skip_serializing_if = "EventRequirements::is_empty")]
    requirements: EventRequirements,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    executed_by: Option<ActorId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization_ref: Option<AuthorizationRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    applet_id: Option<AppletId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    external_ref: Option<BTreeMap<String, Value>>,
}

impl EventIntent {
    /// Build an intent from an already-validated payload object.
    ///
    /// `kind` and `payload` are supplied together and are never re-paired
    /// afterwards; the typed entry point is
    /// [`TypedEventDraft::into_intent`](crate::TypedEventDraft::into_intent),
    /// which proves the pairing before erasing `K`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        kind: EventKind,
        scope_ref: ScopeRef,
        actor_id: ActorId,
        created_at: DateTime<Utc>,
        payload: BTreeMap<String, Value>,
    ) -> Self {
        Self {
            kind,
            scope_ref,
            actor_id,
            created_at,
            payload,
            prev_refs: Vec::new(),
            refs: Vec::new(),
            causal_refs: Vec::new(),
            preconditions: Vec::new(),
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            requirements: EventRequirements::default(),
            executed_by: None,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
        }
    }

    pub fn kind(&self) -> &EventKind {
        &self.kind
    }

    pub fn scope_ref(&self) -> &ScopeRef {
        &self.scope_ref
    }

    /// The Realm this intent is scoped to, or `None` for a Realm genesis whose
    /// Realm id is a function of the Event id and therefore does not exist yet.
    pub fn realm_id_opt(&self) -> Option<&RealmId> {
        self.scope_ref.realm_id_opt()
    }

    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn payload(&self) -> &BTreeMap<String, Value> {
        &self.payload
    }

    /// Read the payload back through its marker's typed shape.
    ///
    /// The kind and payload were paired once, before erasure, so this can only
    /// fail if the caller asks for a different marker.
    pub fn typed_payload<K: crate::EventSpec>(&self) -> Result<K::Payload> {
        if self.kind != K::KIND {
            return Err(crate::EventDraftError::Protocol(format!(
                "intent kind {} does not match requested payload {}",
                self.kind.as_str(),
                K::KIND_STR
            )));
        }
        serde_json::from_value(Value::Object(self.payload.clone().into_iter().collect())).map_err(
            |error| {
                crate::EventDraftError::Protocol(format!(
                    "{} payload invalid: {error}",
                    K::KIND_STR
                ))
            },
        )
    }

    pub fn prev_refs(&self) -> &[EventId] {
        &self.prev_refs
    }

    pub fn refs(&self) -> &[EventRef] {
        &self.refs
    }

    pub fn causal_refs(&self) -> &[Hash] {
        &self.causal_refs
    }

    pub fn preconditions(&self) -> &[Precondition] {
        &self.preconditions
    }

    pub fn seal_ref(&self) -> Option<&SealId> {
        self.seal_ref.as_ref()
    }

    pub fn auth_context(&self) -> Option<&AuthContext> {
        self.auth_context.as_ref()
    }

    pub fn seal_basis(&self) -> Option<&SealBasis> {
        self.seal_basis.as_ref()
    }

    pub fn requirements(&self) -> &EventRequirements {
        &self.requirements
    }

    pub fn executed_by(&self) -> Option<&ActorId> {
        self.executed_by.as_ref()
    }

    pub fn authorization_ref(&self) -> Option<&AuthorizationRef> {
        self.authorization_ref.as_ref()
    }

    pub fn applet_id(&self) -> Option<&AppletId> {
        self.applet_id.as_ref()
    }

    /// Narrow the producer-declared security scope, e.g. from Realm to Circle.
    ///
    /// A Realm genesis has no narrower scope, so its `scope_ref` is fixed.
    pub fn with_scope_ref(mut self, scope_ref: ScopeRef) -> Result<Self> {
        if self.scope_ref == ScopeRef::RealmGenesis {
            return Err(crate::EventDraftError::Protocol(format!(
                "{} is a Realm genesis and cannot be narrowed to another scope",
                self.kind.as_str()
            )));
        }
        self.scope_ref = scope_ref;
        Ok(self)
    }

    pub fn with_created_at(mut self, created_at: DateTime<Utc>) -> Self {
        self.created_at = arkret_canonical::normalize_timestamp_canonical(created_at);
        self
    }

    /// Position this intent on the actor chain's accepted frontier.
    ///
    /// `prev_refs` is refreshed per authoring attempt, which is why it is a
    /// setter and not a construction argument: a retry re-reads the frontier
    /// before it authors again.
    pub fn with_prev_refs(mut self, prev_refs: Vec<EventId>) -> Self {
        self.prev_refs = prev_refs;
        self
    }

    pub fn with_refs(mut self, refs: Vec<EventRef>) -> Self {
        self.refs = refs;
        self
    }

    pub fn with_ref(mut self, event_ref: EventRef) -> Self {
        self.refs.push(event_ref);
        self
    }

    pub fn with_causal_refs(mut self, causal_refs: Vec<Hash>) -> Self {
        self.causal_refs = causal_refs;
        self
    }

    pub fn with_preconditions(mut self, preconditions: Vec<Precondition>) -> Self {
        self.preconditions = preconditions;
        self
    }

    pub fn with_seal_ref(mut self, seal_ref: SealId) -> Self {
        self.seal_ref = Some(seal_ref);
        self
    }

    pub fn with_auth_context(mut self, auth_context: AuthContext) -> Self {
        self.auth_context = Some(auth_context);
        self
    }

    pub fn with_seal_basis(mut self, seal_basis: SealBasis) -> Self {
        self.seal_basis = Some(seal_basis);
        self
    }

    /// Drop the per-attempt CBS basis so the frozen semantic intent does not
    /// remember one attempt's Seal view.
    pub fn without_cbs_basis(mut self) -> Self {
        self.seal_ref = None;
        self.auth_context = None;
        self.seal_basis = None;
        self
    }

    pub fn with_optional_seal_ref(mut self, seal_ref: Option<SealId>) -> Self {
        self.seal_ref = seal_ref;
        self
    }

    pub fn with_optional_auth_context(mut self, auth_context: Option<AuthContext>) -> Self {
        self.auth_context = auth_context;
        self
    }

    pub fn with_optional_seal_basis(mut self, seal_basis: Option<SealBasis>) -> Self {
        self.seal_basis = seal_basis;
        self
    }

    pub fn with_optional_executed_by(mut self, executed_by: Option<ActorId>) -> Self {
        self.executed_by = executed_by;
        self
    }

    pub fn with_optional_authorization_ref(
        mut self,
        authorization_ref: Option<AuthorizationRef>,
    ) -> Self {
        self.authorization_ref = authorization_ref;
        self
    }

    pub fn with_optional_applet_id(mut self, applet_id: Option<AppletId>) -> Self {
        self.applet_id = applet_id;
        self
    }

    pub fn with_optional_external_ref(
        mut self,
        external_ref: Option<BTreeMap<String, Value>>,
    ) -> Self {
        self.external_ref = external_ref;
        self
    }

    pub fn with_requirements(mut self, requirements: EventRequirements) -> Self {
        self.requirements = requirements;
        self
    }

    pub fn with_schema_profile_ref(mut self, profile_ref: ProfileRef) -> Self {
        self.requirements.schema_profile_refs.push(profile_ref);
        self
    }

    pub fn with_executed_by(mut self, executed_by: ActorId) -> Self {
        self.executed_by = Some(executed_by);
        self
    }

    pub fn with_authorization_ref(mut self, authorization_ref: AuthorizationRef) -> Self {
        self.authorization_ref = Some(authorization_ref);
        self
    }

    pub fn with_applet_id(mut self, applet_id: AppletId) -> Self {
        self.applet_id = Some(applet_id);
        self
    }

    pub fn with_external_ref(mut self, external_ref: BTreeMap<String, Value>) -> Self {
        self.external_ref = Some(external_ref);
        self
    }

    /// Finalize under the Realm's declared content digest suite.
    pub fn author_with_digest_suite(
        self,
        actor_seq: u64,
        hlc: Hlc,
        digest_suite: DigestSuite,
    ) -> Result<AuthoredEvent> {
        Ok(AuthoredEvent::finalize_with_digest_suite(
            self.into_unauthored_envelope(actor_seq, hlc),
            digest_suite,
        )?)
    }

    /// Assemble the wire envelope with a placeholder identity.
    ///
    /// Private on purpose: the placeholder id is meaningless, and the only
    /// caller is [`Self::author_with_digest_suite`], which immediately hands it
    /// to [`AuthoredEvent::finalize_with_digest_suite`].
    fn into_unauthored_envelope(self, actor_seq: u64, hlc: Hlc) -> arkret_wire::Event {
        let placeholder = EventId::from_digest(DigestSuite::Sha256, [0; 32]);
        let realm_id = self
            .scope_ref
            .realm_id_opt()
            .cloned()
            .unwrap_or_else(|| RealmId::from_event_id(&placeholder));
        arkret_wire::Event {
            event_id: placeholder,
            kind: self.kind,
            realm_id,
            scope_ref: self.scope_ref,
            actor_id: self.actor_id,
            executed_by: self.executed_by,
            authorization_ref: self.authorization_ref,
            applet_id: self.applet_id,
            external_ref: self.external_ref,
            actor_kind: None,
            actor_seq,
            created_at: arkret_canonical::normalize_timestamp_canonical(self.created_at),
            hlc: Some(hlc),
            prev_refs: self.prev_refs,
            refs: self.refs,
            causal_refs: self.causal_refs,
            preconditions: self.preconditions,
            seal_ref: self.seal_ref,
            auth_context: self.auth_context,
            seal_basis: self.seal_basis,
            payload: self.payload,
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
            requirements: self.requirements,
        }
    }

    /// Recover the semantic intent an already-authored envelope expresses.
    ///
    /// For envelopes authored outside this process — restored from a durable
    /// record, or handed over fully signed — where the caller needs the intent
    /// but never held one. The authoring position (`actor_seq`, `hlc`,
    /// `prev_refs`), the derived identity, proofs and `unsigned` are not part of
    /// an intent, and the CBS members come back unpinned so a later attempt may
    /// resolve them against a fresher Seal view.
    ///
    /// Prefer keeping the intent you authored from: this direction cannot know
    /// whether the producer *chose* a CBS basis or merely stamped one.
    pub fn from_authored(event: &arkret_wire::Event) -> Self {
        Self {
            kind: event.kind.clone(),
            scope_ref: event.scope_ref.clone(),
            actor_id: event.actor_id.clone(),
            created_at: event.created_at,
            payload: event.payload.clone(),
            prev_refs: Vec::new(),
            refs: event.refs.clone(),
            causal_refs: event.causal_refs.clone(),
            preconditions: event.preconditions.clone(),
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            requirements: event.requirements.clone(),
            executed_by: event.executed_by.clone(),
            authorization_ref: event.authorization_ref.clone(),
            applet_id: event.applet_id.clone(),
            external_ref: event.external_ref.clone(),
        }
    }

    /// Prove that an authored envelope still expresses this exact intent.
    ///
    /// The durable queue runs this so a retry cannot quietly change what the
    /// user asked for. The split is by *ownership*, not by kind:
    ///
    /// - members the intent owns must be reproduced verbatim;
    /// - `actor_seq`, `hlc` and `prev_refs` are the authoring position and are re-read on every
    ///   attempt;
    /// - `event_id`, `proofs` and `unsigned` are derived or transport-only;
    /// - a CBS member is per-attempt state *unless this intent pinned it*. A pre-join
    ///   `ak.invite.accept` pins the `seal_basis` its own Station froze in
    ///   `ak.self.realm_join.command.prepare.v1`, because the invitee cannot re-resolve the
    ///   membership-gated Seal view; an ordinary member-authored Event leaves it open and
    ///   re-resolves it each attempt.
    pub fn authored_envelope_matches(&self, event: &arkret_wire::Event) -> bool {
        fn pinned_matches<T: PartialEq>(pinned: Option<&T>, authored: Option<&T>) -> bool {
            pinned.is_none_or(|pinned| authored == Some(pinned))
        }

        self.kind == event.kind
            && self.scope_ref == event.scope_ref
            && self.actor_id == event.actor_id
            && self.created_at == event.created_at
            && self.payload == event.payload
            && self.refs == event.refs
            && self.causal_refs == event.causal_refs
            && self.preconditions == event.preconditions
            && self.requirements == event.requirements
            && self.executed_by == event.executed_by
            && self.authorization_ref == event.authorization_ref
            && self.applet_id == event.applet_id
            && self.external_ref == event.external_ref
            && pinned_matches(self.seal_ref.as_ref(), event.seal_ref.as_ref())
            && pinned_matches(self.auth_context.as_ref(), event.auth_context.as_ref())
            && pinned_matches(self.seal_basis.as_ref(), event.seal_basis.as_ref())
    }
}
