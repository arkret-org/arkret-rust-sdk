//! History visibility decision functions.
//!
//! `spec/v1/zh/governance/history-visibility.md` §3 and §4 fix five decision
//! formulas, a standard-MLS endpoint floor, a closed terminal-reason vocabulary
//! and the minimal-metadata pairwise endpoint identity rules. This module is
//! their only implementation: it is pure, takes every input explicitly, and
//! never reaches for local clocks, `joined_at`, `received_at` or the current
//! epoch.
//!
//! `join_epoch` itself is derived elsewhere — `arkret_state::direct_traversal`
//! is its single source — and arrives here as a `u64`.

use arkret_models_collaboration::history_key::AuthorizationIncarnation;
use arkret_wire::{DidCoreId, ErrorCode, EventId, HistoryAccess, HistoryEffectiveScope, RealmId};
use serde::{Deserialize, Serialize};

/// `allow_event(access, E, join)` — history-visibility.md §4.
///
/// `event_covers_join_activation` is `T0(E) causally covers exact join`: the
/// caller supplies the causal answer computed from the retained Seal closure,
/// never a timestamp comparison.
pub const fn allow_event(access: HistoryAccess, event_covers_join_activation: bool) -> bool {
    match access {
        HistoryAccess::AllHistoryForCurrentMembers => true,
        HistoryAccess::SinceJoin => event_covers_join_activation,
    }
}

/// `allow_epoch(access, N, join_epoch)` — history-visibility.md §4.
pub const fn allow_epoch(access: HistoryAccess, epoch: u64, join_epoch: u64) -> bool {
    match access {
        HistoryAccess::AllHistoryForCurrentMembers => true,
        HistoryAccess::SinceJoin => epoch >= join_epoch,
    }
}

/// The non-policy half of `readable_by_scope`: the recipient's current standing
/// in the scope. Every member is an externally established fact; this type
/// exists so a caller cannot silently omit one of the conjuncts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecipientScopeStanding {
    /// `T0(E)` causally covers the recipient's exact current join activation.
    pub event_covers_join_activation: bool,
    /// The recipient's authorization subject is currently active.
    pub authorization_subject_active: bool,
    /// The scope is readable and not tombstoned.
    pub scope_readable: bool,
}

/// `readable_by_scope(E, recipient)` — history-visibility.md §4.
pub const fn readable_by_scope(
    current_history_access: HistoryAccess,
    recipient: RecipientScopeStanding,
) -> bool {
    allow_event(
        current_history_access,
        recipient.event_covers_join_activation,
    ) && recipient.authorization_subject_active
        && recipient.scope_readable
}

/// The non-policy half of `deliverable`: the current membership, device,
/// account, source, scope, safety and audit gates, already evaluated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeliveryGates {
    pub membership: bool,
    pub device: bool,
    pub account: bool,
    pub source: bool,
    pub scope: bool,
    pub safety: bool,
    pub audit: bool,
}

impl DeliveryGates {
    pub const fn all_pass(self) -> bool {
        self.membership
            && self.device
            && self.account
            && self.source
            && self.scope
            && self.safety
            && self.audit
    }
}

/// `deliverable(N, recipient)` — history-visibility.md §4.
pub const fn deliverable(
    current_history_access: HistoryAccess,
    epoch: u64,
    current_join_epoch: u64,
    gates: DeliveryGates,
) -> bool {
    allow_epoch(current_history_access, epoch, current_join_epoch) && gates.all_pass()
}

/// Closed vocabulary of the standard-MLS endpoint transitions that decide
/// whether an endpoint incarnation survives — history-visibility.md §3.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointTransition {
    /// Same BasicCredential identity and signature key.
    OrdinarySelfUpdate,
    RemoveAndAdd,
    CredentialReplacement,
    SignatureKeyReplacement,
    Reinstall,
}

impl EndpointTransition {
    /// `true` when the transition establishes a new endpoint incarnation and
    /// therefore resets the floor; an ordinary self-update MUST NOT reset it.
    pub const fn resets_endpoint_incarnation(self) -> bool {
        !matches!(self, Self::OrdinarySelfUpdate)
    }
}

/// The standard-MLS `endpoint_admission` window — history-visibility.md §3.
///
/// It opens at the endpoint incarnation's initial winning Add/Welcome
/// activation and closes at its Remove.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointAdmission {
    /// The winning Add/Welcome activation Event that opened this incarnation.
    pub activation_event_id: EventId,
    /// The Remove that closed it, when the incarnation has ended.
    pub removed_by_event_id: Option<EventId>,
}

impl EndpointAdmission {
    pub const fn is_open(&self) -> bool {
        self.removed_by_event_id.is_none()
    }

    /// Apply an endpoint transition. An ordinary self-update keeps the exact
    /// incarnation; every other transition requires the caller to supply the
    /// new activation, because a new incarnation resets the floor.
    pub fn advance(
        &self,
        transition: EndpointTransition,
        next_activation: Option<EventId>,
    ) -> Self {
        match (transition.resets_endpoint_incarnation(), next_activation) {
            (false, _) => self.clone(),
            (true, Some(activation_event_id)) => Self {
                activation_event_id,
                removed_by_event_id: None,
            },
            (true, None) => Self {
                activation_event_id: self.activation_event_id.clone(),
                removed_by_event_id: self.removed_by_event_id.clone(),
            },
        }
    }
}

/// The only two terminal history-decrypt reasons — history-visibility.md §7.
///
/// T1 authority loss, an offline source and missing proof/chunk material are
/// transient and MUST NOT enter this vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryTerminalReason {
    DecryptionUnavailableByPolicy,
    DecryptionUnavailableByProfileFloor,
}

impl HistoryTerminalReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DecryptionUnavailableByPolicy => "decryption_unavailable_by_policy",
            Self::DecryptionUnavailableByProfileFloor => "decryption_unavailable_by_profile_floor",
        }
    }

    /// The wire face of a terminal decision. Both reasons surface as
    /// `history_not_visible`; the distinction stays local because
    /// `error-code-registry.json` registers no second code for it.
    pub const fn error_code(self) -> ErrorCode {
        ErrorCode::HistoryNotVisible
    }
}

/// The identity of one terminal decision — history-visibility.md §7 fixes the
/// key as `(effective_scope, epoch, authorization_incarnation,
/// endpoint_incarnation, reason)`.
///
/// `endpoint_incarnation` is `None` on the exporter lane, which carries no
/// endpoint floor. The field is always serialized so the key keeps a fixed
/// member set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryTerminalDecision {
    pub effective_scope: HistoryEffectiveScope,
    pub epoch: u64,
    pub authorization_incarnation: AuthorizationIncarnation,
    pub endpoint_incarnation: Option<EventId>,
    pub reason: HistoryTerminalReason,
}

impl HistoryTerminalDecision {
    /// A profile-floor terminal decision always names the endpoint incarnation
    /// whose floor produced it; a policy terminal decision on the exporter lane
    /// has none.
    pub fn validate(&self) -> Result<(), &'static str> {
        match (self.reason, self.endpoint_incarnation.as_ref()) {
            (HistoryTerminalReason::DecryptionUnavailableByProfileFloor, None) => {
                Err("a profile-floor terminal decision must name its endpoint incarnation")
            }
            _ => Ok(()),
        }
    }
}

/// The Realm-local pairwise endpoint identity of a minimal-metadata author —
/// history-visibility.md §3.
///
/// This is **not** the peer-pairing concept in `arkret_identity::handles`.
/// There the pair is `(principal, peer_principal)`; here it is
/// `(Realm, endpoint incarnation)`, and the same actor is reused across the
/// Realm's Circles rather than across a peer relationship.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimalMetadataEndpointIdentity {
    pub realm_id: RealmId,
    /// The endpoint incarnation this pairwise actor belongs to.
    pub endpoint_incarnation: EventId,
    /// The Realm-local pairwise `did:key` actor.
    pub pairwise_actor_id: DidCoreId,
    /// The Event `actor_id` this endpoint authors with.
    pub event_actor_id: DidCoreId,
    /// The MLS leaf BasicCredential identity.
    pub leaf_credential_identity: String,
    /// The proof key identifier.
    pub proof_key_id: String,
    /// The sender KDF / counter domain.
    pub sender_kdf_domain: String,
    /// The request sender domain.
    pub request_sender_domain: String,
}

impl MinimalMetadataEndpointIdentity {
    /// Every projection of the pairwise actor MUST be byte-identical, and the
    /// actor MUST be a `did:key` — history-visibility.md §3.
    pub fn validate(&self) -> Result<(), &'static str> {
        let actor = self.pairwise_actor_id.as_str();
        if !actor.starts_with("ak:did_core:key:") && !actor.starts_with("did:key:") {
            return Err("a minimal-metadata pairwise actor must be a did:key identifier");
        }
        if self.event_actor_id.as_str() != actor
            || self.leaf_credential_identity != actor
            || self.proof_key_id != actor
            || self.sender_kdf_domain != actor
            || self.request_sender_domain != actor
        {
            return Err(
                "minimal-metadata Event actor, leaf credential, proof key, KDF domain and request sender domain must be byte-identical",
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use arkret_wire::CircleId;

    use super::*;

    fn realm_scope() -> HistoryEffectiveScope {
        HistoryEffectiveScope::Realm {
            realm_id: RealmId::new("ak:realm:AfjSiYTXJZS-0ifVfy1f_uzsmJIBjDyN11_-dxnne50e")
                .unwrap(),
        }
    }

    fn circle_scope() -> HistoryEffectiveScope {
        HistoryEffectiveScope::Circle {
            realm_id: RealmId::new("ak:realm:AfjSiYTXJZS-0ifVfy1f_uzsmJIBjDyN11_-dxnne50e")
                .unwrap(),
            circle_id: CircleId::new("ak:circle:ARIqxK3jWXYxpb544UphWaZm_ti9wclu9_0-eSuyZ2e_")
                .unwrap(),
        }
    }

    fn event_id(byte: char) -> EventId {
        EventId::new(format!(
            "ak:event:A{}",
            std::iter::repeat_n(byte, 43).collect::<String>()
        ))
        .unwrap()
    }

    fn standing(covers_join: bool) -> RecipientScopeStanding {
        RecipientScopeStanding {
            event_covers_join_activation: covers_join,
            authorization_subject_active: true,
            scope_readable: true,
        }
    }

    const OPEN_GATES: DeliveryGates = DeliveryGates {
        membership: true,
        device: true,
        account: true,
        source: true,
        scope: true,
        safety: true,
        audit: true,
    };

    /// `ak.vector.history_access.since_join_prejoin_denied.v1`
    /// (`visibility-policy-fixture.json`).
    #[test]
    fn since_join_prejoin_vector_executes_against_the_decision_functions() {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/visibility-policy-fixture.json",
        )
        .unwrap();
        let case = find_case(
            &fixture,
            "ak.vector.history_access.since_join_prejoin_denied.v1",
        );
        assert_eq!(case["history_access"].as_str(), Some("since_join"));
        let access = HistoryAccess::SinceJoin;
        let join_epoch = case["viewer"]["join_epoch"].as_u64().unwrap();
        assert_eq!(case["viewer"]["membership_state"].as_str(), Some("join"));

        for event in case["events"].as_array().unwrap() {
            let epoch = event["epoch"].as_u64().unwrap();
            let expected = event["expected_visible"].as_bool().unwrap();
            assert_eq!(
                deliverable(access, epoch, join_epoch, OPEN_GATES),
                expected,
                "{} drifted",
                event["event_id"].as_str().unwrap()
            );
            assert_eq!(allow_epoch(access, epoch, join_epoch), expected);
        }

        // A non-member has no active authorization subject, so no epoch is
        // readable however the epoch compares to the floor.
        let control = &case["non_member_control"];
        assert!(control["membership_state"].is_null());
        let epoch = control["epoch"].as_u64().unwrap();
        assert!(allow_epoch(access, epoch, join_epoch));
        assert_eq!(
            readable_by_scope(
                access,
                RecipientScopeStanding {
                    event_covers_join_activation: true,
                    authorization_subject_active: false,
                    scope_readable: true,
                },
            ),
            control["expected_visible"].as_bool().unwrap()
        );
        assert_eq!(
            case["expected"]["prejoin_error"].as_str(),
            Some(
                HistoryTerminalReason::DecryptionUnavailableByPolicy
                    .error_code()
                    .as_str()
            )
        );
    }

    /// `ak.vector.history_access.direct_conversation_scope_local.v1`
    /// (`history-key-recovery-fixture.json`).
    ///
    /// The vector's whole content is that a Direct Conversation Realm has no
    /// special case: it uses its explicit current `history_access` and the
    /// ordinary exporter path. The executable form of "no special case" is that
    /// these functions take no Direct-Conversation input at all, so the same
    /// inputs decide identically for a Direct Conversation Realm scope and for
    /// any other Realm scope.
    #[test]
    fn direct_conversation_scope_has_no_local_history_rule() {
        let fixture = arkret_schema_conformance::spec_json_artifact(
            "fixtures/history-key-recovery-fixture.json",
        )
        .unwrap();
        assert!(
            fixture["covers_vectors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|vector| vector.as_str()
                    == Some("ak.vector.history_access.direct_conversation_scope_local.v1")),
            "the fixture must still cover the Direct Conversation scope vector"
        );

        for access in [
            HistoryAccess::SinceJoin,
            HistoryAccess::AllHistoryForCurrentMembers,
        ] {
            for epoch in 0..4u64 {
                let realm = deliverable(access, epoch, 2, OPEN_GATES);
                let circle = deliverable(access, epoch, 2, OPEN_GATES);
                assert_eq!(realm, circle);
            }
        }
        // The decision inputs carry no scope-kind branch: both scopes reach the
        // same terminal key shape and differ only in the scope they name.
        for scope in [realm_scope(), circle_scope()] {
            let decision = HistoryTerminalDecision {
                effective_scope: scope,
                epoch: 3,
                authorization_incarnation: AuthorizationIncarnation::Realm {
                    realm_membership_incarnation_ref: event_id('a'),
                },
                endpoint_incarnation: None,
                reason: HistoryTerminalReason::DecryptionUnavailableByPolicy,
            };
            decision.validate().unwrap();
        }
    }

    fn find_case<'a>(fixture: &'a serde_json::Value, vector_id: &str) -> &'a serde_json::Value {
        fn walk<'a>(
            value: &'a serde_json::Value,
            vector_id: &str,
        ) -> Option<&'a serde_json::Value> {
            match value {
                serde_json::Value::Object(map) => {
                    if map.get("vector_id").and_then(serde_json::Value::as_str) == Some(vector_id) {
                        return Some(value);
                    }
                    map.values().find_map(|child| walk(child, vector_id))
                }
                serde_json::Value::Array(values) => {
                    values.iter().find_map(|child| walk(child, vector_id))
                }
                _ => None,
            }
        }
        walk(fixture, vector_id).expect("the registered vector must exist in its fixture")
    }

    #[test]
    fn all_history_ignores_the_join_floor_and_since_join_does_not() {
        assert!(allow_event(
            HistoryAccess::AllHistoryForCurrentMembers,
            false
        ));
        assert!(!allow_event(HistoryAccess::SinceJoin, false));
        assert!(allow_epoch(
            HistoryAccess::AllHistoryForCurrentMembers,
            0,
            9
        ));
        assert!(!allow_epoch(HistoryAccess::SinceJoin, 8, 9));
        assert!(allow_epoch(HistoryAccess::SinceJoin, 9, 9));
    }

    #[test]
    fn scope_readability_requires_every_conjunct() {
        let access = HistoryAccess::AllHistoryForCurrentMembers;
        assert!(readable_by_scope(access, standing(true)));
        assert!(!readable_by_scope(
            access,
            RecipientScopeStanding {
                authorization_subject_active: false,
                ..standing(true)
            }
        ));
        assert!(!readable_by_scope(
            access,
            RecipientScopeStanding {
                scope_readable: false,
                ..standing(true)
            }
        ));
    }

    #[test]
    fn an_ordinary_self_update_keeps_the_endpoint_incarnation() {
        let admission = EndpointAdmission {
            activation_event_id: event_id('a'),
            removed_by_event_id: None,
        };
        assert!(admission.is_open());
        assert_eq!(
            admission.advance(EndpointTransition::OrdinarySelfUpdate, Some(event_id('b'))),
            admission
        );
        for transition in [
            EndpointTransition::RemoveAndAdd,
            EndpointTransition::CredentialReplacement,
            EndpointTransition::SignatureKeyReplacement,
            EndpointTransition::Reinstall,
        ] {
            assert!(transition.resets_endpoint_incarnation());
            assert_eq!(
                admission
                    .advance(transition, Some(event_id('b')))
                    .activation_event_id,
                event_id('b')
            );
        }
    }

    #[test]
    fn delivery_needs_every_current_gate() {
        let access = HistoryAccess::AllHistoryForCurrentMembers;
        assert!(deliverable(access, 0, 4, OPEN_GATES));
        assert!(!deliverable(
            access,
            0,
            4,
            DeliveryGates {
                safety: false,
                ..OPEN_GATES
            }
        ));
    }

    #[test]
    fn a_profile_floor_terminal_decision_names_its_endpoint_incarnation() {
        let mut decision = HistoryTerminalDecision {
            effective_scope: realm_scope(),
            epoch: 5,
            authorization_incarnation: AuthorizationIncarnation::Realm {
                realm_membership_incarnation_ref: event_id('a'),
            },
            endpoint_incarnation: None,
            reason: HistoryTerminalReason::DecryptionUnavailableByProfileFloor,
        };
        assert!(decision.validate().is_err());
        decision.endpoint_incarnation = Some(event_id('b'));
        decision.validate().unwrap();
        assert_eq!(decision.reason.error_code(), ErrorCode::HistoryNotVisible);
    }

    fn pairwise(actor: &str, incarnation: char) -> MinimalMetadataEndpointIdentity {
        MinimalMetadataEndpointIdentity {
            realm_id: RealmId::new("ak:realm:AfjSiYTXJZS-0ifVfy1f_uzsmJIBjDyN11_-dxnne50e")
                .unwrap(),
            endpoint_incarnation: event_id(incarnation),
            pairwise_actor_id: DidCoreId::new(actor).unwrap(),
            event_actor_id: DidCoreId::new(actor).unwrap(),
            leaf_credential_identity: actor.to_owned(),
            proof_key_id: actor.to_owned(),
            sender_kdf_domain: actor.to_owned(),
            request_sender_domain: actor.to_owned(),
        }
    }

    #[test]
    fn every_pairwise_projection_must_be_byte_identical() {
        let actor = "ak:did_core:key:z6MkPairwiseOne";
        pairwise(actor, 'a').validate().unwrap();

        let mut drifted = pairwise(actor, 'a');
        drifted.sender_kdf_domain = "ak:did_core:key:z6MkPairwiseTwo".to_owned();
        assert!(drifted.validate().is_err());

        let mut not_did_key = pairwise("ak:did_core:webvh:z6mkalice", 'a');
        not_did_key.leaf_credential_identity = "ak:did_core:webvh:z6mkalice".to_owned();
        assert!(not_did_key.validate().is_err());
    }
}
