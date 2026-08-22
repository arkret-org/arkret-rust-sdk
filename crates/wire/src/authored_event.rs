//! The producer-authoring identity boundary.
//!
//! [`Event`] is the wire shape: every field is public because a receiver has to
//! be able to construct one from arbitrary canonical JSON. That makes it the
//! wrong type for *producing* an Event, because `event_id` is a function of the
//! finished envelope (`zh/conformance/encoding.md` section 4.0) and a public
//! mutable field lets a caller read a "final" id while `actor_seq`, `hlc` or the
//! CBA basis are still missing. Anything derived from that premature id —
//! `retype(event_id)` object ids, dedupe keys, routes, storage keys — names an
//! Event that will never exist.
//!
//! [`AuthoredEvent`] closes that hole. It is the only type in the SDK whose
//! `event_id` is guaranteed to equal the value re-derived from its own content,
//! and it can only be obtained by finishing producer authoring
//! ([`AuthoredEvent::finalize_with_digest_suite`]) or by proving an existing
//! envelope already satisfies that equality
//! ([`AuthoredEvent::from_verified_with_digest_suite`]). Producer fields
//! are unreachable through `&mut`; the only in-place mutations are `proofs` and
//! `unsigned`, both of which `event_digest_preimage` removes, so neither can
//! move the identity.

use std::ops::Deref;

use arkret_canonical::DigestSuite;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::event_envelope::Event;
use crate::primitives::EventProof;
use crate::{Error, EventId, Result};

/// An Event whose producer-signed content is complete and whose `event_id` was
/// derived once from exactly that content.
///
/// Read access goes through [`Deref`], so `authored.kind`, `authored.payload`
/// and `authored.event_id` behave as they do on [`Event`]. There is no
/// `DerefMut`: a producer field can only be changed by leaving this type
/// through [`AuthoredEvent::into_event`] and authoring again, which re-derives
/// the identity.
///
/// A producer field cannot be rewritten under a settled identity:
///
/// ```compile_fail
/// # use arkret_wire::AuthoredEvent;
/// fn retroactive_authoring(authored: &mut AuthoredEvent) {
///     authored.actor_seq = 42;
/// }
/// ```
///
/// nor can the envelope be borrowed mutably to do the same thing:
///
/// ```compile_fail
/// # use arkret_wire::{AuthoredEvent, Event};
/// fn borrow_out_the_envelope(authored: &mut AuthoredEvent) -> &mut Event {
///     authored
/// }
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct AuthoredEvent {
    event: Event,
    digest_suite: DigestSuite,
}

impl AuthoredEvent {
    /// Finish producer authoring under the Realm's declared content digest suite.
    ///
    /// The suite is an explicit input because it is accepted Realm state, never
    /// a fact inferred from the Event being authored. It is retained so proof
    /// attachment and any later verification use the same suite that produced
    /// the identity.
    pub fn finalize_with_digest_suite(event: Event, digest_suite: DigestSuite) -> Result<Self> {
        if !event.proofs.is_empty() {
            return Err(Error::Protocol(
                "authored_event_finalize_after_proof: proofs are attached to an AuthoredEvent, \
                 not carried into authoring"
                    .to_owned(),
            ));
        }
        let mut event = event;
        event.refresh_content_bound_identity_with_digest_suite(digest_suite)?;
        Ok(Self {
            event,
            digest_suite,
        })
    }

    /// Accept an envelope that already carries its final identity, proving the
    /// carried `event_id` equals the value re-derived from its own content.
    ///
    /// This is the boundary for Events that were authored elsewhere: read off
    /// the wire, restored from a durable queue, or reconstructed from canonical
    /// digest-payload bytes. It never rewrites `event_id`; a mismatch is a
    /// fail-closed error naming the caller's authoring mistake.
    /// Accept an already identified Event under an explicit Realm digest suite.
    pub fn from_verified_with_digest_suite(
        event: Event,
        digest_suite: DigestSuite,
    ) -> Result<Self> {
        event.verify_event_id_matches_content_with_digest_suite(digest_suite)?;
        Ok(Self {
            event,
            digest_suite,
        })
    }

    /// The digest suite this Event's identity and proofs are bound to.
    pub fn digest_suite(&self) -> DigestSuite {
        self.digest_suite
    }

    /// The final content-bound Event identity.
    pub fn event_id(&self) -> &EventId {
        &self.event.event_id
    }

    /// Borrow the wire envelope for serialization, digesting and reads.
    pub fn event(&self) -> &Event {
        &self.event
    }

    /// Leave the authoring boundary.
    ///
    /// The returned [`Event`] is fully mutable again, which is exactly why this
    /// consumes `self`: a caller that edits producer fields no longer holds an
    /// [`AuthoredEvent`] and must author again to get one.
    pub fn into_event(self) -> Event {
        self.event
    }

    /// Attach or replace a proof.
    ///
    /// `proofs` is removed by `event_digest_preimage`, so this cannot move the
    /// identity. A producer proof replaces an existing producer proof carrying
    /// the same `verification_method`, matching the idempotent re-sign the
    /// signer relies on.
    pub fn attach_proof(&mut self, proof: EventProof) {
        if let Some(incoming) = proof.as_producer() {
            let method = incoming.verification_method.clone();
            if let Some(slot) = self.event.proofs.iter_mut().find(|existing| {
                existing
                    .as_producer()
                    .is_some_and(|existing| existing.verification_method == method)
            }) {
                *slot = proof;
                return;
            }
        }
        self.event.proofs.push(proof);
    }

    /// Drop every attached proof, e.g. before re-signing with a different key.
    pub fn clear_proofs(&mut self) {
        self.event.proofs.clear();
    }

    /// Record a transport- or holder-local member outside the signed
    /// transcript. `unsigned` is removed by `event_digest_preimage`, so this
    /// cannot move the identity, and it never participates in protocol
    /// identity or authorization.
    pub fn insert_unsigned(&mut self, key: impl Into<String>, value: Value) {
        self.event.unsigned.insert(key.into(), value);
    }

    /// Remove a holder-local `unsigned` member.
    pub fn remove_unsigned(&mut self, key: &str) -> Option<Value> {
        self.event.unsigned.remove(key)
    }

    /// Test-only constructor that skips the identity proof.
    ///
    /// Production code cannot reach it: `test-support` is a dev-dependency
    /// feature. It exists so downstream tests can build the one input shape the
    /// public constructors refuse, and prove that the paths consuming an
    /// `AuthoredEvent` — signing above all — fail closed on it.
    #[cfg(feature = "test-support")]
    #[doc(hidden)]
    pub fn from_unverified_for_test(event: Event, digest_suite: DigestSuite) -> Self {
        Self {
            event,
            digest_suite,
        }
    }

    /// Re-prove the identity invariant against the carried content.
    ///
    /// Held by construction; kept as the explicit assertion the signer runs so
    /// tampering between authoring and signing fails closed instead of being
    /// papered over by a silent re-derivation.
    pub fn verify_identity(&self) -> Result<()> {
        self.event
            .verify_event_id_matches_content_with_digest_suite(self.digest_suite)
    }
}

impl Deref for AuthoredEvent {
    type Target = Event;

    fn deref(&self) -> &Self::Target {
        &self.event
    }
}

impl AsRef<Event> for AuthoredEvent {
    fn as_ref(&self) -> &Event {
        &self.event
    }
}

impl From<AuthoredEvent> for Event {
    fn from(value: AuthoredEvent) -> Self {
        value.event
    }
}

impl Serialize for AuthoredEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        AuthoredEventRecordRef {
            digest_suite: self.digest_suite,
            event: &self.event,
        }
        .serialize(serializer)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AuthoredEventRecordRef<'a> {
    digest_suite: DigestSuite,
    event: &'a Event,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoredEventRecord {
    digest_suite: DigestSuite,
    event: Event,
}

impl<'de> Deserialize<'de> for AuthoredEvent {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let record = AuthoredEventRecord::deserialize(deserializer)?;
        Self::from_verified_with_digest_suite(record.event, record.digest_suite)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;
    use crate::{
        DidCoreId, DidUrl, EventId, EventRequirements, Hash, Hlc, ProducerEventProof, RealmId,
        ScopeRef,
    };

    const SUITE: DigestSuite = DigestSuite::Sha256;

    fn realm() -> RealmId {
        RealmId::new("ak:realm:ARQRpvtCGBgQfVQzTK4_Hgbg0D0HSnc3gPCvXOQUICir").unwrap()
    }

    fn envelope() -> Event {
        let actor = DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap();
        Event {
            event_id: EventId::from_digest(DigestSuite::Sha256, [0xa0; 32]),
            kind: "ak.message.create".into(),
            realm_id: realm(),
            scope_ref: ScopeRef::Realm { realm_id: realm() },
            actor_id: actor.clone(),
            executed_by: None,
            principal_server_id: actor,
            authorization_ref: None,
            applet_id: None,
            external_ref: None,
            actor_kind: None,
            actor_seq: 7,
            created_at: "2026-08-09T01:02:03.000Z".parse().unwrap(),
            hlc: Some(Hlc::new("01970e589d21-0001-a13f9c2e").unwrap()),
            prev_refs: Vec::new(),
            refs: Vec::new(),
            causal_refs: Vec::new(),
            preconditions: Vec::new(),
            seal_ref: None,
            auth_context: None,
            seal_basis: None,
            payload: serde_json::from_value(json!({
                "strand_id": "ak:strand:AT3ARBdH1FM6GjXK9ulTx-YMvQOXys39dlUzZV6KyID9",
                "track_name": "discussion",
                "content": {"kind": "ak.content.text", "body": "hello"}
            }))
            .unwrap(),
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
            requirements: EventRequirements::default(),
        }
    }

    fn producer_proof() -> EventProof {
        EventProof::Producer(ProducerEventProof {
            kind: "detached_jws".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1").unwrap(),
            event_digest: Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap(),
            signer_resolution_evidence_ref: None,
            signer_resolution_evidence_digest: None,
            created_at: "2026-08-09T01:02:03.000Z".parse().unwrap(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "stub..signature".to_owned(),
        })
    }

    #[test]
    fn finalize_derives_the_identity_and_verification_holds() {
        let authored = AuthoredEvent::finalize_with_digest_suite(envelope(), SUITE).unwrap();
        assert_eq!(
            authored.event_id(),
            &authored
                .event()
                .derive_event_id_with_digest_suite(SUITE)
                .unwrap()
        );
        authored.verify_identity().unwrap();
    }

    #[test]
    fn finalize_refuses_an_envelope_that_already_carries_proofs() {
        let mut event = AuthoredEvent::finalize_with_digest_suite(envelope(), SUITE)
            .unwrap()
            .into_event();
        event.proofs = vec![producer_proof()];
        let error = AuthoredEvent::finalize_with_digest_suite(event, SUITE)
            .expect_err("proofs precede nothing");
        assert!(
            format!("{error}").contains("authored_event_finalize_after_proof"),
            "got: {error}"
        );
    }

    /// Proof and transport-only members sit outside the digest preimage, so
    /// attaching them must leave the identity exactly where authoring put it.
    #[test]
    fn proof_and_unsigned_members_do_not_move_the_identity() {
        let mut authored = AuthoredEvent::finalize_with_digest_suite(envelope(), SUITE).unwrap();
        let event_id = authored.event_id().clone();
        authored.attach_proof(producer_proof());
        authored.insert_unsigned("local_operation_id", json!("holder-local"));
        assert_eq!(authored.event_id(), &event_id);
        assert_eq!(authored.proofs.len(), 1);
        authored.verify_identity().unwrap();
    }

    #[test]
    fn from_verified_rejects_a_carried_identity_that_does_not_match_its_content() {
        let mut event = AuthoredEvent::finalize_with_digest_suite(envelope(), SUITE)
            .unwrap()
            .into_event();
        event.actor_seq += 1;
        let error = AuthoredEvent::from_verified_with_digest_suite(event, SUITE)
            .expect_err("content moved under a settled id");
        assert!(
            format!("{error}").contains("event_id_digest_mismatch"),
            "got: {error}"
        );
    }

    /// A durable record is not a trusted source of identity: restoring one
    /// re-proves the binding rather than believing the stored `event_id`.
    #[test]
    fn restoration_reproves_the_identity_with_the_frozen_suite() {
        let authored = AuthoredEvent::finalize_with_digest_suite(envelope(), SUITE).unwrap();
        let json = serde_json::to_value(&authored).unwrap();
        let restored: AuthoredEvent = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(restored, authored);

        let mut tampered = json;
        tampered["event"]["event_id"] =
            json!(EventId::from_digest(DigestSuite::Sha256, [0x11; 32]).as_str());
        let error = serde_json::from_value::<AuthoredEvent>(tampered)
            .expect_err("a rewritten event_id must not restore");
        assert!(
            format!("{error}").contains("event_id_digest_mismatch"),
            "got: {error}"
        );
    }

    /// The genesis Realm id is a function of the create Event id, so both must
    /// come out of one finalize. Splitting them is how a caller ends up holding
    /// a Realm id that no accepted Event names.
    #[test]
    fn a_realm_genesis_derives_its_realm_id_from_the_same_finalize() {
        let mut event = envelope();
        event.kind = "ak.realm.create".into();
        event.scope_ref = ScopeRef::RealmGenesis;
        event.actor_seq = 0;
        event.payload = BTreeMap::new();
        let authored = AuthoredEvent::finalize_with_digest_suite(event, SUITE).unwrap();
        assert_eq!(
            authored.realm_id,
            RealmId::from_event_id(authored.event_id())
        );
        authored.verify_identity().unwrap();
    }
}
