use arkret_identity::AuthorityHistoryUnavailable;
use arkret_models_identity::IdentityLogListOutcome;
use arkret_signatures::webvh::{ServiceInceptionInput, prepare_service_inception};
use arkret_wire::{AccountId, Base64UrlString, Did, DidUrl};
use chrono::{Duration, TimeZone as _};
use ed25519_dalek::{Signer as _, SigningKey};
use rand_chacha::ChaChaRng;
use rand_core::SeedableRng as _;

use super::*;

struct Fixture {
    key: SigningKey,
    history: IdentityLogListOutcome,
    signature: ProtocolSignature,
    issuer: ContactPeer,
    peer: ContactPeer,
    round: Hash,
}
impl AuthorityDidHistoryResolver for Fixture {
    fn resolve_complete_history(
        &self,
        _did: &Did,
    ) -> std::result::Result<IdentityLogListOutcome, AuthorityHistoryUnavailable> {
        Ok(self.history.clone())
    }
}
impl Fixture {
    fn new() -> Self {
        let at = Utc.with_ymd_and_hms(2026, 9, 12, 0, 0, 0).unwrap();
        let endpoint = "https://contact-authority.example/".parse().unwrap();
        let mut rng = ChaChaRng::seed_from_u64(719);
        let inception = prepare_service_inception(
            &mut rng,
            &ServiceInceptionInput {
                principal_endpoint: &endpoint,
                local_id: "service",
                also_known_as: &[],
                version_time: at,
                did_key_fragment: Some("assertion-1"),
            },
        )
        .unwrap();
        let did = Did::new(inception.did.clone()).unwrap();
        let station = arkret_wire::project_did_to_core_id(&did).unwrap();
        Self {
            key: SigningKey::from_bytes(&inception.did_key_seed),
            history: IdentityLogListOutcome {
                did,
                method: DidMethodUri::Webvh,
                native_history: Some(true),
                entries: vec![inception.log_entry.clone()],
                next_cursor: None,
                has_more: false,
            },
            signature: ProtocolSignature {
                verification_method: DidUrl::new(inception.did_key_id.clone()).unwrap(),
                created_at: at,
                jws: Base64UrlString::new("AA").unwrap(),
            },
            issuer: ContactPeer::Human {
                account_id: AccountId::new(
                    DidCoreId::new("ak:did_core:webvh:zfixturealice").unwrap(),
                    station,
                ),
            },
            peer: ContactPeer::Human {
                account_id: AccountId::new(
                    DidCoreId::new("ak:did_core:webvh:zfixturebob").unwrap(),
                    DidCoreId::new("ak:did_core:webvh:zfixturebobstation").unwrap(),
                ),
            },
            round: Hash::new(format!("sha256:{}", "33".repeat(32))).unwrap(),
        }
    }
    fn sign(&self, bytes: &[u8]) -> Base64UrlString {
        Base64UrlString::new(arkret_canonical::base64url_encode(
            self.key.sign(bytes).to_bytes(),
        ))
        .unwrap()
    }
    fn lineage(&self, version: u8, scopes: &[ContactScope], terminal: bool) -> ContactLineage {
        let mut lineage = ContactLineage {
            contact_round_id: self.round.clone(),
            issuer: self.issuer.clone(),
            peer: self.peer.clone(),
            version: u64::from(version),
            predecessor_event_ref: (version > 1).then(|| event_id(version - 1)),
            event_ref: event_id(version),
            granted_to_peer_scopes: scopes.to_vec(),
            terminal: terminal.then_some(true),
            signature: self.signature.clone(),
        };
        self.resign(&mut lineage);
        lineage
    }
    fn resign(&self, lineage: &mut ContactLineage) {
        lineage.signature.jws = self.sign(&lineage.canonical_signing_bytes().unwrap());
    }
    fn checkpoint(&self, last: &ContactLineage) -> ContactCurrentProof {
        let mut proof = ContactCurrentProof {
            contact_round_id: self.round.clone(),
            issuer_id: self.issuer.delivery_station_id().clone(),
            peer: self.peer.clone(),
            terminal: last.terminal == Some(true),
            head_event_ref: last.event_ref.clone(),
            accepted_frontier: vec![last.event_ref.clone()],
            complete_through: last.version,
            fresh_until: self.signature.created_at + Duration::minutes(5),
            signature: self.signature.clone(),
        };
        proof.signature.jws = self.sign(&proof.canonical_signing_bytes().unwrap());
        proof
    }
    fn verify(&self, chain: &[ContactLineage]) -> Result<VerifiedContactDirection> {
        verify_contact_direction_history(
            &self.issuer,
            &self.peer,
            &self.round,
            chain,
            &self.checkpoint(chain.last().unwrap()),
            self.signature.created_at,
            self,
        )
    }
}
fn event_id(value: u8) -> EventId {
    EventId::from_digest(arkret_canonical::DigestSuite::Sha256, [value; 32])
}

#[test]
fn scopes_keep_their_generation_until_removed_then_readded() {
    use ContactScope::{DirectMessage, Presence, VoiceCall};
    let fixture = Fixture::new();
    let chain = vec![
        fixture.lineage(1, &[DirectMessage, Presence], false),
        fixture.lineage(2, &[DirectMessage, VoiceCall], false),
        fixture.lineage(3, &[VoiceCall], false),
        fixture.lineage(4, &[DirectMessage, VoiceCall], false),
    ];
    let verified = fixture.verify(&chain).unwrap();
    let retained = verified.open_interval(VoiceCall).unwrap();
    assert_eq!(retained.authorization_event_id(), &event_id(1));
    assert_eq!(retained.generation_event_id(), &event_id(2));
    let readded = verified.open_interval(DirectMessage).unwrap();
    assert_eq!(readded.authorization_event_id(), &event_id(1));
    assert_eq!(readded.generation_event_id(), &event_id(4));
    assert!(
        verified
            .intervals()
            .iter()
            .any(|interval| interval.scope() == DirectMessage
                && interval.generation_event_id() == &event_id(1)
                && interval.closed_by() == Some(&event_id(3)))
    );
    assert!(verified.open_interval(Presence).is_none());
    assert!(matches!(
        verified.require_current_at(fixture.signature.created_at + Duration::hours(1)),
        Err(ContactAuthorizationError::NotCurrent)
    ));
    assert_eq!(
        verified
            .open_interval(DirectMessage)
            .unwrap()
            .generation_event_id(),
        &event_id(4)
    );
}

#[test]
fn terminal_closes_every_scope_and_cannot_reopen_the_round() {
    let fixture = Fixture::new();
    let mut chain = vec![
        fixture.lineage(1, &[ContactScope::DirectMessage], false),
        fixture.lineage(2, &[ContactScope::DirectMessage], true),
    ];
    let verified = fixture.verify(&chain).unwrap();
    assert!(
        verified
            .open_interval(ContactScope::DirectMessage)
            .is_none()
    );
    assert_eq!(verified.intervals()[0].closed_by(), Some(&event_id(2)));
    chain.push(fixture.lineage(3, &[ContactScope::DirectMessage], false));
    assert!(matches!(
        fixture.verify(&chain),
        Err(ContactAuthorizationError::InvalidEvidence(_))
    ));
}

#[test]
fn incomplete_chains_are_pending_but_false_predecessors_are_invalid() {
    let fixture = Fixture::new();
    let first = fixture.lineage(1, &[ContactScope::DirectMessage], false);
    let second = fixture.lineage(2, &[], false);
    let third = fixture.lineage(3, &[ContactScope::DirectMessage], false);
    assert!(matches!(
        fixture.verify(&[second.clone(), third.clone()]),
        Err(ContactAuthorizationError::MissingMaterial(_))
    ));
    assert!(matches!(
        fixture.verify(&[first.clone(), third]),
        Err(ContactAuthorizationError::MissingMaterial(_))
    ));
    let mut bad = second;
    bad.predecessor_event_ref = Some(event_id(9));
    fixture.resign(&mut bad);
    assert!(matches!(
        fixture.verify(&[first, bad]),
        Err(ContactAuthorizationError::InvalidEvidence(_))
    ));
}

#[test]
fn rejects_wrong_pair_round_source_and_payload_tampering() {
    let fixture = Fixture::new();
    let original = fixture.lineage(1, &[ContactScope::DirectMessage], false);
    let mut wrong_pair = original.clone();
    wrong_pair.peer = fixture.issuer.clone();
    fixture.resign(&mut wrong_pair);
    assert!(matches!(
        fixture.verify(&[wrong_pair]),
        Err(ContactAuthorizationError::InvalidEvidence(_))
    ));
    let mut wrong_round = original.clone();
    wrong_round.contact_round_id = Hash::new(format!("sha256:{}", "44".repeat(32))).unwrap();
    fixture.resign(&mut wrong_round);
    assert!(matches!(
        fixture.verify(&[wrong_round]),
        Err(ContactAuthorizationError::InvalidEvidence(_))
    ));
    let mut wrong_source = original.clone();
    wrong_source.signature.verification_method =
        DidUrl::new("did:webvh:zother:other.example#key").unwrap();
    assert!(matches!(
        fixture.verify(&[wrong_source]),
        Err(ContactAuthorizationError::InvalidEvidence(_))
    ));
    let mut tampered = original;
    tampered.granted_to_peer_scopes.push(ContactScope::Presence);
    assert!(matches!(
        fixture.verify(&[tampered]),
        Err(ContactAuthorizationError::InvalidEvidence(_))
    ));
}

#[test]
fn verifies_method_history_and_historical_assertion_relationship() {
    let mut fixture = Fixture::new();
    let mut lineage = fixture.lineage(1, &[ContactScope::DirectMessage], false);
    lineage.signature.verification_method =
        DidUrl::new(format!("{}#not-an-assertion-key", fixture.history.did)).unwrap();
    assert!(matches!(
        fixture.verify(&[lineage]),
        Err(ContactAuthorizationError::InvalidEvidence(_))
    ));
    let lineage = fixture.lineage(1, &[ContactScope::DirectMessage], false);
    fixture.history.has_more = true;
    assert!(matches!(
        fixture.verify(&[lineage.clone()]),
        Err(ContactAuthorizationError::MissingMaterial(_))
    ));
    fixture.history.has_more = false;
    fixture.history.entries[0]["state"]["alsoKnownAs"] =
        serde_json::json!(["https://forged.example/"]);
    assert!(matches!(
        fixture.verify(&[lineage]),
        Err(ContactAuthorizationError::InvalidEvidence(_))
    ));
}

#[test]
fn first_observation_requires_current_evidence() {
    let fixture = Fixture::new();
    let chain = vec![fixture.lineage(1, &[ContactScope::DirectMessage], false)];
    let checkpoint = fixture.checkpoint(&chain[0]);
    assert!(matches!(
        verify_contact_direction_history(
            &fixture.issuer,
            &fixture.peer,
            &fixture.round,
            &chain,
            &checkpoint,
            checkpoint.fresh_until,
            &fixture
        ),
        Err(ContactAuthorizationError::NotCurrent)
    ));
}
