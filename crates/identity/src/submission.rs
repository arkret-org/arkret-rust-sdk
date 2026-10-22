//! Immutable producer values for publication after complete local verification.
//!
//! Verification here authenticates the exact producer bytes against a caller's
//! trusted signing context. It does not establish current server authorization,
//! acceptance, Realm ordering, or the authority's independent RealmCommit.

use arkret_canonical::DigestSuite;
use arkret_event_draft::{ValidatedExtensionPayload, validate_event_for_submit};
use arkret_signatures::{
    EventProofBuilder, PublicKeyMaterial, verify_ed25519_detached_jws_proof_with_digest_suite,
};
use arkret_wire::{ActorId, DidUrl, Event, RealmCommit};
use serde::{Serialize, Serializer};

use crate::test_material::{PublicKeyFingerprintInput, enforce_formal_test_material_policy};
use crate::{IdentityError, Result};

mod requests;
pub use requests::PublicationRequest;

/// Independently trusted inputs for one producer's signature verification.
///
/// Resolve these from accepted authority state, a verified genesis authoring
/// context, or the producer's own authorized signing material. Never derive the
/// key or digest suite from unverified Event fields. A session PoP key is not an
/// Event device signing key. Retain the original trusted context for an exact
/// retry; this constructor adds no current-key lookup or proof expiry window.
#[derive(Clone, Debug)]
pub struct ProducerVerificationContext {
    pub actor: ActorId,
    pub verification_method: DidUrl,
    pub public_key: PublicKeyMaterial,
    pub digest_suite: DigestSuite,
}

/// A complete typed Event whose identity and producer proof have verified.
///
/// There is no unchecked constructor, deserializer, mutable accessor, or
/// `DerefMut`. Recovering a wire/draft copy does not transfer this guarantee.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedProducerEvent {
    event: Event,
    canonical_bytes: Vec<u8>,
}

impl VerifiedProducerEvent {
    /// Parse canonical wire bytes into a draft, then run the complete verifier.
    pub fn from_canonical_json_slice(
        bytes: &[u8],
        context: &ProducerVerificationContext,
    ) -> Result<Self> {
        Self::verify(Event::from_canonical_json_slice(bytes)?, context)
    }

    /// Verify a registered standard kind through the SDK's complete typed gate.
    pub fn verify(event: Event, context: &ProducerVerificationContext) -> Result<Self> {
        validate_event_for_submit(&event)
            .map_err(|error| IdentityError::Protocol(error.to_string()))?;
        Self::verify_producer(event, context)
    }

    /// Verify an extension without treating an unknown kind as a standard kind.
    /// The payload token binds the already loaded, digest-pinned manifest/schema.
    pub fn verify_extension(
        event: Event,
        payload: &ValidatedExtensionPayload,
        context: &ProducerVerificationContext,
    ) -> Result<Self> {
        payload
            .validate_event(&event)
            .map_err(|error| IdentityError::Protocol(error.to_string()))?;
        Self::verify_producer(event, context)
    }

    fn verify_producer(event: Event, context: &ProducerVerificationContext) -> Result<Self> {
        event.verify_producer_proof_self_consistency(context.digest_suite)?;
        Self::verify_signature(event, context)
    }

    fn verify_signature(event: Event, context: &ProducerVerificationContext) -> Result<Self> {
        if event.actual_signer() != &context.actor {
            return Err(IdentityError::Protocol(
                "producer verification context names another actor".to_owned(),
            ));
        }
        event.verify_event_id_matches_content_with_digest_suite(context.digest_suite)?;
        event.validate_proof_bindings_with_digest_suite(context.digest_suite)?;
        let proof = event.producer_proof.as_ref().ok_or_else(|| {
            IdentityError::Protocol("producer verification requires a proof".to_owned())
        })?;
        proof.validate_production()?;
        if proof.verification_method != context.verification_method {
            return Err(IdentityError::Protocol(
                "producer verification context names another verification method".to_owned(),
            ));
        }
        let key = context.public_key.ed25519_bytes()?;
        let did = crate::verification_method_did(proof.verification_method.as_str())?;
        enforce_formal_test_material_policy(
            Some(&PublicKeyFingerprintInput::Ed25519Rfc8032(&key)),
            Some(&did),
            Some(&proof.verification_method),
            None,
        )
        .map_err(|error| IdentityError::Protocol(error.to_string()))?;
        let transcript = EventProofBuilder::new().envelope_bytes(&event)?;
        verify_ed25519_detached_jws_proof_with_digest_suite(
            proof,
            &transcript,
            &event.actor_id,
            &context.public_key,
            context.digest_suite,
        )
        .map_err(|error| IdentityError::Crypto(error.to_string()))?;
        let canonical_bytes = arkret_canonical::canonical_json_bytes(&event)?;
        Ok(Self {
            event,
            canonical_bytes,
        })
    }

    pub fn event(&self) -> &Event {
        &self.event
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    /// Recover a draft/wire value. It must be verified again after any change.
    pub fn into_event(self) -> Event {
        self.event
    }
}

/// Verify the closed identity-root/founding-device PCR pair. The registration
/// root uses a method-native did:key controller, so it cannot be treated as an
/// ordinary principal DID business method. No standalone root bypass is exposed.
pub fn verify_pcr_genesis_events(
    unit: &arkret_wire::PcrGenesisUnit,
    anchor: &arkret_models_identity::PrincipalRegistrationAnchor,
    expected_actor: &ActorId,
) -> Result<[VerifiedProducerEvent; 2]> {
    use arkret_models_collaboration::events_payloads::{
        DeviceAuthorizationBindingKind, DeviceAuthorizePayload, DeviceOrPrincipalRef,
        RealmCreatePayload, RealmPurpose, validate_root_anchored_authorize_payload_digest,
    };
    unit.validate_ordered_envelopes()?;
    let validated = crate::validate_principal_registration_anchor(anchor)?;
    let root = unit.create();
    let authorize = unit.founding_authorize();
    if expected_actor.as_account_id().is_none()
        || expected_actor.signing_principal_id() != &validated.principal_id
        || root.actor_id != *expected_actor
        || root.actual_signer() != expected_actor
        || authorize.actor_id != *expected_actor
        || authorize.actual_signer() != expected_actor
    {
        return Err(IdentityError::Protocol(
            "PCR genesis differs from its trusted account actor".to_owned(),
        ));
    }
    validate_event_for_submit(root).map_err(|e| IdentityError::Protocol(e.to_string()))?;
    validate_event_for_submit(authorize).map_err(|e| IdentityError::Protocol(e.to_string()))?;
    let create: RealmCreatePayload = serde_json::from_value(serde_json::to_value(&root.payload)?)?;
    let resolution = create.object.initial_resolution.as_ref().ok_or_else(|| {
        IdentityError::Protocol("PCR genesis has no initial resolution".to_owned())
    })?;
    if resolution.did != validated.did
        || resolution.method_history_head != validated.method_history_head.as_str()
        || resolution.version_id != validated.did_version_id
    {
        return Err(IdentityError::Protocol(
            "PCR initial resolution differs from its trusted registration anchor".to_owned(),
        ));
    }
    let descriptor = create
        .object
        .founding_device_descriptor
        .as_ref()
        .ok_or_else(|| {
            IdentityError::Protocol("PCR genesis has no founding Device descriptor".to_owned())
        })?;
    let payload: DeviceAuthorizePayload =
        serde_json::from_value(serde_json::to_value(&authorize.payload)?)?;
    if create.object.purpose != RealmPurpose::PrincipalControl
        || payload.authorization_binding_kind != DeviceAuthorizationBindingKind::RegistrationAnchor
        || descriptor.device_id != payload.device_id
        || descriptor.device_public_key_did != payload.device_public_key_did
        || descriptor.hpke_key != payload.hpke_key
        || descriptor.algorithms != payload.algorithms
        || !matches!(&payload.authorized_by, DeviceOrPrincipalRef::Principal(principal) if principal == &validated.principal_id)
    {
        return Err(IdentityError::Protocol(
            "PCR founding Device differs from its root-authenticated descriptor".to_owned(),
        ));
    }
    validate_root_anchored_authorize_payload_digest(
        &descriptor.founding_authorize_payload_digest,
        &serde_json::to_value(&authorize.payload)?,
        DigestSuite::Sha256,
    )?;
    enforce_formal_test_material_policy(None, Some(&validated.did), None, None)
        .map_err(|e| IdentityError::Protocol(e.to_string()))?;
    let root_context = ProducerVerificationContext {
        actor: expected_actor.clone(),
        verification_method: validated.root_verification_method,
        public_key: PublicKeyMaterial::Ed25519Multibase {
            value: validated.root_public_key_multibase,
        },
        digest_suite: DigestSuite::Sha256,
    };
    let device_key = descriptor
        .device_public_key_did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| {
            IdentityError::Protocol("founding Device key is not a did:key".to_owned())
        })?;
    let device_context = ProducerVerificationContext {
        actor: expected_actor.clone(),
        verification_method: DidUrl::new(format!("{}#{}", validated.did, descriptor.device_id))
            .map_err(|e| IdentityError::Protocol(e.to_owned()))?,
        public_key: PublicKeyMaterial::Ed25519Multibase {
            value: device_key.to_owned(),
        },
        digest_suite: DigestSuite::Sha256,
    };
    Ok([
        VerifiedProducerEvent::verify_signature(root.clone(), &root_context)?,
        VerifiedProducerEvent::verify_producer(authorize.clone(), &device_context)?,
    ])
}

impl Serialize for VerifiedProducerEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.event.serialize(serializer)
    }
}

/// An immutable authority Commit authenticated against a verified Realm chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRealmCommit {
    commit: RealmCommit,
}

impl VerifiedRealmCommit {
    pub fn verify(
        commit: RealmCommit,
        authority: &crate::VerifiedRealmAuthority,
        keys: &dyn crate::RealmAuthorityKeyDirectory,
    ) -> Result<Self> {
        commit.validate_content_address()?;
        authority
            .verify_commit(&commit, keys)
            .map_err(|error| IdentityError::Protocol(error.to_string()))?;
        Ok(Self { commit })
    }

    pub fn commit(&self) -> &RealmCommit {
        &self.commit
    }

    /// The canonical Commit body used for content-address derivation.
    pub fn canonical_id_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.commit.canonical_id_bytes()?)
    }
}

impl Serialize for VerifiedRealmCommit {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.commit.serialize(serializer)
    }
}

/// An immutable canonical request whose producer Events and original authority
/// Commits have all been authenticated. Other admission predicates, including
/// current permissions, approvals and atomic-unit state, remain server checks.
/// This type has no Deserialize implementation or mutable wire accessor.
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedSubmission<T: PublicationRequest> {
    request: T,
}

impl<T: PublicationRequest> VerifiedSubmission<T> {
    /// Bind a request to exactly its verified producer Events in wire order.
    /// Requests carrying authority originals require `from_verified_parts`.
    pub fn from_verified_events(request: T, events: &[VerifiedProducerEvent]) -> Result<Self> {
        Self::from_verified_parts(request, events, &[])
    }

    pub fn from_verified_parts(
        request: T,
        events: &[VerifiedProducerEvent],
        commits: &[VerifiedRealmCommit],
    ) -> Result<Self> {
        request.validate_publication_shape()?;
        let wire_events = request.producer_events();
        let wire_commits = request.realm_commits();
        if wire_events.len() != events.len() || wire_commits.len() != commits.len() {
            return Err(IdentityError::Protocol(
                "publication verification does not cover every original exactly once".to_owned(),
            ));
        }
        for (wire, verified) in wire_events.into_iter().zip(events) {
            if arkret_canonical::canonical_json_bytes(wire)? != verified.canonical_bytes {
                return Err(IdentityError::Protocol(
                    "publication Event differs from its verified original".to_owned(),
                ));
            }
        }
        for (wire, verified) in wire_commits.into_iter().zip(commits) {
            if wire != &verified.commit {
                return Err(IdentityError::Protocol(
                    "publication Commit differs from its verified original".to_owned(),
                ));
            }
        }
        Ok(Self { request })
    }

    /// Verify each standard producer against independently trusted context.
    /// The callback supplies key material, never a boolean verification verdict.
    /// Authority originals are deliberately not accepted by this constructor.
    pub fn verify(
        request: T,
        mut context: impl FnMut(&Event) -> Result<ProducerVerificationContext>,
    ) -> Result<Self> {
        let events = request
            .producer_events()
            .into_iter()
            .map(|event| VerifiedProducerEvent::verify(event.clone(), &context(event)?))
            .collect::<Result<Vec<_>>>()?;
        Self::from_verified_events(request, &events)
    }

    pub fn wire(&self) -> &T {
        &self.request
    }

    /// Reuse authentication only when every original remains byte identical.
    /// This permits closed endpoint wrappers without reopening a raw bypass.
    pub fn rebind<U: PublicationRequest>(&self, request: U) -> Result<VerifiedSubmission<U>> {
        request.validate_publication_shape()?;
        let original_events = self.request.producer_events();
        let next_events = request.producer_events();
        if original_events.len() != next_events.len()
            || self.request.realm_commits() != request.realm_commits()
        {
            return Err(IdentityError::Protocol(
                "publication rebinding changes the verified original set".to_owned(),
            ));
        }
        for (original, next) in original_events.into_iter().zip(next_events) {
            if arkret_canonical::canonical_json_bytes(original)?
                != arkret_canonical::canonical_json_bytes(next)?
            {
                return Err(IdentityError::Protocol(
                    "publication rebinding changes a verified Event".to_owned(),
                ));
            }
        }
        Ok(VerifiedSubmission { request })
    }

    /// Return an unverified wire/draft carrier, losing its verified identity.
    pub fn into_wire(self) -> T {
        self.request
    }
}

impl<T: PublicationRequest + Serialize> Serialize for VerifiedSubmission<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        self.request.serialize(serializer)
    }
}

impl<T: PublicationRequest> std::ops::Deref for VerifiedSubmission<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.request
    }
}

#[cfg(test)]
mod tests {
    use arkret_event_draft::TypedEventDraft;
    use arkret_models_collaboration::events_payloads::message::{
        ContentBlock, MessageCreatePayload,
    };
    use arkret_signatures::{Ed25519DetachedJwsSigner, SignEventOptions, sign_event};
    use arkret_wire::{AuthoredEvent, DidCoreId, EventId, RealmId, ScopeRef, StrandId, event_spec};
    use chrono::TimeZone;
    use ed25519_dalek::SigningKey;

    use super::*;

    fn signed() -> (Event, ProducerVerificationContext) {
        let digest_suite = DigestSuite::Sha256;
        let realm_id = RealmId::from_event_id(&EventId::from_digest(digest_suite, [137; 32]));
        let actor = ActorId::service(DidCoreId::new("ak:did_core:web:sdk.arkret.org").unwrap());
        let method = DidUrl::new("did:web:sdk.arkret.org#producer".to_owned()).unwrap();
        let key = SigningKey::from_bytes(&[137; 32]);
        let context = ProducerVerificationContext {
            actor: actor.clone(),
            verification_method: method.clone(),
            public_key: PublicKeyMaterial::Ed25519Raw {
                bytes: key.verifying_key().as_bytes().to_vec(),
            },
            digest_suite,
        };
        let payload = MessageCreatePayload::with_content(
            StrandId::from_event_id(&EventId::from_digest(digest_suite, [138; 32])),
            "main",
            ContentBlock::text("producer verification"),
        );
        let mut authored = TypedEventDraft::<event_spec::MessageCreate>::new(
            ScopeRef::Realm { realm_id },
            actor,
            payload,
        )
        .unwrap()
        .author_with_digest_suite(
            chrono::Utc.with_ymd_and_hms(2026, 9, 19, 0, 0, 0).unwrap(),
            digest_suite,
        )
        .unwrap();
        sign_event(
            &mut authored,
            &Ed25519DetachedJwsSigner::new(key, method.as_str()),
            SignEventOptions::new().with_created_at(authored_time()),
        )
        .unwrap();
        (authored.into_event(), context)
    }

    fn authored_time() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.with_ymd_and_hms(2026, 9, 19, 0, 0, 0).unwrap()
    }

    #[test]
    fn verified_producer_serializes_exactly_and_retains_old_proof_time() {
        let (wire, context) = signed();
        let original = arkret_canonical::canonical_json_bytes(&wire).unwrap();
        let verified = VerifiedProducerEvent::verify(wire.clone(), &context).unwrap();
        assert_eq!(verified.canonical_bytes(), original);
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&verified).unwrap(),
            original
        );
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&verified).unwrap(),
            original
        );
        let mut draft = verified.clone().into_event();
        draft.payload.insert(
            "content".to_owned(),
            serde_json::json!({
                "kind": "ak.content.text", "body": "changed"
            }),
        );
        assert!(VerifiedProducerEvent::verify(draft, &context).is_err());
        assert_eq!(verified.event(), &wire);
    }

    #[test]
    fn producer_verification_rejects_signature_and_trusted_context_changes() {
        let (wire, context) = signed();
        let mut wrong = context.clone();
        wrong.public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: SigningKey::from_bytes(&[139; 32])
                .verifying_key()
                .as_bytes()
                .to_vec(),
        };
        assert!(VerifiedProducerEvent::verify(wire.clone(), &wrong).is_err());
        wrong = context.clone();
        wrong.verification_method = DidUrl::new("did:web:sdk.arkret.org#other".to_owned()).unwrap();
        assert!(VerifiedProducerEvent::verify(wire.clone(), &wrong).is_err());
        wrong = context.clone();
        wrong.actor = ActorId::service(DidCoreId::new("ak:did_core:web:other.arkret.org").unwrap());
        assert!(VerifiedProducerEvent::verify(wire.clone(), &wrong).is_err());
        let mut tampered = wire;
        tampered.producer_proof.as_mut().unwrap().created_at += chrono::Duration::seconds(1);
        assert!(VerifiedProducerEvent::verify(tampered, &context).is_err());
    }

    #[test]
    fn valid_signature_cannot_upgrade_invalid_typed_payload_or_missing_proof() {
        let (mut wire, context) = signed();
        wire.producer_proof = None;
        assert!(VerifiedProducerEvent::verify(wire.clone(), &context).is_err());
        wire.payload
            .insert("unregistered_member".to_owned(), serde_json::json!(true));
        let mut authored =
            AuthoredEvent::finalize_with_digest_suite(wire, context.digest_suite).unwrap();
        sign_event(
            &mut authored,
            &Ed25519DetachedJwsSigner::new(
                SigningKey::from_bytes(&[137; 32]),
                context.verification_method.as_str(),
            ),
            SignEventOptions::new().with_created_at(authored_time()),
        )
        .unwrap();
        let wire = authored.into_event();
        let transcript = EventProofBuilder::new().envelope_bytes(&wire).unwrap();
        verify_ed25519_detached_jws_proof_with_digest_suite(
            wire.producer_proof.as_ref().unwrap(),
            &transcript,
            &wire.actor_id,
            &context.public_key,
            context.digest_suite,
        )
        .unwrap();
        assert!(VerifiedProducerEvent::verify(wire, &context).is_err());
    }

    #[test]
    fn formal_publication_rejects_registered_public_test_key_after_relabeling() {
        let (mut wire, mut context) = signed();
        wire.producer_proof = None;
        let mut authored =
            AuthoredEvent::finalize_with_digest_suite(wire, context.digest_suite).unwrap();
        let key = SigningKey::from_bytes(&std::array::from_fn(|index| index as u8));
        context.public_key = PublicKeyMaterial::Ed25519Raw {
            bytes: key.verifying_key().as_bytes().to_vec(),
        };
        sign_event(
            &mut authored,
            &Ed25519DetachedJwsSigner::new(key, context.verification_method.as_str()),
            SignEventOptions::new().with_created_at(authored_time()),
        )
        .unwrap();
        let error = VerifiedProducerEvent::verify(authored.into_event(), &context).unwrap_err();
        assert!(error.to_string().contains("test_signing_material_denied"));
    }

    #[test]
    fn endpoint_rebinding_preserves_exact_verified_bytes_and_rejects_mutated_draft() {
        use arkret_models_collaboration::authority_commit::SelfAuthoritySubmitRequest;
        use arkret_wire::EventAdmissionSubmission;
        let (wire, context) = signed();
        let original = EventAdmissionSubmission::new(wire.clone());
        let bytes = arkret_canonical::canonical_json_bytes(&original).unwrap();
        let verified = VerifiedSubmission::verify(original, |_| Ok(context.clone())).unwrap();
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&verified).unwrap(),
            bytes
        );
        let endpoint = verified
            .rebind(SelfAuthoritySubmitRequest::Event(verified.wire().clone()))
            .unwrap();
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&endpoint).unwrap(),
            bytes
        );
        let mut changed = verified.wire().clone();
        changed.event.producer_proof.as_mut().unwrap().created_at += chrono::Duration::seconds(1);
        assert!(verified.rebind(changed).is_err());
        assert_eq!(verified.event, wire);
    }

    #[test]
    fn aggregate_requires_every_original_and_never_restores_verification_from_wire() {
        use arkret_wire::{EventAdmissionSubmission, EventsSubmitBatchRequestBody};
        let (wire, context) = signed();
        let token = VerifiedProducerEvent::verify(wire.clone(), &context).unwrap();
        let request = EventsSubmitBatchRequestBody::new(vec![
            EventAdmissionSubmission::new(wire.clone()),
            EventAdmissionSubmission::new(wire),
        ])
        .unwrap();
        assert!(VerifiedSubmission::from_verified_events(request.clone(), &[]).is_err());
        assert!(
            VerifiedSubmission::from_verified_events(request.clone(), std::slice::from_ref(&token))
                .is_err()
        );
        let verified =
            VerifiedSubmission::from_verified_events(request, &[token.clone(), token.clone()])
                .unwrap();
        let mut omitted = verified.wire().clone();
        omitted.events.pop();
        assert!(verified.rebind(omitted).is_err());
        let mut changed = verified.wire().clone();
        changed.events[1]
            .event
            .producer_proof
            .as_mut()
            .unwrap()
            .jws
            .push('A');
        assert!(
            VerifiedSubmission::from_verified_events(changed, &[token.clone(), token]).is_err()
        );
        let bytes = arkret_canonical::canonical_json_bytes(&verified).unwrap();
        let restored: EventsSubmitBatchRequestBody = serde_json::from_slice(&bytes).unwrap();
        let independently_verified =
            VerifiedSubmission::verify(restored, |_| Ok(context.clone())).unwrap();
        assert_eq!(
            arkret_canonical::canonical_json_bytes(&independently_verified).unwrap(),
            bytes
        );
    }
}
