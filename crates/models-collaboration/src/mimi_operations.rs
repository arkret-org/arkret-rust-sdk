//! MIMI interoperability moderation and consent facade.

use std::collections::BTreeMap;

use arkret_wire::serde_helpers::canonical_timestamp;
use arkret_wire::{
    AccountId, ActorId, AuditReasonText, CommittedEventRef, ConsentId, DeviceId, DidCoreId,
    EventCommitSubmission, EventId, EventKind, Hash, NonEmptyString, PayloadProof, ProofContextId,
    ReportId, Result, ServiceOperationId, StrandId, UnsignedPayloadProof, WireError, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::objects::mimi::{
    MimiCiphertext, MimiConsentPurpose, MimiDelivery, MimiDeliveryStatus, MimiFailure,
    MimiIdentifierMatch, MimiOpaquePayload,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiReporterAuthority {
    pub actor_id: ActorId,
    pub membership_ref: CommittedEventRef,
    pub room_binding_ref: CommittedEventRef,
    #[serde(with = "canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proof: PayloadProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiReportAbuseRequestBody {
    pub reporter_authority: MimiReporterAuthority,
    pub report_event: EventCommitSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiReportAbuseOutcome {
    pub report_id: ReportId,
    pub status: MimiReportAbuseStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routed_to_ids: Vec<DidCoreId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MimiReportAbuseStatus {
    Queued,
}

/// Ask a named Arkret holder to grant consent to a named Arkret Actor.
///
/// The signed request writes both identities in full and the facade freezes
/// exactly those into its private correlation, so `update_consent` is a byte
/// comparison rather than a re-resolution against whatever the facade's
/// current Station or alias table happens to say.
// Field declaration order is byte-for-byte the properties order of
// mimi-operations.schema.json#/$defs/mimi_request_consent_request_body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiRequestConsentRequestBody {
    /// Exact Actor the requester is asking as, Station and actor role
    /// included. `consent-model.md` section 6.1 compares an ordinary peer by
    /// complete `ActorId` and forbids falling back to a bare principal, so a
    /// correlation frozen on a principal core could never be reconciled
    /// without one side reducing dimensions.
    pub requester_actor_id: ActorId,
    /// Exact Account the request is addressed to, chosen and signed by the
    /// requester. It is not evidence that the holder exists, is visible or has
    /// consented: a syntactically valid authenticated request returns an
    /// indistinguishable opaque outcome either way.
    pub holder_account_id: AccountId,
    pub purpose: MimiConsentPurpose,
    /// Optional interop context. It grants no Realm authority and neither
    /// widens nor narrows the consent scope; when present it is covered by the
    /// unsigned-body digest like every other member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_wire::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    /// Required requester operation proof over
    /// `ak.mimi_request_consent_request_proof.v1`. Missing authorized current
    /// evidence fails closed before correlation creation or holder lookup.
    pub proofs: Vec<PayloadProof>,
}

impl MimiRequestConsentRequestBody {
    pub fn validate(&self) -> Result<()> {
        self.holder_account_id.validate()?;
        if self.proofs.is_empty() {
            return Err(WireError::Protocol(
                "MIMI request_consent requires at least one requester proof".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn unsigned_payload(&self) -> Result<Value> {
        mimi_unsigned_body_without_proofs(self)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        mimi_payload_digest(&self.unsigned_payload()?)
    }

    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        proof.validate_production()?;
        self.unsigned_proof_binding_bytes(&proof.unsigned())
    }

    /// Construct the signing preimage before a signature exists.
    pub fn unsigned_proof_binding_bytes(&self, proof: &UnsignedPayloadProof) -> Result<Vec<u8>> {
        mimi_proof_binding_bytes(
            ProofContextId::MIMI_REQUEST_CONSENT_REQUEST_PROOF_V1,
            ServiceOperationId::OPEN_MIMI_COMMAND_REQUEST_CONSENT_V1,
            Some(serde_json::to_value(&self.requester_actor_id)?),
            vec![
                (
                    "holder_account_id",
                    serde_json::to_value(&self.holder_account_id)?,
                ),
                ("purpose", serde_json::to_value(self.purpose)?),
            ],
            &self.payload_digest()?,
            proof,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MimiConsentDecision {
    Accept,
    Deny,
    Revoke,
}

impl MimiConsentDecision {
    /// Event kind the decision's carried consent Event must already be.
    ///
    /// `accept` requires `ak.consent.grant`; `deny` and `revoke` both require
    /// `ak.consent.revoke`. The facade never synthesizes, rebuilds or co-signs
    /// that Event, so the decision and the caller-authored kind have to agree
    /// on the wire.
    #[must_use]
    pub const fn required_consent_event_kind(self) -> EventKind {
        match self {
            Self::Accept => EventKind::ConsentGrant,
            Self::Deny | Self::Revoke => EventKind::ConsentRevoke,
        }
    }
}

/// Carries the caller-authored, caller-signed Arkret consent Event.
///
/// The facade verifies the detached MIMI operation signature over the complete
/// unsigned body using the exact holder Account's current accepted PCR device
/// generation and revocation state, not DID Document controller keys, then
/// submits `consent_event` unchanged through authority Event submission.
// Field declaration order is byte-for-byte the properties order of
// mimi-operations.schema.json#/$defs/mimi_update_consent_request_body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MimiUpdateConsentRequestBody {
    pub consent_id: ConsentId,
    pub decision: MimiConsentDecision,
    pub actor_id: ActorId,
    pub consent_event: EventCommitSubmission,
    pub signature: PayloadProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<AuditReasonText>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_wire::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

impl MimiUpdateConsentRequestBody {
    /// The carried Event must be the decision's own kind, authored by the same
    /// Actor the request is signed as, and already name this correlation.
    pub fn validate_consent_event(&self) -> Result<()> {
        let event = &self.consent_event.event;
        let expected_kind = self.decision.required_consent_event_kind();
        if event.kind != expected_kind || event.actor_id != self.actor_id {
            return Err(WireError::Protocol(
                "MIMI consent decision, event kind, and actor binding mismatch".to_owned(),
            ));
        }
        if event.payload.get("consent_id").and_then(Value::as_str) != Some(self.consent_id.as_str())
        {
            return Err(WireError::Protocol(
                "MIMI consent event payload.consent_id mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical request value covered by the operation proof. The detached
    /// proof is omitted to avoid a self-referential digest.
    pub fn unsigned_payload(&self) -> Result<Value> {
        mimi_unsigned_body_without_signature(self)
    }

    /// Digest of the complete request with only the detached proof omitted.
    pub fn payload_digest(&self) -> Result<Hash> {
        mimi_payload_digest(&self.unsigned_payload()?)
    }

    /// Canonical `ak.mimi_update_consent_request_proof.v1` transcript shared by
    /// MIMI consent proof producers and verifiers.
    pub fn signature_binding_bytes(&self) -> Result<Vec<u8>> {
        self.signature.validate_production()?;
        self.unsigned_signature_binding_bytes(&self.signature.unsigned())
    }

    /// Bind unsigned proof metadata before finalizing the request signature.
    pub fn unsigned_signature_binding_bytes(
        &self,
        proof: &UnsignedPayloadProof,
    ) -> Result<Vec<u8>> {
        mimi_proof_binding_bytes(
            ProofContextId::MIMI_UPDATE_CONSENT_REQUEST_PROOF_V1,
            ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_CONSENT_V1,
            Some(serde_json::to_value(&self.actor_id)?),
            vec![
                ("consent_id", serde_json::to_value(&self.consent_id)?),
                ("decision", serde_json::to_value(self.decision)?),
            ],
            &self.payload_digest()?,
            proof,
        )
    }
}

/// Canonical unsigned MIMI body for the array-carrier families: the top-level
/// `proofs` member is removed outright — never set to `null` — and every
/// optional field that is actually present is retained
/// (`extensions/mimi-interop.md` section 5.1).
fn mimi_unsigned_body_without_proofs<T: Serialize>(body: &T) -> Result<Value> {
    Ok(canonical::unsigned_value(body, &["proofs"])?)
}

/// Same rule for the families whose detached proof is carried by a single
/// top-level `signature` member.
fn mimi_unsigned_body_without_signature<T: Serialize>(body: &T) -> Result<Value> {
    Ok(canonical::unsigned_value(body, &["signature"])?)
}

fn mimi_payload_digest(unsigned_body: &Value) -> Result<Hash> {
    Hash::new(canonical::canonical_sha256(unsigned_body)?).map_err(Into::into)
}

/// Canonical MIMI actor-proof transcript
/// (`extensions/mimi-interop.md` section 5.1).
///
/// `context` is the object family's own registered context, so a signature
/// valid under one family can never be replayed into another and a
/// request/outcome direction swap is blocked by the context alone. `targets`
/// carries the family's verbatim target identifiers in
/// `proof-context-registry.json` `binding_fields` order; `issuer` is present
/// iff the family's wire shape defines an originator field.
fn mimi_proof_binding_bytes(
    context: &str,
    operation_id: &str,
    issuer: Option<Value>,
    targets: Vec<(&'static str, Value)>,
    payload_digest: &Hash,
    proof: &UnsignedPayloadProof,
) -> Result<Vec<u8>> {
    arkret_wire::service_operation_proof_binding_bytes(
        context,
        operation_id,
        issuer,
        targets,
        payload_digest,
        proof,
    )
}

#[cfg(test)]
mod tests {
    use arkret_wire::{
        Audience, DidCoreId, DidUrl, EventId, RealmId, ScopeRef, proof_kind, test_support,
    };
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn alice() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn bob() -> DidCoreId {
        DidCoreId::new("ak:did_core:webvh:z6mkfixture:bob.example").unwrap()
    }

    fn station() -> DidCoreId {
        DidCoreId::new("ak:did_core:web:station.example").unwrap()
    }

    fn consent_id() -> ConsentId {
        ConsentId::new("ak:consent:0198ff00-0000-7000-8000-000000000001").unwrap()
    }

    fn holder_actor_id() -> ActorId {
        ActorId::account(AccountId::new(bob(), station()))
    }

    fn fixture_proof() -> PayloadProof {
        PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method: DidUrl::new("did:web:alice.example#device-1").unwrap(),
            payload_digest: Hash::new(format!("sha256:{}", "ab".repeat(32))).unwrap(),
            created_at: Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
            domain: Some("ak:trust_domain:station.example".to_owned()),
            audience: Some(Audience::Single(
                "ak:did_core:web:station.example".to_owned(),
            )),
            proof_purpose: None,
            jws: "eyJhbGciOiJFZERTQSJ9..c2ln".to_owned(),
        }
    }

    fn consent_event(kind: EventKind, payload: Value) -> EventCommitSubmission {
        let realm_id = RealmId::from_event_id(&EventId::from_digest(
            arkret_canonical::DigestSuite::Sha256,
            [0x21; 32],
        ));
        EventCommitSubmission {
            event: test_support::raw_event_for_actor_at(
                kind.as_str(),
                ScopeRef::Realm { realm_id },
                holder_actor_id(),
                payload,
                Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
            )
            .unwrap(),
        }
    }

    fn request_consent_value() -> Value {
        json!({
            "requester_actor_id": {
                "kind": "account",
                "account_id": {
                    "principal_id": alice(),
                    "station_id": station()
                }
            },
            "holder_account_id": {
                "principal_id": bob(),
                "station_id": station()
            },
            "purpose": "voice_call",
            "expires_at": "2026-09-08T00:00:00.000Z",
            "proofs": [fixture_proof()]
        })
    }

    fn update_consent_value(decision: &str, kind: EventKind) -> Value {
        json!({
            "consent_id": consent_id(),
            "decision": decision,
            "actor_id": holder_actor_id(),
            "consent_event": consent_event(kind, json!({"consent_id": consent_id()})),
            "signature": fixture_proof()
        })
    }

    #[test]
    fn request_consent_body_round_trips_and_is_closed() {
        let value = request_consent_value();
        let parsed: MimiRequestConsentRequestBody =
            serde_json::from_value(value.clone()).expect("closed request body");
        parsed.validate().expect("one requester proof is present");
        assert_eq!(parsed.purpose, MimiConsentPurpose::VoiceCall);
        assert!(parsed.strand_id.is_none());
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("policy_revision".to_owned(), json!(7));
        assert!(serde_json::from_value::<MimiRequestConsentRequestBody>(unknown).is_err());

        for required in [
            "requester_actor_id",
            "holder_account_id",
            "purpose",
            "proofs",
        ] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(required);
            assert!(
                serde_json::from_value::<MimiRequestConsentRequestBody>(missing).is_err(),
                "{required} must not become optional"
            );
        }
    }

    #[test]
    fn request_consent_transcript_binds_the_holder_and_purpose() {
        let body: MimiRequestConsentRequestBody =
            serde_json::from_value(request_consent_value()).unwrap();
        let mut unsigned = body.clone();
        unsigned.proofs = Vec::new();
        let mut proof = fixture_proof();
        proof.payload_digest = unsigned.payload_digest().unwrap();

        let bytes = unsigned
            .unsigned_proof_binding_bytes(&proof.unsigned())
            .expect("canonical transcript");
        let transcript: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            transcript["context"],
            json!(ProofContextId::MIMI_REQUEST_CONSENT_REQUEST_PROOF_V1)
        );
        assert_eq!(
            transcript["operation_id"],
            json!(ServiceOperationId::OPEN_MIMI_COMMAND_REQUEST_CONSENT_V1)
        );
        assert_eq!(transcript["purpose"], json!("voice_call"));
        assert_eq!(
            transcript["issuer"],
            serde_json::to_value(&unsigned.requester_actor_id).unwrap()
        );

        // The unsigned digest covers `holder_account_id`, so a swapped holder
        // cannot reuse a proof frozen on the original correlation.
        let mut swapped = unsigned;
        swapped.holder_account_id.principal_id =
            DidCoreId::new("ak:did_core:webvh:z6mkfixture:mallory.example").unwrap();
        assert!(
            swapped
                .unsigned_proof_binding_bytes(&proof.unsigned())
                .is_err()
        );
    }

    #[test]
    fn update_consent_body_round_trips_and_is_closed() {
        let value = update_consent_value("accept", EventKind::ConsentGrant);
        let parsed: MimiUpdateConsentRequestBody =
            serde_json::from_value(value.clone()).expect("closed request body");
        parsed
            .validate_consent_event()
            .expect("a grant Event matches decision=accept");
        assert_eq!(parsed.decision, MimiConsentDecision::Accept);
        assert!(parsed.reason.is_none());
        assert_eq!(serde_json::to_value(&parsed).unwrap(), value);

        let mut unknown = value.clone();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("policy_revision".to_owned(), json!(7));
        assert!(serde_json::from_value::<MimiUpdateConsentRequestBody>(unknown).is_err());

        for required in [
            "consent_id",
            "decision",
            "actor_id",
            "consent_event",
            "signature",
        ] {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(required);
            assert!(
                serde_json::from_value::<MimiUpdateConsentRequestBody>(missing).is_err(),
                "{required} must not become optional"
            );
        }
    }

    #[test]
    fn update_consent_rejects_an_event_that_contradicts_the_decision() {
        assert_eq!(
            MimiConsentDecision::Deny.required_consent_event_kind(),
            EventKind::ConsentRevoke
        );
        assert_eq!(
            MimiConsentDecision::Revoke.required_consent_event_kind(),
            EventKind::ConsentRevoke
        );

        let wrong_kind: MimiUpdateConsentRequestBody =
            serde_json::from_value(update_consent_value("deny", EventKind::ConsentGrant)).unwrap();
        assert!(wrong_kind.validate_consent_event().is_err());

        let mut wrong_correlation: MimiUpdateConsentRequestBody =
            serde_json::from_value(update_consent_value("revoke", EventKind::ConsentRevoke))
                .unwrap();
        wrong_correlation.consent_id =
            ConsentId::new("ak:consent:0198ff00-0000-7000-8000-000000000002").unwrap();
        assert!(wrong_correlation.validate_consent_event().is_err());
    }

    #[test]
    fn update_consent_transcript_binds_the_correlation_and_decision() {
        let body: MimiUpdateConsentRequestBody =
            serde_json::from_value(update_consent_value("accept", EventKind::ConsentGrant))
                .unwrap();
        let mut proof = fixture_proof();
        proof.payload_digest = body.payload_digest().unwrap();

        let bytes = body
            .unsigned_signature_binding_bytes(&proof.unsigned())
            .expect("canonical transcript");
        let transcript: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            transcript["context"],
            json!(ProofContextId::MIMI_UPDATE_CONSENT_REQUEST_PROOF_V1)
        );
        assert_eq!(
            transcript["operation_id"],
            json!(ServiceOperationId::OPEN_MIMI_COMMAND_UPDATE_CONSENT_V1)
        );
        assert_eq!(transcript["consent_id"], json!(body.consent_id));
        assert_eq!(transcript["decision"], json!("accept"));

        // The carried proof's digest is part of the transcript contract: a
        // digest that no longer matches the unsigned body is refused rather
        // than silently re-derived.
        let mut stale = proof;
        stale.payload_digest = Hash::new(format!("sha256:{}", "cd".repeat(32))).unwrap();
        assert!(
            body.unsigned_signature_binding_bytes(&stale.unsigned())
                .is_err()
        );
    }
}

/// Counterpart for
/// `mimi-operations.schema.json#/$defs/mimi_submit_message_request_body`.
///
/// Operation `ak.open.mimi.command.submit_message.v1`. The facade never sees
/// plaintext: the Arkret side supplies one already-encrypted MIMI ciphertext
/// plus the exact sender coordinates, and `associated_data` carries only the
/// opaque AAD descriptor.
// Field declaration order is byte-for-byte the properties order of
// mimi-operations.schema.json#/$defs/mimi_submit_message_request_body.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiSubmitMessageRequestBody {
    pub sender_actor_id: ActorId,
    pub device_id: DeviceId,
    pub ciphertext: MimiCiphertext,
    /// Foreign MLS group identifier. It belongs to the MIMI provider's name
    /// space, so the schema's `non_typed_identifier_floor` forbids the `ak:`
    /// prefix outright rather than trying to bound it by length.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub associated_data: Option<MimiOpaquePayload>,
}

impl MimiSubmitMessageRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self
            .mls_group_id
            .as_ref()
            .is_some_and(|value| value.as_str().starts_with("ak:"))
        {
            return Err(WireError::Protocol(
                "MIMI mls_group_id must not use the ak: typed identifier namespace".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Counterpart for
/// `mimi-operations.schema.json#/$defs/mimi_submit_message_outcome`.
///
/// `event_ref` is present only when the submission also produced an Arkret
/// Event; a pure outbound relay reports delivery without one.
// Field declaration order is byte-for-byte the properties order of
// mimi-operations.schema.json#/$defs/mimi_submit_message_outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiSubmitMessageOutcome {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_ref: Option<EventId>,
    pub delivery: MimiDelivery,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rejections: Vec<MimiFailure>,
}

impl MimiSubmitMessageOutcome {
    /// `accepted` and `rejected` are total statements about the same fan-out,
    /// so neither can be reported together with evidence of the other.
    pub fn validate(&self) -> Result<()> {
        match self.delivery.status {
            MimiDeliveryStatus::Accepted if !self.rejections.is_empty() => Err(
                WireError::Protocol("accepted MIMI delivery carries no rejections".to_owned()),
            ),
            MimiDeliveryStatus::Rejected if !self.delivery.delivered_to_ids.is_empty() => {
                Err(WireError::Protocol(
                    "rejected MIMI delivery carries no delivered_to_ids".to_owned(),
                ))
            }
            _ => Ok(()),
        }
    }
}

/// Counterpart for
/// `mimi-operations.schema.json#/$defs/mimi_identifier_query_outcome`.
///
/// The outcome is a proof-carrying object: its registered proof context is
/// `ak.mimi_identifier_query_outcome_proof.v1`, and the signed transcript is
/// the canonical body with `proofs` removed.
// Field declaration order is byte-for-byte the properties order of
// mimi-operations.schema.json#/$defs/mimi_identifier_query_outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiIdentifierQueryOutcome {
    #[serde(default)]
    pub matches: Vec<MimiIdentifierMatch>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<PayloadProof>,
    pub has_more: bool,
}

impl MimiIdentifierQueryOutcome {
    pub fn unsigned_payload(&self) -> Result<Value> {
        mimi_unsigned_body_without_proofs(self)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        mimi_payload_digest(&self.unsigned_payload()?)
    }

    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        proof.validate_production()?;
        self.unsigned_proof_binding_bytes(&proof.unsigned())
    }

    /// Construct the signing preimage before a signature exists.
    pub fn unsigned_proof_binding_bytes(&self, proof: &UnsignedPayloadProof) -> Result<Vec<u8>> {
        mimi_proof_binding_bytes(
            ProofContextId::MIMI_IDENTIFIER_QUERY_OUTCOME_PROOF_V1,
            ServiceOperationId::OPEN_MIMI_READ_IDENTIFIERS_V1,
            None,
            Vec::new(),
            &self.payload_digest()?,
            proof,
        )
    }
}

/// Counterpart for
/// `mimi-operations.schema.json#/$defs/mimi_proxy_download_outcome`.
///
/// Operation `ak.open.mimi.command.proxy_download.v1`. `download_ref` is the
/// provider's own opaque handle; the SDK never interprets it as a URL or as a
/// typed Arkret identifier.
// Field declaration order is byte-for-byte the properties order of
// mimi-operations.schema.json#/$defs/mimi_proxy_download_outcome.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct MimiProxyDownloadOutcome {
    pub download_ref: NonEmptyString,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, NonEmptyString>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod mimi_relay_tests {
    use arkret_wire::{AccountId, DidCoreId, DidUrl, proof_kind};
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    const EVENT: &str = "ak:event:Aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DEVICE: &str = "ak:device:0198ff00-0000-7000-8000-000000000001";
    const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn sender() -> Value {
        json!({
            "kind": "account",
            "account_id": {
                "principal_id": "ak:did_core:webvh:z6mksender",
                "station_id": "ak:did_core:web:station.example"
            }
        })
    }

    fn submit_body_value() -> Value {
        json!({
            "sender_actor_id": sender(),
            "device_id": DEVICE,
            "ciphertext": {
                "content_type": "application/mls",
                "ciphertext_digest": DIGEST,
                "payload": "Y2lwaGVydGV4dA"
            },
            "mls_group_id": "mimi-group-1",
            "epoch": 7,
            "associated_data": {
                "content_type": "application/octet-stream",
                "payload_digest": DIGEST
            }
        })
    }

    fn submit_outcome_value() -> Value {
        json!({
            "event_ref": EVENT,
            "delivery": {
                "status": "partial",
                "delivered_to_ids": ["ak:did_core:web:provider.example"]
            },
            "rejections": [{
                "reason_code": "consent_missing",
                "target_ref": "ak:did_core:web:other.example",
                "retry_after_ms": 500
            }]
        })
    }

    #[test]
    fn submit_request_round_trips_in_schema_property_order() {
        let body: MimiSubmitMessageRequestBody =
            serde_json::from_value(submit_body_value()).unwrap();
        assert_eq!(body.device_id.as_str(), DEVICE);
        assert_eq!(body.epoch, Some(7));
        body.validate().unwrap();
        assert_eq!(serde_json::to_value(&body).unwrap(), submit_body_value());
    }

    #[test]
    fn only_sender_device_and_ciphertext_are_required() {
        for member in ["sender_actor_id", "device_id", "ciphertext"] {
            let mut missing = submit_body_value();
            missing.as_object_mut().unwrap().remove(member);
            assert!(
                serde_json::from_value::<MimiSubmitMessageRequestBody>(missing).is_err(),
                "{member} must be required"
            );
        }
        let mut minimal = submit_body_value();
        let object = minimal.as_object_mut().unwrap();
        for member in ["mls_group_id", "epoch", "associated_data"] {
            object.remove(member);
        }
        let body: MimiSubmitMessageRequestBody = serde_json::from_value(minimal.clone()).unwrap();
        body.validate().unwrap();
        assert_eq!(serde_json::to_value(&body).unwrap(), minimal);
    }

    #[test]
    fn a_foreign_group_id_never_borrows_the_ak_namespace() {
        let mut typed = submit_body_value();
        typed
            .as_object_mut()
            .unwrap()
            .insert("mls_group_id".to_owned(), json!("ak:realm:borrowed"));
        let body: MimiSubmitMessageRequestBody = serde_json::from_value(typed).unwrap();
        assert!(body.validate().is_err());
    }

    #[test]
    fn submit_request_rejects_unknown_members() {
        let mut extended = submit_body_value();
        extended
            .as_object_mut()
            .unwrap()
            .insert("plaintext".to_owned(), json!("hello"));
        assert!(serde_json::from_value::<MimiSubmitMessageRequestBody>(extended).is_err());
    }

    #[test]
    fn submit_outcome_round_trips_in_schema_property_order() {
        let outcome: MimiSubmitMessageOutcome =
            serde_json::from_value(submit_outcome_value()).unwrap();
        assert_eq!(outcome.delivery.status, MimiDeliveryStatus::Partial);
        assert_eq!(outcome.rejections.len(), 1);
        outcome.validate().unwrap();
        assert_eq!(
            serde_json::to_value(&outcome).unwrap(),
            submit_outcome_value()
        );
    }

    #[test]
    fn delivery_is_the_only_required_outcome_member() {
        let mut missing = submit_outcome_value();
        missing.as_object_mut().unwrap().remove("delivery");
        assert!(serde_json::from_value::<MimiSubmitMessageOutcome>(missing).is_err());

        let relayed_only = json!({ "delivery": { "status": "accepted" } });
        let outcome: MimiSubmitMessageOutcome =
            serde_json::from_value(relayed_only.clone()).unwrap();
        outcome.validate().unwrap();
        assert!(outcome.event_ref.is_none());
        assert_eq!(serde_json::to_value(&outcome).unwrap(), relayed_only);
    }

    #[test]
    fn accepted_and_rejected_never_carry_the_other_branch_evidence() {
        let mut accepted = submit_outcome_value();
        accepted["delivery"]
            .as_object_mut()
            .unwrap()
            .insert("status".to_owned(), json!("accepted"));
        let outcome: MimiSubmitMessageOutcome = serde_json::from_value(accepted).unwrap();
        assert!(outcome.validate().is_err());

        let mut rejected = submit_outcome_value();
        rejected["delivery"]
            .as_object_mut()
            .unwrap()
            .insert("status".to_owned(), json!("rejected"));
        let outcome: MimiSubmitMessageOutcome = serde_json::from_value(rejected).unwrap();
        assert!(outcome.validate().is_err());
    }

    fn identifier_outcome_value() -> Value {
        json!({
            "matches": [{
                "identifier_commitment": DIGEST,
                "matched": true,
                "mimi_uri": "mimi://provider.example",
                "subject_id": "ak:did_core:web:provider.example"
            }],
            "has_more": false
        })
    }

    #[test]
    fn identifier_outcome_round_trips_and_binds_its_own_proof_context() {
        let outcome: MimiIdentifierQueryOutcome =
            serde_json::from_value(identifier_outcome_value()).unwrap();
        assert_eq!(outcome.matches.len(), 1);
        assert!(!outcome.has_more);
        assert_eq!(
            serde_json::to_value(&outcome).unwrap(),
            identifier_outcome_value()
        );

        let proof = PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method: DidUrl::new("did:web:provider.example#key-1").unwrap(),
            payload_digest: outcome.payload_digest().unwrap(),
            created_at: Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
            domain: Some(ProofContextId::MIMI_IDENTIFIER_QUERY_OUTCOME_PROOF_V1.to_owned()),
            audience: Some(arkret_wire::Audience::Single(
                "ak:did_core:web:station.example".to_owned(),
            )),
            proof_purpose: None,
            jws: "eyJhbGciOiJFZERTQSJ9..c2ln".to_owned(),
        };
        let bytes = outcome.proof_binding_bytes(&proof).unwrap();
        let transcript = String::from_utf8(bytes).unwrap();
        assert!(transcript.contains(ProofContextId::MIMI_IDENTIFIER_QUERY_OUTCOME_PROOF_V1));
        assert!(transcript.contains(ServiceOperationId::OPEN_MIMI_READ_IDENTIFIERS_V1));
    }

    #[test]
    fn the_identifier_outcome_transcript_excludes_its_own_proofs() {
        let mut outcome: MimiIdentifierQueryOutcome =
            serde_json::from_value(identifier_outcome_value()).unwrap();
        let without_proofs = outcome.payload_digest().unwrap();
        outcome.proofs.push(PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method: DidUrl::new("did:web:provider.example#key-1").unwrap(),
            payload_digest: without_proofs.clone(),
            created_at: Utc.timestamp_opt(1_800_000_000, 0).unwrap(),
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "eyJhbGciOiJFZERTQSJ9..c2ln".to_owned(),
        });
        assert_eq!(outcome.payload_digest().unwrap(), without_proofs);
        assert!(
            !outcome.unsigned_payload().unwrap()["matches"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn identifier_outcome_requires_has_more() {
        let mut missing = identifier_outcome_value();
        missing.as_object_mut().unwrap().remove("has_more");
        assert!(serde_json::from_value::<MimiIdentifierQueryOutcome>(missing).is_err());
    }

    fn proxy_outcome_value() -> Value {
        json!({
            "download_ref": "provider-download-1",
            "headers": { "content-type": "application/octet-stream" },
            "expires_at": "2026-09-16T00:05:00.000Z"
        })
    }

    #[test]
    fn proxy_download_outcome_round_trips_in_schema_property_order() {
        let outcome: MimiProxyDownloadOutcome =
            serde_json::from_value(proxy_outcome_value()).unwrap();
        assert_eq!(outcome.download_ref.as_str(), "provider-download-1");
        assert_eq!(outcome.headers.len(), 1);
        assert!(outcome.expires_at.is_some());
        assert_eq!(
            serde_json::to_value(&outcome).unwrap(),
            proxy_outcome_value()
        );
    }

    #[test]
    fn download_ref_is_the_only_required_proxy_member() {
        let mut missing = proxy_outcome_value();
        missing.as_object_mut().unwrap().remove("download_ref");
        assert!(serde_json::from_value::<MimiProxyDownloadOutcome>(missing).is_err());

        let minimal = json!({ "download_ref": "provider-download-1" });
        let outcome: MimiProxyDownloadOutcome = serde_json::from_value(minimal.clone()).unwrap();
        assert_eq!(serde_json::to_value(&outcome).unwrap(), minimal);

        let mut empty_ref = proxy_outcome_value();
        empty_ref
            .as_object_mut()
            .unwrap()
            .insert("download_ref".to_owned(), json!(""));
        assert!(serde_json::from_value::<MimiProxyDownloadOutcome>(empty_ref).is_err());
    }

    #[test]
    fn proxy_download_header_values_are_non_empty_and_timestamps_canonical() {
        let mut empty_header = proxy_outcome_value();
        empty_header["headers"]
            .as_object_mut()
            .unwrap()
            .insert("content-type".to_owned(), json!(""));
        assert!(serde_json::from_value::<MimiProxyDownloadOutcome>(empty_header).is_err());

        let mut loose = proxy_outcome_value();
        loose
            .as_object_mut()
            .unwrap()
            .insert("expires_at".to_owned(), json!("2026-09-16T00:05:00Z"));
        assert!(serde_json::from_value::<MimiProxyDownloadOutcome>(loose).is_err());
    }

    #[test]
    fn a_sender_actor_id_is_a_complete_actor_identity() {
        let body: MimiSubmitMessageRequestBody =
            serde_json::from_value(submit_body_value()).unwrap();
        assert_eq!(
            body.sender_actor_id.as_account_id(),
            Some(&AccountId::new(
                DidCoreId::new("ak:did_core:webvh:z6mksender").unwrap(),
                DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            ))
        );
    }
}
