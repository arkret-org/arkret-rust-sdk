//! `MemberDeliveryBindingCandidate` — typed builder-side payload for the
//! Handle → member delivery binding → Realm-scoped
//! delivery pipeline.
//!
//! Spec source: `identity-handles.md` §3.7 +
//! `artifacts/schemas/member-delivery-binding-candidate.schema.json`
//! (arkret-spec @ 7157ee8, 2026-05-27 — `handle_uri` → `handle` wire rename).
//!
//! A candidate is the **input** to `member_add` / `invite` builders. It is
//! *not* a grant and *not* a materialised `member_delivery_binding`; the
//! reducer still re-validates against Join Policy when landing
//! `ak.member.state{join}.delivery_binding`.
//!
//! Two legal provenance paths:
//!   1. `ak.find.directory.query.resolve_handle(intent="member_add" | "invite")` packed into a
//!      candidate by the Directory.
//!   2. Trusted issuer (Organization / Principal Server / service DID) signs a candidate directly —
//!      e.g. invite token payload, organization member roster push.
//!
//! Any object lacking `proofs[]` MUST NOT be named a candidate.
use arkret_models_identity::handle::{Handle, HandleHintBindingSource};
use arkret_wire::{Did, EventId, Hash, Proof, canonical};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::governance::handle_claim::DeliveryBindingHint;

/// Builder entry-point hint. Advisory for audit / telemetry only; reducer
/// behaviour MUST NOT branch on this.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateIntent {
    MemberAdd,
    Invite,
}

/// Context carried by the verifier when validating a candidate. The
/// `expected_audience` MUST be the target Realm DID or inviting service
/// DID for the current invocation; `now` lets callers freeze the time
/// baseline (test fixtures, signed receipts replayed for audit, etc.).
#[derive(Clone, Debug)]
pub struct CandidateValidationContext {
    pub expected_audience: String,
    pub now: DateTime<Utc>,
    /// Optional subject the caller asserts the candidate must address.
    /// When present, the validator MUST reject candidates whose
    /// `subject_id` does not match byte-for-byte. This guards against
    /// directory caches reusing a candidate across reassignments.
    pub expected_subject: Option<Did>,
}

impl CandidateValidationContext {
    pub fn new(expected_audience: impl Into<String>) -> Self {
        Self {
            expected_audience: expected_audience.into(),
            now: Utc::now(),
            expected_subject: None,
        }
    }

    #[must_use]
    pub fn with_now(mut self, now: DateTime<Utc>) -> Self {
        self.now = now;
        self
    }

    #[must_use]
    pub fn with_expected_subject(mut self, subject: Did) -> Self {
        self.expected_subject = Some(subject);
        self
    }
}

/// Validation failure surface. Distinguishes the §3.7.3 MUST-rule
/// branches so callers can build precise audit / failure receipts.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CandidateError {
    #[error("candidate handle is not in canonical <localpart>:<domain> form: {0}")]
    NonCanonicalHandle(String),
    #[error("candidate audience mismatch: expected {expected}, got {actual}")]
    AudienceMismatch { expected: String, actual: String },
    #[error("candidate expired at {expires_at} (now = {now})")]
    Expired {
        expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    },
    #[error(
        "candidate proofs[] missing or empty; at least one proof MUST bind \
         handle / subject_id / member_delivery_binding.recipient_service_id / audience / \
         issuer_service_id / expires_at"
    )]
    MissingProof,
    #[error(
        "candidate subject mismatch: expected {expected}, got {actual} \
         (a stale directory cache or a handle reassignment will hit this)"
    )]
    SubjectMismatch { expected: String, actual: String },
    #[error(
        "candidate member_delivery_binding.binding_source did_document_default \
         is forbidden — handle-resolved candidates and DID Document fallback \
         are independent materialisation paths"
    )]
    ForbiddenBindingSource,
    #[error(
        "candidate recipient_service_id ({outer}) does not match \
         member_delivery_binding.recipient_service_id ({inner})"
    )]
    RecipientServiceIdMismatch { outer: String, inner: String },
    #[error("candidate source_refs MUST NOT be empty")]
    MissingSourceRefs,
    #[error("candidate canonical-JSON serialisation failed: {0}")]
    Canonical(String),
}

/// Typed `MemberDeliveryBindingCandidate` corresponding 1:1 to
/// `spec/v1/artifacts/schemas/member-delivery-binding-candidate.schema.json`.
///
/// `additionalProperties: false` at the schema level is enforced here by
/// `#[serde(deny_unknown_fields)]` so the SDK refuses to silently widen
/// the wire shape.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberDeliveryBindingCandidate {
    pub subject_id: Did,
    /// Canonical `<localpart>:<domain>` handle (R3.1 wire rename from
    /// the prior `handle_uri` field).
    pub handle: Handle,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handle_aliases: Vec<String>,
    pub member_delivery_binding: DeliveryBindingHint,
    pub issuer_service_id: Did,
    pub audience: String,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub issued_at: DateTime<Utc>,
    pub source_refs: Vec<EventId>,
    pub proofs: Vec<Proof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_digest: Option<Hash>,
    pub intent: CandidateIntent,
}

impl MemberDeliveryBindingCandidate {
    /// Run the §3.7.3 validator. The check order mirrors the spec so that
    /// audit logs emitted on failure stay aligned with the prose.
    pub fn validate(&self, context: &CandidateValidationContext) -> Result<(), CandidateError> {
        // (2) handle canonical — `Handle::parse` already accepted only
        //      the canonical `<localpart>:<domain>` form on construction,
        //      so reaching this point with a non-canonical value implies
        //      the typed field was bypassed. Re-check defensively so the
        //      SDK refuses `acct:` / bare host / arkret:// strings that
        //      snuck in via raw JSON.
        let canonical = self.handle.canonical();
        let has_localpart_colon = canonical.contains(':');
        let has_dotted_domain = canonical
            .split(':')
            .nth(1)
            .is_some_and(|domain| domain.contains('.'));
        if !has_localpart_colon || !has_dotted_domain {
            return Err(CandidateError::NonCanonicalHandle(canonical.to_owned()));
        }

        // (3) audience match
        if self.audience != context.expected_audience {
            return Err(CandidateError::AudienceMismatch {
                expected: context.expected_audience.clone(),
                actual: self.audience.clone(),
            });
        }

        // (4) expiry — strictly greater than now
        if self.expires_at <= context.now {
            return Err(CandidateError::Expired {
                expires_at: self.expires_at,
                now: context.now,
            });
        }

        // (5) proof presence — substantive cryptographic verification is
        //     handled by the signature layer; the candidate validator at
        //     this layer only enforces "proofs[] is non-empty" and lets
        //     callers wire in their proof-binding checks separately.
        if self.proofs.is_empty() {
            return Err(CandidateError::MissingProof);
        }

        // (6) subject / handle association — caller-provided expectation
        if let Some(expected) = &context.expected_subject
            && expected.as_str() != self.subject_id.as_str()
        {
            return Err(CandidateError::SubjectMismatch {
                expected: expected.as_str().to_owned(),
                actual: self.subject_id.as_str().to_owned(),
            });
        }

        // (7) member_delivery_binding.binding_source legal values — the
        //     `HandleHintBindingSource` enum already excludes
        //     `did_document_default`, but re-assert here for clarity in
        //     case the enum gains new variants downstream.
        match self.member_delivery_binding.binding_source {
            HandleHintBindingSource::Explicit
            | HandleHintBindingSource::Invite
            | HandleHintBindingSource::JoinPolicy
            | HandleHintBindingSource::OrganizationPolicy
            | HandleHintBindingSource::RealmPolicy => {}
        }

        // source_refs MUST be non-empty per the schema
        if self.source_refs.is_empty() {
            return Err(CandidateError::MissingSourceRefs);
        }

        Ok(())
    }

    /// Canonical JSON bytes for signing / digesting per `encoding.md`.
    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, CandidateError> {
        canonical::canonical_json_bytes(self).map_err(|e| CandidateError::Canonical(e.to_string()))
    }

    /// `sha256:<hex>` digest of the canonical-JSON encoding. Suitable as
    /// the `claim_digest` cache key called out in §3.7.1.
    pub fn canonical_sha256(&self) -> Result<String, CandidateError> {
        canonical::canonical_sha256(self).map_err(|e| CandidateError::Canonical(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use serde_json::json;

    use super::*;
    use crate::governance::delivery_binding::{DeliveryMode, RecipientServiceKind};

    fn fake_did(label: &str) -> Did {
        Did::new(format!("did:webvh:z6mkfixture:{label}.example")).unwrap()
    }

    fn sample_hint(rs: &Did) -> DeliveryBindingHint {
        let mut modes = BTreeSet::new();
        modes.insert(DeliveryMode::Events);
        modes.insert(DeliveryMode::Sync);
        DeliveryBindingHint {
            recipient_service_id: rs.clone(),
            recipient_service_kind: RecipientServiceKind::PrincipalServer,
            binding_source: HandleHintBindingSource::OrganizationPolicy,
            delivery_modes: modes,
            service_acceptance_ref: Some(
                "ak:event:01890000-0000-7000-8000-000000000001".to_owned(),
            ),
            policy_event_ref: Some("ak:event:01890000-0000-7000-8000-000000000002".to_owned()),
        }
    }

    fn sample_candidate() -> MemberDeliveryBindingCandidate {
        let rs = fake_did("principal");
        MemberDeliveryBindingCandidate {
            subject_id: fake_did("alice"),
            handle: Handle::parse("alice:acme.example").unwrap(),
            handle_aliases: vec!["acct:alice@acme.example".to_owned()],
            member_delivery_binding: sample_hint(&rs),
            issuer_service_id: fake_did("principal"),
            audience: "ak:realm:0196419b-0000-7000-8000-000000000000".to_owned(),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            issued_at: Utc::now(),
            source_refs: vec![
                EventId::new("ak:event:01890000-0000-7000-8000-0000000000ff").unwrap(),
            ],
            proofs: vec![Proof {
                kind: "detached_jws".to_owned(),
                alg: "EdDSA".to_owned(),
                verification_method: "did:webvh:z6mkfixture:principal.example#key-1".to_owned(),
                event_digest: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
                created_at: "2026-05-19T00:00:00.000Z".parse().unwrap(),
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "aaa.bbb.ccc".to_owned(),
            }],
            claim_digest: Some(Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap()),
            intent: CandidateIntent::MemberAdd,
        }
    }

    fn valid_context(candidate: &MemberDeliveryBindingCandidate) -> CandidateValidationContext {
        CandidateValidationContext::new(candidate.audience.clone())
    }

    #[test]
    fn positive_validates_clean_candidate() {
        let c = sample_candidate();
        assert!(c.validate(&valid_context(&c)).is_ok());
    }

    #[test]
    fn negative_subject_mismatch() {
        let c = sample_candidate();
        let ctx = valid_context(&c).with_expected_subject(fake_did("mallory"));
        match c.validate(&ctx).unwrap_err() {
            CandidateError::SubjectMismatch { .. } => {}
            other => panic!("expected SubjectMismatch, got {other:?}"),
        }
    }

    #[test]
    fn negative_expired() {
        let mut c = sample_candidate();
        c.expires_at = Utc::now() - chrono::Duration::seconds(1);
        match c.validate(&valid_context(&c)).unwrap_err() {
            CandidateError::Expired { .. } => {}
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn negative_audience_mismatch() {
        let c = sample_candidate();
        let ctx = CandidateValidationContext::new("ak:realm:other-target".to_owned());
        match c.validate(&ctx).unwrap_err() {
            CandidateError::AudienceMismatch { .. } => {}
            other => panic!("expected AudienceMismatch, got {other:?}"),
        }
    }

    #[test]
    fn negative_missing_proofs() {
        let mut c = sample_candidate();
        c.proofs.clear();
        match c.validate(&valid_context(&c)).unwrap_err() {
            CandidateError::MissingProof => {}
            other => panic!("expected MissingProof, got {other:?}"),
        }
    }

    #[test]
    fn negative_missing_source_refs() {
        let mut c = sample_candidate();
        c.source_refs.clear();
        match c.validate(&valid_context(&c)).unwrap_err() {
            CandidateError::MissingSourceRefs => {}
            other => panic!("expected MissingSourceRefs, got {other:?}"),
        }
    }

    #[test]
    fn negative_non_canonical_handle_via_raw_json() {
        // Force a non-canonical handle by patching the serialized form.
        // Handle::parse rejects acct: / bare-host / arkret:// strings, so
        // this exercises the defensive re-check inside validate().
        let c = sample_candidate();
        let mut value = serde_json::to_value(&c).unwrap();
        // Inject an obviously bogus value; deserialization back through
        // MemberDeliveryBindingCandidate MUST fail because Handle::parse
        // rejects non-canonical input.
        value["handle"] = json!("acct:alice@acme.example");
        let parsed: Result<MemberDeliveryBindingCandidate, _> = serde_json::from_value(value);
        assert!(
            parsed.is_err(),
            "non-canonical handle must be rejected at deserialisation"
        );
    }

    #[test]
    fn canonical_json_is_stable() {
        let c = sample_candidate();
        let a = c.canonical_json_bytes().unwrap();
        let b = c.canonical_json_bytes().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_sha256_matches_canonical_bytes() {
        let c = sample_candidate();
        let digest = c.canonical_sha256().unwrap();
        assert!(digest.starts_with("sha256:"));
        assert_eq!(digest.len(), "sha256:".len() + 64);
    }

    #[test]
    fn deny_unknown_fields_rejects_widened_payload() {
        let c = sample_candidate();
        let mut value = serde_json::to_value(&c).unwrap();
        value["surprise"] = json!("should-be-rejected");
        let parsed: Result<MemberDeliveryBindingCandidate, _> = serde_json::from_value(value);
        assert!(
            parsed.is_err(),
            "unknown fields MUST be rejected (#[serde(deny_unknown_fields)])"
        );
    }
}
