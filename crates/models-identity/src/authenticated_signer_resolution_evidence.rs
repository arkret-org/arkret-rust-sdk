//! Compact signer-key evidence binding one resolved key to one
//! authority-committed stream revision.
//!
//! The object is the portable half of signer resolution: a consumer that holds
//! it can check which key signed, which subject owns the key, and which
//! `RealmCommit` the binding was resolved against, without replaying a stream
//! or asking the resolving service again. It is content addressed, so the
//! carriers that reference it (`signer_resolution_evidence_ref` on the Agent
//! key state and on the account lifecycle proof) commit to these exact bytes.
//!
//! The Account Authority controller gate family, which answers a different
//! question (is the controller principal still eligible), lives in
//! [`crate::agent_signer_evidence`]; the query-local current-key projection
//! lives in [`crate::agent_signer_state`].

use arkret_canonical::canonical::{canonical_json_bytes, sha256_hex};
use arkret_wire::{
    DidCoreId, DidUrl, ErrorCode, NonEmptyJsonObject, RealmCommitId, Result, SignerEvidenceRef,
    WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Minimum property count a public key JWK must carry to be a usable key.
///
/// A single-member object cannot name both a key type and its key material, so
/// the schema floor is two and a shorter object is a schema violation rather
/// than a partially usable key.
pub const AUTHENTICATED_SIGNER_PUBLIC_KEY_JWK_MIN_PROPERTIES: usize = 2;

/// Which principal class the resolved key belongs to.
///
/// The three classes are distinct authorities, never fallbacks for one another:
/// a service key never stands in for the account key of its hosted principal,
/// and an Agent key never stands in for its controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AuthenticatedSignerKind {
    Principal,
    Service,
    Agent,
}

/// Content-addressed signer resolution evidence.
///
/// `authority_commit_id` is the single revision coordinate: the evidence
/// asserts the binding as of that committed revision and carries no window,
/// no frontier, and no reusable grant. A consumer that needs a later binding
/// resolves again; it never extrapolates this one forward.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
// Field declaration order is byte-for-byte the `properties` order of
// `authenticated-signer-resolution-evidence.schema.json#/$defs/base`; the three
// `oneOf` branches differ only by the `signer_kind` const, which this enum
// field already carries.
pub struct AuthenticatedSignerResolutionEvidence {
    pub signer_kind: AuthenticatedSignerKind,
    pub subject_id: DidCoreId,
    pub verification_method: DidUrl,
    pub public_key_jwk: NonEmptyJsonObject,
    pub authority_commit_id: RealmCommitId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub resolved_at: DateTime<Utc>,
}

impl AuthenticatedSignerResolutionEvidence {
    /// Structural invariants a consumer re-checks before it trusts the key.
    ///
    /// Binding the `verification_method` to `subject_id` is a resolution step,
    /// not a string comparison: the DID URL is resolved through the method
    /// adapter that produced the core id. This type therefore checks only what
    /// is decidable from its own bytes.
    pub fn validate(&self) -> Result<()> {
        if self.public_key_jwk.as_map().len() < AUTHENTICATED_SIGNER_PUBLIC_KEY_JWK_MIN_PROPERTIES {
            return Err(evidence_error(
                "signer resolution evidence public key JWK must carry at least two properties",
            ));
        }
        Ok(())
    }

    /// Content address of this exact evidence object.
    ///
    /// The ref is `SHA-256(RFC8785-JCS(self))` in the registered
    /// `ak:signer_evidence:` form. Every carrier that reports a
    /// `signer_resolution_evidence_ref` alongside the evidence must report the
    /// value this helper returns; a consumer recomputes it here rather than
    /// trusting the reported sibling.
    pub fn signer_evidence_ref(&self) -> Result<SignerEvidenceRef> {
        let bytes = canonical_json_bytes(self).map_err(|error| {
            evidence_error(&format!("evidence is not canonicalizable: {error}"))
        })?;
        SignerEvidenceRef::new(format!("ak:signer_evidence:sha256:{}", sha256_hex(bytes)))
    }

    /// Whether `reported` is the content address of this exact evidence object.
    pub fn matches_ref(&self, reported: &SignerEvidenceRef) -> Result<bool> {
        Ok(&self.signer_evidence_ref()? == reported)
    }
}

/// Assemble one signer-resolution evidence object without signing anything.
///
/// Every input is supplied by the caller, including `resolved_at`: the helper
/// reads no clock, holds no key and consults no service, so the same inputs
/// always produce the same bytes and therefore the same
/// [`SignerEvidenceRef`]. A resolving Station calls it after it has already
/// resolved the key against `authority_commit_id`; the evidence records that
/// resolution, it does not perform one.
///
/// It is deliberately not a trait or a builder: an evidence object with a
/// field left to a default is an evidence object that asserts something its
/// producer never checked.
pub fn build_signer_resolution_evidence(
    signer_kind: AuthenticatedSignerKind,
    subject_id: DidCoreId,
    verification_method: DidUrl,
    public_key_jwk: NonEmptyJsonObject,
    authority_commit_id: RealmCommitId,
    resolved_at: DateTime<Utc>,
) -> Result<AuthenticatedSignerResolutionEvidence> {
    let evidence = AuthenticatedSignerResolutionEvidence {
        signer_kind,
        subject_id,
        verification_method,
        public_key_jwk,
        authority_commit_id,
        resolved_at,
    };
    evidence.validate()?;
    Ok(evidence)
}

/// [`build_signer_resolution_evidence`] for an Agent runtime key.
///
/// An Agent key never stands in for its controller, so the kind is fixed here
/// rather than passed in: a caller that holds an Agent key has no way to spell
/// the principal or service branch by accident.
pub fn build_agent_signer_evidence(
    agent_id: DidCoreId,
    verification_method: DidUrl,
    public_key_jwk: NonEmptyJsonObject,
    authority_commit_id: RealmCommitId,
    resolved_at: DateTime<Utc>,
) -> Result<AuthenticatedSignerResolutionEvidence> {
    build_signer_resolution_evidence(
        AuthenticatedSignerKind::Agent,
        agent_id,
        verification_method,
        public_key_jwk,
        authority_commit_id,
        resolved_at,
    )
}

/// [`build_signer_resolution_evidence`] for an account principal key.
pub fn build_principal_signer_evidence(
    principal_id: DidCoreId,
    verification_method: DidUrl,
    public_key_jwk: NonEmptyJsonObject,
    authority_commit_id: RealmCommitId,
    resolved_at: DateTime<Utc>,
) -> Result<AuthenticatedSignerResolutionEvidence> {
    build_signer_resolution_evidence(
        AuthenticatedSignerKind::Principal,
        principal_id,
        verification_method,
        public_key_jwk,
        authority_commit_id,
        resolved_at,
    )
}

/// [`build_signer_resolution_evidence`] for a Station Service key.
pub fn build_service_signer_evidence(
    service_id: DidCoreId,
    verification_method: DidUrl,
    public_key_jwk: NonEmptyJsonObject,
    authority_commit_id: RealmCommitId,
    resolved_at: DateTime<Utc>,
) -> Result<AuthenticatedSignerResolutionEvidence> {
    build_signer_resolution_evidence(
        AuthenticatedSignerKind::Service,
        service_id,
        verification_method,
        public_key_jwk,
        authority_commit_id,
        resolved_at,
    )
}

fn evidence_error(message: &str) -> WireError {
    WireError::ProtocolCode {
        code: ErrorCode::SchemaViolation,
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence_json() -> serde_json::Value {
        serde_json::json!({
            "signer_kind": "agent",
            "subject_id": "ak:did_core:web:agent.example",
            "verification_method": "did:web:agent.example#runtime-key",
            "public_key_jwk": {
                "crv": "Ed25519",
                "kty": "OKP",
                "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
            },
            "authority_commit_id":
                "ak:realm_commit:ARNRmzDi2r78zveOLmoHOb6AephFMwVuGE1fwXmCoeo4",
            "resolved_at": "2026-09-16T00:00:00.000Z"
        })
    }

    fn evidence() -> AuthenticatedSignerResolutionEvidence {
        serde_json::from_value(evidence_json()).unwrap()
    }

    #[test]
    fn evidence_round_trips_byte_for_byte() {
        let json = evidence_json();
        let evidence: AuthenticatedSignerResolutionEvidence =
            serde_json::from_value(json.clone()).unwrap();
        evidence.validate().unwrap();
        assert_eq!(serde_json::to_value(&evidence).unwrap(), json);
    }

    #[test]
    fn every_signer_kind_decodes() {
        for (kind, expected) in [
            ("principal", AuthenticatedSignerKind::Principal),
            ("service", AuthenticatedSignerKind::Service),
            ("agent", AuthenticatedSignerKind::Agent),
        ] {
            let mut json = evidence_json();
            json["signer_kind"] = serde_json::json!(kind);
            let evidence: AuthenticatedSignerResolutionEvidence =
                serde_json::from_value(json).unwrap();
            assert_eq!(evidence.signer_kind, expected);
        }

        let mut json = evidence_json();
        json["signer_kind"] = serde_json::json!("device");
        serde_json::from_value::<AuthenticatedSignerResolutionEvidence>(json)
            .expect_err("signer kind is a closed enum");
    }

    #[test]
    fn required_members_and_closure_are_enforced() {
        for required in [
            "signer_kind",
            "subject_id",
            "verification_method",
            "public_key_jwk",
            "authority_commit_id",
            "resolved_at",
        ] {
            let mut json = evidence_json();
            json.as_object_mut().unwrap().remove(required);
            serde_json::from_value::<AuthenticatedSignerResolutionEvidence>(json)
                .expect_err("required member omission must be rejected");
        }

        let mut json = evidence_json();
        json["stream_position"] = serde_json::json!(7);
        serde_json::from_value::<AuthenticatedSignerResolutionEvidence>(json)
            .expect_err("the evidence object is closed");
    }

    #[test]
    fn public_key_jwk_floor_is_two_properties() {
        let mut json = evidence_json();
        json["public_key_jwk"] = serde_json::json!({ "kty": "OKP" });
        let evidence: AuthenticatedSignerResolutionEvidence = serde_json::from_value(json).unwrap();
        evidence
            .validate()
            .expect_err("a one-member JWK cannot name both key type and key material");

        let mut json = evidence_json();
        json["public_key_jwk"] = serde_json::json!({});
        serde_json::from_value::<AuthenticatedSignerResolutionEvidence>(json)
            .expect_err("an empty JWK is not a key");
    }

    #[test]
    fn signer_evidence_ref_is_the_canonical_content_address() {
        let evidence = evidence();
        let reference = evidence.signer_evidence_ref().unwrap();
        let expected = sha256_hex(canonical_json_bytes(&evidence).unwrap());
        assert_eq!(
            reference.as_ref(),
            format!("ak:signer_evidence:sha256:{expected}")
        );
        assert!(evidence.matches_ref(&reference).unwrap());

        let mut rebound = evidence;
        rebound.authority_commit_id =
            RealmCommitId::new("ak:realm_commit:AdA0TA9zF1BPiudM7qe4WqKZLjMn0r7--gKAHqstAWDZ")
                .unwrap();
        assert!(!rebound.matches_ref(&reference).unwrap());
    }

    /// The builder takes `resolved_at` rather than reading a clock, so calling
    /// it twice for the same resolution yields the same content address. A
    /// helper that stamped its own time would mint a new ref on every call and
    /// silently break every carrier that commits to these bytes.
    #[test]
    fn the_builders_are_deterministic_and_stamp_no_time_of_their_own() {
        let template = evidence();
        let built = build_agent_signer_evidence(
            template.subject_id.clone(),
            template.verification_method.clone(),
            template.public_key_jwk.clone(),
            template.authority_commit_id.clone(),
            template.resolved_at,
        )
        .unwrap();
        assert_eq!(built, template);
        assert_eq!(
            built.signer_evidence_ref().unwrap(),
            build_agent_signer_evidence(
                template.subject_id.clone(),
                template.verification_method.clone(),
                template.public_key_jwk.clone(),
                template.authority_commit_id.clone(),
                template.resolved_at,
            )
            .unwrap()
            .signer_evidence_ref()
            .unwrap()
        );
    }

    /// Each named builder fixes its own `signer_kind`: the three classes are
    /// distinct authorities, never fallbacks for one another.
    #[test]
    fn each_named_builder_fixes_its_own_signer_kind() {
        let template = evidence();
        let cases: [(
            fn(
                DidCoreId,
                DidUrl,
                NonEmptyJsonObject,
                RealmCommitId,
                DateTime<Utc>,
            ) -> Result<AuthenticatedSignerResolutionEvidence>,
            AuthenticatedSignerKind,
        ); 3] = [
            (build_agent_signer_evidence, AuthenticatedSignerKind::Agent),
            (
                build_principal_signer_evidence,
                AuthenticatedSignerKind::Principal,
            ),
            (
                build_service_signer_evidence,
                AuthenticatedSignerKind::Service,
            ),
        ];
        for (build, expected) in cases {
            let built = build(
                template.subject_id.clone(),
                template.verification_method.clone(),
                template.public_key_jwk.clone(),
                template.authority_commit_id.clone(),
                template.resolved_at,
            )
            .unwrap();
            assert_eq!(built.signer_kind, expected);
        }
    }

    /// The builder validates, so an unusable key never reaches a content
    /// address at all.
    #[test]
    fn the_builder_refuses_a_jwk_that_cannot_name_a_key() {
        let template = evidence();
        let mut json = evidence_json();
        json["public_key_jwk"] = serde_json::json!({ "kty": "OKP" });
        let thin: AuthenticatedSignerResolutionEvidence = serde_json::from_value(json).unwrap();
        build_agent_signer_evidence(
            template.subject_id,
            template.verification_method,
            thin.public_key_jwk,
            template.authority_commit_id,
            template.resolved_at,
        )
        .expect_err("a one-member JWK is not a usable key");
    }
}
