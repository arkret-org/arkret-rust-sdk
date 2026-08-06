//! Bounded offline publication: [`AuthorizationLease`] and [`IngressReceipt`].
//!
//! `zh/authz/offline-publication.md`. Neither object is an Event field and
//! neither enters the Event digest: they are independently verified
//! publication evidence carried by the submit wrappers in
//! [`crate::event_submission`].
//!
//! The revocation boundary comes from the basis-bound lease plus a signed
//! ingress receipt. An Event's `created_at` — and the verifier's own local
//! first-sight time — carry no such authority, so backdating cannot buy an
//! expired lease more time.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cba::SealBasis;
use crate::error::{Error, Result};
use crate::event_envelope::ScopeRef;
use crate::generated::ProofContextId;
pub use crate::generated::{AuthoritySetPolicyKind, AuthoritySetSourceKind};
use crate::primitives::{Audience, PayloadProof};
use crate::{
    AuthorizationLeaseId, DeviceId, Did, DidUrl, Hash, RealmId, ReceiptId, SchemaId, SealId,
    canonical,
};

/// Maximum number of issuer proofs on a lease or receipt
/// (`offline-publication.schema.json`).
pub const MAX_PUBLICATION_PROOFS: usize = 32;

/// Protocol ceiling on `expires_at - issued_at` per risk tier
/// (`offline-publication.md` §1). Realm policy MAY tighten, never widen.
pub const LEASE_MAX_TTL_LOW: Duration = Duration::hours(24);
pub const LEASE_MAX_TTL_MEDIUM: Duration = Duration::hours(8);
pub const LEASE_MAX_TTL_HIGH: Duration = Duration::hours(1);

/// Risk tier of the leased action. An unregistered action is treated as
/// [`RiskTier::High`] by the caller before a lease is minted or checked.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Medium,
    High,
}

impl RiskTier {
    /// Protocol maximum lease lifetime for this tier.
    pub fn max_lease_ttl(self) -> Duration {
        match self {
            Self::Low => LEASE_MAX_TTL_LOW,
            Self::Medium => LEASE_MAX_TTL_MEDIUM,
            Self::High => LEASE_MAX_TTL_HIGH,
        }
    }
}

/// Immutable reference to the CBA authority-set policy resolved at `basis_ref`.
///
/// `authority_set_digest` binds the canonical policy bytes, so a later mutation
/// of a registry entry cannot silently change which issuers a lease or receipt
/// was checked against.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySetRef {
    pub authority_set_id: String,
    pub authority_set_digest: Hash,
}

pub const RECOVERY_CROSS_SIGNING_AUTHORITY_SET_ID: &str =
    "ak.authority_set.recovery_cross_signing.v1";
pub const RECOVERY_IDENTITY_REANCHOR_AUTHORITY_SET_ID: &str =
    "ak.authority_set.recovery_identity_reanchor.v1";
pub const RECOVERY_ACCOUNT_AUTHORITY_SET_ID: &str =
    "ak.authority_set.recovery_account_authority.v1";

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoritySetIssuerRole {
    CrossSigningSelfSigning,
    IdentityRecovery,
    AccountEnrollmentAuthority,
    RealmAdmission,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySetPolicySource {
    pub source_kind: AuthoritySetSourceKind,
    pub source_ref: String,
    pub source_digest: Hash,
    pub generation_ref: String,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySetIssuer {
    pub verification_method: DidUrl,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySetAuthorizationRule {
    pub rule_id: String,
    pub issuer_role: AuthoritySetIssuerRole,
    pub allowed_actions: Vec<String>,
    pub issuers: Vec<AuthoritySetIssuer>,
    pub threshold: u32,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySetPolicy {
    pub schema: String,
    pub authority_set_id: String,
    pub policy_kind: AuthoritySetPolicyKind,
    pub scope_ref: ScopeRef,
    pub source: AuthoritySetPolicySource,
    pub authorization_rules: Vec<AuthoritySetAuthorizationRule>,
}

impl AuthoritySetPolicy {
    pub fn digest(&self) -> Result<Hash> {
        Ok(Hash::new(canonical::canonical_sha256(self)?)?)
    }

    pub fn validate_structural(&self) -> Result<()> {
        if self.schema != SchemaId::AUTHORITY_SET_POLICY_V1
            || self.authority_set_id.is_empty()
            || self.source.source_ref.is_empty()
            || self.source.generation_ref.is_empty()
            || self.authorization_rules.is_empty()
            || self.authorization_rules.len() > MAX_PUBLICATION_PROOFS
        {
            return Err(Error::Protocol(
                "authority-set policy contains an invalid required value".to_owned(),
            ));
        }
        let mut previous_rule_id: Option<&str> = None;
        for rule in &self.authorization_rules {
            if rule.rule_id.is_empty()
                || rule.allowed_actions.is_empty()
                || rule.issuers.is_empty()
                || rule.threshold == 0
                || usize::try_from(rule.threshold).unwrap_or(usize::MAX) > rule.issuers.len()
            {
                return Err(Error::Protocol(
                    "authority-set authorization rule is invalid".to_owned(),
                ));
            }
            if previous_rule_id.is_some_and(|previous| previous >= rule.rule_id.as_str()) {
                return Err(Error::Protocol(
                    "authority-set authorization rules are not strictly ordered".to_owned(),
                ));
            }
            previous_rule_id = Some(&rule.rule_id);
            if !strictly_ordered_unique(rule.allowed_actions.iter().map(String::as_str))
                || !strictly_ordered_unique(
                    rule.issuers
                        .iter()
                        .map(|issuer| issuer.verification_method.as_str()),
                )
            {
                return Err(Error::Protocol(
                    "authority-set rule actions or issuers are not strictly ordered".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub fn validate_reference_and_action(
        &self,
        authority_set_ref: &AuthoritySetRef,
        scope_ref: &ScopeRef,
        authorization_rule_id: &str,
        action: &str,
    ) -> Result<&AuthoritySetAuthorizationRule> {
        self.validate_structural()?;
        if self.authority_set_id != authority_set_ref.authority_set_id
            || self.digest()? != authority_set_ref.authority_set_digest
            || self.scope_ref != *scope_ref
        {
            return Err(Error::Protocol(
                "authority-set policy ref, digest, or scope mismatch".to_owned(),
            ));
        }
        let rule = self
            .authorization_rules
            .iter()
            .find(|rule| rule.rule_id == authorization_rule_id)
            .ok_or_else(|| {
                Error::Protocol(
                    "authority-set policy does not contain the selected authorization rule"
                        .to_owned(),
                )
            })?;
        if !rule
            .allowed_actions
            .iter()
            .any(|candidate| candidate == action)
        {
            return Err(Error::Protocol(
                "selected authority-set rule does not allow the requested action".to_owned(),
            ));
        }
        Ok(rule)
    }
}

fn strictly_ordered_unique<'a>(values: impl Iterator<Item = &'a str>) -> bool {
    let mut previous: Option<&str> = None;
    for value in values {
        if previous.is_some_and(|candidate| candidate >= value) {
            return false;
        }
        previous = Some(value);
    }
    true
}

/// Exact digest commitment for one registered, closed genesis anchor unit.
///
/// A Realm has no accepted Seal before its founding unit, so a Seal-only lease
/// basis would make the first Seal circular. This basis is deliberately narrow:
/// callers may select it only after recognizing and validating a complete
/// ordinary-Realm or self-principal PCR bootstrap unit.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorUnitLeaseBasis {
    pub realm_id: RealmId,
    pub event_digests: Vec<Hash>,
    pub unit_digest: Hash,
}

/// Object wrapper that keeps the untagged [`LeaseBasisRef`] variants
/// unambiguous on the wire.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorUnitLeaseBasisRef {
    pub anchor_unit: AnchorUnitLeaseBasis,
}

/// Accepted authorization basis a lease narrows.
///
/// Single-chain finality profiles cite one accepted Seal; `open_set` MUST
/// carry the complete signed multi-leaf basis, because no single leaf can
/// stand in for the joined view. The object-form anchor-unit commitment is
/// permitted only for a caller-validated registered genesis unit.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LeaseBasisRef {
    Seal(SealId),
    Joined(SealBasis),
    AnchorUnit(AnchorUnitLeaseBasisRef),
}

/// Basis-bound, expiring permission to publish one action offline.
///
/// A lease only narrows authorization that the accepted basis already grants:
/// it cannot mint a capability, cannot downgrade a medium/high action to low,
/// and cannot be replayed into another scope.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationLease {
    pub authorization_lease_id: AuthorizationLeaseId,
    pub basis_ref: LeaseBasisRef,
    pub actor_id: Did,
    pub device_id: DeviceId,
    pub scope_ref: ScopeRef,
    pub action: String,
    pub authorization_rule_id: String,
    pub risk_tier: RiskTier,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub authority_set_ref: AuthoritySetRef,
    pub authority_set_policy: AuthoritySetPolicy,
    pub proofs: Vec<PayloadProof>,
}

/// Signed proof that a policy-accepted ingress received one Event digest
/// while its lease was still valid.
///
/// A receipt proves arrival, nothing more: it does not assert that the Event
/// passed the reducer, entered a data projection, was seen by a peer, or
/// reached Seal finality.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressReceipt {
    pub receipt_id: ReceiptId,
    pub event_digest: Hash,
    pub authorization_lease_id: AuthorizationLeaseId,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    pub service_id: Did,
    pub authority_set_ref: AuthoritySetRef,
    pub proofs: Vec<PayloadProof>,
}

fn digest_without_proofs<T: Serialize>(value: &T) -> Result<Hash> {
    let mut json = serde_json::to_value(value)?;
    if let Value::Object(map) = &mut json {
        map.remove("proofs");
    }
    Ok(Hash::new(canonical::canonical_sha256(&json)?)?)
}

/// Canonical bytes each issuer signs for a lease or receipt.
///
/// `payload_digest` is the object's digest with `proofs` removed, so an issuer
/// proof commits to every other member. The fixed `context` keeps a lease proof
/// from being replayed as a receipt proof or as an Event proof.
fn publication_binding_bytes(
    context: &str,
    payload_digest: &Hash,
    authority_set_ref: &AuthoritySetRef,
    verification_method: &str,
    created_at: DateTime<Utc>,
    domain: Option<&str>,
    audience: Option<&Audience>,
) -> Result<Vec<u8>> {
    let mut object = serde_json::Map::new();
    object.insert("context".to_owned(), Value::String(context.to_owned()));
    object.insert(
        "payload_digest".to_owned(),
        Value::String(payload_digest.as_str().to_owned()),
    );
    object.insert(
        "authority_set_ref".to_owned(),
        serde_json::to_value(authority_set_ref)?,
    );
    object.insert(
        "verification_method".to_owned(),
        Value::String(verification_method.to_owned()),
    );
    object.insert(
        "created_at".to_owned(),
        Value::String(canonical::format_timestamp_canonical(created_at)),
    );
    if let Some(domain) = domain {
        object.insert("domain".to_owned(), Value::String(domain.to_owned()));
    }
    if let Some(audience) = audience {
        object.insert("audience".to_owned(), serde_json::to_value(audience)?);
    }
    Ok(canonical::canonical_json_bytes(&Value::Object(object))?)
}

fn validate_proof_set(proofs: &[PayloadProof], expected_digest: &Hash) -> Result<()> {
    if proofs.is_empty() || proofs.len() > MAX_PUBLICATION_PROOFS {
        return Err(Error::Protocol(format!(
            "publication evidence requires 1..={MAX_PUBLICATION_PROOFS} proofs"
        )));
    }
    for proof in proofs {
        proof.validate()?;
        if proof.payload_digest != *expected_digest {
            return Err(Error::Protocol(
                "publication proof does not cover the object's canonical digest".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Count distinct issuer verification methods.
///
/// Signature array length is not a quorum: a duplicated verification method
/// counts once (`offline-publication.md` §1 / §2).
pub fn distinct_issuer_count(proofs: &[PayloadProof]) -> usize {
    proofs
        .iter()
        .map(|proof| proof.verification_method.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len()
}

impl AuthorizationLease {
    /// `sha256(canonical_json(lease_without_proofs))`.
    pub fn lease_digest(&self) -> Result<Hash> {
        digest_without_proofs(self)
    }

    /// Canonical bytes the issuer identified by `proof` must sign.
    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        publication_binding_bytes(
            ProofContextId::AUTHORIZATION_LEASE_PROOF_V1,
            &self.lease_digest()?,
            &self.authority_set_ref,
            &proof.verification_method,
            proof.created_at,
            proof.domain.as_deref(),
            proof.audience.as_ref(),
        )
    }

    /// Structural validation of the closed lease and its concrete authority
    /// policy. Accepted-basis/CBA source rederivation and cryptographic
    /// signature verification remain caller responsibilities.
    pub fn validate_structural(&self) -> Result<()> {
        if let LeaseBasisRef::AnchorUnit(reference) = &self.basis_ref {
            reference.anchor_unit.validate_structural()?;
            // A lease over a Realm genesis anchor unit carries the genesis
            // scope, which names no Realm — the unit's own realm_id is the
            // resolved one. Compare only when the scope names a Realm.
            if let Some(scope_realm_id) = self.scope_ref.realm_id_opt()
                && scope_realm_id != &reference.anchor_unit.realm_id
            {
                return Err(Error::Protocol(
                    "anchor-unit lease basis realm_id does not match lease scope_ref".to_owned(),
                ));
            }
        }
        if self.expires_at <= self.issued_at {
            return Err(Error::Protocol(
                "lease expires_at must be strictly after issued_at".to_owned(),
            ));
        }
        let ttl = self.expires_at - self.issued_at;
        let ceiling = self.risk_tier.max_lease_ttl();
        if ttl > ceiling {
            return Err(Error::Protocol(format!(
                "lease TTL {} exceeds the {:?} risk-tier ceiling of {} minutes",
                ttl.num_minutes(),
                self.risk_tier,
                ceiling.num_minutes()
            )));
        }
        let digest = self.lease_digest()?;
        validate_proof_set(&self.proofs, &digest)?;
        for proof in &self.proofs {
            if proof.created_at != self.issued_at {
                return Err(Error::Protocol(
                    "lease proof created_at must equal issued_at".to_owned(),
                ));
            }
        }
        let rule = self.authority_set_policy.validate_reference_and_action(
            &self.authority_set_ref,
            &self.scope_ref,
            &self.authorization_rule_id,
            &self.action,
        )?;
        let accepted_issuers = rule
            .issuers
            .iter()
            .map(|issuer| issuer.verification_method.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let proof_issuers = self
            .proofs
            .iter()
            .map(|proof| proof.verification_method.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        if !proof_issuers.is_subset(&accepted_issuers)
            || proof_issuers.len() < usize::try_from(rule.threshold).unwrap_or(usize::MAX)
        {
            return Err(Error::Protocol(
                "lease proofs do not satisfy the selected authority-set rule".to_owned(),
            ));
        }
        Ok(())
    }

    /// Whether this lease still authorizes a first publication at `instant`.
    pub fn covers_instant(&self, instant: DateTime<Utc>) -> bool {
        self.issued_at <= instant && instant <= self.expires_at
    }
}

impl AnchorUnitLeaseBasis {
    /// `sha256(canonical_json({realm_id,event_digests}))`.
    pub fn expected_unit_digest(&self) -> Result<Hash> {
        Ok(Hash::new(canonical::canonical_sha256(
            &serde_json::json!({
                "realm_id": self.realm_id,
                "event_digests": self.event_digests,
            }),
        )?)?)
    }

    pub fn validate_structural(&self) -> Result<()> {
        if self.event_digests.is_empty() || self.event_digests.len() > 500 {
            return Err(Error::Protocol(
                "anchor-unit lease basis requires 1..=500 event digests".to_owned(),
            ));
        }
        if self
            .event_digests
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != self.event_digests.len()
        {
            return Err(Error::Protocol(
                "anchor-unit lease basis event_digests must be unique".to_owned(),
            ));
        }
        if self.unit_digest != self.expected_unit_digest()? {
            return Err(Error::Protocol(
                "anchor-unit lease basis unit_digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }
}

impl IngressReceipt {
    /// `sha256(canonical_json(receipt_without_proofs))`.
    pub fn receipt_digest(&self) -> Result<Hash> {
        digest_without_proofs(self)
    }

    /// Canonical bytes the ingress identified by `proof` must sign.
    pub fn proof_binding_bytes(&self, proof: &PayloadProof) -> Result<Vec<u8>> {
        publication_binding_bytes(
            ProofContextId::INGRESS_RECEIPT_PROOF_V1,
            &self.receipt_digest()?,
            &self.authority_set_ref,
            &proof.verification_method,
            proof.created_at,
            proof.domain.as_deref(),
            proof.audience.as_ref(),
        )
    }

    /// Structural validation independent of Realm issuer policy.
    pub fn validate_structural(&self) -> Result<()> {
        let digest = self.receipt_digest()?;
        validate_proof_set(&self.proofs, &digest)?;
        for proof in &self.proofs {
            if proof.created_at != self.received_at {
                return Err(Error::Protocol(
                    "ingress receipt proof created_at must equal received_at".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Bind this receipt to the lease and Event digest it claims to cover.
    ///
    /// `issued_at <= received_at <= expires_at` is the revocation boundary: a
    /// receipt minted outside the lease window proves nothing, and a service
    /// MUST NOT re-sign an idempotent retry with a later `received_at` to
    /// extend a window that is already fixed.
    pub fn validate_against_lease(
        &self,
        lease: &AuthorizationLease,
        event_digest: &Hash,
    ) -> Result<()> {
        if self.authorization_lease_id != lease.authorization_lease_id {
            return Err(Error::Protocol(
                "ingress receipt authorization_lease_id does not match the submitted lease"
                    .to_owned(),
            ));
        }
        if self.event_digest != *event_digest {
            return Err(Error::Protocol(
                "ingress receipt event_digest does not match the submitted Event".to_owned(),
            ));
        }
        if !lease.covers_instant(self.received_at) {
            return Err(Error::Protocol(
                "ingress receipt received_at is outside the lease validity window".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;
    use crate::primitives::proof_kind;

    fn actor() -> Did {
        Did::new("did:webvh:z6mkfixture:alice.example").unwrap()
    }

    fn scope() -> ScopeRef {
        ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:01904100-0000-8000-8000-65c7feb295d7").unwrap(),
        }
    }

    fn authority_policy() -> AuthoritySetPolicy {
        AuthoritySetPolicy {
            schema: SchemaId::AUTHORITY_SET_POLICY_V1.to_owned(),
            authority_set_id: "ak.authority_set.realm_admission.v1".to_owned(),
            policy_kind: AuthoritySetPolicyKind::RealmAdmission,
            scope_ref: scope(),
            source: AuthoritySetPolicySource {
                source_kind: AuthoritySetSourceKind::RealmControl,
                source_ref: "ak:event:01904100-0000-8000-8000-111111111111".to_owned(),
                source_digest: Hash::new(format!("sha256:{}", "e".repeat(64))).unwrap(),
                generation_ref: "1".to_owned(),
            },
            authorization_rules: vec![AuthoritySetAuthorizationRule {
                rule_id: "realm_admission".to_owned(),
                issuer_role: AuthoritySetIssuerRole::RealmAdmission,
                allowed_actions: vec!["ak.message.create".to_owned()],
                issuers: vec![AuthoritySetIssuer {
                    verification_method: DidUrl::new(
                        "did:webvh:z6mkfixture:authority.example#key-1",
                    )
                    .unwrap(),
                }],
                threshold: 1,
            }],
        }
    }

    fn instant(hour: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 28, hour, 0, 0).unwrap()
    }

    fn lease_with(risk_tier: RiskTier, expires_at: DateTime<Utc>) -> AuthorizationLease {
        let authority_set_policy = authority_policy();
        let authority_set_ref = AuthoritySetRef {
            authority_set_id: authority_set_policy.authority_set_id.clone(),
            authority_set_digest: authority_set_policy.digest().unwrap(),
        };
        let mut lease = AuthorizationLease {
            authorization_lease_id: AuthorizationLeaseId::new(
                "ak:authorization_lease:01904100-0000-7000-8000-aaaaaaaaaaaa",
            )
            .unwrap(),
            basis_ref: LeaseBasisRef::Seal(
                SealId::new(format!("ak:seal:sha256:{}", "a".repeat(64))).unwrap(),
            ),
            actor_id: actor(),
            device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-bbbbbbbbbbbb").unwrap(),
            scope_ref: scope(),
            action: "ak.message.create".to_owned(),
            authorization_rule_id: "realm_admission".to_owned(),
            risk_tier,
            issued_at: instant(0),
            expires_at,
            authority_set_ref,
            authority_set_policy,
            proofs: Vec::new(),
        };
        let digest = lease.lease_digest().unwrap();
        lease.proofs = vec![PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:authority.example#key-1")
                .unwrap(),
            payload_digest: digest,
            created_at: lease.issued_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        }];
        lease
    }

    fn receipt_for(lease: &AuthorizationLease, received_at: DateTime<Utc>) -> IngressReceipt {
        let mut receipt = IngressReceipt {
            receipt_id: ReceiptId::new("ak:receipt:01904100-0000-7000-8000-cccccccccccc").unwrap(),
            event_digest: Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap(),
            authorization_lease_id: lease.authorization_lease_id.clone(),
            received_at,
            service_id: Did::new("did:webvh:z6mkfixture:ingress.example").unwrap(),
            authority_set_ref: lease.authority_set_ref.clone(),
            proofs: Vec::new(),
        };
        let digest = receipt.receipt_digest().unwrap();
        receipt.proofs = vec![PayloadProof {
            kind: proof_kind::DETACHED_JWS.to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:ingress.example#key-1")
                .unwrap(),
            payload_digest: digest,
            created_at: received_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "a..b".to_owned(),
        }];
        receipt
    }

    #[test]
    fn lease_digest_excludes_proofs_but_covers_every_other_member() {
        let lease = lease_with(RiskTier::Medium, instant(8));
        let baseline = lease.lease_digest().unwrap();

        let mut resigned = lease.clone();
        resigned.proofs[0].jws = "z..z".to_owned();
        assert_eq!(baseline, resigned.lease_digest().unwrap());

        let mut rescoped = lease;
        rescoped.action = "ak.member.state".to_owned();
        assert_ne!(baseline, rescoped.lease_digest().unwrap());
    }

    #[test]
    fn lease_ttl_ceiling_is_enforced_per_risk_tier() {
        lease_with(RiskTier::Medium, instant(8))
            .validate_structural()
            .expect("8h medium lease is at the ceiling");
        let err = lease_with(RiskTier::Medium, instant(9))
            .validate_structural()
            .unwrap_err();
        assert!(err.to_string().contains("risk-tier ceiling"), "{err}");
        let err = lease_with(RiskTier::High, instant(2))
            .validate_structural()
            .unwrap_err();
        assert!(err.to_string().contains("risk-tier ceiling"), "{err}");
    }

    #[test]
    fn anchor_unit_basis_binds_ordered_event_digests_and_scope() {
        let realm_id = scope().realm_id().clone();
        let mut anchor = AnchorUnitLeaseBasis {
            realm_id,
            event_digests: vec![
                Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
                Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap(),
            ],
            unit_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
        };
        anchor.unit_digest = anchor.expected_unit_digest().unwrap();
        anchor.validate_structural().unwrap();

        let mut lease = lease_with(RiskTier::High, instant(1));
        lease.basis_ref = LeaseBasisRef::AnchorUnit(AnchorUnitLeaseBasisRef {
            anchor_unit: anchor.clone(),
        });
        let digest = lease.lease_digest().unwrap();
        lease.proofs[0].payload_digest = digest;
        lease.validate_structural().unwrap();

        anchor.event_digests.reverse();
        assert_ne!(anchor.unit_digest, anchor.expected_unit_digest().unwrap());
        let mut wrong_order = lease;
        wrong_order.basis_ref = LeaseBasisRef::AnchorUnit(AnchorUnitLeaseBasisRef {
            anchor_unit: anchor,
        });
        let digest = wrong_order.lease_digest().unwrap();
        wrong_order.proofs[0].payload_digest = digest;
        assert!(
            wrong_order
                .validate_structural()
                .unwrap_err()
                .to_string()
                .contains("unit_digest mismatch")
        );
    }

    #[test]
    fn lease_proof_created_at_must_equal_issued_at() {
        let mut lease = lease_with(RiskTier::Low, instant(12));
        lease.proofs[0].created_at = instant(1);
        let err = lease.validate_structural().unwrap_err();
        assert!(err.to_string().contains("created_at"), "{err}");
    }

    #[test]
    fn duplicate_verification_method_does_not_inflate_the_issuer_count() {
        let mut lease = lease_with(RiskTier::Low, instant(12));
        let duplicate = lease.proofs[0].clone();
        lease.proofs.push(duplicate);
        assert_eq!(lease.proofs.len(), 2);
        assert_eq!(distinct_issuer_count(&lease.proofs), 1);
    }

    #[test]
    fn lease_rejects_policy_digest_and_issuer_substitution() {
        let mut wrong_digest = lease_with(RiskTier::Low, instant(12));
        wrong_digest.authority_set_ref.authority_set_digest =
            Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap();
        assert!(wrong_digest.validate_structural().is_err());

        let mut wrong_issuer = lease_with(RiskTier::Low, instant(12));
        wrong_issuer.proofs[0].verification_method =
            DidUrl::new("did:webvh:z6mkfixture:attacker.example#key-1").unwrap();
        assert!(wrong_issuer.validate_structural().is_err());
    }

    #[test]
    fn authority_policy_selects_overlapping_action_rules_explicitly() {
        let mut policy = authority_policy();
        let mut second = policy.authorization_rules[0].clone();
        second.rule_id = "realm_admission_second".to_owned();
        policy.authorization_rules.push(second);
        let authority_set_ref = AuthoritySetRef {
            authority_set_id: policy.authority_set_id.clone(),
            authority_set_digest: policy.digest().unwrap(),
        };
        let selected = policy
            .validate_reference_and_action(
                &authority_set_ref,
                &scope(),
                "realm_admission_second",
                "ak.message.create",
            )
            .unwrap();
        assert_eq!(selected.rule_id, "realm_admission_second");
        let error = policy
            .validate_reference_and_action(
                &authority_set_ref,
                &scope(),
                "unknown_rule",
                "ak.message.create",
            )
            .unwrap_err();
        assert!(error.to_string().contains("selected authorization rule"));
    }

    #[test]
    fn receipt_outside_the_lease_window_is_rejected() {
        let lease = lease_with(RiskTier::Medium, instant(8));
        let digest = Hash::new(format!("sha256:{}", "d".repeat(64))).unwrap();

        let inside = receipt_for(&lease, instant(7));
        inside.validate_structural().unwrap();
        inside.validate_against_lease(&lease, &digest).unwrap();

        // A backdated Event cannot buy an expired lease more time: only the
        // signed `received_at` decides, and it must fall inside the window.
        let after_expiry = receipt_for(&lease, instant(9));
        let err = after_expiry
            .validate_against_lease(&lease, &digest)
            .unwrap_err();
        assert!(err.to_string().contains("validity window"), "{err}");
    }

    #[test]
    fn lease_and_receipt_bindings_use_distinct_contexts() {
        let lease = lease_with(RiskTier::Low, instant(12));
        let receipt = receipt_for(&lease, instant(1));
        let lease_bytes = lease.proof_binding_bytes(&lease.proofs[0]).unwrap();
        let receipt_bytes = receipt.proof_binding_bytes(&receipt.proofs[0]).unwrap();

        assert!(
            String::from_utf8(lease_bytes)
                .unwrap()
                .contains("ak.authorization-lease-proof-v1")
        );
        assert!(
            String::from_utf8(receipt_bytes)
                .unwrap()
                .contains("ak.ingress-receipt-proof-v1")
        );
    }
}
