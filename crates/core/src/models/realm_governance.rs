//! Realm-organization statement projection rows and the SDK-ORG-06
//! statement verifier retained by `arkret-core`.
//!
//! The R1.2 Realm link / inheritance / derived-capability wire types and
//! the Realm Link FSM migrated to `arkret-models-collaboration`
//! (re-exported below). The `RealmOrganization*` projection rows and the
//! statement verifier stay here because they consume the
//! `RealmOrganizationPayload` family from the (not yet migrated)
//! event-payload artifacts modules.

pub use arkret_models_collaboration::governance::realm_governance::*;

use super::*;

/// One projected `ak.realm.organization` relationship row surfaced by
/// `ak.self.realm_organization.query.list`. Mirrors the canonical
/// `realm_organization_payload` field order; `lifecycle_phase` is
/// reducer-derived. A row here is a projection only: an organization
/// relationship is only verified when `lifecycle_phase=verified_active`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmOrganizationRelationshipRow {
    pub statement_id: String,
    pub organization_id: Did,
    pub relationship: RealmOrganizationRelationship,
    pub status: RealmOrganizationStatus,
    pub control_scopes: Vec<RealmOrganizationControlScope>,
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_statement_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revokes_statement_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_frontier_digest: Option<Hash>,
    pub issuer_role: RealmOrganizationIssuerRole,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_ref: Option<String>,
    pub lifecycle_phase: RealmOrganizationLifecyclePhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Response DTO for `ak.self.realm_organization.query.list`
/// (`realm-organization-operations.schema.json#/$defs/realm_organization_relationship_list`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct RealmOrganizationRelationshipList {
    pub realm_id: RealmId,
    #[serde(default)]
    pub relationships: Vec<RealmOrganizationRelationshipRow>,
    /// `owning_organizations` declared hints with no verified statement. These
    /// are unverified claims and MUST NOT be rendered as official / governed /
    /// endorsed.
    #[serde(default)]
    pub declared_organization_hints: Vec<Did>,
}

// ── SDK-ORG-06 — ak.realm.organization statement verifier ──────────────
//
// Stateless, injectable verification of a [`RealmOrganizationPayload`]
// relationship statement. This is the canonical organization-side check
// shared across soland / teabay / cotest so none of them re-implements the
// issuer-role / delegation / proof / validity-window / scope / revocation
// invariants. The helper performs NO product-side DB queries; the DID /
// delegation resolution it needs is injected via
// [`RealmOrganizationDelegationResolver`].
//
// `DateTime`/`Utc`/`Did`/`ObjectRef`/`RealmId`/`SignatureMaterial` and the
// `RealmOrganization*` payload enums are all in scope via `use super::*`.

/// Outcome of resolving an `authorization.delegation_ref` for a delegated
/// organization statement (`issuer_role` ∈ {governance_service,
/// account_authority}).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmOrganizationDelegation {
    /// Organization DID the delegation is anchored to. MUST equal the
    /// statement's `organization_id`; the helper rejects otherwise.
    pub organization_id: Did,
    /// Whether the delegation is currently live (not expired / not revoked).
    pub is_live: bool,
    /// Relationships the delegation's purpose authorizes. The statement's
    /// `relationship` MUST be covered.
    pub covered_relationships: Vec<RealmOrganizationRelationship>,
    /// Control scopes the delegation's purpose authorizes. The statement's
    /// `control_scopes` MUST be a subset.
    pub covered_control_scopes: Vec<RealmOrganizationControlScope>,
}

/// Injection hook resolving `authorization.delegation_ref` to a live
/// organization DID delegation. Production callers wire this to their DID /
/// delegation store; offline callers use [`NoDelegationResolver`] (which
/// fails closed for any delegated statement).
pub trait RealmOrganizationDelegationResolver {
    /// Resolve `delegation_ref`. Return `Ok(None)` when the reference does
    /// not resolve to any delegation (verification then fails closed).
    fn resolve_delegation(
        &self,
        delegation_ref: &ObjectRef,
        organization_id: &Did,
    ) -> Result<Option<RealmOrganizationDelegation>>;
}

/// Offline / test resolver: never resolves a delegation. Any statement whose
/// `issuer_role` requires a delegation fails closed when verified with this
/// resolver, so production callers MUST inject a real resolver.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoDelegationResolver;

impl RealmOrganizationDelegationResolver for NoDelegationResolver {
    fn resolve_delegation(
        &self,
        _delegation_ref: &ObjectRef,
        _organization_id: &Did,
    ) -> Result<Option<RealmOrganizationDelegation>> {
        Ok(None)
    }
}

/// Verify a [`RealmOrganizationPayload`] organization-side relationship
/// statement.
///
/// This checks, fail-closed:
/// 1. `realm_id` matches the enclosing `Event.realm_id` (`expected_realm_id`).
/// 2. issuer-role / delegation coupling: delegated roles (governance_service / account_authority)
///    MUST carry a `delegation_ref` that resolves (via `resolver`) to a live delegation anchored to
///    `organization_id` and covering the requested relationship + scopes; non-delegated roles MUST
///    NOT carry one.
/// 3. proof presence / structure (non-empty signature material).
/// 4. validity window: `not_before <= now < expires_at`.
/// 5. status / revocation consistency (`revoked` requires `revokes_statement_id`; `active` must not
///    carry it).
///
/// It does NOT verify the cryptographic signature bytes themselves (the
/// caller's crypto layer does that against `verification_method`); it
/// guarantees the statement is structurally and semantically authorized to
/// be evaluated. Error messages embed the spec wire error-code constant.
pub fn verify_realm_organization_statement<R>(
    payload: &RealmOrganizationPayload,
    expected_realm_id: &RealmId,
    now: DateTime<Utc>,
    resolver: &R,
) -> Result<()>
where
    R: RealmOrganizationDelegationResolver,
{
    // 1. realm binding.
    if &payload.realm_id != expected_realm_id {
        return Err(Error::Protocol(format!(
            "ak.realm.organization realm_id must equal Event.realm_id ({})",
            crate::ErrorCode::SCHEMA_VIOLATION
        )));
    }

    // 3. proof presence / structure (checked early; cheap and pure).
    let proof_ok = match &payload.authorization.proof {
        SignatureMaterial::NonEmptyString(s) => !s.trim().is_empty(),
        SignatureMaterial::Variant1(map) => !map.is_empty(),
    };
    if !proof_ok {
        return Err(Error::Protocol(format!(
            "ak.realm.organization authorization.proof must be present ({})",
            crate::ErrorCode::INVALID_SIGNATURE
        )));
    }

    // 2. issuer-role / delegation coupling.
    let role = payload.authorization.issuer_role;
    match (
        role.requires_delegation_ref(),
        &payload.authorization.delegation_ref,
    ) {
        (true, None) => {
            return Err(Error::Protocol(format!(
                "ak.realm.organization issuer_role requires delegation_ref ({})",
                crate::ErrorCode::SCHEMA_VIOLATION
            )));
        }
        (false, Some(_)) => {
            return Err(Error::Protocol(format!(
                "ak.realm.organization delegation_ref only valid for delegated issuer_role ({})",
                crate::ErrorCode::SCHEMA_VIOLATION
            )));
        }
        (true, Some(delegation_ref)) => {
            let delegation = resolver
                .resolve_delegation(delegation_ref, &payload.organization_id)?
                .ok_or_else(|| {
                    Error::Protocol(format!(
                        "ak.realm.organization delegation_ref did not resolve ({})",
                        crate::ReasonCode::GRANT_REVOKED_UPSTREAM
                    ))
                })?;
            if !delegation.is_live {
                return Err(Error::Protocol(format!(
                    "ak.realm.organization delegation is not live ({})",
                    crate::ReasonCode::GRANT_REVOKED_UPSTREAM
                )));
            }
            if delegation.organization_id != payload.organization_id {
                return Err(Error::Protocol(format!(
                    "ak.realm.organization delegation anchored to a different organization ({})",
                    crate::ReasonCode::GRANT_EXCEEDS_ISSUER_AUTHORITY
                )));
            }
            if !delegation
                .covered_relationships
                .contains(&payload.relationship)
            {
                return Err(Error::Protocol(format!(
                    "ak.realm.organization delegation does not cover relationship ({})",
                    crate::ReasonCode::GRANT_EXCEEDS_ISSUER_AUTHORITY
                )));
            }
            if !payload
                .control_scopes
                .iter()
                .all(|scope| delegation.covered_control_scopes.contains(scope))
            {
                return Err(Error::Protocol(format!(
                    "ak.realm.organization delegation does not cover all control_scopes ({})",
                    crate::ReasonCode::GRANT_EXCEEDS_ISSUER_AUTHORITY
                )));
            }
        }
        (false, None) => {}
    }

    // 4. validity window.
    if payload.is_not_yet_valid(now) {
        return Err(Error::Protocol(format!(
            "ak.realm.organization statement is not yet valid ({})",
            crate::ErrorCode::FAILED_PRECONDITION
        )));
    }
    if payload.is_expired(now) {
        return Err(Error::Protocol(format!(
            "ak.realm.organization statement is expired ({})",
            crate::ReasonCode::TTL_EXPIRED
        )));
    }

    // 5. status / revocation consistency.
    match payload.status {
        RealmOrganizationStatus::Revoked if payload.revokes_statement_id.is_none() => {
            Err(Error::Protocol(format!(
                "ak.realm.organization revoked status requires revokes_statement_id ({})",
                crate::ErrorCode::SCHEMA_VIOLATION
            )))
        }
        RealmOrganizationStatus::Active if payload.revokes_statement_id.is_some() => {
            Err(Error::Protocol(format!(
                "ak.realm.organization active status must not carry revokes_statement_id ({})",
                crate::ErrorCode::SCHEMA_VIOLATION
            )))
        }
        _ => Ok(()),
    }
}

/// Transcript discriminator for the bytes an organization-side proof signs over.
pub const ORGANIZATION_STATEMENT_TRANSCRIPT_KIND: &str = "ak.realm.organization.statement.v1";

/// Canonical transcript the organization-side proof signs over. Every statement
/// field except `authorization.proof` (the signature itself) and the redundant
/// `signed_at` is included, so a verifier can rebuild the exact bytes from the
/// wire statement. Optional fields are omitted when absent so the bytes are
/// stable.
#[derive(Debug, Serialize)]
struct OrganizationStatementTranscript<'a> {
    kind: &'a str,
    statement_id: &'a str,
    realm_id: &'a RealmId,
    organization_id: &'a Did,
    relationship: &'a RealmOrganizationRelationship,
    status: &'a RealmOrganizationStatus,
    control_scopes: &'a [RealmOrganizationControlScope],
    issued_at: &'a DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    not_before: Option<&'a DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<&'a DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    supersedes_statement_id: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    revokes_statement_id: Option<&'a String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    realm_frontier_digest: Option<&'a Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    organization_policy_ref: Option<&'a ObjectRef>,
    issuer: &'a Did,
    issuer_role: &'a RealmOrganizationIssuerRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegation_ref: Option<&'a ObjectRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    executed_by: Option<&'a Did>,
}

/// Canonical bytes the organization-side `authorization.proof` signs over.
///
/// Both the issuing side (coauth) and the verifying side (soland) MUST derive
/// the signing input from this one function so the bytes are byte-identical.
/// The transcript binds every semantic field of the statement except the proof
/// itself, so a detached signature over these bytes authenticates the whole
/// statement. The signing key MUST be a verification method in the
/// `organization_id` DID document (`authorization.verification_method`); the
/// verifier resolves that document and checks the signature.
pub fn realm_organization_statement_signing_bytes(
    payload: &RealmOrganizationPayload,
) -> Result<Vec<u8>> {
    let authorization = &payload.authorization;
    let transcript = OrganizationStatementTranscript {
        kind: ORGANIZATION_STATEMENT_TRANSCRIPT_KIND,
        statement_id: &payload.statement_id,
        realm_id: &payload.realm_id,
        organization_id: &payload.organization_id,
        relationship: &payload.relationship,
        status: &payload.status,
        control_scopes: &payload.control_scopes,
        issued_at: &payload.issued_at,
        not_before: payload.not_before.as_ref(),
        expires_at: payload.expires_at.as_ref(),
        supersedes_statement_id: payload.supersedes_statement_id.as_ref(),
        revokes_statement_id: payload.revokes_statement_id.as_ref(),
        realm_frontier_digest: payload.realm_frontier_digest.as_ref(),
        organization_policy_ref: payload.organization_policy_ref.as_ref(),
        issuer: &authorization.issuer,
        issuer_role: &authorization.issuer_role,
        delegation_ref: authorization.delegation_ref.as_ref(),
        executed_by: authorization.executed_by.as_ref(),
    };
    Ok(canonical::canonical_json_bytes(&transcript)?)
}

#[cfg(test)]
mod realm_organization_verifier_tests {
    use chrono::TimeZone;

    use super::*;

    fn realm_id() -> RealmId {
        RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000010").unwrap()
    }

    fn org_did() -> Did {
        Did::new("did:webvh:example.test:orgs:org1".to_owned()).unwrap()
    }

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 25, 12, 0, 0).unwrap()
    }

    fn active_payload() -> RealmOrganizationPayload {
        RealmOrganizationPayload {
            statement_id: "org-stmt-1".to_owned(),
            realm_id: realm_id(),
            organization_id: org_did(),
            relationship: RealmOrganizationRelationship::Owner,
            status: RealmOrganizationStatus::Active,
            control_scopes: vec![
                RealmOrganizationControlScope::OfficialBadge,
                RealmOrganizationControlScope::RealmAdmin,
            ],
            issued_at: now(),
            not_before: None,
            expires_at: None,
            supersedes_statement_id: None,
            revokes_statement_id: None,
            realm_frontier_digest: None,
            organization_policy_ref: None,
            authorization: RealmOrganizationAuthorization {
                issuer: org_did(),
                issuer_role: RealmOrganizationIssuerRole::OrganizationDid,
                verification_method: DidUrl::new("did:webvh:example.test:orgs:org1#k1").unwrap(),
                delegation_ref: None,
                executed_by: None,
                signed_at: now(),
                proof: SignatureMaterial::NonEmptyString(NonEmptyString::new("c2ln").unwrap()),
            },
        }
    }

    fn live_delegation() -> RealmOrganizationDelegation {
        RealmOrganizationDelegation {
            organization_id: org_did(),
            is_live: true,
            covered_relationships: vec![RealmOrganizationRelationship::Owner],
            covered_control_scopes: vec![
                RealmOrganizationControlScope::OfficialBadge,
                RealmOrganizationControlScope::RealmAdmin,
            ],
        }
    }

    struct FixedResolver(Option<RealmOrganizationDelegation>);
    impl RealmOrganizationDelegationResolver for FixedResolver {
        fn resolve_delegation(
            &self,
            _delegation_ref: &ObjectRef,
            _organization_id: &Did,
        ) -> Result<Option<RealmOrganizationDelegation>> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn active_organization_did_statement_passes() {
        verify_realm_organization_statement(
            &active_payload(),
            &realm_id(),
            now(),
            &NoDelegationResolver,
        )
        .unwrap();
    }

    #[test]
    fn realm_id_mismatch_fails() {
        let other = RealmId::new("ak:realm:0196419b-0000-7000-8000-000000000099").unwrap();
        assert!(
            verify_realm_organization_statement(
                &active_payload(),
                &other,
                now(),
                &NoDelegationResolver
            )
            .is_err()
        );
    }

    #[test]
    fn delegated_role_without_delegation_ref_fails() {
        let mut p = active_payload();
        p.authorization.issuer_role = RealmOrganizationIssuerRole::GovernanceService;
        assert!(
            verify_realm_organization_statement(&p, &realm_id(), now(), &NoDelegationResolver)
                .is_err()
        );
    }

    #[test]
    fn delegated_role_with_unresolvable_delegation_fails_closed() {
        let mut p = active_payload();
        p.authorization.issuer_role = RealmOrganizationIssuerRole::AccountAuthority;
        p.authorization.delegation_ref =
            Some("ak:grant:01904100-0000-7000-8000-000000000001".to_owned());
        assert!(
            verify_realm_organization_statement(&p, &realm_id(), now(), &NoDelegationResolver)
                .is_err()
        );
    }

    #[test]
    fn delegated_role_with_live_covering_delegation_passes() {
        let mut p = active_payload();
        p.authorization.issuer_role = RealmOrganizationIssuerRole::GovernanceService;
        p.authorization.delegation_ref =
            Some("ak:grant:01904100-0000-7000-8000-000000000001".to_owned());
        verify_realm_organization_statement(
            &p,
            &realm_id(),
            now(),
            &FixedResolver(Some(live_delegation())),
        )
        .unwrap();
    }

    #[test]
    fn non_delegated_role_with_delegation_ref_fails() {
        let mut p = active_payload();
        p.authorization.delegation_ref =
            Some("ak:grant:01904100-0000-7000-8000-000000000001".to_owned());
        assert!(
            verify_realm_organization_statement(&p, &realm_id(), now(), &NoDelegationResolver)
                .is_err()
        );
    }

    #[test]
    fn delegation_not_covering_scopes_fails() {
        let mut p = active_payload();
        p.authorization.issuer_role = RealmOrganizationIssuerRole::GovernanceService;
        p.authorization.delegation_ref =
            Some("ak:grant:01904100-0000-7000-8000-000000000001".to_owned());
        let mut delegation = live_delegation();
        delegation.covered_control_scopes = vec![RealmOrganizationControlScope::OfficialBadge];
        assert!(
            verify_realm_organization_statement(
                &p,
                &realm_id(),
                now(),
                &FixedResolver(Some(delegation))
            )
            .is_err()
        );
    }

    #[test]
    fn empty_proof_fails() {
        let mut p = active_payload();
        p.authorization.proof =
            SignatureMaterial::NonEmptyString(NonEmptyString::new("   ").unwrap());
        assert!(
            verify_realm_organization_statement(&p, &realm_id(), now(), &NoDelegationResolver)
                .is_err()
        );
    }

    #[test]
    fn expired_and_not_yet_valid_fail() {
        let mut expired = active_payload();
        expired.expires_at = Some(Utc.with_ymd_and_hms(2026, 6, 25, 6, 0, 0).unwrap());
        assert!(
            verify_realm_organization_statement(
                &expired,
                &realm_id(),
                now(),
                &NoDelegationResolver
            )
            .is_err()
        );

        let mut future = active_payload();
        future.not_before = Some(Utc.with_ymd_and_hms(2026, 6, 26, 0, 0, 0).unwrap());
        assert!(
            verify_realm_organization_statement(&future, &realm_id(), now(), &NoDelegationResolver)
                .is_err()
        );
    }

    #[test]
    fn revoked_requires_revokes_statement_id() {
        let mut p = active_payload();
        p.status = RealmOrganizationStatus::Revoked;
        assert!(
            verify_realm_organization_statement(&p, &realm_id(), now(), &NoDelegationResolver)
                .is_err()
        );
        p.revokes_statement_id = Some("org-stmt-0".to_owned());
        verify_realm_organization_statement(&p, &realm_id(), now(), &NoDelegationResolver).unwrap();
    }
}
