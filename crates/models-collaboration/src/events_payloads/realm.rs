//! Realm lifecycle, policy, and organization event payloads.

use std::collections::BTreeSet;

use crate::governance::delivery_binding::BindingSource;
use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/hierarchy_link_status`.
pub type HierarchyLinkStatus = String;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/inheritance_policy_status`.
pub type InheritancePolicyStatus = String;

/// `rebind_authorization` enum for [`DeliveryBindingPolicyPayload`]
/// (`event-payload.schema.json#/$defs/delivery_binding_policy_payload`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RebindAuthorization {
    Member,
    MemberAndAdmin,
    AdminOnly,
    ServiceOnly,
    Any,
}

/// `allowed_recipient_services` value of [`DeliveryBindingPolicyPayload`].
///
/// The spec models this as a `oneOf`: either an allow-list of recipient
/// service DIDs — where the **empty** list means "reject every recipient
/// service" (fail-closed, never "unrestricted") — or exactly the one-element
/// sentinel `["*"]`. Keeping the two cases in separate variants is what makes
/// the fail-closed reading unmistakable at the call site; a bare `Vec<Did>`
/// could not carry the sentinel at all, since `*` is not a DID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AllowedRecipientServices {
    /// The explicit `["*"]` sentinel. Lifts only the recipient-service
    /// allow-list dimension; `required_endorsers` still applies.
    Unrestricted,
    /// Closed allow-list. Empty = reject every recipient service.
    Allowlist(Vec<Did>),
}

/// Wire token for [`AllowedRecipientServices::Unrestricted`].
const ALLOWED_RECIPIENT_SERVICES_UNRESTRICTED: &str = "*";

impl Serialize for AllowedRecipientServices {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Unrestricted => [ALLOWED_RECIPIENT_SERVICES_UNRESTRICTED].serialize(serializer),
            Self::Allowlist(dids) => dids.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for AllowedRecipientServices {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let entries = Vec::<String>::deserialize(deserializer)?;
        if entries
            .iter()
            .any(|entry| entry == ALLOWED_RECIPIENT_SERVICES_UNRESTRICTED)
        {
            if entries.len() != 1 {
                return Err(serde::de::Error::custom(
                    "allowed_recipient_services sentinel must be exactly [\"*\"]",
                ));
            }
            return Ok(Self::Unrestricted);
        }
        entries
            .into_iter()
            .map(|entry| Did::new(entry).map_err(serde::de::Error::custom))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map(Self::Allowlist)
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/delivery_binding_policy_payload`.
///
/// Payload of `ak.realm.delivery_binding_policy`. Field declaration order
/// mirrors the spec schema `properties` ordering. `minProperties: 1` in the
/// schema means an all-absent payload is a `schema_violation`; [`Self::validate`]
/// enforces it locally so the Event is never authored in that shape.
/// No `Default`: an all-absent value violates `minProperties: 1`, so there is
/// no such thing as a default delivery-binding policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryBindingPolicyPayload {
    /// Optional echo of the governed Realm; the authoritative scope is the
    /// enclosing envelope `realm_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_id: Option<RealmId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_binding_sources: Option<BTreeSet<BindingSource>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_document_default_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_recipient_services: Option<AllowedRecipientServices>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_endorsers: Option<BTreeSet<Did>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unroutable_membership_allowed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rebind_authorization: Option<RebindAuthorization>,
    /// `None` (absent) and a wire `null` both mean "no expiry"; only a
    /// positive value is a real cap, so the absent form is the only one this
    /// type emits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_after_seconds: Option<u64>,
}

impl DeliveryBindingPolicyPayload {
    pub fn validate(&self) -> Result<()> {
        if self.realm_id.is_none()
            && self.allowed_binding_sources.is_none()
            && self.did_document_default_allowed.is_none()
            && self.allowed_recipient_services.is_none()
            && self.required_endorsers.is_none()
            && self.unroutable_membership_allowed.is_none()
            && self.rebind_authorization.is_none()
            && self.expires_after_seconds.is_none()
        {
            return Err(Error::Protocol(
                "delivery_binding_policy_payload must declare at least one property \
                 (schema_violation)"
                    .to_owned(),
            ));
        }
        if self.expires_after_seconds == Some(0) {
            return Err(Error::Protocol(
                "delivery_binding_policy_payload.expires_after_seconds must be >= 1 \
                 (schema_violation)"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        serde_json::to_value(self).map_err(|err| {
            Error::Protocol(format!("delivery binding policy payload serialize: {err}"))
        })
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmCreatePayload {
    pub object: Realm,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_relations: Option<Vec<BTreeMap<String, Value>>>,
}

impl RealmCreatePayload {
    pub fn new(object: Realm) -> Self {
        Self {
            object,
            initial_relations: None,
        }
    }

    /// Serialize the create payload, first re-checking the Realm invariants the
    /// receiver's candidate gate checks (soland
    /// `validate_realm_proposal_policy`). Authoring is the cheapest place to
    /// learn that `security_class=high_assurance` was paired with
    /// `federation_policy=open`, or that `notary_profile` disagrees with
    /// `notary.kind`.
    pub fn to_value(&self) -> Result<Value> {
        self.object.validate_kind_invariants()?;
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("realm create payload serialize: {err}")))
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_notary_payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmNotaryPayload {
    pub realm_id: RealmId,
    pub notary: NotaryValue,
}

impl RealmNotaryPayload {
    pub fn validate(&self) -> Result<()> {
        self.notary.validate()
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/
/// realm_digest_suite_transition_payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmDigestSuiteTransitionPayload {
    pub from_digest_algorithm: canonical::DigestSuite,
    pub to_digest_algorithm: canonical::DigestSuite,
    pub transition_snapshot_ref: SnapshotId,
    pub snapshot_commitment: Hash,
}

impl RealmDigestSuiteTransitionPayload {
    pub fn validate(&self) -> Result<()> {
        if self.from_digest_algorithm == self.to_digest_algorithm {
            return Err(Error::Protocol(
                "realm digest suite transition must change digest_algorithm (schema_violation)"
                    .to_owned(),
            ));
        }
        if matches!(
            (&self.from_digest_algorithm, &self.to_digest_algorithm),
            (
                canonical::DigestSuite::Blake3,
                canonical::DigestSuite::Sha256
            )
        ) {
            return Err(Error::Protocol(
                "realm digest suite transition must not downgrade hash strength (schema_violation)"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

// `realm_destroy_payload` now has a strong type:
// `models::operation_payloads::RealmDestroyPayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration).

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_disappearing_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmDisappearingPolicyPayload {
    pub enabled: bool,
    pub max_ttl_ms: u64,
    pub allowed_triggers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_grace_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_realms_allowed: Option<bool>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_freeze_payload`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmFreezePayload {
    pub frozen: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub effective_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub freeze_expires_at: Option<DateTime<Utc>>,
}

impl RealmFreezePayload {
    pub fn new(frozen: bool) -> Self {
        Self {
            frozen,
            reason: None,
            effective_at: None,
            freeze_expires_at: None,
        }
    }

    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        if !reason.trim().is_empty() {
            self.reason = Some(reason);
        }
        self
    }

    pub fn with_freeze_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.freeze_expires_at = Some(expires_at);
        self
    }

    pub fn to_value(&self) -> Result<Value> {
        serde_json::to_value(self)
            .map_err(|err| Error::Protocol(format!("realm freeze payload serialize: {err}")))
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_inheritance_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInheritancePolicyPayloadInherits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_bundles: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_rules: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notification_defaults: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInheritancePolicyPayload {
    pub source_realm_id: RealmId,
    pub inherits: RealmInheritancePolicyPayloadInherits,
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_depth: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<InheritancePolicyStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `relationship` discriminator for [`RealmOrganizationPayload`]
/// (event-payload.schema.json `#/$defs/realm_organization_payload`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmOrganizationRelationship {
    Owner,
    Governance,
    Sponsor,
    DirectoryCertifier,
}

/// `status` discriminator for [`RealmOrganizationPayload`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmOrganizationStatus {
    Active,
    Revoked,
}

/// `control_scopes[]` item enum for [`RealmOrganizationPayload`]. A scope is an
/// endorsement boundary only; actual Realm control still requires the matching
/// Realm policy / notary / capability / service-binding event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmOrganizationControlScope {
    OfficialBadge,
    RealmAdmin,
    NotaryControl,
    PolicyServer,
    DeliveryBindingPolicy,
    DurabilityPolicy,
    ModerationPolicy,
    RetentionPolicy,
    DirectoryListing,
    PlaintextVisibleService,
}

/// `authorization.issuer_role` enum for [`RealmOrganizationAuthorization`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RealmOrganizationIssuerRole {
    OrganizationDid,
    GovernanceService,
    AccountAuthority,
    ThresholdQuorum,
}

impl RealmOrganizationIssuerRole {
    /// Roles whose statement MUST carry a `delegation_ref` resolving to a live
    /// organization DID delegation (governance_service / account_authority).
    pub fn requires_delegation_ref(self) -> bool {
        matches!(self, Self::GovernanceService | Self::AccountAuthority)
    }
}

/// Counterpart for the inner `authorization` object of
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_organization_payload`.
///
/// This is the organization-side authorization proof, independent of the
/// Realm-side `ak.realm.admin` authorization required to write the event into
/// Realm history.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmOrganizationAuthorization {
    /// Organization DID or delegated service DID that issued this statement.
    pub issuer: Did,
    pub issuer_role: RealmOrganizationIssuerRole,
    /// DID URL of a concrete verification method (bare DIDs are not valid).
    pub verification_method: DidUrl,
    /// REQUIRED when `issuer_role` is `governance_service` or
    /// `account_authority`; MUST resolve to a live organization DID delegation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_ref: Option<ObjectRef>,
    /// Optional human admin / service principal that initiated the decision.
    /// Does not become the organization principal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executed_by: Option<Did>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub signed_at: DateTime<Utc>,
    /// Signature, threshold transcript, or governance-service attestation over
    /// the canonical organization statement.
    pub proof: SignatureMaterial,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_organization_payload`.
///
/// Organization-side endorsement or revocation for a Realm relationship. The
/// reducer cell subject is `(organization_id, relationship)` — `statement_id`
/// is audit identity, not the cell subject. Field order mirrors the spec schema
/// `properties` ordering.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmOrganizationPayload {
    /// Stable id of this organization statement (audit identity).
    pub statement_id: String,
    /// Realm the statement is bound to; MUST equal the enclosing
    /// `Event.realm_id`.
    pub realm_id: RealmId,
    /// Organization principal DID that endorses / governs / sponsors /
    /// certifies / revokes the Realm relationship.
    pub organization_id: Did,
    pub relationship: RealmOrganizationRelationship,
    pub status: RealmOrganizationStatus,
    /// Machine-readable scopes covered by the organization's consent
    /// (non-empty, unique).
    pub control_scopes: Vec<RealmOrganizationControlScope>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub issued_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub not_before: Option<DateTime<Utc>>,
    /// Nullable expiry — `Some(None)` and absence both mean "no expiry".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes_statement_id: Option<String>,
    /// REQUIRED when `status == revoked`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revokes_statement_id: Option<String>,
    /// Optional digest of the Realm control frontier the organization evaluated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_frontier_digest: Option<Hash>,
    /// Optional DID-document delegation URL / policy object / governance
    /// decision / attestation reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_policy_ref: Option<ObjectRef>,
    pub authorization: RealmOrganizationAuthorization,
}

impl RealmOrganizationPayload {
    /// `true` when the statement asserts the relationship (not a revocation).
    pub fn is_active_status(&self) -> bool {
        matches!(self.status, RealmOrganizationStatus::Active)
    }

    /// `true` when the statement revokes the relationship.
    pub fn is_revoked_status(&self) -> bool {
        matches!(self.status, RealmOrganizationStatus::Revoked)
    }

    /// `true` when `not_before` is set and lies strictly after `now` (the
    /// statement is not yet within its validity window).
    pub fn is_not_yet_valid(&self, now: DateTime<Utc>) -> bool {
        self.not_before.is_some_and(|nbf| now < nbf)
    }

    /// `true` when `expires_at` is set and lies at or before `now`.
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|exp| now >= exp)
    }

    /// `true` when the statement is an `active` relationship currently inside
    /// its validity window (`not_before <= now < expires_at`).
    pub fn is_effective_active(&self, now: DateTime<Utc>) -> bool {
        self.is_active_status() && !self.is_not_yet_valid(now) && !self.is_expired(now)
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_search_policy_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmSearchPolicyPayload {
    pub enabled_profile_refs: Vec<String>,
    pub allowed_service_ids: Vec<Did>,
    pub data_classes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_retention_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_behavior: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub leakage_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_rotation_cadence_ms: Option<u64>,
}

// `realm_tombstone_payload` now has a strong type:
// `models::operation_payloads::RealmTombstonePayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration).

// `relation_create_payload` now has a strong type:
// `models::operation_payloads::RelationCreatePayload` (replaces the former
// `= Value` alias as part of the wire strong-type migration).

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
    #[serde(serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp")]
    issued_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp"
    )]
    not_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp"
    )]
    expires_at: Option<DateTime<Utc>>,
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
        issued_at: payload.issued_at,
        not_before: payload.not_before,
        expires_at: payload.expires_at,
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
mod realm_control_payload_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn realm_notary_payload_is_closed_and_validated() {
        let value = json!({
            "realm_id": "ak:realm:01904100-0000-7000-8000-000000000001",
            "notary": {
                "kind": "single_did",
                "did": "did:web:notary.example"
            }
        });
        let payload: RealmNotaryPayload = serde_json::from_value(value.clone()).unwrap();
        payload.validate().unwrap();

        let mut unknown = value;
        unknown["notary"]["endpoint"] = json!("https://notary.example");
        assert!(serde_json::from_value::<RealmNotaryPayload>(unknown).is_err());
    }

    #[test]
    fn digest_suite_transition_rejects_noop_and_downgrade() {
        let value = json!({
            "from_digest_algorithm": "sha256",
            "to_digest_algorithm": "blake3",
            "transition_snapshot_ref": "ak:snapshot:01904100-0000-7000-8000-000000000002",
            "snapshot_commitment": format!("sha256:{}", "a".repeat(64))
        });
        let payload: RealmDigestSuiteTransitionPayload =
            serde_json::from_value(value.clone()).unwrap();
        payload.validate().unwrap();

        let mut noop = value.clone();
        noop["to_digest_algorithm"] = json!("sha256");
        let noop: RealmDigestSuiteTransitionPayload = serde_json::from_value(noop).unwrap();
        assert!(noop.validate().is_err());

        let mut downgrade = value;
        downgrade["from_digest_algorithm"] = json!("blake3");
        downgrade["to_digest_algorithm"] = json!("sha256");
        let downgrade: RealmDigestSuiteTransitionPayload =
            serde_json::from_value(downgrade).unwrap();
        assert!(downgrade.validate().is_err());
    }
}
#[cfg(test)]
mod realm_organization_tests {
    use serde_json::json;

    use super::*;

    fn active_value() -> Value {
        json!({
            "statement_id": "org-stmt-1",
            "realm_id": "ak:realm:0196419b-0000-7000-8000-000000000010",
            "organization_id": "did:webvh:example.test:orgs:01J0000000000000000000000A",
            "relationship": "owner",
            "status": "active",
            "control_scopes": ["official_badge", "realm_admin"],
            "issued_at": "2026-06-25T00:00:00.000Z",
            "authorization": {
                "issuer": "did:webvh:example.test:orgs:01J0000000000000000000000A",
                "issuer_role": "organization_did",
                "verification_method": "did:webvh:example.test:orgs:01J0000000000000000000000A#k1",
                "signed_at": "2026-06-25T00:00:00.000Z",
                "proof": "c2ln"
            }
        })
    }

    #[test]
    fn active_payload_round_trips_and_enum_renames_match_spec() {
        let value = active_value();
        let payload: RealmOrganizationPayload = serde_json::from_value(value).unwrap();
        assert!(payload.is_active_status());
        assert_eq!(payload.relationship, RealmOrganizationRelationship::Owner);
        assert_eq!(
            payload.control_scopes,
            vec![
                RealmOrganizationControlScope::OfficialBadge,
                RealmOrganizationControlScope::RealmAdmin
            ]
        );
        let reserialized = serde_json::to_value(&payload).unwrap();
        assert_eq!(reserialized["status"], json!("active"));
        assert_eq!(reserialized["relationship"], json!("owner"));
        assert_eq!(
            reserialized["authorization"]["issuer_role"],
            json!("organization_did")
        );
        // Optional/absent fields must not be emitted.
        assert!(reserialized.get("expires_at").is_none());
        assert!(reserialized.get("revokes_statement_id").is_none());
    }

    #[test]
    fn validity_window_helpers() {
        let now = DateTime::parse_from_rfc3339("2026-06-25T12:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut payload: RealmOrganizationPayload = serde_json::from_value(active_value()).unwrap();
        assert!(payload.is_effective_active(now));

        payload.not_before = Some(
            DateTime::parse_from_rfc3339("2026-06-26T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        assert!(payload.is_not_yet_valid(now));
        assert!(!payload.is_effective_active(now));

        payload.not_before = None;
        payload.expires_at = Some(
            DateTime::parse_from_rfc3339("2026-06-25T06:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        assert!(payload.is_expired(now));
        assert!(!payload.is_effective_active(now));
    }

    #[test]
    fn issuer_role_delegation_requirement() {
        assert!(RealmOrganizationIssuerRole::GovernanceService.requires_delegation_ref());
        assert!(RealmOrganizationIssuerRole::AccountAuthority.requires_delegation_ref());
        assert!(!RealmOrganizationIssuerRole::OrganizationDid.requires_delegation_ref());
        assert!(!RealmOrganizationIssuerRole::ThresholdQuorum.requires_delegation_ref());
    }

    #[test]
    fn legacy_organization_ref_shape_fails_to_deserialize() {
        // The pre-migration singleton shape `{ "organization_ref": ... }` must
        // not deserialize into the relationship-statement strong type.
        let legacy = json!({ "organization_ref": "did:webvh:z6mkfixture:org.example" });
        assert!(serde_json::from_value::<RealmOrganizationPayload>(legacy).is_err());
    }
}
