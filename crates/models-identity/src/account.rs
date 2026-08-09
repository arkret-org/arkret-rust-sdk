use arkret_wire::{
    DeviceId, Did, Error, EventId, Hash, PayloadProof, RealmId, ReasonCode, RequestId, Result,
    TypedTrustDomainId, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::actor_profile::ActorProfile;
use crate::artifacts_account::DeviceSummaryStatus;
use crate::handle::Handle;
use crate::identity::DidOperationSubmitRequestBody;
use crate::session_credential::CanonicalSessionPublicJwk;

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_default_registration_verification_policy(
    value: &AccountRegistrationVerificationPolicy,
) -> bool {
    !value.required && value.code_digest.is_none()
}

fn is_default_registration_invitation_policy(value: &AccountRegistrationInvitationPolicy) -> bool {
    !value.required && value.token_digests.is_empty()
}

fn registration_policy_enabled_default() -> bool {
    true
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRegistrationVerificationPolicy {
    #[serde(default, skip_serializing_if = "is_false")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_digest: Option<Hash>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRegistrationInvitationPolicy {
    #[serde(default, skip_serializing_if = "is_false")]
    pub required: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub token_digests: Vec<Hash>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRegistrationRateLimitPolicy {
    pub max_attempts: u32,
    pub window_seconds: u64,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRegistrationPolicy {
    #[serde(default = "registration_policy_enabled_default")]
    pub enabled: bool,
    #[serde(
        default,
        skip_serializing_if = "is_default_registration_verification_policy"
    )]
    pub verification_code: AccountRegistrationVerificationPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub organization_allowlist: Vec<String>,
    #[serde(
        default,
        skip_serializing_if = "is_default_registration_invitation_policy"
    )]
    pub invitation: AccountRegistrationInvitationPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<AccountRegistrationRateLimitPolicy>,
}

impl Default for AccountRegistrationPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            verification_code: AccountRegistrationVerificationPolicy::default(),
            organization_allowlist: Vec::new(),
            invitation: AccountRegistrationInvitationPolicy::default(),
            rate_limit: None,
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRegistrationPolicyEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invitation_token: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountRegistrationAuditOutcome {
    Accepted,
    RegistrationClosed,
    VerificationCodeRequired,
    VerificationCodeInvalid,
    OrganizationNotAllowed,
    InvitationRequired,
    InvitationInvalid,
    RateLimited,
    DuplicateConflict,
}

impl AccountRegistrationAuditOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::RegistrationClosed => "registration_closed",
            Self::VerificationCodeRequired => "verification_code_required",
            Self::VerificationCodeInvalid => "verification_code_invalid",
            Self::OrganizationNotAllowed => "organization_not_allowed",
            Self::InvitationRequired => "invitation_required",
            Self::InvitationInvalid => "invitation_invalid",
            Self::RateLimited => "rate_limited",
            Self::DuplicateConflict => "duplicate_conflict",
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRegistrationEvidenceSummary {
    #[serde(default, skip_serializing_if = "is_false")]
    pub verification_code_present: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub invitation_token_present: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRegistrationAudit {
    pub outcome: AccountRegistrationAuditOutcome,
    pub policy_digest: Hash,
    pub evidence: AccountRegistrationEvidenceSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

/// Body of `ak.self.account_data.resource.replace`.
///
/// `ak.account_data.set`'s actor-private cell subject is
/// `composite[envelope.actor_id, payload.key]`, so the subject *is* the holder:
/// only the holder can sign the Event, and a service that authors it under its own
/// DID collapses every holder's value for one key into a single cell keyed by the
/// service, sharing one `server_revision_cas` counter.
///
/// So the body carries the signed Event and nothing else. `expected_revision`,
/// `key` and the value (`body` or `encrypted_payload`) all live in
/// `set_event.event.payload`, which is where the CAS precondition has its one
/// source. A tombstone payload is rejected here; erasure goes through
/// [`AccountDataDeleteRequestBody`], which enforces the registered
/// `deletion_mode`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountDataReplaceRequestBody {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub set_event: arkret_wire::EventInitialSubmission,
}

/// Body of `ak.self.account_data.resource.delete`.
///
/// Same signer rule as [`AccountDataReplaceRequestBody`]; the payload MUST carry
/// `tombstone`. The DELETE takes a body because that is the only place the
/// holder's signature can go — `ak.self.keys.backups.resource.delete` already
/// shows a DELETE may carry one — and `expected_revision` moved into the payload
/// rather than staying a query parameter, so one CAS precondition has one source.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountDataDeleteRequestBody {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub set_event: arkret_wire::EventInitialSubmission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountDataRow {
    pub account_data_key: String,
    pub revision: u64,
    pub content: Value,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
}

/// Closed `cas_conflict` / `not_found` details for one Account Data key.
///
/// `current_entry` is present only while the key has a live value. A missing
/// entry still carries the authoritative revision high-water mark.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountDataCasConflictDetails {
    pub account_data_key: String,
    pub current_revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_entry: Option<AccountDataRow>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountDataList {
    #[serde(default)]
    pub entries: Vec<AccountDataRow>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountDataDeleteOutcome {
    pub ok: bool,
    pub account_data_key: String,
    pub revision: u64,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountDeviceSummary {
    pub device_id: DeviceId,
    pub status: DeviceSummaryStatus,
    /// device-lifecycle.md §6 trust dimension: `unverified` / `authorized`
    /// / `needs_reverification` / `verified`. Distinct from `status`, which is
    /// the lifecycle rollup (`active` / `revoked` / `unknown`). Clients render
    /// the §6 trust pill and gate device-to-device pairing fan-out on it.
    pub verification_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub authorized_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub last_seen_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub revoked_at: Option<DateTime<Utc>>,
}

pub const ACCOUNT_HANDOFF_AUTHENTICATION_PROOF_DOMAIN: &str =
    "ak.account-handoff-authentication-proof-v1\n";
pub const IDENTITY_CREATION_CONTROL_PROOF_DOMAIN: &str = "ak.identity-creation-control-proof-v1\n";

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountHandoffAuthenticationProofKind {
    OidcCodeExchange,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountHandoffAuthenticationProof {
    pub proof_kind: AccountHandoffAuthenticationProofKind,
    pub challenge: String,
    pub request_canonical_digest: Hash,
    pub audience: Did,
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub nonce: String,
    pub authorization_code: String,
    pub code_verifier: String,
    pub signature: String,
}

impl AccountHandoffAuthenticationProof {
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        account_handoff_proof_signing_bytes(&serde_json::json!({
            "proof_kind": self.proof_kind,
            "challenge": &self.challenge,
            "request_canonical_digest": &self.request_canonical_digest,
            "audience": &self.audience,
            "issuer": &self.issuer,
            "client_id": &self.client_id,
            "redirect_uri": &self.redirect_uri,
            "state": &self.state,
            "nonce": &self.nonce,
            "authorization_code": &self.authorization_code,
            "code_verifier": &self.code_verifier,
        }))
    }

    fn unsigned_proof(&self) -> UnsignedAccountHandoffAuthenticationProof {
        UnsignedAccountHandoffAuthenticationProof {
            challenge: self.challenge.clone(),
            audience: self.audience.clone(),
            issuer: self.issuer.clone(),
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            state: self.state.clone(),
            nonce: self.nonce.clone(),
            authorization_code: self.authorization_code.clone(),
            code_verifier: self.code_verifier.clone(),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountHandoffRequestBody {
    pub request_id: RequestId,
    pub proof: AccountHandoffAuthenticationProof,
}

impl AccountHandoffRequestBody {
    pub fn canonical_request_digest(&self) -> Result<Hash> {
        account_handoff_request_digest(&self.request_id, &self.proof.unsigned_proof())
    }
}

/// OIDC handoff proof members before the request digest and holder signature
/// have been derived. This authoring type is intentionally not serializable.
#[derive(Clone, Debug)]
pub struct UnsignedAccountHandoffAuthenticationProof {
    pub challenge: String,
    pub audience: Did,
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub state: String,
    pub nonce: String,
    pub authorization_code: String,
    pub code_verifier: String,
}

/// Non-serializable account-handoff request authoring state.
#[derive(Clone, Debug)]
pub struct UnsignedAccountHandoffRequestBody {
    request_id: RequestId,
    proof: UnsignedAccountHandoffAuthenticationProof,
}

impl UnsignedAccountHandoffRequestBody {
    pub fn new(
        request_id: RequestId,
        proof: UnsignedAccountHandoffAuthenticationProof,
    ) -> Result<Self> {
        for (name, value) in [
            ("challenge", proof.challenge.as_str()),
            ("issuer", proof.issuer.as_str()),
            ("client_id", proof.client_id.as_str()),
            ("redirect_uri", proof.redirect_uri.as_str()),
            ("state", proof.state.as_str()),
            ("nonce", proof.nonce.as_str()),
            ("authorization_code", proof.authorization_code.as_str()),
            ("code_verifier", proof.code_verifier.as_str()),
        ] {
            if value.is_empty() {
                return Err(Error::Protocol(format!(
                    "account handoff proof {name} must not be empty"
                )));
            }
        }
        Ok(Self { request_id, proof })
    }

    pub fn canonical_request_digest(&self) -> Result<Hash> {
        account_handoff_request_digest(&self.request_id, &self.proof)
    }

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        let request_canonical_digest = self.canonical_request_digest()?;
        account_handoff_proof_signing_bytes(&account_handoff_unsigned_proof_value(
            &self.proof,
            &request_canonical_digest,
        ))
    }

    pub fn attach_signature(
        self,
        signature: arkret_wire::Base64UrlString,
    ) -> Result<AccountHandoffRequestBody> {
        let request_canonical_digest = self.canonical_request_digest()?;
        Ok(AccountHandoffRequestBody {
            request_id: self.request_id,
            proof: AccountHandoffAuthenticationProof {
                proof_kind: AccountHandoffAuthenticationProofKind::OidcCodeExchange,
                challenge: self.proof.challenge,
                request_canonical_digest,
                audience: self.proof.audience,
                issuer: self.proof.issuer,
                client_id: self.proof.client_id,
                redirect_uri: self.proof.redirect_uri,
                state: self.proof.state,
                nonce: self.proof.nonce,
                authorization_code: self.proof.authorization_code,
                code_verifier: self.proof.code_verifier,
                signature: signature.into_string(),
            },
        })
    }
}

fn account_handoff_request_digest(
    request_id: &RequestId,
    proof: &UnsignedAccountHandoffAuthenticationProof,
) -> Result<Hash> {
    let value = serde_json::json!({
        "request_id": request_id,
        "proof": {
            "proof_kind": AccountHandoffAuthenticationProofKind::OidcCodeExchange,
            "challenge": &proof.challenge,
            "audience": &proof.audience,
            "issuer": &proof.issuer,
            "client_id": &proof.client_id,
            "redirect_uri": &proof.redirect_uri,
            "state": &proof.state,
            "nonce": &proof.nonce,
            "authorization_code": &proof.authorization_code,
            "code_verifier": &proof.code_verifier,
        }
    });
    Hash::new(canonical::canonical_sha256(&value)?).map_err(Into::into)
}

fn account_handoff_unsigned_proof_value(
    proof: &UnsignedAccountHandoffAuthenticationProof,
    request_canonical_digest: &Hash,
) -> Value {
    serde_json::json!({
        "proof_kind": AccountHandoffAuthenticationProofKind::OidcCodeExchange,
        "challenge": &proof.challenge,
        "request_canonical_digest": request_canonical_digest,
        "audience": &proof.audience,
        "issuer": &proof.issuer,
        "client_id": &proof.client_id,
        "redirect_uri": &proof.redirect_uri,
        "state": &proof.state,
        "nonce": &proof.nonce,
        "authorization_code": &proof.authorization_code,
        "code_verifier": &proof.code_verifier,
    })
}

fn account_handoff_proof_signing_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = ACCOUNT_HANDOFF_AUTHENTICATION_PROOF_DOMAIN
        .as_bytes()
        .to_vec();
    bytes.extend(canonical::canonical_json_bytes(value)?);
    Ok(bytes)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AccountHandoffAllowedOperation {
    #[serde(rename = "ak.gate.account.command.issue_identity_binding_challenge")]
    IssueIdentityBindingChallenge,
    #[serde(rename = "ak.gate.account.command.register")]
    Register,
    #[serde(rename = "ak.gate.account.command.issue_session_grant")]
    IssueSessionGrant,
    #[serde(rename = "ak.gate.account.command.issue_recovery_completion_grant")]
    IssueRecoveryCompletionGrant,
    #[serde(rename = "ak.gate.account.command.issue_identity_abandonment_challenge")]
    IssueIdentityAbandonmentChallenge,
    #[serde(rename = "ak.gate.account.command.abandon_identity_creation")]
    AbandonIdentityCreation,
}

pub const ACCOUNT_HANDOFF_ALLOWED_OPERATIONS: [AccountHandoffAllowedOperation; 6] = [
    AccountHandoffAllowedOperation::IssueIdentityBindingChallenge,
    AccountHandoffAllowedOperation::IssueIdentityAbandonmentChallenge,
    AccountHandoffAllowedOperation::AbandonIdentityCreation,
    AccountHandoffAllowedOperation::Register,
    AccountHandoffAllowedOperation::IssueSessionGrant,
    AccountHandoffAllowedOperation::IssueRecoveryCompletionGrant,
];

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservedIdentityCreation {
    pub principal_id: Did,
    pub operation_digest: Hash,
    pub did_operation: DidOperationSubmitRequestBody,
}

impl ReservedIdentityCreation {
    pub fn from_operation(did_operation: DidOperationSubmitRequestBody) -> Result<Self> {
        did_operation.validate()?;
        let principal_id = did_operation.did.clone();
        let operation_digest = Hash::new(canonical::canonical_sha256(&did_operation)?)?;
        Ok(Self {
            principal_id,
            operation_digest,
            did_operation,
        })
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityCreationLease {
    pub identity_creation_lease_id: String,
    pub fence: u64,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved_identity: Option<ReservedIdentityCreation>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccountHandoffBinding {
    IdentityCreationActive {
        identity_creation_lease: IdentityCreationLease,
    },
    IdentityCreationBusy {
        retry_after_ms: u64,
        #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
        expires_at: DateTime<Utc>,
    },
    Bound {
        principal_id: Did,
    },
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountHandoffOutcome {
    pub request_id: RequestId,
    /// Canonical handle of the authenticated service account.
    ///
    /// This unsigned value is a UX hint for display and local artifact
    /// naming only. It is not principal identity evidence or authorization.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub account_handle: Handle,
    /// Deployment-local stable digest for the authenticated service account.
    pub account_subject: Hash,
    /// Authenticated account's private UI-language preference.
    ///
    /// This is returned only on the DPoP-bound account-handoff response. It is
    /// intentionally not part of the public actor profile: clients need it to
    /// continue the just-completed sign-in in the language the user selected,
    /// but other Realm members must never observe it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_locale: Option<arkret_locale::UiLocale>,
    pub account_handoff_grant: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub allowed_operations: [AccountHandoffAllowedOperation; 6],
    pub binding: AccountHandoffBinding,
}

impl AccountHandoffOutcome {
    pub fn validate(&self) -> Result<()> {
        if self.allowed_operations != ACCOUNT_HANDOFF_ALLOWED_OPERATIONS {
            return Err(Error::Protocol(
                "account handoff allowed_operations does not match the canonical closed set"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityAbandonmentConsequence {
    OrphanAnchorPermanentlyUnusable,
    OrphanAnchorCannotBeDeactivated,
    NoContinuableStateOnTheOrphanAnchor,
    #[serde(rename = "a_new_identity_root_did_and_pcr_must_be_created")]
    ANewIdentityRootDidAndPcrMustBeCreated,
}

pub const IDENTITY_ABANDONMENT_CONSEQUENCE_DISCLOSURE: [IdentityAbandonmentConsequence; 4] = [
    IdentityAbandonmentConsequence::OrphanAnchorPermanentlyUnusable,
    IdentityAbandonmentConsequence::OrphanAnchorCannotBeDeactivated,
    IdentityAbandonmentConsequence::NoContinuableStateOnTheOrphanAnchor,
    IdentityAbandonmentConsequence::ANewIdentityRootDidAndPcrMustBeCreated,
];

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityAbandonmentChallengeRequestBody {
    pub request_id: RequestId,
    pub identity_creation_lease_id: String,
    pub lease_fence: u64,
    pub principal_id: Did,
    pub did_version_id: String,
}

impl IdentityAbandonmentChallengeRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.identity_creation_lease_id.is_empty()
            || self.lease_fence == 0
            || self.did_version_id.is_empty()
        {
            return Err(Error::Protocol(
                "identity abandonment challenge request is incomplete".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_request_digest(&self) -> Result<Hash> {
        self.validate()?;
        Hash::new(canonical::canonical_sha256(self)?).map_err(Into::into)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum IdentityAbandonmentPurpose {
    #[serde(rename = "provisional_identity_abandonment")]
    ProvisionalIdentityAbandonment,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityAbandonmentChallengeOutcome {
    pub request_id: RequestId,
    pub challenge_id: String,
    pub challenge: String,
    pub purpose: IdentityAbandonmentPurpose,
    pub account_subject: Hash,
    pub principal_id: Did,
    pub did_version_id: String,
    pub identity_creation_lease_id: String,
    pub lease_fence: u64,
    pub consequence_disclosure: [IdentityAbandonmentConsequence; 4],
    pub dpop_jkt: String,
    pub audience: Did,
    pub origin: String,
    pub trust_domain: TypedTrustDomainId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl IdentityAbandonmentChallengeOutcome {
    pub fn validate(&self) -> Result<()> {
        if self.challenge_id.is_empty()
            || self.challenge.len() < 22
            || self.did_version_id.is_empty()
            || self.identity_creation_lease_id.is_empty()
            || self.lease_fence == 0
            || self.consequence_disclosure != IDENTITY_ABANDONMENT_CONSEQUENCE_DISCLOSURE
            || self.dpop_jkt.is_empty()
            || self.origin.is_empty()
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > chrono::Duration::seconds(300)
        {
            return Err(Error::Protocol(
                "identity abandonment challenge violates the closed transcript".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityAbandonmentRequestBody {
    pub request_id: RequestId,
    pub challenge_id: String,
    pub challenge: String,
    pub identity_creation_lease_id: String,
    pub lease_fence: u64,
    pub principal_id: Did,
    pub did_version_id: String,
}

impl IdentityAbandonmentRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.challenge_id.is_empty()
            || self.challenge.len() < 22
            || self.identity_creation_lease_id.is_empty()
            || self.lease_fence == 0
            || self.did_version_id.is_empty()
        {
            return Err(Error::Protocol(
                "identity abandonment confirmation is incomplete".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_request_digest(&self) -> Result<Hash> {
        self.validate()?;
        Hash::new(canonical::canonical_sha256(self)?).map_err(Into::into)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityAbandonmentStatus {
    Abandoned,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityAbandonmentOutcome {
    pub request_id: RequestId,
    pub status: IdentityAbandonmentStatus,
    pub account_subject: Hash,
    pub principal_id: Did,
    pub did_version_id: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub abandoned_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityBindingChallengeRequestBody {
    pub request_id: RequestId,
    pub identity_creation_lease_id: String,
    pub lease_fence: u64,
    pub did_operation: DidOperationSubmitRequestBody,
    pub pcr_realm_id: RealmId,
    pub realm_create_payload_digest: Hash,
    pub founding_authorize_payload_digest: Hash,
    pub initial_session_request_digest: Hash,
}

impl IdentityBindingChallengeRequestBody {
    pub fn canonical_request_digest(&self) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(self)?).map_err(Into::into)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityBindingPurpose {
    AccountBindingAndPcrGenesis,
}

/// Request a durable single-use challenge for an already-published DID.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidBindingChallengeRequestBody {
    pub request_id: RequestId,
    pub principal_id: Did,
}

impl DidBindingChallengeRequestBody {
    pub fn canonical_request_digest(&self) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(self)?).map_err(Into::into)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DidBindingPurpose {
    AccountBindingForPublishedDid,
}

/// Account-Authority-derived pins and freshness evidence for an
/// already-published DID. Callers copy this transcript verbatim before signing
/// with the update key active at `did_version_id`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DidBindingChallengeOutcome {
    pub request_id: RequestId,
    pub challenge_id: String,
    pub challenge: String,
    pub purpose: DidBindingPurpose,
    pub account_subject: Hash,
    pub principal_id: Did,
    pub did_version_id: String,
    pub log_head_digest: Hash,
    pub control_key_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_evidence: Option<String>,
    pub dpop_jkt: String,
    pub audience: Did,
    pub origin: String,
    pub trust_domain: TypedTrustDomainId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl DidBindingChallengeOutcome {
    pub fn validate(&self) -> Result<()> {
        if self.challenge_id.is_empty()
            || self.challenge.len() < 22
            || self.did_version_id.is_empty()
            || self.dpop_jkt.is_empty()
            || self.origin.is_empty()
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > chrono::Duration::seconds(300)
        {
            return Err(Error::Protocol(
                "published-DID binding challenge violates the closed transcript".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PcrGenesisUnitEventKind {
    #[serde(rename = "ak.realm.create")]
    RealmCreate,
    #[serde(rename = "ak.device.authorize")]
    DeviceAuthorize,
}

pub const PCR_GENESIS_UNIT_KINDS: [PcrGenesisUnitEventKind; 2] = [
    PcrGenesisUnitEventKind::RealmCreate,
    PcrGenesisUnitEventKind::DeviceAuthorize,
];

/// The first sender-constrained Standard grant requested atomically with
/// account binding and PCR genesis.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialSessionGrantRequest {
    pub device_id: DeviceId,
    pub session_public_key: CanonicalSessionPublicJwk,
    pub audience: Did,
    pub requested_scope: Vec<String>,
}

impl InitialSessionGrantRequest {
    pub fn validate(&self) -> Result<()> {
        if self.requested_scope.is_empty()
            || self.requested_scope.iter().any(String::is_empty)
            || self
                .requested_scope
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.requested_scope.len()
        {
            return Err(Error::Protocol(
                "initial session requested_scope must be non-empty and unique".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_request_digest(&self) -> Result<Hash> {
        self.validate()?;
        Hash::new(canonical::canonical_sha256(self)?).map_err(Into::into)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityBindingChallengeOutcome {
    pub request_id: RequestId,
    pub challenge_id: String,
    pub challenge: String,
    pub purpose: IdentityBindingPurpose,
    pub account_subject: Hash,
    pub principal_id: Did,
    pub operation_digest: Hash,
    pub did_version_id: String,
    pub log_head_digest: Hash,
    pub control_key_digest: Hash,
    pub pcr_realm_id: RealmId,
    pub realm_create_payload_digest: Hash,
    pub founding_authorize_payload_digest: Hash,
    pub initial_session_request_digest: Hash,
    pub genesis_unit_kinds: [PcrGenesisUnitEventKind; 2],
    pub identity_creation_lease_id: String,
    pub lease_fence: u64,
    pub dpop_jkt: String,
    pub audience: Did,
    pub origin: String,
    pub trust_domain: TypedTrustDomainId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityCreationControlProofKind {
    DidWebvhInceptionUpdateKey,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityCreationControlProof {
    pub proof_kind: IdentityCreationControlProofKind,
    pub challenge_id: String,
    pub challenge: String,
    pub purpose: IdentityBindingPurpose,
    pub account_subject: Hash,
    pub principal_id: Did,
    pub operation_digest: Hash,
    pub did_version_id: String,
    pub log_head_digest: Hash,
    pub control_key_digest: Hash,
    pub pcr_realm_id: RealmId,
    pub realm_create_payload_digest: Hash,
    pub founding_authorize_payload_digest: Hash,
    pub initial_session_request_digest: Hash,
    pub genesis_unit_kinds: [PcrGenesisUnitEventKind; 2],
    pub identity_creation_lease_id: String,
    pub lease_fence: u64,
    pub dpop_jkt: String,
    pub audience: Did,
    pub origin: String,
    pub trust_domain: TypedTrustDomainId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub verification_key_multibase: String,
    pub signature: String,
}

impl IdentityCreationControlProof {
    pub fn validate_shape(&self) -> Result<()> {
        validate_identity_creation_control_proof_body(&self.unsigned_body())?;
        arkret_wire::Base64UrlString::new(self.signature.clone())
            .map(|_| ())
            .map_err(|error| Error::Protocol(error.to_owned()))
    }

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        identity_creation_control_proof_signing_bytes(&self.unsigned_body())
    }

    fn unsigned_body(&self) -> UnsignedIdentityCreationControlProofBody {
        UnsignedIdentityCreationControlProofBody {
            challenge_id: self.challenge_id.clone(),
            challenge: self.challenge.clone(),
            purpose: self.purpose,
            account_subject: self.account_subject.clone(),
            principal_id: self.principal_id.clone(),
            operation_digest: self.operation_digest.clone(),
            did_version_id: self.did_version_id.clone(),
            log_head_digest: self.log_head_digest.clone(),
            control_key_digest: self.control_key_digest.clone(),
            pcr_realm_id: self.pcr_realm_id.clone(),
            realm_create_payload_digest: self.realm_create_payload_digest.clone(),
            founding_authorize_payload_digest: self.founding_authorize_payload_digest.clone(),
            initial_session_request_digest: self.initial_session_request_digest.clone(),
            genesis_unit_kinds: self.genesis_unit_kinds,
            identity_creation_lease_id: self.identity_creation_lease_id.clone(),
            lease_fence: self.lease_fence,
            dpop_jkt: self.dpop_jkt.clone(),
            audience: self.audience.clone(),
            origin: self.origin.clone(),
            trust_domain: self.trust_domain.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            verification_key_multibase: self.verification_key_multibase.clone(),
        }
    }
}

/// Identity-creation control members before the cold-root signature exists.
#[derive(Clone, Debug)]
pub struct UnsignedIdentityCreationControlProofBody {
    pub challenge_id: String,
    pub challenge: String,
    pub purpose: IdentityBindingPurpose,
    pub account_subject: Hash,
    pub principal_id: Did,
    pub operation_digest: Hash,
    pub did_version_id: String,
    pub log_head_digest: Hash,
    pub control_key_digest: Hash,
    pub pcr_realm_id: RealmId,
    pub realm_create_payload_digest: Hash,
    pub founding_authorize_payload_digest: Hash,
    pub initial_session_request_digest: Hash,
    pub genesis_unit_kinds: [PcrGenesisUnitEventKind; 2],
    pub identity_creation_lease_id: String,
    pub lease_fence: u64,
    pub dpop_jkt: String,
    pub audience: Did,
    pub origin: String,
    pub trust_domain: TypedTrustDomainId,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub verification_key_multibase: String,
}

/// Non-serializable cold-root authoring state.
#[derive(Clone, Debug)]
pub struct UnsignedIdentityCreationControlProof {
    body: UnsignedIdentityCreationControlProofBody,
}

impl UnsignedIdentityCreationControlProof {
    pub fn new(body: UnsignedIdentityCreationControlProofBody) -> Result<Self> {
        validate_identity_creation_control_proof_body(&body)?;
        Ok(Self { body })
    }

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        identity_creation_control_proof_signing_bytes(&self.body)
    }

    pub fn attach_signature(
        self,
        signature: arkret_wire::Base64UrlString,
    ) -> Result<IdentityCreationControlProof> {
        let body = self.body;
        let proof = IdentityCreationControlProof {
            proof_kind: IdentityCreationControlProofKind::DidWebvhInceptionUpdateKey,
            challenge_id: body.challenge_id,
            challenge: body.challenge,
            purpose: body.purpose,
            account_subject: body.account_subject,
            principal_id: body.principal_id,
            operation_digest: body.operation_digest,
            did_version_id: body.did_version_id,
            log_head_digest: body.log_head_digest,
            control_key_digest: body.control_key_digest,
            pcr_realm_id: body.pcr_realm_id,
            realm_create_payload_digest: body.realm_create_payload_digest,
            founding_authorize_payload_digest: body.founding_authorize_payload_digest,
            initial_session_request_digest: body.initial_session_request_digest,
            genesis_unit_kinds: body.genesis_unit_kinds,
            identity_creation_lease_id: body.identity_creation_lease_id,
            lease_fence: body.lease_fence,
            dpop_jkt: body.dpop_jkt,
            audience: body.audience,
            origin: body.origin,
            trust_domain: body.trust_domain,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            verification_key_multibase: body.verification_key_multibase,
            signature: signature.into_string(),
        };
        proof.validate_shape()?;
        Ok(proof)
    }
}

fn validate_identity_creation_control_proof_body(
    body: &UnsignedIdentityCreationControlProofBody,
) -> Result<()> {
    if body.purpose != IdentityBindingPurpose::AccountBindingAndPcrGenesis
        || body.genesis_unit_kinds != PCR_GENESIS_UNIT_KINDS
        || body.lease_fence == 0
        || body.did_version_id.is_empty()
        || body.expires_at <= body.issued_at
    {
        return Err(Error::Protocol(
            "identity creation control proof has an invalid PCR genesis binding".to_owned(),
        ));
    }
    Ok(())
}

fn identity_creation_control_proof_signing_bytes(
    body: &UnsignedIdentityCreationControlProofBody,
) -> Result<Vec<u8>> {
    validate_identity_creation_control_proof_body(body)?;
    let value = serde_json::json!({
        "proof_kind": IdentityCreationControlProofKind::DidWebvhInceptionUpdateKey,
        "challenge_id": &body.challenge_id,
        "challenge": &body.challenge,
        "purpose": body.purpose,
        "account_subject": &body.account_subject,
        "principal_id": &body.principal_id,
        "operation_digest": &body.operation_digest,
        "did_version_id": &body.did_version_id,
        "log_head_digest": &body.log_head_digest,
        "control_key_digest": &body.control_key_digest,
        "pcr_realm_id": &body.pcr_realm_id,
        "realm_create_payload_digest": &body.realm_create_payload_digest,
        "founding_authorize_payload_digest": &body.founding_authorize_payload_digest,
        "initial_session_request_digest": &body.initial_session_request_digest,
        "genesis_unit_kinds": body.genesis_unit_kinds,
        "identity_creation_lease_id": &body.identity_creation_lease_id,
        "lease_fence": body.lease_fence,
        "dpop_jkt": &body.dpop_jkt,
        "audience": &body.audience,
        "origin": &body.origin,
        "trust_domain": &body.trust_domain,
        "issued_at": canonical::format_timestamp_canonical(body.issued_at),
        "expires_at": canonical::format_timestamp_canonical(body.expires_at),
        "verification_key_multibase": &body.verification_key_multibase,
    });
    let mut bytes = IDENTITY_CREATION_CONTROL_PROOF_DOMAIN.as_bytes().to_vec();
    bytes.extend(canonical::canonical_json_bytes(&value)?);
    Ok(bytes)
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityCreationRegistration {
    pub identity_creation_lease_id: String,
    pub lease_fence: u64,
    pub did_operation: DidOperationSubmitRequestBody,
    pub control_proof: IdentityCreationControlProof,
    pub pcr_genesis_unit: arkret_wire::PcrGenesisUnit,
    pub initial_session: InitialSessionGrantRequest,
}

impl IdentityCreationRegistration {
    pub fn validate(&self) -> Result<()> {
        self.control_proof.validate_shape()?;
        self.pcr_genesis_unit.validate_ordered_envelopes()?;
        self.initial_session.validate()?;
        if self.initial_session.canonical_request_digest()?
            != self.control_proof.initial_session_request_digest
            || self
                .initial_session
                .session_public_key
                .thumbprint_sha256()?
                != self.control_proof.dpop_jkt
            || self.identity_creation_lease_id != self.control_proof.identity_creation_lease_id
            || self.lease_fence != self.control_proof.lease_fence
            || Hash::new(canonical::canonical_sha256(&self.did_operation)?)?
                != self.control_proof.operation_digest
            || self.pcr_genesis_unit.create().actor_id != self.control_proof.principal_id
            || self.pcr_genesis_unit.create().realm_id != self.control_proof.pcr_realm_id
            || Hash::new(canonical::canonical_sha256(
                &self.pcr_genesis_unit.create().payload,
            )?)? != self.control_proof.realm_create_payload_digest
            || Hash::new(canonical::canonical_sha256(
                &self.pcr_genesis_unit.founding_authorize().payload,
            )?)? != self.control_proof.founding_authorize_payload_digest
        {
            return Err(Error::Protocol(
                "initial session does not match identity creation control proof".to_owned(),
            ));
        }
        let descriptor_device_id = self
            .pcr_genesis_unit
            .create()
            .payload
            .get("object")
            .and_then(Value::as_object)
            .and_then(|object| object.get("founding_device_descriptor"))
            .and_then(Value::as_object)
            .and_then(|descriptor| descriptor.get("device_id"))
            .and_then(Value::as_str);
        if descriptor_device_id != Some(self.initial_session.device_id.as_str()) {
            return Err(Error::Protocol(
                "initial session device_id does not match founding device descriptor".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountBindingState {
    Bound,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityCreationOperationStatus {
    Accepted,
    Duplicate,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBindingReceipt {
    pub binding_state: AccountBindingState,
    pub account_authority_id: Did,
    pub account_subject: Hash,
    pub principal_id: Did,
    pub identity_creation_lease_id: String,
    pub lease_fence: u64,
    pub operation_status: IdentityCreationOperationStatus,
    pub operation_digest: Hash,
    pub head_event_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    pub proof: PayloadProof,
}

impl AccountBindingReceipt {
    pub fn canonical_payload_digest(&self) -> Result<Hash> {
        let value = serde_json::json!({
            "binding_state": self.binding_state,
            "account_authority_id": &self.account_authority_id,
            "account_subject": &self.account_subject,
            "principal_id": &self.principal_id,
            "identity_creation_lease_id": &self.identity_creation_lease_id,
            "lease_fence": self.lease_fence,
            "operation_status": self.operation_status,
            "operation_digest": &self.operation_digest,
            "head_event_digest": &self.head_event_digest,
            "issued_at": canonical::format_timestamp_canonical(self.issued_at),
        });
        Hash::new(canonical::canonical_sha256(&value)?).map_err(Into::into)
    }

    pub fn validate_shape(&self) -> Result<()> {
        self.proof.validate_production()?;
        if self.lease_fence == 0
            || self.identity_creation_lease_id.is_empty()
            || self.proof.created_at != self.issued_at
            || self.proof.payload_digest != self.canonical_payload_digest()?
            || !self
                .proof
                .verification_method
                .as_str()
                .starts_with(&format!("{}#", self.account_authority_id))
        {
            return Err(Error::Protocol(
                "account binding receipt proof does not bind the complete receipt".to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical detached-JWS binding object for the Account Authority proof.
    pub fn canonical_proof_binding_bytes(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        canonical::canonical_json_bytes(&serde_json::json!({
            "context": arkret_wire::ProofContextId::ACCOUNT_BINDING_RECEIPT_PROOF_V1,
            "payload_digest": &self.proof.payload_digest,
            "account_authority_id": &self.account_authority_id,
            "account_subject": &self.account_subject,
            "principal_id": &self.principal_id,
            "verification_method": &self.proof.verification_method,
            "created_at": canonical::format_timestamp_canonical(self.proof.created_at),
        }))
        .map_err(Into::into)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountUpdateProfileOutcome {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub profile: ActorProfile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum CursorRevokeScope {
    ThisCursor,
    SameDevice,
    SameSession,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountCursorRevokeRequestBody {
    pub cursor: String,
    pub reason_code: ReasonCode,
    #[serde(default = "default_cursor_revoke_scope")]
    pub revoke_scope: CursorRevokeScope,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountCursorRevokeOutcome {
    pub revoked: bool,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_scope_effective: Option<CursorRevokeScope>,
}

fn default_cursor_revoke_scope() -> CursorRevokeScope {
    CursorRevokeScope::ThisCursor
}

#[cfg(test)]
mod account_data_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn cas_conflict_details_preserve_revision_without_live_entry() {
        let details: AccountDataCasConflictDetails = serde_json::from_value(json!({
            "account_data_key": "ak.client.ui_state",
            "current_revision": 7
        }))
        .unwrap();

        assert_eq!(details.current_revision, 7);
        assert!(details.current_entry.is_none());
    }

    #[test]
    fn cas_conflict_details_reject_unknown_fields() {
        assert!(
            serde_json::from_value::<AccountDataCasConflictDetails>(json!({
                "account_data_key": "ak.client.ui_state",
                "current_revision": 7,
                "expected_revision": 6
            }))
            .is_err()
        );
    }
}

#[cfg(test)]
mod account_handoff_tests {
    use serde_json::json;

    use super::*;

    fn handoff_request() -> AccountHandoffRequestBody {
        AccountHandoffRequestBody {
            request_id: RequestId::new("ak:request:019b0000-0000-7000-8000-000000000001").unwrap(),
            proof: AccountHandoffAuthenticationProof {
                proof_kind: AccountHandoffAuthenticationProofKind::OidcCodeExchange,
                challenge: "challenge-0123456789".to_owned(),
                request_canonical_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                audience: Did::new("did:webvh:z6mkfixture:account.example").unwrap(),
                issuer: "https://auth.example".to_owned(),
                client_id: "arkret-client".to_owned(),
                redirect_uri: "https://client.example/callback".to_owned(),
                state: "state-0123456789".to_owned(),
                nonce: "nonce-0123456789".to_owned(),
                authorization_code: "authorization-code".to_owned(),
                code_verifier: "v".repeat(43),
                signature: "signature-one".to_owned(),
            },
        }
    }

    #[test]
    fn handoff_request_digest_omits_digest_and_signature_fields() {
        let first = handoff_request();
        let mut second = first.clone();
        second.proof.request_canonical_digest =
            Hash::new(format!("sha256:{}", "f".repeat(64))).unwrap();
        second.proof.signature = "signature-two".to_owned();

        assert_eq!(
            first.canonical_request_digest().unwrap(),
            second.canonical_request_digest().unwrap()
        );
        assert_ne!(
            first.proof.canonical_signing_bytes().unwrap(),
            second.proof.canonical_signing_bytes().unwrap()
        );
    }

    #[test]
    fn account_handoff_outcome_enforces_canonical_allowlist() {
        let mut outcome = AccountHandoffOutcome {
            request_id: handoff_request().request_id,
            account_handle: Handle::parse("alice:example.com").unwrap(),
            account_subject: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            preferred_locale: Some(arkret_locale::UiLocale::En),
            account_handoff_grant: "g".repeat(32),
            expires_at: Utc::now(),
            allowed_operations: ACCOUNT_HANDOFF_ALLOWED_OPERATIONS,
            binding: AccountHandoffBinding::IdentityCreationBusy {
                retry_after_ms: 1,
                expires_at: Utc::now(),
            },
        };
        outcome.validate().unwrap();

        outcome.allowed_operations.swap(0, 1);
        assert!(outcome.validate().is_err());
    }

    #[test]
    fn account_handoff_request_rejects_unknown_fields() {
        let mut value = serde_json::to_value(handoff_request()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("recovery_secret".to_owned(), json!("must-not-pass"));
        assert!(serde_json::from_value::<AccountHandoffRequestBody>(value).is_err());
    }

    #[test]
    fn account_handoff_outcome_requires_canonical_account_handle() {
        let outcome = AccountHandoffOutcome {
            request_id: handoff_request().request_id,
            account_handle: Handle::parse("alice:example.com").unwrap(),
            account_subject: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            preferred_locale: Some(arkret_locale::UiLocale::Zh),
            account_handoff_grant: "g".repeat(32),
            expires_at: Utc::now(),
            allowed_operations: ACCOUNT_HANDOFF_ALLOWED_OPERATIONS,
            binding: AccountHandoffBinding::IdentityCreationBusy {
                retry_after_ms: 1,
                expires_at: Utc::now(),
            },
        };
        let mut value = serde_json::to_value(outcome).unwrap();
        value.as_object_mut().unwrap().remove("account_handle");
        assert!(serde_json::from_value::<AccountHandoffOutcome>(value.clone()).is_err());

        value
            .as_object_mut()
            .unwrap()
            .insert("account_handle".to_owned(), json!("not-a-canonical-handle"));
        assert!(serde_json::from_value::<AccountHandoffOutcome>(value).is_err());
    }

    #[test]
    fn account_handoff_locale_is_private_typed_metadata() {
        let outcome = AccountHandoffOutcome {
            request_id: handoff_request().request_id,
            account_handle: Handle::parse("alice:example.com").unwrap(),
            account_subject: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            preferred_locale: Some(arkret_locale::UiLocale::En),
            account_handoff_grant: "g".repeat(32),
            expires_at: Utc::now(),
            allowed_operations: ACCOUNT_HANDOFF_ALLOWED_OPERATIONS,
            binding: AccountHandoffBinding::IdentityCreationBusy {
                retry_after_ms: 1,
                expires_at: Utc::now(),
            },
        };
        let value = serde_json::to_value(&outcome).unwrap();
        assert_eq!(value["preferred_locale"], "en");

        let mut unsupported = value;
        unsupported["preferred_locale"] = json!("fr");
        assert!(serde_json::from_value::<AccountHandoffOutcome>(unsupported).is_err());
    }
}
