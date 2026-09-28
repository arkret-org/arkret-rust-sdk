use arkret_wire::{
    AppletId, DetachedSignatureAlgorithm, DeviceId, DeviceRevocationGateRecord, Did, DidCoreId,
    DidUrl, EventId, Hash, PayloadProof, PcrGenesisUnit, RealmId, ReasonCode, RequestId, Result,
    SchemaId, ScopeRef, ServiceOperationId, SessionGrantId, TrustDomainId, WebOrigin, WireError,
    canonical, project_did_to_core_id,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::artifacts_account::{
    DeviceSummaryStatus, DeviceSummaryVerificationSource, DeviceSummaryVerificationState,
    validate_device_summary_evidence,
};
use crate::handle::Handle;
use crate::principal_registration_anchor::PrincipalRegistrationAnchor;
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
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
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

/// Body of `ak.self.account_data.resource.replace.v1`.
///
/// `ak.account_data.set` is actor-private and therefore bypasses RealmCommit.
/// Its logical key is `(envelope.actor_id, payload.key)`, so only the holder may
/// sign it and each holder keeps an independent `server_revision_cas` counter.
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
    pub set_event: arkret_wire::Event,
}

/// Body of `ak.self.account_data.resource.delete.v1`.
///
/// Same signer rule as [`AccountDataReplaceRequestBody`]; the payload MUST carry
/// `tombstone`. The DELETE takes a body because that is the only place the
/// holder's signature can go — `ak.self.keys.backups.resource.delete.v1` already
/// shows a DELETE may carry one — and `expected_revision` moved into the payload
/// rather than staying a query parameter, so one CAS precondition has one source.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountDataDeleteRequestBody {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub set_event: arkret_wire::Event,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
pub struct AccountDataCasConflict {
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
    pub account_data_entries: Vec<AccountDataRow>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountDataDeleteOutcome {
    pub account_data_key: String,
    pub revision: u64,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountDeviceSummary {
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub status: DeviceSummaryStatus,
    pub verification_state: DeviceSummaryVerificationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_source: Option<DeviceSummaryVerificationSource>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_states: Option<Vec<DeviceRevocationGateRecord>>,
}

impl AccountDeviceSummary {
    pub fn validate(&self) -> Result<()> {
        validate_device_summary_evidence(
            self.status,
            self.verification_state,
            self.verification_source,
            self.authorized_event_ref.as_ref(),
            self.revocation_states.as_deref(),
        )
    }
}

pub const ACCOUNT_HANDOFF_AUTHENTICATION_PROOF_DOMAIN: &str =
    "ak.account_handoff_authentication_proof.v1\n";
pub const IDENTITY_CREATION_CONTROL_PROOF_DOMAIN: &str = "ak.identity_creation_control_proof.v1\n";
pub const ACCOUNT_REGISTRATION_CONTROL_PROOF_DOMAIN: &str =
    "ak.account_registration_control_proof.v1\n";

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
    pub audience_id: DidCoreId,
    pub issuer_uri: String,
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
            "audience_id": &self.audience_id,
            "issuer_uri": &self.issuer_uri,
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
            audience_id: self.audience_id.clone(),
            issuer_uri: self.issuer_uri.clone(),
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
    pub audience_id: DidCoreId,
    pub issuer_uri: String,
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
            ("issuer", proof.issuer_uri.as_str()),
            ("client_id", proof.client_id.as_str()),
            ("redirect_uri", proof.redirect_uri.as_str()),
            ("state", proof.state.as_str()),
            ("nonce", proof.nonce.as_str()),
            ("authorization_code", proof.authorization_code.as_str()),
            ("code_verifier", proof.code_verifier.as_str()),
        ] {
            if value.is_empty() {
                return Err(WireError::Protocol(format!(
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
                audience_id: self.proof.audience_id,
                issuer_uri: self.proof.issuer_uri,
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
            "audience_id": &proof.audience_id,
            "issuer_uri": &proof.issuer_uri,
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
        "audience_id": &proof.audience_id,
        "issuer_uri": &proof.issuer_uri,
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
    #[serde(rename = "ak.gate.account.command.issue_did_binding_challenge.v1")]
    IssueDidBindingChallenge,
    #[serde(rename = "ak.gate.account.command.issue_identity_binding_challenge.v1")]
    IssueIdentityBindingChallenge,
    #[serde(rename = "ak.gate.account.command.register.v1")]
    Register,
    #[serde(rename = "ak.gate.account.command.finalize_device_pairing.v1")]
    FinalizeDevicePairing,
    #[serde(rename = "ak.gate.account.command.issue_session_grant.v1")]
    IssueSessionGrant,
    #[serde(rename = "ak.gate.account.command.issue_recovery_completion_grant.v1")]
    IssueRecoveryCompletionGrant,
    #[serde(rename = "ak.gate.account.command.abandon_identity_creation.v1")]
    AbandonIdentityCreation,
}

pub const ACCOUNT_HANDOFF_ALLOWED_OPERATIONS: [AccountHandoffAllowedOperation; 7] = [
    AccountHandoffAllowedOperation::IssueIdentityBindingChallenge,
    AccountHandoffAllowedOperation::IssueDidBindingChallenge,
    AccountHandoffAllowedOperation::AbandonIdentityCreation,
    AccountHandoffAllowedOperation::Register,
    AccountHandoffAllowedOperation::FinalizeDevicePairing,
    AccountHandoffAllowedOperation::IssueSessionGrant,
    AccountHandoffAllowedOperation::IssueRecoveryCompletionGrant,
];

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReservedIdentityCreation {
    pub principal_id: DidCoreId,
    pub did: Did,
    pub registration_anchor_digest: Hash,
    pub principal_registration_anchor: PrincipalRegistrationAnchor,
}

impl ReservedIdentityCreation {
    pub fn from_anchor(principal_registration_anchor: PrincipalRegistrationAnchor) -> Result<Self> {
        principal_registration_anchor.validate()?;
        let did = principal_registration_anchor.did().clone();
        let principal_id = project_did_to_core_id(&did)?;
        let registration_anchor_digest = principal_registration_anchor.canonical_digest()?;
        Ok(Self {
            principal_id,
            did,
            registration_anchor_digest,
            principal_registration_anchor,
        })
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityCreationLeaseState {
    #[default]
    Active,
    Reserved,
    DidPublished,
    PcrAccepted,
    AccountBound,
    Completed,
}

impl IdentityCreationLeaseState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Reserved => "reserved",
            Self::DidPublished => "did_published",
            Self::PcrAccepted => "pcr_accepted",
            Self::AccountBound => "account_bound",
            Self::Completed => "completed",
        }
    }

    pub const fn ordinal(self) -> u8 {
        match self {
            Self::Active => 0,
            Self::Reserved => 1,
            Self::DidPublished => 2,
            Self::PcrAccepted => 3,
            Self::AccountBound => 4,
            Self::Completed => 5,
        }
    }

    pub const fn has_reserved_identity(self) -> bool {
        !matches!(self, Self::Active)
    }
}

impl TryFrom<&str> for IdentityCreationLeaseState {
    type Error = String;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "active" => Ok(Self::Active),
            "reserved" => Ok(Self::Reserved),
            "did_published" => Ok(Self::DidPublished),
            "pcr_accepted" => Ok(Self::PcrAccepted),
            "account_bound" => Ok(Self::AccountBound),
            "completed" => Ok(Self::Completed),
            other => Err(format!("unknown identity creation lease state: {other}")),
        }
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityCreationGoal {
    CompleteIdentity,
    AbandonProvisionalIdentity,
}

/// Server-authored goal for the currently authenticated onboarding flow.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "goal", rename_all = "snake_case", deny_unknown_fields)]
pub enum AccountOnboardingGoal {
    CompleteIdentity,
}

impl AccountOnboardingGoal {
    pub const fn kind(&self) -> IdentityCreationGoal {
        IdentityCreationGoal::CompleteIdentity
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityCreationCommandKind {
    IssueIdentityBindingChallenge,
    SubmitRegistration,
    ConfirmAbandonment,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityCreationLocalArtifactKind {
    RegistrationCheckpoint,
    PreparedRegistrationRequest,
    FreshAccountHandoff,
}

/// Process-local availability of the recovery authority for identity creation.
///
/// This is deliberately separate from durable public checkpoints. A checkpoint
/// can prove which identity was reserved, but it never proves that this process
/// currently holds the secret that controls it. Likewise, `LocallyValidated`
/// only means that the words matched during the current interaction and were
/// durably retained by this device; it does not claim that the user memorized,
/// exported, or otherwise backed them up.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityCreationRecoveryKeyState {
    #[default]
    Unavailable,
    GeneratedPendingConfirmation,
    RecoveredPendingConfirmation,
    GeneratedLocallyValidatedDurable,
    ExistingValidatedDurable,
}

impl IdentityCreationRecoveryKeyState {
    pub const fn can_control_identity(self) -> bool {
        matches!(
            self,
            Self::GeneratedLocallyValidatedDurable | Self::ExistingValidatedDurable
        )
    }

    pub const fn needs_confirmation(self) -> bool {
        matches!(
            self,
            Self::GeneratedPendingConfirmation | Self::RecoveredPendingConfirmation
        )
    }
}

/// Server-authored identity-creation state carried by an account handoff.
///
/// The lease state is the only onboarding phase authority. Clients may use
/// local artifacts to satisfy the requirements derived from this value, but
/// MUST NOT infer a different phase from local checkpoint presence.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityCreationLease {
    pub identity_creation_lease_id: String,
    pub fence: u64,
    #[serde(default)]
    pub state: IdentityCreationLeaseState,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reserved_identity: Option<ReservedIdentityCreation>,
}

impl IdentityCreationLease {
    pub fn validate(&self) -> Result<()> {
        if self.identity_creation_lease_id.is_empty() || self.fence == 0 {
            return Err(WireError::Protocol(
                "identity creation lease identity or fence is invalid".to_owned(),
            ));
        }
        if self.state.has_reserved_identity() != self.reserved_identity.is_some() {
            return Err(WireError::Protocol(
                "identity creation lease state contradicts its reserved identity".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn allowed_goals(&self) -> &'static [IdentityCreationGoal] {
        use IdentityCreationGoal::{AbandonProvisionalIdentity, CompleteIdentity};
        match self.state {
            IdentityCreationLeaseState::Active => &[CompleteIdentity],
            IdentityCreationLeaseState::Reserved | IdentityCreationLeaseState::DidPublished => {
                &[CompleteIdentity, AbandonProvisionalIdentity]
            }
            IdentityCreationLeaseState::PcrAccepted
            | IdentityCreationLeaseState::AccountBound
            | IdentityCreationLeaseState::Completed => &[CompleteIdentity],
        }
    }

    pub fn required_local_artifacts(
        &self,
        goal: IdentityCreationGoal,
    ) -> Result<&'static [IdentityCreationLocalArtifactKind]> {
        use IdentityCreationGoal::{AbandonProvisionalIdentity, CompleteIdentity};
        use IdentityCreationLeaseState::{
            AccountBound, Active, Completed, DidPublished, PcrAccepted, Reserved,
        };
        use IdentityCreationLocalArtifactKind::{
            FreshAccountHandoff, PreparedRegistrationRequest, RegistrationCheckpoint,
        };
        if !self.allowed_goals().contains(&goal) {
            return Err(WireError::Protocol(
                "identity creation goal is not allowed by the server state".to_owned(),
            ));
        }
        Ok(match (self.state, goal) {
            (Active, CompleteIdentity) => &[RegistrationCheckpoint],
            (Reserved, CompleteIdentity) => &[RegistrationCheckpoint],
            (DidPublished | PcrAccepted | AccountBound, CompleteIdentity) => {
                &[RegistrationCheckpoint, PreparedRegistrationRequest]
            }
            (Completed, CompleteIdentity) => &[],
            (Reserved | DidPublished, AbandonProvisionalIdentity) => &[FreshAccountHandoff],
            _ => unreachable!("goal membership was checked above"),
        })
    }
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
        principal_id: DidCoreId,
        did: Did,
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
    pub allowed_operations: [AccountHandoffAllowedOperation; 7],
    pub binding: AccountHandoffBinding,
}

impl AccountHandoffOutcome {
    pub fn validate(&self) -> Result<()> {
        if self.allowed_operations != ACCOUNT_HANDOFF_ALLOWED_OPERATIONS {
            return Err(WireError::Protocol(
                "account handoff allowed_operations does not match the canonical closed set"
                    .to_owned(),
            ));
        }
        if let AccountHandoffBinding::IdentityCreationActive {
            identity_creation_lease,
        } = &self.binding
        {
            identity_creation_lease.validate()?;
        }
        Ok(())
    }
}

/// Fresh Account-Authority projection of the authenticated holder's current
/// onboarding state. This read model contains no credential and never accepts
/// client-authored phase fields.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountOnboardingState {
    pub handoff_request_id: RequestId,
    pub account_subject: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    pub binding: AccountHandoffBinding,
    pub goal: AccountOnboardingGoal,
}

impl AccountOnboardingState {
    pub fn validate(&self) -> Result<()> {
        match &self.binding {
            AccountHandoffBinding::IdentityCreationActive {
                identity_creation_lease,
            } => {
                identity_creation_lease.validate()?;
                if !identity_creation_lease
                    .allowed_goals()
                    .contains(&self.goal.kind())
                {
                    return Err(WireError::Protocol(
                        "account onboarding goal is not allowed by the server lease state"
                            .to_owned(),
                    ));
                }
            }
            AccountHandoffBinding::Bound { principal_id, did } => {
                if project_did_to_core_id(did)?.as_str() != principal_id.as_str() {
                    return Err(WireError::Protocol(
                        "bound account onboarding did does not project to principal_id".to_owned(),
                    ));
                }
            }
            AccountHandoffBinding::IdentityCreationBusy { .. } => {}
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityAbandonmentRequestBody {
    pub request_id: RequestId,
    pub identity_creation_lease_id: String,
    pub lease_fence: u64,
    pub principal_id: DidCoreId,
    pub did_version_id: String,
}

impl IdentityAbandonmentRequestBody {
    pub fn validate(&self) -> Result<()> {
        if self.identity_creation_lease_id.is_empty()
            || self.lease_fence == 0
            || self.did_version_id.is_empty()
        {
            return Err(WireError::Protocol(
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityAbandonmentOutcome {
    pub request_id: RequestId,
    pub account_subject: Hash,
    pub principal_id: DidCoreId,
    pub did_version_id: String,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub abandoned_at: DateTime<Utc>,
}

/// Request body of `ak.gate.account.command.request_erasure.v1`
/// (`POST /_arkret/gate/account/erasure-requests`; account-lifecycle.md
/// section 8.1). Acceptance records the erasure intent only; it is neither
/// the signed `erasure_pending` AccountStatusRecord nor a completion receipt.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRequestErasureRequestBody {
    /// Idempotency identity of the erasure request. Exact replay returns the
    /// recorded acceptance outcome; the same request_id with different
    /// canonical bytes is `duplicate_conflict`; a different request_id while
    /// a live unsigned-record intent exists is `failed_precondition` with
    /// reason code `erasure_request_already_pending`.
    pub request_id: RequestId,
}

impl AccountRequestErasureRequestBody {
    pub fn validate(&self) -> Result<()> {
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
pub enum AccountRequestErasureStatus {
    Accepted,
}

/// Acceptance confirmation of a self-initiated account erasure request. It
/// proves only that the intent is durably recorded; completion is observed
/// through the existing account-status read surface and physical completion
/// through the erasure receipt rail (account-lifecycle.md section 8).
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRequestErasureOutcome {
    pub request_id: RequestId,
    pub status: AccountRequestErasureStatus,
    pub principal_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub recorded_at: DateTime<Utc>,
    /// Present only when the deployment grants a withdrawal window; the
    /// Account Authority MUST NOT sign the `erasure_pending` AccountStatusRecord
    /// before this time, and once the record is signed no withdrawal is
    /// possible.
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub withdrawal_window_ends_at: Option<DateTime<Utc>>,
}

impl AccountRequestErasureOutcome {
    pub fn validate(&self) -> Result<()> {
        if self
            .withdrawal_window_ends_at
            .is_some_and(|ends_at| ends_at <= self.recorded_at)
        {
            return Err(WireError::Protocol(
                "erasure acceptance withdrawal window must end after recorded_at".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityBindingChallengeRequestBody {
    pub request_id: RequestId,
    pub identity_creation_lease_id: String,
    pub lease_fence: u64,
    pub did: Did,
    pub principal_registration_anchor: PrincipalRegistrationAnchor,
    pub pcr_realm_id: RealmId,
    pub realm_create_payload_digest: Hash,
    pub founding_authorize_payload_digest: Hash,
    pub initial_session_request_digest: Hash,
}

impl IdentityBindingChallengeRequestBody {
    pub fn canonical_request_digest(&self) -> Result<Hash> {
        self.principal_registration_anchor.validate()?;
        if &self.did != self.principal_registration_anchor.did() {
            return Err(WireError::Protocol(
                "identity creation did is not the registration anchor did".to_owned(),
            ));
        }
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
    pub principal_id: DidCoreId,
    pub did: Did,
}

impl DidBindingChallengeRequestBody {
    pub fn canonical_request_digest(&self) -> Result<Hash> {
        if project_did_to_core_id(&self.did)?.as_str() != self.principal_id.as_str() {
            return Err(WireError::Protocol(
                "published DID did does not project to principal_id".to_owned(),
            ));
        }
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
    pub principal_id: DidCoreId,
    pub did: Did,
    pub did_version_id: String,
    pub control_key_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_evidence: Option<String>,
    pub dpop_jkt: String,
    pub audience_id: DidCoreId,
    pub origin: WebOrigin,
    pub trust_domain: TrustDomainId,
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
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > chrono::Duration::seconds(300)
            || project_did_to_core_id(&self.did)?.as_str() != self.principal_id.as_str()
        {
            return Err(WireError::Protocol(
                "published-DID binding challenge violates the closed transcript".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountRegistrationControlProofKind {
    DidBoundSignature,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRegistrationControlProof {
    pub proof_kind: AccountRegistrationControlProofKind,
    pub challenge_id: String,
    pub challenge: String,
    pub purpose: DidBindingPurpose,
    pub request_canonical_digest: Hash,
    pub account_subject: Hash,
    pub principal_id: DidCoreId,
    pub did: Did,
    pub did_version_id: String,
    pub control_key_digest: Hash,
    pub dpop_jkt: String,
    pub audience_id: DidCoreId,
    pub origin: WebOrigin,
    pub trust_domain: TrustDomainId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub verification_method: DidUrl,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_evidence: Option<String>,
    pub signature: String,
}

impl AccountRegistrationControlProof {
    pub fn validate_shape(&self) -> Result<()> {
        let controller = self
            .verification_method
            .as_str()
            .split_once('#')
            .map(|(value, _)| value);
        if self.challenge.len() < 22
            || self.did_version_id.is_empty()
            || self.dpop_jkt.is_empty()
            || self.signature.is_empty()
            || self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > chrono::Duration::seconds(300)
            || project_did_to_core_id(&self.did)?.as_str() != self.principal_id.as_str()
            || controller != Some(self.did.as_str())
        {
            return Err(WireError::Protocol(
                "published DID registration control proof violates its closed transcript"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate_shape()?;
        let value = canonical::unsigned_value(self, &["signature"])?;
        let mut bytes = ACCOUNT_REGISTRATION_CONTROL_PROOF_DOMAIN
            .as_bytes()
            .to_vec();
        bytes.extend(canonical::canonical_json_bytes(&value)?);
        Ok(bytes)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PcrGenesisUnitKind {
    #[serde(rename = "ak.realm.create")]
    RealmCreate,
    #[serde(rename = "ak.device.authorize")]
    DeviceAuthorize,
}

pub const PCR_GENESIS_UNIT_KINDS: [PcrGenesisUnitKind; 2] = [
    PcrGenesisUnitKind::RealmCreate,
    PcrGenesisUnitKind::DeviceAuthorize,
];

/// The first sender-constrained Standard grant requested atomically with
/// account binding and PCR genesis.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum InitialSessionGrantOperation {
    #[serde(rename = "ak.self.account.read.describe.v1")]
    AccountReadDescribe,
    #[serde(rename = "ak.self.committed_event.read.scan.v1")]
    CommittedEventReadScan,
}

impl InitialSessionGrantOperation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AccountReadDescribe => ServiceOperationId::SELF_ACCOUNT_READ_DESCRIBE_V1,
            Self::CommittedEventReadScan => ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
        }
    }
}

pub const STANDARD_INITIAL_SESSION_GRANT_OPERATIONS: [InitialSessionGrantOperation; 2] = [
    InitialSessionGrantOperation::AccountReadDescribe,
    InitialSessionGrantOperation::CommittedEventReadScan,
];

pub fn standard_initial_session_grant_scope() -> Vec<String> {
    STANDARD_INITIAL_SESSION_GRANT_OPERATIONS
        .iter()
        .map(|operation| operation.as_str().to_owned())
        .collect()
}

pub const RECOVERY_SESSION_GRANT_OPERATIONS: [&str; 12] = [
    ServiceOperationId::ROOT_IDENTITY_LOG_READ_LIST_V1,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_POLICY_RESOURCE_GET_V1,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_CREATE_V1,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_COMMAND_SUBMIT_PROOF_V1,
    ServiceOperationId::ROOT_IDENTITY_RECOVERY_SESSION_RESOURCE_GET_V1,
    ServiceOperationId::SELF_COMMITTED_EVENT_READ_SCAN_V1,
    ServiceOperationId::SELF_KEYS_BACKUPS_COMMAND_UNLOCK_V1,
    ServiceOperationId::SELF_KEYS_BACKUPS_READ_LIST_V1,
    ServiceOperationId::SELF_KEYS_READ_LOOKUP_V1,
    ServiceOperationId::SELF_SECURITY_TRANSACTION_COMMAND_CONTINUE_V1,
    ServiceOperationId::SELF_SECURITY_TRANSACTION_COMMAND_CREATE_V1,
    ServiceOperationId::SELF_SECURITY_TRANSACTION_RESOURCE_GET_V1,
];

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialSessionGrantIntent {
    pub device_id: DeviceId,
    pub session_public_key: CanonicalSessionPublicJwk,
    pub audience_id: DidCoreId,
}

impl InitialSessionGrantIntent {
    pub fn validate(&self) -> Result<()> {
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

impl IdentityCreationControlProofKind {
    /// The registered `registration_anchor_kind` this derivation pairs with.
    /// A proof whose kind disagrees with its anchor fails closed rather than
    /// letting a caller choose which root-key derivation is checked.
    pub const fn registration_anchor_kind(self) -> &'static str {
        match self {
            Self::DidWebvhInceptionUpdateKey => crate::WEBVH_REGISTRATION_ANCHOR_KIND,
        }
    }
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
    pub principal_id: DidCoreId,
    pub did: Did,
    pub registration_anchor_digest: Hash,
    pub did_version_id: String,
    pub control_key_digest: Hash,
    pub pcr_realm_id: RealmId,
    pub realm_create_payload_digest: Hash,
    pub founding_authorize_payload_digest: Hash,
    pub initial_session_request_digest: Hash,
    pub genesis_unit_kinds: [PcrGenesisUnitKind; 2],
    pub identity_creation_lease_id: String,
    pub lease_fence: u64,
    pub dpop_jkt: String,
    pub audience_id: DidCoreId,
    pub origin: WebOrigin,
    pub trust_domain: TrustDomainId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub verification_key_multibase: String,
    pub signature_algorithm: DetachedSignatureAlgorithm,
    pub signature: String,
}

impl IdentityCreationControlProof {
    pub fn validate_shape(&self) -> Result<()> {
        validate_identity_creation_control_proof_body(&self.unsigned_body())?;
        let signature = arkret_canonical::base64url_decode(&self.signature)
            .map_err(|error| WireError::Protocol(error.to_string()))?;
        if signature.len() != 64 {
            return Err(WireError::Protocol(
                "identity creation control proof signature must be 64-byte Ed25519".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        identity_creation_control_proof_signing_bytes(&self.unsigned_body())
    }

    fn unsigned_body(&self) -> UnsignedIdentityCreationControlProofBody {
        UnsignedIdentityCreationControlProofBody {
            proof_kind: self.proof_kind,
            challenge_id: self.challenge_id.clone(),
            challenge: self.challenge.clone(),
            purpose: self.purpose,
            account_subject: self.account_subject.clone(),
            principal_id: self.principal_id.clone(),
            did: self.did.clone(),
            registration_anchor_digest: self.registration_anchor_digest.clone(),
            did_version_id: self.did_version_id.clone(),
            control_key_digest: self.control_key_digest.clone(),
            pcr_realm_id: self.pcr_realm_id.clone(),
            realm_create_payload_digest: self.realm_create_payload_digest.clone(),
            founding_authorize_payload_digest: self.founding_authorize_payload_digest.clone(),
            initial_session_request_digest: self.initial_session_request_digest.clone(),
            genesis_unit_kinds: self.genesis_unit_kinds,
            identity_creation_lease_id: self.identity_creation_lease_id.clone(),
            lease_fence: self.lease_fence,
            dpop_jkt: self.dpop_jkt.clone(),
            audience_id: self.audience_id.clone(),
            origin: self.origin.clone(),
            trust_domain: self.trust_domain.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            verification_key_multibase: self.verification_key_multibase.clone(),
            signature_algorithm: self.signature_algorithm,
        }
    }
}

/// Identity-creation control members before the cold-root signature exists.
#[derive(Clone, Debug)]
pub struct UnsignedIdentityCreationControlProofBody {
    pub proof_kind: IdentityCreationControlProofKind,
    pub challenge_id: String,
    pub challenge: String,
    pub purpose: IdentityBindingPurpose,
    pub account_subject: Hash,
    pub principal_id: DidCoreId,
    pub did: Did,
    pub registration_anchor_digest: Hash,
    pub did_version_id: String,
    pub control_key_digest: Hash,
    pub pcr_realm_id: RealmId,
    pub realm_create_payload_digest: Hash,
    pub founding_authorize_payload_digest: Hash,
    pub initial_session_request_digest: Hash,
    pub genesis_unit_kinds: [PcrGenesisUnitKind; 2],
    pub identity_creation_lease_id: String,
    pub lease_fence: u64,
    pub dpop_jkt: String,
    pub audience_id: DidCoreId,
    pub origin: WebOrigin,
    pub trust_domain: TrustDomainId,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub verification_key_multibase: String,
    pub signature_algorithm: DetachedSignatureAlgorithm,
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
            proof_kind: body.proof_kind,
            challenge_id: body.challenge_id,
            challenge: body.challenge,
            purpose: body.purpose,
            account_subject: body.account_subject,
            principal_id: body.principal_id,
            did: body.did,
            registration_anchor_digest: body.registration_anchor_digest,
            did_version_id: body.did_version_id,
            control_key_digest: body.control_key_digest,
            pcr_realm_id: body.pcr_realm_id,
            realm_create_payload_digest: body.realm_create_payload_digest,
            founding_authorize_payload_digest: body.founding_authorize_payload_digest,
            initial_session_request_digest: body.initial_session_request_digest,
            genesis_unit_kinds: body.genesis_unit_kinds,
            identity_creation_lease_id: body.identity_creation_lease_id,
            lease_fence: body.lease_fence,
            dpop_jkt: body.dpop_jkt,
            audience_id: body.audience_id,
            origin: body.origin,
            trust_domain: body.trust_domain,
            issued_at: body.issued_at,
            expires_at: body.expires_at,
            verification_key_multibase: body.verification_key_multibase,
            signature_algorithm: body.signature_algorithm,
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
        || body.signature_algorithm != DetachedSignatureAlgorithm::Ed25519
        || project_did_to_core_id(&body.did)?.as_str() != body.principal_id.as_str()
    {
        return Err(WireError::Protocol(
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
        "proof_kind": body.proof_kind,
        "challenge_id": &body.challenge_id,
        "challenge": &body.challenge,
        "purpose": body.purpose,
        "account_subject": &body.account_subject,
        "principal_id": &body.principal_id,
        "did": &body.did,
        "registration_anchor_digest": &body.registration_anchor_digest,
        "did_version_id": &body.did_version_id,
        "control_key_digest": &body.control_key_digest,
        "pcr_realm_id": &body.pcr_realm_id,
        "realm_create_payload_digest": &body.realm_create_payload_digest,
        "founding_authorize_payload_digest": &body.founding_authorize_payload_digest,
        "initial_session_request_digest": &body.initial_session_request_digest,
        "genesis_unit_kinds": body.genesis_unit_kinds,
        "identity_creation_lease_id": &body.identity_creation_lease_id,
        "lease_fence": body.lease_fence,
        "dpop_jkt": &body.dpop_jkt,
        "audience_id": &body.audience_id,
        "origin": &body.origin,
        "trust_domain": &body.trust_domain,
        "issued_at": canonical::format_timestamp_canonical(body.issued_at),
        "expires_at": canonical::format_timestamp_canonical(body.expires_at),
        "verification_key_multibase": &body.verification_key_multibase,
        "signature_algorithm": body.signature_algorithm,
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
    pub did: Did,
    pub principal_registration_anchor: PrincipalRegistrationAnchor,
    pub registration_did_evidence_draft: arkret_wire::RegistrationDidEvidenceDraft,
    pub control_proof: IdentityCreationControlProof,
    pub pcr_genesis_unit: PcrGenesisUnit,
    pub initial_session: InitialSessionGrantIntent,
}

impl IdentityCreationRegistration {
    pub fn validate(&self) -> Result<()> {
        self.control_proof.validate_shape()?;
        self.principal_registration_anchor.validate()?;
        self.registration_did_evidence_draft.validate_shape()?;
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
            || &self.did != self.principal_registration_anchor.did()
            || self.control_proof.proof_kind.registration_anchor_kind()
                != self.principal_registration_anchor.anchor_kind()
            || self.did != self.control_proof.did
            || self.registration_did_evidence_draft.principal_id != self.control_proof.principal_id
            || self.registration_did_evidence_draft.did != self.did
            || self.registration_did_evidence_draft.version_id != self.control_proof.did_version_id
            || self.registration_did_evidence_draft.method_history_head
                != self
                    .principal_registration_anchor
                    .declared_method_history_head()?
                    .as_str()
            || self.registration_did_evidence_draft.control_key_digest
                != self.control_proof.control_key_digest
            || project_did_to_core_id(&self.did)?.as_str()
                != self.control_proof.principal_id.as_str()
            || self.principal_registration_anchor.canonical_digest()?
                != self.control_proof.registration_anchor_digest
            || self
                .pcr_genesis_unit
                .create()
                .actor_id
                .signing_principal_id()
                != &self.control_proof.principal_id
            || self.pcr_genesis_unit.create().realm_id != self.control_proof.pcr_realm_id
            || Hash::new(canonical::canonical_sha256(
                &self.pcr_genesis_unit.create().payload,
            )?)? != self.control_proof.realm_create_payload_digest
            || Hash::new(canonical::canonical_sha256(
                &self.pcr_genesis_unit.founding_authorize().payload,
            )?)? != self.control_proof.founding_authorize_payload_digest
        {
            return Err(WireError::Protocol(
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
            return Err(WireError::Protocol(
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
pub enum AccountBindingKind {
    PublishedDid,
    IdentityCreation,
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
    pub binding_kind: AccountBindingKind,
    pub account_authority_id: DidCoreId,
    pub account_subject: Hash,
    pub principal_id: DidCoreId,
    pub did: Did,
    pub did_version_id: String,
    pub control_key_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_creation_lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_fence: Option<u64>,
    pub operation_status: IdentityCreationOperationStatus,
    pub registration_anchor_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    pub proof: PayloadProof,
}

#[derive(Serialize)]
struct AccountBindingReceiptPayload<'a> {
    binding_state: AccountBindingState,
    binding_kind: AccountBindingKind,
    account_authority_id: &'a DidCoreId,
    account_subject: &'a Hash,
    principal_id: &'a DidCoreId,
    did: &'a Did,
    did_version_id: &'a str,
    control_key_digest: &'a Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_creation_lease_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lease_fence: Option<u64>,
    operation_status: IdentityCreationOperationStatus,
    registration_anchor_digest: &'a Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    issued_at: DateTime<Utc>,
}

#[derive(Serialize)]
struct AccountBindingReceiptProofBinding<'a> {
    context: &'static str,
    payload_digest: &'a Hash,
    account_authority_id: &'a DidCoreId,
    account_subject: &'a Hash,
    principal_id: &'a DidCoreId,
    did: &'a Did,
    did_version_id: &'a str,
    control_key_digest: &'a Hash,
    verification_method: &'a DidUrl,
    created_at: String,
}

impl AccountBindingReceipt {
    pub fn canonical_payload_digest(&self) -> Result<Hash> {
        let payload = AccountBindingReceiptPayload {
            binding_state: self.binding_state,
            binding_kind: self.binding_kind,
            account_authority_id: &self.account_authority_id,
            account_subject: &self.account_subject,
            principal_id: &self.principal_id,
            did: &self.did,
            did_version_id: &self.did_version_id,
            control_key_digest: &self.control_key_digest,
            identity_creation_lease_id: self.identity_creation_lease_id.as_deref(),
            lease_fence: self.lease_fence,
            operation_status: self.operation_status,
            registration_anchor_digest: &self.registration_anchor_digest,
            issued_at: self.issued_at,
        };
        Hash::new(canonical::canonical_sha256(&payload)?).map_err(Into::into)
    }

    pub fn validate_shape(&self) -> Result<()> {
        self.proof.validate_production()?;
        self.validate_proof_binding_fields()
    }

    fn validate_proof_binding_fields(&self) -> Result<()> {
        self.proof.unsigned().validate_production()?;
        let proof_controller = self
            .proof
            .verification_method
            .as_str()
            .split_once('#')
            .map(|(controller, _)| controller)
            .ok_or_else(|| {
                WireError::Protocol(
                    "account binding receipt verification_method requires a fragment".to_owned(),
                )
            })?;
        let proof_controller = project_did_to_core_id(&Did::new(proof_controller.to_owned())?)?;
        let branch_valid = match self.binding_kind {
            AccountBindingKind::PublishedDid => {
                self.identity_creation_lease_id.is_none() && self.lease_fence.is_none()
            }
            AccountBindingKind::IdentityCreation => {
                self.identity_creation_lease_id
                    .as_ref()
                    .is_some_and(|value| !value.is_empty())
                    && self.lease_fence.is_some_and(|value| value > 0)
            }
        };
        if !branch_valid
            || self.did_version_id.is_empty()
            || project_did_to_core_id(&self.did)?.as_str() != self.principal_id.as_str()
            || self.proof.created_at != self.issued_at
            || self.proof.payload_digest != self.canonical_payload_digest()?
            || proof_controller != self.account_authority_id
        {
            return Err(WireError::Protocol(
                "account binding receipt proof does not bind the complete receipt".to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical detached-JWS binding object for the Account Authority proof.
    pub fn canonical_proof_binding_bytes(&self) -> Result<Vec<u8>> {
        // The binding bytes are needed before the detached JWS exists. Validate
        // the fully typed unsigned proof metadata and every receipt binding,
        // but deliberately do not require the final signature at this stage.
        self.validate_proof_binding_fields()?;
        canonical::canonical_json_bytes(&AccountBindingReceiptProofBinding {
            context: arkret_wire::ProofContextId::ACCOUNT_BINDING_RECEIPT_PROOF_V1,
            payload_digest: &self.proof.payload_digest,
            account_authority_id: &self.account_authority_id,
            account_subject: &self.account_subject,
            principal_id: &self.principal_id,
            did: &self.did,
            did_version_id: &self.did_version_id,
            control_key_digest: &self.control_key_digest,
            verification_method: &self.proof.verification_method,
            created_at: canonical::format_timestamp_canonical(self.proof.created_at),
        })
        .map_err(Into::into)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountUpdateProfileOutcome {
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub profile: crate::actor_profile::AccountMaterializedProfile,
    /// The exact RealmCommit covering the submitted profile Event.
    #[cfg_attr(feature = "openapi", salvo(schema(value_type = serde_json::Value)))]
    pub commit: arkret_wire::RealmCommit,
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
    fn identity_creation_control_signature_covers_algorithm_and_excludes_signature() {
        let value = json!({
            "proof_kind": "did_webvh_inception_update_key",
            "challenge_id": "challenge-identity-creation-1",
            "challenge": "challenge-material-0123456789",
            "purpose": "account_binding_and_pcr_genesis",
            "account_subject": format!("sha256:{}", "1".repeat(64)),
            "principal_id": "ak:did_core:web:alice.example",
            "did": "did:web:alice.example",
            "registration_anchor_digest": format!("sha256:{}", "2".repeat(64)),
            "did_version_id": "1-fixture",
            "control_key_digest": format!("sha256:{}", "3".repeat(64)),
            "pcr_realm_id": "ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19",
            "realm_create_payload_digest": format!("sha256:{}", "4".repeat(64)),
            "founding_authorize_payload_digest": format!("sha256:{}", "5".repeat(64)),
            "initial_session_request_digest": format!("sha256:{}", "6".repeat(64)),
            "genesis_unit_kinds": ["ak.realm.create", "ak.device.authorize"],
            "identity_creation_lease_id": "lease-identity-creation-1",
            "lease_fence": 1,
            "dpop_jkt": "A".repeat(43),
            "audience_id": "ak:did_core:web:authority.example",
            "origin": "https://client.example",
            "trust_domain": "ak:trust_domain:example.net",
            "issued_at": "2026-09-19T00:00:00.000Z",
            "expires_at": "2026-09-19T00:05:00.000Z",
            "verification_key_multibase": "z6Mkh6h1dMiHWPXNm45oJZhVjZVZJHhZ8cQSRg2WQ2Yh8wXH",
            "signature_algorithm": "Ed25519",
            "signature": "A".repeat(86)
        });
        let proof: IdentityCreationControlProof = serde_json::from_value(value.clone()).unwrap();
        proof.validate_shape().unwrap();
        let signing_bytes = String::from_utf8(proof.canonical_signing_bytes().unwrap()).unwrap();
        assert!(signing_bytes.starts_with(IDENTITY_CREATION_CONTROL_PROOF_DOMAIN));
        assert!(signing_bytes.contains("\"signature_algorithm\":\"Ed25519\""));
        assert!(!signing_bytes.contains("\"signature\":"));

        let mut missing_algorithm = value;
        missing_algorithm
            .as_object_mut()
            .unwrap()
            .remove("signature_algorithm");
        assert!(serde_json::from_value::<IdentityCreationControlProof>(missing_algorithm).is_err());
    }

    #[test]
    fn cas_conflict_details_preserve_revision_without_live_entry() {
        let details: AccountDataCasConflict = serde_json::from_value(json!({
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
            serde_json::from_value::<AccountDataCasConflict>(json!({
                "account_data_key": "ak.client.ui_state",
                "current_revision": 7,
                "expected_revision": 6
            }))
            .is_err()
        );
    }

    #[test]
    fn verified_device_summary_requires_exact_authorization_provenance() {
        let mut value = json!({
            "device_id": "ak:device:0196419b-0000-7000-8000-000000000001",
            "status": "active",
            "verification_state": "verified",
            "verification_source": "pairing_code"
        });
        let summary: AccountDeviceSummary = serde_json::from_value(value.clone()).unwrap();
        assert!(summary.validate().is_err());

        value["authorized_event_ref"] =
            json!("ak:event:AfAnsJqSlM9bHVI7P1QBMOEW3p5P1PNQu7BBMpiSnD_e");
        let summary: AccountDeviceSummary = serde_json::from_value(value.clone()).unwrap();
        summary.validate().unwrap();

        let mut retired = value.clone();
        retired["signer_resolution_evidence_ref"] =
            json!(format!("ak:signer_evidence:sha256:{}", "a".repeat(64)));
        assert!(serde_json::from_value::<AccountDeviceSummary>(retired).is_err());
        value["authorization_ref"] = json!("retired");
        assert!(serde_json::from_value::<AccountDeviceSummary>(value).is_err());
    }
}

#[cfg(test)]
mod account_handoff_tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn account_binding_receipt_signing_transcript_accepts_unsigned_typed_proof_only() {
        let now = Utc::now();
        let authority_did = Did::new("did:webvh:z6mkaccountauthority:auth.example").unwrap();
        let authority_core_id = project_did_to_core_id(&authority_did).unwrap();
        let principal_did = Did::new("did:webvh:z6mkprincipal:example.com").unwrap();
        let principal_core_id = project_did_to_core_id(&principal_did).unwrap();
        let mut receipt = AccountBindingReceipt {
            binding_state: AccountBindingState::Bound,
            binding_kind: AccountBindingKind::IdentityCreation,
            account_authority_id: authority_core_id,
            account_subject: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            principal_id: principal_core_id,
            did: principal_did,
            did_version_id: "1-fixture".to_owned(),
            control_key_digest: Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap(),
            identity_creation_lease_id: Some("lease-fixture".to_owned()),
            lease_fence: Some(1),
            operation_status: IdentityCreationOperationStatus::Accepted,
            registration_anchor_digest: Hash::new(format!("sha256:{}", "c".repeat(64))).unwrap(),
            issued_at: now,
            proof: PayloadProof {
                kind: arkret_wire::proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new(
                    "did:webvh:z6mkaccountauthority:auth.example#service-key-1".to_owned(),
                )
                .unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: now,
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: String::new(),
            },
        };
        receipt.proof.payload_digest = receipt.canonical_payload_digest().unwrap();

        receipt.canonical_proof_binding_bytes().unwrap();
        assert!(receipt.validate_shape().is_err());
    }

    fn handoff_request() -> AccountHandoffRequestBody {
        AccountHandoffRequestBody {
            request_id: RequestId::new("ak:request:019b0000-0000-7000-8000-000000000001").unwrap(),
            proof: AccountHandoffAuthenticationProof {
                proof_kind: AccountHandoffAuthenticationProofKind::OidcCodeExchange,
                challenge: "challenge-0123456789".to_owned(),
                request_canonical_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                audience_id: DidCoreId::new("ak:did_core:webvh:z6mkfixture").unwrap(),
                issuer_uri: "https://auth.example".to_owned(),
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

    #[test]
    fn identity_creation_lease_state_is_the_closed_onboarding_authority() {
        let mut lease = IdentityCreationLease {
            identity_creation_lease_id: "lease-fixture".to_owned(),
            fence: 1,
            state: IdentityCreationLeaseState::Active,
            expires_at: Utc::now() + chrono::Duration::minutes(15),
            reserved_identity: None,
        };
        lease.validate().unwrap();
        assert_eq!(
            lease.allowed_goals(),
            &[IdentityCreationGoal::CompleteIdentity]
        );

        lease.state = IdentityCreationLeaseState::Reserved;
        assert!(lease.validate().is_err());
    }

    #[test]
    fn pcr_acceptance_removes_the_provisional_abandonment_goal() {
        let lease = IdentityCreationLease {
            identity_creation_lease_id: "lease-fixture".to_owned(),
            fence: 1,
            state: IdentityCreationLeaseState::PcrAccepted,
            expires_at: Utc::now() + chrono::Duration::minutes(15),
            reserved_identity: None,
        };
        assert_eq!(
            lease.allowed_goals(),
            &[IdentityCreationGoal::CompleteIdentity]
        );
        assert!(
            lease
                .required_local_artifacts(IdentityCreationGoal::AbandonProvisionalIdentity)
                .is_err()
        );
    }

    #[test]
    fn onboarding_state_is_a_closed_server_goal_projection() {
        let did = Did::new("did:webvh:z6mkfixture:example.com").unwrap();
        let snapshot = AccountOnboardingState {
            handoff_request_id: handoff_request().request_id,
            account_subject: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            observed_at: Utc::now(),
            binding: AccountHandoffBinding::Bound {
                principal_id: project_did_to_core_id(&did).unwrap(),
                did,
            },
            goal: AccountOnboardingGoal::CompleteIdentity,
        };

        snapshot.validate().unwrap();
        let wire = serde_json::to_value(snapshot).unwrap();
        assert_eq!(wire["goal"]["goal"], "complete_identity");
        assert!(wire["binding"]["did"].is_string());
    }

    #[test]
    fn bound_onboarding_rejects_a_core_and_did_mismatch() {
        let alice = Did::new("did:webvh:z6mkalice:alice.example").unwrap();
        let snapshot = AccountOnboardingState {
            handoff_request_id: handoff_request().request_id,
            account_subject: Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap(),
            observed_at: Utc::now(),
            binding: AccountHandoffBinding::Bound {
                principal_id: project_did_to_core_id(&alice).unwrap(),
                did: Did::new("did:webvh:z6mkbob:bob.example").unwrap(),
            },
            goal: AccountOnboardingGoal::CompleteIdentity,
        };

        let error = snapshot.validate().unwrap_err();
        assert!(error.to_string().contains("does not project"));
    }

    /// `account-lifecycle.md` section 8.1 says the acceptance outcome omits
    /// `withdrawal_window_ends_at` when the deployment grants no withdrawal
    /// window, and the schema keeps it out of `required`. The type must
    /// therefore round-trip a response that leaves the field out.
    #[test]
    fn acceptance_outcome_round_trips_without_a_withdrawal_window() {
        let outcome = AccountRequestErasureOutcome {
            request_id: RequestId::new("ak:request:0196419b-0000-7000-8000-00000000000a").unwrap(),
            status: AccountRequestErasureStatus::Accepted,
            principal_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            // Canonical timestamps carry millisecond precision, so the
            // fixture is pinned to a whole millisecond: a `now()` with
            // sub-millisecond digits would fail the round-trip on the
            // serializer's truncation rather than on the field's optionality.
            recorded_at: DateTime::from_timestamp_millis(1_775_000_000_000).unwrap(),
            withdrawal_window_ends_at: None,
        };
        outcome.validate().unwrap();
        let wire = serde_json::to_value(&outcome).unwrap();
        assert!(wire.get("withdrawal_window_ends_at").is_none());
        let parsed: AccountRequestErasureOutcome = serde_json::from_value(wire).unwrap();
        assert_eq!(parsed, outcome);
    }

    /// A window that does not end after `recorded_at` grants nothing, so it is
    /// a malformed acceptance rather than a zero-length window.
    #[test]
    fn acceptance_outcome_rejects_a_window_that_does_not_outlast_recording() {
        let recorded_at = DateTime::from_timestamp_millis(1_775_000_000_000).unwrap();
        let outcome = AccountRequestErasureOutcome {
            request_id: RequestId::new("ak:request:0196419b-0000-7000-8000-00000000000b").unwrap(),
            status: AccountRequestErasureStatus::Accepted,
            principal_id: DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            recorded_at,
            withdrawal_window_ends_at: Some(recorded_at),
        };
        outcome.validate().unwrap_err();
    }

    #[test]
    fn public_progress_never_implies_recovery_key_possession_or_user_memory() {
        for state in [
            IdentityCreationRecoveryKeyState::Unavailable,
            IdentityCreationRecoveryKeyState::GeneratedPendingConfirmation,
            IdentityCreationRecoveryKeyState::RecoveredPendingConfirmation,
        ] {
            assert!(!state.can_control_identity());
        }
        assert!(
            IdentityCreationRecoveryKeyState::GeneratedLocallyValidatedDurable
                .can_control_identity()
        );
        assert!(IdentityCreationRecoveryKeyState::ExistingValidatedDurable.can_control_identity());
    }
}

pub const ACCOUNT_LIFECYCLE_PROOF_SCHEMA: &str = SchemaId::ACCOUNT_OPERATIONS_V1;

/// Closed authorization factor set for the account lifecycle commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountLifecycleProofKind {
    DidBoundSignature,
    PairedDeviceProof,
    PasskeyAssertion,
    OidcCodeExchange,
    AgentKeyProof,
}

// Field declaration order is byte-for-byte the properties order of
// account-operations.schema.json#/$defs/account_lifecycle_proof.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountLifecycleProof {
    pub proof_kind: AccountLifecycleProofKind,
    pub challenge: String,
    pub request_canonical_digest: Hash,
    pub audience_id: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<DidUrl>,
    pub signature: String,
}

/// Maximum issued lifetime of an account lifecycle proof, in seconds.
pub const ACCOUNT_LIFECYCLE_PROOF_MAX_LIFETIME_SECONDS: i64 = 15 * 60;

/// Applet selector bound into the session-revoke request digest. It is not a
/// standalone wire object: `session_revoke_request_body` inlines these members
/// under `dependentRequired`, and this grouping keeps the digest transcript and
/// the request body from drifting apart.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SessionGrantAppletSelector {
    pub applet_id: AppletId,
    pub effective_scope: ScopeRef,
    pub registration_epoch: Hash,
    pub service_id: DidCoreId,
    pub capability_grant_refs: Vec<String>,
    pub expected_inventory_digest: Hash,
}

impl AccountLifecycleProof {
    #[allow(clippy::too_many_arguments)]
    pub fn session_revoke_request_digest(
        actor_id: &DidCoreId,
        service_id: &DidCoreId,
        session_device_id: &DeviceId,
        target_session_grant_id: Option<&SessionGrantId>,
        target_device_id: Option<&DeviceId>,
        all_sessions: bool,
        applet_selector: Option<&SessionGrantAppletSelector>,
    ) -> Result<Hash> {
        let request = json!({
            "schema": SchemaId::ACCOUNT_OPERATIONS_V1,
            "operation": ServiceOperationId::GATE_ACCOUNT_COMMAND_REVOKE_SESSION_V1,
            "actor_id": actor_id,
            "service_id": service_id,
            "session_device_id": session_device_id,
            "target_session_grant_id": target_session_grant_id,
            "target_device_id": target_device_id,
            "all_sessions": all_sessions,
            "applet_selector": applet_selector,
        });
        Ok(Hash::new(canonical::canonical_sha256(&request)?)?)
    }

    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        let signing_input = json!({
            "schema": ACCOUNT_LIFECYCLE_PROOF_SCHEMA,
            "proof_kind": &self.proof_kind,
            "challenge": &self.challenge,
            "request_canonical_digest": &self.request_canonical_digest,
            "audience_id": &self.audience_id,
            "issued_at": arkret_canonical::format_timestamp_canonical(self.issued_at),
            "expires_at": arkret_canonical::format_timestamp_canonical(self.expires_at),
            "verification_method": &self.verification_method,
        });
        Ok(canonical::canonical_json_bytes(&signing_input)?)
    }

    pub fn validate_shape(&self) -> Result<()> {
        if self.challenge.chars().count() < 16 {
            return Err(WireError::Protocol(
                "account lifecycle proof challenge is too short".to_owned(),
            ));
        }
        if self.signature.is_empty() {
            return Err(WireError::Protocol(
                "account lifecycle proof requires a signature".to_owned(),
            ));
        }
        if self.expires_at <= self.issued_at
            || (self.expires_at - self.issued_at).num_seconds()
                > ACCOUNT_LIFECYCLE_PROOF_MAX_LIFETIME_SECONDS
        {
            return Err(WireError::Protocol(
                "account lifecycle proof lifetime exceeds the 15 minute ceiling".to_owned(),
            ));
        }
        Ok(())
    }
}
