use arkret_wire::{
    DeviceId, Did, Error, EventId, Hash, RequestId, Result, TypedTrustDomainId, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::actor_profile::ActorProfile;
use crate::handle::Handle;
use crate::identity::DidOperationSubmitRequestBody;

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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountDataReplaceRequestBody {
    pub expected_revision: u64,
    pub content: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountDataRow {
    pub account_data_key: String,
    pub revision: u64,
    pub content: Value,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
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
    pub status: String,
    /// device-lifecycle.md §6 trust dimension: `unverified` / `cross_signed`
    /// / `needs_reverification` / `verified`. Distinct from `status`, which is
    /// the lifecycle rollup (`active` / `revoked` / `unknown`). Clients render
    /// the §6 trust pill and gate device-to-device pairing fan-out on it.
    pub verification_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorized_event_ref: Option<EventId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub authorized_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub last_seen_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
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
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("account handoff proof serializes as an object")
            .remove("signature");
        let mut bytes = ACCOUNT_HANDOFF_AUTHENTICATION_PROOF_DOMAIN
            .as_bytes()
            .to_vec();
        bytes.extend(canonical::canonical_json_bytes(&value)?);
        Ok(bytes)
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
        let mut value = serde_json::to_value(self)?;
        let proof = value
            .as_object_mut()
            .and_then(|object| object.get_mut("proof"))
            .and_then(Value::as_object_mut)
            .expect("account handoff request proof serializes as an object");
        proof.remove("request_canonical_digest");
        proof.remove("signature");
        Hash::new(canonical::canonical_sha256(&value)?).map_err(Into::into)
    }
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
}

pub const ACCOUNT_HANDOFF_ALLOWED_OPERATIONS: [AccountHandoffAllowedOperation; 3] = [
    AccountHandoffAllowedOperation::IssueIdentityBindingChallenge,
    AccountHandoffAllowedOperation::Register,
    AccountHandoffAllowedOperation::IssueSessionGrant,
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
    pub lease_id: String,
    pub fence: u64,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
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
    pub account_handoff_grant: String,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    pub allowed_operations: [AccountHandoffAllowedOperation; 3],
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
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityBindingChallengeRequestBody {
    pub request_id: RequestId,
    pub lease_id: String,
    pub lease_fence: u64,
    pub did_operation: DidOperationSubmitRequestBody,
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
    AccountBinding,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityBindingChallengeOutcome {
    pub request_id: RequestId,
    pub challenge_id: String,
    pub challenge: String,
    pub purpose: IdentityBindingPurpose,
    pub principal_id: Did,
    pub operation_digest: Hash,
    pub lease_id: String,
    pub lease_fence: u64,
    pub dpop_jkt: String,
    pub audience: Did,
    pub origin: String,
    pub trust_domain: TypedTrustDomainId,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub issued_at: DateTime<Utc>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
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
    pub principal_id: Did,
    pub operation_digest: Hash,
    pub lease_id: String,
    pub lease_fence: u64,
    pub dpop_jkt: String,
    pub audience: Did,
    pub origin: String,
    pub trust_domain: TypedTrustDomainId,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub issued_at: DateTime<Utc>,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub expires_at: DateTime<Utc>,
    pub verification_key_multibase: String,
    pub signature: String,
}

impl IdentityCreationControlProof {
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("identity creation proof serializes as an object")
            .remove("signature");
        let mut bytes = IDENTITY_CREATION_CONTROL_PROOF_DOMAIN.as_bytes().to_vec();
        bytes.extend(canonical::canonical_json_bytes(&value)?);
        Ok(bytes)
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityCreationRegistration {
    pub lease_id: String,
    pub lease_fence: u64,
    pub did_operation: DidOperationSubmitRequestBody,
    pub control_proof: IdentityCreationControlProof,
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
    pub lease_id: String,
    pub lease_fence: u64,
    pub operation_status: IdentityCreationOperationStatus,
    pub operation_digest: Hash,
    pub head_event_digest: Hash,
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
    pub reason_code: String,
    #[serde(default = "default_cursor_revoke_scope")]
    pub revoke_scope: CursorRevokeScope,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountCursorRevokeOutcome {
    pub revoked: bool,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
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
            account_handoff_grant: "g".repeat(32),
            expires_at: Utc::now(),
            allowed_operations: ACCOUNT_HANDOFF_ALLOWED_OPERATIONS,
            binding: AccountHandoffBinding::IdentityCreationBusy { retry_after_ms: 1 },
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
            account_handoff_grant: "g".repeat(32),
            expires_at: Utc::now(),
            allowed_operations: ACCOUNT_HANDOFF_ALLOWED_OPERATIONS,
            binding: AccountHandoffBinding::IdentityCreationBusy { retry_after_ms: 1 },
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
}
