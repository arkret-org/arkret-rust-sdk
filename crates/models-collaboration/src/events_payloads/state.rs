//! Generic state event payloads.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use arkret_wire::{DidCoreId, DidFullId, TrustDomainId, validate_canonical_idna_domain};

use crate::governance::operation_wire::Policy;
use crate::internal_prelude::*;

fn schema_violation<T>(message: impl Into<String>) -> Result<T> {
    Err(Error::Protocol(format!(
        "schema_violation: {}",
        message.into()
    )))
}

macro_rules! validated_string_newtype {
    ($name:ident, $validator:ident, $message:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if !$validator(&value) {
                    return schema_violation($message);
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

fn reducer_profile_id_is_valid(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ak.reducer") else {
        return false;
    };
    let Some((namespace, version)) = rest.rsplit_once(".v") else {
        return false;
    };
    if version.is_empty() || !version.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    namespace.is_empty()
        || namespace.strip_prefix('.').is_some_and(|name| {
            name.bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                && name.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'_' | b'.' | b'-')
                })
        })
}

fn policy_rule_id_is_valid(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

validated_string_newtype!(
    ReducerProfileId,
    reducer_profile_id_is_valid,
    "invalid reducer profile id"
);
validated_string_newtype!(
    PolicyRuleId,
    policy_rule_id_is_valid,
    "invalid policy rule id"
);

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/state_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatePayload {
    /// Spec-declared open state value. `state` is lifecycle metadata and does
    /// not discriminate this value's shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Counterpart for `event-payload.schema.json#/$defs/realm_upgrade_state_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmUpgradeStatePayload {
    pub target_reducer_profile: ReducerProfileId,
}

macro_rules! state_payload_with_subject {
    ($name:ident, $field:ident, $field_type:ty) => {
        #[derive(Clone, Debug, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $name {
            pub $field: $field_type,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub value: Option<Value>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub state: Option<String>,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            pub reason: Option<String>,
        }
    };
}

state_payload_with_subject!(
    OrganizationDiscoveryStatePayload,
    organization_principal_id,
    DidFullId
);
state_payload_with_subject!(ResourceDiscoveryStatePayload, resource_id, NonEmptyString);
state_payload_with_subject!(DidProofStatePayload, did, DidFullId);
state_payload_with_subject!(PolicyRuleStatePayload, rule_id, PolicyRuleId);
state_payload_with_subject!(SovereignDidPolicyStatePayload, trust_domain, TrustDomainId);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityPresentationClaimRequest {
    pub claim_kind: NonEmptyString,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub constraints: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<NonEmptyString>,
    pub disclosure: IdentityDisclosureMode,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityPresentationRequestDocument {
    pub verifier_service_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub represented_org: Option<DidCoreId>,
    pub domain: String,
    pub challenge: NonEmptyString,
    pub purpose: NonEmptyString,
    pub accepted_issuers: Vec<DidCoreId>,
    pub required_claims: Vec<IdentityPresentationClaimRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub optional_claims: Vec<IdentityPresentationClaimRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_claims: Vec<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transport_hints: Vec<IdentityDisclosureTransport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityPresentationRequestStatePayload {
    pub request_id: RequestId,
    pub value: IdentityPresentationRequestDocument,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityPresentationResponseDocument {
    pub holder_subject: DidCoreId,
    pub proof_profile: IdentityDisclosureProofProfile,
    pub presentation: BTreeMap<String, Value>,
    pub disclosed_fields: Vec<NonEmptyString>,
    pub presentation_digest: Hash,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityPresentationResponseStatePayload {
    pub request_id: RequestId,
    pub request_digest: Hash,
    pub value: IdentityPresentationResponseDocument,
}

fn values_are_unique<T: Ord>(values: &[T]) -> bool {
    let mut seen = BTreeSet::new();
    values.iter().all(|value| seen.insert(value))
}

/// The immutable public-key tuple selected by the Realm organization-recovery
/// key cell.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationRecoveryKeyTuple {
    pub recovery_key_id: String,
    pub holder_principal_id: DidCoreId,
    pub holder_service_id: DidCoreId,
    pub key_agreement_ref: DidUrl,
    pub holder_signing_ref: DidUrl,
    pub hpke_suite: OrganizationRecoveryHpkeSuite,
    pub frozen_public_key_b64u: String,
}

impl OrganizationRecoveryKeyTuple {
    pub fn validate(&self) -> Result<()> {
        organization_recovery::validate_recovery_key_id(&self.recovery_key_id)?;
        organization_recovery::validate_frozen_x25519_public_key(&self.frozen_public_key_b64u)
    }
}

/// Holder-signed acceptance of one organization-recovery key tuple.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationRecoveryHolderAcceptance {
    pub realm_id: RealmId,
    pub new_key_tuple: OrganizationRecoveryKeyTuple,
    pub holder_trusted_basis: SealBasis,
    pub holder_proof: PayloadProof,
}

impl OrganizationRecoveryHolderAcceptance {
    pub fn validate(&self) -> Result<()> {
        self.new_key_tuple.validate()?;
        self.holder_trusted_basis.validate_protocol_bounds()?;
        self.holder_proof.validate()?;
        if self.holder_proof.verification_method != self.new_key_tuple.holder_signing_ref {
            return schema_violation(
                "organization recovery holder proof must use holder_signing_ref",
            );
        }
        Ok(())
    }
}

/// Initial create-once registration of the Realm organization-recovery key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationRecoveryKeyRegisterPayload {
    pub realm_id: RealmId,
    pub new_key_tuple: OrganizationRecoveryKeyTuple,
    pub holder_trusted_basis: SealBasis,
    pub holder_acceptance: OrganizationRecoveryHolderAcceptance,
}

impl OrganizationRecoveryKeyRegisterPayload {
    pub fn validate(&self) -> Result<()> {
        self.new_key_tuple.validate()?;
        self.holder_trusted_basis.validate_protocol_bounds()?;
        self.holder_acceptance.validate()?;
        if self.holder_acceptance.realm_id != self.realm_id
            || self.holder_acceptance.new_key_tuple != self.new_key_tuple
            || self.holder_acceptance.holder_trusted_basis != self.holder_trusted_basis
        {
            return schema_violation(
                "organization recovery holder acceptance must duplicate the registered tuple and basis exactly",
            );
        }
        Ok(())
    }
}

/// CAS rotation of the active Realm organization-recovery key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationRecoveryKeyRotatePayload {
    pub realm_id: RealmId,
    pub expected_previous_key_evidence_ref: EventId,
    pub expected_previous_key_evidence_seal_ref: SealId,
    pub new_key_tuple: OrganizationRecoveryKeyTuple,
    pub holder_trusted_basis: SealBasis,
    pub holder_acceptance: OrganizationRecoveryHolderAcceptance,
}

impl OrganizationRecoveryKeyRotatePayload {
    pub fn validate(&self) -> Result<()> {
        self.new_key_tuple.validate()?;
        self.holder_trusted_basis.validate_protocol_bounds()?;
        self.holder_acceptance.validate()?;
        if self.holder_acceptance.realm_id != self.realm_id
            || self.holder_acceptance.new_key_tuple != self.new_key_tuple
            || self.holder_acceptance.holder_trusted_basis != self.holder_trusted_basis
        {
            return schema_violation(
                "organization recovery holder acceptance must duplicate the rotated tuple and basis exactly",
            );
        }
        Ok(())
    }
}

fn schema_definition_id_is_valid(value: &str) -> bool {
    let Some(body) = value.strip_prefix("ak.schema.") else {
        return false;
    };
    let Some((name, version)) = body.rsplit_once(".v") else {
        return false;
    };
    !name.is_empty()
        && name.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
        && !version.is_empty()
        && version.bytes().all(|byte| byte.is_ascii_digit())
}

fn claim_constraint_name_is_valid(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn policy_action_name_is_valid(value: &str) -> bool {
    let Some(body) = value.strip_prefix("ak.") else {
        return false;
    };
    !body.is_empty()
        && body.split('.').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        })
}

fn policy_scope_ref_is_valid(value: &str) -> bool {
    if let Some(rest) = value.strip_prefix("did:") {
        return !rest.is_empty() && !rest.chars().any(char::is_whitespace);
    }
    let Some(rest) = value.strip_prefix("ak:") else {
        return false;
    };
    let mut segments = rest.split(':');
    let Some(kind) = segments.next() else {
        return false;
    };
    let valid_kind = !kind.is_empty()
        && kind
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    let valid_value = |segment: &str| {
        !segment.is_empty()
            && segment.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'=' | b'-')
            })
    };
    valid_kind && segments.clone().next().is_some() && segments.all(valid_value)
}

fn moderation_reason_code_is_valid(value: &str) -> bool {
    claim_constraint_name_is_valid(value)
}

fn moderation_domain_is_valid(value: &str) -> bool {
    validate_canonical_idna_domain(value).is_ok() && value.contains('.')
}

validated_string_newtype!(
    SchemaDefinitionId,
    schema_definition_id_is_valid,
    "invalid schema definition id"
);
validated_string_newtype!(
    ClaimConstraintName,
    claim_constraint_name_is_valid,
    "invalid disclosure claim constraint name"
);
validated_string_newtype!(
    PolicyActionName,
    policy_action_name_is_valid,
    "invalid policy action name"
);
validated_string_newtype!(
    PolicyScopeRef,
    policy_scope_ref_is_valid,
    "invalid policy scope reference"
);
validated_string_newtype!(
    ModerationReasonCode,
    moderation_reason_code_is_valid,
    "invalid moderation reason code"
);
validated_string_newtype!(
    ModerationDomain,
    moderation_domain_is_valid,
    "invalid canonical moderation domain"
);

#[derive(Clone, Debug, PartialEq)]
pub enum IdentityDisclosureConstraintValue {
    Null,
    Boolean(bool),
    Number(serde_json::Number),
    String(String),
}

impl Serialize for IdentityDisclosureConstraintValue {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Null => serializer.serialize_none(),
            Self::Boolean(value) => serializer.serialize_bool(*value),
            Self::Number(value) => value.serialize(serializer),
            Self::String(value) => serializer.serialize_str(value),
        }
    }
}

impl<'de> Deserialize<'de> for IdentityDisclosureConstraintValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match Value::deserialize(deserializer)? {
            Value::Null => Ok(Self::Null),
            Value::Bool(value) => Ok(Self::Boolean(value)),
            Value::Number(value) => Ok(Self::Number(value)),
            Value::String(value) => Ok(Self::String(value)),
            _ => Err(serde::de::Error::custom(
                "disclosure value constraint must be a JSON scalar",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityDisclosureMode {
    Abstract,
    Explicit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityDisclosurePolicyClaim {
    pub claim_kind: NonEmptyString,
    pub issuer: DidFullId,
    pub subject_id: DidCoreId,
    pub disclosure: IdentityDisclosureMode,
    pub fields: Vec<NonEmptyString>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub value_constraints: BTreeMap<ClaimConstraintName, IdentityDisclosureConstraintValue>,
}

impl IdentityDisclosurePolicyClaim {
    fn validate(&self) -> Result<()> {
        if self.fields.is_empty() || !values_are_unique(&self.fields) {
            return schema_violation("disclosure claim fields must be non-empty and unique");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityDisclosureAudience {
    pub represented_org: DidCoreId,
    pub verifier_service_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tsp_vids: Vec<DidFullId>,
}

impl IdentityDisclosureAudience {
    fn validate(&self) -> Result<()> {
        if self.verifier_service_ids.is_empty()
            || !values_are_unique(&self.verifier_service_ids)
            || !values_are_unique(&self.tsp_vids)
        {
            return schema_violation(
                "disclosure audience identifiers must be unique and verifier_service_ids must be non-empty",
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityDisclosurePolicyDocument {
    pub holder_principal_id: DidCoreId,
    pub audience: IdentityDisclosureAudience,
    pub allowed_claims: Vec<IdentityDisclosurePolicyClaim>,
    pub denied_fields: Vec<NonEmptyString>,
    pub user_consent_required: bool,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl IdentityDisclosurePolicyDocument {
    pub fn validate(&self) -> Result<()> {
        self.audience.validate()?;
        if !values_are_unique(&self.denied_fields) {
            return schema_violation("denied disclosure fields must be unique");
        }
        for claim in &self.allowed_claims {
            claim.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityDisclosurePolicyStatePayload {
    pub policy_id: PolicyId,
    pub value: IdentityDisclosurePolicyDocument,
}

impl IdentityDisclosurePolicyStatePayload {
    pub fn validate(&self) -> Result<()> {
        self.value.validate()
    }
}

impl<'de> Deserialize<'de> for IdentityDisclosurePolicyStatePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            policy_id: PolicyId,
            value: IdentityDisclosurePolicyDocument,
        }
        let wire = Wire::deserialize(deserializer)?;
        let payload = Self {
            policy_id: wire.policy_id,
            value: wire.value,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityDisclosureProofProfile {
    #[serde(rename = "vc_di_bbs_2023")]
    VcDiBbs2023,
    SdJwtVc,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityDisclosureTransport {
    Tsp,
    HttpJwe,
    DidcommLike,
    ToDevice,
    MlsDm,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityDisclosureReceiptDocument {
    pub receipt_id: ReceiptId,
    pub request_id: RequestId,
    pub request_digest: Hash,
    pub presentation_digest: Hash,
    pub proof_profile: IdentityDisclosureProofProfile,
    pub transport: IdentityDisclosureTransport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsp_relationship_id: Option<NonEmptyString>,
    pub disclosed_fields: Vec<NonEmptyString>,
    pub withheld_fields: Vec<NonEmptyString>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

impl IdentityDisclosureReceiptDocument {
    pub fn validate(&self) -> Result<()> {
        if !values_are_unique(&self.disclosed_fields) || !values_are_unique(&self.withheld_fields) {
            return schema_violation("disclosure receipt field lists must be unique");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityDisclosureReceiptStatePayload {
    pub holder_principal_id: DidCoreId,
    pub value: IdentityDisclosureReceiptDocument,
}

impl IdentityDisclosureReceiptStatePayload {
    pub fn validate(&self) -> Result<()> {
        self.value.validate()
    }
}

impl<'de> Deserialize<'de> for IdentityDisclosureReceiptStatePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            holder_principal_id: DidCoreId,
            value: IdentityDisclosureReceiptDocument,
        }
        let wire = Wire::deserialize(deserializer)?;
        let payload = Self {
            holder_principal_id: wire.holder_principal_id,
            value: wire.value,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationModerationPolicyScope {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm_ids: Option<Vec<RealmId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_ids: Option<Vec<DidCoreId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applies_to_owned_realms: Option<bool>,
}

impl OrganizationModerationPolicyScope {
    fn validate(&self) -> Result<()> {
        if self.realm_ids.is_none()
            && self.service_ids.is_none()
            && self.applies_to_owned_realms.is_none()
        {
            return schema_violation("organization moderation policy scope must not be empty");
        }
        if self
            .realm_ids
            .as_ref()
            .is_some_and(|values| values.is_empty() || !values_are_unique(values))
            || self
                .service_ids
                .as_ref()
                .is_some_and(|values| values.is_empty() || !values_are_unique(values))
        {
            return schema_violation(
                "organization moderation policy scope identifiers must be unique",
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationDidTargetKind {
    Actor,
    Device,
    Organization,
}

#[derive(Clone, Debug)]
pub enum ModerationPolicyTarget {
    Did {
        kind: ModerationDidTargetKind,
        did: DidFullId,
    },
    Device {
        device_id: DeviceId,
    },
    ServiceId {
        did_core_id: DidCoreId,
    },
    Domain {
        domain: ModerationDomain,
        match_subdomains: Option<bool>,
    },
    TrustDomain {
        trust_domain: TrustDomainId,
    },
    ClaimSelector {
        claim_kind: NonEmptyString,
        issuer: DidCoreId,
    },
    MediaDigest {
        digest: Hash,
    },
    ContentLabel {
        label: NonEmptyString,
    },
}

impl Serialize for ModerationPolicyTarget {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = match self {
            Self::Did { kind, did } => serde_json::json!({"kind": kind, "did": did}),
            Self::Device { device_id } => {
                serde_json::json!({"kind": "device", "device_id": device_id})
            }
            Self::ServiceId { did_core_id } => {
                serde_json::json!({"kind": "service_id", "did_core_id": did_core_id})
            }
            Self::Domain {
                domain,
                match_subdomains,
            } => {
                let mut value = serde_json::json!({"kind": "domain", "domain": domain});
                if let Some(match_subdomains) = match_subdomains {
                    value["match_subdomains"] = Value::Bool(*match_subdomains);
                }
                value
            }
            Self::TrustDomain { trust_domain } => {
                serde_json::json!({"kind": "trust_domain", "trust_domain": trust_domain})
            }
            Self::ClaimSelector { claim_kind, issuer } => {
                serde_json::json!({"kind": "claim_selector", "claim_kind": claim_kind, "issuer": issuer})
            }
            Self::MediaDigest { digest } => {
                serde_json::json!({"kind": "media_digest", "digest": digest})
            }
            Self::ContentLabel { label } => {
                serde_json::json!({"kind": "content_label", "label": label})
            }
        };
        value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ModerationPolicyTarget {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let kind = value
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| serde::de::Error::custom("moderation target requires kind"))?
            .to_owned();
        macro_rules! parse {
            ($wire:ty) => {
                serde_json::from_value::<$wire>(value).map_err(serde::de::Error::custom)?
            };
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct DidWire {
            kind: ModerationDidTargetKind,
            did: DidFullId,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct DeviceWire {
            kind: String,
            device_id: DeviceId,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ServiceWire {
            kind: String,
            did_core_id: DidCoreId,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct DomainWire {
            kind: String,
            domain: ModerationDomain,
            match_subdomains: Option<bool>,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct TrustDomainWire {
            kind: String,
            trust_domain: TrustDomainId,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ClaimWire {
            kind: String,
            claim_kind: NonEmptyString,
            issuer: DidCoreId,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct DigestWire {
            kind: String,
            digest: Hash,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct LabelWire {
            kind: String,
            label: NonEmptyString,
        }

        match kind.as_str() {
            "actor" | "organization" => {
                let wire = parse!(DidWire);
                Ok(Self::Did {
                    kind: wire.kind,
                    did: wire.did,
                })
            }
            "device" if value.get("did").is_some() => {
                let wire = parse!(DidWire);
                Ok(Self::Did {
                    kind: wire.kind,
                    did: wire.did,
                })
            }
            "device" => {
                let wire = parse!(DeviceWire);
                debug_assert_eq!(wire.kind, "device");
                Ok(Self::Device {
                    device_id: wire.device_id,
                })
            }
            "service_id" => {
                let wire = parse!(ServiceWire);
                debug_assert_eq!(wire.kind, "service_id");
                Ok(Self::ServiceId {
                    did_core_id: wire.did_core_id,
                })
            }
            "domain" => {
                let wire = parse!(DomainWire);
                debug_assert_eq!(wire.kind, "domain");
                Ok(Self::Domain {
                    domain: wire.domain,
                    match_subdomains: wire.match_subdomains,
                })
            }
            "trust_domain" => {
                let wire = parse!(TrustDomainWire);
                debug_assert_eq!(wire.kind, "trust_domain");
                Ok(Self::TrustDomain {
                    trust_domain: wire.trust_domain,
                })
            }
            "claim_selector" => {
                let wire = parse!(ClaimWire);
                debug_assert_eq!(wire.kind, "claim_selector");
                Ok(Self::ClaimSelector {
                    claim_kind: wire.claim_kind,
                    issuer: wire.issuer,
                })
            }
            "media_digest" => {
                let wire = parse!(DigestWire);
                debug_assert_eq!(wire.kind, "media_digest");
                Ok(Self::MediaDigest {
                    digest: wire.digest,
                })
            }
            "content_label" => {
                let wire = parse!(LabelWire);
                debug_assert_eq!(wire.kind, "content_label");
                Ok(Self::ContentLabel { label: wire.label })
            }
            _ => Err(serde::de::Error::custom("unknown moderation target kind")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrganizationModerationAction {
    DenyJoin,
    DenyRestrictedJoin,
    DenyInvite,
    DenyWrite,
    DenyFederation,
    QuarantineMessage,
    RequireReview,
    RedactOnAccept,
    ShadowCollapse,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationModerationPolicyRule {
    pub target: ModerationPolicyTarget,
    pub action: OrganizationModerationAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<ModerationReasonCode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<DidCoreId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub created_at: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationModerationPolicyDocument {
    pub policy_id: PolicyId,
    pub policy_scope: OrganizationModerationPolicyScope,
    pub rules: Vec<OrganizationModerationPolicyRule>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub not_before: Option<DateTime<Utc>>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
}

impl OrganizationModerationPolicyDocument {
    pub fn validate(&self) -> Result<()> {
        self.policy_scope.validate()?;
        if self.rules.is_empty() {
            return schema_violation("organization moderation policy rules must be non-empty");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationModerationPolicyStatePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_principal_id: Option<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<NonEmptyString>,
    pub value: OrganizationModerationPolicyDocument,
}

impl OrganizationModerationPolicyStatePayload {
    pub fn validate(&self) -> Result<()> {
        if self.organization_principal_id.is_some() == self.organization_id.is_some() {
            return schema_violation(
                "organization moderation policy requires exactly one organization identifier",
            );
        }
        self.value.validate()
    }
}

impl<'de> Deserialize<'de> for OrganizationModerationPolicyStatePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            organization_principal_id: Option<DidCoreId>,
            organization_id: Option<NonEmptyString>,
            value: OrganizationModerationPolicyDocument,
        }
        let wire = Wire::deserialize(deserializer)?;
        let payload = Self {
            organization_principal_id: wire.organization_principal_id,
            organization_id: wire.organization_id,
            value: wire.value,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

#[derive(Clone, Debug)]
pub enum PolicyDocument {
    Policy(Policy),
    RecoveryPolicy(RecoveryPolicy),
}

impl PolicyDocument {
    pub fn policy_id(&self) -> &PolicyId {
        match self {
            Self::Policy(value) => &value.id,
            Self::RecoveryPolicy(value) => &value.policy_id,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Policy(value) => value.validate(),
            Self::RecoveryPolicy(value) => value.validate(),
        }
    }
}

impl Serialize for PolicyDocument {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Policy(value) => value.serialize(serializer),
            Self::RecoveryPolicy(value) => value.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for PolicyDocument {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        match value.get("schema").and_then(Value::as_str) {
            Some(Policy::SCHEMA) => serde_json::from_value::<Policy>(value)
                .map(Self::Policy)
                .map_err(serde::de::Error::custom),
            Some(RecoveryPolicy::SCHEMA) => serde_json::from_value::<RecoveryPolicy>(value)
                .map(Self::RecoveryPolicy)
                .map_err(serde::de::Error::custom),
            _ => Err(serde::de::Error::custom(
                "policy value has an unknown schema family",
            )),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySetStatePayload {
    pub policy_id: PolicyId,
    pub value: PolicyDocument,
}

impl PolicySetStatePayload {
    pub fn validate(&self) -> Result<()> {
        self.value.validate()?;
        if &self.policy_id != self.value.policy_id() {
            return schema_violation(
                "policy.set policy_id must equal the selected value policy id",
            );
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for PolicySetStatePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            policy_id: PolicyId,
            value: PolicyDocument,
        }
        let wire = Wire::deserialize(deserializer)?;
        let payload = Self {
            policy_id: wire.policy_id,
            value: wire.value,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyActionDocument {
    pub action: PolicyActionName,
    pub approval_required: bool,
    pub approval_quorum: u64,
    pub policy_scope: PolicyScopeRef,
}

impl PolicyActionDocument {
    pub fn validate(&self) -> Result<()> {
        if self.approval_quorum == 0 {
            return schema_violation("policy action approval_quorum must be at least one");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyActionStatePayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<NonEmptyString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_id: Option<NonEmptyString>,
    pub value: PolicyActionDocument,
}

impl PolicyActionStatePayload {
    pub fn validate(&self) -> Result<()> {
        if self.policy_id.is_some() == self.action_id.is_some() {
            return schema_violation("policy action requires exactly one policy_id or action_id");
        }
        if self
            .action_id
            .as_ref()
            .is_some_and(|id| id.as_str().starts_with("ak:"))
        {
            return schema_violation(
                "policy action action_id must satisfy the non-typed identifier floor",
            );
        }
        self.value.validate()
    }
}

impl<'de> Deserialize<'de> for PolicyActionStatePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            policy_id: Option<NonEmptyString>,
            action_id: Option<NonEmptyString>,
            value: PolicyActionDocument,
        }
        let wire = Wire::deserialize(deserializer)?;
        let payload = Self {
            policy_id: wire.policy_id,
            action_id: wire.action_id,
            value: wire.value,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SchemaDefinitionDocument {
    #[serde(rename = "$schema")]
    pub schema: SchemaDefinitionDialect,
    #[serde(rename = "$id")]
    pub id: SchemaDefinitionId,
    #[serde(flatten)]
    pub keywords: BTreeMap<String, Value>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchemaDefinitionDialect {
    #[serde(rename = "https://json-schema.org/draft/2020-12/schema")]
    Draft202012,
}

impl SchemaDefinitionDocument {
    fn validate(&self) -> Result<()> {
        if self.keywords.contains_key("$schema") || self.keywords.contains_key("$id") {
            return schema_violation("schema definition keywords must not shadow $schema or $id");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaDefineStatePayload {
    pub schema_id: SchemaDefinitionId,
    pub value: SchemaDefinitionDocument,
}

impl SchemaDefineStatePayload {
    pub fn validate(&self) -> Result<()> {
        self.value.validate()?;
        if self.schema_id != self.value.id {
            return schema_violation("schema definition schema_id must equal value.$id");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for SchemaDefineStatePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_id: SchemaDefinitionId,
            value: SchemaDefinitionDocument,
        }
        let wire = Wire::deserialize(deserializer)?;
        let payload = Self {
            schema_id: wire.schema_id,
            value: wire.value,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

/// Counterpart for `event-payload.schema.json#/$defs/state_conflict_recovery_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateConflictRecoveryPayload {
    pub target_cell: CellRef,
    pub resolved_value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateConflictRecoveryPayloadWire {
    target_cell: CellRef,
    resolved_value: Value,
    reason: Option<String>,
}

impl StateConflictRecoveryPayload {
    pub fn validate(&self) -> Result<()> {
        if self
            .reason
            .as_ref()
            .is_some_and(|reason| reason.chars().count() > 512)
        {
            return schema_violation("conflict recovery reason exceeds 512 characters");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for StateConflictRecoveryPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = StateConflictRecoveryPayloadWire::deserialize(deserializer)?;
        let payload = Self {
            target_cell: wire.target_cell,
            resolved_value: wire.resolved_value,
            reason: wire.reason,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

/// Counterpart for `event-payload.schema.json#/$defs/notary_fault_equivocation_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotaryFaultEquivocationPayload {
    pub signer_id: DidCoreId,
    pub seal_a: Seal,
    pub seal_b: Seal,
}

/// Open signed receipt object used by notary censorship evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotaryCensorshipReceipt {
    pub event_digest: Value,
    pub received_at: Value,
    pub signature: Value,
    #[serde(default, flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
}

/// Counterpart for `event-payload.schema.json#/$defs/notary_fault_censorship_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotaryFaultCensorshipPayload {
    pub signer_id: DidCoreId,
    pub receipt: NotaryCensorshipReceipt,
    pub seal_ref: SealId,
    pub non_membership_proof: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub missing_rejection_or_defer_proof: Option<BTreeMap<String, Value>>,
}
