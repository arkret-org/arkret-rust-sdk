//! Generic state event payloads.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use arkret_wire::{
    ActorId, AppletId, CellFamilyId, CollisionVariantRecordId, Did, DidCoreId, TrustDomainId,
    validate_canonical_idna_domain,
};

use super::event_wire::decode_payload_after_kind_validation;
use crate::governance::operation_wire::Policy;
use crate::internal_prelude::*;
use crate::objects::media::MediaBackendKind;

fn schema_violation<T>(message: impl Into<String>) -> Result<T> {
    Err(WireError::Protocol(format!(
        "schema_violation: {}",
        message.into()
    )))
}

fn deserialize_non_null_optional<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
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
/// Deployment roles supported by one Realm media service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmMediaServiceMode {
    Turn,
    Sfu,
    Mcu,
}

/// Call topologies allowed or selected by one Realm media service.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmMediaCallMode {
    P2p,
    Sfu,
    Mcu,
}

/// Counterpart for `event-payload.schema.json#/$defs/media_service_focus`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct MediaServiceFocus {
    pub focus_id: NonEmptyString,
    pub focus_kind: MediaBackendKind,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub region: Option<NonEmptyString>,
    pub token_endpoint: String,
    pub connect_url: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<NonEmptyString>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub health_endpoint: Option<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub cascade_group: Option<NonEmptyString>,
}

impl MediaServiceFocus {
    fn validate(&self) -> Result<()> {
        if self.focus_id.as_str().starts_with("ak:") {
            return schema_violation("media service focus_id must not use the ak: namespace");
        }
        if !is_url_with_scheme(&self.token_endpoint, "https://") {
            return schema_violation("media service token_endpoint must be an https URL");
        }
        if !is_url_with_allowed_schemes(&self.connect_url, &["https://", "wss://"]) {
            return schema_violation("media service connect_url must be an https or wss URL");
        }
        if self
            .health_endpoint
            .as_deref()
            .is_some_and(|url| !is_url_with_scheme(url, "https://"))
        {
            return schema_violation("media service health_endpoint must be an https URL");
        }
        if contains_duplicate(&self.capabilities) {
            return schema_violation("media service focus capabilities must be unique");
        }
        Ok(())
    }
}

/// Closed descriptor carried under `RealmMediaServicePayload::value`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmMediaServiceValue {
    pub service_id: DidCoreId,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub modes: Option<Vec<RealmMediaServiceMode>>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub ice_config_endpoint: Option<String>,
    pub foci: Vec<MediaServiceFocus>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub default_call_mode: Option<RealmMediaCallMode>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub allowed_call_modes: Option<Vec<RealmMediaCallMode>>,
    #[serde(
        default,
        deserialize_with = "deserialize_non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub recording_supported: Option<bool>,
}

impl RealmMediaServiceValue {
    pub fn validate(&self) -> Result<()> {
        if self
            .modes
            .as_ref()
            .is_some_and(|modes| modes.is_empty() || contains_duplicate(modes))
        {
            return schema_violation("media service modes must be non-empty and unique");
        }
        if self
            .ice_config_endpoint
            .as_deref()
            .is_some_and(|url| !is_url_with_scheme(url, "https://"))
        {
            return schema_violation("media service ice_config_endpoint must be an https URL");
        }
        if self.foci.is_empty() || contains_duplicate(&self.foci) {
            return schema_violation("media service foci must be non-empty and unique");
        }
        for focus in &self.foci {
            focus.validate()?;
        }
        if self
            .allowed_call_modes
            .as_ref()
            .is_some_and(|modes| modes.is_empty() || contains_duplicate(modes))
        {
            return schema_violation(
                "media service allowed_call_modes must be non-empty and unique",
            );
        }
        Ok(())
    }
}

/// Counterpart for `event-payload.schema.json#/$defs/realm_media_service_payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmMediaServicePayload {
    pub value: RealmMediaServiceValue,
}

impl RealmMediaServicePayload {
    pub fn validate(&self) -> Result<()> {
        self.value.validate()
    }
}

fn contains_duplicate<T: PartialEq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, value)| values[..index].contains(value))
}

fn is_url_with_allowed_schemes(value: &str, schemes: &[&str]) -> bool {
    schemes
        .iter()
        .any(|scheme| is_url_with_scheme(value, scheme))
}

fn is_url_with_scheme(value: &str, scheme: &str) -> bool {
    value
        .strip_prefix(scheme)
        .is_some_and(|rest| !rest.is_empty() && !rest.chars().any(char::is_whitespace))
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

state_payload_with_subject!(OrganizationDiscoveryStatePayload, organization_id, Did);

/// Canonical resource key for actor/applet/handle discovery cells.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResourceDiscoveryId {
    Actor(ActorId),
    Applet(AppletId),
    Handle(CanonicalDiscoveryHandle),
}

validated_string_newtype!(
    CanonicalDiscoveryHandle,
    canonical_discovery_handle_is_valid,
    "discovery handle must be canonical prepared-localpart:lowercase-domain"
);

fn canonical_discovery_handle_is_valid(value: &str) -> bool {
    static PATTERN: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r"^[^\s:@/#?\\]+:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$",
        )
        .expect("canonical handle regex")
    });
    value.chars().count() >= 5
        && value.chars().count() <= 382
        && value
            .split_once(':')
            .is_some_and(|(local, domain)| local.chars().count() <= 128 && domain.len() <= 253)
        && PATTERN.is_match(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceDiscoveryKind {
    Actor,
    Applet,
    Handle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceDiscoverability {
    Public,
    Listed,
    Restricted,
    Unlisted,
    InviteOnly,
    Secret,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDiscoveryStateValue {
    pub resource_kind: ResourceDiscoveryKind,
    pub discoverability: ResourceDiscoverability,
    pub directory_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_visibility: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDiscoveryStatePayload {
    pub resource_id: ResourceDiscoveryId,
    pub value: ResourceDiscoveryStateValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ResourceDiscoveryStatePayload {
    pub fn validate(&self) -> Result<()> {
        let kind_matches = matches!(
            (&self.resource_id, self.value.resource_kind),
            (ResourceDiscoveryId::Actor(_), ResourceDiscoveryKind::Actor)
                | (
                    ResourceDiscoveryId::Applet(_),
                    ResourceDiscoveryKind::Applet
                )
                | (
                    ResourceDiscoveryId::Handle(_),
                    ResourceDiscoveryKind::Handle
                )
        );
        if !kind_matches {
            return schema_violation("discovery resource_id does not match value.resource_kind");
        }
        if self.value.directory_ids.len() > 64 || contains_duplicate(&self.value.directory_ids) {
            return schema_violation("discovery directory_ids must contain at most 64 unique ids");
        }
        Ok(())
    }
}

state_payload_with_subject!(DidProofStatePayload, did, Did);
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
    pub verifier_id: DidCoreId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub represented_organization_id: Option<DidCoreId>,
    pub domain: String,
    pub challenge: NonEmptyString,
    pub purpose: NonEmptyString,
    pub accepted_issuer_ids: Vec<DidCoreId>,
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
    pub holder_subject_id: DidCoreId,
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
    pub controller_id: DidCoreId,
    pub holder_id: DidCoreId,
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
    pub issuer_id: DidCoreId,
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
    pub represented_organization_id: DidCoreId,
    pub verifier_ids: Vec<DidCoreId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tsp_vids: Vec<TspVid>,
}

impl IdentityDisclosureAudience {
    fn validate(&self) -> Result<()> {
        if self.verifier_ids.is_empty()
            || !values_are_unique(&self.verifier_ids)
            || !values_are_unique(&self.tsp_vids)
        {
            return schema_violation(
                "disclosure audience identifiers must be unique and verifier_ids must be non-empty",
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityDisclosurePolicyDocument {
    pub holder_id: DidCoreId,
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
    pub holder_id: DidCoreId,
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
            holder_id: DidCoreId,
            value: IdentityDisclosureReceiptDocument,
        }
        let wire = Wire::deserialize(deserializer)?;
        let payload = Self {
            holder_id: wire.holder_id,
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

#[derive(Clone, Debug)]
pub enum ModerationPolicyTarget {
    Actor {
        actor_id: ActorId,
    },
    Organization {
        organization_id: DidCoreId,
    },
    Device {
        device_id: DeviceId,
    },
    Service {
        service_id: DidCoreId,
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
        issuer_id: DidCoreId,
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
            Self::Actor { actor_id } => {
                serde_json::json!({"kind": "actor", "actor_id": actor_id})
            }
            Self::Organization { organization_id } => {
                serde_json::json!({"kind": "organization", "organization_id": organization_id})
            }
            Self::Device { device_id } => {
                serde_json::json!({"kind": "device", "device_id": device_id})
            }
            Self::Service { service_id } => {
                serde_json::json!({"kind": "service", "service_id": service_id})
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
            Self::ClaimSelector {
                claim_kind,
                issuer_id,
            } => {
                serde_json::json!({"kind": "claim_selector", "claim_kind": claim_kind, "issuer_id": issuer_id})
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
        struct ActorWire {
            kind: String,
            actor_id: ActorId,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct OrganizationWire {
            kind: String,
            organization_id: DidCoreId,
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
            service_id: DidCoreId,
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
            issuer_id: DidCoreId,
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
            "actor" => {
                let wire = parse!(ActorWire);
                debug_assert_eq!(wire.kind, "actor");
                Ok(Self::Actor {
                    actor_id: wire.actor_id,
                })
            }
            "organization" => {
                let wire = parse!(OrganizationWire);
                debug_assert_eq!(wire.kind, "organization");
                Ok(Self::Organization {
                    organization_id: wire.organization_id,
                })
            }
            "device" => {
                let wire = parse!(DeviceWire);
                debug_assert_eq!(wire.kind, "device");
                Ok(Self::Device {
                    device_id: wire.device_id,
                })
            }
            "service" => {
                let wire = parse!(ServiceWire);
                debug_assert_eq!(wire.kind, "service");
                Ok(Self::Service {
                    service_id: wire.service_id,
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
                    issuer_id: wire.issuer_id,
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
    pub created_by: Option<ActorId>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrganizationModerationPolicyStatePayload {
    pub organization_id: DidCoreId,
    pub value: OrganizationModerationPolicyDocument,
}

impl OrganizationModerationPolicyStatePayload {
    pub fn validate(&self) -> Result<()> {
        self.value.validate()
    }
}

#[derive(Clone, Debug)]
pub enum PolicyDocument {
    Policy(Box<Policy>),
    RecoveryPolicy(Box<RecoveryPolicy>),
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
                .map(Box::new)
                .map(Self::Policy)
                .map_err(serde::de::Error::custom),
            Some(RecoveryPolicy::SCHEMA) => serde_json::from_value::<RecoveryPolicy>(value)
                .map(Box::new)
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
    pub value: SchemaDefinitionDocument,
}

impl SchemaDefineStatePayload {
    pub fn validate(&self) -> Result<()> {
        self.value.validate()
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
            value: SchemaDefinitionDocument,
        }
        let wire = Wire::deserialize(deserializer)?;
        let payload = Self { value: wire.value };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

/// Counterpart for `event-payload.schema.json#/$defs/state_conflict_recovery_payload`.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateConflictRecoveryPayload {
    pub target_cell_id: CellRef,
    pub resolved_value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StateConflictRecoveryPayloadWire {
    target_cell_id: CellRef,
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
            target_cell_id: wire.target_cell_id,
            resolved_value: wire.resolved_value,
            reason: wire.reason,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

/// The disputed scope one `ak.fork.resolution` normalizes.
///
/// This is the whole cell subject, so it carries the position and nothing
/// else. A single-bucket overflow and a cross-bucket overflow at the same
/// position have to converge on one cell, which is why `prev_frontier_digest`
/// lives in the evidence instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ForkResolutionSubject {
    EventSiblingPosition { actor_id: ActorId, actor_seq: u64 },
    EventIdCollision { event_id: EventId },
}

/// One complete canonical Event preimage, inline or by reference.
///
/// The reference arm is not a convenience: base64 of an Event near the 1 MiB
/// ceiling cannot fit twice inside a resolution Event that is itself bounded by
/// 1 MiB, so without it those collisions would be unadjudicable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ForkResolutionVariantLocator {
    InlineCanonicalBytes {
        canonical_event_bytes_b64u: Base64UrlString,
    },
    CollisionVariantRecord {
        collision_variant_record_id: CollisionVariantRecordId,
        collision_variant_record_digest: Hash,
    },
}

impl ForkResolutionVariantLocator {
    /// Stable comparison key. Two locators denote the same variant only when
    /// they are the same arm with the same content; an inline copy and a record
    /// reference are never compared as equal here, because proving they agree
    /// requires resolving the record.
    fn identity(&self) -> (&'static str, &str) {
        match self {
            Self::InlineCanonicalBytes {
                canonical_event_bytes_b64u,
            } => ("inline", canonical_event_bytes_b64u.as_str()),
            Self::CollisionVariantRecord {
                collision_variant_record_id,
                ..
            } => ("record", collision_variant_record_id.as_str()),
        }
    }
}

/// Why the subject is disputed.
///
/// Every arm is bounded at the cardinality that actually proves its claim:
/// 17 siblings pass the v1 single-bucket ceiling of 16, 65 pass the cumulative
/// ceiling of 64. A producer is never asked to enumerate every sibling an
/// attacker may still submit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ForkResolutionConflictEvidence {
    BucketOverflow {
        prev_frontier_digest: Hash,
        event_ids: Vec<EventId>,
    },
    ActorSeqOverflow {
        event_ids: Vec<EventId>,
    },
    DomainNonJoinable {
        cell_family: CellFamilyId,
        event_ids: Vec<EventId>,
    },
    FullHashCollision {
        variants: Vec<ForkResolutionVariantLocator>,
    },
}

pub(crate) const FORK_RESOLUTION_BUCKET_OVERFLOW_EVENT_IDS: usize = 17;
pub(crate) const FORK_RESOLUTION_ACTOR_SEQ_OVERFLOW_EVENT_IDS: usize = 65;
pub(crate) const FORK_RESOLUTION_COLLISION_VARIANTS: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkResolutionWinnerKind {
    CanonicalWinner,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkResolutionVoidKind {
    VoidAll,
}

/// Closed subject-specific fork verdict. The two winner shapes deliberately
/// cannot be interchanged: a full-hash collision has no digest-only identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ForkResolutionVerdict {
    SiblingWinner {
        kind: ForkResolutionWinnerKind,
        winner_event_id: EventId,
    },
    CollisionWinner {
        kind: ForkResolutionWinnerKind,
        winner_index: u8,
    },
    VoidAll {
        kind: ForkResolutionVoidKind,
    },
}

/// Counterpart for `event-payload.schema.json#/$defs/fork_resolution_payload`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ForkResolutionPayload {
    pub subject: ForkResolutionSubject,
    pub conflict_evidence: ForkResolutionConflictEvidence,
    pub verdict: ForkResolutionVerdict,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ForkResolutionPayloadWire {
    subject: ForkResolutionSubject,
    conflict_evidence: ForkResolutionConflictEvidence,
    verdict: ForkResolutionVerdict,
}

impl ForkResolutionPayload {
    pub fn validate(&self) -> Result<()> {
        self.conflict_evidence.validate()?;
        match (&self.subject, &self.conflict_evidence, &self.verdict) {
            (
                ForkResolutionSubject::EventSiblingPosition { .. },
                ForkResolutionConflictEvidence::BucketOverflow { event_ids, .. }
                | ForkResolutionConflictEvidence::ActorSeqOverflow { event_ids }
                | ForkResolutionConflictEvidence::DomainNonJoinable { event_ids, .. },
                ForkResolutionVerdict::SiblingWinner {
                    winner_event_id, ..
                },
            ) => {
                if !event_ids.contains(winner_event_id) {
                    return schema_violation(
                        "fork resolution sibling winner is outside its own evidence set",
                    );
                }
            }
            (
                ForkResolutionSubject::EventSiblingPosition { .. },
                ForkResolutionConflictEvidence::BucketOverflow { .. }
                | ForkResolutionConflictEvidence::ActorSeqOverflow { .. }
                | ForkResolutionConflictEvidence::DomainNonJoinable { .. },
                ForkResolutionVerdict::VoidAll { .. },
            ) => {}
            (
                ForkResolutionSubject::EventIdCollision { .. },
                ForkResolutionConflictEvidence::FullHashCollision { variants },
                ForkResolutionVerdict::CollisionWinner { winner_index, .. },
            ) => {
                if usize::from(*winner_index) >= variants.len() {
                    return schema_violation(
                        "fork resolution collision winner_index is outside its own evidence set",
                    );
                }
            }
            (
                ForkResolutionSubject::EventIdCollision { .. },
                ForkResolutionConflictEvidence::FullHashCollision { .. },
                ForkResolutionVerdict::VoidAll { .. },
            ) => {}
            _ => {
                return schema_violation(
                    "fork resolution subject, evidence and verdict are not the same branch",
                );
            }
        }
        Ok(())
    }
}

impl ForkResolutionConflictEvidence {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::BucketOverflow { event_ids, .. } => validate_resolution_event_ids(
                event_ids,
                FORK_RESOLUTION_BUCKET_OVERFLOW_EVENT_IDS,
                FORK_RESOLUTION_BUCKET_OVERFLOW_EVENT_IDS,
                "bucket overflow Event ids",
            ),
            Self::ActorSeqOverflow { event_ids } => validate_resolution_event_ids(
                event_ids,
                FORK_RESOLUTION_ACTOR_SEQ_OVERFLOW_EVENT_IDS,
                FORK_RESOLUTION_ACTOR_SEQ_OVERFLOW_EVENT_IDS,
                "actor_seq overflow Event ids",
            ),
            // `cell_family` is the generated closed registry enum, so an
            // unregistered family cannot survive deserialization and there is
            // no second, hand-maintained answer to what is registered.
            Self::DomainNonJoinable { event_ids, .. } => {
                validate_resolution_event_ids(event_ids, 2, 64, "domain conflict Event ids")
            }
            Self::FullHashCollision { variants } => {
                if variants.len() != FORK_RESOLUTION_COLLISION_VARIANTS {
                    return schema_violation(
                        "fork resolution collision evidence must carry exactly two variants",
                    );
                }
                if variants[0].identity() == variants[1].identity() {
                    return schema_violation("fork resolution collision variants must be distinct");
                }
                Ok(())
            }
        }
    }

    /// Event ids the evidence commits to, empty for the collision branch whose
    /// members are canonical bytes rather than identities.
    #[must_use]
    pub fn event_ids(&self) -> &[EventId] {
        match self {
            Self::BucketOverflow { event_ids, .. }
            | Self::ActorSeqOverflow { event_ids }
            | Self::DomainNonJoinable { event_ids, .. } => event_ids,
            Self::FullHashCollision { .. } => &[],
        }
    }
}

impl ForkResolutionSubject {
    /// Canonical cell subject. It covers the position alone, so both overflow
    /// evidence shapes at one position resolve into the same cell.
    pub fn cell_subject_key(&self) -> Result<Hash> {
        Ok(Hash::new(arkret_canonical::sha256_digest(
            arkret_canonical::canonical_json_bytes(self)?,
        ))?)
    }
}

fn validate_resolution_event_ids(
    event_ids: &[EventId],
    min: usize,
    max: usize,
    label: &str,
) -> Result<()> {
    if event_ids.len() < min || event_ids.len() > max {
        return schema_violation(if min == max {
            format!("fork resolution {label} must contain exactly {min} items")
        } else {
            format!("fork resolution {label} must contain {min}..={max} items")
        });
    }
    if !event_ids
        .windows(2)
        .all(|pair| pair[0].as_str() < pair[1].as_str())
    {
        return schema_violation(format!(
            "fork resolution {label} must be strictly bytewise ascending and unique"
        ));
    }
    Ok(())
}

impl<'de> Deserialize<'de> for ForkResolutionPayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ForkResolutionPayloadWire::deserialize(deserializer)?;
        let payload = Self {
            subject: wire.subject,
            conflict_evidence: wire.conflict_evidence,
            verdict: wire.verdict,
        };
        payload.validate().map_err(serde::de::Error::custom)?;
        Ok(payload)
    }
}

/// Canonical consumer record projected only from an accepted recovery Seal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForkResolutionRecord {
    pub realm_id: RealmId,
    pub subject: ForkResolutionSubject,
    pub conflict_evidence: ForkResolutionConflictEvidence,
    pub verdict: ForkResolutionVerdict,
    pub resolution_event_digest: Hash,
}

impl ForkResolutionRecord {
    pub fn from_accepted_seal(
        event: &Event,
        covering_seal: &Seal,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<Self> {
        if event.kind != EventKind::ForkResolution || event.realm_id != covering_seal.realm_id {
            return schema_violation(
                "fork resolution record source is not an exact same-Realm ak.fork.resolution Event",
            );
        }
        if covering_seal.predecessor_refs.is_empty() {
            return schema_violation("fork resolution cannot be carried by a genesis Seal");
        }
        let payload = decode_payload_after_kind_validation::<ForkResolutionPayload>(event)?;
        payload.validate()?;
        let resolution_event_digest =
            Hash::new(event.event_digest_with_digest_suite(digest_suite)?)?;
        if !covering_seal.delta.contains(&resolution_event_digest) {
            return schema_violation(
                "fork resolution Event is not covered by the supplied accepted Seal",
            );
        }
        if event
            .refs
            .iter()
            .filter(|reference| reference.critical && reference.role == "recovery_capability")
            .count()
            != 1
        {
            return schema_violation(ReasonCode::RECOVERY_CAPABILITY_NOT_SEALED);
        }
        // `state_witness` attests the legal value a cell held before Bottom.
        // The fork-resolution cell is `__unset__` until this very write, so the
        // role has no referent here and must not be smuggled in from the
        // section 9.5 cell-recovery contract.
        if event
            .refs
            .iter()
            .any(|reference| reference.role == "state_witness")
        {
            return schema_violation("fork resolution must not carry a state_witness reference");
        }
        Ok(Self {
            realm_id: event.realm_id.clone(),
            subject: payload.subject,
            conflict_evidence: payload.conflict_evidence,
            verdict: payload.verdict,
            resolution_event_digest,
        })
    }
}

/// Signing context for [`CollisionVariantRecord`] detached proofs.
pub const COLLISION_VARIANT_RECORD_PROOF_CONTEXT: &str =
    ProofContextId::COLLISION_VARIANT_RECORD_PROOF_V1;

/// Counterpart for `collision-variant-record.schema.json`.
///
/// A typed non-Event governance-dependency object holding one complete
/// canonical Event preimage. It exists because two preimages close to the
/// 1 MiB Event ceiling cannot be inlined into a resolution Event that is
/// itself bounded by 1 MiB. It is never a Seal `covered_set` member: the Seal
/// covers the resolution Move that references it.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollisionVariantRecord {
    pub schema: SchemaId,
    pub collision_variant_record_id: CollisionVariantRecordId,
    pub realm_id: RealmId,
    pub collision_event_id: EventId,
    pub canonical_event_bytes_b64u: Base64UrlString,
    pub canonical_event_size_bytes: u64,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub recorded_at: DateTime<Utc>,
    pub proof: PayloadProof,
}

impl CollisionVariantRecord {
    /// Decoded canonical Event preimage bytes, length-checked against the
    /// signed `canonical_event_size_bytes` so a truncated transfer cannot pass
    /// itself off as a shorter legal preimage.
    pub fn canonical_event_bytes(&self) -> Result<Vec<u8>> {
        let bytes = arkret_canonical::base64url_decode(self.canonical_event_bytes_b64u.as_str())?;
        if bytes.len() as u64 != self.canonical_event_size_bytes {
            return schema_violation(
                "collision variant record decoded length does not match canonical_event_size_bytes",
            );
        }
        Ok(bytes)
    }

    /// Digest the referencing locator signs: the Realm's active suite over the
    /// complete canonical record, `proof` included.
    pub fn content_digest(&self, digest_suite: arkret_canonical::DigestSuite) -> Result<Hash> {
        Ok(Hash::new(arkret_canonical::canonical::digest(
            digest_suite,
            &arkret_canonical::canonical_json_bytes(self)?,
        ))?)
    }

    /// Digest the detached proof commits to: the complete record with `proof`
    /// removed. A producer needs it to sign, and a receiver recomputes it
    /// rather than trusting `proof.payload_digest`.
    pub fn unsigned_payload_digest(&self) -> Result<Hash> {
        #[derive(Serialize)]
        struct Unsigned<'a> {
            canonical_event_bytes_b64u: &'a Base64UrlString,
            canonical_event_size_bytes: u64,
            collision_event_id: &'a EventId,
            collision_variant_record_id: &'a CollisionVariantRecordId,
            realm_id: &'a RealmId,
            #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
            recorded_at: DateTime<Utc>,
            schema: &'a SchemaId,
        }
        Ok(Hash::new(arkret_canonical::canonical_sha256(&Unsigned {
            canonical_event_bytes_b64u: &self.canonical_event_bytes_b64u,
            canonical_event_size_bytes: self.canonical_event_size_bytes,
            collision_event_id: &self.collision_event_id,
            collision_variant_record_id: &self.collision_variant_record_id,
            realm_id: &self.realm_id,
            recorded_at: self.recorded_at,
            schema: &self.schema,
        })?)?)
    }

    /// Canonical bytes the detached proof signs.
    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Binding<'a> {
            context: &'static str,
            #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
            created_at: DateTime<Utc>,
            payload_digest: Hash,
            verification_method: &'a DidUrl,
        }
        Ok(arkret_canonical::canonical_json_bytes(&Binding {
            context: COLLISION_VARIANT_RECORD_PROOF_CONTEXT,
            created_at: self.proof.created_at,
            payload_digest: self.unsigned_payload_digest()?,
            verification_method: &self.proof.verification_method,
        })?)
    }

    /// The suite-independent half of [`Self::validate`]: schema id, proof shape
    /// and payload binding, and the decoded preimage length. A governance
    /// dependency store can check this much without knowing which Realm suite
    /// the referencing Move will be replayed under.
    pub fn validate_structural(&self) -> Result<()> {
        if self.schema != SchemaId::CollisionVariantRecordV1 {
            return schema_violation("collision variant record carries a foreign schema id");
        }
        self.proof.validate_production()?;
        if self.proof.payload_digest != self.unsigned_payload_digest()?
            || self.proof.domain.is_some()
            || self.proof.audience.is_some()
            || self.proof.proof_purpose.is_some()
        {
            return schema_violation("collision variant record proof binding mismatch");
        }
        self.canonical_event_bytes()?;
        Ok(())
    }

    /// Everything a receiver can check from the record alone, before it is
    /// bound to a particular resolution Move: schema id, proof shape and
    /// binding, decoded length, canonical encoding and structure of the
    /// preimage, the Realm the preimage itself declares, and the independently
    /// recomputed Event identity. The carried `collision_event_id` is never
    /// trusted.
    pub fn validate(&self, digest_suite: arkret_canonical::DigestSuite) -> Result<()> {
        self.validate_structural()?;
        let variant = self.recomputed_variant(digest_suite)?;
        if variant.realm_id != self.realm_id {
            return schema_violation(
                "collision variant record Realm does not match the Realm its own preimage declares",
            );
        }
        if variant.event_id != self.collision_event_id {
            return Err(WireError::Protocol(format!(
                "{}: collision variant record preimage does not recompute to collision_event_id",
                ReasonCode::EVENT_ID_DIGEST_MISMATCH
            )));
        }
        Ok(())
    }

    /// The Event the stored preimage actually is, structurally parsed with its
    /// identity re-derived. This is the only variant a receiver may act on:
    /// two records in one collision group carry byte-distinct preimages that
    /// both land on one identity here.
    ///
    /// Reconstruction also rejects a non-canonically encoded preimage, which
    /// would otherwise hash to something no other implementation reproduces.
    pub fn recomputed_variant(&self, digest_suite: arkret_canonical::DigestSuite) -> Result<Event> {
        Event::from_digest_payload_bytes(&self.canonical_event_bytes()?, digest_suite)
    }

    /// Bind the record to the exact locator and resolution Move that reference
    /// it, and hand back the canonical preimage bytes the verdict may compare.
    ///
    /// Availability of the record is a transport concern; every authority claim
    /// it makes is re-derived here, so a record fetched from any peer is worth
    /// exactly as much as one fetched from the issuer.
    pub fn canonical_event_bytes_for_locator(
        &self,
        resolution: &Event,
        locator: &ForkResolutionVariantLocator,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<Vec<u8>> {
        let ForkResolutionVariantLocator::CollisionVariantRecord {
            collision_variant_record_id,
            collision_variant_record_digest,
        } = locator
        else {
            return schema_violation(
                "collision variant record was supplied for an inline locator arm",
            );
        };
        if collision_variant_record_id != &self.collision_variant_record_id {
            return schema_violation("collision variant record id does not match its locator");
        }
        if collision_variant_record_digest != &self.content_digest(digest_suite)? {
            return Err(WireError::Protocol(format!(
                "{}: collision variant record does not hash to the digest its locator signs",
                ErrorCode::DIGEST_MISMATCH
            )));
        }
        self.validate(digest_suite)?;
        if self.realm_id != resolution.realm_id {
            return schema_violation(
                "collision variant record belongs to another Realm recovery authority",
            );
        }
        let controller = self
            .proof
            .verification_method
            .as_str()
            .split_once('#')
            .map(|(controller, _)| controller)
            .ok_or_else(|| {
                WireError::Protocol(
                    "collision variant record verification method is not a DID URL".to_owned(),
                )
            })?;
        let move_principal = resolution
            .executed_by
            .as_ref()
            .unwrap_or(&resolution.actor_id)
            .signing_principal_id();
        if &project_did_to_core_id(&Did::new(controller.to_owned())?)? != move_principal {
            return schema_violation(
                "collision variant record proof controller is not the resolution Move principal",
            );
        }
        self.canonical_event_bytes()
    }
}

/// Canonical preimage bytes one locator denotes, once every reference it makes
/// has been resolved and checked.
fn locator_canonical_event_bytes(
    locator: &ForkResolutionVariantLocator,
    resolution: &Event,
    records: &BTreeMap<CollisionVariantRecordId, CollisionVariantRecord>,
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<Vec<u8>> {
    match locator {
        ForkResolutionVariantLocator::InlineCanonicalBytes {
            canonical_event_bytes_b64u,
        } => Ok(arkret_canonical::base64url_decode(
            canonical_event_bytes_b64u.as_str(),
        )?),
        ForkResolutionVariantLocator::CollisionVariantRecord {
            collision_variant_record_id,
            ..
        } => {
            let record = records.get(collision_variant_record_id).ok_or_else(|| {
                WireError::Protocol(format!(
                    "{}: collision variant record {} is not resolved",
                    ReasonCode::DEPENDENCY_MISSING,
                    collision_variant_record_id.as_str()
                ))
            })?;
            record.canonical_event_bytes_for_locator(resolution, locator, digest_suite)
        }
    }
}

/// Event identity a canonical preimage produces under `digest_suite`.
///
/// Both locator arms go through the same reconstruction, so an inline copy and
/// a record reference of the same variant can never disagree about what the
/// bytes are or what they identify.
fn preimage_event_id(
    canonical_event_bytes: &[u8],
    digest_suite: arkret_canonical::DigestSuite,
) -> Result<EventId> {
    Ok(Event::from_digest_payload_bytes(canonical_event_bytes, digest_suite)?.event_id)
}

impl ForkResolutionRecord {
    /// Second half of the collision branch, run once the referenced records
    /// have been resolved.
    ///
    /// [`Self::from_accepted_seal`] can only check what the Move itself
    /// carries: locator identities, not the bytes behind them. This proves the
    /// claim — two byte-distinct preimages that both recompute to the subject
    /// identity — and that the winner is one of those two. Anything less would
    /// let a Move quarantine a position by asserting a collision nobody can
    /// reproduce.
    pub fn validate_collision_evidence(
        &self,
        resolution: &Event,
        records: &BTreeMap<CollisionVariantRecordId, CollisionVariantRecord>,
        digest_suite: arkret_canonical::DigestSuite,
    ) -> Result<()> {
        let (ForkResolutionSubject::EventIdCollision { event_id }, evidence) =
            (&self.subject, &self.conflict_evidence)
        else {
            return Ok(());
        };
        let ForkResolutionConflictEvidence::FullHashCollision { variants } = evidence else {
            return Ok(());
        };
        let mut variant_bytes = Vec::with_capacity(variants.len());
        for locator in variants {
            let bytes = locator_canonical_event_bytes(locator, resolution, records, digest_suite)?;
            if &preimage_event_id(&bytes, digest_suite)? != event_id {
                return Err(WireError::Protocol(format!(
                    "{}: collision variant does not recompute to the subject event_id",
                    ReasonCode::EVENT_ID_DIGEST_MISMATCH
                )));
            }
            variant_bytes.push(bytes);
        }
        if variant_bytes[0] == variant_bytes[1] {
            return schema_violation("collision evidence variants are not byte-distinct");
        }
        // `winner_index` indexes this Move's own two locators, so the winner is
        // structurally one of the bytes just proven; only the range needs
        // checking (`authz/event-auth-state-resolution.md` collision
        // adjudication).
        if let ForkResolutionVerdict::CollisionWinner { winner_index, .. } = &self.verdict
            && variant_bytes.get(usize::from(*winner_index)).is_none()
        {
            return schema_violation("collision winner index does not select an evidence variant");
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn moderation_actor_target_preserves_full_actor_schema() {
        let registry = arkret_schema_conformance::schema_registry_from_default_spec_artifacts()
            .unwrap()
            .expect("spec schema registry");
        let schema = format!(
            "{}#/$defs/moderation_policy_target",
            SchemaId::EVENT_PAYLOAD_V1
        );
        let principal = DidCoreId::new("ak:did_core:web:actor.example").unwrap();
        let mut identities = BTreeSet::new();
        for actor in [
            ActorId::account(AccountId::new(
                principal.clone(),
                DidCoreId::new("ak:did_core:web:station-a.example").unwrap(),
            )),
            ActorId::account(AccountId::new(
                principal.clone(),
                DidCoreId::new("ak:did_core:web:station-b.example").unwrap(),
            )),
            ActorId::service(principal.clone()),
        ] {
            let wire = json!({"kind": "actor", "actor_id": actor});
            registry.validate_value(&schema, &wire).unwrap();
            let decoded: ModerationPolicyTarget = serde_json::from_value(wire.clone()).unwrap();
            assert!(
                matches!(&decoded, ModerationPolicyTarget::Actor { actor_id } if actor_id == &actor)
            );
            assert_eq!(serde_json::to_value(decoded).unwrap(), wire);
            assert!(identities.insert(actor));
        }
        assert_eq!(identities.len(), 3);
        let legacy = json!({"kind": "actor", "actor_id": principal});
        assert!(registry.validate_value(&schema, &legacy).is_err());
        assert!(serde_json::from_value::<ModerationPolicyTarget>(legacy).is_err());
    }

    #[test]
    fn realm_media_service_uses_the_current_typed_descriptor() {
        let wire = json!({
            "value": {
                "service_id": "ak:did_core:webvh:z6mkfixturemedia",
                "modes": ["turn", "sfu"],
                "ice_config_endpoint": "https://media.example/_arkret/self/rtc/ice-config",
                "foci": [{
                    "focus_id": "fra-1",
                    "focus_kind": "livekit",
                    "region": "eu-central",
                    "token_endpoint": "https://media.example/_arkret/self/rtc/token",
                    "connect_url": "wss://media.example/livekit",
                    "capabilities": ["simulcast"],
                    "health_endpoint": "https://media.example/health",
                    "cascade_group": "eu"
                }],
                "default_call_mode": "sfu",
                "allowed_call_modes": ["p2p", "sfu"],
                "recording_supported": true
            }
        });
        let payload: RealmMediaServicePayload =
            serde_json::from_value(wire.clone()).expect("current media-service payload");

        payload.validate().expect("schema constraints");
        assert_eq!(serde_json::to_value(payload).expect("serialize"), wire);
    }

    #[test]
    fn identity_disclosure_claim_uses_stable_issuer_id() {
        let claim = json!({
            "claim_kind": "employee_credential",
            "issuer_id": "ak:did_core:web:issuer.example",
            "subject_id": "ak:did_core:web:subject.example",
            "disclosure": "explicit",
            "fields": ["name"]
        });
        serde_json::from_value::<IdentityDisclosurePolicyClaim>(claim.clone())
            .expect("stable issuer selector");

        let mut legacy = claim;
        legacy["issuer"] = legacy["issuer_id"].take();
        legacy.as_object_mut().unwrap().remove("issuer_id");
        assert!(serde_json::from_value::<IdentityDisclosurePolicyClaim>(legacy).is_err());
    }

    #[test]
    fn moderation_identity_targets_use_stable_typed_ids() {
        for value in [
            json!({"kind": "actor", "actor_id": ActorId::service(
                DidCoreId::new("ak:did_core:web:actor.example").unwrap()
            )}),
            json!({
                "kind": "organization",
                "organization_id": "ak:did_core:web:organization.example"
            }),
            json!({"kind": "device", "device_id": "ak:device:0196419b-0000-7000-8000-000000000000"}),
            json!({"kind": "service", "service_id": "ak:did_core:web:service.example"}),
        ] {
            serde_json::from_value::<ModerationPolicyTarget>(value)
                .expect("stable moderation target");
        }

        assert!(
            serde_json::from_value::<ModerationPolicyTarget>(json!({
                "kind": "actor",
                "did": "did:web:actor.example"
            }))
            .is_err()
        );
    }

    #[test]
    fn fork_resolution_collision_requires_canonical_bytes_winner() {
        let valid = json!({
            "subject": {
                "kind": "event_id_collision",
                "event_id": "ak:event:AUl7i16DNG_PX5V_-ud5fDx65PwcMpaj4uSW2K4C0Ev9"
            },
            "conflict_evidence": {
                "kind": "full_hash_collision",
                "variants": [
                    {"kind": "inline_canonical_bytes", "canonical_event_bytes_b64u": "YQ"},
                    {"kind": "inline_canonical_bytes", "canonical_event_bytes_b64u": "Yg"}
                ]
            },
            "verdict": {
                "kind": "canonical_winner",
                "winner_index": 0
            }
        });
        serde_json::from_value::<ForkResolutionPayload>(valid.clone())
            .expect("canonical bytes winner");

        // A digest cannot name a variant when both variants hash to the same
        // Event identity, so the digest-only verdict has no referent.
        let mut digest_only = valid.clone();
        digest_only["verdict"] = json!({
            "kind": "canonical_winner",
            "winner_event_id": "ak:event:AUl7i16DNG_PX5V_-ud5fDx65PwcMpaj4uSW2K4C0Ev9"
        });
        assert!(serde_json::from_value::<ForkResolutionPayload>(digest_only).is_err());

        let mut outside = valid.clone();
        outside["verdict"]["winner_index"] = json!(2);
        assert!(serde_json::from_value::<ForkResolutionPayload>(outside).is_err());

        let mut one_variant = valid.clone();
        one_variant["conflict_evidence"]["variants"] = json!([
            {"kind": "inline_canonical_bytes", "canonical_event_bytes_b64u": "YQ"}
        ]);
        assert!(serde_json::from_value::<ForkResolutionPayload>(one_variant).is_err());

        let mut duplicate = valid;
        duplicate["conflict_evidence"]["variants"] = json!([
            {"kind": "inline_canonical_bytes", "canonical_event_bytes_b64u": "YQ"},
            {"kind": "inline_canonical_bytes", "canonical_event_bytes_b64u": "YQ"}
        ]);
        assert!(serde_json::from_value::<ForkResolutionPayload>(duplicate).is_err());
    }

    /// A near-1-MiB original Event cannot be inlined twice, so the record
    /// locator has to be a first-class way to name a collision variant.
    #[test]
    fn fork_resolution_collision_accepts_a_variant_record_locator() {
        let record = json!({
            "kind": "collision_variant_record",
            "collision_variant_record_id":
                "ak:collision_variant_record:01964140-0000-7000-8000-000000000000",
            "collision_variant_record_digest": format!("sha256:{}", "b".repeat(64))
        });
        let payload = json!({
            "subject": {
                "kind": "event_id_collision",
                "event_id": "ak:event:AUl7i16DNG_PX5V_-ud5fDx65PwcMpaj4uSW2K4C0Ev9"
            },
            "conflict_evidence": {
                "kind": "full_hash_collision",
                "variants": [
                    record.clone(),
                    {"kind": "inline_canonical_bytes", "canonical_event_bytes_b64u": "Yg"}
                ]
            },
            "verdict": {"kind": "canonical_winner", "winner_index": 0}
        });
        serde_json::from_value::<ForkResolutionPayload>(payload).expect("record locator winner");
    }

    /// Distinct fixture Event ids. The leading token octet selects the digest
    /// suite; construct complete 33-byte tokens so every value passes the same
    /// semantic identifier decoder as production input.
    fn fork_resolution_event_ids(count: usize) -> Vec<String> {
        let mut ids: Vec<String> = (0..count)
            .map(|index| {
                let mut digest = [0_u8; 32];
                digest[24..].copy_from_slice(&(index as u64 + 1).to_be_bytes());
                EventId::from_digest(arkret_canonical::DigestSuite::Sha256, digest).to_string()
            })
            .collect();
        ids.sort();
        ids
    }

    #[test]
    fn fork_resolution_sibling_evidence_is_minimal_sorted_and_binds_winner() {
        let ids = fork_resolution_event_ids(17);
        let valid = json!({
            "subject": {
                "kind": "event_sibling_position",
                "actor_id": {
                    "kind": "service",
                    "service_id": "ak:did_core:web:actor.example"
                },
                "actor_seq": 4
            },
            "conflict_evidence": {
                "kind": "bucket_overflow",
                "prev_frontier_digest": format!("sha256:{}", "a".repeat(64)),
                "event_ids": ids.clone()
            },
            "verdict": {"kind": "canonical_winner", "winner_event_id": ids[0].clone()}
        });
        serde_json::from_value::<ForkResolutionPayload>(valid.clone()).expect("sorted winner");

        // 16 siblings are legal under the v1 single-bucket ceiling, so they do
        // not prove an overflow.
        let mut too_few = valid.clone();
        too_few["conflict_evidence"]["event_ids"] = json!(fork_resolution_event_ids(16));
        too_few["verdict"]["winner_event_id"] = json!(fork_resolution_event_ids(16)[0].clone());
        assert!(serde_json::from_value::<ForkResolutionPayload>(too_few).is_err());

        let mut outside = valid.clone();
        outside["verdict"]["winner_event_id"] =
            json!("ak:event:AUl7i16DNG_PX5V_-ud5fDx65PwcMpaj4uSW2K4C9999");
        assert!(serde_json::from_value::<ForkResolutionPayload>(outside).is_err());

        let mut reversed = valid.clone();
        let mut descending = ids.clone();
        descending.reverse();
        reversed["conflict_evidence"]["event_ids"] = json!(descending);
        assert!(serde_json::from_value::<ForkResolutionPayload>(reversed).is_err());

        // The bucket digest belongs to the evidence: inside the subject it
        // would split one position into two conflicting resolution cells.
        let mut bucket_in_subject = valid;
        bucket_in_subject["subject"]["prev_frontier_digest"] =
            json!(format!("sha256:{}", "a".repeat(64)));
        assert!(serde_json::from_value::<ForkResolutionPayload>(bucket_in_subject).is_err());
    }

    #[test]
    fn fork_resolution_cross_bucket_overflow_shares_the_position_cell_subject() {
        let subject = json!({
            "kind": "event_sibling_position",
            "actor_id": {"kind": "service", "service_id": "ak:did_core:web:actor.example"},
            "actor_seq": 4
        });
        let bucket = json!({
            "subject": subject,
            "conflict_evidence": {
                "kind": "actor_seq_overflow",
                "event_ids": fork_resolution_event_ids(65)
            },
            "verdict": {"kind": "void_all"}
        });
        let cross: ForkResolutionPayload =
            serde_json::from_value(bucket).expect("cross-bucket overflow");
        let ids = fork_resolution_event_ids(17);
        let single: ForkResolutionPayload = serde_json::from_value(json!({
            "subject": {
                "kind": "event_sibling_position",
                "actor_id": {"kind": "service", "service_id": "ak:did_core:web:actor.example"},
                "actor_seq": 4
            },
            "conflict_evidence": {
                "kind": "bucket_overflow",
                "prev_frontier_digest": format!("sha256:{}", "a".repeat(64)),
                "event_ids": ids
            },
            "verdict": {"kind": "void_all"}
        }))
        .expect("single-bucket overflow");
        assert_eq!(
            cross.subject.cell_subject_key().unwrap(),
            single.subject.cell_subject_key().unwrap(),
            "both overflow shapes at one position must normalize into one cell"
        );
    }

    #[test]
    fn fork_resolution_domain_conflict_needs_a_registered_cell_family() {
        let ids = fork_resolution_event_ids(2);
        let valid = json!({
            "subject": {
                "kind": "event_sibling_position",
                "actor_id": {"kind": "service", "service_id": "ak:did_core:web:actor.example"},
                "actor_seq": 4
            },
            "conflict_evidence": {
                "kind": "domain_non_joinable",
                "cell_family": "ak.component.notary.v1",
                "event_ids": ids.clone()
            },
            "verdict": {"kind": "canonical_winner", "winner_event_id": ids[0].clone()}
        });
        serde_json::from_value::<ForkResolutionPayload>(valid.clone()).expect("domain conflict");

        let mut unregistered = valid;
        unregistered["conflict_evidence"]["cell_family"] = json!("notary");
        assert!(serde_json::from_value::<ForkResolutionPayload>(unregistered).is_err());
    }

    #[test]
    fn fork_resolution_rejects_a_mismatched_subject_and_evidence_branch() {
        let payload = json!({
            "subject": {
                "kind": "event_id_collision",
                "event_id": "ak:event:AUl7i16DNG_PX5V_-ud5fDx65PwcMpaj4uSW2K4C0Ev9"
            },
            "conflict_evidence": {
                "kind": "actor_seq_overflow",
                "event_ids": fork_resolution_event_ids(65)
            },
            "verdict": {"kind": "void_all"}
        });
        assert!(serde_json::from_value::<ForkResolutionPayload>(payload).is_err());
    }

    const COLLISION_RECORD_REALM: &str = "ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5";
    const COLLISION_RECORD_ID: &str =
        "ak:collision_variant_record:01964140-0000-7000-8000-000000000000";

    fn collision_variant(nonce: &str) -> Event {
        test_support::raw_event_for_actor_at(
            "ak.note.create",
            ScopeRef::Realm {
                realm_id: RealmId::new(COLLISION_RECORD_REALM).unwrap(),
            },
            ActorId::service(DidCoreId::new("ak:did_core:web:fixture-actor.example").unwrap()),
            7,
            Hlc::new("01970e589d21-0000-a13f9c2e").unwrap(),
            json!({"nonce": nonce}),
            "2026-05-01T00:00:00.000Z".parse().unwrap(),
        )
        .expect("collision variant envelope")
    }

    fn collision_variant_record(variant: &Event) -> CollisionVariantRecord {
        let bytes =
            arkret_canonical::canonical_json_bytes(&variant.digest_payload().unwrap()).unwrap();
        let mut record = CollisionVariantRecord {
            schema: SchemaId::CollisionVariantRecordV1,
            collision_variant_record_id: CollisionVariantRecordId::new(COLLISION_RECORD_ID)
                .unwrap(),
            realm_id: variant.realm_id.clone(),
            collision_event_id: variant.event_id.clone(),
            canonical_event_bytes_b64u: Base64UrlString::new(arkret_canonical::base64url_encode(
                &bytes,
            ))
            .unwrap(),
            canonical_event_size_bytes: bytes.len() as u64,
            recorded_at: "2026-05-01T00:00:00.000Z".parse().unwrap(),
            proof: PayloadProof {
                kind: "detached_jws".to_owned(),
                verification_method: DidUrl::new(
                    "did:web:recovery.example#ed25519-2026-05-fixture",
                )
                .unwrap(),
                payload_digest: Hash::new(format!("sha256:{}", "0".repeat(64))).unwrap(),
                created_at: "2026-05-02T00:00:00.000Z".parse().unwrap(),
                domain: None,
                audience: None,
                proof_purpose: None,
                jws: "eyJhbGciOiJFZDI1NTE5In0..c2ln".to_owned(),
            },
        };
        record.proof.payload_digest = record.unsigned_payload_digest().unwrap();
        record
    }

    #[test]
    fn collision_variant_record_matches_its_registered_schema() {
        let registry = arkret_schema_conformance::schema_registry_from_default_spec_artifacts()
            .unwrap()
            .expect("spec schema registry");
        let record = collision_variant_record(&collision_variant("a"));
        registry
            .validate_value(
                SchemaId::COLLISION_VARIANT_RECORD_V1,
                &serde_json::to_value(&record).unwrap(),
            )
            .expect("record matches the registered schema");
    }

    #[test]
    fn collision_variant_record_recomputes_its_own_identity_and_realm() {
        let suite = arkret_canonical::DigestSuite::Sha256;
        let record = collision_variant_record(&collision_variant("a"));
        record.validate(suite).expect("self-consistent record");

        // The carried identity is never the answer: a record naming someone
        // else's Event is exactly how a forged collision would be introduced.
        let mut foreign_identity = record.clone();
        foreign_identity.collision_event_id =
            EventId::new("ak:event:AUl7i16DNG_PX5V_-ud5fDx65PwcMpaj4uSW2K4C0Ev9").unwrap();
        foreign_identity.proof.payload_digest = foreign_identity.unsigned_payload_digest().unwrap();
        assert!(
            foreign_identity
                .validate(suite)
                .unwrap_err()
                .to_string()
                .contains(ReasonCode::EVENT_ID_DIGEST_MISMATCH)
        );

        let mut foreign_realm = record.clone();
        foreign_realm.realm_id =
            RealmId::new("ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj6").unwrap();
        foreign_realm.proof.payload_digest = foreign_realm.unsigned_payload_digest().unwrap();
        assert!(foreign_realm.validate(suite).is_err());

        // A truncated transfer must not pass itself off as a shorter preimage.
        let mut short = record.clone();
        short.canonical_event_size_bytes -= 1;
        short.proof.payload_digest = short.unsigned_payload_digest().unwrap();
        assert!(short.validate(suite).is_err());

        let mut resigned_elsewhere = record;
        resigned_elsewhere.proof.payload_digest =
            Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap();
        assert!(resigned_elsewhere.validate(suite).is_err());
    }

    #[test]
    fn collision_variant_record_preimage_must_be_canonically_encoded() {
        let suite = arkret_canonical::DigestSuite::Sha256;
        let variant = collision_variant("a");
        let mut record = collision_variant_record(&variant);
        // Same Event, one stray space. It hashes to something no other
        // implementation reproduces, so a claim built on it is unverifiable.
        let mut loose =
            arkret_canonical::canonical_json_bytes(&variant.digest_payload().unwrap()).unwrap();
        loose.insert(1, b' ');
        record.canonical_event_bytes_b64u =
            Base64UrlString::new(arkret_canonical::base64url_encode(&loose)).unwrap();
        record.canonical_event_size_bytes = loose.len() as u64;
        record.proof.payload_digest = record.unsigned_payload_digest().unwrap();
        assert!(
            record
                .validate(suite)
                .unwrap_err()
                .to_string()
                .contains("not canonical")
        );
    }

    #[test]
    fn collision_evidence_requires_resolved_records_and_distinct_bytes() {
        let suite = arkret_canonical::DigestSuite::Sha256;
        let variant_a = collision_variant_record(&collision_variant("a"));
        let mut variant_b = collision_variant_record(&collision_variant("b"));
        variant_b.collision_variant_record_id = CollisionVariantRecordId::new(
            "ak:collision_variant_record:01964140-0000-7000-8000-000000000001",
        )
        .unwrap();
        variant_b.collision_event_id = variant_a.collision_event_id.clone();
        variant_b.proof.payload_digest = variant_b.unsigned_payload_digest().unwrap();

        let locator = |record: &CollisionVariantRecord| {
            ForkResolutionVariantLocator::CollisionVariantRecord {
                collision_variant_record_id: record.collision_variant_record_id.clone(),
                collision_variant_record_digest: record.content_digest(suite).unwrap(),
            }
        };
        let record = ForkResolutionRecord {
            realm_id: RealmId::new(COLLISION_RECORD_REALM).unwrap(),
            subject: ForkResolutionSubject::EventIdCollision {
                event_id: variant_a.collision_event_id.clone(),
            },
            conflict_evidence: ForkResolutionConflictEvidence::FullHashCollision {
                variants: vec![locator(&variant_a), locator(&variant_b)],
            },
            verdict: ForkResolutionVerdict::CollisionWinner {
                kind: ForkResolutionWinnerKind::CanonicalWinner,
                winner_index: 0,
            },
            resolution_event_digest: Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap(),
        };
        let resolution = test_support::raw_event_for_actor_at(
            "ak.fork.resolution",
            ScopeRef::Realm {
                realm_id: RealmId::new(COLLISION_RECORD_REALM).unwrap(),
            },
            ActorId::service(DidCoreId::new("ak:did_core:web:recovery.example").unwrap()),
            1,
            Hlc::new("01970e589d21-0000-a13f9c2f").unwrap(),
            json!({}),
            "2026-05-02T00:00:00.000Z".parse().unwrap(),
        )
        .expect("resolution Move envelope");

        // Nothing is resolved yet: this is a typed dependency miss, not a
        // licence to adjudicate on whatever the Move inlined.
        let missing = BTreeMap::new();
        assert!(
            record
                .validate_collision_evidence(&resolution, &missing, suite)
                .unwrap_err()
                .to_string()
                .contains(ReasonCode::DEPENDENCY_MISSING)
        );

        // Both variants recompute to one identity but hold different bytes,
        // which is the whole claim a collision resolution makes.
        let records = BTreeMap::from([
            (
                variant_a.collision_variant_record_id.clone(),
                variant_a.clone(),
            ),
            (
                variant_b.collision_variant_record_id.clone(),
                variant_b.clone(),
            ),
        ]);
        assert!(
            record
                .validate_collision_evidence(&resolution, &records, suite)
                .unwrap_err()
                .to_string()
                .contains(ReasonCode::EVENT_ID_DIGEST_MISMATCH),
            "distinct preimages cannot share one identity without a real collision"
        );
    }
}
