//! Generic state event payloads.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use arkret_wire::{
    ActorId, AppletId, Did, DidCoreId, TrustDomainId, validate_canonical_idna_domain,
};

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

state_payload_with_subject!(
    OrganizationDiscoveryStatePayload,
    organization_principal_id,
    Did
);

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
    pub holder_principal_id: DidCoreId,
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
}
