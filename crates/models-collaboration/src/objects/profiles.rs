//! Strand track profiles, Morph object, identity-link binding, and
//! federation actor validation wire shapes (split from the former
//! the `arkret` umbrella `models::profiles` module).

use std::collections::{BTreeMap, BTreeSet};

use arkret_canonical::binding_contexts;
use arkret_models_crypto::encrypted_envelope::EncryptedEnvelope;
use arkret_wire::constants::MORPH_SCHEMA;
use arkret_wire::{
    CircleId, DeviceId, Did, Error, Hash, MorphId, ObjectStage, ObjectState, PolicyId, RealmId,
    Result, StrandId, TypedTrustDomainId, canonical,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events_payloads::morph_message::ContentBlock;
use crate::objects::strand::ObjectMetadata;

fn now_utc_canonical() -> DateTime<Utc> {
    arkret_canonical::normalize_timestamp_canonical(Utc::now())
}

/// Standard track profile names.
pub const STRAND_TRACK_NAME_SYNTHESIS: &str = "synthesis";
pub const STRAND_TRACK_NAME_DISCUSSION: &str = "discussion";

/// Per-track configuration carried as the value side of the `Strand.tracks` map.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct StrandTrackConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_primary: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
}

impl StrandTrackConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Standard `synthesis` track config.
    pub fn synthesis() -> Self {
        Self::default()
    }

    /// Standard `discussion` track config.
    pub fn discussion() -> Self {
        Self {
            profile: Some("discussion".to_owned()),
            ..Self::default()
        }
    }

    /// Standard `discussion` track config marked as the Strand's primary entry point.
    pub fn discussion_primary() -> Self {
        Self {
            is_primary: Some(true),
            ..Self::discussion()
        }
    }

    /// Set the track as the Strand's primary entry point.
    pub fn primary(mut self) -> Self {
        self.is_primary = Some(true);
        self
    }

    /// Set a profile string.
    pub fn with_profile(mut self, profile: impl Into<String>) -> Self {
        self.profile = Some(profile.into());
        self
    }

    /// Add one track-local UI metadata field.
    pub fn with_metadata_field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

/// Validate a `StrandTrack` map key against `^[a-z][a-z0-9_]{0,63}$`.
pub fn validate_strand_track_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(Error::Protocol(
            "StrandTrack name must be 1..=64 chars".to_owned(),
        ));
    }
    let mut chars = name.chars();
    let first = chars
        .next()
        .ok_or_else(|| Error::Protocol("StrandTrack name must not be empty".to_owned()))?;
    if !first.is_ascii_lowercase() {
        return Err(Error::Protocol(
            "StrandTrack name must start with [a-z]".to_owned(),
        ));
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return Err(Error::Protocol(format!(
                "StrandTrack name contains invalid character '{c}'"
            )));
        }
    }
    Ok(())
}

/// Resolve the primary track of a Strand.
pub fn resolve_primary_track<'a>(
    tracks: &'a BTreeMap<String, StrandTrackConfig>,
    profile_default: Option<&str>,
) -> Result<Option<(&'a String, &'a StrandTrackConfig)>> {
    let explicit: Vec<(&String, &StrandTrackConfig)> = tracks
        .iter()
        .filter(|(_, cfg)| cfg.is_primary == Some(true))
        .collect();
    match explicit.len() {
        0 => {}
        1 => return Ok(Some(explicit[0])),
        _ => {
            return Err(Error::Protocol(
                "Strand has more than one track with is_primary=true".to_owned(),
            ));
        }
    }
    if let Some((k, v)) = tracks.get_key_value(STRAND_TRACK_NAME_SYNTHESIS) {
        return Ok(Some((k, v)));
    }
    if tracks.len() == 1 {
        return Ok(tracks.iter().next());
    }
    if let Some(default_name) = profile_default
        && let Some((k, v)) = tracks.get_key_value(default_name)
    {
        return Ok(Some((k, v)));
    }
    Ok(None)
}

/// Morph `metadata` shape — shares [`ObjectMetadata`] with Strand. Morph carries
/// its data in the top-level `Morph.fields`, so `metadata.fields` stays empty
/// and is omitted from the wire (preserving the prior `MorphMetadata` shape of
/// `{title?, summary?, ...extra}`).
pub type MorphMetadata = ObjectMetadata;

fn serialize_non_empty_schema_refs<S>(
    schema_refs: &[String],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if schema_refs.is_empty() {
        return Err(serde::ser::Error::custom(
            "Morph.schema_refs must contain at least one schema ref",
        ));
    }
    schema_refs.serialize(serializer)
}

fn deserialize_non_empty_schema_refs<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let schema_refs = Vec::<String>::deserialize(deserializer)?;
    if schema_refs.is_empty() {
        return Err(serde::de::Error::custom(
            "Morph.schema_refs must contain at least one schema ref",
        ));
    }
    let mut seen = BTreeSet::new();
    for schema_ref in &schema_refs {
        if !seen.insert(schema_ref) {
            return Err(serde::de::Error::custom(format!(
                "Morph.schema_refs contains duplicate schema ref `{schema_ref}`"
            )));
        }
    }
    Ok(schema_refs)
}

/// Morph object (data-structures.md §7).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct Morph {
    pub id: MorphId,
    pub schema: String,
    pub realm_id: RealmId,
    /// AKP-0007 (spec b7d35be) — optional Circle scope binding. Morphs that
    /// carry confidential synthesis fields can be bound to a Circle so their
    /// payload is encrypted inside that Circle's MLS group.
    ///
    /// Declaration order mirrors `morph.schema.json`: `realm_id`,
    /// `scope_circle_id`, `schema_refs`, …
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<CircleId>,
    /// Round C47 (spec e10b6ad): authoritative schema set for Morph fields and
    /// transition validation. Reducers MUST validate Morph fields against
    /// exactly these refs (set-equal compare on `ak.morph.schema_migrate`);
    /// `morph_type` / `facets` are not a replacement.
    #[serde(
        serialize_with = "serialize_non_empty_schema_refs",
        deserialize_with = "deserialize_non_empty_schema_refs"
    )]
    pub schema_refs: Vec<String>,
    pub morph_type: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facets: BTreeMap<String, BTreeMap<String, Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<MorphMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
    pub encrypted_metadata: Option<EncryptedEnvelope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
    pub content: Option<ContentBlock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
    pub encrypted_content: Option<EncryptedEnvelope>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ObjectState>,
    /// Reducer-derived timestamp of the most recent `state` transition;
    /// preserved on deserialize, omitted by producers (servers populate it).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub state_changed_at: Option<DateTime<Utc>>,
    /// Business progress axis (spec `morph.schema.json` required `stage`).
    /// Only Strand/Morph carry a `stage`. Distinct from `state` (lifecycle).
    pub stage: ObjectStage,
    /// Reducer-derived timestamp of the last `stage` transition; preserved on
    /// deserialize, omitted by producers (servers populate it).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub stage_changed_at: Option<DateTime<Utc>>,
    pub created_by: Did,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

impl Morph {
    pub fn new(
        id: MorphId,
        realm_id: RealmId,
        morph_type: impl Into<String>,
        created_by: Did,
    ) -> Self {
        Self {
            id,
            schema: MORPH_SCHEMA.to_owned(),
            realm_id,
            scope_circle_id: None,
            schema_refs: vec![MORPH_SCHEMA.to_owned()],
            morph_type: morph_type.into(),
            facets: BTreeMap::new(),
            metadata: None,
            encrypted_metadata: None,
            content: None,
            encrypted_content: None,
            fields: BTreeMap::new(),
            state: Some(ObjectState::Active),
            state_changed_at: None,
            stage: ObjectStage::Draft,
            stage_changed_at: None,
            created_by,
            created_at: now_utc_canonical(),
            updated_by: None,
            updated_at: None,
        }
    }

    pub fn with_metadata_title(mut self, title: impl Into<String>) -> Self {
        self.metadata
            .get_or_insert_with(MorphMetadata::default)
            .title = Some(title.into());
        self
    }

    pub fn metadata_title(&self) -> Option<&str> {
        self.metadata
            .as_ref()
            .and_then(|metadata| metadata.title.as_deref())
    }

    pub fn metadata_summary(&self) -> Option<&str> {
        self.metadata
            .as_ref()
            .and_then(|metadata| metadata.summary.as_deref())
    }

    /// Validate that `morph_type` does not use the reserved `ak.` prefix
    /// for unregistered types (morph.md §3 / data-structures.md §7).
    pub fn validate_morph_type(&self, registered_ak_types: &[&str]) -> Result<()> {
        if self.morph_type.starts_with("ak.")
            && !registered_ak_types.contains(&self.morph_type.as_str())
        {
            return Err(Error::Protocol(format!(
                "morph_type '{}' uses reserved ak. prefix without registration",
                self.morph_type
            )));
        }
        if self.morph_type.trim().is_empty() {
            return Err(Error::Protocol("morph_type must not be empty".to_owned()));
        }
        Ok(())
    }
}

/// Constraint evaluation class (constraint-schema.md §2.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum IdentityLinkStatus {
    Active,
    Revoked,
}

fn identity_link_default_status() -> IdentityLinkStatus {
    IdentityLinkStatus::Active
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct IdentityLinkProof {
    pub verification_method: String,
    pub signature_algorithm: String,
    pub payload_digest: Hash,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct IdentityLink {
    pub schema: String,
    #[serde(default = "identity_link_default_status")]
    pub status: IdentityLinkStatus,
    pub pairwise_did: Did,
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub realm_id: RealmId,
    pub trust_domain: TypedTrustDomainId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strand_id: Option<StrandId>,
    #[serde(
        rename = "track_name",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub track: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mls_group_id: Option<String>,
    pub mls_leaf_index: u64,
    pub mls_epoch: u64,
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp"
    )]
    pub effective_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disclosure_policy_id: Option<PolicyId>,
    pub proof: IdentityLinkProof,
}

impl IdentityLink {
    pub const SCHEMA: &'static str = "ak.schema.identity_link.v1";

    pub fn validate_minimal(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(Error::Protocol(
                "identity_link schema must be ak.schema.identity_link.v1".to_owned(),
            ));
        }
        if self.strand_id.is_some() && self.track.as_deref().is_none_or(str::is_empty) {
            return Err(Error::Protocol(
                "identity_link strand_id requires track_name".to_owned(),
            ));
        }
        if let Some(track_name) = self.track.as_deref() {
            validate_strand_track_name(track_name)?;
        }
        if self.proof.verification_method.trim().is_empty()
            || self.proof.signature_algorithm.trim().is_empty()
            || self.proof.signature.trim().is_empty()
        {
            return Err(Error::Protocol(
                "identity_link proof requires verification_method, signature_algorithm, and signature"
                    .to_owned(),
            ));
        }
        let expected = self.canonical_payload_digest()?;
        if self.proof.payload_digest != expected {
            return Err(Error::Protocol(
                "identity_link proof payload_digest mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_proof_input(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self).map_err(|error| {
            Error::Protocol(format!("identity_link serialization failed: {error}"))
        })?;
        if let Value::Object(object) = &mut value
            && let Some(Value::Object(proof)) = object.get_mut("proof")
        {
            proof.remove("payload_digest");
            proof.remove("signature");
        }
        let canonical = canonical::canonical_json_bytes(&value)?;
        let mut input =
            Vec::with_capacity(binding_contexts::IDENTITY_LINK_PREFIX.len() + canonical.len());
        input.extend_from_slice(binding_contexts::IDENTITY_LINK_PREFIX);
        input.extend_from_slice(&canonical);
        Ok(input)
    }

    pub fn canonical_payload_digest(&self) -> Result<Hash> {
        let input = self.canonical_proof_input()?;
        Hash::new(canonical::sha256_digest(&input)).map_err(|error| {
            Error::Protocol(format!("identity_link payload hash invalid: {error}"))
        })
    }
}

/// Verification class returned by federation `verify_actor` (M-19).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum FederationActorValidationClass {
    Valid,
    Stale,
    Unknown,
    Invalid,
}
