//! Strand model and shared object metadata.

use std::collections::BTreeMap;

use arkret_models_crypto::encrypted_envelope::EncryptedEnvelope;
use arkret_wire::constants::STRAND_SCHEMA;
use arkret_wire::{CircleId, Did, Error, ObjectStage, ObjectState, RealmId, Result, StrandId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events_payloads::morph_message::ContentBlock;
use crate::governance::agent_participation::AgentParticipationPolicy;
use crate::objects::profiles::{
    STRAND_TRACK_NAME_DISCUSSION, STRAND_TRACK_NAME_SYNTHESIS, StrandTrackConfig,
    resolve_primary_track, validate_strand_track_name,
};

/// Shared `metadata` shape for materialised objects that carry
/// `metadata.title` / `metadata.summary` (Strand, Morph). Field set matches
/// `strand.schema.json#/$defs/strand_metadata` (common-fields §3): `title`, `summary`,
/// `fields`, plus a `#[serde(flatten)]` `extra` catch-all. Empty `fields` is
/// omitted from the wire (`skip_serializing_if`), so objects that do not use
/// `metadata.fields` (e.g. Morph, which carries top-level `fields`) serialise
/// identically to a metadata object without a `fields` member.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct ObjectMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl ObjectMetadata {
    pub fn with_title(title: impl Into<String>) -> Self {
        Self {
            title: Some(title.into()),
            ..Self::default()
        }
    }
}

/// Strand `metadata` shape — see [`ObjectMetadata`].
pub type StrandMetadata = ObjectMetadata;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
pub struct MessageMetadata {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// `message.schema.json#/$defs/message_metadata` key of the Agent Sidecar
/// exchange binding. Legal only inside `encrypted_metadata` plaintext of an
/// Event whose effective scope is the Sidecar backing Circle; forbidden in
/// plaintext metadata and shared Realm/Circle events (forbidden-wire-fields
/// `sidecar_exchange_binding`).
pub const MESSAGE_METADATA_SIDECAR_EXCHANGE_BINDING_KEY: &str = "sidecar_exchange_binding";

impl MessageMetadata {
    /// Fail-closed consumer accessor for the exchange binding. Any missing
    /// key, schema mismatch, unknown role, or field-validation failure yields
    /// `None` — the Event is then non-echo by default, while the carrying
    /// message still renders as an ordinary private message
    /// (`zh/models/sidecar.md` §7.2.1).
    pub fn sidecar_exchange_binding(
        &self,
    ) -> Option<crate::agent_operations::AgentSidecarEventExchangeBinding> {
        let value = self
            .extra
            .get(MESSAGE_METADATA_SIDECAR_EXCHANGE_BINDING_KEY)?;
        let binding: crate::agent_operations::AgentSidecarEventExchangeBinding =
            serde_json::from_value(value.clone()).ok()?;
        binding.validate().ok()?;
        Some(binding)
    }

    /// Producer setter: validates the binding before mounting it. Callers MUST
    /// only place the resulting metadata into `encrypted_metadata` plaintext
    /// of a Sidecar-scoped Event, never into plaintext `metadata`.
    pub fn set_sidecar_exchange_binding(
        &mut self,
        binding: &crate::agent_operations::AgentSidecarEventExchangeBinding,
    ) -> Result<()> {
        binding.validate()?;
        self.extra.insert(
            MESSAGE_METADATA_SIDECAR_EXCHANGE_BINDING_KEY.to_owned(),
            serde_json::to_value(binding).map_err(|_| {
                Error::Protocol("Sidecar exchange binding serialization failed".to_owned())
            })?,
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo-oapi", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct Strand {
    pub id: StrandId,
    pub schema: String,
    pub realm_id: RealmId,
    /// AKP-0007 (spec b7d35be) — optional Circle scope binding. When set, all
    /// Strand tracks share the referenced Circle's MLS group, membership and
    /// history visibility; when unset the Strand lives in the Realm-default
    /// scope. Rebinding `scope_circle_id` is forbidden by default (reducer
    /// reason `scope_rebind_forbidden`). The Circle's parent Realm MUST
    /// equal the Strand's Realm.
    ///
    /// Declaration order mirrors `spec/v1/artifacts/schemas/strand.schema.json`
    /// (common-fields §3.2): `id, schema, realm_id, scope_circle_id, …`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<CircleId>,
    /// Optional native-agent participation ceiling, wrapped by agent class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_participation: Option<AgentParticipationPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<StrandMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
    pub encrypted_metadata: Option<EncryptedEnvelope>,
    #[serde(rename = "content", skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
    pub body: Option<ContentBlock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "salvo-oapi", salvo(schema(value_type = serde_json::Value)))]
    pub encrypted_content: Option<EncryptedEnvelope>,
    /// Active Strand tracks keyed by canonical track name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tracks: BTreeMap<String, StrandTrackConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ObjectState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    pub state_changed_at: Option<DateTime<Utc>>,
    /// Optional business-progression stage. Orthogonal to lifecycle `state`.
    /// Mutated only via `ak.strand.stage.set`; constructors fill `draft`,
    /// while sparse wire objects may omit the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<ObjectStage>,
    /// Reducer-derived timestamp of the most recent `stage` transition;
    /// preserved on deserialize, omitted by producers (servers populate it).
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

impl Strand {
    pub fn new(id: StrandId, realm_id: RealmId, title: impl Into<String>, created_by: Did) -> Self {
        let mut tracks = BTreeMap::new();
        tracks.insert(
            STRAND_TRACK_NAME_SYNTHESIS.to_owned(),
            StrandTrackConfig::synthesis(),
        );
        Self {
            id,
            schema: STRAND_SCHEMA.to_owned(),
            realm_id,
            scope_circle_id: None,
            agent_participation: None,
            metadata: Some(StrandMetadata::with_title(title)),
            encrypted_metadata: None,
            body: None,
            encrypted_content: None,
            tracks,
            state: Some(ObjectState::Active),
            state_changed_at: None,
            stage: Some(ObjectStage::Draft),
            stage_changed_at: None,
            created_by,
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
        }
    }

    pub fn with_metadata_title(mut self, title: impl Into<String>) -> Self {
        self.metadata
            .get_or_insert_with(StrandMetadata::default)
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

    pub fn metadata_fields(&self) -> Option<&BTreeMap<String, Value>> {
        self.metadata.as_ref().map(|metadata| &metadata.fields)
    }

    /// Construct a Strand whose primary entry point is the `discussion` track.
    pub fn discussion(
        id: StrandId,
        realm_id: RealmId,
        title: impl Into<String>,
        created_by: Did,
    ) -> Self {
        let mut strand = Self::new(id, realm_id, title, created_by);
        let mut tracks = BTreeMap::new();
        tracks.insert(
            STRAND_TRACK_NAME_SYNTHESIS.to_owned(),
            StrandTrackConfig::synthesis(),
        );
        tracks.insert(
            STRAND_TRACK_NAME_DISCUSSION.to_owned(),
            StrandTrackConfig::discussion_primary(),
        );
        strand.tracks = tracks;
        strand
    }

    pub fn is_conversational(&self) -> bool {
        resolve_primary_track(&self.tracks, None)
            .ok()
            .flatten()
            .is_some_and(|(name, _)| name == STRAND_TRACK_NAME_DISCUSSION)
    }

    pub fn validate_title(&self) -> Result<()> {
        if self
            .metadata_title()
            .is_none_or(|title| title.trim().is_empty())
        {
            return Err(Error::Protocol("strand title must not be empty".to_owned()));
        }
        if self.tracks.is_empty() {
            return Err(Error::Protocol(
                "strand tracks must not be empty".to_owned(),
            ));
        }
        for track_name in self.tracks.keys() {
            validate_strand_track_name(track_name)?;
        }
        Ok(())
    }
}
