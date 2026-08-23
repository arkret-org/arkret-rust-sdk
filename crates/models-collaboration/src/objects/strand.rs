//! Strand model and shared object metadata.

use std::collections::{BTreeMap, BTreeSet};

use arkret_models_crypto::encrypted_envelope::EncryptedEnvelope;
use arkret_wire::{
    CircleId, DidCoreId, ObjectStage, ObjectState, RealmId, Result, SchemaId, StrandId, WireError,
};
use chrono::{DateTime, Utc};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events_payloads::ContentBlock;
use crate::governance::agent_participation::AgentParticipationPolicy;
use crate::objects::profiles::{
    STRAND_TRACK_NAME_DISCUSSION, STRAND_TRACK_NAME_SYNTHESIS, StrandTrack, resolve_primary_track,
    validate_strand_track_name,
};

const STRAND_METADATA_FORBIDDEN_KEYS: &[&str] = &[
    "id",
    "schema",
    "realm_id",
    "stage",
    "stage_changed_at",
    "state",
    "state_changed_at",
    "tracks",
    "scope_circle_id",
    "created_by",
    "created_at",
    "updated_by",
    "updated_at",
    "content",
    "encrypted_content",
    "encrypted_payload",
];

/// Extensible user-readable Strand metadata.
#[derive(Clone, Debug, Default)]
pub struct StrandMetadata {
    pub title: Option<String>,
    pub summary: Option<String>,
    pub fields: BTreeMap<String, Value>,
    pub extra: BTreeMap<String, Value>,
}

impl StrandMetadata {
    pub fn with_title(title: impl Into<String>) -> Self {
        Self {
            title: Some(title.into()),
            ..Self::default()
        }
    }
}

impl Serialize for StrandMetadata {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        for key in self.extra.keys() {
            if matches!(key.as_str(), "title" | "summary" | "fields")
                || STRAND_METADATA_FORBIDDEN_KEYS.contains(&key.as_str())
            {
                return Err(serde::ser::Error::custom(format!(
                    "Strand metadata forbids `{key}`"
                )));
            }
        }
        let mut map = serializer.serialize_map(None)?;
        if let Some(title) = &self.title {
            map.serialize_entry("title", title)?;
        }
        if let Some(summary) = &self.summary {
            map.serialize_entry("summary", summary)?;
        }
        if !self.fields.is_empty() {
            map.serialize_entry("fields", &self.fields)?;
        }
        for (key, value) in &self.extra {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for StrandMetadata {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut raw = BTreeMap::<String, Value>::deserialize(deserializer)?;
        if let Some(key) = STRAND_METADATA_FORBIDDEN_KEYS
            .iter()
            .find(|key| raw.contains_key(**key))
        {
            return Err(serde::de::Error::custom(format!(
                "Strand metadata forbids `{key}`"
            )));
        }
        let title = raw
            .remove("title")
            .map(serde_json::from_value)
            .transpose()
            .map_err(serde::de::Error::custom)?;
        let summary = raw
            .remove("summary")
            .map(serde_json::from_value)
            .transpose()
            .map_err(serde::de::Error::custom)?;
        let fields = raw
            .remove("fields")
            .map(serde_json::from_value)
            .transpose()
            .map_err(serde::de::Error::custom)?
            .unwrap_or_default();
        Ok(Self {
            title,
            summary,
            fields,
            extra: raw,
        })
    }
}

/// Registered `(profile schema id, metadata.fields namespace)` pairs subject to
/// the bidirectional co-presence rule. v1 registers exactly one pair; adding a
/// Strand profile subtree means adding its pair here and in
/// `strand.schema.json` together, never in prose alone.
pub const PROFILE_SUBTREE_ACTIVATION_PAIRS: &[(&str, &str)] =
    &[(SchemaId::CALENDAR_EVENT_V1, "calendar")];

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MessageMetadata {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// `message.schema.json#/$defs/message_metadata` key of the Agent Sidecar
/// exchange binding. Legal only inside `encrypted_metadata` plaintext of an
/// Event whose effective scope is the native Sidecar; forbidden in
/// plaintext metadata and shared Realm/Circle events (forbidden-wire-fields
/// `sidecar_exchange_binding`).
pub const MESSAGE_METADATA_SIDECAR_EXCHANGE_BINDING_KEY: &str = "sidecar_exchange_binding";

impl MessageMetadata {
    /// Fail-closed consumer accessor for the exchange binding. Any missing
    /// key, schema mismatch, unknown role, or field-validation failure yields
    /// `None` — the Event is then non-echo by default, while the carrying
    /// message still renders as an ordinary private message
    /// (`zh/models/sidecar.md` §8).
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
                WireError::Protocol("Sidecar exchange binding serialization failed".to_owned())
            })?,
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Strand {
    /// The object id.
    ///
    /// Absent on the create payload: this kind's registry `id_source` is
    /// `event_derived`, so the id is `from_event_id(&create.event_id)` and a
    /// payload copy would be a second, forgeable truth (spec
    /// `zh/models/common-fields.md` section 6.0). Present on every projected
    /// snapshot, where the receiver has already derived it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<StrandId>,
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
    /// Authoritative schema set for profile-defined `metadata.fields` subtrees,
    /// and the only profile activation axis: `metadata.fields.profile` and
    /// `profile_refs` are forbidden impostors.
    ///
    /// Unlike Morph this field is optional — a plain discussion Strand carries
    /// no profile subtree and omits it rather than filling a placeholder id.
    /// The container self-schema `ak.schema.strand.v1` MUST NOT appear here.
    /// Every listed profile schema and its `metadata.fields` namespace MUST
    /// co-occur in both directions on the post-patch object; writers MUST also
    /// bind the same id in the Event `requirements.schema[]` so replay
    /// validates against the write-time schema.
    ///
    /// Declaration order mirrors `strand.schema.json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_refs: Option<Vec<String>>,
    /// Optional native-agent participation ceiling, wrapped by agent class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_participation: Option<AgentParticipationPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<StrandMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_metadata: Option<EncryptedEnvelope>,
    /// Strand base body, rendered as Description. This field is independent
    /// of every track and uses the canonical wire name `content` directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<ContentBlock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted_content: Option<EncryptedEnvelope>,
    /// Strand collaboration surfaces keyed by canonical track name.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub tracks: BTreeMap<String, StrandTrack>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ObjectState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
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
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub stage_changed_at: Option<DateTime<Utc>>,
    pub created_by: DidCoreId,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<DidCoreId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

impl Strand {
    pub const SCHEMA: &'static str = SchemaId::STRAND_V1;

    /// Build the object carried by an `ak.strand.create` payload.
    ///
    /// The id is deliberately absent: the accepted Event's complete 33-byte
    /// identity token is retyped as the projected [`StrandId`]. Producers must
    /// not mint a placeholder UUID or truncate that Event token merely to use
    /// a projected-object constructor.
    pub fn new_create(realm_id: RealmId, title: impl Into<String>, created_by: DidCoreId) -> Self {
        let mut tracks = BTreeMap::new();
        tracks.insert(
            STRAND_TRACK_NAME_SYNTHESIS.to_owned(),
            StrandTrack::synthesis(),
        );
        Self {
            id: None,
            schema: SchemaId::STRAND_V1.to_owned(),
            realm_id,
            scope_circle_id: None,
            schema_refs: None,
            agent_participation: None,
            metadata: Some(StrandMetadata::with_title(title)),
            encrypted_metadata: None,
            content: None,
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

    /// Build a materialized Strand snapshot with its already-derived id.
    pub fn new(
        id: StrandId,
        realm_id: RealmId,
        title: impl Into<String>,
        created_by: DidCoreId,
    ) -> Self {
        let mut strand = Self::new_create(realm_id, title, created_by);
        strand.id = Some(id);
        strand
    }

    pub fn has_schema_ref(&self, schema_id: &str) -> bool {
        self.schema_refs
            .as_ref()
            .is_some_and(|refs| refs.iter().any(|value| value == schema_id))
    }

    /// Checks the bidirectional co-presence rule for every registered profile
    /// pair on the post-patch object. v1 registers exactly one pair:
    /// `ak.schema.calendar_event.v1` and `metadata.fields.calendar`.
    ///
    /// Only decidable when plaintext `metadata` is present; an
    /// `encrypted_metadata` Strand is checked by the producer before encryption
    /// and by authorized clients after decryption.
    pub fn validate_profile_activation(&self) -> Result<()> {
        if let Some(refs) = &self.schema_refs {
            if refs.is_empty() {
                return Err(WireError::Protocol(
                    "strand schema_refs must be omitted rather than empty".to_owned(),
                ));
            }
            if refs.iter().any(|value| value == SchemaId::STRAND_V1) {
                return Err(WireError::Protocol(
                    "strand schema_refs must not list the container self-schema".to_owned(),
                ));
            }
            let unique = refs.iter().collect::<BTreeSet<_>>().len();
            if unique != refs.len() {
                return Err(WireError::Protocol(
                    "strand schema_refs must not contain duplicates".to_owned(),
                ));
            }
        }
        let Some(fields) = self.metadata_fields() else {
            // No plaintext metadata object: the co-presence half is not
            // decidable here.
            return Ok(());
        };
        for (schema_id, namespace) in PROFILE_SUBTREE_ACTIVATION_PAIRS {
            let has_ref = self.has_schema_ref(schema_id);
            let has_subtree = fields.contains_key(*namespace);
            if has_ref != has_subtree {
                return Err(WireError::Protocol(format!(
                    "strand schema_refs {schema_id} and metadata.fields.{namespace} must co-occur in both directions"
                )));
            }
        }
        Ok(())
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
        created_by: DidCoreId,
    ) -> Self {
        let mut strand = Self::new(id, realm_id, title, created_by);
        let mut tracks = BTreeMap::new();
        tracks.insert(
            STRAND_TRACK_NAME_SYNTHESIS.to_owned(),
            StrandTrack::synthesis(),
        );
        tracks.insert(
            STRAND_TRACK_NAME_DISCUSSION.to_owned(),
            StrandTrack::discussion_primary(),
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
            return Err(WireError::Protocol(
                "strand title must not be empty".to_owned(),
            ));
        }
        if self.tracks.is_empty() {
            return Err(WireError::Protocol(
                "strand tracks must not be empty".to_owned(),
            ));
        }
        for track_name in self.tracks.keys() {
            validate_strand_track_name(track_name)?;
        }
        Ok(())
    }

    /// Validate the three distinct Strand content surfaces and the closed v1
    /// track registry. Description is the top-level content pair, Synthesis is
    /// the pair inside `tracks.synthesis`, and Discussion content is carried by
    /// Message objects rather than by the track entry.
    pub fn validate_content_surfaces(&self) -> Result<()> {
        if self.content.is_some() && self.encrypted_content.is_some() {
            return Err(WireError::Protocol(
                "Strand Description content and encrypted_content are mutually exclusive"
                    .to_owned(),
            ));
        }
        if self.tracks.is_empty() {
            return Err(WireError::Protocol(
                "strand tracks must not be empty".to_owned(),
            ));
        }
        for (track_name, track) in &self.tracks {
            validate_strand_track_name(track_name)?;
            if track_name != STRAND_TRACK_NAME_SYNTHESIS
                && track_name != STRAND_TRACK_NAME_DISCUSSION
            {
                return Err(WireError::Protocol(format!(
                    "unregistered Strand track name: {track_name}"
                )));
            }
            if track.content.is_some() && track.encrypted_content.is_some() {
                return Err(WireError::Protocol(format!(
                    "tracks.{track_name}.content and encrypted_content are mutually exclusive"
                )));
            }
            if track_name == STRAND_TRACK_NAME_DISCUSSION
                && (track.content.is_some() || track.encrypted_content.is_some())
            {
                return Err(WireError::Protocol(
                    "discussion track content must use Message objects".to_owned(),
                ));
            }
        }
        if self.state == Some(ObjectState::Redacted)
            && (self.content.is_some()
                || self.encrypted_content.is_some()
                || self
                    .tracks
                    .get(STRAND_TRACK_NAME_SYNTHESIS)
                    .is_some_and(|track| {
                        track.content.is_some() || track.encrypted_content.is_some()
                    }))
        {
            return Err(WireError::Protocol(
                "redacted Strand must not retain Description or Synthesis content".to_owned(),
            ));
        }
        resolve_primary_track(&self.tracks, None)?;
        Ok(())
    }
}
