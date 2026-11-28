// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/current-state.schema.json
// sha256=303069f3b12147816e080f5948d4877f5444a1ff82f532785c8244cc0a173e34
//
// Bindings: tools/closed-model-bindings.json
// sha256=b4e6ef8619a8ab13fb2b01f284145948f8c4b76ec554079ef024afb647993bac

/// Counterpart: `current-state.schema.json#/$defs/current_realm_actor_key_backup_active_series`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentRealmActorKeyBackupActiveSeries {
    pub selector: RealmActorKeyBackupActiveSeriesSelector,
    pub source_stream_ref: arkret_wire::CommitStreamRef,
    pub revision: arkret_wire::CurrentRevision,
    pub value: RealmActorKeyBackupActiveSeriesValue,
}

/// Counterpart:
/// `current-state.schema.json#/$defs/realm_actor_key_backup_active_series_selector/properties/
/// kind`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorKeyBackupActiveSeriesSelectorKind {
    #[serde(rename = "realm_actor_key_backup_active_series")]
    Value,
}

/// Counterpart:
/// `current-state.schema.json#/$defs/realm_actor_key_backup_active_series_selector/properties/
/// backup_kind`.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RealmActorKeyBackupActiveSeriesSelectorBackupKind {
    #[serde(rename = "secret_storage")]
    Value,
}

/// Counterpart: `current-state.schema.json#/$defs/realm_actor_key_backup_active_series_selector`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorKeyBackupActiveSeriesSelector {
    pub kind: RealmActorKeyBackupActiveSeriesSelectorKind,
    pub actor_id: arkret_wire::ActorId,
    pub effective_scope: arkret_wire::ScopeRef,
    pub backup_kind: RealmActorKeyBackupActiveSeriesSelectorBackupKind,
}

/// Counterpart: `current-state.schema.json#/$defs/realm_actor_key_backup_active_series_value`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmActorKeyBackupActiveSeriesValue {
    pub active_series_id: arkret_wire::BackupSeriesId,
    pub series_pointer_version: u64,
    pub manager_ref: arkret_wire::CommittedEventRef,
    pub recovery_ref: arkret_wire::CommittedEventRef,
    pub recipient_ref: arkret_wire::CommittedEventRef,
}
