// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/current-state.schema.json
// sha256=b9b2fcecf87470a1def1e55bf536bdb637b04f0e6f42083d5ed9962a80b14c61
//
// Bindings: tools/closed-model-bindings.json
// sha256=bb8c3350621b1f35ac031f7e6919326951b3576cd3c52db20323ba3e6e740687

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
