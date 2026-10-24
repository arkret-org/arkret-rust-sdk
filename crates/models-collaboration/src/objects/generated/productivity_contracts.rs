// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/account-blocklist.schema.json
// sha256=b8ff86553e660cc671db516597984cb9a27dc88da77b423869bb2aaaaf1ed452
//
// Input: schemas/event-payload.schema.json
// sha256=6e557b3350ecfe34a8c4836bb00abf61dce039fa6a5fbbc58b07ec74dbaaba7f
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Input: schemas/calendar-event.schema.json
// sha256=0d2cfc5291ce27be8aa7651beeb7692f9c6714823dae17fda78bbdbbfb7dc938
//
// Input: schemas/encrypted-envelope.schema.json
// sha256=a0f5bb09fcb5ae9612cd3a27c533f4bf7dfa29f0b19aa178443af54fa4817c10
//
// Bindings: tools/closed-model-bindings.json
// sha256=449548ffe916fc20fdfa401c27c8bb4c71e9b2b7d85b5d4534c920be64e8ac22

/// Counterpart: `account-blocklist.schema.json`.
/// Decrypted plaintext value of the holder-private `ak.account.blocklist`
/// account-data key, written only through `ak.account_data.set` under its
/// `expected_server_revision` CAS; the value carries no revision of its own.
///
/// Spec: `account-blocklist.schema.json`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBlocklistValue {
    pub entries: Vec<AccountBlocklistEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}

/// Counterpart: `calendar-event.schema.json`.
/// Calendar schedule subtree carried at `metadata.fields.calendar` and
/// activated by `ak.schema.calendar_event.v1` in `Strand.schema_refs`.
///
/// The schedule never carries an absolute instant: timed events use a
/// whole-second RFC 8984 `LocalDateTime` resolved through `timezone` plus
/// `tzdb_version`. Field order mirrors `calendar-event.schema.json`.
///
/// [`Self::validate`] covers every rule expressible without the TZDB registry.
/// Resolving `timezone` to the canonical Zone of the pinned release requires
/// that registry, so it lives in `arkret-schema`, which is the layer that
/// embeds spec artifacts.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CalendarEventFields {
    pub start: String,
    pub end: String,
    pub timezone: String,
    pub tzdb_version: String,
    pub all_day: bool,
    pub status: CalendarStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub recurrence: Option<CalendarRecurrence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub location: Option<CalendarEventLocation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional"
    )]
    pub call_id: Option<CallId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attendees: Vec<CalendarAttendee>,
}
