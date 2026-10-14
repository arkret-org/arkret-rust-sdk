// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/account-blocklist.schema.json
// sha256=584c88087d88d5e92c024cf3c7c9396cc828789201325faf09993de7ee2060b7
//
// Input: schemas/event-payload.schema.json
// sha256=de27d59cb9c0ba1d3406094e8270d20e117f9583ea8f1ef314e561fde7a2161f
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Input: schemas/calendar-event.schema.json
// sha256=38fe22c271aff3c30bf76c08dbf26143c4b95ec1ad4b98d0a27ff005d0b7d7f1
//
// Input: schemas/encrypted-envelope.schema.json
// sha256=5f2752ea44fd1fbc9de2b85e1d89524b11ee593a43ddc700d52484230e874397
//
// Bindings: tools/closed-model-bindings.json
// sha256=0d15b2210f53e3ecb358b80e5858039829cf28976becf4e6cb7d83548e0c39dd

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
