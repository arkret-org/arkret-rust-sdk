// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/notification.schema.json
// sha256=45e7443fe58e3de2a8bbb6deaeb433ad8f66e1f52ae55bf67101f3541d192ec5
//
// Input: schemas/time.schema.json
// sha256=7d4e6b177c7028caef664ddbb893c09cef4ffab791f19fbff1d7d710a2104a61
//
// Bindings: tools/closed-model-bindings.json
// sha256=4262c38f5c99fc4a61ddb6e91e7b7f08062a8a80502ab2cc5dca79d57658ca4b

/// Counterpart: `notification.schema.json#/$defs/ordinary_projection_content`.
/// Counterpart for
/// `notification.schema.json#/$defs/ordinary_projection_content`: the current
/// content of one ordinary source-Event notification projection as it is
/// delivered on the account-subscribe `notifications` channel.
///
/// Four members of [`Notification`] are deliberately absent, and the absence is
/// the contract, not an omission: `id` is carried by the delta row, `schema` is
/// implied by the channel, `actor_id` is the authenticated account, and `state`
/// stays in the holder-private inbox
/// (`ak.notifications.inbox.<notification_id>` plus the read cursor). A Station
/// that put any of them on this row would be publishing a second source of
/// truth for inbox disposition. [`Self::into_notification`] is the only way
/// back to a full object, and it takes those four from the receiver's own
/// state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrdinaryProjectionContent {
    pub realm_id: RealmId,
    pub source_event_id: EventId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub source_ref: Option<NotificationSourceRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub strand_id: Option<StrandId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub track_name: Option<String>,
    pub notification_kind: OrdinaryNotificationKind,
    pub priority: NotificationPriority,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub preview: Option<BTreeMap<String, Value>>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "arkret_canonical::serde_helpers::serialize_optional_canonical_timestamp",
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional_timestamp"
    )]
    pub updated_at: Option<DateTime<Utc>>,
}
