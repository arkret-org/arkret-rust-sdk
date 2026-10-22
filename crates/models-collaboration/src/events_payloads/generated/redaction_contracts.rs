// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=6c0740fab50fcb796331bad41ee632e0602de445969cee69c4962e45dab65b27
//
// Input: schemas/typed-current-result.schema.json
// sha256=af1796a65736414a650ecb791939112f02920d691fd8ee4b9e46397ad70aadbd
//
// Bindings: tools/closed-model-bindings.json
// sha256=c47c2cf65d6369093f5d7c6c29aaabfd64872c6277db759f4cd74b82db0a8236

/// Counterpart: `event-payload.schema.json#/$defs/cross_object_redaction_payload`.
/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/cross_object_redaction_payload`.
///
/// `ak.redaction` is the cross-object redaction kind. Per
/// `models/common-fields.md` Â§5.1 (Message exemption) its target set excludes
/// Message: `message_id` is not a member and `target_ref` cannot spell
/// `ak:message:`, because Message reaches `state=redacted` only through the
/// object-scoped `ak.message.redact`. This type is the single place that
/// decision is enforced; implementations MUST NOT keep a private prefix
/// allow/deny table beside it.
///
/// `target_ref` is the single target carrier. Its lexical space already covers
/// both object targets and `ak:event:` targets, so the registered
/// `ak.component.object.redaction.v1` cell subject is that one scalar and the
/// same target cannot be spelled two ways.
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CrossObjectRedactionPayload {
    pub target_ref: ObjectRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_non_null_optional")]
    pub preserve: Option<Vec<String>>,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/object_redaction_entry`.
/// One tagged `object_redaction` assertion: the accepting Event's canonical
/// dot and its unassembled redact payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRedactionEntry {
    pub tag_id: CanonicalEventDot,
    pub value: ObjectRedactionAssertionValue,
}

/// Counterpart: `typed-current-result.schema.json#/$defs/object_redaction_value`.
/// Closed value of the `object_redaction` typed current result
/// (`typed-current-result.schema.json#/$defs/object_redaction_value`): the
/// canonically sorted dot set of committed redactions of one subject. Both
/// writers only add a dot, and the object's own `state` and `redaction_ref`
/// are never mirrored here.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRedactionCurrentValue {
    pub assertions: Vec<ObjectRedactionEntry>,
}
