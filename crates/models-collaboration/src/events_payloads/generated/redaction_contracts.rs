// @generated; do not edit by hand.
// Generator: tools/generate-closed-models.py
//
// Input: schemas/event-payload.schema.json
// sha256=140d80954da7fc35c298320ecd75b1ee6c9fc268ffbbfccbab10a19f879f3468
//
// Input: schemas/typed-current-result.schema.json
// sha256=9794e5f6afb46725da6449147dea930e65a3b535ffefdf5c0f3541306be35c63
//
// Bindings: tools/closed-model-bindings.json
// sha256=af95236e8ff82e50c34d7765747d25e44d52146a0301a74856e3530bb2a4bf50

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
