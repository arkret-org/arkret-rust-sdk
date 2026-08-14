use arkret_models_identity::handle::Handle;
use arkret_wire::DidCoreId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::events_payloads::message::{ContentBlockValidationError, ContentBlockValidationResult};

/// Content Block field carrying structured direct mention nodes.
///
/// Spec source: `models/strand-and-message.md §9.4.1` +
/// `models/content-types.md §3`.
pub const MENTION_NODE_FIELD: &str = "mentions";

/// Content Block field carrying structured broadcast mention nodes
/// (`models/strand-and-message.md §9.4.3`).
pub const AUDIENCE_MENTION_NODE_FIELD: &str = "audience_mentions";

/// AST discriminator of a direct mention node.
pub const MENTION_NODE_KIND: &str = "mention";

/// AST discriminator of a broadcast mention node.
pub const AUDIENCE_MENTION_NODE_KIND: &str = "audience_mention";

/// Structured `@mention` node embedded in message body.
///
/// Spec source: `models/strand-and-message.md §9.4` + `identity/identity-handles.md §3.8.1`.
///
/// The authoritative reference field is `subject_id` (principal
/// `did_core_id`). The handle / display strings are audit metadata only
/// (`handle_at_time` / `display_name_at_time` / `mention_text_original`)
/// and MUST NOT be used as the current display value or for actor
/// attribution — verifier / reducer / policy engine MUST ignore them and
/// read `subject_id` exclusively.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MentionKind {
    #[serde(rename = "mention")]
    Mention,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mention {
    pub kind: MentionKind,
    /// Principal DID of the mentioned subject. The ONLY field that
    /// participates in actor attribution, authorization, resolution and
    /// render lookup.
    pub subject_id: DidCoreId,
    /// Snapshot of the subject's display name at compose time. Persistent
    /// snapshot semantics (anti-impersonation guard).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name_at_time: Option<String>,
    /// Snapshot of the canonical `<localpart>:<domain>` handle at compose
    /// time. Audit / search / fallback metadata only; MUST NOT be used as
    /// the current display handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle_at_time: Option<Handle>,
    /// Controller principal DID captured when the mention came from a
    /// controller-scoped agent selector. Audit metadata only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_subject_id: Option<DidCoreId>,
    /// Controller handle snapshot from `@<controller-handle>/<agent_slug>`.
    /// Audit / search / fallback metadata only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_handle_at_time: Option<Handle>,
    /// Agent selector slug snapshot from `@<controller-handle>/<agent_slug>`.
    /// Audit / search / fallback metadata only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_slug_at_time: Option<String>,
    /// Original string the user typed (e.g. `@alice:acme.com`). Audit /
    /// search-index use only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mention_text_original: Option<String>,
    /// When the handle was resolved. Audit metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub resolved_at: Option<DateTime<Utc>>,
}

/// Canonical audience variants for an `audience_mention` AST node.
///
/// `StrandEngaged` is the v1 mapping for common UI token `@here`; it means
/// `strand_participants ∪ strand_watchers` and is never presence-filtered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AudienceMentionAudience {
    EffectiveScopeMembers,
    StrandParticipants,
    StrandWatchers,
    StrandEngaged,
    AssignedActors,
}

impl AudienceMentionAudience {
    pub fn from_ui_token(token: &str) -> Option<Self> {
        match token
            .trim()
            .trim_start_matches('@')
            .to_ascii_lowercase()
            .as_str()
        {
            "all" => Some(Self::EffectiveScopeMembers),
            "participants" => Some(Self::StrandParticipants),
            "watchers" => Some(Self::StrandWatchers),
            "here" => Some(Self::StrandEngaged),
            "assigned" | "assignees" => Some(Self::AssignedActors),
            _ => None,
        }
    }

    pub fn as_wire(self) -> &'static str {
        match self {
            Self::EffectiveScopeMembers => "effective_scope_members",
            Self::StrandParticipants => "strand_participants",
            Self::StrandWatchers => "strand_watchers",
            Self::StrandEngaged => "strand_engaged",
            Self::AssignedActors => "assigned_actors",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AudienceMentionKind {
    #[serde(rename = "audience_mention")]
    AudienceMention,
}

/// Structured broadcast mention node embedded in a Message content AST.
///
/// This node is not expanded into direct [`Mention`] entries in shared
/// history. Dispatcher-side expansion is gated by
/// `ak.message.mention.broadcast`, Realm/Circle audience policy, finite
/// recipient/quota limits, and receiver visibility.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AudienceMention {
    pub kind: AudienceMentionKind,
    pub audience: AudienceMentionAudience,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mention_text_original: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub resolved_at: Option<DateTime<Utc>>,
}

/// Message content AST mention node.
///
/// The v1 wire currently admits direct actor mentions and audience mentions.
/// Entity/object references are modeled separately as links or relation refs,
/// not as `mentions[]` entries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum MentionNode {
    Mention(Mention),
    AudienceMention(AudienceMention),
}

impl AudienceMention {
    pub fn new(audience: AudienceMentionAudience) -> Self {
        Self {
            kind: AudienceMentionKind::AudienceMention,
            audience,
            mention_text_original: None,
            resolved_at: None,
        }
    }

    pub fn from_ui_token(token: &str) -> Option<Self> {
        AudienceMentionAudience::from_ui_token(token).map(|audience| {
            Self::new(audience)
                .with_mention_text_original(format!("@{}", token.trim().trim_start_matches('@')))
        })
    }

    pub fn with_mention_text_original(mut self, text: impl Into<String>) -> Self {
        self.mention_text_original = Some(text.into());
        self
    }

    pub fn with_resolved_at(mut self, at: DateTime<Utc>) -> Self {
        self.resolved_at = Some(at);
        self
    }

    pub fn is_strand_engaged_here(&self) -> bool {
        self.audience == AudienceMentionAudience::StrandEngaged
    }

    /// Enforce the `strand-and-message.md §9.4.3` UI-token bindings that the
    /// closed `audience` enum alone cannot express: `@here` MUST map to
    /// `strand_engaged`, and a presence-filtered `@online` audience is only
    /// admissible under a separately declared profile.
    pub fn validate(&self) -> ContentBlockValidationResult<()> {
        let token = self
            .mention_text_original
            .as_deref()
            .map(str::trim)
            .unwrap_or_default();
        if token.eq_ignore_ascii_case("@online") {
            return Err(ContentBlockValidationError::new(
                "presence-filtered audience mention requires an explicit profile",
            ));
        }
        if token.eq_ignore_ascii_case("@here") && !self.is_strand_engaged_here() {
            return Err(ContentBlockValidationError::new(
                "@here MUST map to audience strand_engaged",
            ));
        }
        Ok(())
    }
}

/// Parse one canonical mention AST node.
///
/// Only the current wire shapes are admitted: `{"kind":"mention",...}` with a
/// `did_core_id` `subject_id`, and `{"kind":"audience_mention",...}` with a
/// closed `audience`. Both node types are `deny_unknown_fields`.
pub fn parse_mention_node(value: &Value) -> ContentBlockValidationResult<MentionNode> {
    match value.get("kind").and_then(Value::as_str) {
        Some(MENTION_NODE_KIND) => serde_json::from_value::<Mention>(value.clone())
            .map(MentionNode::Mention)
            .map_err(|_| ContentBlockValidationError::new("mention node is invalid")),
        Some(AUDIENCE_MENTION_NODE_KIND) => {
            let node = serde_json::from_value::<AudienceMention>(value.clone()).map_err(|_| {
                ContentBlockValidationError::new("audience mention node is invalid")
            })?;
            node.validate()?;
            Ok(MentionNode::AudienceMention(node))
        }
        _ => Err(ContentBlockValidationError::new(
            "mention node kind must be mention or audience_mention",
        )),
    }
}

/// Collect every mention AST node reachable from a Content Block tree.
///
/// `mentions[]` / `audience_mentions[]` are the canonical carriers, and every
/// entry in them MUST be a canonical node. Nodes discriminated by `kind`
/// elsewhere in the tree are collected as well so a nested part cannot smuggle
/// an unvalidated mention past the carrier check.
pub fn collect_mention_nodes(content: &Value) -> ContentBlockValidationResult<Vec<MentionNode>> {
    let mut nodes = Vec::new();
    collect_mention_nodes_into(content, &mut nodes)?;
    Ok(nodes)
}

/// Collect only the direct mention nodes of a Content Block tree, in wire
/// order. Broadcast nodes are dropped; they address an audience, not a subject.
pub fn collect_mention_subject_ids(
    content: &Value,
) -> ContentBlockValidationResult<Vec<DidCoreId>> {
    Ok(collect_mention_nodes(content)?
        .into_iter()
        .filter_map(|node| match node {
            MentionNode::Mention(mention) => Some(mention.subject_id),
            MentionNode::AudienceMention(_) => None,
        })
        .collect())
}

/// Collect only the broadcast mention nodes of a Content Block tree.
pub fn collect_audience_mention_nodes(
    content: &Value,
) -> ContentBlockValidationResult<Vec<AudienceMention>> {
    Ok(collect_mention_nodes(content)?
        .into_iter()
        .filter_map(|node| match node {
            MentionNode::AudienceMention(node) => Some(node),
            MentionNode::Mention(_) => None,
        })
        .collect())
}

/// Validate the mention carriers declared directly on one Content Block
/// object, without descending into `parts`.
pub(crate) fn validate_mention_carriers(
    object: &serde_json::Map<String, Value>,
) -> ContentBlockValidationResult<()> {
    for field in [MENTION_NODE_FIELD, AUDIENCE_MENTION_NODE_FIELD] {
        let Some(value) = object.get(field) else {
            continue;
        };
        let Some(entries) = value.as_array() else {
            return Err(ContentBlockValidationError::new(
                "mention carrier must be an array",
            ));
        };
        for entry in entries {
            parse_mention_node(entry)?;
        }
    }
    Ok(())
}

fn collect_mention_nodes_into(
    value: &Value,
    nodes: &mut Vec<MentionNode>,
) -> ContentBlockValidationResult<()> {
    match value {
        Value::Object(object) => {
            if matches!(
                object.get("kind").and_then(Value::as_str),
                Some(MENTION_NODE_KIND | AUDIENCE_MENTION_NODE_KIND)
            ) {
                nodes.push(parse_mention_node(value)?);
                return Ok(());
            }
            for (key, child) in object {
                if key == MENTION_NODE_FIELD || key == AUDIENCE_MENTION_NODE_FIELD {
                    let Some(entries) = child.as_array() else {
                        return Err(ContentBlockValidationError::new(
                            "mention carrier must be an array",
                        ));
                    };
                    for entry in entries {
                        nodes.push(parse_mention_node(entry)?);
                    }
                    continue;
                }
                collect_mention_nodes_into(child, nodes)?;
            }
        }
        Value::Array(entries) => {
            for entry in entries {
                collect_mention_nodes_into(entry, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

impl Mention {
    /// Construct a mention from its authoritative `subject_id`. Audit
    /// metadata is attached via the builder setters.
    pub fn new(subject_id: DidCoreId) -> Self {
        Self {
            kind: MentionKind::Mention,
            subject_id,
            display_name_at_time: None,
            handle_at_time: None,
            controller_subject_id: None,
            controller_handle_at_time: None,
            agent_slug_at_time: None,
            mention_text_original: None,
            resolved_at: None,
        }
    }

    pub fn with_handle_at_time(mut self, handle: Handle) -> Self {
        self.handle_at_time = Some(handle);
        self
    }

    pub fn with_display_name_at_time(mut self, name: impl Into<String>) -> Self {
        self.display_name_at_time = Some(name.into());
        self
    }

    pub fn with_agent_selector_metadata(
        mut self,
        controller_subject_id: DidCoreId,
        controller_handle_at_time: Handle,
        agent_slug_at_time: impl Into<String>,
    ) -> Self {
        self.controller_subject_id = Some(controller_subject_id);
        self.controller_handle_at_time = Some(controller_handle_at_time);
        self.agent_slug_at_time = Some(agent_slug_at_time.into());
        self
    }

    pub fn with_mention_text_original(mut self, text: impl Into<String>) -> Self {
        self.mention_text_original = Some(text.into());
        self
    }

    pub fn with_resolved_at(mut self, at: DateTime<Utc>) -> Self {
        self.resolved_at = Some(at);
        self
    }
}

impl MentionNode {
    pub fn mention(mention: Mention) -> Self {
        Self::Mention(mention)
    }

    pub fn audience_mention(audience_mention: AudienceMention) -> Self {
        Self::AudienceMention(audience_mention)
    }

    pub fn as_mention(&self) -> Option<&Mention> {
        match self {
            Self::Mention(mention) => Some(mention),
            Self::AudienceMention(_) => None,
        }
    }

    pub fn as_audience_mention(&self) -> Option<&AudienceMention> {
        match self {
            Self::Mention(_) => None,
            Self::AudienceMention(mention) => Some(mention),
        }
    }

    pub fn target_id(&self) -> &str {
        match self {
            Self::Mention(mention) => mention.subject_id.as_str(),
            Self::AudienceMention(mention) => mention.audience.as_wire(),
        }
    }

    pub fn mention_text_original(&self) -> Option<&str> {
        match self {
            Self::Mention(mention) => mention.mention_text_original.as_deref(),
            Self::AudienceMention(mention) => mention.mention_text_original.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mention_minimal_shape_round_trips() {
        let m = Mention::new(DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap());
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(json["kind"], "mention");
        assert!(json.get("subject_id").is_some());
        // Audit metadata omitted when unset.
        assert!(json.get("handle_at_time").is_none());
        assert!(json.get("display_name_at_time").is_none());
        let decoded: Mention = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, m);
    }

    #[test]
    fn mention_agent_selector_metadata_round_trips() {
        let m = Mention::new(DidCoreId::new("ak:did_core:webvh:z6mkfixtureagent").unwrap())
            .with_agent_selector_metadata(
                DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
                Handle::parse("alice:example.com").unwrap(),
                "summary",
            )
            .with_mention_text_original("@alice:example.com/summary");
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(
            json["controller_subject_id"],
            "ak:did_core:webvh:z6mkfixturealice"
        );
        assert_eq!(json["controller_handle_at_time"], "alice:example.com");
        assert_eq!(json["agent_slug_at_time"], "summary");
        let decoded: Mention = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, m);
    }

    #[test]
    fn audience_mention_here_maps_to_strand_engaged() {
        let node = AudienceMention::from_ui_token("@here").expect("@here should be known");
        assert_eq!(node.audience, AudienceMentionAudience::StrandEngaged);
        assert!(node.is_strand_engaged_here());
        let json = serde_json::to_value(&node).unwrap();
        assert_eq!(json["kind"], "audience_mention");
        assert_eq!(json["audience"], "strand_engaged");
    }

    #[test]
    fn mention_node_round_trips_actor_and_audience_variants() {
        let actor = MentionNode::mention(Mention::new(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturealice").unwrap(),
        ));
        let actor_json = serde_json::to_value(&actor).unwrap();
        assert_eq!(actor_json["kind"], "mention");
        let decoded_actor: MentionNode = serde_json::from_value(actor_json).unwrap();
        assert!(decoded_actor.as_mention().is_some());

        let audience = MentionNode::audience_mention(
            AudienceMention::from_ui_token("@all").expect("@all should be known"),
        );
        let audience_json = serde_json::to_value(&audience).unwrap();
        assert_eq!(audience_json["kind"], "audience_mention");
        let decoded_audience: MentionNode = serde_json::from_value(audience_json).unwrap();
        assert!(decoded_audience.as_audience_mention().is_some());
    }

    #[test]
    fn audience_mention_rejects_presence_online_without_profile() {
        assert!(AudienceMention::from_ui_token("@online").is_none());
        let node = serde_json::json!({
            "kind": "audience_mention",
            "audience": "strand_engaged",
            "mention_text_original": "@online"
        });
        assert_eq!(
            parse_mention_node(&node).unwrap_err().message(),
            "presence-filtered audience mention requires an explicit profile"
        );
    }

    #[test]
    fn audience_mention_rejects_here_mapped_off_strand_engaged() {
        let node = serde_json::json!({
            "kind": "audience_mention",
            "audience": "effective_scope_members",
            "mention_text_original": "@here"
        });
        assert_eq!(
            parse_mention_node(&node).unwrap_err().message(),
            "@here MUST map to audience strand_engaged"
        );
    }

    #[test]
    fn collect_mention_nodes_walks_carriers_and_parts() {
        let content = serde_json::json!({
            "kind": "ak.content.composite",
            "body": "",
            "parts": [
                {
                    "kind": "ak.content.text",
                    "body": "hi @bob",
                    "mentions": [{
                        "kind": "mention",
                        "subject_id": "ak:did_core:webvh:z6mkfixturebob"
                    }],
                    "audience_mentions": [{
                        "kind": "audience_mention",
                        "audience": "strand_engaged",
                        "mention_text_original": "@here"
                    }]
                }
            ]
        });
        assert_eq!(
            collect_mention_subject_ids(&content).unwrap(),
            vec![DidCoreId::new("ak:did_core:webvh:z6mkfixturebob").unwrap()]
        );
        assert_eq!(collect_audience_mention_nodes(&content).unwrap().len(), 1);
    }

    #[test]
    fn collect_mention_nodes_rejects_non_canonical_entries() {
        for entry in [
            serde_json::json!("ak:did_core:webvh:z6mkfixturebob"),
            serde_json::json!({"type": "actor", "did": "did:web:bob.example"}),
            serde_json::json!({"type": "strand", "strand_id": "ak:strand:x"}),
        ] {
            let content = serde_json::json!({
                "kind": "ak.content.text",
                "body": "hi",
                "mentions": [entry]
            });
            assert_eq!(
                collect_mention_nodes(&content).unwrap_err().message(),
                "mention node kind must be mention or audience_mention"
            );
        }
    }

    #[test]
    fn collect_mention_nodes_rejects_full_did_subject() {
        let content = serde_json::json!({
            "kind": "ak.content.text",
            "body": "hi",
            "mentions": [{"kind": "mention", "subject_id": "did:web:bob.example"}]
        });
        assert_eq!(
            collect_mention_nodes(&content).unwrap_err().message(),
            "mention node is invalid"
        );
    }
}
