use super::super::snapshot::{canonicalize_strand_ref, membership_rank};
use super::super::*;
use super::RealmState;

impl RealmState {
    /// Extract morph_id from event content.
    pub(super) fn extract_morph_id(&self, content: &Value) -> Result<String> {
        self.extract_optional_field(content, "morph_id")
            .or_else(|| self.extract_optional_field(content, "id"))
            .ok_or_else(|| Error::Protocol("morph event requires morph_id or id".to_owned()))
    }

    /// Extract strand_id from event content.
    pub(super) fn extract_strand_id(&self, content: &Value) -> Result<String> {
        self.extract_optional_field::<String>(content, "strand_id")
            .or_else(|| self.extract_optional_field::<String>(content, "id"))
            .map(|value| canonicalize_strand_ref(&value))
            .ok_or_else(|| Error::Protocol("strand event requires strand_id".to_owned()))
    }

    /// Extract the container `space_id` from event content.
    pub(super) fn extract_space_id(&self, content: &Value) -> Result<String> {
        self.extract_optional_field::<String>(content, "space_id")
            .or_else(|| self.extract_optional_field::<String>(content, "id"))
            .ok_or_else(|| Error::Protocol("container event requires space_id".to_owned()))
    }

    /// Extract relation_id from event content.
    pub(super) fn extract_relation_id(&self, content: &Value) -> Result<String> {
        self.extract_optional_field(content, "relation_id")
            .or_else(|| self.extract_optional_field(content, "id"))
            .ok_or_else(|| Error::Protocol("relation event requires relation_id or id".to_owned()))
    }

    /// Extract a required field from event content.
    pub(super) fn extract_field<T: serde::de::DeserializeOwned>(
        &self,
        content: &Value,
        field: &str,
    ) -> Result<T> {
        let obj = content
            .as_object()
            .ok_or_else(|| Error::Protocol("event content must be an object".to_owned()))?;
        let value = obj
            .get(field)
            .ok_or_else(|| Error::Protocol(format!("missing field: {}", field)))?;

        serde_json::from_value(value.clone())
            .map_err(|_| Error::Protocol(format!("invalid field {}: wrong type", field)))
    }

    /// Extract an optional field from event content.
    pub(super) fn extract_optional_field<T: serde::de::DeserializeOwned>(
        &self,
        content: &Value,
        field: &str,
    ) -> Option<T> {
        let obj = content.as_object()?;
        let value = obj.get(field)?;
        serde_json::from_value(value.clone()).ok()
    }

    /// Extract fields map from event content.
    pub(super) fn extract_fields(&self, content: &Value) -> Result<BTreeMap<String, Value>> {
        Ok(self
            .extract_optional_field(content, "fields")
            .unwrap_or_default())
    }

    /// Derive the cell subject for an event from typed payload fields,
    /// per the spec event-kind-registry's `cell_subject` declaration.
    pub(super) fn subject_for_event(&self, event: &Event) -> Result<String> {
        match event.kind.as_str() {
            "ck.member.state" => self
                .extract_optional_field::<String>(&event.content, "actor_id")
                .or_else(|| self.extract_optional_field::<String>(&event.content, "principal_id"))
                .or_else(|| self.extract_optional_field::<String>(&event.content, "member_id"))
                .ok_or_else(|| {
                    Error::Protocol("member state requires payload.actor_id".to_owned())
                }),
            // Per spec event-kind-registry: all `ck.capability.*` kinds
            // declare `cell_subject.field = payload.grant_id` over the shared
            // `ck.component.capability.grant.v1` cell family.
            "ck.capability.grant"
            | "ck.capability.delegate"
            | "ck.capability.revoke"
            | "ck.capability.derived" => self
                .extract_optional_field::<String>(&event.content, "grant_id")
                .ok_or_else(|| {
                    Error::Protocol("capability event requires payload.grant_id".to_owned())
                }),
            "ck.realm.policy" | "ck.policy.set" => Ok(self
                .extract_optional_field::<String>(&event.content, "policy_id")
                .unwrap_or_else(|| "space_policy".to_owned())),
            "ck.invite.create" | "ck.invite.cancel" | "ck.invite.accept" => self
                .extract_optional_field::<String>(&event.content, "invite_id")
                .or_else(|| self.extract_optional_field::<String>(&event.content, "id"))
                .ok_or_else(|| Error::Protocol("invite event requires invite_id or id".to_owned())),
            "ck.read_cursor.advance" => self
                .extract_optional_field::<String>(&event.content, "scope")
                .or_else(|| self.extract_optional_field::<String>(&event.content, "target_ref"))
                .ok_or_else(|| {
                    Error::Protocol("read marker requires scope or target_ref".to_owned())
                }),
            // Realm lifecycle events use the realm_id as state key.
            "ck.realm.create"
            | "ck.realm.update"
            | "ck.realm.organization"
            | "ck.realm.link"
            | "ck.realm.inheritance_policy"
            | "ck.realm.join_rule"
            | "ck.realm.history_visibility"
            | "ck.realm.discovery"
            | "ck.realm.archive"
            | "ck.realm.freeze"
            | "ck.realm.destroy"
            | "ck.realm.upgrade" => Ok(event.realm_id.as_str().to_owned()),
            // View events use view_id as state key
            "ck.view.create" | "ck.view.update" | "ck.view.reconcile" => self
                .extract_optional_field::<String>(&event.content, "view_id")
                .or_else(|| self.extract_optional_field::<String>(&event.content, "id"))
                .ok_or_else(|| Error::Protocol("view event requires view_id or id".to_owned())),
            _ => Ok(String::new()),
        }
    }

    pub(super) fn generic_state_candidate_wins(
        existing: &ResolvedStateEvent,
        candidate: &ResolvedStateEvent,
    ) -> bool {
        if candidate.kind == "ck.member.state" && existing.kind == "ck.member.state" {
            let existing_rank = membership_rank(&existing.content);
            let candidate_rank = membership_rank(&candidate.content);
            if existing_rank != candidate_rank {
                return candidate_rank > existing_rank;
            }
        }

        candidate
            .hlc
            .cmp(&existing.hlc)
            .then_with(|| candidate.actor_id.as_str().cmp(existing.actor_id.as_str()))
            .then_with(|| candidate.actor_seq.cmp(&existing.actor_seq))
            .then_with(|| {
                candidate
                    .source_event_id
                    .as_str()
                    .cmp(existing.source_event_id.as_str())
            })
            .is_gt()
    }

    pub(super) fn message_candidate_wins(existing: &ResolvedMessage, candidate: &Event) -> bool {
        candidate
            .hlc
            .cmp(&existing.latest_hlc)
            .then_with(|| {
                candidate
                    .actor_id
                    .as_str()
                    .cmp(existing.latest_actor_id.as_str())
            })
            .then_with(|| candidate.actor_seq.cmp(&existing.latest_actor_seq))
            .then_with(|| {
                candidate
                    .event_id
                    .as_str()
                    .cmp(existing.latest_event_id.as_str())
            })
            .is_gt()
    }

    pub(super) fn reaction_candidate_wins(
        existing: &ResolvedReaction,
        candidate: &ResolvedReaction,
    ) -> bool {
        candidate
            .hlc
            .cmp(&existing.hlc)
            .then_with(|| candidate.actor_id.as_str().cmp(existing.actor_id.as_str()))
            .then_with(|| candidate.actor_seq.cmp(&existing.actor_seq))
            .then_with(|| {
                candidate
                    .source_event_id
                    .as_str()
                    .cmp(existing.source_event_id.as_str())
            })
            .is_gt()
    }
}
