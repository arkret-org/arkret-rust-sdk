use super::super::snapshot::{canonicalize_strand_ref, membership_rank};
use super::super::*;
use super::RealmState;

pub(super) trait JsonFields {
    fn json_field(&self, field: &str) -> Option<&Value>;
}

impl JsonFields for Value {
    fn json_field(&self, field: &str) -> Option<&Value> {
        self.as_object()?.get(field)
    }
}

impl JsonFields for BTreeMap<String, Value> {
    fn json_field(&self, field: &str) -> Option<&Value> {
        self.get(field)
    }
}

impl RealmState {
    /// Extract Morph id from event content.
    pub(super) fn extract_morph_id(&self, content: &(impl JsonFields + ?Sized)) -> Result<String> {
        self.extract_optional_field(content, "target_ref")
            .or_else(|| self.extract_optional_field(content, "morph_id"))
            .or_else(|| self.extract_optional_field(content, "id"))
            .ok_or_else(|| {
                WireError::Protocol("morph event requires target_ref, morph_id, or id".to_owned())
            })
    }

    /// Extract strand_id from event content.
    pub(super) fn extract_strand_id(&self, content: &(impl JsonFields + ?Sized)) -> Result<String> {
        self.extract_optional_field::<String>(content, "strand_id")
            .or_else(|| self.extract_optional_field::<String>(content, "target_ref"))
            .or_else(|| self.extract_optional_field::<String>(content, "id"))
            .map(|value| canonicalize_strand_ref(&value))
            .ok_or_else(|| {
                WireError::Protocol("strand event requires target_ref or strand_id".to_owned())
            })
    }

    /// Extract the container `space_id` from event content.
    pub(super) fn extract_space_id(&self, content: &(impl JsonFields + ?Sized)) -> Result<String> {
        self.extract_optional_field::<String>(content, "space_id")
            .or_else(|| self.extract_optional_field::<String>(content, "id"))
            .ok_or_else(|| WireError::Protocol("container event requires space_id".to_owned()))
    }

    /// Extract relation_id from event content.
    pub(super) fn extract_relation_id(
        &self,
        content: &(impl JsonFields + ?Sized),
    ) -> Result<String> {
        self.extract_optional_field(content, "relation_id")
            .or_else(|| self.extract_optional_field(content, "id"))
            .ok_or_else(|| {
                WireError::Protocol("relation event requires relation_id or id".to_owned())
            })
    }

    /// Extract a required field from event content.
    pub(super) fn extract_field<T: serde::de::DeserializeOwned>(
        &self,
        content: &(impl JsonFields + ?Sized),
        field: &str,
    ) -> Result<T> {
        let value = content
            .json_field(field)
            .ok_or_else(|| WireError::Protocol(format!("missing field: {}", field)))?;

        serde_json::from_value(value.clone())
            .map_err(|_| WireError::Protocol(format!("invalid field {}: wrong type", field)))
    }

    /// Extract an optional field from event content.
    pub(super) fn extract_optional_field<T: serde::de::DeserializeOwned>(
        &self,
        content: &(impl JsonFields + ?Sized),
        field: &str,
    ) -> Option<T> {
        let value = content.json_field(field)?;
        serde_json::from_value(value.clone()).ok()
    }

    /// Extract fields map from event content.
    pub(super) fn extract_fields(
        &self,
        content: &(impl JsonFields + ?Sized),
    ) -> Result<BTreeMap<String, Value>> {
        Ok(self
            .extract_optional_field(content, "fields")
            .unwrap_or_default())
    }

    /// Derive the cell subject for an event from typed payload fields,
    /// per the spec event-kind-registry's `cell_subject` declaration.
    pub(super) fn subject_for_event(&self, event: &Event) -> Result<String> {
        match event.kind.as_str() {
            arkret_wire::event_kind_str::MEMBER_STATE => self
                .extract_optional_field::<String>(&event.payload, "actor_id")
                .or_else(|| self.extract_optional_field::<String>(&event.payload, "principal_id"))
                .or_else(|| self.extract_optional_field::<String>(&event.payload, "member_id"))
                .ok_or_else(|| {
                    WireError::Protocol("member state requires payload.actor_id".to_owned())
                }),
            // A grant mints its grant id from envelope.event_id; subsequent
            // capability operations address that cell through payload.grant_id.
            arkret_wire::event_kind_str::CAPABILITY_GRANT => {
                Ok(arkret_wire::GrantId::from_event_id(&event.event_id)
                    .as_str()
                    .to_owned())
            }
            arkret_wire::event_kind_str::CAPABILITY_REVOKE
            | arkret_wire::event_kind_str::CAPABILITY_RELINQUISH
            | arkret_wire::event_kind_str::CAPABILITY_DERIVED => self
                .extract_optional_field::<String>(&event.payload, "grant_id")
                .ok_or_else(|| {
                    WireError::Protocol("capability event requires payload.grant_id".to_owned())
                }),
            arkret_wire::event_kind_str::REALM_POLICY | arkret_wire::event_kind_str::POLICY_SET => {
                Ok(self
                    .extract_optional_field::<String>(&event.payload, "policy_id")
                    .unwrap_or_else(|| "space_policy".to_owned()))
            }
            arkret_wire::event_kind_str::INVITE_CREATE
            | arkret_wire::event_kind_str::INVITE_CANCEL
            | arkret_wire::event_kind_str::INVITE_ACCEPT => self
                .extract_optional_field::<String>(&event.payload, "invite_id")
                .or_else(|| self.extract_optional_field::<String>(&event.payload, "id"))
                .ok_or_else(|| {
                    WireError::Protocol("invite event requires invite_id or id".to_owned())
                }),
            arkret_wire::event_kind_str::READ_CURSOR_ADVANCE => self
                .extract_optional_field::<String>(&event.payload, "scope")
                .or_else(|| self.extract_optional_field::<String>(&event.payload, "target_ref"))
                .ok_or_else(|| {
                    WireError::Protocol("read marker requires scope or target_ref".to_owned())
                }),
            // `ak.realm.organization` declares a tuple `cell_subject`
            // `(organization_id, relationship)`; it is keyed by that composite
            // subject (matching the lattice registry `::` separator), NOT by
            // realm_id, so distinct organization/relationship statements coexist.
            arkret_wire::event_kind_str::REALM_ORGANIZATION => {
                let organization_id = self
                    .extract_optional_field::<String>(&event.payload, "organization_id")
                    .ok_or_else(|| {
                        WireError::Protocol(
                            "realm organization event requires payload.organization_id".to_owned(),
                        )
                    })?;
                let relationship = self
                    .extract_optional_field::<String>(&event.payload, "relationship")
                    .ok_or_else(|| {
                        WireError::Protocol(
                            "realm organization event requires payload.relationship".to_owned(),
                        )
                    })?;
                Ok(format!("{organization_id}::{relationship}"))
            }
            // Realm lifecycle events use the realm_id as state key.
            arkret_wire::event_kind_str::REALM_CREATE
            | arkret_wire::event_kind_str::REALM_PROFILE
            | arkret_wire::event_kind_str::REALM_LINK
            | arkret_wire::event_kind_str::REALM_INHERITANCE_POLICY
            | arkret_wire::event_kind_str::REALM_JOIN_RULE
            | arkret_wire::event_kind_str::REALM_HISTORY_ACCESS
            | arkret_wire::event_kind_str::REALM_DISCOVERY
            | arkret_wire::event_kind_str::REALM_ARCHIVE
            | arkret_wire::event_kind_str::REALM_FREEZE
            | arkret_wire::event_kind_str::REALM_DESTROY
            | arkret_wire::event_kind_str::REALM_UPGRADE => Ok(event.realm_id.as_str().to_owned()),
            // View events use view_id as state key
            arkret_wire::event_kind_str::VIEW_CREATE
            | arkret_wire::event_kind_str::VIEW_UPDATE
            | arkret_wire::event_kind_str::VIEW_RECONCILE => self
                .extract_optional_field::<String>(&event.payload, "view_id")
                .or_else(|| self.extract_optional_field::<String>(&event.payload, "id"))
                .ok_or_else(|| WireError::Protocol("view event requires view_id or id".to_owned())),
            _ => Ok(String::new()),
        }
    }

    pub(super) fn generic_state_candidate_wins(
        existing: &ResolvedStateEvent,
        candidate: &ResolvedStateEvent,
    ) -> bool {
        if candidate.kind == arkret_wire::event_kind_str::MEMBER_STATE
            && existing.kind == arkret_wire::event_kind_str::MEMBER_STATE
        {
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
