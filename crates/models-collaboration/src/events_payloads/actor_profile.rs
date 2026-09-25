//! Actor-profile event payloads and their registered `actor_profile` result
//! projections (`zh/discovery/profiles-presence.md` section 2.3).

use crate::internal_prelude::*;

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/actor_profile_create_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorProfileCreatePayload {
    pub object: ActorProfileDefinition,
}

impl ActorProfileCreatePayload {
    /// The create result: the profile id is this Event's own id retyped, the
    /// Realm is the carrying Event's Realm and the creation time is the
    /// envelope time.
    pub fn materialize(&self, event: &Event) -> Result<ActorProfile> {
        if event.kind != EventKind::ProfileCreate {
            return Err(WireError::Protocol(
                "actor profile create projection needs an ak.profile.create Event".to_owned(),
            ));
        }
        ActorProfile::materialize_create(
            self.object.clone(),
            ActorProfileId::from_event_id(&event.event_id),
            event.realm_id.clone(),
            event.created_at,
        )
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/actor_profile_update_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorProfileUpdatePayload {
    pub target_ref: ActorProfileId,
    pub patch: Patch,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

/// Root members the registered `ak.profile.update` `apply_patch` projection
/// may write; every other member is create-locked or reducer managed.
const UPDATE_ALLOWED_ROOTS: [&str; 6] = [
    "display_name",
    "handle",
    "agent_slug",
    "avatar_blob_ref",
    "accountable_principal_ids",
    "profile_fields",
];

impl ActorProfileUpdatePayload {
    pub fn validate_for_account_self_service(&self) -> Result<()> {
        self.validate_paths()?;
        for (path, _) in self.patch.iter() {
            if !account_profile_patch_path_allowed(path.as_str()) {
                return Err(WireError::Protocol(format!(
                    "account profile update patch path `{path}` is not writable"
                )));
            }
        }
        Ok(())
    }

    /// Reject every path outside the registered `allowed_paths` set; this
    /// also closes the create-locked `principal_id`/`actor_kind` and the
    /// reducer-managed `resolution` subtree.
    pub fn validate_paths(&self) -> Result<()> {
        self.patch.validate()?;
        for (path, _) in self.patch.iter() {
            let root = path.split('.').next().unwrap_or(path.as_str());
            if !UPDATE_ALLOWED_ROOTS.contains(&root)
                || reducer_managed_patch_reason("actor_profile", path).is_some()
            {
                return Err(WireError::Protocol(format!(
                    "actor profile update patch path `{path}` is not an allowed display path"
                )));
            }
        }
        Ok(())
    }

    /// The digest an optional `expected_state_digest` compares: SHA-256 over
    /// the RFC 8785 bytes of the complete current value.
    pub fn state_digest(current: &ActorProfile) -> Result<Hash> {
        Ok(Hash::new(canonical::sha256_digest(
            &canonical::canonical_json_bytes(current)?,
        ))?)
    }

    /// The update result: apply the patch to the frozen current value, keep
    /// the create-locked members, and derive `updated_by`/`updated_at` from
    /// this Event's actor and time.
    pub fn apply(&self, event: &Event, current: &ActorProfile) -> Result<ActorProfile> {
        if event.kind != EventKind::ProfileUpdate {
            return Err(WireError::Protocol(
                "actor profile update projection needs an ak.profile.update Event".to_owned(),
            ));
        }
        if current.id.as_ref() != Some(&self.target_ref) {
            return Err(WireError::Protocol(
                "ak.profile.update target_ref does not match the current profile".to_owned(),
            ));
        }
        self.validate_paths()?;
        if let Some(expected) = &self.expected_state_digest
            && *expected != Self::state_digest(current)?
        {
            return Err(WireError::Protocol(
                "expected_state_digest does not match the current Actor Profile".to_owned(),
            ));
        }
        let prestate = serde_json::to_value(current)?;
        let poststate = self.patch.apply(&prestate)?;
        let mut next: ActorProfile = serde_json::from_value(poststate)?;
        if next.id != current.id
            || next.schema != current.schema
            || next.realm_id != current.realm_id
            || next.principal_id != current.principal_id
            || next.actor_kind != current.actor_kind
            || next.created_at != current.created_at
            || next.resolution != current.resolution
        {
            return Err(WireError::Protocol(
                "actor profile update changed a create-locked member".to_owned(),
            ));
        }
        next.updated_by = Some(event.actor_id.clone());
        next.updated_at = Some(event.created_at);
        next.validate_display_members()?;
        Ok(next)
    }
}

fn account_profile_patch_path_allowed(path: &str) -> bool {
    if matches!(path, "display_name" | "avatar_blob_ref") {
        return true;
    }
    let Some(key) = path.strip_prefix("profile_fields.") else {
        return false;
    };
    let mut bytes = key.bytes();
    key.len() <= 64
        && bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const PRINCIPAL: &str = "ak:did_core:webvh:z6mkfixture";
    const STATION: &str = "ak:did_core:web:station.example";
    const REALM: &str = "ak:realm:ARmJMvTcKFyiF-V_8oL4mIoHfnlqERCrcgNBONtY4HQD";

    fn event(kind: &str, payload: Value, created_at: &str) -> Event {
        serde_json::from_value(json!({
            "event_id": "ak:event:AQsHmGu_9sPOyJ4aG8VlWQBp8wGGhdC-BjfAaXqrIbk-",
            "kind": kind,
            "realm_id": REALM,
            "scope_ref": {"kind": "realm", "realm_id": REALM},
            "actor_id": {"kind": "account", "account_id": {"principal_id": PRINCIPAL, "station_id": STATION}},
            "created_at": created_at,
            "payload": payload
        }))
        .unwrap()
    }

    fn created() -> ActorProfile {
        let payload: ActorProfileCreatePayload = serde_json::from_value(json!({
            "object": {
                "principal_id": PRINCIPAL,
                "actor_kind": "user",
                "display_name": "Alice",
                "profile_fields": {"bio": "hi"}
            }
        }))
        .unwrap();
        payload
            .materialize(&event(
                "ak.profile.create",
                serde_json::to_value(&payload).unwrap(),
                "2026-04-26T00:00:00.000Z",
            ))
            .unwrap()
    }

    #[test]
    fn create_derives_id_realm_and_time_from_the_event() {
        let profile = created();
        assert_eq!(
            profile.id.as_ref().map(ActorProfileId::as_str),
            Some("ak:actor_profile:AQsHmGu_9sPOyJ4aG8VlWQBp8wGGhdC-BjfAaXqrIbk-")
        );
        assert_eq!(profile.realm_id.as_ref().map(RealmId::as_str), Some(REALM));
        assert_eq!(profile.schema, ActorProfile::SCHEMA);
        assert!(profile.updated_by.is_none() && profile.updated_at.is_none());
    }

    #[test]
    fn update_is_a_delta_with_derived_update_members() {
        let current = created();
        let payload: ActorProfileUpdatePayload = serde_json::from_value(json!({
            "target_ref": current.id,
            "patch": {"display_name": "Alice C.", "profile_fields.bio": {"$op": "unset"}},
            "expected_state_digest": ActorProfileUpdatePayload::state_digest(&current).unwrap()
        }))
        .unwrap();
        let update = event(
            "ak.profile.update",
            serde_json::to_value(&payload).unwrap(),
            "2026-04-26T00:01:00.000Z",
        );
        let next = payload.apply(&update, &current).unwrap();
        assert_eq!(next.display_name, "Alice C.");
        assert!(next.profile_fields.is_empty());
        assert_eq!(next.updated_by.as_ref(), Some(&update.actor_id));
        assert_eq!(next.created_at, current.created_at);
    }

    #[test]
    fn update_rejects_locked_paths_foreign_targets_and_stale_digests() {
        let current = created();
        for patch in [
            json!({"principal_id": "ak:did_core:web:mallory.example"}),
            json!({"actor_kind": "agent"}),
            json!({"resolution.did": "did:web:mallory.example"}),
            json!({"created_at": "2026-01-01T00:00:00.000Z"}),
            json!({"schema": "ak.schema.other.v1"}),
        ] {
            let Ok(payload) = serde_json::from_value::<ActorProfileUpdatePayload>(json!({
                "target_ref": current.id,
                "patch": patch
            })) else {
                continue;
            };
            let update = event(
                "ak.profile.update",
                serde_json::to_value(&payload).unwrap(),
                "2026-04-26T00:01:00.000Z",
            );
            assert!(payload.apply(&update, &current).is_err(), "{patch}");
        }
        let stale: ActorProfileUpdatePayload = serde_json::from_value(json!({
            "target_ref": current.id,
            "patch": {"display_name": "Alice C."},
            "expected_state_digest": format!("sha256:{}", "0".repeat(64))
        }))
        .unwrap();
        let update = event(
            "ak.profile.update",
            serde_json::to_value(&stale).unwrap(),
            "2026-04-26T00:01:00.000Z",
        );
        assert!(stale.apply(&update, &current).is_err());
        let foreign: ActorProfileUpdatePayload = serde_json::from_value(json!({
            "target_ref": "ak:actor_profile:AWxu9WEa6ZSBa79XtJFqrj3WsshthqPPUDPk-cMq5gZM",
            "patch": {"display_name": "Alice C."}
        }))
        .unwrap();
        assert!(foreign.apply(&update, &current).is_err());
    }
}
