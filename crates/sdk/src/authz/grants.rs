use super::*;

#[cfg(feature = "full-surface")]
use crate::agent_workspace::AttachedAuthority;

/// Capability grant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    pub issuer: Did,
    pub subject: Did,
    pub actions: Vec<String>,
    pub resources: Vec<ResourceSelector>,
    #[serde(default)]
    pub constraints: Vec<ConstraintEntry>,
    #[serde(default)]
    pub delegable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_grant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    /// `cx.profile.agent_workspace.v1` — optional binding to a
    /// `cx.schema.agent_authority.v1` attestation. Reducer-enforced
    /// REQUIRED when grant subject is an agent DID whose
    /// agent_authority.acting_mode == "delegated_assistant". See
    /// `contrix-spec/spec/v1/zh/extensions/agent-workspace-profile.md §5`.
    #[cfg(feature = "full-surface")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attached_authority: Option<AttachedAuthority>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityFrontierValidation {
    pub checked_grants: usize,
    pub max_delegation_depth: u32,
}

/// Validate capability frontier invariants before using reduced grants.
pub fn validate_capability_frontier(
    grants: &[CapabilityGrant],
) -> Result<CapabilityFrontierValidation> {
    let mut by_id = HashMap::new();
    for grant in grants {
        if grant.id.trim().is_empty() {
            return Err(Error::Protocol("capability grant id is empty".to_owned()));
        }
        if grant.actions.is_empty() {
            return Err(Error::Protocol(format!("capability grant '{}' has no actions", grant.id)));
        }
        if grant.resources.is_empty() {
            return Err(Error::Protocol(format!(
                "capability grant '{}' has no resources",
                grant.id
            )));
        }
        if by_id.insert(grant.id.clone(), grant).is_some() {
            return Err(Error::Protocol(format!("duplicate capability grant id '{}'", grant.id)));
        }
    }

    let mut max_depth = 0;
    for grant in grants {
        let depth = validate_delegation_chain(grant, &by_id)?;
        max_depth = max_depth.max(depth);
    }

    Ok(CapabilityFrontierValidation {
        checked_grants: grants.len(),
        max_delegation_depth: max_depth,
    })
}

/// Reject unknown critical constraint objects in wire JSON before typed deserialization.
pub fn reject_unknown_critical_constraints(value: &Value, supported: &[&str]) -> Result<()> {
    let Some(constraints) = value.get("constraints").and_then(Value::as_array) else {
        return Ok(());
    };
    for constraint in constraints {
        let critical = constraint.get("critical").and_then(Value::as_bool).unwrap_or(false);
        if !critical {
            continue;
        }
        let constraint_type = constraint
            .get("type")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| {
                constraint.as_object().and_then(|object| {
                    object
                        .keys()
                        .find(|key| {
                            !matches!(
                                key.as_str(),
                                "critical" | "constraint_id" | "priority" | "effect"
                            )
                        })
                        .cloned()
                })
            })
            .ok_or_else(|| Error::Protocol("critical constraint is missing a type".to_owned()))?;
        if !supported.iter().any(|supported| *supported == constraint_type) {
            return Err(Error::Protocol(format!("unknown critical constraint: {constraint_type}")));
        }
    }
    Ok(())
}

fn validate_delegation_chain(
    grant: &CapabilityGrant,
    by_id: &HashMap<String, &CapabilityGrant>,
) -> Result<u32> {
    let mut depth = 0;
    let mut seen = HashSet::new();
    let mut child = grant;
    while let Some(parent_id) = &child.parent_grant_id {
        if !seen.insert(child.id.clone()) {
            return Err(Error::Protocol("capability delegation cycle detected".to_owned()));
        }
        let parent = by_id.get(parent_id).ok_or_else(|| {
            Error::Protocol(format!(
                "capability grant '{}' references missing parent '{}'",
                child.id, parent_id
            ))
        })?;
        if !parent.delegable {
            return Err(Error::Protocol(format!(
                "capability parent '{}' is not delegable",
                parent.id
            )));
        }
        if child.issuer != parent.subject {
            return Err(Error::Protocol(format!(
                "capability grant '{}' issuer does not match parent subject",
                child.id
            )));
        }
        if !actions_are_narrowed(&child.actions, &parent.actions) {
            return Err(Error::Protocol(format!(
                "capability grant '{}' widens delegated actions",
                child.id
            )));
        }
        if !resources_are_narrowed(&child.resources, &parent.resources) {
            return Err(Error::Protocol(format!(
                "capability grant '{}' widens delegated resources",
                child.id
            )));
        }
        if let (Some(child_from), Some(parent_from)) = (child.valid_from, parent.valid_from)
            && child_from < parent_from
        {
            return Err(Error::Protocol(format!(
                "capability grant '{}' starts before parent",
                child.id
            )));
        }
        if let (Some(child_until), Some(parent_until)) = (child.valid_until, parent.valid_until)
            && child_until > parent_until
        {
            return Err(Error::Protocol(format!(
                "capability grant '{}' expires after parent",
                child.id
            )));
        }
        depth += 1;
        child = parent;
    }
    Ok(depth)
}

fn actions_are_narrowed(child: &[String], parent: &[String]) -> bool {
    parent.iter().any(|action| action == "*")
        || child.iter().all(|action| parent.iter().any(|parent| parent == action))
}

fn resources_are_narrowed(child: &[ResourceSelector], parent: &[ResourceSelector]) -> bool {
    child.iter().all(|child| parent.iter().any(|parent| resource_is_narrowed(child, parent)))
}

fn resource_is_narrowed(child: &ResourceSelector, parent: &ResourceSelector) -> bool {
    if matches!(parent, ResourceSelector::Wildcard) || child == parent {
        return true;
    }
    match (child, parent) {
        (
            ResourceSelector::Flow { space_id, flow_id },
            ResourceSelector::Flow { space_id: parent_space, flow_id: parent_id },
        ) => {
            space_narrowed(space_id, parent_space)
                && option_narrowed(flow_id.as_ref(), parent_id.as_ref())
        }
        (
            ResourceSelector::Object { space_id, object_type, object_ref },
            ResourceSelector::Object {
                space_id: parent_space,
                object_type: parent_type,
                object_ref: parent_id,
            },
        ) => {
            space_narrowed(space_id, parent_space)
                && option_narrowed(object_type.as_ref(), parent_type.as_ref())
                && option_narrowed(object_ref.as_ref(), parent_id.as_ref())
        }
        (
            ResourceSelector::Message { space_id, message_id },
            ResourceSelector::Message { space_id: parent_space, message_id: parent_id },
        ) => {
            space_narrowed(space_id, parent_space)
                && option_narrowed(message_id.as_ref(), parent_id.as_ref())
        }
        (
            ResourceSelector::Policy { space_id, policy_id },
            ResourceSelector::Policy { space_id: parent_space, policy_id: parent_id },
        ) => {
            space_narrowed(space_id, parent_space)
                && option_narrowed(policy_id.as_ref(), parent_id.as_ref())
        }
        (
            ResourceSelector::Invite { space_id, invite_id },
            ResourceSelector::Invite { space_id: parent_space, invite_id: parent_id },
        ) => {
            space_narrowed(space_id, parent_space)
                && option_narrowed(invite_id.as_ref(), parent_id.as_ref())
        }
        (
            ResourceSelector::Space { space_id },
            ResourceSelector::Space { space_id: parent_space },
        ) => space_narrowed(space_id, parent_space),
        _ => false,
    }
}

fn space_narrowed(child: &str, parent: &str) -> bool {
    parent == "*" || child == parent
}

fn option_narrowed(child: Option<&String>, parent: Option<&String>) -> bool {
    match parent {
        None => true,
        Some(parent) => child.is_some_and(|child| child == parent),
    }
}

/// Extract active grant/delegate capability events from a resolved space state.
pub fn capability_grants_from_space_state(
    state: &crate::SpaceState,
) -> Result<Vec<CapabilityGrant>> {
    let mut grants = Vec::new();

    for event in state.resolved_state.values() {
        if !matches!(event.kind.as_str(), "cx.capability.grant" | "cx.capability.delegate") {
            continue;
        }
        grants.push(capability_grant_from_resolved_event(event, Some(state.space_id.clone()))?);
    }

    Ok(grants)
}

fn capability_grant_from_resolved_event(
    event: &crate::resolver::ResolvedStateEvent,
    default_space_id: Option<SpaceId>,
) -> Result<CapabilityGrant> {
    let content = event
        .content
        .as_object()
        .ok_or_else(|| Error::Protocol("capability content must be an object".to_owned()))?;
    let id = optional_string(content, "capability_id")
        .or_else(|| optional_string(content, "id"))
        .or_else(|| optional_string(content, "grant_id"))
        // Capability events carry their grant_id in payload.
        .ok_or_else(|| Error::Protocol("capability event missing grant_id / id".to_owned()))?;
    let issuer = optional_did(content, "issuer")?.unwrap_or_else(|| event.actor_id.clone());
    let subject = optional_did(content, "subject")?
        .ok_or_else(|| Error::Protocol("capability grant requires subject".to_owned()))?;
    let actions = string_array(content.get("actions"))
        .ok_or_else(|| Error::Protocol("capability grant requires actions".to_owned()))?;
    let resources =
        resource_selectors(content.get("resources").or_else(|| content.get("resource_selectors")))?
            .unwrap_or_else(|| {
                default_space_id
                    .as_ref()
                    .map(|space_id| {
                        vec![ResourceSelector::Space { space_id: space_id.as_str().to_owned() }]
                    })
                    .unwrap_or_default()
            });
    if resources.is_empty() {
        return Err(Error::Protocol("capability grant requires resources".to_owned()));
    }

    Ok(CapabilityGrant {
        id,
        space_id: optional_space_id(content, "space_id")?.or(default_space_id),
        issuer,
        subject,
        actions,
        resources,
        constraints: optional_from_value(content.get("constraints"))?.unwrap_or_default(),
        delegable: content.get("delegable").and_then(Value::as_bool).unwrap_or(false),
        parent_grant_id: optional_string(content, "parent_grant_id"),
        valid_from: optional_from_value(content.get("valid_from"))?,
        valid_until: optional_from_value(content.get("valid_until"))?,
        revoked_by: optional_did(content, "revoked_by")?,
        revoked_at: optional_from_value(content.get("revoked_at"))?,
        #[cfg(feature = "full-surface")]
        attached_authority: optional_from_value(content.get("attached_authority"))?,
    })
}

fn optional_string(content: &serde_json::Map<String, Value>, field: &str) -> Option<String> {
    content.get(field).and_then(Value::as_str).map(ToOwned::to_owned)
}

fn optional_did(content: &serde_json::Map<String, Value>, field: &str) -> Result<Option<Did>> {
    Ok(optional_string(content, field).map(Did::new).transpose()?)
}

fn optional_space_id(
    content: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<SpaceId>> {
    Ok(optional_string(content, field).map(SpaceId::new).transpose()?)
}

fn optional_from_value<T: serde::de::DeserializeOwned>(value: Option<&Value>) -> Result<Option<T>> {
    value.map(|value| serde_json::from_value(value.clone()).map_err(Error::from)).transpose()
}

fn string_array(value: Option<&Value>) -> Option<Vec<String>> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items.iter().filter_map(Value::as_str).map(ToOwned::to_owned).collect::<Vec<_>>()
        })
        .filter(|items| !items.is_empty())
}

fn resource_selectors(value: Option<&Value>) -> Result<Option<Vec<ResourceSelector>>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let array = value
        .as_array()
        .ok_or_else(|| Error::Protocol("capability resources must be an array".to_owned()))?;
    let mut selectors = Vec::with_capacity(array.len());
    for item in array {
        let selector = if let Some(selector) = item.as_str() {
            ResourceSelector::parse(selector)?
        } else {
            serde_json::from_value(item.clone())?
        };
        selectors.push(selector);
    }
    Ok(Some(selectors))
}
