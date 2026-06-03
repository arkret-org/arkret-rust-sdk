use super::*;

/// Capability grant.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<RealmId>,
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
    pub not_before: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
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
        if let (Some(child_from), Some(parent_from)) = (child.not_before, parent.not_before)
            && child_from < parent_from
        {
            return Err(Error::Protocol(format!(
                "capability grant '{}' starts before parent",
                child.id
            )));
        }
        if let (Some(child_until), Some(parent_until)) = (child.expires_at, parent.expires_at)
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
        if !matches!(event.kind.as_str(), "ck.capability.grant" | "ck.capability.delegate") {
            continue;
        }
        grants.push(capability_grant_from_resolved_event(event, Some(state.space_id.clone()))?);
    }

    Ok(grants)
}

fn capability_grant_from_resolved_event(
    event: &crate::resolver::ResolvedStateEvent,
    default_space_id: Option<RealmId>,
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
        not_before: optional_from_value(content.get("not_before"))?,
        expires_at: optional_from_value(content.get("expires_at"))?,
        revoked_by: optional_did(content, "revoked_by")?,
        revoked_at: optional_from_value(content.get("revoked_at"))?,
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
) -> Result<Option<RealmId>> {
    Ok(optional_string(content, field).map(RealmId::new).transpose()?)
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

// ─── S-10 (savfox SDK gap): ck.capability.grant builder ───────────────────

/// Build a `ck.capability.grant` Event Envelope content payload around
/// a [`CapabilityGrant`].
///
/// Chain verification (subject ⇒ issuer narrowing, action / resource
/// narrowing, time-window narrowing, cycle detection) is already in
/// [`validate_capability_frontier`]. This builder is the bookend: it
/// mints the Envelope that goes onto the wire.
#[derive(Clone, Debug)]
pub struct CapabilityGrantBuilder {
    realm_id: RealmId,
    /// The Envelope `actor_id` (signer / issuer of the grant).
    actor_id: Did,
    grant: CapabilityGrant,
}

impl CapabilityGrantBuilder {
    /// Construct a new builder bound to the issuing Realm + actor.
    /// `grant.issuer` MUST equal `actor_id`; the builder enforces this
    /// at `build` time.
    pub fn new(realm_id: RealmId, actor_id: Did, grant: CapabilityGrant) -> Self {
        Self { realm_id, actor_id, grant }
    }

    /// Override the grant subject (delegee).
    pub fn with_subject(mut self, subject: Did) -> Self {
        self.grant.subject = subject;
        self
    }

    /// Replace the allowed actions list.
    pub fn with_actions(mut self, actions: Vec<String>) -> Self {
        self.grant.actions = actions;
        self
    }

    /// Replace the resource selector list.
    pub fn with_resources(mut self, resources: Vec<ResourceSelector>) -> Self {
        self.grant.resources = resources;
        self
    }

    /// Mark this grant as delegable so children can chain off it.
    pub fn with_delegable(mut self, delegable: bool) -> Self {
        self.grant.delegable = delegable;
        self
    }

    /// Bind this grant to a parent grant id (chains the delegation).
    pub fn with_parent_grant_id(mut self, parent_grant_id: impl Into<String>) -> Self {
        self.grant.parent_grant_id = Some(parent_grant_id.into());
        self
    }

    pub fn with_constraints(mut self, constraints: Vec<ConstraintEntry>) -> Self {
        self.grant.constraints = constraints;
        self
    }

    pub fn with_not_before(mut self, not_before: DateTime<Utc>) -> Self {
        self.grant.not_before = Some(not_before);
        self
    }

    pub fn with_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.grant.expires_at = Some(expires_at);
        self
    }

    /// Materialize the unsigned `ck.capability.grant` Envelope.
    pub fn build(self, actor_seq: u64, hlc: crate::Hlc) -> Result<crate::Event> {
        if self.grant.issuer != self.actor_id {
            return Err(Error::Protocol(format!(
                "CapabilityGrantBuilder: grant.issuer '{}' does not match actor_id '{}'",
                self.grant.issuer, self.actor_id
            )));
        }
        let content = serde_json::to_value(&self.grant)?;
        crate::Event::new(
            crate::events::CAPABILITY_GRANT,
            self.realm_id,
            self.actor_id,
            actor_seq,
            hlc,
            content,
        )
    }
}

#[cfg(test)]
mod capability_grant_builder_tests {
    use super::*;

    fn realm() -> crate::RealmId {
        crate::RealmId::new("ck:realm:01904100-0000-7000-8000-65c7feb295d7").unwrap()
    }

    fn alice() -> Did {
        Did::new("did:web:alice.example").unwrap()
    }

    fn bob() -> Did {
        Did::new("did:web:bob.example").unwrap()
    }

    fn hlc() -> crate::Hlc {
        crate::Hlc::new("01970e589d21-0004-a13f9c2e").unwrap()
    }

    fn base_grant() -> CapabilityGrant {
        CapabilityGrant {
            id: "ck:grant:01904100-0000-7000-8000-aaaaaaaaaaaa".to_owned(),
            space_id: None,
            issuer: alice(),
            subject: bob(),
            actions: vec!["ck.message.create".to_owned()],
            resources: vec![ResourceSelector::Wildcard],
            constraints: Vec::new(),
            delegable: false,
            parent_grant_id: None,
            not_before: None,
            expires_at: None,
            revoked_by: None,
            revoked_at: None,
        }
    }

    #[test]
    fn capability_grant_builder_emits_canonical_kind() {
        let event =
            CapabilityGrantBuilder::new(realm(), alice(), base_grant()).build(1, hlc()).unwrap();
        assert_eq!(event.kind, crate::events::CAPABILITY_GRANT);
        assert_eq!(event.content["id"], "ck:grant:01904100-0000-7000-8000-aaaaaaaaaaaa");
        assert_eq!(event.content["issuer"], "did:web:alice.example");
        assert_eq!(event.content["subject"], "did:web:bob.example");
    }

    #[test]
    fn capability_grant_builder_rejects_issuer_actor_mismatch() {
        let err = CapabilityGrantBuilder::new(realm(), bob(), base_grant())
            .build(1, hlc())
            .expect_err("issuer / actor mismatch must be rejected");
        assert!(format!("{err}").contains("does not match"));
    }

    #[test]
    fn capability_chain_verifier_accepts_narrowing_child() {
        let parent = CapabilityGrant {
            id: "ck:grant:00000000-0000-7000-8000-000000000001".to_owned(),
            delegable: true,
            actions: vec!["*".to_owned()],
            ..base_grant()
        };
        let child = CapabilityGrant {
            id: "ck:grant:00000000-0000-7000-8000-000000000002".to_owned(),
            parent_grant_id: Some(parent.id.clone()),
            issuer: bob(),
            subject: Did::new("did:web:carol.example").unwrap(),
            actions: vec!["ck.message.create".to_owned()],
            ..base_grant()
        };
        let validation = validate_capability_frontier(&[parent, child]).unwrap();
        assert_eq!(validation.checked_grants, 2);
        assert!(validation.max_delegation_depth >= 1);
    }
}
