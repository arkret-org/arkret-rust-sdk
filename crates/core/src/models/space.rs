//! Space container model.

use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct Space {
    pub id: SpaceId,
    pub schema: String,
    pub realm_id: RealmId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_realm_id: Option<RealmId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_space_id: Option<SpaceId>,
    // Declaration order mirrors `spec/v1/artifacts/schemas/space.schema.json`
    // (common-fields §3.2): the discriminator cluster `kind, rank, schema_refs`
    // precedes `title, summary`.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub schema_refs: Vec<String>,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<SpaceState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_changed_at: Option<DateTime<Utc>>,
    /// CKP-0007 (spec b7d35be) — optional Circle scope binding on the Space
    /// (container). Authorization-transparent: never carries its own
    /// membership/policy/E2EE group; this field places the Space's metadata
    /// inside an existing Circle encryption scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_circle_id: Option<CircleId>,
    /// CKP-0007 — optional default Circle scope for newly created child
    /// resources. Creation hint only; reducer enforcement uses
    /// [`ChildScopePolicy`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_scope_circle_id: Option<CircleId>,
    /// CKP-0007 — reducer-enforced constraint on how child resources may
    /// pick their scope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_scope_policy: Option<ChildScopePolicy>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[cfg_attr(feature = "salvo", salvo(schema(value_type = serde_json::Value)))]
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// CKP-0007 (spec b7d35be) — Space `child_scope_policy` discriminator.
///
/// Mirrors `spec/v1/artifacts/schemas/space.schema.json` `$defs.child_scope_policy`.
/// The `require_scope_circle_id` variant carries the required Circle id.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChildScopePolicy {
    /// Any scope is accepted, including unscoped.
    AllowAny {
        #[serde(skip_serializing_if = "Option::is_none")]
        metadata_encryption_floor: Option<EncryptionFloor>,
    },
    /// Child resources MUST live in an E2EE scope (any Circle or the
    /// Realm-default E2EE scope).
    RequireE2ee {
        #[serde(skip_serializing_if = "Option::is_none")]
        metadata_encryption_floor: Option<EncryptionFloor>,
    },
    /// Child resources MUST share the parent Space's `scope_circle_id`.
    RequireSameScope {
        #[serde(skip_serializing_if = "Option::is_none")]
        metadata_encryption_floor: Option<EncryptionFloor>,
    },
    /// Child resources MUST set `scope_circle_id` to the named Circle.
    RequireScopeCircleId {
        scope_circle_id: CircleId,
        #[serde(skip_serializing_if = "Option::is_none")]
        metadata_encryption_floor: Option<EncryptionFloor>,
    },
}

impl Space {
    pub fn new(
        id: SpaceId,
        realm_id: RealmId,
        kind: impl Into<String>,
        title: impl Into<String>,
        created_by: Did,
    ) -> Self {
        Self {
            id,
            schema: SPACE_SCHEMA.to_owned(),
            realm_id,
            default_realm_id: None,
            parent_space_id: None,
            kind: kind.into(),
            rank: None,
            schema_refs: Vec::new(),
            title: title.into(),
            summary: None,
            fields: BTreeMap::new(),
            labels: Vec::new(),
            avatar_blob_ref: None,
            state: Some(SpaceState::Active),
            state_changed_at: None,
            scope_circle_id: None,
            default_scope_circle_id: None,
            child_scope_policy: None,
            created_by,
            created_at: Utc::now(),
            updated_by: None,
            updated_at: None,
            extra: BTreeMap::new(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.kind.trim().is_empty() {
            return Err(Error::Protocol("space kind must not be empty".to_owned()));
        }
        if self.title.trim().is_empty() {
            return Err(Error::Protocol("space title must not be empty".to_owned()));
        }
        Ok(())
    }
}
