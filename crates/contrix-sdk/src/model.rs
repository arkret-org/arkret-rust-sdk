use std::{cmp::Ordering, collections::BTreeMap, fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{Error, Result, canonical};

pub const PROTOCOL_VERSION: &str = "1.0";
pub const CORE_SCHEMA_PROFILE: &str = "cx.schema.core.v1";
pub const CORE_REDUCER_PROFILE: &str = "cx.reducer.v1";

pub const SPACE_SCHEMA: &str = "cx.schema.space.v1";
pub const ACTOR_PROFILE_SCHEMA: &str = "cx.schema.actor_profile.v1";
pub const ENTITY_SCHEMA: &str = "cx.schema.entity.v1";
pub const RELATION_SCHEMA: &str = "cx.schema.relation.v1";
pub const EVENT_SCHEMA: &str = "cx.schema.event.v1";
pub const VIEW_SCHEMA: &str = "cx.schema.view.v1";
pub const POLICY_SCHEMA: &str = "cx.schema.policy.v1";
pub const CAPABILITY_SCHEMA: &str = "cx.schema.capability.v1";
pub const INVITE_SCHEMA: &str = "cx.schema.invite.v1";
pub const READ_MARKER_SCHEMA: &str = "cx.schema.read_marker.v1";
pub const NOTIFICATION_SCHEMA: &str = "cx.schema.notification.v1";
pub const COMMIT_SCHEMA: &str = "cx.schema.commit.v1";
pub const OPERATION_SCHEMA: &str = "cx.schema.operation.v1";
pub const BLOB_SCHEMA: &str = "cx.schema.blob.v1";
pub const ENCRYPTED_PAYLOAD_SCHEMA: &str = "cx.schema.encrypted_payload.v1";
pub const CLIENT_SYNC_RESPONSE_SCHEMA: &str = "cx.schema.client_sync_response.v1";

macro_rules! id_type {
    ($name:ident, $expect:expr) => {
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let value = value.into();
                if !$expect(&value) {
                    return Err(Error::InvalidId(value));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(value: &str) -> Result<Self> {
                Self::new(value)
            }
        }
    };
}

fn is_did(value: &str) -> bool {
    value.starts_with("did:") && value.len() > 4
}

fn is_hash(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value["sha256:".len()..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn has_prefix<'a>(prefix: &'a str) -> impl Fn(&str) -> bool + 'a {
    move |value| value.starts_with(prefix) && value.len() > prefix.len()
}

id_type!(Did, is_did);
id_type!(SpaceId, has_prefix("cx:space:"));
id_type!(EntityId, has_prefix("cx:entity:"));
id_type!(RelationId, has_prefix("cx:relation:"));
id_type!(EventId, |value: &str| value.starts_with("cx:event:") || is_hash(value));
id_type!(CommitId, has_prefix("cx:commit:"));
id_type!(OperationId, |value: &str| value.starts_with("cx:operation:") || is_hash(value));
id_type!(GrantId, has_prefix("cx:grant:"));
id_type!(InviteId, has_prefix("cx:invite:"));
id_type!(DeviceId, |value: &str| (value.starts_with("dev_") && value.len() > "dev_".len())
    || (value.starts_with("cx:device:") && value.len() > "cx:device:".len()));
id_type!(PolicyId, has_prefix("cx:policy:"));
id_type!(BlobRef, |value: &str| value.starts_with("cx:blob:") || is_hash(value));
id_type!(ViewId, has_prefix("cx:view:"));
id_type!(Hash, is_hash);
id_type!(Cursor, has_prefix("cx:cursor:"));

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hlc(String);

impl Hlc {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        Self::parse_parts(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn parse_parts(value: &str) -> Result<(u64, u64, &str)> {
        let mut parts = value.split('-');
        let unix_ms = parts
            .next()
            .ok_or_else(|| Error::InvalidId(value.to_owned()))
            .and_then(|part| parse_lower_hex(part, value))?;
        let logical = parts
            .next()
            .ok_or_else(|| Error::InvalidId(value.to_owned()))
            .and_then(|part| parse_lower_hex(part, value))?;
        let node = parts.next().ok_or_else(|| Error::InvalidId(value.to_owned()))?;
        if parts.next().is_some()
            || node.is_empty()
            || !node.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(Error::InvalidId(value.to_owned()));
        }
        Ok((unix_ms, logical, node))
    }
}

impl fmt::Display for Hlc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for Hlc {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

impl PartialOrd for Hlc {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Hlc {
    fn cmp(&self, other: &Self) -> Ordering {
        let (self_ms, self_logical, self_node) =
            Self::parse_parts(&self.0).expect("HLC constructed with valid parts");
        let (other_ms, other_logical, other_node) =
            Self::parse_parts(&other.0).expect("HLC constructed with valid parts");
        (self_ms, self_logical, self_node).cmp(&(other_ms, other_logical, other_node))
    }
}

fn parse_lower_hex(part: &str, original: &str) -> Result<u64> {
    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err(Error::InvalidId(original.to_owned()));
    }
    u64::from_str_radix(part, 16).map_err(|_| Error::InvalidId(original.to_owned()))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceKind {
    Collaboration,
    Direct,
    Group,
    Project,
    Document,
    Board,
    Channel,
    SocialFeed,
    Enclave,
    #[serde(untagged)]
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Discoverability {
    Public,
    Listed,
    Restricted,
    Unlisted,
    InviteOnly,
    Secret,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinRule {
    Public,
    Invite,
    Knock,
    Restricted,
    KnockRestricted,
    Closed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryVisibility {
    WorldReadable,
    Shared,
    Invited,
    Joined,
    Restricted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FederationPolicy {
    Open,
    Restricted,
    Closed,
    Quarantine,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptionProfile {
    None,
    MlsRfc9420,
    External,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    User,
    Org,
    Team,
    Agent,
    Service,
    Device,
    Integration,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorStatus {
    Active,
    Suspended,
    Deleted,
    Deactivated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Board,
    Collection,
    Task,
    Message,
    Topic,
    Channel,
    Document,
    File,
    Memory,
    Run,
    ActorProfile,
    Poll,
    SocialPost,
    SocialFeed,
    SocialCircle,
    #[serde(untagged)]
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    Contains,
    BelongsTo,
    RepliesTo,
    DependsOn,
    Blocks,
    Mentions,
    AssignedTo,
    References,
    DerivedFrom,
    AttachedTo,
    HasTopic,
    HasDefaultView,
    Produced,
    Used,
    TriggeredBy,
    HasLog,
    Reposts,
    Quotes,
    #[serde(untagged)]
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewKind {
    Kanban,
    List,
    Table,
    Calendar,
    Gantt,
    Chat,
    Thread,
    Forum,
    Tree,
    Graph,
    Timeline,
    ReviewQueue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectState {
    Active,
    Archived,
    Deleted,
    Redacted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationState {
    Active,
    Deleted,
    Redacted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyType {
    Access,
    Encryption,
    Retention,
    Federation,
    Moderation,
    Discoverability,
    Join,
    HistoryVisibility,
    PlaintextVisibility,
    Media,
    Applet,
    Agent,
    Social,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Deny,
    Quarantine,
    RequireReview,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthzDecision {
    Allow,
    Deny,
    Quarantine,
    RequireReview,
    SoftFail,
}

pub type Decision = AuthzDecision;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteState {
    Pending,
    Accepted,
    Rejected,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationType {
    Mention,
    Reply,
    Assignment,
    Invite,
    Reaction,
    Policy,
    Call,
    Applet,
    Agent,
    Moderation,
    System,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationPriority {
    Low,
    Normal,
    High,
    Urgent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationState {
    Unread,
    Read,
    Dismissed,
    Archived,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadScope {
    Space,
    Channel,
    Topic,
    Thread,
    View,
    Entity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationType {
    Create,
    Update,
    Delete,
    Redact,
    Grant,
    Revoke,
    SnapshotRef,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KanbanColumnModel {
    FieldValue,
    Collection,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UncategorizedPolicy {
    Show,
    Hide,
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SortDirection {
    Asc,
    Desc,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NullsOrder {
    First,
    Last,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterOp {
    Eq,
    Neq,
    In,
    NotIn,
    Lt,
    Lte,
    Gt,
    Gte,
    Contains,
    Exists,
    Prefix,
    FullText,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationDirection {
    Out,
    In,
    Both,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EncryptedPayloadScheme {
    MlsRfc9420,
}

impl EncryptedPayloadScheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MlsRfc9420 => "mls-rfc9420",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proof {
    pub kind: String,
    pub alg: String,
    pub verification_method: String,
    pub payload_hash: Hash,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
    pub jws: String,
}

impl Proof {
    pub fn binding_payload(&self, actor_id: &Did) -> SignatureBindingPayload {
        SignatureBindingPayload {
            payload_hash: self.payload_hash.clone(),
            actor_id: actor_id.clone(),
            verification_method: self.verification_method.clone(),
            created_at: self.created_at,
            domain: self.domain.clone(),
            audience: self.audience.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureBindingPayload {
    pub payload_hash: Hash,
    pub actor_id: Did,
    pub verification_method: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Space {
    pub schema: String,
    pub id: SpaceId,
    #[serde(rename = "type")]
    pub object_type: String,
    pub space_version: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    pub space_kind: SpaceKind,
    pub created_by_principal: Did,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owning_organizations: Vec<Did>,
    pub schema_refs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<PolicyId>,
    pub default_discoverability: Discoverability,
    pub default_join_rule: JoinRule,
    pub history_visibility: HistoryVisibility,
    pub encryption_profile: EncryptionProfile,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub federation_policy: Option<FederationPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retention_policy_ref: Option<PolicyId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Space {
    pub fn new(
        id: SpaceId,
        title: impl Into<String>,
        space_kind: SpaceKind,
        created_by_principal: Did,
    ) -> Self {
        Self {
            schema: SPACE_SCHEMA.to_owned(),
            id,
            object_type: "space".to_owned(),
            space_version: "1".to_owned(),
            title: title.into(),
            summary: None,
            space_kind,
            created_by_principal,
            owning_organizations: Vec::new(),
            schema_refs: vec![CORE_SCHEMA_PROFILE.to_owned()],
            policy_ref: None,
            default_discoverability: Discoverability::InviteOnly,
            default_join_rule: JoinRule::Invite,
            history_visibility: HistoryVisibility::Joined,
            encryption_profile: EncryptionProfile::None,
            federation_policy: None,
            retention_policy_ref: None,
            avatar_blob_ref: None,
            created_at: Utc::now(),
            updated_at: None,
            labels: Vec::new(),
            metadata: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActorProfile {
    pub schema: String,
    pub id: EntityId,
    #[serde(rename = "type")]
    pub object_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    pub principal_id: Did,
    pub actor_type: ActorType,
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ActorStatus>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accountable_to: Vec<Did>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub profile_fields: BTreeMap<String, Value>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entity {
    pub schema: String,
    pub id: EntityId,
    #[serde(rename = "type")]
    pub object_type: String,
    pub space_id: SpaceId,
    pub entity_type: EntityType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ObjectState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, Value>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Entity {
    pub fn validate_content_object(&self) -> Result<()> {
        match &self.content {
            Some(Value::Object(_)) | None => Ok(()),
            Some(_) => Err(Error::Protocol("entity content must be a JSON object".to_owned())),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Relation {
    pub schema: String,
    pub id: RelationId,
    #[serde(rename = "type")]
    pub object_type: String,
    pub space_id: SpaceId,
    pub relation_kind: RelationKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_entity_id: Option<EntityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_actor_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_entity_id: Option<EntityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_actor_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_space_id: Option<SpaceId>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<RelationState>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
}

impl Relation {
    pub fn validate_endpoints(&self) -> Result<()> {
        let from_count = self.from_entity_id.is_some() as u8
            + self.from_actor_id.is_some() as u8
            + self.from_space_id.is_some() as u8;
        let to_count = self.to_entity_id.is_some() as u8
            + self.to_actor_id.is_some() as u8
            + self.to_space_id.is_some() as u8;

        if from_count == 1 && to_count == 1 {
            Ok(())
        } else {
            Err(Error::Protocol(
                "relation must have exactly one from_* and one to_* endpoint".to_owned(),
            ))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub event_id: EventId,
    pub kind: String,
    pub space_id: SpaceId,
    pub space_version: String,
    pub actor_id: Did,
    pub actor_seq: u64,
    pub created_at: DateTime<Utc>,
    pub hlc: Hlc,
    pub prev_refs: Vec<EventId>,
    pub auth_refs: Vec<EventId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacts: Option<EventId>,
    pub content: Value,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unsigned: BTreeMap<String, Value>,
    pub proofs: Vec<Proof>,
}

impl Event {
    pub fn digest_payload(&self) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        if let Value::Object(map) = &mut value {
            map.remove("event_id");
            map.remove("proofs");
            map.remove("unsigned");
        }
        Ok(value)
    }

    pub fn event_digest(&self) -> Result<String> {
        canonical::canonical_sha256(&self.digest_payload()?)
    }

    pub fn validate_for_submit(&self) -> Result<()> {
        if self.proofs.is_empty() {
            return Err(Error::Protocol("event proofs must contain at least one proof".to_owned()));
        }
        if !self.content.is_object() {
            return Err(Error::Protocol("event content must be a JSON object".to_owned()));
        }
        Ok(())
    }

    pub fn new(
        kind: impl Into<String>,
        space_id: SpaceId,
        actor_id: Did,
        actor_seq: u64,
        hlc: Hlc,
        content: Value,
    ) -> Result<Self> {
        let mut event = Self {
            event_id: EventId::new(
                "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            )?,
            kind: kind.into(),
            space_id,
            space_version: "1".to_owned(),
            actor_id,
            actor_seq,
            created_at: Utc::now(),
            hlc,
            prev_refs: Vec::new(),
            auth_refs: Vec::new(),
            redacts: None,
            content,
            unsigned: BTreeMap::new(),
            proofs: Vec::new(),
        };
        event.event_id = EventId::new(event.event_digest()?)?;
        Ok(event)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SortSpec {
    pub field: String,
    pub direction: SortDirection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nulls: Option<NullsOrder>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FieldFilter {
    pub field: String,
    pub op: FilterOp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Filter {
    Predicate(FieldFilter),
    And { and: Vec<Filter> },
    Or { or: Vec<Filter> },
    Not { not: Box<Filter> },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelationQuery {
    pub kind: RelationKind,
    pub direction: RelationDirection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_entity_id: Option<EntityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_actor_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_entity_id: Option<EntityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_actor_id: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_space_id: Option<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
}

impl RelationQuery {
    pub fn validate_endpoints(&self) -> Result<()> {
        let source_count = self.source_entity_id.is_some() as u8
            + self.source_actor_id.is_some() as u8
            + self.source_space_id.is_some() as u8;
        let target_count = self.target_entity_id.is_some() as u8
            + self.target_actor_id.is_some() as u8
            + self.target_space_id.is_some() as u8;

        if source_count <= 1 && target_count <= 1 {
            Ok(())
        } else {
            Err(Error::Protocol(
                "relation query may specify at most one source_* and one target_* endpoint"
                    .to_owned(),
            ))
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct QueryContext {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub event_kinds: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relation_kinds: Vec<RelationKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_tiebreak: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryConsistency {
    pub wait_for: String,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryRequest {
    pub space_ids: Vec<SpaceId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entity_types: Vec<EntityType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_entity_id: Option<EntityId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub filters: Vec<Filter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relation: Option<RelationQuery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<QueryContext>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub order_by: Vec<SortSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub projection: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consistency: Option<QueryConsistency>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryFrontier {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sync_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_hlc: Option<Hlc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueryResponse<T = Value> {
    pub items: Vec<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    pub has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<QueryFrontier>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct View {
    pub schema: String,
    pub id: ViewId,
    #[serde(rename = "type")]
    pub object_type: String,
    pub space_id: SpaceId,
    pub kind: ViewKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub query: QueryRequest,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub visible_fields: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kanban: Option<KanbanConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sort: Vec<SortSpec>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KanbanConfig {
    pub column_model: KanbanColumnModel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_by: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub columns: Vec<KanbanColumn>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub board_entity_id: Option<EntityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column_relation_kind: Option<RelationKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_relation_kind: Option<RelationKind>,
    pub card_order_by: Vec<SortSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncategorized_policy: Option<UncategorizedPolicy>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KanbanColumn {
    pub key: String,
    pub title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rank: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wip_limit: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Operation {
    pub schema: String,
    pub operation_id: OperationId,
    #[serde(rename = "type")]
    pub record_type: String,
    pub operation_type: OperationType,
    pub space_id: SpaceId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    pub object_type: String,
    pub payload: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl Operation {
    pub fn create(
        operation_id: OperationId,
        space_id: SpaceId,
        object_type: impl Into<String>,
        payload: Value,
    ) -> Self {
        Self {
            schema: OPERATION_SCHEMA.to_owned(),
            operation_id,
            record_type: "operation".to_owned(),
            operation_type: OperationType::Create,
            space_id,
            object_id: None,
            object_type: object_type.into(),
            payload,
            idempotency_key: None,
            created_at: Utc::now(),
        }
    }

    pub fn operation_digest(&self) -> Result<String> {
        canonical::canonical_sha256(self)
    }

    pub fn validate_payload_object(&self) -> Result<()> {
        if self.payload.is_object() {
            Ok(())
        } else {
            Err(Error::Protocol("operation payload must be a JSON object".to_owned()))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationEnvelope {
    pub operation_id: OperationId,
    pub space_id: SpaceId,
    pub actor: Did,
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_ref: Option<String>,
    pub causal: CausalRef,
    pub body: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authz_ref: Option<GrantId>,
    pub signature: OperationSignature,
}

impl OperationEnvelope {
    pub fn operation_digest(&self) -> Result<String> {
        canonical::canonical_sha256(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CausalRef {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deps: Vec<OperationId>,
    pub hlc: Hlc,
    pub actor_seq: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperationSignature {
    pub key_id: String,
    pub alg: String,
    pub sig: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commit {
    pub schema: String,
    pub commit_id: CommitId,
    #[serde(rename = "type")]
    pub object_type: String,
    pub repo_id: String,
    pub author: Did,
    pub author_seq: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_commit: Option<Hash>,
    pub operations: Vec<Hash>,
    pub created_at: DateTime<Utc>,
    pub proofs: Vec<Proof>,
}

impl Commit {
    pub fn new(
        commit_id: CommitId,
        repo_id: impl Into<String>,
        author: Did,
        author_seq: u64,
    ) -> Self {
        Self {
            schema: COMMIT_SCHEMA.to_owned(),
            commit_id,
            object_type: "commit".to_owned(),
            repo_id: repo_id.into(),
            author,
            author_seq,
            prev_commit: None,
            operations: Vec::new(),
            created_at: Utc::now(),
            proofs: Vec::new(),
        }
    }

    pub fn digest_payload(&self) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        if let Value::Object(map) = &mut value {
            map.remove("proofs");
        }
        Ok(value)
    }

    pub fn commit_digest(&self) -> Result<String> {
        canonical::canonical_sha256(&self.digest_payload()?)
    }

    pub fn validate_for_submit(&self) -> Result<()> {
        if self.proofs.is_empty() {
            return Err(Error::Protocol(
                "commit proofs must contain at least one proof".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CapabilitySubject {
    Did(Did),
    Selector(Value),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub schema: String,
    pub id: GrantId,
    #[serde(rename = "type")]
    pub object_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    pub issuer: Did,
    pub subject: CapabilitySubject,
    pub actions: Vec<String>,
    pub resources: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<Value>,
    #[serde(default)]
    pub delegable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_grant_id: Option<GrantId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    pub schema: String,
    pub id: PolicyId,
    #[serde(rename = "type")]
    pub object_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    pub policy_type: PolicyType,
    pub rules: Vec<Value>,
    pub default_effect: PolicyEffect,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invite {
    pub schema: String,
    pub id: InviteId,
    #[serde(rename = "type")]
    pub object_type: String,
    pub space_id: SpaceId,
    pub inviter: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invitee: Option<Did>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub third_party_id: Option<Value>,
    pub join_rule_snapshot: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_grant_refs: Vec<GrantId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    pub state: InviteState,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadMarker {
    pub schema: String,
    pub id: String,
    #[serde(rename = "type")]
    pub object_type: String,
    pub actor_id: Did,
    pub space_id: SpaceId,
    pub scope: ReadScope,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_id: Option<String>,
    pub event_id: EventId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline_order_key: Option<Value>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Notification {
    pub schema: String,
    pub id: String,
    #[serde(rename = "type")]
    pub object_type: String,
    pub actor_id: Did,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    pub source_event_id: EventId,
    pub notification_type: NotificationType,
    pub priority: NotificationPriority,
    pub state: NotificationState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<Value>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobMetadata {
    pub schema: String,
    pub blob_ref: BlobRef,
    #[serde(rename = "type")]
    pub object_type: String,
    pub sha256: String,
    pub size: u64,
    pub media_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    pub encryption: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thumbnail_ref: Option<BlobRef>,
    pub created_by: Did,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub scheme: EncryptedPayloadScheme,
    pub group_id: String,
    pub epoch: u64,
    pub content_type: String,
    pub ciphertext: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<Value>,
    pub payload_digest: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ref: Option<String>,
}

impl EncryptedPayload {
    pub fn mls_payload_digest(
        epoch: u64,
        content_type: &str,
        aad: Option<&Value>,
        ciphertext_bytes: &[u8],
    ) -> Result<Hash> {
        let metadata = EncryptedPayloadDigestMetadata {
            content_type,
            encryption: EncryptedPayloadScheme::MlsRfc9420.as_str(),
            epoch,
            aad,
        };
        let mut input = canonical::canonical_json_bytes(&metadata)?;
        input.extend_from_slice(ciphertext_bytes);
        Hash::new(format!("sha256:{:x}", Sha256::digest(&input)))
    }

    pub fn verify_mls_payload_digest(&self, ciphertext_bytes: &[u8]) -> Result<()> {
        let expected = Self::mls_payload_digest(
            self.epoch,
            &self.content_type,
            self.aad.as_ref(),
            ciphertext_bytes,
        )?;
        if expected == self.payload_digest {
            Ok(())
        } else {
            Err(Error::Protocol("encrypted payload digest mismatch".to_owned()))
        }
    }
}

#[derive(Serialize)]
struct EncryptedPayloadDigestMetadata<'a> {
    pub content_type: &'a str,
    pub encryption: &'a str,
    pub epoch: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<&'a Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlsKeyPackageRecord {
    pub principal_id: Did,
    pub device_id: DeviceId,
    pub key_package: String,
    pub key_package_hash: Hash,
    pub cipher_suites: Vec<String>,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_signature: Option<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlsCommitEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub commit: String,
    pub commit_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MlsWelcomeEnvelope {
    pub group_id: String,
    pub epoch: u64,
    pub recipient_principal_id: Did,
    pub recipient_device_id: DeviceId,
    pub welcome: String,
    pub welcome_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ratchet_tree: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerDescription {
    pub service_did: Did,
    pub service_type: String,
    pub protocol_version: String,
    #[serde(default)]
    pub supported_profiles: Vec<String>,
    #[serde(default)]
    pub supported_features: Vec<String>,
    #[serde(default)]
    pub supported_operations: Vec<String>,
    #[serde(default)]
    pub supported_bindings: Vec<Value>,
    #[serde(default)]
    pub supported_reducer_profiles: Vec<String>,
    #[serde(default)]
    pub supported_schema_profiles: Vec<String>,
    #[serde(default)]
    pub auth_metadata: Value,
    #[serde(default)]
    pub limits: Value,
}

impl ServerDescription {
    pub fn supports_contrix_v1(&self) -> bool {
        self.protocol_version == PROTOCOL_VERSION
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub errcode: String,
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl fmt::Display for ErrorEnvelope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.errcode, self.error)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitCommitResponse {
    pub head: Hash,
    #[serde(default)]
    pub accepted_operations: Vec<OperationId>,
    #[serde(default)]
    pub sync_tokens: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub space_ids: Vec<SpaceId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncResponse {
    pub next_batch: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub rooms: BTreeMap<SpaceId, SyncSpace>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub to_device: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub device_lists: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub account_data: Vec<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub presence: Vec<Value>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub partial: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SyncSpace {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline: Option<SyncTimeline>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub state: Vec<Event>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub summary: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ephemeral: Vec<Value>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub unread: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncTimeline {
    pub events: Vec<Event>,
    pub limited: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_batch: Option<String>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthzCheckRequest {
    pub actor_id: Did,
    pub action: String,
    pub resource: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<SpaceId>,
    #[serde(default)]
    pub proofs: Vec<Proof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthzCheckResponse {
    pub decision: AuthzDecision,
    #[serde(default)]
    pub matched_grants: Vec<GrantId>,
    #[serde(default)]
    pub applied_constraints: Vec<Value>,
    #[serde(default)]
    pub policy_results: Vec<Value>,
    #[serde(default)]
    pub missing_proofs: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frontier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_valid_until: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysUploadRequest {
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub one_time_keys: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fallback_keys: BTreeMap<String, Value>,
    pub device_signature: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysUploadResponse {
    pub one_time_key_counts: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fallback_keys: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysQueryRequest {
    pub device_keys: BTreeMap<Did, Vec<DeviceId>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysQueryResponse {
    pub device_keys: BTreeMap<Did, BTreeMap<DeviceId, Value>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub failures: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysClaimRequest {
    pub one_time_keys: BTreeMap<Did, BTreeMap<DeviceId, String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeysClaimResponse {
    pub one_time_keys: BTreeMap<Did, BTreeMap<DeviceId, Value>>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub failures: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceMessagesSendRequest {
    pub messages: BTreeMap<Did, BTreeMap<DeviceId, ToDeviceMessage>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToDeviceMessage {
    #[serde(rename = "type")]
    pub message_type: String,
    pub content: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceMessagesSendResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub delivered: BTreeMap<String, Value>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub unknown_devices: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceMessagesReceiveResponse {
    pub events: Vec<ToDeviceMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_batch: Option<String>,
    #[serde(default)]
    pub limited: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn did_validation_rejects_handles() {
        assert!(Did::new("did:web:alice.example").is_ok());
        assert!(Did::new("alice.example").is_err());
    }

    #[test]
    fn device_id_accepts_protocol_device_forms() {
        assert!(DeviceId::new("dev_alice_1").is_ok());
        assert!(DeviceId::new("cx:device:01js0ke000000000000000000").is_ok());
        assert!(DeviceId::new("device-1").is_err());
    }

    #[test]
    fn server_description_checks_protocol_version() {
        let desc = ServerDescription {
            service_did: Did::new("did:web:svc.example").unwrap(),
            service_type: "principal_server".to_owned(),
            protocol_version: "1.0".to_owned(),
            supported_profiles: vec![],
            supported_features: vec![],
            supported_operations: vec![],
            supported_bindings: vec![],
            supported_reducer_profiles: vec![],
            supported_schema_profiles: vec![],
            auth_metadata: Value::Null,
            limits: Value::Null,
        };
        assert!(desc.supports_contrix_v1());
    }

    #[test]
    fn event_new_sets_required_event_id() {
        let event = Event::new(
            "cx.message.create",
            SpaceId::new("cx:space:01js0ke000000000000000000").unwrap(),
            Did::new("did:web:alice.example").unwrap(),
            1,
            Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            json!({ "body": "hello" }),
        )
        .unwrap();

        assert!(event.event_id.as_str().starts_with("sha256:"));
    }

    #[test]
    fn event_digest_uses_canonical_payload_without_event_id_proofs_or_unsigned() {
        let event = Event {
            event_id: EventId::new(
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
            .unwrap(),
            kind: "cx.message.create".to_owned(),
            space_version: "1".to_owned(),
            space_id: SpaceId::new("cx:space:01js0ke000000000000000000").unwrap(),
            actor_id: Did::new("did:web:alice.example").unwrap(),
            actor_seq: 1,
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            hlc: Hlc::new("01970e589d21-0004-a13f9c2e").unwrap(),
            prev_refs: Vec::new(),
            auth_refs: Vec::new(),
            redacts: None,
            content: json!({ "body": "hello" }),
            unsigned: BTreeMap::from([("local_receive_time".to_owned(), json!("ignored"))]),
            proofs: Vec::new(),
        };

        assert_eq!(
            event.event_digest().unwrap(),
            "sha256:eb874f42a73755f5e77d3815a9cefa19487d84e12459d9c53766fdd6dc43cc5a"
        );
    }

    #[test]
    fn commit_digest_uses_canonical_payload_without_proofs() {
        let commit = Commit {
            schema: COMMIT_SCHEMA.to_owned(),
            commit_id: CommitId::new("cx:commit:01js0ke000000000000000000").unwrap(),
            object_type: "commit".to_owned(),
            repo_id: "did:web:alice.example".to_owned(),
            author: Did::new("did:web:alice.example").unwrap(),
            author_seq: 1,
            prev_commit: Some(
                Hash::new(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
            ),
            operations: vec![
                Hash::new(
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
            ],
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            proofs: Vec::new(),
        };

        assert_eq!(
            commit.commit_digest().unwrap(),
            "sha256:8ee2713192bc01d5a6ba7c0a6b2125e00dffff1fb6f4ee85add16c81e6d2d8f0"
        );
    }

    #[test]
    fn signature_binding_payload_matches_canonical_vector() {
        let proof = Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: "did:web:alice.example#device-1".to_owned(),
            payload_hash: Hash::new(
                "sha256:43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
            )
            .unwrap(),
            created_at: "2026-04-26T00:00:00Z".parse().unwrap(),
            domain: None,
            audience: None,
            jws: "...".to_owned(),
        };
        let payload = proof.binding_payload(&Did::new("did:web:alice.example").unwrap());

        assert_eq!(
            canonical::canonical_sha256(&payload).unwrap(),
            "sha256:5b8863e858c1964ca1901d27ce687b65d87dcef0d3535ed617de7b4763cfdaf8"
        );
    }

    #[test]
    fn encrypted_payload_digest_matches_conformance_vector() {
        let digest = EncryptedPayload::mls_payload_digest(
            7,
            "application/json",
            None,
            b"ciphertext-example-001",
        )
        .unwrap();

        assert_eq!(
            digest.as_str(),
            "sha256:3bef5270548d5b2c14e46ac1c9a801376d243ca6d71b914ec1d3283268a981fa"
        );
    }

    #[test]
    fn hlc_sorts_by_structured_parts() {
        let mut hlcs = [
            "01970e589d21-0004-bbbbbbbb",
            "01970e589d20-0009-ffffffff",
            "01970e589d21-0003-ffffffff",
            "01970e589d21-0004-a13f9c2e",
        ]
        .map(|value| Hlc::new(value).unwrap());
        hlcs.sort();
        let actual = hlcs.map(|value| value.to_string());
        assert_eq!(
            actual,
            [
                "01970e589d20-0009-ffffffff",
                "01970e589d21-0003-ffffffff",
                "01970e589d21-0004-a13f9c2e",
                "01970e589d21-0004-bbbbbbbb",
            ]
        );
    }

    #[test]
    fn relation_requires_exact_wire_endpoints() {
        let relation = Relation {
            schema: RELATION_SCHEMA.to_owned(),
            id: RelationId::new("cx:relation:01").unwrap(),
            object_type: "relation".to_owned(),
            space_id: SpaceId::new("cx:space:01").unwrap(),
            relation_kind: RelationKind::Mentions,
            from_entity_id: Some(EntityId::new("cx:entity:01").unwrap()),
            from_actor_id: None,
            from_space_id: None,
            to_entity_id: None,
            to_actor_id: Some(Did::new("did:web:alice.example").unwrap()),
            to_space_id: None,
            fields: BTreeMap::new(),
            state: None,
            created_by: Did::new("did:web:alice.example").unwrap(),
            created_at: Utc::now(),
        };
        relation.validate_endpoints().unwrap();
    }

    #[test]
    fn query_request_uses_protocol_filters_array() {
        let request = QueryRequest {
            space_ids: vec![SpaceId::new("cx:space:01").unwrap()],
            entity_types: vec![EntityType::Task],
            anchor_entity_id: None,
            filters: vec![Filter::Predicate(FieldFilter {
                field: "fields.status".to_owned(),
                op: FilterOp::Eq,
                value: Some(json!("todo")),
            })],
            relation: None,
            context: None,
            order_by: vec![],
            projection: vec![],
            cursor: None,
            limit: Some(50),
            consistency: None,
        };

        let value = serde_json::to_value(request).unwrap();
        assert!(value.get("space_ids").unwrap().is_array());
        assert!(value.get("filters").unwrap().is_array());
        assert!(value.get("sync_token").is_none());
    }

    #[test]
    fn operation_serializes_protocol_field_names() {
        let mut operation = Operation::create(
            OperationId::new("cx:operation:01").unwrap(),
            SpaceId::new("cx:space:01").unwrap(),
            "entity",
            json!({"id":"cx:entity:01"}),
        );
        operation.object_id = Some("cx:entity:01".to_owned());

        let value = serde_json::to_value(operation).unwrap();

        assert_eq!(value["type"], "operation");
        assert_eq!(value["operation_type"], "create");
        assert_eq!(value["object_id"], "cx:entity:01");
        assert_eq!(value["object_type"], "entity");
        assert!(value.get("target_object_id").is_none());
        assert_eq!(value["schema"], OPERATION_SCHEMA);
    }

    #[test]
    fn sync_response_uses_rooms_key_not_spaces() {
        let response = SyncResponse {
            next_batch: "cx:sync:abc".to_owned(),
            rooms: BTreeMap::from([(
                SpaceId::new("cx:space:01").unwrap(),
                SyncSpace {
                    timeline: Some(SyncTimeline {
                        events: Vec::new(),
                        limited: false,
                        prev_batch: None,
                    }),
                    state: Vec::new(),
                    summary: Value::Null,
                    ephemeral: Vec::new(),
                    unread: Value::Null,
                },
            )]),
            to_device: Vec::new(),
            device_lists: Value::Null,
            account_data: Vec::new(),
            presence: Vec::new(),
            partial: false,
        };

        let value = serde_json::to_value(response).unwrap();

        assert!(value.get("rooms").unwrap().is_object());
        assert!(value.get("spaces").is_none());
    }
}
