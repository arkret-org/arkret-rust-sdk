use std::fmt;
use std::str::FromStr;

use super::*;
use crate::{DidCoreId, ProofContextId};

/// Complete protocol identity for one principal at one Station, including
/// human accounts, Agents and integration actors. This identity does
/// not select a credential class, provisioning workflow or authorization.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct AccountId {
    pub principal_id: DidCoreId,
    pub station_id: DidCoreId,
}

impl AccountId {
    pub fn new(principal_id: DidCoreId, station_id: DidCoreId) -> Self {
        Self {
            principal_id,
            station_id,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.principal_id.as_str().is_empty() || self.station_id.as_str().is_empty() {
            return Err(WireError::Protocol(
                "account id components must be non-empty".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(arkret_canonical::canonical::canonical_json_bytes(self)?)
    }

    pub fn canonical_key(&self) -> Result<String> {
        String::from_utf8(self.canonical_bytes()?)
            .map_err(|error| WireError::Protocol(format!("account id canonical UTF-8: {error}")))
    }
}

impl fmt::Display for AccountId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let canonical = self.canonical_key().map_err(|_| fmt::Error)?;
        formatter.write_str(&canonical)
    }
}

/// An entry whose identity, rather than its complete value, defines set membership.
pub trait CanonicalIdentityEntry {
    type Identity: Serialize;
    fn identity(&self) -> &Self::Identity;
    fn validate_entry(&self) -> Result<()> {
        Ok(())
    }
}

/// Validate the unsigned UTF-8 JCS identity order, rejecting repeated identities
/// even when the associated values differ.
pub fn validate_identity_entries<T: CanonicalIdentityEntry>(entries: &[T]) -> Result<()> {
    let mut previous: Option<Vec<u8>> = None;
    for entry in entries {
        entry.validate_entry()?;
        let key = arkret_canonical::canonical_json_bytes(entry.identity())?;
        if previous.as_ref().is_some_and(|previous| previous >= &key) {
            return Err(WireError::Protocol(
                "identity entries must be unique and sorted by JCS identity bytes".to_owned(),
            ));
        }
        previous = Some(key);
    }
    Ok(())
}

pub fn deserialize_identity_entries<'de, D, T>(
    deserializer: D,
) -> std::result::Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + CanonicalIdentityEntry,
{
    let entries = Vec::<T>::deserialize(deserializer)?;
    validate_identity_entries(&entries).map_err(serde::de::Error::custom)?;
    Ok(entries)
}

pub fn serialize_identity_entries<S, T>(
    entries: &[T],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    T: Serialize + CanonicalIdentityEntry,
{
    validate_identity_entries(entries).map_err(serde::ser::Error::custom)?;
    entries.serialize(serializer)
}

impl CanonicalIdentityEntry for ActorId {
    type Identity = Self;

    fn identity(&self) -> &Self {
        self
    }
}

/// Complete identity for an Event author, Realm member, or durable byline.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ActorId {
    Account { account_id: AccountId },
    Service { service_id: DidCoreId },
}

impl ActorId {
    pub fn account(account_id: AccountId) -> Self {
        Self::Account { account_id }
    }

    pub fn service(service_id: DidCoreId) -> Self {
        Self::Service { service_id }
    }

    pub fn signing_principal_id(&self) -> &DidCoreId {
        match self {
            Self::Account { account_id } => &account_id.principal_id,
            Self::Service { service_id } => service_id,
        }
    }

    pub fn route_service_id(&self) -> &DidCoreId {
        match self {
            Self::Account { account_id } => &account_id.station_id,
            Self::Service { service_id } => service_id,
        }
    }

    pub fn as_account_id(&self) -> Option<&AccountId> {
        match self {
            Self::Account { account_id } => Some(account_id),
            Self::Service { .. } => None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Account { account_id } => account_id.validate(),
            Self::Service { service_id } if service_id.as_str().is_empty() => Err(
                WireError::Protocol("service actor id must be non-empty".to_owned()),
            ),
            Self::Service { .. } => Ok(()),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(arkret_canonical::canonical::canonical_json_bytes(self)?)
    }

    pub fn canonical_key(&self) -> Result<String> {
        String::from_utf8(self.canonical_bytes()?)
            .map_err(|error| WireError::Protocol(format!("actor id canonical UTF-8: {error}")))
    }
}

impl fmt::Display for ActorId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let canonical = self.canonical_key().map_err(|_| fmt::Error)?;
        formatter.write_str(&canonical)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Discoverability {
    Public,
    Listed,
    Restricted,
    Unlisted,
    InviteOnly,
    Secret,
}

impl Discoverability {
    pub const ALL: [Self; 6] = [
        Self::Public,
        Self::Listed,
        Self::Restricted,
        Self::Unlisted,
        Self::InviteOnly,
        Self::Secret,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Listed => "listed",
            Self::Restricted => "restricted",
            Self::Unlisted => "unlisted",
            Self::InviteOnly => "invite_only",
            Self::Secret => "secret",
        }
    }
}

impl FromStr for Discoverability {
    type Err = DiscoverabilityParseError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|discoverability| discoverability.as_str() == value)
            .ok_or(DiscoverabilityParseError)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoverabilityParseError;

impl fmt::Display for DiscoverabilityParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown discoverability value")
    }
}

impl std::error::Error for DiscoverabilityParseError {}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum HistoryAccess {
    SinceJoin,
    AllHistoryForCurrentMembers,
}

impl HistoryAccess {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SinceJoin => "since_join",
            Self::AllHistoryForCurrentMembers => "all_history_for_current_members",
        }
    }
}

impl FromStr for HistoryAccess {
    type Err = HistoryAccessParseError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "since_join" => Ok(Self::SinceJoin),
            "all_history_for_current_members" => Ok(Self::AllHistoryForCurrentMembers),
            _ => Err(HistoryAccessParseError),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryAccessParseError;

impl fmt::Display for HistoryAccessParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown history_access value")
    }
}

impl std::error::Error for HistoryAccessParseError {}

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
pub enum SecurityClass {
    Standard,
    HighAssurance,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum EncryptionProfile {
    None,
    MlsRfc9420,
    External,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    User,
    Organization,
    Team,
    Agent,
    Bot,
    Service,
    // No Device variant: a device is not an actor principal and has no DID of
    // its own. It belongs to a principal, is identified by
    // device_id (ak:device:<uuid>), and uses a verification method under the
    // principal DID. See spec models/actor.md §2.
    Integration,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorStatus {
    Active,
    SoftLoggedOut,
    Locked,
    Suspended,
    Deactivated,
    ErasurePending,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Facet {
    Container,
    Replyable,
    Schedulable,
    Assignable,
    Stateful,
    Rankable,
    Reviewable,
    Notifiable,
    Documentable,
    Renderable,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Facets {
    Names(Vec<Facet>),
    Configs(BTreeMap<Facet, Value>),
}

impl Default for Facets {
    fn default() -> Self {
        Self::Names(Vec::new())
    }
}

impl Facets {
    pub fn names(names: impl IntoIterator<Item = Facet>) -> Self {
        Self::Names(names.into_iter().collect())
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Names(names) => names.is_empty(),
            Self::Configs(configs) => configs.is_empty(),
        }
    }

    pub fn contains(&self, facet: &Facet) -> bool {
        match self {
            Self::Names(names) => names.contains(facet),
            Self::Configs(configs) => configs.contains_key(facet),
        }
    }
}

pub use crate::generated::relation_kinds::{
    RELATION_KIND_DESCRIPTORS, RelationKind, RelationKindDescriptor, RelationTruthSourceClass,
};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewKind {
    Collection,
    Timeline,
    Graph,
    Document,
    Composite,
}

impl ViewKind {
    /// Renderers permitted for this `ViewKind` per `views.md` §4.
    ///
    /// Implementations MUST refuse to materialize a view whose
    /// `(kind, renderer)` pair is not in this whitelist. The
    /// whitelist intentionally allows `ViewRenderer::Custom` everywhere
    /// because profiles MAY declare additional renderers per kind.
    pub fn allowed_renderers(self) -> &'static [ViewRenderer] {
        use ViewRenderer::*;
        match self {
            ViewKind::Collection => &[Board, List, Table, Calendar, Gantt, Custom],
            ViewKind::Timeline => &[Timeline, Thread, Chat, Forum, Custom],
            ViewKind::Graph => &[Graph, Tree, Custom],
            ViewKind::Document => &[Document, Custom],
            ViewKind::Composite => &[Dashboard, Custom],
        }
    }

    /// `true` when `renderer` is permitted for this `ViewKind`. Returns
    /// `false` for the strict whitelist; callers SHOULD also accept
    /// profile-declared renderers via the `Custom` variant.
    pub fn allows_renderer(self, renderer: ViewRenderer) -> bool {
        self.allowed_renderers().contains(&renderer)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewRenderer {
    Board,
    List,
    Table,
    Calendar,
    Gantt,
    Timeline,
    Thread,
    Chat,
    Forum,
    Graph,
    Tree,
    Document,
    Dashboard,
    Custom,
}

/// View sharing visibility (spec e10b6ad, view.schema.json). Private views are
/// actor-private account data; shared views are canonical Space objects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewVisibility {
    Private,
    Shared,
}

/// Lifecycle state for Strand / Morph (and other objects sharing this lattice).
///
/// Round C47 (spec e10b6ad): the `deleted` terminal state was dropped from
/// both `strand.schema.json` and `morph.schema.json`. Only `redacted` is a
/// terminal state now; `ak.strand.tombstone` / `ak.strand.delete` / equivalent
/// kinds collapse into a single `ak.redaction` event targeting the object.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectState {
    Active,
    Archived,
    Redacted,
}

/// Business progression stage shared by Strand and Morph objects.
///
/// This is distinct from physical lifecycle [`ObjectState`]. The stage
/// lattice is mutated only through the dedicated `ak.<object>.stage.set`
/// event family; create payloads must set an initial stage.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectStage {
    Draft,
    Proposed,
    Planned,
    InProgress,
    Blocked,
    Done,
    Cancelled,
    Superseded,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpaceState {
    Active,
    Archived,
    Tombstoned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationState {
    Active,
    Tombstoned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyKind {
    Access,
    Encryption,
    Retention,
    Federation,
    Moderation,
    Discoverability,
    Join,
    HistoryAccess,
    PlaintextVisibility,
    Media,
    Applet,
    Agent,
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AuthzDecision {
    Allow,
    SoftDeny,
    HardDeny,
    Quarantine,
    RequireReview,
}

/// Checkpoint freshness classification for revocation-sensitive authz decisions.
/// Spec `AuthzCheckOutcome.freshness_state` enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum FreshnessState {
    Fresh,
    Stale,
    Unknown,
}

/// Coarse status of the current governance Station and committed-stream source
/// used to diagnose stale or unknown revocation freshness. Spec
/// `AuthzCheckOutcome.authority_status` enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum AuthorityStatus {
    Fresh,
    Lagging,
    Unreachable,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteState {
    Pending,
    Accepted,
    Rejected,
    Revoked,
    Expired,
    Claimed,
    SendFailed,
    RevokedByCapabilityLoss,
    RevokedByInviterLeft,
    InvalidatedByRateLimit,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationKind {
    Message,
    Mention,
    Reply,
    Assignment,
    Schedule,
    Invite,
    Reaction,
    Policy,
    Call,
    Applet,
    Agent,
    Moderation,
    System,
}

/// Closed `notification_kind` subset carried by an ordinary source-Event
/// notification projection
/// (`notification.schema.json#/$defs/ordinary_notification_kind`).
///
/// `invite` has its own private Invite delivery carrier and `agent` belongs to
/// the account-artifact branch, so neither participates in the deterministic
/// projection preimage. Keeping the subset as its own type means the exclusion
/// is a compile-time fact of the preimage and of the account-subscribe ordinary
/// row, not a runtime rejection each producer has to remember.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrdinaryNotificationKind {
    Message,
    Mention,
    Reply,
    Assignment,
    Schedule,
    Reaction,
    Policy,
    Call,
    Applet,
    Moderation,
    System,
}

impl From<OrdinaryNotificationKind> for NotificationKind {
    fn from(value: OrdinaryNotificationKind) -> Self {
        match value {
            OrdinaryNotificationKind::Message => Self::Message,
            OrdinaryNotificationKind::Mention => Self::Mention,
            OrdinaryNotificationKind::Reply => Self::Reply,
            OrdinaryNotificationKind::Assignment => Self::Assignment,
            OrdinaryNotificationKind::Schedule => Self::Schedule,
            OrdinaryNotificationKind::Reaction => Self::Reaction,
            OrdinaryNotificationKind::Policy => Self::Policy,
            OrdinaryNotificationKind::Call => Self::Call,
            OrdinaryNotificationKind::Applet => Self::Applet,
            OrdinaryNotificationKind::Moderation => Self::Moderation,
            OrdinaryNotificationKind::System => Self::System,
        }
    }
}

impl TryFrom<&NotificationKind> for OrdinaryNotificationKind {
    type Error = WireError;

    fn try_from(value: &NotificationKind) -> Result<Self> {
        match value {
            NotificationKind::Message => Ok(Self::Message),
            NotificationKind::Mention => Ok(Self::Mention),
            NotificationKind::Reply => Ok(Self::Reply),
            NotificationKind::Assignment => Ok(Self::Assignment),
            NotificationKind::Schedule => Ok(Self::Schedule),
            NotificationKind::Reaction => Ok(Self::Reaction),
            NotificationKind::Policy => Ok(Self::Policy),
            NotificationKind::Call => Ok(Self::Call),
            NotificationKind::Applet => Ok(Self::Applet),
            NotificationKind::Moderation => Ok(Self::Moderation),
            NotificationKind::System => Ok(Self::System),
            NotificationKind::Invite | NotificationKind::Agent => Err(WireError::Protocol(
                "notification category has a dedicated carrier".to_owned(),
            )),
        }
    }
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
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ReadScopeKind {
    Realm,
    Circle,
    Space,
    Strand,
    Thread,
    View,
    Message,
    Morph,
}

impl ReadScopeKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Realm => "realm",
            Self::Circle => "circle",
            Self::Space => "space",
            Self::Strand => "strand",
            Self::Thread => "thread",
            Self::View => "view",
            Self::Message => "message",
            Self::Morph => "morph",
        }
    }

    /// Read-scope kinds valid for a `ak.read_cursor` object
    /// (`read-cursor.schema.json`: realm/circle/space/strand/thread).
    pub fn valid_for_read_cursor(&self) -> bool {
        matches!(
            self,
            Self::Realm | Self::Circle | Self::Space | Self::Strand | Self::Thread
        )
    }

    /// Read-scope kinds valid for a `ak.read_receipt` object
    /// (`read-receipt.schema.json`: realm/strand/thread/view/message/morph).
    pub fn valid_for_read_receipt(&self) -> bool {
        matches!(
            self,
            Self::Realm | Self::Strand | Self::Thread | Self::View | Self::Message | Self::Morph
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct ReadCursorScope {
    pub kind: ReadScopeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_ref: Option<String>,
    #[serde(rename = "track_name", skip_serializing_if = "Option::is_none")]
    pub track: Option<String>,
}

impl ReadCursorScope {
    pub fn realm() -> Self {
        Self {
            kind: ReadScopeKind::Realm,
            container_ref: None,
            track: None,
        }
    }

    pub fn strand(strand_id: impl Into<String>, track: Option<impl Into<String>>) -> Self {
        Self {
            kind: ReadScopeKind::Strand,
            container_ref: Some(strand_id.into()),
            track: track.map(Into::into),
        }
    }

    pub fn thread(thread_id: impl Into<String>) -> Self {
        Self {
            kind: ReadScopeKind::Thread,
            container_ref: Some(thread_id.into()),
            track: None,
        }
    }

    pub fn circle(circle_id: impl Into<String>) -> Self {
        Self {
            kind: ReadScopeKind::Circle,
            container_ref: Some(circle_id.into()),
            track: None,
        }
    }

    pub fn space(space_id: impl Into<String>) -> Self {
        Self {
            kind: ReadScopeKind::Space,
            container_ref: Some(space_id.into()),
            track: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !self.kind.valid_for_read_cursor() {
            return Err(WireError::Protocol(format!(
                "read_scope kind '{}' is not valid for read cursors",
                self.kind.as_str()
            )));
        }
        if self.kind == ReadScopeKind::Realm {
            if self.container_ref.is_some() {
                return Err(WireError::Protocol(
                    "read_scope.container_ref must be omitted when kind is realm".to_owned(),
                ));
            }
            if self.track.is_some() {
                return Err(WireError::Protocol(
                    "read_scope.track_name must be omitted when kind is realm".to_owned(),
                ));
            }
        } else if self
            .container_ref
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            return Err(WireError::Protocol(
                "read_scope.container_ref is required when kind is not realm".to_owned(),
            ));
        }

        match self.kind {
            ReadScopeKind::Strand => {
                if let Some(track) = self.track.as_deref() {
                    validate_read_scope_track(track)?;
                }
            }
            _ if self.track.is_some() => {
                return Err(WireError::Protocol(
                    "read_scope.track_name is only valid when kind is strand".to_owned(),
                ));
            }
            _ => {}
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadReceiptScope {
    pub kind: ReadScopeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<String>,
    #[serde(rename = "track_name", skip_serializing_if = "Option::is_none")]
    pub track: Option<String>,
}

impl ReadReceiptScope {
    pub fn realm() -> Self {
        Self {
            kind: ReadScopeKind::Realm,
            object_ref: None,
            track: None,
        }
    }

    pub fn strand(strand_id: impl Into<String>, track: Option<impl Into<String>>) -> Self {
        Self {
            kind: ReadScopeKind::Strand,
            object_ref: Some(strand_id.into()),
            track: track.map(Into::into),
        }
    }

    pub fn thread(thread_id: impl Into<String>) -> Self {
        Self {
            kind: ReadScopeKind::Thread,
            object_ref: Some(thread_id.into()),
            track: None,
        }
    }

    pub fn view(view_id: impl Into<String>) -> Self {
        Self {
            kind: ReadScopeKind::View,
            object_ref: Some(view_id.into()),
            track: None,
        }
    }

    pub fn message(message_id: impl Into<String>) -> Self {
        Self {
            kind: ReadScopeKind::Message,
            object_ref: Some(message_id.into()),
            track: None,
        }
    }

    pub fn morph(morph_id: impl Into<String>) -> Self {
        Self {
            kind: ReadScopeKind::Morph,
            object_ref: Some(morph_id.into()),
            track: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if !self.kind.valid_for_read_receipt() {
            return Err(WireError::Protocol(format!(
                "read_scope kind '{}' is not valid for read receipts",
                self.kind.as_str()
            )));
        }
        if self.kind == ReadScopeKind::Realm {
            if self.object_ref.is_some() {
                return Err(WireError::Protocol(
                    "read_scope.object_ref must be omitted when kind is realm".to_owned(),
                ));
            }
            if self.track.is_some() {
                return Err(WireError::Protocol(
                    "read_scope.track_name must be omitted when kind is realm".to_owned(),
                ));
            }
        } else if self.object_ref.as_deref().unwrap_or("").trim().is_empty() {
            return Err(WireError::Protocol(
                "read_scope.object_ref is required when kind is not realm".to_owned(),
            ));
        }

        match self.kind {
            ReadScopeKind::Strand => {
                if let Some(track) = self.track.as_deref() {
                    validate_read_scope_track(track)?;
                }
            }
            _ if self.track.is_some() => {
                return Err(WireError::Protocol(
                    "read_scope.track_name is only valid when kind is strand".to_owned(),
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

fn validate_read_scope_track(track: &str) -> Result<()> {
    let mut bytes = track.bytes();
    let Some(first) = bytes.next() else {
        return Err(WireError::Protocol(
            "read_scope.track_name must not be empty".to_owned(),
        ));
    };
    if !first.is_ascii_lowercase() {
        return Err(WireError::Protocol(format!(
            "invalid read_scope.track_name '{track}'"
        )));
    }
    if track.len() > 64
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(WireError::Protocol(format!(
            "invalid read_scope.track_name '{track}'"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Create,
    Update,
    Delete,
    Redact,
    Grant,
    Revoke,
    RealmStateSnapshotRef,
    Move,
    Reorder,
    Rebalance,
    Link,
    Unlink,
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
// Deliberate exception to the crate-wide `snake_case` enum convention: the
// `encrypted-envelope.schema.json` `scheme` const is the kebab-case token
// `mls_rfc9420`. The exception is made explicit per-variant rather than via
// `rename_all = "kebab-case"` so a future `snake_case` variant added by habit
// doesn't silently produce a wire-incompatible token.
#[serde(rename_all = "snake_case")]
pub enum EncryptedPayloadScheme {
    #[serde(rename = "mls_rfc9420")]
    MlsRfc9420,
    // §2.10 exporter content scheme: content is encrypted under the local
    // per-epoch `epoch_content_root` derived from the MLS exporter.
    #[serde(rename = "mls_exporter_aead_v1")]
    MlsExporterAeadV1,
}

impl EncryptedPayloadScheme {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MlsRfc9420 => "mls_rfc9420",
            Self::MlsExporterAeadV1 => "mls_exporter_aead_v1",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

impl Audience {
    fn covers(&self, required: &Self) -> bool {
        match (self, required) {
            (Self::Single(actual), Self::Single(expected)) => actual == expected,
            (Self::Multiple(actual), Self::Single(expected)) => actual.contains(expected),
            (Self::Single(actual), Self::Multiple(expected)) => {
                expected.len() == 1 && expected.first() == Some(actual)
            }
            (Self::Multiple(actual), Self::Multiple(expected)) => {
                expected.iter().all(|value| actual.contains(value))
            }
        }
    }

    fn validate_binding_value(&self) -> Result<()> {
        match self {
            Self::Single(value) => {
                if value.trim().is_empty() {
                    return Err(WireError::Protocol(
                        "proof audience must not be empty".to_owned(),
                    ));
                }
            }
            Self::Multiple(values) => {
                if values.is_empty() {
                    return Err(WireError::Protocol(
                        "proof audience list must not be empty".to_owned(),
                    ));
                }
                let mut seen = BTreeSet::new();
                for value in values {
                    if value.trim().is_empty() {
                        return Err(WireError::Protocol(
                            "proof audience entries must not be empty".to_owned(),
                        ));
                    }
                    if !seen.insert(value) {
                        return Err(WireError::Protocol(
                            "proof audience entries must be unique".to_owned(),
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofBindingRequirements {
    pub require_domain: bool,
    pub require_audience: bool,
}

impl ProofBindingRequirements {
    pub const fn local() -> Self {
        Self {
            require_domain: false,
            require_audience: false,
        }
    }

    pub const fn cross_domain() -> Self {
        Self {
            require_domain: true,
            require_audience: true,
        }
    }
}

fn proof_binding_missing(field: &str) -> WireError {
    WireError::ProtocolCode {
        code: ErrorCode::SchemaViolation,
        message: format!("proof {field} is required"),
    }
}

fn require_proof_domain(proof: Option<&str>, expected: Option<&str>) -> Result<()> {
    if proof.map(str::trim).map(str::is_empty).unwrap_or(true) {
        return Err(proof_binding_missing("domain"));
    }
    if expected.map(str::trim).map(str::is_empty).unwrap_or(true) {
        return Err(WireError::ProtocolCode {
            code: ErrorCode::SchemaViolation,
            message: "expected domain is required".to_owned(),
        });
    }
    Ok(())
}

fn require_proof_audience(proof: Option<&Audience>, expected: Option<&Audience>) -> Result<()> {
    if proof.is_none() {
        return Err(proof_binding_missing("audience"));
    }
    if expected.is_none() {
        return Err(WireError::ProtocolCode {
            code: ErrorCode::SchemaViolation,
            message: "expected audience is required".to_owned(),
        });
    }
    Ok(())
}

fn proof_audience_covers_expected(proof: Option<&Audience>, expected: Option<&Audience>) -> bool {
    match (proof, expected) {
        (_, None) => true,
        (Some(proof), Some(expected)) => proof.covers(expected),
        _ => false,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ProducerEventProof {
    pub kind: String,
    pub verification_method: DidUrl,
    pub event_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_purpose: Option<PayloadProofPurpose>,
    pub jws: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum PayloadProofPurpose {
    IssuerAttestation,
    HolderAcceptance,
    StatusAttestation,
    RevocationAuthorization,
    /// `discovery-directory.md` §8.7.1 write-surface authorization by the
    /// resource governance key (`DirectoryGovernanceProof`).
    GovernanceAuthorization,
}

/// Fully typed proof metadata before a detached JWS exists.
///
/// Signing code must use this type instead of manufacturing an invalid
/// [`PayloadProof`] with an empty `jws`. [`UnsignedPayloadProof::finalize`]
/// is the only transition to the wire type and validates the completed proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedPayloadProof {
    pub kind: String,
    pub verification_method: DidUrl,
    pub payload_digest: Hash,
    pub created_at: DateTime<Utc>,
    pub domain: Option<String>,
    pub audience: Option<Audience>,
    pub proof_purpose: Option<PayloadProofPurpose>,
}

impl UnsignedPayloadProof {
    pub fn validate_production(&self) -> Result<()> {
        if self.kind != proof_kind::DETACHED_JWS {
            return Err(WireError::Protocol(format!(
                "unsupported production proof kind: {}",
                self.kind
            )));
        }
        if self
            .domain
            .as_deref()
            .is_some_and(|domain| domain.trim().is_empty())
        {
            return Err(WireError::Protocol(
                "proof domain must not be empty".to_owned(),
            ));
        }
        if let Some(audience) = &self.audience {
            audience.validate_binding_value()?;
        }
        Ok(())
    }

    pub fn finalize(self, jws: impl Into<String>) -> Result<PayloadProof> {
        self.validate_production()?;
        let proof = PayloadProof {
            kind: self.kind,
            verification_method: self.verification_method,
            payload_digest: self.payload_digest,
            created_at: self.created_at,
            domain: self.domain,
            audience: self.audience,
            proof_purpose: self.proof_purpose,
            jws: jws.into(),
        };
        proof.validate_production()?;
        Ok(proof)
    }
}

/// Shared leading members of a service-operation requester-proof binding
/// object.
///
/// `discovery-directory.md` §9.0.1 and `mimi-interop.md` §5.1 register the same
/// opening sequence: the family's own `context`, the unsigned `payload_digest`,
/// the originator `issuer` when the family's wire shape defines one, the
/// `operation_id`, the family's verbatim target members in
/// `proof-context-registry.json` `binding_fields` order, and then the signer's
/// `verification_method` and `created_at`.
///
/// The two families diverge only in the trailer — MIMI appends `domain` plus
/// `audience`, the Directory read surface appends `audience_id` — so this
/// returns the partially built map for the caller to close out rather than the
/// canonical bytes. Keeping the shared opening in one place stops the two
/// registered orders from drifting apart in independent edits.
pub fn service_operation_proof_binding_prefix(
    context: &str,
    operation_id: &str,
    issuer: Option<Value>,
    targets: Vec<(&'static str, Value)>,
    payload_digest: &Hash,
    verification_method: &DidUrl,
    created_at: DateTime<Utc>,
) -> Result<serde_json::Map<String, Value>> {
    let mut binding = serde_json::Map::new();
    binding.insert("context".to_owned(), Value::String(context.to_owned()));
    binding.insert(
        "payload_digest".to_owned(),
        serde_json::to_value(payload_digest)?,
    );
    if let Some(issuer) = issuer {
        binding.insert("issuer".to_owned(), issuer);
    }
    binding.insert(
        "operation_id".to_owned(),
        Value::String(operation_id.to_owned()),
    );
    for (name, value) in targets {
        binding.insert(name.to_owned(), value);
    }
    binding.insert(
        "verification_method".to_owned(),
        serde_json::to_value(verification_method)?,
    );
    binding.insert(
        "created_at".to_owned(),
        Value::String(canonical::format_timestamp_canonical(created_at)),
    );
    Ok(binding)
}

/// Complete canonical detached-JWS binding bytes for one registered
/// service-operation proof context (`conformance/encoding.md` §6 (b)-(d)).
///
/// The `context` constant is written by the verifier from the registry row, is
/// carried as a binding-object member, and never appears as a JWS header
/// parameter or a wire field of the signed object. The returned bytes are the
/// detached JWS payload segment; there is no additional domain-tag prefix.
pub fn service_operation_proof_binding_bytes(
    context: &str,
    operation_id: &str,
    issuer: Option<Value>,
    targets: Vec<(&'static str, Value)>,
    payload_digest: &Hash,
    proof: &UnsignedPayloadProof,
) -> Result<Vec<u8>> {
    proof.validate_production()?;
    if proof.proof_purpose.is_some() {
        return Err(WireError::Protocol(format!(
            "{context} proof must not carry proof_purpose"
        )));
    }
    if &proof.payload_digest != payload_digest {
        return Err(WireError::Protocol(format!(
            "{context} proof payload_digest mismatch"
        )));
    }
    let domain = proof
        .domain
        .as_ref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| WireError::Protocol(format!("{context} proof requires domain")))?;
    let audience = proof
        .audience
        .as_ref()
        .ok_or_else(|| WireError::Protocol(format!("{context} proof requires audience")))?;
    let mut binding = service_operation_proof_binding_prefix(
        context,
        operation_id,
        issuer,
        targets,
        payload_digest,
        &proof.verification_method,
        proof.created_at,
    )?;
    binding.insert("domain".to_owned(), Value::String(domain.clone()));
    binding.insert("audience".to_owned(), serde_json::to_value(audience)?);
    canonical::canonical_json_bytes(&Value::Object(binding)).map_err(Into::into)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PayloadProof {
    pub kind: String,
    pub verification_method: DidUrl,
    pub payload_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_purpose: Option<PayloadProofPurpose>,
    pub jws: String,
}

impl PayloadProof {
    pub fn unsigned(&self) -> UnsignedPayloadProof {
        UnsignedPayloadProof {
            kind: self.kind.clone(),
            verification_method: self.verification_method.clone(),
            payload_digest: self.payload_digest.clone(),
            created_at: self.created_at,
            domain: self.domain.clone(),
            audience: self.audience.clone(),
            proof_purpose: self.proof_purpose.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.kind.is_empty() {
            return Err(WireError::Protocol(
                "proof kind must not be empty".to_owned(),
            ));
        }
        if !is_compact_detached_jws(&self.jws) {
            return Err(WireError::Protocol(
                "proof JWS must use compact detached JWS syntax".to_owned(),
            ));
        }
        if self
            .domain
            .as_deref()
            .is_some_and(|domain| domain.trim().is_empty())
        {
            return Err(WireError::Protocol(
                "proof domain must not be empty".to_owned(),
            ));
        }
        if let Some(audience) = &self.audience {
            audience.validate_binding_value()?;
        }
        Ok(())
    }

    pub fn validate_production(&self) -> Result<()> {
        self.validate()?;
        if self.kind != proof_kind::DETACHED_JWS {
            return Err(WireError::Protocol(format!(
                "unsupported production proof kind: {}",
                self.kind
            )));
        }
        Ok(())
    }
}

/// Fixed signing-context domain tag for Event proof bindings (`encoding.md`
/// §2). Included in every [`ProducerEventProof::binding_object`] so an Event proof
/// signature is domain-separated from other proof families (receipts,
/// snapshot witnesses, handle claims, which carry their own context values).
pub const EVENT_PROOF_BINDING_CONTEXT: &str = ProofContextId::EVENT_PROOF_V1;

/// Canonical proof kind constants.
pub mod proof_kind {
    /// Standard actor / device / service detached JWS. Per `encoding.md` §6
    /// the signed bytes are the canonical **proof binding object**
    /// (`{event_digest, actor_id, verification_method, created_at, domain?,
    /// audience?}`), NOT the raw canonical event bytes — see
    /// [`super::ProducerEventProof::canonical_binding_bytes`].
    pub const DETACHED_JWS: &str = "detached_jws";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CriticalExtension {
    pub id: String,
    pub extension_scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub material_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<String>,
    pub fail_closed: bool,
}

/// Allowed proof algorithms for production use — the single source of truth
/// for the SDK's proof-algorithm gate (`arkret-signatures` re-exports it).
///
/// This is the intersection of the `active` rows of
/// `artifacts/registry/signature-alg-registry.json` (`jose_algorithm` values, per
/// `encoding.md` §6.1) with what this SDK can actually verify: only `Ed25519`
/// (Ed25519, default-MUST). `ES256` and `ML-DSA-65` are registered active rows
/// but ship no signer/verifier here — admitting them in `validate_production`
/// would let an `alg` the SDK cannot check pass a gate that callers may treat
/// as authoritative (alg-confusion foot-gun), so they are fail-closed excluded
/// until an implementation lands. Matching is exact and case-sensitive, in
/// line with the verifiers (`alg == "Ed25519"`).
pub const PRODUCTION_ALGORITHMS: &[&str] = &["Ed25519"];

/// Proof kinds that indicate development/test mode and are rejected in production.
const DEV_PROOF_KINDS: &[&str] = &["dev", "test", "mock", "stub", "dummy"];

/// Hard replay/freshness tolerance for matching a proof to its expected
/// binding payload. This is the same hard ceiling as the default HLC future
/// skew guard in encoding.md §7.2, but proof binding only has a binary
/// accept/reject result, not the HLC soft-fail layer.
const PROOF_CREATED_AT_HARD_SKEW_MINUTES: i64 = 5;

impl ProducerEventProof {
    /// Deserialize an inbound Proof after canonical JSON ingress checks
    /// (NFC strings, duplicate keys, number profile).
    pub fn from_canonical_json_slice(bytes: &[u8]) -> Result<Self> {
        Ok(canonical::from_canonical_json_slice(bytes)?)
    }

    pub fn binding_payload(&self, actor_id: &ActorId) -> SignatureBindingPayload {
        SignatureBindingPayload {
            payload_digest: self.event_digest.clone(),
            actor_id: actor_id.clone(),
            verification_method: self.verification_method.clone(),
            created_at: self.created_at,
            domain: self.domain.clone(),
            audience: self.audience.clone(),
        }
    }

    /// Build the canonical **proof binding object** that the detached JWS
    /// signs (encoding.md §6 / event-and-patch.md §3): a canonical-JSON
    /// object over `{event_digest, actor_id, verification_method,
    /// created_at, domain?, audience?}`.
    ///
    /// The detached-JWS payload MUST be these bytes — **not** the raw
    /// canonical Event bytes — so that `created_at`, `domain`, `audience`
    /// and `verification_method` are cryptographically covered by the
    /// signature, not just compared as plaintext. `created_at` is emitted
    /// in canonical UTC `YYYY-MM-DDTHH:MM:SS.sssZ` form so the wire field
    /// and transcript contain the same byte-identical timestamp string.
    pub fn canonical_binding_bytes(&self, actor_id: &ActorId) -> Result<Vec<u8>> {
        self.canonical_binding_bytes_with_context(actor_id, EVENT_PROOF_BINDING_CONTEXT)
    }

    fn canonical_binding_bytes_with_context(
        &self,
        actor_id: &ActorId,
        context: &str,
    ) -> Result<Vec<u8>> {
        Ok(canonical::canonical_json_bytes(
            &self.binding_object_with_context(actor_id, context)?,
        )?)
    }

    /// The proof binding object as a [`serde_json::Value`] (key order is
    /// irrelevant — canonical JSON re-sorts by JCS). Shared by signer and
    /// verifier so both derive identical transcripts.
    pub fn binding_object(&self, actor_id: &ActorId) -> Value {
        self.binding_object_with_context(actor_id, EVENT_PROOF_BINDING_CONTEXT)
            .expect("the fixed event proof context is non-empty")
    }

    fn binding_object_with_context(&self, actor_id: &ActorId, context: &str) -> Result<Value> {
        if context.trim().is_empty() {
            return Err(WireError::Protocol(
                "proof binding context must not be empty".to_owned(),
            ));
        }
        let mut obj = serde_json::Map::new();
        // Fixed signing-context domain tag (encoding.md §2): every Event proof
        // binding MUST carry `context = "ak.event_proof.v1"` so an Event proof
        // signature cannot be confused with another object family's binding
        // (receipts, snapshot witnesses, handle claims each use their own
        // context). Key order is irrelevant — canonical JSON re-sorts by JCS.
        obj.insert("context".to_owned(), Value::String(context.to_owned()));
        obj.insert(
            "event_digest".to_owned(),
            Value::String(self.event_digest.as_str().to_owned()),
        );
        obj.insert("actor_id".to_owned(), serde_json::to_value(actor_id)?);
        obj.insert(
            "verification_method".to_owned(),
            Value::String(self.verification_method.as_str().to_owned()),
        );
        obj.insert(
            "created_at".to_owned(),
            Value::String(canonical::format_timestamp_canonical(self.created_at)),
        );
        if let Some(domain) = &self.domain {
            obj.insert("domain".to_owned(), Value::String(domain.clone()));
        }
        if let Some(audience) = &self.audience {
            obj.insert(
                "audience".to_owned(),
                serde_json::to_value(audience).unwrap_or(Value::Null),
            );
        }
        Ok(Value::Object(obj))
    }

    /// Validate proof structural requirements.
    ///
    /// Rejects empty JWS and kind values. The signature layer validates the
    /// protected JOSE `alg`; the Arkret wrapper deliberately does not repeat it.
    pub fn validate(&self) -> Result<()> {
        if !is_compact_detached_jws(&self.jws) {
            return Err(WireError::Protocol(
                "proof JWS is not compact detached JWS".to_owned(),
            ));
        }
        if self.kind != proof_kind::DETACHED_JWS {
            return Err(WireError::Protocol(
                "producer proof kind must equal detached_jws".to_owned(),
            ));
        }
        if self
            .domain
            .as_deref()
            .is_some_and(|domain| domain.trim().is_empty())
        {
            return Err(WireError::Protocol(
                "proof domain must not be empty".to_owned(),
            ));
        }
        if let Some(audience) = &self.audience {
            audience.validate_binding_value()?;
        }
        if self.proof_purpose == Some(PayloadProofPurpose::GovernanceAuthorization) {
            return Err(WireError::Protocol(
                "producer proof purpose is not registered for Event proofs".to_owned(),
            ));
        }
        Ok(())
    }

    /// Validate that this proof uses a production-grade algorithm and kind.
    ///
    /// Rejects dev/test proof kinds. The cryptographic verifier rejects an
    /// unsupported protected-header algorithm.
    pub fn validate_production(&self) -> Result<()> {
        self.validate()?;
        if DEV_PROOF_KINDS
            .iter()
            .any(|k| self.kind.eq_ignore_ascii_case(k))
        {
            return Err(WireError::Protocol(format!(
                "production proofs must not use dev/test kind: {}",
                self.kind
            )));
        }
        Ok(())
    }

    /// Validate that the proof's structural fields match the expected binding.
    ///
    /// Checks: verification_method, event_digest, created_at (within tolerance),
    /// domain, and audience.
    pub fn validate_binding(&self, expected: &SignatureBindingPayload) -> Result<()> {
        self.validate_binding_with_requirements(expected, ProofBindingRequirements::local())
    }

    pub fn validate_binding_with_requirements(
        &self,
        expected: &SignatureBindingPayload,
        requirements: ProofBindingRequirements,
    ) -> Result<()> {
        self.validate()?;
        if self.verification_method != expected.verification_method {
            return Err(WireError::Protocol(format!(
                "proof verification_method '{}' does not match expected '{}'",
                self.verification_method, expected.verification_method
            )));
        }
        if self.event_digest != expected.payload_digest {
            return Err(WireError::Protocol(
                "proof event_digest does not match expected digest".to_owned(),
            ));
        }
        let diff = if self.created_at > expected.created_at {
            self.created_at - expected.created_at
        } else {
            expected.created_at - self.created_at
        };
        if diff > chrono::Duration::minutes(PROOF_CREATED_AT_HARD_SKEW_MINUTES) {
            return Err(WireError::Protocol(format!(
                "proof created_at differs from expected by {} seconds (max {} seconds)",
                diff.num_seconds(),
                PROOF_CREATED_AT_HARD_SKEW_MINUTES
                    .checked_mul(60)
                    .expect("proof skew constant fits seconds")
            )));
        }
        if requirements.require_domain {
            require_proof_domain(self.domain.as_deref(), expected.domain.as_deref())?;
        } else if expected.domain.is_some() && self.domain.is_none() {
            return Err(proof_binding_missing("domain"));
        }
        if requirements.require_audience {
            require_proof_audience(self.audience.as_ref(), expected.audience.as_ref())?;
        } else if expected.audience.is_some() && self.audience.is_none() {
            return Err(proof_binding_missing("audience"));
        }
        if expected.domain.is_some() && self.domain != expected.domain {
            return Err(WireError::Protocol(format!(
                "proof domain {:?} does not match expected {:?}",
                self.domain, expected.domain
            )));
        }
        if !proof_audience_covers_expected(self.audience.as_ref(), expected.audience.as_ref()) {
            return Err(WireError::Protocol(format!(
                "proof audience {:?} does not match expected {:?}",
                self.audience, expected.audience
            )));
        }
        Ok(())
    }
}

/// Return whether `value` has the protocol's compact detached-JWS carrier
/// shape: exactly `protected..signature`, with unpadded base64url segments.
///
/// This is deliberately only the wire-shape gate. Cryptographic consumers
/// must still decode the protected header, require the active `Ed25519`
/// algorithm, and verify the signature over the registered transcript.
pub fn is_compact_detached_jws(value: &str) -> bool {
    let mut segments = value.split('.');
    let protected = segments.next().unwrap_or_default();
    let payload = segments.next().unwrap_or_default();
    let signature = segments.next().unwrap_or_default();
    !protected.is_empty()
        && payload.is_empty()
        && !signature.is_empty()
        && segments.next().is_none()
        && value
            .bytes()
            .all(|byte| byte == b'.' || byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureBindingPayload {
    pub payload_digest: Hash,
    pub actor_id: ActorId,
    pub verification_method: DidUrl,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn station_actor_identity_is_independent_of_principal_classification() {
        let principal = DidCoreId::new("ak:did_core:web:agent.example").unwrap();
        let station = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        let account = AccountId::new(principal.clone(), station.clone());
        let actor = ActorId::account(account.clone());
        let value = serde_json::json!({"kind": "account", "account_id": account});
        assert_eq!(serde_json::to_value(&actor).unwrap(), value);
        assert_eq!(serde_json::from_value::<ActorId>(value).unwrap(), actor);
        assert_eq!(actor.as_account_id(), Some(&account));
        assert_eq!(actor.signing_principal_id(), &principal);
        assert_eq!(actor.route_service_id(), &station);
        assert_ne!(actor, ActorId::service(principal.clone()));
        assert_ne!(
            actor,
            ActorId::account(AccountId::new(
                principal,
                DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
            ))
        );
    }

    #[test]
    fn actor_identity_rejects_removed_variant_and_incomplete_account_shapes() {
        let principal = "ak:did_core:web:agent.example";
        let station = "ak:did_core:web:station.example";
        for value in [
            serde_json::json!({"kind": "hosted_principal", "principal_id": principal, "station_id": station}),
            serde_json::json!({"kind": "account", "principal_id": principal, "station_id": station}),
            serde_json::json!({"kind": "account", "account_id": {"principal_id": principal}}),
            serde_json::json!({"kind": "account", "account_id": {"principal_id": principal, "station_id": station}, "actor_kind": "agent"}),
        ] {
            assert!(serde_json::from_value::<ActorId>(value).is_err());
        }
    }

    #[test]
    fn discoverability_tokens_are_closed_and_round_trip() {
        let tokens = [
            "public",
            "listed",
            "restricted",
            "unlisted",
            "invite_only",
            "secret",
        ];
        assert_eq!(Discoverability::ALL.map(Discoverability::as_str), tokens);
        for (value, token) in Discoverability::ALL.into_iter().zip(tokens) {
            assert_eq!(Discoverability::from_str(token), Ok(value));
            assert_eq!(serde_json::to_value(value).unwrap(), token);
        }
        assert!(Discoverability::from_str("private").is_err());
    }
}
