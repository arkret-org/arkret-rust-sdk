use std::fmt;
use std::str::FromStr;

use super::*;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum HistoryVisibility {
    WorldReadable,
    Shared,
    Invited,
    Joined,
    Restricted,
}

impl HistoryVisibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WorldReadable => "world_readable",
            Self::Shared => "shared",
            Self::Invited => "invited",
            Self::Joined => "joined",
            Self::Restricted => "restricted",
        }
    }

    pub fn admits_pre_join_history(&self) -> bool {
        matches!(self, Self::WorldReadable | Self::Shared | Self::Invited)
    }
}

impl FromStr for HistoryVisibility {
    type Err = HistoryVisibilityParseError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "world_readable" => Ok(Self::WorldReadable),
            "shared" => Ok(Self::Shared),
            "invited" => Ok(Self::Invited),
            "joined" => Ok(Self::Joined),
            "restricted" => Ok(Self::Restricted),
            _ => Err(HistoryVisibilityParseError),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryVisibilityParseError;

impl fmt::Display for HistoryVisibilityParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown history_visibility value")
    }
}

impl std::error::Error for HistoryVisibilityParseError {}

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    User,
    Org,
    Team,
    Agent,
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FacetSelector {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub all: Vec<Facet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub any: Vec<Facet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub none: Vec<Facet>,
}

impl FacetSelector {
    pub fn matches(&self, facets: &[Facet]) -> bool {
        self.all.iter().all(|facet| facets.contains(facet))
            && (self.any.is_empty() || self.any.iter().any(|facet| facets.contains(facet)))
            && self.none.iter().all(|facet| !facets.contains(facet))
    }
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

    pub fn facet_names(&self) -> Vec<Facet> {
        match self {
            Self::Names(names) => names.clone(),
            Self::Configs(configs) => configs.keys().cloned().collect(),
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
    STANDARD_RELATION_KIND_METADATA, StandardRelationKindMetadata, standard_relation_kind_metadata,
};
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// `(kind, renderer)` pair is not in this whitelist (or `Custom` /
    /// `Composite`, which delegate to profile-declared renderers). The
    /// whitelist intentionally allows `ViewRenderer::Custom` everywhere
    /// because profiles MAY declare additional renderers per kind.
    pub fn allowed_renderers(self) -> &'static [ViewRenderer] {
        use ViewRenderer::*;
        match self {
            ViewKind::Collection => &[Board, Card, Row, Table, Calendar, Gantt, Custom],
            ViewKind::Timeline => &[Timeline, Thread, Chat, Forum, Custom],
            ViewKind::Graph => &[Graph, Custom],
            ViewKind::Document => &[Document, Custom],
            ViewKind::Composite => &[
                Board, Card, Row, Table, Calendar, Gantt, Timeline, Thread, Chat, Forum, Graph,
                Tree, Document, Dashboard, Custom,
            ],
        }
    }

    /// `true` when `renderer` is permitted for this `ViewKind`. Returns
    /// `false` for the strict whitelist; callers SHOULD also accept
    /// profile-declared renderers via the `Custom` variant.
    pub fn allows_renderer(self, renderer: ViewRenderer) -> bool {
        self.allowed_renderers().contains(&renderer)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewRenderer {
    Board,
    Card,
    Row,
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    HistoryVisibility,
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

pub type Decision = AuthzDecision;

/// Frontier freshness classification for revocation-sensitive authz decisions.
/// Spec `AuthzCheckOutcome.freshness_state` enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum FreshnessState {
    Fresh,
    Stale,
    Unknown,
}

/// Coarse status of the notary / frontier source used to diagnose stale or
/// unknown revocation freshness. Spec `AuthzCheckOutcome.notary_status` enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum NotaryStatus {
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
            return Err(Error::Protocol(format!(
                "read_scope kind '{}' is not valid for read cursors",
                self.kind.as_str()
            )));
        }
        if self.kind == ReadScopeKind::Realm {
            if self.container_ref.is_some() {
                return Err(Error::Protocol(
                    "read_scope.container_ref must be omitted when kind is realm".to_owned(),
                ));
            }
            if self.track.is_some() {
                return Err(Error::Protocol(
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
            return Err(Error::Protocol(
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
                return Err(Error::Protocol(
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
            return Err(Error::Protocol(format!(
                "read_scope kind '{}' is not valid for read receipts",
                self.kind.as_str()
            )));
        }
        if self.kind == ReadScopeKind::Realm {
            if self.object_ref.is_some() {
                return Err(Error::Protocol(
                    "read_scope.object_ref must be omitted when kind is realm".to_owned(),
                ));
            }
            if self.track.is_some() {
                return Err(Error::Protocol(
                    "read_scope.track_name must be omitted when kind is realm".to_owned(),
                ));
            }
        } else if self.object_ref.as_deref().unwrap_or("").trim().is_empty() {
            return Err(Error::Protocol(
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
                return Err(Error::Protocol(
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
        return Err(Error::Protocol(
            "read_scope.track_name must not be empty".to_owned(),
        ));
    };
    if !first.is_ascii_lowercase() {
        return Err(Error::Protocol(format!(
            "invalid read_scope.track_name '{track}'"
        )));
    }
    if track.len() > 64
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(Error::Protocol(format!(
            "invalid read_scope.track_name '{track}'"
        )));
    }
    Ok(())
}

/// Account lifecycle states.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountState {
    Active,
    SoftLoggedOut,
    Locked,
    Suspended,
    Deactivated,
    Erased,
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
    SnapshotRef,
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
// `mls_rfc9420` (distinct from the `encryption_profile` enum value
// `mls_rfc9420`). The exception is made explicit per-variant rather than via
// `rename_all = "kebab-case"` so a future `snake_case` variant added by habit
// doesn't silently produce a wire-incompatible token.
#[serde(rename_all = "snake_case")]
pub enum EncryptedPayloadScheme {
    #[serde(rename = "mls_rfc9420")]
    MlsRfc9420,
    // §2.10 history-shareable content scheme: content is encrypted under a
    // retainable / re-sealable per-epoch `history_secret` (MLS exporter) instead
    // of the forward-secret message ratchet, so a late joiner granted the
    // epoch's `history_secret` via `ak.realm_key.share` can decrypt pre-join
    // content. Trades per-message forward secrecy for per-epoch (§2.10.5).
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
                    return Err(Error::Protocol(
                        "proof audience must not be empty".to_owned(),
                    ));
                }
            }
            Self::Multiple(values) => {
                if values.is_empty() {
                    return Err(Error::Protocol(
                        "proof audience list must not be empty".to_owned(),
                    ));
                }
                let mut seen = BTreeSet::new();
                for value in values {
                    if value.trim().is_empty() {
                        return Err(Error::Protocol(
                            "proof audience entries must not be empty".to_owned(),
                        ));
                    }
                    if !seen.insert(value) {
                        return Err(Error::Protocol(
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

fn proof_binding_missing(field: &str) -> Error {
    Error::Protocol(format!(
        "{}: proof {field} is required",
        ReasonCode::PROOF_BINDING_MISSING
    ))
}

fn require_proof_domain(proof: Option<&str>, expected: Option<&str>) -> Result<()> {
    if proof.map(str::trim).map(str::is_empty).unwrap_or(true) {
        return Err(proof_binding_missing("domain"));
    }
    if expected.map(str::trim).map(str::is_empty).unwrap_or(true) {
        return Err(Error::Protocol(format!(
            "{}: expected domain is required",
            ReasonCode::PROOF_BINDING_MISSING
        )));
    }
    Ok(())
}

fn require_proof_audience(proof: Option<&Audience>, expected: Option<&Audience>) -> Result<()> {
    if proof.is_none() {
        return Err(proof_binding_missing("audience"));
    }
    if expected.is_none() {
        return Err(Error::Protocol(format!(
            "{}: expected audience is required",
            ReasonCode::PROOF_BINDING_MISSING
        )));
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
pub struct Proof {
    pub kind: String,
    pub verification_method: DidUrl,
    pub alg: String,
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct PayloadProof {
    pub kind: String,
    pub verification_method: DidUrl,
    pub alg: String,
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
    pub fn validate(&self) -> Result<()> {
        if self.kind.is_empty() {
            return Err(Error::Protocol("proof kind must not be empty".to_owned()));
        }
        if self.alg.is_empty() || self.alg.eq_ignore_ascii_case("none") {
            return Err(Error::Protocol(
                "proof algorithm must be a concrete registered algorithm".to_owned(),
            ));
        }
        if self.jws.is_empty() {
            return Err(Error::Protocol("proof JWS must not be empty".to_owned()));
        }
        if self
            .domain
            .as_deref()
            .is_some_and(|domain| domain.trim().is_empty())
        {
            return Err(Error::Protocol("proof domain must not be empty".to_owned()));
        }
        if let Some(audience) = &self.audience {
            audience.validate_binding_value()?;
        }
        Ok(())
    }

    pub fn validate_production(&self) -> Result<()> {
        self.validate()?;
        if self.kind != proof_kind::DETACHED_JWS {
            return Err(Error::Protocol(format!(
                "unsupported production proof kind: {}",
                self.kind
            )));
        }
        if !PRODUCTION_ALGORITHMS.contains(&self.alg.as_str()) {
            return Err(Error::Protocol(format!(
                "unsupported production proof algorithm: {}",
                self.alg
            )));
        }
        Ok(())
    }
}

/// Fixed signing-context domain tag for Event proof bindings (`encoding.md`
/// §2). Included in every [`Proof::binding_object`] so an Event proof
/// signature is domain-separated from other proof families (receipts,
/// snapshot witnesses, handle claims, which carry their own context values).
pub const EVENT_PROOF_BINDING_CONTEXT: &str = ProofContextId::EVENT_PROOF_V1;

/// Canonical proof kind constants.
pub mod proof_kind {
    /// Standard actor / device / service detached JWS. Per `encoding.md` §6
    /// the signed bytes are the canonical **proof binding object**
    /// (`{event_digest, actor_id, verification_method, created_at, domain?,
    /// audience?}`), NOT the raw canonical event bytes — see
    /// [`super::Proof::canonical_binding_bytes`].
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
/// `artifacts/registry/signature-alg-registry.json` (`proof_alg` values, per
/// `encoding.md` §6.1) with what this SDK can actually verify: only `EdDSA`
/// (Ed25519, default-MUST). `ES256` and `ML-DSA-65` are registered active rows
/// but ship no signer/verifier here — admitting them in `validate_production`
/// would let an `alg` the SDK cannot check pass a gate that callers may treat
/// as authoritative (alg-confusion foot-gun), so they are fail-closed excluded
/// until an implementation lands. Matching is exact and case-sensitive, in
/// line with the verifiers (`alg == "EdDSA"`).
pub const PRODUCTION_ALGORITHMS: &[&str] = &["EdDSA"];

/// Proof kinds that indicate development/test mode and are rejected in production.
const DEV_PROOF_KINDS: &[&str] = &["dev", "test", "mock", "stub", "dummy"];

/// Hard replay/freshness tolerance for matching a proof to its expected
/// binding payload. This is the same hard ceiling as the default HLC future
/// skew guard in encoding.md §7.2, but proof binding only has a binary
/// accept/reject result, not the HLC soft-fail layer.
const PROOF_CREATED_AT_HARD_SKEW_MINUTES: i64 = 5;

impl Proof {
    /// Deserialize an inbound Proof after canonical JSON ingress checks
    /// (NFC strings, duplicate keys, number profile).
    pub fn from_canonical_json_slice(bytes: &[u8]) -> Result<Self> {
        Ok(canonical::from_canonical_json_slice(bytes)?)
    }

    pub fn binding_payload(&self, actor_id: &Did) -> SignatureBindingPayload {
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
    pub fn canonical_binding_bytes(&self, actor_id: &Did) -> Result<Vec<u8>> {
        self.canonical_binding_bytes_with_context(actor_id, EVENT_PROOF_BINDING_CONTEXT)
    }

    fn canonical_binding_bytes_with_context(
        &self,
        actor_id: &Did,
        context: &str,
    ) -> Result<Vec<u8>> {
        Ok(canonical::canonical_json_bytes(
            &self.binding_object_with_context(actor_id, context)?,
        )?)
    }

    /// The proof binding object as a [`serde_json::Value`] (key order is
    /// irrelevant — canonical JSON re-sorts by JCS). Shared by signer and
    /// verifier so both derive identical transcripts.
    pub fn binding_object(&self, actor_id: &Did) -> Value {
        self.binding_object_with_context(actor_id, EVENT_PROOF_BINDING_CONTEXT)
            .expect("the fixed event proof context is non-empty")
    }

    fn binding_object_with_context(&self, actor_id: &Did, context: &str) -> Result<Value> {
        if context.trim().is_empty() {
            return Err(Error::Protocol(
                "proof binding context must not be empty".to_owned(),
            ));
        }
        let mut obj = serde_json::Map::new();
        // Fixed signing-context domain tag (encoding.md §2): every Event proof
        // binding MUST carry `context = "ak.event-proof-v1"` so an Event proof
        // signature cannot be confused with another object family's binding
        // (receipts, snapshot witnesses, handle claims each use their own
        // context). Key order is irrelevant — canonical JSON re-sorts by JCS.
        obj.insert("context".to_owned(), Value::String(context.to_owned()));
        obj.insert(
            "event_digest".to_owned(),
            Value::String(self.event_digest.as_str().to_owned()),
        );
        obj.insert(
            "actor_id".to_owned(),
            Value::String(actor_id.as_str().to_owned()),
        );
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
    /// Rejects `alg:none`, empty verification methods, empty JWS, and
    /// empty kind.
    pub fn validate(&self) -> Result<()> {
        if self.alg.eq_ignore_ascii_case("none") {
            return Err(Error::Protocol(
                "proof algorithm 'none' is not allowed".to_owned(),
            ));
        }
        if self.alg.is_empty() {
            return Err(Error::Protocol(
                "proof algorithm must not be empty".to_owned(),
            ));
        }
        if self.jws.is_empty() {
            return Err(Error::Protocol("proof JWS must not be empty".to_owned()));
        }
        if self.kind.is_empty() {
            return Err(Error::Protocol("proof kind must not be empty".to_owned()));
        }
        if self
            .domain
            .as_deref()
            .is_some_and(|domain| domain.trim().is_empty())
        {
            return Err(Error::Protocol("proof domain must not be empty".to_owned()));
        }
        if let Some(audience) = &self.audience {
            audience.validate_binding_value()?;
        }
        Ok(())
    }

    /// Validate that this proof uses a production-grade algorithm and kind.
    ///
    /// Rejects `alg:none`, unknown algorithms, and dev/test proof kinds.
    pub fn validate_production(&self) -> Result<()> {
        self.validate()?;
        if DEV_PROOF_KINDS
            .iter()
            .any(|k| self.kind.eq_ignore_ascii_case(k))
        {
            return Err(Error::Protocol(format!(
                "production proofs must not use dev/test kind: {}",
                self.kind
            )));
        }
        // Exact case-sensitive match, consistent with the verifiers: a proof
        // with `alg = "eddsa"` must not pass this gate only to be rejected by
        // the case-sensitive signature verifier.
        if !PRODUCTION_ALGORITHMS.contains(&self.alg.as_str()) {
            return Err(Error::Protocol(format!(
                "unsupported production proof algorithm: {}",
                self.alg
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

    pub fn validate_cross_domain_binding(&self, expected: &SignatureBindingPayload) -> Result<()> {
        self.validate_binding_with_requirements(expected, ProofBindingRequirements::cross_domain())
    }

    pub fn validate_binding_with_requirements(
        &self,
        expected: &SignatureBindingPayload,
        requirements: ProofBindingRequirements,
    ) -> Result<()> {
        self.validate()?;
        if self.verification_method != expected.verification_method {
            return Err(Error::Protocol(format!(
                "proof verification_method '{}' does not match expected '{}'",
                self.verification_method, expected.verification_method
            )));
        }
        if self.event_digest != expected.payload_digest {
            return Err(Error::Protocol(
                "proof event_digest does not match expected digest".to_owned(),
            ));
        }
        let diff = if self.created_at > expected.created_at {
            self.created_at - expected.created_at
        } else {
            expected.created_at - self.created_at
        };
        if diff > chrono::Duration::minutes(PROOF_CREATED_AT_HARD_SKEW_MINUTES) {
            return Err(Error::Protocol(format!(
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
            return Err(Error::Protocol(format!(
                "proof domain {:?} does not match expected {:?}",
                self.domain, expected.domain
            )));
        }
        if !proof_audience_covers_expected(self.audience.as_ref(), expected.audience.as_ref()) {
            return Err(Error::Protocol(format!(
                "proof audience {:?} does not match expected {:?}",
                self.audience, expected.audience
            )));
        }
        Ok(())
    }

    /// Validate that the proof's event_digest matches the canonical digest of a payload.
    pub fn validate_payload_digest(&self, payload: &impl Serialize) -> Result<()> {
        let computed = canonical::canonical_sha256(payload)?;
        let expected = Hash::new(computed)?;
        if self.event_digest != expected {
            return Err(Error::Protocol(format!(
                "proof event_digest '{}' does not match computed digest '{}'",
                self.event_digest, expected
            )));
        }
        Ok(())
    }
}

/// Server-verified fact-chain echo returned to clients after write admission.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FactChainEcho {
    pub echo_id: String,
    pub subject_ref: String,
    pub server_did: Did,
    pub operation_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_echo_hash: Option<Hash>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub observed_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proofs: Vec<Proof>,
}

impl FactChainEcho {
    /// Build the canonical payload signed by a server.
    pub fn digest_payload(&self) -> Result<Value> {
        let mut value = serde_json::to_value(self)?;
        if let Value::Object(map) = &mut value {
            map.remove("proofs");
        }
        Ok(value)
    }

    /// Compute the canonical digest for this echo.
    pub fn echo_digest(&self) -> Result<String> {
        Ok(canonical::canonical_sha256(&self.digest_payload()?)?)
    }

    /// Precheck server proof structure and echo digest binding.
    ///
    /// This does not verify detached JWS signatures because the wire layer
    /// deliberately has no DID/public-key resolver. Callers that need a
    /// trusted fact-chain echo must verify every proof with the signatures
    /// crate after this structural precheck.
    pub fn precheck_server_proofs(&self) -> Result<()> {
        if self.proofs.is_empty() {
            return Err(Error::Protocol(
                "fact-chain echo has no server proof".to_owned(),
            ));
        }
        let expected = Hash::new(self.echo_digest()?)?;
        for proof in &self.proofs {
            proof.validate_production()?;
            if proof.event_digest != expected {
                return Err(Error::Protocol(format!(
                    "fact-chain proof event_digest '{}' does not match echo digest '{}'",
                    proof.event_digest, expected
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureBindingPayload {
    pub payload_digest: Hash,
    pub actor_id: Did,
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
    use super::*;

    #[test]
    fn fact_chain_echo_validates_server_proof_binding() {
        let mut echo = FactChainEcho {
            echo_id: "echo1".to_owned(),
            subject_ref: "ak:event:01904100-0000-7000-8000-834e21b98552".to_owned(),
            server_did: Did::new("did:webvh:z6mkfixture:server.example").unwrap(),
            operation_hash: Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            commit_digest: Some(Hash::new(format!("sha256:{}", "2".repeat(64))).unwrap()),
            previous_echo_hash: None,
            observed_at: "2026-04-26T00:00:00.000Z".parse().unwrap(),
            proofs: Vec::new(),
        };
        let digest = Hash::new(echo.echo_digest().unwrap()).unwrap();
        echo.proofs.push(Proof {
            kind: "detached_jws".to_owned(),
            alg: "EdDSA".to_owned(),
            verification_method: DidUrl::new("did:webvh:z6mkfixture:server.example#key-1").unwrap(),
            event_digest: digest,
            created_at: echo.observed_at,
            domain: None,
            audience: None,
            proof_purpose: None,
            jws: "server.signature".to_owned(),
        });

        echo.precheck_server_proofs().unwrap();

        echo.proofs[0].event_digest = Hash::new(format!("sha256:{}", "3".repeat(64))).unwrap();
        assert!(echo.precheck_server_proofs().is_err());
    }
}
