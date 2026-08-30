use std::fmt;
use std::str::FromStr;

use super::*;
use crate::{Did, DidCoreId, ProofContextId, SignerEvidenceRef};

/// Complete protocol identity for one account at one Station.
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

/// Complete identity for an Event author, Realm member, or durable byline.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ActorId {
    Account {
        account_id: AccountId,
    },
    HostedPrincipal {
        principal_id: DidCoreId,
        station_id: DidCoreId,
    },
    Service {
        service_id: DidCoreId,
    },
}

impl ActorId {
    pub fn account(account_id: AccountId) -> Self {
        Self::Account { account_id }
    }

    pub fn hosted_principal(principal_id: DidCoreId, station_id: DidCoreId) -> Self {
        Self::HostedPrincipal {
            principal_id,
            station_id,
        }
    }

    pub fn service(service_id: DidCoreId) -> Self {
        Self::Service { service_id }
    }

    pub fn signing_principal_id(&self) -> &DidCoreId {
        match self {
            Self::Account { account_id } => &account_id.principal_id,
            Self::HostedPrincipal { principal_id, .. } => principal_id,
            Self::Service { service_id } => service_id,
        }
    }

    pub fn route_service_id(&self) -> &DidCoreId {
        match self {
            Self::Account { account_id } => &account_id.station_id,
            Self::HostedPrincipal { station_id, .. } => station_id,
            Self::Service { service_id } => service_id,
        }
    }

    pub fn as_account_id(&self) -> Option<&AccountId> {
        match self {
            Self::Account { account_id } => Some(account_id),
            Self::HostedPrincipal { .. } | Self::Service { .. } => None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Account { account_id } => account_id.validate(),
            Self::HostedPrincipal {
                principal_id,
                station_id,
            } if principal_id.as_str().is_empty() || station_id.as_str().is_empty() => {
                Err(WireError::Protocol(
                    "hosted principal actor id components must be non-empty".to_owned(),
                ))
            }
            Self::Service { service_id } if service_id.as_str().is_empty() => Err(
                WireError::Protocol("service actor id must be non-empty".to_owned()),
            ),
            Self::HostedPrincipal { .. } | Self::Service { .. } => Ok(()),
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

/// MLS-backed content envelope scheme, frozen by the accepted MLS group
/// Genesis.
///
/// `models/realm-and-space.md` section 2.3 and `models/circle.md` section 2 both
/// make this a closed two-value union that applies exactly when
/// `encryption_profile = mls_rfc9420`. `mls_rfc9420` uses MLS PrivateMessage and
/// produces no deliverable history secret, so it pins `history_access` to
/// `since_join`; `mls_exporter_aead_v1` derives a per-epoch `history_secret` and
/// admits either state. It is immutable for the lifetime of the derived
/// `mls_group_id`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum ContentScheme {
    MlsRfc9420,
    MlsExporterAeadV1,
}

impl ContentScheme {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MlsRfc9420 => "mls_rfc9420",
            Self::MlsExporterAeadV1 => "mls_exporter_aead_v1",
        }
    }
}

impl FromStr for ContentScheme {
    type Err = ContentSchemeParseError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "mls_rfc9420" => Ok(Self::MlsRfc9420),
            "mls_exporter_aead_v1" => Ok(Self::MlsExporterAeadV1),
            _ => Err(ContentSchemeParseError),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContentSchemeParseError;

impl fmt::Display for ContentSchemeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("content_scheme is unregistered")
    }
}

impl std::error::Error for ContentSchemeParseError {}

/// Realm Recovery Key (RRK) persistence policy, frozen together with
/// [`ContentScheme`] by the accepted MLS group Genesis.
///
/// `models/realm-and-space.md` section 2.3.1 makes this a required closed
/// two-value string on an exporter effective scope and forbids it on every
/// other scheme. Custody topology — replica count, HSM, Shamir, threshold —
/// never reaches the Realm or Circle wire, so this carries no recipient or
/// threshold structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum DurabilityPolicy {
    None,
    OrganizationRecoveryKey,
}

impl DurabilityPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::OrganizationRecoveryKey => "organization_recovery_key",
        }
    }
}

impl FromStr for DurabilityPolicy {
    type Err = DurabilityPolicyParseError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "none" => Ok(Self::None),
            "organization_recovery_key" => Ok(Self::OrganizationRecoveryKey),
            _ => Err(DurabilityPolicyParseError),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DurabilityPolicyParseError;

impl fmt::Display for DurabilityPolicyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("durability_policy is unregistered")
    }
}

impl std::error::Error for DurabilityPolicyParseError {}

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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    // retainable per-epoch `history_secret` (MLS exporter) instead of the
    // forward-secret message ratchet, so an authorized current member can
    // receive encrypted history keys through the history-key protocol.
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
    WireError::Protocol(format!(
        "{}: proof {field} is required",
        ReasonCode::PROOF_BINDING_MISSING
    ))
}

fn require_proof_domain(proof: Option<&str>, expected: Option<&str>) -> Result<()> {
    if proof.map(str::trim).map(str::is_empty).unwrap_or(true) {
        return Err(proof_binding_missing("domain"));
    }
    if expected.map(str::trim).map(str::is_empty).unwrap_or(true) {
        return Err(WireError::Protocol(format!(
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
        return Err(WireError::Protocol(format!(
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
pub struct ProducerEventProof {
    pub kind: String,
    pub verification_method: DidUrl,
    pub event_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_resolution_evidence_ref: Option<SignerEvidenceRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_resolution_evidence_digest: Option<Hash>,
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
        if self.jws.is_empty() {
            return Err(WireError::Protocol(
                "proof JWS must not be empty".to_owned(),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum StationAdmissionProofKind {
    #[serde(rename = "station_admission")]
    StationAdmission,
}

/// Origin Station attestation over the exact producer proof it admitted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct StationAdmissionProof {
    pub kind: StationAdmissionProofKind,
    pub verification_method: DidUrl,
    pub event_digest: Hash,
    pub producer_proof_digest: Hash,
    pub producer_verification_method: DidUrl,
    pub producer_signing_key_did: DidKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_signer_resolution_evidence_ref: Option<SignerEvidenceRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub producer_signer_resolution_evidence_digest: Option<Hash>,
    pub signer_resolution_evidence_ref: SignerEvidenceRef,
    pub signer_resolution_evidence_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub accepted_at: DateTime<Utc>,
    pub jws: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[serde(untagged)]
pub enum EventProof {
    Producer(ProducerEventProof),
    StationAdmission(StationAdmissionProof),
}

impl EventProof {
    pub fn as_producer(&self) -> Option<&ProducerEventProof> {
        match self {
            Self::Producer(proof) => Some(proof),
            Self::StationAdmission(_) => None,
        }
    }

    pub fn as_producer_mut(&mut self) -> Option<&mut ProducerEventProof> {
        match self {
            Self::Producer(proof) => Some(proof),
            Self::StationAdmission(_) => None,
        }
    }

    pub fn as_station_admission(&self) -> Option<&StationAdmissionProof> {
        match self {
            Self::Producer(_) => None,
            Self::StationAdmission(proof) => Some(proof),
        }
    }
}

impl From<ProducerEventProof> for EventProof {
    fn from(value: ProducerEventProof) -> Self {
        Self::Producer(value)
    }
}

impl From<StationAdmissionProof> for EventProof {
    fn from(value: StationAdmissionProof) -> Self {
        Self::StationAdmission(value)
    }
}

pub const STATION_ADMISSION_PROOF_CONTEXT: &str = crate::ProofContextId::STATION_ADMISSION_PROOF_V1;

impl StationAdmissionProof {
    pub fn producer_proof_digest(proof: &ProducerEventProof) -> Result<Hash> {
        Hash::new(canonical::canonical_sha256(proof)?).map_err(Into::into)
    }

    pub fn validate_binding(
        &self,
        expected_event_digest: &Hash,
        producer_proof: &ProducerEventProof,
        expected_station_id: &DidCoreId,
    ) -> Result<()> {
        let (controller, fragment) = self
            .verification_method
            .as_str()
            .split_once('#')
            .ok_or_else(|| {
                WireError::Protocol("admission verification method has no fragment".to_owned())
            })?;
        let controller = Did::new(controller.to_owned())?;
        let producer_evidence_pair_valid = match (
            &self.producer_signer_resolution_evidence_ref,
            &self.producer_signer_resolution_evidence_digest,
        ) {
            (None, None) => true,
            (Some(reference), Some(digest)) => {
                reference
                    .content_digest()
                    .is_ok_and(|value| value == *digest)
                    && digest.as_ref().starts_with("sha256:")
            }
            _ => false,
        };
        if fragment.is_empty()
            || project_did_to_core_id(&controller)? != *expected_station_id
            || self.event_digest != *expected_event_digest
            || self.producer_proof_digest != Self::producer_proof_digest(producer_proof)?
            || self.producer_verification_method != producer_proof.verification_method
            || !producer_evidence_pair_valid
            || self.signer_resolution_evidence_ref.content_digest()?
                != self.signer_resolution_evidence_digest
            || !self
                .signer_resolution_evidence_digest
                .as_ref()
                .starts_with("sha256:")
            || !is_compact_jws(&self.jws)
        {
            return Err(WireError::Protocol(
                "Station admission proof binding mismatch".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn canonical_binding_bytes(&self) -> Result<Vec<u8>> {
        let mut binding = serde_json::Map::new();
        binding.insert(
            "context".to_owned(),
            Value::String(STATION_ADMISSION_PROOF_CONTEXT.to_owned()),
        );
        binding.insert(
            "verification_method".to_owned(),
            serde_json::to_value(&self.verification_method)?,
        );
        binding.insert(
            "event_digest".to_owned(),
            serde_json::to_value(&self.event_digest)?,
        );
        binding.insert(
            "producer_proof_digest".to_owned(),
            serde_json::to_value(&self.producer_proof_digest)?,
        );
        binding.insert(
            "producer_verification_method".to_owned(),
            serde_json::to_value(&self.producer_verification_method)?,
        );
        binding.insert(
            "producer_signing_key_did".to_owned(),
            serde_json::to_value(&self.producer_signing_key_did)?,
        );
        if let Some(reference) = &self.producer_signer_resolution_evidence_ref {
            binding.insert(
                "producer_signer_resolution_evidence_ref".to_owned(),
                serde_json::to_value(reference)?,
            );
        }
        if let Some(digest) = &self.producer_signer_resolution_evidence_digest {
            binding.insert(
                "producer_signer_resolution_evidence_digest".to_owned(),
                serde_json::to_value(digest)?,
            );
        }
        binding.insert(
            "signer_resolution_evidence_ref".to_owned(),
            serde_json::to_value(&self.signer_resolution_evidence_ref)?,
        );
        binding.insert(
            "signer_resolution_evidence_digest".to_owned(),
            serde_json::to_value(&self.signer_resolution_evidence_digest)?,
        );
        binding.insert(
            "accepted_at".to_owned(),
            Value::String(canonical::format_timestamp_canonical(self.accepted_at)),
        );
        canonical::canonical_json_bytes(&Value::Object(binding)).map_err(Into::into)
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
    pub fn validate_signer_resolution_evidence_pair(&self) -> Result<()> {
        match (
            &self.signer_resolution_evidence_ref,
            &self.signer_resolution_evidence_digest,
        ) {
            (None, None) => Ok(()),
            (Some(reference), Some(digest))
                if reference.content_digest()? == *digest
                    && digest.as_ref().starts_with("sha256:") =>
            {
                Ok(())
            }
            _ => Err(WireError::Protocol(
                "producer signer resolution evidence ref and digest must be absent together or match"
                    .to_owned(),
            )),
        }
    }

    pub fn validate_direct_signer_resolution_evidence(&self) -> Result<()> {
        self.validate_signer_resolution_evidence_pair()?;
        if self.signer_resolution_evidence_ref.is_none() {
            return Err(WireError::Protocol(
                "direct producer proof requires signer resolution evidence".to_owned(),
            ));
        }
        Ok(())
    }

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
    /// signer_resolution_evidence_ref?, signer_resolution_evidence_digest?,
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
        if let Some(reference) = &self.signer_resolution_evidence_ref {
            obj.insert(
                "signer_resolution_evidence_ref".to_owned(),
                Value::String(reference.as_ref().to_owned()),
            );
        }
        if let Some(digest) = &self.signer_resolution_evidence_digest {
            obj.insert(
                "signer_resolution_evidence_digest".to_owned(),
                Value::String(digest.as_str().to_owned()),
            );
        }
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
        if !is_compact_jws(&self.jws) {
            return Err(WireError::Protocol(
                "proof JWS is not compact JWS".to_owned(),
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
        self.validate_signer_resolution_evidence_pair()?;
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

fn is_compact_jws(value: &str) -> bool {
    let mut segments = value.split('.');
    let protected = segments.next().unwrap_or_default();
    let _payload = segments.next().unwrap_or_default();
    let signature = segments.next().unwrap_or_default();
    !protected.is_empty()
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
