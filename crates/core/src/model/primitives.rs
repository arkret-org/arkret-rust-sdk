use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum HistoryVisibility {
    WorldReadable,
    Shared,
    Invited,
    Joined,
    Restricted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum FederationPolicy {
    Open,
    Restricted,
    Closed,
    Quarantine,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SecurityClass {
    Standard,
    HighAssurance,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum EncryptionProfile {
    None,
    MlsRfc9420,
    External,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    User,
    Org,
    Team,
    Agent,
    Service,
    Device,
    Integration,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ActorStatus {
    Active,
    Suspended,
    Deleted,
    Deactivated,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
    SummarizedFrom,
    PromotedFromDiscussion,
    AttachedTo,
    HasDefaultView,
    /// CXP-0007 (spec b7d35be) — couples a "wide synthesis" Flow (often
    /// Realm-default scope) to a "narrow discussion" Flow bound to a
    /// `scope_circle_id` Circle. The discussion side carries the confidential
    /// conversation; the synthesis side stays in the Realm scope. See
    /// zh/models/circle.md §7.2.
    ConfidentialDiscussionOf,
    /// CXP-0008 / CXP-0009 (spec head 37ce729) — links a sidecar Circle to
    /// its (controller, native agent) actor pair. Weak-semantic,
    /// non-structural, non-cascading: reducers and federation invariants
    /// MUST NOT drive lifecycle cascade through this relation.
    AgentSidecarOf,
    #[serde(untagged)]
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ViewVisibility {
    Private,
    Shared,
}

/// Lifecycle state for Flow / Morph (and other objects sharing this lattice).
///
/// Round C47 (spec e10b6ad): the `deleted` terminal state was dropped from
/// both `flow.schema.json` and `morph.schema.json`. Only `redacted` is a
/// terminal state now; `cx.flow.tombstone` / `cx.flow.delete` / equivalent
/// kinds collapse into a single `cx.redaction` event targeting the object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ObjectState {
    Active,
    Archived,
    Redacted,
}

/// Business progression stage shared by Flow and Morph objects.
///
/// This is distinct from physical lifecycle [`ObjectState`]. The stage
/// lattice is mutated only through the dedicated `cx.<object>.stage.set`
/// event family; create payloads must set an initial stage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PlaceState {
    Active,
    Archived,
    Tombstoned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RelationState {
    Active,
    Tombstoned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum PolicyEffect {
    Allow,
    Deny,
    Quarantine,
    RequireReview,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum InviteState {
    Pending,
    Accepted,
    Rejected,
    Revoked,
    Expired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum NotificationPriority {
    Low,
    Normal,
    High,
    Urgent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum NotificationState {
    Unread,
    Read,
    Dismissed,
    Archived,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ReadScopeKind {
    Realm,
    Flow,
    Thread,
    View,
    Message,
    Morph,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct ReadScope {
    pub kind: ReadScopeKind,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    pub object_ref: Option<String>,
    #[serde(rename = "track_name", skip_serializing_if = "Option::is_none")]
    pub track: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub track_scope: Option<ReadScopeTrackScope>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ReadScopeTrackScope {
    All,
}

impl ReadScope {
    pub fn realm() -> Self {
        Self { kind: ReadScopeKind::Realm, object_ref: None, track: None, track_scope: None }
    }

    pub fn flow(flow_id: impl Into<String>, track: Option<impl Into<String>>) -> Self {
        Self {
            kind: ReadScopeKind::Flow,
            object_ref: Some(flow_id.into()),
            track: track.map(Into::into),
            track_scope: None,
        }
    }

    pub fn flow_all(flow_id: impl Into<String>) -> Self {
        Self {
            kind: ReadScopeKind::Flow,
            object_ref: Some(flow_id.into()),
            track: None,
            track_scope: Some(ReadScopeTrackScope::All),
        }
    }

    pub fn thread(thread_id: impl Into<String>) -> Self {
        Self {
            kind: ReadScopeKind::Thread,
            object_ref: Some(thread_id.into()),
            track: None,
            track_scope: None,
        }
    }

    pub fn view(view_id: impl Into<String>) -> Self {
        Self {
            kind: ReadScopeKind::View,
            object_ref: Some(view_id.into()),
            track: None,
            track_scope: None,
        }
    }

    pub fn message(message_id: impl Into<String>) -> Self {
        Self {
            kind: ReadScopeKind::Message,
            object_ref: Some(message_id.into()),
            track: None,
            track_scope: None,
        }
    }

    pub fn morph(morph_id: impl Into<String>) -> Self {
        Self {
            kind: ReadScopeKind::Morph,
            object_ref: Some(morph_id.into()),
            track: None,
            track_scope: None,
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.kind == ReadScopeKind::Realm {
            if self.object_ref.is_some() {
                return Err(Error::Protocol(
                    "read_scope.ref must be omitted when kind is realm".to_owned(),
                ));
            }
            if self.track.is_some() || self.track_scope.is_some() {
                return Err(Error::Protocol(
                    "read_scope.track_name/track_scope must be omitted when kind is realm"
                        .to_owned(),
                ));
            }
        } else if self.object_ref.as_deref().unwrap_or("").trim().is_empty() {
            return Err(Error::Protocol(
                "read_scope.ref is required when kind is not realm".to_owned(),
            ));
        }

        match self.kind {
            ReadScopeKind::Flow => match (self.track.as_deref(), self.track_scope.as_ref()) {
                (Some(track), None) => validate_read_scope_track(track)?,
                (None, Some(ReadScopeTrackScope::All)) => {}
                (Some(_), Some(_)) => {
                    return Err(Error::Protocol(
                        "read_scope must not carry both track_name and track_scope".to_owned(),
                    ));
                }
                (None, None) => {
                    return Err(Error::Protocol(
                        "read_scope kind=flow requires track_name or track_scope=all".to_owned(),
                    ));
                }
            },
            _ if self.track.is_some() || self.track_scope.is_some() => {
                return Err(Error::Protocol(
                    "read_scope.track_name/track_scope is only valid when kind is flow".to_owned(),
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
        return Err(Error::Protocol("read_scope.track_name must not be empty".to_owned()));
    };
    if !first.is_ascii_lowercase() {
        return Err(Error::Protocol(format!("invalid read_scope.track_name '{track}'")));
    }
    if track.len() > 64
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(Error::Protocol(format!("invalid read_scope.track_name '{track}'")));
    }
    Ok(())
}

/// Account lifecycle states.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum OperationType {
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum SortDirection {
    Asc,
    Desc,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum NullsOrder {
    First,
    Last,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RelationDirection {
    Out,
    In,
    Both,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub kind: String,
    pub alg: String,
    pub verification_method: String,
    pub payload_digest: Hash,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
    pub jws: String,
}

/// Canonical proof kind constants.
pub mod proof_kind {
    /// Standard actor / device / service signature over canonical event bytes.
    pub const DETACHED_JWS: &str = "detached_jws";
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct CriticalExtension {
    pub id: String,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema_ref: Option<String>,
    pub fail_closed: bool,
}

/// Allowed proof algorithms for production use.
const PRODUCTION_ALGORITHMS: &[&str] = &["EdDSA", "ES256", "ES256K", "RS256", "PS256"];

/// Proof kinds that indicate development/test mode and are rejected in production.
const DEV_PROOF_KINDS: &[&str] = &["dev", "test", "mock", "stub", "dummy"];

impl Proof {
    pub fn binding_payload(&self, actor_id: &Did) -> SignatureBindingPayload {
        SignatureBindingPayload {
            payload_digest: self.payload_digest.clone(),
            actor_id: actor_id.clone(),
            verification_method: self.verification_method.clone(),
            created_at: self.created_at,
            domain: self.domain.clone(),
            audience: self.audience.clone(),
        }
    }

    /// Validate proof structural requirements.
    ///
    /// Rejects `alg:none`, empty verification methods, empty JWS, and
    /// empty kind.
    pub fn validate(&self) -> Result<()> {
        if self.alg.eq_ignore_ascii_case("none") {
            return Err(Error::Protocol("proof algorithm 'none' is not allowed".to_owned()));
        }
        if self.alg.is_empty() {
            return Err(Error::Protocol("proof algorithm must not be empty".to_owned()));
        }
        if self.verification_method.is_empty() {
            return Err(Error::Protocol("proof verification_method must not be empty".to_owned()));
        }
        if self.jws.is_empty() {
            return Err(Error::Protocol("proof JWS must not be empty".to_owned()));
        }
        if self.kind.is_empty() {
            return Err(Error::Protocol("proof kind must not be empty".to_owned()));
        }
        Ok(())
    }

    /// Validate that this proof uses a production-grade algorithm and kind.
    ///
    /// Rejects `alg:none`, unknown algorithms, and dev/test proof kinds.
    pub fn validate_production(&self) -> Result<()> {
        self.validate()?;
        if DEV_PROOF_KINDS.iter().any(|k| self.kind.eq_ignore_ascii_case(k)) {
            return Err(Error::Protocol(format!(
                "production proofs must not use dev/test kind: {}",
                self.kind
            )));
        }
        if !PRODUCTION_ALGORITHMS.iter().any(|a| self.alg.eq_ignore_ascii_case(a)) {
            return Err(Error::Protocol(format!(
                "unsupported production proof algorithm: {}",
                self.alg
            )));
        }
        Ok(())
    }

    /// Validate that the proof's structural fields match the expected binding.
    ///
    /// Checks: verification_method, payload_digest, created_at (within tolerance),
    /// domain, and audience.
    pub fn validate_binding(&self, expected: &SignatureBindingPayload) -> Result<()> {
        self.validate()?;
        if self.verification_method != expected.verification_method {
            return Err(Error::Protocol(format!(
                "proof verification_method '{}' does not match expected '{}'",
                self.verification_method, expected.verification_method
            )));
        }
        if self.payload_digest != expected.payload_digest {
            return Err(Error::Protocol(
                "proof payload_digest does not match expected digest".to_owned(),
            ));
        }
        // Allow 5-minute clock skew tolerance for created_at
        let diff = if self.created_at > expected.created_at {
            self.created_at - expected.created_at
        } else {
            expected.created_at - self.created_at
        };
        if diff.num_minutes() > 5 {
            return Err(Error::Protocol(format!(
                "proof created_at differs from expected by {} minutes (max 5)",
                diff.num_minutes()
            )));
        }
        if self.domain != expected.domain {
            return Err(Error::Protocol(format!(
                "proof domain {:?} does not match expected {:?}",
                self.domain, expected.domain
            )));
        }
        if self.audience != expected.audience {
            return Err(Error::Protocol(format!(
                "proof audience {:?} does not match expected {:?}",
                self.audience, expected.audience
            )));
        }
        Ok(())
    }

    /// Validate that the proof's payload_digest matches the canonical digest of a payload.
    pub fn validate_payload_digest(&self, payload: &impl Serialize) -> Result<()> {
        let computed = canonical::canonical_sha256(payload)?;
        let expected = Hash::new(computed)?;
        if self.payload_digest != expected {
            return Err(Error::Protocol(format!(
                "proof payload_digest '{}' does not match computed digest '{}'",
                self.payload_digest, expected
            )));
        }
        Ok(())
    }
}

/// Server-verified fact-chain echo returned to clients after write admission.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct FactChainEcho {
    pub echo_id: String,
    pub subject_ref: String,
    pub server_did: Did,
    pub operation_hash: Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_digest: Option<Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_echo_hash: Option<Hash>,
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
        canonical::canonical_sha256(&self.digest_payload()?)
    }

    /// Validate server proofs against this echo's digest.
    pub fn validate_server_proofs(&self) -> Result<()> {
        if self.proofs.is_empty() {
            return Err(Error::Protocol("fact-chain echo has no server proof".to_owned()));
        }
        let expected = Hash::new(self.echo_digest()?)?;
        for proof in &self.proofs {
            proof.validate_production()?;
            if proof.payload_digest != expected {
                return Err(Error::Protocol(format!(
                    "fact-chain proof payload_digest '{}' does not match echo digest '{}'",
                    proof.payload_digest, expected
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "salvo", derive(salvo::oapi::ToSchema))]
pub struct SignatureBindingPayload {
    pub payload_digest: Hash,
    pub actor_id: Did,
    pub verification_method: String,
    pub created_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<Audience>,
}
