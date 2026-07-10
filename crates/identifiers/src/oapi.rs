//! Salvo OpenAPI schema impls for Arkret identifier types.
//!
//! Each identifier is a `String` newtype that validates a specific prefix or
//! hex-encoded shape. We hand-implement [`ToSchema`] so the generated
//! component is a real string schema with the correct regex pattern, rather
//! than a derive-from-fields opaque object.

use salvo::oapi::{
    BasicType, Components, ComposeSchema, Object, RefOr, Schema, SchemaFormat, ToSchema,
};

use crate::{
    ActorProfileId, AgentInteropSessionId, AnnounceId, AppletId, AttestationId, AuditBindingId,
    AuditReleaseId, AuditSessionId, BackupId, BackupSeriesId, BatchId, BlobId, BlobRef, BlockId,
    CallId, CapabilityId, CellRef, ChunkId, CircleId, ClaimId, Cursor, DeviceId, DeviceMessageId,
    Did, EventId, FilterId, FrameId, FrankingProofId, GrantId, Hash, Hlc, InviteId, KeyEventId,
    MessageId, ModerationQueueItemId, MorphId, MoveId, NotificationId, OperationId, PolicyId,
    PresentationId, ReadCursorId, RealmId, ReceiptId, RecoverySessionId, RelationId, ReportId,
    RequestId, RtcParticipantId, SealId, SnapshotId, SpaceId, StrandId, TransactionId,
    TypedAppealId, TypedTrustDomainId, ViewId,
};

fn string_schema(pattern: &str) -> RefOr<Schema> {
    Object::new()
        .schema_type(BasicType::String)
        .pattern(pattern)
        .into()
}

macro_rules! impl_string_schema {
    ($ty:ty, $pattern:literal) => {
        impl ToSchema for $ty {
            fn to_schema(_components: &mut Components) -> RefOr<Schema> {
                string_schema($pattern)
            }
        }

        impl ComposeSchema for $ty {
            fn compose(
                components: &mut Components,
                _generics: Vec<RefOr<Schema>>,
            ) -> RefOr<Schema> {
                Self::to_schema(components)
            }
        }
    };
}

// Round 4 (2026-05-20, spec a77b995) — tightened DID scalar regex. Method
// name MUST be lowercase alpha + digits only (no `.`/`-`/`_`/`:`), and the
// method-specific-id contains no whitespace, query, or fragment marker.
impl_string_schema!(Did, r"^did:[a-z0-9]+:[^\s#?]+$");
impl_string_schema!(
    ActorProfileId,
    r"^ak:actor_profile:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    AgentInteropSessionId,
    r"^ak:agent_interop_session:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    AttestationId,
    r"^ak:attestation:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    AuditBindingId,
    r"^ak:audit_binding:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    AuditReleaseId,
    r"^ak:audit_release:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    AuditSessionId,
    r"^ak:audit_session:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    RtcParticipantId,
    r"^ak:rtc_participant:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    BackupSeriesId,
    r"^ak:backup_series:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    RecoverySessionId,
    r"^ak:recovery_session:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    AnnounceId,
    r"^ak:announce:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    AppletId,
    r"^ak:applet:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    BackupId,
    r"^ak:backup:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    BatchId,
    r"^ak:batch:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    BlobId,
    r"^ak:blob:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    BlockId,
    r"^ak:block:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    CallId,
    r"^ak:call:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    CapabilityId,
    r"^ak:capability:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    ChunkId,
    r"^ak:chunk:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    CircleId,
    r"^ak:circle:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    ClaimId,
    r"^ak:claim:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    DeviceMessageId,
    r"^ak:device_message:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    StrandId,
    r"^ak:strand:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    FilterId,
    r"^ak:filter:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    FrameId,
    r"^ak:frame:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    FrankingProofId,
    r"^ak:franking_proof:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    MorphId,
    r"^ak:morph:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    RealmId,
    r"^ak:realm:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    SpaceId,
    r"^ak:space:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    MessageId,
    r"^ak:message:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    RelationId,
    r"^ak:relation:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    EventId,
    r"^ak:event:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(OperationId, r"^(ak:operation:.+|sha256:[0-9a-f]{64})$");
impl_string_schema!(
    GrantId,
    r"^ak:grant:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    InviteId,
    r"^ak:invite:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    KeyEventId,
    r"^ak:key_event:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    DeviceId,
    r"^ak:device:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    NotificationId,
    r"^ak:notification:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    PolicyId,
    r"^ak:policy:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    PresentationId,
    r"^ak:presentation:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    ReceiptId,
    r"^ak:receipt:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    ReportId,
    r"^ak:report:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    ReadCursorId,
    r"^ak:read_cursor:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    ModerationQueueItemId,
    r"^ak:moderation_queue_item:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    RequestId,
    r"^ak:request:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    SnapshotId,
    r"^ak:snapshot:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    TransactionId,
    r"^ak:transaction:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    BlobRef,
    r"^(?:ak:blob:(?:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|sha256:[0-9a-f]{64})|sha256:[0-9a-f]{64})$"
);
impl_string_schema!(
    ViewId,
    r"^ak:view:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(Hash, r"^sha256:[0-9a-f]{64}$");
impl_string_schema!(Cursor, r"^ak:cursor:.+$");
// Seal frontier event_digest: bare `<algo>:<hex>` hash (spec e10b6ad
// dropped the `ak:move:` typed-id prefix). Same hex shape as `Hash` above.
impl_string_schema!(MoveId, r"^sha256:[0-9a-f]{64}$");
impl_string_schema!(SealId, r"^ak:seal:sha256:[0-9a-f]{64}$");
impl_string_schema!(
    CellRef,
    r"^ak:cell:ak\.component\.[a-z0-9_]+(?:\.[a-z0-9_]+)*\.v[0-9]+:[A-Za-z0-9._~=-]*(?::[A-Za-z0-9._~=-]+)*$"
);
impl_string_schema!(
    TypedAppealId,
    r"^ak:appeal:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    TypedTrustDomainId,
    r"^ak:trust_domain:[a-z0-9][a-z0-9._\-:]{0,127}$"
);

impl ToSchema for Hlc {
    fn to_schema(_components: &mut Components) -> RefOr<Schema> {
        Object::new()
            .schema_type(BasicType::String)
            .format(SchemaFormat::Custom("hlc".to_owned()))
            .pattern(r"^[0-9a-f]{12}-[0-9a-f]{8}-[0-9a-f]{8}$")
            .into()
    }
}

impl ComposeSchema for Hlc {
    fn compose(components: &mut Components, _generics: Vec<RefOr<Schema>>) -> RefOr<Schema> {
        Self::to_schema(components)
    }
}
