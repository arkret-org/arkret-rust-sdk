//! Salvo OpenAPI schema impls for Cokret identifier types.
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
    r"^ck:actor_profile:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    AgentInteropSessionId,
    r"^ck:agent_interop_session:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    AttestationId,
    r"^ck:attestation:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    AuditBindingId,
    r"^ck:audit_binding:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    AuditReleaseId,
    r"^ck:audit_release:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    AuditSessionId,
    r"^ck:audit_session:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    RtcParticipantId,
    r"^ck:rtc_participant:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    BackupSeriesId,
    r"^ck:backup_series:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    RecoverySessionId,
    r"^ck:recovery_session:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    AnnounceId,
    r"^ck:announce:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    AppletId,
    r"^ck:applet:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    BackupId,
    r"^ck:backup:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    BatchId,
    r"^ck:batch:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    BlobId,
    r"^ck:blob:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    BlockId,
    r"^ck:block:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    CallId,
    r"^ck:call:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    CapabilityId,
    r"^ck:capability:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    ChunkId,
    r"^ck:chunk:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    CircleId,
    r"^ck:circle:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    ClaimId,
    r"^ck:claim:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    DeviceMessageId,
    r"^ck:device_message:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    StrandId,
    r"^ck:strand:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    FilterId,
    r"^ck:filter:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    FrameId,
    r"^ck:frame:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    FrankingProofId,
    r"^ck:franking_proof:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    MorphId,
    r"^ck:morph:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    RealmId,
    r"^ck:realm:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    SpaceId,
    r"^ck:space:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    MessageId,
    r"^ck:message:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    RelationId,
    r"^ck:relation:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    EventId,
    r"^ck:event:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    OperationId,
    r"^(ck:operation:.+|(?:sha256|blake3):[0-9a-f]{64})$"
);
impl_string_schema!(
    GrantId,
    r"^ck:grant:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    InviteId,
    r"^ck:invite:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    KeyEventId,
    r"^ck:key_event:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    DeviceId,
    r"^ck:device:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    NotificationId,
    r"^ck:notification:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    PolicyId,
    r"^ck:policy:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    PresentationId,
    r"^ck:presentation:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    ReceiptId,
    r"^ck:receipt:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    ReportId,
    r"^ck:report:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    ReadCursorId,
    r"^ck:read_cursor:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    ModerationQueueItemId,
    r"^ck:moderation_queue_item:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    RequestId,
    r"^ck:request:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    SnapshotId,
    r"^ck:snapshot:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    TransactionId,
    r"^ck:transaction:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    BlobRef,
    r"^(?:ck:blob:(?:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|(?:sha256|blake3):[0-9a-f]{64})|(?:sha256|blake3):[0-9a-f]{64})$"
);
impl_string_schema!(
    ViewId,
    r"^ck:view:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(Hash, r"^(?:sha256|blake3):[0-9a-f]{64}$");
impl_string_schema!(Cursor, r"^ck:cursor:.+$");
// Seal frontier event_digest: bare `<algo>:<hex>` hash (spec e10b6ad
// dropped the `ck:move:` typed-id prefix). Same hex shape as `Hash` above.
impl_string_schema!(MoveId, r"^(?:sha256|blake3):[0-9a-f]{64}$");
impl_string_schema!(SealId, r"^ck:seal:(?:sha256|blake3):[0-9a-f]{64}$");
impl_string_schema!(
    CellRef,
    r"^ck:cell:[A-Za-z0-9._~=-]+(?::[A-Za-z0-9._~=-]+)*$"
);
impl_string_schema!(
    TypedAppealId,
    r"^ck:appeal:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    TypedTrustDomainId,
    r"^ck:trust_domain:[a-z0-9][a-z0-9._\-:]{0,127}$"
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
