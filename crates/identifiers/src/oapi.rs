//! Salvo OpenAPI schema impls for Contrix identifier types.
//!
//! Each identifier is a `String` newtype that validates a specific prefix or
//! hex-encoded shape. We hand-implement [`ToSchema`] so the generated
//! component is a real string schema with the correct regex pattern, rather
//! than a derive-from-fields opaque object.

use salvo::oapi::{
    BasicType, Components, ComposeSchema, Object, RefOr, Schema, SchemaFormat, ToSchema,
};

use crate::{
    ActorProfileId, AgentSessionId, AnchorId, AppletId, BackupId, BatchId, BlobId, BlobRef,
    BlockId, CallId, CapabilityId, CellRef, ChunkId, ClaimId, Cursor, DeviceId, DevmsgId, Did,
    EventId, FilterId, FlowId, FrameId, FrankId, GrantId, Hash, Hlc, InviteId, KeyevtId, MessageId,
    ModqId, MorphId, MoveId, NotifId, OperationId, PlaceId, RealmId, PolicyId, PresentationId,
    ReceiptId,
    RelationId, ReportId, ReqId, SnapshotId, SpaceId, TxnId, TypedAppealId, TypedTrustDomainId,
    ViewId,
};

fn string_schema(pattern: &str) -> RefOr<Schema> {
    Object::new().schema_type(BasicType::String).pattern(pattern).into()
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

// Round 4 (2026-05-20, spec a77b995) — tightened DID regex. Method name
// MUST be lowercase alpha + digits only (no `.`/`-`/`_`/`:`), and the
// method-specific-id is `[^\s]+` (no whitespace).
impl_string_schema!(Did, r"^did:[a-z0-9]+:[^\s]+$");
impl_string_schema!(
    ActorProfileId,
    r"^cx:actor_profile:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    AgentSessionId,
    r"^cx:agent_session:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    AppletId,
    r"^cx:applet:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    SpaceId,
    r"^cx:space:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    BackupId,
    r"^cx:backup:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    BatchId,
    r"^cx:batch:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    BlobId,
    r"^cx:blob:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    BlockId,
    r"^cx:block:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    CallId,
    r"^cx:call:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    CapabilityId,
    r"^cx:capability:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    ChunkId,
    r"^cx:chunk:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    ClaimId,
    r"^cx:claim:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    DevmsgId,
    r"^cx:devmsg:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    FlowId,
    r"^cx:flow:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    FilterId,
    r"^cx:filter:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    FrameId,
    r"^cx:frame:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    FrankId,
    r"^cx:frank:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    MorphId,
    r"^cx:morph:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    RealmId,
    r"^cx:realm:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
// TODO(realm-rework): drop PlaceId once container migration to SpaceId
// is complete.
impl_string_schema!(
    PlaceId,
    r"^cx:place:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    MessageId,
    r"^cx:message:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    RelationId,
    r"^cx:relation:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    EventId,
    r"^cx:event:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    OperationId,
    r"^(cx:operation:.+|(?:sha256|sha3_256|blake3):[0-9a-f]{64}|sha512:[0-9a-f]{128})$"
);
impl_string_schema!(
    GrantId,
    r"^cx:grant:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    InviteId,
    r"^cx:invite:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    KeyevtId,
    r"^cx:keyevt:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    DeviceId,
    r"^cx:device:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    NotifId,
    r"^cx:notif:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    PolicyId,
    r"^cx:policy:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    PresentationId,
    r"^cx:presentation:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    ReceiptId,
    r"^cx:receipt:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    ReportId,
    r"^cx:report:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    ModqId,
    r"^cx:modq:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    ReqId,
    r"^cx:req:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    SnapshotId,
    r"^cx:snapshot:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    TxnId,
    r"^cx:txn:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(
    BlobRef,
    r"^(?:cx:blob:(?:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|(?:sha256|sha3_256|blake3):[0-9a-f]{64}|sha512:[0-9a-f]{128})|(?:sha256|sha3_256|blake3):[0-9a-f]{64}|sha512:[0-9a-f]{128})$"
);
impl_string_schema!(
    ViewId,
    r"^cx:view:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(Hash, r"^(?:sha256|sha3_256|blake3):[0-9a-f]{64}$|^sha512:[0-9a-f]{128}$");
impl_string_schema!(Cursor, r"^cx:cursor:.+$");
// Anchor frontier event_digest: bare `<algo>:<hex>` hash (spec e10b6ad
// dropped the `cx:move:` typed-id prefix). Same hex shape as `Hash` above.
impl_string_schema!(MoveId, r"^(?:sha256|sha3_256|blake3):[0-9a-f]{64}$|^sha512:[0-9a-f]{128}$");
impl_string_schema!(
    AnchorId,
    r"^cx:anchor:(?:(?:sha256|sha3_256|blake3):[0-9a-f]{64}|sha512:[0-9a-f]{128})$"
);
impl_string_schema!(CellRef, r"^cx:cell:[A-Za-z0-9._~=-]+(?::[A-Za-z0-9._~=-]+)*$");
impl_string_schema!(
    TypedAppealId,
    r"^cx:appeal:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
);
impl_string_schema!(TypedTrustDomainId, r"^cx:trust_domain:[a-z0-9][a-z0-9._\-:]{0,127}$");

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
