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
    BlobRef, CommitId, Cursor, DeviceId, Did, EntityId, EventId, FlowId, GrantId, Hash, Hlc,
    InviteId, OperationId, PolicyId, RelationId, SpaceId, ViewId,
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

impl_string_schema!(Did, r"^did:[a-z0-9]+:.+$");
impl_string_schema!(SpaceId, r"^cx:space:.+$");
impl_string_schema!(FlowId, r"^cx:flow:.+$");
impl_string_schema!(EntityId, r"^cx:entity:.+$");
impl_string_schema!(RelationId, r"^cx:relation:.+$");
impl_string_schema!(EventId, r"^(cx:event:.+|sha256:[0-9a-f]{64})$");
impl_string_schema!(CommitId, r"^cx:commit:.+$");
impl_string_schema!(OperationId, r"^(cx:operation:.+|sha256:[0-9a-f]{64})$");
impl_string_schema!(GrantId, r"^cx:grant:.+$");
impl_string_schema!(InviteId, r"^cx:invite:.+$");
impl_string_schema!(DeviceId, r"^(dev_.+|cx:device:.+)$");
impl_string_schema!(PolicyId, r"^cx:policy:.+$");
impl_string_schema!(BlobRef, r"^(cx:blob:.+|sha256:[0-9a-f]{64})$");
impl_string_schema!(ViewId, r"^cx:view:.+$");
impl_string_schema!(Hash, r"^sha256:[0-9a-f]{64}$");
impl_string_schema!(Cursor, r"^cx:cursor:.+$");

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
