//! Optional PostgreSQL persistence shared by every crate that binds a
//! validated Arkret newtype to a Postgres column.
//!
//! Diesel's `ToSql` / `FromSql` impls must live in the crate that owns the
//! type, so the identifier impls here and the `arkret-wire` impls for
//! `AccountId` / `ActorId` / `OpaqueLocalId` cannot be collapsed into a single
//! module — the orphan rule forbids it. What *is* shared is the boilerplate,
//! and it lives here: [`impl_sql_value!`](crate::impl_sql_value) and
//! [`impl_text_identifier_sql!`](crate::impl_text_identifier_sql) are exported
//! at the crate root and generate the local trait implementations for both
//! crates. No foreign-type derive or unused proxy is involved.

use std::error::Error;
use std::fmt;

use diesel::deserialize::{self, FromSql};
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{self, Output, ToSql};
use diesel::sql_types::Text;

use super::{DidCoreId, Hash, WebOrigin};

/// Implement Diesel expression and row traits for a locally owned value.
///
/// Generated identifier definitions need selective SQL mappings without adding
/// derives to every identifier kind. These are the ordinary local-type impls:
/// owned, borrowed and doubly borrowed expressions, with nullable counterparts.
/// Diesel's `foreign_derive` is unsuitable here: it also emits smart-pointer
/// impls intended for Diesel's own primitive types and violates coherence for
/// downstream local types. Callers can explicitly borrow a `Box`/`Rc`/`Arc`
/// inner value with `as_ref()` instead; this macro does not claim direct
/// smart-pointer expression support.
#[macro_export]
macro_rules! impl_sql_value {
    (@expression $value:ty, $sql_type:ty) => {
        impl ::diesel::expression::AsExpression<$sql_type> for $value {
            type Expression = ::diesel::internal::derives::as_expression::Bound<$sql_type, Self>;

            fn as_expression(self) -> Self::Expression {
                ::diesel::internal::derives::as_expression::Bound::new(self)
            }
        }

        impl ::diesel::expression::AsExpression<$sql_type> for &$value {
            type Expression = ::diesel::internal::derives::as_expression::Bound<$sql_type, Self>;

            fn as_expression(self) -> Self::Expression {
                ::diesel::internal::derives::as_expression::Bound::new(self)
            }
        }

        impl ::diesel::expression::AsExpression<$sql_type> for &&$value
        {
            type Expression = ::diesel::internal::derives::as_expression::Bound<$sql_type, Self>;

            fn as_expression(self) -> Self::Expression {
                ::diesel::internal::derives::as_expression::Bound::new(self)
            }
        }
    };
    ($value:ty, $sql_type:ty) => {
        $crate::impl_sql_value!(@expression $value, $sql_type);
        $crate::impl_sql_value!(@expression $value, ::diesel::sql_types::Nullable<$sql_type>);

        impl<__DB> ::diesel::serialize::ToSql<::diesel::sql_types::Nullable<$sql_type>, __DB>
            for $value
        where
            __DB: ::diesel::backend::Backend,
            Self: ::diesel::serialize::ToSql<$sql_type, __DB>,
        {
            fn to_sql<'b>(
                &'b self,
                out: &mut ::diesel::serialize::Output<'b, '_, __DB>,
            ) -> ::diesel::serialize::Result {
                <Self as ::diesel::serialize::ToSql<$sql_type, __DB>>::to_sql(self, out)
            }
        }

        impl<__ST, __DB> ::diesel::deserialize::Queryable<__ST, __DB> for $value
        where
            __DB: ::diesel::backend::Backend,
            __ST: ::diesel::sql_types::SingleValue,
            Self: ::diesel::deserialize::FromSql<__ST, __DB>,
        {
            type Row = Self;

            fn build(row: Self) -> ::diesel::deserialize::Result<Self> {
                Ok(row)
            }
        }
    };
}

/// Bind a validated text-backed newtype to a PostgreSQL `text` column.
///
/// Writes emit the already canonical string; reads pass back through the
/// type's own `new` constructor, so a malformed stored value is rejected by the
/// same authority that validates the wire form. The rejection carries only the
/// type name: echoing the offending column contents into an error string would
/// leak database rows into logs.
///
/// This emits only the `ToSql` / `FromSql` pair. A type whose own definition
/// cannot carry `AsExpression` / `FromSqlRow` needs
/// [`impl_sql_value!`](crate::impl_sql_value) alongside it.
#[macro_export]
macro_rules! impl_text_identifier_sql {
    ($identifier:ty, $kind:literal) => {
        impl ::diesel::serialize::ToSql<::diesel::sql_types::Text, ::diesel::pg::Pg>
            for $identifier
        {
            fn to_sql<'b>(
                &'b self,
                out: &mut ::diesel::serialize::Output<'b, '_, ::diesel::pg::Pg>,
            ) -> ::diesel::serialize::Result {
                <str as ::diesel::serialize::ToSql<
                                                                    ::diesel::sql_types::Text,
                                                                    ::diesel::pg::Pg,
                                                                >>::to_sql(self.as_str(), out)
            }
        }

        impl ::diesel::deserialize::FromSql<::diesel::sql_types::Text, ::diesel::pg::Pg>
            for $identifier
        {
            fn from_sql(value: ::diesel::pg::PgValue<'_>) -> ::diesel::deserialize::Result<Self> {
                let value = <String as ::diesel::deserialize::FromSql<
                    ::diesel::sql_types::Text,
                    ::diesel::pg::Pg,
                >>::from_sql(value)?;
                $crate::__parse_text_identifier(value, <$identifier>::new, $kind)
            }
        }
    };
}

impl ToSql<Text, Pg> for DidCoreId {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        <str as ToSql<Text, Pg>>::to_sql(self.as_str(), out)
    }
}

impl FromSql<Text, Pg> for DidCoreId {
    fn from_sql(value: PgValue<'_>) -> deserialize::Result<Self> {
        let value = <String as FromSql<Text, Pg>>::from_sql(value)?;
        parse_database_text(value)
    }
}

fn parse_database_text(value: String) -> deserialize::Result<DidCoreId> {
    parse_text_identifier(value, DidCoreId::new, "DidCoreId")
}

#[derive(Debug)]
struct InvalidDatabaseIdentifier(&'static str);

impl fmt::Display for InvalidDatabaseIdentifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "database text is not a valid {}", self.0)
    }
}

impl Error for InvalidDatabaseIdentifier {}

/// Macro support: re-exported at the crate root as `__parse_text_identifier`
/// only so [`impl_text_identifier_sql!`](crate::impl_text_identifier_sql)
/// expands in other crates. Not part of the stable surface.
pub fn parse_text_identifier<T, E>(
    value: String,
    parse: impl FnOnce(String) -> Result<T, E>,
    kind: &'static str,
) -> deserialize::Result<T> {
    parse(value)
        .map_err(|_| -> Box<dyn Error + Send + Sync> { Box::new(InvalidDatabaseIdentifier(kind)) })
}

// `Hash` comes out of the shared id_type definition, so it takes its diesel
// expression and row impls through the selective local implementation macro.
// `DidCoreId` and `WebOrigin` carry the derives on their own definitions.
crate::impl_sql_value!(Hash, ::diesel::sql_types::Text);

crate::impl_text_identifier_sql!(Hash, "Hash");
crate::impl_text_identifier_sql!(WebOrigin, "WebOrigin");

#[cfg(test)]
mod tests {
    use diesel::deserialize::{FromSqlRow, QueryableByName};
    use diesel::expression::AsExpression;
    use diesel::pg::Pg;
    use diesel::prelude::*;
    use diesel::sql_types::{Nullable, Text};

    use super::{DidCoreId, Hash, WebOrigin, parse_database_text, parse_text_identifier};

    diesel::table! {
        did_core_rows (core_id) {
            core_id -> Text,
            optional_core_id -> Nullable<Text>,
            hash -> Text,
            origin -> Text,
        }
    }

    #[derive(Queryable, Selectable, QueryableByName)]
    #[diesel(table_name = did_core_rows)]
    #[diesel(check_for_backend(Pg))]
    #[allow(dead_code)]
    struct DidCoreRow {
        core_id: DidCoreId,
        optional_core_id: Option<DidCoreId>,
        hash: Hash,
        origin: WebOrigin,
    }

    #[derive(Insertable)]
    #[diesel(table_name = did_core_rows)]
    struct NewDidCoreRow<'a> {
        core_id: &'a DidCoreId,
        optional_core_id: Option<&'a DidCoreId>,
        hash: &'a Hash,
        origin: &'a WebOrigin,
    }

    #[test]
    fn database_text_accepts_only_valid_did_core_ids() {
        let canonical = "ak:did_core:webvh:zQ3shExampleScid";
        let parsed = parse_database_text(canonical.to_owned()).unwrap();
        assert_eq!(parsed.as_str(), canonical);

        for invalid in [
            "",
            "did:webvh:zQ3shExampleScid:alice.example",
            "ak:did_core:",
            "ak:did_core:web:example.test/path",
            "ak:did_core:Web:example.test",
        ] {
            let error = parse_database_text(invalid.to_owned()).unwrap_err();
            assert_eq!(error.to_string(), "database text is not a valid DidCoreId");
            if !invalid.is_empty() {
                assert!(
                    !error.to_string().contains(invalid),
                    "the persistence error must not echo database contents"
                );
            }
        }
    }

    #[test]
    fn diesel_text_traits_cover_bind_select_query_by_name_and_option() {
        fn assert_from_sql_row<T>()
        where
            T: FromSqlRow<Text, Pg>,
        {
        }

        fn assert_nullable_from_sql_row<T>()
        where
            T: FromSqlRow<Nullable<Text>, Pg>,
        {
        }

        fn assert_text_expression<T>()
        where
            T: AsExpression<Text>,
        {
        }

        fn assert_nullable_text_expression<T>()
        where
            T: AsExpression<Nullable<Text>>,
        {
        }

        fn assert_queryable_by_name<T>()
        where
            T: QueryableByName<Pg>,
        {
        }

        assert_from_sql_row::<DidCoreId>();
        assert_from_sql_row::<Hash>();
        assert_from_sql_row::<WebOrigin>();
        assert_nullable_from_sql_row::<Option<DidCoreId>>();
        assert_nullable_from_sql_row::<Option<Hash>>();
        assert_text_expression::<DidCoreId>();
        assert_text_expression::<Hash>();
        assert_text_expression::<WebOrigin>();
        assert_text_expression::<&DidCoreId>();
        assert_text_expression::<&Hash>();
        assert_text_expression::<&&Hash>();
        assert_text_expression::<&WebOrigin>();
        assert_nullable_text_expression::<Hash>();
        assert_nullable_text_expression::<&Hash>();
        assert_nullable_text_expression::<&&Hash>();
        assert_nullable_text_expression::<Option<Hash>>();
        assert_nullable_text_expression::<Option<&Hash>>();
        assert_nullable_text_expression::<DidCoreId>();
        assert_nullable_text_expression::<&DidCoreId>();
        assert_nullable_text_expression::<Option<DidCoreId>>();
        assert_nullable_text_expression::<Option<&DidCoreId>>();
        assert_queryable_by_name::<DidCoreRow>();

        let core_id = DidCoreId::new("ak:did_core:web:peer-ps.example").unwrap();
        let hash = Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let origin = WebOrigin::new("https://example.test").unwrap();
        let insert = diesel::insert_into(did_core_rows::table).values(NewDidCoreRow {
            core_id: &core_id,
            optional_core_id: Some(&core_id),
            hash: &hash,
            origin: &origin,
        });
        let insert_sql = diesel::debug_query::<Pg, _>(&insert).to_string();
        assert!(insert_sql.contains("$1"));
        assert!(insert_sql.contains("$2"));
        assert!(insert_sql.contains("$3"));

        let select = did_core_rows::table
            .filter(did_core_rows::core_id.eq(&core_id))
            .select(DidCoreRow::as_select());
        let select_sql = diesel::debug_query::<Pg, _>(&select).to_string();
        assert!(select_sql.contains("WHERE"));
        assert!(select_sql.contains("$1"));
    }

    #[test]
    fn local_hash_expression_preserves_owned_and_nullable_query_bindings() {
        let hash = Hash::new(format!("sha256:{}", "b".repeat(64))).unwrap();
        let owned = did_core_rows::table.filter(did_core_rows::hash.eq(hash.clone()));
        assert!(
            diesel::debug_query::<Pg, _>(&owned)
                .to_string()
                .contains("$1")
        );
        let nullable = did_core_rows::table.filter(did_core_rows::hash.nullable().eq(Some(&hash)));
        assert!(
            diesel::debug_query::<Pg, _>(&nullable)
                .to_string()
                .contains("$1")
        );
        let boxed = Box::new(hash);
        let borrowed = did_core_rows::table.filter(did_core_rows::hash.eq(boxed.as_ref()));
        assert!(
            diesel::debug_query::<Pg, _>(&borrowed)
                .to_string()
                .contains("$1")
        );
    }

    #[test]
    fn database_text_validates_hashes() {
        let hash =
            parse_text_identifier(format!("sha256:{}", "a".repeat(64)), Hash::new, "Hash").unwrap();
        assert_eq!(hash.as_str(), format!("sha256:{}", "a".repeat(64)));

        let hash_error =
            parse_text_identifier("not-a-hash".to_owned(), Hash::new, "Hash").unwrap_err();
        assert_eq!(hash_error.to_string(), "database text is not a valid Hash");
    }
}
