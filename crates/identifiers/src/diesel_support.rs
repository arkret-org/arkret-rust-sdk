//! Optional PostgreSQL persistence shared by every crate that binds a
//! validated Arkret newtype to a Postgres column.
//!
//! Diesel's `ToSql` / `FromSql` impls must live in the crate that owns the
//! type, so the identifier impls here and the `arkret-wire` impls for
//! `AccountId` / `ActorId` / `OpaqueLocalId` cannot be collapsed into a single
//! module — the orphan rule forbids it. What *is* shared is the boilerplate,
//! and it lives here: [`diesel_foreign_sql_proxy!`](crate::diesel_foreign_sql_proxy)
//! and [`impl_text_identifier_sql!`](crate::impl_text_identifier_sql) are
//! exported at the crate root and generate it for both crates, so the
//! `foreign_derive` proxy pattern — and its unavoidable dead-code exemption —
//! is written exactly once.

use std::error::Error;
use std::fmt;

use diesel::deserialize::{self, FromSql};
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{self, Output, ToSql};
use diesel::sql_types::Text;

use super::{CellRef, DidCoreId, Hash, WebOrigin};

/// Emit diesel's `AsExpression` / `FromSqlRow` impls for a type whose
/// definition cannot carry the derives directly.
///
/// Identifier kinds produced by `declare_special_form_id_kinds!` share one
/// generated definition, so attaching `#[diesel(sql_type = ...)]` there would
/// silently give a Postgres mapping to every kind in the group. Diesel's
/// `foreign_derive` escape hatch instead reads the field type off a local proxy
/// struct that is never constructed — hence the dead-code exemption, which
/// belongs here once rather than at each call site.
#[macro_export]
macro_rules! diesel_foreign_sql_proxy {
    ($proxy:ident, $identifier:ty, $sql_type:ty) => {
        #[derive(::diesel::expression::AsExpression, ::diesel::deserialize::FromSqlRow)]
        #[diesel(foreign_derive)]
        #[diesel(sql_type = $sql_type)]
        #[allow(dead_code)]
        struct $proxy($identifier);
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
/// [`diesel_foreign_sql_proxy!`](crate::diesel_foreign_sql_proxy) alongside it.
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

// `CellRef` and `Hash` come out of the shared special-form / id_type
// definitions, so they take their diesel expression impls through a proxy.
// `DidCoreId` and `WebOrigin` carry the derives on their own definitions.
crate::diesel_foreign_sql_proxy!(CellRefDieselProxy, CellRef, ::diesel::sql_types::Text);
crate::diesel_foreign_sql_proxy!(HashDieselProxy, Hash, ::diesel::sql_types::Text);

crate::impl_text_identifier_sql!(CellRef, "CellRef");
crate::impl_text_identifier_sql!(Hash, "Hash");
crate::impl_text_identifier_sql!(WebOrigin, "WebOrigin");

#[cfg(test)]
mod tests {
    use diesel::deserialize::{FromSqlRow, QueryableByName};
    use diesel::expression::AsExpression;
    use diesel::pg::Pg;
    use diesel::prelude::*;
    use diesel::sql_types::{Nullable, Text};

    use super::{CellRef, DidCoreId, Hash, WebOrigin, parse_database_text, parse_text_identifier};

    diesel::table! {
        did_core_rows (core_id) {
            core_id -> Text,
            optional_core_id -> Nullable<Text>,
            cell_ref -> Text,
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
        cell_ref: CellRef,
        hash: Hash,
        origin: WebOrigin,
    }

    #[derive(Insertable)]
    #[diesel(table_name = did_core_rows)]
    struct NewDidCoreRow<'a> {
        core_id: &'a DidCoreId,
        optional_core_id: Option<&'a DidCoreId>,
        cell_ref: &'a CellRef,
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
        assert_from_sql_row::<CellRef>();
        assert_from_sql_row::<Hash>();
        assert_from_sql_row::<WebOrigin>();
        assert_nullable_from_sql_row::<Option<DidCoreId>>();
        assert_nullable_from_sql_row::<Option<CellRef>>();
        assert_nullable_from_sql_row::<Option<Hash>>();
        assert_text_expression::<DidCoreId>();
        assert_text_expression::<CellRef>();
        assert_text_expression::<Hash>();
        assert_text_expression::<WebOrigin>();
        assert_text_expression::<&DidCoreId>();
        assert_text_expression::<&CellRef>();
        assert_text_expression::<&Hash>();
        assert_text_expression::<&WebOrigin>();
        assert_nullable_text_expression::<DidCoreId>();
        assert_nullable_text_expression::<&DidCoreId>();
        assert_nullable_text_expression::<Option<DidCoreId>>();
        assert_nullable_text_expression::<Option<&DidCoreId>>();
        assert_queryable_by_name::<DidCoreRow>();

        let core_id = DidCoreId::new("ak:did_core:web:peer-ps.example").unwrap();
        let cell_ref = CellRef::new(
            "ak:cell:ak.component.consent.grant.v1:ak:consent:019640ed-6000-7000-8000-000000000001",
        )
        .unwrap();
        let hash = Hash::new(format!("sha256:{}", "a".repeat(64))).unwrap();
        let origin = WebOrigin::new("https://example.test").unwrap();
        let insert = diesel::insert_into(did_core_rows::table).values(NewDidCoreRow {
            core_id: &core_id,
            optional_core_id: Some(&core_id),
            cell_ref: &cell_ref,
            hash: &hash,
            origin: &origin,
        });
        let insert_sql = diesel::debug_query::<Pg, _>(&insert).to_string();
        assert!(insert_sql.contains("$1"));
        assert!(insert_sql.contains("$2"));
        assert!(insert_sql.contains("$3"));
        assert!(insert_sql.contains("$4"));

        let select = did_core_rows::table
            .filter(did_core_rows::core_id.eq(&core_id))
            .select(DidCoreRow::as_select());
        let select_sql = diesel::debug_query::<Pg, _>(&select).to_string();
        assert!(select_sql.contains("WHERE"));
        assert!(select_sql.contains("$1"));
    }

    #[test]
    fn database_text_validates_cell_refs_and_hashes() {
        let cell_ref = parse_text_identifier(
            "ak:cell:ak.component.consent.grant.v1:ak:consent:019640ed-6000-7000-8000-000000000001"
                .to_owned(),
            CellRef::new,
            "CellRef",
        )
        .unwrap();
        assert_eq!(
            cell_ref.as_str(),
            "ak:cell:ak.component.consent.grant.v1:ak:consent:019640ed-6000-7000-8000-000000000001"
        );

        let hash =
            parse_text_identifier(format!("sha256:{}", "a".repeat(64)), Hash::new, "Hash").unwrap();
        assert_eq!(hash.as_str(), format!("sha256:{}", "a".repeat(64)));

        let cell_error =
            parse_text_identifier("not-a-cell".to_owned(), CellRef::new, "CellRef").unwrap_err();
        assert_eq!(
            cell_error.to_string(),
            "database text is not a valid CellRef"
        );
        let hash_error =
            parse_text_identifier("not-a-hash".to_owned(), Hash::new, "Hash").unwrap_err();
        assert_eq!(hash_error.to_string(), "database text is not a valid Hash");
    }
}
