//! Optional PostgreSQL `text` persistence for [`DidCoreId`](super::DidCoreId).

use std::error::Error;
use std::fmt;

use diesel::deserialize::{self, FromSql};
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{self, Output, ToSql};
use diesel::sql_types::Text;

use super::DidCoreId;

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
    DidCoreId::new(value)
        .map_err(|_| -> Box<dyn Error + Send + Sync> { Box::new(InvalidDatabaseDidCoreId) })
}

#[derive(Debug)]
struct InvalidDatabaseDidCoreId;

impl fmt::Display for InvalidDatabaseDidCoreId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("database text is not a valid DidCoreId")
    }
}

impl Error for InvalidDatabaseDidCoreId {}

#[cfg(test)]
mod tests {
    use diesel::deserialize::{FromSqlRow, QueryableByName};
    use diesel::expression::AsExpression;
    use diesel::pg::Pg;
    use diesel::prelude::*;
    use diesel::sql_types::{Nullable, Text};

    use super::{DidCoreId, parse_database_text};

    diesel::table! {
        did_core_rows (core_id) {
            core_id -> Text,
            optional_core_id -> Nullable<Text>,
        }
    }

    #[derive(Queryable, Selectable, QueryableByName)]
    #[diesel(table_name = did_core_rows)]
    #[diesel(check_for_backend(Pg))]
    #[allow(dead_code)]
    struct DidCoreRow {
        core_id: DidCoreId,
        optional_core_id: Option<DidCoreId>,
    }

    #[derive(Insertable)]
    #[diesel(table_name = did_core_rows)]
    struct NewDidCoreRow<'a> {
        core_id: &'a DidCoreId,
        optional_core_id: Option<&'a DidCoreId>,
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
        assert_nullable_from_sql_row::<Option<DidCoreId>>();
        assert_text_expression::<DidCoreId>();
        assert_text_expression::<&DidCoreId>();
        assert_nullable_text_expression::<DidCoreId>();
        assert_nullable_text_expression::<&DidCoreId>();
        assert_nullable_text_expression::<Option<DidCoreId>>();
        assert_nullable_text_expression::<Option<&DidCoreId>>();
        assert_queryable_by_name::<DidCoreRow>();

        let core_id = DidCoreId::new("ak:did_core:web:peer-ps.example").unwrap();
        let insert = diesel::insert_into(did_core_rows::table).values(NewDidCoreRow {
            core_id: &core_id,
            optional_core_id: Some(&core_id),
        });
        let insert_sql = diesel::debug_query::<Pg, _>(&insert).to_string();
        assert!(insert_sql.contains("$1"));
        assert!(insert_sql.contains("$2"));

        let select = did_core_rows::table
            .filter(did_core_rows::core_id.eq(&core_id))
            .select(DidCoreRow::as_select());
        let select_sql = diesel::debug_query::<Pg, _>(&select).to_string();
        assert!(select_sql.contains("WHERE"));
        assert!(select_sql.contains("$1"));
    }
}
