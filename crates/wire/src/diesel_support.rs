//! Optional PostgreSQL `text` persistence for validated wire-string newtypes.

use std::error::Error;
use std::fmt;

use diesel::deserialize::{self, FromSql};
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{self, Output, ToSql};
use diesel::sql_types::Text;

use crate::OpaqueLocalId;

#[derive(diesel::expression::AsExpression, diesel::deserialize::FromSqlRow)]
#[diesel(foreign_derive)]
#[diesel(sql_type = Text)]
#[allow(dead_code)]
struct OpaqueLocalIdDieselProxy(OpaqueLocalId);

impl ToSql<Text, Pg> for OpaqueLocalId {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        <str as ToSql<Text, Pg>>::to_sql(self.as_str(), out)
    }
}

impl FromSql<Text, Pg> for OpaqueLocalId {
    fn from_sql(value: PgValue<'_>) -> deserialize::Result<Self> {
        let value = <String as FromSql<Text, Pg>>::from_sql(value)?;
        OpaqueLocalId::new(value)
            .map_err(|_| -> Box<dyn Error + Send + Sync> { Box::new(InvalidDatabaseOpaqueLocalId) })
    }
}

#[derive(Debug)]
struct InvalidDatabaseOpaqueLocalId;

impl fmt::Display for InvalidDatabaseOpaqueLocalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("database text is not a valid OpaqueLocalId")
    }
}

impl Error for InvalidDatabaseOpaqueLocalId {}

#[cfg(test)]
mod tests {
    use diesel::deserialize::FromSqlRow;
    use diesel::expression::AsExpression;
    use diesel::pg::Pg;
    use diesel::sql_types::{Nullable, Text};

    use super::OpaqueLocalId;

    #[test]
    fn diesel_text_traits_cover_required_and_optional_values() {
        fn assert_from_sql_row<T: FromSqlRow<Text, Pg>>() {}
        fn assert_nullable_from_sql_row<T: FromSqlRow<Nullable<Text>, Pg>>() {}
        fn assert_text_expression<T: AsExpression<Text>>() {}
        fn assert_nullable_text_expression<T: AsExpression<Nullable<Text>>>() {}

        assert_from_sql_row::<OpaqueLocalId>();
        assert_nullable_from_sql_row::<Option<OpaqueLocalId>>();
        assert_text_expression::<OpaqueLocalId>();
        assert_text_expression::<&OpaqueLocalId>();
        assert_nullable_text_expression::<OpaqueLocalId>();
        assert_nullable_text_expression::<&OpaqueLocalId>();
        assert_nullable_text_expression::<Option<OpaqueLocalId>>();
        assert_nullable_text_expression::<Option<&OpaqueLocalId>>();
    }
}
