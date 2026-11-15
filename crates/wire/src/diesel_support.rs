//! Optional PostgreSQL persistence for the structured identities this crate
//! owns.
//!
//! Diesel's `ToSql` / `FromSql` impls must be written in the crate that defines
//! the type, so these cannot move into `arkret-identifiers` alongside the
//! identifier mappings. The boilerplate is shared instead: the expression/row and
//! text-column macros come from `arkret_identifiers`, which is why
//! `OpaqueLocalId` needs no hand-written impls here.

use std::io::Write;

use diesel::deserialize::{self, FromSql};
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{self, Output, ToSql};
use diesel::sql_types::{Jsonb, Text};

use crate::{AccountId, ActorId, OpaqueLocalId};

arkret_identifiers::impl_sql_value!(AccountId, ::diesel::sql_types::Text);
arkret_identifiers::impl_sql_value!(ActorId, ::diesel::sql_types::Jsonb);

impl ToSql<Text, Pg> for AccountId {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        out.write_all(&self.canonical_bytes()?)?;
        Ok(serialize::IsNull::No)
    }
}

impl FromSql<Text, Pg> for AccountId {
    fn from_sql(value: PgValue<'_>) -> deserialize::Result<Self> {
        let text = <String as FromSql<Text, Pg>>::from_sql(value)?;
        parse_account_text(&text)
    }
}

fn parse_account_text(text: &str) -> deserialize::Result<AccountId> {
    serde_json::from_str(text).map_err(|_| "database text is not a valid AccountId".into())
}

impl ToSql<Jsonb, Pg> for ActorId {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        let value = serde_json::to_value(self)?;
        <serde_json::Value as ToSql<Jsonb, Pg>>::to_sql(&value, &mut out.reborrow())
    }
}

impl FromSql<Jsonb, Pg> for ActorId {
    fn from_sql(value: PgValue<'_>) -> deserialize::Result<Self> {
        let value = <serde_json::Value as FromSql<Jsonb, Pg>>::from_sql(value)?;
        parse_actor_json(value)
    }
}

fn parse_actor_json(value: serde_json::Value) -> deserialize::Result<ActorId> {
    serde_json::from_value(value).map_err(|_| "database JSONB is not a valid ActorId".into())
}

arkret_identifiers::impl_sql_value!(OpaqueLocalId, ::diesel::sql_types::Text);
arkret_identifiers::impl_text_identifier_sql!(OpaqueLocalId, "OpaqueLocalId");

#[cfg(test)]
mod tests {
    use diesel::deserialize::FromSqlRow;
    use diesel::expression::AsExpression;
    use diesel::pg::Pg;
    use diesel::prelude::*;
    use diesel::sql_types::{Jsonb, Nullable, Text};

    use super::{AccountId, ActorId, OpaqueLocalId};

    diesel::table! {
        identity_rows (account) {
            account -> Text,
            actor -> Jsonb,
            local_id -> Text,
        }
    }

    #[test]
    fn structured_identity_adapters_preserve_station_and_stay_closed() {
        use crate::{AccountId, ActorId, DidCoreId};
        let principal = DidCoreId::new("ak:did_core:web:alice.example").unwrap();
        let first = AccountId::new(
            principal.clone(),
            DidCoreId::new("ak:did_core:web:a.example").unwrap(),
        );
        let second = AccountId::new(
            principal,
            DidCoreId::new("ak:did_core:web:b.example").unwrap(),
        );
        for account in [first.clone(), second.clone()] {
            assert_eq!(
                super::parse_account_text(&account.to_string()).unwrap(),
                account
            );
            let actor = ActorId::account(account);
            assert_eq!(
                super::parse_actor_json(serde_json::to_value(&actor).unwrap()).unwrap(),
                actor
            );
        }
        assert_ne!(first, second);
        let service = ActorId::service(DidCoreId::new("ak:did_core:web:notary.example").unwrap());
        assert_eq!(
            super::parse_actor_json(serde_json::to_value(&service).unwrap()).unwrap(),
            service
        );
        {
            let invalid = serde_json::json!({"principal_id": "ak:did_core:web:alice.example", "station_id": "ak:did_core:web:a.example", "extra": true});
            assert!(super::parse_account_text(&invalid.to_string()).is_err());
            assert!(super::parse_actor_json(invalid).is_err());
        }
        assert!(
            super::parse_actor_json(
                serde_json::json!({"kind":"service", "service_id":"did:web:notary.example"})
            )
            .is_err()
        );
    }

    #[test]
    fn structured_identity_expressions_preserve_sql_and_nullable_bindings() {
        fn assert_text<T: AsExpression<Text> + AsExpression<Nullable<Text>>>() {}
        fn assert_json<T: AsExpression<Jsonb> + AsExpression<Nullable<Jsonb>>>() {}
        fn assert_text_row<T: FromSqlRow<Text, Pg>>() {}
        fn assert_json_row<T: FromSqlRow<Jsonb, Pg>>() {}

        assert_text::<AccountId>();
        assert_text::<&AccountId>();
        assert_text::<&&AccountId>();
        assert_json::<ActorId>();
        assert_json::<&ActorId>();
        assert_json::<&&ActorId>();
        assert_text_row::<AccountId>();
        assert_json_row::<ActorId>();

        let account = AccountId::new(
            crate::DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
            crate::DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        );
        let actor = ActorId::account(account.clone());
        let local = OpaqueLocalId::new("selected-local-value").unwrap();
        let owned = identity_rows::table
            .filter(identity_rows::account.eq(account.clone()))
            .filter(identity_rows::actor.eq(actor.clone()));
        let sql = diesel::debug_query::<Pg, _>(&owned).to_string();
        assert!(sql.contains("$1") && sql.contains("$2"));
        let nullable = identity_rows::table
            .filter(identity_rows::account.nullable().eq(Some(&account)))
            .filter(identity_rows::actor.nullable().eq(Some(&actor)));
        let sql = diesel::debug_query::<Pg, _>(&nullable).to_string();
        assert!(sql.contains("$1") && sql.contains("$2"));

        // Borrow the local value instead of asking Diesel to derive a foreign
        // smart-pointer expression impl in this crate.
        let boxed = Box::new(account);
        let shared = std::rc::Rc::new(actor);
        let synchronized = std::sync::Arc::new(local);
        let insert = diesel::insert_into(identity_rows::table).values((
            identity_rows::account.eq(boxed.as_ref()),
            identity_rows::actor.eq(shared.as_ref()),
            identity_rows::local_id.eq(synchronized.as_ref()),
        ));
        let sql = diesel::debug_query::<Pg, _>(&insert).to_string();
        assert!(sql.contains("$1") && sql.contains("$2") && sql.contains("$3"));
    }

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
        assert_text_expression::<&&OpaqueLocalId>();
        assert_nullable_text_expression::<OpaqueLocalId>();
        assert_nullable_text_expression::<&OpaqueLocalId>();
        assert_nullable_text_expression::<&&OpaqueLocalId>();
        assert_nullable_text_expression::<Option<OpaqueLocalId>>();
        assert_nullable_text_expression::<Option<&OpaqueLocalId>>();
    }
}
