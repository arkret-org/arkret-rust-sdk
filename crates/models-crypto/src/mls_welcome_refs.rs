//! Authenticated recipient discovery without governance replay or consume side effects.

use std::collections::BTreeSet;

use arkret_wire::{Base64UrlString, EventId, Result, ScopeRef, WireError};
use serde::{Deserialize, Serialize};

pub const MLS_WELCOME_REFS_MAX_BYTES: usize = 64 * 1024;
pub const MLS_WELCOME_REFS_DEFAULT_LIMIT: u32 = 20;
pub const MLS_WELCOME_REFS_MAX_LIMIT: u32 = 100;
pub const MLS_WELCOME_REFS_MAX_CURSOR_CHARACTERS: usize = 4096;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsWelcomeRefsRequestBody {
    pub effective_scope: ScopeRef,
    pub mls_group_id: Base64UrlString,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub limit: Option<u32>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub cursor: Option<String>,
}

impl MlsWelcomeRefsRequestBody {
    pub fn effective_limit(&self) -> u32 {
        self.limit.unwrap_or(MLS_WELCOME_REFS_DEFAULT_LIMIT)
    }

    pub fn validate(&self) -> Result<()> {
        validate_bytes(self, arkret_wire::ErrorCode::PayloadTooLarge)?;
        if !matches!(
            self.effective_scope,
            ScopeRef::Realm { .. } | ScopeRef::Circle { .. }
        ) || self.effective_scope.canonical_mls_group_id()? != self.mls_group_id.as_str()
        {
            return invalid("Welcome discovery scope/group mismatch (state_mismatch)");
        }
        if !(1..=MLS_WELCOME_REFS_MAX_LIMIT).contains(&self.effective_limit()) {
            return Err(WireError::ProtocolCode {
                code: arkret_wire::ErrorCode::SchemaViolation,
                message: "Welcome discovery limit must be between 1 and 100".to_owned(),
            });
        }
        if let Some(cursor) = &self.cursor {
            validate_cursor(cursor)?;
        }
        Ok(())
    }
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MlsWelcomeRefsOutcome {
    pub welcome_refs: Vec<EventId>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::serde_absence::deserialize_non_null_optional"
    )]
    pub next_cursor: Option<String>,
    pub limited: bool,
}

impl MlsWelcomeRefsOutcome {
    pub fn validate(&self) -> Result<()> {
        if self.welcome_refs.len() > MLS_WELCOME_REFS_MAX_LIMIT as usize
            || self.welcome_refs.iter().collect::<BTreeSet<_>>().len() != self.welcome_refs.len()
            || self.limited != self.next_cursor.is_some()
            || (self.limited && self.welcome_refs.is_empty())
        {
            return invalid(
                "Welcome discovery page violates bounds or continuation shape (schema_violation)",
            );
        }
        if let Some(cursor) = &self.next_cursor {
            validate_cursor(cursor)?;
        }
        validate_bytes(self, arkret_wire::ErrorCode::LimitExceeded)
    }

    /// Validate framing and request association; current recipient authority remains the Station's
    /// decision.
    pub fn validate_for_request(&self, request: &MlsWelcomeRefsRequestBody) -> Result<()> {
        request.validate()?;
        self.validate()?;
        if self.welcome_refs.len() > request.effective_limit() as usize {
            return Err(WireError::ProtocolCode {
                code: arkret_wire::ErrorCode::StateMismatch,
                message: "Welcome discovery page exceeds the requested item limit".to_owned(),
            });
        }
        if let Some(cursor) = &self.next_cursor {
            if request.cursor.as_ref() == Some(cursor) {
                return invalid("Welcome discovery continuation made no progress (cursor_invalid)");
            }
            let mut next = request.clone();
            next.cursor = Some(cursor.clone());
            validate_bytes(&next, arkret_wire::ErrorCode::LimitExceeded)?;
            next.validate()?;
        }
        Ok(())
    }
}

fn validate_cursor(cursor: &str) -> Result<()> {
    if cursor.is_empty() || cursor.chars().count() > MLS_WELCOME_REFS_MAX_CURSOR_CHARACTERS {
        return invalid("Welcome discovery cursor exceeds its character bound (schema_violation)");
    }
    Ok(())
}

fn validate_bytes(value: &impl Serialize, error_code: arkret_wire::ErrorCode) -> Result<()> {
    if arkret_canonical::canonical_json_bytes(value)?.len() > MLS_WELCOME_REFS_MAX_BYTES {
        return Err(WireError::ProtocolCode {
            code: error_code,
            message: "Welcome discovery canonical body exceeds 64 KiB".to_owned(),
        });
    }
    Ok(())
}

fn invalid(message: &str) -> Result<()> {
    Err(WireError::Protocol(message.to_owned()))
}

#[cfg(test)]
mod tests {
    use arkret_wire::RealmId;

    use super::*;

    fn request() -> MlsWelcomeRefsRequestBody {
        let effective_scope = ScopeRef::Realm {
            realm_id: RealmId::new("ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI")
                .unwrap(),
        };
        MlsWelcomeRefsRequestBody {
            mls_group_id: Base64UrlString::new(effective_scope.canonical_mls_group_id().unwrap())
                .unwrap(),
            effective_scope,
            limit: None,
            cursor: None,
        }
    }

    #[test]
    fn byte_budget_precedes_schema_and_keeps_response_budget_distinct() {
        let mut query = request();
        query.limit = Some(101);
        assert_eq!(
            query.validate().unwrap_err().error_code(),
            Some(arkret_wire::ErrorCode::SchemaViolation)
        );
        query.cursor = Some("x".repeat(MLS_WELCOME_REFS_MAX_BYTES));
        assert_eq!(
            query.validate().unwrap_err().error_code(),
            Some(arkret_wire::ErrorCode::PayloadTooLarge)
        );
        assert_eq!(
            validate_bytes(&query, arkret_wire::ErrorCode::LimitExceeded)
                .unwrap_err()
                .error_code(),
            Some(arkret_wire::ErrorCode::LimitExceeded)
        );
    }

    #[test]
    fn recipient_override_null_and_duplicate_fields_are_rejected() {
        let query = request();
        query.validate().unwrap();
        for field in ["limit", "cursor", "recipient"] {
            let mut value = serde_json::to_value(&query).unwrap();
            value[field] = serde_json::Value::Null;
            assert!(serde_json::from_value::<MlsWelcomeRefsRequestBody>(value).is_err());
        }
        let json = serde_json::to_string(&query).unwrap();
        let duplicate = format!("{},\"limit\":1,\"limit\":2}}", &json[..json.len() - 1]);
        assert!(serde_json::from_str::<MlsWelcomeRefsRequestBody>(&duplicate).is_err());
    }

    #[test]
    fn final_and_limited_page_shapes_are_distinct() {
        let query = request();
        let mut page = MlsWelcomeRefsOutcome {
            welcome_refs: vec![],
            next_cursor: None,
            limited: false,
        };
        page.validate_for_request(&query).unwrap();
        page.next_cursor = Some("opaque".to_owned());
        assert!(page.validate_for_request(&query).is_err());
        page.limited = true;
        assert!(page.validate_for_request(&query).is_err());
        let event = EventId::new("ak:event:AZEvldDJcWI9IRHqP2BMibDDfc59Ax_LwrbsrQmeD6Ml").unwrap();
        page.welcome_refs.push(event.clone());
        page.validate_for_request(&query).unwrap();
        let mut resumed = query.clone();
        resumed.cursor = page.next_cursor.clone();
        assert!(page.validate_for_request(&resumed).is_err());
        page.welcome_refs.push(event);
        assert!(page.validate_for_request(&query).is_err());
        let mut value = serde_json::to_value(&page).unwrap();
        value["next_cursor"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<MlsWelcomeRefsOutcome>(value).is_err());
    }

    #[test]
    fn limits_and_opaque_cursor_are_validated_without_decoding() {
        let mut query = request();
        for limit in [0, 101] {
            query.limit = Some(limit);
            assert!(query.validate().is_err());
        }
        query.limit = Some(100);
        query.cursor = Some("x".repeat(4096));
        query.validate().unwrap();
        query.cursor = Some("x".repeat(4097));
        assert!(query.validate().is_err());
    }
}
