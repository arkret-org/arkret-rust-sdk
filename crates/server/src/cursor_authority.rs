//! Server-side authority for v1 stateful cursor handles.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use arkret_core::{Cursor, CursorPurpose};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Fields bound server-side to a stream cursor handle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorBindingContext {
    pub principal_id: String,
    pub device_id: Option<String>,
    pub service_id: String,
    pub filter_digest: String,
}

impl CursorBindingContext {
    pub fn new(
        principal_id: impl Into<String>,
        device_id: Option<String>,
        service_id: impl Into<String>,
        filter_digest: impl Into<String>,
    ) -> Self {
        Self {
            principal_id: principal_id.into(),
            device_id,
            service_id: service_id.into(),
            filter_digest: filter_digest.into(),
        }
    }
}

/// Server-private row addressed by the cursor body's opaque `h` handle.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CursorBindingRecord {
    pub handle: String,
    pub context: CursorBindingContext,
    pub purpose: CursorPurpose,
    pub positions: Value,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

/// Failure classes required by the v1 cursor contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CursorAuthorityError {
    InvalidParam(String),
    Expired,
    IntegrityInvalid,
}

impl fmt::Display for CursorAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParam(message) => formatter.write_str(message),
            Self::Expired => formatter.write_str("cursor has expired"),
            Self::IntegrityInvalid => formatter.write_str("cursor integrity check failed"),
        }
    }
}

impl std::error::Error for CursorAuthorityError {}

/// Compute the canonical digest bound to a cursor's query/filter semantics.
pub fn cursor_filter_digest<T: Serialize>(filter: &T) -> Result<String, CursorAuthorityError> {
    arkret_canonical::canonical_sha256(filter)
        .map_err(|error| CursorAuthorityError::InvalidParam(error.to_string()))
}

/// Stateless v1 cursor codec and binding validator.
pub struct CursorAuthority;

impl CursorAuthority {
    /// Mint a stream token and the server-private row that must be persisted
    /// before the token is returned to a caller.
    pub fn mint_stream(
        context: CursorBindingContext,
        positions: Value,
        ttl_ms: i64,
    ) -> Result<(String, CursorBindingRecord), CursorAuthorityError> {
        let issued_at = chrono::Utc::now();
        let cursor = Cursor::new_at(issued_at, ttl_ms)
            .map_err(|error| CursorAuthorityError::InvalidParam(error.to_string()))?;
        let token = cursor
            .encode()
            .map_err(|error| CursorAuthorityError::InvalidParam(error.to_string()))?;
        let issued_at_ms = chrono::DateTime::parse_from_rfc3339(&cursor.t)
            .map_err(|error| CursorAuthorityError::InvalidParam(error.to_string()))?
            .timestamp_millis();
        let record = CursorBindingRecord {
            handle: cursor.h.clone(),
            context,
            purpose: CursorPurpose::Stream,
            positions,
            issued_at_ms,
            expires_at_ms: cursor.x,
        };
        Ok((token, record))
    }

    /// Decode a stream token before looking up its server-private binding.
    pub fn decode_stream(token: &str) -> Result<Cursor, CursorAuthorityError> {
        let cursor =
            Cursor::decode(token).map_err(|error| match arkret_core::Error::from(error) {
                arkret_core::Error::Protocol(message) if message == "cursor has expired" => {
                    CursorAuthorityError::Expired
                }
                other => CursorAuthorityError::InvalidParam(other.to_string()),
            })?;
        if cursor.purpose != CursorPurpose::Stream {
            return Err(CursorAuthorityError::InvalidParam(
                "cursor purpose must be stream".to_owned(),
            ));
        }
        Ok(cursor)
    }

    /// Validate a decoded cursor against its stored row and request context.
    pub fn resolve_stream(
        cursor: &Cursor,
        expected: &CursorBindingContext,
        record: Option<&CursorBindingRecord>,
    ) -> Result<Value, CursorAuthorityError> {
        let record = record.ok_or(CursorAuthorityError::IntegrityInvalid)?;
        let cursor_issued_at_ms = chrono::DateTime::parse_from_rfc3339(&cursor.t)
            .map_err(|_| CursorAuthorityError::InvalidParam("invalid cursor timestamp".to_owned()))?
            .timestamp_millis();
        if cursor.purpose != CursorPurpose::Stream
            || record.purpose != CursorPurpose::Stream
            || record.handle != cursor.h
            || record.issued_at_ms != cursor_issued_at_ms
            || record.expires_at_ms != cursor.x
            || &record.context != expected
        {
            return Err(CursorAuthorityError::IntegrityInvalid);
        }
        Ok(record.positions.clone())
    }
}

/// Bounded process-local binding table for services without a durable store.
#[derive(Clone)]
pub struct MemoryCursorAuthority {
    rows: Arc<Mutex<BTreeMap<String, CursorBindingRecord>>>,
    max_rows: usize,
}

impl Default for MemoryCursorAuthority {
    fn default() -> Self {
        Self::new(16_384)
    }
}

impl MemoryCursorAuthority {
    pub fn new(max_rows: usize) -> Self {
        assert!(max_rows > 0, "cursor authority capacity must be non-zero");
        Self {
            rows: Arc::new(Mutex::new(BTreeMap::new())),
            max_rows,
        }
    }

    pub fn mint_stream(
        &self,
        context: CursorBindingContext,
        positions: Value,
        ttl_ms: i64,
    ) -> Result<String, CursorAuthorityError> {
        let (token, record) = CursorAuthority::mint_stream(context, positions, ttl_ms)?;
        let now_ms = chrono::Utc::now().timestamp_millis();
        let mut rows = self
            .rows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        rows.retain(|_, row| row.expires_at_ms >= now_ms);
        while rows.len() >= self.max_rows {
            let Some(oldest) = rows
                .iter()
                .min_by_key(|(_, row)| row.expires_at_ms)
                .map(|(handle, _)| handle.clone())
            else {
                break;
            };
            rows.remove(&oldest);
        }
        rows.insert(record.handle.clone(), record);
        Ok(token)
    }

    pub fn resolve_stream(
        &self,
        token: &str,
        expected: &CursorBindingContext,
    ) -> Result<Value, CursorAuthorityError> {
        let cursor = CursorAuthority::decode_stream(token)?;
        let rows = self
            .rows
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        CursorAuthority::resolve_stream(&cursor, expected, rows.get(&cursor.h))
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn context(subject: &str, filter: &str) -> CursorBindingContext {
        CursorBindingContext::new(subject, None, "did:web:directory.example", filter)
    }

    #[test]
    fn memory_authority_round_trips_sdk_cursor_and_positions() {
        let authority = MemoryCursorAuthority::default();
        let context = context("did:web:alice.example", "sha256:filter-a");
        let token = authority
            .mint_stream(context.clone(), json!({"offset": 20}), 60_000)
            .unwrap();
        assert!(token.starts_with("ak:cursor:"));
        assert_eq!(
            authority.resolve_stream(&token, &context).unwrap(),
            json!({"offset": 20})
        );
    }

    #[test]
    fn memory_authority_rejects_cross_subject_and_cross_filter_replay() {
        let authority = MemoryCursorAuthority::default();
        let original = context("did:web:alice.example", "sha256:filter-a");
        let token = authority
            .mint_stream(original, json!({"offset": 20}), 60_000)
            .unwrap();
        assert_eq!(
            authority
                .resolve_stream(&token, &context("did:web:bob.example", "sha256:filter-a"))
                .unwrap_err(),
            CursorAuthorityError::IntegrityInvalid
        );
        assert_eq!(
            authority
                .resolve_stream(&token, &context("did:web:alice.example", "sha256:filter-b"))
                .unwrap_err(),
            CursorAuthorityError::IntegrityInvalid
        );
    }

    #[test]
    fn memory_authority_rejects_unknown_and_malformed_handles() {
        let authority = MemoryCursorAuthority::default();
        let context = context("did:web:alice.example", "sha256:filter-a");
        let (_, record) =
            CursorAuthority::mint_stream(context.clone(), json!({"offset": 20}), 60_000).unwrap();
        let token = Cursor {
            v: "1".to_owned(),
            purpose: CursorPurpose::Stream,
            t: arkret_canonical::format_timestamp_canonical(chrono::Utc::now()),
            x: record.expires_at_ms,
            h: record.handle,
        }
        .encode()
        .unwrap();
        assert_eq!(
            authority.resolve_stream(&token, &context).unwrap_err(),
            CursorAuthorityError::IntegrityInvalid
        );
        assert!(matches!(
            authority.resolve_stream("not-a-cursor", &context),
            Err(CursorAuthorityError::InvalidParam(_))
        ));
    }

    #[test]
    fn authority_rejects_timestamp_tampering_for_a_known_handle() {
        let context = context("did:web:alice.example", "sha256:filter-a");
        let (token, record) =
            CursorAuthority::mint_stream(context.clone(), json!({"offset": 20}), 60_000).unwrap();
        let mut cursor = CursorAuthority::decode_stream(&token).unwrap();
        let changed =
            chrono::DateTime::parse_from_rfc3339(&cursor.t).unwrap() - chrono::Duration::seconds(1);
        cursor.t = arkret_canonical::format_timestamp_canonical(changed.into());
        let tampered = cursor.encode().unwrap();
        let decoded = CursorAuthority::decode_stream(&tampered).unwrap();
        assert_eq!(
            CursorAuthority::resolve_stream(&decoded, &context, Some(&record)).unwrap_err(),
            CursorAuthorityError::IntegrityInvalid
        );
    }
}
