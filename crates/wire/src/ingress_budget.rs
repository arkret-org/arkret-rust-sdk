//! One budgeted ingress boundary for every inbound JSON body class.
//!
//! `scalability-constraints.md` §2.1 defines three different byte bounds and
//! they apply in a fixed order: the HTTP message content bound stops reading
//! before any parse, structural depth is capped during parsing, and the
//! class-specific canonical bound applies to the parsed body. Spreading
//! those checks across call sites is how a path ends up borrowing the Event
//! Envelope's 1 MiB bound for an 8 MiB operation body — or skipping the wire
//! bound entirely and materializing an oversized `Value` first.
//!
//! Item counts are not part of this boundary: they are per-field bounds that
//! the schema for the concrete body already declares, and enforcing a single
//! global item cap here would be wrong for every one of them.

use arkret_canonical::canonical;
use serde_json::Value;

use crate::error::{Result, WireError};
use crate::event_envelope::{
    MAX_EVENT_ENVELOPE_BYTES, MAX_HTTP_MESSAGE_CONTENT_BYTES, MAX_OPERATION_CANONICAL_BODY_BYTES,
};

/// The inbound JSON body classes that carry distinct canonical byte bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireBodyClass {
    /// A full canonical Event Envelope (`scalability-constraints.md` §2.1.1).
    EventEnvelope,
    /// A `body_class=non_streaming_json` operation request or response body
    /// (§2.1.2). `max_canonical_body_bytes` is the operation registry's lower
    /// per-operation bound when the operation registers one.
    NonStreamingJsonOperation {
        max_canonical_body_bytes: Option<usize>,
    },
}

impl WireBodyClass {
    /// The canonical byte bound this class admits.
    ///
    /// A per-operation registration can only lower the general bound; §2.1.2
    /// forbids registering a higher one, so a larger value is clamped rather
    /// than trusted.
    #[must_use]
    pub fn canonical_byte_limit(self) -> usize {
        match self {
            Self::EventEnvelope => MAX_EVENT_ENVELOPE_BYTES,
            Self::NonStreamingJsonOperation {
                max_canonical_body_bytes,
            } => max_canonical_body_bytes
                .unwrap_or(MAX_OPERATION_CANONICAL_BODY_BYTES)
                .min(MAX_OPERATION_CANONICAL_BODY_BYTES),
        }
    }

    /// Admit inbound wire bytes as a canonical JSON value under this class.
    ///
    /// The order is normative: the HTTP message content bound first, then the
    /// duplicate-aware/depth-bounded parse, then the class-specific JCS byte
    /// bound, and finally the byte-for-byte canonical-form check.
    ///
    /// The returned value is what a schema validator should receive; running
    /// schema validation on unbudgeted input is the amplification this
    /// boundary exists to prevent.
    pub fn admit_canonical(self, bytes: &[u8]) -> Result<Value> {
        validate_http_message_content_len(bytes.len())?;
        let value = canonical::parse_json_rejecting_duplicate_keys_within(
            bytes,
            MAX_HTTP_MESSAGE_CONTENT_BYTES,
        )?;
        let canonical_bytes = canonical::canonical_json_bytes(&value)?;
        let limit = self.canonical_byte_limit();
        if canonical_bytes.len() > limit {
            return Err(WireError::BodyCanonicalBytesExceeded {
                body_class: self.label(),
                actual: canonical_bytes.len(),
                limit,
            });
        }
        if canonical_bytes.as_slice() != bytes {
            return Err(WireError::Protocol(
                "canonical JSON input is not byte-for-byte canonical".to_owned(),
            ));
        }
        Ok(value)
    }

    fn label(self) -> &'static str {
        match self {
            Self::EventEnvelope => "event envelope",
            Self::NonStreamingJsonOperation { .. } => "non-streaming JSON operation",
        }
    }
}

/// Reject an HTTP message content length before the body is read or parsed
/// (`scalability-constraints.md` §2.1.3).
pub fn validate_http_message_content_len(byte_len: usize) -> Result<()> {
    if byte_len > MAX_HTTP_MESSAGE_CONTENT_BYTES {
        return Err(WireError::BodyWireBytesExceeded {
            actual: byte_len,
            limit: MAX_HTTP_MESSAGE_CONTENT_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_object_of_len(target: usize) -> Vec<u8> {
        // {"a":"<padding>"} — canonical form, sized to the byte target.
        let overhead = br#"{"a":""}"#.len();
        let padding = "a".repeat(target - overhead);
        format!(r#"{{"a":"{padding}"}}"#).into_bytes()
    }

    #[test]
    fn each_class_admits_its_own_bound_and_rejects_one_byte_more() {
        for class in [
            WireBodyClass::EventEnvelope,
            WireBodyClass::NonStreamingJsonOperation {
                max_canonical_body_bytes: None,
            },
        ] {
            let limit = class.canonical_byte_limit();
            let at_limit = canonical_object_of_len(limit);
            assert_eq!(at_limit.len(), limit);
            class
                .admit_canonical(&at_limit)
                .unwrap_or_else(|error| panic!("{class:?} must admit its own bound: {error}"));

            let over_limit = canonical_object_of_len(limit + 1);
            assert!(
                class.admit_canonical(&over_limit).is_err(),
                "{class:?} must reject one byte over its bound"
            );
        }
    }

    #[test]
    fn an_operation_body_is_not_held_to_the_event_envelope_bound() {
        let body = canonical_object_of_len(MAX_EVENT_ENVELOPE_BYTES + 1);
        assert!(WireBodyClass::EventEnvelope.admit_canonical(&body).is_err());
        WireBodyClass::NonStreamingJsonOperation {
            max_canonical_body_bytes: None,
        }
        .admit_canonical(&body)
        .expect("an operation body above 1 MiB is legal up to 8 MiB");
    }

    #[test]
    fn a_registered_operation_bound_can_only_lower_the_general_bound() {
        let lowered = WireBodyClass::NonStreamingJsonOperation {
            max_canonical_body_bytes: Some(4096),
        };
        assert_eq!(lowered.canonical_byte_limit(), 4096);
        let raised = WireBodyClass::NonStreamingJsonOperation {
            max_canonical_body_bytes: Some(MAX_OPERATION_CANONICAL_BODY_BYTES * 2),
        };
        assert_eq!(
            raised.canonical_byte_limit(),
            MAX_OPERATION_CANONICAL_BODY_BYTES
        );
    }

    #[test]
    fn structural_depth_is_capped_inside_the_budgeted_parse() {
        let depth = canonical::MAX_CANONICAL_JSON_NESTING_DEPTH + 1;
        let body = format!("{}{}", "[".repeat(depth), "]".repeat(depth)).into_bytes();
        let error = WireBodyClass::NonStreamingJsonOperation {
            max_canonical_body_bytes: None,
        }
        .admit_canonical(&body)
        .unwrap_err();
        assert!(error.to_string().contains("structure_depth_exceeded"));
    }

    #[test]
    fn canonical_limit_measures_jcs_after_parsing() {
        let class = WireBodyClass::NonStreamingJsonOperation {
            max_canonical_body_bytes: Some(8),
        };
        let non_canonical = br#"{ "a": 1 }"#;
        let error = class.admit_canonical(non_canonical).unwrap_err();
        assert!(matches!(error, WireError::Protocol(_)));

        let canonical_over_limit = br#"{"a":100}"#;
        let error = class.admit_canonical(canonical_over_limit).unwrap_err();
        assert!(matches!(
            error,
            WireError::BodyCanonicalBytesExceeded {
                actual: 9,
                limit: 8,
                ..
            }
        ));
    }
}
