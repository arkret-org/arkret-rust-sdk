//! Canonical digests over exact registered request bodies.
//!
//! Several own-Station and service-to-service results bind themselves to the
//! request that produced them without echoing the request members back. The
//! spec spells that binding as `SHA-256(UTF8(label) || 0x00 || JCS(exact
//! request body))`, so the label and the canonical JSON of the body are the
//! only inputs: a result cannot be replayed onto a different request, and a
//! protected member such as an invite token stays covered without ever
//! appearing in a response.
//!
//! It lives here because the request bodies it covers are spread across the
//! sibling model crates, and a second copy of the framing would be a second
//! definition of the transcript.

use serde::Serialize;

use crate::{Hash, Result, canonical};

/// `SHA-256(UTF8(label) || 0x00 || JCS(value))` as a suite-tagged [`struct@Hash`].
pub fn framed_request_digest<T>(label: &str, value: &T) -> Result<Hash>
where
    T: Serialize + ?Sized,
{
    let mut preimage = label.as_bytes().to_vec();
    preimage.push(0);
    preimage.extend(canonical::canonical_json_bytes(value)?);
    Ok(Hash::new(canonical::sha256_digest(preimage))?)
}

/// The original management creation body, removing only its outer evidence.
/// This is plain SHA-256(JCS(body)); it introduces no new signature domain.
pub fn management_creation_request_digest<T: Serialize + ?Sized>(request: &T) -> Result<Hash> {
    let mut value = serde_json::to_value(request)?;
    value
        .as_object_mut()
        .ok_or_else(|| {
            crate::WireError::Protocol("management creation request must be an object".into())
        })?
        .remove("approval_signatures");
    Ok(Hash::new(canonical::canonical_sha256(&value)?)?)
}

#[cfg(test)]
mod tests {
    use super::framed_request_digest;

    #[test]
    fn management_creation_digest_retains_nested_originals_and_rejects_nonobjects() {
        let original = serde_json::json!({"authoring_request":{"proof":"original"},"managed_actor_bundle":{"approval_signatures":["nested"]},"approval_signatures":["outer"]});
        let digest = super::management_creation_request_digest(&original).unwrap();
        let mut another_vote = original.clone();
        another_vote["approval_signatures"] = serde_json::json!(["another outer"]);
        assert_eq!(
            digest,
            super::management_creation_request_digest(&another_vote).unwrap()
        );
        another_vote["managed_actor_bundle"]["approval_signatures"] =
            serde_json::json!(["changed nested original"]);
        assert_ne!(
            digest,
            super::management_creation_request_digest(&another_vote).unwrap()
        );
        assert!(super::management_creation_request_digest(&serde_json::json!([])).is_err());
        assert!(super::management_creation_request_digest(&serde_json::Value::Null).is_err());
    }

    #[test]
    fn the_label_separates_two_otherwise_identical_bodies() {
        let body = serde_json::json!({"request_id": "ak:request:a"});
        let left = framed_request_digest("ak.left-v1", &body).expect("digest");
        let right = framed_request_digest("ak.right-v1", &body).expect("digest");
        assert_ne!(left, right);
    }

    #[test]
    fn the_zero_byte_stops_label_body_confusion() {
        // Without the separator, a label ending in the first canonical byte of
        // one body would collide with a shorter label and a longer body.
        let digest = framed_request_digest("ak.x", &serde_json::json!({})).expect("digest");
        let mut preimage = b"ak.x".to_vec();
        preimage.push(0);
        preimage.extend(b"{}");
        assert_eq!(
            digest.as_str(),
            arkret_canonical::canonical::sha256_digest(preimage)
        );
    }
}
