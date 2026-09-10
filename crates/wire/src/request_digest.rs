//! Domain-separated digest over an exact canonical request body.
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

/// `SHA-256(UTF8(label) || 0x00 || JCS(value))` as a suite-tagged [`Hash`].
pub fn framed_request_digest<T>(label: &str, value: &T) -> Result<Hash>
where
    T: Serialize + ?Sized,
{
    let mut preimage = label.as_bytes().to_vec();
    preimage.push(0);
    preimage.extend(canonical::canonical_json_bytes(value)?);
    Ok(Hash::new(canonical::sha256_digest(preimage))?)
}

#[cfg(test)]
mod tests {
    use super::framed_request_digest;

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
