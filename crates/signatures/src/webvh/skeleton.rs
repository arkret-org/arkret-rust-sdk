//! The single `did:webvh` inception-skeleton, `{SCID}` and entry-hash
//! implementation.
//!
//! `identity-did.md` §3.4.4 fixes the `{SCID}` placeholder substitution scope:
//! it is a literal text replacement of **every** occurrence over the whole
//! preliminary log entry, at any depth, in both JSON member names and string
//! values, exactly as DIF did:webvh v1.0 requires. Substituting only selected
//! skeleton members would let two conforming producers publish different
//! entries for the same input, so every producer and verifier in this
//! workspace routes through [`substitute_webvh_scid`] and
//! [`webvh_scid_preimage`].

use arkret_canonical::canonical::canonical_json_bytes;
use arkret_canonical::sha256_multihash_base58btc;
use serde_json::{Map, Value, json};
use thiserror::Error;

/// The literal placeholder a preliminary log entry carries wherever the
/// not-yet-derived SCID will appear.
pub const WEBVH_SCID_PLACEHOLDER: &str = "{SCID}";

/// The only `parameters.method` value this workspace produces or accepts.
pub const WEBVH_METHOD_VERSION: &str = "did:webvh:1.0";

#[derive(Debug, Error)]
pub enum WebvhSkeletonError {
    #[error("webvh entry is not canonical JSON: {0}")]
    Canonical(String),
    #[error("webvh inception skeleton must contain {{SCID}} placeholders")]
    MissingPlaceholder,
    #[error("substituted webvh entry still contains a literal {{SCID}}")]
    ResidualPlaceholder,
}

/// Inputs for the registered `did:webvh` v1.0 inception parameters.
///
/// Deployment-specific extra parameters are deliberately absent: a caller that
/// needs one inserts it into the returned skeleton's `parameters` object before
/// deriving the SCID, so this constructor stays the single owner of the
/// registered core.
pub struct WebvhInceptionSkeletonInput<'a> {
    /// RFC3339 `versionTime` of the inception entry.
    pub version_time: &'a str,
    /// `parameters.updateKeys` — the active method-native roots.
    pub update_keys: &'a [String],
    /// `parameters.nextKeyHashes` — pre-rotation commitments. Omitted when empty.
    pub next_key_hashes: &'a [String],
    /// `parameters.portable`. `None` omits the member (did:webvh default `false`).
    pub portable: Option<bool>,
    /// Method-native `parameters.witness` policy block, when declared.
    pub witness: Option<&'a Value>,
    /// The preliminary DID document, built against [`webvh_placeholder_did`].
    pub state: &'a Value,
}

/// Build the preliminary inception log entry whose canonical bytes the SCID is
/// derived from.
///
/// Per DIF did:webvh v1.0 the preliminary entry's `versionId` is the bare
/// `{SCID}` placeholder (not a `<seq>-{SCID}` form) and carries no `proof`.
#[must_use]
pub fn build_webvh_inception_skeleton(input: &WebvhInceptionSkeletonInput<'_>) -> Value {
    let mut parameters = Map::new();
    parameters.insert(
        "method".to_owned(),
        Value::String(WEBVH_METHOD_VERSION.to_owned()),
    );
    parameters.insert(
        "scid".to_owned(),
        Value::String(WEBVH_SCID_PLACEHOLDER.to_owned()),
    );
    parameters.insert(
        "updateKeys".to_owned(),
        Value::Array(
            input
                .update_keys
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    if !input.next_key_hashes.is_empty() {
        parameters.insert(
            "nextKeyHashes".to_owned(),
            Value::Array(
                input
                    .next_key_hashes
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    if let Some(portable) = input.portable {
        parameters.insert("portable".to_owned(), Value::Bool(portable));
    }
    if let Some(witness) = input.witness {
        parameters.insert("witness".to_owned(), witness.clone());
    }
    json!({
        "versionId": WEBVH_SCID_PLACEHOLDER,
        "versionTime": input.version_time,
        "parameters": Value::Object(parameters),
        "state": input.state,
    })
}

/// The `did:webvh` identifier for `scid` under the embedded-provider layout.
#[must_use]
pub fn format_webvh_did(method_authority: &str, scid: &str, local_id: &str) -> String {
    format!("did:webvh:{scid}:{method_authority}:webvh:{local_id}")
}

/// The preliminary DID a document skeleton is authored against.
#[must_use]
pub fn webvh_placeholder_did(method_authority: &str, local_id: &str) -> String {
    format_webvh_did(method_authority, WEBVH_SCID_PLACEHOLDER, local_id)
}

/// `(method_authority, https_authority)` for a webvh hosting endpoint.
///
/// The first uses `%3A` before a port so it is DID-syntax safe; the second
/// uses a literal colon so it is URL-syntax safe.
#[must_use]
pub fn webvh_authority_pair(host: &str, port: Option<u16>) -> (String, String) {
    match port {
        Some(port) => (format!("{host}%3A{port}"), format!("{host}:{port}")),
        None => (host.to_owned(), host.to_owned()),
    }
}

/// Replace every occurrence of `{SCID}` in `entry` with `scid`.
///
/// §3.4.4: the replacement is a literal text replacement over the whole entry.
/// The recursive walk below covers both JSON member names and string values,
/// which is exactly what serializing the entry and replacing the placeholder in
/// the resulting text produces — `{`, `S`, `C`, `I`, `D` and `}` are never
/// escaped in a JSON string, so no occurrence can straddle an escape sequence.
#[must_use]
pub fn substitute_webvh_scid(entry: &Value, scid: &str) -> Value {
    replace_in_tree(entry, WEBVH_SCID_PLACEHOLDER, scid)
}

/// Reverse of [`substitute_webvh_scid`]: rebuild the preliminary skeleton from
/// a published entry so its SCID can be recomputed.
///
/// `proof` is dropped, every occurrence of `scid` becomes `{SCID}`, and
/// `versionId` is reset to the bare placeholder.
#[must_use]
pub fn webvh_scid_preimage(entry: &Value, scid: &str) -> Value {
    let mut stripped = entry.clone();
    if let Value::Object(map) = &mut stripped {
        map.remove("proof");
        map.remove("versionId");
    }
    let mut skeleton = replace_in_tree(&stripped, scid, WEBVH_SCID_PLACEHOLDER);
    if let Value::Object(map) = &mut skeleton {
        map.insert(
            "versionId".to_owned(),
            Value::String(WEBVH_SCID_PLACEHOLDER.to_owned()),
        );
    }
    skeleton
}

/// Whether any `{SCID}` placeholder is still present anywhere in `value`.
///
/// True on a preliminary skeleton (required) and false on a published entry
/// (required) — §3.4.4 makes a residual placeholder a rejection condition.
#[must_use]
pub fn webvh_scid_placeholder_present(value: &Value) -> bool {
    match value {
        Value::String(text) => text.contains(WEBVH_SCID_PLACEHOLDER),
        Value::Array(items) => items.iter().any(webvh_scid_placeholder_present),
        Value::Object(map) => map.iter().any(|(name, member)| {
            name.contains(WEBVH_SCID_PLACEHOLDER) || webvh_scid_placeholder_present(member)
        }),
        _ => false,
    }
}

/// Derive the SCID of a preliminary inception skeleton.
///
/// The pre-image is normalised first (`proof` removed, `versionId` reset to the
/// bare placeholder) so the result is independent of anything a caller left in
/// place.
pub fn derive_webvh_scid(skeleton: &Value) -> Result<String, WebvhSkeletonError> {
    if !webvh_scid_placeholder_present(skeleton) {
        return Err(WebvhSkeletonError::MissingPlaceholder);
    }
    let mut preimage = skeleton.clone();
    if let Value::Object(map) = &mut preimage {
        map.remove("proof");
        map.insert(
            "versionId".to_owned(),
            Value::String(WEBVH_SCID_PLACEHOLDER.to_owned()),
        );
    }
    Ok(sha256_multihash_base58btc(&canonical_bytes(&preimage)?))
}

/// Substitute the SCID and reject any residual placeholder.
///
/// §3.4.4: a published entry MUST NOT contain a literal `{SCID}`.
pub fn finalize_webvh_scid_substitution(
    skeleton: &Value,
    scid: &str,
) -> Result<Value, WebvhSkeletonError> {
    let entry = substitute_webvh_scid(skeleton, scid);
    if webvh_scid_placeholder_present(&entry) {
        return Err(WebvhSkeletonError::ResidualPlaceholder);
    }
    Ok(entry)
}

/// The DIF did:webvh v1.0 entry-hash pre-image: drop `proof[]` and set
/// `versionId` to the predecessor anchor — the SCID for the inception entry, or
/// the previous entry's `versionId` for every subsequent entry.
#[must_use]
pub fn webvh_entry_hash_preimage(entry: &Value, prev_anchor: &str) -> Value {
    let mut clone = entry.clone();
    if let Value::Object(map) = &mut clone {
        map.remove("proof");
        map.insert(
            "versionId".to_owned(),
            Value::String(prev_anchor.to_owned()),
        );
    }
    clone
}

/// `base58btc(multihash(JCS(entry-hash pre-image), sha2-256))` — the value a
/// `versionId` carries after its `<seq>-` prefix.
pub fn webvh_entry_hash_multibase(
    entry: &Value,
    prev_anchor: &str,
) -> Result<String, WebvhSkeletonError> {
    let preimage = webvh_entry_hash_preimage(entry, prev_anchor);
    Ok(sha256_multihash_base58btc(&canonical_bytes(&preimage)?))
}

/// The `nextKeyHashes` commitment to a multibase update key: the sha2-256
/// multihash of the key's own multibase text.
#[must_use]
pub fn webvh_next_key_hash_value(public_key_multibase: &str) -> String {
    sha256_multihash_base58btc(public_key_multibase.as_bytes())
}

fn replace_in_tree(value: &Value, from: &str, to: &str) -> Value {
    match value {
        Value::String(text) => Value::String(text.replace(from, to)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| replace_in_tree(item, from, to))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(name, member)| (name.replace(from, to), replace_in_tree(member, from, to)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn canonical_bytes(value: &Value) -> Result<Vec<u8>, WebvhSkeletonError> {
    canonical_json_bytes(value).map_err(|error| WebvhSkeletonError::Canonical(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitution_reaches_every_depth_and_member_name() {
        let skeleton = json!({
            "versionId": WEBVH_SCID_PLACEHOLDER,
            "parameters": {
                "scid": WEBVH_SCID_PLACEHOLDER,
                "nested": [WEBVH_SCID_PLACEHOLDER],
            },
            "state": {
                "id": format!("did:webvh:{WEBVH_SCID_PLACEHOLDER}:host:webvh:alice"),
                "alsoKnownAs": [format!("keep {WEBVH_SCID_PLACEHOLDER} here")],
                (WEBVH_SCID_PLACEHOLDER): "member name is rewritten too",
            },
        });
        let entry = finalize_webvh_scid_substitution(&skeleton, "QmFixture").unwrap();

        assert_eq!(entry["versionId"], "QmFixture");
        assert_eq!(entry["parameters"]["scid"], "QmFixture");
        assert_eq!(entry["parameters"]["nested"][0], "QmFixture");
        assert_eq!(entry["state"]["id"], "did:webvh:QmFixture:host:webvh:alice");
        assert_eq!(entry["state"]["alsoKnownAs"][0], "keep QmFixture here");
        assert_eq!(entry["state"]["QmFixture"], "member name is rewritten too");
        assert!(!webvh_scid_placeholder_present(&entry));
    }

    #[test]
    fn scid_preimage_round_trips_the_substitution() {
        let state = json!({
            "id": webvh_placeholder_did("host.example", "alice"),
            "alsoKnownAs": [format!("literal {WEBVH_SCID_PLACEHOLDER}")],
        });
        let skeleton = build_webvh_inception_skeleton(&WebvhInceptionSkeletonInput {
            version_time: "2026-08-15T00:00:00Z",
            update_keys: &["z6MkFixtureUpdateKey".to_owned()],
            next_key_hashes: &[webvh_next_key_hash_value("z6MkFixtureNextKey")],
            portable: None,
            witness: None,
            state: &state,
        });
        let scid = derive_webvh_scid(&skeleton).unwrap();
        let entry = finalize_webvh_scid_substitution(&skeleton, &scid).unwrap();

        let recovered = webvh_scid_preimage(&entry, &scid);
        assert_eq!(recovered, skeleton);
        assert_eq!(derive_webvh_scid(&recovered).unwrap(), scid);
    }

    #[test]
    fn a_residual_placeholder_is_rejected() {
        // A producer that substitutes only selected members leaves a literal
        // placeholder behind; §3.4.4 makes that entry non-conforming.
        let partially_substituted = json!({
            "versionId": "QmFixture",
            "parameters": {"scid": "QmFixture"},
            "state": {"alsoKnownAs": [WEBVH_SCID_PLACEHOLDER]},
        });
        assert!(webvh_scid_placeholder_present(&partially_substituted));
    }

    #[test]
    fn skeleton_omits_absent_optional_parameters() {
        let state = json!({"id": webvh_placeholder_did("host.example", "alice")});
        let skeleton = build_webvh_inception_skeleton(&WebvhInceptionSkeletonInput {
            version_time: "2026-08-15T00:00:00Z",
            update_keys: &["z6MkFixtureUpdateKey".to_owned()],
            next_key_hashes: &[],
            portable: None,
            witness: None,
            state: &state,
        });
        let parameters = skeleton["parameters"].as_object().unwrap();
        assert_eq!(parameters["method"], WEBVH_METHOD_VERSION);
        assert!(!parameters.contains_key("nextKeyHashes"));
        assert!(!parameters.contains_key("portable"));
        assert!(!parameters.contains_key("witness"));
    }
}
