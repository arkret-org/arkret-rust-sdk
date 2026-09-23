//! Formal-verification guard inputs for the canonical test-material registry.
//!
//! The public API deliberately has no "allow test material" mode. Isolated
//! conformance harnesses can call the underlying cryptographic primitives;
//! formal verifier and trust-admission paths call these matchers and reject a
//! match with `test_signing_material_denied`.

use arkret_wire::{Did, DidUrl, TrustDomainId};

pub const TEST_SIGNING_MATERIAL_DENIED: &str = "test_signing_material_denied";

pub const PUBLISHED_TEST_KEY_FINGERPRINTS: &[&str] = &[
    "sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c",
    "sha256:c6f4e212a3ac26051c507ab582c041f01044b2d140d5ee018c4f950acd061460",
    "sha256:7dc6f48006fb83016824a718645146e3c9653afe9c63e1c5ff255f9e78717ebd",
    "sha256:21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9",
];

const RESERVED_WEBVH_SCID_PREFIXES: &[&str] = &["z6mkfixture", "z6mkagent"];
const RESERVED_KEY_ID_SUFFIXES: &[&str] = &["-fixture"];
const RESERVED_TRUST_DOMAIN_VALUES: &[&str] = &[
    "recovery-fixture",
    "did.webvh.example",
    "did.webvh.alice.example",
    "did.webvh.acme.example",
    "did.webvh.defense.example",
    "example.test",
    "registry.example",
    "fixture.example",
];
const RESERVED_TRUST_DOMAIN_TOP_LABELS: &[&str] = &["example", "invalid", "localhost", "test"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicKeyFingerprintInput<'a> {
    Ed25519Rfc8032(&'a [u8]),
    P256Sec1Uncompressed(&'a [u8]),
    MlDsa65Fips204(&'a [u8]),
}

impl PublicKeyFingerprintInput<'_> {
    fn algorithm_bytes(&self) -> Result<&[u8], TestMaterialMatchError> {
        let (bytes, expected, encoding) = match self {
            Self::Ed25519Rfc8032(bytes) => (*bytes, 32, "ed25519_rfc8032_public_key"),
            Self::P256Sec1Uncompressed(bytes) => (*bytes, 65, "p256_sec1_uncompressed_point"),
            Self::MlDsa65Fips204(bytes) => (*bytes, 1952, "mldsa65_fips204_public_key"),
        };
        if bytes.len() != expected {
            return Err(TestMaterialMatchError::InvalidPublicKeyEncoding {
                encoding,
                expected,
                actual: bytes.len(),
            });
        }
        if matches!(self, Self::P256Sec1Uncompressed(_)) && bytes[0] != 0x04 {
            return Err(TestMaterialMatchError::InvalidPublicKeyEncoding {
                encoding,
                expected,
                actual: bytes.len(),
            });
        }
        Ok(bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TestMaterialMatchError {
    #[error("invalid {encoding} length/shape: expected {expected} bytes, received {actual} bytes")]
    InvalidPublicKeyEncoding {
        encoding: &'static str,
        expected: usize,
        actual: usize,
    },
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReservedIdentifierMatches {
    pub did: bool,
    pub key_id: bool,
    pub trust_domain: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("test_signing_material_denied")]
pub struct TestMaterialDenied {
    pub published_key_fingerprint: Option<String>,
    pub reserved_identifiers: ReservedIdentifierMatches,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FormalTestMaterialPolicyError {
    #[error(transparent)]
    InvalidPublicKey(#[from] TestMaterialMatchError),
    #[error(transparent)]
    Denied(#[from] TestMaterialDenied),
}

impl ReservedIdentifierMatches {
    pub fn any(&self) -> bool {
        self.did || self.key_id || self.trust_domain
    }
}

pub fn public_key_fingerprint(
    input: &PublicKeyFingerprintInput<'_>,
) -> Result<String, TestMaterialMatchError> {
    Ok(arkret_canonical::canonical::sha256_digest(
        input.algorithm_bytes()?,
    ))
}

pub fn is_published_test_key(
    input: &PublicKeyFingerprintInput<'_>,
) -> Result<bool, TestMaterialMatchError> {
    let fingerprint = public_key_fingerprint(input)?;
    Ok(PUBLISHED_TEST_KEY_FINGERPRINTS.contains(&fingerprint.as_str()))
}

pub fn is_reserved_test_did(did: &Did) -> bool {
    if did.method() != "webvh" {
        return false;
    }
    let Some(scid) = did
        .as_str()
        .strip_prefix("did:webvh:")
        .and_then(|value| value.split(':').next())
    else {
        return false;
    };
    RESERVED_WEBVH_SCID_PREFIXES
        .iter()
        .any(|prefix| scid.starts_with(prefix))
}

pub fn is_reserved_test_key_id(key_id: &DidUrl) -> bool {
    let Some((_, fragment)) = key_id.as_str().split_once('#') else {
        return false;
    };
    RESERVED_KEY_ID_SUFFIXES
        .iter()
        .any(|suffix| fragment.ends_with(suffix))
}

pub fn is_reserved_test_trust_domain(trust_domain: &TrustDomainId) -> bool {
    let value = trust_domain
        .as_str()
        .strip_prefix("ak:trust_domain:")
        .expect("TrustDomainId always has its typed prefix");
    RESERVED_TRUST_DOMAIN_VALUES.contains(&value)
        || value
            .rsplit('.')
            .next()
            .is_some_and(|label| RESERVED_TRUST_DOMAIN_TOP_LABELS.contains(&label))
}

pub fn reserved_identifier_matches(
    did: Option<&Did>,
    key_id: Option<&DidUrl>,
    trust_domain: Option<&TrustDomainId>,
) -> ReservedIdentifierMatches {
    ReservedIdentifierMatches {
        did: did.is_some_and(is_reserved_test_did),
        key_id: key_id.is_some_and(is_reserved_test_key_id),
        trust_domain: trust_domain.is_some_and(is_reserved_test_trust_domain),
    }
}

/// Formal-path guard. There is intentionally no mode or configuration input
/// that can turn a match into acceptance.
pub fn enforce_formal_test_material_policy(
    public_key: Option<&PublicKeyFingerprintInput<'_>>,
    did: Option<&Did>,
    key_id: Option<&DidUrl>,
    trust_domain: Option<&TrustDomainId>,
) -> Result<(), FormalTestMaterialPolicyError> {
    let published_key_fingerprint = public_key
        .map(public_key_fingerprint)
        .transpose()?
        .filter(|fingerprint| PUBLISHED_TEST_KEY_FINGERPRINTS.contains(&fingerprint.as_str()));
    let reserved_identifiers = reserved_identifier_matches(did, key_id, trust_domain);
    if published_key_fingerprint.is_some() || reserved_identifiers.any() {
        return Err(TestMaterialDenied {
            published_key_fingerprint,
            reserved_identifiers,
        }
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use arkret_canonical::base64url::base64url_decode;
    use serde_json::Value;

    use super::*;

    fn registry() -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../arkret-spec/spec/v1/artifacts/registry/test-material-registry.json");
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn generated_matchers_equal_the_canonical_registry_examples() {
        let registry = registry();
        let fingerprints = registry["published_signing_material"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["fingerprint"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(fingerprints, PUBLISHED_TEST_KEY_FINGERPRINTS);

        for rule in registry["reserved_identifiers"].as_array().unwrap() {
            let kind = rule["kind"].as_str().unwrap();
            for example in rule["examples"].as_array().unwrap() {
                assert!(matches_identifier(kind, example.as_str().unwrap()));
            }
            for non_example in rule["non_examples"].as_array().unwrap() {
                assert!(!matches_identifier(kind, non_example.as_str().unwrap()));
            }
        }
    }

    /// `identity_examples` is the closed did:webvh occurrence inventory. Each
    /// value is matched by its own terminal: a bare DID by the `did` rule and a
    /// DID URL by the `key_id` fragment rule, independently of the DID it hangs
    /// under. Only `test_material` may enter the reserved namespace, and each
    /// `derived_positive` must recompute from its fixture JSON Pointer.
    #[test]
    fn identity_example_inventory_roles_follow_the_formal_policy() {
        const ROLES: [&str; 3] = [
            "test_material",
            "deployment_like_example",
            "derived_positive",
        ];
        let spec_root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../arkret-spec");
        let registry = registry();
        let rows = registry["identity_examples"].as_array().unwrap();
        assert!(!rows.is_empty());

        let mut roles_present = std::collections::BTreeSet::new();
        let mut values = std::collections::BTreeSet::new();
        for row in rows {
            let row = row.as_object().unwrap();
            let value = row["value"].as_str().unwrap();
            let role = row["role"].as_str().unwrap();
            assert!(ROLES.contains(&role), "{value}: unknown role {role}");
            assert!(values.insert(value), "{value}: duplicate inventory value");
            roles_present.insert(role);

            let mut expected_keys = std::collections::BTreeSet::from(["role", "sources", "value"]);
            if role == "derived_positive" {
                expected_keys.insert("derivation_ref");
            }
            assert_eq!(
                row.keys()
                    .map(String::as_str)
                    .collect::<std::collections::BTreeSet<_>>(),
                expected_keys,
                "{value}: inventory row key set"
            );
            assert!(value.starts_with("did:webvh:"), "{value}: not did:webvh");
            assert!(
                !row["sources"].as_array().unwrap().is_empty(),
                "{value}: sources must name every occurrence"
            );

            let (did, key_id) = if value.contains('#') {
                (None, Some(DidUrl::new(value).unwrap()))
            } else {
                (Some(Did::new(value).unwrap()), None)
            };
            let decision =
                enforce_formal_test_material_policy(None, did.as_ref(), key_id.as_ref(), None);
            if role == "test_material" {
                let Err(FormalTestMaterialPolicyError::Denied(denial)) = decision else {
                    panic!("{value}: test_material must be denied as reserved test material")
                };
                assert_eq!(denial.published_key_fingerprint, None);
                assert_eq!(
                    denial.reserved_identifiers,
                    ReservedIdentifierMatches {
                        did: did.is_some(),
                        key_id: key_id.is_some(),
                        trust_domain: false,
                    },
                    "{value}: exactly its own terminal rule must match"
                );
            } else {
                assert_eq!(
                    decision,
                    Ok(()),
                    "{value}: {role} must not enter the reserved namespace"
                );
            }

            if role == "derived_positive" {
                let reference = row["derivation_ref"].as_str().unwrap();
                let (file, pointer) = reference
                    .split_once('#')
                    .unwrap_or_else(|| panic!("{value}: derivation_ref lacks a JSON Pointer"));
                assert!(pointer.starts_with('/'), "{value}: pointer {pointer}");
                let fixture: Value =
                    serde_json::from_slice(&std::fs::read(spec_root.join(file)).unwrap()).unwrap();
                assert_eq!(
                    fixture.pointer(pointer).and_then(Value::as_str),
                    Some(value),
                    "{value}: derivation_ref {reference} must recompute the value"
                );
            }
        }
        assert_eq!(
            roles_present,
            ROLES.into_iter().collect::<std::collections::BTreeSet<_>>()
        );
    }

    fn matches_identifier(kind: &str, value: &str) -> bool {
        match kind {
            "did" => Did::new(value).is_ok_and(|value| is_reserved_test_did(&value)),
            "key_id" => DidUrl::new(value).is_ok_and(|value| is_reserved_test_key_id(&value)),
            "trust_domain" => {
                TrustDomainId::new(value).is_ok_and(|value| is_reserved_test_trust_domain(&value))
            }
            _ => panic!("unknown registry rule kind {kind}"),
        }
    }

    #[test]
    fn algorithm_defined_bytes_recompute_all_published_fingerprints() {
        let artifacts = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../arkret-spec/spec/v1/artifacts");
        let fixture: Value = serde_json::from_slice(
            &std::fs::read(artifacts.join("fixtures/crypto-signature-fixture.json")).unwrap(),
        )
        .unwrap();
        let vectors = fixture["vectors"].as_array().unwrap();

        let ed_x = vectors[0]["did_document_fragment"]["publicKeyJwk"]["x"]
            .as_str()
            .unwrap();
        let ed = base64url_decode(ed_x).unwrap();
        assert_eq!(
            public_key_fingerprint(&PublicKeyFingerprintInput::Ed25519Rfc8032(&ed)).unwrap(),
            PUBLISHED_TEST_KEY_FINGERPRINTS[0]
        );
        let reordered_jwk = serde_json::json!({
            "x": ed_x,
            "crv": "Ed25519",
            "kty": "OKP"
        });
        let jwk_bytes = arkret_signatures::PublicKeyMaterial::Jwk {
            value: reordered_jwk,
        }
        .ed25519_bytes()
        .unwrap();
        let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&jwk_bytes);
        let multibase_bytes =
            arkret_signatures::PublicKeyMaterial::Ed25519Multibase { value: multibase }
                .ed25519_bytes()
                .unwrap();
        assert_eq!(jwk_bytes, multibase_bytes);
        assert_eq!(
            public_key_fingerprint(&PublicKeyFingerprintInput::Ed25519Rfc8032(&multibase_bytes))
                .unwrap(),
            PUBLISHED_TEST_KEY_FINGERPRINTS[0]
        );

        let x = base64url_decode(
            vectors[1]["did_document_fragment"]["publicKeyJwk"]["x"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let y = base64url_decode(
            vectors[1]["did_document_fragment"]["publicKeyJwk"]["y"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let mut p256 = vec![0x04];
        p256.extend(x);
        p256.extend(y);
        assert_eq!(
            public_key_fingerprint(&PublicKeyFingerprintInput::P256Sec1Uncompressed(&p256))
                .unwrap(),
            PUBLISHED_TEST_KEY_FINGERPRINTS[1]
        );

        let mldsa = base64url_decode(vectors[2]["public_key_b64u"].as_str().unwrap()).unwrap();
        assert_eq!(
            public_key_fingerprint(&PublicKeyFingerprintInput::MlDsa65Fips204(&mldsa)).unwrap(),
            PUBLISHED_TEST_KEY_FINGERPRINTS[2]
        );

        let websocket: Value = serde_json::from_slice(
            &std::fs::read(artifacts.join("fixtures/websocket-binding-fixture.json")).unwrap(),
        )
        .unwrap();
        let rfc8032 =
            base64url_decode(websocket["dpop_kat"]["public_jwk"]["x"].as_str().unwrap()).unwrap();
        assert_eq!(
            public_key_fingerprint(&PublicKeyFingerprintInput::Ed25519Rfc8032(&rfc8032)).unwrap(),
            PUBLISHED_TEST_KEY_FINGERPRINTS[3]
        );
    }

    #[test]
    fn identifier_rules_are_independent_and_do_not_guess_by_words_or_suffixes() {
        let reserved_did = Did::new("did:webvh:z6mkfixture:alice.example").unwrap();
        let ordinary_key = DidUrl::new("did:webvh:z6mkfixture:alice.example#runtime-1").unwrap();
        let ordinary_domain = TrustDomainId::new("ak:trust_domain:examples.net").unwrap();
        assert_eq!(
            reserved_identifier_matches(
                Some(&reserved_did),
                Some(&ordinary_key),
                Some(&ordinary_domain)
            ),
            ReservedIdentifierMatches {
                did: true,
                key_id: false,
                trust_domain: false,
            }
        );

        let ordinary_did = Did::new("did:webvh:acmelive:acme.example").unwrap();
        let reserved_key =
            DidUrl::new("did:webvh:acmelive:acme.example#assertion-fixture").unwrap();
        assert_eq!(
            reserved_identifier_matches(Some(&ordinary_did), Some(&reserved_key), None),
            ReservedIdentifierMatches {
                did: false,
                key_id: true,
                trust_domain: false,
            }
        );

        let reserved_domain = TrustDomainId::new("ak:trust_domain:anything.test").unwrap();
        assert_eq!(
            reserved_identifier_matches(None, None, Some(&reserved_domain)),
            ReservedIdentifierMatches {
                did: false,
                key_id: false,
                trust_domain: true,
            }
        );
    }

    #[test]
    fn unlisted_ed25519_material_is_not_denied() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[91; 32]);
        let verifying_key = key.verifying_key();
        let material = PublicKeyFingerprintInput::Ed25519Rfc8032(verifying_key.as_bytes());
        assert!(!is_published_test_key(&material).unwrap());
        enforce_formal_test_material_policy(Some(&material), None, None, None).unwrap();
    }

    #[test]
    fn formal_guard_has_no_bypass_and_reports_each_independent_match() {
        let registry = registry();
        let fingerprint = registry["published_signing_material"][0]["fingerprint"]
            .as_str()
            .unwrap();
        assert_eq!(fingerprint, PUBLISHED_TEST_KEY_FINGERPRINTS[0]);
        let fixture: Value = serde_json::from_slice(
            &std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
                "../../../arkret-spec/spec/v1/artifacts/fixtures/crypto-signature-fixture.json",
            ))
            .unwrap(),
        )
        .unwrap();
        let bytes = base64url_decode(
            fixture["vectors"][0]["did_document_fragment"]["publicKeyJwk"]["x"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let key = PublicKeyFingerprintInput::Ed25519Rfc8032(&bytes);
        let ordinary_did = Did::new("did:webvh:acmelive:acme.example").unwrap();
        let reserved_key = DidUrl::new("did:webvh:acmelive:acme.example#key-fixture").unwrap();
        let denial = enforce_formal_test_material_policy(
            Some(&key),
            Some(&ordinary_did),
            Some(&reserved_key),
            None,
        )
        .unwrap_err();
        let FormalTestMaterialPolicyError::Denied(denial) = denial else {
            panic!("valid registered material must reach the denial decision")
        };
        assert_eq!(
            denial.published_key_fingerprint.as_deref(),
            Some(fingerprint)
        );
        assert_eq!(
            denial.reserved_identifiers,
            ReservedIdentifierMatches {
                did: false,
                key_id: true,
                trust_domain: false,
            }
        );
    }
}
