use super::*;

fn local_spec_artifacts_dir() -> Option<PathBuf> {
    if let Some(dir) = default_spec_artifacts_dir() {
        return Some(dir);
    }
    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join("arkret-spec")
        .join("spec")
        .join("v1")
        .join("artifacts");
    candidate.is_dir().then_some(candidate)
}

fn collect_json_artifact_paths(root: &Path, dir: &Path, out: &mut BTreeSet<String>) {
    let entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", dir.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|error| panic!("failed to read entry in {}: {error}", dir.display()))
            .path();
        if path.is_dir() {
            collect_json_artifact_paths(root, &path, out);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            let rel = path
                .strip_prefix(root)
                .unwrap_or_else(|error| {
                    panic!(
                        "failed to strip {} from {}: {error}",
                        root.display(),
                        path.display()
                    )
                })
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel);
        }
    }
}

#[test]
fn embedded_spec_artifacts_match_live_spec_when_available() {
    let Some(artifacts_dir) = local_spec_artifacts_dir() else {
        // Without a spec checkout this drift gate cannot run. By default it
        // skips (downstream consumers build the SDK without the spec repo),
        // but environments that exist to enforce the gate — CI with a spec
        // co-checkout, release runners — set ARKRET_REQUIRE_SPEC=1 so a
        // missing/misconfigured spec path fails loudly instead of silently
        // passing (SDK-TEST-07).
        if std::env::var("ARKRET_REQUIRE_SPEC").as_deref() == Ok("1") {
            panic!(
                "ARKRET_REQUIRE_SPEC=1 but no spec artifacts directory was found; \
                 set ARKRET_SPEC_ARTIFACTS or provide a ../arkret-spec co-checkout"
            );
        }
        return;
    };
    let embedded: BTreeSet<String> = embedded_spec_artifact_paths()
        .expect("embedded artifacts must load")
        .into_iter()
        .collect();
    let mut live = BTreeSet::new();
    collect_json_artifact_paths(&artifacts_dir, &artifacts_dir, &mut live);

    assert_eq!(embedded, live, "embedded spec artifact path set drifted");
    for path in live {
        let live_path = artifacts_dir.join(&path);
        let live_text = fs::read_to_string(&live_path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", live_path.display()));
        let live_value: Value = serde_json::from_str(&live_text)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", live_path.display()));
        let embedded_value = read_embedded_json_artifact(&path)
            .unwrap_or_else(|error| panic!("embedded artifact {path} failed to load: {error}"));
        assert_eq!(embedded_value, live_value, "artifact {path} drifted");
    }
}

fn fixture_artifact(name: &str) -> Value {
    if let Some(artifacts_dir) = default_spec_artifacts_dir() {
        let path = artifacts_dir.join("fixtures").join(name);
        let text = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
        serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
    } else {
        read_embedded_json_artifact(&format!("fixtures/{name}")).unwrap()
    }
}

fn assert_warns_additional_field(warnings: &[String], field: &str) {
    assert!(
        warnings
            .iter()
            .any(|warning| warning.contains("additional field") && warning.contains(field)),
        "expected warning for additional field {field:?}, got {warnings:?}"
    );
}

#[test]
fn schema_catalog_reports_all_registered_schemas() {
    let catalog = schema_catalog();
    catalog.validate().unwrap();
    assert!(
        catalog
            .entries
            .iter()
            .any(|entry| entry.schema_id == EVENT_SCHEMA)
    );
}

#[test]
fn schema_vectors_include_negative_security_extension_case() {
    validate_schema_vectors(&built_in_schema_vectors()).unwrap();
}

#[test]
fn federation_fixture_expected_digest_matches_sdk_canonicalizer() {
    let fixture = fixture_artifact("federation-fixture.json");
    let cases = fixture
        .get("cases")
        .and_then(Value::as_array)
        .expect("federation fixture missing cases");
    let case = cases
        .iter()
        .find(|case| {
            case.get("name").and_then(Value::as_str)
                == Some("reducer_profile_digest_federation_minimal")
        })
        .expect("federation fixture missing reducer_profile_digest_federation_minimal");
    let canonical_input = case
        .get("canonical_input")
        .expect("federation reducer profile fixture missing canonical_input");
    let expected_digest = case
        .get("expected_digest")
        .and_then(Value::as_str)
        .expect("federation reducer profile fixture missing expected_digest");

    assert_eq!(
        crate::canonical::canonical_sha256(canonical_input).unwrap(),
        expected_digest
    );
}

/// Execute every vector in the spec `encoding-fixture.json` against the SDK's
/// first-party implementations (canonical JSON, digests, HLC ordering, cursor
/// opaqueness, base64url). Unknown vector kinds fail the test so newly added
/// spec vectors cannot be silently skipped.
#[test]
fn encoding_fixture_vectors_execute_against_sdk() {
    let fixture = fixture_artifact("encoding-fixture.json");
    let vectors = fixture
        .get("vectors")
        .and_then(Value::as_array)
        .expect("encoding fixture missing vectors");
    assert!(!vectors.is_empty());

    for vector in vectors {
        let vector_id = vector
            .get("vector_id")
            .and_then(Value::as_str)
            .expect("encoding vector missing vector_id");
        let kind = vector
            .get("kind")
            .and_then(Value::as_str)
            .expect("encoding vector missing kind");
        match kind {
            "canonical_json" | "canonical_json_digest" => {
                let input = vector.get("input").expect("vector missing input");
                let bytes = crate::canonical::canonical_json_bytes(input)
                    .unwrap_or_else(|error| panic!("{vector_id}: canonicalize failed: {error}"));
                if let Some(expected) = vector
                    .get("expected_canonical_bytes_utf8")
                    .and_then(Value::as_str)
                {
                    assert_eq!(
                        std::str::from_utf8(&bytes).unwrap(),
                        expected,
                        "{vector_id}: canonical bytes drifted"
                    );
                }
                if let Some(expected) = vector.get("expected_digest").and_then(Value::as_str) {
                    assert_eq!(
                        crate::canonical::sha256_digest(&bytes),
                        expected,
                        "{vector_id}: digest drifted"
                    );
                }
            }
            "canonical_json_with_ciphertext_digest" => {
                let metadata = vector
                    .get("payload_metadata")
                    .expect("vector missing payload_metadata");
                let metadata_bytes = crate::canonical::canonical_json_bytes(metadata).unwrap();
                assert_eq!(
                    std::str::from_utf8(&metadata_bytes).unwrap(),
                    vector["expected_metadata_canonical_bytes_utf8"]
                        .as_str()
                        .unwrap(),
                    "{vector_id}: metadata canonical bytes drifted"
                );
                let ciphertext = crate::base64url::base64url_decode(
                    vector["ciphertext_base64url"].as_str().unwrap(),
                )
                .unwrap();
                assert_eq!(
                    ciphertext,
                    vector["ciphertext_bytes_utf8"].as_str().unwrap().as_bytes(),
                    "{vector_id}: ciphertext base64url decode drifted"
                );
                let mut digest_input = metadata_bytes;
                digest_input.extend_from_slice(&ciphertext);
                assert_eq!(
                    crate::canonical::sha256_digest(&digest_input),
                    vector["expected_digest"].as_str().unwrap(),
                    "{vector_id}: envelope digest drifted"
                );
                assert_eq!(
                    crate::canonical::canonical_sha256(&metadata["aad"]).unwrap(),
                    vector["aad_digest"].as_str().unwrap(),
                    "{vector_id}: aad digest drifted"
                );
            }
            "canonical_json_reject" => {
                if let Some(rejected) = vector.get("rejected_inputs").and_then(Value::as_array) {
                    for entry in rejected {
                        if let Some(literal) = entry.get("n").and_then(Value::as_str) {
                            // The fixture carries non-JSON literals (NaN /
                            // Infinity / -Infinity) as strings; reconstruct
                            // the raw JSON text they describe.
                            let raw = format!("{{\"n\":{literal}}}");
                            assert!(
                                crate::canonical::parse_canonical_json(raw.as_bytes()).is_err(),
                                "{vector_id}: raw literal {literal} must reject"
                            );
                        } else if entry.get("n_literal").is_some() {
                            // JSON number 1.0: reject at both the value layer
                            // (float in canonical emit) and the raw ingress.
                            assert!(
                                crate::canonical::canonical_json_bytes(&json!({"n": 1.0})).is_err(),
                                "{vector_id}: float value 1.0 must reject"
                            );
                            assert!(
                                crate::canonical::parse_canonical_json(br#"{"n":1.0}"#).is_err(),
                                "{vector_id}: raw 1.0 must reject"
                            );
                        } else if entry.get("n_literal_alt").is_some() {
                            assert!(
                                crate::canonical::parse_canonical_json(br#"{"n":1e0}"#).is_err(),
                                "{vector_id}: raw 1e0 must reject"
                            );
                        } else {
                            panic!("{vector_id}: unknown rejected_inputs entry {entry}");
                        }
                    }
                    // rules: "-0 MUST reject".
                    assert!(
                        crate::canonical::parse_canonical_json(br#"{"n":-0}"#).is_err(),
                        "{vector_id}: raw -0 must reject"
                    );
                } else {
                    // reject_malformed_json: prose input classes; execute one
                    // representative raw input per declared class.
                    let classes = vector
                        .get("rejected_input_classes")
                        .and_then(Value::as_array)
                        .unwrap_or_else(|| panic!("{vector_id}: missing rejected_input_classes"));
                    assert!(!classes.is_empty());
                    let representatives: [&[u8]; 5] = [
                        b"{\"a\":\"\xff\"}",  // malformed UTF-8
                        br#"{"a":1,"a":2}"#,  // duplicate keys
                        br#"{"a":"\ud800"}"#, // lone surrogate escape
                        br#"{"n":NaN}"#,      // non-standard literal
                        br#"{"n":1.5}"#,      // non-integer number
                    ];
                    for raw in representatives {
                        assert!(
                            crate::canonical::parse_canonical_json(raw).is_err(),
                            "{vector_id}: raw input {:?} must reject",
                            String::from_utf8_lossy(raw)
                        );
                    }
                }
            }
            "canonical_json_reject_raw" => {
                let input_hex = vector
                    .get("input_hex")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("{vector_id}: missing input_hex"));
                let bytes = hex_decode(input_hex)
                    .unwrap_or_else(|| panic!("{vector_id}: input_hex is not valid hex"));
                match crate::canonical::parse_canonical_json(&bytes) {
                    Err(_) => {}
                    Ok(value) => {
                        // The bytes are canonical JSON; the rejection layer is
                        // the typed field validator (malformed HLC case).
                        let hlc = value.get("hlc").and_then(Value::as_str).unwrap_or_else(|| {
                            panic!("{vector_id}: input unexpectedly accepted end-to-end")
                        });
                        assert!(
                            crate::Hlc::new(hlc).is_err(),
                            "{vector_id}: malformed HLC {hlc:?} must reject"
                        );
                    }
                }
            }
            "ordering" => {
                let inputs = vector
                    .get("input")
                    .and_then(Value::as_array)
                    .unwrap_or_else(|| panic!("{vector_id}: missing input array"));
                let mut hlcs = inputs
                    .iter()
                    .map(|value| crate::Hlc::new(value.as_str().unwrap()).unwrap())
                    .collect::<Vec<_>>();
                hlcs.sort();
                let sorted = hlcs.iter().map(crate::Hlc::as_str).collect::<Vec<_>>();
                let expected = vector["expected_ascending"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap())
                    .collect::<Vec<_>>();
                assert_eq!(sorted, expected, "{vector_id}: HLC ordering drifted");
            }
            "producer_constraint" => {
                // hlc_logical_overflow: the saturated HLC parses, and the
                // "wait for the next millisecond" outcome sorts strictly
                // after it while a wrap-around would sort before it (the
                // declared fail condition). The producer-side error path is
                // exercised by `arkret::hlc` generator tests.
                let last =
                    crate::Hlc::new(vector["input"]["last_emitted_hlc"].as_str().unwrap()).unwrap();
                let outcomes = vector["expected_acceptable_outcomes"].as_array().unwrap();
                let wait_outcome = outcomes
                    .iter()
                    .filter_map(Value::as_str)
                    .find_map(|outcome| outcome.split("then emit ").nth(1))
                    .expect("overflow vector must describe the wait-then-emit outcome");
                let waited = crate::Hlc::new(wait_outcome.trim()).unwrap();
                assert!(waited > last, "{vector_id}: waited HLC must sort after");
                let wrapped = crate::Hlc::new("01970e589d21-0000-a13f9c2e").unwrap();
                assert!(
                    wrapped < last,
                    "{vector_id}: a wrapped logical counter sorts before the last emitted HLC"
                );
            }
            "cursor_opaqueness" => {
                let token = vector["input_cursor"].as_str().unwrap();
                let body = token
                    .strip_prefix("ak:cursor:")
                    .unwrap_or_else(|| panic!("{vector_id}: cursor missing ak:cursor: prefix"));
                let bytes = crate::base64url::base64url_decode(body).unwrap();
                let expected = vector["decoded_payload_canonical_bytes_utf8"]
                    .as_str()
                    .unwrap();
                assert_eq!(
                    std::str::from_utf8(&bytes).unwrap(),
                    expected,
                    "{vector_id}: decoded cursor payload drifted"
                );
                // The payload is byte-for-byte canonical JSON.
                crate::canonical::validate_canonical_bytes(&bytes).unwrap();
                // The wire shape parses into the v1 core cursor body and
                // round-trips verbatim (client opaqueness: same bytes out).
                let cursor: crate::cursor::Cursor =
                    crate::canonical::from_canonical_json_slice(&bytes).unwrap();
                assert_eq!(cursor.v, "1", "{vector_id}: cursor version drifted");
                let reencoded = crate::canonical::canonical_json_bytes(&cursor).unwrap();
                assert_eq!(
                    reencoded, bytes,
                    "{vector_id}: cursor re-encode not verbatim"
                );
                assert_eq!(
                    format!(
                        "ak:cursor:{}",
                        crate::base64url::base64url_encode(&reencoded)
                    ),
                    token,
                    "{vector_id}: cursor token round-trip not verbatim"
                );
            }
            "canonical_json_reject_generated" => {
                // Generator-described input (the fixture stores parameters,
                // the runner builds the literal): deep-nesting depth cap.
                let generator = vector.get("generator").expect("vector missing generator");
                assert_eq!(generator["kind"].as_str().unwrap(), "deep_nesting");
                let depth = generator["nesting_depth"].as_u64().unwrap() as usize;
                let build_nested = |levels: usize| -> Vec<u8> {
                    let mut raw = String::new();
                    for _ in 0..levels {
                        raw.push_str("{\"a\":");
                    }
                    raw.push('1');
                    for _ in 0..levels {
                        raw.push('}');
                    }
                    raw.into_bytes()
                };
                assert!(
                    crate::canonical::parse_canonical_json(&build_nested(depth)).is_err(),
                    "{vector_id}: depth-{depth} object must reject"
                );
                // Mixed object/array variant of the same depth must also reject.
                let mut mixed = String::new();
                for level in 0..depth {
                    mixed.push_str(if level % 2 == 0 { "{\"a\":" } else { "[" });
                }
                mixed.push('1');
                for level in (0..depth).rev() {
                    mixed.push(if level % 2 == 0 { '}' } else { ']' });
                }
                assert!(
                    crate::canonical::parse_canonical_json(mixed.as_bytes()).is_err(),
                    "{vector_id}: mixed depth-{depth} nesting must reject"
                );
                // Control: depth exactly 64 is inclusive and MUST be accepted.
                crate::canonical::parse_canonical_json(&build_nested(depth - 1)).unwrap_or_else(
                    |error| {
                        panic!(
                            "{vector_id}: depth-{} control must accept: {error}",
                            depth - 1
                        )
                    },
                );
            }
            "cbor_reject_raw" => {
                let input_hex = vector
                    .get("input_hex")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("{vector_id}: missing input_hex"));
                let bytes = hex_decode(input_hex)
                    .unwrap_or_else(|| panic!("{vector_id}: input_hex is not valid hex"));
                assert!(
                    crate::models::MlsGovernanceBindingPayload::from_deterministic_cbor(&bytes)
                        .is_err(),
                    "{vector_id}: raw CBOR must reject"
                );
            }
            "cbor_reject_generated" => {
                let generator = vector.get("generator").expect("vector missing generator");
                assert_eq!(generator["kind"].as_str().unwrap(), "cbor_array_items");
                let count = generator["array_item_count"].as_u64().unwrap();
                // Per the fixture rule: definite-length array header declaring
                // `count` items followed by `count` encodings of unsigned
                // integer 0 (one byte each).
                let mut raw: Vec<u8> = vec![0x9a];
                raw.extend_from_slice(&(count as u32).to_be_bytes());
                raw.extend(std::iter::repeat_n(0x00u8, count as usize));
                let err = crate::models::MlsGovernanceBindingPayload::from_deterministic_cbor(&raw)
                    .expect_err("oversized CBOR array must reject");
                assert!(
                    err.to_string().contains("65536"),
                    "{vector_id}: rejection must be the container-item bound, got: {err}"
                );
            }
            "multibase_did_key" => {
                // ak.vector.encoding.multibase_did_key.core.v1: base58btc
                // multibase of Ed25519 public keys (0xed01 multicodec prefix)
                // and the resulting did:key identifier, plus decode round-trip.
                let cases = vector
                    .get("cases")
                    .and_then(Value::as_array)
                    .unwrap_or_else(|| panic!("{vector_id}: missing cases"));
                for case in cases {
                    let label = case["label"].as_str().unwrap_or("<unlabelled>");
                    let key_bytes = hex_decode(case["public_key_hex"].as_str().unwrap())
                        .unwrap_or_else(|| panic!("{vector_id}/{label}: bad public_key_hex"));
                    let key: [u8; 32] = key_bytes
                        .as_slice()
                        .try_into()
                        .unwrap_or_else(|_| panic!("{vector_id}/{label}: key must be 32 bytes"));
                    let multibase = crate::multibase::ed25519_pubkey_to_did_key_multibase(&key);
                    assert_eq!(
                        multibase,
                        case["expected_multibase"].as_str().unwrap(),
                        "{vector_id}/{label}: multibase encoding drift"
                    );
                    assert_eq!(
                        format!("did:key:{multibase}"),
                        case["expected_did_key"].as_str().unwrap(),
                        "{vector_id}/{label}: did:key identifier drift"
                    );
                    let decoded = crate::multibase::decode_ed25519_multibase(&multibase)
                        .unwrap_or_else(|error| {
                            panic!("{vector_id}/{label}: decode round-trip failed: {error}")
                        });
                    assert_eq!(decoded, key, "{vector_id}/{label}: decode round-trip drift");
                }
            }
            "blake3_digest" => {
                // ak.vector.encoding.digest.blake3.v1: typed `blake3:<hex>`
                // digest over the UTF-8 input, plus suite-mismatch rejections.
                let input = vector
                    .get("input_utf8")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("{vector_id}: missing input_utf8"));
                if let Some(expected_hex) = vector.get("expected_input_hex").and_then(Value::as_str)
                {
                    assert_eq!(
                        hex::encode(input.as_bytes()),
                        expected_hex,
                        "{vector_id}: input bytes drifted"
                    );
                }
                let expected_digest = vector
                    .get("expected_digest")
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("{vector_id}: missing expected_digest"));
                assert_eq!(
                    crate::canonical::blake3_digest(input.as_bytes()),
                    expected_digest,
                    "{vector_id}: blake3 digest drifted"
                );
                crate::canonical::verify_digest(input.as_bytes(), expected_digest).unwrap_or_else(
                    |error| {
                        panic!("{vector_id}: verify_digest must accept the golden value: {error}")
                    },
                );
                for case in vector
                    .get("negative_cases")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let name = case["name"].as_str().unwrap_or("<unnamed>");
                    let value = case["value"]
                        .as_str()
                        .unwrap_or_else(|| panic!("{vector_id}/{name}: missing value"));
                    if let Some(realm_suite) =
                        case.get("realm_digest_algorithm").and_then(Value::as_str)
                    {
                        // Suite-policy case: the realm pins a digest suite, so
                        // any other (or unknown) suite prefix must be treated
                        // as a mismatch even when the digest bytes themselves
                        // verify. The driver checks the prefix discipline the
                        // validators enforce.
                        assert!(
                            !value.starts_with(&format!("{realm_suite}:")),
                            "{vector_id}/{name}: value unexpectedly matches the realm suite"
                        );
                    } else {
                        // Content case: the typed digest itself must fail
                        // verification (wrong suite for these bytes, or a
                        // malformed / truncated hex payload).
                        assert!(
                            crate::canonical::verify_digest(input.as_bytes(), value).is_err(),
                            "{vector_id}/{name}: verify_digest must reject {value}"
                        );
                    }
                }
            }
            other => {
                panic!("encoding vector {vector_id} has unknown kind {other}; extend this driver")
            }
        }
    }

    // Top-level rank_order block: hex-Base32 rank strings order items by
    // plain byte comparison in the fixed single-character profile.
    let rank_order = fixture
        .get("rank_order")
        .and_then(Value::as_array)
        .expect("encoding fixture missing rank_order");
    let mut sorted = rank_order.clone();
    sorted.sort_by(|left, right| {
        left["rank"]
            .as_str()
            .unwrap()
            .cmp(right["rank"].as_str().unwrap())
    });
    let actual = sorted
        .iter()
        .map(|entry| entry["strand_id"].as_str().unwrap())
        .collect::<Vec<_>>();
    let expected = fixture["expected_order"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry.as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(actual, expected, "rank_order drifted");
}

/// Minimal hex decoder for fixture `input_hex` payloads.
fn hex_decode(input: &str) -> Option<Vec<u8>> {
    if input.len() % 2 != 0 {
        return None;
    }
    (0..input.len())
        .step_by(2)
        .map(|idx| u8::from_str_radix(&input[idx..idx + 2], 16).ok())
        .collect()
}

#[test]
fn event_payload_catalog_validates_known_payload_fields() {
    let catalog = event_payload_validator_catalog().unwrap();
    // `ak.strand.move` payload requires Space container ids:
    // `board_space_id` (ak:space prefix) + `target_space_id`.
    catalog
        .validate_payload(
            "ak.strand.move",
            &json!({
                "board_space_id": "ak:space:01904100-0000-7000-8000-111111111111",
                "strand_id": "ak:strand:01904100-0000-7000-8000-6c663fa0205f",
                "target_space_id": "ak:space:01904100-0000-7000-8000-222222222222",
                "rank": "U"
            }),
        )
        .unwrap();
    assert!(matches!(
        catalog.validate_payload(
            "ak.strand.move",
            &json!({
                "strand_id": "ak:strand:01904100-0000-7000-8000-6c663fa0205f",
                "target_space_id": "ak:space:01904100-0000-7000-8000-222222222222",
                "rank": "U"
            })
        ),
        Err(Error::Protocol(_))
    ));
}

#[test]
fn relation_create_payload_strong_type_passes_spec_validator() {
    let catalog = event_payload_validator_catalog().unwrap();
    let payload = crate::models::RelationCreatePayload::new(
        "ak.relation.parent_of",
        "ak:strand:01904100-0000-7000-8000-111111111111",
        "ak:strand:01904100-0000-7000-8000-222222222222",
    )
    .with_rank("U");
    catalog
        .validate_payload("ak.relation.create", &payload.to_value().unwrap())
        .unwrap();

    // Unknown additive keys are reported but do not fail schema validation.
    let mut leaky = payload.to_value().unwrap();
    leaky["fields"] = json!({"role": "x"});
    let warnings = catalog
        .validate_payload_with_warnings("ak.relation.create", &leaky)
        .unwrap();
    assert_warns_additional_field(&warnings, "fields");
}

#[test]
fn membership_payload_strong_type_passes_spec_validator() {
    use crate::models::{DeliveryStatus, MembershipPayload, MembershipPayloadState};
    let catalog = event_payload_validator_catalog().unwrap();

    // invite transition (non-join): only `membership` is structurally required.
    let invite = MembershipPayload::transition(
        MembershipPayloadState::Invite,
        crate::models::Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
        "space_create",
    );
    catalog
        .validate_payload("ak.member.state", &invite.to_value().unwrap())
        .unwrap();

    // join transition (unroutable): realm_id + actor_id + delivery_status
    // required, but delivery_binding only when routable.
    let join = MembershipPayload::join(
        crate::models::RealmId::new("ak:realm:01904100-0000-7000-8000-111111111111").unwrap(),
        crate::models::Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
        DeliveryStatus::Unroutable,
        "invite_accept",
    )
    .with_invite_ref("ak:event:01904100-0000-7000-8000-222222222222");
    catalog
        .validate_payload("ak.member.state", &join.to_value().unwrap())
        .unwrap();

    // join missing delivery_status is rejected by to_value (conditional req).
    let mut bad = join;
    bad.delivery_status = None;
    assert!(matches!(bad.to_value(), Err(Error::Protocol(_))));

    // Unknown additive keys are reported but do not fail schema validation.
    let mut leaky = invite.to_value().unwrap();
    leaky["handle"] = json!("bob:example.com");
    let warnings = catalog
        .validate_payload_with_warnings("ak.member.state", &leaky)
        .unwrap();
    assert_warns_additional_field(&warnings, "handle");
}

#[test]
fn invite_payload_strong_types_pass_spec_validator() {
    use crate::models::{
        Did, Hash, InviteCreatePayload, InviteDeliveryTarget, InviteId, InviteRefPayload,
    };
    let catalog = event_payload_validator_catalog().unwrap();

    // Directed-create (anyOf branch: invitee + invite_delivery_target +
    // introduction_evidence_digest + expires_at), with an `x_role` extension.
    let create = InviteCreatePayload::new(
        InviteId::new("ak:invite:01904100-0000-7000-8000-111111111111").unwrap(),
        Did::new("did:webvh:z6mkfixture:bob.example").unwrap(),
        InviteDeliveryTarget::principal_server(
            Did::new("did:webvh:z6mkfixture:ps.example").unwrap(),
        ),
        Hash::new("sha256:".to_owned() + &"a".repeat(64)).unwrap(),
        chrono::Utc::now() + chrono::Duration::days(7),
    )
    .with_extension("role", json!("member"));
    let create_value = create.to_value().unwrap();
    assert_eq!(create_value["x_role"], "member");
    catalog
        .validate_payload("ak.invite.create", &create_value)
        .unwrap();
    InviteCreatePayload::from_wire_value(&create_value).unwrap();
    let mut leaky_create = create_value;
    leaky_create["hlc"] = json!("2026-06-14T10:00:00Z/node/1");
    assert!(InviteCreatePayload::from_wire_value(&leaky_create).is_err());

    // invite_id ref form (accept / cancel / revoke).
    let cancel = InviteRefPayload::new(
        InviteId::new("ak:invite:01904100-0000-7000-8000-222222222222").unwrap(),
    )
    .with_reason("withdrawn");
    let cancel_value = cancel.to_value().unwrap();
    catalog
        .validate_payload("ak.invite.cancel", &cancel_value)
        .unwrap();
    catalog
        .validate_payload("ak.invite.revoke", &cancel_value)
        .unwrap();
}

#[test]
fn realm_lifecycle_payloads_strong_types_pass_spec_validator() {
    use crate::models::{
        RealmArchivePayload, RealmDestroyPayload, RealmFreezePayload, RealmId,
        RealmTombstonePayload,
    };
    let catalog = event_payload_validator_catalog().unwrap();

    // ak.realm.archive: reversible boolean register; `archived:false` un-archives.
    let archive = RealmArchivePayload::new(true).with_reason("retiring inactive realm");
    catalog
        .validate_payload("ak.realm.archive", &archive.to_value().unwrap())
        .unwrap();
    catalog
        .validate_payload(
            "ak.realm.archive",
            &RealmArchivePayload::new(false).to_value().unwrap(),
        )
        .unwrap();

    // ak.realm.freeze: reversible boolean register; `frozen:false` unfreezes.
    let freeze = RealmFreezePayload::new(true).with_reason("incident response hold");
    catalog
        .validate_payload("ak.realm.freeze", &freeze.to_value().unwrap())
        .unwrap();
    catalog
        .validate_payload(
            "ak.realm.freeze",
            &RealmFreezePayload::new(false).to_value().unwrap(),
        )
        .unwrap();

    // ak.realm.tombstone: reason + successor_realm_id both required by spec.
    let tombstone = RealmTombstonePayload::new(
        RealmId::new("ak:realm:01904100-0000-7000-8000-333333333333").unwrap(),
        "migrated to successor",
    );
    catalog
        .validate_payload("ak.realm.tombstone", &tombstone.to_value().unwrap())
        .unwrap();

    // ak.realm.destroy: reason required; verification_stub_required omitted so
    // the reducer applies its default (true).
    let destroy = RealmDestroyPayload::new("permanent retirement");
    catalog
        .validate_payload("ak.realm.destroy", &destroy.to_value().unwrap())
        .unwrap();

    // Unknown additive keys are reported but do not fail schema validation.
    let mut leaky = archive.to_value().unwrap();
    leaky["successor_realm_id"] = json!("ak:realm:01904100-0000-7000-8000-444444444444");
    let warnings = catalog
        .validate_payload_with_warnings("ak.realm.archive", &leaky)
        .unwrap();
    assert_warns_additional_field(&warnings, "successor_realm_id");
}

#[test]
fn strand_lifecycle_payloads_strong_types_pass_spec_validator() {
    use crate::models::{
        Did, ObjectLifecyclePayload, SpaceId, StrandId, StrandMovePayload,
        StrandReorderExpectedPosition, StrandReorderPayload, StrandWatchExpectedValue,
        StrandWatchLevel, StrandWatchSetPayload,
    };
    let catalog = event_payload_validator_catalog().unwrap();
    let board = || SpaceId::new("ak:space:01904100-0000-7000-8000-111111111111").unwrap();
    let target = || SpaceId::new("ak:space:01904100-0000-7000-8000-222222222222").unwrap();
    let strand = || StrandId::new("ak:strand:01904100-0000-7000-8000-6c663fa0205f").unwrap();
    let actor = || Did::new("did:webvh:z6mkfixture:alice.example").unwrap();

    // ak.strand.move — board/target Space ids + rank; from_space_id +
    // expected_position optional. Destination is single-sourced by
    // target_space_id (a stray `list_space_id` is reported as additive).
    let mv = StrandMovePayload::new(board(), strand(), target(), "U")
        .with_from_space_id(board())
        .with_expected_position(crate::models::StrandMoveExpectedPosition {
            space_id: Some(board()),
            rank: Some("T".to_owned()),
            relation_id: None,
        });
    catalog
        .validate_payload("ak.strand.move", &mv.to_value().unwrap())
        .unwrap();

    // ak.strand.reorder — single List Space (`space_id`); no destination field.
    let reorder = StrandReorderPayload::new(board(), strand(), target(), "V")
        .with_expected_position(StrandReorderExpectedPosition {
            rank: Some("U".to_owned()),
            relation_id: None,
        });
    catalog
        .validate_payload("ak.strand.reorder", &reorder.to_value().unwrap())
        .unwrap();

    // ak.strand.watch.set — concrete level + clear (level:null) + CAS guard.
    let set = StrandWatchSetPayload::set(strand(), actor(), StrandWatchLevel::All, Some(true));
    catalog
        .validate_payload("ak.strand.watch.set", &set.to_value().unwrap())
        .unwrap();
    let cleared = StrandWatchSetPayload::clear(strand(), actor());
    let cleared_value = cleared.to_value().unwrap();
    assert!(cleared_value["level"].is_null());
    // allOf: level_public MUST be omitted when level is null.
    assert!(cleared_value.get("level_public").is_none());
    catalog
        .validate_payload("ak.strand.watch.set", &cleared_value)
        .unwrap();
    let guarded =
        StrandWatchSetPayload::set(strand(), actor(), StrandWatchLevel::Participating, None)
            .with_expected_value(Some(StrandWatchExpectedValue {
                level: StrandWatchLevel::Muted,
                level_public: None,
            }));
    catalog
        .validate_payload("ak.strand.watch.set", &guarded.to_value().unwrap())
        .unwrap();
    // expected_value may also assert "no prior cell" via null.
    let guarded_null = StrandWatchSetPayload::set(strand(), actor(), StrandWatchLevel::All, None)
        .with_expected_value(None);
    let guarded_null_value = guarded_null.to_value().unwrap();
    assert!(guarded_null_value["expected_value"].is_null());
    catalog
        .validate_payload("ak.strand.watch.set", &guarded_null_value)
        .unwrap();

    // ak.strand.archive / ak.strand.restore — object_lifecycle_payload, single
    // truth source `target_ref`.
    let archive = ObjectLifecyclePayload::new("ak:strand:01904100-0000-7000-8000-6c663fa0205f")
        .with_target_state("archived")
        .with_reason("season closed");
    catalog
        .validate_payload("ak.strand.archive", &archive.to_value().unwrap())
        .unwrap();
    catalog
        .validate_payload(
            "ak.strand.restore",
            &ObjectLifecyclePayload::new("ak:strand:01904100-0000-7000-8000-6c663fa0205f")
                .to_value()
                .unwrap(),
        )
        .unwrap();

    // Unknown additive keys are reported but do not fail schema validation.
    let mut leaky = mv.to_value().unwrap();
    leaky["list_space_id"] = json!("ak:space:01904100-0000-7000-8000-222222222222");
    let warnings = catalog
        .validate_payload_with_warnings("ak.strand.move", &leaky)
        .unwrap();
    assert_warns_additional_field(&warnings, "list_space_id");
}

#[test]
fn realm_state_payloads_strong_types_match_named_spec_defs() {
    // Validate the strong types directly against the named `$defs/*_payload`
    // schema_ref so this test stays pinned to the exact artifact shape.
    use crate::models::{
        Did, HistoryKeyShareDefault, HistoryKeySource, HistorySharingPolicyPayload,
        HistorySharingPolicyPayloadValue, HistorySharingPolicyPayloadValueAudit, HistoryVisibility,
        HistoryVisibilityPayload, PlaintextDataClassKind, PlaintextServiceVisibility,
        PlaintextVisibleService, PlaintextVisibleServicesPayload,
    };
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let registry = schema_registry_from_spec_artifacts(&artifacts_dir).unwrap();
    let catalog = event_payload_validator_catalog_from_spec_artifacts(&artifacts_dir).unwrap();
    let history_ref = format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/history_visibility_payload");
    let history_policy_ref =
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/history_sharing_policy_payload");
    let services_ref = format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/plaintext_visible_services_payload");

    // history_visibility: non-restricted value carries just `{value}`.
    let shared = HistoryVisibilityPayload::new(HistoryVisibility::Shared);
    registry
        .validate_value(&history_ref, &shared.to_value().unwrap())
        .unwrap();
    catalog
        .validate_payload(
            crate::events::REALM_HISTORY_VISIBILITY,
            &shared.to_value().unwrap(),
        )
        .unwrap();
    // restricted requires restricted_policy_digest (schema allOf); to_value
    // refuses to emit a non-conformant restricted payload.
    assert!(
        HistoryVisibilityPayload::new(HistoryVisibility::Restricted)
            .to_value()
            .is_err()
    );
    let restricted = HistoryVisibilityPayload::restricted("sha256:".to_owned() + &"a".repeat(64));
    registry
        .validate_value(&history_ref, &restricted.to_value().unwrap())
        .unwrap();
    // Unknown additive keys are reported but do not fail schema validation.
    let mut leaky = shared.to_value().unwrap();
    leaky["unexpected"] = json!(true);
    let warnings = registry
        .validate_value_with_warnings(&history_ref, &leaky)
        .unwrap();
    assert_warns_additional_field(&warnings, "unexpected");

    let history_policy = HistorySharingPolicyPayload {
        value: HistorySharingPolicyPayloadValue {
            version: 1,
            default_key_share: HistoryKeyShareDefault::EventTimeVisibility,
            pre_join_history: None,
            post_removal_recovery: None,
            allowed_key_sources: vec![HistoryKeySource::VerifiedMemberDevice],
            allowed_receiver_states: None,
            audit: HistorySharingPolicyPayloadValueAudit {
                share_audit_event_required: false,
                access_audit_required: false,
            },
            restricted_rules: None,
        },
        reason: None,
    };
    let history_policy_value = serde_json::to_value(&history_policy).unwrap();
    registry
        .validate_value(&history_policy_ref, &history_policy_value)
        .unwrap();
    catalog
        .validate_payload(
            crate::events::REALM_HISTORY_SHARING_POLICY,
            &history_policy_value,
        )
        .unwrap();

    // plaintext_visible_services: required item fields strongly typed.
    let services = PlaintextVisibleServicesPayload::new(vec![PlaintextVisibleService::new(
        Did::new("did:webvh:z6mkfixture:index.example").unwrap(),
        "principal_server",
        vec![
            PlaintextDataClassKind::MessageContent,
            PlaintextDataClassKind::FullTextIndex,
            PlaintextDataClassKind::NotificationSummary,
            PlaintextDataClassKind::InboxPreview,
        ],
        vec!["message_index".to_owned(), "notification_fanout".to_owned()],
        PlaintextServiceVisibility::PrivatePlaintext,
    )]);
    registry
        .validate_value(&services_ref, &services.to_value().unwrap())
        .unwrap();
    // Top-level additive keys are warnings, not schema violations.
    let mut leaky_services = services.to_value().unwrap();
    leaky_services["unexpected"] = json!(true);
    let warnings = registry
        .validate_value_with_warnings(&services_ref, &leaky_services)
        .unwrap();
    assert_warns_additional_field(&warnings, "unexpected");
}

#[test]
fn artifact_payload_catalog_enforces_deep_schema_rules() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();
    // `ak.strand.move` requires current Space container ids:
    // `board_space_id` and `target_space_id`.
    catalog
        .validate_payload(
            crate::events::STRAND_MOVE,
            &json!({
                "board_space_id": "ak:space:01904100-0000-7000-8000-111111111111",
                "strand_id": "ak:strand:01904100-0000-7000-8000-6c663fa0205f",
                "target_space_id": "ak:space:01904100-0000-7000-8000-222222222222",
                "rank": "U"
            }),
        )
        .unwrap();
    assert!(
        catalog
            .validate_payload(
                crate::events::STRAND_MOVE,
                &json!({
                    "board_space_id": "not-a-space-id",
                    "strand_id": "ak:strand:01904100-0000-7000-8000-6c663fa0205f",
                    "target_space_id": "ak:space:01904100-0000-7000-8000-222222222222",
                    "rank": "U"
                }),
            )
            .is_err()
    );
    let warnings = catalog
        .validate_payload_with_warnings(
            crate::events::STRAND_MOVE,
            &json!({
                "board_space_id": "ak:space:01904100-0000-7000-8000-111111111111",
                "strand_id": "ak:strand:01904100-0000-7000-8000-6c663fa0205f",
                "target_space_id": "ak:space:01904100-0000-7000-8000-222222222222",
                "rank": "U",
                "unexpected": true
            }),
        )
        .unwrap();
    assert_warns_additional_field(&warnings, "unexpected");
}

#[test]
fn artifact_payload_catalog_prefers_registered_specialized_defs_over_name_matches() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();

    assert_eq!(
        catalog.rules["ak.space.archive"].payload_schema_id,
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/space_state_transition_payload")
    );
    assert_eq!(
        catalog.rules["ak.space.restore"].payload_schema_id,
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/space_state_transition_payload")
    );
    assert_eq!(
        catalog.rules["ak.space.tombstone"].payload_schema_id,
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/space_object_tombstone_payload")
    );

    catalog
        .validate_payload(
            "ak.space.archive",
            &json!({
                "space_id": "ak:space:01904100-0000-7000-8000-111111111111",
                "reason": "done"
            }),
        )
        .unwrap();
    assert!(
        catalog
            .validate_payload("ak.space.archive", &json!({ "archived": true }))
            .is_err()
    );
}

#[test]
fn artifact_payload_catalog_maps_patch_event_family_to_canonical_payloads() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();
    let patch_kinds = [
        (
            "ak.realm.update",
            "object_patch_payload",
            json!({
                "target_ref": "ak:realm:0196419b-0000-7000-8000-000000000001",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
        ),
        (
            "ak.strand.update",
            "strand_patch_payload",
            json!({
                "target_ref": "ak:strand:0196419b-0000-7000-8000-000000000001",
                "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
            }),
        ),
        (
            "ak.morph.update",
            "morph_update_payload",
            json!({
                "target_ref": "ak:morph:0196419b-0000-7000-8000-000000000001",
                "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
            }),
        ),
        (
            "ak.space.update",
            "space_patch_payload",
            json!({
                "space_id": "ak:space:0196419b-0000-7000-8000-000000000001",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
        ),
        (
            "ak.profile.update",
            "object_patch_payload",
            json!({
                "target_ref": "ak:actor_profile:0196419b-0000-7000-8000-000000000001",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
        ),
    ];
    for (event_kind, payload_def, payload) in patch_kinds {
        assert_eq!(
            catalog.rules[event_kind].payload_schema_id,
            format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/{payload_def}"),
            "{event_kind} must use the canonical patch payload schema"
        );
        catalog
            .validate_payload(event_kind, &payload)
            .unwrap_or_else(|err| panic!("{event_kind} should accept {payload_def}: {err}"));
    }
    // ak.profile.realm_override carries a Realm-scoped override and needs
    // target_realm_id in addition to target_ref+patch, so the spec gives it a
    // dedicated profile_realm_override_payload def rather than folding it into
    // the generic object_patch_payload.
    assert_eq!(
        catalog.rules["ak.profile.realm_override"].payload_schema_id,
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/profile_realm_override_payload"),
        "ak.profile.realm_override must use the dedicated profile_realm_override_payload schema"
    );
    catalog
        .validate_payload(
            "ak.profile.realm_override",
            &json!({
                "target_ref": "ak:actor_profile:0196419b-0000-7000-8000-000000000001",
                "target_realm_id": "ak:realm:0196419b-0000-7000-8000-000000000002",
                "patch": { "title": { "$op": "set", "value": "Roadmap" } }
            }),
        )
        .unwrap_or_else(|err| {
            panic!("ak.profile.realm_override should accept profile_realm_override_payload: {err}")
        });
    assert_eq!(
        catalog.rules["ak.strand.tracks.update"].payload_schema_id,
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/generic_standard_payload"),
        "ak.strand.tracks.update has dedicated track-table semantics and must not be folded into object_patch_payload"
    );
    catalog
        .validate_payload(
            "ak.strand.tracks.update",
            &json!({
                "strand_id": "ak:strand:0196419b-0000-7000-8000-000000000001",
                "tracks": {
                    "main": { "title": "Main", "rank": "a0" }
                }
            }),
        )
        .unwrap_or_else(|err| {
            panic!("ak.strand.tracks.update should accept track payloads: {err}")
        });
    assert!(
        catalog
            .validate_payload(
                "ak.strand.tracks.update",
                &json!({
                    "type": "ak.strand.tracks.update",
                    "strand_id": "ak:strand:0196419b-0000-7000-8000-000000000001"
                }),
            )
            .is_err(),
        "ak.strand.tracks.update must still reject the retired type discriminator"
    );
    assert!(
        catalog
            .validate_payload(
                "ak.strand.update",
                &json!({
                    "target_ref": "ak:morph:0196419b-0000-7000-8000-000000000001",
                    "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
                }),
            )
            .is_err(),
        "ak.strand.update target_ref must be a Strand id"
    );
}

#[test]
fn morph_update_payload_rejects_create_locked_morph_type() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();

    catalog
        .validate_payload(
            "ak.morph.update",
            &json!({
                "target_ref": "ak:morph:0196419b-0000-7000-8000-000000000001",
                "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
            }),
        )
        .unwrap();
    assert!(
        catalog
            .validate_payload(
                "ak.morph.update",
                &json!({
                    "target_ref": "ak:morph:0196419b-0000-7000-8000-000000000001",
                    "patch": { "morph_type": { "$op": "set", "value": "task" } }
                }),
            )
            .is_err(),
        "ak.morph.update must reject create-locked morph_type changes"
    );
    assert!(
        catalog
            .validate_payload(
                "ak.morph.update",
                &json!({
                    "target_ref": "ak:strand:0196419b-0000-7000-8000-000000000001",
                    "patch": { "metadata.title": { "$op": "set", "value": "Roadmap" } }
                }),
            )
            .is_err(),
        "ak.morph.update target_ref must be a Morph id"
    );
}

#[test]
fn artifact_payload_catalog_enforces_invite_create_payload_shape() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();
    let payload = json!({
        "invite_id": "ak:invite:01904100-0000-7000-8000-000000000001",
        "invitee": "did:webvh:z6mkfixture:bob.example",
        "invite_delivery_target": {
            "recipient_service_id": "did:webvh:z6mkfixture:server.example",
            "recipient_service_type": "principal_server"
        },
        "introduction_evidence_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "expires_at": "2026-06-14T10:00:00Z",
        "x_role": "member"
    });

    assert_eq!(
        catalog.rules[crate::events::INVITE_CREATE].payload_schema_id,
        format!("{EVENT_PAYLOAD_SCHEMA}#/$defs/invite_payload")
    );
    assert!(
        catalog.rules[crate::events::INVITE_CREATE]
            .required_fields
            .iter()
            .any(|field| field == "invite_id"),
        "ak.invite.create must require invite_id"
    );
    catalog
        .validate_payload(crate::events::INVITE_CREATE, &payload)
        .unwrap_or_else(|err| panic!("ak.invite.create should accept directed invite: {err}"));

    let mut missing_invite_id = payload.clone();
    missing_invite_id
        .as_object_mut()
        .unwrap()
        .remove("invite_id");
    assert!(
        catalog
            .validate_payload(crate::events::INVITE_CREATE, &missing_invite_id)
            .is_err(),
        "ak.invite.create must reject directed invite payloads without invite_id"
    );

    let mut missing_expires_at = payload;
    missing_expires_at
        .as_object_mut()
        .unwrap()
        .remove("expires_at");
    assert!(
        catalog
            .validate_payload(crate::events::INVITE_CREATE, &missing_expires_at)
            .is_err(),
        "ak.invite.create must reject directed invite payloads without expires_at"
    );
}

#[test]
fn artifact_payload_catalog_enforces_external_schema_refs_and_enums() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let catalog = event_payload_validator_catalog_from_spec_artifacts(artifacts_dir).unwrap();
    let key = json!({
        "kid": "did:webvh:z6mkfixture:alice.example#psk-1",
        "alg": "EdDSA",
        "public_key": "z6MkiExample",
        "key_format": "multibase"
    });
    let subordinate_key = json!({
        "kid": "did:webvh:z6mkfixture:alice.example#ssk-1",
        "alg": "EdDSA",
        "public_key": "z6MkiExampleSub",
        "key_format": "multibase",
        "binding": {
            "verification_method": "did:webvh:z6mkfixture:alice.example#psk-1",
            "alg": "EdDSA",
            "signature": "sig"
        }
    });
    catalog
        .validate_payload(
            crate::events::CROSS_SIGNING_PUBLISH,
            &json!({
                "principal_id": "did:webvh:z6mkfixture:alice.example",
                "trust_domain": "ak:trust_domain:example.net",
                "principal_signing_key": key,
                "self_signing_key": subordinate_key,
                "user_signing_key": subordinate_key,
                "expected_previous_generation": 0,
                "generation": 1,
                "issued_at": "2026-05-02T00:00:00Z"
            }),
        )
        .unwrap();
    assert!(
        catalog
            .validate_payload(
                crate::events::CROSS_SIGNING_PUBLISH,
                &json!({
                    "principal_id": "did:webvh:z6mkfixture:alice.example",
                    "principal_signing_key": key,
                    "self_signing_key": subordinate_key,
                    "user_signing_key": subordinate_key,
                    "generation": 0,
                    "issued_at": "2026-05-02T00:00:00Z"
                }),
            )
            .is_err()
    );
}

#[test]
fn schema_registry_enforces_json_schema_composition_and_value_rules() {
    let mut registry = ProtocolSchemaRegistry::new();
    registry.register(
        "ak.schema.deep_test.v1",
        json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "ak.schema.deep_test.v1",
            "type": "object",
            "required": ["kind", "items", "target"],
            "properties": {
                "kind": {"const": "demo"},
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string", "pattern": "^[a-z]+$"}
                },
                "target": {
                    "oneOf": [
                        {"type": "string", "enum": ["user", "space"]},
                        {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}
                    ]
                }
            },
            "allOf": [{"properties": {"kind": {"type": "string"}}}],
            "patternProperties": {
                "^x_[a-z][a-z0-9_]{0,63}$": {"type": "string"}
            },
            "additionalProperties": false
        }),
    );
    registry
        .validate_value(
            "ak.schema.deep_test.v1",
            &json!({"kind": "demo", "items": ["alpha"], "target": "user", "x_role": "member"}),
        )
        .unwrap();
    assert!(
        registry
            .validate_value(
                "ak.schema.deep_test.v1",
                &json!({"kind": "demo", "items": [], "target": "user"}),
            )
            .is_err()
    );
    assert!(
        registry
            .validate_value(
                "ak.schema.deep_test.v1",
                &json!({"kind": "demo", "items": ["alpha"], "target": "other"}),
            )
            .is_err()
    );
    assert!(
        registry
            .validate_value(
                "ak.schema.deep_test.v1",
                &json!({"kind": "other", "items": ["alpha"], "target": "user"}),
            )
            .is_err()
    );
    let warnings = registry
        .validate_value_with_warnings(
            "ak.schema.deep_test.v1",
            &json!({"kind": "demo", "items": ["alpha"], "target": "user", "extra": true}),
        )
        .unwrap();
    assert_warns_additional_field(&warnings, "extra");
    assert!(
        registry
            .validate_value(
                "ak.schema.deep_test.v1",
                &json!({"kind": "demo", "items": ["alpha"], "target": "user", "x_role": false}),
            )
            .is_err()
    );
}

#[test]
fn component_descriptor_resolves_canonical_and_alias_kinds() {
    let Some(artifacts_dir) = default_spec_artifacts_dir() else {
        return;
    };
    let bundle = SpecArtifactBundle::load(artifacts_dir).unwrap();

    // Canonical kind owns its slot — no alias_of.
    let canonical = bundle
        .component("ak.capability.grant")
        .unwrap()
        .expect("ak.capability.grant should be registered");
    assert_eq!(canonical.criticality, Criticality::Required);
    assert!(canonical.component_type.starts_with("ak.component."));
    assert!(canonical.component_version >= 1);
    assert!(canonical.component_slot_alias_of.is_none());

    // Alias kind shares the canonical kind's slot.
    let alias = bundle
        .component("ak.capability.revoke")
        .unwrap()
        .expect("ak.capability.revoke should be registered");
    assert_eq!(
        alias.component_slot_alias_of.as_deref(),
        Some("ak.capability.grant"),
        "ak.capability.revoke should slot-alias ak.capability.grant"
    );
    assert_eq!(alias.component_type, canonical.component_type);
    assert_eq!(alias.component_version, canonical.component_version);

    // Unknown kind is a clean None, not an error.
    assert!(bundle.component("ak.bogus.kind").unwrap().is_none());
}

#[test]
fn evolution_plan_rejects_breaking_release_candidate() {
    let mut breaking_changes = BTreeSet::new();
    breaking_changes.insert(SchemaBreakingChange::NewRequiredField);
    let plan = SchemaEvolutionPlan {
        from_version: "0.1.0".to_owned(),
        to_version: "0.2.0".to_owned(),
        affected_schemas: vec![EVENT_SCHEMA.to_owned()],
        breaking_changes,
    };
    assert!(matches!(
        plan.validate_release_candidate(),
        Err(Error::Protocol(_))
    ));
}
