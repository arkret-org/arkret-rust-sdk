use arkret_identifiers::Hlc;
use arkret_models_crypto::MlsGovernanceBindingPayload;
use arkret_schema::embedded_json_artifact;
use arkret_wire::cursor::Cursor;
use serde_json::{Value, json};

/// Minimal hex decoder for fixture input_hex payloads.
fn hex_decode(input: &str) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return None;
    }
    (0..input.len())
        .step_by(2)
        .map(|idx| u8::from_str_radix(&input[idx..idx + 2], 16).ok())
        .collect()
}

#[test]
fn encoding_fixture_vectors_execute_against_sdk() {
    let fixture = embedded_json_artifact("fixtures/encoding-fixture.json").unwrap();
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
                let bytes = arkret_canonical::canonical_json_bytes(input)
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
                        arkret_canonical::sha256_digest(&bytes),
                        expected,
                        "{vector_id}: digest drifted"
                    );
                }
            }
            "canonical_json_with_ciphertext_digest" => {
                let metadata = vector
                    .get("payload_metadata")
                    .expect("vector missing payload_metadata");
                let metadata_bytes = arkret_canonical::canonical_json_bytes(metadata).unwrap();
                assert_eq!(
                    std::str::from_utf8(&metadata_bytes).unwrap(),
                    vector["expected_metadata_canonical_bytes_utf8"]
                        .as_str()
                        .unwrap(),
                    "{vector_id}: metadata canonical bytes drifted"
                );
                let ciphertext = arkret_canonical::base64url_decode(
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
                    arkret_canonical::sha256_digest(&digest_input),
                    vector["expected_digest"].as_str().unwrap(),
                    "{vector_id}: envelope digest drifted"
                );
                assert_eq!(
                    arkret_canonical::canonical_sha256(&metadata["aad"]).unwrap(),
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
                                arkret_canonical::parse_canonical_json(raw.as_bytes()).is_err(),
                                "{vector_id}: raw literal {literal} must reject"
                            );
                        } else if entry.get("n_literal").is_some() {
                            // JSON number 1.0: reject at both the value layer
                            // (float in canonical emit) and the raw ingress.
                            assert!(
                                arkret_canonical::canonical_json_bytes(&json!({"n": 1.0})).is_err(),
                                "{vector_id}: float value 1.0 must reject"
                            );
                            assert!(
                                arkret_canonical::parse_canonical_json(br#"{"n":1.0}"#).is_err(),
                                "{vector_id}: raw 1.0 must reject"
                            );
                        } else if entry.get("n_literal_alt").is_some() {
                            assert!(
                                arkret_canonical::parse_canonical_json(br#"{"n":1e0}"#).is_err(),
                                "{vector_id}: raw 1e0 must reject"
                            );
                        } else {
                            panic!("{vector_id}: unknown rejected_inputs entry {entry}");
                        }
                    }
                    // rules: "-0 MUST reject".
                    assert!(
                        arkret_canonical::parse_canonical_json(br#"{"n":-0}"#).is_err(),
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
                            arkret_canonical::parse_canonical_json(raw).is_err(),
                            "{vector_id}: raw input {:?} must reject",
                            String::from_utf8_lossy(raw)
                        );
                    }
                }
            }
            "canonical_json_reject_raw" => {
                let cases = vector
                    .get("cases")
                    .and_then(Value::as_array)
                    .map(|cases| cases.iter().collect::<Vec<_>>())
                    .unwrap_or_else(|| vec![vector]);
                for case in cases {
                    let name = case["name"].as_str().unwrap_or("direct");
                    let input_hex = case
                        .get("input_hex")
                        .and_then(Value::as_str)
                        .unwrap_or_else(|| panic!("{vector_id}/{name}: missing input_hex"));
                    let bytes = hex_decode(input_hex).unwrap_or_else(|| {
                        panic!("{vector_id}/{name}: input_hex is not valid hex")
                    });
                    match arkret_canonical::parse_canonical_json(&bytes) {
                        Err(_) => {}
                        Ok(value) => {
                            // The bytes are canonical JSON; the rejection layer is
                            // the typed field validator (malformed HLC case).
                            let hlc =
                                value.get("hlc").and_then(Value::as_str).unwrap_or_else(|| {
                                    panic!(
                                        "{vector_id}/{name}: input unexpectedly accepted end-to-end"
                                    )
                                });
                            assert!(
                                Hlc::new(hlc).is_err(),
                                "{vector_id}/{name}: malformed HLC {hlc:?} must reject"
                            );
                        }
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
                    .map(|value| Hlc::new(value.as_str().unwrap()).unwrap())
                    .collect::<Vec<_>>();
                hlcs.sort();
                let sorted = hlcs.iter().map(Hlc::as_str).collect::<Vec<_>>();
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
                let last = Hlc::new(vector["input"]["last_emitted_hlc"].as_str().unwrap()).unwrap();
                let outcomes = vector["expected_acceptable_outcomes"].as_array().unwrap();
                let wait_outcome = outcomes
                    .iter()
                    .filter_map(Value::as_str)
                    .find_map(|outcome| outcome.split("then emit ").nth(1))
                    .expect("overflow vector must describe the wait-then-emit outcome");
                let waited = Hlc::new(wait_outcome.trim()).unwrap();
                assert!(waited > last, "{vector_id}: waited HLC must sort after");
                let wrapped = Hlc::new("01970e589d21-0000-a13f9c2e").unwrap();
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
                let bytes = arkret_canonical::base64url_decode(body).unwrap();
                let expected = vector["decoded_payload_canonical_bytes_utf8"]
                    .as_str()
                    .unwrap();
                assert_eq!(
                    std::str::from_utf8(&bytes).unwrap(),
                    expected,
                    "{vector_id}: decoded cursor payload drifted"
                );
                // The payload is byte-for-byte canonical JSON.
                arkret_canonical::validate_canonical_bytes(&bytes).unwrap();
                // The wire shape parses into the v1 core cursor body and
                // round-trips verbatim (client opaqueness: same bytes out).
                let cursor: Cursor = arkret_canonical::from_canonical_json_slice(&bytes).unwrap();
                assert_eq!(cursor.v, "1", "{vector_id}: cursor version drifted");
                let reencoded = arkret_canonical::canonical_json_bytes(&cursor).unwrap();
                assert_eq!(
                    reencoded, bytes,
                    "{vector_id}: cursor re-encode not verbatim"
                );
                assert_eq!(
                    format!(
                        "ak:cursor:{}",
                        arkret_canonical::base64url_encode(&reencoded)
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
                    arkret_canonical::parse_canonical_json(&build_nested(depth)).is_err(),
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
                    arkret_canonical::parse_canonical_json(mixed.as_bytes()).is_err(),
                    "{vector_id}: mixed depth-{depth} nesting must reject"
                );
                // Control: depth exactly 64 is inclusive and MUST be accepted.
                arkret_canonical::parse_canonical_json(&build_nested(depth - 1)).unwrap_or_else(
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
                    MlsGovernanceBindingPayload::from_deterministic_cbor(&bytes).is_err(),
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
                let err = MlsGovernanceBindingPayload::from_deterministic_cbor(&raw)
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
                    let multibase = arkret_canonical::ed25519_pubkey_to_did_key_multibase(&key);
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
                    let decoded = arkret_canonical::decode_ed25519_multibase(&multibase)
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
                    arkret_canonical::blake3_digest(input.as_bytes()),
                    expected_digest,
                    "{vector_id}: blake3 digest drifted"
                );
                arkret_canonical::verify_digest(input.as_bytes(), expected_digest).unwrap_or_else(
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
                            arkret_canonical::verify_digest(input.as_bytes(), value).is_err(),
                            "{vector_id}/{name}: verify_digest must reject {value}"
                        );
                    }
                }
            }
            "open_registry_unknown_roundtrip" => {
                let input = vector
                    .get("input")
                    .unwrap_or_else(|| panic!("{vector_id}: missing input"));
                let unknown = input["registry_value"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{vector_id}: registry_value must be a string"));
                let encoded =
                    arkret_canonical::canonical_json_bytes(input).unwrap_or_else(|error| {
                        panic!("{vector_id}: canonical encode failed: {error}")
                    });
                assert_eq!(
                    encoded,
                    vector["expected_canonical_bytes_utf8"]
                        .as_str()
                        .unwrap()
                        .as_bytes(),
                    "{vector_id}: canonical bytes drifted"
                );
                let decoded: Value = arkret_canonical::from_canonical_json_slice(&encoded)
                    .unwrap_or_else(|error| panic!("{vector_id}: decode failed: {error}"));
                assert_eq!(
                    decoded["registry_value"].as_str(),
                    Some(unknown),
                    "{vector_id}: unknown open-registry value was not preserved"
                );
            }
            "extension_slot_canonical_roundtrip" => {
                let input = vector
                    .get("input")
                    .unwrap_or_else(|| panic!("{vector_id}: missing input"));
                let expected = vector["expected_canonical_bytes_utf8"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{vector_id}: missing expected canonical bytes"))
                    .as_bytes();
                let mut bytes =
                    arkret_canonical::canonical_json_bytes(input).unwrap_or_else(|error| {
                        panic!("{vector_id}: canonical encode failed: {error}")
                    });
                assert_eq!(bytes, expected, "{vector_id}: initial bytes drifted");
                for stage in ["store_reload", "federation_forward", "backfill"] {
                    let decoded: Value = arkret_canonical::from_canonical_json_slice(&bytes)
                        .unwrap_or_else(|error| {
                            panic!("{vector_id}: {stage} decode failed: {error}")
                        });
                    bytes =
                        arkret_canonical::canonical_json_bytes(&decoded).unwrap_or_else(|error| {
                            panic!("{vector_id}: {stage} re-encode failed: {error}")
                        });
                    assert_eq!(
                        bytes, expected,
                        "{vector_id}: {stage} did not preserve extension bytes"
                    );
                }
            }
            "canonical_event_tie_break" => {
                // encoding.md 4.2: one winner rule for both concurrent
                // candidate sets and logical-slot equivocation candidate sets.
                // The key is the DECODED digest octets, bytewise greatest, with
                // the canonical suite id as a second key only when the octets
                // are identical. Comparing the typed `<suite>:<hex>` wire string
                // would let the suite name decide before the content does.
                let comparison = vector
                    .get("comparison")
                    .unwrap_or_else(|| panic!("{vector_id}: missing comparison"));
                for forbidden in comparison["forbidden_keys"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{vector_id}: missing forbidden_keys"))
                {
                    let key = forbidden.as_str().unwrap();
                    assert!(
                        !key.is_empty(),
                        "{vector_id}: forbidden tie-break key must be named"
                    );
                }
                let cases = vector["cases"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{vector_id}: missing cases"));
                for case in cases {
                    let case_name = case["name"].as_str().unwrap();
                    let Some(expected_winner) = case.get("expected_winner").and_then(Value::as_str)
                    else {
                        // Non-ordering cases (duplicate idempotence, collision
                        // fail-closed, proofs-only difference) are executed by
                        // the ordered-log lattice suite, which owns the slot
                        // state machine. Here we only assert they are declared.
                        assert!(
                            case.get("expected").is_some(),
                            "{vector_id}/{case_name}: case declares neither expected_winner nor expected"
                        );
                        continue;
                    };
                    let candidates = case["candidates"].as_array().unwrap();
                    let mut best: Option<(&str, Vec<u8>, &str)> = None;
                    for candidate in candidates {
                        let label = candidate["label"].as_str().unwrap();
                        let wire = candidate["event_digest"].as_str().unwrap_or_else(|| {
                            panic!("{vector_id}/{case_name}: ordering case needs event_digest")
                        });
                        let (suite, hex_digits) = wire.split_once(':').unwrap_or_else(|| {
                            panic!("{vector_id}/{case_name}: typed digest must be <suite>:<hex>")
                        });
                        let octets = hex::decode(hex_digits).unwrap_or_else(|error| {
                            panic!("{vector_id}/{case_name}: digest hex decode failed: {error}")
                        });
                        let replace = match &best {
                            None => true,
                            Some((_, best_octets, best_suite)) => {
                                (octets.as_slice(), suite) > (best_octets.as_slice(), *best_suite)
                            }
                        };
                        if replace {
                            best = Some((label, octets, suite));
                        }
                    }
                    let (winner, ..) =
                        best.unwrap_or_else(|| panic!("{vector_id}/{case_name}: no candidates"));
                    assert_eq!(
                        winner, expected_winner,
                        "{vector_id}/{case_name}: decoded-octet winner drifted"
                    );
                    if let Some(wrong) = case
                        .get("expected_wrong_winner_if_wire_string_compared")
                        .and_then(Value::as_str)
                    {
                        let wire_winner = candidates
                            .iter()
                            .max_by_key(|candidate| candidate["event_digest"].as_str().unwrap())
                            .map(|candidate| candidate["label"].as_str().unwrap())
                            .unwrap();
                        assert_eq!(
                            wire_winner, wrong,
                            "{vector_id}/{case_name}: the wire-string trap case no longer traps"
                        );
                        assert_ne!(
                            wire_winner, expected_winner,
                            "{vector_id}/{case_name}: transition case must disagree with the wire-string order"
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
