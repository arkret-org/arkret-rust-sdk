use arkret_identifiers::Hlc;
use arkret_models_crypto::MlsGovernanceBindingPayload;
use arkret_schema::embedded_json_artifact;
use arkret_wire::EventKind;
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
            "canonical_minimal_encrypted_envelope_digest" => {
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
                        .get("rejected_input_categories")
                        .and_then(Value::as_array)
                        .unwrap_or_else(|| {
                            panic!("{vector_id}: missing rejected_input_categories")
                        });
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
                let comparison = vector
                    .get("comparison")
                    .unwrap_or_else(|| panic!("{vector_id}: missing comparison"));
                assert_eq!(comparison["semantic_winner_allowed"], false);
                assert_eq!(vector["producer_bias"]["semantic_winner_allowed"], false);
                assert!(
                    vector["producer_bias"]["prohibited_consumers"]
                        .as_array()
                        .is_some_and(|consumers| consumers.len() >= 7),
                    "{vector_id}: semantic consumers must remain explicitly prohibited"
                );
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
                    let Some(expected_order) = case.get("expected_order").and_then(Value::as_array)
                    else {
                        assert!(case.get("expected").is_some());
                        continue;
                    };
                    let candidates = case["candidates"].as_array().unwrap();
                    let mut ordered = Vec::<(&str, Vec<u8>, &str)>::new();
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
                        ordered.push((label, octets, suite));
                    }
                    ordered.sort_by(|left, right| {
                        (left.1.as_slice(), left.2).cmp(&(right.1.as_slice(), right.2))
                    });
                    let labels = ordered.iter().map(|entry| entry.0).collect::<Vec<_>>();
                    let expected = expected_order
                        .iter()
                        .map(|label| label.as_str().unwrap())
                        .collect::<Vec<_>>();
                    assert_eq!(
                        labels, expected,
                        "{vector_id}/{case_name}: decoded-octet presentation order drifted"
                    );
                    assert!(case.get("expected_winner").is_none_or(Value::is_null));
                    if let Some(wrong) = case
                        .get("expected_wrong_order_if_wire_string_compared")
                        .and_then(Value::as_array)
                    {
                        let mut wire_order = candidates.iter().collect::<Vec<_>>();
                        wire_order
                            .sort_by_key(|candidate| candidate["event_digest"].as_str().unwrap());
                        let wire_labels = wire_order
                            .iter()
                            .map(|candidate| candidate["label"].as_str().unwrap())
                            .collect::<Vec<_>>();
                        let wrong = wrong
                            .iter()
                            .map(|label| label.as_str().unwrap())
                            .collect::<Vec<_>>();
                        assert_eq!(
                            wire_labels, wrong,
                            "{vector_id}/{case_name}: the wire-string trap case no longer traps"
                        );
                        assert_ne!(
                            wire_labels, expected,
                            "{vector_id}/{case_name}: transition case must disagree with the wire-string order"
                        );
                    }
                }
            }
            "string_set_digest_composite_subject" => {
                let source = &vector["source_descriptor"];
                let event_kind = source["event_kind"].as_str().unwrap();
                let descriptor = EventKind::try_new(event_kind)
                    .and_then(|kind| kind.descriptor())
                    .unwrap_or_else(|| panic!("{vector_id}: source event kind is not registered"));
                assert_eq!(descriptor.cell_writes.len(), 1);
                let write = descriptor.cell_writes[0];
                assert_eq!(
                    write.cell_family.map(|family| family.as_str()),
                    source["cell_family"].as_str(),
                    "{vector_id}: source cell family drifted"
                );
                let registered_rule = write.cell_subject_rule.unwrap().to_json_value();
                assert_eq!(
                    registered_rule["components"], source["components"],
                    "{vector_id}: fixture sources drifted from the generated descriptor"
                );

                let set_descriptor = &source["components"][2];
                assert_eq!(set_descriptor["kind"], "string_set_digest");
                assert_eq!(set_descriptor["field"], "payload.accountability_scope");
                let context = set_descriptor["context"].as_str().unwrap();
                let issuer = vector["issuer_id"].as_str().unwrap();
                let subject = vector["subject_id"].as_str().unwrap();
                let allowed = ["agent_operator", "contracted_service", "employment"];
                let mut subjects = std::collections::BTreeMap::new();

                for case in vector["positive_cases"].as_array().unwrap() {
                    let name = case["name"].as_str().unwrap();
                    let values = match &case["input"] {
                        Value::String(value) => vec![value.clone()],
                        Value::Array(values) => values
                            .iter()
                            .map(|value| value.as_str().unwrap().to_owned())
                            .collect(),
                        _ => panic!("{vector_id}/{name}: positive scope has invalid shape"),
                    };
                    assert!(
                        values.iter().all(|value| allowed.contains(&value.as_str())),
                        "{vector_id}/{name}: positive scope is outside the closed vocabulary"
                    );
                    let component = arkret_wire::string_set_digest_component(&values, context)
                        .unwrap_or_else(|error| panic!("{vector_id}/{name}: {error}"));
                    assert_eq!(
                        component,
                        case["scope_set_component"].as_str().unwrap(),
                        "{vector_id}/{name}: scope-set component drifted"
                    );
                    let cell_subject = arkret_wire::composite_subject(&[
                        Value::String(issuer.to_owned()),
                        Value::String(subject.to_owned()),
                        Value::String(component),
                    ])
                    .unwrap();
                    assert_eq!(
                        cell_subject,
                        case["cell_subject"].as_str().unwrap(),
                        "{vector_id}/{name}: outer composite subject drifted"
                    );
                    subjects.insert(name, cell_subject);
                }
                for case in vector["positive_cases"].as_array().unwrap() {
                    if let Some(equivalent) = case.get("equivalent_to").and_then(Value::as_str) {
                        assert_eq!(
                            subjects[case["name"].as_str().unwrap()],
                            subjects[equivalent],
                            "{vector_id}: equivalent set encodings diverged"
                        );
                    }
                }

                for case in vector["negative_cases"].as_array().unwrap() {
                    let name = case["name"].as_str().unwrap();
                    match name {
                        "wrong_context" => {
                            let wrong = arkret_wire::string_set_digest_component(
                                &["employment".to_owned()],
                                case["context"].as_str().unwrap(),
                            )
                            .unwrap();
                            assert_ne!(
                                wrong,
                                vector["positive_cases"][0]["scope_set_component"]
                                    .as_str()
                                    .unwrap(),
                                "{vector_id}: context separation failed"
                            );
                        }
                        _ => {
                            let values = match &case["input"] {
                                Value::String(value) if allowed.contains(&value.as_str()) => {
                                    Some(vec![value.clone()])
                                }
                                Value::Array(values)
                                    if values.iter().all(Value::is_string)
                                        && values.iter().all(|value| {
                                            allowed.contains(&value.as_str().unwrap())
                                        }) =>
                                {
                                    Some(
                                        values
                                            .iter()
                                            .map(|value| value.as_str().unwrap().to_owned())
                                            .collect::<Vec<_>>(),
                                    )
                                }
                                _ => None,
                            };
                            assert!(
                                values.is_none_or(|values| {
                                    arkret_wire::string_set_digest_component(&values, context)
                                        .is_err()
                                }),
                                "{vector_id}/{name}: invalid scope was accepted"
                            );
                            assert_eq!(case["expected_error"], "schema_violation");
                        }
                    }
                }
            }
            "typed_composite_subject" => {
                let source = &vector["source_descriptor"];
                let event_kind = source["event_kind"].as_str().unwrap();
                let descriptor = EventKind::try_new(event_kind)
                    .and_then(|kind| kind.descriptor())
                    .unwrap_or_else(|| panic!("{vector_id}: source event kind is not registered"));
                assert_eq!(descriptor.cell_writes.len(), 1);
                let write = descriptor.cell_writes[0];
                assert_eq!(
                    write.cell_family.map(|family| family.as_str()),
                    source["cell_family"].as_str(),
                    "{vector_id}: source cell family drifted"
                );
                let registered_rule = write
                    .cell_subject_rule
                    .unwrap_or_else(|| panic!("{vector_id}: source subject rule is missing"))
                    .to_json_value();
                assert_eq!(
                    registered_rule["kind"], "composite",
                    "{vector_id}: registered subject is not composite"
                );
                assert_eq!(
                    registered_rule["components"], source["components"],
                    "{vector_id}: fixture sources drifted from the generated descriptor"
                );

                let cases = vector["positive_cases"]
                    .as_array()
                    .unwrap_or_else(|| panic!("{vector_id}: missing positive_cases"));
                let mut subjects = std::collections::BTreeMap::new();
                for case in cases {
                    let name = case["name"].as_str().unwrap();
                    let components = case["components_array"].as_array().unwrap();
                    let bytes = arkret_canonical::canonical_json_bytes(components).unwrap_or_else(
                        |error| panic!("{vector_id}/{name}: canonicalize failed: {error}"),
                    );
                    if let Some(expected) = case
                        .get("expected_canonical_bytes_utf8")
                        .and_then(Value::as_str)
                    {
                        assert_eq!(
                            std::str::from_utf8(&bytes).unwrap(),
                            expected,
                            "{vector_id}/{name}: canonical bytes drifted"
                        );
                    }
                    let subject = arkret_wire::composite_subject(components)
                        .unwrap_or_else(|error| panic!("{vector_id}/{name}: {error}"));
                    assert_eq!(
                        subject,
                        case["expected_subject"].as_str().unwrap(),
                        "{vector_id}/{name}: composite subject drifted"
                    );
                    assert!(
                        subjects.insert(name, subject).is_none(),
                        "{vector_id}: duplicate positive case {name}"
                    );
                }
                for case in cases {
                    if let Some(other) = case.get("must_differ_from").and_then(Value::as_str) {
                        assert_ne!(
                            subjects[case["name"].as_str().unwrap()],
                            subjects[other],
                            "{vector_id}: reordered components must diverge"
                        );
                    }
                }
                for case in vector["negative_cases"].as_array().unwrap() {
                    let name = case["name"].as_str().unwrap();
                    if let Some(component) = case.get("component") {
                        assert!(
                            arkret_wire::composite_subject(std::slice::from_ref(component))
                                .is_err(),
                            "{vector_id}/{}: invalid component was accepted",
                            name
                        );
                        assert_eq!(case["expected_error"], "schema_violation");
                    } else if let Some(source) = case.get("source").and_then(Value::as_str) {
                        assert!(
                            !source.starts_with("payload.") && source != "envelope.actor_id",
                            "{vector_id}/{name}: source negative is actually registered"
                        );
                        assert_eq!(case["expected_error"], "schema_violation");
                    } else if case.get("expected_component").is_some() {
                        assert_eq!(
                            case["expected_component"],
                            String::from_utf8(
                                arkret_canonical::canonical_json_bytes(&case["envelope_actor_id"])
                                    .unwrap()
                            )
                            .unwrap(),
                            "{vector_id}/{name}: envelope actor was not selected"
                        );
                        assert_ne!(
                            case["expected_component"],
                            String::from_utf8(
                                arkret_canonical::canonical_json_bytes(&case["payload_actor_id"])
                                    .unwrap()
                            )
                            .unwrap(),
                            "{vector_id}/{name}: payload actor shadowed the envelope"
                        );
                    } else {
                        assert_eq!(
                            case["expected_error"], "schema_violation",
                            "{vector_id}/{name}: semantic negative has no schema_violation"
                        );
                    }
                }
                for case in vector["mv_register_cases"].as_array().unwrap() {
                    assert!(
                        case["expected_heads"]
                            .as_array()
                            .is_some_and(|heads| !heads.is_empty()),
                        "{vector_id}/{}: convergence case omits heads",
                        case["name"].as_str().unwrap()
                    );
                }
            }
            "or_set_dot_and_batch_tag" => {
                let event_id = vector["event_id"].as_str().unwrap();
                for case in vector["dot_cases"].as_array().unwrap() {
                    let name = case["name"].as_str().unwrap();
                    let write_index = case["write_index"].as_u64().unwrap() as usize;
                    assert_eq!(
                        arkret_schema::or_set_dot(event_id, write_index),
                        case["dot"].as_str().unwrap(),
                        "{vector_id}/{name}: or_set dot drifted"
                    );
                }

                let batch = &vector["batch_add"];
                let tag_context = batch["tag_context"].as_str().unwrap();
                let dot = batch["dot"].as_str().unwrap();
                // The vector's sorted_values are the canonical value order the
                // projection sorts into; the numbered cases must follow it.
                let sorted_values = batch["sorted_values"].as_array().unwrap();
                for case in batch["cases"].as_array().unwrap() {
                    let index = case["index"].as_u64().unwrap() as usize;
                    let value = &case["value"];
                    assert_eq!(
                        &sorted_values[index], value,
                        "{vector_id}: batch case {index} is out of canonical value order"
                    );
                    let preimage = format!(
                        "{tag_context}\n{dot}\n{}",
                        std::str::from_utf8(
                            &arkret_canonical::canonical_json_bytes(value).unwrap()
                        )
                        .unwrap()
                    );
                    assert_eq!(
                        preimage,
                        case["tag_preimage_utf8"].as_str().unwrap(),
                        "{vector_id}: batch tag preimage {index} drifted"
                    );
                    let tag =
                        arkret_schema::batch_add_tag(tag_context, dot, value, "ak.mls.commit")
                            .unwrap_or_else(|error| panic!("{vector_id}: {error}"));
                    assert_eq!(
                        tag,
                        case["batch_tag"].as_str().unwrap(),
                        "{vector_id}: batch tag {index} drifted"
                    );
                }

                for case in vector["negative_cases"].as_array().unwrap() {
                    let name = case["name"].as_str().unwrap();
                    assert_eq!(
                        case["reason"], "reducer_projection_failed",
                        "{vector_id}/{name}: negative case has the wrong reason"
                    );
                    let tag = case["tag"].as_str().unwrap();
                    match name {
                        // A bare event_id carries no write index, so it cannot
                        // identify an element when one Event writes several
                        // or_set targets.
                        "bare_event_id_as_tag" => assert_ne!(
                            tag,
                            arkret_schema::or_set_dot(event_id, 0),
                            "{vector_id}/{name}: a bare event_id must not equal a dot"
                        ),
                        // Textually indistinguishable from a valid dot, which is
                        // exactly why the contract pins the provenance: the
                        // registry `cell_writes[]` index, never a payload index.
                        "wire_array_index_as_third_segment" => {
                            assert_eq!(tag, arkret_schema::or_set_dot(event_id, 0));
                            assert_eq!(case["derived_from"], "payload array index");
                        }
                        other => {
                            panic!("{vector_id}: unknown negative case {other}; extend this driver")
                        }
                    }
                }
            }
            "domain_separated_canonical_json_digest" => {
                let domain = vector["domain_separator_utf8"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{vector_id}: missing domain separator"));
                let input = vector
                    .get("input")
                    .unwrap_or_else(|| panic!("{vector_id}: missing input"));
                let canonical = arkret_canonical::canonical_json_bytes(input)
                    .unwrap_or_else(|error| panic!("{vector_id}: canonicalize failed: {error}"));
                assert_eq!(
                    canonical,
                    vector["expected_canonical_bytes_utf8"]
                        .as_str()
                        .unwrap()
                        .as_bytes(),
                    "{vector_id}: canonical bytes drifted"
                );
                let mut digest_input = domain.as_bytes().to_vec();
                digest_input.extend_from_slice(&canonical);
                assert_eq!(
                    hex::encode(&digest_input),
                    vector["digest_input_hex"].as_str().unwrap(),
                    "{vector_id}: domain-separated digest input drifted"
                );
                let valid_digest = arkret_canonical::sha256_digest(&digest_input);
                assert_eq!(
                    valid_digest,
                    vector["expected_digest"].as_str().unwrap(),
                    "{vector_id}: digest drifted"
                );

                for case in vector
                    .get("normalization_cases")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let name = case["name"].as_str().unwrap();
                    let mut normalized = case["payload"].clone();
                    let object = normalized
                        .as_object_mut()
                        .unwrap_or_else(|| panic!("{vector_id}/{name}: payload must be an object"));
                    object.remove("created_at");
                    object.remove("binding_digest");
                    if let Some(participants) = object
                        .get_mut("unordered_participant_ids")
                        .and_then(Value::as_array_mut)
                    {
                        participants.sort_by_key(|value| {
                            arkret_canonical::canonical_json_bytes(value).unwrap()
                        });
                    }
                    if let Some(event_refs) = object
                        .get_mut("authorization_basis")
                        .and_then(Value::as_object_mut)
                        .and_then(|basis| basis.get_mut("event_refs"))
                        .and_then(Value::as_array_mut)
                    {
                        event_refs.sort_by(|left, right| {
                            left.as_str()
                                .unwrap()
                                .as_bytes()
                                .cmp(right.as_str().unwrap().as_bytes())
                        });
                    }
                    let bytes = arkret_canonical::canonical_json_bytes(&normalized)
                        .unwrap_or_else(|error| panic!("{vector_id}/{name}: {error}"));
                    let mut preimage = domain.as_bytes().to_vec();
                    preimage.extend_from_slice(&bytes);
                    assert_eq!(
                        arkret_canonical::sha256_digest(&preimage),
                        case["expected_digest"].as_str().unwrap(),
                        "{vector_id}/{name}: normalized digest drifted"
                    );
                    assert!(
                        case.get("event_context").is_some(),
                        "{vector_id}/{name}: normalization case must prove Event context exclusion"
                    );
                }

                for case in vector
                    .get("mutation_cases")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    let name = case["name"].as_str().unwrap();
                    let mutation_input =
                        if let Some(hex) = case.get("digest_input_hex").and_then(Value::as_str) {
                            hex_decode(hex).unwrap_or_else(|| {
                                panic!("{vector_id}/{name}: invalid digest_input_hex")
                            })
                        } else {
                            let mutation_canonical = arkret_canonical::canonical_json_bytes(
                                case.get("input").unwrap_or_else(|| {
                                    panic!("{vector_id}/{name}: missing mutation input")
                                }),
                            )
                            .unwrap_or_else(|error| panic!("{vector_id}/{name}: {error}"));
                            if let Some(expected) = case
                                .get("expected_canonical_bytes_utf8")
                                .and_then(Value::as_str)
                            {
                                assert_eq!(
                                    mutation_canonical,
                                    expected.as_bytes(),
                                    "{vector_id}/{name}: mutation canonical bytes drifted"
                                );
                            }
                            let mutation_domain = case
                                .get("domain_separator_utf8")
                                .and_then(Value::as_str)
                                .unwrap_or(domain);
                            let mut bytes = mutation_domain.as_bytes().to_vec();
                            bytes.extend_from_slice(&mutation_canonical);
                            bytes
                        };
                    let mutation_digest = arkret_canonical::sha256_digest(&mutation_input);
                    assert_eq!(
                        mutation_digest,
                        case["expected_digest"].as_str().unwrap(),
                        "{vector_id}/{name}: mutation digest drifted"
                    );
                    if case
                        .get("must_not_equal_valid")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                    {
                        assert_ne!(
                            mutation_digest, valid_digest,
                            "{vector_id}/{name}: semantic mutation did not change digest"
                        );
                    }
                }
            }
            // `conformance/encoding.md` section 4 `uri` subject kind. Two
            // halves are locked here: the canonical wire form the typed value
            // accepts, and the full percent-encoding that turns it into a
            // single CellRef subject segment.
            "uri_cell_subject" => {
                let source = &vector["source_descriptor"];
                let event_kind = source["event_kind"].as_str().unwrap();
                let descriptor = EventKind::try_new(event_kind)
                    .and_then(|kind| kind.descriptor())
                    .unwrap_or_else(|| panic!("{vector_id}: source event kind is not registered"));
                let write = descriptor
                    .cell_writes
                    .iter()
                    .find(|write| {
                        write.cell_family.map(|family| family.as_str())
                            == source["cell_family"].as_str()
                    })
                    .unwrap_or_else(|| panic!("{vector_id}: source cell family is not registered"));
                let registered_rule = write
                    .cell_subject_rule
                    .unwrap_or_else(|| panic!("{vector_id}: source subject rule is missing"))
                    .to_json_value();
                assert_eq!(
                    registered_rule["kind"], source["subject_kind"],
                    "{vector_id}: registered subject kind drifted"
                );
                assert_eq!(
                    registered_rule["field"], source["field"],
                    "{vector_id}: registered subject field drifted"
                );

                let mut subjects = std::collections::BTreeMap::new();
                for case in vector["positive_cases"].as_array().unwrap() {
                    let name = case["name"].as_str().unwrap();
                    let input = case["input"].as_str().unwrap();
                    let room = arkret_wire::MimiRoomUri::new(input)
                        .unwrap_or_else(|error| panic!("{vector_id}/{name}: {error}"));
                    let subject = room.cell_subject();
                    assert_eq!(
                        subject,
                        case["expected_subject"].as_str().unwrap(),
                        "{vector_id}/{name}: uri subject drifted"
                    );
                    assert_eq!(
                        arkret_wire::subject_cell(
                            source["cell_family"].as_str().unwrap(),
                            &subject
                        ),
                        case["expected_cell_ref"].as_str().unwrap(),
                        "{vector_id}/{name}: cell ref drifted"
                    );
                    assert!(
                        arkret_identifiers::is_cell_ref(
                            case["expected_cell_ref"].as_str().unwrap()
                        ),
                        "{vector_id}/{name}: derived cell ref is not a legal CellRef"
                    );
                    subjects.insert(name, subject);
                }
                for case in vector["positive_cases"].as_array().unwrap() {
                    if let Some(other) = case.get("must_differ_from").and_then(Value::as_str) {
                        assert_ne!(
                            subjects[case["name"].as_str().unwrap()],
                            subjects[other],
                            "{vector_id}: escaped and unescaped separators must not fold"
                        );
                    }
                }
                for case in vector["negative_cases"].as_array().unwrap() {
                    let name = case["name"].as_str().unwrap();
                    assert!(
                        arkret_wire::MimiRoomUri::new(case["input"].as_str().unwrap()).is_err(),
                        "{vector_id}/{name}: non-canonical room URI was accepted"
                    );
                    assert_eq!(case["expected_error"], "schema_violation");
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
