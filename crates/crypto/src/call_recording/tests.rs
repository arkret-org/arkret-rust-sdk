use std::fs;

use arkret_canonical::base64url_decode;
use arkret_canonical::canonical::sha256_digest;
use serde_json::Value;

use super::*;

fn kat() -> Value {
    let artifacts = arkret_schema_conformance::default_spec_artifacts_dir().unwrap();
    let fixture: Value = serde_json::from_slice(
        &fs::read(artifacts.join("fixtures/call-current-fixture.json")).unwrap(),
    )
    .unwrap();
    fixture["capture_transcripts"]["recording_codec_kat"].clone()
}

fn decode(value: &Value) -> Vec<u8> {
    base64url_decode(value.as_str().unwrap()).unwrap()
}

fn vector_key(kat: &Value, vector: &Value) -> [u8; 32] {
    #[cfg(feature = "aead")]
    {
        let artifact: CallRecordingArtifact =
            serde_json::from_value(vector["artifact"].clone()).unwrap();
        let secret = decode(&kat["qualified_source"]["exporter_secret"]);
        let key = crate::mls_exporter::mls_exporter_from_secret(
            &secret,
            ExporterLabelId::RTC_RECORDING_KEY_V1,
            &canonical_json_bytes(&artifact.encryption.context).unwrap(),
            32,
        )
        .unwrap();
        assert_eq!(key, decode(&vector["expected"]["key"]));
        key.try_into().unwrap()
    }
    #[cfg(not(feature = "aead"))]
    {
        let _ = kat;
        decode(&vector["expected"]["key"]).try_into().unwrap()
    }
}

fn readdress(artifact: &mut CallRecordingArtifact, bytes: &[u8]) {
    artifact.size_bytes = bytes.len() as u64;
    artifact.blob_ref = BlobRef::new(format!("ak:blob:{}", sha256_digest(bytes))).unwrap();
}

#[test]
fn formal_recording_kat_uses_real_stream_aead_and_bounded_chunking() {
    let kat = kat();
    for vector in kat["vectors"].as_array().unwrap() {
        let artifact: CallRecordingArtifact =
            serde_json::from_value(vector["artifact"].clone()).unwrap();
        let plaintext = decode(&vector["plaintext"]);
        let expected_ciphertext = decode(&vector["expected"]["ciphertext"]);
        let key = vector_key(&kat, vector);
        let prefix = validate_recording_nonce_prefix(&artifact.encryption.nonce_prefix).unwrap();
        let (_, count) =
            recording_stream_geometry(artifact.size_bytes, artifact.encryption.segment_bytes)
                .unwrap();
        for index in 0..count {
            let last = index + 1 == count;
            assert_eq!(
                recording_segment_aad(&artifact.encryption, &artifact.media_type, index, last)
                    .unwrap(),
                decode(&vector["expected"]["segment_aad"][index as usize])
            );
            assert_eq!(
                recording_segment_nonce(&prefix, index, last)
                    .unwrap()
                    .as_slice(),
                decode(&vector["expected"]["segment_nonces"][index as usize])
            );
        }
        // Different caller chunking must not change segment boundaries or bytes.
        for chunk_size in [1, 511, 1024, 4099] {
            let mut encoder = RecordingStreamEncoder::with_prefix(
                key,
                artifact.encryption.context.clone(),
                artifact.encryption.key_ref.clone(),
                artifact.encryption.segment_bytes,
                artifact.media_type.clone(),
                DigestSuite::Sha256,
                prefix,
            )
            .unwrap();
            let mut ciphertext = Vec::new();
            for chunk in plaintext.chunks(chunk_size) {
                encoder
                    .push_to(chunk, |bytes| {
                        ciphertext.extend_from_slice(bytes);
                        Ok(())
                    })
                    .unwrap();
                assert!(encoder.pending.len() <= artifact.encryption.segment_bytes as usize);
            }
            let output = encoder
                .finish(|bytes| {
                    ciphertext.extend_from_slice(bytes);
                    Ok(())
                })
                .unwrap();
            assert_eq!(ciphertext, expected_ciphertext, "{}", vector["name"]);
            assert_eq!(output.encryption(), &artifact.encryption);
            assert_eq!(output.size_bytes(), artifact.size_bytes);
            assert_eq!(output.blob_ref(), &artifact.blob_ref);
            assert_eq!(
                &*decrypt_recording(&key, &artifact, &ciphertext).unwrap(),
                &plaintext
            );
            let mut receiver = RecordingStreamDecoder::new(key, &artifact).unwrap();
            let mut provisional = Vec::new();
            for chunk in ciphertext.chunks(chunk_size) {
                receiver
                    .push_to(chunk, |bytes| {
                        provisional.extend_from_slice(bytes);
                        Ok(())
                    })
                    .unwrap();
                assert!(
                    receiver.pending.len()
                        <= artifact.encryption.segment_bytes as usize + TAG_BYTES
                );
            }
            receiver.finish().unwrap();
            assert_eq!(provisional, plaintext);
        }
    }
}

#[cfg(feature = "aead")]
#[test]
fn formal_recording_keys_use_the_real_rfc9420_mls_exporter() {
    let kat = kat();
    for vector in kat["vectors"].as_array().unwrap() {
        vector_key(&kat, vector);
    }
}

#[test]
fn decoder_completion_requires_whole_digest_even_after_every_tag_passes() {
    let kat = kat();
    let vector = &kat["vectors"][0];
    let mut artifact: CallRecordingArtifact =
        serde_json::from_value(vector["artifact"].clone()).unwrap();
    let key = vector_key(&kat, vector);
    let ciphertext = decode(&vector["expected"]["ciphertext"]);
    artifact.blob_ref = BlobRef::new(format!("ak:blob:sha256:{}", "00".repeat(32))).unwrap();
    let mut receiver = RecordingStreamDecoder::new(key, &artifact).unwrap();
    let mut provisional = Vec::new();
    receiver
        .push_to(&ciphertext, |bytes| {
            provisional.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap();
    assert_eq!(provisional, decode(&vector["plaintext"]));
    assert!(receiver.finish().is_err());
    assert!(decrypt_recording(&key, &artifact, &ciphertext).is_err());
}

#[test]
fn valid_whole_digest_cannot_hide_tag_aad_key_order_or_geometry_errors() {
    let kat = kat();
    let vector = &kat["vectors"][0];
    let original: CallRecordingArtifact =
        serde_json::from_value(vector["artifact"].clone()).unwrap();
    let key = vector_key(&kat, vector);
    let ciphertext = decode(&vector["expected"]["ciphertext"]);
    let width = original.encryption.segment_bytes as usize + TAG_BYTES;
    for mutation in 0..6 {
        let mut artifact = original.clone();
        let mut bytes = ciphertext.clone();
        match mutation {
            0 => bytes[width - 1] ^= 1,
            1 => {
                bytes.pop();
            }
            2 => bytes.push(0),
            3 => {
                let first = bytes[..width].to_vec();
                bytes.drain(..width);
                bytes.extend_from_slice(&first);
            }
            4 => artifact.media_type = "audio/webm".into(),
            5 => artifact.encryption.context.focus_id = "another-focus".into(),
            _ => unreachable!(),
        }
        // A new valid BlobRef is intentionally supplied; AEAD remains mandatory.
        readdress(&mut artifact, &bytes);
        assert!(
            decrypt_recording(&key, &artifact, &bytes).is_err(),
            "mutation {mutation}"
        );
    }
    let mut wrong = key;
    wrong[0] ^= 1;
    assert!(decrypt_recording(&wrong, &original, &ciphertext).is_err());
    for length in [0, 15, 1041, 1055, 1056] {
        assert!(
            recording_stream_geometry(length, 1024).is_err(),
            "gap {length}"
        );
    }
    assert_eq!(recording_stream_geometry(16, 1024).unwrap(), (0, 1));
    assert_eq!(recording_stream_geometry(1040, 1024).unwrap(), (1024, 1));
    assert_eq!(recording_stream_geometry(1057, 1024).unwrap(), (1025, 2));
}

#[test]
fn uncertain_sink_poisoning_requires_fresh_attempt_and_prefix() {
    let kat = kat();
    let artifact: CallRecordingArtifact =
        serde_json::from_value(kat["vectors"][0]["artifact"].clone()).unwrap();
    let make = || {
        RecordingStreamEncoder::fresh(
            [7; 32],
            artifact.encryption.context.clone(),
            artifact.encryption.key_ref.clone(),
            1024,
            artifact.media_type.clone(),
            DigestSuite::Sha256,
        )
        .unwrap()
    };
    let mut first = make();
    let second = make();
    assert_ne!(
        first.encryption().nonce_prefix,
        second.encryption().nonce_prefix
    );
    let mut emitted = 0;
    assert!(
        first
            .push_to(&vec![42; 1025], |_| {
                emitted += 1;
                Err(Error::Protocol("uncertain durable sink write".into()))
            })
            .is_err()
    );
    assert_eq!(emitted, 1);
    assert!(
        first
            .push_to(b"changed bytes", |_| { panic!("poisoned attempt emitted") })
            .is_err()
    );
    assert!(
        first
            .finish(|_| { panic!("poisoned attempt finished") })
            .is_err()
    );
}
