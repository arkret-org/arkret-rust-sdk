use arkret_models_collaboration::history_key::{
    HistoryResponseCapabilityPlaintext, HistoryResponseCapabilityPlaintextKind,
    response_capability_commitment,
};

const CAPABILITY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";

#[test]
fn response_capability_commitment_matches_registered_kat() {
    let plaintext = HistoryResponseCapabilityPlaintext {
        kind: HistoryResponseCapabilityPlaintextKind::Value,
        response_capability_b64u: CAPABILITY.to_owned(),
    };
    plaintext.validate().unwrap();
    assert_eq!(
        response_capability_commitment(CAPABILITY).unwrap().as_ref(),
        "sha256:14d790fb66c28cb85c6ba29b7e801ef995e6c56e21fae5076239dea4f2706dc6"
    );
}

#[test]
fn response_capability_rejects_noncanonical_or_wrong_length_values() {
    for value in [
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg",
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
    ] {
        assert!(response_capability_commitment(value).is_err(), "{value}");
    }
}
