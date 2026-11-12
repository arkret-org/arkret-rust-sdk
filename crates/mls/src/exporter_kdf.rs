//! RFC 9420 §8.5 exporter primitives and the registry-bound derivations.
//!
//! RFC 9420 defines two byte-level primitives on the epoch key schedule:
//! `ExpandWithLabel` and `MLS-Exporter`. They live in [`arkret_crypto`] so the
//! AEAD nonce contract cannot grow a second copy; this module is the
//! `arkret-mls` face over them, and it is the only place a caller should reach
//! for an exporter-derived secret that is not already wrapped by a dedicated
//! module (Signal in `crate::signal`, SFrame media frame keys in
//! [`arkret_crypto::sframe`]).
//!
//! Every derivation here is gated on the label's entry in the spec exporter
//! label registry ([`arkret_wire::EXPORTER_LABELS`]): the registered primitive
//! must match the primitive being evaluated, and a label whose entry sets
//! `empty_context_forbidden` MUST fail closed on an empty `Context`. The label
//! set is generated from `artifacts/registry/exporter-label-registry.json`, so
//! this module cannot derive under an unregistered label at all — the label
//! argument is [`arkret_wire::ExporterLabelId`], not a free string.
//!
//! Content roots are exported once per accepted epoch context. Body and
//! attachment keys expand that root with the hash of their exact object context.
//! Restored roots grant history decryption without restoring MLS membership.

use arkret_canonical::canonical::canonical_json_bytes;
use arkret_models_collaboration::events_payloads::call::CallRecordingId;
use arkret_models_crypto::{AttachmentContentKeyContext, ContentRootContext};
use arkret_wire::{
    CallId, DidCoreId, EventId, ExporterLabelDescriptor, ExporterLabelId, RealmId, ReasonCode,
    ScopeRef, exporter_label_descriptor,
};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::group::ArkretMlsGroup;
use crate::{MlsError as Error, Result};

/// `KDF.Nh` for the Arkret v1 ciphersuite, in bytes (RFC 9420 §8).
pub const MLS_HASH_LEN: usize = arkret_crypto::mls_exporter::MLS_HASH_LEN;

/// Output width every registered RTC artifact key derivation produces.
pub const RTC_ARTIFACT_KEY_LEN: usize = 32;

/// Output width of the one-hour reaction routing HMAC key.
pub const REACTION_ROUTING_KEY_LEN: usize = 32;

/// Derive an attachment key from an authorized original epoch content root.
/// The caller resolves immutable genesis and winning state before constructing Context.
pub fn derive_attachment_content_key(
    group: &ArkretMlsGroup,
    root_context: &ContentRootContext,
    context: &AttachmentContentKeyContext,
) -> Result<Zeroizing<[u8; 32]>> {
    context.validate()?;
    if group.scope() != &context.effective_scope
        || root_context.effective_scope != context.effective_scope
        || root_context.genesis_event_ref != context.genesis_event_ref
        || root_context.epoch != context.epoch
    {
        return Err(Error::Protocol(
            "attachment_group_state_unresolved: scope/epoch mismatch".into(),
        ));
    }
    let root = group.export_content_root(root_context)?;
    arkret_crypto::content_history::derive_attachment_content_key(&root, context)
        .map_err(|error| Error::Crypto(error.to_string()))
}

const PRIMITIVE_MLS_EXPORTER: &str = "MLS-Exporter";
const PRIMITIVE_EXPAND_WITH_LABEL: &str = "ExpandWithLabel";

fn descriptor(label: ExporterLabelId) -> &'static ExporterLabelDescriptor {
    exporter_label_descriptor(label)
}

/// Enforce the registry entry for `label` before any key material is produced.
///
/// Two things are checked, and both are wire-breaking if skipped: the
/// registered `primitive` must be the primitive the caller is about to
/// evaluate (an `ExpandWithLabel` label evaluated as an `MLS-Exporter` label
/// would silently be a different key schedule), and a registered
/// `empty_context_forbidden` label must reject an empty `Context` rather than
/// derive an epoch-wide key that binds no subject.
fn ensure_registered(label: ExporterLabelId, primitive: &str, context: &[u8]) -> Result<()> {
    let entry = descriptor(label);
    if entry.primitive != Some(primitive) {
        return Err(Error::Protocol(format!(
            "{}: exporter label {} is registered for {:?}, not {primitive}",
            ReasonCode::E2EE_KEY_SOURCE_UNAUTHORISED,
            entry.label,
            entry.primitive,
        )));
    }
    if entry.empty_context_forbidden && context.is_empty() {
        return Err(Error::Protocol(format!(
            "{}: exporter label {} forbids an empty Context",
            ReasonCode::E2EE_KEY_SOURCE_UNAUTHORISED,
            entry.label,
        )));
    }
    Ok(())
}

fn ensure_len(label: ExporterLabelId, key: &[u8], expected: usize) -> Result<()> {
    if key.len() != expected {
        return Err(Error::Crypto(format!(
            "exporter label {} produced {} bytes, expected {expected}",
            descriptor(label).label,
            key.len(),
        )));
    }
    Ok(())
}

/// RFC 9420 §8 `ExpandWithLabel(Secret, Label, Context, Length)`.
///
/// The returned buffer is key material: it is [`Zeroizing`] and is wiped on
/// drop. Callers that hold a registered label should prefer
/// [`expand_with_registered_label`], which additionally enforces the registry
/// entry.
pub fn expand_with_label(
    secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let output = arkret_crypto::mls_exporter::mls_expand_with_label(secret, label, context, length)
        .map_err(|error| Error::Crypto(error.to_string()))?;
    Ok(Zeroizing::new(output))
}

/// RFC 9420 §8.5 `MLS-Exporter(Label, Context, Length)` evaluated from an
/// epoch `exporter_secret` that the caller already holds.
///
/// [`ArkretMlsGroup::export_secret`] is the normal entry point; this form
/// exists for conformance KATs and for callers that reproduce a peer's
/// derivation from a recorded epoch secret.
pub fn mls_exporter_from_secret(
    exporter_secret: &[u8],
    label: &str,
    context: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    let output = arkret_crypto::mls_exporter::mls_exporter_from_secret(
        exporter_secret,
        label,
        context,
        length,
    )
    .map_err(|error| Error::Crypto(error.to_string()))?;
    Ok(Zeroizing::new(output))
}

/// `ExpandWithLabel` under a registered `ExpandWithLabel` label.
pub fn expand_with_registered_label(
    secret: &[u8],
    label: ExporterLabelId,
    context: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure_registered(label, PRIMITIVE_EXPAND_WITH_LABEL, context)?;
    expand_with_label(secret, label.as_str(), context, length)
}

/// `MLS-Exporter` under a registered `MLS-Exporter` label, evaluated against a
/// live group's current epoch.
///
/// Taking [`ArkretMlsGroup`] rather than raw secret bytes is what makes a
/// non-MLS key provenance unrepresentable: there is no argument a caller can
/// pass that is not an epoch of a real group.
pub fn export_registered_secret(
    group: &ArkretMlsGroup,
    label: ExporterLabelId,
    context: &[u8],
    length: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure_registered(label, PRIMITIVE_MLS_EXPORTER, context)?;
    let key = group.export_secret(label.as_str(), context, length)?;
    ensure_len(label, &key, length)?;
    Ok(key)
}

/// Exporter `Context` for `ak.rtc-recording-key/v1`.
///
/// Field order is the registry `context_fields` order; the canonical JSON
/// serializer sorts members, so the bytes are stable either way.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RtcRecordingKeyContext {
    pub realm_id: RealmId,
    pub call_id: CallId,
    pub focus_id: String,
    pub recording_id: CallRecordingId,
    pub media_service_id: DidCoreId,
    pub recording_start_event_id: EventId,
}

/// Exporter `Context` for `ak.rtc-transcript-key/v1`.
///
/// Identical in shape to [`RtcRecordingKeyContext`] except for the terminal
/// event coordinate. They are separate types on purpose: the registry forbids
/// reuse between the two labels, and a shared context type would let a caller
/// derive both keys from one value and lose that separation by accident.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RtcTranscriptKeyContext {
    pub realm_id: RealmId,
    pub call_id: CallId,
    pub focus_id: String,
    pub recording_id: CallRecordingId,
    pub media_service_id: DidCoreId,
    pub transcript_start_event_id: EventId,
}

fn ensure_focus_bound(focus_id: &str) -> Result<()> {
    arkret_wire::validate_bounded_non_typed_identifier(focus_id, 256).map_err(|reason| {
        Error::Protocol(format!(
            "{}: invalid RTC artifact exporter focus_id: {reason}",
            ReasonCode::E2EE_KEY_SOURCE_UNAUTHORISED
        ))
    })
}

/// Derive the 32-byte encryption key for one call recording artifact.
pub fn derive_rtc_recording_key(
    group: &ArkretMlsGroup,
    context: &RtcRecordingKeyContext,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure_focus_bound(&context.focus_id)?;
    let bytes = canonical_json_bytes(context)?;
    export_registered_secret(
        group,
        ExporterLabelId::RtcRecordingKeyV1,
        &bytes,
        RTC_ARTIFACT_KEY_LEN,
    )
}

/// Derive the 32-byte encryption key for one call transcription artifact.
pub fn derive_rtc_transcript_key(
    group: &ArkretMlsGroup,
    context: &RtcTranscriptKeyContext,
) -> Result<Zeroizing<Vec<u8>>> {
    ensure_focus_bound(&context.focus_id)?;
    let bytes = canonical_json_bytes(context)?;
    export_registered_secret(
        group,
        ExporterLabelId::RtcTranscriptKeyV1,
        &bytes,
        RTC_ARTIFACT_KEY_LEN,
    )
}

/// Exporter `Context` for `ak.reaction-routing-v1`.
///
/// `effective_scope` repeats the scope the root was exported under; the
/// registry pins the routing key `Context` as the closed object
/// `{effective_scope, target_ref, routing_window}`, so the scope is bound
/// twice on purpose — once in the root's own `Context`, once inside the
/// routing key's.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReactionRoutingKeyContext {
    pub effective_scope: ScopeRef,
    pub target_ref: EventId,
    pub routing_window: u64,
}

/// Export the non-deliverable reaction routing root for one effective scope.
///
/// The root is `KDF.Nh` wide and is never sent: it exists only to be expanded
/// into per-target routing keys by [`derive_reaction_routing_key`].
pub fn derive_reaction_routing_root(
    group: &ArkretMlsGroup,
    effective_scope: &ScopeRef,
) -> Result<Zeroizing<Vec<u8>>> {
    let context = effective_scope.canonical_effective_scope_key_bytes()?;
    export_registered_secret(
        group,
        ExporterLabelId::ReactionRoutingRootV1,
        &context,
        MLS_HASH_LEN,
    )
}

/// Expand the routing root into the one-hour, target-bound routing HMAC key.
pub fn derive_reaction_routing_key(
    routing_root: &[u8],
    context: &ReactionRoutingKeyContext,
) -> Result<Zeroizing<Vec<u8>>> {
    let bytes = canonical_json_bytes(context)?;
    expand_with_registered_label(
        routing_root,
        ExporterLabelId::ReactionRoutingV1,
        &bytes,
        REACTION_ROUTING_KEY_LEN,
    )
}

#[cfg(test)]
mod tests {
    use arkret_canonical::DigestSuite;

    use super::*;

    fn context_hash(bytes: &[u8], hash: arkret_crypto::mls_exporter::MlsExporterHash) -> Vec<u8> {
        use sha2::{Digest, Sha256, Sha384};
        match hash {
            arkret_crypto::mls_exporter::MlsExporterHash::Sha256 => Sha256::digest(bytes).to_vec(),
            arkret_crypto::mls_exporter::MlsExporterHash::Sha384 => Sha384::digest(bytes).to_vec(),
        }
    }

    #[test]
    fn attachment_content_key_matches_the_frozen_spec_kats() {
        use arkret_crypto::mls_exporter::{MlsExporterHash, mls_expand_with_label_with_hash};
        let artifacts = std::env::var_os("ARKRET_SPEC_ARTIFACTS_DIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../../arkret-spec/spec/v1/artifacts")
            });
        let fixture: serde_json::Value = serde_json::from_slice(
            &std::fs::read(artifacts.join("fixtures/blob-content-key-fixture.json")).unwrap(),
        )
        .unwrap();
        let label = ExporterLabelId::BlobContentKeyV1;
        for kat in fixture["kats"].as_array().unwrap() {
            let context: AttachmentContentKeyContext =
                serde_json::from_value(kat["context"].clone()).unwrap();
            context.validate().unwrap();
            let bytes = canonical_json_bytes(&context).unwrap();
            assert_eq!(bytes, kat["context_utf8"].as_str().unwrap().as_bytes());
            ensure_registered(label, PRIMITIVE_EXPAND_WITH_LABEL, &bytes).unwrap();
            let hash = match kat["hash"].as_str().unwrap() {
                "sha256" => MlsExporterHash::Sha256,
                "sha384" => MlsExporterHash::Sha384,
                _ => panic!("unregistered KAT hash"),
            };
            let secret = hex::decode(kat["content_root_hex"].as_str().unwrap()).unwrap();
            let expected = hex::decode(kat["content_key_hex"].as_str().unwrap()).unwrap();
            assert_eq!(
                mls_expand_with_label_with_hash(
                    &secret,
                    label.as_str(),
                    &context_hash(&bytes, hash),
                    32,
                    hash
                )
                .unwrap(),
                expected
            );
            for (field, replacement) in kat["separation_inputs"].as_object().unwrap() {
                let mut altered = kat["context"].clone();
                altered[field] = replacement.clone();
                let bytes = canonical_json_bytes(&altered).unwrap();
                assert_ne!(
                    mls_expand_with_label_with_hash(
                        &secret,
                        label.as_str(),
                        &context_hash(&bytes, hash),
                        32,
                        hash
                    )
                    .unwrap(),
                    expected
                );
            }
        }
        for case in fixture["salt_cases"].as_array().unwrap() {
            assert_eq!(
                serde_json::from_value::<arkret_models_crypto::AttachmentContentKeySalt>(
                    case["value"].clone()
                )
                .is_ok(),
                case["valid"].as_bool().unwrap()
            );
        }
        for case in fixture["descriptor_cases"].as_array().unwrap() {
            assert_eq!(
                serde_json::from_value::<arkret_models_crypto::EncryptedAttachment>(
                    case["descriptor"].clone()
                )
                .is_ok(),
                case["valid"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
        }
    }

    fn realm() -> RealmId {
        RealmId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [3; 32]))
    }

    fn call() -> CallId {
        CallId::from_event_id(&EventId::from_digest(DigestSuite::Sha256, [5; 32]))
    }

    fn recording() -> CallRecordingId {
        CallRecordingId::new("rec-01").unwrap()
    }

    fn media_service() -> DidCoreId {
        DidCoreId::new("ak:did_core:web:media.example").unwrap()
    }

    fn scope() -> ScopeRef {
        ScopeRef::Realm { realm_id: realm() }
    }

    fn routing_context() -> ReactionRoutingKeyContext {
        ReactionRoutingKeyContext {
            effective_scope: scope(),
            target_ref: EventId::from_digest(DigestSuite::Sha256, [9; 32]),
            routing_window: 484_512,
        }
    }

    #[test]
    fn expand_with_label_matches_the_crypto_primitive() {
        let derived = expand_with_label(&[7; 32], "ak.signal-v1", b"sender", 16).unwrap();
        let expected = arkret_crypto::mls_exporter::mls_expand_with_label(
            &[7; 32],
            "ak.signal-v1",
            b"sender",
            16,
        )
        .unwrap();
        assert_eq!(derived.as_slice(), expected.as_slice());
        assert_eq!(derived.len(), 16);
    }

    #[test]
    fn mls_exporter_from_secret_matches_the_crypto_primitive() {
        let derived =
            mls_exporter_from_secret(&[11; 32], "ak.rtc-frame-key/v1", b"ctx", MLS_HASH_LEN)
                .unwrap();
        let expected = arkret_crypto::mls_exporter::mls_exporter_from_secret(
            &[11; 32],
            "ak.rtc-frame-key/v1",
            b"ctx",
            MLS_HASH_LEN,
        )
        .unwrap();
        assert_eq!(derived.as_slice(), expected.as_slice());
    }

    #[test]
    fn registered_primitive_mismatch_fails_closed() {
        // `ak.signal-root-v1` is registered as MLS-Exporter, so evaluating it
        // as ExpandWithLabel must be refused rather than silently derived.
        let error =
            expand_with_registered_label(&[1; 32], ExporterLabelId::SignalRootV1, b"ctx", 32)
                .unwrap_err();
        assert!(error.to_string().contains("registered for"));
    }

    #[test]
    fn empty_context_fails_closed_for_every_registered_label() {
        for label in ExporterLabelId::ALL {
            let entry = descriptor(*label);
            assert!(entry.empty_context_forbidden);
            let error = match entry.primitive {
                Some(PRIMITIVE_EXPAND_WITH_LABEL) => {
                    expand_with_registered_label(&[1; 32], *label, b"", 32).unwrap_err()
                }
                _ => ensure_registered(*label, PRIMITIVE_MLS_EXPORTER, b"").unwrap_err(),
            };
            assert!(error.to_string().contains("forbids an empty Context"));
        }
    }

    #[test]
    fn reaction_routing_key_is_bound_to_target_and_window() {
        let root = [5_u8; 32];
        let base = derive_reaction_routing_key(&root, &routing_context()).unwrap();
        assert_eq!(base.len(), REACTION_ROUTING_KEY_LEN);

        let mut other_window = routing_context();
        other_window.routing_window += 1;
        assert_ne!(
            base.as_slice(),
            derive_reaction_routing_key(&root, &other_window)
                .unwrap()
                .as_slice()
        );

        let mut other_target = routing_context();
        other_target.target_ref = EventId::from_digest(DigestSuite::Sha256, [10; 32]);
        assert_ne!(
            base.as_slice(),
            derive_reaction_routing_key(&root, &other_target)
                .unwrap()
                .as_slice()
        );
    }

    #[test]
    fn reaction_routing_context_is_canonical_json_of_the_registered_fields() {
        let bytes = canonical_json_bytes(&routing_context()).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let object = value.as_object().unwrap();
        let mut keys = object.keys().cloned().collect::<Vec<_>>();
        keys.sort();
        assert_eq!(keys, ["effective_scope", "routing_window", "target_ref"]);
    }

    #[test]
    fn content_labels_use_the_registered_root_then_expand_primitives() {
        assert_eq!(
            descriptor(ExporterLabelId::EpochContentRootV1).primitive,
            Some(PRIMITIVE_MLS_EXPORTER)
        );
        assert_eq!(
            descriptor(ExporterLabelId::ContentV1).primitive,
            Some(PRIMITIVE_EXPAND_WITH_LABEL)
        );
        assert_eq!(
            descriptor(ExporterLabelId::BlobContentKeyV1).primitive,
            Some(PRIMITIVE_EXPAND_WITH_LABEL)
        );
        assert!(ExporterLabelId::from_wire("ak.history-v1").is_none());
    }

    #[test]
    fn rtc_artifact_contexts_carry_the_registered_field_sets() {
        for (label, expected) in [
            (
                ExporterLabelId::RtcRecordingKeyV1,
                vec![
                    "call_id",
                    "focus_id",
                    "media_service_id",
                    "realm_id",
                    "recording_id",
                    "recording_start_event_id",
                ],
            ),
            (
                ExporterLabelId::RtcTranscriptKeyV1,
                vec![
                    "call_id",
                    "focus_id",
                    "media_service_id",
                    "realm_id",
                    "recording_id",
                    "transcript_start_event_id",
                ],
            ),
        ] {
            let mut registered = descriptor(label).context_fields.to_vec();
            registered.sort_unstable();
            assert_eq!(registered, expected);
        }
    }

    #[test]
    fn recording_context_serializes_exactly_the_registered_fields() {
        let context = RtcRecordingKeyContext {
            realm_id: realm(),
            call_id: call(),
            focus_id: "focus-1".to_owned(),
            recording_id: recording(),
            media_service_id: media_service(),
            recording_start_event_id: EventId::from_digest(DigestSuite::Sha256, [4; 32]),
        };
        let value: serde_json::Value =
            serde_json::from_slice(&canonical_json_bytes(&context).unwrap()).unwrap();
        let mut keys = value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        let mut registered = descriptor(ExporterLabelId::RtcRecordingKeyV1)
            .context_fields
            .to_vec();
        registered.sort_unstable();
        assert_eq!(keys, registered);
    }

    #[test]
    fn empty_focus_id_is_refused_before_any_derivation() {
        let context = RtcTranscriptKeyContext {
            realm_id: realm(),
            call_id: call(),
            focus_id: String::new(),
            recording_id: recording(),
            media_service_id: media_service(),
            transcript_start_event_id: EventId::from_digest(DigestSuite::Sha256, [4; 32]),
        };
        assert!(ensure_focus_bound(&context.focus_id).is_err());
    }
    #[test]
    fn rtc_public_derivations_apply_the_focus_profile_to_real_mls_contexts() {
        let identity = crate::ArkretMlsIdentity::new_test_human_device(
            arkret_wire::ActorId::account(arkret_wire::AccountId::new(
                DidCoreId::new("ak:did_core:web:exporter.example").unwrap(),
                DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            )),
            arkret_wire::DeviceId::new("ak:device:01904100-0000-7000-8000-000000000008").unwrap(),
        )
        .unwrap();
        let group = identity.create_group(&scope()).unwrap();
        for literal in [
            " ".to_owned(),
            "é".to_owned(),
            "🦀".repeat(256),
            String::new(),
            "ak:focus:invalid".into(),
            "🦀".repeat(257),
        ] {
            let recording = RtcRecordingKeyContext {
                realm_id: realm(),
                call_id: call(),
                focus_id: literal.clone(),
                recording_id: recording(),
                media_service_id: media_service(),
                recording_start_event_id: EventId::from_digest(DigestSuite::Sha256, [4; 32]),
            };
            let transcript = RtcTranscriptKeyContext {
                realm_id: recording.realm_id.clone(),
                call_id: recording.call_id.clone(),
                focus_id: literal.clone(),
                recording_id: recording.recording_id.clone(),
                media_service_id: recording.media_service_id.clone(),
                transcript_start_event_id: recording.recording_start_event_id.clone(),
            };
            let recording_key = derive_rtc_recording_key(&group, &recording);
            let transcript_key = derive_rtc_transcript_key(&group, &transcript);
            if arkret_wire::validate_bounded_non_typed_identifier(&literal, 256).is_err() {
                assert!(recording_key.unwrap_err().to_string().contains("focus_id"));
                assert!(transcript_key.unwrap_err().to_string().contains("focus_id"));
                continue;
            }
            if !arkret_canonical::canonical::is_nfc(&literal) {
                assert_eq!(recording.focus_id, literal);
                assert_eq!(transcript.focus_id, literal);
                assert!(
                    recording_key
                        .unwrap_err()
                        .to_string()
                        .contains("Unicode NFC")
                );
                assert!(
                    transcript_key
                        .unwrap_err()
                        .to_string()
                        .contains("Unicode NFC")
                );
                continue;
            }
            let bytes = canonical_json_bytes(&recording).unwrap();
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["focus_id"],
                literal
            );
            assert_eq!(
                recording_key.unwrap(),
                group
                    .export_secret(
                        ExporterLabelId::RtcRecordingKeyV1.as_str(),
                        &bytes,
                        RTC_ARTIFACT_KEY_LEN
                    )
                    .unwrap()
            );
            assert_eq!(
                transcript_key.unwrap(),
                group
                    .export_secret(
                        ExporterLabelId::RtcTranscriptKeyV1.as_str(),
                        &canonical_json_bytes(&transcript).unwrap(),
                        RTC_ARTIFACT_KEY_LEN
                    )
                    .unwrap()
            );
        }
    }
}
