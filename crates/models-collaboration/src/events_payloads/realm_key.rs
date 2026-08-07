//! Realm-key request, delivery, durability, and audit event payloads.

use arkret_wire::ProofContextId;

use crate::internal_prelude::*;

/// Counterpart for `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_scope`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeyScope {
    pub effective_scope: ScopeRef,
    pub policy_digest: Hash,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_frontier_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_visibility: Option<HistoryVisibilityValue>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/device-message.schema.json#/$defs/realm_key_request_scope`.
///
/// Request-flavoured scope: unlike [`RealmKeyScope`] (used by the durable
/// share), `policy_digest` is an OPTIONAL requester hint (the key source MUST
/// recompute effective policy) and `from_epoch` / `to_epoch` are REQUIRED (the
/// requester always names the epoch range it wants).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeyRequestScope {
    pub effective_scope: ScopeRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_frontier_digest: Option<Hash>,
    pub from_epoch: u64,
    pub to_epoch: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_visibility: Option<HistoryVisibilityValue>,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/device-message.schema.json#/$defs/realm_key_request_content`.
///
/// Ephemeral `ak.realm_key.request` body: a device asks a provider to seal the
/// retained `history_secret[from..to]` for a Realm to its HPKE public key so it
/// can decrypt pre-join content. The sealed material rides back inside a
/// `ak.realm_key.share` `ciphertext`.
///
/// `requested_source_kind` reuses the authoritative
/// [`HistoryKeySource`] (defined in `history_visibility.rs`).
/// The direct request/share path is not allowed to request the
/// [`HistoryKeySource::KeyBackup`] class — backup-derived history keys are out
/// of scope here; [`RealmKeyRequestPayload::validate`] rejects it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeyRequestPayload {
    pub key_scope: RealmKeyRequestScope,
    pub recipient_principal_id: Did,
    pub recipient_device_id: DeviceId,
    pub recipient_hpke_public_key: NonEmptyString,
    pub requested_source_kind: HistoryKeySource,
    pub target_source_ref: RealmKeySourceRef,
    pub target_principal_id: Did,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

impl RealmKeyRequestPayload {
    /// Reject empty load-bearing fields and the out-of-scope `key_backup`
    /// source class before the request is shipped.
    pub fn validate(&self) -> Result<()> {
        if self.requested_source_kind == HistoryKeySource::KeyBackup {
            return Err(Error::Protocol(
                "ak.realm_key.request.requested_source_kind must not be key_backup".to_owned(),
            ));
        }
        if self.recipient_hpke_public_key.trim().is_empty() {
            return Err(Error::Protocol(
                "ak.realm_key.request.recipient_hpke_public_key must not be blank".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RealmKeySourceRef {
    Device(DeviceId),
    Service(Did),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmKeyShareResult {
    Shared,
    Withheld,
    Rejected,
    Expired,
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_share_audit_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeyShareAuditPayload {
    pub share_event_ref: EventId,
    pub result: RealmKeyShareResult,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_principal_id: Option<Did>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_digest: Option<Hash>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub recorded_at: DateTime<Utc>,
}

/// Discriminator for `realm_key_share_payload.share_kind`
/// (event-payload.schema.json, device-lifecycle.md §13). `member_device` is the
/// ordinary per-member history delivery path (carries `recipient_device_id`);
/// `realm_recovery_key` is the Realm `durability_policy` RRK durability seal
/// (carries `recipient_verification_method` + `recovery_recipient_id`, never a
/// device id) — see encryption-and-audit.md §2.10.8.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealmKeyShareClass {
    MemberDevice,
    RealmRecoveryKey,
}

/// Variant target of a realm key share, keyed by `share_kind`.
///
/// `share_kind` is the discriminator the cell subject and the sender
/// transcript both read, so it stays a top-level field on the payload; this
/// enum is untagged and carries only the branch-specific target fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RealmKeyShareTarget {
    /// `share_kind=member_device`: the authorized recipient device whose HPKE
    /// public key receives the sealed history secret.
    MemberDevice { recipient_device_id: DeviceId },
    /// `share_kind=realm_recovery_key`: the RRK verification method
    /// (identity-did.md §8.3) plus the stable durability-policy recipient id.
    RealmRecoveryKey {
        recipient_verification_method: DidUrl,
        recovery_recipient_id: NonEmptyString,
    },
}

/// Sealed key material carried by a realm key share (exactly one form).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RealmKeyShareMaterial {
    Ciphertext { ciphertext: NonEmptyString },
    EncryptedKeyRef { encrypted_key_ref: ObjectRef },
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_share_payload`.
///
/// Serialization flattens the two variant enums back to the exact wire shape.
/// `deny_unknown_fields` cannot be combined with `flatten`, so strict field
/// rejection lives in the hand-written [`Deserialize`] below rather than being
/// silently dropped.
#[derive(Clone, Debug, Serialize)]
pub struct RealmKeySharePayload {
    pub share_kind: RealmKeyShareClass,
    pub recipient_principal_id: Did,
    /// Variant target. Flattened so the wire shape stays exactly the schema's
    /// `oneOf`, while cross-carrying or omitting a branch's fields becomes
    /// unrepresentable in Rust instead of a runtime check.
    #[serde(flatten)]
    pub target: RealmKeyShareTarget,
    pub sender_device_id: DeviceId,
    /// Accepted policy/grant/source authorization event reference covering this
    /// delivery at the Event CBA basis. The receiver verifies it before
    /// installing any history secret material.
    pub source_authorization_ref: EventId,
    pub sender_device_signature: SignatureMaterial,
    pub key_scope: RealmKeyScope,
    /// Sealed material. The schema fixes exactly-one of `ciphertext` /
    /// `encrypted_key_ref`, so this is an enum rather than two `Option`s that
    /// could both be set or both be empty.
    #[serde(flatten)]
    pub material: RealmKeyShareMaterial,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad_digest: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub created_at: DateTime<Utc>,
}

/// Strict wire mirror used only while deserializing [`RealmKeySharePayload`].
///
/// Keeping every branch field as an `Option` here is what lets
/// `deny_unknown_fields` stay in force; the conversion below then rejects a
/// missing, cross-carried or doubled branch instead of dropping it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RealmKeySharePayloadWire {
    share_kind: RealmKeyShareClass,
    recipient_principal_id: Did,
    #[serde(default)]
    recipient_device_id: Option<DeviceId>,
    #[serde(default)]
    recipient_verification_method: Option<DidUrl>,
    #[serde(default)]
    recovery_recipient_id: Option<NonEmptyString>,
    sender_device_id: DeviceId,
    source_authorization_ref: EventId,
    sender_device_signature: SignatureMaterial,
    key_scope: RealmKeyScope,
    #[serde(default)]
    ciphertext: Option<NonEmptyString>,
    #[serde(default)]
    encrypted_key_ref: Option<ObjectRef>,
    #[serde(default)]
    aad_digest: Option<Hash>,
    #[serde(
        default,
        deserialize_with = "arkret_canonical::serde_helpers::deserialize_optional_canonical_timestamp"
    )]
    expires_at: Option<DateTime<Utc>>,
    #[serde(deserialize_with = "arkret_canonical::serde_helpers::deserialize_canonical_timestamp")]
    created_at: DateTime<Utc>,
}

impl<'de> Deserialize<'de> for RealmKeySharePayload {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        let wire = RealmKeySharePayloadWire::deserialize(deserializer)?;
        // The schema's `oneOf` says exactly one branch and exactly one
        // material; mirroring that here keeps a cross-carried field from being
        // silently discarded on the way into the strong type.
        let target = match (
            wire.share_kind,
            wire.recipient_device_id,
            wire.recipient_verification_method,
            wire.recovery_recipient_id,
        ) {
            (RealmKeyShareClass::MemberDevice, Some(recipient_device_id), None, None) => {
                RealmKeyShareTarget::MemberDevice {
                    recipient_device_id,
                }
            }
            (
                RealmKeyShareClass::RealmRecoveryKey,
                None,
                Some(recipient_verification_method),
                Some(recovery_recipient_id),
            ) => RealmKeyShareTarget::RealmRecoveryKey {
                recipient_verification_method,
                recovery_recipient_id,
            },
            _ => {
                return Err(D::Error::custom(
                    "realm key share target fields must match share_kind exactly:                      member_device carries only recipient_device_id, realm_recovery_key                      carries only recipient_verification_method + recovery_recipient_id",
                ));
            }
        };
        let material = match (wire.ciphertext, wire.encrypted_key_ref) {
            (Some(ciphertext), None) => RealmKeyShareMaterial::Ciphertext { ciphertext },
            (None, Some(encrypted_key_ref)) => {
                RealmKeyShareMaterial::EncryptedKeyRef { encrypted_key_ref }
            }
            _ => {
                return Err(D::Error::custom(
                    "realm key share must carry exactly one of ciphertext / encrypted_key_ref",
                ));
            }
        };
        Ok(Self {
            share_kind: wire.share_kind,
            recipient_principal_id: wire.recipient_principal_id,
            target,
            sender_device_id: wire.sender_device_id,
            source_authorization_ref: wire.source_authorization_ref,
            sender_device_signature: wire.sender_device_signature,
            key_scope: wire.key_scope,
            material,
            aad_digest: wire.aad_digest,
            expires_at: wire.expires_at,
            created_at: wire.created_at,
        })
    }
}

impl RealmKeySharePayload {
    /// Canonical bytes the sender device MUST sign and place in
    /// `sender_device_signature`, per the transcript fixed in
    /// device-lifecycle.md §13.0.
    ///
    /// Unselected variant target fields, the unselected material field and
    /// absent optional fields are **omitted**, never written as `null`: a
    /// null-padded transcript is a second, unregistered signing shape.
    ///
    /// Returns an error rather than empty bytes when canonicalization fails —
    /// signing over `[]` would produce a signature that verifies against no
    /// meaningful content.
    pub fn sender_signing_input(&self) -> Result<Vec<u8>> {
        // Serialising the payload itself is what makes omission the default:
        // both flattened enums emit exactly the selected branch, and absent
        // optionals are skipped, so no `null` placeholder can reach the
        // transcript. Building the object field-by-field would let the
        // transcript drift from the wire shape whenever the payload changes.
        let Value::Object(mut covered) = serde_json::to_value(self)? else {
            return Err(Error::Protocol(
                "realm key share payload must serialize to a JSON object".to_owned(),
            ));
        };
        // The signature cannot cover itself.
        covered.remove("sender_device_signature");
        covered.insert(
            "context".to_owned(),
            Value::String(ProofContextId::REALM_KEY_SHARE_SENDER_PROOF_V1.to_owned()),
        );
        Ok(canonical::canonical_json_bytes(&Value::Object(covered))?)
    }
}

/// Counterpart for
/// `spec/v1/artifacts/schemas/event-payload.schema.json#/$defs/realm_key_withheld_payload`.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmKeyWithheldPayload {
    /// Shared with `RealmKeySharePayload` so both kinds derive the same
    /// `ak.component.realm_key.delivery.v1` subject. v1 registers
    /// `member_device` only.
    pub share_kind: RealmKeyShareClass,
    pub recipient_principal_id: Did,
    pub recipient_device_id: DeviceId,
    pub sender_device_id: DeviceId,
    /// Accepted authorisation covering this refusal at the Event CBA basis. A
    /// withheld carries subject-level terminal semantics, so an unauthorized
    /// one MUST be rejected with `late_recovery_share_not_authorized` rather
    /// than projected as terminal (device-lifecycle.md §13).
    pub source_authorization_ref: EventId,
    /// Required: `key_scope.effective_scope` supplies the delivery cell
    /// subject, and `policy_digest` pins the refusal basis.
    pub key_scope: RealmKeyScope,
    pub withheld_reason_code: RealmKeyWithheldReasonCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "arkret_canonical::serde_helpers::optional_canonical_timestamp")]
    pub created_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod realm_key_request_tests {
    use serde_json::json;

    use super::*;

    fn request_scope() -> RealmKeyRequestScope {
        RealmKeyRequestScope {
            effective_scope: ScopeRef::Realm {
                realm_id: RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19")
                    .unwrap(),
            },
            policy_digest: None,
            membership_frontier_digest: None,
            from_epoch: 0,
            to_epoch: 4,
            history_visibility: None,
        }
    }

    fn request(source: HistoryKeySource) -> RealmKeyRequestPayload {
        RealmKeyRequestPayload {
            key_scope: request_scope(),
            recipient_principal_id: Did::new(
                "did:webvh:example.test:users:01J0000000000000000000000A".to_owned(),
            )
            .unwrap(),
            recipient_device_id: DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000b")
                .unwrap(),
            recipient_hpke_public_key: NonEmptyString::new("cHVia2V5").unwrap(),
            requested_source_kind: source,
            target_source_ref: RealmKeySourceRef::Device(
                DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000c").unwrap(),
            ),
            target_principal_id: Did::new(
                "did:webvh:example.test:users:01J0000000000000000000000D".to_owned(),
            )
            .unwrap(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn realm_key_request_round_trips_and_field_order_is_stable() {
        let payload = request(HistoryKeySource::VerifiedMemberDevice);
        payload.validate().unwrap();
        let value = serde_json::to_value(&payload).unwrap();
        assert_eq!(
            value["requested_source_kind"],
            json!("verified_member_device")
        );
        let parsed: RealmKeyRequestPayload = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.recipient_device_id, payload.recipient_device_id);
        assert_eq!(parsed.target_source_ref, payload.target_source_ref);
    }

    #[test]
    fn realm_key_request_rejects_key_backup_and_empty_fields() {
        assert!(request(HistoryKeySource::KeyBackup).validate().is_err());

        let mut bad = request(HistoryKeySource::OwnDevice);
        bad.recipient_hpke_public_key = NonEmptyString::new("   ").unwrap();
        assert!(bad.validate().is_err());
    }
}
#[cfg(test)]
mod realm_key_share_tests {
    use super::*;

    fn wire(share_kind: &str, extra: Value) -> Value {
        let mut base = serde_json::json!({
            "share_kind": share_kind,
            "recipient_principal_id": "did:webvh:z6mkfixture:bob.example",
            "sender_device_id": "ak:device:019f9000-0000-7000-8000-000000000004",
            "source_authorization_ref": "ak:event:Adl8EVE0XuYmtOeRAa0WJVGy5DWansCGrXuwPONweuzs",
            "sender_device_signature": {"kid": "k", "signature_algorithm": "Ed25519", "sig": "AAAA"},
            "key_scope": {
                "effective_scope": {
                    "kind": "realm",
                    "realm_id": "ak:realm:AVqz6eQZLqR_ZRLY8DW-ewi2BPdIfeJyWu9HXB2dz2Wy"
                },
                "policy_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            },
            "created_at": "2026-07-26T00:00:00.000Z"
        });
        let object = base.as_object_mut().unwrap();
        for (key, value) in extra.as_object().unwrap() {
            object.insert(key.clone(), value.clone());
        }
        base
    }

    fn member(extra: Value) -> Value {
        let mut value = wire("member_device", extra);
        let object = value.as_object_mut().unwrap();
        object.entry("recipient_device_id").or_insert_with(|| {
            Value::String("ak:device:019f9000-0000-7000-8000-000000000003".to_owned())
        });
        object
            .entry("ciphertext")
            .or_insert_with(|| Value::String("Y2lwaGVy".to_owned()));
        value
    }

    fn parse(value: Value) -> std::result::Result<RealmKeySharePayload, serde_json::Error> {
        serde_json::from_value(value)
    }

    #[test]
    fn round_trips_both_variants_byte_identically() {
        for value in [
            member(serde_json::json!({})),
            wire(
                "realm_recovery_key",
                serde_json::json!({
                    "recipient_verification_method":
                        "did:webvh:z6mkfixture:acme.example#realm-history-recovery-1",
                    "recovery_recipient_id": "rr-1",
                    "encrypted_key_ref":
                        "ak:blob:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                }),
            ),
        ] {
            let parsed = parse(value.clone()).expect("valid share");
            assert_eq!(serde_json::to_value(&parsed).unwrap(), value);
        }
    }

    #[test]
    fn rejects_cross_carried_branch_field() {
        // Without the strict wire mirror this would deserialize as
        // member_device and silently drop `recovery_recipient_id`.
        let error = parse(member(serde_json::json!({"recovery_recipient_id": "rr-1"})))
            .expect_err("cross-carried target must be rejected");
        assert!(format!("{error}").contains("match share_kind exactly"));
    }

    #[test]
    fn rejects_missing_and_doubled_material() {
        let mut none = member(serde_json::json!({}));
        none.as_object_mut().unwrap().remove("ciphertext");
        parse(none).expect_err("material is required");

        let both = member(serde_json::json!({
            "encrypted_key_ref":
                "ak:blob:sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        }));
        parse(both).expect_err("exactly one material only");
    }

    #[test]
    fn rejects_unknown_fields() {
        parse(member(serde_json::json!({"surprise": 1})))
            .expect_err("unknown wire fields must still be rejected");
    }

    #[test]
    fn transcript_omits_unselected_and_absent_fields() {
        let payload = parse(member(serde_json::json!({}))).unwrap();
        let bytes = payload.sender_signing_input().unwrap();
        let transcript: Value = serde_json::from_slice(&bytes).unwrap();
        let object = transcript.as_object().unwrap();
        assert_eq!(
            object.get("context").unwrap(),
            ProofContextId::REALM_KEY_SHARE_SENDER_PROOF_V1
        );
        assert!(!object.contains_key("sender_device_signature"));
        for absent in [
            "recipient_verification_method",
            "recovery_recipient_id",
            "encrypted_key_ref",
            "aad_digest",
            "expires_at",
        ] {
            assert!(
                !object.contains_key(absent),
                "{absent} must be omitted, not null"
            );
        }
        assert!(object.contains_key("ciphertext"));
        assert!(object.contains_key("created_at"));
    }

    #[test]
    fn transcript_covers_expires_at_when_present() {
        let without = parse(member(serde_json::json!({}))).unwrap();
        let with = parse(member(
            serde_json::json!({"expires_at": "2026-07-27T00:00:00.000Z"}),
        ))
        .unwrap();
        assert_ne!(
            without.sender_signing_input().unwrap(),
            with.sender_signing_input().unwrap(),
            "expires_at must be covered by the sender transcript"
        );
    }
}
