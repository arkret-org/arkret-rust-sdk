//! Native Realm-actor backup wire carriers. Authority and durable custody are
//! established by the bound operation, never by deserializing these values.

use arkret_wire::{Result, WireError};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

include!("generated/realm_actor_content_backup_contracts.rs");

// Serde remote-Self emits the canonical field decoder without a second DTO.
// Cross-field/curve invariants are then enforced at actual Deserialize ingress.
macro_rules! checked_native_serde {
    ($($ty:ty),+ $(,)?) => {$(
        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
                <$ty>::serialize(self, serializer)
            }
        }
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
                let value = serde_json::Value::deserialize(deserializer)?;
                let result = <$ty>::deserialize(value).map_err(serde::de::Error::custom)?;
                result.validate().map_err(serde::de::Error::custom)?;
                Ok(result)
            }
        }
    )+};
}
checked_native_serde!(
    RealmActorContentBackupRecipient,
    RealmActorBackupAuthBinding,
    RealmActorBackupIssueUnlockChallengeRequestBody,
    RealmActorDeviceKeyBackupUnlockProof,
    RealmActorManagerKeyBackupUnlockProof
);

/// All three closed authority branches of the registered unlock proof. The
/// established Account proof keeps its exact historical wire representation.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KeyBackupUnlockProofBody {
    Account(crate::KeyBackupUnlockProof),
    Device(RealmActorDeviceKeyBackupUnlockProof),
    Manager(RealmActorManagerKeyBackupUnlockProof),
}

/// Operation request, as opposed to the retained legacy Account request API.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysBackupsUnlockOperationRequestBody {
    pub proof: KeyBackupUnlockProofBody,
}

/// A private 32-byte key or transfer challenge. Copies and decoding buffers are
/// zeroized, and Debug never exposes the material.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes(Zeroizing<[u8; 32]>);

impl SecretBytes {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes(<redacted>)")
    }
}

impl Serialize for SecretBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let encoded = Zeroizing::new(arkret_canonical::base64url_encode(self.expose()));
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let encoded = Zeroizing::new(String::deserialize(deserializer)?);
        let decoded = Zeroizing::new(
            arkret_canonical::base64url_decode(&encoded).map_err(serde::de::Error::custom)?,
        );
        let bytes = decoded
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("secret must be exactly 32 bytes"))?;
        if *encoded != arkret_canonical::base64url_encode(decoded.as_slice()) {
            return Err(serde::de::Error::custom("noncanonical secret encoding"));
        }
        Ok(Self::new(bytes))
    }
}

fn deserialize_present_nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Option<T>>, D::Error> {
    Option::<T>::deserialize(deserializer).map(Some)
}

pub fn validate_realm_actor_backup_scope(
    actor: &arkret_wire::RealmActorId,
    scope: &arkret_wire::ScopeRef,
) -> Result<()> {
    actor.validate()?;
    match scope {
        arkret_wire::ScopeRef::Realm { realm_id }
        | arkret_wire::ScopeRef::Circle { realm_id, .. }
            if realm_id == &actor.realm_id =>
        {
            Ok(())
        }
        _ => Err(WireError::Protocol(
            "native backup requires the actor's exact Realm or Circle".into(),
        )),
    }
}

impl RealmActorContentBackupRecipient {
    pub fn validate(&self) -> Result<()> {
        validate_native_archive_recipient_public_key(&self.public_key_base64url)?;
        Ok(())
    }
}

/// Deterministic contributory-key check. X25519 with a fixed clamped scalar
/// rejects every low-order/noncontributory input (including masked/noncanonical
/// representatives), without trusting a caller assertion or requiring entropy.
pub fn validate_native_archive_recipient_public_key(encoded: &str) -> Result<[u8; 32]> {
    let public = crate::content_history::bytes32(encoded)?;
    let shared = curve25519_dalek::montgomery::MontgomeryPoint(public)
        .mul_clamped([0x42; 32])
        .to_bytes();
    if shared == [0; 32] {
        return Err(WireError::Protocol(
            "native archive recipient is a noncontributory X25519 key".into(),
        ));
    }
    Ok(public)
}

impl RealmActorBackupAuthBinding {
    pub fn validate(&self) -> Result<()> {
        if self.device_generation == 0 {
            return Err(WireError::Protocol(
                "native Device generation must be positive".into(),
            ));
        }
        Ok(())
    }
}

impl ContentBackupNextPrepareInput {
    pub fn validate(&self) -> Result<()> {
        self.auth_binding.validate()?;
        self.content_backup_recipient.validate()
    }
}

impl RealmActorBackupHeadQuery {
    pub fn new(actor: arkret_wire::RealmActorId, circle: Option<arkret_wire::CircleId>) -> Self {
        Self {
            purpose: KeysBackupsListQueryOneOf1Purpose::Value,
            realm_actor_id: actor,
            circle_id: circle,
        }
    }

    pub fn effective_scope(&self) -> arkret_wire::ScopeRef {
        match &self.circle_id {
            Some(circle_id) => arkret_wire::ScopeRef::Circle {
                realm_id: self.realm_actor_id.realm_id.clone(),
                circle_id: circle_id.clone(),
            },
            None => arkret_wire::ScopeRef::Realm {
                realm_id: self.realm_actor_id.realm_id.clone(),
            },
        }
    }
}

impl RealmActorArchiveInventoryQuery {
    pub fn new(actor: arkret_wire::RealmActorId) -> Self {
        Self {
            purpose: KeysBackupsListQueryOneOf2Purpose::Value,
            realm_actor_id: actor,
            cursor: None,
            limit: None,
        }
    }
}

impl KeysBackupsListParameters {
    /// Parse decoded raw pairs exactly once. Deep-object members are closed;
    /// duplicates, partial identities, aliases and branch mixing are errors.
    pub fn from_query_pairs<K: AsRef<str>, V: AsRef<str>>(
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Result<Self> {
        use arkret_wire::{CircleId, DidCoreId, RealmActorId, RealmId};
        let mut values = std::collections::BTreeMap::new();
        for (key, value) in pairs {
            if values
                .insert(key.as_ref().to_owned(), value.as_ref().to_owned())
                .is_some()
            {
                return Err(WireError::Protocol("duplicate backup query member".into()));
            }
        }
        let purpose = values.remove("purpose");
        let result = match purpose.as_deref() {
            Some("series_predecessor" | "archive_inventory") => {
                let realm = values.remove("realm_actor_id[realm_id]").ok_or_else(|| {
                    WireError::Protocol("backup query requires complete RealmActorId".into())
                })?;
                let principal = values
                    .remove("realm_actor_id[principal_id]")
                    .ok_or_else(|| {
                        WireError::Protocol("backup query requires complete RealmActorId".into())
                    })?;
                let actor = RealmActorId::new(RealmId::new(realm)?, DidCoreId::new(principal)?);
                actor.validate()?;
                if purpose.as_deref() == Some("series_predecessor") {
                    Self::Device(RealmActorBackupHeadQuery::new(
                        actor,
                        values.remove("circle_id").map(CircleId::new).transpose()?,
                    ))
                } else {
                    let mut query = RealmActorArchiveInventoryQuery::new(actor);
                    query.cursor = values
                        .remove("cursor")
                        .map(arkret_wire::Cursor::new)
                        .transpose()?;
                    query.limit = values
                        .remove("limit")
                        .map(|s| parse_limit(&s))
                        .transpose()?;
                    Self::Manager(query)
                }
            }
            None => {
                let query = crate::KeyBackupsListQuery {
                    agent_id: values.remove("agent_id").map(DidCoreId::new).transpose()?,
                    series_id: values
                        .remove("series_id")
                        .map(arkret_wire::BackupSeriesId::new)
                        .transpose()?,
                    backup_kind: values
                        .remove("backup_kind")
                        .map(|s| match s.as_str() {
                            "secret_storage" => Ok(crate::BackupKind::SecretStorage),
                            _ => Err(WireError::Protocol("unsupported backup kind".into())),
                        })
                        .transpose()?,
                    cursor: values
                        .remove("cursor")
                        .map(arkret_wire::Cursor::new)
                        .transpose()?,
                    limit: values
                        .remove("limit")
                        .map(|s| parse_limit(&s).map(|n| n as u32))
                        .transpose()?,
                };
                Self::Account(query)
            }
            _ => {
                return Err(WireError::Protocol(
                    "unsupported backup query purpose".into(),
                ));
            }
        };
        if !values.is_empty() {
            return Err(WireError::Protocol(
                "unknown or mixed backup query member".into(),
            ));
        }
        Ok(result)
    }

    /// Return decoded raw pairs for a standards-compliant URL form encoder.
    /// The encoder percent-escapes deepObject brackets; values are never JSON.
    pub fn to_query_pairs(&self) -> Result<Vec<(String, String)>> {
        let mut pairs = Vec::new();
        let mut push = |key: &str, value: String| pairs.push((key.to_owned(), value));
        match self {
            Self::Account(q) => {
                if let Some(id) = &q.agent_id {
                    push("agent_id", id.to_string());
                }
                if let Some(id) = &q.series_id {
                    push("series_id", id.to_string());
                }
                if q.backup_kind.is_some() {
                    push("backup_kind", "secret_storage".into());
                }
                if let Some(cursor) = &q.cursor {
                    push("cursor", cursor.to_string());
                }
                if let Some(limit) = q.limit {
                    push("limit", limit.to_string());
                }
            }
            Self::Device(q) => {
                push("purpose", "series_predecessor".into());
                push(
                    "realm_actor_id[realm_id]",
                    q.realm_actor_id.realm_id.to_string(),
                );
                push(
                    "realm_actor_id[principal_id]",
                    q.realm_actor_id.principal_id.to_string(),
                );
                if let Some(id) = &q.circle_id {
                    push("circle_id", id.to_string());
                }
            }
            Self::Manager(q) => {
                push("purpose", "archive_inventory".into());
                push(
                    "realm_actor_id[realm_id]",
                    q.realm_actor_id.realm_id.to_string(),
                );
                push(
                    "realm_actor_id[principal_id]",
                    q.realm_actor_id.principal_id.to_string(),
                );
                if let Some(cursor) = &q.cursor {
                    push("cursor", cursor.to_string());
                }
                if let Some(limit) = q.limit {
                    push("limit", limit.to_string());
                }
            }
        }
        Self::from_query_pairs(pairs.iter().map(|(k, v)| (k, v)))?;
        Ok(pairs)
    }
}

fn parse_limit(value: &str) -> Result<u64> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| WireError::Protocol("invalid backup query limit".into()))?;
    if !(1..=200).contains(&parsed) || parsed.to_string() != value {
        return Err(WireError::Protocol(
            "backup query limit must be canonical 1..200".into(),
        ));
    }
    Ok(parsed)
}

impl RealmActorBackupIssueUnlockChallengeRequestBody {
    pub fn validate(&self) -> Result<()> {
        validate_realm_actor_backup_scope(&self.realm_actor_id, &self.effective_scope)?;
        let roles_match = matches!(
            (&self.kind, &self.purpose),
            (
                RealmActorBackupUnlockChallengeKind::RealmActorDevice,
                RealmActorBackupUnlockChallengePurpose::SeriesPredecessor
            ) | (
                RealmActorBackupUnlockChallengeKind::RealmActorManager,
                RealmActorBackupUnlockChallengePurpose::ArchiveRecovery
            )
        );
        if !roles_match
            || !(22..=128).contains(&self.request_id.as_str().len())
            || !self.envelope_digest.as_str().starts_with("sha256:")
        {
            return Err(WireError::Protocol(
                "invalid native backup challenge role or request binding".into(),
            ));
        }
        Ok(())
    }
}

impl RealmActorBackupUnlockChallenge {
    pub fn validate_for_native_request(
        &self,
        request: &RealmActorBackupIssueUnlockChallengeRequestBody,
        backup_id: &arkret_wire::BackupId,
    ) -> Result<()> {
        request.validate()?;
        if self.realm_actor_id != request.realm_actor_id
            || self.effective_scope != request.effective_scope
            || self.kind != request.kind
            || self.purpose != request.purpose
            || self.request_id.as_str() != request.request_id.as_str()
            || &self.backup_id != backup_id
            || self.envelope_digest != request.envelope_digest
        {
            return Err(WireError::Protocol(
                "native challenge differs from its exact request".into(),
            ));
        }
        self.validate_at(chrono::Utc::now())
    }

    pub fn validate_at(&self, now: chrono::DateTime<chrono::Utc>) -> Result<()> {
        validate_realm_actor_backup_scope(&self.realm_actor_id, &self.effective_scope)?;
        let device = self.kind == RealmActorBackupUnlockChallengeKind::RealmActorDevice;
        if device != (self.purpose == RealmActorBackupUnlockChallengePurpose::SeriesPredecessor)
            || device != self.requesting_device_id.is_some()
            || device != self.device_authorize_event_id.is_some()
            || device != self.device_generation.is_some()
            || self.device_generation == Some(0)
            || now < self.issued_at
            || now >= self.expires_at
            || self.expires_at <= self.issued_at
            || self.signature_free_challenge_bytes()?.len() != 32
            || self.nonce == self.challenge
        {
            return Err(WireError::Protocol(
                "invalid native challenge requester, freshness or authority branch".into(),
            ));
        }
        Ok(())
    }

    fn signature_free_challenge_bytes(&self) -> Result<Vec<u8>> {
        let bytes = arkret_canonical::base64url_decode(self.challenge.as_str())?;
        if arkret_canonical::base64url_encode(&bytes) != self.challenge.as_str() {
            return Err(WireError::Protocol("noncanonical native challenge".into()));
        }
        Ok(bytes)
    }

    /// Sign the exact server challenge without a provisional signature value.
    pub fn sign_device_unlock_proof(
        &self,
        verification_method: arkret_wire::DidUrl,
        sign: impl FnOnce(&[u8]) -> Result<Vec<u8>>,
    ) -> Result<RealmActorDeviceKeyBackupUnlockProof> {
        self.validate_at(chrono::Utc::now())?;
        if self.kind != RealmActorBackupUnlockChallengeKind::RealmActorDevice {
            return Err(WireError::Protocol(
                "Device cannot sign a Manager archive intent".into(),
            ));
        }
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| WireError::Protocol("invalid challenge object".into()))?;
        for field in ["operation", "request_id"] {
            object.remove(field);
        }
        object.insert(
            "schema".into(),
            serde_json::json!(crate::KeyBackupUnlockProof::SCHEMA),
        );
        object.insert("backup_kind".into(), serde_json::json!("secret_storage"));
        object.insert("signature_proof".into(), serde_json::json!({"verification_method":verification_method,"signature_algorithm":"Ed25519"}));
        let signature = sign(&arkret_canonical::canonical_json_bytes(&value)?)?;
        if signature.len() != 64 {
            return Err(WireError::Protocol(
                "native unlock requires an actual Ed25519 signature".into(),
            ));
        }
        value["signature_proof"]["signature"] =
            serde_json::json!(arkret_canonical::base64url_encode(signature));
        let proof: RealmActorDeviceKeyBackupUnlockProof = serde_json::from_value(value)?;
        proof.validate()?;
        Ok(proof)
    }
}

impl RealmActorDeviceKeyBackupUnlockProof {
    pub fn validate(&self) -> Result<()> {
        validate_realm_actor_backup_scope(&self.realm_actor_id, &self.effective_scope)?;
        if self.schema != crate::KeyBackupUnlockProof::SCHEMA
            || self.kind != RealmActorBackupUnlockChallengeKind::RealmActorDevice
            || self.purpose != RealmActorBackupUnlockChallengePurpose::SeriesPredecessor
            || self.device_generation == 0
            || self.signature_proof.signature_algorithm
                != crate::KeyBackupSignatureAlgorithm::Ed25519
            || self.expires_at <= self.issued_at
        {
            return Err(WireError::Protocol(
                "invalid native Device unlock intent".into(),
            ));
        }
        Ok(())
    }

    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut value = serde_json::to_value(self)?;
        value
            .get_mut("signature_proof")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| WireError::Protocol("missing native unlock signature".into()))?
            .remove("signature");
        Ok(arkret_canonical::canonical_json_bytes(&value)?)
    }
}

impl RealmActorManagerKeyBackupUnlockProof {
    pub fn validate(&self) -> Result<()> {
        validate_realm_actor_backup_scope(&self.realm_actor_id, &self.effective_scope)?;
        if self.schema != crate::KeyBackupUnlockProof::SCHEMA
            || self.kind != RealmActorBackupUnlockChallengeKind::RealmActorManager
            || self.purpose != RealmActorBackupUnlockChallengePurpose::ArchiveRecovery
            || self.signature_proof.signature_algorithm
                != crate::KeyBackupSignatureAlgorithm::Ed25519
            || self.expires_at <= self.issued_at
        {
            return Err(WireError::Protocol(
                "invalid native Manager archive unlock intent".into(),
            ));
        }
        Ok(())
    }

    pub fn signing_payload_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut value = serde_json::to_value(self)?;
        value
            .get_mut("signature_proof")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| WireError::Protocol("missing native unlock signature".into()))?
            .remove("signature");
        Ok(arkret_canonical::canonical_json_bytes(&value)?)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn fixture() -> Value {
        serde_json::from_str(include_str!("../../../../arkret-spec/spec/v1/artifacts/fixtures/realm-actor-content-backup-fixture.json")).unwrap()
    }

    #[test]
    fn native_expiry_is_rejected_by_presence_at_deserialize() {
        let original = fixture()["native_packet"].clone();
        let packet: crate::KeyBackup = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(serde_json::to_value(packet).unwrap(), original);
        for expiry in [Value::Null, json!("2027-01-01T00:00:00Z")] {
            let mut value = original.clone();
            value["expires_at"] = expiry;
            assert!(serde_json::from_value::<crate::KeyBackup>(value).is_err());
        }
    }

    #[test]
    fn archive_curve_check_rejects_all_low_order_representatives() {
        let low = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ];
        for encoded in low {
            let mut bytes = hex::decode(encoded).unwrap();
            for masked in [false, true] {
                if masked {
                    bytes[31] |= 0x80;
                }
                assert!(
                    validate_native_archive_recipient_public_key(
                        &arkret_canonical::base64url_encode(&bytes)
                    )
                    .is_err(),
                    "{encoded} masked={masked}"
                );
            }
        }
        let recipient: RealmActorContentBackupRecipient =
            serde_json::from_value(fixture()["recipient"].clone()).unwrap();
        recipient.validate().unwrap();
        let mut malformed = fixture()["recipient"].clone();
        malformed["public_key_base64url"] = json!(arkret_canonical::base64url_encode([0; 32]));
        assert!(serde_json::from_value::<RealmActorContentBackupRecipient>(malformed).is_err());
    }

    #[test]
    fn native_deep_object_query_is_closed_and_roundtrips_exact_pairs() {
        let actor = fixture()["current_reference_cut"]["realm_actor_id"].clone();
        let actor: arkret_wire::RealmActorId = serde_json::from_value(actor).unwrap_or_else(|_| {
            serde_json::from_value(fixture()["native_packet"]["actor_id"]["realm_actor_id"].clone())
                .unwrap()
        });
        let query = KeysBackupsListParameters::Device(RealmActorBackupHeadQuery::new(actor, None));
        let pairs = query.to_query_pairs().unwrap();
        assert_eq!(
            serde_json::to_value(
                KeysBackupsListParameters::from_query_pairs(pairs.clone()).unwrap()
            )
            .unwrap(),
            serde_json::to_value(query).unwrap()
        );
        for key in ["agent_id", "realm_actor_id", "cursor", "limit", "unknown"] {
            let mut bad = pairs.clone();
            bad.push((key.into(), "x".into()));
            assert!(
                KeysBackupsListParameters::from_query_pairs(bad).is_err(),
                "{key}"
            );
        }
        let mut duplicate = pairs.clone();
        duplicate.push(pairs[0].clone());
        assert!(KeysBackupsListParameters::from_query_pairs(duplicate).is_err());
        let missing = pairs
            .into_iter()
            .filter(|(key, _)| key != "realm_actor_id[principal_id]");
        assert!(KeysBackupsListParameters::from_query_pairs(missing).is_err());
    }

    #[test]
    fn device_head_cannot_deserialize_a_sibling_full_source() {
        let mut head = fixture()["device_head_response"].clone();
        head["items"][0]["native_source"] = fixture()["native_source"].clone();
        assert!(serde_json::from_value::<RealmActorBackupSeriesHeadResponseBody>(head).is_err());
        let admission = serde_json::to_string(&fixture()["device_head_response"]).unwrap();
        assert!(!admission.contains("device_authorization"));
    }

    #[test]
    fn private_material_debug_is_redacted_and_null_is_not_a_key() {
        let secret = SecretBytes::new([73; 32]);
        assert_eq!(format!("{secret:?}"), "SecretBytes(<redacted>)");
        let value = serde_json::to_value(&secret).unwrap();
        assert_eq!(
            serde_json::from_value::<SecretBytes>(value)
                .unwrap()
                .expose(),
            secret.expose()
        );
        assert!(serde_json::from_value::<SecretBytes>(Value::Null).is_err());
    }
}
