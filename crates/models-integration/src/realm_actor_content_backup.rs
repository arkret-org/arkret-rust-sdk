//! Manager-only immutable backup sources, inventory and private handover models.
//! These carriers are never returned to a daily native Device.

include!("generated/realm_actor_content_backup_contracts.rs");

#[cfg(feature = "openapi")]
#[path = "generated/key_backup_openapi_contracts.rs"]
mod openapi;

impl serde::Serialize for KeysBackupsUnlockResponseBody {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        KeysBackupsUnlockResponseBody::serialize(self, serializer)
    }
}
impl<'de> serde::Deserialize<'de> for KeysBackupsUnlockResponseBody {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        let result =
            KeysBackupsUnlockResponseBody::deserialize(value).map_err(serde::de::Error::custom)?;
        if matches!(&result, Self::Account(packet) if packet.actor_id.as_realm_actor_id().is_some())
        {
            return Err(serde::de::Error::custom(
                "native unlock cannot select the bare Account/Agent packet branch",
            ));
        }
        Ok(result)
    }
}

impl RealmActorArchiveInventoryEntry {
    /// Canonical typed identity, independent of arrival order and timestamps.
    pub fn identity_key(&self) -> arkret_wire::Result<Vec<u8>> {
        let identity = match self {
            Self::Backup(entry) => serde_json::json!(["backup", entry.backup.backup_id]),
            Self::Series(entry) => serde_json::json!([
                "series",
                entry.effective_scope,
                entry.record.active_series_id,
                entry.record.series_pointer_version
            ]),
            Self::Recipient(entry) => serde_json::json!(["recipient", entry.recipient_ref]),
        };
        Ok(arkret_canonical::canonical_json_bytes(&identity)?)
    }
}

impl RealmActorArchiveInventoryManifest {
    pub fn sort_entries(&mut self) -> arkret_wire::Result<()> {
        let mut entries = self
            .entries
            .iter()
            .cloned()
            .map(|entry| Ok((entry.identity_key()?, entry)))
            .collect::<arkret_wire::Result<Vec<_>>>()?;
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        self.entries = entries.into_iter().map(|(_, entry)| entry).collect();
        self.validate_order()
    }

    pub fn validate_order(&self) -> arkret_wire::Result<()> {
        self.realm_actor_id.validate()?;
        let mut previous: Option<Vec<u8>> = None;
        for entry in &self.entries {
            let key = entry.identity_key()?;
            if previous.as_ref().is_some_and(|value| value >= &key) {
                return Err(arkret_wire::WireError::Protocol(
                    "archive entries require unique canonical identity order".into(),
                ));
            }
            previous = Some(key);
        }
        Ok(())
    }

    /// Digest the entire immutable cut, never a page or the local ACK journal.
    /// Completeness and independently verified source/secret import remain the
    /// namespace owner's transaction and archive capability obligations.
    pub fn inventory_digest(&self) -> arkret_wire::Result<arkret_wire::Hash> {
        self.validate_order()?;
        Ok(arkret_wire::Hash::new(arkret_canonical::canonical_sha256(
            self,
        )?)?)
    }
}
