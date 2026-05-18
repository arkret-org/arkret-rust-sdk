use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use contrix_core::{DeviceId, Did, Error, Hash, IdentityLink, IdentityLinkStatus, Result, SpaceId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityLinkCacheEntry {
    pub link: IdentityLink,
    pub verified_at: DateTime<Utc>,
    pub proof_digest: Hash,
}

#[derive(Clone, Debug, Default)]
pub struct IdentityLinkCache {
    entries: BTreeMap<(SpaceId, Did), IdentityLinkCacheEntry>,
}

impl IdentityLinkCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert_verified(
        &mut self,
        link: IdentityLink,
        verified_at: DateTime<Utc>,
    ) -> Result<()> {
        link.validate_minimal()?;
        let key = (link.space_id.clone(), link.pairwise_did.clone());
        if matches!(link.status, IdentityLinkStatus::Revoked) {
            self.entries.remove(&key);
            return Ok(());
        }
        let proof_digest = link.canonical_payload_hash()?;
        self.entries.insert(key, IdentityLinkCacheEntry { link, verified_at, proof_digest });
        Ok(())
    }

    pub fn get(&self, space_id: &SpaceId, pairwise_did: &Did) -> Option<&IdentityLinkCacheEntry> {
        self.entries.get(&(space_id.clone(), pairwise_did.clone()))
    }

    pub fn invalidate_pairwise(&mut self, space_id: &SpaceId, pairwise_did: &Did) {
        self.entries.remove(&(space_id.clone(), pairwise_did.clone()));
    }

    pub fn invalidate_space(&mut self, space_id: &SpaceId) {
        self.entries.retain(|(space, _), _| space != space_id);
    }

    pub fn invalidate_member(&mut self, space_id: &SpaceId, did: &Did) {
        self.entries.retain(|(space, _), entry| {
            space != space_id
                || (entry.link.pairwise_did != *did && entry.link.principal_did != *did)
        });
    }

    pub fn invalidate_device(&mut self, device_id: &DeviceId) {
        self.entries.retain(|_, entry| entry.link.device_id != *device_id);
    }

    pub fn invalidate_on_epoch_advance(&mut self, space_id: &SpaceId, new_epoch: u64) {
        self.entries
            .retain(|(space, _), entry| space != space_id || entry.link.mls_epoch >= new_epoch);
    }

    pub fn require_principal(&self, space_id: &SpaceId, pairwise_did: &Did) -> Result<&Did> {
        self.get(space_id, pairwise_did).map(|entry| &entry.link.principal_did).ok_or_else(|| {
            Error::Protocol("identity_link cache entry is missing or invalidated".to_owned())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use contrix_core::{Hash, IdentityLinkProof};

    fn did(value: &str) -> Did {
        Did::new(value.to_owned()).unwrap()
    }

    fn space() -> SpaceId {
        SpaceId::new("cx:space:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn device() -> DeviceId {
        DeviceId::new("cx:device:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn link(status: IdentityLinkStatus, epoch: u64) -> IdentityLink {
        let mut link = IdentityLink {
            schema: IdentityLink::SCHEMA.to_owned(),
            status,
            pairwise_did: did("did:peer:alice-pairwise"),
            principal_did: did("did:web:alice.example"),
            device_id: device(),
            space_id: space(),
            flow_id: None,
            track: None,
            mls_group_id: Some("group-1".to_owned()),
            mls_leaf_index: 7,
            mls_epoch: epoch,
            effective_at: Utc::now(),
            expires_at: None,
            disclosure_policy_ref: None,
            proof: IdentityLinkProof {
                verification_method: "did:web:alice.example#key-1".to_owned(),
                signature_algorithm: "Ed25519".to_owned(),
                payload_hash: Hash::new(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                signature: "sig".to_owned(),
            },
        };
        link.proof.payload_hash = link.canonical_payload_hash().unwrap();
        link
    }

    #[test]
    fn cache_upsert_and_eager_invalidation_work() {
        let mut cache = IdentityLinkCache::new();
        let active = link(IdentityLinkStatus::Active, 3);
        let space = active.space_id.clone();
        let pairwise = active.pairwise_did.clone();
        let principal = active.principal_did.clone();
        let device = active.device_id.clone();
        cache.upsert_verified(active, Utc::now()).unwrap();
        assert_eq!(cache.require_principal(&space, &pairwise).unwrap(), &principal);

        cache.invalidate_on_epoch_advance(&space, 4);
        assert!(cache.get(&space, &pairwise).is_none());

        let active = link(IdentityLinkStatus::Active, 5);
        cache.upsert_verified(active, Utc::now()).unwrap();
        cache.invalidate_device(&device);
        assert!(cache.get(&space, &pairwise).is_none());

        let active = link(IdentityLinkStatus::Active, 5);
        cache.upsert_verified(active, Utc::now()).unwrap();
        cache.invalidate_member(&space, &principal);
        assert!(cache.get(&space, &pairwise).is_none());
    }

    #[test]
    fn revoked_identity_link_removes_existing_entry() {
        let mut cache = IdentityLinkCache::new();
        let active = link(IdentityLinkStatus::Active, 1);
        let space = active.space_id.clone();
        let pairwise = active.pairwise_did.clone();
        cache.upsert_verified(active, Utc::now()).unwrap();
        let revoked = link(IdentityLinkStatus::Revoked, 1);
        cache.upsert_verified(revoked, Utc::now()).unwrap();
        assert!(cache.get(&space, &pairwise).is_none());
    }
}
