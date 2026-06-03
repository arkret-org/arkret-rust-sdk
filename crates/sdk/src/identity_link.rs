use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use cokret_core::{
    DeviceId, Did, Error, Hash, IdentityLink, IdentityLinkStatus, RealmId, Result,
    compute_policy_frontier_digest,
};
use serde_json::Value;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityLinkCacheEntry {
    pub link: IdentityLink,
    pub verified_at: DateTime<Utc>,
    pub proof_digest: Hash,
    pub policy_frontier_digest: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Default)]
pub struct IdentityLinkCache {
    entries: BTreeMap<(RealmId, Did), IdentityLinkCacheEntry>,
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
        self.upsert_verified_with_policy_frontier_digest(link, verified_at, None)
    }

    pub fn upsert_verified_with_policy_frontier_digest(
        &mut self,
        link: IdentityLink,
        verified_at: DateTime<Utc>,
        policy_frontier_digest: Option<[u8; 32]>,
    ) -> Result<()> {
        link.validate_minimal()?;
        let key = (link.realm_id.clone(), link.pairwise_did.clone());
        if matches!(link.status, IdentityLinkStatus::Revoked) {
            self.entries.remove(&key);
            return Ok(());
        }
        let proof_digest = link.canonical_payload_digest()?;
        self.entries.insert(
            key,
            IdentityLinkCacheEntry { link, verified_at, proof_digest, policy_frontier_digest },
        );
        Ok(())
    }

    pub fn upsert_verified_with_policy_frontier(
        &mut self,
        link: IdentityLink,
        verified_at: DateTime<Utc>,
        disclosure_policy: &Value,
        history_visibility: &Value,
        identity_disclosure_profile: &Value,
        minimal_metadata_mode: &Value,
    ) -> Result<()> {
        let digest = compute_policy_frontier_digest(
            disclosure_policy,
            history_visibility,
            identity_disclosure_profile,
            minimal_metadata_mode,
        )?;
        self.upsert_verified_with_policy_frontier_digest(link, verified_at, Some(digest))
    }

    pub fn get(&self, realm_id: &RealmId, pairwise_did: &Did) -> Option<&IdentityLinkCacheEntry> {
        self.entries.get(&(realm_id.clone(), pairwise_did.clone()))
    }

    pub fn invalidate_pairwise(&mut self, realm_id: &RealmId, pairwise_did: &Did) {
        self.entries.remove(&(realm_id.clone(), pairwise_did.clone()));
    }

    pub fn invalidate_space(&mut self, realm_id: &RealmId) {
        self.entries.retain(|(realm, _), _| realm != realm_id);
    }

    pub fn invalidate_member(&mut self, realm_id: &RealmId, did: &Did) {
        self.entries.retain(|(realm, _), entry| {
            realm != realm_id
                || (entry.link.pairwise_did != *did && entry.link.principal_id != *did)
        });
    }

    pub fn invalidate_device(&mut self, device_id: &DeviceId) {
        self.entries.retain(|_, entry| entry.link.device_id != *device_id);
    }

    pub fn invalidate_on_epoch_advance(&mut self, realm_id: &RealmId, new_epoch: u64) {
        self.entries
            .retain(|(realm, _), entry| realm != realm_id || entry.link.mls_epoch >= new_epoch);
    }

    pub fn invalidate_on_policy_frontier_change(
        &mut self,
        realm_id: &RealmId,
        current_digest: [u8; 32],
    ) {
        self.entries.retain(|(realm, _), entry| {
            realm != realm_id || entry.policy_frontier_digest == Some(current_digest)
        });
    }

    pub fn require_principal(&self, realm_id: &RealmId, pairwise_did: &Did) -> Result<&Did> {
        self.get(realm_id, pairwise_did).map(|entry| &entry.link.principal_id).ok_or_else(|| {
            Error::Protocol("identity_link cache entry is missing or invalidated".to_owned())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cokret_core::{Hash, IdentityLinkProof, TypedTrustDomainId};

    fn did(value: &str) -> Did {
        Did::new(value.to_owned()).unwrap()
    }

    fn realm() -> RealmId {
        RealmId::new("ck:realm:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn device() -> DeviceId {
        DeviceId::new("ck:device:01904100-0000-7000-8000-000000000001").unwrap()
    }

    fn link(status: IdentityLinkStatus, epoch: u64) -> IdentityLink {
        let mut link = IdentityLink {
            schema: IdentityLink::SCHEMA.to_owned(),
            status,
            pairwise_did: did("did:peer:alice-pairwise"),
            principal_id: did("did:web:alice.example"),
            device_id: device(),
            realm_id: realm(),
            trust_domain: TypedTrustDomainId::new("ck:trust_domain:example").unwrap(),
            flow_id: None,
            track: None,
            mls_group_id: Some("group-1".to_owned()),
            mls_leaf_index: 7,
            mls_epoch: epoch,
            effective_at: Utc::now(),
            expires_at: None,
            disclosure_policy_id: None,
            proof: IdentityLinkProof {
                verification_method: "did:web:alice.example#key-1".to_owned(),
                signature_algorithm: "Ed25519".to_owned(),
                payload_digest: Hash::new(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                signature: "sig".to_owned(),
            },
        };
        link.proof.payload_digest = link.canonical_payload_digest().unwrap();
        link
    }

    #[test]
    fn cache_upsert_and_eager_invalidation_work() {
        let mut cache = IdentityLinkCache::new();
        let active = link(IdentityLinkStatus::Active, 3);
        let realm = active.realm_id.clone();
        let pairwise = active.pairwise_did.clone();
        let principal = active.principal_id.clone();
        let device = active.device_id.clone();
        cache.upsert_verified(active, Utc::now()).unwrap();
        assert_eq!(cache.require_principal(&realm, &pairwise).unwrap(), &principal);

        cache.invalidate_on_epoch_advance(&realm, 4);
        assert!(cache.get(&realm, &pairwise).is_none());

        let active = link(IdentityLinkStatus::Active, 5);
        cache.upsert_verified(active, Utc::now()).unwrap();
        cache.invalidate_device(&device);
        assert!(cache.get(&realm, &pairwise).is_none());

        let active = link(IdentityLinkStatus::Active, 5);
        cache.upsert_verified(active, Utc::now()).unwrap();
        cache.invalidate_member(&realm, &principal);
        assert!(cache.get(&realm, &pairwise).is_none());
    }

    #[test]
    fn revoked_identity_link_removes_existing_entry() {
        let mut cache = IdentityLinkCache::new();
        let active = link(IdentityLinkStatus::Active, 1);
        let realm = active.realm_id.clone();
        let pairwise = active.pairwise_did.clone();
        cache.upsert_verified(active, Utc::now()).unwrap();
        let revoked = link(IdentityLinkStatus::Revoked, 1);
        cache.upsert_verified(revoked, Utc::now()).unwrap();
        assert!(cache.get(&realm, &pairwise).is_none());
    }

    #[test]
    fn policy_frontier_digest_invalidates_stale_identity_links() {
        let mut cache = IdentityLinkCache::new();
        let active = link(IdentityLinkStatus::Active, 1);
        let realm = active.realm_id.clone();
        let pairwise = active.pairwise_did.clone();
        let current = compute_policy_frontier_digest(
            &serde_json::json!({"mode": "strict"}),
            &serde_json::json!("members_only"),
            &serde_json::json!({"profile": "default"}),
            &serde_json::json!(false),
        )
        .unwrap();
        let changed = compute_policy_frontier_digest(
            &serde_json::json!({"mode": "strict"}),
            &serde_json::json!("members_only"),
            &serde_json::json!({"profile": "default"}),
            &serde_json::json!(true),
        )
        .unwrap();

        cache
            .upsert_verified_with_policy_frontier_digest(active, Utc::now(), Some(current))
            .unwrap();
        cache.invalidate_on_policy_frontier_change(&realm, current);
        assert!(cache.get(&realm, &pairwise).is_some());

        cache.invalidate_on_policy_frontier_change(&realm, changed);
        assert!(cache.get(&realm, &pairwise).is_none());
    }
}
