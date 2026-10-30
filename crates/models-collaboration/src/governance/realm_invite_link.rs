//! User-shared Realm invitations. Bearer secrets never cross the network boundary.

use arkret_wire::{Result, WireError};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use super::realm_join_intake::{RealmJoinCandidate, validate_authority_locator_hints};

include!("generated/realm_invite_link_contracts.rs");

/// The private seed is redacted and zeroed on drop, including temporary wire encodings.
#[derive(Clone)]
pub struct RealmInviteLinkSecret([u8; 32]);

impl RealmInviteLinkSecret {
    /// The caller must supply 32 freshly generated CSPRNG bytes for each new link.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(seed)
    }

    /// Expose only to the local signing primitive; never persist or send these bytes.
    pub fn seed_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for RealmInviteLinkSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RealmInviteLinkSecret([REDACTED])")
    }
}

impl Drop for RealmInviteLinkSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Serialize for RealmInviteLinkSecret {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        let encoded = zeroize::Zeroizing::new(arkret_canonical::base64url_encode(self.0));
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for RealmInviteLinkSecret {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let encoded = zeroize::Zeroizing::new(String::deserialize(deserializer)?);
        let bytes = zeroize::Zeroizing::new(
            arkret_canonical::base64url_decode(encoded.as_bytes())
                .map_err(|_| serde::de::Error::custom("invalid invite link secret encoding"))?,
        );
        if bytes.len() != 32 || arkret_canonical::base64url_encode(&*bytes) != *encoded {
            return Err(serde::de::Error::custom(
                "invalid invite link secret length or canonical encoding",
            ));
        }
        let mut seed = [0; 32];
        seed.copy_from_slice(&bytes);
        Ok(Self(seed))
    }
}

/// The closed, private fragment credential. Debug never prints the credential.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmInviteLinkToken {
    pub schema: String,
    pub realm_id: arkret_wire::RealmId,
    pub realm_invite_link_id: arkret_wire::RealmInviteLinkId,
    pub secret_seed: RealmInviteLinkSecret,
    pub authority_locator_hints: Vec<RealmJoinCandidate>,
}

impl std::fmt::Debug for RealmInviteLinkToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealmInviteLinkToken")
            .field("realm_id", &self.realm_id)
            .field("realm_invite_link_id", &self.realm_invite_link_id)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

impl RealmInviteLinkToken {
    pub const SCHEMA: &str = arkret_wire::SchemaId::REALM_INVITE_LINK_TOKEN_V1;

    pub fn validate(&self) -> Result<()> {
        if self.schema != Self::SCHEMA {
            return Err(WireError::Protocol(
                "invalid invite link credential schema".into(),
            ));
        }
        validate_authority_locator_hints(&self.authority_locator_hints)
    }

    pub fn encode(&self) -> Result<zeroize::Zeroizing<String>> {
        self.validate()?;
        let bytes = zeroize::Zeroizing::new(arkret_canonical::canonical_json_bytes(self)?);
        Ok(zeroize::Zeroizing::new(arkret_canonical::base64url_encode(
            &*bytes,
        )))
    }

    pub fn decode(encoded: &str, target_realm: &arkret_wire::RealmId) -> Result<Self> {
        let invalid = || WireError::Protocol("invalid invite link credential".into());
        if encoded.len() > 8192 {
            return Err(invalid());
        }
        let bytes = zeroize::Zeroizing::new(
            arkret_canonical::base64url_decode(encoded).map_err(|_| invalid())?,
        );
        let token: Self = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        token.validate().map_err(|_| invalid())?;
        if &token.realm_id != target_realm || token.encode()?.as_str() != encoded {
            return Err(invalid());
        }
        Ok(token)
    }
}

impl Default for RealmInviteLinkLimits {
    fn default() -> Self {
        Self {
            max_lifetime_seconds: 2_592_000,
            max_uses_per_link: 1000,
        }
    }
}

impl RealmInviteLinkLimits {
    pub fn validate(&self) -> Result<()> {
        if self.max_lifetime_seconds < 60 || self.max_uses_per_link == 0 {
            return Err(WireError::Protocol(
                "invalid Realm invite link generation limits".into(),
            ));
        }
        Ok(())
    }
}

impl RealmInviteLinkCreatePayload {
    pub fn validate(&self) -> Result<()> {
        let bytes = arkret_canonical::base64url_decode(&self.public_key)?;
        if bytes.len() != 32
            || arkret_canonical::base64url_encode(&bytes) != self.public_key
            || self.max_uses == 0
        {
            return Err(WireError::Protocol(
                "invalid Realm invite link definition".into(),
            ));
        }
        Ok(())
    }
}

/// Construct the exact domain-separated transcript; the boolean cannot be supplied over the wire.
pub fn realm_invite_link_proof_bytes(
    realm_id: &arkret_wire::RealmId,
    realm_invite_link_id: &arkret_wire::RealmInviteLinkId,
    subject_account_id: &arkret_wire::AccountId,
    request_id: &arkret_wire::RequestId,
    accepting: bool,
) -> Result<Vec<u8>> {
    subject_account_id.validate()?;
    let (context, audience) = if accepting {
        (
            "ak.realm_invite_link.accept_proof.v1\n",
            "arkret.realm_invite_link.accept",
        )
    } else {
        (
            "ak.realm_invite_link.preview_proof.v1\n",
            "arkret.realm_invite_link.preview",
        )
    };
    let mut bytes = context.as_bytes().to_vec();
    bytes.extend(arkret_canonical::canonical_json_bytes(&serde_json::json!({
        "realm_id": realm_id, "realm_invite_link_id": realm_invite_link_id,
        "subject_account_id": subject_account_id, "request_id": request_id, "audience": audience,
    }))?);
    Ok(bytes)
}

impl RealmInviteLinkProof {
    pub fn validate_transcript(&self, bytes: &[u8]) -> Result<()> {
        let signature = arkret_canonical::base64url_decode(&self.signature)?;
        if self.transcript_digest != arkret_wire::Hash::new(arkret_canonical::sha256_digest(bytes))?
            || signature.len() != 64
            || arkret_canonical::base64url_encode(&signature) != self.signature
        {
            return Err(WireError::Protocol(
                "invalid Realm invite link possession proof".into(),
            ));
        }
        Ok(())
    }
}

/// Project metadata from an already authenticated full snapshot. This grants no admission
/// authority.
pub fn realm_invite_link_views(
    snapshot: &arkret_wire::RealmStateSnapshot,
) -> Result<Vec<RealmInviteLinkView>> {
    use std::collections::{BTreeMap, BTreeSet};

    use arkret_wire::{CurrentSelector as S, CurrentState};
    snapshot.require_full_recovery()?;
    let mut definitions = BTreeMap::new();
    let mut lifecycle = BTreeMap::new();
    let mut uses = BTreeMap::<arkret_wire::RealmInviteLinkId, BTreeSet<Vec<u8>>>::new();
    let invalid = || WireError::Protocol("invalid Realm invite link snapshot projection".into());
    for row in &snapshot.current_state_entries {
        let CurrentState::Value {
            selector, value, ..
        } = row;
        match selector {
            S::RealmInviteLinkDefinition {
                realm_invite_link_id,
            } => {
                let definition: RealmInviteLinkDefinitionValue =
                    serde_json::from_value(value.clone())?;
                if definition.create_event_id != realm_invite_link_id.event_id()
                    || definitions
                        .insert(realm_invite_link_id.clone(), definition)
                        .is_some()
                {
                    return Err(invalid());
                }
            }
            S::RealmInviteLinkLifecycle {
                realm_invite_link_id,
            } => {
                let state: RealmInviteLinkLifecycle = serde_json::from_value(value.clone())?;
                if lifecycle
                    .insert(realm_invite_link_id.clone(), state)
                    .is_some()
                {
                    return Err(invalid());
                }
            }
            S::RealmInviteLinkUse {
                realm_invite_link_id,
                subject_account_id,
            } => {
                let fact: RealmInviteLinkUseRecord = serde_json::from_value(value.clone())?;
                if fact.realm_invite_link_id != *realm_invite_link_id
                    || fact.subject_account_id != *subject_account_id
                    || !uses
                        .entry(realm_invite_link_id.clone())
                        .or_default()
                        .insert(arkret_canonical::canonical_json_bytes(subject_account_id)?)
                {
                    return Err(invalid());
                }
            }
            _ => {}
        }
    }
    if lifecycle.keys().ne(definitions.keys())
        || uses.keys().any(|id| !definitions.contains_key(id))
    {
        return Err(invalid());
    }
    let mut views = Vec::new();
    for (id, definition) in definitions {
        let count = u32::try_from(uses.get(&id).map_or(0, BTreeSet::len)).map_err(|_| invalid())?;
        if count > definition.max_uses {
            return Err(invalid());
        }
        let status = if lifecycle[&id] == RealmInviteLinkLifecycle::Revoked {
            RealmInviteLinkStatus::Revoked
        } else if snapshot.created_at >= definition.expires_at {
            RealmInviteLinkStatus::Expired
        } else if count == definition.max_uses {
            RealmInviteLinkStatus::Exhausted
        } else {
            RealmInviteLinkStatus::Active
        };
        views.push(RealmInviteLinkView {
            realm_invite_link_id: id,
            realm_id: snapshot.realm_id.clone(),
            inviter_account_id: definition
                .creator_actor_id
                .as_account_id()
                .ok_or_else(invalid)?
                .clone(),
            expires_at: definition.expires_at,
            max_uses: definition.max_uses,
            use_count: count,
            status,
            create_event_id: definition.create_event_id,
            as_of: snapshot.created_at,
        });
    }
    Ok(views)
}
