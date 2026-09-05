//! Holder-private Station-written quarantine cells.
//!
//! `ak.account.holder_quarantine` is the single pending-review carrier for the
//! two closed admission surfaces named by `surface_kind`: private invite
//! delivery, and `ak.self.consent.command.request.v1`. Contact delivery is
//! deliberately not a branch here - a Contact request keeps its own
//! `pending_incoming` state machine and MUST NOT get a second parallel review
//! carrier - even though it shares the same new-source quota chokepoint.
//!
//! Membership in `quarantine_entries` is the only state the cell expresses, so
//! an entry carries no status member: it is pending review until the holder
//! reviews it or its TTL discards it, and leaving that state removes it from
//! the array.

use arkret_wire::{
    AccountId, ConsentRequestScope, ConsentScope, DidCoreId, EventId, Hash, Result, WireError,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

crate::string_marker!(HolderQuarantineSchema, V1, "ak.schema.holder_quarantine.v1");
crate::string_marker!(HolderQuarantineInviteScope, Invite, "invite");
crate::string_marker!(
    HolderQuarantineInvalidationReason,
    ConsentRevoke,
    "consent_revoke"
);

/// Closed discriminator for the admission surface that produced an entry. An
/// unregistered value fails closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum HolderQuarantineSurfaceKind {
    InviteDelivery,
    ConsentRequest,
}

/// Introduction evidence kind. It exists only on the `invite_delivery` branch:
/// a consent request presents no introduction evidence, so any value there
/// would be fabricated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum HolderQuarantineIntroductionKind {
    LocatorRef,
    ConsentGrant,
    SharedRealm,
    HandleClaim,
    SameStation,
    ExplicitAddress,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum InviteTrustTier {
    High,
    Discovery,
    Low,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum HolderQuarantineInvalidationScope {
    Invite,
    Any,
}

/// Closed tagged union over the two admission surfaces.
///
/// Every member the schema declares for exactly one branch lives inside that
/// branch, so a cross-filled entry - an `invite_delivery` without its
/// introduction evidence, or a `consent_request` carrying `invite_event_id`,
/// `request_digest` or `idempotency_key_digest` - has no Rust representation.
/// `consent_scope` is likewise branch-local: `invite_delivery` pins the `invite`
/// constant and `consent_request` admits section 4 without it.
///
/// The `consent_request` branch deliberately carries no digest. Its operation
/// declares `idempotency_mechanism="none"` and its body has no nonce and no
/// timestamp, so there is no wire source for one; deduplication is holder-local
/// live-entry uniqueness over
/// `(account_id, source_peer_principal_id, consent_scope)` instead. Adding a
/// third digest here would create a second, unsourced deduplication rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "surface_kind", rename_all = "snake_case", deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub enum HolderQuarantineSurface {
    InviteDelivery {
        consent_scope: HolderQuarantineInviteScope,
        introduction_kind: HolderQuarantineIntroductionKind,
        effective_kind: HolderQuarantineIntroductionKind,
        trust_tier: InviteTrustTier,
        invite_event_id: EventId,
        request_digest: Hash,
        idempotency_key_digest: Hash,
    },
    ConsentRequest {
        consent_scope: ConsentRequestScope,
    },
}

impl HolderQuarantineSurface {
    #[must_use]
    pub const fn surface_kind(&self) -> HolderQuarantineSurfaceKind {
        match self {
            Self::InviteDelivery { .. } => HolderQuarantineSurfaceKind::InviteDelivery,
            Self::ConsentRequest { .. } => HolderQuarantineSurfaceKind::ConsentRequest,
        }
    }

    #[must_use]
    pub const fn consent_scope(&self) -> ConsentScope {
        match self {
            Self::InviteDelivery { .. } => ConsentScope::Invite,
            Self::ConsentRequest { consent_scope } => (*consent_scope).as_consent_scope(),
        }
    }

    /// Accepted invite Event of the `invite_delivery` branch, if this is one.
    #[must_use]
    pub const fn invite_event_id(&self) -> Option<&EventId> {
        match self {
            Self::InviteDelivery {
                invite_event_id, ..
            } => Some(invite_event_id),
            Self::ConsentRequest { .. } => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HolderQuarantineEntry {
    pub entry_digest: Hash,
    pub account_id: AccountId,
    pub source_peer_principal_id: DidCoreId,
    pub source_id: DidCoreId,
    #[serde(flatten)]
    pub surface: HolderQuarantineSurface,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub received_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
}

impl HolderQuarantineEntry {
    #[must_use]
    pub const fn surface_kind(&self) -> HolderQuarantineSurfaceKind {
        self.surface.surface_kind()
    }

    #[must_use]
    pub const fn consent_scope(&self) -> ConsentScope {
        self.surface.consent_scope()
    }

    /// Holder-local live-entry identity of the `consent_request` branch. Two
    /// live entries sharing it are the same pending request, not a replay to
    /// record twice.
    #[must_use]
    pub fn consent_request_live_key(
        &self,
    ) -> Option<(&AccountId, &DidCoreId, ConsentRequestScope)> {
        match &self.surface {
            HolderQuarantineSurface::ConsentRequest { consent_scope } => Some((
                &self.account_id,
                &self.source_peer_principal_id,
                *consent_scope,
            )),
            HolderQuarantineSurface::InviteDelivery { .. } => None,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HolderQuarantineEntryWire {
    entry_digest: Hash,
    account_id: AccountId,
    source_peer_principal_id: DidCoreId,
    source_id: DidCoreId,
    surface_kind: HolderQuarantineSurfaceKind,
    consent_scope: ConsentScope,
    introduction_kind: Option<HolderQuarantineIntroductionKind>,
    effective_kind: Option<HolderQuarantineIntroductionKind>,
    trust_tier: Option<InviteTrustTier>,
    invite_event_id: Option<EventId>,
    request_digest: Option<Hash>,
    idempotency_key_digest: Option<Hash>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    received_at: DateTime<Utc>,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    expires_at: DateTime<Utc>,
}

fn holder_quarantine_surface_from_parts(
    wire: &mut HolderQuarantineEntryWire,
) -> std::result::Result<HolderQuarantineSurface, String> {
    match (
        wire.surface_kind,
        wire.consent_scope,
        wire.introduction_kind,
        wire.effective_kind,
        wire.trust_tier,
        wire.invite_event_id.take(),
        wire.request_digest.take(),
        wire.idempotency_key_digest.take(),
    ) {
        (
            HolderQuarantineSurfaceKind::InviteDelivery,
            ConsentScope::Invite,
            Some(introduction_kind),
            Some(effective_kind),
            Some(trust_tier),
            Some(invite_event_id),
            Some(request_digest),
            Some(idempotency_key_digest),
        ) => Ok(HolderQuarantineSurface::InviteDelivery {
            consent_scope: HolderQuarantineInviteScope::Invite,
            introduction_kind,
            effective_kind,
            trust_tier,
            invite_event_id,
            request_digest,
            idempotency_key_digest,
        }),
        (
            HolderQuarantineSurfaceKind::ConsentRequest,
            scope,
            None,
            None,
            None,
            None,
            None,
            None,
        ) => ConsentRequestScope::from_consent_scope(scope)
            .map(|consent_scope| HolderQuarantineSurface::ConsentRequest { consent_scope })
            .ok_or_else(|| {
                "consent_request quarantine entry must not request the invite scope".to_owned()
            }),
        _ => Err(
            "holder quarantine entry must carry exactly the members selected by surface_kind"
                .to_owned(),
        ),
    }
}

impl<'de> Deserialize<'de> for HolderQuarantineEntry {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut wire = HolderQuarantineEntryWire::deserialize(deserializer)?;
        let surface =
            holder_quarantine_surface_from_parts(&mut wire).map_err(serde::de::Error::custom)?;
        Ok(Self {
            entry_digest: wire.entry_digest,
            account_id: wire.account_id,
            source_peer_principal_id: wire.source_peer_principal_id,
            source_id: wire.source_id,
            surface,
            received_at: wire.received_at,
            expires_at: wire.expires_at,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HolderQuarantineInvalidation {
    pub reason: HolderQuarantineInvalidationReason,
    pub peer_principal_id: DidCoreId,
    pub consent_scope: HolderQuarantineInvalidationScope,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub revoked_at: DateTime<Utc>,
    pub removed_entries: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
pub struct HolderQuarantine {
    pub schema: HolderQuarantineSchema,
    #[serde(with = "arkret_wire::serde_helpers::canonical_timestamp")]
    pub updated_at: DateTime<Utc>,
    pub quarantine_entries: Vec<HolderQuarantineEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_invalidation: Option<HolderQuarantineInvalidation>,
}

impl HolderQuarantine {
    pub fn new(updated_at: DateTime<Utc>) -> Self {
        Self {
            schema: HolderQuarantineSchema::V1,
            updated_at,
            quarantine_entries: Vec::new(),
            last_invalidation: None,
        }
    }

    /// Entries of one admission surface, oldest first. Holder review is per
    /// surface: the two branches share this cell but not their terminal
    /// semantics.
    pub fn entries_for(
        &self,
        surface_kind: HolderQuarantineSurfaceKind,
    ) -> impl Iterator<Item = &HolderQuarantineEntry> {
        self.quarantine_entries
            .iter()
            .filter(move |entry| entry.surface_kind() == surface_kind)
    }

    /// Live `consent_request` entry for one holder-local dedup key, if any.
    /// Every entry in the cell is live by construction, so a hit means the
    /// repeat request is a no-op that MUST NOT bill the new-source quota.
    pub fn live_consent_request(
        &self,
        source_peer_principal_id: &DidCoreId,
        consent_scope: ConsentRequestScope,
    ) -> Option<&HolderQuarantineEntry> {
        self.quarantine_entries.iter().find(|entry| {
            matches!(
                &entry.surface,
                HolderQuarantineSurface::ConsentRequest { consent_scope: scope }
                    if *scope == consent_scope
            ) && &entry.source_peer_principal_id == source_peer_principal_id
        })
    }

    /// Check the cell against its authenticated holder, not an identity inferred
    /// from the first entry. An empty cell still belongs to one exact account.
    pub fn validate_holder(&self, account_id: &AccountId) -> Result<()> {
        account_id.validate()?;
        let mut digests = std::collections::BTreeSet::new();
        let mut consent_request_keys = std::collections::BTreeSet::new();
        if self.quarantine_entries.len() > 200
            || self
                .quarantine_entries
                .windows(2)
                .any(|pair| pair[0].received_at > pair[1].received_at)
        {
            return Err(WireError::Protocol(
                "holder quarantine must contain at most 200 entries, oldest first".to_owned(),
            ));
        }
        for entry in &self.quarantine_entries {
            if &entry.account_id != account_id
                || entry.received_at >= entry.expires_at
                || entry.received_at > self.updated_at
                || entry.expires_at <= self.updated_at
                || !digests.insert(&entry.entry_digest)
            {
                return Err(WireError::Protocol(
                    "holder quarantine contains a foreign, duplicate, expired, or invalid entry"
                        .to_owned(),
                ));
            }
            if let Some((_, source_peer_principal_id, consent_scope)) =
                entry.consent_request_live_key()
                && !consent_request_keys.insert((source_peer_principal_id, consent_scope))
            {
                return Err(WireError::Protocol(
                    "holder quarantine holds two live consent_request entries for one \
                     (account_id, source_peer_principal_id, consent_scope)"
                        .to_owned(),
                ));
            }
        }
        if self.last_invalidation.as_ref().is_some_and(|value| {
            !(1..=200).contains(&value.removed_entries) || value.revoked_at > self.updated_at
        }) {
            return Err(WireError::Protocol(
                "invalid holder quarantine revocation diagnostic".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::*;

    fn invite_entry_json() -> Value {
        json!({
            "entry_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "account_id": {
                "principal_id": "ak:did_core:key:z6MkfHolderCoreOne",
                "station_id": "ak:did_core:web:station.example"
            },
            "source_peer_principal_id": "ak:did_core:key:z6MkfPeerCoreOne",
            "source_id": "ak:did_core:web:peer.example",
            "surface_kind": "invite_delivery",
            "consent_scope": "invite",
            "introduction_kind": "locator_ref",
            "effective_kind": "locator_ref",
            "trust_tier": "high",
            "invite_event_id": "ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5",
            "request_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "idempotency_key_digest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "received_at": "2026-09-05T00:00:00.000Z",
            "expires_at": "2026-10-05T00:00:00.000Z"
        })
    }

    fn consent_request_entry_json() -> Value {
        json!({
            "entry_digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "account_id": {
                "principal_id": "ak:did_core:key:z6MkfHolderCoreOne",
                "station_id": "ak:did_core:web:station.example"
            },
            "source_peer_principal_id": "ak:did_core:key:z6MkfPeerCoreTwo",
            "source_id": "ak:did_core:web:peer.example",
            "surface_kind": "consent_request",
            "consent_scope": "direct_message",
            "received_at": "2026-09-05T00:00:00.000Z",
            "expires_at": "2026-10-05T00:00:00.000Z"
        })
    }

    #[test]
    fn both_branches_round_trip_without_leaking_the_other_branch_members() {
        let invite: HolderQuarantineEntry = serde_json::from_value(invite_entry_json()).unwrap();
        assert_eq!(
            invite.surface_kind(),
            HolderQuarantineSurfaceKind::InviteDelivery
        );
        assert_eq!(invite.consent_scope(), ConsentScope::Invite);
        assert!(invite.consent_request_live_key().is_none());
        assert_eq!(serde_json::to_value(&invite).unwrap(), invite_entry_json());

        let request: HolderQuarantineEntry =
            serde_json::from_value(consent_request_entry_json()).unwrap();
        assert_eq!(
            request.surface_kind(),
            HolderQuarantineSurfaceKind::ConsentRequest
        );
        assert_eq!(request.consent_scope(), ConsentScope::DirectMessage);
        assert!(request.consent_request_live_key().is_some());
        let encoded = serde_json::to_value(&request).unwrap();
        for absent in [
            "introduction_kind",
            "effective_kind",
            "trust_tier",
            "invite_event_id",
            "request_digest",
            "idempotency_key_digest",
        ] {
            assert!(encoded.get(absent).is_none(), "{absent} leaked");
        }
        assert_eq!(encoded, consent_request_entry_json());
    }

    #[test]
    fn consent_request_rejects_every_invite_delivery_member() {
        for member in [
            ("introduction_kind", json!("locator_ref")),
            ("effective_kind", json!("locator_ref")),
            ("trust_tier", json!("high")),
            (
                "invite_event_id",
                json!("ak:event:AS8XThowW7JnZc80U10gJh-_lqkA-iSQ-LAvBXj6_9O5"),
            ),
            (
                "request_digest",
                json!("sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
            ),
            (
                "idempotency_key_digest",
                json!("sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
            ),
        ] {
            let mut value = consent_request_entry_json();
            value[member.0] = member.1;
            assert!(
                serde_json::from_value::<HolderQuarantineEntry>(value).is_err(),
                "consent_request accepted {}",
                member.0
            );
        }
    }

    #[test]
    fn consent_request_rejects_the_invite_scope() {
        let mut value = consent_request_entry_json();
        value["consent_scope"] = json!("invite");
        assert!(serde_json::from_value::<HolderQuarantineEntry>(value).is_err());
    }

    #[test]
    fn invite_delivery_rejects_a_non_invite_scope_and_missing_evidence() {
        let mut scope = invite_entry_json();
        scope["consent_scope"] = json!("direct_message");
        assert!(serde_json::from_value::<HolderQuarantineEntry>(scope).is_err());

        for member in [
            "introduction_kind",
            "effective_kind",
            "trust_tier",
            "invite_event_id",
            "request_digest",
            "idempotency_key_digest",
        ] {
            let mut value = invite_entry_json();
            value.as_object_mut().unwrap().remove(member);
            assert!(
                serde_json::from_value::<HolderQuarantineEntry>(value).is_err(),
                "invite_delivery accepted a missing {member}"
            );
        }
    }

    #[test]
    fn an_unregistered_surface_kind_fails_closed() {
        let mut value = consent_request_entry_json();
        value["surface_kind"] = json!("contact_delivery");
        assert!(serde_json::from_value::<HolderQuarantineEntry>(value).is_err());
    }

    #[test]
    fn two_live_consent_requests_for_one_dedup_key_are_rejected() {
        let account_id = serde_json::from_value(json!({
            "principal_id": "ak:did_core:key:z6MkfHolderCoreOne",
            "station_id": "ak:did_core:web:station.example"
        }))
        .unwrap();
        let first: HolderQuarantineEntry =
            serde_json::from_value(consent_request_entry_json()).unwrap();
        let mut second_json = consent_request_entry_json();
        second_json["entry_digest"] =
            json!("sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let second: HolderQuarantineEntry = serde_json::from_value(second_json).unwrap();

        let mut cell = HolderQuarantine::new("2026-09-06T00:00:00.000Z".parse().unwrap());
        cell.quarantine_entries = vec![first.clone(), second];
        assert!(cell.validate_holder(&account_id).is_err());

        let mut widened = cell;
        widened.quarantine_entries[1].surface = HolderQuarantineSurface::ConsentRequest {
            consent_scope: ConsentRequestScope::VoiceCall,
        };
        widened.validate_holder(&account_id).unwrap();

        assert!(
            widened
                .live_consent_request(
                    &first.source_peer_principal_id,
                    ConsentRequestScope::VoiceCall
                )
                .is_some()
        );
        assert!(
            widened
                .live_consent_request(
                    &first.source_peer_principal_id,
                    ConsentRequestScope::Presence
                )
                .is_none()
        );
        assert_eq!(
            widened
                .entries_for(HolderQuarantineSurfaceKind::ConsentRequest)
                .count(),
            2
        );
        assert_eq!(
            widened
                .entries_for(HolderQuarantineSurfaceKind::InviteDelivery)
                .count(),
            0
        );
    }
}
