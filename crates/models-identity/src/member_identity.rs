//! R3.2 — Realm-scoped `MemberIdentity` segment + replacement event payload.
//!
//! Spec source (arkret-spec @ b56cab1, 2026-05-28):
//! * `artifacts/schemas/member-identity.schema.json`
//! * `artifacts/schemas/event-payload.schema.json#/$defs/member_identity_update_payload`
//! * `artifacts/schemas/account-subscribe-frame.schema.json#/$defs/member_roster_entry`
//!
//! R3.2 wire-breaking changes:
//! * `MemberIdentity` no longer carries `primary_handle` / `handles[]`; handle lifecycle is
//!   governed solely by `ak.schema.handle_claim.v1`. This object discloses `subject_actor_id` +
//!   `display_profile` for Realm UI projection only.
//! * The payload does not repeat the locally derivable carrier digest.
//! * Roster `identity_state_digest` renamed to `member_display_state_digest` and now folds the
//!   visible handle-claim digest set.
//!
//! Two wire digests plus one local helper live here and MUST NOT be confused:
//! * [`IdentityPayloadCarrier::carrier_sha256`] derives the exact `identity_payload` carrier digest
//!   locally; it is not a payload field.
//! * [`member_identity_effective_set_digest`] → `expected_state_digest` (writer-observed
//!   effective-set guard over the exact signed payloads, `current-results.md` §2).
//! * [`member_display_state_digest`] → roster display cache key (includes effective events +
//!   visible handle-claim digests).

use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
use arkret_wire::DidCoreId;
use arkret_wire::{ActorId, BlobRef, DidUrl, EventId, Hash, RealmId, Result, SchemaId, canonical};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Realm-scoped, actor-scoped full `member_identity` segment.
///
/// Carried by `ak.member.identity.update` in plaintext or inside an
/// `encrypted_envelope` carrier. Replacement events that name
/// `segment=member_identity` MUST carry this complete object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberIdentity {
    /// `ak.schema.member_identity.v1`.
    pub schema: String,
    pub realm_id: RealmId,
    pub actor_id: ActorId,
    pub subject_actor_id: ActorId,
    pub display_profile: DisplayProfile,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub asserted_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        with = "arkret_canonical::serde_helpers::optional_canonical_timestamp"
    )]
    pub expires_at: Option<DateTime<Utc>>,
    pub proof: MemberIdentityProof,
}

impl MemberIdentity {
    pub const SCHEMA: &'static str = SchemaId::MEMBER_IDENTITY_V1;
    /// Constructor that fills in the canonical schema discriminator so
    /// callers can't drift from `ak.schema.member_identity.v1`.
    pub fn new(
        realm_id: RealmId,
        actor_id: ActorId,
        subject_actor_id: ActorId,
        display_profile: DisplayProfile,
        asserted_at: DateTime<Utc>,
        proof: MemberIdentityProof,
    ) -> Self {
        Self {
            schema: SchemaId::MEMBER_IDENTITY_V1.to_owned(),
            realm_id,
            actor_id,
            subject_actor_id,
            display_profile,
            asserted_at,
            expires_at: None,
            proof,
        }
    }

    /// Canonical-JSON digest helper. Returns the `sha256:<hex>` digest
    /// over the RFC 8785 JCS canonical JSON of this MemberIdentity with
    /// the top-level `proof` field excluded. The signature in `proof`
    /// MUST cover the same canonical bytes.
    ///
    /// Exported so soland + inkson + cotest agree on the exact bytes
    /// used for `MemberIdentityProof.payload_digest`.
    pub fn canonical_payload_sha256(&self) -> Result<String> {
        let bytes = self.canonical_payload_bytes()?;
        Ok(canonical::sha256_digest(bytes))
    }

    /// Raw canonical-JSON bytes (RFC 8785 JCS) with the top-level
    /// `proof` field excluded. The signature in `proof` MUST cover the
    /// same canonical bytes.
    pub fn canonical_payload_bytes(&self) -> Result<Vec<u8>> {
        let value = canonical::unsigned_value(self, &["proof"])?;
        Ok(canonical::canonical_json_value_bytes(&value)?)
    }
}

/// Display profile carried inside a [`MemberIdentity`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisplayProfile {
    /// 1..=128 chars per spec; we keep validation at the schema layer
    /// rather than re-implementing UTF-16 codepoint counting here.
    pub display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_blob_ref: Option<BlobRef>,
}

/// Signing proof carried by every [`MemberIdentity`]. Verified
/// out-of-band (MLS / DID signature suite); this struct just types the
/// wire surface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberIdentityProof {
    /// `did:method:identifier#fragment`.
    pub verification_method: DidUrl,
    pub signature_algorithm: MemberIdentitySignatureAlgorithm,
    pub payload_digest: Hash,
    /// Base64url-encoded raw signature bytes (per schema pattern
    /// `^[A-Za-z0-9_-]+$`).
    pub signature: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberIdentitySignatureAlgorithm {
    Ed25519,
    #[serde(rename = "ES256")]
    Es256,
    #[serde(rename = "ES384")]
    Es384,
}

/// `segment` field on a `ak.member.identity.update` payload. v1 core
/// defines a single full `member_identity` segment; v1 receivers MUST
/// reject any other value. Narrower segments require a future
/// schema/profile revision that extends this enum.
pub use arkret_wire::MemberIdentitySegment;

/// One edge in [`MemberIdentityUpdatePayload::replaces`]. Identifies the
/// prior event id + the `payload_digest` of that event's
/// `identity_payload` carrier wrapper. The digest binding prevents
/// replacing a different payload under a reused / confused event id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberIdentityReplacementRef {
    pub event_id: EventId,
    pub payload_digest: Hash,
}

/// Carrier for the actual `member_identity` segment body. Mirrors the
/// `oneOf` in the spec schema: plaintext [`MemberIdentity`] OR encrypted
/// envelope (carried as raw [`Value`] because the SDK does not yet ship
/// a typed `EncryptedEnvelope`).
// API-stable carrier wrapper consumed by inkson/cotest. Boxing
// `MemberIdentity` would be a breaking change for the constructor
// pattern `IdentityPayloadCarrier::MemberIdentity { member_identity }`.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum IdentityPayloadCarrier {
    MemberIdentity { member_identity: MemberIdentity },
    EncryptedContent { encrypted_content: Value },
}

impl IdentityPayloadCarrier {
    /// Canonical-JSON digest of the carrier wrapper object. This is the
    /// value that goes into `MemberIdentityReplacementRef.payload_digest`.
    pub fn carrier_sha256(&self) -> Result<String> {
        Ok(canonical::sha256_digest(canonical::canonical_json_bytes(
            self,
        )?))
    }
}

/// Typed payload for `ak.member.identity.update`. Append-only
/// replacement event for one Realm-scoped member identity segment.
///
/// Service-visible metadata names the segment and the prior events it
/// replaces; the segment body is plaintext or the original encrypted
/// envelope and MUST contain the complete data for that segment.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberIdentityUpdatePayload {
    pub realm_id: RealmId,
    pub member_id: ActorId,
    pub segment: MemberIdentitySegment,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub replaces: Vec<MemberIdentityReplacementRef>,
    pub identity_payload: IdentityPayloadCarrier,
    /// Optimistic concurrency guard. When present, MUST equal the
    /// writer-observed effective-set digest computed by
    /// [`member_identity_effective_set_digest`]. This is not the locally
    /// derived carrier digest or the roster `member_display_state_digest`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_state_digest: Option<Hash>,
}

/// One accepted identity dot. The payload stays raw because the digest names
/// its exact signed field set, including explicitly present empty members.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberIdentityUpdateAssertion {
    pub tag_id: String,
    pub value: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberIdentityUpdatesCurrentValue {
    pub assertions: Vec<MemberIdentityUpdateAssertion>,
}

impl MemberIdentityUpdatesCurrentValue {
    /// Validate the closed family without verifying display proofs or folding
    /// replacement edges, neither of which may reject an accepted assertion.
    pub fn validate_for_tuple(
        &self,
        realm_id: &RealmId,
        member_id: &ActorId,
        segment: MemberIdentitySegment,
    ) -> Result<()> {
        let mut dots = BTreeSet::new();
        for assertion in &self.assertions {
            let event_id = assertion.tag_id.strip_suffix(":0").ok_or_else(|| {
                arkret_wire::WireError::Protocol(
                    "member identity dot must name its one registered assertion".to_owned(),
                )
            })?;
            EventId::new(event_id)?;
            if !dots.insert(&assertion.tag_id) {
                return Err(arkret_wire::WireError::Protocol(
                    "duplicate member identity assertion dot".to_owned(),
                ));
            }
            let payload: MemberIdentityUpdatePayload =
                serde_json::from_value(assertion.value.clone())
                    .map_err(|error| arkret_wire::WireError::Protocol(error.to_string()))?;
            if &payload.realm_id != realm_id
                || &payload.member_id != member_id
                || payload.segment != segment
            {
                return Err(arkret_wire::WireError::Protocol(
                    "member identity assertion differs from its exact selector".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Per-(event_id, segment) entry used by
/// [`member_identity_effective_set_digest`] and
/// [`member_display_state_digest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EffectiveIdentityEntry {
    pub event_id: EventId,
    pub segment: MemberIdentitySegment,
    pub payload_digest: Hash,
}

/// Visible handle-claim summary folded into the roster
/// [`member_display_state_digest`]. Mirrors the spec
/// `{claim_digest, status, revocation_digest, fresh_until}` status-view summary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RosterHandleClaimDigestEntry {
    pub claim_digest: Hash,
    pub status: crate::HandleClaimStatus,
    pub revocation_digest: Option<Hash>,
    #[serde(with = "arkret_canonical::serde_helpers::canonical_timestamp")]
    pub fresh_until: DateTime<Utc>,
}

/// MID-6 — effective-set helper.
///
/// Given a slice of candidate `(event_id, payload)` pairs for a single
/// `(realm_id, actor_id, segment)` tuple, returns the events that are
/// not pointed at by any valid replacement edge in any other candidate.
///
/// "Valid replacement edge" means: there exists a candidate whose
/// `payload.replaces[]` contains a [`MemberIdentityReplacementRef`] with
/// `event_id == this.event_id` AND `payload_digest` equal to the
/// canonical-JSON digest of `this.payload.identity_payload` carrier.
///
/// The caller is expected to have already filtered by `(realm_id,
/// actor_id, segment)` and to have validated the signature on each
/// underlying payload — the helper is purely a graph operation over
/// the replacement edges.
pub fn effective_identity_events<'a, I>(
    candidates: I,
) -> Result<Vec<(&'a EventId, &'a MemberIdentityUpdatePayload)>>
where
    I: IntoIterator<Item = (&'a EventId, &'a MemberIdentityUpdatePayload)>,
{
    let materialised: Vec<(&'a EventId, &'a MemberIdentityUpdatePayload)> =
        candidates.into_iter().collect();

    // Build digest cache once.
    let mut carrier_digests = BTreeMap::<&str, String>::new();
    for (event_id, payload) in &materialised {
        let digest = payload.identity_payload.carrier_sha256()?;
        carrier_digests.insert(event_id.as_str(), digest);
    }

    // Collect ids that any candidate validly replaces.
    let mut replaced: BTreeSet<String> = BTreeSet::new();
    for (_, payload) in &materialised {
        for edge in &payload.replaces {
            let edge_event = edge.event_id.as_str();
            if let Some(actual_digest) = carrier_digests.get(edge_event)
                && edge.payload_digest.as_str() == actual_digest.as_str()
            {
                replaced.insert(edge_event.to_owned());
            }
        }
    }

    let effective = materialised
        .into_iter()
        .filter(|(event_id, _)| !replaced.contains(event_id.as_str()))
        .collect();
    Ok(effective)
}

/// `expected_state_digest` writer-observed effective-set guard
/// (`current-results.md` §2, decision 0115).
///
/// `"sha256:" || lowercase_hex(SHA-256(RFC8785_JCS(v)))` with no domain
/// prefix, where `v` is the array of the exact signed payload objects of every
/// update in the `(realm_id, member_id, segment)` effective set, ordered by
/// the carrying `event_id` ascending. The empty effective set digests `[]`.
/// Callers pass the payloads exactly as signed, never a re-serialized typed
/// struct, so the digest names the bytes the writer observed.
pub fn member_identity_effective_set_digest(effective: &[(&EventId, &Value)]) -> Result<String> {
    let mut sorted: Vec<&(&EventId, &Value)> = effective.iter().collect();
    sorted.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
    let payloads: Vec<&Value> = sorted.into_iter().map(|(_, payload)| *payload).collect();
    Ok(canonical::sha256_digest(canonical::canonical_json_bytes(
        &payloads,
    )?))
}

/// R3.2 — roster `member_display_state_digest` projection.
///
/// SHA-256 over RFC 8785 JCS canonical JSON of
/// `{realm_id, actor_id, effective_events:[{event_id, segment, payload_digest}],
///   handle_claims:[{claim_digest, status, revocation_digest, fresh_until}]}`
/// with `effective_events` sorted by `(segment, event_id)` and
/// `handle_claims` sorted by `claim_digest`.
///
/// Used for roster display cache invalidation. Folds the visible
/// handle-claim digest set so handle reassignment (issuer signs a new
/// claim / revokes an old one) changes the digest. A refreshed signed status
/// view also changes `fresh_until`, so stale evidence cannot retain a roster
/// display cache key.
pub fn member_display_state_digest(
    realm_id: &RealmId,
    actor_id: &ActorId,
    entries: &[EffectiveIdentityEntry],
    handle_claims: &[RosterHandleClaimDigestEntry],
) -> Result<String> {
    let sorted_events = sorted_effective_entries(entries);
    let mut sorted_claims: Vec<&RosterHandleClaimDigestEntry> = handle_claims.iter().collect();
    sorted_claims.sort_by(|a, b| a.claim_digest.as_str().cmp(b.claim_digest.as_str()));

    let projection = serde_json::json!({
        "realm_id": realm_id,
        "actor_id": actor_id,
        "effective_events": sorted_events,
        "handle_claims": sorted_claims,
    });
    Ok(canonical::sha256_digest(canonical::canonical_json_bytes(
        &projection,
    )?))
}

fn sorted_effective_entries(entries: &[EffectiveIdentityEntry]) -> Vec<&EffectiveIdentityEntry> {
    let mut sorted: Vec<&EffectiveIdentityEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| {
        let seg_a = serde_json::to_string(&a.segment).unwrap_or_default();
        let seg_b = serde_json::to_string(&b.segment).unwrap_or_default();
        seg_a
            .cmp(&seg_b)
            .then_with(|| a.event_id.as_str().cmp(b.event_id.as_str()))
    });
    sorted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_realm() -> RealmId {
        RealmId::new("ak:realm:AdkQ-RmB1a8zyc52yl9GWAsodQ_EUle1WAVZqbO7pc19").unwrap()
    }

    fn fake_actor(label: &str) -> ActorId {
        ActorId::service(DidCoreId::new(format!("ak:did_core:webvh:{label}")).unwrap())
    }

    fn fake_principal(label: &str) -> ActorId {
        ActorId::service(DidCoreId::new(format!("ak:did_core:webvh:{label}")).unwrap())
    }

    fn sample_identity(name: &str) -> MemberIdentity {
        MemberIdentity::new(
            fake_realm(),
            fake_actor("alice"),
            fake_principal("alice-principal"),
            DisplayProfile {
                display_name: name.to_owned(),
                avatar_blob_ref: None,
            },
            Utc::now(),
            MemberIdentityProof {
                verification_method: DidUrl::new("did:webvh:z6mkfixture:alice.example#key-1")
                    .unwrap(),
                signature_algorithm: MemberIdentitySignatureAlgorithm::Ed25519,
                payload_digest: Hash::new(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                signature: "AAAA".to_owned(),
            },
        )
    }

    fn fake_event_ref(suffix: &str) -> EventId {
        EventId::from_event_digest(
            &Hash::new(arkret_canonical::sha256_digest(suffix.as_bytes())).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn canonical_payload_digest_excludes_proof() {
        let a = sample_identity("Alice");
        let mut b = a.clone();
        // Mutate proof.signature; canonical_payload_sha256 MUST be
        // invariant under proof field mutations.
        b.proof.signature = "BBBB".to_owned();
        // asserted_at is the only timestamp; pin it equal across both.
        b.asserted_at = a.asserted_at;
        assert_eq!(
            a.canonical_payload_sha256().unwrap(),
            b.canonical_payload_sha256().unwrap(),
        );
    }

    #[test]
    fn replacement_filter_drops_replaced_events() {
        let id_a = sample_identity("Alice v1");
        let id_b = sample_identity("Alice v2");
        let event_a = fake_event_ref("000a");
        let event_b = fake_event_ref("000b");

        let carrier_a = IdentityPayloadCarrier::MemberIdentity {
            member_identity: id_a,
        };
        let carrier_b = IdentityPayloadCarrier::MemberIdentity {
            member_identity: id_b,
        };

        let digest_a = Hash::new(carrier_a.carrier_sha256().unwrap()).unwrap();

        let payload_a = MemberIdentityUpdatePayload {
            realm_id: fake_realm(),
            member_id: fake_actor("alice"),
            segment: MemberIdentitySegment::MemberIdentity,
            replaces: vec![],
            identity_payload: carrier_a,
            expected_state_digest: None,
        };
        let payload_b = MemberIdentityUpdatePayload {
            realm_id: fake_realm(),
            member_id: fake_actor("alice"),
            segment: MemberIdentitySegment::MemberIdentity,
            replaces: vec![MemberIdentityReplacementRef {
                event_id: event_a.clone(),
                payload_digest: digest_a,
            }],
            identity_payload: carrier_b,
            expected_state_digest: None,
        };

        let effective =
            effective_identity_events([(&event_a, &payload_a), (&event_b, &payload_b)]).unwrap();
        assert_eq!(effective.len(), 1);
        assert_eq!(effective[0].0.as_str(), event_b.as_str());
    }

    #[test]
    fn replacement_with_wrong_digest_is_ignored() {
        let id_a = sample_identity("Alice v1");
        let id_b = sample_identity("Alice v2");
        let event_a = fake_event_ref("0010");
        let event_b = fake_event_ref("0011");

        let carrier_a = IdentityPayloadCarrier::MemberIdentity {
            member_identity: id_a,
        };
        let carrier_b = IdentityPayloadCarrier::MemberIdentity {
            member_identity: id_b,
        };

        let payload_a = MemberIdentityUpdatePayload {
            realm_id: fake_realm(),
            member_id: fake_actor("alice"),
            segment: MemberIdentitySegment::MemberIdentity,
            replaces: vec![],
            identity_payload: carrier_a,
            expected_state_digest: None,
        };
        let payload_b = MemberIdentityUpdatePayload {
            realm_id: fake_realm(),
            member_id: fake_actor("alice"),
            segment: MemberIdentitySegment::MemberIdentity,
            replaces: vec![MemberIdentityReplacementRef {
                event_id: event_a.clone(),
                // Wrong digest — must NOT be applied.
                payload_digest: Hash::new(
                    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                )
                .unwrap(),
            }],
            identity_payload: carrier_b,
            expected_state_digest: None,
        };

        let effective =
            effective_identity_events([(&event_a, &payload_a), (&event_b, &payload_b)]).unwrap();
        assert_eq!(effective.len(), 2);
    }

    #[test]
    fn identity_state_digest_is_sort_stable() {
        let first = fake_event_ref("0020");
        let second = fake_event_ref("0021");
        let payload_first = serde_json::json!({"segment": "member_identity", "n": 1});
        let payload_second = serde_json::json!({"segment": "member_identity", "n": 2});
        let forward = member_identity_effective_set_digest(&[
            (&first, &payload_first),
            (&second, &payload_second),
        ])
        .unwrap();
        let reverse = member_identity_effective_set_digest(&[
            (&second, &payload_second),
            (&first, &payload_first),
        ])
        .unwrap();
        assert_eq!(forward, reverse);
    }

    #[test]
    fn empty_effective_set_digests_the_empty_array() {
        assert_eq!(
            member_identity_effective_set_digest(&[]).unwrap(),
            "sha256:4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
        );
    }
    #[test]
    fn current_assertions_preserve_signed_empty_members_and_bad_inner_proof() {
        let realm = fake_realm();
        let actor = ActorId::account(arkret_wire::AccountId::new(
            DidCoreId::new("ak:did_core:web:identity.example").unwrap(),
            DidCoreId::new("ak:did_core:web:station.example").unwrap(),
        ));
        let raw = serde_json::json!({"realm_id":realm,"member_id":actor,"segment":"member_identity",
            "replaces":[],"identity_payload":{"member_identity":sample_identity("Unverified")}});
        let value = serde_json::json!({"assertions":[{"tag_id":format!("{}:0",fake_event_ref("raw-current")),"value":raw}]});
        let parsed: MemberIdentityUpdatesCurrentValue =
            serde_json::from_value(value.clone()).unwrap();
        parsed
            .validate_for_tuple(&realm, &actor, MemberIdentitySegment::MemberIdentity)
            .unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), value);
    }

    #[test]
    fn current_assertion_selector_keeps_station_and_rejects_duplicate_dots_and_aliases() {
        let realm = fake_realm();
        let principal = DidCoreId::new("ak:did_core:web:identity.example").unwrap();
        let first = ActorId::account(arkret_wire::AccountId::new(
            principal.clone(),
            DidCoreId::new("ak:did_core:web:first.example").unwrap(),
        ));
        let second = ActorId::account(arkret_wire::AccountId::new(
            principal,
            DidCoreId::new("ak:did_core:web:second.example").unwrap(),
        ));
        let raw = serde_json::json!({"realm_id":realm,"member_id":first,"segment":"member_identity","identity_payload":{"member_identity":sample_identity("Unverified")}});
        let assertion = serde_json::json!({"tag_id":format!("{}:0",fake_event_ref("selector-current")),"value":raw});
        let parsed: MemberIdentityUpdatesCurrentValue =
            serde_json::from_value(serde_json::json!({"assertions":[assertion]})).unwrap();
        parsed
            .validate_for_tuple(&realm, &first, MemberIdentitySegment::MemberIdentity)
            .unwrap();
        assert!(
            parsed
                .validate_for_tuple(&realm, &second, MemberIdentitySegment::MemberIdentity)
                .is_err()
        );
        let duplicate: MemberIdentityUpdatesCurrentValue =
            serde_json::from_value(serde_json::json!({"assertions":[assertion.clone(),assertion]}))
                .unwrap();
        assert!(
            duplicate
                .validate_for_tuple(&realm, &first, MemberIdentitySegment::MemberIdentity)
                .is_err()
        );
        let mut alias = assertion;
        alias["value"]["actor_id"] = alias["value"]["member_id"].take();
        alias["value"].as_object_mut().unwrap().remove("member_id");
        let invalid: MemberIdentityUpdatesCurrentValue =
            serde_json::from_value(serde_json::json!({"assertions":[alias]})).unwrap();
        assert!(
            invalid
                .validate_for_tuple(&realm, &first, MemberIdentitySegment::MemberIdentity)
                .is_err()
        );
    }
}
