//! Source-signed Directory authorization for exact Event resolve.
//!
//! A source service mints the carrier on the Directory announce face
//! (`ak.directory.announce.v1`) and replays it unchanged on the federation
//! resolve face (`ak.peer.events.read.resolve.v1`), so it is written by
//! `arkret-models-discovery` and read by `arkret-models-collaboration`. Those
//! two model crates are siblings, so the shared carrier lives below both — in
//! the wire vocabulary that already owns every type it is built from.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    Audience, DidCoreId, EventId, Hash, PayloadProof, ProofContextId, RealmId, Result, WireError,
    canonical,
};

/// Source-signed, bounded Directory authorization for exact Event resolve.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectorySourceRefAccess {
    pub kind: DirectorySourceRefAccessKind,
    pub source_id: DidCoreId,
    pub directory_id: DidCoreId,
    pub realm_id: RealmId,
    pub discovery_event_id: EventId,
    pub source_refs: Vec<EventId>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub as_of: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub proof: PayloadProof,
}

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DirectorySourceRefAccessKind {
    #[serde(rename = "directory_announce")]
    DirectoryAnnounce,
}

impl DirectorySourceRefAccess {
    pub fn validate(&self) -> Result<()> {
        if self.source_refs.is_empty() || self.source_refs.len() > 1_024 {
            return Err(WireError::Protocol(
                "directory source-ref access requires 1..=1024 refs".to_owned(),
            ));
        }
        for pair in self.source_refs.windows(2) {
            if pair[0].as_str() >= pair[1].as_str() {
                return Err(WireError::Protocol(
                    "directory source-ref access refs must be canonical-bytewise sorted and unique"
                        .to_owned(),
                ));
            }
        }
        if self.as_of >= self.expires_at {
            return Err(WireError::Protocol(
                "directory source-ref access expiry must follow as_of".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn unsigned_payload(&self) -> Result<serde_json::Value> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .and_then(|object| object.remove("proof"))
            .ok_or_else(|| {
                WireError::Protocol("directory source-ref proof is required".to_owned())
            })?;
        Ok(value)
    }

    pub fn payload_digest(&self) -> Result<Hash> {
        let bytes = canonical::canonical_json_bytes(&self.unsigned_payload()?)?;
        Ok(Hash::new(canonical::sha256_digest(&bytes))?)
    }

    pub fn proof_binding_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        self.proof.validate_production()?;
        let payload_digest = self.payload_digest()?;
        if self.proof.payload_digest != payload_digest || self.proof.proof_purpose.is_some() {
            return Err(WireError::Protocol(
                "directory source-ref proof metadata is invalid".to_owned(),
            ));
        }
        let domain = self
            .proof
            .domain
            .as_ref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                WireError::Protocol("directory source-ref proof requires domain".to_owned())
            })?;
        let audience = self.proof.audience.as_ref().ok_or_else(|| {
            WireError::Protocol("directory source-ref proof requires audience".to_owned())
        })?;
        if !matches!(
            audience,
            Audience::Single(value) if value == self.directory_id.as_str()
        ) {
            return Err(WireError::Protocol(
                "directory source-ref proof audience mismatch".to_owned(),
            ));
        }
        canonical::canonical_json_bytes(&serde_json::json!({
            "context": ProofContextId::DIRECTORY_SOURCE_REF_ACCESS_PROOF_V1,
            "payload_digest": payload_digest,
            "source_id": self.source_id,
            "directory_id": self.directory_id,
            "realm_id": self.realm_id,
            "discovery_event_id": self.discovery_event_id,
            "source_refs": self.source_refs,
            "as_of": canonical::format_timestamp_canonical(self.as_of),
            "expires_at": canonical::format_timestamp_canonical(self.expires_at),
            "verification_method": self.proof.verification_method,
            "created_at": canonical::format_timestamp_canonical(self.proof.created_at),
            "domain": domain,
            "audience": audience,
        }))
        .map_err(Into::into)
    }
}

#[cfg(test)]
mod directory_source_ref_access_tests {
    use super::{DirectorySourceRefAccess, DirectorySourceRefAccessKind};
    use crate::{Audience, DidCoreId, DidUrl, EventId, Hash, PayloadProof, RealmId, proof_kind};

    fn event_id(seed: &[u8]) -> EventId {
        EventId::from_event_digest(
            &Hash::new(arkret_canonical::sha256_digest(seed)).expect("digest"),
        )
        .expect("event id")
    }

    fn access() -> DirectorySourceRefAccess {
        let as_of = "2026-09-01T00:00:00Z".parse().unwrap();
        let directory_id = DidCoreId::new("ak:did_core:web:directory.example").unwrap();
        let mut access = DirectorySourceRefAccess {
            kind: DirectorySourceRefAccessKind::DirectoryAnnounce,
            source_id: DidCoreId::new("ak:did_core:web:station.example").unwrap(),
            directory_id: directory_id.clone(),
            realm_id: RealmId::new(
                "ak:realm:AY789mrKRCQEVlbVgiTgLdjVO5oCMJiUCrF-D-JlRNxI".to_owned(),
            )
            .unwrap(),
            discovery_event_id: event_id(b"discovery"),
            source_refs: vec![event_id(b"discovery"), event_id(b"policy")],
            as_of,
            expires_at: as_of + chrono::Duration::minutes(5),
            proof: PayloadProof {
                kind: proof_kind::DETACHED_JWS.to_owned(),
                verification_method: DidUrl::new("did:web:station.example#notary-key").unwrap(),
                payload_digest: Hash::new(arkret_canonical::sha256_digest(b"placeholder")).unwrap(),
                created_at: as_of,
                domain: Some("ak:trust_domain:example.com".to_owned()),
                audience: Some(Audience::Single(directory_id.to_string())),
                proof_purpose: None,
                jws: "e30..c2ln".to_owned(),
            },
        };
        access
            .source_refs
            .sort_by(|left, right| left.as_str().cmp(right.as_str()));
        access.proof.payload_digest = access.payload_digest().unwrap();
        access
    }

    #[test]
    fn transcript_binds_exact_directory_announce_and_refs() {
        let access = access();
        let transcript: serde_json::Value =
            arkret_canonical::from_canonical_json_slice(&access.proof_binding_bytes().unwrap())
                .unwrap();
        assert_eq!(
            transcript["context"],
            "ak.directory_source_ref_access_proof.v1"
        );
        assert_eq!(transcript["directory_id"], access.directory_id.as_str());
        assert_eq!(
            transcript["discovery_event_id"],
            access.discovery_event_id.as_str()
        );
        assert_eq!(transcript["source_refs"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn rejects_unsorted_expired_wrong_audience_and_mutated_carriers() {
        let valid = access();

        let mut unsorted = valid.clone();
        unsorted.source_refs.reverse();
        assert!(unsorted.validate().is_err());

        let mut expired = valid.clone();
        expired.expires_at = expired.as_of;
        assert!(expired.validate().is_err());

        let mut wrong_audience = valid.clone();
        wrong_audience.proof.audience = Some(Audience::Single(
            "ak:did_core:web:other-directory.example".to_owned(),
        ));
        assert!(wrong_audience.proof_binding_bytes().is_err());

        let mut mutated = valid;
        mutated.discovery_event_id = event_id(b"other-discovery");
        assert!(mutated.proof_binding_bytes().is_err());
    }
}
