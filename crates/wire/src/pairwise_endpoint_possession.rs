//! Minimal-metadata pairwise endpoint possession proof used by SessionGrant
//! issuance (`identity/key-management.md` §6.5).
//!
//! The pairwise endpoint is a Realm-local `did:key` identity that owns no
//! Account, Device or Agent. The proof authenticates possession of that key to
//! the Account Authority; the hosting Station still re-evaluates the actor's
//! current active leaf and join on every admission.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    AccountId, ActorId, Base64UrlString, Did, DidCoreId, DidUrl, Hash, ProofContextId, RealmId,
    RequestId, Result, WireError, canonical,
};

pub const PAIRWISE_ENDPOINT_POSSESSION_PROOF_CONTEXT: &str =
    ProofContextId::SESSION_GRANT_PAIRWISE_ENDPOINT_POSSESSION_PROOF_V1;
pub const MAX_PAIRWISE_ENDPOINT_POSSESSION_PROOF_LIFETIME_SECONDS: i64 = 300;

#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PairwiseEndpointPossessionProofContext {
    #[serde(rename = "ak.session_grant_pairwise_endpoint_possession_proof.v1")]
    V1,
}

/// Signed pairwise endpoint possession proof.
///
/// Field order mirrors
/// `service-operation-dtos.schema.json#/$defs/PairwiseEndpointPossessionProof`.
#[cfg_attr(feature = "openapi", derive(salvo_oapi::ToSchema))]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairwiseEndpointPossessionProof {
    pub context: PairwiseEndpointPossessionProofContext,
    pub request_id: RequestId,
    pub account_id: AccountId,
    pub realm_id: RealmId,
    pub actor_id: ActorId,
    pub audience_id: DidCoreId,
    pub holder_jkt: String,
    pub session_intent_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub verification_method: DidUrl,
    pub signature: Base64UrlString,
}

/// Authoring projection: the exact bytes signed before a signature exists.
#[derive(Clone, Debug, Serialize)]
pub struct UnsignedPairwiseEndpointPossessionProof {
    pub context: PairwiseEndpointPossessionProofContext,
    pub request_id: RequestId,
    pub account_id: AccountId,
    pub realm_id: RealmId,
    pub actor_id: ActorId,
    pub audience_id: DidCoreId,
    pub holder_jkt: String,
    pub session_intent_digest: Hash,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub issued_at: DateTime<Utc>,
    #[serde(with = "crate::serde_helpers::canonical_timestamp")]
    pub expires_at: DateTime<Utc>,
    pub verification_method: DidUrl,
}

impl UnsignedPairwiseEndpointPossessionProof {
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        validate_unsigned(
            &self.actor_id,
            &self.audience_id,
            &self.verification_method,
            &self.holder_jkt,
            self.issued_at,
            self.expires_at,
        )?;
        pairwise_endpoint_signing_bytes(self)
    }

    pub fn attach_signature(
        self,
        signature: Base64UrlString,
    ) -> Result<PairwiseEndpointPossessionProof> {
        let proof = PairwiseEndpointPossessionProof {
            context: self.context,
            request_id: self.request_id,
            account_id: self.account_id,
            realm_id: self.realm_id,
            actor_id: self.actor_id,
            audience_id: self.audience_id,
            holder_jkt: self.holder_jkt,
            session_intent_digest: self.session_intent_digest,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            verification_method: self.verification_method,
            signature,
        };
        proof.validate()?;
        Ok(proof)
    }
}

impl PairwiseEndpointPossessionProof {
    /// The pairwise endpoint ActorId, which always uses the account branch.
    pub fn endpoint_account_id(&self) -> Result<&AccountId> {
        match &self.actor_id {
            ActorId::Account { account_id } => Ok(account_id),
            ActorId::Service { .. } => Err(WireError::Protocol(
                "pairwise endpoint actor_id must use the account branch".to_owned(),
            )),
        }
    }

    pub fn validate(&self) -> Result<()> {
        validate_unsigned(
            &self.actor_id,
            &self.audience_id,
            &self.verification_method,
            &self.holder_jkt,
            self.issued_at,
            self.expires_at,
        )?;
        let signature =
            crate::base64url::base64url_decode(self.signature.as_str()).map_err(|_| {
                WireError::Protocol("pairwise endpoint proof signature is invalid".to_owned())
            })?;
        if signature.len() != 64 {
            return Err(WireError::Protocol(
                "pairwise endpoint proof signature must encode 64 Ed25519 bytes".to_owned(),
            ));
        }
        Ok(())
    }

    /// Canonical signing transcript:
    /// `utf8("<context>\n") || JCS(proof without signature)`.
    pub fn canonical_signing_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let value = canonical::unsigned_value(self, &["signature"])?;
        pairwise_endpoint_signing_bytes(&value)
    }
}

fn pairwise_endpoint_signing_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    let canonical_json = canonical::canonical_json_bytes(value)?;
    let mut bytes = Vec::with_capacity(
        PAIRWISE_ENDPOINT_POSSESSION_PROOF_CONTEXT.len() + 1 + canonical_json.len(),
    );
    bytes.extend_from_slice(PAIRWISE_ENDPOINT_POSSESSION_PROOF_CONTEXT.as_bytes());
    bytes.push(b'\n');
    bytes.extend_from_slice(&canonical_json);
    Ok(bytes)
}

fn validate_unsigned(
    actor_id: &ActorId,
    audience_id: &DidCoreId,
    verification_method: &DidUrl,
    holder_jkt: &str,
    issued_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
) -> Result<()> {
    let ActorId::Account { account_id } = actor_id else {
        return Err(WireError::Protocol(
            "pairwise endpoint actor_id must use the account branch".to_owned(),
        ));
    };
    let (controller, fragment) = verification_method
        .as_str()
        .split_once('#')
        .ok_or_else(|| {
            WireError::Protocol("pairwise endpoint verification_method has no fragment".to_owned())
        })?;
    let method_specific_id = controller.strip_prefix("did:key:").ok_or_else(|| {
        WireError::Protocol("pairwise endpoint verification_method must be a did:key".to_owned())
    })?;
    if fragment != method_specific_id {
        return Err(WireError::Protocol(
            "pairwise endpoint verification_method fragment must repeat its multibase key"
                .to_owned(),
        ));
    }
    let controller = Did::new(controller.to_owned())?;
    if crate::project_did_to_core_id(&controller)? != account_id.principal_id {
        return Err(WireError::Protocol(
            "pairwise endpoint verification_method does not project onto actor_id.principal_id"
                .to_owned(),
        ));
    }
    if &account_id.station_id != audience_id {
        return Err(WireError::Protocol(
            "pairwise endpoint actor_id.station_id must equal the hosting Station audience"
                .to_owned(),
        ));
    }
    if holder_jkt.len() != 43
        || !holder_jkt
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(WireError::Protocol(
            "pairwise endpoint proof holder_jkt must be a base64url SHA-256 thumbprint".to_owned(),
        ));
    }
    if expires_at <= issued_at
        || (expires_at - issued_at).num_seconds()
            > MAX_PAIRWISE_ENDPOINT_POSSESSION_PROOF_LIFETIME_SECONDS
    {
        return Err(WireError::Protocol(
            "pairwise endpoint proof validity window must be positive and at most 300 seconds"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    const ENDPOINT_MULTIBASE: &str = "z6MkfixturePairwiseEndpointKeyAAAAAAAAAAAAAAAA";

    fn at(second: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + second, 0).unwrap()
    }

    fn unsigned() -> UnsignedPairwiseEndpointPossessionProof {
        let station = DidCoreId::new("ak:did_core:web:station.example").unwrap();
        UnsignedPairwiseEndpointPossessionProof {
            context: PairwiseEndpointPossessionProofContext::V1,
            request_id: RequestId::new("ak:request:01970000-0000-7000-8000-000000000031").unwrap(),
            account_id: AccountId::new(
                DidCoreId::new("ak:did_core:web:alice.example").unwrap(),
                station.clone(),
            ),
            realm_id: RealmId::new("ak:realm:Ac1aCK8aQdnkYImvdH3DFjq4jDCP198pXYWCGzGuVyj5")
                .unwrap(),
            actor_id: ActorId::account(AccountId::new(
                DidCoreId::new(format!("ak:did_core:key:{ENDPOINT_MULTIBASE}")).unwrap(),
                station.clone(),
            )),
            audience_id: station,
            holder_jkt: "A".repeat(43),
            session_intent_digest: Hash::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
            issued_at: at(0),
            expires_at: at(300),
            verification_method: DidUrl::new(format!(
                "did:key:{ENDPOINT_MULTIBASE}#{ENDPOINT_MULTIBASE}"
            ))
            .unwrap(),
        }
    }

    fn signature() -> Base64UrlString {
        Base64UrlString::new(crate::base64url::base64url_encode([5u8; 64])).unwrap()
    }

    #[test]
    fn unsigned_authoring_matches_the_final_proof_transcript() {
        let unsigned = unsigned();
        let signing_bytes = unsigned.canonical_signing_bytes().unwrap();
        let proof = unsigned.attach_signature(signature()).unwrap();

        assert_eq!(signing_bytes, proof.canonical_signing_bytes().unwrap());
        assert!(
            signing_bytes
                .starts_with(format!("{PAIRWISE_ENDPOINT_POSSESSION_PROOF_CONTEXT}\n").as_bytes())
        );
        assert!(
            !String::from_utf8(signing_bytes)
                .unwrap()
                .contains("\"signature\"")
        );
    }

    #[test]
    fn endpoint_station_must_equal_the_audience() {
        let mut unsigned = unsigned();
        unsigned.actor_id = ActorId::account(AccountId::new(
            DidCoreId::new(format!("ak:did_core:key:{ENDPOINT_MULTIBASE}")).unwrap(),
            DidCoreId::new("ak:did_core:web:other-station.example").unwrap(),
        ));
        assert!(unsigned.canonical_signing_bytes().is_err());
    }

    #[test]
    fn verification_method_must_project_onto_the_endpoint_principal() {
        let mut unsigned = unsigned();
        unsigned.verification_method =
            DidUrl::new("did:key:z6MkfixtureOther#z6MkfixtureOther").unwrap();
        assert!(unsigned.canonical_signing_bytes().is_err());
    }

    #[test]
    fn service_actor_branch_is_rejected() {
        let mut unsigned = unsigned();
        unsigned.actor_id =
            ActorId::service(DidCoreId::new("ak:did_core:web:station.example").unwrap());
        assert!(unsigned.canonical_signing_bytes().is_err());
    }

    #[test]
    fn window_must_be_positive_and_bounded() {
        let mut unsigned = unsigned();
        unsigned.expires_at = unsigned.issued_at;
        assert!(unsigned.canonical_signing_bytes().is_err());

        let mut unsigned = self::unsigned();
        unsigned.expires_at = at(301);
        assert!(unsigned.canonical_signing_bytes().is_err());
    }
}
