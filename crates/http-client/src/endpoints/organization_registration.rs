//! Deployment-governed organization registration, independent of Account onboarding.
use arkret_models_identity::{
    OrganizationRegistrationChallenge, OrganizationRegistrationChallengeRequestBody,
    OrganizationRegistrationEnsureRequestBody, OrganizationRegistrationOutcome,
    OrganizationRegistrationRefreshRequestBody, OrganizationRegistrationRevokeRequestBody,
    OrganizationRegistrationStatus,
};
use arkret_wire::DidCoreId;
use reqwest::Method;

use crate::{Client, Error, Result};

const BASE: &str = "/_arkret/root/identity/organization-registrations";

impl Client {
    pub async fn organization_registration_prepare(
        &self,
        request: &OrganizationRegistrationChallengeRequestBody,
    ) -> Result<OrganizationRegistrationChallenge> {
        request.validate()?;
        let challenge: OrganizationRegistrationChallenge =
            self.post(&format!("{BASE}:prepare"), request).await?;
        challenge.validate_for(request)?;
        if url::Url::parse(challenge.origin.as_str())?.origin() != self.base_url().origin() {
            return Err(Error::Protocol(
                "organization challenge origin differs from registry".into(),
            ));
        }
        Ok(challenge)
    }

    pub async fn organization_registration_ensure(
        &self,
        request: &OrganizationRegistrationEnsureRequestBody,
    ) -> Result<OrganizationRegistrationOutcome> {
        request.validate()?;
        let outcome: OrganizationRegistrationOutcome =
            self.post(&format!("{BASE}:ensure"), request).await?;
        validate_organization(&outcome, &request.organization_id)?;
        let receipt = &outcome.registration_receipt;
        if receipt.organization_did != request.organization_did
            || receipt.version_id != request.version_id
            || receipt.log_head_digest != request.log_head_digest
            || receipt.local_admin_subject_id != request.local_admin_subject_id
            || receipt.delegated_scopes != request.requested_scopes
            || receipt.status != OrganizationRegistrationStatus::Active
        {
            return Err(Error::Protocol(
                "organization ensure response differs from request".into(),
            ));
        }
        Ok(outcome)
    }

    pub async fn organization_registration_get(
        &self,
        organization: &DidCoreId,
    ) -> Result<OrganizationRegistrationOutcome> {
        let builder = self
            .request(Method::GET, BASE)?
            .query(&[("organization_id", organization.as_str())]);
        let outcome: OrganizationRegistrationOutcome = self.send_json(builder).await?;
        validate_organization(&outcome, organization)?;
        require_existing(&outcome)?;
        Ok(outcome)
    }

    pub async fn organization_registration_refresh(
        &self,
        request: &OrganizationRegistrationRefreshRequestBody,
    ) -> Result<OrganizationRegistrationOutcome> {
        request.validate()?;
        let outcome: OrganizationRegistrationOutcome =
            self.post(&format!("{BASE}:refresh"), request).await?;
        validate_organization(&outcome, &request.organization_id)?;
        require_existing(&outcome)?;
        let receipt = &outcome.registration_receipt;
        if receipt.organization_did != request.organization_did
            || receipt.version_id != request.version_id
            || receipt.log_head_digest != request.log_head_digest
            || receipt.status != OrganizationRegistrationStatus::Active
        {
            return Err(Error::Protocol(
                "organization refresh response differs from request".into(),
            ));
        }
        // The refresh proof binds the current beneficiary even though it is
        // deliberately absent from the refresh wire body.
        request.control_proof.validate_transcript_bindings(
            &request.challenge_id,
            &request.organization_id,
            &request.organization_did,
            &receipt.local_admin_subject_id,
            &request.version_id,
            &request.log_head_digest,
        )?;
        Ok(outcome)
    }

    pub async fn organization_registration_revoke(
        &self,
        request: &OrganizationRegistrationRevokeRequestBody,
    ) -> Result<OrganizationRegistrationOutcome> {
        let outcome: OrganizationRegistrationOutcome =
            self.post(&format!("{BASE}:revoke"), request).await?;
        validate_organization(&outcome, &request.organization_id)?;
        require_existing(&outcome)?;
        if outcome.registration_receipt.status != OrganizationRegistrationStatus::Revoked {
            return Err(Error::Protocol(
                "organization revoke response is not terminal".into(),
            ));
        }
        Ok(outcome)
    }
}

fn validate_organization(
    outcome: &OrganizationRegistrationOutcome,
    organization: &DidCoreId,
) -> Result<()> {
    outcome.validate()?;
    if outcome.organization_id() != organization {
        return Err(Error::Protocol(
            "organization registration response targets another organization".into(),
        ));
    }
    Ok(())
}

fn require_existing(outcome: &OrganizationRegistrationOutcome) -> Result<()> {
    if outcome.created {
        return Err(Error::Protocol(
            "organization read/lifecycle response cannot create a generation".into(),
        ));
    }
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use arkret_models_identity::{
        OrganizationControlProofKind, OrganizationRegistrationReceipt,
        OrganizationRegistrationScope,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    fn outcome(
        organization: &str,
        status: OrganizationRegistrationStatus,
        created: bool,
    ) -> OrganizationRegistrationOutcome {
        let did = arkret_wire::Did::new(format!("did:web:{organization}")).unwrap();
        let at = arkret_canonical::normalize_timestamp_canonical(chrono::Utc::now());
        let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
            [27; 32],
            "did:web:registry.example#key".to_owned(),
        );
        let mut receipt: OrganizationRegistrationReceipt = serde_json::from_value(serde_json::json!({
            "registration_receipt_id":format!("ak:organization_registration_receipt:{}", "0".repeat(64)),
            "organization_id": arkret_wire::project_did_to_core_id(&did).unwrap(), "organization_did":did,
            "registration_generation":1, "version_id":"1-fixture", "log_head_digest":format!("sha256:{}", "1".repeat(64)),
            "control_proof_kind":OrganizationControlProofKind::ResolvedVerificationMethod,
            "control_key_digest":format!("sha256:{}", "2".repeat(64)),
            "local_admin_subject_id":"ak:did_core:web:admin.example", "delegated_scopes":[OrganizationRegistrationScope::OrganizationProfileManage],
            "status":status, "issued_at":arkret_canonical::format_timestamp_canonical(at),
            "expires_at":arkret_canonical::format_timestamp_canonical(at+chrono::Duration::days(90)),
            "issuer_id":"ak:did_core:web:registry.example",
            "proof":{"kind":arkret_wire::proof_kind::DETACHED_JWS,"verification_method":"did:web:registry.example#key",
            "payload_digest":format!("sha256:{}", "0".repeat(64)),"created_at":arkret_canonical::format_timestamp_canonical(at),
            "jws":signer.sign_detached_jws(b"pending")}
        })).unwrap();
        receipt.registration_receipt_id = receipt.expected_receipt_id().unwrap();
        receipt.proof.payload_digest = receipt.expected_payload_digest().unwrap();
        receipt.proof.jws = signer.sign_detached_jws(&receipt.proof_signing_bytes().unwrap());
        receipt.validate().unwrap();
        OrganizationRegistrationOutcome {
            registration_receipt: receipt,
            created,
        }
    }

    async fn reply(body: serde_json::Value) -> (Client, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = vec![];
            let mut chunk = [0; 4096];
            loop {
                let n = stream.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                bytes.extend_from_slice(&chunk[..n]);
                if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                    let size = head
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("content-length: ")
                                .and_then(|v| v.parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    if bytes.len() >= end + 4 + size {
                        break;
                    }
                }
            }
            let body = body.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8(bytes).unwrap()
        });
        (
            Client::builder(url::Url::parse(&format!("http://{address}")).unwrap())
                .allow_insecure_localhost()
                .build()
                .unwrap(),
            handle,
        )
    }

    #[tokio::test]
    async fn organization_get_rejects_valid_receipt_substitution_and_created_claim() {
        let organization = DidCoreId::new("ak:did_core:web:organization.example").unwrap();
        for (other, created, accepted) in [
            (false, false, true),
            (true, false, false),
            (false, true, false),
        ] {
            let output = outcome(
                if other {
                    "other.example"
                } else {
                    "organization.example"
                },
                OrganizationRegistrationStatus::Active,
                created,
            );
            let (client, capture) = reply(serde_json::to_value(output).unwrap()).await;
            assert_eq!(
                client
                    .organization_registration_get(&organization)
                    .await
                    .is_ok(),
                accepted
            );
            let request = capture.await.unwrap().to_ascii_lowercase();
            assert!(request.starts_with("get /_arkret/root/identity/organization-registrations?organization_id=ak%3adid_core%3aweb%3aorganization.example "));
            assert!(request.contains("ak.root.identity.organization_registration.resource.get.v1"));
        }
    }

    #[tokio::test]
    async fn organization_revoke_requires_valid_terminal_response() {
        for status in [
            OrganizationRegistrationStatus::Active,
            OrganizationRegistrationStatus::Revoked,
        ] {
            let output = outcome("organization.example", status, false);
            let request = OrganizationRegistrationRevokeRequestBody {
                organization_id: output.organization_id().clone(),
                reason_code: None,
            };
            let (client, capture) = reply(serde_json::to_value(output).unwrap()).await;
            assert_eq!(
                client
                    .organization_registration_revoke(&request)
                    .await
                    .is_ok(),
                status == OrganizationRegistrationStatus::Revoked
            );
            assert!(
                capture
                    .await
                    .unwrap()
                    .contains("ak.root.identity.organization_registration.command.revoke.v1")
            );
        }
    }

    #[tokio::test]
    async fn organization_ensure_rejects_other_head_beneficiary_and_scope() {
        use arkret_models_identity::OrganizationControlProof;
        let output = outcome(
            "organization.example",
            OrganizationRegistrationStatus::Active,
            true,
        );
        let receipt = &output.registration_receipt;
        let signer = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
            [28; 32],
            "did:web:organization.example#key".to_owned(),
        );
        let mut request = OrganizationRegistrationEnsureRequestBody {
            organization_id: receipt.organization_id.clone(),
            organization_did: receipt.organization_did.clone(),
            challenge_id: format!("ak:organization_registration_challenge:{}", "a".repeat(64)),
            version_id: receipt.version_id.clone(),
            log_head_digest: receipt.log_head_digest.clone(),
            local_admin_subject_id: receipt.local_admin_subject_id.clone(),
            requested_scopes: receipt.delegated_scopes.clone(),
            control_proof: OrganizationControlProof {
                proof_kind: OrganizationControlProofKind::ResolvedVerificationMethod,
                quorum_threshold: None,
                proofs: vec![receipt.proof.clone()],
            },
            handle_attestation: None,
        };
        let proof = &mut request.control_proof.proofs[0];
        proof.verification_method =
            arkret_wire::DidUrl::new("did:web:organization.example#key").unwrap();
        let transcript = serde_json::json!({"context": arkret_wire::ProofContextId::ORGANIZATION_REGISTRATION_CONTROL_PROOF_V1,
            "challenge_id":request.challenge_id,"organization_id":request.organization_id,"organization_did":request.organization_did,
            "local_admin_subject_id":request.local_admin_subject_id,"version_id":request.version_id,"log_head_digest":request.log_head_digest,
            "verification_method":proof.verification_method,"created_at":proof.created_at});
        let bytes = arkret_canonical::canonical_json_bytes(&transcript).unwrap();
        proof.payload_digest =
            arkret_wire::Hash::new(arkret_canonical::sha256_digest(&bytes)).unwrap();
        proof.jws = signer.sign_detached_jws(&bytes);
        request.validate().unwrap();
        for variant in 0..5 {
            let mut response = output.clone();
            match variant {
                1 => response.registration_receipt.version_id = "another-version".into(),
                2 => {
                    response.registration_receipt.log_head_digest =
                        arkret_wire::Hash::new(format!("sha256:{}", "9".repeat(64))).unwrap()
                }
                3 => {
                    response.registration_receipt.local_admin_subject_id =
                        DidCoreId::new("ak:did_core:web:other-admin.example").unwrap()
                }
                4 => {
                    response.registration_receipt.delegated_scopes =
                        vec![OrganizationRegistrationScope::OrganizationRealmEndorse]
                }
                _ => {}
            }
            let r = &mut response.registration_receipt;
            r.registration_receipt_id = r.expected_receipt_id().unwrap();
            r.proof.payload_digest = r.expected_payload_digest().unwrap();
            let registry = arkret_signatures::Ed25519DetachedJwsSigner::from_seed(
                [27; 32],
                "did:web:registry.example#key".to_owned(),
            );
            r.proof.jws = registry.sign_detached_jws(&r.proof_signing_bytes().unwrap());
            response.validate().unwrap();
            let (client, capture) = reply(serde_json::to_value(response).unwrap()).await;
            assert_eq!(
                client
                    .organization_registration_ensure(&request)
                    .await
                    .is_ok(),
                variant == 0
            );
            assert!(
                capture
                    .await
                    .unwrap()
                    .contains("ak.root.identity.organization_registration.command.ensure.v1")
            );
        }
    }
}
