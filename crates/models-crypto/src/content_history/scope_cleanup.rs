//! Closed cleanup byte bindings. Native qualification and first acceptance
//! time are independent from decoding or hashing these protocol objects.

use super::*;

fn validate_signature_shape(
    signature: &crate::KeyOperationSignature,
    method: &arkret_wire::DidUrl,
) -> Result<()> {
    let bytes = base64url_decode(signature.signature.as_str())
        .map_err(|error| WireError::Protocol(error.to_string()))?;
    if signature.kid.as_str() != method.as_str()
        || signature
            .signature_algorithm
            .as_ref()
            .is_some_and(|alg| alg.as_str() != "Ed25519")
        || bytes.len() != 64
        || base64url_encode(&bytes) != signature.signature.as_str()
    {
        return protocol("cleanup signature shape differs from its exact method");
    }
    Ok(())
}

fn signing_bytes(domain: &[u8], value: &impl Serialize) -> Result<Vec<u8>> {
    let mut value = serde_json::to_value(value)?;
    value
        .as_object_mut()
        .and_then(|value| value.remove("signature"))
        .ok_or_else(|| WireError::Protocol("cleanup signature member missing".into()))?;
    let mut bytes = domain.to_vec();
    bytes.extend(arkret_canonical::canonical_json_bytes(&value)?);
    Ok(bytes)
}

impl ContentRecoveryScopeCleanupRequestBody {
    pub fn validate(&self) -> Result<()> {
        sha256_ref(&self.inventory_digest)?;
        self.effective_scope.canonical_mls_group_id()?;
        bytes32(&self.nonce_base64url)?;
        bytes32(&self.delivery_challenge_base64url)?;
        Ok(())
    }
}

impl ContentRecoveryScopeCleanupAuthorization {
    pub fn validate(&self) -> Result<()> {
        self.replacement.validate()?;
        if self.replacement.actor_id.as_account_id().is_none()
            || self.expires_at <= self.attested_at
            || self.expires_at - self.attested_at > chrono::Duration::seconds(300)
        {
            return protocol("invalid cleanup source subject or source window");
        }
        sha256_ref(&self.inventory_digest)?;
        self.inventory_entry
            .effective_scope
            .canonical_mls_group_id()?;
        bytes32(&self.nonce_base64url)?;
        bytes32(&self.delivery_challenge_base64url)?;
        if self
            .predecessor_authorization_event_refs
            .windows(2)
            .any(|pair| pair[0].as_str().as_bytes() >= pair[1].as_str().as_bytes())
        {
            return protocol("cleanup predecessor authorizations must be unique and UTF-8 sorted");
        }
        validate_signature_shape(&self.signature, &self.verification_method)
    }

    /// Stable I excludes route, current challenge, method and source renewal.
    /// Predecessor references are a separately frozen native association,
    /// authenticated by the complete source signature rather than this digest.
    /// Its hash is not native authorization or an outer transport cache key.
    pub fn intent_digest(&self) -> Result<arkret_wire::Hash> {
        #[derive(Serialize)]
        struct Intent<'a> {
            replacement: &'a ContentEndpoint,
            inventory_digest: &'a arkret_wire::Hash,
            inventory_entry: &'a ContentRecoveryInventoryEntry,
            nonce_base64url: &'a str,
        }
        let mut bytes = b"ak.mls.recovery_scope_cleanup_request.v1\n".to_vec();
        bytes.extend(arkret_canonical::canonical_json_bytes(&Intent {
            replacement: &self.replacement,
            inventory_digest: &self.inventory_digest,
            inventory_entry: &self.inventory_entry,
            nonce_base64url: &self.nonce_base64url,
        })?);
        Ok(arkret_wire::Hash::new(arkret_canonical::sha256_digest(
            bytes,
        ))?)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        signing_bytes(b"ak.mls.recovery_scope_cleanup_authorization.v1\n", self)
    }
}

struct ProofCoordinates<'a> {
    replacement: &'a ContentEndpoint,
    inventory_digest: &'a arkret_wire::Hash,
    request_digest: &'a arkret_wire::Hash,
    effective_scope: &'a arkret_wire::ScopeRef,
    genesis_event_ref: &'a arkret_wire::EventId,
    scope_cut: &'a arkret_wire::CommittedEventRef,
    nonce: &'a str,
    method: &'a arkret_wire::DidUrl,
    signature: &'a crate::KeyOperationSignature,
}

impl ContentScopeRetirementProof {
    fn coordinates(&self) -> ProofCoordinates<'_> {
        let (Self::Removed {
            replacement,
            inventory_digest,
            request_digest,
            effective_scope,
            genesis_event_ref,
            scope_cut,
            nonce_base64url,
            verification_method,
            signature,
            ..
        }
        | Self::Terminated {
            replacement,
            inventory_digest,
            request_digest,
            effective_scope,
            genesis_event_ref,
            scope_cut,
            nonce_base64url,
            verification_method,
            signature,
            ..
        }) = self;
        ProofCoordinates {
            replacement,
            inventory_digest,
            request_digest,
            effective_scope,
            genesis_event_ref,
            scope_cut,
            nonce: nonce_base64url,
            method: verification_method,
            signature,
        }
    }

    pub fn validate_shape(&self) -> Result<()> {
        let proof = self.coordinates();
        proof.replacement.validate()?;
        if proof.replacement.actor_id.as_account_id().is_none()
            || proof.scope_cut.stream_ref
                != arkret_wire::CommitStreamRef::from_scope(proof.effective_scope, None)?
        {
            return protocol("retirement proof subject or scope cut differs");
        }
        bytes32(proof.nonce)?;
        sha256_ref(proof.inventory_digest)?;
        sha256_ref(proof.request_digest)?;
        match self {
            Self::Removed {
                remaining_old_leaf_count,
                ..
            } if *remaining_old_leaf_count != 0 => {
                return protocol("removed proof retains old leaves");
            }
            Self::Terminated {
                terminal_source_digest,
                ..
            } => sha256_ref(terminal_source_digest)?,
            _ => {}
        }
        validate_signature_shape(proof.signature, proof.method)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        signing_bytes(b"ak.mls.scope_retirement.v1\n", self)
    }
}

impl ContentRetiredScopeCleanup {
    pub fn validate_shape(&self) -> Result<()> {
        self.retirement_proof.validate_shape()?;
        let proof = self.retirement_proof.coordinates();
        if self.effective_scope != *proof.effective_scope
            || self.genesis_event_ref != *proof.genesis_event_ref
            || !matches!(
                (&self.state, &self.retirement_proof),
                (
                    ContentScopeRetirementState::Removed,
                    ContentScopeRetirementProof::Removed { .. }
                ) | (
                    ContentScopeRetirementState::Terminated,
                    ContentScopeRetirementProof::Terminated { .. }
                )
            )
        {
            return protocol("retired cleanup differs from its original proof");
        }
        Ok(())
    }
}

impl ContentScopeRetirementDeliveryAttestation {
    pub fn validate_shape(&self) -> Result<()> {
        for digest in [
            &self.request_digest,
            &self.authorization_digest,
            &self.proof_digest,
        ] {
            sha256_ref(digest)?;
        }
        bytes32(&self.nonce_base64url)?;
        bytes32(&self.delivery_challenge_base64url)?;
        if self.expires_at <= self.attested_at
            || self.expires_at - self.attested_at > chrono::Duration::seconds(300)
        {
            return protocol("invalid retirement delivery window");
        }
        validate_signature_shape(&self.signature, &self.verification_method)
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        signing_bytes(b"ak.mls.scope_retirement_delivery.v1\n", self)
    }
}

impl ContentRecoveryScopeCleanupResponseBody {
    pub fn validate_shape(&self) -> Result<()> {
        if let Self::Retired(result) = self {
            result.cleanup.validate_shape()?;
            result.delivery_attestation.validate_shape()?;
            let proof = result.cleanup.retirement_proof.coordinates();
            let delivery = &result.delivery_attestation;
            if delivery.request_digest != *proof.request_digest
                || delivery.nonce_base64url != proof.nonce
                || delivery.proof_digest.as_str()
                    != arkret_canonical::canonical_sha256(&result.cleanup.retirement_proof)?
                || proof
                    .replacement
                    .actor_id
                    .as_account_id()
                    .map(|account| &account.station_id)
                    != Some(&delivery.recipient_service_id)
            {
                return protocol("current delivery differs from the original subject or proof");
            }
        }
        Ok(())
    }

    /// Bind current delivery to a complete origin source, without assuming the
    /// current governor/key is the historical proof's governor/key.
    pub fn validate_for_source(
        &self,
        source: &ContentRecoveryScopeCleanupAuthorization,
    ) -> Result<()> {
        self.validate_shape()?;
        source.validate()?;
        if let Self::Retired(result) = self {
            result.cleanup.retirement_proof.validate_binding(
                &source.replacement,
                &source.inventory_entry,
                &source.inventory_digest,
            )?;
            let delivery = &result.delivery_attestation;
            if delivery.request_digest != source.intent_digest()?
                || delivery.authorization_digest.as_str()
                    != arkret_canonical::canonical_sha256(source)?
                || delivery.delivery_challenge_base64url != source.delivery_challenge_base64url
                || delivery.attested_at < source.attested_at
                || delivery.expires_at > source.expires_at
            {
                return protocol("retirement delivery differs from its current authorization");
            }
        }
        Ok(())
    }
}

impl ContentRecoveryScopeCleanupSelfResponseBody {
    /// Exact-key projection shape only. The host qualifies the own Station,
    /// original signatures, current reader and first acceptance time separately.
    pub fn validate_for_request(
        &self,
        request: &ContentRecoveryScopeCleanupRequestBody,
    ) -> Result<()> {
        request.validate()?;
        self.delivery.validate_shape()?;
        match &self.delivery {
            ContentRecoveryScopeCleanupResponseBody::Pending(_)
                if self.attestor_signing_key.is_none() && self.delivery_signing_key.is_none() =>
            {
                Ok(())
            }
            ContentRecoveryScopeCleanupResponseBody::Retired(result) => {
                let old = self
                    .attestor_signing_key
                    .as_ref()
                    .ok_or_else(|| WireError::Protocol("original proof key missing".into()))?;
                let current = self
                    .delivery_signing_key
                    .as_ref()
                    .ok_or_else(|| WireError::Protocol("current delivery key missing".into()))?;
                let proof = result.cleanup.retirement_proof.coordinates();
                let delivery = &result.delivery_attestation;
                bytes32(old.public_key_base64url.as_str())?;
                bytes32(current.public_key_base64url.as_str())?;
                if proof.replacement.authorization_event_ref != request.authorization_event_ref
                    || *proof.inventory_digest != request.inventory_digest
                    || *proof.effective_scope != request.effective_scope
                    || *proof.genesis_event_ref != request.genesis_event_ref
                    || proof.nonce != request.nonce_base64url
                    || delivery.delivery_challenge_base64url != request.delivery_challenge_base64url
                    || old.proof_digest != delivery.proof_digest
                    || old.verification_method != *proof.method
                    || current.delivery_digest.as_str()
                        != arkret_canonical::canonical_sha256(delivery)?
                    || current.verification_method != delivery.verification_method
                {
                    return protocol(
                        "self retirement response differs from the exact request or projected keys",
                    );
                }
                Ok(())
            }
            _ => protocol("pending retirement response discloses signing keys"),
        }
    }
}
