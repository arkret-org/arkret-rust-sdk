use super::backup::validate_key_backup_payload;
use super::*;

/// In-memory device manager.
#[derive(Clone, Debug, Default)]
pub struct DeviceManager {
    devices: BTreeMap<Did, BTreeMap<DeviceId, Device>>,
    changes: Vec<DeviceChange>,
    to_device_queue: VecDeque<ToDeviceEnvelope>,
    key_backups: BTreeMap<String, KeyBackup>,
    protocol_device_messages: VecDeque<DeviceMessageEnvelope>,
    protocol_key_backups: BTreeMap<String, ProtocolKeyBackup>,
    verification_challenges: BTreeMap<String, DeviceVerificationChallenge>,
    revoked_devices: BTreeMap<Did, BTreeMap<DeviceId, DateTime<Utc>>>,
    /// Latest accepted `cx.cross_signing.publish.v1` per principal.
    cross_signing_publishes: BTreeMap<Did, CrossSigningPublishContent>,
}

impl DeviceManager {
    /// Create an empty device manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a device.
    pub fn upsert_device(&mut self, user_id: Did, device_id: DeviceId, metadata: DeviceMetadata) {
        let entry = self.devices.entry(user_id.clone()).or_default();
        let (verification, device_public_key, cross_signing_binding, bootstrap_binding) =
            if let Some(device) = entry.get(&device_id) {
                (
                    device.verification,
                    device.device_public_key.clone(),
                    device.cross_signing_binding.clone(),
                    device.bootstrap_binding.clone(),
                )
            } else {
                (DeviceVerificationState::Unverified, None, None, None)
            };
        entry.insert(
            device_id.clone(),
            Device {
                user_id: user_id.clone(),
                device_id: device_id.clone(),
                metadata,
                verification,
                device_public_key,
                cross_signing_binding,
                bootstrap_binding,
                updated_at: Utc::now(),
            },
        );
        self.changes.push(DeviceChange { user_id, device_id, removed: false });
    }

    /// Insert / replace the device record together with its public key (spec §4).
    pub fn upsert_device_with_key(
        &mut self,
        user_id: Did,
        device_id: DeviceId,
        metadata: DeviceMetadata,
        device_public_key: impl Into<String>,
    ) {
        self.upsert_device(user_id.clone(), device_id.clone(), metadata);
        if let Some(device) =
            self.devices.get_mut(&user_id).and_then(|devices| devices.get_mut(&device_id))
        {
            device.device_public_key = Some(device_public_key.into());
        }
    }

    /// Get all devices for a user.
    pub fn user_devices(&self, user_id: &Did) -> Vec<&Device> {
        self.devices.get(user_id).map(|devices| devices.values().collect()).unwrap_or_default()
    }

    /// Get one device.
    pub fn device(&self, user_id: &Did, device_id: &DeviceId) -> Option<&Device> {
        self.devices.get(user_id).and_then(|devices| devices.get(device_id))
    }

    /// Drain tracked device-list changes.
    pub fn drain_changes(&mut self) -> Vec<DeviceChange> {
        self.changes.drain(..).collect()
    }

    /// Delete a device and track removal.
    pub fn delete_device(&mut self, user_id: &Did, device_id: &DeviceId) -> Result<()> {
        let devices = self
            .devices
            .get_mut(user_id)
            .ok_or_else(|| Error::Protocol("user device list not found".to_owned()))?;
        let mut device = devices
            .remove(device_id)
            .ok_or_else(|| Error::Protocol("device not found".to_owned()))?;
        device.verification = DeviceVerificationState::Deleted;
        self.changes.push(DeviceChange {
            user_id: user_id.clone(),
            device_id: device_id.clone(),
            removed: true,
        });
        Ok(())
    }

    /// Queue an outgoing to-device message.
    pub fn send_to_device(
        &mut self,
        sender: Did,
        recipient: Did,
        device_id: DeviceId,
        message_type: impl Into<String>,
        content: Value,
    ) {
        self.to_device_queue.push_back(ToDeviceEnvelope {
            sender,
            recipient,
            device_id,
            message_type: message_type.into(),
            content,
            queued_at: Utc::now(),
        });
    }

    /// Receive an incoming to-device message into the local queue.
    pub fn receive_to_device(&mut self, message: ToDeviceEnvelope) {
        self.to_device_queue.push_back(message);
    }

    /// Drain queued to-device messages.
    pub fn drain_to_device(&mut self) -> Vec<ToDeviceEnvelope> {
        self.to_device_queue.drain(..).collect()
    }

    /// Queue a schema-aligned device message envelope.
    pub fn queue_protocol_device_message(&mut self, message: DeviceMessageEnvelope) {
        self.protocol_device_messages.push_back(message);
    }

    /// Drain schema-aligned device message envelopes.
    pub fn drain_protocol_device_messages(&mut self) -> Vec<DeviceMessageEnvelope> {
        self.protocol_device_messages.drain(..).collect()
    }

    /// Start device verification.
    pub fn start_verification(&mut self, user_id: &Did, device_id: &DeviceId) -> Result<()> {
        self.set_verification(user_id, device_id, DeviceVerificationState::VerificationStarted)
    }

    pub fn begin_verification_flow(
        &mut self,
        user_id: &Did,
        device_id: &DeviceId,
        method: impl Into<String>,
        challenge: impl Into<String>,
    ) -> Result<DeviceVerificationChallenge> {
        self.start_verification(user_id, device_id)?;
        let method = method.into();
        let challenge_value = challenge.into();
        let created_at = Utc::now();
        let expires_at = created_at + Duration::minutes(10);
        let transaction_id = format!(
            "cx:verify:{}:{}:{}",
            user_id.as_str(),
            device_id.as_str(),
            created_at.timestamp_millis()
        );
        let challenge = DeviceVerificationChallenge {
            transaction_id,
            user_id: user_id.clone(),
            device_id: device_id.clone(),
            method,
            commitment: device_verification_commitment(
                user_id,
                device_id,
                &challenge_value,
                created_at,
            )?,
            challenge: challenge_value,
            created_at,
            expires_at,
        };
        self.verification_challenges.insert(challenge.transaction_id.clone(), challenge.clone());
        Ok(challenge)
    }

    /// Start a SAS-style verification flow with a canonical commitment.
    pub fn begin_sas_verification(
        &mut self,
        user_id: &Did,
        device_id: &DeviceId,
        sas_code: impl Into<String>,
    ) -> Result<DeviceVerificationChallenge> {
        self.begin_verification_flow(user_id, device_id, "sas_v1", sas_code)
    }

    /// Return a scanner-facing QR payload for a pending verification transaction.
    pub fn qr_verification_payload(&self, transaction_id: &str) -> Result<QrVerificationPayload> {
        let challenge = self
            .verification_challenges
            .get(transaction_id)
            .ok_or_else(|| Error::Protocol("verification transaction not found".to_owned()))?;
        Ok(QrVerificationPayload {
            version: 1,
            transaction_id: challenge.transaction_id.clone(),
            user_id: challenge.user_id.clone(),
            device_id: challenge.device_id.clone(),
            method: challenge.method.clone(),
            commitment: challenge.commitment.clone(),
        })
    }

    /// Validate a scanned QR payload against the expected device.
    pub fn validate_qr_verification_payload(
        payload: &QrVerificationPayload,
        expected_user: &Did,
        expected_device: &DeviceId,
    ) -> Result<()> {
        if payload.version != 1 {
            return Err(Error::Protocol("unsupported verification QR version".to_owned()));
        }
        if &payload.user_id != expected_user || &payload.device_id != expected_device {
            return Err(Error::Protocol("verification QR device mismatch".to_owned()));
        }
        if payload.commitment.trim().is_empty() {
            return Err(Error::Protocol("verification QR commitment is empty".to_owned()));
        }
        Ok(())
    }

    pub fn confirm_verification_flow(
        &mut self,
        transaction_id: &str,
        response: &str,
        cross_signing_binding: Option<DeviceTrustBinding>,
    ) -> Result<()> {
        let challenge = self
            .verification_challenges
            .remove(transaction_id)
            .ok_or_else(|| Error::Protocol("verification transaction not found".to_owned()))?;
        if challenge.expires_at <= Utc::now() {
            self.set_verification(
                &challenge.user_id,
                &challenge.device_id,
                DeviceVerificationState::VerificationExpired,
            )?;
            return Err(Error::Protocol("verification transaction expired".to_owned()));
        }
        if challenge.challenge != response {
            self.set_verification(
                &challenge.user_id,
                &challenge.device_id,
                DeviceVerificationState::VerificationFailed,
            )?;
            return Err(Error::Protocol("verification challenge mismatch".to_owned()));
        }
        let expected = device_verification_commitment(
            &challenge.user_id,
            &challenge.device_id,
            response,
            challenge.created_at,
        )?;
        if expected != challenge.commitment {
            self.set_verification(
                &challenge.user_id,
                &challenge.device_id,
                DeviceVerificationState::VerificationFailed,
            )?;
            return Err(Error::Protocol("verification commitment mismatch".to_owned()));
        }
        self.verify_device(&challenge.user_id, &challenge.device_id, cross_signing_binding)
    }

    /// Cancel a pending verification flow.
    pub fn cancel_verification_flow(&mut self, transaction_id: &str) -> Result<()> {
        let challenge = self
            .verification_challenges
            .remove(transaction_id)
            .ok_or_else(|| Error::Protocol("verification transaction not found".to_owned()))?;
        self.set_verification(
            &challenge.user_id,
            &challenge.device_id,
            DeviceVerificationState::VerificationCancelled,
        )
    }

    /// Mark all expired pending verification flows as expired.
    pub fn expire_verification_challenges(&mut self, now: DateTime<Utc>) -> Result<usize> {
        let expired = self
            .verification_challenges
            .iter()
            .filter_map(
                |(id, challenge)| {
                    if challenge.expires_at <= now { Some(id.clone()) } else { None }
                },
            )
            .collect::<Vec<_>>();
        for transaction_id in &expired {
            if let Some(challenge) = self.verification_challenges.remove(transaction_id) {
                self.set_verification(
                    &challenge.user_id,
                    &challenge.device_id,
                    DeviceVerificationState::VerificationExpired,
                )?;
            }
        }
        Ok(expired.len())
    }

    /// Mark a device verified, optionally attaching the SSK-signed
    /// `cross_signing_binding` (spec §5.2). Without a binding, the device
    /// is locally trusted but not part of the cross-signed chain.
    pub fn verify_device(
        &mut self,
        user_id: &Did,
        device_id: &DeviceId,
        cross_signing_binding: Option<DeviceTrustBinding>,
    ) -> Result<()> {
        let device = self.device_mut(user_id, device_id)?;
        device.verification = DeviceVerificationState::Verified;
        if let Some(binding) = cross_signing_binding {
            device.cross_signing_binding = Some(binding);
        }
        device.updated_at = Utc::now();
        Ok(())
    }

    /// Attach a bootstrap binding (spec §5.3 — first-device inception).
    /// Only valid before any `cx.cross_signing.publish.v1` has been
    /// recorded for the principal.
    pub fn attach_bootstrap_binding(
        &mut self,
        user_id: &Did,
        device_id: &DeviceId,
        binding: DeviceBootstrapBinding,
    ) -> Result<()> {
        if self.cross_signing_publishes.contains_key(user_id) {
            return Err(Error::Protocol(
                "bootstrap binding refused: cross-signing publish already accepted for principal"
                    .to_owned(),
            ));
        }
        let device = self.device_mut(user_id, device_id)?;
        device.bootstrap_binding = Some(binding);
        device.cross_signing_binding = None;
        device.updated_at = Utc::now();
        Ok(())
    }

    /// Block a device.
    pub fn block_device(&mut self, user_id: &Did, device_id: &DeviceId) -> Result<()> {
        self.set_verification(user_id, device_id, DeviceVerificationState::Blocked)
    }

    /// Revoke a device, causing all future encrypted writes from it to fail closed.
    pub fn revoke_device(&mut self, user_id: &Did, device_id: &DeviceId) {
        self.revoked_devices
            .entry(user_id.clone())
            .or_default()
            .insert(device_id.clone(), Utc::now());
    }

    /// Check if a device has been revoked.
    pub fn is_device_revoked(&self, user_id: &Did, device_id: &DeviceId) -> bool {
        self.revoked_devices.get(user_id).and_then(|devices| devices.get(device_id)).is_some()
    }

    /// Get all revoked devices for a user.
    pub fn revoked_devices_for_user(&self, user_id: &Did) -> Vec<(&DeviceId, &DateTime<Utc>)> {
        self.revoked_devices
            .get(user_id)
            .map(|devices| devices.iter().collect())
            .unwrap_or_default()
    }

    /// Propagate trust from an already verified, cross-signed device to
    /// another device of the same user.
    ///
    /// Unlike the legacy "copy a field" implementation, this now requires
    /// a valid `cross_signing_binding` on the target device AND a current
    /// `cx.cross_signing.publish.v1` for the principal — otherwise it
    /// returns `Error::Protocol`. This implements spec §5.2.1 step 4:
    /// "cross-signed" status MUST come from a SSK signature over the
    /// target device's `verify_key`, not from a sibling device's trust
    /// state.
    pub fn propagate_trust(
        &mut self,
        user_id: &Did,
        trusted_device_id: &DeviceId,
        target_device_id: &DeviceId,
    ) -> Result<()> {
        let publish = self.cross_signing_publishes.get(user_id).ok_or_else(|| {
            Error::Protocol(
                "no cross_signing publish accepted for principal — cannot propagate trust"
                    .to_owned(),
            )
        })?;
        let accepted_generation = publish.generation;

        let trusted = self
            .device(user_id, trusted_device_id)
            .ok_or_else(|| Error::Protocol("trusted device not found".to_owned()))?;
        if trusted.verification != DeviceVerificationState::Verified {
            return Err(Error::Protocol("source device is not verified".to_owned()));
        }
        let trusted_binding = trusted.cross_signing_binding.as_ref().ok_or_else(|| {
            Error::Protocol("source device is not cross-signed under current generation".to_owned())
        })?;
        if trusted_binding.ssk_generation != accepted_generation {
            return Err(Error::Protocol(
                "source device cross_signing_binding generation is stale".to_owned(),
            ));
        }

        // Target device MUST already carry its own SSK-signed binding under
        // the same generation — trust is not transitive in the protocol.
        let target_binding = self
            .device(user_id, target_device_id)
            .ok_or_else(|| Error::Protocol("target device not found".to_owned()))?
            .cross_signing_binding
            .clone()
            .ok_or_else(|| {
                Error::Protocol(
                    "target device has no cross_signing_binding — SSK must sign it directly"
                        .to_owned(),
                )
            })?;
        if target_binding.ssk_generation != accepted_generation {
            return Err(Error::Protocol(
                "target device cross_signing_binding generation is stale".to_owned(),
            ));
        }
        self.verify_device(user_id, target_device_id, Some(target_binding))
    }

    /// Upload or replace a key backup.
    pub fn upload_key_backup(
        &mut self,
        version: impl Into<String>,
        algorithm: impl Into<String>,
        payload: Value,
    ) -> KeyBackup {
        self.upload_authenticated_key_backup(version, algorithm, payload, None, None)
    }

    /// Upload a key backup with sender identity and optional rotation link.
    pub fn upload_authenticated_key_backup(
        &mut self,
        version: impl Into<String>,
        algorithm: impl Into<String>,
        payload: Value,
        sender: Option<Did>,
        previous_version: Option<String>,
    ) -> KeyBackup {
        let payload_sha256 = canonical::canonical_sha256(&payload)
            .unwrap_or_else(|_| format!("sha256:{:x}", Sha256::digest(payload.to_string())));
        let backup = KeyBackup {
            version: version.into(),
            algorithm: algorithm.into(),
            sender,
            previous_version,
            payload_sha256,
            payload,
            uploaded_at: Utc::now(),
        };
        self.key_backups.insert(backup.version.clone(), backup.clone());
        backup
    }

    /// Download a key backup by version.
    pub fn download_key_backup(&self, version: &str) -> Option<&KeyBackup> {
        self.key_backups.get(version)
    }

    /// Restore a key backup payload.
    pub fn restore_key_backup(&self, version: &str) -> Result<Value> {
        let backup = self
            .key_backups
            .get(version)
            .ok_or_else(|| Error::Protocol("key backup not found".to_owned()))?;
        validate_key_backup_payload(backup)?;
        Ok(backup.payload.clone())
    }

    /// Restore a key backup only if it was uploaded by the expected sender.
    pub fn restore_key_backup_from_sender(
        &self,
        version: &str,
        expected_sender: &Did,
    ) -> Result<Value> {
        let backup = self
            .key_backups
            .get(version)
            .ok_or_else(|| Error::Protocol("key backup not found".to_owned()))?;
        validate_key_backup_payload(backup)?;
        if backup.sender.as_ref() != Some(expected_sender) {
            return Err(Error::Protocol("key backup sender mismatch".to_owned()));
        }
        Ok(backup.payload.clone())
    }

    /// Store a schema-aligned encrypted key backup scaffold.
    pub fn store_protocol_key_backup(&mut self, backup: ProtocolKeyBackup) -> Result<()> {
        if backup.backup_id.trim().is_empty() {
            return Err(Error::Protocol(
                "protocol key backup backup_id must not be empty".to_owned(),
            ));
        }
        if backup.backup_version.trim().is_empty() {
            return Err(Error::Protocol(
                "protocol key backup backup_version must not be empty".to_owned(),
            ));
        }
        if backup.ciphertext.trim().is_empty() || backup.ciphertext_digest.trim().is_empty() {
            return Err(Error::Protocol(
                "protocol key backup ciphertext and digest must not be empty".to_owned(),
            ));
        }
        self.protocol_key_backups.insert(backup.backup_id.clone(), backup);
        Ok(())
    }

    /// Get a schema-aligned encrypted key backup scaffold.
    pub fn protocol_key_backup(&self, backup_id: &str) -> Option<&ProtocolKeyBackup> {
        self.protocol_key_backups.get(backup_id)
    }

    fn set_verification(
        &mut self,
        user_id: &Did,
        device_id: &DeviceId,
        state: DeviceVerificationState,
    ) -> Result<()> {
        let device = self.device_mut(user_id, device_id)?;
        device.verification = state;
        device.updated_at = Utc::now();
        Ok(())
    }

    fn device_mut(&mut self, user_id: &Did, device_id: &DeviceId) -> Result<&mut Device> {
        self.devices
            .get_mut(user_id)
            .and_then(|devices| devices.get_mut(device_id))
            .ok_or_else(|| Error::Protocol("device not found".to_owned()))
    }

    // ---- Cross-signing publish / reset / trust-chain ------------------

    /// Record a `cx.cross_signing.publish.v1` event for `principal` (spec
    /// §5.1). The publish MUST monotonically advance `generation` unless it
    /// is the first one (generation 1). Stale publishes are rejected.
    ///
    /// Implementations MUST also verify the PSK and SSK / USK bindings
    /// against the principal's DID key-log head before calling this; this
    /// method handles only the state-machine bookkeeping.
    pub fn record_cross_signing_publish(
        &mut self,
        publish: CrossSigningPublishContent,
    ) -> Result<()> {
        publish.validate_structure()?;
        let principal = publish.principal_id.clone();
        if let Some(existing) = self.cross_signing_publishes.get(&principal) {
            if publish.generation <= existing.generation {
                return Err(Error::Protocol(format!(
                    "cross_signing publish generation {} is not greater than current {}",
                    publish.generation, existing.generation
                )));
            }
            // A new accepted generation invalidates every device chain.
            self.mark_principal_needs_reverification(&principal)?;
        }
        self.cross_signing_publishes.insert(principal, publish);
        Ok(())
    }

    /// Record a `cx.cross_signing.reset.v1` event (spec §14.1) and drop the
    /// current PSK / SSK / USK state for `principal`. The caller MUST follow
    /// with a fresh `record_cross_signing_publish` within the window
    /// declared by §14.2 step 5.
    pub fn record_cross_signing_reset(&mut self, reset: &CrossSigningResetContent) -> Result<()> {
        reset.validate_structure()?;
        let principal = &reset.principal_id;
        let current = self.cross_signing_publishes.get(principal).ok_or_else(|| {
            Error::Protocol(
                "cannot reset cross-signing: no current publish accepted for principal".to_owned(),
            )
        })?;
        if reset.previous_generation != current.generation {
            return Err(Error::Protocol(format!(
                "cross_signing reset previous_generation {} does not match accepted {}",
                reset.previous_generation, current.generation
            )));
        }
        self.cross_signing_publishes.remove(principal);
        self.mark_principal_needs_reverification(principal)?;
        // Cancel any in-flight verification transactions for this principal
        // (spec §14.2 step 4).
        let cancel_ids: Vec<String> = self
            .verification_challenges
            .iter()
            .filter_map(
                |(id, challenge)| {
                    if &challenge.user_id == principal { Some(id.clone()) } else { None }
                },
            )
            .collect();
        for id in cancel_ids {
            let _ = self.cancel_verification_flow(&id);
        }
        Ok(())
    }

    /// Current accepted cross-signing publish for `principal`, if any.
    pub fn current_cross_signing(&self, principal: &Did) -> Option<&CrossSigningPublishContent> {
        self.cross_signing_publishes.get(principal)
    }

    /// Re-key a device's `cross_signing_binding` (called when the SDK has
    /// completed verification or received a fresh binding from a peer).
    pub fn attach_cross_signing_binding(
        &mut self,
        user_id: &Did,
        device_id: &DeviceId,
        binding: DeviceTrustBinding,
    ) -> Result<()> {
        let publish = self.cross_signing_publishes.get(user_id).ok_or_else(|| {
            Error::Protocol(
                "no cross_signing publish accepted for principal — cannot attach binding"
                    .to_owned(),
            )
        })?;
        if binding.ssk_generation != publish.generation {
            return Err(Error::Protocol(
                "binding generation does not match accepted publish generation".to_owned(),
            ));
        }
        let device = self.device_mut(user_id, device_id)?;
        device.cross_signing_binding = Some(binding);
        device.bootstrap_binding = None;
        device.updated_at = Utc::now();
        Ok(())
    }

    /// Resolve a device's trust chain outcome (spec §5.2.1).
    ///
    /// The `verify_signature` closure is invoked twice when both a
    /// publish AND a device binding are available: once for the SSK ←
    /// PSK binding, and once for the device-key ← SSK binding. Each call
    /// receives `(verification_method, alg, canonical_bytes, signature)`
    /// and MUST return `Ok(true)` only when the signature verifies.
    pub fn evaluate_trust_chain<F>(
        &self,
        user_id: &Did,
        device_id: &DeviceId,
        mut verify_signature: F,
    ) -> Result<DeviceTrustChainOutcome>
    where
        F: FnMut(&str, &str, &[u8], &str) -> Result<bool>,
    {
        let device = self
            .device(user_id, device_id)
            .ok_or_else(|| Error::Protocol("device not found".to_owned()))?;

        // Bootstrap path: §5.3.
        if let Some(_bootstrap) = &device.bootstrap_binding {
            if self.cross_signing_publishes.contains_key(user_id) {
                // A publish has landed — bootstrap path is no longer legitimate
                // and the device needs a real cross-signing binding.
                return Ok(DeviceTrustChainOutcome::NeedsReverification);
            }
            return Ok(DeviceTrustChainOutcome::Bootstrap);
        }

        let Some(binding) = &device.cross_signing_binding else {
            return Ok(DeviceTrustChainOutcome::Unverified);
        };

        let Some(publish) = self.cross_signing_publishes.get(user_id) else {
            // Spec §5.2.1 step 4: missing publish + binding = legacy /
            // unbootstrapped state. We treat it as unverified because no
            // SSK is on record to evaluate against.
            return Ok(DeviceTrustChainOutcome::Unverified);
        };

        let accepted_generation = publish.generation;
        if binding.ssk_generation < accepted_generation {
            return Ok(DeviceTrustChainOutcome::NeedsReverification);
        }
        if binding.ssk_generation > accepted_generation {
            return Ok(DeviceTrustChainOutcome::AwaitingPublish);
        }

        let device_public_key = device.device_public_key.as_deref().ok_or_else(|| {
            Error::Protocol(
                "device has no device_public_key — cannot evaluate cross-signing binding"
                    .to_owned(),
            )
        })?;
        let ssk_input = publish.self_signing_binding_input()?;
        let ssk_ok = verify_signature(
            &publish.principal_signing_key.kid,
            &publish.self_signing_key.binding.alg,
            &ssk_input,
            &publish.self_signing_key.binding.signature,
        )?;
        if !ssk_ok {
            return Ok(DeviceTrustChainOutcome::Invalid);
        }
        let device_input = DeviceTrustBinding::canonical_input(
            user_id,
            device_id,
            device_public_key,
            binding.ssk_generation,
        )?;
        let device_ok =
            verify_signature(&binding.signed_by, &binding.alg, &device_input, &binding.signature)?;
        if !device_ok {
            return Ok(DeviceTrustChainOutcome::Invalid);
        }
        Ok(DeviceTrustChainOutcome::CrossSigned)
    }

    fn mark_principal_needs_reverification(&mut self, principal: &Did) -> Result<()> {
        let Some(devices) = self.devices.get_mut(principal) else {
            return Ok(());
        };
        let now = Utc::now();
        for device in devices.values_mut() {
            if matches!(device.verification, DeviceVerificationState::Verified) {
                device.verification = DeviceVerificationState::NeedsReverification;
            }
            device.cross_signing_binding = None;
            device.updated_at = now;
        }
        Ok(())
    }
}

pub fn device_verification_commitment(
    user_id: &Did,
    device_id: &DeviceId,
    challenge: &str,
    created_at: DateTime<Utc>,
) -> Result<String> {
    let payload = serde_json::json!({
        "context": "contrix-device-verification-v1",
        "user_id": user_id,
        "device_id": device_id,
        "challenge": challenge,
        "created_at": created_at,
    });
    canonical::canonical_sha256(&payload)
}
