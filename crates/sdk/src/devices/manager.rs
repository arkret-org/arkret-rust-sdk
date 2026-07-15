use arkret_core::{BackupId, KeyBackup};

use super::*;

/// In-memory device manager.
#[derive(Clone, Debug, Default)]
pub struct DeviceManager {
    devices: BTreeMap<Did, BTreeMap<DeviceId, Device>>,
    changes: Vec<DeviceChange>,
    to_device_queue: VecDeque<ToDeviceEnvelope>,
    device_message_envelopes: VecDeque<DeviceMessageEnvelope>,
    key_backups: BTreeMap<BackupId, KeyBackup>,
    verification_challenges: BTreeMap<String, DeviceVerificationChallenge>,
    revoked_devices: BTreeMap<Did, BTreeMap<DeviceId, DateTime<Utc>>>,
    /// Latest accepted `ak.cross_signing.publish.v1` per principal.
    cross_signing_publishes: BTreeMap<Did, CrossSigningPublish>,
    /// Round 4 (spec a77b995) — generation lineage counter that survives
    /// a `ak.cross_signing.reset`. The next accepted publish MUST carry
    /// `expected_previous_generation == cross_signing_generation_high_water` and
    /// `generation == cross_signing_generation_high_water + 1` for the CAS
    /// to succeed. After a reset, the high-water survives but the publish
    /// record is dropped — the principal is in `needs_publish` state.
    cross_signing_generation_high_water: BTreeMap<Did, u64>,
}

impl DeviceManager {
    /// Create an empty device manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or update a device.
    pub fn upsert_device(&mut self, user_id: Did, device_id: DeviceId, metadata: DeviceMetadata) {
        let entry = self.devices.entry(user_id.clone()).or_default();
        let (verification, device_public_key, hpke_key, algorithms, cross_signing_binding) =
            if let Some(device) = entry.get(&device_id) {
                (
                    device.verification,
                    device.device_public_key.clone(),
                    device.hpke_key.clone(),
                    device.algorithms.clone(),
                    device.cross_signing_binding.clone(),
                )
            } else {
                (DeviceVerificationState::Unverified, None, None, None, None)
            };
        entry.insert(
            device_id.clone(),
            Device {
                user_id: user_id.clone(),
                device_id: device_id.clone(),
                metadata,
                verification,
                device_public_key,
                hpke_key,
                algorithms,
                cross_signing_binding,
                updated_at: Utc::now(),
            },
        );
        self.changes.push(DeviceChange {
            user_id,
            device_id,
            removed: false,
        });
    }

    /// Insert / replace the device record together with its key material
    /// (spec §4): verify key, HPKE sealing key and canonical algorithm set.
    pub fn upsert_device_with_key(
        &mut self,
        user_id: Did,
        device_id: DeviceId,
        metadata: DeviceMetadata,
        device_public_key: impl Into<String>,
        hpke_key: impl Into<String>,
        algorithms: Vec<String>,
    ) {
        self.upsert_device(user_id.clone(), device_id.clone(), metadata);
        if let Some(device) = self
            .devices
            .get_mut(&user_id)
            .and_then(|devices| devices.get_mut(&device_id))
        {
            device.device_public_key = Some(device_public_key.into());
            device.hpke_key = Some(hpke_key.into());
            device.algorithms = Some(algorithms);
        }
    }

    /// Get all devices for a user.
    pub fn user_devices(&self, user_id: &Did) -> Vec<&Device> {
        self.devices
            .get(user_id)
            .map(|devices| devices.values().collect())
            .unwrap_or_default()
    }

    /// Get one device.
    pub fn device(&self, user_id: &Did, device_id: &DeviceId) -> Option<&Device> {
        self.devices
            .get(user_id)
            .and_then(|devices| devices.get(device_id))
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
    pub fn queue_device_message_envelope(&mut self, message: DeviceMessageEnvelope) {
        self.device_message_envelopes.push_back(message);
    }

    /// Drain schema-aligned device message envelopes.
    pub fn drain_device_message_envelopes(&mut self) -> Vec<DeviceMessageEnvelope> {
        self.device_message_envelopes.drain(..).collect()
    }

    /// Start device verification.
    pub fn start_verification(&mut self, user_id: &Did, device_id: &DeviceId) -> Result<()> {
        self.set_verification(
            user_id,
            device_id,
            DeviceVerificationState::VerificationStarted,
        )
    }

    pub fn begin_verification_strand(
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
            "ak:verify:{}:{}:{}",
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
        self.verification_challenges
            .insert(challenge.transaction_id.clone(), challenge.clone());
        Ok(challenge)
    }

    /// Start a SAS-style verification strand with a canonical commitment.
    pub fn begin_sas_verification(
        &mut self,
        user_id: &Did,
        device_id: &DeviceId,
        sas_code: impl Into<String>,
    ) -> Result<DeviceVerificationChallenge> {
        self.begin_verification_strand(user_id, device_id, "sas_v1", sas_code)
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
            return Err(Error::Protocol(
                "unsupported verification QR version".to_owned(),
            ));
        }
        if &payload.user_id != expected_user || &payload.device_id != expected_device {
            return Err(Error::Protocol(
                "verification QR device mismatch".to_owned(),
            ));
        }
        if payload.commitment.trim().is_empty() {
            return Err(Error::Protocol(
                "verification QR commitment is empty".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn confirm_verification_strand(
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
            return Err(Error::Protocol(
                "verification transaction expired".to_owned(),
            ));
        }
        if challenge.challenge != response {
            self.set_verification(
                &challenge.user_id,
                &challenge.device_id,
                DeviceVerificationState::VerificationFailed,
            )?;
            return Err(Error::Protocol(
                "verification challenge mismatch".to_owned(),
            ));
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
            return Err(Error::Protocol(
                "verification commitment mismatch".to_owned(),
            ));
        }
        self.verify_device(
            &challenge.user_id,
            &challenge.device_id,
            cross_signing_binding,
        )
    }

    /// Cancel a pending verification strand.
    pub fn cancel_verification_strand(&mut self, transaction_id: &str) -> Result<()> {
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

    /// Mark all expired pending verification strands as expired.
    pub fn expire_verification_challenges(&mut self, now: DateTime<Utc>) -> Result<usize> {
        let expired = self
            .verification_challenges
            .iter()
            .filter_map(|(id, challenge)| {
                if challenge.expires_at <= now {
                    Some(id.clone())
                } else {
                    None
                }
            })
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
        self.revoked_devices
            .get(user_id)
            .and_then(|devices| devices.get(device_id))
            .is_some()
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
    /// Requires a valid `cross_signing_binding` on the target device AND a current
    /// `ak.cross_signing.publish.v1` for the principal — otherwise it
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
        let accepted_generation = publish.generation.get();

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

    /// Store a schema-aligned encrypted key backup.
    pub fn store_key_backup(&mut self, backup: KeyBackup) -> Result<()> {
        if backup.backup_version.trim().is_empty() {
            return Err(Error::Protocol(
                "key backup backup_version must not be empty".to_owned(),
            ));
        }
        if backup.ciphertext.trim().is_empty() || backup.ciphertext_digest.trim().is_empty() {
            return Err(Error::Protocol(
                "key backup ciphertext and digest must not be empty".to_owned(),
            ));
        }
        self.key_backups.insert(backup.backup_id.clone(), backup);
        Ok(())
    }

    /// Get a schema-aligned encrypted key backup.
    pub fn key_backup(&self, backup_id: &BackupId) -> Option<&KeyBackup> {
        self.key_backups.get(backup_id)
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

    /// Record a `ak.cross_signing.publish.v1` event for `principal` (spec
    /// §5.1). The publish MUST monotonically advance `generation` unless it
    /// is the first one (generation 1). Stale publishes are rejected.
    ///
    /// Implementations MUST also verify the PSK and SSK / USK bindings
    /// against the principal's DID key-log head before calling this; this
    /// method handles only the state-machine bookkeeping.
    pub fn record_cross_signing_publish(&mut self, publish: CrossSigningPublish) -> Result<()> {
        publish.validate_structure()?;
        let principal = publish.principal_id.clone();
        // Round 4 (spec a77b995) — high-water tracks the lineage across
        // reset, so a publish following a reset must continue
        // monotonically from `reset.new_generation`.
        let current_generation = self
            .cross_signing_generation_high_water
            .get(&principal)
            .copied()
            .unwrap_or(0);
        // Round 4 CAS guard: `expected_previous_generation` MUST equal
        // the currently accepted generation BEFORE signature verification.
        // Mismatch is `cas_conflict`, not `invalid_signature`.
        if publish.expected_previous_generation != current_generation {
            return Err(Error::Protocol(format!(
                "cross_signing publish expected_previous_generation {} does not match accepted {} \
                 (cas_conflict)",
                publish.expected_previous_generation, current_generation
            )));
        }
        if publish.generation.get() != current_generation + 1 {
            return Err(Error::Protocol(format!(
                "cross_signing publish generation {} must equal current {} + 1 (cas_conflict)",
                publish.generation, current_generation
            )));
        }
        if self.cross_signing_publishes.contains_key(&principal) {
            // A new accepted generation invalidates every device chain.
            self.mark_principal_needs_reverification(&principal)?;
        }
        self.cross_signing_generation_high_water
            .insert(principal.clone(), publish.generation.get());
        self.cross_signing_publishes.insert(principal, publish);
        Ok(())
    }

    /// Record a `ak.cross_signing.reset.v1` event (spec §14.1) and drop the
    /// current PSK / SSK / USK state for `principal`. The caller MUST follow
    /// with a fresh `record_cross_signing_publish` within the window
    /// declared by §14.2 step 5.
    pub fn record_cross_signing_reset(&mut self, reset: &CrossSigningResetPayload) -> Result<()> {
        reset.validate_structure()?;
        let principal = reset.principal_id();
        let current = self.cross_signing_publishes.get(principal).ok_or_else(|| {
            Error::Protocol(
                "cannot reset cross-signing: no current publish accepted for principal".to_owned(),
            )
        })?;
        if reset.previous_generation() != current.generation.get() {
            return Err(Error::Protocol(format!(
                "cross_signing reset previous_generation {} does not match accepted {}",
                reset.previous_generation(),
                current.generation
            )));
        }
        self.cross_signing_publishes.remove(principal);
        // Round 4 — reset bumps the generation high-water so the next
        // publish MUST chain from `reset.new_generation`.
        self.cross_signing_generation_high_water
            .insert(principal.clone(), reset.new_generation());
        self.mark_principal_needs_reverification(principal)?;
        if let Some(device_ids) = reset.revoked_device_ids() {
            for device_id in device_ids {
                self.revoke_device(principal, device_id);
            }
        }
        // Cancel any in-flight verification transactions for this principal
        // (spec §14.2 step 4).
        let cancel_ids: Vec<String> = self
            .verification_challenges
            .iter()
            .filter_map(|(id, challenge)| {
                if &challenge.user_id == principal {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect();
        for id in cancel_ids {
            let _ = self.cancel_verification_strand(&id);
        }
        Ok(())
    }

    /// Current accepted cross-signing publish for `principal`, if any.
    pub fn current_cross_signing(&self, principal: &Did) -> Option<&CrossSigningPublish> {
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
        if binding.ssk_generation != publish.generation.get() {
            return Err(Error::Protocol(
                "binding generation does not match accepted publish generation".to_owned(),
            ));
        }
        let device = self.device_mut(user_id, device_id)?;
        device.cross_signing_binding = Some(binding);
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

        let Some(binding) = &device.cross_signing_binding else {
            return Ok(DeviceTrustChainOutcome::Unverified);
        };

        let Some(publish) = self.cross_signing_publishes.get(user_id) else {
            // Spec §5.2.1 step 4: missing publish + binding means the device
            // is unbootstrapped. We treat it as unverified because no
            // SSK is on record to evaluate against.
            return Ok(DeviceTrustChainOutcome::Unverified);
        };

        // DID anchoring (§5.2.1): the PSK we evaluate against MUST belong to
        // this principal. Assert it cheaply here so a naive caller closure that
        // only "resolve verification_method → verify → Ok(true)" cannot have the
        // trust chain anchored to a foreign principal's PSK. The stateless
        // verifier (`crypto::verify_device_cross_signing_chain`) requires a
        // pre-anchored PSK for the same reason; keep both paths consistent.
        if kid_did_part(&publish.principal_signing_key.kid) != user_id.as_str() {
            return Ok(DeviceTrustChainOutcome::Invalid);
        }

        let accepted_generation = publish.generation.get();
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
        // §5.2: the trust binding transcript covers verify key, HPKE sealing
        // key and the canonical algorithm set — a record missing either cannot
        // be evaluated (fail closed, never silently downgrade coverage).
        let hpke_key = device.hpke_key.as_deref().ok_or_else(|| {
            Error::Protocol(
                "device has no hpke_key — cannot evaluate cross-signing binding".to_owned(),
            )
        })?;
        let algorithms = device.algorithms.as_deref().ok_or_else(|| {
            Error::Protocol(
                "device has no algorithms — cannot evaluate cross-signing binding".to_owned(),
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
            hpke_key,
            algorithms,
            binding.ssk_generation,
        )?;
        // Anchor the device binding to the *published* SSK, not to the
        // device-self-reported `verification_method`. The device binding was
        // stored after only checking `ssk_generation` matched
        // (`attach_cross_signing_binding`), so its `verification_method` is not
        // otherwise guaranteed to reference the SSK the PSK cross-signed. Pin
        // the locator to `publish.self_signing_key.kid` so the closure
        // resolves the published SSK — mirroring `verify_device_cross_signing_chain`,
        // which verifies against `publish.self_signing_key.public_key`.
        let ssk_locator = publish.self_signing_key.kid.as_str();
        let device_ok =
            verify_signature(ssk_locator, &binding.alg, &device_input, &binding.signature)?;
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

/// Return the DID portion of a `did:...#fragment` key id (kid), i.e. everything
/// before the first `#`. Used to assert cross-signing keys are anchored to the
/// expected principal DID.
fn kid_did_part(kid: &str) -> &str {
    kid.split_once('#').map(|(did, _)| did).unwrap_or(kid)
}

pub fn device_verification_commitment(
    user_id: &Did,
    device_id: &DeviceId,
    challenge: &str,
    created_at: DateTime<Utc>,
) -> Result<String> {
    let payload = serde_json::json!({
        "context": "arkretice-verification-v1",
        "user_id": user_id,
        "device_id": device_id,
        "challenge": challenge,
        "created_at": created_at,
    });
    Ok(canonical::canonical_sha256(&payload)?)
}
