use std::collections::BTreeMap;

use arkret_canonical::base64url::base64url_encode;
use chrono::Utc;
use zeroize::Zeroizing;

use super::commitment::ct_eq;
use super::compute_key_commitment;
use super::envelopes::{
    KeyVerificationAccept, KeyVerificationCancel, KeyVerificationDone, KeyVerificationKey,
    KeyVerificationMac, KeyVerificationStart, KeyVerificationState,
};
use super::key_agreement::{
    EphemeralX25519Keypair, ShortAuthenticationString, derive_sas_bytes, hkdf_expand_sha256,
    hmac_sha256,
};
use crate::{DeviceId, Did, Error, Result};

/// Strict-transition state machine that consumes [`KeyVerificationStart`],
/// [`KeyVerificationAccept`], [`KeyVerificationKey`], [`KeyVerificationMac`]
/// and [`KeyVerificationDone`] in order.
///
/// On any out-of-order envelope or transaction-id mismatch the call
/// returns `Err(Error::Protocol(...))` and the state is moved to
/// [`KeyVerificationState::Cancelled`].
#[derive(Clone, Debug)]
pub struct KeyVerificationStrand {
    state: KeyVerificationState,
    transaction_id: Option<String>,
    initiator: Option<(Did, DeviceId)>,
    responder: Option<(Did, DeviceId)>,
    /// The accepted `start` envelope — retained because the canonical
    /// `start` message is an input to the commitment (§10.3) and the
    /// MAC transcript.
    start: Option<KeyVerificationStart>,
    /// The accepted `accept` envelope — retained for the commitment
    /// check in `on_key` and the algorithm selection in the transcript.
    accept: Option<KeyVerificationAccept>,
    // `pub(super)` (not private) so the parent module's `#[cfg(test)]`
    // tests can read this field; still crate-internal, no external API
    // change.
    pub(super) keys_exchanged: BTreeMap<DeviceId, String>,
    macs_received: BTreeMap<DeviceId, KeyVerificationMac>,
    done_received: BTreeMap<DeviceId, KeyVerificationDone>,
    cancel: Option<KeyVerificationCancel>,
    /// This side's ephemeral X25519 keypair for the SAS exchange.
    /// `None` until the caller installs one via
    /// [`Self::with_ephemeral_key`]; once installed, the public half
    /// MUST be the value put on the wire as `KeyVerificationKey.key`,
    /// and the private half is used in [`Self::compute_sas`] together
    /// with the peer's public key from `keys_exchanged` to derive the
    /// shared secret.
    ephemeral: Option<EphemeralX25519Keypair>,
}

impl Default for KeyVerificationStrand {
    fn default() -> Self {
        Self {
            state: KeyVerificationState::Idle,
            transaction_id: None,
            initiator: None,
            responder: None,
            start: None,
            accept: None,
            keys_exchanged: BTreeMap::new(),
            macs_received: BTreeMap::new(),
            done_received: BTreeMap::new(),
            cancel: None,
            ephemeral: None,
        }
    }
}

impl KeyVerificationStrand {
    /// Create an `Idle` strand.
    pub fn new() -> Self {
        Self::default()
    }

    /// Install this side's ephemeral X25519 keypair. Builder-style so
    /// call sites stay readable:
    /// `KeyVerificationStrand::new().with_ephemeral_key(EphemeralX25519Keypair::generate()?)`.
    /// MUST be called before the first `on_key` step or
    /// [`Self::compute_sas`] will refuse with `Error::Protocol`.
    pub fn with_ephemeral_key(mut self, key: EphemeralX25519Keypair) -> Self {
        self.ephemeral = Some(key);
        self
    }

    /// Base64 (no-pad) public half of the installed ephemeral
    /// keypair. Returns `None` when no keypair is installed yet —
    /// callers SHOULD use this to fill `KeyVerificationKey.key` when
    /// sending the `key` envelope to the peer.
    pub fn ephemeral_public_base64(&self) -> Option<String> {
        self.ephemeral
            .as_ref()
            .map(EphemeralX25519Keypair::public_base64)
    }

    /// Compute the SAS pair for this strand. Steps:
    ///   1. Look up the peer's public key in `keys_exchanged` — the `self_device` argument is OUR
    ///      `DeviceId`, so the peer's key is the only entry not keyed by `self_device`.
    ///   2. Run X25519 between our ephemeral private + the peer's public to produce the 32-byte
    ///      shared secret.
    ///   3. Feed `(shared_secret, info)` through `derive_sas_bytes`.
    ///
    /// `info` is the canonical SAS binding string both sides MUST
    /// derive identically — typical content is
    /// `<transaction_id>|<initiator_did>|<initiator_device>|<responder_did>|<responder_device>`.
    pub fn compute_sas(
        &self,
        self_device: &DeviceId,
        info: &[u8],
    ) -> Result<ShortAuthenticationString> {
        let ephemeral = self
            .ephemeral
            .as_ref()
            .ok_or_else(|| Error::Protocol("ephemeral keypair not installed".to_owned()))?;
        let peer_key_b64 = self
            .keys_exchanged
            .iter()
            .find(|(device_id, _)| *device_id != self_device)
            .map(|(_, key)| key)
            .ok_or_else(|| {
                Error::Protocol(
                    "peer public key not received yet (waiting on on_key step)".to_owned(),
                )
            })?;
        let shared = ephemeral.compute_shared_secret(peer_key_b64)?;
        Ok(derive_sas_bytes(&shared[..], info))
    }

    /// Read the current state.
    pub fn state(&self) -> KeyVerificationState {
        self.state
    }

    /// Active transaction id, if any.
    pub fn transaction_id(&self) -> Option<&str> {
        self.transaction_id.as_deref()
    }

    /// Cancellation record, set when `Cancelled` was reached via the
    /// internal `cancel` step or a violated invariant.
    pub fn cancel_record(&self) -> Option<&KeyVerificationCancel> {
        self.cancel.as_ref()
    }

    /// Step 1: accept `start`. Only legal in `Idle`.
    pub fn on_start(&mut self, msg: &KeyVerificationStart) -> Result<()> {
        if self.state != KeyVerificationState::Idle {
            return self.fail("invalid_transition", "start only legal in Idle");
        }
        validate_transaction_id(&msg.transaction_id)?;
        if msg.method.trim().is_empty() {
            return self.fail("invalid_param", "start.method must not be empty");
        }
        if msg.key_agreement_protocols.is_empty()
            || msg.message_authentication_codes.is_empty()
            || msg.short_authentication_string.is_empty()
        {
            return self.fail(
                "invalid_param",
                "start protocol/mac/SAS lists must not be empty",
            );
        }
        self.transaction_id = Some(msg.transaction_id.clone());
        self.initiator = Some((msg.from_user.clone(), msg.from_device.clone()));
        self.start = Some(msg.clone());
        self.state = KeyVerificationState::Started;
        Ok(())
    }

    /// Step 2: accept `accept`. Only legal in `Started`.
    ///
    /// The commitment itself can only be checked once the responder
    /// reveals its ephemeral key — see [`Self::on_key`].
    pub fn on_accept(&mut self, msg: &KeyVerificationAccept) -> Result<()> {
        if self.state != KeyVerificationState::Started {
            return self.fail("invalid_transition", "accept only legal in Started");
        }
        self.assert_txn(&msg.transaction_id)?;
        if msg.commitment.trim().is_empty() {
            return self.fail("invalid_param", "accept.commitment must not be empty");
        }
        if let Some((init_did, init_device)) = &self.initiator
            && (init_did, init_device) == (&msg.from_user, &msg.from_device)
        {
            return self.fail(
                "invalid_param",
                "accept must come from responder, not initiator",
            );
        }
        self.responder = Some((msg.from_user.clone(), msg.from_device.clone()));
        self.accept = Some(msg.clone());
        self.state = KeyVerificationState::Accepted;
        Ok(())
    }

    /// Step 3: accept `key` envelopes (one per side, in any order).
    ///
    /// When the responder's key arrives, the commitment from the
    /// `accept` envelope is recomputed over the revealed key + canonical
    /// `start` message and compared fail-closed; a mismatch cancels the
    /// strand with `code=mismatched_commitment` (§10.3).
    pub fn on_key(&mut self, msg: &KeyVerificationKey) -> Result<()> {
        let next = match self.state {
            KeyVerificationState::Accepted => KeyVerificationState::KeyHalfExchanged,
            KeyVerificationState::KeyHalfExchanged => KeyVerificationState::KeysExchanged,
            _ => return self.fail("invalid_transition", "key only legal after accept"),
        };
        self.assert_txn(&msg.transaction_id)?;
        if msg.key.trim().is_empty() {
            return self.fail("invalid_param", "key.key must not be empty");
        }
        if !self.is_known_party(&msg.from_user, &msg.from_device) {
            return self.fail(
                "invalid_param",
                "key.from_user/device not part of this strand",
            );
        }
        if self.keys_exchanged.contains_key(&msg.from_device) {
            return self.fail(
                "invalid_transition",
                "key already received from this device",
            );
        }
        // §10.3: the responder committed to its ephemeral key in
        // `accept.commitment` before seeing the initiator's key. Now
        // that the key is revealed, recompute and compare.
        let from_responder = self
            .responder
            .as_ref()
            .is_some_and(|(_, device)| device == &msg.from_device);
        if from_responder {
            let Some(start) = self.start.clone() else {
                return self.fail(
                    "unexpected_message",
                    "key received without a recorded start",
                );
            };
            let Some(expected) = self.accept.as_ref().map(|a| a.commitment.clone()) else {
                return self.fail(
                    "unexpected_message",
                    "key received without a recorded accept",
                );
            };
            let computed = match compute_key_commitment(&msg.key, &start) {
                Ok(commitment) => commitment,
                Err(err) => {
                    return self.fail(
                        "mismatched_commitment",
                        &format!("cannot recompute commitment: {err}"),
                    );
                }
            };
            if !ct_eq(&computed, &expected) {
                return self.fail(
                    "mismatched_commitment",
                    "accept.commitment does not match the responder's revealed ephemeral key",
                );
            }
        }
        self.keys_exchanged
            .insert(msg.from_device.clone(), msg.key.clone());
        self.state = next;
        Ok(())
    }

    /// The canonical SAS transcript both sides MUST derive identically
    /// (§10.3): transaction id, both parties, method, the algorithm
    /// selection fixed by `accept`, and both ephemeral public keys.
    fn sas_transcript(&self) -> Result<String> {
        let (init_did, init_device) = self
            .initiator
            .as_ref()
            .ok_or_else(|| Error::Protocol("transcript requires an initiator".to_owned()))?;
        let (resp_did, resp_device) = self
            .responder
            .as_ref()
            .ok_or_else(|| Error::Protocol("transcript requires a responder".to_owned()))?;
        let start = self
            .start
            .as_ref()
            .ok_or_else(|| Error::Protocol("transcript requires the start envelope".to_owned()))?;
        let accept = self
            .accept
            .as_ref()
            .ok_or_else(|| Error::Protocol("transcript requires the accept envelope".to_owned()))?;
        let txn = self
            .transaction_id
            .as_deref()
            .ok_or_else(|| Error::Protocol("transcript requires a transaction id".to_owned()))?;
        let init_key = self.keys_exchanged.get(init_device).ok_or_else(|| {
            Error::Protocol("transcript requires the initiator's ephemeral key".to_owned())
        })?;
        let resp_key = self.keys_exchanged.get(resp_device).ok_or_else(|| {
            Error::Protocol("transcript requires the responder's ephemeral key".to_owned())
        })?;
        Ok([
            txn,
            init_did.as_str(),
            init_device.as_str(),
            resp_did.as_str(),
            resp_device.as_str(),
            start.method.as_str(),
            accept.key_agreement_protocol.as_str(),
            accept.message_authentication_code.as_str(),
            &accept.short_authentication_string.join(","),
            init_key.as_str(),
            resp_key.as_str(),
        ]
        .join("|"))
    }

    /// HKDF-derived MAC key for `sender_device`, bound to the full SAS
    /// transcript: `HKDF-Expand(HMAC(0, shared_secret),
    /// "arkret-sas-mac-v1|<transcript>|<sender_device>", 32)`.
    fn mac_key_for(&self, sender_device: &DeviceId) -> Result<Zeroizing<[u8; 32]>> {
        let ephemeral = self
            .ephemeral
            .as_ref()
            .ok_or_else(|| Error::Protocol("ephemeral keypair not installed".to_owned()))?;
        let own_public = ephemeral.public_base64();
        let peer_public = self
            .keys_exchanged
            .values()
            .find(|key| key.as_str() != own_public)
            .ok_or_else(|| Error::Protocol("peer public key not received yet".to_owned()))?;
        let shared = ephemeral.compute_shared_secret(peer_public)?;
        let prk = Zeroizing::new(hmac_sha256(&[0u8; 32], &shared[..]));
        let transcript = self.sas_transcript()?;
        let info = format!("arkret-sas-mac-v1|{transcript}|{}", sender_device.as_str());
        let mut mac_key = Zeroizing::new([0u8; 32]);
        hkdf_expand_sha256(&prk, info.as_bytes(), &mut mac_key[..]);
        Ok(mac_key)
    }

    /// Build this side's `mac` envelope over the verified keys
    /// (`key_id -> public key`, e.g. `"ed25519:<device_id>" ->
    /// base64(device verify key)`). Per §10.3 each per-key MAC covers the
    /// key id and key value, and `keys` covers the sorted key-id list;
    /// the MAC key binds the full negotiated transcript.
    ///
    /// Requires both `key` envelopes and this side's ephemeral keypair,
    /// i.e. legal from `KeysExchanged` onwards.
    pub fn build_mac(
        &self,
        from_user: &Did,
        from_device: &DeviceId,
        verify_keys: &BTreeMap<String, String>,
    ) -> Result<KeyVerificationMac> {
        if verify_keys.is_empty() {
            return Err(Error::Protocol(
                "mac requires at least one key to verify".to_owned(),
            ));
        }
        let txn = self
            .transaction_id
            .clone()
            .ok_or_else(|| Error::Protocol("mac requires an active transaction".to_owned()))?;
        let mac_key = self.mac_key_for(from_device)?;
        let mut mac = BTreeMap::new();
        for (key_id, key_value) in verify_keys {
            let tag = hmac_sha256(&mac_key[..], format!("{key_id}|{key_value}").as_bytes());
            mac.insert(key_id.clone(), base64url_encode(tag));
        }
        let key_ids = verify_keys.keys().cloned().collect::<Vec<_>>().join(",");
        let keys = base64url_encode(hmac_sha256(&mac_key[..], key_ids.as_bytes()));
        Ok(KeyVerificationMac {
            transaction_id: txn,
            from_user: from_user.clone(),
            from_device: from_device.clone(),
            keys,
            mac,
            sent_at: Utc::now(),
        })
    }

    /// Step 4: accept `mac` envelopes (one per side) and verify them.
    ///
    /// `expected_verify_keys` is the receiver's own view of the keys the
    /// sender claims to MAC (`key_id -> public key`); each per-key MAC
    /// and the key-id list MAC are recomputed with the transcript-bound
    /// MAC key and compared fail-closed. Any mismatch (including an
    /// unknown key id or a missing ephemeral keypair) cancels the strand
    /// with `code=mismatched_mac` (§10.3).
    pub fn on_mac(
        &mut self,
        msg: &KeyVerificationMac,
        expected_verify_keys: &BTreeMap<String, String>,
    ) -> Result<()> {
        let next = match self.state {
            KeyVerificationState::KeysExchanged => KeyVerificationState::MacHalfReceived,
            KeyVerificationState::MacHalfReceived => KeyVerificationState::MacsReceived,
            _ => {
                return self.fail(
                    "invalid_transition",
                    "mac only legal after both keys exchanged",
                );
            }
        };
        self.assert_txn(&msg.transaction_id)?;
        if msg.keys.trim().is_empty() || msg.mac.is_empty() {
            return self.fail("invalid_param", "mac.keys and mac.mac must not be empty");
        }
        if !self.is_known_party(&msg.from_user, &msg.from_device) {
            return self.fail(
                "invalid_param",
                "mac.from_user/device not part of this strand",
            );
        }
        if self.macs_received.contains_key(&msg.from_device) {
            return self.fail(
                "invalid_transition",
                "mac already received from this device",
            );
        }
        // §10.3: the MAC MUST be verified against the transcript-bound
        // MAC key; an unverifiable MAC is a mismatch, not a pass.
        let mac_key = match self.mac_key_for(&msg.from_device) {
            Ok(key) => key,
            Err(err) => {
                return self.fail("mismatched_mac", &format!("cannot verify mac: {err}"));
            }
        };
        let key_ids = msg.mac.keys().cloned().collect::<Vec<_>>().join(",");
        let expected_keys_mac = base64url_encode(hmac_sha256(&mac_key[..], key_ids.as_bytes()));
        if !ct_eq(&expected_keys_mac, &msg.keys) {
            return self.fail("mismatched_mac", "mac.keys does not match the transcript");
        }
        for (key_id, mac_value) in &msg.mac {
            let Some(key_value) = expected_verify_keys.get(key_id) else {
                return self.fail(
                    "mismatched_mac",
                    &format!("mac covers unknown key id {key_id:?}"),
                );
            };
            let expected = base64url_encode(hmac_sha256(
                &mac_key[..],
                format!("{key_id}|{key_value}").as_bytes(),
            ));
            if !ct_eq(&expected, mac_value) {
                return self.fail(
                    "mismatched_mac",
                    &format!("mac for key id {key_id:?} does not match"),
                );
            }
        }
        self.macs_received
            .insert(msg.from_device.clone(), msg.clone());
        self.state = next;
        Ok(())
    }

    /// Step 5: accept `done` envelopes (one per side) — closes the strand.
    pub fn on_done(&mut self, msg: &KeyVerificationDone) -> Result<()> {
        let next = match self.state {
            KeyVerificationState::MacsReceived => KeyVerificationState::DoneHalfReceived,
            KeyVerificationState::DoneHalfReceived => KeyVerificationState::Done,
            _ => {
                return self.fail(
                    "invalid_transition",
                    "done only legal after both macs received",
                );
            }
        };
        self.assert_txn(&msg.transaction_id)?;
        if !self.is_known_party(&msg.from_user, &msg.from_device) {
            return self.fail(
                "invalid_param",
                "done.from_user/device not part of this strand",
            );
        }
        if self.done_received.contains_key(&msg.from_device) {
            return self.fail(
                "invalid_transition",
                "done already received from this device",
            );
        }
        self.done_received
            .insert(msg.from_device.clone(), msg.clone());
        self.state = next;
        Ok(())
    }

    /// Cancel the strand at any non-terminal state.
    pub fn on_cancel(&mut self, msg: &KeyVerificationCancel) -> Result<()> {
        if self.state.is_terminal() {
            return Err(Error::Protocol(
                "cannot cancel terminal verification strand".to_owned(),
            ));
        }
        if let Some(ref txn) = self.transaction_id
            && txn != &msg.transaction_id
        {
            return Err(Error::Protocol("cancel.transaction_id mismatch".to_owned()));
        }
        self.cancel = Some(msg.clone());
        self.state = KeyVerificationState::Cancelled;
        Ok(())
    }

    fn assert_txn(&self, txn: &str) -> Result<()> {
        match &self.transaction_id {
            Some(active) if active == txn => Ok(()),
            _ => Err(Error::Protocol(
                "key-verification envelope transaction_id mismatch".to_owned(),
            )),
        }
    }

    fn is_known_party(&self, did: &Did, device: &DeviceId) -> bool {
        self.initiator
            .as_ref()
            .is_some_and(|(d, dev)| d == did && dev == device)
            || self
                .responder
                .as_ref()
                .is_some_and(|(d, dev)| d == did && dev == device)
    }

    fn fail(&mut self, code: &str, reason: &str) -> Result<()> {
        self.cancel = Some(KeyVerificationCancel {
            transaction_id: self.transaction_id.clone().unwrap_or_default(),
            from_user: self
                .initiator
                .as_ref()
                .map(|(d, _)| d.clone())
                .or_else(|| self.responder.as_ref().map(|(d, _)| d.clone()))
                .unwrap_or_else(|| Did::new("did:webvh:z6mkfixture:unknown.example").unwrap()),
            from_device: self
                .initiator
                .as_ref()
                .map(|(_, d)| d.clone())
                .or_else(|| self.responder.as_ref().map(|(_, d)| d.clone()))
                .unwrap_or_else(|| {
                    DeviceId::new("ak:device:01904100-0000-7000-8000-00000000000d").unwrap()
                }),
            code: code.to_owned(),
            reason: reason.to_owned(),
            sent_at: Utc::now(),
        });
        self.state = KeyVerificationState::Cancelled;
        Err(Error::Protocol(format!("{code}: {reason}")))
    }
}

fn validate_transaction_id(txn: &str) -> Result<()> {
    if txn.trim().is_empty() {
        return Err(Error::Protocol(
            "transaction_id must not be empty".to_owned(),
        ));
    }
    if txn.len() > 256 {
        return Err(Error::Protocol(
            "transaction_id exceeds 256 chars".to_owned(),
        ));
    }
    Ok(())
}
