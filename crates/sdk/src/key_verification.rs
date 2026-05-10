//! Production typed key-verification flow per `crypto-media/device-lifecycle.md` §4.
//!
//! Round 24 (2026-05-09) graduates the key-verification helper from the
//! schema-aligned but raw [`crate::devices::DeviceVerificationMessageContent`]
//! scaffold to a typed envelope-per-step API + state machine.
//!
//! Mirrors the Matrix-style `start → accept → key → mac → done` flow with
//! a typed envelope per step:
//!
//! - [`KeyVerificationStart`]
//! - [`KeyVerificationAccept`]
//! - [`KeyVerificationKey`]
//! - [`KeyVerificationMac`]
//! - [`KeyVerificationDone`]
//! - [`KeyVerificationCancel`]
//!
//! and a [`KeyVerificationFlow`] state machine that consumes them in
//! strict order. Every transition is validated and an out-of-order
//! call returns `Error::Protocol(...)` rather than silently accepting it.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{DeviceId, Did, Error, Result};

/// Initiator's first message: agree on protocols + commit to a SAS code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVerificationStart {
    pub transaction_id: String,
    pub from_user: Did,
    pub from_device: DeviceId,
    pub method: String,
    /// Supported key-agreement protocols (e.g. `curve25519-hkdf-sha256`).
    pub key_agreement_protocols: Vec<String>,
    /// Supported MAC algorithms (e.g. `hkdf-hmac-sha256`).
    pub message_authentication_codes: Vec<String>,
    /// Supported short-authentication-string forms (`decimal`, `emoji`).
    pub short_authentication_string: Vec<String>,
    /// Wall-clock send time.
    pub sent_at: DateTime<Utc>,
}

/// Responder's reply to `start`: pick one protocol/MAC/SAS combo and
/// commit to the responder's keying material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVerificationAccept {
    pub transaction_id: String,
    pub from_user: Did,
    pub from_device: DeviceId,
    pub method: String,
    pub key_agreement_protocol: String,
    pub message_authentication_code: String,
    pub short_authentication_string: Vec<String>,
    /// SHA-256 commitment over the responder's public key.
    pub commitment: String,
    pub sent_at: DateTime<Utc>,
}

/// Public key exchange (one per side, both must arrive before MAC).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVerificationKey {
    pub transaction_id: String,
    pub from_user: Did,
    pub from_device: DeviceId,
    /// Multibase-encoded public key contributed to the SAS DH.
    pub key: String,
    pub sent_at: DateTime<Utc>,
}

/// MAC over each side's keys binding to the agreed transcript.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVerificationMac {
    pub transaction_id: String,
    pub from_user: Did,
    pub from_device: DeviceId,
    /// MAC over the entire keys block, keyed with HKDF-derived key.
    pub keys: String,
    /// Per-key MACs keyed by `key_id`.
    pub mac: BTreeMap<String, String>,
    pub sent_at: DateTime<Utc>,
}

/// Final ack closing the transaction successfully.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVerificationDone {
    pub transaction_id: String,
    pub from_user: Did,
    pub from_device: DeviceId,
    pub sent_at: DateTime<Utc>,
}

/// Cancellation envelope (may arrive at any state and aborts the flow).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyVerificationCancel {
    pub transaction_id: String,
    pub from_user: Did,
    pub from_device: DeviceId,
    pub code: String,
    pub reason: String,
    pub sent_at: DateTime<Utc>,
}

/// Strict state machine state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyVerificationState {
    /// No envelopes accepted yet.
    Idle,
    /// `start` received; waiting for `accept`.
    Started,
    /// `accept` received; waiting for both sides' `key` exchange.
    Accepted,
    /// First side's `key` accepted; waiting for the other side's.
    KeyHalfExchanged,
    /// Both sides' `key` exchanged; waiting for both `mac` envelopes.
    KeysExchanged,
    /// First side's `mac` accepted; waiting for the other.
    MacHalfReceived,
    /// Both `mac` envelopes verified; waiting for `done` from each.
    MacsReceived,
    /// First `done` accepted; waiting for the second.
    DoneHalfReceived,
    /// Flow completed successfully.
    Done,
    /// Flow cancelled or aborted.
    Cancelled,
}

impl KeyVerificationState {
    /// Whether the flow has reached a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Done | Self::Cancelled)
    }
}

/// Strict-transition state machine that consumes [`KeyVerificationStart`],
/// [`KeyVerificationAccept`], [`KeyVerificationKey`], [`KeyVerificationMac`]
/// and [`KeyVerificationDone`] in order.
///
/// On any out-of-order envelope or transaction-id mismatch the call
/// returns `Err(Error::Protocol(...))` and the state is moved to
/// [`KeyVerificationState::Cancelled`].
#[derive(Clone, Debug)]
pub struct KeyVerificationFlow {
    state: KeyVerificationState,
    transaction_id: Option<String>,
    initiator: Option<(Did, DeviceId)>,
    responder: Option<(Did, DeviceId)>,
    keys_exchanged: BTreeMap<DeviceId, String>,
    macs_received: BTreeMap<DeviceId, KeyVerificationMac>,
    done_received: BTreeMap<DeviceId, KeyVerificationDone>,
    cancel: Option<KeyVerificationCancel>,
}

impl Default for KeyVerificationFlow {
    fn default() -> Self {
        Self {
            state: KeyVerificationState::Idle,
            transaction_id: None,
            initiator: None,
            responder: None,
            keys_exchanged: BTreeMap::new(),
            macs_received: BTreeMap::new(),
            done_received: BTreeMap::new(),
            cancel: None,
        }
    }
}

impl KeyVerificationFlow {
    /// Create an `Idle` flow.
    pub fn new() -> Self {
        Self::default()
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
            return self.fail("invalid_param", "start protocol/mac/SAS lists must not be empty");
        }
        self.transaction_id = Some(msg.transaction_id.clone());
        self.initiator = Some((msg.from_user.clone(), msg.from_device.clone()));
        self.state = KeyVerificationState::Started;
        Ok(())
    }

    /// Step 2: accept `accept`. Only legal in `Started`.
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
            return self.fail("invalid_param", "accept must come from responder, not initiator");
        }
        self.responder = Some((msg.from_user.clone(), msg.from_device.clone()));
        self.state = KeyVerificationState::Accepted;
        Ok(())
    }

    /// Step 3: accept `key` envelopes (one per side, in any order).
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
            return self.fail("invalid_param", "key.from_user/device not part of this flow");
        }
        if self.keys_exchanged.contains_key(&msg.from_device) {
            return self.fail("invalid_transition", "key already received from this device");
        }
        self.keys_exchanged.insert(msg.from_device.clone(), msg.key.clone());
        self.state = next;
        Ok(())
    }

    /// Step 4: accept `mac` envelopes (one per side).
    pub fn on_mac(&mut self, msg: &KeyVerificationMac) -> Result<()> {
        let next = match self.state {
            KeyVerificationState::KeysExchanged => KeyVerificationState::MacHalfReceived,
            KeyVerificationState::MacHalfReceived => KeyVerificationState::MacsReceived,
            _ => {
                return self.fail("invalid_transition", "mac only legal after both keys exchanged");
            }
        };
        self.assert_txn(&msg.transaction_id)?;
        if msg.keys.trim().is_empty() || msg.mac.is_empty() {
            return self.fail("invalid_param", "mac.keys and mac.mac must not be empty");
        }
        if !self.is_known_party(&msg.from_user, &msg.from_device) {
            return self.fail("invalid_param", "mac.from_user/device not part of this flow");
        }
        if self.macs_received.contains_key(&msg.from_device) {
            return self.fail("invalid_transition", "mac already received from this device");
        }
        self.macs_received.insert(msg.from_device.clone(), msg.clone());
        self.state = next;
        Ok(())
    }

    /// Step 5: accept `done` envelopes (one per side) — closes the flow.
    pub fn on_done(&mut self, msg: &KeyVerificationDone) -> Result<()> {
        let next = match self.state {
            KeyVerificationState::MacsReceived => KeyVerificationState::DoneHalfReceived,
            KeyVerificationState::DoneHalfReceived => KeyVerificationState::Done,
            _ => {
                return self.fail("invalid_transition", "done only legal after both macs received");
            }
        };
        self.assert_txn(&msg.transaction_id)?;
        if !self.is_known_party(&msg.from_user, &msg.from_device) {
            return self.fail("invalid_param", "done.from_user/device not part of this flow");
        }
        if self.done_received.contains_key(&msg.from_device) {
            return self.fail("invalid_transition", "done already received from this device");
        }
        self.done_received.insert(msg.from_device.clone(), msg.clone());
        self.state = next;
        Ok(())
    }

    /// Cancel the flow at any non-terminal state.
    pub fn on_cancel(&mut self, msg: &KeyVerificationCancel) -> Result<()> {
        if self.state.is_terminal() {
            return Err(Error::Protocol("cannot cancel terminal verification flow".to_owned()));
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
            _ => {
                Err(Error::Protocol("key-verification envelope transaction_id mismatch".to_owned()))
            }
        }
    }

    fn is_known_party(&self, did: &Did, device: &DeviceId) -> bool {
        self.initiator.as_ref().is_some_and(|(d, dev)| d == did && dev == device)
            || self.responder.as_ref().is_some_and(|(d, dev)| d == did && dev == device)
    }

    fn fail(&mut self, code: &str, reason: &str) -> Result<()> {
        self.cancel = Some(KeyVerificationCancel {
            transaction_id: self.transaction_id.clone().unwrap_or_default(),
            from_user: self
                .initiator
                .as_ref()
                .map(|(d, _)| d.clone())
                .or_else(|| self.responder.as_ref().map(|(d, _)| d.clone()))
                .unwrap_or_else(|| Did::new("did:web:unknown.example").unwrap()),
            from_device: self
                .initiator
                .as_ref()
                .map(|(_, d)| d.clone())
                .or_else(|| self.responder.as_ref().map(|(_, d)| d.clone()))
                .unwrap_or_else(|| DeviceId::new("dev_unknown").unwrap()),
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
        return Err(Error::Protocol("transaction_id must not be empty".to_owned()));
    }
    if txn.len() > 256 {
        return Err(Error::Protocol("transaction_id exceeds 256 chars".to_owned()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    fn dev(name: &str) -> DeviceId {
        DeviceId::new(format!("dev_{name}")).unwrap()
    }

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    fn start(txn: &str) -> KeyVerificationStart {
        KeyVerificationStart {
            transaction_id: txn.to_owned(),
            from_user: did("alice"),
            from_device: dev("alice_phone"),
            method: "sas_v1".to_owned(),
            key_agreement_protocols: vec!["curve25519-hkdf-sha256".to_owned()],
            message_authentication_codes: vec!["hkdf-hmac-sha256".to_owned()],
            short_authentication_string: vec!["decimal".to_owned()],
            sent_at: now(),
        }
    }

    fn accept(txn: &str) -> KeyVerificationAccept {
        KeyVerificationAccept {
            transaction_id: txn.to_owned(),
            from_user: did("bob"),
            from_device: dev("bob_laptop"),
            method: "sas_v1".to_owned(),
            key_agreement_protocol: "curve25519-hkdf-sha256".to_owned(),
            message_authentication_code: "hkdf-hmac-sha256".to_owned(),
            short_authentication_string: vec!["decimal".to_owned()],
            commitment: "sha256:cafe".to_owned(),
            sent_at: now(),
        }
    }

    fn key(txn: &str, who: &Did, dvc: &DeviceId, k: &str) -> KeyVerificationKey {
        KeyVerificationKey {
            transaction_id: txn.to_owned(),
            from_user: who.clone(),
            from_device: dvc.clone(),
            key: k.to_owned(),
            sent_at: now(),
        }
    }

    fn mac(txn: &str, who: &Did, dvc: &DeviceId) -> KeyVerificationMac {
        KeyVerificationMac {
            transaction_id: txn.to_owned(),
            from_user: who.clone(),
            from_device: dvc.clone(),
            keys: "MAC_keys".to_owned(),
            mac: BTreeMap::from([("ed25519:k1".to_owned(), "MAC_k1".to_owned())]),
            sent_at: now(),
        }
    }

    fn done(txn: &str, who: &Did, dvc: &DeviceId) -> KeyVerificationDone {
        KeyVerificationDone {
            transaction_id: txn.to_owned(),
            from_user: who.clone(),
            from_device: dvc.clone(),
            sent_at: now(),
        }
    }

    #[test]
    fn full_flow_runs_to_done() {
        let txn = "txn-1";
        let mut flow = KeyVerificationFlow::new();
        flow.on_start(&start(txn)).unwrap();
        assert_eq!(flow.state(), KeyVerificationState::Started);
        flow.on_accept(&accept(txn)).unwrap();
        assert_eq!(flow.state(), KeyVerificationState::Accepted);
        flow.on_key(&key(txn, &did("alice"), &dev("alice_phone"), "AKEY")).unwrap();
        flow.on_key(&key(txn, &did("bob"), &dev("bob_laptop"), "BKEY")).unwrap();
        assert_eq!(flow.state(), KeyVerificationState::KeysExchanged);
        flow.on_mac(&mac(txn, &did("alice"), &dev("alice_phone"))).unwrap();
        flow.on_mac(&mac(txn, &did("bob"), &dev("bob_laptop"))).unwrap();
        assert_eq!(flow.state(), KeyVerificationState::MacsReceived);
        flow.on_done(&done(txn, &did("alice"), &dev("alice_phone"))).unwrap();
        flow.on_done(&done(txn, &did("bob"), &dev("bob_laptop"))).unwrap();
        assert_eq!(flow.state(), KeyVerificationState::Done);
        assert!(flow.state().is_terminal());
    }

    #[test]
    fn rejects_out_of_order_accept_without_start() {
        let mut flow = KeyVerificationFlow::new();
        let err = flow.on_accept(&accept("txn-x")).unwrap_err();
        assert!(format!("{err}").contains("invalid_transition"));
        assert_eq!(flow.state(), KeyVerificationState::Cancelled);
    }

    #[test]
    fn rejects_transaction_id_mismatch() {
        let mut flow = KeyVerificationFlow::new();
        flow.on_start(&start("txn-1")).unwrap();
        let err = flow.on_accept(&accept("txn-2")).unwrap_err();
        assert!(format!("{err}").contains("transaction_id"));
    }

    #[test]
    fn rejects_unknown_party_key() {
        let txn = "txn-1";
        let mut flow = KeyVerificationFlow::new();
        flow.on_start(&start(txn)).unwrap();
        flow.on_accept(&accept(txn)).unwrap();
        let err = flow.on_key(&key(txn, &did("eve"), &dev("eve_box"), "EKEY")).unwrap_err();
        assert!(format!("{err}").contains("not part of this flow"));
        assert_eq!(flow.state(), KeyVerificationState::Cancelled);
    }

    #[test]
    fn cancel_records_reason_and_terminates() {
        let txn = "txn-1";
        let mut flow = KeyVerificationFlow::new();
        flow.on_start(&start(txn)).unwrap();
        flow.on_cancel(&KeyVerificationCancel {
            transaction_id: txn.to_owned(),
            from_user: did("alice"),
            from_device: dev("alice_phone"),
            code: "user_cancel".to_owned(),
            reason: "user pressed cancel".to_owned(),
            sent_at: now(),
        })
        .unwrap();
        assert_eq!(flow.state(), KeyVerificationState::Cancelled);
        assert_eq!(flow.cancel_record().unwrap().code, "user_cancel");
    }

    #[test]
    fn cannot_cancel_terminal_flow() {
        let txn = "txn-1";
        let mut flow = KeyVerificationFlow::new();
        flow.on_start(&start(txn)).unwrap();
        flow.on_cancel(&KeyVerificationCancel {
            transaction_id: txn.to_owned(),
            from_user: did("alice"),
            from_device: dev("alice_phone"),
            code: "x".to_owned(),
            reason: "x".to_owned(),
            sent_at: now(),
        })
        .unwrap();
        let err = flow
            .on_cancel(&KeyVerificationCancel {
                transaction_id: txn.to_owned(),
                from_user: did("alice"),
                from_device: dev("alice_phone"),
                code: "y".to_owned(),
                reason: "y".to_owned(),
                sent_at: now(),
            })
            .unwrap_err();
        assert!(format!("{err}").contains("terminal"));
    }
}
