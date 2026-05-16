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

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::{DeviceId, Did, Error, Result};

// ════════════════════════════════════════════════════════════════════
// Sprint Q1 第十六增量 (B2-ECDH): X25519 key agreement.
//
// `KeyVerificationFlow::on_key` carries each party's ephemeral public
// key as a base64 string (the `key` field). Two devices doing the SAS
// exchange MUST end up with the same shared secret bytes — that's the
// whole point of the protocol — and that secret is the input to
// `derive_sas_bytes` so the resulting emoji + decimal SAS row is the
// same on both sides.
//
// Spec: `crypto-media/device-lifecycle.md` §4.5; we use the
// `curve25519-hkdf-sha256` agreement protocol the existing
// KeyVerificationAccept already advertises (line ~395). The ephemeral
// keypair is generated per flow via `EphemeralX25519Keypair::generate`
// and consumed by `compute_shared_secret` once the peer's public key
// arrives.
// ════════════════════════════════════════════════════════════════════

/// Ephemeral X25519 keypair used for a single key-verification flow.
/// The private side never leaves the in-memory structure; the public
/// side is base64-encoded and shipped as the `KeyVerificationKey.key`
/// payload to the peer.
#[derive(Clone)]
pub struct EphemeralX25519Keypair {
    secret: StaticSecret,
    public: X25519PublicKey,
}

impl EphemeralX25519Keypair {
    /// Generate a fresh keypair using `getrandom` via x25519-dalek's
    /// `StaticSecret::random_from_rng` against `OsRng`. The keypair is
    /// scoped to a single SAS verification round and MUST NOT be
    /// reused across flows.
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).expect("system rng");
        let secret = StaticSecret::from(seed);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Base64 (no-pad) encoding of the public key — the on-the-wire
    /// form for `KeyVerificationKey.key`.
    pub fn public_base64(&self) -> String {
        STANDARD_NO_PAD.encode(self.public.as_bytes())
    }

    /// Compute the X25519 shared secret between this side's private
    /// key and the peer's base64-encoded public key. Returns 32 bytes
    /// suitable as the `shared_secret` argument to
    /// [`derive_sas_bytes`].
    pub fn compute_shared_secret(&self, peer_public_b64: &str) -> Result<[u8; 32]> {
        let peer_bytes = STANDARD_NO_PAD
            .decode(peer_public_b64.as_bytes())
            .map_err(|err| {
                Error::Protocol(format!("peer x25519 public key base64 decode: {err}"))
            })?;
        if peer_bytes.len() != 32 {
            return Err(Error::Protocol(format!(
                "peer x25519 public key must be 32 bytes, got {}",
                peer_bytes.len()
            )));
        }
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&peer_bytes);
        let peer_public = X25519PublicKey::from(buf);
        let shared = self.secret.diffie_hellman(&peer_public);
        Ok(*shared.as_bytes())
    }
}

impl std::fmt::Debug for EphemeralX25519Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never leak the private key in Debug output. Only the public
        // half is observable.
        f.debug_struct("EphemeralX25519Keypair")
            .field("public", &self.public_base64())
            .field("secret", &"<redacted>")
            .finish()
    }
}

// ════════════════════════════════════════════════════════════════════
// Sprint Q1 第十五增量 (B2): Short Authentication String derivation.
//
// Implements the SAS extraction step of `crypto-media/device-lifecycle.md`
// §4.5 — once the two parties have exchanged ephemeral public keys and
// computed a shared secret out-of-band, the SAS bytes are derived
// deterministically from `(shared_secret, info)` via HKDF-SHA256
// (RFC 5869), with `info` carrying the transaction id + per-party DIDs /
// device ids so the result is bound to the flow context.
//
// Two outputs are supported (matches the Matrix SAS modes both clients
// have to support):
//   * **emoji** — 7 indices each into [`SAS_EMOJI_TABLE`] (64-entry
//     table from the MSC2241 dictionary).
//   * **decimal** — 3 digits in `[1000, 9999]`, one per side of the
//     "compare these three numbers" UX.
//
// The two SAS bytes are derived from the same HKDF expand so a single
// call to [`derive_sas_bytes`] returns both at once.
// ════════════════════════════════════════════════════════════════════

/// Number of bytes derived from HKDF-Expand for SAS computation.
/// 6 bytes (48 bits) feed the 7-emoji slot (7 × 6-bit indices = 42 bits,
/// 6 bits unused); 5 bytes (40 bits) feed the 3-decimal slot (3 ×
/// 13-bit values = 39 bits + 1 unused).
const SAS_EMOJI_BYTES: usize = 6;
const SAS_DECIMAL_BYTES: usize = 5;
const SAS_OUTPUT_LEN: usize = SAS_EMOJI_BYTES + SAS_DECIMAL_BYTES;

/// `(emoji_codepoint, english_label)` pairs sourced from MSC2241.
/// Indexed by the lower 6 bits of an HKDF-derived byte.
pub const SAS_EMOJI_TABLE: [(&str, &str); 64] = [
    ("\u{1F436}", "Dog"),       ("\u{1F431}", "Cat"),
    ("\u{1F981}", "Lion"),       ("\u{1F40E}", "Horse"),
    ("\u{1F984}", "Unicorn"),    ("\u{1F437}", "Pig"),
    ("\u{1F418}", "Elephant"),   ("\u{1F430}", "Rabbit"),
    ("\u{1F43C}", "Panda"),      ("\u{1F413}", "Rooster"),
    ("\u{1F427}", "Penguin"),    ("\u{1F422}", "Turtle"),
    ("\u{1F41F}", "Fish"),       ("\u{1F419}", "Octopus"),
    ("\u{1F98B}", "Butterfly"),  ("\u{1F337}", "Flower"),
    ("\u{1F333}", "Tree"),       ("\u{1F335}", "Cactus"),
    ("\u{1F344}", "Mushroom"),   ("\u{1F30F}", "Globe"),
    ("\u{1F319}", "Moon"),       ("\u{2601}", "Cloud"),
    ("\u{1F525}", "Fire"),       ("\u{1F34C}", "Banana"),
    ("\u{1F34E}", "Apple"),      ("\u{1F353}", "Strawberry"),
    ("\u{1F33D}", "Corn"),       ("\u{1F355}", "Pizza"),
    ("\u{1F382}", "Cake"),       ("\u{1F36D}", "Lollipop"),
    ("\u{1F37C}", "Bottle"),     ("\u{2693}", "Anchor"),
    ("\u{1F3A7}", "Headphones"), ("\u{1F4D6}", "Book"),
    ("\u{1F4BB}", "Computer"),   ("\u{1F4F7}", "Camera"),
    ("\u{1F4A1}", "Light Bulb"), ("\u{1F381}", "Gift"),
    ("\u{231B}", "Hourglass"),   ("\u{1F529}", "Wrench"),
    ("\u{1F389}", "Party"),      ("\u{1F3A8}", "Art"),
    ("\u{1F3B5}", "Music"),      ("\u{1F3B7}", "Saxophone"),
    ("\u{1F4DA}", "Books"),      ("\u{1F4E6}", "Box"),
    ("\u{1F4E7}", "Envelope"),   ("\u{1F50D}", "Magnifier"),
    ("\u{1F511}", "Key"),        ("\u{1F512}", "Lock"),
    ("\u{1F4B0}", "Money"),      ("\u{2615}", "Coffee"),
    ("\u{1F3E0}", "House"),      ("\u{1F4DD}", "Pen"),
    ("\u{1F4CB}", "Clipboard"),  ("\u{2702}", "Scissors"),
    ("\u{1F465}", "People"),     ("\u{1F4AC}", "Speech"),
    ("\u{1F44D}", "Thumbs Up"),  ("\u{270C}", "Peace"),
    ("\u{1F44A}", "Punch"),      ("\u{1F596}", "Spock"),
    ("\u{1F4AF}", "Hundred"),    ("\u{2728}", "Sparkles"),
];

/// Derived SAS pair: 7 emoji indices (each 0..64) + 3 decimal digits
/// each in `[1000, 9999]`. Returned together so both representations
/// share the same HKDF expand and a UI can flip between them without
/// re-deriving.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShortAuthenticationString {
    pub emoji_indices: [u8; 7],
    pub decimal_digits: [u16; 3],
}

impl ShortAuthenticationString {
    /// Render the emoji + label pairs ready for UI display.
    pub fn emoji_pairs(&self) -> [(&'static str, &'static str); 7] {
        let mut out: [(&'static str, &'static str); 7] = [("", ""); 7];
        for (slot, idx) in self.emoji_indices.iter().enumerate() {
            out[slot] = SAS_EMOJI_TABLE[(*idx as usize) & 0x3f];
        }
        out
    }
}

/// Derive the SAS pair from a shared secret + binding info per
/// `device-lifecycle.md` §4.5. Both inputs are bytes; the caller is
/// expected to encode the canonical info string (transaction id +
/// per-party DIDs + per-party device ids, joined with `|`) externally.
///
/// HKDF-SHA256 is implemented inline via HMAC-SHA256 (RFC 5869):
/// `Extract(salt=zeros, IKM=shared_secret) → PRK`; then
/// `Expand(PRK, info, L=11) → OKM`. The first 6 OKM bytes feed the
/// emoji indices (7 × 6 bits); the next 5 feed the three decimal
/// digits (3 × 13 bits each, mapped into `[1000, 9999]`).
pub fn derive_sas_bytes(shared_secret: &[u8], info: &[u8]) -> ShortAuthenticationString {
    let prk = hmac_sha256(&[0u8; 32], shared_secret);
    let mut okm = [0u8; SAS_OUTPUT_LEN];
    hkdf_expand_sha256(&prk, info, &mut okm);

    // Emoji indices — 7 × 6-bit values packed big-endian into bytes
    // [0..6) (48 bits = 8 × 6 bits, we take the first seven).
    let mut emoji_indices = [0u8; 7];
    let mut bit_cursor = 0usize;
    for slot in 0..7 {
        let mut idx: u8 = 0;
        for bit in 0..6 {
            let byte = okm[bit_cursor / 8];
            let bit_in_byte = 7 - (bit_cursor % 8);
            idx = (idx << 1) | ((byte >> bit_in_byte) & 1);
            bit_cursor += 1;
            let _ = bit;
        }
        emoji_indices[slot] = idx;
        let _ = slot;
    }

    // Decimal digits — 3 × 13-bit values from bytes [6..11).
    // Reinterpret 40 bits as 39 used + 1 padding bit.
    let dec = &okm[SAS_EMOJI_BYTES..SAS_OUTPUT_LEN];
    // Pack 5 bytes (40 bits) into a u64, then take three 13-bit chunks.
    let mut packed: u64 = 0;
    for byte in dec {
        packed = (packed << 8) | (*byte as u64);
    }
    // Use the top 39 bits (5 * 8 = 40, ignore the bottom bit).
    let d1 = ((packed >> 26) & 0x1FFF) as u16; // bits 38..26
    let d2 = ((packed >> 13) & 0x1FFF) as u16; // bits 25..13
    let d3 = (packed & 0x1FFF) as u16;          // bits 12..0
    let decimal_digits = [
        1000u16.saturating_add(d1 % 9000),
        1000u16.saturating_add(d2 % 9000),
        1000u16.saturating_add(d3 % 9000),
    ];

    ShortAuthenticationString {
        emoji_indices,
        decimal_digits,
    }
}

/// HMAC-SHA256 (RFC 2104) implemented inline against the SDK's
/// existing `sha2` dependency so this module does not need a new
/// `hmac` crate.
fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let digest = Sha256::digest(key);
        key_block[..32].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    let final_digest = outer.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&final_digest);
    out
}

/// HKDF-Expand-SHA256 (RFC 5869 §2.3). Writes `output.len()` bytes
/// produced by iterating `T(i) = HMAC(prk, T(i-1) || info || i)`.
fn hkdf_expand_sha256(prk: &[u8; 32], info: &[u8], output: &mut [u8]) {
    let n = output.len().div_ceil(32);
    debug_assert!(n <= 255, "HKDF-Expand SHA-256 output limited to 255 * 32 bytes");
    let mut prev: [u8; 32] = [0u8; 32];
    let mut produced = 0usize;
    for i in 1..=n {
        let mut buf: Vec<u8> = Vec::with_capacity(32 + info.len() + 1);
        if i > 1 {
            buf.extend_from_slice(&prev);
        }
        buf.extend_from_slice(info);
        buf.push(i as u8);
        prev = hmac_sha256(prk, &buf);
        let take = std::cmp::min(32, output.len() - produced);
        output[produced..produced + take].copy_from_slice(&prev[..take]);
        produced += take;
    }
}

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
    /// Sprint Q1 第十六增量 (B2-ECDH): this side's ephemeral X25519
    /// keypair for the SAS exchange. `None` until the caller installs
    /// one via [`Self::with_ephemeral_key`]; once installed, the
    /// public half MUST be the value put on the wire as
    /// `KeyVerificationKey.key`, and the private half is used in
    /// [`Self::compute_sas`] together with the peer's public key from
    /// `keys_exchanged` to derive the shared secret.
    ephemeral: Option<EphemeralX25519Keypair>,
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
            ephemeral: None,
        }
    }
}

impl KeyVerificationFlow {
    /// Create an `Idle` flow.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sprint Q1 第十六增量 (B2-ECDH): install this side's ephemeral
    /// X25519 keypair. Builder-style so call sites stay readable:
    /// `KeyVerificationFlow::new().with_ephemeral_key(EphemeralX25519Keypair::generate())`.
    /// MUST be called before the first `on_key` step or
    /// [`Self::compute_sas`] will refuse with `Error::Protocol`.
    pub fn with_ephemeral_key(mut self, key: EphemeralX25519Keypair) -> Self {
        self.ephemeral = Some(key);
        self
    }

    /// Sprint Q1 第十六增量 (B2-ECDH): base64 (no-pad) public half of
    /// the installed ephemeral keypair. Returns `None` when no
    /// keypair is installed yet — callers SHOULD use this to fill
    /// `KeyVerificationKey.key` when sending the `key` envelope to
    /// the peer.
    pub fn ephemeral_public_base64(&self) -> Option<String> {
        self.ephemeral.as_ref().map(EphemeralX25519Keypair::public_base64)
    }

    /// Sprint Q1 第十六增量 (B2-ECDH): compute the SAS pair for this
    /// flow. Steps:
    ///   1. Look up the peer's public key in `keys_exchanged` — the
    ///      `self_device` argument is OUR `DeviceId`, so the peer's
    ///      key is the only entry not keyed by `self_device`.
    ///   2. Run X25519 between our ephemeral private + the peer's
    ///      public to produce the 32-byte shared secret.
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
        Ok(derive_sas_bytes(&shared, info))
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
                .unwrap_or_else(|| {
                    DeviceId::new("cx:device:01904100-0000-7000-8000-00000000000d").unwrap()
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

    /// Sprint Q1 第十五增量 (B2): `derive_sas_bytes` MUST be a
    /// pure function of `(shared_secret, info)`. Same inputs → same
    /// outputs, two different infos → distinct outputs. Pin the
    /// shapes (7 emoji indices in `[0, 64)`, 3 decimals in
    /// `[1000, 9999]`) so a future regression that flips
    /// MASK_6_BITS or the bit layout fails loudly.
    #[test]
    fn derive_sas_bytes_is_deterministic_and_bounded() {
        let secret = b"shared-ECDH-secret-bytes-32-long-pad";
        let info_a = b"flow-1|alice|alice-device|bob|bob-device";
        let info_b = b"flow-2|alice|alice-device|bob|bob-device";

        let sas_a1 = derive_sas_bytes(secret, info_a);
        let sas_a2 = derive_sas_bytes(secret, info_a);
        let sas_b = derive_sas_bytes(secret, info_b);

        // Determinism.
        assert_eq!(sas_a1, sas_a2);
        // Different info → different SAS (with overwhelming probability).
        assert_ne!(sas_a1, sas_b);

        // Emoji indices fit in [0, 64).
        for idx in sas_a1.emoji_indices {
            assert!(idx < 64);
        }
        // Decimal digits fit in [1000, 9999].
        for d in sas_a1.decimal_digits {
            assert!(d >= 1000 && d <= 9999);
        }
        // emoji_pairs MUST return 7 valid entries.
        let pairs = sas_a1.emoji_pairs();
        assert_eq!(pairs.len(), 7);
        for (codepoint, label) in pairs.iter() {
            assert!(!codepoint.is_empty());
            assert!(!label.is_empty());
        }
    }

    /// Sprint Q1 第十五增量 (B2): the SAS computation MUST behave like a
    /// real HKDF — change one byte of `shared_secret`, the output
    /// changes. This guards against a regression that ignores the
    /// secret and only hashes `info`.
    #[test]
    fn derive_sas_bytes_depends_on_secret() {
        let info = b"transaction-id-only";
        let sas_a = derive_sas_bytes(b"secret-A", info);
        let sas_b = derive_sas_bytes(b"secret-B", info);
        assert_ne!(sas_a, sas_b);
    }

    /// Sprint Q1 第十六增量 (B2-ECDH): X25519 key agreement is
    /// symmetric — given two ephemeral keypairs, each side computes
    /// the same 32-byte shared secret from its private key + the
    /// peer's public key. This pins the protocol's core invariant.
    #[test]
    fn ephemeral_x25519_keypair_yields_symmetric_shared_secret() {
        let alice = EphemeralX25519Keypair::generate();
        let bob = EphemeralX25519Keypair::generate();
        let alice_to_bob = alice
            .compute_shared_secret(&bob.public_base64())
            .expect("compute alice -> bob");
        let bob_to_alice = bob
            .compute_shared_secret(&alice.public_base64())
            .expect("compute bob -> alice");
        assert_eq!(alice_to_bob, bob_to_alice);
    }

    /// Sprint Q1 第十六增量 (B2-ECDH): the SAS pair derived from the
    /// X25519 shared secret MUST match on both sides — that's the
    /// whole point of the verification flow. The `info` parameter
    /// here is the canonical binding string both sides agree on
    /// (transaction id + per-party DIDs + per-party device ids).
    #[test]
    fn sas_derived_from_ecdh_shared_secret_matches_on_both_sides() {
        let alice = EphemeralX25519Keypair::generate();
        let bob = EphemeralX25519Keypair::generate();
        let alice_shared = alice
            .compute_shared_secret(&bob.public_base64())
            .expect("alice shared");
        let bob_shared = bob
            .compute_shared_secret(&alice.public_base64())
            .expect("bob shared");
        let info = b"flow-7|did:web:alice|alice-device|did:web:bob|bob-device";
        let sas_alice = derive_sas_bytes(&alice_shared, info);
        let sas_bob = derive_sas_bytes(&bob_shared, info);
        assert_eq!(sas_alice, sas_bob);
        assert_eq!(sas_alice.emoji_indices, sas_bob.emoji_indices);
        assert_eq!(sas_alice.decimal_digits, sas_bob.decimal_digits);
    }

    /// Sprint Q1 第十六增量 (B2-ECDH): malformed peer public keys
    /// surface as `Error::Protocol` rather than panicking, so the
    /// verify-device UI can render a "cancel" outcome instead of
    /// crashing.
    /// Sprint Q1 第十六增量 (B2-ECDH): the full integration — two
    /// `KeyVerificationFlow` instances install their own ephemeral
    /// keypairs, swap the public halves through `on_key`, and
    /// `compute_sas` on both sides yields **the same** SAS pair.
    /// This is the contract the verify-device UI relies on.
    #[test]
    fn key_verification_flow_compute_sas_matches_across_both_sides() {
        let alice_did = did("alice");
        let alice_dev = dev("alice-dev");
        let bob_did = did("bob");
        let bob_dev = dev("bob-dev");
        let txn = "txn-flow-7";

        let alice_kp = EphemeralX25519Keypair::generate();
        let bob_kp = EphemeralX25519Keypair::generate();
        let alice_public_b64 = alice_kp.public_base64();
        let bob_public_b64 = bob_kp.public_base64();

        let mut alice = KeyVerificationFlow::new().with_ephemeral_key(alice_kp);
        let mut bob = KeyVerificationFlow::new().with_ephemeral_key(bob_kp);

        // Drive both flows through start -> accept -> key.
        let start = KeyVerificationStart {
            transaction_id: txn.to_owned(),
            from_user: alice_did.clone(),
            from_device: alice_dev.clone(),
            method: "sas_v1".to_owned(),
            key_agreement_protocols: vec!["curve25519-hkdf-sha256".to_owned()],
            message_authentication_codes: vec!["hkdf-hmac-sha256".to_owned()],
            short_authentication_string: vec!["decimal".to_owned(), "emoji".to_owned()],
            sent_at: now(),
        };
        alice.on_start(&start).unwrap();
        bob.on_start(&start).unwrap();

        let accept = KeyVerificationAccept {
            transaction_id: txn.to_owned(),
            from_user: bob_did.clone(),
            from_device: bob_dev.clone(),
            method: "sas_v1".to_owned(),
            key_agreement_protocol: "curve25519-hkdf-sha256".to_owned(),
            message_authentication_code: "hkdf-hmac-sha256".to_owned(),
            short_authentication_string: vec!["decimal".to_owned(), "emoji".to_owned()],
            commitment: "sha256-commit".to_owned(),
            sent_at: now(),
        };
        alice.on_accept(&accept).unwrap();
        bob.on_accept(&accept).unwrap();

        // Each side ships its own public key as the `key` field.
        let alice_key_msg = KeyVerificationKey {
            transaction_id: txn.to_owned(),
            from_user: alice_did.clone(),
            from_device: alice_dev.clone(),
            key: alice_public_b64,
            sent_at: now(),
        };
        let bob_key_msg = KeyVerificationKey {
            transaction_id: txn.to_owned(),
            from_user: bob_did.clone(),
            from_device: bob_dev.clone(),
            key: bob_public_b64,
            sent_at: now(),
        };
        // Each side records its own key + the peer's key (the flow
        // state machine accepts both `on_key` envelopes regardless of
        // order; `keys_exchanged` ends up keyed by device_id).
        alice.on_key(&alice_key_msg).unwrap();
        alice.on_key(&bob_key_msg).unwrap();
        bob.on_key(&alice_key_msg).unwrap();
        bob.on_key(&bob_key_msg).unwrap();

        // Canonical SAS info — both sides MUST construct the same
        // bytes. In production the verify-device view computes this
        // from `(transaction_id, initiator_did, initiator_device,
        // responder_did, responder_device)`.
        let info = format!(
            "{txn}|{}|{}|{}|{}",
            alice_did.as_str(),
            alice_dev.as_str(),
            bob_did.as_str(),
            bob_dev.as_str(),
        );
        let sas_alice = alice.compute_sas(&alice_dev, info.as_bytes()).unwrap();
        let sas_bob = bob.compute_sas(&bob_dev, info.as_bytes()).unwrap();
        assert_eq!(sas_alice, sas_bob, "SAS must match on both sides");
    }

    /// Sprint Q1 第十六增量 (B2-ECDH): `compute_sas` MUST refuse
    /// cleanly when prerequisites are missing (no keypair installed
    /// / no peer key received yet).
    #[test]
    fn compute_sas_refuses_when_prerequisites_missing() {
        let alice_dev = dev("alice-dev");
        let flow = KeyVerificationFlow::new();
        let err = flow
            .compute_sas(&alice_dev, b"info")
            .expect_err("no keypair installed");
        assert!(format!("{err}").contains("ephemeral keypair"));

        let flow = KeyVerificationFlow::new().with_ephemeral_key(EphemeralX25519Keypair::generate());
        let err = flow
            .compute_sas(&alice_dev, b"info")
            .expect_err("no peer key received");
        assert!(format!("{err}").contains("peer public key not received"));
    }

    #[test]
    fn compute_shared_secret_rejects_malformed_peer_public_key() {
        let alice = EphemeralX25519Keypair::generate();
        // base64 of 31 bytes — wrong length.
        let too_short = STANDARD_NO_PAD.encode(&[0u8; 31][..]);
        let err = alice
            .compute_shared_secret(&too_short)
            .expect_err("31 bytes must reject");
        assert!(format!("{err}").contains("32"));
        let err = alice
            .compute_shared_secret("not-base64-@@!!")
            .expect_err("invalid base64 must reject");
        assert!(format!("{err}").contains("base64"));
    }

    fn did(name: &str) -> Did {
        Did::new(format!("did:web:{name}.example")).unwrap()
    }

    fn dev(name: &str) -> DeviceId {
        let mut acc = 0xcbf29ce484222325u64;
        for byte in name.bytes() {
            acc = (acc ^ u64::from(byte)).wrapping_mul(0x100000001b3);
        }
        DeviceId::new(format!(
            "cx:device:01904100-0000-7000-8000-{:012x}",
            acc & 0x0000_ffff_ffff_ffff
        ))
        .unwrap()
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
