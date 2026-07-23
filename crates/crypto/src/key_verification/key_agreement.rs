use arkret_canonical::base64url::{base64url_decode, base64url_encode};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

// ════════════════════════════════════════════════════════════════════
// X25519 key agreement.
//
// The key-verification key step carries each party's ephemeral public key as
// a base64 string (the `key` field). Two devices doing the SAS
// exchange MUST end up with the same shared secret bytes — that's the
// whole point of the protocol — and that secret is the input to
// `derive_sas_bytes` so the resulting emoji + decimal SAS row is the
// same on both sides.
//
// Spec: `crypto-media/device-lifecycle.md` §4.5; we use the
// `curve25519-hkdf-sha256` agreement protocol the existing
// accept message advertises. The ephemeral
// keypair is generated per strand via `EphemeralX25519Keypair::generate`
// and consumed by `compute_shared_secret` once the peer's public key
// arrives.
// ════════════════════════════════════════════════════════════════════

/// Ephemeral X25519 keypair used for a single key-verification strand.
/// The private side never leaves the in-memory structure; the public
/// side is base64-encoded and shipped as the `KeyVerificationKey.key`
/// payload to the peer.
#[derive(Clone)]
pub struct EphemeralX25519Keypair {
    secret: StaticSecret,
    public: X25519PublicKey,
}

impl EphemeralX25519Keypair {
    /// Generate a fresh keypair from OS randomness via `getrandom`. The
    /// keypair is scoped to a single SAS verification round and MUST NOT
    /// be reused across strands.
    ///
    /// Returns `Err(Error::Crypto(..))` when the OS RNG is unavailable
    /// (early boot, restricted sandbox, seccomp-blocked `getrandom`),
    /// matching the fallible error-propagation used by every other RNG
    /// site in the SDK rather than panicking.
    pub fn generate() -> Result<Self> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|error| Error::Crypto(error.to_string()))?;
        let secret = StaticSecret::from(seed);
        seed.zeroize();
        let public = X25519PublicKey::from(&secret);
        Ok(Self { secret, public })
    }

    /// Base64 (no-pad) encoding of the public key — the on-the-wire
    /// form for `KeyVerificationKey.key`.
    pub fn public_base64(&self) -> String {
        base64url_encode(self.public.as_bytes())
    }

    /// Compute the X25519 shared secret between this side's private
    /// key and the peer's base64-encoded public key. Returns 32 bytes
    /// suitable as the `shared_secret` argument to
    /// [`derive_sas_bytes`].
    pub fn compute_shared_secret(&self, peer_public_b64: &str) -> Result<Zeroizing<[u8; 32]>> {
        let peer_bytes = base64url_decode(peer_public_b64.as_bytes()).map_err(|err| {
            Error::Protocol(format!("peer x25519 public key base64url decode: {err}"))
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
        let shared = Zeroizing::new(*shared.as_bytes());
        if shared.iter().all(|byte| *byte == 0) {
            return Err(Error::Protocol(
                "x25519 shared secret must not be all zero".to_owned(),
            ));
        }
        Ok(shared)
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
// Short Authentication String derivation.
//
// Implements the SAS extraction step of `crypto-media/device-lifecycle.md`
// §4.5 — once the two parties have exchanged ephemeral public keys and
// computed a shared secret out-of-band, the SAS bytes are derived
// deterministically from `(shared_secret, info)` via HKDF-SHA256
// (RFC 5869), with `info` carrying the transaction id + per-party DIDs /
// device ids so the result is bound to the strand context.
//
// Two outputs are supported (matches the Matrix SAS modes both clients
// have to support):
//   * **emoji** — 7 indices each into [`SAS_EMOJI_TABLE`] (64-entry table from the MSC2241
//     dictionary).
//   * **decimal** — 3 digits in `[1000, 9999]`, one per side of the "compare these three numbers"
//     UX.
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
    ("\u{1F436}", "Dog"),
    ("\u{1F431}", "Cat"),
    ("\u{1F981}", "Lion"),
    ("\u{1F40E}", "Horse"),
    ("\u{1F984}", "Unicorn"),
    ("\u{1F437}", "Pig"),
    ("\u{1F418}", "Elephant"),
    ("\u{1F430}", "Rabbit"),
    ("\u{1F43C}", "Panda"),
    ("\u{1F413}", "Rooster"),
    ("\u{1F427}", "Penguin"),
    ("\u{1F422}", "Turtle"),
    ("\u{1F41F}", "Fish"),
    ("\u{1F419}", "Octopus"),
    ("\u{1F98B}", "Butterfly"),
    ("\u{1F337}", "Strander"),
    ("\u{1F333}", "Tree"),
    ("\u{1F335}", "Cactus"),
    ("\u{1F344}", "Mushroom"),
    ("\u{1F30F}", "Globe"),
    ("\u{1F319}", "Moon"),
    ("\u{2601}", "Cloud"),
    ("\u{1F525}", "Fire"),
    ("\u{1F34C}", "Banana"),
    ("\u{1F34E}", "Apple"),
    ("\u{1F353}", "Strawberry"),
    ("\u{1F33D}", "Corn"),
    ("\u{1F355}", "Pizza"),
    ("\u{1F382}", "Cake"),
    ("\u{1F36D}", "Lollipop"),
    ("\u{1F37C}", "Bottle"),
    ("\u{2693}", "Seal"),
    ("\u{1F3A7}", "Headphones"),
    ("\u{1F4D6}", "Book"),
    ("\u{1F4BB}", "Computer"),
    ("\u{1F4F7}", "Camera"),
    ("\u{1F4A1}", "Light Bulb"),
    ("\u{1F381}", "Gift"),
    ("\u{231B}", "Hourglass"),
    ("\u{1F529}", "Wrench"),
    ("\u{1F389}", "Party"),
    ("\u{1F3A8}", "Art"),
    ("\u{1F3B5}", "Music"),
    ("\u{1F3B7}", "Saxophone"),
    ("\u{1F4DA}", "Books"),
    ("\u{1F4E6}", "Box"),
    ("\u{1F4E7}", "Envelope"),
    ("\u{1F50D}", "Magnifier"),
    ("\u{1F511}", "Key"),
    ("\u{1F512}", "Lock"),
    ("\u{1F4B0}", "Money"),
    ("\u{2615}", "Coffee"),
    ("\u{1F3E0}", "House"),
    ("\u{1F4DD}", "Pen"),
    ("\u{1F4CB}", "Clipboard"),
    ("\u{2702}", "Scissors"),
    ("\u{1F465}", "People"),
    ("\u{1F4AC}", "Speech"),
    ("\u{1F44D}", "Thumbs Up"),
    ("\u{270C}", "Peace"),
    ("\u{1F44A}", "Punch"),
    ("\u{1F596}", "Spock"),
    ("\u{1F4AF}", "Hundred"),
    ("\u{2728}", "Sparkles"),
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
/// HKDF-SHA256 uses an empty salt and expands 11 output bytes. The first
/// 6 OKM bytes feed the
/// emoji indices (7 × 6 bits); the next 5 feed the three decimal
/// digits (3 × 13 bits each, mapped into `[1000, 9999]`).
pub fn derive_sas_bytes(shared_secret: &[u8], info: &[u8]) -> ShortAuthenticationString {
    let mut okm = Zeroizing::new([0u8; SAS_OUTPUT_LEN]);
    Hkdf::<Sha256>::new(None, shared_secret)
        .expand(info, &mut okm[..])
        .expect("11-byte HKDF-SHA256 output is always valid");

    // Emoji indices — 7 × 6-bit values packed big-endian into bytes
    // [0..6) (48 bits = 8 × 6 bits, we take the first seven).
    let mut emoji_indices = [0u8; 7];
    let mut bit_cursor = 0usize;
    for emoji_index in &mut emoji_indices {
        let mut idx: u8 = 0;
        for _ in 0..6 {
            let byte = okm[bit_cursor / 8];
            let bit_in_byte = 7 - (bit_cursor % 8);
            idx = (idx << 1) | ((byte >> bit_in_byte) & 1);
            bit_cursor += 1;
        }
        *emoji_index = idx;
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
    let d3 = (packed & 0x1FFF) as u16; // bits 12..0
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

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts keys of any length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

pub fn hkdf_expand_sha256(prk: &[u8; 32], info: &[u8], output: &mut [u8]) {
    Hkdf::<Sha256>::from_prk(prk)
        .expect("SHA-256 PRK has the required digest length")
        .expand(info, output)
        .expect("requested HKDF-SHA256 output is within the RFC 5869 limit");
}
