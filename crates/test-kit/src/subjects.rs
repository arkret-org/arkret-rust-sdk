//! The standard test subjects.
//!
//! Before this module the same two actors were spelled at least eight
//! different ways across the workspace (`did:web:alice.example`,
//! `did:webvh:z6mkfixture:alice.example`, `ak:did_core:web:alice`,
//! `did:webvh:QmTest:alice.example`, ...). Nothing enforced a relationship
//! between the spellings, so a fixture moved between repositories kept
//! compiling while addressing a different principal.
//!
//! Everything here is a plain constant plus a typed accessor. The accessors
//! panic on an invalid spelling on purpose: an invalid standard subject is a
//! defect in this crate, never a runtime condition a caller can handle.

use arkret_wire::{AccountId, DeviceId, Did, DidCoreId, DidUrl, RealmId, StrandId};

/// Alice's DID: the first principal of any scenario.
pub const ALICE_DID: &str = "did:web:alice.example";
/// Alice's stable core identifier.
pub const ALICE_CORE_ID: &str = "ak:did_core:web:alice.example";
/// Alice's device.
pub const ALICE_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-000000000001";

/// Bob's DID: the second principal, used for cross-actor cases.
pub const BOB_DID: &str = "did:web:bob.example";
/// Bob's stable core identifier.
pub const BOB_CORE_ID: &str = "ak:did_core:web:bob.example";
/// Bob's device.
pub const BOB_DEVICE_ID: &str = "ak:device:01904100-0000-7000-8000-000000000002";

/// The Station both principals are homed on.
pub const STATION_DID: &str = "did:web:station.example";
/// The Station's stable core identifier.
pub const STATION_CORE_ID: &str = "ak:did_core:web:station.example";

/// The standard Realm.
pub const REALM_ID: &str = "ak:realm:AVYxXzYx_KzaGx7X62doksaQR0ISkneyOwwF1k6ExHKy";
/// The standard Strand inside [`REALM_ID`].
pub const STRAND_ID: &str = "ak:strand:AcweNVvZUYNuOdCMey9HT7PQHKPbHPJwOFTgn_cx7yjo";
/// The only Strand track a v1 Message may sit on.
pub const DISCUSSION_TRACK: &str = "discussion";

/// Alice as a DID.
#[must_use]
pub fn alice_did() -> Did {
    Did::new(ALICE_DID.to_owned()).expect("standard subject alice has a valid DID")
}

/// Alice as a stable core id.
#[must_use]
pub fn alice_core_id() -> DidCoreId {
    DidCoreId::new(ALICE_CORE_ID).expect("standard subject alice has a valid core id")
}

/// Alice's account on the standard Station.
#[must_use]
pub fn alice_account_id() -> AccountId {
    AccountId::new(alice_core_id(), station_core_id())
}

/// Alice's device.
#[must_use]
pub fn alice_device_id() -> DeviceId {
    DeviceId::new(ALICE_DEVICE_ID).expect("standard subject alice has a valid device id")
}

/// The verification method Alice's device key is published under.
#[must_use]
pub fn alice_verification_method() -> DidUrl {
    verification_method(ALICE_DID, ALICE_DEVICE_ID)
}

/// Bob as a DID.
#[must_use]
pub fn bob_did() -> Did {
    Did::new(BOB_DID.to_owned()).expect("standard subject bob has a valid DID")
}

/// Bob as a stable core id.
#[must_use]
pub fn bob_core_id() -> DidCoreId {
    DidCoreId::new(BOB_CORE_ID).expect("standard subject bob has a valid core id")
}

/// Bob's account on the standard Station.
#[must_use]
pub fn bob_account_id() -> AccountId {
    AccountId::new(bob_core_id(), station_core_id())
}

/// Bob's device.
#[must_use]
pub fn bob_device_id() -> DeviceId {
    DeviceId::new(BOB_DEVICE_ID).expect("standard subject bob has a valid device id")
}

/// The verification method Bob's device key is published under.
#[must_use]
pub fn bob_verification_method() -> DidUrl {
    verification_method(BOB_DID, BOB_DEVICE_ID)
}

/// The standard Station as a DID.
#[must_use]
pub fn station_did() -> Did {
    Did::new(STATION_DID.to_owned()).expect("the standard station has a valid DID")
}

/// The standard Station as a stable core id.
#[must_use]
pub fn station_core_id() -> DidCoreId {
    DidCoreId::new(STATION_CORE_ID).expect("the standard station has a valid core id")
}

/// The standard Realm.
#[must_use]
pub fn realm_id() -> RealmId {
    RealmId::new(REALM_ID.to_owned()).expect("the standard realm id is valid")
}

/// The standard Strand.
#[must_use]
pub fn strand_id() -> StrandId {
    StrandId::new(STRAND_ID.to_owned()).expect("the standard strand id is valid")
}

/// Compose the DID URL a device key is published under.
///
/// The fragment is the full `ak:device:` identifier, which is the form every
/// implementation in the workspace already converged on; it is spelled once
/// here so a fixture cannot address a device key through a second convention.
#[must_use]
pub fn verification_method(did: &str, device_id: &str) -> DidUrl {
    let device_id = if device_id.starts_with("ak:device:") {
        device_id.to_owned()
    } else {
        format!("ak:device:{device_id}")
    };
    DidUrl::new(format!("{did}#{device_id}"))
        .expect("a standard subject verification method is a DID URL")
}
