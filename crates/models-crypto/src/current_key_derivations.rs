//! Crypto-domain typed-current row-key derivations.
//!
//! The API is family-specific and typed. It intentionally does not expose a
//! generic component-array or JSON-value hashing surface.

use arkret_wire::{ActorId, Result};
use serde::Serialize;

use crate::BackupKind;

const KEY_BACKUP_ACTIVE_SERIES_DOMAIN: &str = "ak.current_key.key_backup_active_series.v1";

fn derive<T: Serialize + ?Sized>(domain: &str, components: &T) -> Result<String> {
    let mut preimage = domain.as_bytes().to_vec();
    preimage.push(b'\n');
    preimage.extend(arkret_canonical::canonical_json_bytes(components)?);
    Ok(arkret_canonical::sha256_base64url(preimage))
}

/// Derive the opaque current-row locator for one `(actor_id, backup_kind)` pair.
pub fn derive_key_backup_active_series_current_key(
    actor_id: &ActorId,
    backup_kind: BackupKind,
) -> Result<String> {
    derive(KEY_BACKUP_ACTIVE_SERIES_DOMAIN, &(actor_id, backup_kind))
}

#[cfg(test)]
mod tests {
    use arkret_wire::{AccountId, DidCoreId};
    use serde_json::json;

    use super::*;

    fn actor() -> ActorId {
        ActorId::account(AccountId::new(
            DidCoreId::new("ak:did_core:webvh:z6mkfixturemember").unwrap(),
            DidCoreId::new("ak:did_core:webvh:z6mkfixturestation").unwrap(),
        ))
    }

    #[test]
    fn formal_kat_matches() {
        assert_eq!(
            derive_key_backup_active_series_current_key(&actor(), BackupKind::SecretStorage)
                .unwrap(),
            "wfWg_46S_n3Iuu_w8t9uuQ_yiNYjEqWOSjykPH-11Sc"
        );
    }

    #[test]
    fn component_order_and_family_domain_diverge() {
        let actor_value = serde_json::to_value(actor()).unwrap();
        assert_eq!(
            derive(
                KEY_BACKUP_ACTIVE_SERIES_DOMAIN,
                &json!(["secret_storage", actor_value])
            )
            .unwrap(),
            "sefgoFcbcI9ljlq2RkSZVVOKZxRIfQkew_bP-t7qBac"
        );
        assert_eq!(
            derive(
                "ak.current_key.wrong_family.v1",
                &json!([actor_value, "secret_storage"])
            )
            .unwrap(),
            "VMGzO5QZxvBod1MLeI0OK5memSK7smP7FXWqdNfaz5U"
        );
    }
}
