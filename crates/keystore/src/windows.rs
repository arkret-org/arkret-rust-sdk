//! Durable Windows user-profile-protected encrypted key storage.
//!
//! DPAPI protects the vault master key for the current user. The existing
//! encrypted-file backend owns authenticated secret CRUD and atomic updates.
//! Neither master custody nor secrets depend on Credential Manager blob or
//! credential quota limits. There is no plaintext or ephemeral fallback.

use std::io::{Read, Write};
use std::path::PathBuf;

use windows::Win32::Foundation::{HLOCAL, LocalFree};
use windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use zeroize::{Zeroize, Zeroizing};

use crate::contract::Result;
use crate::{EncryptedFileKeyStore, KeyBytes, KeyStore, KeyStoreError};

fn backend(error: impl std::fmt::Display) -> KeyStoreError {
    KeyStoreError::backend(error.to_string())
}

/// Durable Windows key storage with a DPAPI-custodied master key.
pub struct WindowsProtectedKeyStore {
    vault: EncryptedFileKeyStore,
}

impl WindowsProtectedKeyStore {
    pub fn new(application_id: &str) -> std::result::Result<Self, KeyStoreError> {
        use sha2::{Digest, Sha256};
        let root = std::env::var_os("LOCALAPPDATA")
            .filter(|value| !value.is_empty())
            .ok_or_else(|| backend("LOCALAPPDATA is unavailable"))?;
        let namespace = Sha256::digest(application_id.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Self::open(
            application_id,
            PathBuf::from(root)
                .join("Arkret")
                .join("keystore")
                .join(namespace)
                .join("secrets.v1"),
        )
    }

    fn open(application_id: &str, path: PathBuf) -> std::result::Result<Self, KeyStoreError> {
        if application_id.is_empty() {
            return Err(KeyStoreError::invalid_id(
                "application_id must be non-empty",
            ));
        }
        let parent = path
            .parent()
            .ok_or_else(|| backend("vault path has no parent"))?;
        std::fs::create_dir_all(parent).map_err(backend)?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(parent.join("master.lock"))
            .map_err(backend)?;
        lock.lock().map_err(backend)?;
        let master_path = parent.join("master.dpapi");
        // The stable lock serializes first-open across processes. Existing
        // ciphertext without its master custody must never be overwritten.
        let master = match std::fs::File::open(&master_path) {
            Ok(file) => {
                let mut protected = Vec::new();
                file.take(16_385)
                    .read_to_end(&mut protected)
                    .map_err(backend)?;
                if protected.len() > 16_384 {
                    return Err(backend("Windows vault master file exceeds the size limit"));
                }
                protect(&protected, application_id.as_bytes(), false)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !path.exists() => {
                let mut master = Zeroizing::new(vec![0; 32]);
                getrandom::fill(master.as_mut_slice()).map_err(backend)?;
                let protected = protect(master.as_slice(), application_id.as_bytes(), true)?;
                let mut file = atomic_write_file::OpenOptions::new()
                    .open(&master_path)
                    .map_err(backend)?;
                file.write_all(protected.as_slice()).map_err(backend)?;
                file.commit().map_err(backend)?;
                master
            }
            Err(error) => return Err(backend(error)),
        };
        let master: [u8; 32] = master
            .as_slice()
            .try_into()
            .map_err(|_| backend("Windows vault master key has invalid length"))?;
        let master = Zeroizing::new(master);
        let vault = EncryptedFileKeyStore::new(path, application_id, *master)?;
        Ok(Self { vault })
    }
}

impl KeyStore for WindowsProtectedKeyStore {
    fn load(&self, id: &str) -> Result<KeyBytes> {
        self.vault.load(id)
    }
    fn store(&self, id: &str, key: &[u8]) -> Result<()> {
        self.vault.store(id, key)
    }
    fn list(&self) -> Result<Vec<String>> {
        self.vault.list()
    }
    fn delete(&self, id: &str) -> Result<()> {
        self.vault.delete(id)
    }
}

struct ProtectedOutput(CRYPT_INTEGER_BLOB);

impl Drop for ProtectedOutput {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            // SAFETY: DPAPI allocated this output; it remains valid until
            // LocalFree. Clear decrypted key material before releasing it.
            unsafe {
                std::slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize).zeroize();
                LocalFree(Some(HLOCAL(self.0.pbData.cast())));
            }
        }
    }
}

fn protect(bytes: &[u8], namespace: &[u8], encrypt: bool) -> Result<Zeroizing<Vec<u8>>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(bytes.len()).map_err(backend)?,
        pbData: bytes.as_ptr().cast_mut(),
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(namespace.len()).map_err(backend)?,
        pbData: namespace.as_ptr().cast_mut(),
    };
    let mut output = ProtectedOutput(CRYPT_INTEGER_BLOB::default());
    // SAFETY: both input blobs borrow live immutable slices. DPAPI only
    // reads them and writes a separately allocated output owned by the guard.
    // The default protection scope is CurrentUser, never LOCAL_MACHINE.
    unsafe {
        if encrypt {
            CryptProtectData(
                &input,
                windows::core::PCWSTR::null(),
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        } else {
            CryptUnprotectData(
                &input,
                None,
                Some(&entropy),
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output.0,
            )
        }
    }
    .map_err(|error| backend(format!("Windows vault DPAPI: {error}")))?;
    if output.0.pbData.is_null() {
        return Err(backend("Windows vault DPAPI returned no output"));
    }
    // SAFETY: a successful DPAPI call owns this buffer until the guard drops.
    let bytes = unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize) };
    Ok(Zeroizing::new(bytes.to_vec()))
}

#[cfg(test)]
mod tests {
    //! Live CurrentUser DPAPI vault round-trip tests. They write under
    //! per-test unique application ids so concurrent runs don't collide.

    use super::*;

    fn unique_app_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("test.{nanos:x}")
    }

    struct TestVault {
        store: WindowsProtectedKeyStore,
        app: String,
        root: PathBuf,
    }

    impl TestVault {
        fn new(app: String) -> Self {
            let root = std::env::temp_dir().join(format!("arkret-windows-vault-{app}"));
            let store = WindowsProtectedKeyStore::open(&app, root.join("secrets.v1")).unwrap();
            Self { store, app, root }
        }
    }

    impl std::ops::Deref for TestVault {
        type Target = WindowsProtectedKeyStore;
        fn deref(&self) -> &Self::Target {
            &self.store
        }
    }

    impl Drop for TestVault {
        fn drop(&mut self) {
            assert_eq!(self.root.parent(), Some(std::env::temp_dir().as_path()));
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn large_secrets_reopen_and_corruption_fails_closed() {
        let store = TestVault::new(unique_app_id());
        let secret = vec![0x5a; 8192];
        store.store("checkpoint", &secret).unwrap();
        let reopened =
            WindowsProtectedKeyStore::open(&store.app, store.root.join("secrets.v1")).unwrap();
        assert_eq!(reopened.load("checkpoint").unwrap().as_slice(), secret);
        assert_eq!(reopened.list().unwrap(), vec!["checkpoint"]);
        std::fs::write(store.root.join("secrets.v1"), b"corrupt").unwrap();
        assert!(reopened.load("checkpoint").is_err());
        assert!(reopened.store("checkpoint", b"replacement").is_err());
    }

    #[test]
    fn lost_master_custody_cannot_replace_an_existing_vault() {
        let store = TestVault::new(unique_app_id());
        store.store("secret", b"original").unwrap();
        std::fs::remove_file(store.root.join("master.dpapi")).unwrap();
        assert!(WindowsProtectedKeyStore::open(&store.app, store.root.join("secrets.v1")).is_err());
    }

    #[test]
    fn round_trip_store_load_delete() {
        let store = TestVault::new(unique_app_id());
        let id = "arkret:signer:alice:k1";
        store.store(id, b"win-secret-1").unwrap();
        assert_eq!(store.load(id).unwrap().as_slice(), b"win-secret-1");
        store.delete(id).unwrap();
        let err = store.load(id).unwrap_err();
        assert!(err.is_not_found());
    }

    #[test]
    fn store_overwrites_existing_id() {
        let store = TestVault::new(unique_app_id());
        let id = "arkret:signer:bob:k1";
        store.store(id, b"first").unwrap();
        store.store(id, b"second").unwrap();
        assert_eq!(store.load(id).unwrap().as_slice(), b"second");
        store.delete(id).unwrap();
    }

    #[test]
    fn delete_missing_id_is_idempotent() {
        let store = TestVault::new(unique_app_id());
        store.delete("never-stored").unwrap();
    }

    #[test]
    fn rejects_empty_id() {
        let store = TestVault::new(unique_app_id());
        assert!(store.store("", b"x").is_err());
        assert!(store.load("").is_err());
        assert!(store.delete("").is_err());
    }

    #[test]
    fn list_returns_only_keys_in_service_namespace() {
        let app_a = unique_app_id();
        let app_b = unique_app_id();
        let store_a = TestVault::new(app_a);
        let store_b = TestVault::new(app_b);
        store_a.store("k-a-1", b"a1").unwrap();
        store_a.store("k-a-2", b"a2").unwrap();
        store_b.store("k-b-1", b"b1").unwrap();

        let listed_a = store_a.list().unwrap();
        assert!(
            listed_a.contains(&"k-a-1".to_owned()),
            "listed_a={listed_a:?}"
        );
        assert!(
            listed_a.contains(&"k-a-2".to_owned()),
            "listed_a={listed_a:?}"
        );
        assert!(
            !listed_a.contains(&"k-b-1".to_owned()),
            "listed_a={listed_a:?}"
        );

        store_a.delete("k-a-1").unwrap();
        store_a.delete("k-a-2").unwrap();
        store_b.delete("k-b-1").unwrap();
    }
}
