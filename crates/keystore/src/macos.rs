//! macOS Keychain Services backend for [`KeyStore`].
//!
//! Wires generic-password keychain items via the `security-framework`
//! crate. Each Arkret-using app supplies an `application_id` at
//! construction time; items are stored under the service name
//! `"arkret.<application_id>"` so independent apps don't trample each
//! other on a shared host.
//!
//! Implementation notes:
//! - Items are written as **generic passwords** (`SecGenericPasswordItem`) keyed on `(service,
//!   account)` where `service` is the namespaced service-name and `account` is the caller-supplied
//!   key id.
//! - `list()` enumerates all generic-password items whose service field equals our service name.
//! - `delete()` is idempotent — a "not found" error from the underlying `delete_generic_password`
//!   is swallowed.

use security_framework::base::Error as SfError;
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};

use crate::contract::{KeyBytes, Result, service_name, validate_id};
use crate::{KeyStore, KeyStoreError};

/// macOS Keychain-backed [`KeyStore`].
///
/// Construct with [`MacOsKeychainKeyStore::new`] supplying the host
/// application id (a stable reverse-DNS string, e.g.
/// `"chat.acroidea.inkson"`). All keychain items written through this
/// keystore live under service `"arkret.<application_id>"`.
pub struct MacOsKeychainKeyStore {
    service: String,
}

impl MacOsKeychainKeyStore {
    /// Construct the keystore for the given application id.
    ///
    /// On macOS with the `keystore-macos` feature enabled this just
    /// records the namespaced service-name; the underlying Keychain
    /// session is acquired lazily on each call.
    pub fn new(application_id: &str) -> std::result::Result<Self, KeyStoreError> {
        if application_id.is_empty() {
            return Err(KeyStoreError::invalid_id(
                "application_id must be non-empty",
            ));
        }
        Ok(Self {
            service: service_name(application_id),
        })
    }

    /// Service-name prefix used by this keystore (testing hook).
    #[doc(hidden)]
    pub fn service_name(&self) -> &str {
        &self.service
    }

    fn with_mutation_lock<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        let lock = mutation_lock(&self.service)?;
        lock.lock().map_err(io_error)?;
        let result = operation();
        let unlocked = lock.unlock().map_err(io_error);
        match (result, unlocked) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        }
    }

    fn map_sf<T>(res: std::result::Result<T, SfError>) -> std::result::Result<T, KeyStoreError> {
        res.map_err(|err| KeyStoreError::backend(format!("keychain: {err}")))
    }
}

impl KeyStore for MacOsKeychainKeyStore {
    fn load(&self, id: &str) -> Result<KeyBytes> {
        validate_id(id)?;
        match get_generic_password(&self.service, id) {
            Ok(bytes) => Ok(KeyBytes::new(bytes)),
            Err(err) if is_not_found(&err) => Err(KeyStoreError::not_found(id)),
            Err(err) => Err(KeyStoreError::backend(format!("keychain: {err}"))),
        }
    }

    fn store(&self, id: &str, key: &[u8]) -> Result<()> {
        validate_id(id)?;
        self.with_mutation_lock(|| Self::map_sf(set_generic_password(&self.service, id, key)))
    }

    fn create_if_absent(&self, id: &str, key: &[u8]) -> Result<KeyBytes> {
        use security_framework::os::macos::keychain::SecKeychain;

        validate_id(id)?;
        self.with_mutation_lock(|| {
            let keychain = Self::map_sf(SecKeychain::default())?;
            match keychain.add_generic_password(&self.service, id, key) {
                Ok(()) => self.load(id),
                // errSecDuplicateItem: another creator won; never update that item.
                Err(error) if error.code() == -25299 => self.load(id),
                Err(error) => Self::map_sf(Err(error)),
            }
        })
    }

    fn compare_exchange(
        &self,
        id: &str,
        expected: Option<&[u8]>,
        replacement: &[u8],
    ) -> Result<bool> {
        validate_id(id)?;
        self.with_mutation_lock(|| {
            let existing = match self.load(id) {
                Ok(bytes) => Some(bytes),
                Err(error) if error.is_not_found() => None,
                Err(error) => return Err(error),
            };
            if existing.as_ref().map(KeyBytes::as_slice) != expected {
                return Ok(false);
            }
            Self::map_sf(set_generic_password(&self.service, id, replacement))?;
            Ok(true)
        })
    }

    fn list(&self) -> Result<Vec<String>> {
        // Use SecItemCopyMatching via security-framework's item module.
        // We request `load_attributes(true)` so each result is a `Dict`
        // containing the `acct` (account / our key id) attribute.
        use security_framework::item::{ItemClass, ItemSearchOptions};

        let mut search = ItemSearchOptions::new();
        search.class(ItemClass::generic_password());
        search.service(&self.service);
        // `i64::MAX` would overflow the underlying CFNumber; use a high
        // but bounded ceiling. Real keystores never approach this.
        search.limit(i64::from(i32::MAX));
        search.load_attributes(true);

        let results = match search.search() {
            Ok(results) => results,
            Err(err) if is_not_found(&err) => return Ok(Vec::new()),
            Err(err) => {
                return Err(KeyStoreError::backend(format!("keychain enum: {err}")));
            }
        };

        let mut ids = Vec::new();
        for result in results {
            // `simplify_dict()` returns the loaded attribute dict as a
            // `HashMap<String, String>`. The "acct" attribute holds our
            // caller-supplied key id.
            if let Some(attrs) = result.simplify_dict()
                && let Some(account) = attrs.get("acct")
            {
                ids.push(account.clone());
            }
        }
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    fn delete(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        self.with_mutation_lock(|| match delete_generic_password(&self.service, id) {
            Ok(()) => Ok(()),
            Err(err) if is_not_found(&err) => Ok(()), // idempotent
            Err(err) => Err(KeyStoreError::backend(format!("keychain delete: {err}"))),
        })
    }
}

fn io_error(error: std::io::Error) -> KeyStoreError {
    KeyStoreError::backend(format!("keychain mutation lock: {error}"))
}

// Resolve the system account's actual home, not caller-controlled HOME/TMPDIR.
// The private directory is persistent: system temporary-file cleanup cannot
// replace a live lock inode. Every SDK mutation in a service uses this lock.
fn mutation_lock(service: &str) -> Result<std::fs::File> {
    use std::os::unix::ffi::OsStringExt;
    // SAFETY: getuid has no inputs and no ownership/lifetime requirements.
    let uid = unsafe { libc::getuid() };
    let mut size = 16 * 1024;
    let directory = loop {
        let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut buffer = vec![0_u8; size];
        let mut result = std::ptr::null_mut();
        // SAFETY: record and buffer are writable for their declared sizes.
        // A successful non-null result points into these live allocations.
        let code = unsafe {
            libc::getpwuid_r(
                uid,
                record.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if code == libc::ERANGE && size < 1024 * 1024 {
            size *= 2;
            continue;
        }
        if code != 0 || result.is_null() {
            return Err(KeyStoreError::backend("system user home is unavailable"));
        }
        // SAFETY: getpwuid_r succeeded with result pointing to record. pw_dir
        // is a NUL-terminated string in buffer and is copied before it drops.
        let bytes = unsafe {
            if (*result).pw_dir.is_null() {
                return Err(KeyStoreError::backend("system user home is absent"));
            }
            std::ffi::CStr::from_ptr((*result).pw_dir)
                .to_bytes()
                .to_vec()
        };
        break std::path::PathBuf::from(std::ffi::OsString::from_vec(bytes));
    };
    open_mutation_lock(&directory, uid, service)
}

fn open_mutation_lock(base: &std::path::Path, uid: u32, service: &str) -> Result<std::fs::File> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    let valid_directory = |path: &std::path::Path| -> Result<()> {
        let metadata = std::fs::symlink_metadata(path).map_err(io_error)?;
        if !path.is_absolute()
            || !metadata.is_dir()
            || metadata.uid() != uid
            || metadata.mode() & 0o077 != 0
        {
            return Err(KeyStoreError::backend(
                "keychain lock directory is not private and owned by this user",
            ));
        }
        Ok(())
    };
    let home = std::fs::symlink_metadata(base).map_err(io_error)?;
    if !base.is_absolute() || !home.is_dir() || home.uid() != uid || home.mode() & 0o022 != 0 {
        return Err(KeyStoreError::backend(
            "system user home is not owned and protected against other writers",
        ));
    }
    let directory = base.join(".arkret-keystore-locks");
    match std::fs::DirBuilder::new().mode(0o700).create(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(io_error(error)),
    }
    valid_directory(&directory)?;
    let name: String = Sha256::digest(service.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory.join(name))
        .map_err(io_error)?;
    let metadata = lock.metadata().map_err(io_error)?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(KeyStoreError::backend(
            "keychain lock file is not private and owned by this user",
        ));
    }
    Ok(lock)
}

/// Map Keychain Services' "errSecItemNotFound" to our `NotFound` shape.
fn is_not_found(err: &SfError) -> bool {
    // errSecItemNotFound = -25300
    err.code() == -25300
}

#[cfg(test)]
mod tests {
    //! These tests are skipped automatically off-macOS via the parent
    //! module's `cfg(target_os = "macos", feature = "keystore-macos")`
    //! gate. On a macOS CI runner they exercise live Keychain Services
    //! calls; on a fresh user account that's harmless because each test
    //! cleans up its own items.

    use super::*;

    fn unique_app_id() -> String {
        format!("arkret.test.{}", uuid_like())
    }

    fn uuid_like() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{nanos:x}")
    }

    #[test]
    fn round_trip_store_load_delete() {
        let store = MacOsKeychainKeyStore::new(&unique_app_id()).unwrap();
        let id = "arkret:signer:alice:k1";
        store.store(id, b"keychain-secret-1").unwrap();
        assert_eq!(store.load(id).unwrap().as_slice(), b"keychain-secret-1");
        store.delete(id).unwrap();
        let err = store.load(id).unwrap_err();
        assert!(err.is_not_found());
    }

    #[test]
    fn store_overwrites_existing_id() {
        let store = MacOsKeychainKeyStore::new(&unique_app_id()).unwrap();
        let id = "arkret:signer:bob:k1";
        store.store(id, b"first").unwrap();
        store.store(id, b"second").unwrap();
        assert_eq!(store.load(id).unwrap().as_slice(), b"second");
        store.delete(id).unwrap();
    }

    #[test]
    fn delete_missing_id_is_idempotent() {
        let store = MacOsKeychainKeyStore::new(&unique_app_id()).unwrap();
        store.delete("never-stored").unwrap();
    }

    #[test]
    fn rejects_empty_id() {
        let store = MacOsKeychainKeyStore::new(&unique_app_id()).unwrap();
        assert!(store.store("", b"x").is_err());
        assert!(store.load("").is_err());
        assert!(store.delete("").is_err());
    }

    #[test]
    fn list_returns_only_keys_in_service_namespace() {
        let app_a = unique_app_id();
        let app_b = unique_app_id();
        let store_a = MacOsKeychainKeyStore::new(&app_a).unwrap();
        let store_b = MacOsKeychainKeyStore::new(&app_b).unwrap();
        store_a.store("k-a-1", b"a1").unwrap();
        store_a.store("k-a-2", b"a2").unwrap();
        store_b.store("k-b-1", b"b1").unwrap();

        let listed_a = store_a.list().unwrap();
        assert!(listed_a.contains(&"k-a-1".to_owned()));
        assert!(listed_a.contains(&"k-a-2".to_owned()));
        assert!(!listed_a.contains(&"k-b-1".to_owned()));

        store_a.delete("k-a-1").unwrap();
        store_a.delete("k-a-2").unwrap();
        store_b.delete("k-b-1").unwrap();
    }
}

#[cfg(test)]
mod mutation_lock_tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    fn private_scratch() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "arkret-keychain-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        path
    }

    #[test]
    fn rejects_relative_wrong_owner_permissive_and_symlink_lock_paths() {
        // SAFETY: getuid has no ownership/lifetime requirements.
        let uid = unsafe { libc::getuid() };
        assert!(open_mutation_lock(std::path::Path::new("relative"), uid, "one").is_err());
        let base = private_scratch();
        assert!(open_mutation_lock(&base, uid.wrapping_add(1), "one").is_err());
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(open_mutation_lock(&base, uid, "one").is_err());
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let redirected = base.join("redirected");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&redirected)
            .unwrap();
        std::os::unix::fs::symlink(&redirected, base.join(".arkret-keystore-locks")).unwrap();
        assert!(open_mutation_lock(&base, uid, "one").is_err());
        std::fs::remove_file(base.join(".arkret-keystore-locks")).unwrap();
        let lock = open_mutation_lock(&base, uid, "one").unwrap();
        drop(lock);
        use sha2::{Digest, Sha256};
        let name: String = Sha256::digest(b"one")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let path = base.join(".arkret-keystore-locks").join(name);
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(base.join("missing-target"), &path).unwrap();
        assert!(open_mutation_lock(&base, uid, "one").is_err());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    #[ignore = "spawned only by mutation_lock_is_released_on_process_crash"]
    fn mutation_lock_crash_worker() {
        use std::io::Write;
        let app = std::env::var("ARKRET_MACOS_LOCK_APP").unwrap();
        let store = MacOsKeychainKeyStore::new(&app).unwrap();
        store
            .with_mutation_lock(|| {
                println!("READY");
                std::io::stdout().flush().unwrap();
                let mut signal = String::new();
                std::io::stdin().read_line(&mut signal).unwrap();
                Err::<(), _>(KeyStoreError::backend("lock worker must be killed"))
            })
            .unwrap();
    }

    #[test]
    fn mutation_lock_is_released_on_process_crash() {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        use std::time::Duration;
        let app = format!(
            "test.keychain.lock.{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "macos::mutation_lock_tests::mutation_lock_crash_worker",
                "--ignored",
                "--nocapture",
            ])
            .env("ARKRET_MACOS_LOCK_APP", &app)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        loop {
            let mut line = String::new();
            assert!(output.read_line(&mut line).unwrap() > 0);
            if line.trim() == "READY" {
                break;
            }
        }
        let (send, receive) = std::sync::mpsc::channel();
        let contender = std::thread::spawn(move || {
            let store = MacOsKeychainKeyStore::new(&app).unwrap();
            let acquired = store.with_mutation_lock(|| Ok(()));
            send.send(acquired).unwrap();
        });
        assert!(receive.recv_timeout(Duration::from_millis(200)).is_err());
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success());
        receive
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        contender.join().unwrap();
    }
}
