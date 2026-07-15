//! Durable encrypted-file [`KeyStore`] backend.
//!
//! The complete namespaced key map is authenticated and encrypted as one small
//! binary container. Updates take an exclusive lock on a separate stable lock
//! file, decrypt the current map, mutate it, and atomically replace the
//! ciphertext file. This keeps read-modify-write safe across processes even
//! though replacing the ciphertext changes its inode.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use arkret_core::keystore::{KeyBytes, KeyStore, KeyStoreError, service_name, validate_id};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const FILE_MAGIC: &[u8; 8] = b"ARKRETKS";
const FILE_VERSION: u16 = 1;
const PAYLOAD_MAGIC: &[u8; 8] = b"ARKKSPAY";
const PAYLOAD_VERSION: u16 = 1;
const KDF_SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const AEAD_TAG_LEN: usize = 16;
const FILE_HEADER_LEN: usize = FILE_MAGIC.len() + 2 + KDF_SALT_LEN + NONCE_LEN + 8;
const HKDF_INFO: &[u8] = b"arkret.encrypted-file-keystore.v1";
const MAX_FILE_BYTES: usize = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 4_096;
const MAX_NAMESPACE_BYTES: usize = 4 * 1024;
const MAX_ID_BYTES: usize = 16 * 1024;
const MAX_KEY_BYTES: usize = 1024 * 1024;

type EntryMap = BTreeMap<(String, String), KeyBytes>;
type DecodedFile<'a> = (&'a [u8], [u8; KDF_SALT_LEN], [u8; NONCE_LEN], &'a [u8]);

/// File-backed encrypted key storage using a caller-custodied 32-byte master
/// key.
///
/// Multiple instances may safely share one file. `application_id` is converted
/// to the same `arkret.<application_id>` namespace used by the OS-native
/// backends, so [`KeyStore::list`] and CRUD operations expose only that
/// instance's entries. The master key is zeroized when the store is dropped.
#[derive(ZeroizeOnDrop)]
pub struct EncryptedFileKeyStore {
    #[zeroize(skip)]
    path: PathBuf,
    #[zeroize(skip)]
    lock_path: PathBuf,
    #[zeroize(skip)]
    namespace: String,
    master_key: [u8; 32],
}

impl fmt::Debug for EncryptedFileKeyStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EncryptedFileKeyStore")
            .field("path", &self.path)
            .field("namespace", &self.namespace)
            .field("master_key", &"<redacted>")
            .finish()
    }
}

impl EncryptedFileKeyStore {
    /// Open an encrypted key-store namespace at `path`.
    ///
    /// The file is created lazily on the first successful [`KeyStore::store`].
    /// Its parent directory is created when necessary. `master_key` must be
    /// generated from a cryptographically secure random source and custodied
    /// separately from the encrypted file.
    pub fn new(
        path: impl Into<PathBuf>,
        application_id: &str,
        master_key: [u8; 32],
    ) -> Result<Self, KeyStoreError> {
        if application_id.is_empty() {
            return Err(KeyStoreError::invalid_id(
                "application_id must be non-empty",
            ));
        }
        let namespace = service_name(application_id);
        if namespace.len() > MAX_NAMESPACE_BYTES {
            return Err(KeyStoreError::invalid_id(format!(
                "application namespace exceeds {MAX_NAMESPACE_BYTES} bytes"
            )));
        }
        let path = path.into();
        if path.as_os_str().is_empty() || path.file_name().is_none() {
            return Err(KeyStoreError::invalid_id(
                "encrypted key-store path must name a file",
            ));
        }
        ensure_parent_directory(&path)?;
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".lock");
        Ok(Self {
            path,
            lock_path: PathBuf::from(lock_name),
            namespace,
            master_key,
        })
    }

    /// Ciphertext file used by this store.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn with_exclusive_lock<T>(
        &self,
        operation: impl FnOnce() -> arkret_core::Result<T>,
    ) -> arkret_core::Result<T> {
        let lock_file = open_lock_file(&self.lock_path).map_err(backend_io)?;
        lock_file.lock().map_err(backend_io)?;
        let result = operation();
        let unlock_result = lock_file.unlock().map_err(backend_io);
        match (result, unlock_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn read_entries(&self) -> arkret_core::Result<EntryMap> {
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(BTreeMap::new());
            }
            Err(error) => return Err(backend_io(error)),
        };
        let file_len = file.metadata().map_err(backend_io)?.len();
        if file_len > MAX_FILE_BYTES as u64 {
            return Err(backend("encrypted key-store file exceeds the size limit"));
        }
        let mut encoded = Vec::with_capacity(file_len as usize);
        file.read_to_end(&mut encoded).map_err(backend_io)?;
        let (header, salt, nonce, ciphertext) = decode_file(&encoded)?;
        let mut file_key = self.derive_file_key(&salt)?;
        let cipher = XChaCha20Poly1305::new((&file_key).into());
        let nonce = XNonce::from(nonce);
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: header,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| {
                backend(
                    "encrypted key-store authentication failed: wrong master key or corrupt file",
                )
            });
        file_key.zeroize();
        decode_payload(&plaintext?)
    }

    fn write_entries(&self, entries: &EntryMap) -> arkret_core::Result<()> {
        let plaintext = encode_payload(entries)?;
        let mut salt = [0u8; KDF_SALT_LEN];
        getrandom::fill(&mut salt)
            .map_err(|error| backend(format!("generating key-store KDF salt failed: {error}")))?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce)
            .map_err(|error| backend(format!("generating key-store nonce failed: {error}")))?;
        let ciphertext_len = plaintext
            .len()
            .checked_add(AEAD_TAG_LEN)
            .ok_or_else(|| backend("encrypted key-store ciphertext length overflow"))?;
        let ciphertext_len = u64::try_from(ciphertext_len)
            .map_err(|_| backend("encrypted key-store ciphertext is too large"))?;
        let header = encode_header(&salt, &nonce, ciphertext_len);
        let mut file_key = self.derive_file_key(&salt)?;
        let cipher = XChaCha20Poly1305::new((&file_key).into());
        let nonce = XNonce::from(nonce);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &header,
                },
            )
            .map_err(|_| backend("encrypting key-store file failed"));
        file_key.zeroize();
        let ciphertext = ciphertext?;
        if header.len() + ciphertext.len() > MAX_FILE_BYTES {
            return Err(backend("encrypted key-store file exceeds the size limit"));
        }

        #[cfg(unix)]
        let options = {
            use std::os::unix::fs::OpenOptionsExt as _;

            use atomic_write_file::unix::OpenOptionsExt as _;

            let mut options = atomic_write_file::OpenOptions::new();
            options.mode(0o600).preserve_mode(false);
            options
        };
        #[cfg(not(unix))]
        let options = atomic_write_file::OpenOptions::new();
        let mut file = options.open(&self.path).map_err(backend_io)?;
        file.write_all(&header).map_err(backend_io)?;
        file.write_all(&ciphertext).map_err(backend_io)?;
        file.commit().map_err(backend_io)?;
        sync_parent_directory(&self.path).map_err(backend_io)
    }

    fn derive_file_key(&self, salt: &[u8; KDF_SALT_LEN]) -> arkret_core::Result<[u8; 32]> {
        let hkdf = Hkdf::<Sha256>::new(Some(salt), &self.master_key);
        let mut key = [0u8; 32];
        hkdf.expand(HKDF_INFO, &mut key)
            .map_err(|_| backend("deriving encrypted key-store file key failed"))?;
        Ok(key)
    }
}

impl KeyStore for EncryptedFileKeyStore {
    fn load(&self, id: &str) -> arkret_core::Result<KeyBytes> {
        validate_id(id)?;
        self.with_exclusive_lock(|| {
            self.read_entries()?
                .get(&(self.namespace.clone(), id.to_owned()))
                .cloned()
                .ok_or_else(|| KeyStoreError::not_found(id).into())
        })
    }

    fn store(&self, id: &str, key: &[u8]) -> arkret_core::Result<()> {
        validate_entry(id, key)?;
        self.with_exclusive_lock(|| {
            let mut entries = self.read_entries()?;
            entries.insert(
                (self.namespace.clone(), id.to_owned()),
                KeyBytes::new(key.to_vec()),
            );
            self.write_entries(&entries)
        })
    }

    fn list(&self) -> arkret_core::Result<Vec<String>> {
        self.with_exclusive_lock(|| {
            Ok(self
                .read_entries()?
                .keys()
                .filter(|(namespace, _)| namespace == &self.namespace)
                .map(|(_, id)| id.clone())
                .collect())
        })
    }

    fn delete(&self, id: &str) -> arkret_core::Result<()> {
        validate_id(id)?;
        self.with_exclusive_lock(|| {
            let mut entries = self.read_entries()?;
            if entries
                .remove(&(self.namespace.clone(), id.to_owned()))
                .is_some()
            {
                self.write_entries(&entries)?;
            }
            Ok(())
        })
    }
}

fn ensure_parent_directory(path: &Path) -> Result<(), KeyStoreError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(parent).map_err(|error| {
        KeyStoreError::backend(format!("creating key-store directory failed: {error}"))
    })
}

fn open_lock_file(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn validate_entry(id: &str, key: &[u8]) -> arkret_core::Result<()> {
    validate_id(id)?;
    if id.len() > MAX_ID_BYTES {
        return Err(KeyStoreError::invalid_id(format!("id exceeds {MAX_ID_BYTES} bytes")).into());
    }
    if key.len() > MAX_KEY_BYTES {
        return Err(backend(format!(
            "key material exceeds {MAX_KEY_BYTES} bytes"
        )));
    }
    Ok(())
}

fn encode_header(
    salt: &[u8; KDF_SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext_len: u64,
) -> Vec<u8> {
    let mut header = Vec::with_capacity(FILE_HEADER_LEN);
    header.extend_from_slice(FILE_MAGIC);
    header.extend_from_slice(&FILE_VERSION.to_be_bytes());
    header.extend_from_slice(salt);
    header.extend_from_slice(nonce);
    header.extend_from_slice(&ciphertext_len.to_be_bytes());
    header
}

fn decode_file(encoded: &[u8]) -> arkret_core::Result<DecodedFile<'_>> {
    if encoded.len() < FILE_HEADER_LEN || encoded.len() > MAX_FILE_BYTES {
        return Err(backend("encrypted key-store file has an invalid length"));
    }
    if &encoded[..FILE_MAGIC.len()] != FILE_MAGIC {
        return Err(backend(
            "encrypted key-store file has an invalid magic value",
        ));
    }
    let mut cursor = FILE_MAGIC.len();
    let version = read_u16(encoded, &mut cursor)?;
    if version != FILE_VERSION {
        return Err(backend(format!(
            "unsupported encrypted key-store file version {version}"
        )));
    }
    let salt = take(encoded, &mut cursor, KDF_SALT_LEN)?
        .try_into()
        .map_err(|_| backend("encrypted key-store salt has an invalid length"))?;
    let nonce = take(encoded, &mut cursor, NONCE_LEN)?
        .try_into()
        .map_err(|_| backend("encrypted key-store nonce has an invalid length"))?;
    let ciphertext_len = read_u64(encoded, &mut cursor)?;
    let ciphertext_len = usize::try_from(ciphertext_len)
        .map_err(|_| backend("encrypted key-store ciphertext length is invalid"))?;
    if ciphertext_len < AEAD_TAG_LEN || encoded.len() != FILE_HEADER_LEN + ciphertext_len {
        return Err(backend(
            "encrypted key-store ciphertext length does not match the file",
        ));
    }
    Ok((
        &encoded[..FILE_HEADER_LEN],
        salt,
        nonce,
        &encoded[FILE_HEADER_LEN..],
    ))
}

fn encode_payload(entries: &EntryMap) -> arkret_core::Result<Zeroizing<Vec<u8>>> {
    if entries.len() > MAX_ENTRIES {
        return Err(backend("encrypted key-store contains too many entries"));
    }
    let mut plaintext = Zeroizing::new(Vec::new());
    plaintext.extend_from_slice(PAYLOAD_MAGIC);
    plaintext.extend_from_slice(&PAYLOAD_VERSION.to_be_bytes());
    push_u32(&mut plaintext, entries.len(), "entry count")?;
    for ((namespace, id), key) in entries {
        if namespace.is_empty() || namespace.len() > MAX_NAMESPACE_BYTES {
            return Err(backend("encrypted key-store contains an invalid namespace"));
        }
        validate_entry(id, key)?;
        push_bytes(&mut plaintext, namespace.as_bytes(), "namespace")?;
        push_bytes(&mut plaintext, id.as_bytes(), "key id")?;
        push_bytes(&mut plaintext, key, "key material")?;
    }
    Ok(plaintext)
}

fn decode_payload(plaintext: &[u8]) -> arkret_core::Result<EntryMap> {
    let mut cursor = 0;
    if take(plaintext, &mut cursor, PAYLOAD_MAGIC.len())? != PAYLOAD_MAGIC {
        return Err(backend(
            "encrypted key-store payload has an invalid magic value",
        ));
    }
    let version = read_u16(plaintext, &mut cursor)?;
    if version != PAYLOAD_VERSION {
        return Err(backend(format!(
            "unsupported encrypted key-store payload version {version}"
        )));
    }
    let entry_count = read_u32(plaintext, &mut cursor)? as usize;
    if entry_count > MAX_ENTRIES {
        return Err(backend(
            "encrypted key-store payload contains too many entries",
        ));
    }
    let mut entries = BTreeMap::new();
    for _ in 0..entry_count {
        let namespace = read_string(plaintext, &mut cursor, MAX_NAMESPACE_BYTES, "namespace")?;
        let id = read_string(plaintext, &mut cursor, MAX_ID_BYTES, "key id")?;
        validate_id(&id)?;
        let key = read_bytes(plaintext, &mut cursor, MAX_KEY_BYTES, "key material")?;
        if namespace.is_empty()
            || entries
                .insert((namespace, id), KeyBytes::new(key.to_vec()))
                .is_some()
        {
            return Err(backend(
                "encrypted key-store payload contains an invalid or duplicate entry",
            ));
        }
    }
    if cursor != plaintext.len() {
        return Err(backend("encrypted key-store payload has trailing bytes"));
    }
    Ok(entries)
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8], label: &str) -> arkret_core::Result<()> {
    push_u32(output, value.len(), label)?;
    output.extend_from_slice(value);
    Ok(())
}

fn push_u32(output: &mut Vec<u8>, value: usize, label: &str) -> arkret_core::Result<()> {
    let value = u32::try_from(value)
        .map_err(|_| backend(format!("encrypted key-store {label} is too large")))?;
    output.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn read_string(
    input: &[u8],
    cursor: &mut usize,
    maximum: usize,
    label: &str,
) -> arkret_core::Result<String> {
    let bytes = read_bytes(input, cursor, maximum, label)?;
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| backend(format!("encrypted key-store {label} is not UTF-8")))
}

fn read_bytes<'a>(
    input: &'a [u8],
    cursor: &mut usize,
    maximum: usize,
    label: &str,
) -> arkret_core::Result<&'a [u8]> {
    let length = read_u32(input, cursor)? as usize;
    if length > maximum {
        return Err(backend(format!(
            "encrypted key-store {label} exceeds the size limit"
        )));
    }
    take(input, cursor, length)
}

fn read_u16(input: &[u8], cursor: &mut usize) -> arkret_core::Result<u16> {
    let bytes: [u8; 2] = take(input, cursor, 2)?
        .try_into()
        .map_err(|_| backend("encrypted key-store integer is truncated"))?;
    Ok(u16::from_be_bytes(bytes))
}

fn read_u32(input: &[u8], cursor: &mut usize) -> arkret_core::Result<u32> {
    let bytes: [u8; 4] = take(input, cursor, 4)?
        .try_into()
        .map_err(|_| backend("encrypted key-store integer is truncated"))?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(input: &[u8], cursor: &mut usize) -> arkret_core::Result<u64> {
    let bytes: [u8; 8] = take(input, cursor, 8)?
        .try_into()
        .map_err(|_| backend("encrypted key-store integer is truncated"))?;
    Ok(u64::from_be_bytes(bytes))
}

fn take<'a>(input: &'a [u8], cursor: &mut usize, length: usize) -> arkret_core::Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| backend("encrypted key-store length overflow"))?;
    let value = input
        .get(*cursor..end)
        .ok_or_else(|| backend("encrypted key-store data is truncated"))?;
    *cursor = end;
    Ok(value)
}

fn backend(message: impl Into<String>) -> arkret_core::Error {
    KeyStoreError::backend(message).into()
}

fn backend_io(error: std::io::Error) -> arkret_core::Error {
    backend(format!("encrypted key-store I/O failed: {error}"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "arkret-encrypted-keystore-{label}-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn file(&self) -> PathBuf {
            self.0.join("keys.bin")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn encrypted_file_round_trips_across_reopen_without_plaintext_leakage() {
        let directory = TestDirectory::new("roundtrip");
        let path = directory.file();
        let key = [7u8; 32];
        {
            let store = EncryptedFileKeyStore::new(&path, "soland", key).unwrap();
            store.store("service-key", b"highly-secret-seed").unwrap();
            assert_eq!(
                store.load("service-key").unwrap().as_slice(),
                b"highly-secret-seed"
            );
        }
        let encoded = fs::read(&path).unwrap();
        assert!(
            !encoded
                .windows(b"service-key".len())
                .any(|window| window == b"service-key")
        );
        assert!(
            !encoded
                .windows(b"highly-secret-seed".len())
                .any(|window| window == b"highly-secret-seed")
        );

        let reopened = EncryptedFileKeyStore::new(&path, "soland", key).unwrap();
        assert_eq!(reopened.list().unwrap(), vec!["service-key"]);
        assert_eq!(
            reopened.load("service-key").unwrap().as_slice(),
            b"highly-secret-seed"
        );
    }

    #[test]
    fn namespaces_share_one_file_without_exposing_each_other() {
        let directory = TestDirectory::new("namespaces");
        let path = directory.file();
        let key = [9u8; 32];
        let first = EncryptedFileKeyStore::new(&path, "soland.identity", key).unwrap();
        let second = EncryptedFileKeyStore::new(&path, "soland.admin", key).unwrap();
        first.store("same-id", b"identity").unwrap();
        second.store("same-id", b"admin").unwrap();

        assert_eq!(first.list().unwrap(), vec!["same-id"]);
        assert_eq!(second.list().unwrap(), vec!["same-id"]);
        assert_eq!(first.load("same-id").unwrap().as_slice(), b"identity");
        assert_eq!(second.load("same-id").unwrap().as_slice(), b"admin");
        first.delete("same-id").unwrap();
        assert!(first.load("same-id").unwrap_err().is_key_store_not_found());
        assert_eq!(second.load("same-id").unwrap().as_slice(), b"admin");
    }

    #[test]
    fn wrong_master_key_and_corruption_fail_closed() {
        let directory = TestDirectory::new("authentication");
        let path = directory.file();
        EncryptedFileKeyStore::new(&path, "soland", [1u8; 32])
            .unwrap()
            .store("key", b"secret")
            .unwrap();

        let wrong = EncryptedFileKeyStore::new(&path, "soland", [2u8; 32]).unwrap();
        assert!(!wrong.load("key").unwrap_err().is_key_store_not_found());

        let mut encoded = fs::read(&path).unwrap();
        *encoded.last_mut().unwrap() ^= 1;
        fs::write(&path, encoded).unwrap();
        let original = EncryptedFileKeyStore::new(&path, "soland", [1u8; 32]).unwrap();
        assert!(!original.load("key").unwrap_err().is_key_store_not_found());
    }

    #[test]
    fn concurrent_instances_do_not_lose_updates() {
        let directory = TestDirectory::new("concurrent");
        let path = directory.file();
        let stores = (0..16)
            .map(|_| Arc::new(EncryptedFileKeyStore::new(&path, "soland", [3u8; 32]).unwrap()))
            .collect::<Vec<_>>();
        let threads = stores
            .into_iter()
            .enumerate()
            .map(|(index, store)| {
                std::thread::spawn(move || {
                    store
                        .store(&format!("key-{index:02}"), &[index as u8; 32])
                        .unwrap();
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }

        let reopened = EncryptedFileKeyStore::new(&path, "soland", [3u8; 32]).unwrap();
        assert_eq!(reopened.list().unwrap().len(), 16);
        for index in 0..16 {
            assert_eq!(
                reopened
                    .load(&format!("key-{index:02}"))
                    .unwrap()
                    .as_slice(),
                &[index as u8; 32]
            );
        }
    }

    #[test]
    fn missing_file_and_delete_are_idempotent() {
        let directory = TestDirectory::new("missing");
        let path = directory.file();
        let store = EncryptedFileKeyStore::new(&path, "soland", [4u8; 32]).unwrap();
        assert!(store.list().unwrap().is_empty());
        store.delete("missing").unwrap();
        assert!(!path.exists());
        assert!(store.load("missing").unwrap_err().is_key_store_not_found());
    }
}
