//! Windows Credential Manager backend for [`KeyStore`].
//!
//! Wraps the Win32 `Cred*W` family
//! (`CredReadW` / `CredWriteW` / `CredDeleteW` / `CredEnumerateW`) via the
//! `windows` crate. Each entry is stored as a generic credential whose
//! `TargetName` is `"cokret.<application_id>:<key_id>"`. The
//! `"cokret.<application_id>"` prefix namespaces multiple Cokret apps on
//! the same host; the `<key_id>` is the caller-supplied opaque id.

use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};

use cokret_core::keystore::{service_name, validate_id};
use cokret_core::{KeyBytes, Result};
use windows::Win32::Foundation::ERROR_NOT_FOUND;
use windows::Win32::Security::Credentials::{
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredEnumerateW,
    CredFree, CredReadW, CredWriteW,
};
use windows::core::PCWSTR;

use crate::{KeyStore, KeyStoreError};

/// Windows Credential Manager-backed [`KeyStore`].
pub struct WindowsCredentialKeyStore {
    /// `"cokret.<application_id>"`. Used as the prefix on the generic
    /// credential `TargetName`, so we can enumerate by filter.
    service: String,
}

impl WindowsCredentialKeyStore {
    /// Construct a keystore for the given application id.
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

    fn target_name(&self, id: &str) -> String {
        format!("{}:{}", self.service, id)
    }

    fn filter(&self) -> String {
        // `CredEnumerateW` filters use `*` as a wildcard. The empty
        // suffix then matches any key id.
        format!("{}:*", self.service)
    }
}

impl KeyStore for WindowsCredentialKeyStore {
    fn load(&self, id: &str) -> Result<KeyBytes> {
        validate_id(id)?;
        let target = wide(&self.target_name(id));
        let mut cred_ptr: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: `target` is a valid NUL-terminated UTF-16 buffer owned for the duration of the
        // call; `cred_ptr` is an out-parameter the Win32 API writes into.
        let res = unsafe {
            CredReadW(
                PCWSTR(target.as_ptr()),
                CRED_TYPE_GENERIC,
                None,
                &mut cred_ptr,
            )
        };
        match res {
            Ok(()) => {
                if cred_ptr.is_null() {
                    return Err(KeyStoreError::not_found(id).into());
                }
                // SAFETY: CredReadW returned Ok and cred_ptr is non-null; the credential
                // struct and its CredentialBlob buffer are valid until we call CredFree below.
                let bytes = unsafe {
                    let cred = &*cred_ptr;
                    let len = cred.CredentialBlobSize as usize;
                    if len == 0 || cred.CredentialBlob.is_null() {
                        KeyBytes::new(Vec::new())
                    } else {
                        KeyBytes::new(std::slice::from_raw_parts(cred.CredentialBlob, len).to_vec())
                    }
                };
                // SAFETY: cred_ptr was allocated by CredReadW and is freed exactly once here.
                unsafe { CredFree(cred_ptr as *const _) };
                Ok(bytes)
            }
            Err(err) => {
                if err.code() == ERROR_NOT_FOUND.to_hresult() {
                    Err(KeyStoreError::not_found(id).into())
                } else {
                    Err(KeyStoreError::backend(format!("CredReadW: {err}")).into())
                }
            }
        }
    }

    fn store(&self, id: &str, key: &[u8]) -> Result<()> {
        validate_id(id)?;
        let target = wide(&self.target_name(id));
        let user = wide(id);
        let mut blob = KeyBytes::new(key.to_vec());
        let cred = CREDENTIALW {
            Flags: windows::Win32::Security::Credentials::CRED_FLAGS(0),
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR_from_slice(&target),
            Comment: windows::core::PWSTR::null(),
            LastWritten: windows::Win32::Foundation::FILETIME::default(),
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_mut_ptr(),
            // Durable persistence (SDK-FEAT-03): device signing keys MUST
            // survive logoff/reboot. `CRED_PERSIST_SESSION` destroys the
            // credential when the interactive logon session ends, which
            // silently discarded device identity on every logout.
            // Trade-off: LOCAL_MACHINE credentials stay resident on this
            // machine until deleted (wider at-rest window than SESSION),
            // but remain DPAPI-protected per user profile — other local
            // users cannot read them. ENTERPRISE (AD roaming) is
            // deliberately not used: device keys are device-bound.
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: windows::core::PWSTR::null(),
            UserName: PWSTR_from_slice(&user),
        };
        // SAFETY: `cred` is a valid CREDENTIALW whose pointer members (TargetName,
        // CredentialBlob, UserName) remain valid through the call because their
        // backing buffers (`target`, `blob`, `user`) outlive this expression.
        let res = unsafe { CredWriteW(&cred, 0) };
        res.map_err(|err| KeyStoreError::backend(format!("CredWriteW: {err}")))?;
        Ok(())
    }

    fn list(&self) -> Result<Vec<String>> {
        let filter = wide(&self.filter());
        let mut count: u32 = 0;
        let mut creds: *mut *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: `filter` is a NUL-terminated UTF-16 buffer; `count` and `creds`
        // are out-parameters that Win32 writes into.
        let res = unsafe { CredEnumerateW(PCWSTR(filter.as_ptr()), None, &mut count, &mut creds) };
        match res {
            Ok(()) => {
                let mut ids = Vec::with_capacity(count as usize);
                let prefix_len = self.service.len() + 1; // service + ':'
                for i in 0..count as isize {
                    // SAFETY: `creds` points to a Win32-allocated array of length `count`;
                    // `i` is strictly less than `count` so the offset and double-deref are
                    // in-bounds.
                    let cred = unsafe { &**(creds.offset(i)) };
                    // SAFETY: TargetName originates from the Win32 credential array above;
                    // the pointer is valid until CredFree(creds) runs below.
                    let target = unsafe { read_pwstr(cred.TargetName.as_ptr()) };
                    if let Some(id) = target.strip_prefix(&format!("{}:", self.service)) {
                        ids.push(id.to_owned());
                    } else if target.len() > prefix_len {
                        // Defensive: filter pattern matched but prefix
                        // shape is unexpected; skip.
                    }
                }
                if !creds.is_null() {
                    // SAFETY: `creds` was allocated by CredEnumerateW and is freed exactly once
                    // here.
                    unsafe { CredFree(creds as *const _) };
                }
                ids.sort();
                ids.dedup();
                Ok(ids)
            }
            Err(err) => {
                if err.code() == ERROR_NOT_FOUND.to_hresult() {
                    return Ok(Vec::new());
                }
                Err(KeyStoreError::backend(format!("CredEnumerateW: {err}")).into())
            }
        }
    }

    fn delete(&self, id: &str) -> Result<()> {
        validate_id(id)?;
        let target = wide(&self.target_name(id));
        // SAFETY: `target` is a valid NUL-terminated UTF-16 buffer owned for the duration of the
        // call.
        let res = unsafe { CredDeleteW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, None) };
        match res {
            Ok(()) => Ok(()),
            Err(err) => {
                if err.code() == ERROR_NOT_FOUND.to_hresult() {
                    Ok(()) // idempotent
                } else {
                    Err(KeyStoreError::backend(format!("CredDeleteW: {err}")).into())
                }
            }
        }
    }
}

/// Encode `s` as a NUL-terminated UTF-16 buffer suitable for `PCWSTR`.
fn wide(s: &str) -> Vec<u16> {
    let os: &std::ffi::OsStr = s.as_ref();
    os.encode_wide().chain(std::iter::once(0)).collect()
}

/// Read a NUL-terminated UTF-16 string from a raw pointer into a
/// `String`. Returns the empty string on null pointer.
unsafe fn read_pwstr(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let mut len = 0;
    // SAFETY: caller-contract requires `ptr` to reference a NUL-terminated UTF-16 string,
    // so walking until the first 0 word stays within the allocation.
    while unsafe { *ptr.offset(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` was just measured as the distance to the NUL terminator,
    // so `ptr..ptr+len` covers a valid, initialised UTF-16 sequence.
    let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    OsString::from_wide(slice).to_string_lossy().into_owned()
}

#[allow(non_snake_case)]
fn PWSTR_from_slice(buf: &[u16]) -> windows::core::PWSTR {
    windows::core::PWSTR(buf.as_ptr() as *mut u16)
}

#[cfg(test)]
mod tests {
    //! Live Credential Manager round-trip tests. They write under
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

    #[test]
    fn round_trip_store_load_delete() {
        let store = WindowsCredentialKeyStore::new(&unique_app_id()).unwrap();
        let id = "cokret:signer:alice:k1";
        store.store(id, b"win-secret-1").unwrap();
        assert_eq!(store.load(id).unwrap().as_slice(), b"win-secret-1");
        store.delete(id).unwrap();
        let err = store.load(id).unwrap_err();
        assert!(format!("{err}").contains("key not found"));
    }

    #[test]
    fn store_overwrites_existing_id() {
        let store = WindowsCredentialKeyStore::new(&unique_app_id()).unwrap();
        let id = "cokret:signer:bob:k1";
        store.store(id, b"first").unwrap();
        store.store(id, b"second").unwrap();
        assert_eq!(store.load(id).unwrap().as_slice(), b"second");
        store.delete(id).unwrap();
    }

    #[test]
    fn delete_missing_id_is_idempotent() {
        let store = WindowsCredentialKeyStore::new(&unique_app_id()).unwrap();
        store.delete("never-stored").unwrap();
    }

    #[test]
    fn rejects_empty_id() {
        let store = WindowsCredentialKeyStore::new(&unique_app_id()).unwrap();
        assert!(store.store("", b"x").is_err());
        assert!(store.load("").is_err());
        assert!(store.delete("").is_err());
    }

    #[test]
    fn list_returns_only_keys_in_service_namespace() {
        let app_a = unique_app_id();
        let app_b = unique_app_id();
        let store_a = WindowsCredentialKeyStore::new(&app_a).unwrap();
        let store_b = WindowsCredentialKeyStore::new(&app_b).unwrap();
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
