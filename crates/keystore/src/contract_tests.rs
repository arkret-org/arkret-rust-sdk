use super::*;

struct ImportOnly;

impl KeyStore for ImportOnly {
    fn load(&self, id: &str) -> Result<KeyBytes> {
        Err(KeyStoreError::not_found(id))
    }
    fn store(&self, _id: &str, _key: &[u8]) -> Result<()> {
        panic!("must not emulate atomic creation")
    }
    fn list(&self) -> Result<Vec<String>> {
        Ok(Vec::new())
    }
    fn delete(&self, _id: &str) -> Result<()> {
        Ok(())
    }
}

#[test]
fn import_only_backend_fails_atomic_creation_closed() {
    assert!(matches!(
        ImportOnly.create_if_absent("key", b"candidate"),
        Err(KeyStoreError::Unsupported { .. })
    ));
    assert!(matches!(
        ImportOnly.create_if_absent("", b"candidate"),
        Err(KeyStoreError::InvalidId { .. })
    ));
}

#[test]
fn key_bytes_debug_output_is_redacted() {
    let bytes = KeyBytes::new(b"must-not-appear".to_vec());
    assert_eq!(format!("{bytes:?}"), "KeyBytes([REDACTED])");
}

#[test]
fn key_store_error_unsupported_renders_reason() {
    let err = KeyStoreError::unsupported("no-D-Bus session bus");
    let rendered = format!("{err}");
    assert!(rendered.contains("unsupported"));
    assert!(rendered.contains("no-D-Bus session bus"));
}

#[test]
fn service_name_namespaces_per_application_id() {
    assert_eq!(service_name("inkson"), "arkret.inkson");
    assert_eq!(service_name("coland.authority"), "arkret.coland.authority");
}
