use super::*;

#[derive(Default)]
struct PriorityStore(std::sync::Mutex<Vec<String>>);

impl KeyStore for PriorityStore {
    fn load(&self, id: &str) -> Result<KeyBytes> {
        self.0.lock().unwrap().push(id.to_owned());
        match id {
            "missing" => Err(KeyStoreError::not_found(id)),
            "present" => Ok(KeyBytes::new(Vec::new())),
            "denied" => Err(KeyStoreError::backend("access denied, not found text")),
            _ => panic!("lower priority key must not be read"),
        }
    }
    fn store(&self, _: &str, _: &[u8]) -> Result<()> {
        panic!("read only")
    }
    fn list(&self) -> Result<Vec<String>> {
        panic!("enumeration not permitted")
    }
    fn delete(&self, _: &str) -> Result<()> {
        panic!("read only")
    }
}

#[test]
fn priority_read_stops_on_present_empty_or_backend_error_without_enumeration() {
    let store = PriorityStore::default();
    assert!(store.load_first(&[]).unwrap().is_none());
    let (index, bytes) = store
        .load_first(&["missing", "present", "unreachable"])
        .unwrap()
        .unwrap();
    assert_eq!(index, 1);
    assert!(bytes.is_empty());
    assert_eq!(*store.0.lock().unwrap(), ["missing", "present"]);
    store.0.lock().unwrap().clear();
    assert!(matches!(
        store.load_first(&["missing", "denied", "unreachable"]),
        Err(KeyStoreError::Backend(_))
    ));
    assert_eq!(*store.0.lock().unwrap(), ["missing", "denied"]);
    assert!(store.load_first(&["missing"]).unwrap().is_none());
}

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
