#![cfg(feature = "keystore-encrypted-file")]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arkret_keystore::{EncryptedFileKeyStore, KeyStore};

const ID: &str = "exact-bytes-cas";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn open_store(kind: &str, path: &Path, app: &str) -> Box<dyn KeyStore> {
    match kind {
        "file" => Box::new(EncryptedFileKeyStore::new(path, app, [0x39; 32]).unwrap()),
        #[cfg(all(target_os = "macos", feature = "keystore-macos"))]
        "macos" => Box::new(arkret_keystore::MacOsKeychainKeyStore::new(app).unwrap()),
        #[cfg(all(target_os = "linux", feature = "keystore-linux"))]
        "linux" => Box::new(arkret_keystore::LinuxSecretServiceKeyStore::new(app).unwrap()),
        #[cfg(all(target_os = "windows", feature = "keystore-windows"))]
        "windows" => Box::new(arkret_keystore::WindowsProtectedKeyStore::new(app).unwrap()),
        _ => panic!("unexpected test backend: {kind}"),
    }
}

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn scratch(kind: &str) -> (String, Scratch) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    loop {
        let app = format!(
            "test.cas.{kind}.{}.{now}.{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(&app);
        match fs::create_dir(&path) {
            Ok(()) => return (app, Scratch(path)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("cannot allocate CAS-test scratch: {error}"),
        }
    }
}

fn worker(directory: &Path, kind: &str, app: &str, candidate: &str, mode: &str) -> Child {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "cas_worker", "--ignored", "--nocapture"])
        .env("ARKRET_CAS_DIRECTORY", directory)
        .env("ARKRET_CAS_BACKEND", kind)
        .env("ARKRET_CAS_APP", app)
        .env("ARKRET_CAS_CANDIDATE", candidate)
        .env("ARKRET_CAS_MODE", mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap()
}

fn ready(child: &mut Child) -> BufReader<std::process::ChildStdout> {
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    loop {
        let mut line = String::new();
        assert!(
            stdout.read_line(&mut line).unwrap() > 0,
            "CAS worker exited before READY"
        );
        if line.trim() == "READY" {
            return stdout;
        }
    }
}

fn vault_lock(directory: &Path, kind: &str, app: &str) -> PathBuf {
    match kind {
        "file" => directory.join("vault.lock"),
        #[cfg(all(target_os = "windows", feature = "keystore-windows"))]
        "windows" => {
            use sha2::{Digest, Sha256};
            let namespace: String = Sha256::digest(app.as_bytes())
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap())
                .join("Arkret")
                .join("keystore")
                .join(namespace)
                .join("secrets.v1.lock")
        }
        _ => panic!("backend has no file vault lock: {kind}, {app}"),
    }
}

#[test]
#[ignore = "spawned only by exact-byte CAS process tests"]
fn cas_worker() {
    let directory = PathBuf::from(std::env::var_os("ARKRET_CAS_DIRECTORY").unwrap());
    let kind = std::env::var("ARKRET_CAS_BACKEND").unwrap();
    let app = std::env::var("ARKRET_CAS_APP").unwrap();
    let candidate = std::env::var("ARKRET_CAS_CANDIDATE").unwrap();
    let mode = std::env::var("ARKRET_CAS_MODE").unwrap();
    let store = open_store(&kind, &directory.join("vault"), &app);
    let _lock = if mode == "lock" {
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(vault_lock(&directory, &kind, &app))
            .unwrap();
        lock.lock().unwrap();
        Some(lock)
    } else {
        assert_eq!(store.load(ID).unwrap().as_slice(), b"initial");
        None
    };
    println!("READY");
    std::io::stdout().flush().unwrap();
    let mut signal = String::new();
    std::io::stdin().read_line(&mut signal).unwrap();
    assert_eq!(signal.trim(), "GO");
    assert_ne!(
        mode, "lock",
        "lock worker must be killed, not released normally"
    );
    let accepted = store
        .compare_exchange(ID, Some(b"initial"), candidate.as_bytes())
        .unwrap();
    fs::write(
        directory.join(candidate),
        if accepted { b"1" } else { b"0" },
    )
    .unwrap();
}

fn cross_process(kind: &str) {
    let (app, directory) = scratch(kind);
    let original = open_store(kind, &directory.0.join("vault"), &app);
    assert!(original.compare_exchange(ID, None, b"initial").unwrap());
    let mut children = [
        worker(&directory.0, kind, &app, "left", "cas"),
        worker(&directory.0, kind, &app, "right", "cas"),
    ];
    let _outputs = children.iter_mut().map(ready).collect::<Vec<_>>();
    // Both processes have loaded the same old value before either can mutate.
    for child in &mut children {
        child.stdin.take().unwrap().write_all(b"GO\n").unwrap();
    }
    for child in &mut children {
        assert!(child.wait().unwrap().success());
    }
    let left = fs::read(directory.0.join("left")).unwrap();
    let right = fs::read(directory.0.join("right")).unwrap();
    assert!(left == b"1" && right == b"0" || left == b"0" && right == b"1");
    let winner: &[u8] = if left == b"1" { b"left" } else { b"right" };
    let reopened = open_store(kind, &directory.0.join("vault"), &app);
    assert_eq!(reopened.load(ID).unwrap().as_slice(), winner);
    assert!(
        !original
            .compare_exchange(ID, Some(b"initial"), b"stale")
            .unwrap()
    );
    assert!(!original.compare_exchange(ID, None, b"stale").unwrap());
    assert!(original.compare_exchange(ID, Some(winner), b"").unwrap());
    assert!(
        !reopened
            .compare_exchange(ID, None, b"absent-is-not-empty")
            .unwrap()
    );
    assert!(
        reopened
            .compare_exchange(ID, Some(b""), b"successor")
            .unwrap()
    );
    original.store(ID, b"ordinary write").unwrap();
    assert!(
        !reopened
            .compare_exchange(ID, Some(b"successor"), b"stale")
            .unwrap()
    );
    original.delete(ID).unwrap();
    assert!(
        !reopened
            .compare_exchange(ID, Some(b"ordinary write"), b"stale")
            .unwrap()
    );
    assert!(
        reopened
            .compare_exchange(ID, None, b"after deletion")
            .unwrap()
    );
    reopened.delete(ID).unwrap();
}

fn crash_releases_vault_lock(kind: &str) {
    let (app, directory) = scratch(kind);
    let store = open_store(kind, &directory.0.join("vault"), &app);
    assert!(store.compare_exchange(ID, None, b"initial").unwrap());
    let mut holder = worker(&directory.0, kind, &app, "holder", "lock");
    let _output = ready(&mut holder);
    let (sent, received) = std::sync::mpsc::channel();
    let waiter = std::thread::spawn(move || {
        sent.send(store.compare_exchange(ID, Some(b"initial"), b"after crash"))
            .unwrap();
    });
    assert!(
        received.recv_timeout(Duration::from_millis(200)).is_err(),
        "mutation bypassed another process's OS lock"
    );
    holder.kill().unwrap();
    assert!(!holder.wait().unwrap().success());
    assert!(
        received
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap()
    );
    waiter.join().unwrap();
    let reopened = open_store(kind, &directory.0.join("vault"), &app);
    assert_eq!(reopened.load(ID).unwrap().as_slice(), b"after crash");
    reopened.delete(ID).unwrap();
}

#[test]
fn file_processes_compare_full_committed_bytes() {
    cross_process("file");
}
#[test]
fn file_process_crash_releases_stable_mutation_lock() {
    crash_releases_vault_lock("file");
}
#[cfg(all(target_os = "windows", feature = "keystore-windows"))]
#[test]
fn dpapi_processes_compare_full_committed_bytes() {
    cross_process("windows");
}
#[cfg(all(target_os = "windows", feature = "keystore-windows"))]
#[test]
fn dpapi_process_crash_releases_stable_mutation_lock() {
    crash_releases_vault_lock("windows");
}
#[cfg(all(target_os = "macos", feature = "keystore-macos"))]
#[test]
fn keychain_processes_compare_full_committed_bytes() {
    cross_process("macos");
}
#[cfg(all(target_os = "linux", feature = "keystore-linux"))]
#[test]
#[ignore = "requires a running, unlocked native Secret Service"]
fn secret_service_processes_compare_full_committed_bytes() {
    cross_process("linux");
}
