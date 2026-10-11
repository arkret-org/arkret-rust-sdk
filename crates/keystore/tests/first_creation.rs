#![cfg(feature = "keystore-encrypted-file")]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use arkret_keystore::{EncryptedFileKeyStore, KeyStore};

const ID: &str = "first-creation";
static SCRATCH_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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

#[test]
#[ignore = "spawned only by cross-process creation tests"]
fn creation_worker() {
    let directory = PathBuf::from(std::env::var("ARKRET_CREATION_DIRECTORY").unwrap());
    let kind = std::env::var("ARKRET_CREATION_BACKEND").unwrap();
    let app = std::env::var("ARKRET_CREATION_APP").unwrap();
    let candidate = std::env::var("ARKRET_CREATION_CANDIDATE").unwrap();
    let store = open_store(&kind, &directory.join("vault"), &app);
    assert!(store.load(ID).unwrap_err().is_not_found());
    println!("READY");
    std::io::stdout().flush().unwrap();
    let mut signal = String::new();
    std::io::stdin().read_line(&mut signal).unwrap();
    assert_eq!(signal.trim(), "GO");
    let winner = store.create_if_absent(ID, candidate.as_bytes()).unwrap();
    fs::write(directory.join(candidate), winner.as_slice()).unwrap();
}

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cross_process(kind: &str) {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let (app, directory) = loop {
        let sequence = SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let app = format!(
            "test.creation.{kind}.{}.{unique}.{sequence}",
            std::process::id()
        );
        let path = std::env::temp_dir().join(&app);
        match fs::create_dir(&path) {
            Ok(()) => break (app, Scratch(path)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("cannot allocate creation-test scratch directory: {error}"),
        }
    };
    let spawn = |candidate: &str| -> Child {
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "creation_worker", "--ignored", "--nocapture"])
            .env("ARKRET_CREATION_DIRECTORY", &directory.0)
            .env("ARKRET_CREATION_BACKEND", kind)
            .env("ARKRET_CREATION_APP", &app)
            .env("ARKRET_CREATION_CANDIDATE", candidate)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap()
    };
    let mut children = [spawn("left"), spawn("right")];
    let mut outputs = children
        .iter_mut()
        .map(|child| BufReader::new(child.stdout.take().unwrap()))
        .collect::<Vec<_>>();
    for output in &mut outputs {
        loop {
            let mut line = String::new();
            assert!(
                output.read_line(&mut line).unwrap() > 0,
                "worker exited before observing a miss"
            );
            if line.trim() == "READY" {
                break;
            }
        }
    }
    // Both independent processes observed a miss before either may create.
    for child in &mut children {
        child.stdin.take().unwrap().write_all(b"GO\n").unwrap();
    }
    for child in &mut children {
        assert!(child.wait().unwrap().success());
    }
    let left = fs::read(directory.0.join("left")).unwrap();
    let right = fs::read(directory.0.join("right")).unwrap();
    assert_eq!(left, right);
    assert!(left == b"left" || left == b"right");
    let reopened = open_store(kind, &directory.0.join("vault"), &app);
    assert_eq!(reopened.load(ID).unwrap().as_slice(), left);
    assert_eq!(
        reopened.create_if_absent(ID, b"third").unwrap().as_slice(),
        left
    );
    // Import/rotation semantics have not silently become create-only.
    reopened.store(ID, b"explicit replacement").unwrap();
    assert_eq!(
        reopened.load(ID).unwrap().as_slice(),
        b"explicit replacement"
    );
    assert_eq!(
        reopened.create_if_absent(ID, b"fourth").unwrap().as_slice(),
        b"explicit replacement"
    );
    reopened.delete(ID).unwrap();
    assert!(reopened.load(ID).unwrap_err().is_not_found());
}

#[test]
fn file_processes_converge_on_one_first_key() {
    cross_process("file");
}

#[cfg(all(target_os = "macos", feature = "keystore-macos"))]
#[test]
fn keychain_processes_converge_on_one_first_key() {
    cross_process("macos");
}

#[cfg(all(target_os = "linux", feature = "keystore-linux"))]
#[test]
#[ignore = "requires a running, unlocked native Secret Service"]
fn secret_service_processes_converge_on_one_first_key() {
    cross_process("linux");
}

#[cfg(all(target_os = "windows", feature = "keystore-windows"))]
#[test]
fn dpapi_processes_converge_on_one_first_key() {
    cross_process("windows");
}
