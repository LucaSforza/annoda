use super::*;
use tempfile::TempDir;

#[test]
fn identity_is_stable_locked_and_only_replaced_with_expected_peer() {
    let data = TempDir::new().expect("temporary data directory");
    let store = NodeIdentityStore::new(data.path());
    let lease = store.open().expect("create identity");
    let first = lease.peer_id();
    assert!(matches!(store.open(), Err(NodeIdentityError::Busy)));
    drop(lease);

    let restored = store.open().expect("restore identity");
    assert_eq!(restored.peer_id(), first);
    drop(restored);

    let other = identity::Keypair::generate_ed25519().public().to_peer_id();
    assert!(matches!(
        store.replace(other),
        Err(NodeIdentityError::PeerIdMismatch { .. })
    ));
    let replacement = store.replace(first).expect("replace expected identity");
    assert_ne!(replacement, first);
    assert_eq!(
        store.open().expect("open replacement").peer_id(),
        replacement
    );
}

#[test]
fn corrupt_identity_is_never_replaced_implicitly() {
    let data = TempDir::new().expect("temporary data directory");
    let store = NodeIdentityStore::new(data.path());
    let lease = store.open().expect("create identity");
    let path = store.directory.join(IDENTITY_FILE);
    drop(lease);
    fs::write(&path, b"corrupt transport identity").expect("corrupt key for test");
    let before = fs::read(&path).expect("read corrupt identity");

    assert!(matches!(store.open(), Err(NodeIdentityError::Corrupt)));
    assert_eq!(fs::read(path).expect("identity remains unchanged"), before);
}

#[test]
fn missing_identity_after_initialization_is_reported_without_replacement() {
    let data = TempDir::new().expect("temporary data directory");
    let store = NodeIdentityStore::new(data.path());
    let lease = store.open().expect("create identity");
    let _original_peer = lease.peer_id();
    drop(lease);
    fs::remove_file(store.directory.join(IDENTITY_FILE)).expect("remove key for test");

    assert!(matches!(store.open(), Err(NodeIdentityError::Missing)));
    assert!(!store.directory.join(IDENTITY_FILE).exists());
}

#[test]
fn nonregular_transport_key_is_rejected_before_reading() {
    let data = TempDir::new().expect("temporary data directory");
    let store = NodeIdentityStore::new(data.path());
    let lease = store.open().expect("create identity");
    drop(lease);
    let key = store.directory.join(IDENTITY_FILE);
    fs::remove_file(&key).expect("remove key");
    fs::create_dir(&key).expect("replace key with directory");
    assert!(matches!(store.open(), Err(NodeIdentityError::Insecure)));
}
