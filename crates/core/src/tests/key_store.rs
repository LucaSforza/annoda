use super::*;
use std::{
    io::{BufRead, BufReader},
    process::{Command, Stdio},
};

const PASS: &[u8] = b"test-only passphrase";

#[test]
fn persists_identity_and_reopens_in_a_fresh_process() {
    const DIR: &str = "ANNODA_VAULT_CHILD_DIR";
    const MODE: &str = "ANNODA_VAULT_CHILD_MODE";
    if let Ok(directory) = std::env::var(DIR) {
        let vault = PortableAccountVault::new(directory);
        if std::env::var(MODE).as_deref() == Ok("create") {
            let account = vault.create(PASS).expect("create vault");
            let issuer = crate::identity::DevelopmentIssuer::new().expect("issuer");
            let credential = issuer
                .issue_synthetic(account.identity(), "Ada", 30, 10, 100)
                .expect("credential");
            fs::write(
                std::path::Path::new(&std::env::var(DIR).expect("directory")).join("credential"),
                postcard::to_allocvec(&credential).expect("serialize credential"),
            )
            .expect("persist public credential fixture");
            fs::write(
                std::path::Path::new(&std::env::var(DIR).expect("directory")).join("issuer"),
                issuer.test_public_key(),
            )
            .expect("persist public issuer key");
            let parcel = account
                .identity()
                .seal(
                    account.identity().encryption_public_key(),
                    b"old-message",
                    b"still decryptable",
                )
                .expect("seal old message");
            fs::write(
                std::path::Path::new(&std::env::var(DIR).expect("directory")).join("parcel"),
                parcel,
            )
            .expect("persist encrypted parcel");
            println!("{}", hex(&account.identity().signing_public_key()));
            return;
        }
        let account = vault.unlock(PASS).expect("unlock vault");
        if std::env::var(MODE).as_deref() == Ok("hold") {
            println!("READY");
            std::io::stdout().flush().expect("flush readiness");
            let mut release = [0u8; 1];
            std::io::stdin()
                .read_exact(&mut release)
                .expect("release child lock");
            drop(account);
            return;
        }
        let directory_value = std::env::var(DIR).expect("directory");
        let directory = std::path::Path::new(&directory_value);
        let credential_bytes = fs::read(directory.join("credential")).expect("credential");
        let credential: crate::identity::VerifiedCredential =
            postcard::from_bytes(&credential_bytes).expect("decode credential");
        let issuer_bytes: [u8; 32] = fs::read(directory.join("issuer"))
            .expect("issuer")
            .try_into()
            .expect("issuer key bytes");
        credential
            .verify(&crate::identity::TrustedIssuers::new([issuer_bytes]), 20)
            .expect("existing credential remains valid");
        assert_eq!(credential.claims.subject, account.identity().profile_id());
        assert_eq!(
            credential.claims.signing_key,
            account.identity().signing_public_key()
        );
        assert_eq!(
            credential.claims.encryption_key,
            account.identity().encryption_public_key()
        );
        let parcel = fs::read(directory.join("parcel")).expect("parcel");
        assert_eq!(
            account
                .identity()
                .open(b"old-message", &parcel)
                .expect("decrypt"),
            b"still decryptable"
        );
        println!("{}", hex(&account.identity().signing_public_key()));
        return;
    }

    let directory = tempfile::tempdir().expect("temporary directory");
    let run_child = |mode: &str| {
        Command::new(std::env::current_exe().expect("test executable"))
            .arg("--exact")
            .arg("key_store::tests::persists_identity_and_reopens_in_a_fresh_process")
            .arg("--nocapture")
            .env(DIR, directory.path().join("vault"))
            .env(MODE, mode)
            .output()
            .expect("child process")
    };
    let created = run_child("create");
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let first = String::from_utf8_lossy(&created.stdout)
        .lines()
        .find(|line| line.len() == 64)
        .expect("public key output")
        .to_owned();
    let reopened = run_child("unlock");
    assert!(
        reopened.status.success(),
        "{}",
        String::from_utf8_lossy(&reopened.stderr)
    );
    let reopened_stdout = String::from_utf8_lossy(&reopened.stdout);
    let second = reopened_stdout
        .lines()
        .find(|line| line.len() == 64)
        .expect("public key output");
    assert_eq!(first, second);

    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .arg("--exact")
        .arg("key_store::tests::persists_identity_and_reopens_in_a_fresh_process")
        .arg("--nocapture")
        .env(DIR, directory.path().join("vault"))
        .env(MODE, "hold")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("locked child process");
    let mut child_stdout = BufReader::new(child.stdout.take().expect("child stdout"));
    let mut ready = String::new();
    loop {
        ready.clear();
        if child_stdout.read_line(&mut ready).expect("child readiness") == 0
            || ready.trim() == "READY"
        {
            break;
        }
    }
    if ready.trim() != "READY" {
        drop(child_stdout);
        let output = child.wait_with_output().expect("failed child output");
        panic!(
            "child failed before acquiring lock: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert_eq!(ready.trim(), "READY");
    let vault = PortableAccountVault::new(directory.path().join("vault"));
    assert_eq!(
        vault.unlock(PASS).err(),
        Some(AccountKeyStoreError::BusyLocked)
    );
    child
        .stdin
        .take()
        .expect("child stdin")
        .write_all(b"x")
        .expect("release child");
    assert!(child.wait().expect("child exit").success());
}

#[test]
fn wrong_passphrase_and_corruption_never_replace_vault() {
    let directory = tempfile::tempdir().expect("directory");
    let vault = PortableAccountVault::new(directory.path().join("vault"));
    let account = vault.create(PASS).expect("create");
    let public = account.identity().signing_public_key();
    let (signing_secret, encryption_secret) = account.identity().export_secret_material();
    let disk = fs::read(vault.vault_path()).expect("vault bytes");
    assert!(!contains(&disk, &signing_secret[..]));
    assert!(!contains(&disk, &encryption_secret[..]));
    account.lock();
    assert_eq!(
        vault.unlock(b"wrong password").err(),
        Some(AccountKeyStoreError::AuthenticationFailed)
    );
    let account = vault.unlock(PASS).expect("original vault remains usable");
    assert_eq!(account.identity().signing_public_key(), public);
    account.lock();
    let path = vault.vault_path();
    let mut bytes = fs::read(&path).expect("read vault");
    *bytes.last_mut().expect("ciphertext") ^= 1;
    fs::write(&path, &bytes).expect("corrupt vault");
    assert_eq!(
        vault.unlock(PASS).err(),
        Some(AccountKeyStoreError::AuthenticationFailed)
    );
    assert_eq!(fs::read(path).expect("vault retained"), bytes);
}

#[test]
fn lock_is_exclusive_and_create_never_overwrites() {
    let directory = tempfile::tempdir().expect("directory");
    let vault = PortableAccountVault::new(directory.path().join("vault"));
    let held = vault.create(PASS).expect("create");
    assert_eq!(
        vault.unlock(PASS).err(),
        Some(AccountKeyStoreError::BusyLocked)
    );
    drop(held);
    assert_eq!(
        vault.create(PASS).err(),
        Some(AccountKeyStoreError::AlreadyExists)
    );
    assert_eq!(vault.unlock(PASS).err(), None);
}

#[test]
fn missing_and_invalid_authorization_are_typed() {
    let directory = tempfile::tempdir().expect("directory");
    let vault = PortableAccountVault::new(directory.path().join("vault"));
    assert_eq!(
        vault.unlock(PASS).err(),
        Some(AccountKeyStoreError::Missing)
    );
    assert_eq!(
        vault.create(b"").err(),
        Some(AccountKeyStoreError::InvalidInput)
    );
    assert_eq!(
        vault.create(&vec![b'x'; MAX_PASSPHRASE_SIZE + 1]).err(),
        Some(AccountKeyStoreError::InvalidInput)
    );
}

#[test]
fn concurrent_creation_has_one_winner_without_overwrite() {
    use std::sync::{Arc, Barrier};

    let directory = tempfile::tempdir().expect("directory");
    let vault = Arc::new(PortableAccountVault::new(directory.path().join("vault")));
    let barrier = Arc::new(Barrier::new(3));
    let workers = (0..2)
        .map(|_| {
            let vault = Arc::clone(&vault);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                vault
                    .create(PASS)
                    .map(|account| account.identity().profile_id())
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().expect("creator thread"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert!(results.iter().all(|result| {
        result.is_ok()
            || matches!(
                result,
                Err(AccountKeyStoreError::BusyLocked | AccountKeyStoreError::AlreadyExists)
            )
    }));
}

#[test]
fn malformed_costs_and_insecure_paths_are_rejected_before_kdf() {
    let directory = tempfile::tempdir().expect("directory");
    let vault = PortableAccountVault::new(directory.path().join("vault"));
    let account = vault.create(PASS).expect("create");
    account.lock();
    let path = vault.vault_path();
    let mut bytes = fs::read(&path).expect("read");
    bytes[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(&path, bytes).expect("write malformed");
    assert_eq!(
        vault.unlock(PASS).err(),
        Some(AccountKeyStoreError::UnsupportedVersion)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("permissions");
        assert_eq!(
            vault.unlock(PASS).err(),
            Some(AccountKeyStoreError::Inaccessible)
        );
    }
}

#[cfg(unix)]
#[test]
fn symlink_directory_is_rejected_without_changing_target_permissions() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let directory = tempfile::tempdir().expect("directory");
    let target = directory.path().join("target");
    fs::create_dir(&target).expect("target directory");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).expect("target mode");
    let alias = directory.path().join("alias");
    symlink(&target, &alias).expect("directory symlink");

    let vault = PortableAccountVault::new(alias);
    assert_eq!(
        vault.create(PASS).err(),
        Some(AccountKeyStoreError::Inaccessible)
    );
    assert_eq!(
        target
            .metadata()
            .expect("target metadata")
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
