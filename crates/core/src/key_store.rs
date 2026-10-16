use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

use crate::identity::DeviceKeyPair;

const MAGIC: &[u8; 8] = b"ANNOVLT1";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 8 + 2 + 1 + 1 + 4 + 4 + 4 + 16 + 24;
const MAX_ENVELOPE_SIZE: usize = 16 * 1024;
const MAX_PASSPHRASE_SIZE: usize = 1024;
const DEFAULT_MEMORY_KIB: u32 = 64 * 1024;
const DEFAULT_ITERATIONS: u32 = 3;
const DEFAULT_LANES: u32 = 1;
const LOCK_FILE: &str = "account.lock";
const VAULT_FILE: &str = "account.vault";
const VAULT_AAD: &[u8] = b"annoda/account-vault/v1\0";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AccountKeyStoreError {
    #[error("account vault is missing")]
    Missing,
    #[error("account vault is already locked")]
    BusyLocked,
    #[error("account vault is inaccessible")]
    Inaccessible,
    #[error("account vault authentication failed")]
    AuthenticationFailed,
    #[error("account vault is corrupt")]
    CorruptFormat,
    #[error("account vault version is unsupported")]
    UnsupportedVersion,
    #[error("account vault already exists")]
    AlreadyExists,
    #[error("invalid account vault input")]
    InvalidInput,
}

pub type KeyStoreResult<T> = std::result::Result<T, AccountKeyStoreError>;

pub trait AccountKeyStore {
    fn create(&self, passphrase: &[u8]) -> KeyStoreResult<UnlockedAccount>;
    fn unlock(&self, passphrase: &[u8]) -> KeyStoreResult<UnlockedAccount>;
}

pub struct PortableAccountVault {
    directory: PathBuf,
}

pub struct UnlockedAccount {
    identity: DeviceKeyPair,
    _lock: File,
}

impl PortableAccountVault {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    fn acquire_lock(&self, create_directory: bool) -> KeyStoreResult<File> {
        if create_directory {
            match fs::symlink_metadata(&self.directory) {
                Ok(metadata) => check_private_directory(&metadata)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    create_private_directory(&self.directory)?;
                }
                Err(error) => return Err(map_io(error)),
            }
        } else {
            let metadata = fs::symlink_metadata(&self.directory).map_err(map_io)?;
            check_private_directory(&metadata)?;
        }
        let lock_path = self.directory.join(LOCK_FILE);
        let file = open_private_file(&lock_path, true)?;
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => Err(AccountKeyStoreError::BusyLocked),
            Err(_) => Err(AccountKeyStoreError::Inaccessible),
        }
    }

    fn vault_path(&self) -> PathBuf {
        self.directory.join(VAULT_FILE)
    }
}

impl AccountKeyStore for PortableAccountVault {
    fn create(&self, passphrase: &[u8]) -> KeyStoreResult<UnlockedAccount> {
        validate_passphrase(passphrase)?;
        let lock = self.acquire_lock(true)?;
        let path = self.vault_path();
        if path_exists(&path)? {
            return Err(AccountKeyStoreError::AlreadyExists);
        }

        let identity = DeviceKeyPair::generate().map_err(|_| AccountKeyStoreError::Inaccessible)?;
        let envelope = encrypt_identity(&identity, passphrase)?;
        publish_new(&self.directory, &path, &envelope)?;
        Ok(UnlockedAccount {
            identity,
            _lock: lock,
        })
    }

    fn unlock(&self, passphrase: &[u8]) -> KeyStoreResult<UnlockedAccount> {
        validate_passphrase(passphrase)?;
        let lock = self.acquire_lock(false)?;
        let path = self.vault_path();
        let envelope = read_envelope(&path)?;
        let identity = decrypt_identity(&envelope, passphrase)?;
        Ok(UnlockedAccount {
            identity,
            _lock: lock,
        })
    }
}

impl UnlockedAccount {
    pub fn identity(&self) -> &DeviceKeyPair {
        &self.identity
    }

    pub fn lock(self) {
        drop(self);
    }
}

fn encrypt_identity(identity: &DeviceKeyPair, passphrase: &[u8]) -> KeyStoreResult<Vec<u8>> {
    let (signing, encryption) = identity.export_secret_material();
    let mut plaintext = Zeroizing::new([0u8; 68]);
    plaintext[..4].copy_from_slice(b"KEY1");
    plaintext[4..36].copy_from_slice(&*signing);
    plaintext[36..68].copy_from_slice(&*encryption);

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.extend_from_slice(&VERSION.to_le_bytes());
    header.extend_from_slice(&[1, 1]); // XChaCha20-Poly1305, Argon2id v19
    header.extend_from_slice(&DEFAULT_MEMORY_KIB.to_le_bytes());
    header.extend_from_slice(&DEFAULT_ITERATIONS.to_le_bytes());
    header.extend_from_slice(&DEFAULT_LANES.to_le_bytes());
    let mut salt = Zeroizing::new([0u8; 16]);
    let mut nonce = Zeroizing::new([0u8; 24]);
    getrandom::fill(&mut *salt).map_err(|_| AccountKeyStoreError::Inaccessible)?;
    getrandom::fill(&mut *nonce).map_err(|_| AccountKeyStoreError::Inaccessible)?;
    header.extend_from_slice(&*salt);
    header.extend_from_slice(&*nonce);

    let key = derive_key(
        passphrase,
        &salt[..],
        DEFAULT_MEMORY_KIB,
        DEFAULT_ITERATIONS,
        DEFAULT_LANES,
    )?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| AccountKeyStoreError::Inaccessible)?;
    let mut aad = Vec::with_capacity(VAULT_AAD.len() + header.len());
    aad.extend_from_slice(VAULT_AAD);
    aad.extend_from_slice(&header);
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: &*plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| AccountKeyStoreError::Inaccessible)?;
    header.extend_from_slice(&ciphertext);
    if header.len() > MAX_ENVELOPE_SIZE {
        return Err(AccountKeyStoreError::CorruptFormat);
    }
    Ok(header)
}

fn decrypt_identity(envelope: &[u8], passphrase: &[u8]) -> KeyStoreResult<DeviceKeyPair> {
    if envelope.len() < HEADER_LEN + 16 || envelope.len() > MAX_ENVELOPE_SIZE {
        return Err(AccountKeyStoreError::CorruptFormat);
    }
    if &envelope[..8] != MAGIC {
        return Err(AccountKeyStoreError::CorruptFormat);
    }
    if u16::from_le_bytes([envelope[8], envelope[9]]) != VERSION {
        return Err(AccountKeyStoreError::UnsupportedVersion);
    }
    if envelope[10] != 1 || envelope[11] != 1 {
        return Err(AccountKeyStoreError::UnsupportedVersion);
    }
    let memory = read_u32(envelope, 12)?;
    let iterations = read_u32(envelope, 16)?;
    let lanes = read_u32(envelope, 20)?;
    if memory != DEFAULT_MEMORY_KIB || iterations != DEFAULT_ITERATIONS || lanes != DEFAULT_LANES {
        return Err(AccountKeyStoreError::UnsupportedVersion);
    }
    let salt = &envelope[24..40];
    let nonce = &envelope[40..64];
    let nonce_array: [u8; 24] = nonce
        .try_into()
        .map_err(|_| AccountKeyStoreError::CorruptFormat)?;
    let header = &envelope[..HEADER_LEN];
    let key = derive_key(passphrase, salt, memory, iterations, lanes)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key[..])
        .map_err(|_| AccountKeyStoreError::CorruptFormat)?;
    let mut aad = Vec::with_capacity(VAULT_AAD.len() + header.len());
    aad.extend_from_slice(VAULT_AAD);
    aad.extend_from_slice(header);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &XNonce::from(nonce_array),
                Payload {
                    msg: &envelope[HEADER_LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| AccountKeyStoreError::AuthenticationFailed)?,
    );
    if plaintext.len() != 68 || &plaintext[..4] != b"KEY1" {
        return Err(AccountKeyStoreError::AuthenticationFailed);
    }
    let signing = Zeroizing::new(array32(&plaintext[4..36])?);
    let encryption = Zeroizing::new(array32(&plaintext[36..68])?);
    DeviceKeyPair::from_secret_material(&signing, &encryption)
        .map_err(|_| AccountKeyStoreError::AuthenticationFailed)
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    memory: u32,
    iterations: u32,
    lanes: u32,
) -> KeyStoreResult<Zeroizing<[u8; 32]>> {
    let params = Params::new(memory, iterations, lanes, Some(32))
        .map_err(|_| AccountKeyStoreError::CorruptFormat)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase, salt, &mut *key)
        .map_err(|_| AccountKeyStoreError::Inaccessible)?;
    Ok(key)
}

fn validate_passphrase(passphrase: &[u8]) -> KeyStoreResult<()> {
    if passphrase.is_empty() || passphrase.len() > MAX_PASSPHRASE_SIZE {
        Err(AccountKeyStoreError::InvalidInput)
    } else {
        Ok(())
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> KeyStoreResult<u32> {
    let raw: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(AccountKeyStoreError::CorruptFormat)?
        .try_into()
        .map_err(|_| AccountKeyStoreError::CorruptFormat)?;
    Ok(u32::from_le_bytes(raw))
}

fn array32(bytes: &[u8]) -> KeyStoreResult<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| AccountKeyStoreError::AuthenticationFailed)
}

fn read_envelope(path: &Path) -> KeyStoreResult<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(map_io)?;
    let metadata = file.metadata().map_err(map_io)?;
    check_private_file(&metadata)?;
    if !metadata.is_file() || metadata.len() as usize > MAX_ENVELOPE_SIZE {
        return Err(AccountKeyStoreError::CorruptFormat);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_ENVELOPE_SIZE + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(map_io)?;
    if bytes.len() > MAX_ENVELOPE_SIZE {
        return Err(AccountKeyStoreError::CorruptFormat);
    }
    Ok(bytes)
}

fn publish_new(directory: &Path, destination: &Path, bytes: &[u8]) -> KeyStoreResult<()> {
    let temp = directory.join(format!(".account-{}.tmp", random_suffix()?));
    let mut file = open_private_file(&temp, false)?;
    let write_result = (|| {
        file.write_all(bytes).map_err(map_io)?;
        file.sync_all().map_err(map_io)?;
        fs::hard_link(&temp, destination).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                AccountKeyStoreError::AlreadyExists
            } else {
                map_io(error)
            }
        })?;
        if let Err(error) = sync_directory(directory) {
            let _ = fs::remove_file(destination);
            let _ = sync_directory(directory);
            return Err(error);
        }
        Ok(())
    })();
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temp);
        let _ = sync_directory(directory);
        return Err(error);
    }
    if let Err(error) = fs::remove_file(&temp) {
        let mapped = map_io(error);
        let _ = fs::remove_file(destination);
        let _ = sync_directory(directory);
        return Err(mapped);
    }
    if let Err(error) = sync_directory(directory) {
        let _ = fs::remove_file(destination);
        let _ = sync_directory(directory);
        return Err(error);
    }
    Ok(())
}

fn random_suffix() -> KeyStoreResult<String> {
    let mut bytes = Zeroizing::new([0u8; 16]);
    getrandom::fill(&mut *bytes).map_err(|_| AccountKeyStoreError::Inaccessible)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn path_exists(path: &Path) -> KeyStoreResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(map_io(error)),
    }
}

fn open_private_file(path: &Path, allow_existing: bool) -> KeyStoreResult<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if allow_existing {
        options.create(true);
    } else {
        options.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(map_io)?;
    let metadata = file.metadata().map_err(map_io)?;
    check_private_file(&metadata)?;
    if !metadata.is_file() {
        return Err(AccountKeyStoreError::Inaccessible);
    }
    Ok(file)
}

fn sync_directory(path: &Path) -> KeyStoreResult<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(map_io)
}

fn map_io(error: std::io::Error) -> AccountKeyStoreError {
    match error.kind() {
        std::io::ErrorKind::NotFound => AccountKeyStoreError::Missing,
        std::io::ErrorKind::PermissionDenied => AccountKeyStoreError::Inaccessible,
        std::io::ErrorKind::WouldBlock => AccountKeyStoreError::BusyLocked,
        _ => AccountKeyStoreError::Inaccessible,
    }
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> KeyStoreResult<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    if let Err(error) = builder.create(path)
        && error.kind() != std::io::ErrorKind::AlreadyExists
    {
        return Err(map_io(error));
    }
    let metadata = fs::symlink_metadata(path).map_err(map_io)?;
    check_private_directory(&metadata)
}

#[cfg(unix)]
fn check_private_directory(metadata: &fs::Metadata) -> KeyStoreResult<()> {
    use std::os::unix::fs::PermissionsExt;
    if !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(AccountKeyStoreError::Inaccessible);
    }
    Ok(())
}

#[cfg(unix)]
fn check_private_file(metadata: &fs::Metadata) -> KeyStoreResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = metadata.permissions().mode();
    if !metadata.is_file() || mode & 0o077 != 0 || mode & 0o111 != 0 {
        return Err(AccountKeyStoreError::Inaccessible);
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_private_directory(_path: &Path) -> KeyStoreResult<()> {
    Err(AccountKeyStoreError::Inaccessible)
}

#[cfg(not(unix))]
fn check_private_directory(_metadata: &fs::Metadata) -> KeyStoreResult<()> {
    Err(AccountKeyStoreError::Inaccessible)
}

#[cfg(not(unix))]
fn check_private_file(_metadata: &fs::Metadata) -> KeyStoreResult<()> {
    Err(AccountKeyStoreError::Inaccessible)
}

#[cfg(test)]
mod tests {
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
                    std::path::Path::new(&std::env::var(DIR).expect("directory"))
                        .join("credential"),
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
}
