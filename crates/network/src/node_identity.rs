//! Filesystem-protected persistent libp2p identity for unattended nodes.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use libp2p::{PeerId, identity};
use zeroize::Zeroizing;

const DIRECTORY: &str = "node-identity";
const IDENTITY_FILE: &str = "transport.key";
const LOCK_FILE: &str = "identity.lock";
const MARKER_FILE: &str = "transport.peer";
const MAGIC: &[u8; 8] = b"ANNDNID\0";
const MARKER_MAGIC: &[u8; 8] = b"ANNDNPM\0";
const VERSION: u16 = 1;
const MAX_KEY_BYTES: usize = 512;
const MAX_PEER_BYTES: usize = 128;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, thiserror::Error)]
pub enum NodeIdentityError {
    #[error("node identity file is missing")]
    Missing,
    #[error("node identity path is inaccessible")]
    Io(#[source] std::io::Error),
    #[error("node identity is already in use")]
    Busy,
    #[error("node identity path is insecure or unsupported")]
    Insecure,
    #[error("node identity file is corrupt")]
    Corrupt,
    #[error("node identity version is unsupported")]
    UnsupportedVersion,
    #[error("node identity changed; expected {expected}, found {actual}")]
    PeerIdMismatch {
        expected: Box<PeerId>,
        actual: Box<PeerId>,
    },
}

/// Owns the operator-protected transport identity file beneath a data directory.
#[derive(Clone, Debug)]
pub struct NodeIdentityStore {
    directory: PathBuf,
}

impl NodeIdentityStore {
    pub fn new(data_directory: impl AsRef<Path>) -> Self {
        Self {
            directory: data_directory.as_ref().join(DIRECTORY),
        }
    }

    /// Opens the existing transport key, creating it atomically only when absent.
    pub fn open(&self) -> Result<NodeIdentityLease, NodeIdentityError> {
        let lock = self.lock()?;
        let identity_path = self.directory.join(IDENTITY_FILE);
        let marker_path = self.directory.join(MARKER_FILE);
        let marker = read_marker(&marker_path)?;
        let (key, peer_id) = match read_key(&identity_path) {
            Ok((key, peer_id)) => {
                match marker {
                    None => write_marker_initial(&self.directory, &marker_path, peer_id)?,
                    Some(Marker::Committed(expected)) if expected == peer_id => {}
                    Some(Marker::Committed(expected)) => {
                        return Err(NodeIdentityError::PeerIdMismatch {
                            expected: Box::new(expected),
                            actual: Box::new(peer_id),
                        });
                    }
                    Some(Marker::Replacing { old, new }) if peer_id == old || peer_id == new => {
                        replace_marker(&self.directory, &marker_path, Marker::Committed(peer_id))?;
                    }
                    Some(Marker::Replacing { old, .. }) => {
                        return Err(NodeIdentityError::PeerIdMismatch {
                            expected: Box::new(old),
                            actual: Box::new(peer_id),
                        });
                    }
                }
                (key, peer_id)
            }
            Err(NodeIdentityError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                if marker.is_some() {
                    return Err(NodeIdentityError::Missing);
                }
                let key = identity::Keypair::generate_ed25519();
                match publish_new_key(&self.directory, &identity_path, &key) {
                    Ok(()) => {
                        let peer_id = key.public().to_peer_id();
                        write_marker_initial(&self.directory, &marker_path, peer_id)?;
                        (key, peer_id)
                    }
                    Err(error) if is_already_exists(&error) => {
                        let (key, peer_id) = read_key(&identity_path)?;
                        write_marker_initial(&self.directory, &marker_path, peer_id)?;
                        (key, peer_id)
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        };
        Ok(NodeIdentityLease {
            key,
            peer_id,
            _lock: lock,
        })
    }

    /// Replaces a stopped node identity only if it still has the expected PeerId.
    pub fn replace(&self, expected_peer_id: PeerId) -> Result<PeerId, NodeIdentityError> {
        let _lock = self.lock()?;
        let identity_path = self.directory.join(IDENTITY_FILE);
        let marker_path = self.directory.join(MARKER_FILE);
        let (_, actual) = read_key(&identity_path)?;
        match read_marker(&marker_path)? {
            Some(Marker::Committed(marked)) if marked == actual => {}
            Some(Marker::Replacing { old, new }) if actual == old || actual == new => {}
            Some(Marker::Committed(expected)) => {
                return Err(NodeIdentityError::PeerIdMismatch {
                    expected: Box::new(expected),
                    actual: Box::new(actual),
                });
            }
            Some(Marker::Replacing { old, .. }) => {
                return Err(NodeIdentityError::PeerIdMismatch {
                    expected: Box::new(old),
                    actual: Box::new(actual),
                });
            }
            None => write_marker_initial(&self.directory, &marker_path, actual)?,
        }
        if actual != expected_peer_id {
            return Err(NodeIdentityError::PeerIdMismatch {
                expected: Box::new(expected_peer_id),
                actual: Box::new(actual),
            });
        }

        let key = identity::Keypair::generate_ed25519();
        let temp = write_temp_key(&self.directory, &key)?;
        let replacement = key.public().to_peer_id();
        replace_marker(
            &self.directory,
            &marker_path,
            Marker::Replacing {
                old: actual,
                new: replacement,
            },
        )?;
        fs::rename(&temp, &identity_path).map_err(NodeIdentityError::Io)?;
        sync_directory(&self.directory)?;
        replace_marker(
            &self.directory,
            &marker_path,
            Marker::Committed(replacement),
        )?;
        Ok(replacement)
    }

    fn lock(&self) -> Result<File, NodeIdentityError> {
        create_private_directory(&self.directory)?;
        let path = self.directory.join(LOCK_FILE);
        reject_non_regular(&path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(path).map_err(NodeIdentityError::Io)?;
        set_private_file(&file)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Err(NodeIdentityError::Busy),
            Err(std::fs::TryLockError::Error(error)) => {
                return Err(NodeIdentityError::Io(error));
            }
        }
        Ok(file)
    }
}

/// Holds the identity lock for as long as the corresponding swarm is active.
pub struct NodeIdentityLease {
    key: identity::Keypair,
    peer_id: PeerId,
    _lock: File,
}

impl NodeIdentityLease {
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub(crate) fn into_parts(self) -> (identity::Keypair, PeerId, File) {
        (self.key, self.peer_id, self._lock)
    }
}

fn read_key(path: &Path) -> Result<(identity::Keypair, PeerId), NodeIdentityError> {
    reject_non_regular(path)?;
    let file = open_identity_file(path)?;
    validate_private_file(&file)?;
    let size = file.metadata().map_err(NodeIdentityError::Io)?.len();
    if size < 12 || size > (12 + MAX_KEY_BYTES) as u64 {
        return Err(NodeIdentityError::Corrupt);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(size as usize));
    file.take((12 + MAX_KEY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(NodeIdentityError::Io)?;
    if bytes.len() > 12 + MAX_KEY_BYTES {
        return Err(NodeIdentityError::Corrupt);
    }
    if bytes.get(..8) != Some(MAGIC) {
        return Err(NodeIdentityError::Corrupt);
    }
    let version = u16::from_be_bytes([bytes[8], bytes[9]]);
    if version != VERSION {
        return Err(NodeIdentityError::UnsupportedVersion);
    }
    let encoded_len = u16::from_be_bytes([bytes[10], bytes[11]]) as usize;
    if encoded_len == 0 || encoded_len > MAX_KEY_BYTES || bytes.len() != 12 + encoded_len {
        return Err(NodeIdentityError::Corrupt);
    }
    let key = identity::Keypair::from_protobuf_encoding(&bytes[12..])
        .map_err(|_| NodeIdentityError::Corrupt)?;
    let peer_id = key.public().to_peer_id();
    Ok((key, peer_id))
}

fn publish_new_key(
    directory: &Path,
    identity_path: &Path,
    key: &identity::Keypair,
) -> Result<(), NodeIdentityError> {
    let temp_path = write_temp_key(directory, key)?;
    match fs::hard_link(&temp_path, identity_path) {
        Ok(()) => {
            fs::remove_file(temp_path).map_err(NodeIdentityError::Io)?;
            sync_directory(directory)
        }
        Err(error) => {
            let _ = fs::remove_file(temp_path);
            Err(NodeIdentityError::Io(error))
        }
    }
}

fn write_temp_key(directory: &Path, key: &identity::Keypair) -> Result<PathBuf, NodeIdentityError> {
    let encoded = Zeroizing::new(
        key.to_protobuf_encoding()
            .map_err(|_| NodeIdentityError::Corrupt)?,
    );
    if encoded.is_empty() || encoded.len() > MAX_KEY_BYTES || encoded.len() > u16::MAX as usize {
        return Err(NodeIdentityError::Corrupt);
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(12 + encoded.len()));
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&encoded);

    write_temp_bytes(directory, &bytes)
}

fn write_temp_bytes(directory: &Path, bytes: &[u8]) -> Result<PathBuf, NodeIdentityError> {
    for _ in 0..16 {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(".identity-{}-{sequence}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&path) {
            Ok(mut file) => {
                let result = file.write_all(bytes).and_then(|()| file.sync_all());
                if let Err(error) = result {
                    drop(file);
                    let _ = fs::remove_file(path);
                    return Err(NodeIdentityError::Io(error));
                }
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(NodeIdentityError::Io(error)),
        }
    }
    Err(NodeIdentityError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a private temporary identity file",
    )))
}

#[derive(Clone, Copy)]
enum Marker {
    Committed(PeerId),
    Replacing { old: PeerId, new: PeerId },
}

fn read_marker(path: &Path) -> Result<Option<Marker>, NodeIdentityError> {
    reject_non_regular(path)?;
    let file = match open_identity_file(path) {
        Ok(file) => file,
        Err(NodeIdentityError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    validate_private_file(&file)?;
    let size = file.metadata().map_err(NodeIdentityError::Io)?.len();
    if !(13..=(15 + 2 * MAX_PEER_BYTES) as u64).contains(&size) {
        return Err(NodeIdentityError::Corrupt);
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.take((15 + 2 * MAX_PEER_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(NodeIdentityError::Io)?;
    if bytes.len() > 15 + 2 * MAX_PEER_BYTES {
        return Err(NodeIdentityError::Corrupt);
    }
    if bytes.get(..8) != Some(MARKER_MAGIC) {
        return Err(NodeIdentityError::Corrupt);
    }
    let version = u16::from_be_bytes([bytes[8], bytes[9]]);
    if version != VERSION {
        return Err(NodeIdentityError::UnsupportedVersion);
    }
    let state = bytes[10];
    let active_len = u16::from_be_bytes([bytes[11], bytes[12]]) as usize;
    if active_len == 0 || active_len > MAX_PEER_BYTES || bytes.len() < 13 + active_len {
        return Err(NodeIdentityError::Corrupt);
    }
    let active =
        PeerId::from_bytes(&bytes[13..13 + active_len]).map_err(|_| NodeIdentityError::Corrupt)?;
    match state {
        0 if bytes.len() == 13 + active_len => Ok(Some(Marker::Committed(active))),
        1 if bytes.len() >= 15 + active_len => {
            let offset = 13 + active_len;
            let pending_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            if pending_len == 0
                || pending_len > MAX_PEER_BYTES
                || bytes.len() != offset + 2 + pending_len
            {
                return Err(NodeIdentityError::Corrupt);
            }
            let pending =
                PeerId::from_bytes(&bytes[offset + 2..]).map_err(|_| NodeIdentityError::Corrupt)?;
            Ok(Some(Marker::Replacing {
                old: active,
                new: pending,
            }))
        }
        _ => Err(NodeIdentityError::Corrupt),
    }
}

fn write_marker_initial(
    directory: &Path,
    path: &Path,
    peer_id: PeerId,
) -> Result<(), NodeIdentityError> {
    let bytes = encode_marker(Marker::Committed(peer_id))?;
    let temp = write_temp_bytes(directory, &bytes)?;
    match fs::hard_link(&temp, path) {
        Ok(()) => {
            fs::remove_file(temp).map_err(NodeIdentityError::Io)?;
            sync_directory(directory)
        }
        Err(error) => {
            let _ = fs::remove_file(temp);
            Err(NodeIdentityError::Io(error))
        }
    }
}

fn replace_marker(directory: &Path, path: &Path, marker: Marker) -> Result<(), NodeIdentityError> {
    let bytes = encode_marker(marker)?;
    let temp = write_temp_bytes(directory, &bytes)?;
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(temp);
        return Err(NodeIdentityError::Io(error));
    }
    sync_directory(directory)
}

fn encode_marker(marker: Marker) -> Result<Vec<u8>, NodeIdentityError> {
    let (state, active, pending) = match marker {
        Marker::Committed(peer_id) => (0, peer_id.to_bytes(), None),
        Marker::Replacing { old, new } => (1, old.to_bytes(), Some(new.to_bytes())),
    };
    if active.is_empty()
        || active.len() > MAX_PEER_BYTES
        || pending
            .as_ref()
            .is_some_and(|bytes| bytes.is_empty() || bytes.len() > MAX_PEER_BYTES)
    {
        return Err(NodeIdentityError::Corrupt);
    }
    let mut bytes = Vec::with_capacity(15 + active.len() + pending.as_ref().map_or(0, Vec::len));
    bytes.extend_from_slice(MARKER_MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.push(state);
    bytes.extend_from_slice(&(active.len() as u16).to_be_bytes());
    bytes.extend_from_slice(&active);
    if let Some(pending) = pending {
        bytes.extend_from_slice(&(pending.len() as u16).to_be_bytes());
        bytes.extend_from_slice(&pending);
    }
    Ok(bytes)
}

fn create_private_directory(path: &Path) -> Result<(), NodeIdentityError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(NodeIdentityError::Io)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700);
        match builder.create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(NodeIdentityError::Io(error)),
        }
    }
    #[cfg(not(unix))]
    return Err(NodeIdentityError::Insecure);
    let metadata = fs::symlink_metadata(path).map_err(NodeIdentityError::Io)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(NodeIdentityError::Insecure);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(NodeIdentityError::Insecure);
        }
    }
    Ok(())
}

fn reject_non_regular(path: &Path) -> Result<(), NodeIdentityError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(NodeIdentityError::Insecure),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(NodeIdentityError::Io(error)),
    }
}

fn open_identity_file(path: &Path) -> Result<File, NodeIdentityError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(path).map_err(NodeIdentityError::Io)
}

fn set_private_file(file: &File) -> Result<(), NodeIdentityError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(NodeIdentityError::Io)?;
        validate_private_file(file)
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Err(NodeIdentityError::Insecure)
    }
}

fn validate_private_file(file: &File) -> Result<(), NodeIdentityError> {
    let metadata = file.metadata().map_err(NodeIdentityError::Io)?;
    if !metadata.is_file() {
        return Err(NodeIdentityError::Insecure);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(NodeIdentityError::Insecure);
        }
        Ok(())
    }
    #[cfg(not(unix))]
    Err(NodeIdentityError::Insecure)
}

fn sync_directory(path: &Path) -> Result<(), NodeIdentityError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(NodeIdentityError::Io)
}

fn is_already_exists(error: &NodeIdentityError) -> bool {
    matches!(error, NodeIdentityError::Io(io) if io.kind() == std::io::ErrorKind::AlreadyExists)
}

#[cfg(test)]
#[path = "tests/node_identity.rs"]
mod tests;
