#![forbid(unsafe_code)]

pub mod identity;
pub mod key_store;
pub mod matching;
pub mod notifications;
pub mod protocol;
pub mod storage;

pub use identity::{DeviceKeyPair, VerifiedCredential};
pub use key_store::{AccountKeyStore, AccountKeyStoreError, PortableAccountVault, UnlockedAccount};
pub use protocol::{ContentHash, MessageEnvelope, ProfileId, PublicProfile};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid input")]
    InvalidInput,
    #[error("credential is invalid or untrusted")]
    InvalidCredential,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("message has expired or is not yet valid")]
    InvalidTime,
    #[error("resource limit exceeded")]
    LimitExceeded,
    #[error("recipient is not authorized")]
    Unauthorized,
    #[error("record not found")]
    NotFound,
    #[error("message was already processed")]
    Duplicate,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("serialization failed")]
    Serialization,
    #[error("storage operation failed: {0}")]
    Storage(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
