//! High-level, owner-scoped application API.
//!
//! This module is the boundary used by applications. It owns the unlocked account and
//! hides SQLite, message construction, and transport session details.

use std::{collections::HashSet, path::PathBuf, sync::Arc};

use annoda_core::{
    AccountKeyStore, AccountKeyStoreError, PortableAccountVault, UnlockedAccount,
    identity::{TrustedIssuers, VerifiedCredential},
    matching::{ContactHandle, MatchState},
    protocol::ProfileId,
    protocol::{
        ContentHash, ContentLease, MAX_PROFILE_PHOTOS, MailboxParcel, PhotoManifest, PublicProfile,
    },
    storage::{
        DeliveryFailureKind as CoreDeliveryFailureKind, NotificationEvent, NotificationPreferences,
        OperationRecord, OutgoingOperationKind, OutgoingOperationStatus, PeerStorage,
        StorageLimits,
    },
};
use annoda_intelligence::ranking::{EncoderMode, PhotoEmbedding, PhotoEncoder, RankingError};
use annoda_intelligence::safety::{
    ClassifierMode, PhotoProcessor, PhotoSafetyClassifier, SafetyError, ValidatedPhoto,
};
use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

use crate::{
    BootstrapPeer, Clock, NodeConfig, PeerNode, SyncBudget, SyncCancellationToken, SyncContext,
    SyncError, SyncPeerAddress, SyncReport,
    sync::validate_budget,
    sync::{AccountSyncLock, run_session},
    sync_once,
    transfer::TransferMeter,
};

const MAX_PAGE_SIZE: usize = 64;
const MAX_DISCOVERY_SCAN: usize = 512;

/// Construction settings for one local application account.
#[derive(Clone)]
pub struct ClientConfig {
    /// Private directory containing the encrypted account vault and local database.
    pub data_dir: PathBuf,
    /// Stable volunteer-node identity directory used by finite outbound sessions.
    pub transport_data_dir: PathBuf,
    /// Explicitly configured reachable volunteer peers.
    pub peers: Vec<SyncPeerAddress>,
    /// Current trusted credential issuer set.
    pub issuers: TrustedIssuers,
    /// Per-operation network ceilings.
    pub sync_budget: SyncBudget,
    /// Injectable clock for deterministic application tests.
    pub clock: Arc<dyn Clock>,
    safety_classifier: Option<Arc<dyn PhotoSafetyClassifier>>,
    allow_development_safety_fixture: bool,
    photo_encoder: Option<Arc<dyn PhotoEncoder + Send + Sync>>,
    allow_development_encoder_fixture: bool,
}

impl ClientConfig {
    pub fn new(
        data_dir: impl Into<PathBuf>,
        peers: Vec<SyncPeerAddress>,
        issuers: TrustedIssuers,
    ) -> Self {
        let data_dir = data_dir.into();
        Self {
            transport_data_dir: data_dir.join("transport"),
            data_dir,
            peers,
            issuers,
            sync_budget: SyncBudget::default(),
            clock: Arc::new(crate::SystemClock),
            safety_classifier: None,
            allow_development_safety_fixture: false,
            photo_encoder: None,
            allow_development_encoder_fixture: false,
        }
    }

    pub fn with_sync_budget(mut self, budget: SyncBudget) -> Self {
        self.sync_budget = budget;
        self
    }

    pub fn with_transport_data_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.transport_data_dir = path.into();
        self
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Injects the replaceable local safety implementation. Fixture classifiers need explicit opt-in.
    pub fn with_safety_classifier(
        mut self,
        classifier: Arc<dyn PhotoSafetyClassifier>,
        allow_development_fixture: bool,
    ) -> Self {
        self.safety_classifier = Some(classifier);
        self.allow_development_safety_fixture = allow_development_fixture;
        self
    }

    /// Injects local photo embedding; deterministic development encoders need explicit opt-in.
    pub fn with_photo_encoder(
        mut self,
        encoder: Arc<dyn PhotoEncoder + Send + Sync>,
        allow_development_fixture: bool,
    ) -> Self {
        self.photo_encoder = Some(encoder);
        self.allow_development_encoder_fixture = allow_development_fixture;
        self
    }
}

/// Public identity material provided to an issuer adapter; contains no private key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentitySummary {
    pub profile_id: ProfileId,
    pub signing_public_key: [u8; 32],
    pub encryption_public_key: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageCursor(pub Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<PageCursor>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryQuery {
    pub minimum_age: u8,
    pub maximum_age: u8,
    pub page_size: u8,
    pub cursor: Option<PageCursor>,
    /// Geographic filtering is unsupported by signed profile v1.
    pub coarse_region: Option<String>,
}

impl Default for DiscoveryQuery {
    fn default() -> Self {
        Self {
            minimum_age: 18,
            maximum_age: u8::MAX,
            page_size: 20,
            cursor: None,
            coarse_region: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CandidateProfile {
    pub profile: PublicProfile,
    pub score: Option<f64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPhotoDto {
    pub bytes: Vec<u8>,
    pub hash: ContentHash,
    pub media_type: String,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationReceipt {
    pub operation_id: [u8; 16],
    pub kind: OutgoingOperationKind,
    pub status: OutgoingOperationStatus,
    pub acknowledged_peers: u32,
    pub required_acknowledgements: u32,
    pub pending_items: Vec<[u8; 32]>,
    pub failures: Vec<DeliveryFailure>,
    pub retry_recommended: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryFailureReason {
    Unreachable,
    Rejected,
    Budget,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryFailure {
    pub peer_id: String,
    pub item_hash: [u8; 32],
    pub reason: DeliveryFailureReason,
}

impl From<OperationRecord> for OperationReceipt {
    fn from(operation: OperationRecord) -> Self {
        let required = operation
            .peer_targets
            .len()
            .saturating_mul(operation.items.len());
        let pending_items = operation
            .items
            .iter()
            .copied()
            .filter(|item| {
                operation.peer_targets.iter().any(|peer| {
                    !operation
                        .peer_item_acks
                        .iter()
                        .any(|ack| ack.peer_id == *peer && ack.item == *item && ack.accepted)
                })
            })
            .collect();
        Self {
            operation_id: operation.id,
            kind: operation.kind,
            status: operation.status,
            acknowledged_peers: operation
                .peer_targets
                .iter()
                .filter(|peer| {
                    !operation.items.is_empty()
                        && operation
                            .items
                            .iter()
                            .all(|item| operation_has_ack(&operation, peer, *item))
                })
                .count() as u32,
            required_acknowledgements: required.min(u32::MAX as usize) as u32,
            pending_items,
            failures: operation
                .peer_item_acks
                .iter()
                .filter_map(|ack| {
                    ack.failure.map(|reason| DeliveryFailure {
                        peer_id: ack.peer_id.clone(),
                        item_hash: ack.item,
                        reason: match reason {
                            CoreDeliveryFailureKind::Unreachable => {
                                DeliveryFailureReason::Unreachable
                            }
                            CoreDeliveryFailureKind::Rejected => DeliveryFailureReason::Rejected,
                            CoreDeliveryFailureKind::Budget => DeliveryFailureReason::Budget,
                            CoreDeliveryFailureKind::Cancelled => DeliveryFailureReason::Cancelled,
                        },
                    })
                })
                .collect(),
            retry_recommended: matches!(
                operation.status,
                OutgoingOperationStatus::Pending | OutgoingOperationStatus::Partial
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IncomingLike {
    pub sender: ProfileId,
    pub state: annoda_core::matching::MatchState,
    pub credential: VerifiedCredential,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatchSummary {
    pub peer: ProfileId,
    pub match_id: [u8; 32],
    pub credential: VerifiedCredential,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationReceipt {
    pub operation: OperationReceipt,
    pub revision: u64,
    pub replicated_peers: u32,
}

#[derive(Serialize, Deserialize)]
struct PublicationWork {
    profile: PublicProfile,
    photos: Vec<(PhotoManifest, ContentLease, Vec<u8>)>,
}

/// Stable categories suitable for mapping into a native application's error model.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("input is invalid or exceeds a configured bound")]
    InvalidInput,
    #[error("account is locked or this action is unauthorized")]
    Unauthorized,
    #[error("credential is untrusted or is bound to another account")]
    UntrustedIdentity,
    #[error("credential has expired")]
    CredentialExpired,
    #[error("required photo safety classifier is unavailable")]
    SafetyUnavailable,
    #[error("photo was rejected by the configured safety policy")]
    SafetyRejected,
    #[error("configured peers could not complete the operation")]
    NetworkUnavailable,
    #[error("local storage is full")]
    StorageFull,
    #[error("operation was cancelled")]
    Cancelled,
    #[error("operation is still pending")]
    Pending,
    #[error("operation is not supported by this protocol version")]
    Unsupported,
    #[error("account vault is already open")]
    Busy,
    #[error("local storage failed")]
    Storage,
    #[error("account vault failed")]
    Vault,
    #[error("account vault does not exist")]
    AccountMissing,
    #[error("account vault is inaccessible")]
    AccountInaccessible,
    #[error("account vault authentication failed")]
    AuthenticationFailed,
    #[error("account vault is corrupt")]
    CorruptVault,
    #[error("account vault version is unsupported")]
    UnsupportedVaultVersion,
    #[error("account vault already exists")]
    AccountAlreadyExists,
    #[error("internal application error")]
    Internal,
}

impl From<AccountKeyStoreError> for ClientError {
    fn from(value: AccountKeyStoreError) -> Self {
        match value {
            AccountKeyStoreError::BusyLocked => Self::Busy,
            AccountKeyStoreError::InvalidInput => Self::InvalidInput,
            AccountKeyStoreError::Missing => Self::AccountMissing,
            AccountKeyStoreError::Inaccessible => Self::AccountInaccessible,
            AccountKeyStoreError::AuthenticationFailed => Self::AuthenticationFailed,
            AccountKeyStoreError::CorruptFormat => Self::CorruptVault,
            AccountKeyStoreError::UnsupportedVersion => Self::UnsupportedVaultVersion,
            AccountKeyStoreError::AlreadyExists => Self::AccountAlreadyExists,
        }
    }
}

impl From<SyncError> for ClientError {
    fn from(value: SyncError) -> Self {
        match value {
            SyncError::InvalidBudget | SyncError::InvalidContext => Self::InvalidInput,
            SyncError::AccountCredentialMismatch => Self::UntrustedIdentity,
            SyncError::Busy => Self::Busy,
            SyncError::Startup => Self::NetworkUnavailable,
            SyncError::Storage => Self::Storage,
        }
    }
}

/// An opened account and its serialized application access.
pub struct AnnodaClient {
    config: ClientConfig,
    account: Option<UnlockedAccount>,
    credential: Option<VerifiedCredential>,
    state_path: PathBuf,
}

impl AnnodaClient {
    /// Creates a new account. Existing vaults are never replaced.
    pub fn create(config: ClientConfig, passphrase: &[u8]) -> Result<Self, ClientError> {
        let vault = PortableAccountVault::new(&config.data_dir);
        let account = vault.create(passphrase)?;
        Self::from_account(config, account)
    }

    /// Opens an existing account without creating or replacing identity keys.
    pub fn open(config: ClientConfig, passphrase: &[u8]) -> Result<Self, ClientError> {
        let vault = PortableAccountVault::new(&config.data_dir);
        let account = vault.unlock(passphrase)?;
        Self::from_account(config, account)
    }

    fn from_account(config: ClientConfig, account: UnlockedAccount) -> Result<Self, ClientError> {
        let identity = account.identity().profile_id();
        let state_path = config.data_dir.join("client-state.sqlite3");
        std::fs::create_dir_all(&config.data_dir).map_err(|_| ClientError::Storage)?;
        let mut storage = PeerStorage::open(&state_path, StorageLimits::default())
            .map_err(|_| ClientError::Storage)?;
        storage
            .bind_application_owner(identity)
            .map_err(map_core_error)?;
        let credential = storage
            .load_credential(identity)
            .map_err(|_| ClientError::Storage)?
            .map(|credential| {
                if credential.profile_id() != identity
                    || credential.claims.signing_key != account.identity().signing_public_key()
                    || credential.claims.encryption_key
                        != account.identity().encryption_public_key()
                {
                    return Err(ClientError::UntrustedIdentity);
                }
                Ok(credential)
            })
            .transpose()?;
        Ok(Self {
            config,
            account: Some(account),
            credential,
            state_path,
        })
    }

    fn account(&self) -> Result<&UnlockedAccount, ClientError> {
        self.account.as_ref().ok_or(ClientError::Unauthorized)
    }

    fn owner(&self) -> Result<ProfileId, ClientError> {
        Ok(self.account()?.identity().profile_id())
    }

    fn now(&self) -> u64 {
        self.config.clock.now()
    }

    fn credential_ref(&self) -> Result<&VerifiedCredential, ClientError> {
        self.credential
            .as_ref()
            .ok_or(ClientError::UntrustedIdentity)
    }

    pub fn identity_summary(&self) -> Result<IdentitySummary, ClientError> {
        let identity = self.account()?.identity();
        Ok(IdentitySummary {
            profile_id: identity.profile_id(),
            signing_public_key: identity.signing_public_key(),
            encryption_public_key: identity.encryption_public_key().to_vec(),
        })
    }

    /// Returns this account's current, issuer-verified published profile from local storage.
    pub fn published_profile(&self) -> Result<Option<PublicProfile>, ClientError> {
        let owner = self.owner()?;
        let storage = self.open_storage()?;
        let profile = storage
            .get_profile(owner, &self.config.issuers, self.now())
            .map_err(map_core_error)?;
        if profile.is_some() {
            return Ok(profile);
        }
        if storage
            .latest_profile_revision(owner)
            .map_err(map_core_error)?
            .is_some()
        {
            return Err(ClientError::CredentialExpired);
        }
        Ok(None)
    }

    /// Verifies issuer trust, current validity, and exact binding to both persistent account keys.
    pub fn attach_credential(&mut self, credential: VerifiedCredential) -> Result<(), ClientError> {
        let identity = self.account()?.identity();
        verify_credential(&credential, &self.config.issuers, self.now())?;
        if credential.profile_id() != identity.profile_id()
            || credential.claims.signing_key != identity.signing_public_key()
            || credential.claims.encryption_key != identity.encryption_public_key()
        {
            return Err(ClientError::UntrustedIdentity);
        }
        let mut storage = self.open_storage()?;
        storage
            .save_credential(self.owner()?, &credential, &self.config.issuers, self.now())
            .map_err(map_core_error)?;
        self.credential = Some(credential);
        Ok(())
    }

    pub fn credential(&self) -> Result<VerifiedCredential, ClientError> {
        let credential = self.credential_ref()?;
        verify_credential(credential, &self.config.issuers, self.now())?;
        Ok(credential.clone())
    }

    fn open_storage(&self) -> Result<PeerStorage, ClientError> {
        self.account()?;
        PeerStorage::open_with_busy_timeout(
            &self.state_path,
            StorageLimits::default(),
            self.config
                .sync_budget
                .max_duration
                .min(std::time::Duration::from_millis(25)),
        )
        .map_err(map_core_error)
    }

    fn photo_processor(&self) -> Result<PhotoProcessor<ClassifierAdapter>, ClientError> {
        let classifier = self
            .config
            .safety_classifier
            .clone()
            .ok_or(ClientError::SafetyUnavailable)?;
        PhotoProcessor::new(
            ClassifierAdapter(classifier),
            self.config.allow_development_safety_fixture,
        )
        .map_err(map_safety_error)
    }

    async fn start_network(
        &self,
    ) -> Result<
        (
            PeerNode,
            Arc<TransferMeter>,
            Vec<PeerId>,
            tokio::time::Instant,
        ),
        ClientError,
    > {
        self.account()?;
        if self.config.peers.len() > 256 {
            return Err(ClientError::InvalidInput);
        }
        validate_budget(
            &self.config.sync_budget,
            &crate::PeerContributionPolicy::default(),
        )
        .map_err(ClientError::from)?;
        let mut seen = HashSet::new();
        let mut peers = Vec::with_capacity(self.config.peers.len());
        for peer in &self.config.peers {
            let peer_id = peer
                .peer_id
                .parse::<PeerId>()
                .map_err(|_| ClientError::InvalidInput)?;
            let address = peer
                .address
                .parse::<Multiaddr>()
                .map_err(|_| ClientError::InvalidInput)?;
            if seen.insert(peer_id) && peers.len() < self.config.sync_budget.max_peers as usize {
                peers.push(BootstrapPeer { peer_id, address });
            }
        }
        let peer_ids = peers.iter().map(|peer| peer.peer_id).collect::<Vec<_>>();
        let allowed = peer_ids.iter().copied().collect::<HashSet<_>>();
        let budget = &self.config.sync_budget;
        let meter = TransferMeter::new(budget.max_download_bytes, budget.max_upload_bytes);
        let config = NodeConfig {
            listen_addresses: Vec::new(),
            bootstrap_peers: peers,
            data_dir: self.config.transport_data_dir.clone(),
            request_timeout: budget.request_timeout,
            max_connections: (peer_ids.len() as u32).max(1),
            clock: self.config.clock.clone(),
            ..NodeConfig::default()
        };
        let deadline = tokio::time::Instant::now() + budget.max_duration;
        let node =
            PeerNode::start_sync(config, self.config.issuers.clone(), meter.clone(), allowed)
                .await
                .map_err(|_| ClientError::NetworkUnavailable)?;
        Ok((node, meter, peer_ids, deadline))
    }

    async fn request(
        &self,
        node: &PeerNode,
        peer: PeerId,
        request: crate::RpcRequest,
        cancellation: &SyncCancellationToken,
        deadline: tokio::time::Instant,
    ) -> Result<crate::RpcResponse, ClientError> {
        if cancellation.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        tokio::select! {
            _ = cancellation.inner().cancelled() => Err(ClientError::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Err(ClientError::NetworkUnavailable),
            response = node.request(peer, request) => response.map_err(|_| ClientError::NetworkUnavailable),
        }
    }

    pub async fn sync(
        &mut self,
        cancellation: SyncCancellationToken,
    ) -> Result<SyncReport, ClientError> {
        if self.config.sync_budget.max_mailbox_items == 0
            || self.config.sync_budget.max_download_bytes == 0
            || self.config.sync_budget.max_upload_bytes == 0
        {
            validate_budget(
                &self.config.sync_budget,
                &crate::PeerContributionPolicy::default(),
            )
            .map_err(ClientError::from)?;
            return Ok(SyncReport {
                status: crate::SyncStatus::BudgetExhausted,
                verified_items: 0,
                rejected_items: 0,
                downloaded_bytes: 0,
                uploaded_bytes: 0,
                contacted_peers: Vec::new(),
                new_events: Vec::new(),
                confirmed_replicas: 0,
                deferred_reasons: Vec::new(),
            });
        }
        let account = self.account()?;
        let credential = self.credential()?.clone();
        let context = self.sync_context(credential)?;
        if self.config.peers.is_empty() {
            return sync_once(
                account,
                context,
                self.config.sync_budget.clone(),
                cancellation,
            )
            .await
            .map_err(ClientError::from);
        }
        validate_budget(
            &self.config.sync_budget,
            &crate::PeerContributionPolicy::default(),
        )
        .map_err(ClientError::from)?;
        if cancellation.is_cancelled() {
            return Ok(SyncReport {
                status: crate::SyncStatus::Cancelled,
                verified_items: 0,
                rejected_items: 0,
                downloaded_bytes: 0,
                uploaded_bytes: 0,
                contacted_peers: Vec::new(),
                new_events: Vec::new(),
                confirmed_replicas: 0,
                deferred_reasons: Vec::new(),
            });
        }
        let selected = self.selected_bootstrap_peers()?;
        if selected.is_empty() {
            return sync_once(
                account,
                context,
                self.config.sync_budget.clone(),
                cancellation,
            )
            .await
            .map_err(ClientError::from);
        }
        let deadline = tokio::time::Instant::now() + self.config.sync_budget.max_duration;
        let _lock = AccountSyncLock::acquire(&self.state_path).map_err(ClientError::from)?;
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let mut storage = PeerStorage::open_with_busy_timeout(
            &self.state_path,
            StorageLimits::default(),
            remaining.min(std::time::Duration::from_millis(25)),
        )
        .map_err(map_core_error)?;
        let (node, meter, peers, startup_deadline) = self.start_network().await?;
        let deadline = deadline.min(startup_deadline);
        let pending = scan_pending_operations(
            &mut storage,
            self.owner()?,
            self.now(),
            usize::from(self.config.sync_budget.max_mailbox_items).min(MAX_PAGE_SIZE),
        )?;
        for operation in pending {
            if cancellation.is_cancelled() || tokio::time::Instant::now() >= deadline {
                break;
            }
            let result = match operation.kind {
                OutgoingOperationKind::Publication => {
                    match postcard::from_bytes(&operation.exact_payload) {
                        Ok(work) => {
                            self.deliver_publication_on(
                                operation,
                                work,
                                &node,
                                &peers,
                                &cancellation,
                                deadline,
                            )
                            .await
                        }
                        Err(_) => Err(ClientError::Storage),
                    }
                }
                OutgoingOperationKind::Like | OutgoingOperationKind::Contact => {
                    self.deliver_parcel_on(operation, &node, &peers, &cancellation, deadline)
                        .await
                }
            };
            match result {
                Ok(_) | Err(ClientError::NetworkUnavailable | ClientError::Cancelled) => {}
                Err(error) => {
                    node.shutdown().await;
                    return Err(error);
                }
            }
        }
        let report = run_session(
            account,
            &context,
            &self.config.sync_budget,
            &cancellation,
            deadline,
            &node,
            &mut storage,
            &selected,
            &meter,
        )
        .await;
        node.shutdown().await;
        let mut report = report.map_err(ClientError::from)?;
        report.downloaded_bytes = meter.downloaded();
        report.uploaded_bytes = meter.uploaded();
        if cancellation.is_cancelled() {
            report.status = crate::SyncStatus::Cancelled;
        } else if tokio::time::Instant::now() >= deadline {
            report.status = crate::SyncStatus::Partial;
        }
        if storage
            .pending_operations(self.owner()?, 1)
            .map_err(map_core_error)?
            .is_empty()
            && report.status == crate::SyncStatus::Partial
        {
            // Keep the lower-level mailbox result when no durable outgoing work remains.
        } else if report.status == crate::SyncStatus::Complete
            && !storage
                .pending_operations(self.owner()?, 1)
                .map_err(map_core_error)?
                .is_empty()
        {
            report.status = crate::SyncStatus::Partial;
        }
        Ok(report)
    }

    fn sync_context(&self, credential: VerifiedCredential) -> Result<SyncContext, ClientError> {
        SyncContext::new(
            credential,
            self.config.issuers.clone(),
            self.state_path.clone(),
            self.config.transport_data_dir.clone(),
            self.config.peers.clone(),
        )
        .map(|context| context.with_clock(self.config.clock.clone()))
        .map_err(ClientError::from)
    }

    fn selected_bootstrap_peers(&self) -> Result<Vec<BootstrapPeer>, ClientError> {
        let mut seen = HashSet::new();
        let mut selected = Vec::new();
        for peer in &self.config.peers {
            let peer_id = peer
                .peer_id
                .parse::<PeerId>()
                .map_err(|_| ClientError::InvalidInput)?;
            if !seen.insert(peer_id) {
                continue;
            }
            let address = peer
                .address
                .parse::<Multiaddr>()
                .map_err(|_| ClientError::InvalidInput)?;
            selected.push(BootstrapPeer { peer_id, address });
            if selected.len() >= self.config.sync_budget.max_peers as usize {
                break;
            }
        }
        Ok(selected)
    }

    pub async fn publish_profile(
        &mut self,
        photos: Vec<Vec<u8>>,
    ) -> Result<PublicationReceipt, ClientError> {
        self.publish_profile_with_cancellation(photos, SyncCancellationToken::new())
            .await
    }

    pub async fn publish_profile_with_cancellation(
        &mut self,
        photos: Vec<Vec<u8>>,
        cancellation: SyncCancellationToken,
    ) -> Result<PublicationReceipt, ClientError> {
        if photos.is_empty() || photos.len() > MAX_PROFILE_PHOTOS || self.config.peers.is_empty() {
            return Err(ClientError::InvalidInput);
        }
        if cancellation.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        let processor = self.photo_processor()?;
        let normalized = photos
            .iter()
            .map(|photo| {
                processor
                    .prepare_outgoing(photo, 0.5)
                    .map_err(map_safety_error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut seen = HashSet::new();
        if normalized
            .iter()
            .any(|photo| !seen.insert(photo.content_hash))
        {
            return Err(ClientError::InvalidInput);
        }

        let credential = self.credential()?;
        let owner = self.owner()?;
        let now = self.now();
        let expires_at = credential
            .claims
            .expires_at
            .min(now.saturating_add(24 * 60 * 60));
        if expires_at <= now {
            return Err(ClientError::CredentialExpired);
        }
        let mut storage = self.open_storage()?;
        let revision = storage
            .latest_profile_revision(owner)
            .map_err(map_core_error)?
            .map_or(1, |revision| revision.saturating_add(1));
        if revision == u64::MAX {
            return Err(ClientError::Unsupported);
        }
        let manifests = normalized
            .iter()
            .map(|photo| {
                PhotoManifest::from_bytes(&photo.bytes, photo.media_type).map_err(map_core_error)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let profile = PublicProfile::create_revisioned(
            self.account()?.identity(),
            credential.clone(),
            manifests.clone(),
            revision,
            expires_at,
            &self.config.issuers,
            now,
        )
        .map_err(map_core_error)?;
        let leases = manifests
            .iter()
            .map(|manifest| {
                ContentLease::issue(
                    self.account()?.identity(),
                    &credential,
                    manifest,
                    now,
                    expires_at,
                    &self.config.issuers,
                )
                .map_err(map_core_error)
            })
            .collect::<Result<Vec<_>, ClientError>>()?;
        let photo_records = manifests
            .into_iter()
            .zip(leases)
            .zip(normalized)
            .map(|((manifest, lease), photo)| (manifest, lease, photo.bytes))
            .collect::<Vec<_>>();
        let work = PublicationWork {
            profile: profile.clone(),
            photos: photo_records.clone(),
        };
        let exact_payload = postcard::to_allocvec(&work).map_err(|_| ClientError::Internal)?;
        let mut operation_nonce = [0u8; 16];
        getrandom::fill(&mut operation_nonce).map_err(|_| ClientError::Internal)?;
        let idempotency_key = operation_key(b"publication", owner, operation_nonce);
        let profile_item = profile_item_hash(&profile)?;
        let mut items = vec![profile_item];
        items.extend(photo_records.iter().map(|photo| photo.0.hash.0));
        let peer_targets = self
            .selected_peer_strings()
            .into_iter()
            .map(|peer| peer.to_string())
            .collect::<Vec<_>>();
        if peer_targets.is_empty() {
            return Err(ClientError::NetworkUnavailable);
        }
        let operation = storage
            .save_publication_bundle(
                owner,
                &profile,
                &photo_records,
                &self.config.issuers,
                now,
                idempotency_key,
                exact_payload,
                peer_targets,
                items,
                expires_at,
            )
            .map_err(map_core_error)?;
        drop(storage);
        let operation = self
            .deliver_publication(operation, work, &cancellation)
            .await?;
        let replicated_peers = operation
            .peer_targets
            .iter()
            .filter(|peer| {
                !operation.items.is_empty()
                    && operation
                        .items
                        .iter()
                        .all(|item| operation_has_ack(&operation, peer, *item))
            })
            .count() as u32;
        Ok(PublicationReceipt {
            operation: operation.into(),
            revision,
            replicated_peers,
        })
    }

    async fn deliver_publication(
        &mut self,
        operation: OperationRecord,
        work: PublicationWork,
        cancellation: &SyncCancellationToken,
    ) -> Result<OperationRecord, ClientError> {
        let (node, _meter, peers, deadline) = self.start_network().await?;
        let result = self
            .deliver_publication_on(operation, work, &node, &peers, cancellation, deadline)
            .await;
        node.shutdown().await;
        result
    }

    async fn deliver_publication_on(
        &self,
        mut operation: OperationRecord,
        work: PublicationWork,
        node: &PeerNode,
        peers: &[PeerId],
        cancellation: &SyncCancellationToken,
        deadline: tokio::time::Instant,
    ) -> Result<OperationRecord, ClientError> {
        if operation.expires_at <= self.now() {
            self.open_storage()?
                .fail_operation(self.owner()?, operation.id)
                .map_err(map_core_error)?;
            return Err(ClientError::CredentialExpired);
        }
        for peer in peers {
            let peer_key = peer.to_string();
            if !operation.peer_targets.contains(&peer_key) {
                continue;
            }
            let profile_item = profile_item_hash(&work.profile)?;
            let profile_ack = if operation_has_ack(&operation, &peer_key, profile_item) {
                true
            } else {
                let response = self
                    .request(
                        node,
                        *peer,
                        crate::RpcRequest::PutProfile {
                            profile: work.profile.clone(),
                        },
                        cancellation,
                        deadline,
                    )
                    .await;
                match response {
                    Ok(crate::RpcResponse::Ack) => true,
                    other => {
                        operation = self.record_delivery_failure(
                            operation.id,
                            &peer_key,
                            profile_item,
                            failure_kind(&other, cancellation, deadline),
                        )?;
                        false
                    }
                }
            };
            if profile_ack && !operation_has_ack(&operation, &peer_key, profile_item) {
                operation = self.ack_operation(operation.id, &peer_key, profile_item)?;
            }
            if !profile_ack {
                if cancellation.is_cancelled() {
                    return Err(ClientError::Cancelled);
                }
                continue;
            }
            for (manifest, lease, bytes) in &work.photos {
                if operation_has_ack(&operation, &peer_key, manifest.hash.0) {
                    continue;
                }
                if cancellation.is_cancelled() {
                    return Err(ClientError::Cancelled);
                }
                let response = self
                    .request(
                        node,
                        *peer,
                        crate::RpcRequest::PutPhoto {
                            manifest: manifest.clone(),
                            lease: lease.clone(),
                            owner: work.profile.credential.clone(),
                            blob: bytes.clone(),
                        },
                        cancellation,
                        deadline,
                    )
                    .await;
                let accepted = matches!(response, Ok(crate::RpcResponse::Ack));
                if accepted {
                    operation = self.ack_operation(operation.id, &peer_key, manifest.hash.0)?;
                } else {
                    operation = self.record_delivery_failure(
                        operation.id,
                        &peer_key,
                        manifest.hash.0,
                        failure_kind(&response, cancellation, deadline),
                    )?;
                }
                if !accepted {
                    if matches!(response, Err(ClientError::Cancelled)) {
                        return Err(ClientError::Cancelled);
                    }
                    break;
                }
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
        }
        Ok(operation)
    }

    pub async fn discover(
        &mut self,
        query: DiscoveryQuery,
    ) -> Result<Page<CandidateProfile>, ClientError> {
        self.discover_with_cancellation(query, SyncCancellationToken::new())
            .await
    }

    pub async fn discover_with_cancellation(
        &mut self,
        query: DiscoveryQuery,
        cancellation: SyncCancellationToken,
    ) -> Result<Page<CandidateProfile>, ClientError> {
        validate_discovery_query(&query)?;
        if query.coarse_region.is_some() {
            return Err(ClientError::Unsupported);
        }
        let owner = self.owner()?;
        let model_bytes = self
            .open_storage()?
            .load_preference_model(owner)
            .map_err(map_core_error)?;
        let model_hash = model_bytes
            .as_deref()
            .map(blake3::hash)
            .map(|hash| *hash.as_bytes())
            .unwrap_or([0; 32]);
        let filter_key = discovery_filter_key(&query, model_hash);
        let after = query
            .cursor
            .as_ref()
            .map(|cursor| decode_discovery_cursor(&cursor.0, owner, filter_key))
            .transpose()?;
        let (node, _meter, peers, deadline) = self.start_network().await?;
        let mut remote = Vec::new();
        for peer in &peers {
            if cancellation.is_cancelled() {
                node.shutdown().await;
                return Err(ClientError::Cancelled);
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            if let Ok(crate::RpcResponse::Profiles(profiles)) = self
                .request(
                    &node,
                    *peer,
                    crate::RpcRequest::ListProfiles { limit: 50 },
                    &cancellation,
                    deadline,
                )
                .await
            {
                remote.extend(profiles);
            }
        }
        node.shutdown().await;
        if cancellation.is_cancelled() {
            return Err(ClientError::Cancelled);
        }
        let now = self.now();
        let mut storage = self.open_storage()?;
        let mut unique = std::collections::BTreeMap::<ProfileId, PublicProfile>::new();
        for profile in remote {
            if profile.verify(&self.config.issuers, now).is_err() || profile.owner == owner {
                continue;
            }
            match unique.get(&profile.owner) {
                Some(previous) if previous.revision >= profile.revision => {}
                _ => {
                    unique.insert(profile.owner, profile);
                }
            }
        }
        for profile in unique.values() {
            storage
                .cache_candidate(owner, profile, &self.config.issuers, now)
                .map_err(map_core_error)?;
        }
        let mut excluded = storage
            .seen_profiles(owner, 512)
            .map_err(map_core_error)?
            .into_iter()
            .collect::<HashSet<_>>();
        let mut match_after = None;
        let mut scanned_matches = 0usize;
        loop {
            let records = storage
                .match_records_after(owner, match_after, MAX_PAGE_SIZE)
                .map_err(map_core_error)?;
            if records.is_empty() {
                break;
            }
            scanned_matches = scanned_matches.saturating_add(records.len());
            if scanned_matches > MAX_DISCOVERY_SCAN {
                return Err(ClientError::StorageFull);
            }
            excluded.extend(
                records
                    .iter()
                    .filter(|record| {
                        matches!(record.state(), MatchState::Blocked | MatchState::Rejected)
                    })
                    .map(|record| record.peer()),
            );
            match_after = records.last().map(|record| record.peer());
        }
        let mut profiles = Vec::new();
        let mut scan_after = None;
        loop {
            let batch = storage
                .candidate_profiles_after(
                    owner,
                    &self.config.issuers,
                    now,
                    scan_after,
                    MAX_PAGE_SIZE,
                )
                .map_err(map_core_error)?;
            if batch.is_empty() {
                break;
            }
            if profiles.len().saturating_add(batch.len()) > MAX_DISCOVERY_SCAN {
                return Err(ClientError::StorageFull);
            }
            scan_after = batch.last().map(|profile| profile.owner);
            profiles.extend(batch);
        }
        let mut eligible = profiles
            .into_iter()
            .filter(|profile| {
                profile.credential.claims.age_at_issue >= query.minimum_age
                    && profile.credential.claims.age_at_issue <= query.maximum_age
                    && !excluded.contains(&profile.owner)
            })
            .map(|profile| {
                let score = profile
                    .photos
                    .first()
                    .map(|photo| self.score_cached_profile(profile.owner, photo.hash.0))
                    .transpose()?
                    .unwrap_or(0.5);
                Ok((profile.owner, score, profile))
            })
            .collect::<Result<Vec<_>, ClientError>>()?;
        eligible.sort_by(|left, right| {
            right
                .1
                .total_cmp(&left.1)
                .then_with(|| left.0.cmp(&right.0))
        });
        let snapshot_hash = discovery_snapshot_hash(&eligible);
        if after
            .as_ref()
            .is_some_and(|cursor| cursor.snapshot_hash != snapshot_hash)
        {
            return Err(ClientError::InvalidInput);
        }
        if let Some(cursor) = after {
            eligible.retain(|(id, score, _)| {
                score.total_cmp(&cursor.after_score).is_lt()
                    || (score.total_cmp(&cursor.after_score).is_eq() && *id > cursor.after_id)
            });
        }
        let page_size = query.page_size as usize;
        let has_more = eligible.len() > page_size;
        eligible.truncate(page_size);
        let next_cursor = if has_more {
            eligible
                .last()
                .map(|(id, score, _)| {
                    encode_discovery_cursor(owner, filter_key, snapshot_hash, *score, *id)
                })
                .transpose()?
        } else {
            None
        };
        Ok(Page {
            items: eligible
                .into_iter()
                .map(|(_, score, profile)| CandidateProfile {
                    score: Some(score),
                    profile,
                })
                .collect(),
            next_cursor,
        })
    }

    pub async fn fetch_photo(
        &mut self,
        owner: ProfileId,
        hash: ContentHash,
    ) -> Result<ValidatedPhotoDto, ClientError> {
        self.fetch_photo_with_cancellation(owner, hash, SyncCancellationToken::new())
            .await
    }

    pub async fn fetch_photo_with_cancellation(
        &mut self,
        owner: ProfileId,
        hash: ContentHash,
        cancellation: SyncCancellationToken,
    ) -> Result<ValidatedPhotoDto, ClientError> {
        let cached_profile = self
            .open_storage()?
            .candidate_profile(self.owner()?, owner, &self.config.issuers, self.now())
            .map_err(map_core_error)?;
        let (node, _meter, peers, deadline) = self.start_network().await?;
        let mut profile = cached_profile;
        for peer in &peers {
            match self
                .request(
                    &node,
                    *peer,
                    crate::RpcRequest::GetProfile { owner },
                    &cancellation,
                    deadline,
                )
                .await
            {
                Ok(crate::RpcResponse::Profile(Some(profile_box))) => {
                    let candidate = *profile_box;
                    if candidate.verify(&self.config.issuers, self.now()).is_ok()
                        && candidate.owner == owner
                        && profile
                            .as_ref()
                            .is_none_or(|current| candidate.revision > current.revision)
                    {
                        profile = Some(candidate);
                    }
                }
                Err(ClientError::Cancelled) => {
                    node.shutdown().await;
                    return Err(ClientError::Cancelled);
                }
                _ => {}
            }
        }
        let Some(profile) = profile else {
            node.shutdown().await;
            return Err(ClientError::NetworkUnavailable);
        };
        let Some(manifest) = profile.photos.iter().find(|manifest| manifest.hash == hash) else {
            node.shutdown().await;
            return Err(ClientError::InvalidInput);
        };
        let mut bytes = None;
        for peer in &peers {
            match self
                .request(
                    &node,
                    *peer,
                    crate::RpcRequest::GetPhoto { owner, hash },
                    &cancellation,
                    deadline,
                )
                .await
            {
                Ok(crate::RpcResponse::Photo(Some(candidate)))
                    if candidate.len() == manifest.byte_count as usize
                        && ContentHash::digest(&candidate) == hash =>
                {
                    bytes = Some(candidate);
                    break;
                }
                Err(ClientError::Cancelled) => {
                    node.shutdown().await;
                    return Err(ClientError::Cancelled);
                }
                _ => {}
            }
        }
        node.shutdown().await;
        let bytes = bytes.ok_or(ClientError::NetworkUnavailable)?;
        let validated = self
            .photo_processor()?
            .validate_incoming(&bytes, hash.0, manifest.byte_count as usize, 0.5)
            .map_err(map_safety_error)?;
        if let Some(encoder) = &self.config.photo_encoder
            && let Some(embedding) = encode_photo_if_allowed(
                encoder.as_ref(),
                &validated.bytes,
                self.config.allow_development_encoder_fixture,
            )
            .map_err(|_| ClientError::Internal)?
        {
            self.open_storage()?
                .save_candidate_embedding(
                    self.owner()?,
                    owner,
                    hash.0,
                    embedding.version,
                    &embedding.values,
                )
                .map_err(map_core_error)?;
        }
        Ok(validated_photo_dto(validated, hash))
    }

    pub async fn like(&mut self, peer: ProfileId) -> Result<OperationReceipt, ClientError> {
        self.like_with_cancellation(peer, SyncCancellationToken::new())
            .await
    }

    pub async fn like_with_cancellation(
        &mut self,
        peer: ProfileId,
        cancellation: SyncCancellationToken,
    ) -> Result<OperationReceipt, ClientError> {
        let owner = self.owner()?;
        if owner == peer || self.config.peers.is_empty() {
            return Err(ClientError::InvalidInput);
        }
        self.credential()?;
        let key = stable_peer_operation_key(b"like", owner, peer);
        let mut storage = self.open_storage()?;
        if storage
            .load_match(owner, peer)
            .map_err(map_core_error)?
            .is_some_and(|record| {
                matches!(record.state(), MatchState::Blocked | MatchState::Rejected)
            })
        {
            return Err(ClientError::Unauthorized);
        }
        if let Some(operation) = storage
            .operation_by_key(owner, OutgoingOperationKind::Like, key)
            .map_err(map_core_error)?
        {
            if operation.status == OutgoingOperationStatus::Failed {
                return Err(ClientError::Unauthorized);
            }
            drop(storage);
            self.automatic_feedback(peer, true)?;
            let operation = self.deliver_like(operation, &cancellation).await?;
            return Ok(operation.into());
        }
        let peer_credential = self
            .peer_credential(&storage, peer)?
            .ok_or(ClientError::InvalidInput)?;
        verify_credential(&peer_credential, &self.config.issuers, self.now())?;
        let mut like_id = [0u8; 16];
        getrandom::fill(&mut like_id).map_err(|_| ClientError::Internal)?;
        let mut record = storage
            .load_match(owner, peer)
            .map_err(map_core_error)?
            .unwrap_or(
                annoda_core::matching::MatchRecord::new(owner, peer).map_err(map_core_error)?,
            );
        let expires_at = self
            .credential()?
            .claims
            .expires_at
            .min(peer_credential.claims.expires_at)
            .min(self.now().saturating_add(7 * 24 * 60 * 60));
        let envelope = record
            .create_like_envelope(
                self.account()?.identity(),
                self.credential_ref()?,
                &peer_credential,
                like_id,
                self.now(),
                expires_at,
                &self.config.issuers,
            )
            .map_err(map_core_error)?;
        let parcel = MailboxParcel::create(
            &envelope,
            self.credential_ref()?,
            &peer_credential,
            &self.config.issuers,
            self.now(),
        )
        .map_err(map_core_error)?;
        let exact_payload = postcard::to_allocvec(&parcel).map_err(|_| ClientError::Internal)?;
        let peers = self.selected_peer_strings();
        if peers.is_empty() {
            return Err(ClientError::NetworkUnavailable);
        }
        let operation = storage
            .create_local_like_operation(
                owner,
                peer,
                like_id,
                key,
                exact_payload,
                peers,
                self.now(),
                expires_at,
            )
            .map_err(map_core_error)?;
        drop(storage);
        self.automatic_feedback(peer, true)?;
        let operation = self.deliver_like(operation, &cancellation).await?;
        Ok(operation.into())
    }

    pub async fn pass(&mut self, peer: ProfileId) -> Result<(), ClientError> {
        let owner = self.owner()?;
        self.open_storage()?
            .mark_pass(owner, peer, self.now())
            .map_err(map_core_error)?;
        self.automatic_feedback(peer, false)
    }

    pub async fn block(&mut self, peer: ProfileId) -> Result<(), ClientError> {
        let owner = self.owner()?;
        self.open_storage()?
            .block_match(owner, peer)
            .map_err(map_core_error)
    }

    pub async fn received_likes(
        &mut self,
        page_size: u8,
        cursor: Option<PageCursor>,
    ) -> Result<Page<IncomingLike>, ClientError> {
        let owner = self.owner()?;
        let after = decode_collection_cursor(cursor, owner, b"incoming-likes")?;
        let storage = self.open_storage()?;
        validate_page_size(page_size)?;
        let mut records = Vec::new();
        let mut scan_after = after;
        loop {
            let batch = storage
                .incoming_like_records_after(owner, scan_after, MAX_PAGE_SIZE)
                .map_err(map_core_error)?;
            if batch.is_empty() {
                break;
            }
            scan_after = batch.last().map(|(record, _)| record.peer());
            records.extend(batch.into_iter().filter_map(|(record, credential)| {
                credential
                    .verify(&self.config.issuers, self.now())
                    .ok()
                    .map(|()| IncomingLike {
                        sender: record.peer(),
                        state: record.state(),
                        credential,
                    })
            }));
            if records.len() > page_size as usize || scan_after.is_none() {
                break;
            }
        }
        let has_more = records.len() > page_size as usize;
        records.truncate(page_size as usize);
        let next_cursor = if has_more {
            records
                .last()
                .map(|record| encode_collection_cursor(owner, b"incoming-likes", record.sender))
                .transpose()?
        } else {
            None
        };
        Ok(Page {
            items: records,
            next_cursor,
        })
    }

    pub async fn matches(
        &mut self,
        page_size: u8,
        cursor: Option<PageCursor>,
    ) -> Result<Page<MatchSummary>, ClientError> {
        validate_page_size(page_size)?;
        let owner = self.owner()?;
        let after = decode_collection_cursor(cursor, owner, b"matches")?;
        let storage = self.open_storage()?;
        let mut matches = Vec::new();
        let mut scan_after = after;
        loop {
            let records = storage
                .match_records_after(owner, scan_after, MAX_PAGE_SIZE)
                .map_err(map_core_error)?;
            if records.is_empty() {
                break;
            }
            scan_after = records.last().map(|record| record.peer());
            for record in records {
                if record.state() != MatchState::Matched {
                    continue;
                }
                if let Some(credential) = self.peer_credential(&storage, record.peer())?
                    && credential.verify(&self.config.issuers, self.now()).is_ok()
                {
                    matches.push(MatchSummary {
                        peer: record.peer(),
                        match_id: record.match_id().map_err(map_core_error)?,
                        credential,
                    });
                }
            }
            if matches.len() > page_size as usize || scan_after.is_none() {
                break;
            }
        }
        let has_more = matches.len() > page_size as usize;
        matches.truncate(page_size as usize);
        let next_cursor = if has_more {
            matches
                .last()
                .map(|record| encode_collection_cursor(owner, b"matches", record.peer))
                .transpose()?
        } else {
            None
        };
        Ok(Page {
            items: matches,
            next_cursor,
        })
    }

    pub async fn disclose_contacts(
        &mut self,
        peer: ProfileId,
        handles: Vec<ContactHandle>,
    ) -> Result<OperationReceipt, ClientError> {
        self.disclose_contacts_with_cancellation(peer, handles, SyncCancellationToken::new())
            .await
    }

    pub async fn disclose_contacts_with_cancellation(
        &mut self,
        peer: ProfileId,
        handles: Vec<ContactHandle>,
        cancellation: SyncCancellationToken,
    ) -> Result<OperationReceipt, ClientError> {
        let owner = self.owner()?;
        if self.config.peers.is_empty() {
            return Err(ClientError::NetworkUnavailable);
        }
        annoda_core::matching::validate_handles(&handles).map_err(map_core_error)?;
        let encoded_handles =
            postcard::to_allocvec(&handles).map_err(|_| ClientError::InvalidInput)?;
        let key = contact_operation_key(owner, peer, &encoded_handles);
        let storage = self.open_storage()?;
        let record = storage
            .load_match(owner, peer)
            .map_err(map_core_error)?
            .ok_or(ClientError::Unauthorized)?;
        if record.state() != MatchState::Matched {
            return Err(ClientError::Unauthorized);
        }
        if let Some(operation) = storage
            .operation_by_key(owner, OutgoingOperationKind::Contact, key)
            .map_err(map_core_error)?
        {
            drop(storage);
            return Ok(self.deliver_parcel(operation, cancellation).await?.into());
        }
        let peer_credential = self
            .peer_credential(&storage, peer)?
            .ok_or(ClientError::InvalidInput)?;
        let mut message_id = [0u8; 16];
        getrandom::fill(&mut message_id).map_err(|_| ClientError::Internal)?;
        let expires_at = self
            .credential()?
            .claims
            .expires_at
            .min(peer_credential.claims.expires_at)
            .min(self.now().saturating_add(7 * 24 * 60 * 60));
        let envelope = record
            .encrypted_disclosure(
                self.account()?.identity(),
                self.credential_ref()?,
                &peer_credential,
                handles,
                message_id,
                self.now(),
                expires_at,
                &self.config.issuers,
            )
            .map_err(map_core_error)?;
        let parcel = MailboxParcel::create(
            &envelope,
            self.credential_ref()?,
            &peer_credential,
            &self.config.issuers,
            self.now(),
        )
        .map_err(map_core_error)?;
        let exact_payload = postcard::to_allocvec(&parcel).map_err(|_| ClientError::Internal)?;
        let mut storage = self.open_storage()?;
        let operation = storage
            .create_contact_operation(
                owner,
                peer,
                key,
                exact_payload,
                self.selected_peer_strings(),
                expires_at,
            )
            .map_err(map_core_error)?;
        drop(storage);
        Ok(self.deliver_parcel(operation, cancellation).await?.into())
    }

    pub async fn received_contacts(
        &mut self,
        peer: ProfileId,
    ) -> Result<Vec<ContactHandle>, ClientError> {
        let owner = self.owner()?;
        let storage = self.open_storage()?;
        let match_id = storage
            .load_match(owner, peer)
            .map_err(map_core_error)?
            .ok_or(ClientError::Unauthorized)?
            .match_id()
            .map_err(map_core_error)?;
        let record = storage
            .load_match(owner, peer)
            .map_err(map_core_error)?
            .ok_or(ClientError::Unauthorized)?;
        if record.state() != MatchState::Matched {
            return Err(ClientError::Unauthorized);
        }
        collect_match_contacts(&storage, owner, match_id)
    }

    pub async fn disclose_match_contacts(
        &mut self,
        match_id: [u8; 32],
        handles: Vec<ContactHandle>,
    ) -> Result<OperationReceipt, ClientError> {
        let peer = self.peer_for_match_id(match_id)?;
        self.disclose_contacts(peer, handles).await
    }

    pub async fn disclose_match_contacts_with_cancellation(
        &mut self,
        match_id: [u8; 32],
        handles: Vec<ContactHandle>,
        cancellation: SyncCancellationToken,
    ) -> Result<OperationReceipt, ClientError> {
        let peer = self.peer_for_match_id(match_id)?;
        self.disclose_contacts_with_cancellation(peer, handles, cancellation)
            .await
    }

    pub async fn received_match_contacts(
        &mut self,
        match_id: [u8; 32],
    ) -> Result<Vec<ContactHandle>, ClientError> {
        let owner = self.owner()?;
        let storage = self.open_storage()?;
        let mut after = None;
        let mut matched = false;
        loop {
            let records = storage
                .match_records_after(owner, after, MAX_PAGE_SIZE)
                .map_err(map_core_error)?;
            if records.is_empty() {
                break;
            }
            if records.iter().any(|record| {
                record.state() == MatchState::Matched
                    && record.match_id().is_ok_and(|id| id == match_id)
            }) {
                matched = true;
                break;
            }
            after = records.last().map(|record| record.peer());
        }
        if !matched {
            return Err(ClientError::Unauthorized);
        }
        collect_match_contacts(&storage, owner, match_id)
    }

    pub fn operations(&self, limit: usize) -> Result<Vec<OperationReceipt>, ClientError> {
        if limit == 0 || limit > 64 {
            return Err(ClientError::InvalidInput);
        }
        self.open_storage()?
            .operations_after(self.owner()?, None, limit)
            .map(|operations| operations.into_iter().map(Into::into).collect())
            .map_err(map_core_error)
    }

    pub fn operations_page(
        &self,
        page_size: u8,
        cursor: Option<PageCursor>,
    ) -> Result<Page<OperationReceipt>, ClientError> {
        validate_page_size(page_size)?;
        let owner = self.owner()?;
        let after = decode_operation_cursor(cursor, owner)?;
        let operations = self
            .open_storage()?
            .operations_after(owner, after, page_size as usize)
            .map_err(map_core_error)?;
        let has_more = operations.len() == page_size as usize;
        let next_cursor = if has_more {
            operations
                .last()
                .map(|operation| encode_operation_cursor(owner, operation.id))
                .transpose()?
        } else {
            None
        };
        Ok(Page {
            items: operations.into_iter().map(Into::into).collect(),
            next_cursor,
        })
    }

    pub fn pending_notifications(
        &self,
        limit: usize,
    ) -> Result<Vec<NotificationEvent>, ClientError> {
        if limit == 0 || limit > 64 {
            return Err(ClientError::InvalidInput);
        }
        self.open_storage()?
            .pending_notifications(self.owner()?, limit)
            .map_err(map_core_error)
    }

    pub fn notification_preferences(&self) -> Result<NotificationPreferences, ClientError> {
        self.open_storage()?
            .notification_preferences(self.owner()?)
            .map_err(map_core_error)
    }

    pub fn set_notification_preferences(
        &mut self,
        preferences: NotificationPreferences,
    ) -> Result<(), ClientError> {
        self.open_storage()?
            .set_notification_preferences(self.owner()?, preferences)
            .map_err(map_core_error)
    }

    pub fn acknowledge_notification(&mut self, event_id: [u8; 32]) -> Result<bool, ClientError> {
        self.open_storage()?
            .acknowledge_notification(self.owner()?, event_id)
            .map_err(map_core_error)
    }

    pub async fn recover_pending(&mut self) -> Result<Vec<OperationReceipt>, ClientError> {
        if self.config.sync_budget.max_mailbox_items == 0 {
            return Ok(Vec::new());
        }
        let owner = self.owner()?;
        let mut storage = self.open_storage()?;
        let operations = scan_pending_operations(
            &mut storage,
            owner,
            self.now(),
            self.config.sync_budget.max_mailbox_items as usize,
        )?;
        drop(storage);
        if operations.is_empty() {
            return Ok(Vec::new());
        }
        let (node, _meter, peers, deadline) = self.start_network().await?;
        let cancellation = SyncCancellationToken::new();
        let mut receipts = Vec::new();
        let result = async {
            for operation in operations {
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                let updated = match operation.kind {
                    OutgoingOperationKind::Publication => {
                        let work: PublicationWork = postcard::from_bytes(&operation.exact_payload)
                            .map_err(|_| ClientError::Storage)?;
                        self.deliver_publication_on(
                            operation,
                            work,
                            &node,
                            &peers,
                            &cancellation,
                            deadline,
                        )
                        .await?
                    }
                    OutgoingOperationKind::Like | OutgoingOperationKind::Contact => {
                        self.deliver_parcel_on(operation, &node, &peers, &cancellation, deadline)
                            .await?
                    }
                };
                receipts.push(updated.into());
            }
            Ok::<_, ClientError>(())
        }
        .await;
        node.shutdown().await;
        result?;
        Ok(receipts)
    }

    fn selected_peer_strings(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        self.config
            .peers
            .iter()
            .filter_map(|peer| {
                let id = peer.peer_id.parse::<PeerId>().ok()?;
                seen.insert(id).then(|| id.to_string())
            })
            .take(self.config.sync_budget.max_peers as usize)
            .collect()
    }

    fn peer_for_match_id(&self, match_id: [u8; 32]) -> Result<ProfileId, ClientError> {
        let storage = self.open_storage()?;
        let mut after = None;
        loop {
            let records = storage
                .match_records_after(self.owner()?, after, MAX_PAGE_SIZE)
                .map_err(map_core_error)?;
            if records.is_empty() {
                return Err(ClientError::Unauthorized);
            }
            for record in &records {
                if record.state() == MatchState::Matched
                    && record.match_id().is_ok_and(|id| id == match_id)
                {
                    return Ok(record.peer());
                }
            }
            after = records.last().map(|record| record.peer());
        }
    }

    async fn deliver_like(
        &mut self,
        operation: OperationRecord,
        cancellation: &SyncCancellationToken,
    ) -> Result<OperationRecord, ClientError> {
        self.deliver_parcel(operation, cancellation.clone()).await
    }

    async fn deliver_parcel(
        &mut self,
        operation: OperationRecord,
        cancellation: SyncCancellationToken,
    ) -> Result<OperationRecord, ClientError> {
        let (node, _meter, peers, deadline) = self.start_network().await?;
        let result = self
            .deliver_parcel_on(operation, &node, &peers, &cancellation, deadline)
            .await;
        node.shutdown().await;
        result
    }

    async fn deliver_parcel_on(
        &self,
        mut operation: OperationRecord,
        node: &PeerNode,
        peers: &[PeerId],
        cancellation: &SyncCancellationToken,
        deadline: tokio::time::Instant,
    ) -> Result<OperationRecord, ClientError> {
        if operation.expires_at <= self.now() {
            self.open_storage()?
                .fail_operation(self.owner()?, operation.id)
                .map_err(map_core_error)?;
            return Err(ClientError::CredentialExpired);
        }
        let parcel: MailboxParcel =
            postcard::from_bytes(&operation.exact_payload).map_err(|_| ClientError::Storage)?;
        let item = *blake3::hash(&operation.exact_payload).as_bytes();
        for peer in peers {
            let peer_key = peer.to_string();
            if !operation.peer_targets.contains(&peer_key)
                || operation_has_ack(&operation, &peer_key, item)
            {
                continue;
            }
            if cancellation.is_cancelled() {
                return Err(ClientError::Cancelled);
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            let response = self
                .request(
                    node,
                    *peer,
                    crate::RpcRequest::DepositMailbox {
                        parcel: parcel.clone(),
                    },
                    cancellation,
                    deadline,
                )
                .await;
            if matches!(
                response,
                Ok(crate::RpcResponse::Ack | crate::RpcResponse::Duplicate)
            ) {
                operation = self.ack_operation(operation.id, &peer_key, item)?;
            } else {
                operation = self.record_delivery_failure(
                    operation.id,
                    &peer_key,
                    item,
                    failure_kind(&response, cancellation, deadline),
                )?;
                if matches!(response, Err(ClientError::Cancelled)) {
                    return Err(ClientError::Cancelled);
                }
            }
        }
        Ok(operation)
    }

    fn peer_credential(
        &self,
        storage: &PeerStorage,
        peer: ProfileId,
    ) -> Result<Option<VerifiedCredential>, ClientError> {
        if let Some(credential) = storage
            .load_peer_credential(self.owner()?, peer)
            .map_err(map_core_error)?
        {
            return Ok(Some(credential));
        }
        Ok(storage
            .candidate_profile(self.owner()?, peer, &self.config.issuers, self.now())
            .map_err(map_core_error)?
            .map(|profile| profile.credential))
    }

    fn ack_operation(
        &self,
        operation_id: [u8; 16],
        peer: &str,
        item: [u8; 32],
    ) -> Result<OperationRecord, ClientError> {
        self.open_storage()?
            .acknowledge_operation_item(self.owner()?, operation_id, peer, item, true)
            .map_err(map_core_error)
    }

    fn record_delivery_failure(
        &self,
        operation_id: [u8; 16],
        peer: &str,
        item: [u8; 32],
        reason: CoreDeliveryFailureKind,
    ) -> Result<OperationRecord, ClientError> {
        self.open_storage()?
            .record_operation_failure(self.owner()?, operation_id, peer, item, reason)
            .map_err(map_core_error)
    }

    /// Consumes the service and releases the exclusive account lease.
    pub fn close(self) {
        drop(self);
    }
}

struct ClassifierAdapter(Arc<dyn PhotoSafetyClassifier>);

impl PhotoSafetyClassifier for ClassifierAdapter {
    fn classify_rgb(&self, width: u32, height: u32, rgb: &[u8]) -> Result<f32, SafetyError> {
        self.0.classify_rgb(width, height, rgb)
    }

    fn mode(&self) -> ClassifierMode {
        self.0.mode()
    }
}

fn map_safety_error(error: SafetyError) -> ClientError {
    match error {
        SafetyError::SafetyUnavailable | SafetyError::DevelopmentFixtureDisabled => {
            ClientError::SafetyUnavailable
        }
        SafetyError::Rejected => ClientError::SafetyRejected,
        SafetyError::InvalidThreshold
        | SafetyError::InvalidSize
        | SafetyError::UnsupportedFormat
        | SafetyError::InvalidImage
        | SafetyError::LengthMismatch
        | SafetyError::HashMismatch => ClientError::InvalidInput,
    }
}

fn verify_credential(
    credential: &VerifiedCredential,
    issuers: &TrustedIssuers,
    now: u64,
) -> Result<(), ClientError> {
    if credential.claims.expires_at <= now {
        let last_valid_second = credential.claims.expires_at.saturating_sub(1);
        credential
            .verify(issuers, last_valid_second)
            .map_err(|_| ClientError::UntrustedIdentity)?;
        return Err(ClientError::CredentialExpired);
    }
    credential
        .verify(issuers, now)
        .map_err(|_| ClientError::UntrustedIdentity)
}

#[derive(Serialize, Deserialize)]
struct DiscoveryCursor {
    owner: ProfileId,
    query_hash: [u8; 32],
    snapshot_hash: [u8; 32],
    after_score: f64,
    after_id: ProfileId,
}

fn validate_discovery_query(query: &DiscoveryQuery) -> Result<(), ClientError> {
    if query.minimum_age < 18
        || query.maximum_age < query.minimum_age
        || query.page_size == 0
        || query.page_size as usize > MAX_PAGE_SIZE
        || query
            .coarse_region
            .as_ref()
            .is_some_and(|region| region.len() > 64 || region.chars().any(char::is_control))
    {
        return Err(ClientError::InvalidInput);
    }
    Ok(())
}

fn discovery_filter_key(query: &DiscoveryQuery, model_hash: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&[query.minimum_age, query.maximum_age]);
    hasher.update(&model_hash);
    *hasher.finalize().as_bytes()
}

fn encode_discovery_cursor(
    owner: ProfileId,
    query_hash: [u8; 32],
    snapshot_hash: [u8; 32],
    after_score: f64,
    after_id: ProfileId,
) -> Result<PageCursor, ClientError> {
    postcard::to_allocvec(&DiscoveryCursor {
        owner,
        query_hash,
        snapshot_hash,
        after_score,
        after_id,
    })
    .map(PageCursor)
    .map_err(|_| ClientError::Internal)
}

fn decode_discovery_cursor(
    bytes: &[u8],
    owner: ProfileId,
    query_hash: [u8; 32],
) -> Result<DiscoveryCursor, ClientError> {
    if bytes.is_empty() || bytes.len() > 256 {
        return Err(ClientError::InvalidInput);
    }
    let (cursor, trailing): (DiscoveryCursor, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|_| ClientError::InvalidInput)?;
    if !trailing.is_empty()
        || cursor.owner != owner
        || cursor.query_hash != query_hash
        || !cursor.after_score.is_finite()
    {
        return Err(ClientError::InvalidInput);
    }
    Ok(cursor)
}

fn discovery_snapshot_hash(profiles: &[(ProfileId, f64, PublicProfile)]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"annoda/discovery-snapshot/v1\0");
    for (owner, score, profile) in profiles {
        hasher.update(&owner.0);
        hasher.update(&profile.revision.to_le_bytes());
        hasher.update(&score.to_bits().to_le_bytes());
        for photo in &profile.photos {
            hasher.update(&photo.hash.0);
        }
    }
    *hasher.finalize().as_bytes()
}

fn operation_key(domain: &[u8], owner: ProfileId, nonce: [u8; 16]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"annoda/application-operation/v1\0");
    hasher.update(domain);
    hasher.update(&owner.0);
    hasher.update(&nonce);
    *hasher.finalize().as_bytes()
}

fn stable_peer_operation_key(domain: &[u8], owner: ProfileId, peer: ProfileId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"annoda/application-peer-operation/v1\0");
    hasher.update(domain);
    hasher.update(&owner.0);
    hasher.update(&peer.0);
    *hasher.finalize().as_bytes()
}

fn contact_operation_key(owner: ProfileId, peer: ProfileId, encoded_handles: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"annoda/application-contact-operation/v1\0");
    hasher.update(&owner.0);
    hasher.update(&peer.0);
    hasher.update(encoded_handles);
    *hasher.finalize().as_bytes()
}

fn profile_item_hash(profile: &PublicProfile) -> Result<[u8; 32], ClientError> {
    let bytes = postcard::to_allocvec(profile).map_err(|_| ClientError::Internal)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

fn validated_photo_dto(photo: ValidatedPhoto, hash: ContentHash) -> ValidatedPhotoDto {
    ValidatedPhotoDto {
        bytes: photo.bytes,
        hash,
        media_type: photo.media_type.to_owned(),
        width: photo.width,
        height: photo.height,
    }
}

fn collect_match_contacts(
    storage: &PeerStorage,
    owner: ProfileId,
    match_id: [u8; 32],
) -> Result<Vec<ContactHandle>, ClientError> {
    let mut cursor = None;
    let mut handles = Vec::new();
    loop {
        let page = storage
            .incoming_contact_disclosures_for_match_page(owner, match_id, cursor, MAX_PAGE_SIZE)
            .map_err(map_core_error)?;
        handles.extend(
            page.disclosures
                .into_iter()
                .flat_map(|disclosure| disclosure.handles),
        );
        cursor = page.next_cursor;
        if cursor.is_none() {
            return Ok(handles);
        }
    }
}

fn operation_has_ack(operation: &OperationRecord, peer_id: &str, item: [u8; 32]) -> bool {
    operation
        .peer_item_acks
        .iter()
        .any(|ack| ack.peer_id == peer_id && ack.item == item && ack.accepted)
}

fn scan_pending_operations(
    storage: &mut PeerStorage,
    owner: ProfileId,
    now: u64,
    limit: usize,
) -> Result<Vec<OperationRecord>, ClientError> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let mut pending = Vec::new();
    let operations = storage
        .pending_operations_rotated(owner, limit.min(MAX_PAGE_SIZE))
        .map_err(map_core_error)?;
    for operation in operations {
        if operation.expires_at <= now {
            storage
                .fail_operation(owner, operation.id)
                .map_err(map_core_error)?;
        } else if matches!(
            operation.status,
            OutgoingOperationStatus::Pending | OutgoingOperationStatus::Partial
        ) {
            pending.push(operation);
        }
    }
    Ok(pending)
}

fn failure_kind(
    result: &Result<crate::RpcResponse, ClientError>,
    cancellation: &SyncCancellationToken,
    deadline: tokio::time::Instant,
) -> CoreDeliveryFailureKind {
    match result {
        Err(ClientError::Cancelled) if cancellation.is_cancelled() => {
            CoreDeliveryFailureKind::Cancelled
        }
        Err(ClientError::NetworkUnavailable) if tokio::time::Instant::now() >= deadline => {
            CoreDeliveryFailureKind::Budget
        }
        Err(_) => CoreDeliveryFailureKind::Unreachable,
        Ok(_) => CoreDeliveryFailureKind::Rejected,
    }
}

#[derive(Serialize, Deserialize)]
struct CollectionCursor {
    owner: ProfileId,
    collection: [u8; 32],
    after: ProfileId,
}

#[derive(Serialize, Deserialize)]
struct OperationCursor {
    owner: ProfileId,
    after: [u8; 16],
}

fn encode_operation_cursor(owner: ProfileId, after: [u8; 16]) -> Result<PageCursor, ClientError> {
    postcard::to_allocvec(&OperationCursor { owner, after })
        .map(PageCursor)
        .map_err(|_| ClientError::Internal)
}

fn decode_operation_cursor(
    cursor: Option<PageCursor>,
    owner: ProfileId,
) -> Result<Option<[u8; 16]>, ClientError> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    if cursor.0.is_empty() || cursor.0.len() > 128 {
        return Err(ClientError::InvalidInput);
    }
    let (decoded, trailing): (OperationCursor, &[u8]) =
        postcard::take_from_bytes(&cursor.0).map_err(|_| ClientError::InvalidInput)?;
    if !trailing.is_empty() || decoded.owner != owner {
        return Err(ClientError::InvalidInput);
    }
    Ok(Some(decoded.after))
}

fn validate_page_size(size: u8) -> Result<(), ClientError> {
    if size == 0 || size as usize > MAX_PAGE_SIZE {
        Err(ClientError::InvalidInput)
    } else {
        Ok(())
    }
}

fn collection_hash(collection: &[u8]) -> [u8; 32] {
    *blake3::hash(collection).as_bytes()
}

fn encode_collection_cursor(
    owner: ProfileId,
    collection: &[u8],
    after: ProfileId,
) -> Result<PageCursor, ClientError> {
    postcard::to_allocvec(&CollectionCursor {
        owner,
        collection: collection_hash(collection),
        after,
    })
    .map(PageCursor)
    .map_err(|_| ClientError::Internal)
}

fn decode_collection_cursor(
    cursor: Option<PageCursor>,
    owner: ProfileId,
    collection: &[u8],
) -> Result<Option<ProfileId>, ClientError> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    if cursor.0.is_empty() || cursor.0.len() > 256 {
        return Err(ClientError::InvalidInput);
    }
    let (decoded, trailing): (CollectionCursor, &[u8]) =
        postcard::take_from_bytes(&cursor.0).map_err(|_| ClientError::InvalidInput)?;
    if !trailing.is_empty()
        || decoded.owner != owner
        || decoded.collection != collection_hash(collection)
    {
        return Err(ClientError::InvalidInput);
    }
    Ok(Some(decoded.after))
}

fn map_core_error(error: annoda_core::Error) -> ClientError {
    match error {
        annoda_core::Error::InvalidInput => ClientError::InvalidInput,
        annoda_core::Error::LimitExceeded => ClientError::StorageFull,
        annoda_core::Error::Unauthorized | annoda_core::Error::NotFound => {
            ClientError::Unauthorized
        }
        annoda_core::Error::InvalidCredential | annoda_core::Error::InvalidSignature => {
            ClientError::UntrustedIdentity
        }
        annoda_core::Error::InvalidTime => ClientError::CredentialExpired,
        annoda_core::Error::Storage(_) => ClientError::Storage,
        _ => ClientError::Internal,
    }
}

mod ranking_reporting;

fn encode_photo_if_allowed(
    encoder: &dyn PhotoEncoder,
    photo: &[u8],
    allow_development_fixture: bool,
) -> Result<Option<PhotoEmbedding>, RankingError> {
    if encoder.mode() == EncoderMode::DevelopmentFixture && !allow_development_fixture {
        return Ok(None);
    }
    encoder.encode(photo).map(Some)
}

#[cfg(test)]
#[path = "tests/client_encoder.rs"]
mod encoder_mode_tests;
