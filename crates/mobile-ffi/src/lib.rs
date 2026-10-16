#![forbid(unsafe_code)]

use std::{
    path::PathBuf,
    sync::{Arc, Condvar, Mutex, OnceLock},
    time::{Duration, Instant},
};

use annoda_core::{
    Error as CoreError,
    key_store::{AccountKeyStore, AccountKeyStoreError, PortableAccountVault, UnlockedAccount},
    notifications::{NotificationEvent, NotificationKind, NotificationPreferences},
    storage::PeerStorage,
};
use annoda_intelligence::ranking::{PhotoEmbedding, PreferenceModel, RankingError};
use annoda_network::{
    AuthorizedReplica, AuthorizedReplicaPhoto, ContributionInputs, HostConditions,
    PeerContributionPolicy, SyncBudget, SyncCancellationToken, SyncContext, SyncDeferredReason,
    SyncError, SyncPeerAddress, SyncReport, SyncStatus,
};
use thiserror::Error;
use zeroize::Zeroizing;

mod application;
pub use application::*;

uniffi::setup_scaffolding!();

const MAX_MODEL_DIMENSIONS: u32 = 4_096;
const MAX_SESSION_WAIT_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq, uniffi::Error)]
pub enum FfiError {
    #[error("input is invalid or exceeds supported bounds")]
    InvalidInput,
    #[error("the embedding does not match this model")]
    IncompatibleModel,
    #[error("the local preference model is unavailable")]
    Internal,
    #[error("account vault is missing")]
    AccountMissing,
    #[error("account is locked")]
    AccountLocked,
    #[error("account is already in use")]
    AccountBusy,
    #[error("account vault is inaccessible")]
    AccountInaccessible,
    #[error("account authorization failed")]
    AuthenticationFailed,
    #[error("account vault is corrupt")]
    CorruptVault,
    #[error("account vault version is unsupported")]
    UnsupportedVaultVersion,
    #[error("account already exists")]
    AccountAlreadyExists,
    #[error("storage capacity limit reached")]
    StorageFull,
    #[error("storage is unavailable")]
    StorageUnavailable,
    #[error("operation is not authorized")]
    Unauthorized,
    #[error("network is unavailable")]
    NetworkUnavailable,
    #[error("operation was cancelled")]
    Cancelled,
    #[error("credential issuer or subject is not trusted")]
    UntrustedIdentity,
    #[error("credential has expired")]
    CredentialExpired,
    #[error("required safety classifier is unavailable")]
    SafetyUnavailable,
    #[error("content was rejected by the safety policy")]
    SafetyRejected,
    #[error("operation is pending")]
    Pending,
    #[error("operation is unsupported")]
    Unsupported,
}

impl From<AccountKeyStoreError> for FfiError {
    fn from(error: AccountKeyStoreError) -> Self {
        match error {
            AccountKeyStoreError::Missing => Self::AccountMissing,
            AccountKeyStoreError::BusyLocked => Self::AccountBusy,
            AccountKeyStoreError::Inaccessible => Self::AccountInaccessible,
            AccountKeyStoreError::AuthenticationFailed => Self::AuthenticationFailed,
            AccountKeyStoreError::CorruptFormat => Self::CorruptVault,
            AccountKeyStoreError::UnsupportedVersion => Self::UnsupportedVaultVersion,
            AccountKeyStoreError::AlreadyExists => Self::AccountAlreadyExists,
            AccountKeyStoreError::InvalidInput => Self::InvalidInput,
        }
    }
}

impl From<CoreError> for FfiError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::InvalidInput | CoreError::InvalidTime => Self::InvalidInput,
            CoreError::Unauthorized
            | CoreError::InvalidCredential
            | CoreError::InvalidSignature => Self::Unauthorized,
            CoreError::LimitExceeded => Self::StorageFull,
            CoreError::Storage(_) => Self::StorageUnavailable,
            _ => Self::Internal,
        }
    }
}

impl From<RankingError> for FfiError {
    fn from(error: RankingError) -> Self {
        match error {
            RankingError::IncompatibleEmbedding => Self::IncompatibleModel,
            RankingError::InvalidEmbedding
            | RankingError::InvalidTrainingConfig
            | RankingError::InvalidExploration => Self::InvalidInput,
            RankingError::NumericalFailure => Self::Internal,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, uniffi::Record)]
pub struct FfiRankingScore {
    pub probability: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiNotificationPreferences {
    pub likes_enabled: bool,
    pub matches_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiNotificationKind {
    NewLike,
    NewMatch,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiNotificationEvent {
    pub event_id: Vec<u8>,
    pub kind: FfiNotificationKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiSyncStatus {
    Complete,
    Partial,
    Deferred,
    Cancelled,
    BudgetExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiSyncDeferredReason {
    NoPeers,
    NoReachablePeers,
    UnsupportedPeer,
    Deadline,
    ContributionSkipped,
    LocalStorageLimit,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSyncReport {
    pub status: FfiSyncStatus,
    pub verified_items: u32,
    pub rejected_items: u32,
    pub downloaded_bytes: u64,
    pub uploaded_bytes: u64,
    pub contacted_peers: Vec<String>,
    pub new_events: Vec<FfiNotificationEvent>,
    pub confirmed_replicas: u32,
    pub deferred_reasons: Vec<FfiSyncDeferredReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiSyncBudget {
    pub max_duration_ms: u64,
    pub max_download_bytes: u64,
    pub max_upload_bytes: u64,
    pub max_peers: u16,
    pub max_mailbox_items: u16,
    pub max_concurrent_requests: u16,
    pub retries: u16,
    pub request_timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSyncPeer {
    pub peer_id: String,
    pub address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiAuthorizedReplicaPhoto {
    pub manifest: Vec<u8>,
    pub lease: Vec<u8>,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiAuthorizedReplica {
    pub profile: Vec<u8>,
    pub owner_credential: Vec<u8>,
    pub photos: Vec<FfiAuthorizedReplicaPhoto>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiPeerContributionPolicy {
    pub enabled: bool,
    pub wifi_only: bool,
    pub charging_only: bool,
    pub max_storage_bytes: u64,
    pub max_transfer_bytes: u64,
    pub max_duration_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct FfiHostConditions {
    pub wifi_available: Option<bool>,
    pub charging: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiSyncRequest {
    /// Postcard-encoded signed public credential; account secret material never enters this DTO.
    pub credential: Vec<u8>,
    pub trusted_issuer_keys: Vec<Vec<u8>>,
    pub revoked_serials: Vec<Vec<u8>>,
    pub peers: Vec<FfiSyncPeer>,
    pub budget: FfiSyncBudget,
    pub contribution_policy: FfiPeerContributionPolicy,
    pub host_conditions: FfiHostConditions,
    pub authorized_replicas: Vec<FfiAuthorizedReplica>,
}

struct SessionShared {
    cancellation: SyncCancellationToken,
    result: Mutex<Option<Result<FfiSyncReport, FfiError>>>,
    completed: Condvar,
}

impl SessionShared {
    fn new() -> Self {
        Self {
            cancellation: SyncCancellationToken::new(),
            result: Mutex::new(None),
            completed: Condvar::new(),
        }
    }

    fn cancel(&self) {
        self.cancellation.cancel();
    }

    fn finish(&self, result: Result<FfiSyncReport, FfiError>) {
        let mut slot = self
            .result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *slot = Some(result);
        self.completed.notify_all();
    }

    fn wait_for_completion(&self) {
        let mut result = self
            .result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while result.is_none() {
            result = self
                .completed
                .wait(result)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    fn wait(&self, timeout_ms: Option<u64>) -> Result<Option<FfiSyncReport>, FfiError> {
        let deadline = match timeout_ms {
            Some(ms) => Some(
                Instant::now()
                    .checked_add(Duration::from_millis(ms))
                    .ok_or(FfiError::InvalidInput)?,
            ),
            None => None,
        };
        let mut result = self.result.lock().map_err(|_| FfiError::Internal)?;
        while result.is_none() {
            let Some(deadline) = deadline else {
                result = self
                    .completed
                    .wait(result)
                    .map_err(|_| FfiError::Internal)?;
                continue;
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            let (next, timeout) = self
                .completed
                .wait_timeout(result, remaining)
                .map_err(|_| FfiError::Internal)?;
            result = next;
            if timeout.timed_out() && result.is_none() {
                return Ok(None);
            }
        }
        match result.as_ref().ok_or(FfiError::Internal)? {
            Ok(report) => Ok(Some(report.clone())),
            Err(error) => Err(*error),
        }
    }
}

#[derive(uniffi::Object)]
pub struct SyncSession {
    shared: Arc<SessionShared>,
}

#[uniffi::export]
impl SyncSession {
    pub fn cancel(&self) {
        self.shared.cancel();
    }

    pub fn wait_result(&self, timeout_ms: u64) -> Result<Option<FfiSyncReport>, FfiError> {
        if timeout_ms > MAX_SESSION_WAIT_MS {
            return Err(FfiError::InvalidInput);
        }
        self.shared.wait(Some(timeout_ms))
    }

    pub fn is_finished(&self) -> Result<bool, FfiError> {
        Ok(self
            .shared
            .result
            .lock()
            .map_err(|_| FfiError::Internal)?
            .is_some())
    }
}

#[derive(uniffi::Object)]
pub struct AccountHandle {
    directory: PathBuf,
    account: Arc<Mutex<Option<Arc<UnlockedAccount>>>>,
    active_session: Arc<Mutex<Option<Arc<SessionShared>>>>,
    lifecycle: Mutex<()>,
}

impl AccountHandle {
    fn new(directory: PathBuf, account: UnlockedAccount) -> Self {
        Self {
            directory,
            account: Arc::new(Mutex::new(Some(Arc::new(account)))),
            active_session: Arc::new(Mutex::new(None)),
            lifecycle: Mutex::new(()),
        }
    }

    fn with_owner<T>(
        &self,
        operation: impl FnOnce(annoda_core::protocol::ProfileId) -> Result<T, FfiError>,
    ) -> Result<T, FfiError> {
        let owner = {
            let account = self.account.lock().map_err(|_| FfiError::Internal)?;
            account
                .as_ref()
                .ok_or(FfiError::AccountLocked)?
                .identity()
                .profile_id()
        };
        operation(owner)
    }

    fn open_state(&self) -> Result<PeerStorage, FfiError> {
        PeerStorage::open_default(self.directory.join("client-state.sqlite3"))
            .map_err(FfiError::from)
    }
}

#[uniffi::export]
impl AccountHandle {
    pub fn profile_id(&self) -> Result<Vec<u8>, FfiError> {
        self.with_owner(|owner| Ok(owner.0.to_vec()))
    }

    pub fn lock(&self) -> Result<(), FfiError> {
        let _lifecycle = self.lifecycle.lock().map_err(|_| FfiError::Internal)?;
        let active = self
            .active_session
            .lock()
            .map_err(|_| FfiError::Internal)?
            .clone();
        if let Some(active) = active {
            active.cancel();
            active.wait_for_completion();
        }
        let mut account = self.account.lock().map_err(|_| FfiError::Internal)?;
        account.take();
        self.active_session
            .lock()
            .map_err(|_| FfiError::Internal)?
            .take();
        Ok(())
    }

    pub fn start_sync_session(
        &self,
        request: FfiSyncRequest,
    ) -> Result<Arc<SyncSession>, FfiError> {
        let context = build_sync_context(&self.directory, &request)?;
        let budget = sync_budget(request.budget);
        let runtime = runtime()?;
        let _lifecycle = self.lifecycle.lock().map_err(|_| FfiError::Internal)?;
        let account = self
            .account
            .lock()
            .map_err(|_| FfiError::Internal)?
            .as_ref()
            .cloned()
            .ok_or(FfiError::AccountLocked)?;
        let shared = Arc::new(SessionShared::new());
        {
            let mut active = self.active_session.lock().map_err(|_| FfiError::Internal)?;
            if active.as_ref().is_some_and(|session| {
                session
                    .result
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .is_none()
            }) {
                return Err(FfiError::AccountBusy);
            }
            *active = Some(shared.clone());
        }

        let session_result = Arc::new(SyncSession {
            shared: shared.clone(),
        });
        let active_slot = self.active_session.clone();
        runtime.spawn(async move {
            let result = annoda_network::sync::sync_once(
                &account,
                context,
                budget,
                shared.cancellation.clone(),
            )
            .await
            .map(map_sync_report)
            .map_err(map_sync_error);
            drop(account);
            shared.finish(result);
            if let Ok(mut active) = active_slot.lock()
                && active
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &shared))
            {
                active.take();
            }
        });
        Ok(session_result)
    }

    pub fn notification_preferences(&self) -> Result<FfiNotificationPreferences, FfiError> {
        self.with_owner(|owner| {
            let db = self.open_state()?;
            let prefs = db.notification_preferences(owner).map_err(FfiError::from)?;
            Ok(FfiNotificationPreferences {
                likes_enabled: prefs.likes_enabled,
                matches_enabled: prefs.matches_enabled,
            })
        })
    }

    pub fn set_notification_preferences(
        &self,
        preferences: FfiNotificationPreferences,
    ) -> Result<(), FfiError> {
        self.with_owner(|owner| {
            let mut db = self.open_state()?;
            db.set_notification_preferences(
                owner,
                NotificationPreferences {
                    likes_enabled: preferences.likes_enabled,
                    matches_enabled: preferences.matches_enabled,
                },
            )
            .map_err(FfiError::from)
        })
    }

    pub fn pending_notifications(&self, limit: u32) -> Result<Vec<FfiNotificationEvent>, FfiError> {
        if limit == 0 || limit > 64 {
            return Err(FfiError::InvalidInput);
        }
        self.with_owner(|owner| {
            let db = self.open_state()?;
            db.pending_notifications(owner, limit as usize)
                .map(|events| events.into_iter().map(ffi_notification).collect())
                .map_err(FfiError::from)
        })
    }

    pub fn acknowledge_notification(&self, event_id: Vec<u8>) -> Result<bool, FfiError> {
        let event_id: [u8; 32] = event_id.try_into().map_err(|_| FfiError::InvalidInput)?;
        self.with_owner(|owner| {
            self.open_state()?
                .acknowledge_notification(owner, event_id)
                .map_err(FfiError::from)
        })
    }
}

#[uniffi::export]
pub fn create_account(
    directory: String,
    passphrase: String,
) -> Result<Arc<AccountHandle>, FfiError> {
    let passphrase = Zeroizing::new(passphrase);
    if passphrase.is_empty() || passphrase.len() > 1024 {
        return Err(FfiError::InvalidInput);
    }
    let directory = portable_directory(directory)?;
    let vault = PortableAccountVault::new(directory.clone());
    let authorization = Zeroizing::new(passphrase.as_bytes().to_vec());
    let account = vault.create(&authorization).map_err(FfiError::from);
    account.map(|account| Arc::new(AccountHandle::new(directory, account)))
}

#[uniffi::export]
pub fn open_account(directory: String, passphrase: String) -> Result<Arc<AccountHandle>, FfiError> {
    let passphrase = Zeroizing::new(passphrase);
    if passphrase.is_empty() || passphrase.len() > 1024 {
        return Err(FfiError::InvalidInput);
    }
    let directory = portable_directory(directory)?;
    let vault = PortableAccountVault::new(directory.clone());
    let authorization = Zeroizing::new(passphrase.as_bytes().to_vec());
    let account = vault.unlock(&authorization).map_err(FfiError::from);
    account.map(|account| Arc::new(AccountHandle::new(directory, account)))
}

fn portable_directory(path: String) -> Result<PathBuf, FfiError> {
    if path.is_empty() || path.len() > 4096 || path.chars().any(char::is_control) {
        return Err(FfiError::InvalidInput);
    }
    Ok(PathBuf::from(path))
}

fn ffi_notification(event: NotificationEvent) -> FfiNotificationEvent {
    FfiNotificationEvent {
        event_id: event.event_id.to_vec(),
        kind: match event.kind {
            NotificationKind::NewLike => FfiNotificationKind::NewLike,
            NotificationKind::NewMatch => FfiNotificationKind::NewMatch,
        },
    }
}

fn build_sync_context(
    directory: &std::path::Path,
    request: &FfiSyncRequest,
) -> Result<SyncContext, FfiError> {
    if request.credential.len() > 16 * 1024
        || request.trusted_issuer_keys.len() > 16
        || request.revoked_serials.len() > 4096
        || request.peers.len() > 256
        || request.authorized_replicas.len() > 16
    {
        return Err(FfiError::InvalidInput);
    }
    let credential =
        postcard::from_bytes(&request.credential).map_err(|_| FfiError::InvalidInput)?;
    let mut issuer_keys = Vec::with_capacity(request.trusted_issuer_keys.len());
    for key in &request.trusted_issuer_keys {
        issuer_keys.push(
            key.as_slice()
                .try_into()
                .map_err(|_| FfiError::InvalidInput)?,
        );
    }
    let mut issuers = annoda_core::identity::TrustedIssuers::new(issuer_keys);
    for serial in &request.revoked_serials {
        issuers.revoke_serial(
            serial
                .as_slice()
                .try_into()
                .map_err(|_| FfiError::InvalidInput)?,
        );
    }
    let peers = request
        .peers
        .iter()
        .map(|peer| SyncPeerAddress {
            peer_id: peer.peer_id.clone(),
            address: peer.address.clone(),
        })
        .collect();
    let mut replicas = Vec::with_capacity(request.authorized_replicas.len());
    let mut photo_count = 0usize;
    let mut contribution_bytes = 0usize;
    for replica in &request.authorized_replicas {
        if replica.profile.len() > 64 * 1024 || replica.owner_credential.len() > 16 * 1024 {
            return Err(FfiError::InvalidInput);
        }
        photo_count = photo_count
            .checked_add(replica.photos.len())
            .ok_or(FfiError::InvalidInput)?;
        if replica.photos.len() > 64 || photo_count > 128 {
            return Err(FfiError::InvalidInput);
        }
        let profile: annoda_core::protocol::PublicProfile =
            postcard::from_bytes(&replica.profile).map_err(|_| FfiError::InvalidInput)?;
        let owner: annoda_core::identity::VerifiedCredential =
            postcard::from_bytes(&replica.owner_credential).map_err(|_| FfiError::InvalidInput)?;
        if profile.credential != owner || profile.owner != owner.profile_id() {
            return Err(FfiError::Unauthorized);
        }
        let mut photos = Vec::with_capacity(replica.photos.len());
        for photo in &replica.photos {
            contribution_bytes = contribution_bytes
                .checked_add(photo.bytes.len())
                .ok_or(FfiError::InvalidInput)?;
            if contribution_bytes > 32 * 1024 * 1024
                || photo.manifest.len() > 4096
                || photo.lease.len() > 4096
            {
                return Err(FfiError::InvalidInput);
            }
            photos.push(AuthorizedReplicaPhoto {
                manifest: postcard::from_bytes(&photo.manifest)
                    .map_err(|_| FfiError::InvalidInput)?,
                lease: postcard::from_bytes(&photo.lease).map_err(|_| FfiError::InvalidInput)?,
                bytes: photo.bytes.clone(),
            });
        }
        replicas.push(AuthorizedReplica {
            profile,
            owner,
            photos,
        });
    }
    let context = SyncContext::new(
        credential,
        issuers,
        directory.join("client-state.sqlite3"),
        directory.join("transport-state"),
        peers,
    )
    .map_err(map_sync_error)?;
    Ok(context.with_contribution(ContributionInputs {
        policy: PeerContributionPolicy {
            enabled: request.contribution_policy.enabled,
            wifi_only: request.contribution_policy.wifi_only,
            charging_only: request.contribution_policy.charging_only,
            max_storage_bytes: request.contribution_policy.max_storage_bytes,
            max_transfer_bytes: request.contribution_policy.max_transfer_bytes,
            max_duration: Duration::from_millis(request.contribution_policy.max_duration_ms),
        },
        conditions: HostConditions {
            wifi_available: request.host_conditions.wifi_available.unwrap_or(false),
            charging: request.host_conditions.charging.unwrap_or(false),
        },
        replicas,
    }))
}

fn sync_budget(budget: FfiSyncBudget) -> SyncBudget {
    SyncBudget {
        max_duration: Duration::from_millis(budget.max_duration_ms),
        max_download_bytes: budget.max_download_bytes,
        max_upload_bytes: budget.max_upload_bytes,
        max_peers: budget.max_peers,
        max_mailbox_items: budget.max_mailbox_items,
        max_concurrent_requests: budget.max_concurrent_requests,
        retries: budget.retries,
        request_timeout: Duration::from_millis(budget.request_timeout_ms),
    }
}

fn map_sync_error(error: SyncError) -> FfiError {
    match error {
        SyncError::InvalidBudget | SyncError::InvalidContext => FfiError::InvalidInput,
        SyncError::AccountCredentialMismatch => FfiError::Unauthorized,
        SyncError::Busy => FfiError::AccountBusy,
        SyncError::Startup => FfiError::NetworkUnavailable,
        SyncError::Storage => FfiError::StorageUnavailable,
    }
}

fn map_sync_report(report: SyncReport) -> FfiSyncReport {
    FfiSyncReport {
        status: match report.status {
            SyncStatus::Complete => FfiSyncStatus::Complete,
            SyncStatus::Partial => FfiSyncStatus::Partial,
            SyncStatus::Deferred => FfiSyncStatus::Deferred,
            SyncStatus::Cancelled => FfiSyncStatus::Cancelled,
            SyncStatus::BudgetExhausted => FfiSyncStatus::BudgetExhausted,
        },
        verified_items: report.verified_items,
        rejected_items: report.rejected_items,
        downloaded_bytes: report.downloaded_bytes,
        uploaded_bytes: report.uploaded_bytes,
        contacted_peers: report.contacted_peers,
        new_events: report
            .new_events
            .into_iter()
            .map(ffi_notification)
            .collect(),
        confirmed_replicas: report.confirmed_replicas,
        deferred_reasons: report
            .deferred_reasons
            .into_iter()
            .map(|reason| match reason {
                SyncDeferredReason::NoPeers => FfiSyncDeferredReason::NoPeers,
                SyncDeferredReason::NoReachablePeers => FfiSyncDeferredReason::NoReachablePeers,
                SyncDeferredReason::UnsupportedPeer => FfiSyncDeferredReason::UnsupportedPeer,
                SyncDeferredReason::Deadline => FfiSyncDeferredReason::Deadline,
                SyncDeferredReason::ContributionSkipped => {
                    FfiSyncDeferredReason::ContributionSkipped
                }
                SyncDeferredReason::LocalStorageLimit => FfiSyncDeferredReason::LocalStorageLimit,
            })
            .collect(),
    }
}

fn runtime() -> Result<&'static tokio::runtime::Runtime, FfiError> {
    static RUNTIME: OnceLock<Result<tokio::runtime::Runtime, FfiError>> = OnceLock::new();
    RUNTIME
        .get_or_init(|| {
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|_| FfiError::Internal)
        })
        .as_ref()
        .map_err(|error| *error)
}

#[derive(uniffi::Object)]
pub struct LocalPreferenceModel {
    model: Mutex<PreferenceModel>,
}

#[uniffi::export]
impl LocalPreferenceModel {
    #[uniffi::constructor]
    pub fn new(dimensions: u32, encoder_version: u16) -> Result<Arc<Self>, FfiError> {
        if dimensions == 0 || dimensions > MAX_MODEL_DIMENSIONS {
            return Err(FfiError::InvalidInput);
        }
        let model = PreferenceModel::new(dimensions as usize, encoder_version, 0.1, 0.001, 64)
            .map_err(FfiError::from)?;
        Ok(Arc::new(Self {
            model: Mutex::new(model),
        }))
    }

    pub fn score(&self, version: u16, values: Vec<f64>) -> Result<FfiRankingScore, FfiError> {
        let embedding = PhotoEmbedding::new(version, values).map_err(FfiError::from)?;
        let model = self.model.lock().map_err(|_| FfiError::Internal)?;
        let score = model.score(&embedding).map_err(FfiError::from)?;
        Ok(FfiRankingScore {
            probability: score.probability,
        })
    }

    pub fn record_feedback(
        &self,
        version: u16,
        values: Vec<f64>,
        liked: bool,
    ) -> Result<(), FfiError> {
        let embedding = PhotoEmbedding::new(version, values).map_err(FfiError::from)?;
        self.model
            .lock()
            .map_err(|_| FfiError::Internal)?
            .update(&embedding, liked)
            .map_err(FfiError::from)
    }

    pub fn reset(&self) -> Result<(), FfiError> {
        self.model.lock().map_err(|_| FfiError::Internal)?.reset();
        Ok(())
    }
}

#[uniffi::export]
pub fn api_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

#[cfg(test)]
#[path = "tests/lib.rs"]
mod tests;
