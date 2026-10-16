//! One finite client session used by foreground and host-scheduled sync.

use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use annoda_core::{
    Error as CoreError, UnlockedAccount,
    identity::{TrustedIssuers, VerifiedCredential},
    notifications::NotificationEvent,
    protocol::{ContentLease, MailboxParcel, MessageKind, PhotoManifest, PublicProfile},
    storage::{MailboxCursor, PeerStorage, StorageLimits},
};
use libp2p::{Multiaddr, PeerId};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::node::NetworkError;
use crate::{BootstrapPeer, Clock, NodeConfig, PeerNode, SystemClock, transfer::TransferMeter};

const MAX_INPUT_PEERS: usize = 256;
const MAX_SESSION_PEERS: usize = 16;
const MAX_SESSION_ITEMS: usize = 256;
const MAX_SESSION_BYTES: u64 = 128 * 1024 * 1024;
const MAX_RETRIES: u16 = 3;
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_SESSION_DURATION: Duration = Duration::from_secs(15 * 60);
const MAX_CONTRIBUTION_DURATION: Duration = Duration::from_secs(5 * 60);
const MAX_CONTRIBUTION_REPLICAS: usize = 32;
const MAX_CONTRIBUTION_PHOTOS: usize = 64;

#[derive(Clone, Debug)]
pub struct SyncPeerAddress {
    pub peer_id: String,
    pub address: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostConditions {
    pub wifi_available: bool,
    pub charging: bool,
}

#[derive(Clone, Debug)]
pub struct PeerContributionPolicy {
    pub enabled: bool,
    pub wifi_only: bool,
    pub charging_only: bool,
    pub max_storage_bytes: u64,
    pub max_transfer_bytes: u64,
    pub max_duration: Duration,
}

impl Default for PeerContributionPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            wifi_only: false,
            charging_only: false,
            max_storage_bytes: 0,
            max_transfer_bytes: 0,
            max_duration: Duration::ZERO,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AuthorizedReplicaPhoto {
    pub manifest: PhotoManifest,
    pub lease: ContentLease,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct AuthorizedReplica {
    pub profile: PublicProfile,
    pub owner: VerifiedCredential,
    pub photos: Vec<AuthorizedReplicaPhoto>,
}

#[derive(Clone, Debug, Default)]
pub struct ContributionInputs {
    pub policy: PeerContributionPolicy,
    pub conditions: HostConditions,
    pub replicas: Vec<AuthorizedReplica>,
}

pub struct SyncContext {
    pub credential: VerifiedCredential,
    pub issuers: TrustedIssuers,
    pub state_path: PathBuf,
    pub transport_data_dir: PathBuf,
    peers: Vec<BootstrapPeer>,
    clock: Arc<dyn Clock>,
    pub contribution: ContributionInputs,
}

impl SyncContext {
    pub fn new(
        credential: VerifiedCredential,
        issuers: TrustedIssuers,
        state_path: PathBuf,
        transport_data_dir: PathBuf,
        peers: Vec<SyncPeerAddress>,
    ) -> Result<Self, SyncError> {
        if peers.len() > MAX_INPUT_PEERS {
            return Err(SyncError::InvalidContext);
        }
        let peers = peers
            .into_iter()
            .map(|peer| {
                Ok(BootstrapPeer {
                    peer_id: peer
                        .peer_id
                        .parse()
                        .map_err(|_| SyncError::InvalidContext)?,
                    address: peer
                        .address
                        .parse::<Multiaddr>()
                        .map_err(|_| SyncError::InvalidContext)?,
                })
            })
            .collect::<Result<Vec<_>, SyncError>>()?;
        Ok(Self {
            credential,
            issuers,
            state_path,
            transport_data_dir,
            peers,
            clock: Arc::new(SystemClock),
            contribution: ContributionInputs::default(),
        })
    }

    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn with_contribution(mut self, inputs: ContributionInputs) -> Self {
        self.contribution = inputs;
        self
    }

    pub fn peer_addresses(&self) -> Vec<SyncPeerAddress> {
        self.peers
            .iter()
            .map(|peer| SyncPeerAddress {
                peer_id: peer.peer_id.to_string(),
                address: peer.address.to_string(),
            })
            .collect()
    }
}

#[derive(Clone, Debug)]
pub struct SyncBudget {
    pub max_duration: Duration,
    pub max_download_bytes: u64,
    pub max_upload_bytes: u64,
    pub max_peers: u16,
    pub max_mailbox_items: u16,
    pub max_concurrent_requests: u16,
    pub retries: u16,
    pub request_timeout: Duration,
}

impl Default for SyncBudget {
    fn default() -> Self {
        Self {
            max_duration: Duration::from_secs(30),
            max_download_bytes: 8 * 1024 * 1024,
            max_upload_bytes: 512 * 1024,
            max_peers: 4,
            max_mailbox_items: 64,
            max_concurrent_requests: 1,
            retries: 1,
            request_timeout: Duration::from_secs(8),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncStatus {
    Complete,
    Partial,
    Deferred,
    Cancelled,
    BudgetExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncDeferredReason {
    NoPeers,
    NoReachablePeers,
    UnsupportedPeer,
    Deadline,
    ContributionSkipped,
    LocalStorageLimit,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncReport {
    pub status: SyncStatus,
    pub verified_items: u32,
    pub rejected_items: u32,
    pub downloaded_bytes: u64,
    pub uploaded_bytes: u64,
    pub contacted_peers: Vec<String>,
    pub new_events: Vec<NotificationEvent>,
    pub confirmed_replicas: u32,
    pub deferred_reasons: Vec<SyncDeferredReason>,
}

impl SyncReport {
    fn new(status: SyncStatus) -> Self {
        Self {
            status,
            verified_items: 0,
            rejected_items: 0,
            downloaded_bytes: 0,
            uploaded_bytes: 0,
            contacted_peers: Vec::new(),
            new_events: Vec::new(),
            confirmed_replicas: 0,
            deferred_reasons: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncError {
    InvalidBudget,
    InvalidContext,
    AccountCredentialMismatch,
    Busy,
    Startup,
    Storage,
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidBudget => "sync budget is invalid",
            Self::InvalidContext => "sync context is invalid",
            Self::AccountCredentialMismatch => "account does not match the credential",
            Self::Busy => "another sync session owns this account state",
            Self::Startup => "sync session could not start",
            Self::Storage => "sync state could not be opened",
        })
    }
}

impl std::error::Error for SyncError {}

#[derive(Clone, Debug, Default)]
pub struct SyncCancellationToken(CancellationToken);

impl SyncCancellationToken {
    pub fn new() -> Self {
        Self(CancellationToken::new())
    }

    pub fn cancel(&self) {
        self.0.cancel();
    }

    pub fn is_cancelled(&self) -> bool {
        self.0.is_cancelled()
    }

    pub(crate) fn inner(&self) -> &CancellationToken {
        &self.0
    }
}

/// Runs one allowlisted P2P session and waits for all swarm work to stop before returning.
pub async fn sync_once(
    account: &UnlockedAccount,
    mut context: SyncContext,
    budget: SyncBudget,
    cancellation: SyncCancellationToken,
) -> Result<SyncReport, SyncError> {
    validate_budget(&budget, &context.contribution.policy)?;
    let owner = context.credential.profile_id();
    if account.identity().profile_id() != owner
        || context
            .credential
            .verify(&context.issuers, context.clock.now())
            .is_err()
    {
        return Err(SyncError::AccountCredentialMismatch);
    }

    let selected = select_peers(
        std::mem::take(&mut context.peers),
        budget.max_peers as usize,
    );
    if selected.is_empty() {
        let mut report = SyncReport::new(SyncStatus::Deferred);
        report.deferred_reasons.push(SyncDeferredReason::NoPeers);
        return Ok(report);
    }
    if budget.max_mailbox_items == 0
        || budget.max_download_bytes == 0
        || budget.max_upload_bytes == 0
    {
        return Ok(SyncReport::new(SyncStatus::BudgetExhausted));
    }
    if cancellation.is_cancelled() {
        return Ok(SyncReport::new(SyncStatus::Cancelled));
    }

    let deadline = Instant::now() + budget.max_duration;
    let lock = AccountSyncLock::acquire(&context.state_path)?;
    let busy_timeout = deadline
        .saturating_duration_since(Instant::now())
        .min(Duration::from_millis(25));
    let mut storage = PeerStorage::open_with_busy_timeout(
        &context.state_path,
        StorageLimits::default(),
        busy_timeout,
    )
    .map_err(|_| SyncError::Storage)?;
    let meter = TransferMeter::new(budget.max_download_bytes, budget.max_upload_bytes);
    let selected_ids = selected
        .iter()
        .map(|peer| peer.peer_id)
        .collect::<HashSet<_>>();
    let mut node_config = NodeConfig {
        data_dir: context.transport_data_dir.clone(),
        bootstrap_peers: selected.clone(),
        request_timeout: budget.request_timeout,
        clock: context.clock.clone(),
        max_connections: (selected.len() as u32).max(1),
        ..NodeConfig::default()
    };
    node_config.listen_addresses.clear();
    let node = PeerNode::start_sync(
        node_config,
        context.issuers.clone(),
        meter.clone(),
        selected_ids,
    )
    .await
    .map_err(|_| SyncError::Startup)?;

    let result = run_session(
        account,
        &context,
        &budget,
        &cancellation,
        deadline,
        &node,
        &mut storage,
        &selected,
        &meter,
    )
    .await;
    node.shutdown().await;
    drop(lock);
    result.map(|mut report| {
        report.downloaded_bytes = meter.downloaded();
        report.uploaded_bytes = meter.uploaded();
        report
    })
}

#[allow(clippy::too_many_arguments)] // Keeps the session's borrowed resources explicit.
pub(crate) async fn run_session(
    account: &UnlockedAccount,
    context: &SyncContext,
    budget: &SyncBudget,
    cancellation: &SyncCancellationToken,
    deadline: Instant,
    node: &PeerNode,
    storage: &mut PeerStorage,
    peers: &[BootstrapPeer],
    meter: &TransferMeter,
) -> Result<SyncReport, SyncError> {
    let mut report = SyncReport::new(SyncStatus::Complete);
    let mut any_success = false;
    for peer in peers {
        if report.verified_items + report.rejected_items >= u32::from(budget.max_mailbox_items) {
            report.status = SyncStatus::BudgetExhausted;
            break;
        }
        if cancellation.is_cancelled() {
            report.status = SyncStatus::Cancelled;
            break;
        }
        if Instant::now() >= deadline {
            report.status = SyncStatus::BudgetExhausted;
            report.deferred_reasons.push(SyncDeferredReason::Deadline);
            break;
        }
        let peer_key = peer.peer_id.to_string();
        let mut cursor = storage
            .load_mailbox_checkpoint(context.credential.profile_id(), &peer_key)
            .map_err(|_| SyncError::Storage)?;
        let mut peer_complete = false;
        let mut peer_responded = false;
        while report.verified_items + report.rejected_items < u32::from(budget.max_mailbox_items) {
            if cancellation.is_cancelled() {
                report.status = SyncStatus::Cancelled;
                return Ok(report);
            }
            if Instant::now() >= deadline {
                report.status = SyncStatus::BudgetExhausted;
                report.deferred_reasons.push(SyncDeferredReason::Deadline);
                return Ok(report);
            }
            if meter.downloaded() >= budget.max_download_bytes
                || meter.uploaded() >= budget.max_upload_bytes
            {
                report.status = SyncStatus::BudgetExhausted;
                break;
            }
            let remaining = (u32::from(budget.max_mailbox_items)
                - report.verified_items
                - report.rejected_items) as usize;
            let page_limit = remaining.min(64);
            let (parcels, next_cursor, completed) = match request_page(
                account,
                context,
                budget,
                cancellation,
                deadline,
                node,
                peer.peer_id,
                cursor,
                page_limit,
            )
            .await
            {
                Ok(page) => {
                    peer_responded = true;
                    any_success = true;
                    page
                }
                Err(RequestStop::Cancelled) => {
                    report.status = SyncStatus::Cancelled;
                    return Ok(report);
                }
                Err(RequestStop::Deadline) => {
                    report.status = SyncStatus::BudgetExhausted;
                    report.deferred_reasons.push(SyncDeferredReason::Deadline);
                    return Ok(report);
                }
                Err(RequestStop::Budget) => {
                    report.status = SyncStatus::BudgetExhausted;
                    return Ok(report);
                }
                Err(RequestStop::PeerUnavailable) => {
                    report
                        .deferred_reasons
                        .push(SyncDeferredReason::UnsupportedPeer);
                    if any_success {
                        report.status = SyncStatus::Partial;
                    }
                    break;
                }
            };
            if !report.contacted_peers.iter().any(|id| id == &peer_key) {
                report.contacted_peers.push(peer_key.clone());
            }
            if parcels.len() > page_limit
                || (parcels.is_empty() && !completed)
                || (parcels.last().map(cursor_for) != next_cursor)
            {
                report.status = SyncStatus::Partial;
                report
                    .deferred_reasons
                    .push(SyncDeferredReason::UnsupportedPeer);
                break;
            }

            let mut previous = cursor;
            let mut local_failure = false;
            for parcel in parcels {
                if cancellation.is_cancelled() {
                    report.status = SyncStatus::Cancelled;
                    return Ok(report);
                }
                if Instant::now() >= deadline {
                    report.status = SyncStatus::BudgetExhausted;
                    report.deferred_reasons.push(SyncDeferredReason::Deadline);
                    return Ok(report);
                }
                let item_cursor = cursor_for(&parcel);
                if previous.is_some_and(|old| !cursor_after(item_cursor, old)) {
                    report.status = SyncStatus::Partial;
                    report
                        .deferred_reasons
                        .push(SyncDeferredReason::UnsupportedPeer);
                    local_failure = true;
                    break;
                }
                let now = context.clock.now();
                if parcel.recipient != context.credential.profile_id() {
                    storage
                        .mark_mailbox_rejected(
                            context.credential.profile_id(),
                            &peer_key,
                            item_cursor,
                        )
                        .map_err(|_| SyncError::Storage)?;
                    report.rejected_items += 1;
                    previous = Some(item_cursor);
                    continue;
                }
                let opened = match parcel.open(
                    account.identity(),
                    &context.credential,
                    &context.issuers,
                    now,
                ) {
                    Ok(opened) => opened,
                    Err(_) => {
                        storage
                            .mark_mailbox_rejected(
                                context.credential.profile_id(),
                                &peer_key,
                                item_cursor,
                            )
                            .map_err(|_| SyncError::Storage)?;
                        report.rejected_items += 1;
                        previous = Some(item_cursor);
                        continue;
                    }
                };
                let result = match opened.envelope.kind {
                    MessageKind::Like => storage
                        .receive_like_checkpointed(
                            &opened.envelope,
                            &opened.sender_credential,
                            account.identity(),
                            &context.credential,
                            &context.issuers,
                            now,
                            &peer_key,
                            item_cursor,
                        )
                        .map(|(_, events)| events),
                    MessageKind::ContactDisclosure => storage
                        .receive_contact_checkpointed(
                            &opened.envelope,
                            &opened.sender_credential,
                            account.identity(),
                            &context.credential,
                            &context.issuers,
                            now,
                            &peer_key,
                            item_cursor,
                        )
                        .map(|_| Vec::new()),
                };
                match result {
                    Ok(events) => {
                        report.verified_items += 1;
                        report.new_events.extend(events);
                    }
                    Err(CoreError::Storage(_) | CoreError::LimitExceeded) => {
                        report.status = SyncStatus::Partial;
                        report
                            .deferred_reasons
                            .push(SyncDeferredReason::LocalStorageLimit);
                        local_failure = true;
                        break;
                    }
                    Err(_) => {
                        storage
                            .mark_mailbox_rejected(
                                context.credential.profile_id(),
                                &peer_key,
                                item_cursor,
                            )
                            .map_err(|_| SyncError::Storage)?;
                        report.rejected_items += 1;
                    }
                }
                previous = Some(item_cursor);
            }
            if local_failure {
                break;
            }
            cursor = next_cursor;
            if completed {
                storage
                    .save_mailbox_checkpoint(context.credential.profile_id(), &peer_key, None)
                    .map_err(|_| SyncError::Storage)?;
                peer_complete = true;
                break;
            }
            if report.verified_items + report.rejected_items >= u32::from(budget.max_mailbox_items)
            {
                report.status = SyncStatus::BudgetExhausted;
                break;
            }
        }
        if peer_responded && !peer_complete && report.status == SyncStatus::Complete {
            report.status = SyncStatus::Partial;
        }
        if report.status != SyncStatus::Complete {
            break;
        }
    }

    if !any_success && report.status == SyncStatus::Complete {
        report.status = SyncStatus::Deferred;
        if report.deferred_reasons.is_empty() {
            report
                .deferred_reasons
                .push(SyncDeferredReason::NoReachablePeers);
        }
    }

    run_contribution(
        context,
        budget,
        cancellation,
        deadline,
        node,
        peers,
        meter,
        &mut report,
    )
    .await;
    Ok(report)
}

enum RequestStop {
    Cancelled,
    Deadline,
    Budget,
    PeerUnavailable,
}

#[allow(clippy::too_many_arguments)] // Mirrors one bounded request's auth and budget inputs.
async fn request_page(
    account: &UnlockedAccount,
    context: &SyncContext,
    budget: &SyncBudget,
    cancellation: &SyncCancellationToken,
    deadline: Instant,
    node: &PeerNode,
    peer: PeerId,
    cursor: Option<MailboxCursor>,
    limit: usize,
) -> Result<(Vec<MailboxParcel>, Option<MailboxCursor>, bool), RequestStop> {
    for attempt in 0..=budget.retries {
        if cancellation.is_cancelled() {
            return Err(RequestStop::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(RequestStop::Deadline);
        }
        let mut challenge = [0u8; 32];
        getrandom::fill(&mut challenge).map_err(|_| RequestStop::PeerUnavailable)?;
        let proof = PeerStorage::signed_poll_proof(
            account.identity(),
            context.credential.profile_id(),
            challenge,
            context.clock.now(),
        )
        .map_err(|_| RequestStop::PeerUnavailable)?;
        let request = node.poll_mailbox_page(
            peer,
            context.credential.clone(),
            proof,
            challenge,
            context.clock.now(),
            cursor,
            limit,
        );
        let response = tokio::select! {
            _ = cancellation.0.cancelled() => return Err(RequestStop::Cancelled),
            _ = tokio::time::sleep_until(deadline) => return Err(RequestStop::Deadline),
            response = request => response,
        };
        match response {
            Ok(page) => return Ok(page),
            Err(error) if is_transfer_exhausted(&error) => return Err(RequestStop::Budget),
            Err(_) if attempt < budget.retries => continue,
            Err(_) => return Err(RequestStop::PeerUnavailable),
        }
    }
    Err(RequestStop::PeerUnavailable)
}

#[allow(clippy::too_many_arguments)] // Contribution is a phase of the same bounded session.
async fn run_contribution(
    context: &SyncContext,
    budget: &SyncBudget,
    cancellation: &SyncCancellationToken,
    deadline: Instant,
    node: &PeerNode,
    peers: &[BootstrapPeer],
    meter: &TransferMeter,
    report: &mut SyncReport,
) {
    let inputs = &context.contribution;
    let policy = &inputs.policy;
    if !policy.enabled {
        return;
    }
    if (policy.wifi_only && !inputs.conditions.wifi_available)
        || (policy.charging_only && !inputs.conditions.charging)
        || policy.max_storage_bytes == 0
        || policy.max_transfer_bytes == 0
        || policy.max_duration.is_zero()
    {
        report
            .deferred_reasons
            .push(SyncDeferredReason::ContributionSkipped);
        if report.status == SyncStatus::Complete {
            report.status = SyncStatus::Partial;
        }
        return;
    }
    if inputs.replicas.len() > MAX_CONTRIBUTION_REPLICAS
        || inputs
            .replicas
            .iter()
            .any(|replica| replica.photos.len() > MAX_CONTRIBUTION_PHOTOS)
    {
        report
            .deferred_reasons
            .push(SyncDeferredReason::ContributionSkipped);
        if report.status == SyncStatus::Complete {
            report.status = SyncStatus::Partial;
        }
        return;
    }
    let mut owners = HashSet::with_capacity(inputs.replicas.len());
    if inputs
        .replicas
        .iter()
        .any(|replica| !owners.insert(replica.profile.owner))
    {
        report
            .deferred_reasons
            .push(SyncDeferredReason::ContributionSkipped);
        if report.status == SyncStatus::Complete {
            report.status = SyncStatus::Partial;
        }
        return;
    }
    let mut raw_photo_bytes = 0u64;
    for replica in &inputs.replicas {
        if cancellation.is_cancelled() {
            report.status = SyncStatus::Cancelled;
            return;
        }
        if Instant::now() >= deadline {
            report.status = SyncStatus::BudgetExhausted;
            report.deferred_reasons.push(SyncDeferredReason::Deadline);
            return;
        }
        for photo in &replica.photos {
            raw_photo_bytes = raw_photo_bytes.saturating_add(photo.bytes.len() as u64);
            if raw_photo_bytes > policy.max_storage_bytes {
                report
                    .deferred_reasons
                    .push(SyncDeferredReason::ContributionSkipped);
                if report.status == SyncStatus::Complete {
                    report.status = SyncStatus::Partial;
                }
                return;
            }
        }
    }
    let allocated = match replica_batch_size(&inputs.replicas) {
        Ok(bytes) if bytes <= policy.max_storage_bytes => bytes,
        _ => {
            report
                .deferred_reasons
                .push(SyncDeferredReason::ContributionSkipped);
            if report.status == SyncStatus::Complete {
                report.status = SyncStatus::Partial;
            }
            return;
        }
    };
    if cancellation.is_cancelled() {
        report.status = SyncStatus::Cancelled;
        return;
    }
    if Instant::now() >= deadline {
        report.status = SyncStatus::BudgetExhausted;
        report.deferred_reasons.push(SyncDeferredReason::Deadline);
        return;
    }
    if allocated == 0 {
        return;
    }
    let contribution_deadline =
        deadline.min(Instant::now() + policy.max_duration.min(MAX_CONTRIBUTION_DURATION));
    let expected_copies = peers.len().saturating_mul(inputs.replicas.len()) as u32;
    let confirmed_before = report.confirmed_replicas;
    meter.start_phase_limit(policy.max_transfer_bytes);
    meter.set_upload_limit(budget.max_upload_bytes);
    'peers: for peer in peers {
        for replica in &inputs.replicas {
            if cancellation.is_cancelled() {
                report.status = SyncStatus::Cancelled;
                break 'peers;
            }
            if Instant::now() >= contribution_deadline
                || meter.uploaded() >= budget.max_upload_bytes
            {
                break 'peers;
            }
            let now = context.clock.now();
            if replica.owner.profile_id() != replica.profile.owner
                || replica.profile.verify(&context.issuers, now).is_err()
                || replica.profile.credential != replica.owner
                || replica.photos.len() != replica.profile.photos.len()
                || replica.profile.photos.iter().any(|manifest| {
                    replica
                        .photos
                        .iter()
                        .filter(|photo| photo.manifest == *manifest)
                        .count()
                        != 1
                })
            {
                report.rejected_items = report.rejected_items.saturating_add(1);
                continue;
            }
            let profile_request = crate::RpcRequest::PutProfile {
                profile: replica.profile.clone(),
            };
            let profile_result = optional_request(
                node,
                cancellation,
                contribution_deadline,
                peer.peer_id,
                profile_request,
            )
            .await;
            let Some(profile_result) = profile_result else {
                if cancellation.is_cancelled() {
                    report.status = SyncStatus::Cancelled;
                }
                break 'peers;
            };
            if !matches!(profile_result, Ok(crate::RpcResponse::Ack)) {
                continue;
            }
            let mut accepted = true;
            for photo in &replica.photos {
                if cancellation.is_cancelled() {
                    report.status = SyncStatus::Cancelled;
                    accepted = false;
                    break;
                }
                if Instant::now() >= contribution_deadline {
                    accepted = false;
                    break;
                }
                if !photo.manifest.verifies(&photo.bytes)
                    || photo.lease.hash != photo.manifest.hash
                    || photo.lease.byte_count != photo.manifest.byte_count
                    || photo
                        .lease
                        .verify(&replica.owner, &context.issuers, now)
                        .is_err()
                    || photo.lease.expires_at > replica.profile.expires_at
                    || !replica
                        .profile
                        .photos
                        .iter()
                        .any(|manifest| manifest == &photo.manifest)
                {
                    accepted = false;
                    break;
                }
                let request = crate::RpcRequest::PutPhoto {
                    manifest: photo.manifest.clone(),
                    lease: photo.lease.clone(),
                    owner: replica.owner.clone(),
                    blob: photo.bytes.clone(),
                };
                let Some(photo_result) = optional_request(
                    node,
                    cancellation,
                    contribution_deadline,
                    peer.peer_id,
                    request,
                )
                .await
                else {
                    if cancellation.is_cancelled() {
                        report.status = SyncStatus::Cancelled;
                    }
                    break 'peers;
                };
                if !matches!(photo_result, Ok(crate::RpcResponse::Ack)) {
                    accepted = false;
                    break;
                }
            }
            if accepted {
                report.confirmed_replicas = report.confirmed_replicas.saturating_add(1);
            }
        }
    }
    meter.end_phase_limit();
    meter.set_upload_limit(budget.max_upload_bytes);
    let completed_copies = report.confirmed_replicas.saturating_sub(confirmed_before);
    if completed_copies < expected_copies
        && !matches!(
            report.status,
            SyncStatus::Cancelled | SyncStatus::BudgetExhausted
        )
    {
        report
            .deferred_reasons
            .push(SyncDeferredReason::ContributionSkipped);
        report.status = SyncStatus::Partial;
    }
}

async fn optional_request(
    node: &PeerNode,
    cancellation: &SyncCancellationToken,
    deadline: Instant,
    peer: PeerId,
    request: crate::RpcRequest,
) -> Option<Result<crate::RpcResponse, NetworkError>> {
    tokio::select! {
        _ = cancellation.0.cancelled() => None,
        _ = tokio::time::sleep_until(deadline) => None,
        response = node.request(peer, request) => Some(response),
    }
}

fn replica_batch_size(replicas: &[AuthorizedReplica]) -> Result<u64, CoreError> {
    let mut bytes = 0u64;
    for replica in replicas {
        bytes = bytes
            .checked_add(
                postcard::to_allocvec(&replica.profile)
                    .map_err(|_| CoreError::Serialization)?
                    .len() as u64,
            )
            .and_then(|total| {
                total.checked_add(postcard::to_allocvec(&replica.owner).ok()?.len() as u64)
            })
            .ok_or(CoreError::LimitExceeded)?;
        for photo in &replica.photos {
            bytes = bytes
                .checked_add(photo.bytes.len() as u64)
                .and_then(|total| {
                    total.checked_add(postcard::to_allocvec(&photo.manifest).ok()?.len() as u64)
                })
                .and_then(|total| {
                    total.checked_add(postcard::to_allocvec(&photo.lease).ok()?.len() as u64)
                })
                .ok_or(CoreError::LimitExceeded)?;
        }
    }
    Ok(bytes)
}

pub(crate) fn validate_budget(
    budget: &SyncBudget,
    policy: &PeerContributionPolicy,
) -> Result<(), SyncError> {
    if budget.max_duration.is_zero()
        || budget.max_duration > MAX_SESSION_DURATION
        || budget.max_download_bytes > MAX_SESSION_BYTES
        || budget.max_upload_bytes > MAX_SESSION_BYTES
        || budget.max_peers == 0
        || usize::from(budget.max_peers) > MAX_SESSION_PEERS
        || usize::from(budget.max_mailbox_items) > MAX_SESSION_ITEMS
        || budget.max_concurrent_requests == 0
        || budget.max_concurrent_requests > 32
        || budget.retries > MAX_RETRIES
        || budget.request_timeout.is_zero()
        || budget.request_timeout > MAX_REQUEST_TIMEOUT
        || (policy.enabled
            && (policy.max_duration > MAX_CONTRIBUTION_DURATION
                || policy.max_storage_bytes > MAX_SESSION_BYTES
                || policy.max_transfer_bytes > MAX_SESSION_BYTES))
    {
        return Err(SyncError::InvalidBudget);
    }
    Ok(())
}

fn select_peers(peers: Vec<BootstrapPeer>, limit: usize) -> Vec<BootstrapPeer> {
    let mut seen = HashSet::new();
    peers
        .into_iter()
        .filter(|peer| seen.insert(peer.peer_id))
        .take(limit.min(MAX_SESSION_PEERS))
        .collect()
}

fn cursor_for(parcel: &MailboxParcel) -> MailboxCursor {
    MailboxCursor {
        expires_at: parcel.expires_at,
        parcel_id: parcel.id,
    }
}

fn cursor_after(left: MailboxCursor, right: MailboxCursor) -> bool {
    (left.expires_at, left.parcel_id) > (right.expires_at, right.parcel_id)
}

fn is_transfer_exhausted(error: &NetworkError) -> bool {
    matches!(error, NetworkError::Request(message) if message.contains("sync transfer budget exhausted"))
        || matches!(error, NetworkError::BandwidthLimited)
}

pub(crate) struct AccountSyncLock {
    _file: File,
}

impl AccountSyncLock {
    pub(crate) fn acquire(state_path: &Path) -> Result<Self, SyncError> {
        let lock_path = state_path.with_extension("sync.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(lock_path).map_err(|_| SyncError::Storage)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(SyncError::Busy),
            Err(std::fs::TryLockError::Error(_)) => Err(SyncError::Storage),
        }
    }
}

#[cfg(test)]
#[path = "tests/sync.rs"]
mod tests;
