//! UniFFI adapter for the owner-scoped application service.

use std::{
    future::Future,
    path::PathBuf,
    pin::Pin,
    sync::{Arc, Mutex},
};

use annoda_core::{
    identity::TrustedIssuers,
    matching::{ContactHandle, ContactService, MatchState},
    protocol::{ContentHash, PhotoManifest, ProfileId, PublicProfile},
    storage::{OutgoingOperationKind, OutgoingOperationStatus},
};
use annoda_intelligence::safety::DeterministicSafetyFixture;
use annoda_intelligence::{
    ranking::{CandidateFilter, PhotoEmbedding, RankingCandidate},
    safety::ProfileReport,
};
use annoda_network::{
    SyncPeerAddress,
    client::{
        AnnodaClient, CandidateProfile, ClientConfig, ClientError, DeliveryFailureReason,
        DiscoveryQuery, IdentitySummary, IncomingLike, MatchSummary, OperationReceipt, PageCursor,
        PublicationReceipt, ValidatedPhotoDto,
    },
};
use zeroize::Zeroizing;

use crate::{
    FfiError, FfiSyncBudget, FfiSyncPeer, SessionShared, SyncSession, map_sync_report, runtime,
    sync_budget,
};

/// Public issuer and peer settings for one private application account.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiApplicationConfig {
    pub data_directory: String,
    pub transport_data_directory: String,
    pub trusted_issuer_keys: Vec<Vec<u8>>,
    pub revoked_serials: Vec<Vec<u8>>,
    pub peers: Vec<FfiSyncPeer>,
    pub sync_budget: FfiSyncBudget,
    /// Enables only the deterministic safety fixture for local development and tests.
    pub allow_development_safety_fixture: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiIdentitySummary {
    pub profile_id: Vec<u8>,
    pub signing_public_key: Vec<u8>,
    pub encryption_public_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPageCursor {
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiDiscoveryQuery {
    pub minimum_age: u8,
    pub maximum_age: u8,
    pub page_size: u8,
    pub cursor: Option<FfiPageCursor>,
    pub coarse_region: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPhotoManifest {
    pub hash: Vec<u8>,
    pub byte_count: u32,
    pub media_type: String,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct FfiCandidateProfile {
    pub profile_id: Vec<u8>,
    pub first_name: String,
    pub age_at_issue: u8,
    pub revision: u64,
    pub expires_at: u64,
    pub photos: Vec<FfiPhotoManifest>,
    pub score: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct FfiCandidatePage {
    pub items: Vec<FfiCandidateProfile>,
    pub next_cursor: Option<FfiPageCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiValidatedPhoto {
    pub bytes: Vec<u8>,
    pub hash: Vec<u8>,
    pub media_type: String,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiMatchState {
    Neutral,
    Outgoing,
    Incoming,
    Matched,
    Rejected,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiIncomingLike {
    pub sender: Vec<u8>,
    pub first_name: String,
    pub age_at_issue: u8,
    pub state: FfiMatchState,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiIncomingLikePage {
    pub items: Vec<FfiIncomingLike>,
    pub next_cursor: Option<FfiPageCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiMatchSummary {
    pub peer: Vec<u8>,
    pub match_id: Vec<u8>,
    pub first_name: String,
    pub age_at_issue: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiMatchPage {
    pub items: Vec<FfiMatchSummary>,
    pub next_cursor: Option<FfiPageCursor>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiContactService {
    Instagram,
    Telegram,
    WhatsApp,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiContactHandle {
    pub service: FfiContactService,
    pub other_service: Option<String>,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiOperationKind {
    Publication,
    Like,
    Contact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiOperationStatus {
    Pending,
    Partial,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiDeliveryFailureReason {
    Unreachable,
    Rejected,
    Budget,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiDeliveryFailure {
    pub peer_id: String,
    pub item_hash: Vec<u8>,
    pub reason: FfiDeliveryFailureReason,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiOperationReceipt {
    pub operation_id: Vec<u8>,
    pub kind: FfiOperationKind,
    pub status: FfiOperationStatus,
    pub acknowledged_peers: u32,
    pub required_acknowledgements: u32,
    pub pending_items: Vec<Vec<u8>>,
    pub failures: Vec<FfiDeliveryFailure>,
    pub retry_recommended: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiOperationPage {
    pub items: Vec<FfiOperationReceipt>,
    pub next_cursor: Option<FfiPageCursor>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiPublicationReceipt {
    pub operation: FfiOperationReceipt,
    pub revision: u64,
    pub replicated_peers: u32,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct FfiRankingCandidate {
    pub profile_id: Vec<u8>,
    pub verified_age: u8,
    pub adult_credential_valid: bool,
    pub coarse_region: Option<String>,
    pub embedding_version: u16,
    pub embedding_values: Vec<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiCandidateFilter {
    pub minimum_age: u8,
    pub maximum_age: u8,
    pub coarse_region: Option<String>,
    pub blocked_profile_ids: Vec<Vec<u8>>,
    pub passed_profile_ids: Vec<Vec<u8>>,
    pub seen_profile_ids: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, uniffi::Record)]
pub struct FfiRankedCandidate {
    pub profile_id: Vec<u8>,
    pub probability: f64,
    pub explored: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiReportDeliveryStatus {
    LocalOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiProfileReport {
    pub report_id: Vec<u8>,
    pub subject: Vec<u8>,
    pub policy_reason: u16,
    pub evidence_hashes: Vec<Vec<u8>>,
    pub created_at: u64,
    pub signature: Vec<u8>,
    pub delivery_status: FfiReportDeliveryStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct FfiProfileReportPage {
    pub items: Vec<FfiProfileReport>,
    pub next_cursor: Option<FfiPageCursor>,
}

fn client_config(config: FfiApplicationConfig) -> Result<ClientConfig, FfiError> {
    if config.trusted_issuer_keys.len() > 16
        || config.revoked_serials.len() > 4096
        || config.peers.len() > 256
    {
        return Err(FfiError::InvalidInput);
    }
    let mut issuer_keys = Vec::with_capacity(config.trusted_issuer_keys.len());
    for key in config.trusted_issuer_keys {
        issuer_keys.push(
            key.as_slice()
                .try_into()
                .map_err(|_| FfiError::InvalidInput)?,
        );
    }
    let mut issuers = TrustedIssuers::new(issuer_keys);
    for serial in config.revoked_serials {
        issuers.revoke_serial(
            serial
                .as_slice()
                .try_into()
                .map_err(|_| FfiError::InvalidInput)?,
        );
    }
    let peers = config
        .peers
        .into_iter()
        .map(|peer| SyncPeerAddress {
            peer_id: peer.peer_id,
            address: peer.address,
        })
        .collect();
    let data_dir = application_path(config.data_directory)?;
    let transport_dir = application_path(config.transport_data_directory)?;
    let mut client = ClientConfig::new(data_dir, peers, issuers)
        .with_transport_data_dir(transport_dir)
        .with_sync_budget(sync_budget(config.sync_budget));
    if config.allow_development_safety_fixture {
        let fixture = DeterministicSafetyFixture::new(0.0).map_err(|_| FfiError::Internal)?;
        client = client.with_safety_classifier(Arc::new(fixture), true);
    }
    Ok(client)
}

fn application_path(path: String) -> Result<PathBuf, FfiError> {
    if path.is_empty() || path.len() > 4096 || path.chars().any(char::is_control) {
        return Err(FfiError::InvalidInput);
    }
    Ok(PathBuf::from(path))
}

fn map_client_error(error: ClientError) -> FfiError {
    match error {
        ClientError::InvalidInput => FfiError::InvalidInput,
        ClientError::Unauthorized => FfiError::Unauthorized,
        ClientError::UntrustedIdentity => FfiError::UntrustedIdentity,
        ClientError::CredentialExpired => FfiError::CredentialExpired,
        ClientError::SafetyUnavailable => FfiError::SafetyUnavailable,
        ClientError::SafetyRejected => FfiError::SafetyRejected,
        ClientError::NetworkUnavailable => FfiError::NetworkUnavailable,
        ClientError::StorageFull => FfiError::StorageFull,
        ClientError::Cancelled => FfiError::Cancelled,
        ClientError::Pending => FfiError::Pending,
        ClientError::Unsupported => FfiError::Unsupported,
        ClientError::Busy => FfiError::AccountBusy,
        ClientError::Storage => FfiError::StorageUnavailable,
        ClientError::AccountMissing => FfiError::AccountMissing,
        ClientError::AccountInaccessible => FfiError::AccountInaccessible,
        ClientError::AuthenticationFailed => FfiError::AuthenticationFailed,
        ClientError::CorruptVault => FfiError::CorruptVault,
        ClientError::UnsupportedVaultVersion => FfiError::UnsupportedVaultVersion,
        ClientError::AccountAlreadyExists => FfiError::AccountAlreadyExists,
        ClientError::Vault | ClientError::Internal => FfiError::Internal,
    }
}

fn ffi_identity(summary: IdentitySummary) -> FfiIdentitySummary {
    FfiIdentitySummary {
        profile_id: summary.profile_id.0.to_vec(),
        signing_public_key: summary.signing_public_key.to_vec(),
        encryption_public_key: summary.encryption_public_key,
    }
}

fn ffi_cursor(cursor: Option<annoda_network::client::PageCursor>) -> Option<FfiPageCursor> {
    cursor.map(|cursor| FfiPageCursor { value: cursor.0 })
}

fn ffi_manifest(manifest: PhotoManifest) -> FfiPhotoManifest {
    FfiPhotoManifest {
        hash: manifest.hash.0.to_vec(),
        byte_count: manifest.byte_count,
        media_type: manifest.media_type,
    }
}

fn ffi_candidate(candidate: CandidateProfile) -> FfiCandidateProfile {
    let PublicProfile {
        revision,
        owner,
        credential,
        photos,
        expires_at,
        ..
    } = candidate.profile;
    FfiCandidateProfile {
        profile_id: owner.0.to_vec(),
        first_name: credential.claims.first_name,
        age_at_issue: credential.claims.age_at_issue,
        revision,
        expires_at,
        photos: photos.into_iter().map(ffi_manifest).collect(),
        score: candidate.score,
    }
}

fn ffi_photo(photo: ValidatedPhotoDto) -> FfiValidatedPhoto {
    FfiValidatedPhoto {
        bytes: photo.bytes,
        hash: photo.hash.0.to_vec(),
        media_type: photo.media_type,
        width: photo.width,
        height: photo.height,
    }
}

fn ffi_match_state(state: MatchState) -> FfiMatchState {
    match state {
        MatchState::Neutral => FfiMatchState::Neutral,
        MatchState::Outgoing => FfiMatchState::Outgoing,
        MatchState::Incoming => FfiMatchState::Incoming,
        MatchState::Matched => FfiMatchState::Matched,
        MatchState::Rejected => FfiMatchState::Rejected,
        MatchState::Blocked => FfiMatchState::Blocked,
    }
}

fn ffi_incoming_like(like: IncomingLike) -> FfiIncomingLike {
    FfiIncomingLike {
        sender: like.sender.0.to_vec(),
        first_name: like.credential.claims.first_name,
        age_at_issue: like.credential.claims.age_at_issue,
        state: ffi_match_state(like.state),
    }
}

fn ffi_match(summary: MatchSummary) -> FfiMatchSummary {
    FfiMatchSummary {
        peer: summary.peer.0.to_vec(),
        match_id: summary.match_id.to_vec(),
        first_name: summary.credential.claims.first_name,
        age_at_issue: summary.credential.claims.age_at_issue,
    }
}

fn from_ffi_contact(contact: FfiContactHandle) -> Result<ContactHandle, FfiError> {
    let service = match contact.service {
        FfiContactService::Instagram => {
            if contact.other_service.is_some() {
                return Err(FfiError::InvalidInput);
            }
            ContactService::Instagram
        }
        FfiContactService::Telegram => {
            if contact.other_service.is_some() {
                return Err(FfiError::InvalidInput);
            }
            ContactService::Telegram
        }
        FfiContactService::WhatsApp => {
            if contact.other_service.is_some() {
                return Err(FfiError::InvalidInput);
            }
            ContactService::WhatsApp
        }
        FfiContactService::Other => {
            ContactService::Other(contact.other_service.ok_or(FfiError::InvalidInput)?)
        }
    };
    Ok(ContactHandle {
        service,
        value: contact.value,
    })
}

fn to_ffi_contact(contact: ContactHandle) -> FfiContactHandle {
    let (service, other_service) = match contact.service {
        ContactService::Instagram => (FfiContactService::Instagram, None),
        ContactService::Telegram => (FfiContactService::Telegram, None),
        ContactService::WhatsApp => (FfiContactService::WhatsApp, None),
        ContactService::Other(value) => (FfiContactService::Other, Some(value)),
    };
    FfiContactHandle {
        service,
        other_service,
        value: contact.value,
    }
}

fn ffi_operation(operation: OperationReceipt) -> FfiOperationReceipt {
    FfiOperationReceipt {
        operation_id: operation.operation_id.to_vec(),
        kind: match operation.kind {
            OutgoingOperationKind::Publication => FfiOperationKind::Publication,
            OutgoingOperationKind::Like => FfiOperationKind::Like,
            OutgoingOperationKind::Contact => FfiOperationKind::Contact,
        },
        status: match operation.status {
            OutgoingOperationStatus::Pending => FfiOperationStatus::Pending,
            OutgoingOperationStatus::Partial => FfiOperationStatus::Partial,
            OutgoingOperationStatus::Completed => FfiOperationStatus::Completed,
            OutgoingOperationStatus::Failed => FfiOperationStatus::Failed,
        },
        acknowledged_peers: operation.acknowledged_peers,
        required_acknowledgements: operation.required_acknowledgements,
        pending_items: operation
            .pending_items
            .into_iter()
            .map(|item| item.to_vec())
            .collect(),
        failures: operation
            .failures
            .into_iter()
            .map(|failure| FfiDeliveryFailure {
                peer_id: failure.peer_id,
                item_hash: failure.item_hash.to_vec(),
                reason: match failure.reason {
                    DeliveryFailureReason::Unreachable => FfiDeliveryFailureReason::Unreachable,
                    DeliveryFailureReason::Rejected => FfiDeliveryFailureReason::Rejected,
                    DeliveryFailureReason::Budget => FfiDeliveryFailureReason::Budget,
                    DeliveryFailureReason::Cancelled => FfiDeliveryFailureReason::Cancelled,
                },
            })
            .collect(),
        retry_recommended: operation.retry_recommended,
    }
}

fn ffi_publication(receipt: PublicationReceipt) -> FfiPublicationReceipt {
    FfiPublicationReceipt {
        operation: ffi_operation(receipt.operation),
        revision: receipt.revision,
        replicated_peers: receipt.replicated_peers,
    }
}

fn parse_profile_id(bytes: Vec<u8>) -> Result<ProfileId, FfiError> {
    Ok(ProfileId(
        bytes.try_into().map_err(|_| FfiError::InvalidInput)?,
    ))
}

fn parse_content_hash(bytes: Vec<u8>) -> Result<ContentHash, FfiError> {
    Ok(ContentHash(
        bytes.try_into().map_err(|_| FfiError::InvalidInput)?,
    ))
}

fn parse_match_id(bytes: Vec<u8>) -> Result<[u8; 32], FfiError> {
    bytes.try_into().map_err(|_| FfiError::InvalidInput)
}

fn profile_id_text(profile_id: ProfileId) -> String {
    profile_id
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_profile_set(values: Vec<Vec<u8>>) -> Result<std::collections::HashSet<String>, FfiError> {
    if values.len() > 512 {
        return Err(FfiError::InvalidInput);
    }
    values
        .into_iter()
        .map(|bytes| parse_profile_id(bytes).map(profile_id_text))
        .collect()
}

fn to_ranking_candidate(candidate: FfiRankingCandidate) -> Result<RankingCandidate, FfiError> {
    let id = profile_id_text(parse_profile_id(candidate.profile_id)?);
    if candidate.embedding_values.len() > 4096 {
        return Err(FfiError::InvalidInput);
    }
    let embedding = PhotoEmbedding::new(candidate.embedding_version, candidate.embedding_values)
        .map_err(|_| FfiError::InvalidInput)?;
    Ok(RankingCandidate {
        id,
        verified_age: candidate.verified_age,
        adult_credential_valid: candidate.adult_credential_valid,
        coarse_region: candidate.coarse_region,
        embedding,
    })
}

fn to_candidate_filter(filter: FfiCandidateFilter) -> Result<CandidateFilter, FfiError> {
    if filter.minimum_age < 18 || filter.maximum_age < filter.minimum_age {
        return Err(FfiError::InvalidInput);
    }
    Ok(CandidateFilter {
        minimum_age: filter.minimum_age,
        maximum_age: filter.maximum_age,
        coarse_region: filter.coarse_region,
        blocked: parse_profile_set(filter.blocked_profile_ids)?,
        passed: parse_profile_set(filter.passed_profile_ids)?,
        seen: parse_profile_set(filter.seen_profile_ids)?,
    })
}

fn ffi_report(report: ProfileReport) -> FfiProfileReport {
    FfiProfileReport {
        report_id: report.report_id.to_vec(),
        subject: report.subject.to_vec(),
        policy_reason: report.policy_reason,
        evidence_hashes: report.evidence_hashes.into_iter().map(Vec::from).collect(),
        created_at: report.created_at,
        signature: report.signature,
        delivery_status: FfiReportDeliveryStatus::LocalOnly,
    }
}

fn to_client_query(query: FfiDiscoveryQuery) -> Result<DiscoveryQuery, FfiError> {
    let cursor = to_client_cursor(query.cursor)?;
    Ok(DiscoveryQuery {
        minimum_age: query.minimum_age,
        maximum_age: query.maximum_age,
        page_size: query.page_size,
        cursor,
        coarse_region: query.coarse_region,
    })
}

fn to_client_cursor(cursor: Option<FfiPageCursor>) -> Result<Option<PageCursor>, FfiError> {
    cursor
        .map(|cursor| {
            if cursor.value.is_empty() || cursor.value.len() > 256 {
                Err(FfiError::InvalidInput)
            } else {
                Ok(PageCursor(cursor.value))
            }
        })
        .transpose()
}

/// An account-owning adapter. All application calls serialize through one service instance.
#[derive(uniffi::Object)]
pub struct ApplicationHandle {
    client: Arc<tokio::sync::Mutex<Option<AnnodaClient>>>,
    active_session: Arc<Mutex<Option<Arc<SessionShared>>>>,
    lifecycle: Mutex<()>,
}

impl ApplicationHandle {
    fn new(client: AnnodaClient) -> Self {
        Self {
            client: Arc::new(tokio::sync::Mutex::new(Some(client))),
            active_session: Arc::new(Mutex::new(None)),
            lifecycle: Mutex::new(()),
        }
    }

    fn with_client<T>(
        &self,
        operation: impl FnOnce(&mut AnnodaClient) -> Result<T, FfiError>,
    ) -> Result<T, FfiError> {
        runtime()?.block_on(async {
            let mut client = self.client.lock().await;
            operation(client.as_mut().ok_or(FfiError::Unauthorized)?)
        })
    }

    fn with_client_async<T>(
        &self,
        operation: impl for<'a> FnOnce(
            &'a mut AnnodaClient,
        )
            -> Pin<Box<dyn Future<Output = Result<T, ClientError>> + 'a>>,
    ) -> Result<T, FfiError> {
        runtime()?.block_on(async {
            let mut client = self.client.lock().await;
            let client = client.as_mut().ok_or(FfiError::Unauthorized)?;
            operation(client).await.map_err(map_client_error)
        })
    }

    fn with_cancellable_client_async<T>(
        &self,
        operation: impl for<'a> FnOnce(
            &'a mut AnnodaClient,
            annoda_network::SyncCancellationToken,
        )
            -> Pin<Box<dyn Future<Output = Result<T, ClientError>> + 'a>>,
    ) -> Result<T, FfiError> {
        runtime()?.block_on(async {
            let mut client = self.client.lock().await;
            let client = client.as_mut().ok_or(FfiError::Unauthorized)?;
            let shared = Arc::new(SessionShared::new());
            {
                let mut active = self.active_session.lock().map_err(|_| FfiError::Internal)?;
                if active.as_ref().is_some_and(|session| {
                    session
                        .result
                        .lock()
                        .map(|result| result.is_none())
                        .unwrap_or(true)
                }) {
                    return Err(FfiError::AccountBusy);
                }
                *active = Some(shared.clone());
            }
            let result = operation(client, shared.cancellation.clone())
                .await
                .map_err(map_client_error);
            shared.finish(Err(FfiError::Internal));
            if let Ok(mut active) = self.active_session.lock()
                && active
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &shared))
            {
                active.take();
            }
            result
        })
    }
}

#[uniffi::export]
impl ApplicationHandle {
    pub fn identity_summary(&self) -> Result<FfiIdentitySummary, FfiError> {
        self.with_client(|client| {
            client
                .identity_summary()
                .map(ffi_identity)
                .map_err(map_client_error)
        })
    }

    pub fn published_profile(&self) -> Result<Option<FfiCandidateProfile>, FfiError> {
        self.with_client(|client| {
            client
                .published_profile()
                .map(|profile| {
                    profile.map(|profile| {
                        ffi_candidate(CandidateProfile {
                            profile,
                            score: None,
                        })
                    })
                })
                .map_err(map_client_error)
        })
    }

    /// Accepts a bounded serialized public credential. The application service verifies trust,
    /// validity, subject, and both account-key bindings before persisting it.
    pub fn import_credential(&self, credential: Vec<u8>) -> Result<(), FfiError> {
        if credential.is_empty() || credential.len() > 16 * 1024 {
            return Err(FfiError::InvalidInput);
        }
        let credential = postcard::from_bytes(&credential).map_err(|_| FfiError::InvalidInput)?;
        self.with_client(|client| {
            client
                .attach_credential(credential)
                .map_err(map_client_error)
        })
    }

    pub fn credential(&self) -> Result<Vec<u8>, FfiError> {
        self.with_client(|client| {
            let credential = client.credential().map_err(map_client_error)?;
            postcard::to_allocvec(&credential).map_err(|_| FfiError::Internal)
        })
    }

    pub fn publish_profile(&self, photos: Vec<Vec<u8>>) -> Result<FfiPublicationReceipt, FfiError> {
        if photos.is_empty()
            || photos.len() > 6
            || photos.iter().any(|photo| photo.len() > 4 * 1024 * 1024)
        {
            return Err(FfiError::InvalidInput);
        }
        self.with_cancellable_client_async(|client, cancellation| {
            Box::pin(async move {
                client
                    .publish_profile_with_cancellation(photos, cancellation)
                    .await
                    .map(ffi_publication)
            })
        })
    }

    pub fn discover(&self, query: FfiDiscoveryQuery) -> Result<FfiCandidatePage, FfiError> {
        let query = to_client_query(query)?;
        self.with_cancellable_client_async(|client, cancellation| {
            Box::pin(async move {
                client
                    .discover_with_cancellation(query, cancellation)
                    .await
                    .map(|page| FfiCandidatePage {
                        items: page.items.into_iter().map(ffi_candidate).collect(),
                        next_cursor: ffi_cursor(page.next_cursor),
                    })
            })
        })
    }

    pub fn fetch_photo(
        &self,
        owner: Vec<u8>,
        hash: Vec<u8>,
    ) -> Result<FfiValidatedPhoto, FfiError> {
        let owner = parse_profile_id(owner)?;
        let hash = parse_content_hash(hash)?;
        self.with_cancellable_client_async(|client, cancellation| {
            Box::pin(async move {
                client
                    .fetch_photo_with_cancellation(owner, hash, cancellation)
                    .await
                    .map(ffi_photo)
            })
        })
    }

    pub fn like(&self, profile_id: Vec<u8>) -> Result<FfiOperationReceipt, FfiError> {
        let profile_id = parse_profile_id(profile_id)?;
        self.with_cancellable_client_async(|client, cancellation| {
            Box::pin(async move {
                client
                    .like_with_cancellation(profile_id, cancellation)
                    .await
                    .map(ffi_operation)
            })
        })
    }

    pub fn pass(&self, profile_id: Vec<u8>) -> Result<(), FfiError> {
        let profile_id = parse_profile_id(profile_id)?;
        self.with_client_async(|client| Box::pin(async move { client.pass(profile_id).await }))
    }

    pub fn block(&self, profile_id: Vec<u8>) -> Result<(), FfiError> {
        let profile_id = parse_profile_id(profile_id)?;
        self.with_client_async(|client| Box::pin(async move { client.block(profile_id).await }))
    }

    pub fn received_likes(
        &self,
        page_size: u8,
        cursor: Option<FfiPageCursor>,
    ) -> Result<FfiIncomingLikePage, FfiError> {
        let cursor = to_client_cursor(cursor)?;
        self.with_client_async(|client| {
            Box::pin(async move {
                client
                    .received_likes(page_size, cursor)
                    .await
                    .map(|page| FfiIncomingLikePage {
                        items: page.items.into_iter().map(ffi_incoming_like).collect(),
                        next_cursor: ffi_cursor(page.next_cursor),
                    })
            })
        })
    }

    pub fn matches(
        &self,
        page_size: u8,
        cursor: Option<FfiPageCursor>,
    ) -> Result<FfiMatchPage, FfiError> {
        let cursor = to_client_cursor(cursor)?;
        self.with_client_async(|client| {
            Box::pin(async move {
                client
                    .matches(page_size, cursor)
                    .await
                    .map(|page| FfiMatchPage {
                        items: page.items.into_iter().map(ffi_match).collect(),
                        next_cursor: ffi_cursor(page.next_cursor),
                    })
            })
        })
    }

    pub fn disclose_contacts(
        &self,
        match_id: Vec<u8>,
        contacts: Vec<FfiContactHandle>,
    ) -> Result<FfiOperationReceipt, FfiError> {
        if contacts.is_empty() || contacts.len() > 16 {
            return Err(FfiError::InvalidInput);
        }
        let match_id = parse_match_id(match_id)?;
        let contacts = contacts
            .into_iter()
            .map(from_ffi_contact)
            .collect::<Result<Vec<_>, _>>()?;
        self.with_cancellable_client_async(|client, cancellation| {
            Box::pin(async move {
                client
                    .disclose_match_contacts_with_cancellation(match_id, contacts, cancellation)
                    .await
                    .map(ffi_operation)
            })
        })
    }

    pub fn received_contacts(&self, match_id: Vec<u8>) -> Result<Vec<FfiContactHandle>, FfiError> {
        let match_id = parse_match_id(match_id)?;
        self.with_client_async(|client| {
            Box::pin(async move {
                client
                    .received_match_contacts(match_id)
                    .await
                    .map(|contacts| contacts.into_iter().map(to_ffi_contact).collect())
            })
        })
    }

    pub fn operations(&self, limit: u8) -> Result<Vec<FfiOperationReceipt>, FfiError> {
        if limit == 0 || limit > 64 {
            return Err(FfiError::InvalidInput);
        }
        self.with_client(|client| {
            client
                .operations(limit as usize)
                .map(|operations| operations.into_iter().map(ffi_operation).collect())
                .map_err(map_client_error)
        })
    }

    pub fn operations_page(
        &self,
        page_size: u8,
        cursor: Option<FfiPageCursor>,
    ) -> Result<FfiOperationPage, FfiError> {
        let cursor = to_client_cursor(cursor)?;
        self.with_client(|client| {
            client
                .operations_page(page_size, cursor)
                .map(|page| FfiOperationPage {
                    items: page.items.into_iter().map(ffi_operation).collect(),
                    next_cursor: ffi_cursor(page.next_cursor),
                })
                .map_err(map_client_error)
        })
    }

    pub fn recover_pending(&self) -> Result<Vec<FfiOperationReceipt>, FfiError> {
        self.with_client_async(|client| {
            Box::pin(async move {
                client
                    .recover_pending()
                    .await
                    .map(|operations| operations.into_iter().map(ffi_operation).collect())
            })
        })
    }

    pub fn rank_candidates(
        &self,
        candidates: Vec<FfiRankingCandidate>,
        filter: FfiCandidateFilter,
        exploration_fraction: f64,
        seed: u64,
    ) -> Result<Vec<FfiRankedCandidate>, FfiError> {
        if candidates.len() > 256 {
            return Err(FfiError::InvalidInput);
        }
        let candidates = candidates
            .into_iter()
            .map(to_ranking_candidate)
            .collect::<Result<Vec<_>, _>>()?;
        let by_id = candidates
            .iter()
            .map(|candidate| (candidate.id.clone(), candidate.id.clone()))
            .collect::<std::collections::HashMap<_, _>>();
        let filter = to_candidate_filter(filter)?;
        self.with_client(|client| {
            client
                .rank_candidates(&candidates, &filter, exploration_fraction, seed)
                .map(|ranked| {
                    ranked
                        .into_iter()
                        .map(|candidate| {
                            let id = by_id
                                .get(&candidate.candidate_id)
                                .ok_or(FfiError::Internal)?;
                            let profile_id = (0..32)
                                .map(|index| {
                                    u8::from_str_radix(&id[index * 2..index * 2 + 2], 16)
                                        .map_err(|_| FfiError::Internal)
                                })
                                .collect::<Result<Vec<_>, _>>()?;
                            Ok(FfiRankedCandidate {
                                profile_id,
                                probability: candidate.score.probability,
                                explored: candidate.explored,
                            })
                        })
                        .collect::<Result<Vec<_>, FfiError>>()
                })
                .map_err(map_client_error)?
        })
    }

    pub fn record_feedback(
        &self,
        profile_id: Vec<u8>,
        embedding_version: u16,
        embedding_values: Vec<f64>,
        liked: bool,
    ) -> Result<(), FfiError> {
        let profile_id = parse_profile_id(profile_id)?;
        if embedding_values.len() > 4096 {
            return Err(FfiError::InvalidInput);
        }
        let embedding = PhotoEmbedding::new(embedding_version, embedding_values)
            .map_err(|_| FfiError::InvalidInput)?;
        self.with_client(|client| {
            client
                .record_feedback(profile_id, &embedding, liked)
                .map_err(map_client_error)
        })
    }

    pub fn reset_learning(&self) -> Result<(), FfiError> {
        self.with_client(|client| client.reset_learning().map_err(map_client_error))
    }

    pub fn report_profile(
        &self,
        subject: Vec<u8>,
        policy_reason: u16,
        evidence_hashes: Vec<Vec<u8>>,
    ) -> Result<FfiProfileReport, FfiError> {
        if evidence_hashes.is_empty() || evidence_hashes.len() > 32 {
            return Err(FfiError::InvalidInput);
        }
        let subject = parse_profile_id(subject)?;
        let evidence_hashes = evidence_hashes
            .into_iter()
            .map(parse_match_id)
            .collect::<Result<Vec<_>, _>>()?;
        self.with_client(|client| {
            client
                .report_profile(subject, policy_reason, evidence_hashes)
                .map(ffi_report)
                .map_err(map_client_error)
        })
    }

    pub fn local_reports(&self, limit: u8) -> Result<Vec<FfiProfileReport>, FfiError> {
        if limit == 0 || limit > 64 {
            return Err(FfiError::InvalidInput);
        }
        self.with_client(|client| {
            client
                .local_reports(limit as usize)
                .map(|reports| reports.into_iter().map(ffi_report).collect())
                .map_err(map_client_error)
        })
    }

    pub fn local_reports_page(
        &self,
        page_size: u8,
        cursor: Option<FfiPageCursor>,
    ) -> Result<FfiProfileReportPage, FfiError> {
        let cursor = to_client_cursor(cursor)?;
        self.with_client(|client| {
            client
                .local_reports_page(page_size, cursor)
                .map(|page| FfiProfileReportPage {
                    items: page.items.into_iter().map(ffi_report).collect(),
                    next_cursor: ffi_cursor(page.next_cursor),
                })
                .map_err(map_client_error)
        })
    }

    pub fn notification_preferences(&self) -> Result<crate::FfiNotificationPreferences, FfiError> {
        self.with_client(|client| {
            client
                .notification_preferences()
                .map(|preferences| crate::FfiNotificationPreferences {
                    likes_enabled: preferences.likes_enabled,
                    matches_enabled: preferences.matches_enabled,
                })
                .map_err(map_client_error)
        })
    }

    pub fn set_notification_preferences(
        &self,
        preferences: crate::FfiNotificationPreferences,
    ) -> Result<(), FfiError> {
        self.with_client(|client| {
            client
                .set_notification_preferences(annoda_core::notifications::NotificationPreferences {
                    likes_enabled: preferences.likes_enabled,
                    matches_enabled: preferences.matches_enabled,
                })
                .map_err(map_client_error)
        })
    }

    pub fn pending_notifications(
        &self,
        limit: u8,
    ) -> Result<Vec<crate::FfiNotificationEvent>, FfiError> {
        if limit == 0 || limit > 64 {
            return Err(FfiError::InvalidInput);
        }
        self.with_client(|client| {
            client
                .pending_notifications(limit as usize)
                .map(|events| events.into_iter().map(crate::ffi_notification).collect())
                .map_err(map_client_error)
        })
    }

    pub fn acknowledge_notification(&self, event_id: Vec<u8>) -> Result<bool, FfiError> {
        let event_id: [u8; 32] = event_id.try_into().map_err(|_| FfiError::InvalidInput)?;
        self.with_client(|client| {
            client
                .acknowledge_notification(event_id)
                .map_err(map_client_error)
        })
    }

    /// Cancels the active bounded network operation, if one is running.
    pub fn cancel_current_operation(&self) -> Result<bool, FfiError> {
        let active = self.active_session.lock().map_err(|_| FfiError::Internal)?;
        let Some(session) = active.as_ref() else {
            return Ok(false);
        };
        let running = session
            .result
            .lock()
            .map(|result| result.is_none())
            .unwrap_or(false);
        if running {
            session.cancel();
        }
        Ok(running)
    }

    pub fn start_sync_session(&self) -> Result<Arc<SyncSession>, FfiError> {
        let runtime = runtime()?;
        let _lifecycle = self.lifecycle.lock().map_err(|_| FfiError::Internal)?;
        self.with_client(|_| Ok(()))?;
        let mut active = self.active_session.lock().map_err(|_| FfiError::Internal)?;
        if active.as_ref().is_some_and(|session| {
            session
                .result
                .lock()
                .map(|result| result.is_none())
                .unwrap_or(true)
        }) {
            return Err(FfiError::AccountBusy);
        }
        let shared = Arc::new(SessionShared::new());
        *active = Some(shared.clone());
        drop(active);

        let client = self.client.clone();
        let active_slot = self.active_session.clone();
        let session = Arc::new(SyncSession {
            shared: shared.clone(),
        });
        runtime.spawn(async move {
            let result = {
                let mut slot = client.lock().await;
                match slot.as_mut() {
                    Some(client) => client
                        .sync(shared.cancellation.clone())
                        .await
                        .map(map_sync_report)
                        .map_err(map_client_error),
                    None => Err(FfiError::Unauthorized),
                }
            };
            shared.finish(result);
            if let Ok(mut active) = active_slot.lock()
                && active
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, &shared))
            {
                active.take();
            }
        });
        Ok(session)
    }

    pub fn close(&self) -> Result<(), FfiError> {
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
        runtime()?.block_on(async {
            let mut client = self.client.lock().await;
            if let Some(client) = client.take() {
                client.close();
            }
        });
        Ok(())
    }
}

#[uniffi::export]
pub fn create_application(
    config: FfiApplicationConfig,
    passphrase: String,
) -> Result<Arc<ApplicationHandle>, FfiError> {
    let passphrase = Zeroizing::new(passphrase);
    if passphrase.is_empty() || passphrase.len() > 1024 {
        return Err(FfiError::InvalidInput);
    }
    let config = client_config(config)?;
    let client = AnnodaClient::create(config, passphrase.as_bytes()).map_err(map_client_error)?;
    Ok(Arc::new(ApplicationHandle::new(client)))
}

#[uniffi::export]
pub fn open_application(
    config: FfiApplicationConfig,
    passphrase: String,
) -> Result<Arc<ApplicationHandle>, FfiError> {
    let passphrase = Zeroizing::new(passphrase);
    if passphrase.is_empty() || passphrase.len() > 1024 {
        return Err(FfiError::InvalidInput);
    }
    let config = client_config(config)?;
    let client = AnnodaClient::open(config, passphrase.as_bytes()).map_err(map_client_error)?;
    Ok(Arc::new(ApplicationHandle::new(client)))
}
