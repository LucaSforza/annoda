use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt::Debug,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use annoda_core::{
    identity::{TrustedIssuers, VerifiedCredential},
    protocol::{ContentHash, ContentLease, MailboxParcel, PhotoManifest, ProfileId, PublicProfile},
    storage::{MailboxCursor, PeerStorage, StorageLimits},
};
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, connection_limits,
    core::{Transport, upgrade},
    kad::{self, store::MemoryStore},
    multiaddr::Protocol,
    noise, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use tokio::sync::{mpsc, oneshot};

use crate::node_identity::NodeIdentityStore;
use crate::transfer::{MeteredIo, TransferMeter};
use crate::wire::{
    AnnodaCodec, MAX_FRAME_BYTES, MAX_MAILBOX_BATCH, RpcErrorCode, RpcMailboxCursor, RpcRequest,
    RpcResponse, frame_len,
};

const COMMAND_QUEUE: usize = 32;
const MAX_IN_FLIGHT: usize = 32;
const MAX_PENDING_PROVIDERS: usize = 16;
const PROTOCOL: &str = "/annoda/1";
const STORAGE_GC_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub struct BootstrapPeer {
    pub peer_id: PeerId,
    pub address: Multiaddr,
}

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub listen_addresses: Vec<Multiaddr>,
    pub bootstrap_peers: Vec<BootstrapPeer>,
    pub data_dir: PathBuf,
    pub storage_bytes: u64,
    pub max_lease_seconds: u64,
    pub max_connections: u32,
    pub request_timeout: Duration,
    pub bandwidth_bytes_per_second: u64,
    pub clock: Arc<dyn Clock>,
}

pub trait Clock: Send + Sync + Debug {
    fn now(&self) -> u64;
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[derive(Debug)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn new(now: u64) -> Self {
        Self(AtomicU64::new(now))
    }
    pub fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen_addresses: Vec::new(),
            bootstrap_peers: Vec::new(),
            data_dir: PathBuf::from("annoda-data"),
            storage_bytes: 1024 * 1024 * 1024,
            max_lease_seconds: 30 * 24 * 60 * 60,
            max_connections: 32,
            request_timeout: Duration::from_secs(10),
            bandwidth_bytes_per_second: 16 * 1024 * 1024,
            clock: Arc::new(SystemClock),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    #[error("network actor is closed")]
    Closed,
    #[error("request to peer failed: {0}")]
    Request(String),
    #[error("peer rejected request: {0:?}")]
    Rejected(RpcErrorCode),
    #[error("invalid or oversized request")]
    InvalidFrame,
    #[error("node startup failed: {0}")]
    Startup(String),
    #[error("only {stored} distinct peers confirmed; {required} required")]
    UnderReplicated { stored: usize, required: usize },
    #[error("no provider returned a hash-valid photo")]
    PhotoUnavailable,
    #[error("configured bandwidth budget is exhausted")]
    BandwidthLimited,
}

type RpcBehaviour = request_response::Behaviour<AnnodaCodec>;

#[derive(NetworkBehaviour)]
struct Behaviour {
    rpc: RpcBehaviour,
    kad: kad::Behaviour<MemoryStore>,
    limits: connection_limits::Behaviour,
}

enum Command {
    Request {
        peer: PeerId,
        request: Box<RpcRequest>,
        response: oneshot::Sender<Result<RpcResponse, NetworkError>>,
    },
    FindProviders {
        hash: [u8; 32],
        response: oneshot::Sender<Vec<PeerId>>,
    },
}

pub struct PeerNode {
    peer_id: PeerId,
    commands: mpsc::Sender<Command>,
    listeners: tokio::sync::watch::Receiver<Vec<Multiaddr>>,
    issuers: TrustedIssuers,
    clock: Arc<dyn Clock>,
    task: Option<tokio::task::JoinHandle<()>>,
    allowed_peers: Option<HashSet<PeerId>>,
}

impl PeerNode {
    pub async fn start(config: NodeConfig, issuers: TrustedIssuers) -> Result<Self, NetworkError> {
        Self::start_mode(config, issuers, None, None, true, true, None).await
    }

    async fn start_mode(
        config: NodeConfig,
        issuers: TrustedIssuers,
        meter: Option<Arc<TransferMeter>>,
        allowed_peers: Option<HashSet<PeerId>>,
        provide_services: bool,
        listen: bool,
        storage_busy_timeout: Option<Duration>,
    ) -> Result<Self, NetworkError> {
        if config.max_connections == 0 || config.bandwidth_bytes_per_second == 0 {
            return Err(NetworkError::Startup(
                "connection and bandwidth limits must be positive".into(),
            ));
        }
        let identity = NodeIdentityStore::new(&config.data_dir)
            .open()
            .map_err(|error| NetworkError::Startup(error.to_string()))?;
        let (keys, peer_id, identity_lock) = identity.into_parts();
        let storage = open_peer_storage(&config, config.clock.now(), storage_busy_timeout)?;
        let store = MemoryStore::new(peer_id);
        let mut kad = kad::Behaviour::new(peer_id, store);
        kad.set_mode(Some(if provide_services {
            kad::Mode::Server
        } else {
            kad::Mode::Client
        }));
        let codec = AnnodaCodec;
        let rpc = RpcBehaviour::with_codec(
            codec,
            [(
                StreamProtocol::new(PROTOCOL),
                if provide_services {
                    request_response::ProtocolSupport::Full
                } else {
                    // Sync clients issue requests only. Omitting inbound support prevents
                    // selected peers from making the client decode unsolicited RPC frames.
                    request_response::ProtocolSupport::Outbound
                },
            )],
            request_response::Config::default()
                .with_request_timeout(config.request_timeout)
                .with_max_concurrent_streams(MAX_IN_FLIGHT),
        );
        let connection_limits = connection_limits::Behaviour::new(
            connection_limits::ConnectionLimits::default()
                .with_max_established(Some(config.max_connections))
                .with_max_established_incoming(Some(config.max_connections.div_ceil(2))),
        );
        let transport_meter = meter.clone();
        let transport = tcp::tokio::Transport::new(tcp::Config::default())
            .map(move |socket, _| MeteredIo::new(socket, transport_meter.clone()))
            .upgrade(upgrade::Version::V1)
            .authenticate(
                noise::Config::new(&keys)
                    .map_err(|e| NetworkError::Startup(format!("configure Noise: {e:?}")))?,
            )
            .multiplex(yamux::Config::default())
            .boxed();
        let transport = libp2p::core::transport::timeout::TransportTimeout::new(
            transport,
            config.request_timeout,
        )
        .boxed();
        let mut swarm = Swarm::new(
            transport,
            Behaviour {
                rpc,
                kad,
                limits: connection_limits,
            },
            peer_id,
            libp2p::swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(Duration::from_secs(60)),
        );

        if listen {
            let listen_addresses = if config.listen_addresses.is_empty() {
                vec![
                    Multiaddr::empty()
                        .with(Protocol::Ip4(std::net::Ipv4Addr::LOCALHOST))
                        .with(Protocol::Tcp(0)),
                ]
            } else {
                config.listen_addresses.clone()
            };
            for address in listen_addresses {
                swarm
                    .listen_on(address.clone())
                    .map_err(|e| NetworkError::Startup(format!("listen on {address}: {e:?}")))?;
            }
        }
        for bootstrap in &config.bootstrap_peers {
            swarm.add_peer_address(bootstrap.peer_id, bootstrap.address.clone());
            if provide_services {
                // Sync sessions dial only their selected peers. Adding addresses to
                // Kademlia can trigger an automatic bootstrap and expand that set.
                swarm
                    .behaviour_mut()
                    .kad
                    .add_address(&bootstrap.peer_id, bootstrap.address.clone());
            }
            let _ = swarm.dial(bootstrap.peer_id);
        }
        let (commands, rx) = mpsc::channel(COMMAND_QUEUE);
        let (listener_tx, listeners) = tokio::sync::watch::channel(Vec::new());
        let task = tokio::spawn(run(
            swarm,
            rx,
            listener_tx,
            Runtime {
                storage,
                issuers: issuers.clone(),
                clock: config.clock.clone(),
                bandwidth_bytes_per_second: config.bandwidth_bytes_per_second,
                max_lease_seconds: config.max_lease_seconds,
                allowed_peers: allowed_peers.clone(),
                provide_services,
                bootstrap_kad: provide_services,
            },
            identity_lock,
        ));
        Ok(Self {
            peer_id,
            commands,
            listeners,
            issuers,
            clock: config.clock,
            task: Some(task),
            allowed_peers,
        })
    }

    pub(crate) async fn start_sync(
        config: NodeConfig,
        issuers: TrustedIssuers,
        meter: Arc<TransferMeter>,
        allowed_peers: HashSet<PeerId>,
    ) -> Result<Self, NetworkError> {
        Self::start_mode(
            config,
            issuers,
            Some(meter),
            Some(allowed_peers),
            false,
            false,
            Some(Duration::from_millis(25)),
        )
        .await
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn listeners(&self) -> Vec<Multiaddr> {
        self.listeners.borrow().clone()
    }

    pub async fn wait_for_listeners(&self) -> Result<Vec<Multiaddr>, NetworkError> {
        let mut listeners = self.listeners.clone();
        loop {
            let current = listeners.borrow().clone();
            if !current.is_empty() {
                return Ok(current);
            }
            listeners
                .changed()
                .await
                .map_err(|_| NetworkError::Closed)?;
        }
    }

    pub async fn shutdown(mut self) {
        drop(self.commands);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }

    pub async fn request(
        &self,
        peer: PeerId,
        request: RpcRequest,
    ) -> Result<RpcResponse, NetworkError> {
        if self
            .allowed_peers
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&peer))
        {
            return Err(NetworkError::Request(
                "peer is outside sync allowlist".into(),
            ));
        }
        if !request.validate_frame_size() {
            return Err(NetworkError::InvalidFrame);
        }
        let (response, receive) = oneshot::channel();
        self.commands
            .send(Command::Request {
                peer,
                request: Box::new(request),
                response,
            })
            .await
            .map_err(|_| NetworkError::Closed)?;
        receive.await.map_err(|_| NetworkError::Closed)?
    }

    pub async fn find_providers(&self, hash: [u8; 32]) -> Result<Vec<PeerId>, NetworkError> {
        let (response, receive) = oneshot::channel();
        self.commands
            .send(Command::FindProviders { hash, response })
            .await
            .map_err(|_| NetworkError::Closed)?;
        receive.await.map_err(|_| NetworkError::Closed)
    }

    pub async fn publish_profile(
        &self,
        peers: &[PeerId],
        profile: PublicProfile,
    ) -> Result<usize, NetworkError> {
        let mut confirmed = HashSet::new();
        for peer in peers.iter().copied() {
            if matches!(
                self.request(
                    peer,
                    RpcRequest::PutProfile {
                        profile: profile.clone()
                    }
                )
                .await,
                Ok(RpcResponse::Ack)
            ) {
                confirmed.insert(peer);
            }
        }
        Ok(confirmed.len())
    }

    pub async fn discover_profiles(
        &self,
        peers: &[PeerId],
        limit: usize,
    ) -> Result<Vec<PublicProfile>, NetworkError> {
        let mut profiles: BTreeMap<ProfileId, PublicProfile> = BTreeMap::new();
        let mut successful_queries = 0;
        for peer in peers.iter().copied() {
            if let Ok(RpcResponse::Profiles(found)) = self
                .request(
                    peer,
                    RpcRequest::ListProfiles {
                        limit: limit.min(50) as u16,
                    },
                )
                .await
            {
                successful_queries += 1;
                for profile in found {
                    insert_verified_profile(
                        &mut profiles,
                        profile,
                        &self.issuers,
                        self.clock.now(),
                    )?;
                    if profiles.len() >= limit {
                        break;
                    }
                }
            }
            if profiles.len() >= limit {
                break;
            }
        }
        if successful_queries == 0 && !peers.is_empty() {
            return Err(NetworkError::Request(
                "profile discovery failed at every peer".into(),
            ));
        }
        Ok(profiles.into_values().collect())
    }

    pub async fn replicate_photo(
        &self,
        peers: &[PeerId],
        manifest: PhotoManifest,
        lease: ContentLease,
        owner: VerifiedCredential,
        blob: Vec<u8>,
        target: usize,
    ) -> Result<Vec<PeerId>, NetworkError> {
        if !manifest.verifies(&blob) || target == 0 {
            return Err(NetworkError::InvalidFrame);
        }
        let mut confirmed = HashSet::new();
        for peer in peers.iter().copied() {
            if confirmed.contains(&peer) {
                continue;
            }
            if matches!(
                self.request(
                    peer,
                    RpcRequest::PutPhoto {
                        manifest: manifest.clone(),
                        lease: lease.clone(),
                        owner: owner.clone(),
                        blob: blob.clone(),
                    }
                )
                .await,
                Ok(RpcResponse::Ack)
            ) {
                confirmed.insert(peer);
                if confirmed.len() == target {
                    break;
                }
            }
        }
        if confirmed.len() < target {
            return Err(NetworkError::UnderReplicated {
                stored: confirmed.len(),
                required: target,
            });
        }
        Ok(confirmed.into_iter().collect())
    }

    pub async fn fetch_photo(
        &self,
        owner: ProfileId,
        hash: ContentHash,
        candidates: &[PeerId],
    ) -> Result<Vec<u8>, NetworkError> {
        let mut providers = self.find_providers(hash.0).await.unwrap_or_default();
        providers.extend(candidates.iter().copied());
        let mut seen = HashSet::new();
        for peer in providers {
            if !seen.insert(peer) {
                continue;
            }
            if let Ok(RpcResponse::Photo(Some(bytes))) = self
                .request(peer, RpcRequest::GetPhoto { owner, hash })
                .await
                && ContentHash::digest(&bytes) == hash
            {
                return Ok(bytes);
            }
        }
        Err(NetworkError::PhotoUnavailable)
    }

    pub async fn deposit_parcel(
        &self,
        peers: &[PeerId],
        parcel: MailboxParcel,
        required: usize,
    ) -> Result<Vec<PeerId>, NetworkError> {
        let mut confirmed = HashSet::new();
        for peer in peers.iter().copied() {
            if confirmed.contains(&peer) {
                continue;
            }
            if matches!(
                self.request(
                    peer,
                    RpcRequest::DepositMailbox {
                        parcel: parcel.clone()
                    }
                )
                .await,
                Ok(RpcResponse::Ack | RpcResponse::Duplicate)
            ) {
                confirmed.insert(peer);
                if confirmed.len() >= required {
                    break;
                }
            }
        }
        if confirmed.len() < required {
            return Err(NetworkError::UnderReplicated {
                stored: confirmed.len(),
                required,
            });
        }
        Ok(confirmed.into_iter().collect())
    }

    pub async fn poll_mailbox(
        &self,
        peer: PeerId,
        recipient: VerifiedCredential,
        proof: Vec<u8>,
        challenge: [u8; 32],
        proof_time: u64,
        limit: usize,
    ) -> Result<Vec<MailboxParcel>, NetworkError> {
        match self
            .request(
                peer,
                RpcRequest::PollMailbox {
                    recipient,
                    proof,
                    challenge,
                    proof_time,
                    limit: u16::try_from(limit)
                        .map_err(|_| NetworkError::Request("mailbox limit too large".into()))?,
                },
            )
            .await?
        {
            RpcResponse::Mailbox(messages) => Ok(messages),
            _ => Err(NetworkError::Request("unexpected mailbox response".into())),
        }
    }

    #[allow(clippy::too_many_arguments)] // Mirrors the authenticated paging RPC fields.
    pub(crate) async fn poll_mailbox_page(
        &self,
        peer: PeerId,
        recipient: VerifiedCredential,
        proof: Vec<u8>,
        challenge: [u8; 32],
        proof_time: u64,
        cursor: Option<MailboxCursor>,
        limit: usize,
    ) -> Result<(Vec<MailboxParcel>, Option<MailboxCursor>, bool), NetworkError> {
        let cursor = cursor.map(|cursor| RpcMailboxCursor {
            expires_at: cursor.expires_at,
            parcel_id: cursor.parcel_id,
        });
        match self
            .request(
                peer,
                RpcRequest::PollMailboxPage {
                    recipient,
                    proof,
                    challenge,
                    proof_time,
                    cursor,
                    limit: u16::try_from(limit)
                        .map_err(|_| NetworkError::Request("mailbox limit too large".into()))?,
                },
            )
            .await?
        {
            RpcResponse::MailboxPage {
                parcels,
                next_cursor,
                completed,
            } => Ok((
                parcels,
                next_cursor.map(|cursor| MailboxCursor {
                    expires_at: cursor.expires_at,
                    parcel_id: cursor.parcel_id,
                }),
                completed,
            )),
            RpcResponse::Mailbox(_) => Err(NetworkError::Request(
                "peer does not support mailbox paging".into(),
            )),
            _ => Err(NetworkError::Request("unexpected mailbox response".into())),
        }
    }
}

fn insert_verified_profile(
    profiles: &mut BTreeMap<ProfileId, PublicProfile>,
    profile: PublicProfile,
    issuers: &TrustedIssuers,
    now: u64,
) -> Result<(), NetworkError> {
    profile
        .verify(issuers, now)
        .map_err(|_| NetworkError::Rejected(RpcErrorCode::Invalid))?;
    match profiles.get(&profile.owner) {
        Some(previous) if previous.revision > profile.revision => {}
        Some(previous) if previous.revision == profile.revision && previous != &profile => {
            return Err(NetworkError::Rejected(RpcErrorCode::Invalid));
        }
        _ => {
            profiles.insert(profile.owner, profile);
        }
    }
    Ok(())
}

struct Runtime {
    storage: PeerStorage,
    issuers: TrustedIssuers,
    clock: Arc<dyn Clock>,
    bandwidth_bytes_per_second: u64,
    max_lease_seconds: u64,
    allowed_peers: Option<HashSet<PeerId>>,
    provide_services: bool,
    bootstrap_kad: bool,
}

async fn run(
    mut swarm: Swarm<Behaviour>,
    mut commands: mpsc::Receiver<Command>,
    listeners: tokio::sync::watch::Sender<Vec<Multiaddr>>,
    mut runtime: Runtime,
    _identity_lock: std::fs::File,
) {
    let mut bandwidth = TokenBucket::new(runtime.bandwidth_bytes_per_second);
    let mut maintenance = tokio::time::interval_at(
        tokio::time::Instant::now() + STORAGE_GC_INTERVAL,
        STORAGE_GC_INTERVAL,
    );
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut pending = HashMap::new();
    let mut pending_providers: HashMap<
        kad::QueryId,
        (HashSet<PeerId>, oneshot::Sender<Vec<PeerId>>),
    > = HashMap::new();
    let mut bootstrapped = false;
    loop {
        tokio::select! {
            _ = maintenance.tick() => {
                if let Err(error) = runtime.storage.expire(runtime.clock.now()) {
                    tracing::warn!(error = %error, "peer storage expiry cleanup failed");
                }
            }
            command = commands.recv() => match command {
                Some(Command::Request { peer, request, response }) => {
                    if pending.len() >= MAX_IN_FLIGHT {
                        let _ = response.send(Err(NetworkError::Request("in-flight request limit reached".into())));
                        continue;
                    }
                    let request_bytes = frame_len(&request);
                    if !bandwidth.consume(request_bytes) {
                        let _ = response.send(Err(NetworkError::BandwidthLimited));
                        continue;
                    }
                    let id = swarm.behaviour_mut().rpc.send_request(&peer, *request);
                    pending.insert(id, response);
                }
                Some(Command::FindProviders { hash, response }) => {
                    if pending_providers.len() >= MAX_PENDING_PROVIDERS {
                        let _ = response.send(Vec::new());
                        continue;
                    }
                    let query = swarm.behaviour_mut().kad.get_providers(kad::RecordKey::new(&hash));
                    pending_providers.insert(query, (HashSet::new(), response));
                }
                None => break,
            },
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    let mut current = listeners.borrow().clone();
                    current.push(address);
                    let _ = listeners.send(current);
                }
                SwarmEvent::ConnectionEstablished { .. } if runtime.bootstrap_kad && !bootstrapped => {
                    bootstrapped = true;
                    let _ = swarm.behaviour_mut().kad.bootstrap();
                }
                SwarmEvent::Behaviour(BehaviourEvent::Rpc(request_response::Event::Message {
                    peer, message: request_response::Message::Request { request, channel, .. }, ..
                })) => {
                    if !runtime.provide_services
                        || runtime.allowed_peers.as_ref().is_some_and(|allowed| !allowed.contains(&peer))
                    {
                        let _ = swarm.behaviour_mut().rpc.send_response(
                            channel,
                            RpcResponse::Error { code: RpcErrorCode::Unauthorized },
                        );
                        continue;
                    }
                    let request_bytes = frame_len(&request);
                    if !bandwidth.consume(request_bytes) {
                        let _ = swarm.behaviour_mut().rpc.send_response(channel, RpcResponse::Error { code: RpcErrorCode::Capacity });
                        continue;
                    }
                    let announcement = match &request {
                        RpcRequest::PutPhoto { manifest, .. } => Some(manifest.hash.0),
                        _ => None,
                    };
                    let result = apply_request(&mut runtime.storage, &runtime.issuers, request, runtime.clock.now(), runtime.max_lease_seconds);
                    if matches!(result, RpcResponse::Ack)
                        && let Some(hash) = announcement
                    {
                        let _ = swarm.behaviour_mut().kad.start_providing(kad::RecordKey::new(&hash));
                    }
                    let response_bytes = frame_len(&result);
                    if bandwidth.consume(response_bytes) {
                        let _ = swarm.behaviour_mut().rpc.send_response(channel, result);
                    } else {
                        let _ = swarm.behaviour_mut().rpc.send_response(channel, RpcResponse::Error { code: RpcErrorCode::Capacity });
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Rpc(request_response::Event::Message {
                    message: request_response::Message::Response { request_id, response }, ..
                })) => {
                    if let Some(sender) = pending.remove(&request_id) {
                        let result = if !bandwidth.consume(frame_len(&response)) {
                            Err(NetworkError::BandwidthLimited)
                        } else { match response {
                            RpcResponse::Error { code } => Err(NetworkError::Rejected(code)),
                            response => Ok(response),
                        }};
                        let _ = sender.send(result);
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Rpc(request_response::Event::OutboundFailure {
                    request_id, error, ..
                })) => {
                    if let Some(sender) = pending.remove(&request_id) {
                        let _ = sender.send(Err(NetworkError::Request(error.to_string())));
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { id, result, step, .. })) => {
                    if let kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders { providers, .. })) = result
                        && let Some((found, _)) = pending_providers.get_mut(&id)
                    {
                        found.extend(providers);
                    }
                    if step.last
                        && let Some((found, sender)) = pending_providers.remove(&id)
                    {
                        let _ = sender.send(found.into_iter().collect());
                    }
                }
                _ => {}
            }
        }
    }
    drop(swarm);
    for (_, response) in pending {
        let _ = response.send(Err(NetworkError::Closed));
    }
    for (_, (_, response)) in pending_providers {
        let _ = response.send(Vec::new());
    }
}

fn open_peer_storage(
    config: &NodeConfig,
    now: u64,
    busy_timeout: Option<Duration>,
) -> Result<PeerStorage, NetworkError> {
    std::fs::create_dir_all(&config.data_dir)
        .map_err(|e| NetworkError::Startup(format!("create storage directory: {e:?}")))?;
    let path = config.data_dir.join("peer-storage.sqlite3");
    let limits = StorageLimits {
        max_bytes: config.storage_bytes,
        ..StorageLimits::default()
    };
    let mut storage = match busy_timeout {
        Some(timeout) => PeerStorage::open_with_busy_timeout(path, limits, timeout),
        None => PeerStorage::open(path, limits),
    }
    .map_err(|e| NetworkError::Startup(format!("open peer storage: {e:?}")))?;
    storage
        .expire(now)
        .map_err(|e| NetworkError::Startup(format!("expire old peer data: {e:?}")))?;
    Ok(storage)
}

fn apply_request(
    storage: &mut PeerStorage,
    issuers: &TrustedIssuers,
    request: RpcRequest,
    now: u64,
    max_lease_seconds: u64,
) -> RpcResponse {
    let result = match request {
        RpcRequest::PutProfile { profile } => storage
            .store_profile(&profile, issuers, now)
            .map(|()| RpcResponse::Ack),
        RpcRequest::GetProfile { owner } => storage
            .get_profile(owner, issuers, now)
            .map(|profile| RpcResponse::Profile(profile.map(Box::new))),
        RpcRequest::PutPhoto {
            manifest,
            lease,
            owner,
            blob,
        } => {
            if !manifest.verifies(&blob)
                || lease.expires_at <= now
                || lease.expires_at.saturating_sub(now) > max_lease_seconds
            {
                Err(annoda_core::Error::InvalidInput)
            } else {
                storage
                    .store_photo(manifest.hash, &lease, &blob, &owner, issuers, now)
                    .map(|()| RpcResponse::Ack)
            }
        }
        RpcRequest::GetPhoto { owner, hash } => storage
            .get_photo(owner, hash, issuers, now)
            .map(RpcResponse::Photo),
        RpcRequest::DepositMailbox { parcel } => storage.deposit_mailbox(&parcel, now).map(|new| {
            if new {
                RpcResponse::Ack
            } else {
                RpcResponse::Duplicate
            }
        }),
        RpcRequest::PollMailbox {
            recipient,
            challenge,
            proof,
            proof_time,
            limit,
        } => {
            if challenge.iter().all(|byte| *byte == 0)
                || now.abs_diff(proof_time) > 30
                || limit == 0
                || limit as usize > MAX_MAILBOX_BATCH
            {
                return RpcResponse::Error {
                    code: RpcErrorCode::Unauthorized,
                };
            }
            storage
                .poll_mailbox_at(
                    &recipient,
                    issuers,
                    &challenge,
                    &proof,
                    proof_time,
                    now,
                    limit as usize,
                )
                .map(RpcResponse::Mailbox)
        }
        RpcRequest::PollMailboxPage {
            recipient,
            challenge,
            proof,
            proof_time,
            cursor,
            limit,
        } => {
            if challenge.iter().all(|byte| *byte == 0)
                || now.abs_diff(proof_time) > 30
                || limit == 0
                || limit as usize > MAX_MAILBOX_BATCH
            {
                return RpcResponse::Error {
                    code: RpcErrorCode::Unauthorized,
                };
            }
            storage
                .poll_mailbox_page(
                    &recipient,
                    issuers,
                    &challenge,
                    &proof,
                    proof_time,
                    now,
                    cursor.map(|cursor| MailboxCursor {
                        expires_at: cursor.expires_at,
                        parcel_id: cursor.parcel_id,
                    }),
                    limit as usize,
                )
                .map(|page| RpcResponse::MailboxPage {
                    parcels: page.parcels,
                    next_cursor: page.next_cursor.map(|cursor| RpcMailboxCursor {
                        expires_at: cursor.expires_at,
                        parcel_id: cursor.parcel_id,
                    }),
                    completed: page.completed,
                })
        }
        RpcRequest::ListProfiles { limit } => {
            if limit == 0 || limit > 50 {
                return RpcResponse::Error {
                    code: RpcErrorCode::Invalid,
                };
            }
            storage
                .list_profiles(issuers, now, limit as usize)
                .map(RpcResponse::Profiles)
        }
    };
    result.unwrap_or_else(|error| RpcResponse::Error {
        code: match error {
            annoda_core::Error::InvalidCredential
            | annoda_core::Error::InvalidSignature
            | annoda_core::Error::Unauthorized => RpcErrorCode::Unauthorized,
            annoda_core::Error::InvalidTime => RpcErrorCode::Expired,
            annoda_core::Error::LimitExceeded => RpcErrorCode::Capacity,
            _ => RpcErrorCode::Invalid,
        },
    })
}

struct TokenBucket {
    rate: f64,
    capacity: f64,
    tokens: f64,
    updated: Instant,
}

impl TokenBucket {
    fn new(bytes_per_second: u64) -> Self {
        let rate = bytes_per_second as f64;
        let capacity = rate.max(MAX_FRAME_BYTES as f64);
        Self {
            rate,
            capacity,
            tokens: capacity,
            updated: Instant::now(),
        }
    }

    fn consume(&mut self, bytes: usize) -> bool {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.updated).as_secs_f64() * self.rate)
            .min(self.capacity);
        self.updated = now;
        if bytes as f64 > self.tokens {
            return false;
        }
        self.tokens -= bytes as f64;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use annoda_core::identity::{DevelopmentIssuer, DeviceKeyPair};
    use annoda_core::protocol::{ContentLease, PhotoManifest};
    use annoda_core::storage::StorageLimits;
    use tempfile::TempDir;

    #[test]
    fn discovery_rejects_unverified_remote_profiles() {
        let issuer = DevelopmentIssuer::new().expect("issuer");
        let issuers = issuer.trusted_issuers();
        let device = DeviceKeyPair::generate().expect("device");
        let credential = issuer
            .issue_synthetic(&device, "Profile", 25, 1, 100)
            .expect("credential");
        let mut profile =
            PublicProfile::create(&device, credential, vec![], 50, &issuers, 2).expect("profile");
        profile.signature[0] ^= 1;
        let mut profiles = BTreeMap::new();
        assert!(insert_verified_profile(&mut profiles, profile, &issuers, 3).is_err());
        assert!(profiles.is_empty());
    }

    #[tokio::test]
    async fn sync_client_does_not_accept_inbound_rpc_requests() {
        let server_dir = TempDir::new().expect("server directory");
        let client_dir = TempDir::new().expect("client directory");
        let issuer = DevelopmentIssuer::new().expect("issuer");
        let issuers = issuer.trusted_issuers();
        let server = PeerNode::start(
            NodeConfig {
                data_dir: server_dir.path().to_owned(),
                request_timeout: Duration::from_secs(2),
                ..NodeConfig::default()
            },
            issuers.clone(),
        )
        .await
        .expect("start server");
        let address = server.wait_for_listeners().await.expect("server address")[0].clone();
        let client = PeerNode::start_sync(
            NodeConfig {
                data_dir: client_dir.path().to_owned(),
                bootstrap_peers: vec![BootstrapPeer {
                    peer_id: server.peer_id(),
                    address,
                }],
                request_timeout: Duration::from_secs(2),
                ..NodeConfig::default()
            },
            issuers,
            TransferMeter::new(1024 * 1024, 1024 * 1024),
            HashSet::from([server.peer_id()]),
        )
        .await
        .expect("start sync client");
        let owner = DeviceKeyPair::generate().expect("device").profile_id();

        assert!(matches!(
            client
                .request(server.peer_id(), RpcRequest::GetProfile { owner })
                .await,
            Ok(RpcResponse::Profile(None))
        ));
        let inbound = tokio::time::timeout(
            Duration::from_secs(2),
            server.request(client.peer_id(), RpcRequest::GetProfile { owner }),
        )
        .await
        .expect("inbound request must fail promptly");
        assert!(
            matches!(inbound, Err(NetworkError::Request(_))),
            "sync clients must reject inbound protocol negotiation, got {inbound:?}"
        );

        client.shutdown().await;
        server.shutdown().await;
    }

    #[test]
    fn startup_cleanup_reclaims_expired_photo_quota() {
        let directory = TempDir::new().expect("storage directory");
        let config = NodeConfig {
            data_dir: directory.path().to_owned(),
            storage_bytes: 120_000,
            ..NodeConfig::default()
        };
        let issuer = DevelopmentIssuer::new().expect("issuer");
        let issuers = issuer.trusted_issuers();
        let old_device = DeviceKeyPair::generate().expect("old device");
        let old_credential = issuer
            .issue_synthetic(&old_device, "Old", 25, 1, 10)
            .expect("old credential");
        let old_bytes = vec![1; 80_000];
        let old_manifest = PhotoManifest::from_bytes(&old_bytes, "image/jpeg").expect("manifest");
        let old_profile = PublicProfile::create(
            &old_device,
            old_credential.clone(),
            vec![old_manifest.clone()],
            10,
            &issuers,
            2,
        )
        .expect("old profile");
        let old_lease =
            ContentLease::issue(&old_device, &old_credential, &old_manifest, 2, 10, &issuers)
                .expect("old lease");

        let mut storage = PeerStorage::open(
            config.data_dir.join("peer-storage.sqlite3"),
            StorageLimits {
                max_bytes: config.storage_bytes,
                ..StorageLimits::default()
            },
        )
        .expect("open storage");
        storage
            .store_profile(&old_profile, &issuers, 3)
            .expect("store old profile");
        storage
            .store_photo(
                old_manifest.hash,
                &old_lease,
                &old_bytes,
                &old_credential,
                &issuers,
                3,
            )
            .expect("store old photo");

        let now = 20;
        let new_device = DeviceKeyPair::generate().expect("new device");
        let new_credential = issuer
            .issue_synthetic(&new_device, "New", 25, now, now + 200)
            .expect("new credential");
        let new_bytes = vec![2; 80_000];
        let new_manifest = PhotoManifest::from_bytes(&new_bytes, "image/jpeg").expect("manifest");
        let new_profile = PublicProfile::create(
            &new_device,
            new_credential.clone(),
            vec![new_manifest.clone()],
            now + 100,
            &issuers,
            now,
        )
        .expect("new profile");
        let new_lease = ContentLease::issue(
            &new_device,
            &new_credential,
            &new_manifest,
            now,
            now + 100,
            &issuers,
        )
        .expect("new lease");

        storage
            .store_profile(&new_profile, &issuers, now)
            .expect("new profile fits");
        assert!(
            storage
                .store_photo(
                    new_manifest.hash,
                    &new_lease,
                    &new_bytes,
                    &new_credential,
                    &issuers,
                    now
                )
                .is_err()
        );
        drop(storage);

        let mut storage = open_peer_storage(&config, now, None).expect("startup expiry cleanup");
        storage
            .store_photo(
                new_manifest.hash,
                &new_lease,
                &new_bytes,
                &new_credential,
                &issuers,
                now,
            )
            .expect("new photo fits after expired blob reclamation");
        assert_eq!(
            storage
                .get_photo(new_device.profile_id(), new_manifest.hash, &issuers, now)
                .expect("read photo"),
            Some(new_bytes),
        );
    }
}
