use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use annoda_core::{
    AccountKeyStore, PortableAccountVault,
    identity::{DevelopmentIssuer, DeviceKeyPair},
    matching::MatchRecord,
    protocol::{ContentLease, MailboxParcel, PhotoManifest, PublicProfile},
    storage::{PeerStorage, StorageLimits},
};
use annoda_network::{
    AuthorizedReplica, AuthorizedReplicaPhoto, ContributionInputs, HostConditions, ManualClock,
    NodeConfig, PeerContributionPolicy, PeerNode, SyncBudget, SyncCancellationToken, SyncContext,
    SyncPeerAddress, SyncStatus, sync_once,
};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm,
    core::{Transport, upgrade},
    identity, noise, request_response,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use serde::{Serialize, de::DeserializeOwned};
use tempfile::TempDir;
use tokio::net::TcpListener;

const NOW: u64 = 2_000;
const PASSPHRASE: &[u8] = b"sync-limits-test-passphrase";

fn node_config(dir: &TempDir, clock: Arc<ManualClock>) -> NodeConfig {
    NodeConfig {
        data_dir: dir.path().to_owned(),
        request_timeout: Duration::from_millis(500),
        bandwidth_bytes_per_second: 64 * 1024 * 1024,
        clock,
        ..NodeConfig::default()
    }
}

struct Alice {
    account: Arc<annoda_core::UnlockedAccount>,
    credential: annoda_core::identity::VerifiedCredential,
    issuer: DevelopmentIssuer,
    clock: Arc<ManualClock>,
    directory: TempDir,
}

fn alice() -> Alice {
    let directory = TempDir::new().unwrap();
    let vault = PortableAccountVault::new(directory.path().join("vault"));
    let first = vault.create(PASSPHRASE).unwrap();
    let issuer = DevelopmentIssuer::new().unwrap();
    let credential = issuer
        .issue_synthetic(first.identity(), "Alice", 28, NOW - 1, NOW + 8_000)
        .unwrap();
    first.lock();
    let account = Arc::new(vault.unlock(PASSPHRASE).unwrap());
    Alice {
        account,
        credential,
        issuer,
        clock: Arc::new(ManualClock::new(NOW)),
        directory,
    }
}

fn context(alice: &Alice, peers: Vec<SyncPeerAddress>) -> SyncContext {
    SyncContext::new(
        alice.credential.clone(),
        alice.issuer.trusted_issuers(),
        alice.directory.path().join("client-state.sqlite3"),
        alice.directory.path().join("transport"),
        peers,
    )
    .unwrap()
    .with_clock(alice.clock.clone())
}

fn peer(node: &PeerNode, address: &libp2p::Multiaddr) -> SyncPeerAddress {
    SyncPeerAddress {
        peer_id: node.peer_id().to_string(),
        address: address.to_string(),
    }
}

fn like_parcel(
    issuer: &DevelopmentIssuer,
    recipient: &annoda_core::identity::VerifiedCredential,
    sender_name: &str,
    id: u8,
) -> MailboxParcel {
    let trust = issuer.trusted_issuers();
    let device = DeviceKeyPair::generate().unwrap();
    let sender = issuer
        .issue_synthetic(&device, sender_name, 30, NOW - 1, NOW + 8_000)
        .unwrap();
    let mut record = MatchRecord::new(sender.profile_id(), recipient.profile_id()).unwrap();
    let envelope = record
        .create_like_envelope(
            &device,
            &sender,
            recipient,
            [id; 16],
            NOW,
            NOW + 1_000,
            &trust,
        )
        .unwrap();
    MailboxParcel::create(&envelope, &sender, recipient, &trust, NOW).unwrap()
}

async fn volunteer(
    issuer: &DevelopmentIssuer,
    clock: Arc<ManualClock>,
) -> (TempDir, PeerNode, libp2p::Multiaddr) {
    let dir = TempDir::new().unwrap();
    let node = PeerNode::start(node_config(&dir, clock), issuer.trusted_issuers())
        .await
        .unwrap();
    let address = node.wait_for_listeners().await.unwrap()[0].clone();
    (dir, node, address)
}

#[derive(Clone, Default)]
struct RetryCodec;

impl request_response::Codec for RetryCodec {
    type Protocol = StreamProtocol;
    type Request = annoda_network::RpcRequest;
    type Response = annoda_network::RpcResponse;

    fn read_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> impl std::future::Future<Output = io::Result<Self::Request>> + Send
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io)
    }

    fn read_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
    ) -> impl std::future::Future<Output = io::Result<Self::Response>> + Send
    where
        T: AsyncRead + Unpin + Send,
    {
        read_frame(io)
    }

    fn write_request<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        request: Self::Request,
    ) -> impl std::future::Future<Output = io::Result<()>> + Send
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, request)
    }

    fn write_response<T>(
        &mut self,
        _: &StreamProtocol,
        io: &mut T,
        response: Self::Response,
    ) -> impl std::future::Future<Output = io::Result<()>> + Send
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, response)
    }
}

async fn read_frame<T, M>(io: &mut T) -> io::Result<M>
where
    T: AsyncRead + Unpin + Send,
    M: DeserializeOwned,
{
    let mut length = [0; 4];
    io.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length > annoda_network::MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut frame = vec![0; length];
    io.read_exact(&mut frame).await?;
    postcard::from_bytes(&frame)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid frame"))
}

async fn write_frame<T, M>(io: &mut T, message: M) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
    M: Serialize,
{
    let frame = postcard::to_allocvec(&message)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid message"))?;
    let length = u32::try_from(frame.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame too large"))?;
    io.write_all(&length.to_be_bytes()).await?;
    io.write_all(&frame).await?;
    io.flush().await
}

#[derive(NetworkBehaviour)]
struct RejectingBehaviour {
    rpc: request_response::Behaviour<RetryCodec>,
}

struct RetryCountingPeer {
    peer_id: PeerId,
    address: Multiaddr,
    requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl RetryCountingPeer {
    async fn start() -> Self {
        let keys = identity::Keypair::generate_ed25519();
        let peer_id = keys.public().to_peer_id();
        let transport = tcp::tokio::Transport::new(tcp::Config::default())
            .upgrade(upgrade::Version::V1)
            .authenticate(noise::Config::new(&keys).unwrap())
            .multiplex(yamux::Config::default())
            .boxed();
        let rpc = request_response::Behaviour::with_codec(
            RetryCodec,
            [(
                StreamProtocol::new("/annoda/1"),
                request_response::ProtocolSupport::Full,
            )],
            request_response::Config::default(),
        );
        let mut swarm = Swarm::new(
            transport,
            RejectingBehaviour { rpc },
            peer_id,
            libp2p::swarm::Config::with_tokio_executor(),
        );
        swarm
            .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
            .unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let count = requests.clone();
        let (address_tx, address_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut address_tx = Some(address_tx);
            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        if let Some(sender) = address_tx.take() {
                            let _ = sender.send(address);
                        }
                    }
                    SwarmEvent::Behaviour(RejectingBehaviourEvent::Rpc(
                        request_response::Event::Message {
                            message: request_response::Message::Request { channel, .. },
                            ..
                        },
                    )) => {
                        count.fetch_add(1, Ordering::SeqCst);
                        let _ = swarm
                            .behaviour_mut()
                            .rpc
                            .send_response(channel, annoda_network::RpcResponse::Ack);
                    }
                    _ => {}
                }
            }
        });
        let address = address_rx.await.unwrap();
        Self {
            peer_id,
            address,
            requests,
            task,
        }
    }

    fn sync_peer(&self) -> SyncPeerAddress {
        SyncPeerAddress {
            peer_id: self.peer_id.to_string(),
            address: self.address.to_string(),
        }
    }

    fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }

    async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_reachable_peer_returns_deferred_without_waiting_for_request_timeout() {
    let alice = alice();
    let (dir, node, address) = volunteer(&alice.issuer, alice.clock.clone()).await;
    let id = node.peer_id();
    node.shutdown().await;

    let started = Instant::now();
    let report = sync_once(
        &alice.account,
        context(
            &alice,
            vec![SyncPeerAddress {
                peer_id: id.to_string(),
                address: address.to_string(),
            }],
        ),
        SyncBudget {
            max_duration: Duration::from_secs(3),
            request_timeout: Duration::from_millis(500),
            retries: 0,
            ..SyncBudget::default()
        },
        SyncCancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.status, SyncStatus::Deferred);
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_and_item_limits_bound_the_committed_work() {
    let alice = alice();
    let mut nodes = Vec::new();
    for _ in 0..2 {
        let (dir, node, address) = volunteer(&alice.issuer, alice.clock.clone()).await;
        nodes.push((dir, node, address));
    }
    let peers = nodes
        .iter()
        .map(|(_, node, address)| peer(node, address))
        .collect();
    let bounded = sync_once(
        &alice.account,
        context(&alice, peers),
        SyncBudget {
            max_peers: 1,
            ..SyncBudget::default()
        },
        SyncCancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(bounded.status, SyncStatus::Complete);
    assert_eq!(bounded.contacted_peers.len(), 1);

    let (dir, node, address) = &nodes[0];
    let mut db = PeerStorage::open(
        dir.path().join("peer-storage.sqlite3"),
        StorageLimits::default(),
    )
    .unwrap();
    for (i, name) in [(1, "Bob"), (2, "Cara")] {
        assert!(
            db.deposit_mailbox(&like_parcel(&alice.issuer, &alice.credential, name, i), NOW)
                .unwrap()
        );
    }
    drop(db);
    let report = sync_once(
        &alice.account,
        context(&alice, vec![peer(node, address)]),
        SyncBudget {
            max_mailbox_items: 1,
            ..SyncBudget::default()
        },
        SyncCancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.status, SyncStatus::BudgetExhausted);
    assert_eq!(report.verified_items + report.rejected_items, 1);
    assert_eq!(report.new_events.len(), 1);
    for (_, node, _) in nodes {
        node.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn byte_and_deadline_limits_hold_during_a_stalled_tcp_handshake() {
    let alice = alice();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer_id = libp2p::PeerId::random();
    let (accepted_tx, mut accepted_rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let _ = accepted_tx.send(());
            tokio::spawn(async move {
                let _socket = socket;
                tokio::time::sleep(Duration::from_secs(4)).await;
            });
        }
    });
    let peer = SyncPeerAddress {
        peer_id: peer_id.to_string(),
        address: format!("/ip4/127.0.0.1/tcp/{}", address.port()),
    };
    let mut budget = SyncBudget {
        max_duration: Duration::from_millis(250),
        max_download_bytes: 7,
        request_timeout: Duration::from_secs(2),
        retries: 2,
        ..SyncBudget::default()
    };
    let start = Instant::now();
    let report = sync_once(
        &alice.account,
        context(&alice, vec![peer.clone()]),
        budget.clone(),
        SyncCancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), accepted_rx.recv())
            .await
            .unwrap()
            .is_some()
    );
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(report.downloaded_bytes <= budget.max_download_bytes);
    assert!(report.uploaded_bytes <= budget.max_upload_bytes);

    budget.max_duration = Duration::from_millis(120);
    budget.max_download_bytes = 1024 * 1024;
    let start = Instant::now();
    let report = sync_once(
        &alice.account,
        context(&alice, vec![peer]),
        budget,
        SyncCancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.status, SyncStatus::BudgetExhausted);
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn retry_count_bounds_repeated_rejected_mailbox_requests() {
    let alice = alice();
    let peer = RetryCountingPeer::start().await;
    let peers = vec![peer.sync_peer()];
    let base_budget = SyncBudget {
        max_duration: Duration::from_secs(5),
        request_timeout: Duration::from_secs(1),
        retries: 0,
        ..SyncBudget::default()
    };
    let once = sync_once(
        &alice.account,
        context(&alice, peers.clone()),
        base_budget.clone(),
        SyncCancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(once.status, SyncStatus::Deferred);
    assert_eq!(peer.request_count(), 1);

    let mut retried_budget = base_budget;
    retried_budget.retries = 2;
    let retried = sync_once(
        &alice.account,
        context(&alice, peers),
        retried_budget,
        SyncCancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(retried.status, SyncStatus::Deferred);
    assert_eq!(
        peer.request_count(),
        4,
        "one first attempt plus two retries after the baseline attempt"
    );
    peer.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancellation_drains_blocked_peer_and_preserves_prior_committed_event_for_resume() {
    let alice = alice();
    let (volunteer_dir, volunteer, volunteer_address) =
        volunteer(&alice.issuer, alice.clock.clone()).await;
    let parcel = like_parcel(&alice.issuer, &alice.credential, "Bob", 42);
    let mut db = PeerStorage::open(
        volunteer_dir.path().join("peer-storage.sqlite3"),
        StorageLimits::default(),
    )
    .unwrap();
    assert!(db.deposit_mailbox(&parcel, NOW).unwrap());
    drop(db);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stall_addr = listener.local_addr().unwrap();
    let stall_id = libp2p::PeerId::random();
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        if let Ok((socket, _)) = listener.accept().await {
            let _ = accepted_tx.send(());
            let _socket = socket;
            tokio::time::sleep(Duration::from_secs(4)).await;
        }
    });
    let stall_peer = SyncPeerAddress {
        peer_id: stall_id.to_string(),
        address: format!("/ip4/127.0.0.1/tcp/{}", stall_addr.port()),
    };
    let healthy_peer = peer(&volunteer, &volunteer_address);
    let sync_context = context(&alice, vec![healthy_peer.clone(), stall_peer]);
    let budget = SyncBudget {
        max_duration: Duration::from_secs(5),
        request_timeout: Duration::from_secs(4),
        ..SyncBudget::default()
    };
    let cancel = SyncCancellationToken::new();
    let task_cancel = cancel.clone();
    let account = alice.account.clone();
    let task = tokio::spawn(async move {
        sync_once(&account, sync_context, budget, task_cancel)
            .await
            .unwrap()
    });
    tokio::time::timeout(Duration::from_secs(2), accepted_rx)
        .await
        .unwrap()
        .unwrap();

    let state_path = alice.directory.path().join("client-state.sqlite3");
    let owner = alice.credential.profile_id();
    let committed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Ok(state) = PeerStorage::open(&state_path, StorageLimits::default())
                && state
                    .pending_notifications(owner, 8)
                    .is_ok_and(|events| !events.is_empty())
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        committed.is_ok(),
        "first volunteer must commit before cancellation"
    );
    let start = Instant::now();
    cancel.cancel();
    let report = task.await.unwrap();
    assert_eq!(report.status, SyncStatus::Cancelled);
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(report.new_events.len(), 1);

    let state = PeerStorage::open(&state_path, StorageLimits::default()).unwrap();
    assert_eq!(state.pending_notifications(owner, 8).unwrap().len(), 1);
    let resumed = sync_once(
        &alice.account,
        context(&alice, vec![healthy_peer]),
        SyncBudget::default(),
        SyncCancellationToken::new(),
    )
    .await
    .unwrap();
    assert!(resumed.new_events.is_empty());
    assert_eq!(state.pending_notifications(owner, 8).unwrap().len(), 1);
    volunteer.shutdown().await;
}

fn replica(
    issuer: &DevelopmentIssuer,
) -> (
    AuthorizedReplica,
    annoda_core::protocol::ContentHash,
    Vec<u8>,
) {
    let trust = issuer.trusted_issuers();
    let owner = DeviceKeyPair::generate().unwrap();
    let credential = issuer
        .issue_synthetic(&owner, "Owner", 31, NOW - 1, NOW + 8_000)
        .unwrap();
    let mut bytes = Vec::new();
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut bytes, 80)
        .encode(&[25, 80, 160], 1, 1, image::ExtendedColorType::Rgb8)
        .unwrap();
    let manifest = PhotoManifest::from_bytes(&bytes, "image/jpeg").unwrap();
    let lease =
        ContentLease::issue(&owner, &credential, &manifest, NOW, NOW + 1_000, &trust).unwrap();
    let profile = PublicProfile::create(
        &owner,
        credential.clone(),
        vec![manifest.clone()],
        NOW + 2_000,
        &trust,
        NOW,
    )
    .unwrap();
    (
        AuthorizedReplica {
            profile,
            owner: credential,
            photos: vec![AuthorizedReplicaPhoto {
                manifest: manifest.clone(),
                lease,
                bytes: bytes.clone(),
            }],
        },
        manifest.hash,
        bytes,
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn contribution_requires_opt_in_and_satisfies_storage_and_transfer_caps() {
    let alice = alice();
    let (dir, node, address) = volunteer(&alice.issuer, alice.clock.clone()).await;
    let (authorized, hash, bytes) = replica(&alice.issuer);
    let owner = authorized.owner.profile_id();
    let peer = peer(&node, &address);

    let disabled = context(&alice, vec![peer.clone()]).with_contribution(ContributionInputs {
        policy: PeerContributionPolicy {
            enabled: false,
            max_storage_bytes: 1024 * 1024,
            max_transfer_bytes: 1024 * 1024,
            max_duration: Duration::from_secs(2),
            ..PeerContributionPolicy::default()
        },
        conditions: HostConditions {
            wifi_available: true,
            charging: true,
        },
        replicas: vec![authorized.clone()],
    });
    let report = sync_once(
        &alice.account,
        disabled,
        SyncBudget::default(),
        SyncCancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(report.confirmed_replicas, 0);
    let storage = PeerStorage::open(
        dir.path().join("peer-storage.sqlite3"),
        StorageLimits::default(),
    )
    .unwrap();
    assert!(
        storage
            .get_profile(owner, &alice.issuer.trusted_issuers(), NOW)
            .unwrap()
            .is_none()
    );

    let enabled = |replicas, max_storage_bytes, max_transfer_bytes| {
        context(&alice, vec![peer.clone()]).with_contribution(ContributionInputs {
            policy: PeerContributionPolicy {
                enabled: true,
                max_storage_bytes,
                max_transfer_bytes,
                max_duration: Duration::from_secs(2),
                ..PeerContributionPolicy::default()
            },
            conditions: HostConditions {
                wifi_available: true,
                charging: true,
            },
            replicas,
        })
    };
    let too_small = sync_once(
        &alice.account,
        enabled(vec![authorized.clone()], 1, 1024 * 1024),
        SyncBudget::default(),
        SyncCancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(too_small.confirmed_replicas, 0);
    assert!(
        storage
            .get_profile(owner, &alice.issuer.trusted_issuers(), NOW)
            .unwrap()
            .is_none()
    );

    let tiny_transfer = sync_once(
        &alice.account,
        enabled(vec![authorized.clone()], 1024 * 1024, 1),
        SyncBudget::default(),
        SyncCancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(tiny_transfer.confirmed_replicas, 0);
    assert!(
        storage
            .get_profile(owner, &alice.issuer.trusted_issuers(), NOW)
            .unwrap()
            .is_none()
    );

    let accepted = sync_once(
        &alice.account,
        enabled(vec![authorized], 1024 * 1024, 1024 * 1024),
        SyncBudget::default(),
        SyncCancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(accepted.confirmed_replicas, 1);
    assert_eq!(
        storage
            .get_profile(owner, &alice.issuer.trusted_issuers(), NOW)
            .unwrap()
            .unwrap()
            .owner,
        owner
    );
    assert_eq!(
        storage
            .get_photo(owner, hash, &alice.issuer.trusted_issuers(), NOW)
            .unwrap()
            .as_deref(),
        Some(bytes.as_slice())
    );
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn duplicate_replica_owners_are_rejected_before_any_contribution_transfer() {
    let alice = alice();
    let (dir, node, address) = volunteer(&alice.issuer, alice.clock.clone()).await;
    let (authorized, _, _) = replica(&alice.issuer);
    let owner = authorized.owner.profile_id();
    let report = sync_once(
        &alice.account,
        context(&alice, vec![peer(&node, &address)]).with_contribution(ContributionInputs {
            policy: PeerContributionPolicy {
                enabled: true,
                max_storage_bytes: 1024 * 1024,
                max_transfer_bytes: 1024 * 1024,
                max_duration: Duration::from_secs(2),
                ..PeerContributionPolicy::default()
            },
            conditions: HostConditions {
                wifi_available: true,
                charging: true,
            },
            replicas: vec![authorized.clone(), authorized],
        }),
        SyncBudget::default(),
        SyncCancellationToken::new(),
    )
    .await
    .unwrap();

    assert_eq!(report.confirmed_replicas, 0);
    assert_eq!(report.status, SyncStatus::Partial);
    let storage = PeerStorage::open(
        dir.path().join("peer-storage.sqlite3"),
        StorageLimits::default(),
    )
    .unwrap();
    assert!(
        storage
            .get_profile(owner, &alice.issuer.trusted_issuers(), NOW)
            .unwrap()
            .is_none(),
        "duplicate owners must be rejected before sending their profile"
    );
    node.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn incomplete_replica_keeps_confirmed_count_and_marks_batch_partial() {
    let alice = alice();
    let (dir, node, address) = volunteer(&alice.issuer, alice.clock.clone()).await;
    let (complete, _, _) = replica(&alice.issuer);
    let complete_owner = complete.owner.profile_id();
    let (mut incomplete, _, _) = replica(&alice.issuer);
    let incomplete_owner = incomplete.owner.profile_id();
    incomplete.photos.clear();

    let report = sync_once(
        &alice.account,
        context(&alice, vec![peer(&node, &address)]).with_contribution(ContributionInputs {
            policy: PeerContributionPolicy {
                enabled: true,
                max_storage_bytes: 1024 * 1024,
                max_transfer_bytes: 1024 * 1024,
                max_duration: Duration::from_secs(2),
                ..PeerContributionPolicy::default()
            },
            conditions: HostConditions {
                wifi_available: true,
                charging: true,
            },
            replicas: vec![complete, incomplete],
        }),
        SyncBudget::default(),
        SyncCancellationToken::new(),
    )
    .await
    .unwrap();

    assert_eq!(report.confirmed_replicas, 1);
    assert_eq!(report.status, SyncStatus::Partial);
    let storage = PeerStorage::open(
        dir.path().join("peer-storage.sqlite3"),
        StorageLimits::default(),
    )
    .unwrap();
    let issuers = alice.issuer.trusted_issuers();
    assert!(
        storage
            .get_profile(complete_owner, &issuers, NOW)
            .unwrap()
            .is_some()
    );
    assert!(
        storage
            .get_profile(incomplete_owner, &issuers, NOW)
            .unwrap()
            .is_none()
    );
    node.shutdown().await;
}
