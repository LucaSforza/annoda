use std::{io::Cursor, sync::Arc, time::Duration};

use annoda_core::{
    identity::{DevelopmentIssuer, DeviceKeyPair},
    matching::{ContactDisclosure, ContactHandle, ContactService, MatchRecord, MatchState},
    protocol::{
        ContentHash, ContentLease, MailboxParcel, MessageKind, PhotoManifest, PublicProfile,
    },
    storage::{PeerStorage, StorageLimits},
};
use annoda_intelligence::safety::{DeterministicSafetyFixture, PhotoProcessor};
use annoda_network::{BootstrapPeer, ManualClock, NodeConfig, PeerNode, RpcRequest, RpcResponse};
use image::{DynamicImage, ImageBuffer, ImageFormat, Rgb};
use libp2p::Multiaddr;
use tempfile::TempDir;

const NOW: u64 = 1_000;

fn config(dir: &TempDir, clock: Arc<ManualClock>, bootstrap: Vec<BootstrapPeer>) -> NodeConfig {
    NodeConfig {
        bootstrap_peers: bootstrap,
        data_dir: dir.path().to_owned(),
        request_timeout: Duration::from_secs(3),
        bandwidth_bytes_per_second: 64 * 1024 * 1024,
        clock,
        ..NodeConfig::default()
    }
}

fn bootstrap(node: &PeerNode, address: Multiaddr) -> BootstrapPeer {
    BootstrapPeer {
        peer_id: node.peer_id(),
        address,
    }
}

fn local_storage(dir: &TempDir) -> PeerStorage {
    PeerStorage::open(dir.path().join("profile.sqlite3"), StorageLimits::default()).unwrap()
}

fn jpeg(seed: u8) -> Vec<u8> {
    let pixels = ImageBuffer::from_fn(24, 18, |x, y| {
        Rgb([seed.wrapping_add(x as u8), y as u8, 90])
    });
    let mut output = Cursor::new(Vec::new());
    DynamicImage::ImageRgb8(pixels)
        .write_to(&mut output, ImageFormat::Jpeg)
        .unwrap();
    output.into_inner()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_swarms_replicate_photos_and_deliver_private_likes_and_contacts() {
    let clock = Arc::new(ManualClock::new(NOW));
    let issuer = DevelopmentIssuer::new().unwrap();
    let issuers = issuer.trusted_issuers();
    let alice_device = DeviceKeyPair::generate().unwrap();
    let bob_device = DeviceKeyPair::generate().unwrap();
    let alice_credential = issuer
        .issue_synthetic(&alice_device, "Alice", 29, NOW - 1, NOW + 8_000)
        .unwrap();
    let bob_credential = issuer
        .issue_synthetic(&bob_device, "Bob", 31, NOW - 1, NOW + 8_000)
        .unwrap();
    let alice_id = alice_credential.profile_id();
    let bob_id = bob_credential.profile_id();

    let volunteer_a_dir = TempDir::new().unwrap();
    let volunteer_b_dir = TempDir::new().unwrap();
    let alice_node_dir = TempDir::new().unwrap();
    let bob_node_dir = TempDir::new().unwrap();
    let volunteer_a = PeerNode::start(
        config(&volunteer_a_dir, clock.clone(), vec![]),
        issuers.clone(),
    )
    .await
    .unwrap();
    let a_addr = volunteer_a.wait_for_listeners().await.unwrap()[0].clone();
    let volunteer_b = PeerNode::start(
        config(
            &volunteer_b_dir,
            clock.clone(),
            vec![bootstrap(&volunteer_a, a_addr.clone())],
        ),
        issuers.clone(),
    )
    .await
    .unwrap();
    let b_addr = volunteer_b.wait_for_listeners().await.unwrap()[0].clone();
    let alice_node = PeerNode::start(
        config(
            &alice_node_dir,
            clock.clone(),
            vec![
                bootstrap(&volunteer_a, a_addr.clone()),
                bootstrap(&volunteer_b, b_addr.clone()),
            ],
        ),
        issuers.clone(),
    )
    .await
    .unwrap();
    alice_node.wait_for_listeners().await.unwrap();
    let volunteers = [volunteer_a.peer_id(), volunteer_b.peer_id()];

    let processor =
        PhotoProcessor::new(DeterministicSafetyFixture::new(0.0).unwrap(), true).unwrap();
    let mut manifests = Vec::new();
    let mut normalized = Vec::new();
    for seed in [8, 80, 160] {
        let prepared = processor.prepare_outgoing(&jpeg(seed), 0.5).unwrap();
        let manifest = PhotoManifest::from_bytes(&prepared.bytes, prepared.media_type).unwrap();
        assert_eq!(manifest.hash, ContentHash(prepared.content_hash));
        manifests.push(manifest);
        normalized.push(prepared.bytes);
    }
    let profile = PublicProfile::create(
        &alice_device,
        alice_credential.clone(),
        manifests.clone(),
        NOW + 4_000,
        &issuers,
        NOW,
    )
    .unwrap();
    assert_eq!(
        alice_node
            .publish_profile(&volunteers, profile.clone())
            .await
            .unwrap(),
        2
    );
    for (manifest, bytes) in manifests.iter().zip(normalized.iter()) {
        let lease = ContentLease::issue(
            &alice_device,
            &alice_credential,
            manifest,
            NOW,
            NOW + 3_000,
            &issuers,
        )
        .unwrap();
        let copies = alice_node
            .replicate_photo(
                &volunteers,
                manifest.clone(),
                lease,
                alice_credential.clone(),
                bytes.clone(),
                2,
            )
            .await
            .unwrap();
        assert_eq!(copies.len(), 2);
    }

    // Alice disconnects. Bob discovers her profile from volunteer RPC without knowing her ID.
    alice_node.shutdown().await;
    let mut bob_node = PeerNode::start(
        config(
            &bob_node_dir,
            clock.clone(),
            vec![
                bootstrap(&volunteer_a, a_addr.clone()),
                bootstrap(&volunteer_b, b_addr),
            ],
        ),
        issuers.clone(),
    )
    .await
    .unwrap();
    bob_node.wait_for_listeners().await.unwrap();
    let discovered = tokio::time::timeout(
        Duration::from_secs(12),
        bob_node.discover_profiles(&volunteers, 20),
    )
    .await
    .unwrap()
    .unwrap();
    let alice_profile = discovered
        .iter()
        .find(|profile| profile.owner == alice_id)
        .expect("discover Alice without her profile ID");
    let providers = tokio::time::timeout(
        Duration::from_secs(12),
        bob_node.find_providers(alice_profile.photos[0].hash.0),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        !providers.is_empty(),
        "Kademlia should discover at least one announced provider"
    );
    for (manifest, expected) in alice_profile.photos.iter().zip(normalized.iter()) {
        let bytes = tokio::time::timeout(
            Duration::from_secs(12),
            bob_node.fetch_photo(alice_id, manifest.hash, &volunteers),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&bytes, expected);
        processor
            .validate_incoming(&bytes, manifest.hash.0, manifest.byte_count as usize, 0.5)
            .unwrap();
    }

    let mut bob_state = local_storage(&bob_node_dir);
    let mut alice_state = local_storage(&alice_node_dir);
    let mut bob_match = MatchRecord::new(bob_id, alice_id).unwrap();
    let like = bob_match
        .create_like_envelope(
            &bob_device,
            &bob_credential,
            &alice_credential,
            [11; 16],
            NOW,
            NOW + 1_000,
            &issuers,
        )
        .unwrap();
    bob_state
        .apply_local_like(bob_id, alice_id, [11; 16])
        .unwrap();
    let like_parcel =
        MailboxParcel::create(&like, &bob_credential, &alice_credential, &issuers, NOW).unwrap();
    bob_node
        .deposit_parcel(&volunteers, like_parcel.clone(), 2)
        .await
        .unwrap();
    assert!(
        bob_node
            .deposit_parcel(&volunteers, like_parcel, 2)
            .await
            .is_ok()
    );

    // A dead replica is skipped when Bob retries retrieval by content hash.
    volunteer_a.shutdown().await;
    let fallback = bob_node
        .fetch_photo(alice_id, manifests[0].hash, &volunteers)
        .await
        .unwrap();
    assert_eq!(fallback, normalized[0]);

    // Restart the replica from SQLite to retain its photo and queued parcels.
    bob_node.shutdown().await;
    let volunteer_b_peer_id = volunteer_b.peer_id();
    volunteer_b.shutdown().await;
    let volunteer_b = PeerNode::start(
        config(&volunteer_b_dir, clock.clone(), vec![]),
        issuers.clone(),
    )
    .await
    .unwrap();
    assert_eq!(
        volunteer_b.peer_id(),
        volunteer_b_peer_id,
        "a volunteer must retain its transport identity after a full restart"
    );
    let b_addr = volunteer_b.wait_for_listeners().await.unwrap()[0].clone();
    bob_node = PeerNode::start(
        config(
            &bob_node_dir,
            clock.clone(),
            vec![bootstrap(&volunteer_b, b_addr.clone())],
        ),
        issuers.clone(),
    )
    .await
    .unwrap();
    bob_node.wait_for_listeners().await.unwrap();
    let persisted_photo = bob_node
        .request(
            volunteer_b.peer_id(),
            RpcRequest::GetProfile { owner: alice_id },
        )
        .await;
    assert!(persisted_photo.is_ok());
    let alice_node = PeerNode::start(
        config(
            &alice_node_dir,
            clock.clone(),
            vec![bootstrap(&volunteer_b, b_addr.clone())],
        ),
        issuers.clone(),
    )
    .await
    .unwrap();
    alice_node.wait_for_listeners().await.unwrap();
    let challenge = [42; 32];
    let proof = PeerStorage::signed_poll_proof(&alice_device, alice_id, challenge, NOW).unwrap();
    let parcels = alice_node
        .poll_mailbox(
            volunteer_b.peer_id(),
            alice_credential.clone(),
            proof,
            challenge,
            NOW,
            10,
        )
        .await
        .unwrap();
    let opened = parcels
        .iter()
        .find_map(|parcel| {
            parcel
                .open(&alice_device, &alice_credential, &issuers, NOW)
                .ok()
        })
        .expect("recipient opens retained mailbox parcel");
    assert_eq!(opened.envelope.kind, MessageKind::Like);
    let incoming = alice_state
        .receive_like(
            &opened.envelope,
            &opened.sender_credential,
            &alice_device,
            &alice_credential,
            &issuers,
            NOW,
        )
        .unwrap();
    assert_eq!(incoming.state(), MatchState::Incoming);

    alice_state
        .apply_local_like(alice_id, bob_id, [22; 16])
        .unwrap();
    let mut alice_match = alice_state.load_match(alice_id, bob_id).unwrap().unwrap();
    let reciprocal = alice_match
        .create_like_envelope(
            &alice_device,
            &alice_credential,
            &bob_credential,
            [22; 16],
            NOW,
            NOW + 1_000,
            &issuers,
        )
        .unwrap();
    let reciprocal_parcel = MailboxParcel::create(
        &reciprocal,
        &alice_credential,
        &bob_credential,
        &issuers,
        NOW,
    )
    .unwrap();
    alice_node
        .deposit_parcel(&[volunteer_b.peer_id()], reciprocal_parcel, 1)
        .await
        .unwrap();
    let challenge = [43; 32];
    let proof = PeerStorage::signed_poll_proof(&bob_device, bob_id, challenge, NOW).unwrap();
    let parcels = bob_node
        .poll_mailbox(
            volunteer_b.peer_id(),
            bob_credential.clone(),
            proof,
            challenge,
            NOW,
            10,
        )
        .await
        .unwrap();
    let opened = parcels
        .iter()
        .find_map(|parcel| {
            parcel
                .open(&bob_device, &bob_credential, &issuers, NOW)
                .ok()
        })
        .expect("Bob opens reciprocal like");
    assert_eq!(opened.envelope.kind, MessageKind::Like);
    let bob_match = bob_state
        .receive_like(
            &opened.envelope,
            &opened.sender_credential,
            &bob_device,
            &bob_credential,
            &issuers,
            NOW,
        )
        .unwrap();
    assert_eq!(bob_match.state(), MatchState::Matched);
    let alice_match = alice_state
        .receive_like(
            &like,
            &bob_credential,
            &alice_device,
            &alice_credential,
            &issuers,
            NOW,
        )
        .unwrap();
    assert_eq!(alice_match.state(), MatchState::Matched);

    let handles = vec![ContactHandle {
        service: ContactService::Telegram,
        value: "@alice".into(),
    }];
    let disclosure = alice_match
        .encrypted_disclosure(
            &alice_device,
            &alice_credential,
            &bob_credential,
            handles,
            [33; 16],
            NOW,
            NOW + 1_000,
            &issuers,
        )
        .unwrap();
    let contact_parcel = MailboxParcel::create(
        &disclosure,
        &alice_credential,
        &bob_credential,
        &issuers,
        NOW,
    )
    .unwrap();
    alice_node
        .deposit_parcel(&[volunteer_b.peer_id()], contact_parcel, 1)
        .await
        .unwrap();
    let challenge = [44; 32];
    let proof = PeerStorage::signed_poll_proof(&bob_device, bob_id, challenge, NOW).unwrap();
    let parcels = bob_node
        .poll_mailbox(
            volunteer_b.peer_id(),
            bob_credential.clone(),
            proof,
            challenge,
            NOW,
            10,
        )
        .await
        .unwrap();
    let opened = parcels
        .iter()
        .filter_map(|parcel| {
            parcel
                .open(&bob_device, &bob_credential, &issuers, NOW)
                .ok()
        })
        .find(|message| message.envelope.kind == MessageKind::ContactDisclosure)
        .expect("contact disclosure delivered after match");
    let payload = opened
        .envelope
        .open(
            &bob_device,
            &opened.sender_credential,
            &bob_credential,
            &issuers,
            NOW,
        )
        .unwrap();
    let expected_match_id = bob_match.match_id().unwrap();
    let contact = ContactDisclosure::decode(&payload, alice_id, bob_id, expected_match_id).unwrap();
    assert_eq!(contact.handles[0].value, "@alice");

    let bob_handles = vec![ContactHandle {
        service: ContactService::Telegram,
        value: "@bob".into(),
    }];
    let bob_disclosure = bob_match
        .encrypted_disclosure(
            &bob_device,
            &bob_credential,
            &alice_credential,
            bob_handles,
            [34; 16],
            NOW,
            NOW + 1_000,
            &issuers,
        )
        .unwrap();
    let bob_contact_parcel = MailboxParcel::create(
        &bob_disclosure,
        &bob_credential,
        &alice_credential,
        &issuers,
        NOW,
    )
    .unwrap();
    bob_node
        .deposit_parcel(&[volunteer_b.peer_id()], bob_contact_parcel, 1)
        .await
        .unwrap();
    let challenge = [46; 32];
    let proof = PeerStorage::signed_poll_proof(&alice_device, alice_id, challenge, NOW).unwrap();
    let parcels = alice_node
        .poll_mailbox(
            volunteer_b.peer_id(),
            alice_credential.clone(),
            proof,
            challenge,
            NOW,
            10,
        )
        .await
        .unwrap();
    let opened = parcels
        .iter()
        .filter_map(|parcel| {
            parcel
                .open(&alice_device, &alice_credential, &issuers, NOW)
                .ok()
        })
        .find(|message| message.envelope.kind == MessageKind::ContactDisclosure)
        .expect("Alice receives Bob's explicit contact disclosure");
    let payload = opened
        .envelope
        .open(
            &alice_device,
            &opened.sender_credential,
            &alice_credential,
            &issuers,
            NOW,
        )
        .unwrap();
    let contact = ContactDisclosure::decode(&payload, bob_id, alice_id, expected_match_id).unwrap();
    assert_eq!(contact.handles[0].value, "@bob");

    // Trusted server clock controls expiry; RPC callers cannot supply an alternate `now`.
    clock.set(NOW + 5_000);
    let challenge = [45; 32];
    let proof =
        PeerStorage::signed_poll_proof(&alice_device, alice_id, challenge, NOW + 5_000).unwrap();
    assert!(
        alice_node
            .poll_mailbox(
                volunteer_b.peer_id(),
                alice_credential,
                proof,
                challenge,
                NOW + 5_000,
                10
            )
            .await
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        bob_node
            .request(
                volunteer_b.peer_id(),
                RpcRequest::GetPhoto {
                    owner: alice_id,
                    hash: manifests[0].hash
                }
            )
            .await
            .unwrap(),
        RpcResponse::Photo(None)
    ));

    bob_node.shutdown().await;
    alice_node.shutdown().await;
    volunteer_b.shutdown().await;
}
